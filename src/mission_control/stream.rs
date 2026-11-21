use std::collections::HashSet;
use std::convert::Infallible;
use std::io;
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::{combinators::UnsyncBoxBody, BodyExt, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::{header, Method, Request, Response, StatusCode};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::admission::{self, Refusal, Route};
use super::authority::{InvalidationReason, Live, Record, Scope};
use super::budgets::{Mode, Slot};
use super::cursor::Partition;
use super::hub::Reset;
use super::protocol::Projection;
use super::transport::{encode_snapshot, error, grants, parse_scope, partition};
use super::upstream::ReadHub;
use super::writer::SessionWriter;
use super::Issuer;

const SNAPSHOT_REPROJECTIONS: usize = 3;
const STREAM_PREFIX: &str = "/v1/mission-control/stream/";

pub(crate) type Body = UnsyncBoxBody<Bytes, Infallible>;

#[derive(Default)]
pub(crate) struct Fence {
    live: Mutex<Option<Arc<Live>>>,
    headers_written: tokio::sync::Notify,
    terminal: Mutex<Option<Terminal>>,
    track_headers: bool,
    #[cfg(test)]
    pub(crate) probe: Option<Arc<WireProbe>>,
}

struct Terminal {
    wire: Vec<u8>,
    sent: usize,
}

impl Fence {
    #[cfg(test)]
    pub(crate) fn with_probe(mut self, probe: Option<Arc<WireProbe>>) -> Self {
        self.probe = probe;
        self
    }

    pub(crate) fn track_headers(mut self, enabled: bool) -> Self {
        self.track_headers = enabled;
        self
    }

    pub(crate) async fn started(&self) {
        self.headers_written.notified().await;
    }

    fn permit_terminal(&self, frame: &Bytes) {
        // Hyper writes each SSE data frame as one HTTP/1.1 chunk.
        let mut wire = format!("{:X}\r\n", frame.len()).into_bytes();
        wire.extend_from_slice(frame);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        if let Ok(mut terminal) = self.terminal.lock() {
            *terminal = Some(Terminal { wire, sent: 0 });
        }
    }

    pub(crate) fn wrap<S>(self: &Arc<Self>, stream: S) -> Fenced<S> {
        Fenced {
            stream,
            fence: self.clone(),
            header_suffix: 0,
            notified: false,
            quiet: false,
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct WireProbe {
    pub(crate) refuse_snapshot: std::sync::atomic::AtomicBool,
    pub(crate) snapshot_attempts: std::sync::atomic::AtomicUsize,
    pub(crate) armed: std::sync::atomic::AtomicBool,
    pub(crate) blocked: tokio::sync::Notify,
    pub(crate) closed: tokio::sync::Notify,
    pub(crate) closed_at: Mutex<Option<std::time::Instant>>,
}

#[cfg(test)]
impl<S> Drop for Fenced<S> {
    fn drop(&mut self) {
        if let Some(probe) = self
            .fence
            .probe
            .as_ref()
            .filter(|probe| probe.armed.load(std::sync::atomic::Ordering::SeqCst))
        {
            *probe.closed_at.lock().unwrap() = Some(std::time::Instant::now());
            probe.closed.notify_one();
        }
    }
}

pub(crate) struct Fenced<S> {
    stream: S,
    fence: Arc<Fence>,
    header_suffix: usize,
    notified: bool,
    quiet: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for Fenced<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Fenced<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let owner = self.fence.clone();
        let guard = owner
            .live
            .lock()
            .map_err(|_| io::Error::other("stream fence unavailable"))?;
        let checked = if let Some(live) = guard.as_ref() {
            match live.authorize_payload(
                std::iter::empty(),
                || true,
                || Pin::new(&mut self.stream).poll_write(cx, bytes),
            ) {
                Ok(result) => result,
                Err(_) => {
                    let mut terminal = owner.terminal.lock().map_err(|_| fenced())?;
                    let terminal = terminal.as_mut().ok_or_else(fenced)?;
                    if (!self.quiet && terminal.sent == 0)
                        || !terminal.wire[terminal.sent..].starts_with(bytes)
                    {
                        return Poll::Ready(Err(fenced()));
                    }
                    let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
                    if let Poll::Ready(Ok(count)) = result {
                        terminal.sent += count;
                    }
                    result
                }
            }
        } else {
            Pin::new(&mut self.stream).poll_write(cx, bytes)
        };
        if matches!(checked, Poll::Ready(Ok(count)) if count != 0) {
            self.quiet = false;
        }
        if owner.track_headers && !self.notified {
            if let Poll::Ready(Ok(count)) = checked {
                for &byte in &bytes[..count] {
                    const END: &[u8] = b"\r\n\r\n";
                    if byte == END[self.header_suffix] {
                        self.header_suffix += 1;
                    } else {
                        self.header_suffix = usize::from(byte == END[0]);
                    }
                    if self.header_suffix == END.len() {
                        self.notified = true;
                        owner.headers_written.notify_one();
                        break;
                    }
                }
            }
        }
        #[cfg(test)]
        if checked.is_pending() {
            if let Some(probe) = owner
                .probe
                .as_ref()
                .filter(|probe| probe.armed.load(std::sync::atomic::Ordering::SeqCst))
            {
                probe.blocked.notify_one();
            }
        }
        checked
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let owner = self.fence.clone();
        let guard = owner
            .live
            .lock()
            .map_err(|_| io::Error::other("stream fence unavailable"))?;
        let result = if let Some(live) = guard.as_ref() {
            match live.authorize_payload(
                std::iter::empty(),
                || true,
                || Pin::new(&mut self.stream).poll_flush(cx),
            ) {
                Ok(result) => result,
                Err(_) => {
                    let terminal = owner.terminal.lock().map_err(|_| fenced())?;
                    if terminal.as_ref().is_some_and(|terminal| terminal.sent != 0) {
                        Pin::new(&mut self.stream).poll_flush(cx)
                    } else if self.quiet {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(fenced()))
                    }
                }
            }
        } else {
            Pin::new(&mut self.stream).poll_flush(cx)
        };
        if matches!(result, Poll::Ready(Ok(()))) {
            self.quiet = true;
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn fenced() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "stream write fenced")
}

pub(crate) fn is_stream(path: &str) -> bool {
    path.starts_with(STREAM_PREFIX)
}

pub(crate) async fn response(
    issuer: &Arc<Issuer>,
    hub: Arc<ReadHub>,
    req: Request<Incoming>,
    abort: Option<TcpStream>,
    fence: Arc<Fence>,
) -> Response<Body> {
    match open(issuer, hub, req, abort, fence).await {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .body(body)
            .expect("fixed SSE headers"),
        Err(refusal) => error(refusal).map(BodyExt::boxed_unsync),
    }
}

async fn open(
    issuer: &Arc<Issuer>,
    hub: Arc<ReadHub>,
    req: Request<Incoming>,
    abort: Option<TcpStream>,
    fence: Arc<Fence>,
) -> Result<Body, Refusal> {
    if req.method() != Method::GET {
        return Err(Refusal::INVALID);
    }
    let scope = parse_scope(
        req.uri()
            .path()
            .strip_prefix(STREAM_PREFIX)
            .ok_or(Refusal::INVALID)?,
    )?;
    let supplied = cursor(&req)?;
    let record = admission::authenticate(issuer, Route::Stream, req.headers()).await?;
    if grants(&record).is_empty() {
        return Err(Refusal::FORBIDDEN);
    }
    let mask = issuer.authority.masked_nodes()?;
    let projection = Projection {
        scope: &scope,
        grants: grants(&record),
        activity: true,
        masked: &|node| mask.contains(node),
    };
    let (snapshot, _) = hub
        .snapshot(&projection)
        .map_err(|_| Refusal::UNAVAILABLE)?
        .ok_or(Refusal::NOT_FOUND)?;
    let slot = hub
        .budgets
        .take(&record, Mode::Stream, &issuer.config.session_limits)?;
    let writer = SessionWriter::register(
        issuer,
        &record,
        abort.ok_or(Refusal::UNAVAILABLE)?,
        Duration::from_secs(issuer.config.session_limits.lease_max_secs),
    )?;
    let partition = partition(&scope, &record)?;
    let resume = supplied
        .as_deref()
        .map(|supplied| hub.resume(supplied, &partition));
    let (after, replay_through, reset, needs_snapshot) = match resume {
        Some(Ok(seq)) => (seq, Some(snapshot.watermark), None, false),
        Some(Err(reset)) => (snapshot.watermark, None, Some(reset), true),
        None => (snapshot.watermark, None, None, true),
    };
    *fence.live.lock().map_err(|_| Refusal::UNAVAILABLE)? = Some(writer.live.clone());
    let reader = Reader {
        issuer: issuer.clone(),
        hub: hub.clone(),
        record,
        writer,
        _slot: slot,
        scope,
        partition,
        seq: after,
        replay_through,
        masked: mask,
        reset,
        needs_snapshot,
        opening: true,
        pending: None,
        ended: false,
        changes: hub.watch(),
        fence,
        next_tick: tokio::time::Instant::now()
            + Duration::from_millis(issuer.config.session_limits.tick_interval_ms),
    };
    let frames = futures_util::stream::unfold(reader, |mut reader| async move {
        let frame = reader.next().await?;
        Some((Ok::<_, Infallible>(Frame::data(frame)), reader))
    });
    Ok(StreamBody::new(frames).boxed_unsync())
}

fn cursor(req: &Request<Incoming>) -> Result<Option<String>, Refusal> {
    let mut headers = req.headers().get_all("last-event-id").iter();
    let found = headers
        .next()
        .map(|value| value.to_str().map_err(|_| Refusal::INVALID))
        .transpose()?;
    if headers.next().is_some() {
        return Err(Refusal::INVALID);
    }
    let query = req
        .uri()
        .query()
        .map(|query| query.strip_prefix("cursor=").ok_or(Refusal::INVALID))
        .transpose()?;
    if found.is_some() && query.is_some() {
        return Err(Refusal::INVALID);
    }
    let cursor = found.or(query);
    if cursor.is_some_and(|value| {
        value.is_empty()
            || value.len() > 512
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    }) {
        return Err(Refusal::INVALID);
    }
    Ok(cursor.map(str::to_owned))
}

struct Reader {
    issuer: Arc<Issuer>,
    hub: Arc<ReadHub>,
    record: Record,
    writer: SessionWriter,
    _slot: Slot,
    scope: Scope,
    partition: Partition,
    seq: u64,
    replay_through: Option<u64>,
    masked: HashSet<String>,
    reset: Option<Reset>,
    needs_snapshot: bool,
    opening: bool,
    pending: Option<super::hub::Sequenced>,
    ended: bool,
    changes: tokio::sync::watch::Receiver<u64>,
    fence: Arc<Fence>,
    next_tick: tokio::time::Instant,
}

impl Reader {
    async fn next(&mut self) -> Option<Bytes> {
        let frame = self.next_frame().await?;
        self.next_tick = tokio::time::Instant::now()
            + Duration::from_millis(self.issuer.config.session_limits.tick_interval_ms);
        Some(frame)
    }

    async fn next_frame(&mut self) -> Option<Bytes> {
        if self.ended {
            return None;
        }
        if std::mem::take(&mut self.opening) {
            return Some(Bytes::from(format!(
                ": lease_expires_at={}\n\n",
                self.writer.lease_at
            )));
        }
        let mut reprojections = 0;
        loop {
            if let Some(reset) = self.reset.take() {
                let reason = match reset {
                    Reset::CursorInvalid => "cursor_invalid",
                    Reset::CursorExpired => "cursor_expired",
                    Reset::EpochChanged => "epoch_changed",
                    Reset::ScopeChanged => "scope_changed",
                    Reset::SlowConsumer => "slow_consumer",
                };
                let gap =
                    json!({"v":1,"type":"gap","reason":reason,"unknown_loss":true,"reset":true});
                return self
                    .writer
                    .handoff([], None, || frame("gap", None, &gap.to_string()))
                    .ok();
            }
            let masked = self.issuer.authority.masked_nodes().ok()?;
            let projection = Projection {
                scope: &self.scope,
                grants: grants(&self.record),
                activity: true,
                masked: &|node| masked.contains(node),
            };
            let changed = self
                .masked
                .symmetric_difference(&masked)
                .any(|node| projection.node_allowed(node));
            self.masked.clone_from(&masked);
            if changed && !self.needs_snapshot {
                self.reset = Some(Reset::ScopeChanged);
                self.needs_snapshot = true;
                self.replay_through = None;
                self.pending = None;
                continue;
            }
            if self.needs_snapshot {
                let (snapshot, epoch) = self.hub.subscribed_snapshot(&projection).ok()?;
                let cursor = self.hub.cursor(snapshot.watermark, &self.partition).ok()?;
                let body = encode_snapshot(
                    &snapshot,
                    &epoch,
                    &cursor,
                    self.issuer.config.session_limits.snapshot_max_bytes,
                )
                .ok()?;
                let nodes = snapshot
                    .nodes
                    .iter()
                    .filter(|node| !node.history_hidden)
                    .map(|node| node.node.as_str());
                let attention = snapshot
                    .attention
                    .iter()
                    .flatten()
                    .filter(|item| item.endpoint.is_some())
                    .map(|item| item.node.as_str());
                let body = std::str::from_utf8(&body).ok()?;
                let handoff = || {
                    self.writer.handoff(nodes.chain(attention), None, || {
                        frame("snapshot", Some(&cursor), body)
                    })
                };
                #[cfg(not(test))]
                let result = handoff();
                #[cfg(test)]
                let result = match &self.fence.probe {
                    Some(probe)
                        if probe
                            .refuse_snapshot
                            .load(std::sync::atomic::Ordering::SeqCst) =>
                    {
                        probe
                            .snapshot_attempts
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Err(fenced())
                    }
                    _ => handoff(),
                };
                let result = match result {
                    Ok(result) => result,
                    Err(_) if self.writer.still_live() => {
                        if reprojections == SNAPSHOT_REPROJECTIONS {
                            return Some(self.terminal_error("unavailable"));
                        }
                        reprojections += 1;
                        tokio::task::yield_now().await;
                        continue;
                    }
                    Err(_) => return None,
                };
                self.seq = snapshot.watermark;
                self.needs_snapshot = false;
                return Some(result);
            }
            let replaying = self
                .replay_through
                .is_some_and(|through| self.seq < through);
            let mut event = self.pending.take();
            match if event.is_some() {
                Ok(None)
            } else {
                self.hub
                    .after(self.seq, &projection, 1, replaying)
                    .map(Some)
            } {
                Ok(batch) => {
                    if let Some(batch) = batch {
                        self.seq = batch.through;
                        event = batch.events.into_iter().next();
                        if batch.coalesced {
                            self.pending = event;
                            let gap = json!({"v":1,"type":"gap","reason":"coalesced","unknown_loss":false,"reset":false});
                            return self
                                .writer
                                .handoff([], None, || frame("gap", None, &gap.to_string()))
                                .ok();
                        }
                    }
                    if let Some(event) = event.as_ref() {
                        let cursor = self.hub.cursor(event.seq, &self.partition).ok()?;
                        let mut body = json!({"v":1,"type":"event","seq":event.seq,"cursor":cursor,"at":event.at,"delta":event.delta});
                        if self.replay_through.is_some_and(|max| event.seq <= max) {
                            body["replayed"] = json!(true);
                        }
                        #[cfg(test)]
                        self.writer
                            .queued_projection_gate(event.delta.contains_history(), false)
                            .await;
                        let nodes = event.delta.contains_history().then(|| event.delta.node());
                        match self.writer.handoff(nodes, Some((&self.hub, event)), || {
                            frame("event", Some(&cursor), &body.to_string())
                        }) {
                            Ok(frame) => return Some(frame),
                            Err(_) if self.writer.still_live() => {
                                self.reset = Some(Reset::ScopeChanged);
                                self.needs_snapshot = true;
                                self.replay_through = None;
                                continue;
                            }
                            Err(_) => return None,
                        }
                    }
                }
                Err(reset) => {
                    self.reset = Some(reset);
                    self.needs_snapshot = true;
                    self.replay_through = None;
                    continue;
                }
            }
            tokio::select! {
                change = self.writer.live.change() => {
                    let code = match change?.reason {
                        InvalidationReason::LeaseExpired => "lease_expired",
                        InvalidationReason::Revoked => "revoked",
                        InvalidationReason::PolicyChanged => "policy_changed",
                    };
                    return Some(self.terminal_error(code));
                }
                result = self.changes.changed() => { result.ok()?; }
                _ = tokio::time::sleep_until(self.next_tick) => {
                    let tick = json!({"v":1,"type":"tick","server_at":crate::storage::now_epoch_secs().saturating_mul(1000)});
                    return self.writer.handoff([],None,|| frame("tick",None,&tick.to_string())).ok();
                }
            }
        }
    }

    fn terminal_error(&mut self, code: &str) -> Bytes {
        self.ended = true;
        let terminal = frame(
            "error",
            None,
            &json!({"v":1,"type":"error","code":code,"fatal":true}).to_string(),
        );
        self.fence.permit_terminal(&terminal);
        terminal
    }
}

fn frame(kind: &str, cursor: Option<&str>, json: &str) -> Bytes {
    let mut output = String::new();
    if let Some(cursor) = cursor {
        output.push_str("id: ");
        output.push_str(cursor);
        output.push('\n');
    }
    output.push_str("event: ");
    output.push_str(kind);
    output.push_str("\ndata: ");
    output.push_str(json);
    output.push_str("\n\n");
    Bytes::from(output)
}
