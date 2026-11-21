use std::collections::{BTreeMap, HashSet};
use std::future::poll_fn;
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{Sink, SinkExt, StreamExt};
use hyper::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use tokio_tungstenite::{
    tungstenite::{
        handshake::derive_accept_key,
        protocol::{
            frame::{
                coding::{CloseCode, Data, OpCode},
                Frame as RawFrame,
            },
            CloseFrame, Role, WebSocketConfig,
        },
        Error, Message,
    },
    WebSocketStream,
};

use super::admission::{self, Refusal, Route};
use super::authority::{Invalidation, InvalidationReason, Record, Scope};
use super::budgets::{Mode, Slot};
use super::cursor::Partition;
use super::hub::{Frozen, Reset, Sequenced};
use super::protocol::Projection;
use super::request::{self, Code, Request as ClientMessage};
use super::transport::{grants, partition, SnapshotMessage};
use super::upstream::ReadHub;
use super::writer::SessionWriter;
use super::{response, Issuer, WebResponse};

const PATH: &str = "/v1/mission-control/session";
const PROTOCOL: &str = "xmsg.mission-control.v1";

type Socket = WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;

struct Subscription {
    scope: Scope,
    partition: Partition,
    seq: u64,
    replay_through: Option<u64>,
    masked: HashSet<String>,
}

pub(crate) fn is_session(path: &str) -> bool {
    path == PATH
}

pub(crate) async fn upgrade(
    issuer: &Arc<Issuer>,
    hub: Arc<ReadHub>,
    mut req: Request<hyper::body::Incoming>,
    abort: Option<TcpStream>,
) -> WebResponse {
    match accept(issuer, &hub, &mut req, abort).await {
        Ok((record, writer, accepted, slot)) => {
            let upgrade = hyper::upgrade::on(&mut req);
            let issuer = issuer.clone();
            tokio::spawn(async move {
                let _slot = slot;
                if let Ok(Ok(stream)) = tokio::time::timeout(
                    Duration::from_millis(writer.limits.hello_timeout_ms),
                    upgrade,
                )
                .await
                {
                    session(issuer, hub, record, writer, stream).await;
                }
            });
            accepted
        }
        Err(error) => response(
            error.status,
            "text/plain",
            "Mission Control upgrade refused\n",
        ),
    }
}

async fn accept(
    issuer: &Issuer,
    hub: &ReadHub,
    req: &mut Request<hyper::body::Incoming>,
    abort: Option<TcpStream>,
) -> Result<(Record, SessionWriter, WebResponse, Slot), Refusal> {
    let hdr = req.headers();
    let single = |name: header::HeaderName| {
        let mut values = hdr.get_all(name).iter();
        let first = values.next().and_then(|value| value.to_str().ok());
        first.filter(|_| values.next().is_none())
    };
    if req.method() != Method::GET
        || req.uri().query().is_some()
        || single(header::SEC_WEBSOCKET_VERSION) != Some("13")
        || single(header::SEC_WEBSOCKET_PROTOCOL) != Some(PROTOCOL)
        || !single(header::UPGRADE).is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        || !single(header::CONNECTION).is_some_and(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    {
        return Err(Refusal::INVALID);
    }
    let key = single(header::SEC_WEBSOCKET_KEY).ok_or(Refusal::INVALID)?;
    if key.len() != 24 || !STANDARD.decode(key).is_ok_and(|bytes| bytes.len() == 16) {
        return Err(Refusal::INVALID);
    }
    let record = admission::authenticate(issuer, Route::Upgrade, hdr).await?;
    let slot = hub
        .budgets
        .take(&record, Mode::Upgrade, &issuer.config.session_limits)?;
    let writer = SessionWriter::register(
        issuer,
        &record,
        abort.ok_or(Refusal::UNAVAILABLE)?,
        Duration::from_secs(issuer.config.session_limits.lease_max_secs),
    )?;
    let accepted = hyper::Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::SEC_WEBSOCKET_PROTOCOL, PROTOCOL)
        .header(
            header::SEC_WEBSOCKET_ACCEPT,
            derive_accept_key(key.as_bytes()),
        )
        .body(http_body_util::Full::default())
        .map_err(|_| Refusal::UNAVAILABLE)?;
    Ok((record, writer, accepted, slot))
}

async fn session(
    issuer: Arc<Issuer>,
    hub: Arc<ReadHub>,
    record: Record,
    writer: SessionWriter,
    stream: hyper::upgrade::Upgraded,
) {
    let limits = &writer.limits;
    let config = WebSocketConfig::default()
        .max_frame_size(Some(limits.max_client_frame_bytes))
        .max_message_size(Some(limits.max_client_message_bytes))
        .write_buffer_size(0)
        .max_write_buffer_size(limits.max_server_frame_bytes + 64);
    let mut socket = WebSocketStream::from_raw_socket(
        hyper_util::rt::TokioIo::new(stream),
        Role::Server,
        Some(config),
    )
    .await;
    let hello = tokio::select! {
        invalidated = writer.live.change() => {
            if let Some(invalidated) = invalidated { finish(&mut socket, invalidated).await; }
            return;
        }
        hello = tokio::time::timeout(Duration::from_millis(limits.hello_timeout_ms), socket.next()) => hello,
    };
    let Ok(Some(frame)) = hello else {
        let _ = close(&mut socket, 4400, "bad_message").await;
        return;
    };
    let (id, offered, required, protocol) = match frame {
        Ok(Message::Text(text)) => match request::decode(
            text.as_bytes(),
            limits.max_json_depth,
            limits.max_string_bytes,
        ) {
            Ok(ClientMessage::Hello {
                id,
                capabilities,
                require,
                protocol,
                ..
            }) => (id, capabilities, require, protocol),
            _ => {
                let _ = send_error(&mut socket, None, Code::BadMessage, true).await;
                let _ = close(&mut socket, 4400, "bad_message").await;
                return;
            }
        },
        other => {
            refuse_frame(&mut socket, other).await;
            return;
        }
    };
    if protocol != 1 {
        let _ = send_error(&mut socket, Some(id), Code::VersionMismatch, true).await;
        let _ = close(&mut socket, 4409, "version_mismatch").await;
        return;
    }
    let capabilities: Vec<_> = ["observe", "activity"]
        .into_iter()
        .filter(|name| offered.iter().any(|item| item == name))
        .collect();
    if !required
        .iter()
        .all(|item| capabilities.contains(&item.as_str()))
    {
        let _ = send_error(&mut socket, Some(id), Code::CapabilityUnavailable, true).await;
        let _ = close(&mut socket, 4409, "capability_unavailable").await;
        return;
    }
    let observe_activity = capabilities.contains(&"activity");
    let connection = ulid::Ulid::new().to_string();
    let hello = json!({"v":1,"type":"hello","re":id,"protocol":1,"capabilities":capabilities,
        "connection":connection,"actor":{"principal":record.principal,"display":display(&record),"class":record.class},
        "lease_expires_at":writer.lease_at,"server_at":stamp(),
        "limits":{"max_client_message_bytes":limits.max_client_message_bytes,"max_server_message_bytes":limits.max_server_message_bytes,
            "max_json_depth":limits.max_json_depth,"subscriptions_per_connection":limits.subscriptions_per_connection,"tick_interval_ms":limits.tick_interval_ms}});
    if send(&mut socket, &writer, &[], None, hello.to_string())
        .await
        .is_err()
    {
        return;
    }

    let mut changes = hub.watch();
    let tick_interval = Duration::from_millis(limits.tick_interval_ms);
    let mut tick =
        tokio::time::interval_at(tokio::time::Instant::now() + tick_interval, tick_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut client_at = tokio::time::Instant::now();
    let mut client_tokens = f64::from(limits.client_message_burst);
    let mut refused = 0;
    let ping_period = Duration::from_millis(limits.ping_interval_ms);
    let mut ping = tokio::time::interval_at(client_at + ping_period, ping_period);
    let mut pong_deadline = None;
    let mut subscriptions = BTreeMap::<String, Subscription>::new();
    loop {
        tokio::select! {
            biased;
            invalidated = writer.live.change() => {
                if let Some(change) = invalidated { finish(&mut socket, change).await; }
                break;
            }
            frame = socket.next() => {
                match frame {
                    Some(Ok(Message::Text(text))) => {
                        let now = tokio::time::Instant::now();
                        client_tokens = (client_tokens + now.duration_since(client_at).as_secs_f64() * f64::from(limits.client_messages_per_sec))
                            .min(f64::from(limits.client_message_burst));
                        client_at = now;
                        if client_tokens < 1.0 {
                            refused += 1;
                            if send_error(&mut socket, None, Code::RateLimited, refused >= 3).await.is_err() { break; }
                            if refused >= 3 {
                                let _ = close(&mut socket, 4429, "rate_limited").await;
                                break;
                            }
                            continue;
                        }
                        refused = 0;
                        client_tokens -= 1.0;
                        match request::decode(text.as_bytes(),limits.max_json_depth,limits.max_string_bytes) {
                            Ok(ClientMessage::Hello { id, .. }) => {
                                let _ = send_error(&mut socket,Some(id),Code::BadMessage,true).await;
                                let _ = close(&mut socket,4400,"bad_message").await;
                                break;
                            }
                            Ok(ClientMessage::Unsubscribe { id, sub, .. }) => {
                                subscriptions.remove(&sub);
                                if send_value(&mut socket,&writer,json!({"v":1,"type":"unsubscribed","re":id,"sub":sub})).await.is_err() { break; }
                            }
                            Ok(ClientMessage::Subscribe { id, sub, scope, cursor, .. }) => {
                                let code = if subscriptions.contains_key(&sub) {
                                    Some(Code::DuplicateSub)
                                } else if subscriptions.len() >= limits.subscriptions_per_connection {
                                    Some(Code::TooManySubscriptions)
                                } else { None };
                                if let Some(code) = code {
                                    if send_error(&mut socket, Some(id), code, false).await.is_err() { break; }
                                    continue;
                                }
                                match begin_subscription(&mut socket,&writer,&issuer,&hub,&record,&sub,scope,id,cursor,observe_activity).await {
                                    Ok(Some(state)) => { subscriptions.insert(sub,state); }
                                    Ok(None) => {}
                                    Err(()) => break,
                                }
                            }
                            Err(error) => {
                                if send_error(&mut socket,error.reply,error.code,false).await.is_err() { break; }
                            }
                        }
                    }
                    Some(Ok(Message::Pong(body))) if body.as_ref() == b"xmsg" => { pong_deadline = None; }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(other) => { refuse_frame(&mut socket,other).await; break; }
                }
            }
            _ = changes.changed(), if !subscriptions.is_empty() => {
                for (sub, state) in &mut subscriptions {
                    if drain(&mut socket,&writer,&issuer,&hub,&record,sub,state,observe_activity).await.is_err() {
                        return;
                    }
                }
            }
            _ = tokio::time::sleep_until(client_at + Duration::from_millis(limits.idle_close_ms)), if subscriptions.is_empty() => {
                let _ = close(&mut socket, 1000, "idle").await;
                break;
            }
            _ = ping.tick(), if pong_deadline.is_none() => {
                if socket.send(Message::Ping(hyper::body::Bytes::from_static(b"xmsg"))).await.is_err() { break; }
                pong_deadline = Some(tokio::time::Instant::now() + Duration::from_millis(limits.pong_timeout_ms));
            }
            _ = async {
                if let Some(deadline) = pong_deadline { tokio::time::sleep_until(deadline).await; }
                else { std::future::pending::<()>().await; }
            } => {
                let _ = close(&mut socket, 1011, "pong_timeout").await;
                break;
            }
            _ = tick.tick() => {
                if send_value(&mut socket,&writer,json!({"v":1,"type":"tick","server_at":stamp()})).await.is_err() { break; }
            }
        }
    }
}

fn display(record: &Record) -> &str {
    match &record.grants {
        super::authority::Grants::Owner => "owner",
        super::authority::Grants::Machine { name, .. } => name,
        super::authority::Grants::Delegated { grant } => &grant.holder,
    }
}

async fn refuse_frame(socket: &mut Socket, frame: Result<Message, Error>) {
    let (code, reason) = match frame {
        Ok(Message::Binary(_)) => (1003, "text_only"),
        Err(Error::Capacity(_)) => (1009, "message_too_large"),
        Err(Error::Protocol(_)) => (1002, "protocol_error"),
        _ => (4400, "bad_message"),
    };
    let _ = close(socket, code, reason).await;
}

async fn finish(socket: &mut Socket, change: Invalidation) {
    let (code, reason) = match change.reason {
        InvalidationReason::LeaseExpired => (4401, "lease_expired"),
        InvalidationReason::Revoked => (4403, "revoked"),
        InvalidationReason::PolicyChanged => (4403, "policy_changed"),
    };
    let _ = tokio::time::timeout_at(change.cutoff.into(), close(socket, code, reason)).await;
}

async fn close(socket: &mut Socket, code: u16, reason: &'static str) -> Result<(), Error> {
    socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: reason.into(),
        })))
        .await
}

async fn send_error(
    socket: &mut Socket,
    reply: Option<u32>,
    code: Code,
    fatal: bool,
) -> Result<(), Error> {
    let mut json = json!({"v":1,"type":"error","code":code,"fatal":fatal});
    if let Some(reply) = reply {
        json["re"] = json!(reply);
    }
    socket.send(Message::Text(json.to_string().into())).await
}

#[derive(Clone, Copy)]
enum WriteFailure {
    ScopeBeforeHandoff,
    Ended,
}

impl From<WriteFailure> for () {
    fn from(_: WriteFailure) {}
}

async fn send_value(socket: &mut Socket, writer: &SessionWriter, value: Value) -> Result<(), ()> {
    send(socket, writer, &[], None, value.to_string())
        .await
        .map_err(Into::into)
}

async fn send(
    socket: &mut Socket,
    writer: &SessionWriter,
    nodes: &[&str],
    source: Option<(&ReadHub, &Sequenced)>,
    payload: String,
) -> Result<(), WriteFailure> {
    #[cfg(test)]
    writer
        .queued_projection_gate(!nodes.is_empty(), source.is_none())
        .await;
    let limits = &writer.limits;
    if payload.len() > limits.max_server_message_bytes {
        return Err(WriteFailure::Ended);
    }
    let count = payload.len().div_ceil(limits.max_server_frame_bytes);
    tokio::time::timeout(
        Duration::from_millis(limits.slow_consumer_close_ms),
        async {
            for (index, chunk) in payload
                .as_bytes()
                .chunks(limits.max_server_frame_bytes)
                .enumerate()
            {
                let (guarded, cursor) = if index == 0 {
                    (nodes, source)
                } else {
                    (&[][..], None)
                };
                let refused = || {
                    if index == 0 && writer.still_live() {
                        WriteFailure::ScopeBeforeHandoff
                    } else {
                        WriteFailure::Ended
                    }
                };
                poll_fn(|cx| {
                    match writer.handoff(guarded.iter().copied(), cursor, || {
                        Pin::new(&mut *socket).poll_ready(cx)
                    }) {
                        Ok(poll) => poll.map_err(|_| WriteFailure::Ended),
                        Err(_) => Poll::Ready(Err(refused())),
                    }
                })
                .await?;
                let opcode = OpCode::Data(if index == 0 {
                    Data::Text
                } else {
                    Data::Continue
                });
                let frame = RawFrame::message(
                    hyper::body::Bytes::copy_from_slice(chunk),
                    opcode,
                    index + 1 == count,
                );
                writer
                    .handoff(guarded.iter().copied(), cursor, || {
                        Pin::new(&mut *socket).start_send(Message::Frame(frame))
                    })
                    .map_err(|_| refused())?
                    .map_err(|_| WriteFailure::Ended)?;
                poll_fn(|cx| {
                    match writer.handoff([], None, || Pin::new(&mut *socket).poll_flush(cx)) {
                        Ok(poll) => poll.map_err(|_| WriteFailure::Ended),
                        Err(_) => Poll::Ready(Err(WriteFailure::Ended)),
                    }
                })
                .await?;
            }
            Ok(())
        },
    )
    .await
    .map_err(|_| WriteFailure::Ended)?
}

#[allow(clippy::too_many_arguments)]
async fn begin_subscription(
    socket: &mut Socket,
    writer: &SessionWriter,
    issuer: &Issuer,
    hub: &ReadHub,
    record: &Record,
    sub: &str,
    scope: Scope,
    id: u32,
    cursor: Option<String>,
    activity: bool,
) -> Result<Option<Subscription>, ()> {
    let mask = issuer.authority.masked_nodes().map_err(|_| ())?;
    let projection = Projection {
        scope: &scope,
        grants: grants(record),
        masked: &|node| mask.contains(node),
        activity,
    };
    let Some((snapshot, epoch)) = hub.frozen(&projection, true)? else {
        send_error(socket, Some(id), Code::NotFoundOrDenied, false)
            .await
            .map_err(|_| ())?;
        return Ok(None);
    };
    let partition = partition(&scope, record).map_err(|_| ())?;
    let resume = cursor
        .as_deref()
        .map(|cursor| hub.resume(cursor, &partition));
    let mode = if matches!(resume, Some(Ok(_))) {
        "resume"
    } else {
        "snapshot"
    };
    send_value(
        socket,
        writer,
        json!({"v":1,"type":"subscribed","re":id,"sub":sub,"mode":mode,"stream_epoch":epoch}),
    )
    .await?;
    let mut subscription = Subscription {
        scope,
        partition,
        seq: snapshot.watermark,
        replay_through: None,
        masked: mask.clone(),
    };
    let projection = Projection {
        scope: &subscription.scope,
        grants: grants(record),
        masked: &|node| mask.contains(node),
        activity,
    };
    match resume {
        Some(Ok(seq)) => {
            subscription.seq = seq;
            subscription.replay_through = Some(snapshot.watermark);
        }
        Some(Err(reason)) => {
            gap(socket, writer, sub, reason).await?;
            parts(
                socket,
                writer,
                hub,
                sub,
                &subscription.partition,
                snapshot,
                &epoch,
                &projection,
            )
            .await?;
        }
        None => {
            parts(
                socket,
                writer,
                hub,
                sub,
                &subscription.partition,
                snapshot,
                &epoch,
                &projection,
            )
            .await?
        }
    }
    drain(
        socket,
        writer,
        issuer,
        hub,
        record,
        sub,
        &mut subscription,
        activity,
    )
    .await?;
    Ok(Some(subscription))
}

async fn gap(
    socket: &mut Socket,
    writer: &SessionWriter,
    sub: &str,
    reason: Reset,
) -> Result<(), ()> {
    let reason = match reason {
        Reset::CursorInvalid => "cursor_invalid",
        Reset::CursorExpired => "cursor_expired",
        Reset::EpochChanged => "epoch_changed",
        Reset::ScopeChanged => "scope_changed",
        Reset::SlowConsumer => "slow_consumer",
    };
    send_value(
        socket,
        writer,
        json!({"v":1,"type":"gap","sub":sub,"reason":reason,"unknown_loss":true,"reset":true}),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn drain(
    socket: &mut Socket,
    writer: &SessionWriter,
    issuer: &Issuer,
    hub: &ReadHub,
    record: &Record,
    sub: &str,
    state: &mut Subscription,
    activity: bool,
) -> Result<(), ()> {
    let mut scope_fenced = false;
    'batch: loop {
        let mask = issuer.authority.masked_nodes().map_err(|_| ())?;
        let projection = Projection {
            scope: &state.scope,
            grants: grants(record),
            masked: &|node| mask.contains(node),
            activity,
        };
        if scope_fenced
            || state
                .masked
                .symmetric_difference(&mask)
                .any(|node| projection.node_allowed(node))
        {
            let (snapshot, epoch) = hub.frozen(&projection, false)?.ok_or(())?;
            gap(socket, writer, sub, Reset::ScopeChanged).await?;
            state.seq = snapshot.watermark;
            state.replay_through = None;
            parts(
                socket,
                writer,
                hub,
                sub,
                &state.partition,
                snapshot,
                &epoch,
                &projection,
            )
            .await?;
        }
        state.masked.clone_from(&mask);
        scope_fenced = false;
        let replaying = state
            .replay_through
            .is_some_and(|through| state.seq < through);
        let batch = match hub.after(state.seq, &projection, 8, replaying) {
            Ok(events) => events,
            Err(reason) => {
                let (snapshot, epoch) = hub.frozen(&projection, false)?.ok_or(())?;
                gap(socket, writer, sub, reason).await?;
                state.seq = snapshot.watermark;
                state.replay_through = None;
                parts(
                    socket,
                    writer,
                    hub,
                    sub,
                    &state.partition,
                    snapshot,
                    &epoch,
                    &projection,
                )
                .await?;
                continue;
            }
        };
        if batch.coalesced {
            send_value(socket, writer, json!({"v":1,"type":"gap","sub":sub,"reason":"coalesced","unknown_loss":false,"reset":false})).await?;
        }
        for event in batch.events {
            let cursor = hub.cursor(event.seq, &state.partition)?;
            let mut message = json!({"v":1,"type":"event","sub":sub,"seq":event.seq,"cursor":cursor,"at":event.at,"delta":event.delta});
            if state.replay_through.is_some_and(|max| event.seq <= max) {
                message["replayed"] = json!(true);
            }
            let nodes = if event.delta.contains_history() {
                vec![event.delta.node()]
            } else {
                vec![]
            };
            match send(
                socket,
                writer,
                &nodes,
                Some((hub, &event)),
                message.to_string(),
            )
            .await
            {
                Ok(()) => {}
                Err(WriteFailure::ScopeBeforeHandoff) => {
                    scope_fenced = true;
                    continue 'batch;
                }
                Err(WriteFailure::Ended) => return Err(()),
            }
        }
        if state.seq == batch.through {
            return Ok(());
        }
        state.seq = batch.through;
    }
}

#[allow(clippy::too_many_arguments)]
async fn parts(
    socket: &mut Socket,
    writer: &SessionWriter,
    hub: &ReadHub,
    sub: &str,
    partition: &Partition,
    snapshot: Frozen,
    epoch: &str,
    projection: &Projection<'_>,
) -> Result<(), ()> {
    let cursor = hub.cursor(snapshot.watermark, partition)?;
    let server_at = stamp();
    let mut number = 0;
    let mut used = 0usize;
    let mut truncated = false;
    let format = |nodes: &[super::protocol::Node],
                  attention: Option<&[super::protocol::Attention]>,
                  part,
                  final_part: bool,
                  truncated| {
        serde_json::to_string(&SnapshotMessage {
            v: 1,
            r#type: "snapshot",
            sub: Some(sub),
            part,
            final_part,
            stream_epoch: epoch,
            cursor: final_part.then_some(cursor.as_str()),
            server_at,
            truncated,
            nodes,
            attention,
        })
        .map_err(|_| ())
    };
    for node in snapshot
        .nodes
        .iter()
        .filter_map(|node| projection.project_node(node))
    {
        let frame = format(std::slice::from_ref(&node), None, number, false, None)?;
        if frame.len() > writer.limits.max_server_message_bytes
            || used.saturating_add(frame.len())
                > writer.limits.snapshot_max_bytes.saturating_sub(1024)
        {
            truncated = true;
            break;
        }
        used += frame.len();
        number += 1;
        let guards: &[&str] = if node.history_hidden {
            &[]
        } else {
            &[node.node.as_str()]
        };
        send(socket, writer, guards, None, frame).await?;
    }
    let mut attention = snapshot.attention.as_deref();
    loop {
        let frame = format(&[], attention, number, true, Some(truncated))?;
        if frame.len() <= writer.limits.max_server_message_bytes {
            let guarded: Vec<_> = attention
                .iter()
                .flat_map(|items| items.iter())
                .filter(|item| item.endpoint.is_some())
                .map(|item| item.node.as_str())
                .collect();
            return send(socket, writer, &guarded, None, frame)
                .await
                .map_err(Into::into);
        }
        let items = attention.filter(|items| !items.is_empty()).ok_or(())?;
        attention = Some(&items[..items.len() / 2]);
        truncated = true;
    }
}

fn stamp() -> i64 {
    crate::storage::now_epoch_secs().saturating_mul(1000)
}
