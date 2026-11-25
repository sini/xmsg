pub mod codec;
#[cfg(test)]
mod vectors;

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Write};
use std::time::Duration;

use clap::Args as ClapArgs;
use futures_util::{SinkExt, StreamExt};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::json;
use tokio::time::{self, Instant};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, http, Error as WebSocketError, Message as Frame,
};

use codec::{Delivery, Message};

const MAX_WIRE: usize = 262_144;
const SUBPROTOCOL: &str = "xmsg.mission-control.v1";

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Collector public origin
    #[arg(long)]
    pub origin: Url,
    /// Configured native device grant client ID
    #[arg(long)]
    pub client_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Mission Control origin or client configuration")]
    Config,
    #[error("collector device authorization failed")]
    Device,
    #[error("device approval expired")]
    Expired,
    #[error("device approval was refused")]
    Denied,
    #[error("Mission Control terminal output failed")]
    Output,
    #[error("re-authenticate with a new Mission Control device grant")]
    Reauthenticate,
    #[error("Mission Control protocol is incompatible with this client")]
    Incompatible,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRequest {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct DeviceError {
    error: String,
}

fn origin_allowed(origin: &Url) -> bool {
    matches!(origin.scheme(), "https" | "http")
        && origin.has_host()
        && (origin.scheme() == "https"
            || matches!(origin.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")))
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none()
}

async fn bounded(body: reqwest::Response) -> Result<Vec<u8>, Error> {
    let mut response = body;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Device)? {
        if bytes.len().saturating_add(chunk.len()) > 16_384 {
            return Err(Error::Device);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn device_grant(args: &Args) -> Result<String, Error> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| Error::Config)?;
    let device = args
        .origin
        .join("/oauth/device_authorization")
        .map_err(|_| Error::Config)?;
    let token = args
        .origin
        .join("/oauth/token")
        .map_err(|_| Error::Config)?;
    let expected_verify = args.origin.join("/device").map_err(|_| Error::Config)?;
    let reply = http
        .post(device)
        .form(&[("client_id", args.client_id.as_str())])
        .send()
        .await
        .map_err(|_| Error::Device)?;
    if reply.status() != StatusCode::OK {
        return Err(Error::Device);
    }
    let grant: DeviceRequest =
        serde_json::from_slice(&bounded(reply).await?).map_err(|_| Error::Device)?;
    if Url::parse(&grant.verification_uri).as_ref() != Ok(&expected_verify)
        || !grant
            .user_code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
        || !(8..=9).contains(&grant.user_code.len())
        || !handle_valid(&grant.device_code)
        || !(1..=86_400).contains(&grant.expires_in)
        || !(1..=600).contains(&grant.interval)
    {
        return Err(Error::Device);
    }
    println!("Open {} and enter {}", expected_verify, grant.user_code);
    let deadline = Instant::now() + Duration::from_secs(grant.expires_in);
    let mut interval = Duration::from_secs(grant.interval);
    loop {
        if Instant::now() + interval >= deadline {
            return Err(Error::Expired);
        }
        time::sleep(interval).await;
        let response = http
            .post(token.clone())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", args.client_id.as_str()),
                ("device_code", grant.device_code.as_str()),
            ])
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) if error.is_timeout() || error.is_connect() => {
                interval *= 2;
                continue;
            }
            Err(_) => return Err(Error::Device),
        };
        let status = response.status();
        let body = bounded(response).await?;
        if status == StatusCode::OK {
            let token: Token = serde_json::from_slice(&body).map_err(|_| Error::Device)?;
            if token.token_type != "Bearer"
                || token.expires_in == 0
                || !handle_valid(&token.access_token)
            {
                return Err(Error::Device);
            }
            return Ok(token.access_token);
        }
        let parsed: DeviceError = serde_json::from_slice(&body).map_err(|_| Error::Device)?;
        match parsed.error.as_str() {
            "authorization_pending" => {}
            "slow_down" => interval += Duration::from_secs(5),
            "access_denied" => return Err(Error::Denied),
            "expired_token" => return Err(Error::Expired),
            _ => return Err(Error::Device),
        }
    }
}

fn is_eligible_current(node: &codec::Node) -> bool {
    !matches!(
        node.status,
        codec::Status::RemovedRetained
            | codec::Status::Loading
            | codec::Status::Denied
            | codec::Status::UnsupportedOutboundOnly
            | codec::Status::UnsupportedTransport
    )
}

fn handle_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Connection {
    Unknown,
    Live,
    Delayed,
    Reconnecting,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LatchedStop {
    Incompatible,
    Reauthenticate,
    ReconnectMaxAttempts,
}

struct View {
    open: bool,
    reconnecting: bool,
    synced: bool,
    latched_stop: Option<LatchedStop>,
    first_dial: Option<Instant>,
    last_message: Option<Instant>,
    last_event: Option<Instant>,
    cursor: Option<String>,
    nodes: BTreeMap<String, codec::Node>,
    parts: BTreeMap<String, codec::Node>,
    last_seq: Option<u64>,
    next_part: u32,
    tick: Duration,
    stale_after: Duration,
    server_clock: Option<(Instant, u64)>,
    source_gaps: VecDeque<String>,
}

impl Default for View {
    fn default() -> Self {
        Self {
            open: false,
            reconnecting: false,
            synced: false,
            latched_stop: None,
            first_dial: None,
            last_message: None,
            last_event: None,
            cursor: None,
            nodes: BTreeMap::new(),
            parts: BTreeMap::new(),
            last_seq: None,
            next_part: 0,
            tick: Duration::from_secs(15),
            stale_after: Duration::from_secs(45),
            server_clock: None,
            source_gaps: VecDeque::new(),
        }
    }
}

impl View {
    fn silence(&self, now: Instant) -> Duration {
        self.last_message
            .or(self.first_dial)
            .map_or(Duration::ZERO, |then| now.saturating_duration_since(then))
    }

    fn clear_for_reauth(&mut self) {
        self.synced = false;
        self.parts.clear();
        self.next_part = 0;
        self.last_seq = None;
        self.cursor = None;
        self.nodes.clear();
        self.source_gaps.clear();
    }

    fn state(&self, now: Instant) -> Connection {
        match self.latched_stop {
            Some(LatchedStop::Incompatible) => return Connection::Unknown,
            Some(LatchedStop::Reauthenticate) => return Connection::Unknown,
            Some(LatchedStop::ReconnectMaxAttempts) => return Connection::Stale,
            None => {}
        }
        let silence = self.silence(now);
        if silence >= self.stale_after {
            return Connection::Stale;
        }
        if !self.open && self.reconnecting {
            return Connection::Reconnecting;
        }
        if !self.open || !self.synced {
            return Connection::Unknown;
        }
        if silence > self.tick * 2 {
            return Connection::Unknown;
        }
        let mut any_eligible = false;
        let mut any_eligible_delayed = false;
        let mut any_in_view_delayed = false;
        for node in self.nodes.values() {
            if is_eligible_current(node) {
                any_eligible = true;
                if node.delivery == Delivery::Delayed {
                    any_eligible_delayed = true;
                }
            } else if node.status != codec::Status::RemovedRetained
                && node.delivery == Delivery::Delayed
            {
                any_in_view_delayed = true;
            }
        }
        if any_eligible {
            if any_eligible_delayed {
                Connection::Delayed
            } else {
                Connection::Live
            }
        } else if any_in_view_delayed {
            Connection::Delayed
        } else {
            Connection::Unknown
        }
    }

    fn apply(&mut self, message: Message, now: Instant) -> Result<(), codec::InvalidMessage> {
        self.last_message = Some(now);
        match message {
            Message::Hello {
                protocol: 1,
                limits,
                server_at,
                ..
            } => {
                if limits.max_server_message_bytes > MAX_WIRE || limits.tick_interval_ms == 0 {
                    return Err(codec::InvalidMessage);
                }
                self.tick = Duration::from_millis(limits.tick_interval_ms);
                self.server_clock = Some((now, server_at));
            }
            Message::Hello { .. } => return Err(codec::InvalidMessage),
            Message::Snapshot {
                part,
                final_part,
                cursor,
                nodes,
                server_at,
                ..
            } => {
                if part != self.next_part {
                    return Err(codec::InvalidMessage);
                }
                self.server_clock = Some((now, server_at));
                self.last_event = Some(now);
                for node in nodes {
                    if self.parts.insert(node.node.clone(), node).is_some() {
                        return Err(codec::InvalidMessage);
                    }
                }
                if final_part {
                    self.nodes = std::mem::take(&mut self.parts);
                    self.next_part = 0;
                    self.last_seq = None;
                    self.cursor = cursor;
                    self.synced = true;
                } else {
                    self.next_part = self.next_part.checked_add(1).ok_or(codec::InvalidMessage)?;
                }
            }
            Message::Event {
                seq, cursor, delta, ..
            } => {
                if !self.synced || self.last_seq.is_some_and(|previous| seq <= previous) {
                    return Err(codec::InvalidMessage);
                }
                self.last_seq = Some(seq);
                self.last_event = Some(now);
                self.cursor = Some(cursor);
                self.delta(*delta);
            }
            Message::Gap { reset: true, .. } => {
                self.synced = false;
                self.parts.clear();
                self.next_part = 0;
                self.last_seq = None;
                self.cursor = None;
                self.nodes.clear();
                self.source_gaps.clear();
            }
            Message::Tick { server_at, .. } => {
                self.server_clock = Some((now, server_at));
            }
            _ => {}
        }
        Ok(())
    }

    fn delta(&mut self, delta: codec::Delta) {
        use codec::Delta;
        match delta {
            Delta::NodeStatus {
                node,
                delivery,
                status,
                last_source_at,
                history_hidden,
                ..
            } => {
                if let Some(view) = self.nodes.get_mut(&node) {
                    view.delivery = delivery;
                    view.status = status;
                    view.last_source_at = last_source_at;
                    view.history_hidden = history_hidden;
                    if history_hidden {
                        view.endpoints.clear();
                        view.exchanges.clear();
                        view.source_gaps.clear();
                    }
                }
            }
            Delta::EndpointUpserted {
                node,
                descriptor,
                activity,
                activity_stale,
            } => {
                if let Some(view) = self.nodes.get_mut(&node) {
                    view.endpoints
                        .retain(|endpoint| endpoint.descriptor.id != descriptor.id);
                    if view.endpoints.len() < 200 {
                        view.endpoints.push(codec::Endpoint {
                            descriptor,
                            activity,
                            activity_stale,
                        });
                    }
                }
            }
            Delta::EndpointRemoved { node, id } => {
                if let Some(view) = self.nodes.get_mut(&node) {
                    view.endpoints.retain(|entry| entry.descriptor.id != id);
                }
            }
            Delta::ActivityChanged { node, event } => {
                if let Some(view) = self.nodes.get_mut(&node) {
                    if let Some(entry) = view
                        .endpoints
                        .iter_mut()
                        .find(|entry| Some(entry.descriptor.id.as_str()) == event.from.as_deref())
                    {
                        entry.activity = event.activity;
                        entry.activity_stale = Some(false);
                    }
                }
            }
            Delta::SourceGap { node, .. } => {
                if self.source_gaps.len() == 64 {
                    self.source_gaps.pop_front();
                }
                self.source_gaps.push_back(node);
            }
            _ => {}
        }
    }

    fn render(&self, out: &mut impl Write) -> io::Result<()> {
        let now = Instant::now();
        let age = self.last_event.map_or_else(
            || "unknown".into(),
            |then| format!("{}s", now.duration_since(then).as_secs()),
        );
        writeln!(out, "{:?}  last event {age}", self.state(now))?;
        let estimated = self.server_clock.map(|(then, server)| {
            server.saturating_add(now.duration_since(then).as_millis() as u64)
        });
        for node in self.nodes.values() {
            let source = estimated.zip(node.last_source_at).map_or_else(
                || "unknown".into(),
                |(now, at)| format!("{}s", now.saturating_sub(at) / 1000),
            );
            let id: String = node.node.chars().filter(|ch| !ch.is_control()).collect();
            writeln!(
                out,
                "{id}  {:?}  {:?}  source {source}  {} endpoints",
                node.status,
                node.delivery,
                node.endpoints.len()
            )?;
        }
        out.flush()
    }
}

fn terminal_handshake_error(error: &WebSocketError) -> bool {
    matches!(error, WebSocketError::Http(response) if response.status().is_redirection()
        || matches!(response.status(), http::StatusCode::UNAUTHORIZED | http::StatusCode::FORBIDDEN))
}

enum End {
    Normal,
    Resume,
    Immediate,
    Incompatible,
}

async fn connect(origin: &Url, handle: &str, view: &mut View) -> Result<End, Error> {
    let mut url = origin
        .join("/v1/mission-control/session")
        .map_err(|_| Error::Config)?;
    url.set_scheme(if origin.scheme() == "https" {
        "wss"
    } else {
        "ws"
    })
    .map_err(|_| Error::Config)?;
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|_| Error::Config)?;
    request.headers_mut().insert(
        http::header::SEC_WEBSOCKET_PROTOCOL,
        http::HeaderValue::from_static(SUBPROTOCOL),
    );
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {handle}")).map_err(|_| Error::Config)?,
    );
    if view.first_dial.is_none() {
        view.first_dial = Some(Instant::now());
    }
    let connection = time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(request),
    )
    .await;
    let mut socket = match connection {
        Ok(Ok((socket, _))) => socket,
        Ok(Err(error)) if terminal_handshake_error(&error) => return Err(Error::Reauthenticate),
        _ => return Ok(End::Resume),
    };
    view.open = true;
    view.reconnecting = false;
    let hello = json!({"v":1,"type":"hello","id":1,"protocol":1,"capabilities":["observe","activity"],"require":["observe"]});
    if socket
        .send(Frame::Text(hello.to_string().into()))
        .await
        .is_err()
    {
        return Ok(End::Resume);
    }
    let mut greeted = false;
    loop {
        let frame = match time::timeout(Duration::from_secs(45), socket.next()).await {
            Ok(Some(Ok(frame))) => frame,
            _ => return Ok(End::Resume),
        };
        let text = match frame {
            Frame::Text(text) => text,
            Frame::Pong(_) | Frame::Ping(_) => continue,
            Frame::Close(close) => {
                return Ok(match close.map(|close| u16::from(close.code)) {
                    Some(1000) => End::Normal,
                    Some(4401 | 4403) => End::Immediate,
                    Some(4409) => End::Incompatible,
                    _ => End::Resume,
                });
            }
            _ => return Ok(End::Incompatible),
        };
        let message = codec::decode(text.as_bytes(), MAX_WIRE).map_err(|_| Error::Incompatible)?;
        if !greeted {
            if !matches!(message, Message::Hello { .. }) {
                return Ok(End::Incompatible);
            }
            greeted = true;
            let mut request =
                json!({"v":1,"type":"subscribe","id":2,"sub":"fleet","scope":{"kind":"fleet"}});
            if let Some(cursor) = &view.cursor {
                request["cursor"] = json!(cursor);
            }
            if socket
                .send(Frame::Text(request.to_string().into()))
                .await
                .is_err()
            {
                return Ok(End::Resume);
            }
        }
        view.apply(message, Instant::now())
            .map_err(|_| Error::Incompatible)?;
        view.render(&mut io::stdout().lock())
            .map_err(|_| Error::Output)?;
    }
}

fn should_reset_backoff(open_elapsed: Duration, synced: bool) -> bool {
    open_elapsed >= Duration::from_secs(60) && synced
}

fn jitter(attempt: u8) -> Duration {
    let cap = 1000u64.saturating_mul(1 << attempt.min(5)).min(30_000);
    let mut sample = [0; 8];
    let millis = if getrandom::fill(&mut sample).is_ok() {
        u64::from_ne_bytes(sample) % (cap + 1)
    } else {
        cap
    };
    Duration::from_millis(millis)
}

pub async fn run(args: Args) -> Result<(), Error> {
    if !origin_allowed(&args.origin) || args.client_id.is_empty() || args.client_id.len() > 128 {
        return Err(Error::Config);
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let handle = device_grant(&args).await?;
    let mut view = View::default();
    let mut attempts = 0;
    let mut immediate = true;
    loop {
        let started = Instant::now();
        let outcome = tokio::select! {
            result = connect(&args.origin, &handle, &mut view) => result,
            _ = tokio::signal::ctrl_c() => return Ok(()),
        };
        let result = match outcome {
            Err(Error::Reauthenticate) => {
                view.open = false;
                view.reconnecting = false;
                view.latched_stop = Some(LatchedStop::Reauthenticate);
                view.clear_for_reauth();
                view.render(&mut io::stdout().lock())
                    .map_err(|_| Error::Output)?;
                return Err(Error::Reauthenticate);
            }
            Err(Error::Incompatible) => {
                view.open = false;
                view.reconnecting = false;
                view.latched_stop = Some(LatchedStop::Incompatible);
                view.render(&mut io::stdout().lock())
                    .map_err(|_| Error::Output)?;
                return Err(Error::Incompatible);
            }
            other => other?,
        };
        view.open = false;
        view.parts.clear();
        view.next_part = 0;
        if should_reset_backoff(started.elapsed(), view.synced) {
            attempts = 0;
            immediate = true;
        }
        match result {
            End::Normal => {
                view.reconnecting = false;
                view.render(&mut io::stdout().lock())
                    .map_err(|_| Error::Output)?;
                return Ok(());
            }
            End::Incompatible => {
                view.reconnecting = false;
                view.latched_stop = Some(LatchedStop::Incompatible);
                view.render(&mut io::stdout().lock())
                    .map_err(|_| Error::Output)?;
                return Err(Error::Incompatible);
            }
            End::Immediate if immediate => {
                immediate = false;
                view.reconnecting = true;
                view.render(&mut io::stdout().lock())
                    .map_err(|_| Error::Output)?;
                continue;
            }
            End::Immediate => {
                view.reconnecting = false;
                view.latched_stop = Some(LatchedStop::Reauthenticate);
                view.clear_for_reauth();
                view.render(&mut io::stdout().lock())
                    .map_err(|_| Error::Output)?;
                return Err(Error::Reauthenticate);
            }
            End::Resume => {}
        }
        if attempts >= 8 {
            view.reconnecting = false;
            view.latched_stop = Some(LatchedStop::ReconnectMaxAttempts);
            view.render(&mut io::stdout().lock())
                .map_err(|_| Error::Output)?;
            return Ok(());
        }
        view.reconnecting = true;
        view.render(&mut io::stdout().lock())
            .map_err(|_| Error::Output)?;
        time::sleep(jitter(attempts)).await;
        attempts += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_is_not_an_event_and_proxy_refusal_is_terminal() {
        let now = Instant::now();
        let live_node = codec::Node {
            node: "live-current".into(),
            status: codec::Status::Healthy,
            delivery: Delivery::Live,
            last_success_at: Some(1000),
            last_source_at: Some(1000),
            via_hub: None,
            history_hidden: false,
            last_activity_at: None,
            activity_authority: None,
            endpoints: Vec::new(),
            endpoints_truncated: false,
            exchanges: Vec::new(),
            source_gaps: Vec::new(),
        };
        let mut nodes = BTreeMap::new();
        nodes.insert(live_node.node.clone(), live_node);
        let mut view = View {
            open: true,
            synced: true,
            last_message: Some(now),
            last_event: Some(now),
            nodes,
            ..View::default()
        };
        view.apply(
            Message::Tick {
                v: 1,
                server_at: 1000,
            },
            now + Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(view.last_event, Some(now));
        assert_eq!(view.state(now + Duration::from_secs(10)), Connection::Live);
        view.open = false;
        view.reconnecting = true;
        assert_eq!(
            view.state(now + Duration::from_secs(11)),
            Connection::Reconnecting
        );
        assert_eq!(view.state(now + Duration::from_secs(56)), Connection::Stale);
        let mut view = View {
            open: true,
            ..View::default()
        };
        assert_eq!(view.state(now), Connection::Unknown);
        let snapshot = codec::decode(
            include_bytes!("../tests/vectors/mission-control/v1/V-P1.json"),
            262_144,
        )
        .unwrap();
        view.apply(snapshot, now).unwrap();
        assert_eq!(view.state(now), Connection::Delayed);
        view.apply(
            Message::Gap {
                v: 1,
                sub: None,
                reason: codec::GapReason::CursorExpired,
                unknown_loss: true,
                reset: true,
            },
            now,
        )
        .unwrap();
        assert_eq!(view.state(now), Connection::Unknown);
        for status in [302, 401, 403] {
            let response = http::Response::builder().status(status).body(None).unwrap();
            assert!(terminal_handshake_error(&WebSocketError::Http(Box::new(
                response
            ))));
        }
    }

    fn test_node(name: &str, status: codec::Status, delivery: Delivery) -> codec::Node {
        codec::Node {
            node: name.into(),
            status,
            delivery,
            last_success_at: None,
            last_source_at: None,
            via_hub: None,
            history_hidden: false,
            last_activity_at: None,
            activity_authority: None,
            endpoints: Vec::new(),
            endpoints_truncated: false,
            exchanges: Vec::new(),
            source_gaps: Vec::new(),
        }
    }

    #[test]
    fn sp13_eligible_current_connection_states() {
        let now = Instant::now();
        let synced_view = |nodes: Vec<codec::Node>| View {
            open: true,
            synced: true,
            last_message: Some(now),
            last_event: Some(now),
            nodes: nodes.into_iter().map(|n| (n.node.clone(), n)).collect(),
            ..View::default()
        };

        // Empty fleet -> Unknown (never Live).
        assert_eq!(synced_view(vec![]).state(now), Connection::Unknown);

        // Removed delayed node + live current node -> Live.
        assert_eq!(
            synced_view(vec![
                test_node("removed", codec::Status::RemovedRetained, Delivery::Delayed),
                test_node("current", codec::Status::Healthy, Delivery::Live),
            ])
            .state(now),
            Connection::Live,
        );

        // Removed delayed node alone -> Unknown (never forces Delayed).
        assert_eq!(
            synced_view(vec![test_node(
                "removed",
                codec::Status::RemovedRetained,
                Delivery::Delayed,
            )])
            .state(now),
            Connection::Unknown,
        );

        // All-loading fleet -> Unknown when live, Delayed when delayed (never Live).
        assert_eq!(
            synced_view(vec![test_node(
                "loading",
                codec::Status::Loading,
                Delivery::Live,
            )])
            .state(now),
            Connection::Unknown,
        );
        assert_eq!(
            synced_view(vec![test_node(
                "loading",
                codec::Status::Loading,
                Delivery::Delayed,
            )])
            .state(now),
            Connection::Delayed,
        );

        // One delayed eligible current node -> Delayed.
        assert_eq!(
            synced_view(vec![
                test_node("live", codec::Status::Healthy, Delivery::Live),
                test_node("delayed", codec::Status::Healthy, Delivery::Delayed),
            ])
            .state(now),
            Connection::Delayed,
        );

        // Non-delivering delayed node + live eligible current node -> Live.
        for status in [
            codec::Status::Loading,
            codec::Status::Denied,
            codec::Status::UnsupportedOutboundOnly,
            codec::Status::UnsupportedTransport,
        ] {
            assert_eq!(
                synced_view(vec![
                    test_node("non-delivering", status, Delivery::Delayed),
                    test_node("current", codec::Status::Healthy, Delivery::Live),
                ])
                .state(now),
                Connection::Live,
            );
        }

        // Empty fleet, then 1006 (closed while synced, within stale_after) -> Reconnecting.
        let mut closed_empty = synced_view(vec![]);
        closed_empty.open = false;
        closed_empty.reconnecting = true;
        assert_eq!(closed_empty.state(now), Connection::Reconnecting);
    }

    #[test]
    fn sp13_connection_state_precedence_truth_table() {
        let t0 = Instant::now();
        let make_synced = |nodes: Vec<codec::Node>| View {
            open: true,
            reconnecting: false,
            synced: true,
            first_dial: Some(t0),
            last_message: Some(t0),
            last_event: Some(t0),
            nodes: nodes.into_iter().map(|n| (n.node.clone(), n)).collect(),
            ..View::default()
        };

        // Row 1: Latched 4409 -> Unknown (beats silence >= stale_after_ms and Live fleet).
        let mut row1 = make_synced(vec![test_node("a", codec::Status::Healthy, Delivery::Live)]);
        row1.latched_stop = Some(LatchedStop::Incompatible);
        assert_eq!(row1.state(t0), Connection::Unknown);
        assert_eq!(
            row1.state(t0 + Duration::from_secs(60)),
            Connection::Unknown
        );

        // Row 2: Latched re-authenticate -> Unknown (beats silence >= stale_after_ms).
        let mut row2 = make_synced(vec![test_node("a", codec::Status::Healthy, Delivery::Live)]);
        row2.latched_stop = Some(LatchedStop::Reauthenticate);
        assert_eq!(row2.state(t0), Connection::Unknown);
        assert_eq!(
            row2.state(t0 + Duration::from_secs(60)),
            Connection::Unknown
        );

        // Row 3: Latched reconnect_max_attempts -> Stale (even at t0).
        let mut row3 = View {
            first_dial: Some(t0),
            latched_stop: Some(LatchedStop::ReconnectMaxAttempts),
            ..View::default()
        };
        assert_eq!(row3.state(t0), Connection::Stale);
        row3.open = false;
        row3.reconnecting = false;
        assert_eq!(row3.state(t0 + Duration::from_secs(1)), Connection::Stale);

        // Row 4: silence >= stale_after_ms -> Stale across all transport states (initial dial, reconnecting, open+!synced, open+synced).
        let initial_dial = View {
            first_dial: Some(t0),
            ..View::default()
        };
        assert_eq!(
            initial_dial.state(t0 + Duration::from_millis(44_999)),
            Connection::Unknown
        );
        assert_eq!(
            initial_dial.state(t0 + Duration::from_millis(45_000)),
            Connection::Stale
        );

        let reconnecting_view = View {
            first_dial: Some(t0),
            reconnecting: true,
            ..View::default()
        };
        assert_eq!(
            reconnecting_view.state(t0 + Duration::from_millis(44_999)),
            Connection::Reconnecting
        );
        assert_eq!(
            reconnecting_view.state(t0 + Duration::from_millis(45_000)),
            Connection::Stale
        );

        let open_unsynced = View {
            open: true,
            first_dial: Some(t0),
            ..View::default()
        };
        assert_eq!(
            open_unsynced.state(t0 + Duration::from_millis(44_999)),
            Connection::Unknown
        );
        assert_eq!(
            open_unsynced.state(t0 + Duration::from_millis(45_000)),
            Connection::Stale
        );

        // Row 5: Not open & reconnecting, silence < stale_after_ms -> Reconnecting.
        let mut reconnecting_after_msg =
            make_synced(vec![test_node("a", codec::Status::Healthy, Delivery::Live)]);
        reconnecting_after_msg.open = false;
        reconnecting_after_msg.reconnecting = true;
        assert_eq!(
            reconnecting_after_msg.state(t0 + Duration::from_secs(10)),
            Connection::Reconnecting
        );

        // Row 6: Initial dial / 1000 idle close, silence < stale_after_ms -> Unknown.
        let mut idle_closed =
            make_synced(vec![test_node("a", codec::Status::Healthy, Delivery::Live)]);
        idle_closed.open = false;
        idle_closed.reconnecting = false;
        assert_eq!(
            idle_closed.state(t0 + Duration::from_secs(1)),
            Connection::Unknown
        );

        // Row 7: Open & !synced (even with retained nodes, or after gap{reset}), silence < stale_after_ms -> Unknown.
        let mut open_unsynced_retained =
            make_synced(vec![test_node("a", codec::Status::Healthy, Delivery::Live)]);
        open_unsynced_retained.synced = false;
        assert_eq!(open_unsynced_retained.state(t0), Connection::Unknown);

        let mut gapped = make_synced(vec![test_node("a", codec::Status::Healthy, Delivery::Live)]);
        gapped
            .apply(
                Message::Gap {
                    v: 1,
                    sub: None,
                    reason: codec::GapReason::CursorExpired,
                    unknown_loss: true,
                    reset: true,
                },
                t0 + Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(
            gapped.state(t0 + Duration::from_secs(5)),
            Connection::Unknown
        );
        assert_eq!(gapped.last_message, Some(t0 + Duration::from_secs(5)));

        // Row 8: Open & synced & 2*tick < silence < stale_after -> Unknown (preserves last_event).
        let row8 = make_synced(vec![test_node("a", codec::Status::Healthy, Delivery::Live)]);
        assert_eq!(
            row8.state(t0 + Duration::from_millis(30_000)),
            Connection::Live
        );
        assert_eq!(
            row8.state(t0 + Duration::from_millis(30_001)),
            Connection::Unknown
        );
        assert_eq!(row8.last_event, Some(t0));

        // Rows 9-12: Open & synced & silence <= 2*tick.
        // Row 9: E >= 1 && !De -> Live
        assert_eq!(
            make_synced(vec![test_node("a", codec::Status::Healthy, Delivery::Live)]).state(t0),
            Connection::Live
        );
        // Row 10: E >= 1 && De -> Delayed
        assert_eq!(
            make_synced(vec![
                test_node("a", codec::Status::Healthy, Delivery::Live),
                test_node("b", codec::Status::Healthy, Delivery::Delayed),
            ])
            .state(t0),
            Connection::Delayed
        );
        // Row 11: E == 0 && Dn -> Delayed
        assert_eq!(
            make_synced(vec![test_node(
                "a",
                codec::Status::Loading,
                Delivery::Delayed
            )])
            .state(t0),
            Connection::Delayed
        );
        // Row 12: E == 0 && !Dn -> Unknown
        assert_eq!(
            make_synced(vec![test_node(
                "a",
                codec::Status::RemovedRetained,
                Delivery::Delayed
            )])
            .state(t0),
            Connection::Unknown
        );

        // Backoff reset requires >= 60s open AND synced (not synced alone).
        assert!(!should_reset_backoff(Duration::from_secs(59), true));
        assert!(!should_reset_backoff(Duration::from_secs(60), false));
        assert!(should_reset_backoff(Duration::from_secs(60), true));
    }
    #[tokio::test]
    async fn proxy_refusal_stops_before_reconnecting() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for status in [302, 401, 403] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
            let proxy = async {
                let (mut conn, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                loop {
                    headers.push(conn.read_u8().await.unwrap());
                    if headers.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(headers.len() < 8192);
                }
                conn.write_all(format!("HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            };
            let mut view = View::default();
            let (result, _) = tokio::join!(connect(&origin, "synthetic-handle", &mut view), proxy);
            assert!(
                matches!(result, Err(Error::Reauthenticate)),
                "proxy status {status} retried"
            );
        }
    }
}
