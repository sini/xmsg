use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub hub_enabled: bool,
    #[serde(default)]
    pub leaf_enabled: bool,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub hub: String,
    pub leaf: String,
    pub collector: String,
}

pub(crate) fn identity_node(value: &str) -> Option<String> {
    if value.len() > 512
        || value.contains('*')
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return None;
    }
    if value.starts_with("spiffe://") {
        crate::fed::validate_spiffe_pattern(value).ok()?;
        crate::node::node_name_from_uri(value).ok()
    } else {
        let pin = value.strip_prefix("sha256:")?;
        if pin.len() != 64
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        crate::node::node_name_from_pin(pin).ok()
    }
}

impl Config {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (index, route) in self.routes.iter().enumerate() {
            if [&route.hub, &route.leaf, &route.collector]
                .iter()
                .any(|v| identity_node(v).is_none())
                || self.routes[..index].contains(route)
                || route.hub == route.leaf
                || route.collector == route.leaf
                || route.collector == route.hub
            {
                return Err("invalid or duplicate reverse observation route".into());
            }
        }
        Ok(())
    }
}

use crate::error::AppError;
use crate::fed::{AuthenticatedPeer, FedInboxItem, FedState, PeerConfig, PeersMap};
use crate::observe_export::{ExportQuery, ExportSnapshot, Scope, SnapshotQuery, MAX_BYTES};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

const MAX_QUERY: usize = 1024;
const MAX_CONTROL: usize = 8192;
const MAX_HEADERS: usize = 1024;
const MAX_WAITERS: usize = 8;
const PER_WAITER_BYTES: usize = 2 * MAX_BYTES;
const AGGREGATE_BYTES: usize = 4 * 1024 * 1024;
// Each retained slot covers the bounded incoming and forwarded DTO buffers.
const _: () = assert!(MAX_WAITERS * PER_WAITER_BYTES <= AGGREGATE_BYTES);
const BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Events,
    Snapshot,
}
impl Kind {
    fn parse(value: &str) -> Result<Self, Failure> {
        match value {
            "events" => Ok(Self::Events),
            "snapshot" => Ok(Self::Snapshot),
            _ => Err(Failure::Invalid),
        }
    }
    fn text(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::Snapshot => "snapshot",
        }
    }
    fn labels(self, query: &str) -> Result<bool, Failure> {
        if query.len() > MAX_QUERY {
            return Err(Failure::Invalid);
        }
        let uri: axum::http::Uri = format!("/observe?{query}")
            .parse()
            .map_err(|_| Failure::Invalid)?;
        match self {
            Self::Events => {
                let axum::extract::Query(q) =
                    axum::extract::Query::<ExportQuery>::try_from_uri(&uri)
                        .map_err(|_| Failure::Invalid)?;
                q.validate().map_err(|_| Failure::Invalid)?;
                Ok(q.labels)
            }
            Self::Snapshot => {
                let axum::extract::Query(q) =
                    axum::extract::Query::<SnapshotQuery>::try_from_uri(&uri)
                        .map_err(|_| Failure::Invalid)?;
                q.validate().map_err(|_| Failure::Invalid)?;
                Ok(q.labels)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: String,
    pub hub: String,
    pub leaf: String,
    pub collector: String,
    pub read: Kind,
    pub query: String,
    pub remaining_ms: u64,
}
impl Control {
    fn validate(&self) -> Result<(), Failure> {
        if !valid_id(&self.id)
            || identity_node(&self.hub).is_none()
            || identity_node(&self.leaf).is_none()
            || identity_node(&self.collector).is_none()
            || self.remaining_ms == 0
            || self.remaining_ms > 5000
            || serde_json::to_vec(self)
                .map_err(|_| Failure::Invalid)?
                .len()
                > MAX_CONTROL
        {
            return Err(Failure::Invalid);
        }
        self.read.labels(&self.query)?;
        Ok(())
    }
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Busy,
    Unsupported,
    Unreachable,
    Denied,
    Invalid,
}
impl Failure {
    fn text(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Unsupported => "unsupported",
            Self::Unreachable => "unreachable",
            Self::Denied => "denied",
            Self::Invalid => "invalid",
        }
    }
    fn parse(s: &str) -> Result<Self, Self> {
        match s {
            "busy" => Ok(Self::Busy),
            "unsupported" => Ok(Self::Unsupported),
            "unreachable" => Ok(Self::Unreachable),
            "denied" => Ok(Self::Denied),
            "invalid" => Ok(Self::Invalid),
            _ => Err(Self::Invalid),
        }
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
            Self::Unsupported => StatusCode::NOT_IMPLEMENTED,
            Self::Unreachable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Denied => StatusCode::FORBIDDEN,
            Self::Invalid => StatusCode::BAD_REQUEST,
        };
        let mut response =
            (status, axum::Json(serde_json::json!({"error":self.text()}))).into_response();
        if self == Self::Busy {
            response
                .headers_mut()
                .insert("retry-after", axum::http::HeaderValue::from_static("2"));
        }
        response
    }
}

fn certificate_identity(cert: &[u8]) -> Result<String, Failure> {
    let uris = crate::fed::extract_uri_sans(cert).map_err(|_| Failure::Denied)?;
    match uris.as_slice() {
        [] => Ok(format!(
            "sha256:{}",
            crate::fed::spki_sha256_from_der(cert).map_err(|_| Failure::Denied)?
        )),
        [uri] if identity_node(uri).is_some() => Ok(uri.clone()),
        _ => Err(Failure::Denied),
    }
}
fn own_identity(fs: &FedState) -> Result<String, Failure> {
    certificate_identity(fs.cert_chain().first().ok_or(Failure::Denied)?.as_ref())
}
fn certificate_matches(cert: &[u8], identity: &str) -> bool {
    if let Some(pin) = identity.strip_prefix("sha256:") {
        crate::fed::spki_sha256_from_der(cert).is_ok_and(|actual| actual == pin)
    } else {
        certificate_identity(cert).is_ok_and(|actual| actual == identity)
    }
}
fn own_matches(fs: &FedState, identity: &str) -> bool {
    fs.cert_chain()
        .first()
        .is_some_and(|cert| certificate_matches(cert.as_ref(), identity))
}
fn unsupported_leaf(fs: &FedState, identity: &str) -> bool {
    identity.starts_with("sha256:")
        && fs.cert_chain().first().is_some_and(|cert| {
            crate::fed::extract_uri_sans(cert.as_ref()).map_or(true, |uris| !uris.is_empty())
        })
}
fn peer_identity(peer: &AuthenticatedPeer) -> String {
    peer.uri
        .clone()
        .unwrap_or_else(|| format!("sha256:{}", crate::fed::normalize_pin(&peer.pin)))
}
fn config_identity(config: &PeerConfig, identity: &str) -> bool {
    match identity.strip_prefix("sha256:") {
        Some(pin) => config
            .pin
            .as_ref()
            .is_some_and(|v| crate::fed::normalize_pin(v) == pin),
        None => config
            .identities
            .as_ref()
            .is_some_and(|ids| ids.as_slice() == [identity]),
    }
}
fn config_for_identity(peers: &PeersMap, identity: &str) -> Option<PeerConfig> {
    let node = identity_node(identity)?;
    let config = peers.get_peer_config(&node)?;
    config_identity(&config, identity).then_some(config)
}
fn grant(config: &PeerConfig, labels: bool) -> Result<(), Failure> {
    if !config.allow.iter().any(|v| v == "observe") || (labels && !config.observe_labels) {
        Err(Failure::Denied)
    } else {
        Ok(())
    }
}
fn leaf_route(peers: &PeersMap, route: &Route) -> Result<(), Failure> {
    let config = &peers.reverse_observe;
    if !config.leaf_enabled || !config.routes.contains(route) {
        Err(Failure::Denied)
    } else {
        Ok(())
    }
}

#[derive(Clone)]
struct Binding {
    control: Control,
    collector: Arc<AuthenticatedPeer>,
    peers: Arc<PeersMap>,
    expected_leaf: String,
    deadline: Instant,
}
struct Waiter {
    binding: Binding,
    dispatched: bool,
    answering: bool,
    tx: oneshot::Sender<Result<Vec<u8>, Failure>>,
    reservations: Option<Arc<OwnedSemaphorePermit>>,
}
impl std::ops::Deref for Waiter {
    type Target = Binding;
    fn deref(&self) -> &Binding {
        &self.binding
    }
}
#[derive(Default)]
struct Queue {
    waiting: HashMap<String, Waiter>,
    pairs: HashSet<(String, String)>,
    turn: HashMap<String, usize>,
}
struct RelayState {
    fed: Arc<FedState>,
    queue: Mutex<Queue>,
    slots: Arc<Semaphore>,
    #[cfg(any(test, feature = "test-hooks"))]
    slot_capacity: usize,
    refusals: Arc<Semaphore>,
    posts: Arc<Semaphore>,
    #[cfg(any(test, feature = "test-hooks"))]
    controls: Arc<test_hooks::Controls>,
}
fn shared(fs: &Arc<FedState>) -> Arc<RelayState> {
    static STATES: OnceLock<Mutex<HashMap<usize, Weak<RelayState>>>> = OnceLock::new();
    let mut states = STATES.get_or_init(Mutex::default).lock().unwrap();
    states.retain(|_, v| v.strong_count() > 0);
    let key = Arc::as_ptr(fs) as usize;
    if let Some(state) = states.get(&key).and_then(Weak::upgrade) {
        return state;
    }
    let slots = Arc::new(Semaphore::new(MAX_WAITERS));
    #[cfg(any(test, feature = "test-hooks"))]
    let slot_capacity = slots.available_permits();
    let state = Arc::new(RelayState {
        fed: fs.clone(),
        queue: Mutex::default(),
        slots,
        #[cfg(any(test, feature = "test-hooks"))]
        slot_capacity,
        refusals: Arc::new(Semaphore::new(MAX_WAITERS)),
        posts: Arc::new(Semaphore::new(1)),
        #[cfg(any(test, feature = "test-hooks"))]
        controls: test_hooks::controls(fs),
    });
    states.insert(key, Arc::downgrade(&state));
    state
}
impl RelayState {
    fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(any(test, feature = "test-hooks"))]
        let now = now
            + Duration::from_millis(
                self.controls
                    .clock_offset_ms
                    .load(std::sync::atomic::Ordering::Relaxed),
            );
        now
    }
    fn authorize(&self, waiter: &Binding) -> Result<PeerConfig, Failure> {
        let peers = self.fed.current_peers();
        if !Arc::ptr_eq(&peers, &waiter.peers) {
            return Err(Failure::Denied);
        }
        let c = &waiter.control;
        if !peers.reverse_observe.hub_enabled {
            return Err(Failure::Denied);
        }
        if !own_matches(&self.fed, &c.hub) || peer_identity(&waiter.collector) != c.collector {
            return Err(Failure::Denied);
        }
        let config = peers
            .get_peer_config(&waiter.collector.name)
            .ok_or(Failure::Denied)?;
        if !config_identity(&config, &c.collector) {
            return Err(Failure::Denied);
        }
        grant(&config, c.read.labels(&c.query)?)?;
        crate::fed::check_peer_source(&config, &waiter.collector.remote_ip)
            .map_err(|_| Failure::Denied)?;
        let leaf = config_for_identity(&peers, &c.leaf).ok_or(Failure::Denied)?;
        if !leaf.leaf || leaf.name != waiter.expected_leaf {
            return Err(Failure::Denied);
        }
        Ok(config)
    }
}

pub(crate) fn router(fs: Arc<FedState>) -> Router {
    Router::new()
        .route("/fed/v2/observe/relay/{leaf}/{kind}", get(relay))
        .route("/fed/v2/observe/relay/answer/{id}", post(answer))
        .with_state(shared(&fs))
}
struct Forget {
    state: Arc<RelayState>,
    id: String,
    pair: (String, String),
}
impl Drop for Forget {
    fn drop(&mut self) {
        let mut queue = self.state.queue.lock().unwrap();
        queue.waiting.remove(&self.id);
        queue.pairs.remove(&self.pair);
    }
}

async fn relay(
    State(state): State<Arc<RelayState>>,
    Path((leaf, kind)): Path<(String, String)>,
    request: Request,
) -> Response {
    match relay_inner(state, leaf, kind, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}
async fn relay_inner(
    state: Arc<RelayState>,
    leaf: String,
    kind: String,
    request: Request,
) -> Result<Response, Failure> {
    let deadline = state.now() + BUDGET;
    let kind = Kind::parse(&kind)?;
    let query = request.uri().query().unwrap_or_default().to_owned();
    kind.labels(&query)?;
    no_body(&request)?;
    let collector = request
        .extensions()
        .get::<Arc<AuthenticatedPeer>>()
        .cloned()
        .ok_or(Failure::Denied)?;
    let tls = request
        .extensions()
        .get::<crate::observe_fed::TlsAdmission>()
        .ok_or(Failure::Denied)?;
    let peers = state.fed.current_peers();
    if !Arc::ptr_eq(&peers, &tls.peers) || tls.config.name != collector.name {
        return Err(Failure::Denied);
    }
    let collector_identity = peer_identity(&collector);
    let route = peers
        .reverse_observe
        .routes
        .iter()
        .find(|r| {
            own_matches(&state.fed, &r.hub)
                && r.collector == collector_identity
                && identity_node(&r.leaf).as_deref() == Some(&leaf)
        })
        .ok_or(Failure::Denied)?
        .clone();
    let leaf_config = config_for_identity(&peers, &route.leaf).ok_or(Failure::Denied)?;
    let control = Control {
        id: ulid::Ulid::new().to_string(),
        hub: route.hub,
        leaf: route.leaf,
        collector: collector_identity,
        read: kind,
        query,
        remaining_ms: 5000,
    };
    control.validate()?;
    let (tx, rx) = oneshot::channel();
    let binding = Binding {
        control: control.clone(),
        collector,
        peers,
        expected_leaf: leaf_config.name.clone(),
        deadline,
    };
    let waiter = Waiter {
        binding: binding.clone(),
        dispatched: false,
        answering: false,
        tx,
        reservations: None,
    };
    state.authorize(&waiter)?;
    if !state
        .fed
        .rate_limiter
        .check_and_consume(&format!("observe:{}", waiter.collector.name), None)
    {
        return Err(Failure::Busy);
    }
    #[cfg(any(test, feature = "test-hooks"))]
    state.controls.before_admission.pause().await;
    let slot = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Failure::Busy)?;
    let reservations = Arc::new(slot);
    let mut waiter = waiter;
    waiter.reservations = Some(reservations.clone());
    {
        let mut queue = state.queue.lock().unwrap();
        if queue
            .pairs
            .contains(&(control.leaf.clone(), control.collector.clone()))
        {
            return Err(Failure::Busy);
        }
        state.authorize(&waiter)?;
        queue
            .pairs
            .insert((control.leaf.clone(), control.collector.clone()));
        queue.waiting.insert(control.id.clone(), waiter);
    }
    let forget = Forget {
        state: state.clone(),
        id: control.id.clone(),
        pair: (control.leaf.clone(), control.collector.clone()),
    };
    let _ = state.fed.notify_tx.send(leaf_config.name);
    let body = tokio::time::timeout_at(deadline, rx)
        .await
        .map_err(|_| Failure::Unreachable)?
        .map_err(|_| Failure::Unreachable)??;
    #[cfg(any(test, feature = "test-hooks"))]
    state.controls.before_forward.pause().await;
    {
        if state.now() >= deadline {
            return Err(Failure::Unreachable);
        }
        let config = state.authorize(&binding)?;
        validate_dto(&body, &control, &config)?;
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::new(HeldBody {
            bytes: Some(body.into()),
            _reservations: reservations,
            _forget: forget,
        }))
        .map_err(|_| Failure::Invalid)
}
struct HeldBody {
    bytes: Option<bytes::Bytes>,
    _reservations: Arc<OwnedSemaphorePermit>,
    _forget: Forget,
}
impl hyper::body::Body for HeldBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(self.bytes.take().map(|b| Ok(hyper::body::Frame::data(b))))
    }
    fn is_end_stream(&self) -> bool {
        self.bytes.is_none()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.bytes.as_ref().map_or(0, |b| b.len()) as u64)
    }
}
fn no_body(request: &Request) -> Result<(), Failure> {
    if request.headers().contains_key("transfer-encoding")
        || request
            .headers()
            .get("content-length")
            .is_some_and(|v| v.to_str().ok() != Some("0"))
    {
        Err(Failure::Invalid)
    } else {
        Ok(())
    }
}

pub(crate) fn control_turn(fs: &Arc<FedState>, peer: &str) -> usize {
    let state = shared(fs);
    let mut queue = state.queue.lock().unwrap();
    let turn = queue.turn.entry(peer.into()).or_default();
    let next = *turn;
    *turn = (*turn + 1) % 3;
    next
}
pub(crate) async fn before_dispatch(fs: &Arc<FedState>) {
    #[cfg(any(test, feature = "test-hooks"))]
    shared(fs).controls.before_dispatch.pause().await;
    #[cfg(not(any(test, feature = "test-hooks")))]
    let _ = fs;
}
pub(crate) fn next_for(
    fs: &Arc<FedState>,
    peer: &AuthenticatedPeer,
    current_poll: bool,
) -> Option<FedInboxItem> {
    let state = shared(fs);
    let mut queue = state.queue.lock().unwrap();
    let mut ids = queue.waiting.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    for id in ids {
        let w = queue.waiting.get_mut(&id)?;
        if w.expected_leaf != peer.name || w.dispatched {
            continue;
        }
        let valid = state.authorize(w).map(|_| ()).and_then(|()| {
            if state.now() < w.deadline {
                Ok(())
            } else {
                Err(Failure::Unreachable)
            }
        });
        if let Err(error) = valid {
            let w = queue.waiting.remove(&id)?;
            let _ = w.tx.send(Err(error));
            continue;
        }
        if !current_poll || w.control.leaf != peer_identity(peer) {
            continue;
        }
        if w.control.leaf.starts_with("sha256:") && peer.certificate_has_uri {
            let w = queue.waiting.remove(&id)?;
            let _ = w.tx.send(Err(Failure::Unsupported));
            continue;
        }
        w.dispatched = true;
        let mut control = w.control.clone();
        control.remaining_ms = (w.deadline - state.now()).as_millis().min(5000) as u64;
        return Some(FedInboxItem::Observe { request: control });
    }
    None
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Failure> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(Failure::Invalid)
}
async fn answer(
    State(state): State<Arc<RelayState>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    match answer_inner(state, id, request).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => error.into_response(),
    }
}
async fn answer_inner(state: Arc<RelayState>, id: String, request: Request) -> Result<(), Failure> {
    if !valid_id(&id) || request.uri().query().is_some() {
        return Err(Failure::Invalid);
    }
    let peer = request
        .extensions()
        .get::<Arc<AuthenticatedPeer>>()
        .cloned()
        .ok_or(Failure::Denied)?;
    let tls = request
        .extensions()
        .get::<crate::observe_fed::TlsAdmission>()
        .ok_or(Failure::Denied)?;
    if !Arc::ptr_eq(&tls.peers, &state.fed.current_peers()) || tls.config.name != peer.name {
        return Err(Failure::Denied);
    }
    if request
        .headers()
        .iter()
        .map(|(n, v)| n.as_str().len() + v.len())
        .sum::<usize>()
        > MAX_HEADERS
    {
        return Err(Failure::Invalid);
    }
    let kind = Kind::parse(header(request.headers(), "xmsg-observe-kind")?)?;
    let status = header(request.headers(), "xmsg-observe-status")?;
    let status = if status == "ok" {
        Ok(())
    } else {
        Err(Failure::parse(status)?)
    };
    let invalid_length = request.headers().get("content-length").is_some_and(|v| {
        v.to_str()
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .is_none_or(|n| n > MAX_BYTES)
    });
    let (deadline, _reservations) = {
        let mut queue = state.queue.lock().unwrap();
        let w = queue.waiting.get_mut(&id).ok_or(Failure::Invalid)?;
        if !w.dispatched
            || w.answering
            || w.expected_leaf != peer.name
            || w.control.leaf != peer_identity(&peer)
            || w.control.read != kind
            || state.now() >= w.deadline
        {
            return Err(Failure::Invalid);
        }
        state.authorize(w)?;
        w.answering = true;
        (w.deadline, w.reservations.clone())
    };
    let body = if invalid_length {
        Err(Failure::Invalid)
    } else {
        tokio::time::timeout_at(deadline, read_answer_body(request.into_body(), &state))
            .await
            .map_err(|_| Failure::Unreachable)
            .and_then(|result| result)
    };
    let mut queue = state.queue.lock().unwrap();
    let w = queue.waiting.remove(&id).ok_or(Failure::Invalid)?;
    let result = (|| {
        if state.now() >= w.deadline {
            return Err(Failure::Invalid);
        }
        let body = body?;
        let config = state.authorize(&w)?;
        match status {
            Ok(()) => {
                validate_dto(&body, &w.control, &config)?;
                Ok(body)
            }
            Err(e) => {
                if !body.is_empty() {
                    return Err(Failure::Invalid);
                }
                Err(e)
            }
        }
    })();
    let accepted = match &result {
        Ok(_) => Ok(()),
        Err(e) => Err(*e),
    };
    let _ = w.tx.send(result);
    accepted
}
async fn read_answer_body(
    mut body: axum::body::Body,
    state: &RelayState,
) -> Result<Vec<u8>, Failure> {
    use http_body_util::BodyExt;
    #[cfg(not(any(test, feature = "test-hooks")))]
    let _ = state;
    #[cfg(any(test, feature = "test-hooks"))]
    state
        .controls
        .answer_read_attempts
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut bytes = Vec::with_capacity(MAX_BYTES);
    while let Some(frame) = body.frame().await {
        let chunk = frame
            .map_err(|_| Failure::Invalid)?
            .into_data()
            .map_err(|_| Failure::Invalid)?;
        if chunk.len() > MAX_BYTES - bytes.len() {
            return Err(Failure::Invalid);
        }
        bytes.extend_from_slice(&chunk);
        #[cfg(any(test, feature = "test-hooks"))]
        state
            .controls
            .max_buffered_answer
            .fetch_max(bytes.len(), std::sync::atomic::Ordering::Relaxed);
        #[cfg(any(test, feature = "test-hooks"))]
        state.controls.after_answer_chunk.pause().await;
    }
    Ok(bytes)
}
fn validate_dto(body: &[u8], control: &Control, config: &PeerConfig) -> Result<(), Failure> {
    if body.len() > MAX_BYTES {
        return Err(Failure::Invalid);
    }
    let node = identity_node(&control.leaf).ok_or(Failure::Invalid)?;
    let scope = Scope::new(
        &node,
        &control.collector,
        config.targets.as_deref(),
        config.observe_labels,
    )
    .map_err(|_| Failure::Invalid)?;
    match control.read {
        Kind::Events => {
            let page = crate::observe_collector_decode::decode_page(body)
                .map_err(|_| Failure::Invalid)?
                .page;
            if page.node != node || page.v != 1 {
                return Err(Failure::Invalid);
            }
            if page.events.iter().any(|e| {
                e.from.as_deref().is_some_and(|id| !scope.allows(id))
                    || e.to.as_deref().is_some_and(|id| !scope.allows(id))
            }) {
                return Err(Failure::Denied);
            }
        }
        Kind::Snapshot => {
            let page: ExportSnapshot =
                serde_json::from_slice(body).map_err(|_| Failure::Invalid)?;
            if page.node != node || page.v != 1 || page.endpoints.len() > 200 {
                return Err(Failure::Invalid);
            }
            if page.endpoints.iter().any(|e| {
                !scope.allows(&e.id)
                    || e.label.is_some() && !control.read.labels(&control.query).unwrap_or(false)
            }) {
                return Err(Failure::Denied);
            }
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "test-hooks"))]
pub mod test_hooks {
    use super::*;
    #[derive(Default)]
    pub struct Controls {
        pub before_admission: crate::observe_fed::test_hooks::Gate,
        pub before_dispatch: crate::observe_fed::test_hooks::Gate,
        pub before_forward: crate::observe_fed::test_hooks::Gate,
        pub before_post: crate::observe_fed::test_hooks::Gate,
        pub before_send: crate::observe_fed::test_hooks::Gate,
        pub after_answer_chunk: crate::observe_fed::test_hooks::Gate,
        pub clock_offset_ms: std::sync::atomic::AtomicU64,
        pub max_buffered_answer: std::sync::atomic::AtomicUsize,
        pub max_buffered_control: std::sync::atomic::AtomicUsize,
        pub answer_read_attempts: std::sync::atomic::AtomicUsize,
        pub control_read_attempts: std::sync::atomic::AtomicUsize,
        pub post_waiters: std::sync::atomic::AtomicUsize,
        pub post_entries: std::sync::atomic::AtomicUsize,
        pub post_active: std::sync::atomic::AtomicUsize,
        pub post_peak: std::sync::atomic::AtomicUsize,
        pub refusal_active: std::sync::atomic::AtomicUsize,
        pub refusal_peak: std::sync::atomic::AtomicUsize,
        pub refusal_spawned: std::sync::atomic::AtomicUsize,
        pub controls_received: std::sync::atomic::AtomicUsize,
        pub received_control: Mutex<Option<Control>>,
        pub listeners: std::sync::atomic::AtomicUsize,
        pub control_polls: std::sync::atomic::AtomicUsize,
        pub custody_polls: std::sync::atomic::AtomicUsize,
        pub acks: std::sync::atomic::AtomicUsize,
        pub delivery_posts: std::sync::atomic::AtomicUsize,
    }
    type Registry = HashMap<usize, (Weak<FedState>, Weak<Controls>)>;
    static CONTROLS: OnceLock<Mutex<Registry>> = OnceLock::new();
    pub fn controls_for_borrowed(fs: &FedState) -> Option<Arc<Controls>> {
        CONTROLS
            .get_or_init(Mutex::default)
            .lock()
            .unwrap()
            .get(&(fs as *const FedState as usize))
            .and_then(|(_, c)| c.upgrade())
    }
    pub fn controls(fs: &Arc<FedState>) -> Arc<Controls> {
        let mut all = CONTROLS.get_or_init(Mutex::default).lock().unwrap();
        all.retain(|_, (f, c)| f.strong_count() > 0 && c.strong_count() > 0);
        let key = Arc::as_ptr(fs) as usize;
        if let Some(c) = all.get(&key).and_then(|(_, c)| c.upgrade()) {
            return c;
        }
        let c = Arc::new(Controls::default());
        all.insert(key, (Arc::downgrade(fs), Arc::downgrade(&c)));
        c
    }
    pub struct Worker {
        _worker: crate::fed::ControlWorker,
    }
    impl Worker {
        pub async fn stop(self) {
            self._worker.stop_for_test().await;
        }
    }
    pub fn start_worker(fs: Arc<FedState>, peer: String) -> Worker {
        Worker {
            _worker: crate::fed::spawn_control_worker(fs, peer),
        }
    }
    pub fn occupy_reads(fs: &Arc<FedState>, count: usize) -> Vec<OwnedSemaphorePermit> {
        let slots = crate::observe_fed::read_slots(fs);
        (0..count)
            .map(|_| slots.clone().try_acquire_owned().unwrap())
            .collect()
    }
    pub(crate) enum TaskCounter {
        PostWaiting,
        PostActive,
        Refusal,
    }
    pub(crate) struct TaskCount(Arc<Controls>, TaskCounter);
    impl TaskCount {
        pub(crate) fn new(controls: Arc<Controls>, kind: TaskCounter) -> Self {
            use std::sync::atomic::Ordering::Relaxed;
            match kind {
                TaskCounter::PostWaiting => {
                    controls.post_waiters.fetch_add(1, Relaxed);
                    controls.post_entries.fetch_add(1, Relaxed);
                }
                TaskCounter::PostActive => {
                    let n = controls.post_active.fetch_add(1, Relaxed) + 1;
                    controls.post_peak.fetch_max(n, Relaxed);
                }
                TaskCounter::Refusal => {
                    let n = controls.refusal_active.fetch_add(1, Relaxed) + 1;
                    controls.refusal_peak.fetch_max(n, Relaxed);
                    controls.refusal_spawned.fetch_add(1, Relaxed);
                }
            }
            Self(controls, kind)
        }
    }
    impl Drop for TaskCount {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering::Relaxed;
            match self.1 {
                TaskCounter::PostWaiting => {
                    self.0.post_waiters.fetch_sub(1, Relaxed);
                }
                TaskCounter::PostActive => {
                    self.0.post_active.fetch_sub(1, Relaxed);
                }
                TaskCounter::Refusal => {
                    self.0.refusal_active.fetch_sub(1, Relaxed);
                }
            }
        }
    }
    pub async fn poll(
        fs: &Arc<FedState>,
        peer: &str,
        advertise: bool,
    ) -> Result<Option<FedInboxItem>, AppError> {
        crate::fed::get_federated_inbox_witnessed(
            fs,
            &fs.current_peers(),
            peer,
            0,
            Some(true),
            advertise,
        )
        .await
        .map(|(item, _)| item)
    }
    pub fn record_request(fs: &Arc<FedState>, method: &str, route: &str, query: Option<&str>) {
        use std::sync::atomic::Ordering::Relaxed;
        let c = controls(fs);
        if method == "GET" && route == "/fed/v2/inbox" {
            if query.is_some_and(|q| q.split('&').any(|p| p == "control=true")) {
                c.control_polls.fetch_add(1, Relaxed);
            } else {
                c.custody_polls.fetch_add(1, Relaxed);
            }
        }
        if method == "POST" && route.starts_with("/fed/v2/inbox/") && route.ends_with("/ack") {
            c.acks.fetch_add(1, Relaxed);
        }
        if method == "POST" && matches!(route, "/fed/v2/messages" | "/fed/v2/replies") {
            c.delivery_posts.fetch_add(1, Relaxed);
        }
    }
    pub fn pending(fs: &Arc<FedState>) -> usize {
        shared(fs).queue.lock().unwrap().waiting.len()
    }
    pub fn reservations(fs: &Arc<FedState>) -> (usize, usize) {
        let state = shared(fs);
        let held = state.slot_capacity - state.slots.available_permits();
        (held, held * PER_WAITER_BYTES)
    }
    fn control_admission(
        fs: &Arc<FedState>,
        hub: &str,
        cert: &[u8],
        ip: std::net::IpAddr,
        control: &Control,
    ) -> Result<LeafAdmission, Failure> {
        let peers = fs.current_peers();
        let peer = peers.get(hub).ok_or(Failure::Denied)?;
        let witness = PollWitness::new(ip, Some(cert), peer).map_err(|_| Failure::Denied)?;
        leaf_admit(fs, peers, hub, witness, control)
    }
    pub fn admit_control(
        fs: &Arc<FedState>,
        hub: &str,
        cert: &[u8],
        ip: std::net::IpAddr,
        control: &Control,
    ) -> u16 {
        match control_admission(fs, hub, cert, ip, control) {
            Ok(_) => 200,
            Err(error) => error.into_response().status().as_u16(),
        }
    }
    pub async fn project_control(
        fs: &Arc<FedState>,
        hub: &str,
        cert: &[u8],
        ip: std::net::IpAddr,
        control: &Control,
    ) -> Result<Vec<u8>, u16> {
        let admission = control_admission(fs, hub, cert, ip, control)
            .map_err(|error| error.into_response().status().as_u16())?;
        let reservation = crate::observe_fed::read_slots(fs).try_acquire_owned();
        crate::observe_fed::test_hooks::controls(fs).read_decision(reservation.is_ok());
        let slot = reservation.map_err(|_| 429_u16)?;
        leaf_read(fs.clone(), Arc::new(admission), control, Arc::new(slot))
            .await
            .map_err(|error| error.into_response().status().as_u16())
    }
    pub async fn deliver_control(
        fs: &Arc<FedState>,
        hub: &str,
        cert: &[u8],
        ip: std::net::IpAddr,
        control: Control,
    ) {
        let peers = fs.current_peers();
        let peer = peers.get(hub).unwrap();
        let witness = PollWitness::new(ip, Some(cert), peer).unwrap();
        spawn_answer(
            fs,
            hub,
            peers,
            witness,
            control,
            &crate::observe_fed::read_slots(fs),
        )
        .await;
    }
}

pub(crate) struct PollWitness {
    ip: std::net::IpAddr,
    identity: String,
}
impl PollWitness {
    pub(crate) fn new(
        ip: std::net::IpAddr,
        cert: Option<&[u8]>,
        config: &PeerConfig,
    ) -> Result<Self, AppError> {
        let cert = cert.ok_or_else(|| AppError::Denied("observation transport denied".into()))?;
        let identity = if let Some(pin) = &config.pin {
            let identity = format!("sha256:{}", crate::fed::normalize_pin(pin));
            if !certificate_matches(cert, &identity) {
                return Err(AppError::Denied("observation transport denied".into()));
            }
            identity
        } else {
            certificate_identity(cert)
                .map_err(|_| AppError::Denied("observation transport denied".into()))?
        };
        Ok(Self { ip, identity })
    }
}
impl Control {
    pub(crate) fn wire_valid(&self) -> bool {
        self.validate().is_ok()
    }
}
struct LeafAdmission {
    peers: Arc<PeersMap>,
    config: PeerConfig,
    hub: String,
    witness: PollWitness,
}
fn leaf_admit(
    fs: &Arc<FedState>,
    peers: Arc<PeersMap>,
    hub: &str,
    witness: PollWitness,
    control: &Control,
) -> Result<LeafAdmission, Failure> {
    control.validate()?;
    if unsupported_leaf(fs, &control.leaf) {
        return Err(Failure::Unsupported);
    }
    if !Arc::ptr_eq(&peers, &fs.current_peers())
        || witness.identity != control.hub
        || own_identity(fs)? != control.leaf
    {
        return Err(Failure::Denied);
    }
    let transport = peers.get_peer_config(hub).ok_or(Failure::Denied)?;
    if !config_identity(&transport, &witness.identity) {
        return Err(Failure::Denied);
    }
    crate::fed::check_peer_source(&transport, &witness.ip).map_err(|_| Failure::Denied)?;
    leaf_route(
        &peers,
        &Route {
            hub: control.hub.clone(),
            leaf: control.leaf.clone(),
            collector: control.collector.clone(),
        },
    )?;
    let config = config_for_identity(&peers, &control.collector).ok_or(Failure::Denied)?;
    grant(&config, false)?;
    if config.from.is_some() {
        return Err(Failure::Denied);
    }
    if !fs
        .rate_limiter
        .check_and_consume(&format!("observe:{}", config.name), None)
    {
        return Err(Failure::Busy);
    }
    Ok(LeafAdmission {
        peers,
        config,
        hub: hub.into(),
        witness,
    })
}
fn leaf_current(
    fs: &Arc<FedState>,
    admission: &LeafAdmission,
    control: &Control,
) -> Result<(), Failure> {
    if !Arc::ptr_eq(&admission.peers, &fs.current_peers()) || own_identity(fs)? != control.leaf {
        return Err(Failure::Denied);
    }
    let peers = fs.current_peers();
    leaf_route(
        &peers,
        &Route {
            hub: control.hub.clone(),
            leaf: control.leaf.clone(),
            collector: control.collector.clone(),
        },
    )?;
    let transport = peers
        .get_peer_config(&admission.hub)
        .ok_or(Failure::Denied)?;
    if !config_identity(&transport, &admission.witness.identity) {
        return Err(Failure::Denied);
    }
    crate::fed::check_peer_source(&transport, &admission.witness.ip)
        .map_err(|_| Failure::Denied)?;
    let config = config_for_identity(&peers, &control.collector).ok_or(Failure::Denied)?;
    grant(&config, false)?;
    if config.from.is_some() {
        return Err(Failure::Denied);
    }
    Ok(())
}

pub(crate) async fn spawn_answer(
    fs: &Arc<FedState>,
    hub: &str,
    peers: Arc<PeersMap>,
    witness: PollWitness,
    control: Control,
    slots: &Arc<Semaphore>,
) {
    let scheduler = shared(fs);
    #[cfg(any(test, feature = "test-hooks"))]
    {
        *scheduler.controls.received_control.lock().unwrap() = Some(control.clone());
    }
    #[cfg(any(test, feature = "test-hooks"))]
    scheduler
        .controls
        .controls_received
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_millis(control.remaining_ms.min(5000));
    let admission = leaf_admit(fs, peers, hub, witness, &control).and_then(|admission| {
        let reservation = slots.clone().try_acquire_owned();
        #[cfg(any(test, feature = "test-hooks"))]
        crate::observe_fed::test_hooks::controls(fs).read_decision(reservation.is_ok());
        reservation
            .map(|slot| (admission, slot))
            .map_err(|_| Failure::Busy)
    });
    let fs = fs.clone();
    let hub = hub.to_owned();
    match admission {
        Ok((admission, slot)) => {
            tokio::spawn(async move {
                let _scheduler = scheduler;
                let admission = Arc::new(admission);
                let slot = Arc::new(slot);
                let result = tokio::time::timeout_at(
                    deadline,
                    leaf_read(fs.clone(), admission.clone(), &control, slot.clone()),
                )
                .await
                .unwrap_or(Err(Failure::Unreachable));
                let _ = tokio::time::timeout_at(
                    deadline,
                    post_answer(&fs, &hub, &control, result, Some(&admission)),
                )
                .await;
                drop(slot);
            });
        }
        Err(error) => {
            let Ok(refusal) = scheduler.refusals.clone().try_acquire_owned() else {
                return;
            };
            #[cfg(any(test, feature = "test-hooks"))]
            let refusal_count = test_hooks::TaskCount::new(
                test_hooks::controls(&fs),
                test_hooks::TaskCounter::Refusal,
            );
            tokio::spawn(async move {
                let _scheduler = scheduler;
                let _refusal = refusal;
                #[cfg(any(test, feature = "test-hooks"))]
                let _refusal_count = refusal_count;
                let _ = tokio::time::timeout_at(
                    deadline,
                    post_answer(&fs, &hub, &control, Err(error), None),
                )
                .await;
            });
        }
    }
}
async fn leaf_read(
    fs: Arc<FedState>,
    admission: Arc<LeafAdmission>,
    control: &Control,
    slot: Arc<OwnedSemaphorePermit>,
) -> Result<Vec<u8>, Failure> {
    let labels = control.read.labels(&control.query)? && admission.config.observe_labels;
    let scope = Scope::new(
        &fs.node_name,
        &admission.config.name,
        admission.config.targets.as_deref(),
        labels,
    )
    .map_err(|_| Failure::Invalid)?;
    let uri: axum::http::Uri = format!("/observe?{}", control.query)
        .parse()
        .map_err(|_| Failure::Invalid)?;
    #[cfg(any(test, feature = "test-hooks"))]
    let controls = crate::observe_fed::test_hooks::controls(&fs);
    #[cfg(any(test, feature = "test-hooks"))]
    controls.before_read.pause().await;
    leaf_current(&fs, &admission, control)?;
    let read = control.read;
    let source = fs.clone();
    #[cfg(any(test, feature = "test-hooks"))]
    let io_controls = controls.clone();
    let body = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        #[cfg(any(test, feature = "test-hooks"))]
        let _completion = crate::observe_fed::test_hooks::Completion(io_controls.clone());
        #[cfg(any(test, feature = "test-hooks"))]
        io_controls.before_io.pause_blocking();
        match read {
            Kind::Events => {
                let axum::extract::Query(query) =
                    axum::extract::Query::<ExportQuery>::try_from_uri(&uri)
                        .map_err(|_| Failure::Invalid)?;
                let journal_query = query.journal_query(&scope).map_err(|_| Failure::Invalid)?;
                let observer = crate::observe::for_db(&source.db).ok_or(Failure::Unreachable)?;
                let page = observer
                    .page(journal_query)
                    .map_err(|_| Failure::Unreachable)?;
                serde_json::to_vec(
                    &crate::observe_export::project_page(
                        page,
                        &query,
                        &scope,
                        crate::storage::now_epoch_secs(),
                    )
                    .map_err(|_| Failure::Unreachable)?,
                )
                .map_err(|_| Failure::Invalid)
            }
            Kind::Snapshot => {
                let (records, partial) = crate::observe_snapshot::collect(&source);
                serde_json::to_vec(
                    &crate::observe_export::project_snapshot(
                        &scope,
                        records,
                        crate::storage::now_epoch_secs(),
                        partial,
                    )
                    .map_err(|_| Failure::Unreachable)?,
                )
                .map_err(|_| Failure::Invalid)
            }
        }
    })
    .await
    .map_err(|_| Failure::Unreachable)??;
    if body.len() > MAX_BYTES {
        return Err(Failure::Invalid);
    }
    #[cfg(any(test, feature = "test-hooks"))]
    controls.before_emit.pause().await;
    leaf_current(&fs, &admission, control)?;
    Ok(body)
}
async fn post_answer(
    fs: &Arc<FedState>,
    hub: &str,
    control: &Control,
    result: Result<Vec<u8>, Failure>,
    admission: Option<&LeafAdmission>,
) -> Result<(), Failure> {
    #[cfg(any(test, feature = "test-hooks"))]
    test_hooks::controls(fs).before_post.pause().await;
    let scheduler = shared(fs);
    #[cfg(any(test, feature = "test-hooks"))]
    let waiting = test_hooks::TaskCount::new(
        test_hooks::controls(fs),
        test_hooks::TaskCounter::PostWaiting,
    );
    let _post = scheduler
        .posts
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Failure::Unreachable)?;
    #[cfg(any(test, feature = "test-hooks"))]
    drop(waiting);
    #[cfg(any(test, feature = "test-hooks"))]
    let _active = test_hooks::TaskCount::new(
        test_hooks::controls(fs),
        test_hooks::TaskCounter::PostActive,
    );
    let peers = fs.current_peers();
    let peer = peers.get(hub).ok_or(Failure::Denied)?;
    if !config_identity(peer, &control.hub) {
        return Err(Failure::Denied);
    }
    let (mut body, mut status) = match result {
        Ok(body) => (body, "ok"),
        Err(e) => (Vec::new(), e.text()),
    };
    let connector =
        crate::fed::make_tls_connector_for_peer(fs, peer).map_err(|_| Failure::Unreachable)?;
    let tcp = tokio::net::TcpStream::connect(&peer.address)
        .await
        .map_err(|_| Failure::Unreachable)?;
    let remote_ip = tcp.peer_addr().map_err(|_| Failure::Unreachable)?.ip();
    let name =
        rustls::pki_types::ServerName::try_from(peer.name.clone()).map_err(|_| Failure::Invalid)?;
    let tls = connector
        .connect(name, tcp)
        .await
        .map_err(|_| Failure::Unreachable)?;
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or(Failure::Denied)?;
    if !certificate_matches(cert.as_ref(), &control.hub) {
        return Err(Failure::Denied);
    }
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|_| Failure::Unreachable)?;
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    struct Abort(tokio::task::JoinHandle<()>);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _connection = Abort(connection);
    #[cfg(any(test, feature = "test-hooks"))]
    test_hooks::controls(fs).before_send.pause().await;
    if !Arc::ptr_eq(&peers, &fs.current_peers()) {
        let current = fs.current_peers();
        if !current
            .get(hub)
            .is_some_and(|p| config_identity(p, &control.hub))
        {
            return Err(Failure::Denied);
        }
        body.clear();
        status = "denied";
    }
    if status == "ok" {
        let current = admission
            .ok_or(Failure::Denied)
            .and_then(|a| leaf_current(fs, a, control))
            .and_then(|()| {
                crate::fed::check_peer_source(peer, &remote_ip).map_err(|_| Failure::Denied)
            });
        if current.is_err() {
            body.clear();
            status = "denied";
        }
    }
    let request = hyper::Request::post(format!("/fed/v2/observe/relay/answer/{}", control.id))
        .header("host", &peer.name)
        .header("content-type", "application/json")
        .header("xmsg-observe-kind", control.read.text())
        .header("xmsg-observe-status", status)
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .map_err(|_| Failure::Invalid)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| Failure::Unreachable)?;
    if !response.status().is_success() {
        return Err(Failure::Invalid);
    }
    Ok(())
}

pub(crate) fn keep_scheduler(fs: &Arc<FedState>) -> impl Send {
    shared(fs)
}
