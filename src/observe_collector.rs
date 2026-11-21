use crate::observe_collector_auth::Verifier;
use crate::observe_collector_net::{self as net, Client, Config};
use crate::observe_collector_store::{NodePolicy, NodeStatus, Store, StoreError, UnavailableKind};
use crate::observe_collector_web::{self as web, CollectorHealth, Filter, NodeFreshness};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

const FRESH: Duration = Duration::from_secs(15);

#[derive(clap::Parser, Debug)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct Args {
    #[arg(long, required = true)]
    pub config: Option<PathBuf>,
    #[arg(long, required = true)]
    pub state_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub action: Option<Action>,
    /// Web listener; non-loopback addresses require configured server TLS
    #[arg(long, default_value = "127.0.0.1:9428")]
    pub listen: SocketAddr,
}

#[derive(clap::Subcommand, Debug)]
pub enum Action {
    Admin(crate::mission_control::admin::Args),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid collector configuration")]
    Configuration,
    #[error("collector storage unavailable")]
    Storage,
    #[error("unsupported collector SQLite engine: required {required}, found {found}")]
    UnsupportedEngine {
        required: &'static str,
        found: &'static str,
    },
    #[error("{0}")]
    CeilingExceeded(String),
    #[error("collector listener unavailable")]
    Listener,
    #[error(transparent)]
    Admin(crate::mission_control::admin::AdminError),
}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::UnsupportedEngine { required, found } => {
                Self::UnsupportedEngine { required, found }
            }
            e @ StoreError::CeilingExceeded { .. } => Self::CeilingExceeded(e.to_string()),
            _ => Self::Storage,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct MaintenanceState {
    last_ok: Option<tokio::time::Instant>,
    last_failed: bool,
}

struct PollerGuard(Arc<AtomicUsize>);
impl PollerGuard {
    fn enter(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}
impl Drop for PollerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct State {
    verifier: Option<Verifier>,
    issuer: Option<Arc<crate::mission_control::Issuer>>,
    read_hub: Option<Arc<crate::mission_control::upstream::ReadHub>>,
    #[cfg(test)]
    wire_probe: Option<Arc<crate::mission_control::stream::WireProbe>>,

    store: Arc<Store>,
    store_slots: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    nodes: Vec<String>,
    denied: Mutex<BTreeSet<String>>,
    failures: Mutex<BTreeMap<String, UnavailableKind>>,
    scopes: Mutex<BTreeMap<String, String>>,
    scope_hidden: Mutex<BTreeSet<String>>,
    success: Mutex<BTreeMap<String, (tokio::time::Instant, i64)>>,
    pollers_alive: Arc<AtomicUsize>,
    supported_sources: usize,
    maintenance: Mutex<MaintenanceState>,
    store_slot_refusals: Arc<AtomicU64>,
}

async fn store_call_counted<T: Send + 'static>(
    store: Arc<Store>,
    slots: Arc<Semaphore>,
    refusals: Option<Arc<AtomicU64>>,
    call: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    let lease = slots.try_acquire_owned().map_err(|_| {
        if let Some(counter) = refusals {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        StoreError::Storage
    })?;
    tokio::task::spawn_blocking(move || {
        // Keep admission while SQLite finishes even if its caller's deadline expires.
        let _lease = lease;
        call(&store)
    })
    .await
    .map_err(|_| StoreError::Storage)?
}

#[cfg(test)]
async fn store_call<T: Send + 'static>(
    store: Arc<Store>,
    slots: Arc<Semaphore>,
    call: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    store_call_counted(store, slots, None, call).await
}

fn response(status: StatusCode, body: impl Into<Bytes>, html: bool) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert("cache-control", "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert(
        "content-security-policy",
        web::content_security_policy().parse().unwrap(),
    );
    headers.insert(
        "content-type",
        if html {
            "text/html; charset=utf-8"
        } else {
            "text/plain; charset=utf-8"
        }
        .parse()
        .unwrap(),
    );
    response
}

impl State {
    async fn prepare<B>(&self, request: Request<B>) -> Response<Full<Bytes>> {
        let header_bytes = request
            .headers()
            .iter()
            .fold(0usize, |count, (key, value)| {
                count.saturating_add(key.as_str().len() + value.as_bytes().len() + 4)
            });
        if header_bytes > 16 * 1024 {
            return response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "request headers too large\n",
                false,
            );
        }
        if request.method() == hyper::Method::GET
            && request.uri().path() == "/health"
            && request.uri().query().is_none()
        {
            return response(StatusCode::OK, "available\n", false);
        }
        let Some(verifier) = &self.verifier else {
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                "collector unavailable\n",
                false,
            );
        };
        let _owner = match verifier.authorize(request.headers()).await {
            Ok(owner) => owner,
            Err(error) => {
                return response(
                    error.status_code(),
                    "owner authentication required\n",
                    false,
                )
            }
        };
        if request.method() != hyper::Method::GET {
            return response(StatusCode::METHOD_NOT_ALLOWED, "GET required\n", false);
        }
        if request.uri().path() != "/" {
            return response(StatusCode::NOT_FOUND, "not found\n", false);
        }
        let filter = match Filter::parse(request.uri().query(), self.nodes.len()) {
            Ok(filter) => filter,
            Err(_) => return response(StatusCode::BAD_REQUEST, "invalid filter\n", false),
        };
        self.render_page(filter).await
    }

    async fn render_page(&self, filter: Filter) -> Response<Full<Bytes>> {
        let selected = filter.node.map(|index| self.nodes[index].clone());
        let result = store_call_counted(
            self.store.clone(),
            self.store_slots.clone(),
            Some(self.store_slot_refusals.clone()),
            move |store| {
                let mut summaries = store.view(None, 0)?;
                for node in &mut summaries {
                    node.latest_snapshot = None;
                }
                let detail = selected
                    .map(|node| store.view(Some(&node), filter.read_limit()))
                    .transpose()?
                    .and_then(|mut views| views.pop());
                Ok((summaries, detail))
            },
        )
        .await;
        match result {
            Ok((mut summaries, mut detail)) => {
                if let Ok(failures) = self.failures.lock() {
                    for view in summaries.iter_mut().chain(detail.iter_mut()) {
                        if let Some(kind) = failures.get(&view.node) {
                            view.failure = Some(*kind);
                            view.status = match kind {
                                UnavailableKind::Unsupported => NodeStatus::Unsupported,
                                UnavailableKind::StorageFull => NodeStatus::StorageFull,
                                _ if view.history_hidden => NodeStatus::HiddenPendingRevalidation,
                                _ => NodeStatus::Stale,
                            };
                        }
                    }
                } else {
                    return response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "collector unavailable\n",
                        false,
                    );
                }

                if let Ok(denied) = self.denied.lock() {
                    for view in summaries.iter_mut().chain(detail.iter_mut()) {
                        if denied.contains(&view.node) {
                            view.history_hidden = true;
                            view.status = NodeStatus::Denied;
                            view.failure = None;
                            view.events.clear();
                            view.latest_snapshot = None;
                            view.cursor = None;
                            view.gaps.clear();
                        }
                    }
                } else {
                    return response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "collector unavailable\n",
                        false,
                    );
                }
                if let Ok(hidden) = self.scope_hidden.lock() {
                    for view in summaries.iter_mut().chain(detail.iter_mut()) {
                        if hidden.contains(&view.node) {
                            view.history_hidden = true;
                            view.status = NodeStatus::HiddenPendingRevalidation;
                            view.events.clear();
                            view.latest_snapshot = None;
                            view.cursor = None;
                            view.gaps.clear();
                        }
                    }
                } else {
                    return response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "collector unavailable\n",
                        false,
                    );
                }

                let now_mono = tokio::time::Instant::now();
                let mut node_freshness = BTreeMap::new();
                if let Ok(success) = self.success.lock() {
                    for view in summaries.iter_mut().chain(detail.iter_mut()) {
                        if view.history_hidden
                            && !view.has_stored_history
                            && view.failure.is_none()
                            && view.status == NodeStatus::HiddenPendingRevalidation
                            && success.get(&view.node).is_none()
                        {
                            view.status = NodeStatus::Loading;
                            view.history_hidden = false;
                        }
                        let masked = view.history_hidden
                            || matches!(
                                view.status,
                                NodeStatus::Loading
                                    | NodeStatus::Denied
                                    | NodeStatus::HiddenPendingRevalidation
                            );
                        if masked {
                            continue;
                        }
                        let last_success = if view.status == NodeStatus::RemovedRetained {
                            view.last_activity
                        } else {
                            success.get(&view.node).map(|(mono, utc)| {
                                (*utc, now_mono.saturating_duration_since(*mono).as_secs())
                            })
                        };
                        let mut entry = NodeFreshness {
                            stale_for_secs: None,
                            stale_since_start: false,
                            last_success,
                        };
                        if view.failure.is_none() && view.status == NodeStatus::Healthy {
                            match last_success {
                                None => {
                                    view.status = NodeStatus::Stale;
                                    entry.stale_since_start = true;
                                }
                                Some((_, age_secs))
                                    if Duration::from_secs(age_secs) > FRESH
                                        || success.get(&view.node).is_some_and(|(mono, _)| {
                                            now_mono.saturating_duration_since(*mono) > FRESH
                                        }) =>
                                {
                                    view.status = NodeStatus::Stale;
                                    entry.stale_for_secs = Some(age_secs);
                                }
                                Some(_) => {}
                            }
                        }
                        node_freshness.insert(view.node.clone(), entry);
                    }
                } else {
                    return response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "collector unavailable\n",
                        false,
                    );
                }

                let Ok(maint) = self.maintenance.lock() else {
                    return response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "collector unavailable\n",
                        false,
                    );
                };
                let health = CollectorHealth {
                    pollers_alive: self.pollers_alive.load(Ordering::SeqCst),
                    supported_sources: self.supported_sources,
                    last_maintenance_ok_secs: maint
                        .last_ok
                        .map(|t| now_mono.saturating_duration_since(t).as_secs()),
                    last_maintenance_failed: maint.last_failed,
                    store_slot_refusals: self.store_slot_refusals.load(Ordering::Relaxed),
                    evicted_inactive: self.store.evicted_inactive(),
                    nodes: node_freshness,
                };
                response(
                    StatusCode::OK,
                    web::render_with_health(&summaries, detail.as_ref(), filter, &health),
                    true,
                )
            }
            Err(_) => response(
                StatusCode::SERVICE_UNAVAILABLE,
                "collector storage unavailable\n",
                false,
            ),
        }
    }
}

fn tls_config(
    config: &Config,
    listen: SocketAddr,
) -> Result<Option<tokio_rustls::TlsAcceptor>, Error> {
    let Some(tls) = &config.web_tls else {
        if !listen.ip().is_loopback() {
            return Err(Error::Configuration);
        }
        return Ok(None);
    };
    let (chain, key) = net::credentials(&tls.cert, &tls.key).map_err(|_| Error::Configuration)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            chain,
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
        .map_err(|_| Error::Configuration)?;
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
}

fn request_slots() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(8))
}

fn connection_slots() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(64))
}

async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<State>,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> Result<(), Error> {
    serve_with_admission(listener, state, tls, connection_slots()).await
}

async fn serve_with_admission(
    listener: tokio::net::TcpListener,
    state: Arc<State>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    connections: Arc<Semaphore>,
) -> Result<(), Error> {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = accepted.map_err(|_| Error::Listener)?;
                let Ok(lease) = connections.clone().try_acquire_owned() else { drop(tcp); continue };
                let state = state.clone();
                let tls = tls.clone();
                tasks.spawn(async move {
                    let _lease = lease;
                    #[cfg(test)]
                    if state.wire_probe.is_some() {
                        socket2::SockRef::from(&tcp).set_send_buffer_size(4096).unwrap();
                    }
                    let (tcp, abort) = if state.read_hub.is_some() {
                        let Ok(socket) = tcp.into_std() else { return };
                        let Ok(abort) = socket.try_clone() else { return };
                        let Ok(tcp) = tokio::net::TcpStream::from_std(socket) else { return };
                        (tcp, Some(abort))
                    } else {
                        (tcp, None)
                    };
                    if let Some(tls) = tls {
                        if let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(5), tls.accept(tcp)).await {
                            serve_stream_with_socket(stream, state, Some(peer), abort).await;
                        }
                    } else {
                        serve_stream_with_socket(tcp, state, Some(peer), abort).await;
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

const WEB_BUDGET: Duration = Duration::from_secs(5);

#[cfg(test)]
async fn serve_stream<I>(stream: I, state: Arc<State>, peer: Option<SocketAddr>)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    serve_stream_with_socket(stream, state, peer, None).await;
}

async fn serve_stream_with_socket<I>(
    stream: I,
    state: Arc<State>,
    peer: Option<SocketAddr>,
    abort: Option<std::net::TcpStream>,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let budget = state.issuer.as_ref().map_or(WEB_BUDGET, |issuer| {
        Duration::from_millis(issuer.config().handshake_timeout_ms)
    });
    let fence = crate::mission_control::stream::Fence::default();
    #[cfg(test)]
    let fence = fence.with_probe(state.wire_probe.clone());
    let fence = Arc::new(fence);
    let connection_fence = fence.clone();
    serve_http_inner(
        connection_fence.wrap(stream),
        state.requests.clone(),
        budget,
        Some(connection_fence),
        move |mut request| async move {
            if let Some(issuer) = &state.issuer {
                if request.method() != hyper::Method::GET
                    || request.uri().path() != "/health"
                    || request.uri().query().is_some()
                {
                    if let Some(peer) = peer {
                        request.extensions_mut().insert(peer);
                    }
                    let header_bytes =
                        request
                            .headers()
                            .iter()
                            .fold(0usize, |size, (name, value)| {
                                size.saturating_add(
                                    name.as_str().len() + value.as_bytes().len() + 4,
                                )
                            });
                    if header_bytes > issuer.config().max_handshake_header_bytes {
                        return response(
                            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                            "request headers too large\n",
                            false,
                        )
                        .map(BodyExt::boxed_unsync);
                    }
                    if let Some(hub) = &state.read_hub {
                        if crate::mission_control::stream::is_stream(request.uri().path()) {
                            return crate::mission_control::stream::response(
                                issuer,
                                hub.clone(),
                                request,
                                abort,
                                fence,
                            )
                            .await;
                        }
                        if crate::mission_control::websocket::is_session(request.uri().path()) {
                            return crate::mission_control::websocket::upgrade(
                                issuer,
                                hub.clone(),
                                request,
                                abort,
                            )
                            .await
                            .map(BodyExt::boxed_unsync);
                        }
                        if crate::mission_control::transport::is_snapshot(request.uri().path()) {
                            return crate::mission_control::transport::snapshot(
                                issuer, hub, request,
                            )
                            .await
                            .map(BodyExt::boxed_unsync);
                        }
                    }
                    return issuer.handle(request).await.map(BodyExt::boxed_unsync);
                }
            }
            state.prepare(request).await.map(BodyExt::boxed_unsync)
        },
    )
    .await;
}

#[cfg(test)]
async fn serve_http<I, F, Fut>(stream: I, requests: Arc<Semaphore>, budget: Duration, prepare: F)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(Request<Incoming>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    serve_http_inner(stream, requests, budget, None, move |request| async move {
        prepare(request).await.map(BodyExt::boxed_unsync)
    })
    .await;
}

async fn serve_http_inner<I, F, Fut>(
    stream: I,
    requests: Arc<Semaphore>,
    budget: Duration,
    fence: Option<Arc<crate::mission_control::stream::Fence>>,
    prepare: F,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(Request<Incoming>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Response<crate::mission_control::stream::Body>>
        + Send
        + 'static,
{
    let (admission_tx, admission_rx) = tokio::sync::oneshot::channel();
    let preparation = Mutex::new(Some((admission_tx, prepare)));
    let service = hyper::service::service_fn(move |request| {
        let operation = preparation
            .lock()
            .ok()
            .and_then(|mut operation| operation.take());
        let requests = requests.clone();
        async move {
            let lease = requests.try_acquire_owned().ok();
            let admitted = lease.is_some();
            let deadline = tokio::time::Instant::now() + budget;
            let Some((admission, prepare)) = operation else {
                return Ok::<_, Infallible>(
                    response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "collector unavailable\n",
                        false,
                    )
                    .map(BodyExt::boxed_unsync),
                );
            };
            if admission.send((deadline, lease)).is_err() {
                return Ok::<_, Infallible>(
                    response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "collector unavailable\n",
                        false,
                    )
                    .map(BodyExt::boxed_unsync),
                );
            }
            let mut response = if admitted {
                prepare(request).await
            } else {
                response(StatusCode::SERVICE_UNAVAILABLE, "collector busy\n", false)
                    .map(BodyExt::boxed_unsync)
            };
            if response.status() != StatusCode::SWITCHING_PROTOCOLS {
                response.headers_mut().insert(
                    hyper::header::CONNECTION,
                    hyper::header::HeaderValue::from_static("close"),
                );
            }
            Ok::<_, Infallible>(response)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(true)
        .max_buf_size(16 * 1024)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5));
    let connection = builder
        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
        .with_upgrades();
    tokio::pin!(connection);
    let admission = tokio::select! {
        _ = &mut connection => return,
        admission = admission_rx => admission,
    };
    if let Ok((deadline, lease)) = admission {
        if let Some(fence) = fence {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {}
                _ = &mut connection => {}
                _ = fence.started() => {
                    drop(lease);
                    let _ = connection.await;
                }
            }
        } else {
            let _lease = lease;
            let _ = tokio::time::timeout_at(deadline, connection).await;
        }
    }
}

fn remember_failure(state: &State, node: &str, kind: UnavailableKind) {
    if state.nodes.iter().any(|known| known == node) {
        if let Ok(mut failures) = state.failures.lock() {
            failures.insert(node.to_owned(), kind);
        }
    }
}

async fn mark_error(state: &State, node: String, error: net::Error) {
    if error == net::Error::Denied {
        if let Some(issuer) = &state.issuer {
            issuer.set_node_masked(&node, true);
        }
        if let Some(hub) = &state.read_hub {
            let _ = hub.mask_poll(&node, true, state.store.epoch_now());
        }
        if let Ok(mut denied) = state.denied.lock() {
            denied.insert(node.clone());
        }
    }
    let kind = match error {
        net::Error::Unsupported => UnavailableKind::Unsupported,
        net::Error::EndpointNotFound => UnavailableKind::EndpointNotFound,
        net::Error::Timeout => UnavailableKind::Timeout,
        net::Error::Malformed => UnavailableKind::Malformed,
        net::Error::RateLimited(_) => UnavailableKind::RateLimited,
        _ => UnavailableKind::Unreachable,
    };
    if error != net::Error::Denied {
        remember_failure(state, &node, kind);
    }
    if let Err(err) = store_call_counted(
        state.store.clone(),
        state.store_slots.clone(),
        Some(state.store_slot_refusals.clone()),
        move |store| {
            if error == net::Error::Denied {
                return store.deny(&node);
            }
            store.unavailable(&node, kind)
        },
    )
    .await
    {
        tracing::warn!(error = ?err, "failed to persist collector node error");
    }
}

async fn mark_storage_error(state: &State, node: String, error: StoreError) {
    let kind = if error == StoreError::Full {
        UnavailableKind::StorageFull
    } else {
        UnavailableKind::Malformed
    };
    remember_failure(state, &node, kind);
    if let Err(err) = store_call_counted(
        state.store.clone(),
        state.store_slots.clone(),
        Some(state.store_slot_refusals.clone()),
        move |store| store.unavailable(&node, kind),
    )
    .await
    {
        tracing::warn!(error = ?err, "failed to persist collector storage error");
    }
}

fn observe_scope(state: &State, node: &str, scope: &str) {
    if scope.len() != 64 || !scope.bytes().all(|b| b.is_ascii_hexdigit()) {
        return;
    }
    if let Ok(scopes) = state.scopes.lock() {
        if scopes.get(node).is_some_and(|old| old != scope) {
            if let Some(issuer) = &state.issuer {
                issuer.set_node_masked(node, true);
            }
            if let Some(hub) = &state.read_hub {
                let _ = hub.mask_poll(node, false, state.store.epoch_now());
            }
            if let Ok(mut hidden) = state.scope_hidden.lock() {
                hidden.insert(node.to_owned());
            }
        }
    }
}

fn on_response_received(_state: &State, _node: &str) {}

fn on_page_ingested(state: &State, node: &str, scope: String, _inserted: usize) {
    accepted_scope(state, node, scope);
}

fn initial_success(_store: &Store) -> BTreeMap<String, (tokio::time::Instant, i64)> {
    BTreeMap::new()
}

fn accepted_scope(state: &State, node: &str, scope: String) {
    if state.read_hub.is_none() {
        if let Some(issuer) = &state.issuer {
            issuer.set_node_masked(node, false);
        }
    }
    if let Ok(mut failures) = state.failures.lock() {
        failures.remove(node);
    }
    if let Ok(mut scopes) = state.scopes.lock() {
        scopes.insert(node.to_owned(), scope);
    }
    if let Ok(mut hidden) = state.scope_hidden.lock() {
        hidden.remove(node);
    }
    if let Ok(mut denied) = state.denied.lock() {
        denied.remove(node);
    }
    if let Ok(mut success) = state.success.lock() {
        success.insert(
            node.to_owned(),
            (tokio::time::Instant::now(), state.store.epoch_now()),
        );
    }
}

async fn publish_poll_view(state: &State, node: &str) {
    let Some(hub) = &state.read_hub else {
        return;
    };
    let name = node.to_owned();
    let Ok(views) = store_call_counted(
        state.store.clone(),
        state.store_slots.clone(),
        Some(state.store_slot_refusals.clone()),
        move |store| store.view(Some(&name), 200),
    )
    .await
    else {
        return;
    };
    let observed = state
        .success
        .lock()
        .ok()
        .and_then(|success| success.get(node).copied());
    let stale = observed.is_none_or(|(time, _)| time.elapsed() > FRESH);
    let denied = state.denied.lock().map_or(true, |set| set.contains(node));
    let transitioning = state
        .scope_hidden
        .lock()
        .map_or(true, |set| set.contains(node));
    if denied || transitioning {
        return;
    }
    for view in views {
        let unmask = !view.history_hidden && view.status != NodeStatus::Denied;
        if hub
            .accept_poll(
                view,
                observed.map(|(_, at)| at),
                stale,
                state.store.epoch_now(),
            )
            .is_err()
        {
            tracing::warn!("Mission Control upstream update refused");
            continue;
        }
        if unmask {
            if let Some(issuer) = &state.issuer {
                issuer.set_node_masked(node, false);
                hub.wake();
            }
        }
    }
}

async fn poll_source(client: Arc<Client>, state: Arc<State>, index: usize) {
    let source = &client.sources[index];
    if !source.supported {
        return;
    }
    let _poller_guard = PollerGuard::enter(state.pollers_alive.clone());
    let mut snapshot_due = true;
    let mut snapshot_at = tokio::time::Instant::now();
    let mut backfill = false;
    loop {
        let started = tokio::time::Instant::now();
        let mut next_start = started + Duration::from_secs(2);
        let mut failure = None;
        if snapshot_due || (!backfill && started >= snapshot_at) {
            snapshot_due = false;
            snapshot_at = started + Duration::from_secs(30);
            match client.snapshot(index).await {
                Ok(snapshot) => {
                    on_response_received(&state, &source.node);
                    let scope = snapshot.scope.clone();
                    observe_scope(&state, &source.node, &scope);
                    let node = source.node.clone();
                    if let Err(error) = store_call_counted(
                        state.store.clone(),
                        state.store_slots.clone(),
                        Some(state.store_slot_refusals.clone()),
                        move |store| store.ingest_snapshot(&node, snapshot),
                    )
                    .await
                    {
                        mark_storage_error(&state, source.node.clone(), error).await;
                    } else {
                        accepted_scope(&state, &source.node, scope);
                    }
                }
                Err(error) => {
                    failure = Some(error);
                }
            }
        } else {
            let node = source.node.clone();
            match store_call_counted(
                state.store.clone(),
                state.store_slots.clone(),
                Some(state.store_slot_refusals.clone()),
                move |store| store.cursor(&node),
            )
            .await
            {
                Ok(cursor) => match client
                    .events_decoded(
                        index,
                        cursor.epoch.as_deref(),
                        cursor.scope.as_deref(),
                        cursor.next,
                    )
                    .await
                {
                    Ok(page) => {
                        on_response_received(&state, &source.node);
                        let scope = page.page.scope.clone();
                        observe_scope(&state, &source.node, &scope);
                        let has_more = page.page.has_more;
                        let node = source.node.clone();
                        match store_call_counted(
                            state.store.clone(),
                            state.store_slots.clone(),
                            Some(state.store_slot_refusals.clone()),
                            move |store| store.ingest_decoded_page(&node, &cursor, page),
                        )
                        .await
                        {
                            Ok(outcome) => {
                                backfill = has_more;
                                on_page_ingested(&state, &source.node, scope, outcome.inserted);
                            }
                            Err(error) => {
                                mark_storage_error(&state, source.node.clone(), error).await
                            }
                        }
                    }
                    Err(error) => {
                        failure = Some(error);
                    }
                },
                Err(error) => {
                    mark_storage_error(&state, source.node.clone(), error).await;
                }
            }
        }
        if let Some(error) = failure {
            if let net::Error::RateLimited(seconds) = error {
                next_start = tokio::time::Instant::now() + Duration::from_secs(seconds);
            }
            if error != net::Error::Pending {
                mark_error(&state, source.node.clone(), error).await;
            }
        }
        publish_poll_view(&state, &source.node).await;
        tokio::time::sleep_until(next_start).await;
    }
}

async fn maintain_once(state: &State) {
    let outcome = store_call_counted(
        state.store.clone(),
        state.store_slots.clone(),
        Some(state.store_slot_refusals.clone()),
        |store| store.maintain(),
    )
    .await;
    if let Ok(mut maint) = state.maintenance.lock() {
        match outcome {
            Ok(_) => {
                maint.last_ok = Some(tokio::time::Instant::now());
                maint.last_failed = false;
            }
            Err(_) => {
                maint.last_failed = true;
            }
        }
    }
}

async fn maintain(state: Arc<State>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        maintain_once(&state).await;
    }
}

fn background_tasks(client: Arc<Client>, state: Arc<State>) -> tokio::task::JoinSet<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..client.sources.len() {
        tasks.spawn(poll_source(client.clone(), state.clone(), index));
    }
    tasks.spawn(maintain(state));
    tasks
}

pub async fn run(args: Args) -> Result<(), Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if let Some(Action::Admin(action)) = args.action {
        return crate::mission_control::admin::run(action, |file| {
            let config = Config::load(file)
                .map_err(|_| crate::mission_control::admin::AdminError::Configuration)?;
            let issuer = config
                .mission_control
                .ok_or(crate::mission_control::admin::AdminError::Configuration)?;
            issuer
                .validate()
                .map_err(|_| crate::mission_control::admin::AdminError::Configuration)?;
            let nodes = config
                .sources
                .into_iter()
                .map(|source| source.node)
                .collect();
            Ok(issuer.authority_config(nodes))
        })
        .await
        .map_err(Error::Admin);
    }
    let config_file = args.config.ok_or(Error::Configuration)?;
    let mut config = Config::load(&config_file).map_err(|_| Error::Configuration)?;
    let tls = tls_config(&config, args.listen)?;
    let clock: crate::observe_collector_store::EpochClock =
        Arc::new(crate::storage::now_epoch_secs);
    let verifier = if config.mission_control.is_none() {
        Some(
            Verifier::new(
                config.auth.clone().ok_or(Error::Configuration)?,
                clock.clone(),
            )
            .map_err(|_| Error::Configuration)?,
        )
    } else {
        None
    };
    let client = Arc::new(Client::new(&config).map_err(|_| Error::Configuration)?);
    let policies = client
        .sources
        .iter()
        .map(|s| NodePolicy {
            node: s.node.clone(),
            labels: s.labels,
            supported: s.supported,
            relay: s.relay.clone(),
        })
        .collect();
    let directory = args.state_dir.ok_or(Error::Configuration)?;
    let mut issuer_tasks = tokio::task::JoinSet::new();
    let issuer = if let Some(settings) = config.mission_control.take() {
        use crate::mission_control::{admin, authority::Authority, Issuer};
        let nodes = config
            .sources
            .iter()
            .map(|source| source.node.clone())
            .collect();
        let authority_config = settings.authority_config(nodes);
        let prepared = Issuer::prepare(settings)
            .await
            .map_err(|_| Error::Configuration)?;
        let authority =
            Authority::open(&directory, authority_config).map_err(|_| Error::Storage)?;
        let listener = admin::bind(&directory, &authority).map_err(Error::Admin)?;
        let issuer = Issuer::start(prepared, authority.clone());
        let watchdog = authority.clone();
        issuer_tasks.spawn(async move { watchdog.watchdog().await.map_err(|_| Error::Storage) });
        issuer_tasks.spawn(async move {
            admin::serve(listener, authority)
                .await
                .map_err(Error::Admin)
        });
        Some(issuer)
    } else {
        None
    };
    let retention_secs = config.retention_after_inactive_secs;
    let store = tokio::task::spawn_blocking(move || {
        Store::open_with_retention(Path::new(&directory), policies, clock, retention_secs)
    })
    .await
    .map_err(|_| Error::Storage)?
    .map_err(Error::from)?;
    let mut nodes = client
        .sources
        .iter()
        .map(|source| source.node.clone())
        .collect::<Vec<_>>();
    nodes.sort();
    let supported_sources = client.sources.iter().filter(|s| s.supported).count();
    let initial_succ = initial_success(&store);
    let requests = issuer.as_ref().map_or_else(request_slots, |issuer| {
        Arc::new(Semaphore::new(issuer.config().pending_handshakes_global))
    });
    let read_hub = if issuer.is_some() {
        let hub = crate::mission_control::upstream::ReadHub::new().map_err(|_| Error::Storage)?;
        for view in store.view(None, 200)? {
            hub.accept_poll(view, None, true, store.epoch_now())
                .map_err(|_| Error::Storage)?;
        }
        Some(Arc::new(hub))
    } else {
        None
    };
    let state = Arc::new(State {
        verifier,
        issuer,
        read_hub,
        #[cfg(test)]
        wire_probe: None,
        store: Arc::new(store),
        store_slots: Arc::new(Semaphore::new(1)),
        requests,
        nodes,
        denied: Mutex::new(BTreeSet::new()),
        failures: Mutex::new(BTreeMap::new()),
        scopes: Mutex::new(BTreeMap::new()),
        scope_hidden: Mutex::new(BTreeSet::new()),
        success: Mutex::new(initial_succ),
        pollers_alive: Arc::new(AtomicUsize::new(0)),
        supported_sources,
        maintenance: Mutex::new(MaintenanceState::default()),
        store_slot_refusals: Arc::new(AtomicU64::new(0)),
    });
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|_| Error::Listener)?;
    let _tasks = background_tasks(client, state.clone());
    tokio::select! {
        result = serve(listener, state, tls) => result,
        exit = issuer_tasks.join_next(), if !issuer_tasks.is_empty() => {
            exit.and_then(Result::ok).unwrap_or(Err(Error::Listener))
        },
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

#[cfg(test)]
#[path = "observe_collector_tests.rs"]
mod tests;
