use crate::observe_collector_auth::Verifier;
use crate::observe_collector_net::{self as net, Client, Config};
use crate::observe_collector_store::{NodePolicy, Store, StoreError, UnavailableKind};
use crate::observe_collector_web::{self as web, Filter};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(clap::Parser, Debug)]
pub struct Args {
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub state_dir: PathBuf,
    /// Web listener; non-loopback addresses require configured server TLS
    #[arg(long, default_value = "127.0.0.1:9428")]
    pub listen: SocketAddr,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid collector configuration")]
    Configuration,
    #[error("collector storage unavailable")]
    Storage,
    #[error("collector listener unavailable")]
    Listener,
}

struct State {
    verifier: Verifier,
    store: Arc<Store>,
    store_slots: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    nodes: Vec<String>,
    denied: Mutex<BTreeSet<String>>,
    scopes: Mutex<BTreeMap<String, String>>,
    scope_hidden: Mutex<BTreeSet<String>>,
}

async fn store_call<T: Send + 'static>(
    store: Arc<Store>,
    slots: Arc<Semaphore>,
    call: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    let lease = slots.try_acquire_owned().map_err(|_| StoreError::Storage)?;
    tokio::task::spawn_blocking(move || {
        // Keep admission while SQLite finishes even if its caller's deadline expires.
        let _lease = lease;
        call(&store)
    })
    .await
    .map_err(|_| StoreError::Storage)?
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
        let _owner = match self.verifier.authorize(request.headers()).await {
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
        let selected = filter.node.map(|index| self.nodes[index].clone());
        let result = store_call(self.store.clone(), self.store_slots.clone(), move |store| {
            let mut summaries = store.view(None, 0)?;
            for node in &mut summaries {
                node.latest_snapshot = None;
            }
            let detail = selected
                .map(|node| store.view(Some(&node), filter.read_limit()))
                .transpose()?
                .and_then(|mut views| views.pop());
            Ok((summaries, detail))
        })
        .await;
        match result {
            Ok((mut summaries, mut detail)) => {
                if let Ok(denied) = self.denied.lock() {
                    for view in summaries.iter_mut().chain(detail.iter_mut()) {
                        if denied.contains(&view.node) {
                            view.history_hidden = true;
                            view.status = crate::observe_collector_store::NodeStatus::Denied;
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
                            view.status = crate::observe_collector_store::NodeStatus::HiddenPendingRevalidation;
                            view.events.clear();
                            view.latest_snapshot = None;
                            view.cursor = None;
                            view.gaps.clear();
                        }
                    }
                    response(
                        StatusCode::OK,
                        web::render(&summaries, detail.as_ref(), filter),
                        true,
                    )
                } else {
                    response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "collector unavailable\n",
                        false,
                    )
                }
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
                let (tcp, _) = accepted.map_err(|_| Error::Listener)?;
                let Ok(lease) = connections.clone().try_acquire_owned() else { drop(tcp); continue };
                let state = state.clone();
                let tls = tls.clone();
                tasks.spawn(async move {
                    let _lease = lease;
                    if let Some(tls) = tls {
                        if let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(5), tls.accept(tcp)).await {
                            serve_stream(stream, state).await;
                        }
                    } else { serve_stream(tcp, state).await; }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

const WEB_BUDGET: Duration = Duration::from_secs(5);

async fn serve_stream<I>(stream: I, state: Arc<State>)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    serve_http(stream, state.requests.clone(), move |request| async move {
        state.prepare(request).await
    })
    .await;
}

async fn serve_http<I, F, Fut>(stream: I, requests: Arc<Semaphore>, prepare: F)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(Request<Incoming>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
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
            let deadline = tokio::time::Instant::now() + WEB_BUDGET;
            let Some((admission, prepare)) = operation else {
                return Ok::<_, Infallible>(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "collector unavailable\n",
                    false,
                ));
            };
            if admission.send((deadline, lease)).is_err() {
                return Ok::<_, Infallible>(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "collector unavailable\n",
                    false,
                ));
            }
            let response = if admitted {
                prepare(request).await
            } else {
                response(StatusCode::SERVICE_UNAVAILABLE, "collector busy\n", false)
            };
            Ok::<_, Infallible>(response)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(false)
        .max_buf_size(16 * 1024)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5));
    let connection = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
    tokio::pin!(connection);
    let admission = tokio::select! {
        _ = &mut connection => return,
        admission = admission_rx => admission,
    };
    if let Ok((deadline, lease)) = admission {
        // HTTP keepalive is disabled, so this lease and deadline cover the one response's flush.
        let _lease = lease;
        let _ = tokio::time::timeout_at(deadline, connection).await;
    }
}

async fn mark_error(state: &State, node: String, error: net::Error) {
    if error == net::Error::Denied {
        if let Ok(mut denied) = state.denied.lock() {
            denied.insert(node.clone());
        }
    }
    let _ = store_call(
        state.store.clone(),
        state.store_slots.clone(),
        move |store| {
            if error == net::Error::Denied {
                return store.deny(&node);
            }
            let kind = match error {
                net::Error::Unsupported => UnavailableKind::Unsupported,
                net::Error::Timeout => UnavailableKind::Timeout,
                net::Error::Malformed => UnavailableKind::Malformed,
                net::Error::RateLimited(_) => UnavailableKind::RateLimited,
                _ => UnavailableKind::Unreachable,
            };
            store.unavailable(&node, kind)
        },
    )
    .await;
}

async fn mark_storage_error(state: &State, node: String, error: StoreError) {
    let kind = if error == StoreError::Full {
        UnavailableKind::StorageFull
    } else {
        UnavailableKind::Malformed
    };
    let _ = store_call(
        state.store.clone(),
        state.store_slots.clone(),
        move |store| store.unavailable(&node, kind),
    )
    .await;
}

fn observe_scope(state: &State, node: &str, scope: &str) {
    if scope.len() != 64 || !scope.bytes().all(|b| b.is_ascii_hexdigit()) {
        return;
    }
    if let Ok(scopes) = state.scopes.lock() {
        if scopes.get(node).is_some_and(|old| old != scope) {
            if let Ok(mut hidden) = state.scope_hidden.lock() {
                hidden.insert(node.to_owned());
            }
        }
    }
}

fn accepted_scope(state: &State, node: &str, scope: String) {
    if let Ok(mut scopes) = state.scopes.lock() {
        scopes.insert(node.to_owned(), scope);
    }
    if let Ok(mut hidden) = state.scope_hidden.lock() {
        hidden.remove(node);
    }
    if let Ok(mut denied) = state.denied.lock() {
        denied.remove(node);
    }
}

async fn poll_source(client: Arc<Client>, state: Arc<State>, index: usize) {
    let source = &client.sources[index];
    if !source.supported {
        return;
    }
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
                    let scope = snapshot.scope.clone();
                    observe_scope(&state, &source.node, &scope);
                    let node = source.node.clone();
                    if let Err(error) = store_call(
                        state.store.clone(),
                        state.store_slots.clone(),
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
            if let Ok(cursor) = store_call(
                state.store.clone(),
                state.store_slots.clone(),
                move |store| store.cursor(&node),
            )
            .await
            {
                match client
                    .events_decoded(
                        index,
                        cursor.epoch.as_deref(),
                        cursor.scope.as_deref(),
                        cursor.next,
                    )
                    .await
                {
                    Ok(page) => {
                        let scope = page.page.scope.clone();
                        observe_scope(&state, &source.node, &scope);
                        let has_more = page.page.has_more;
                        let node = source.node.clone();
                        match store_call(
                            state.store.clone(),
                            state.store_slots.clone(),
                            move |store| store.ingest_decoded_page(&node, &cursor, page),
                        )
                        .await
                        {
                            Ok(_) => {
                                backfill = has_more;
                                accepted_scope(&state, &source.node, scope);
                            }
                            Err(error) => {
                                mark_storage_error(&state, source.node.clone(), error).await
                            }
                        }
                    }
                    Err(error) => {
                        failure = Some(error);
                    }
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
        tokio::time::sleep_until(next_start).await;
    }
}

async fn maintain(state: Arc<State>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let _ = store_call(state.store.clone(), state.store_slots.clone(), |store| {
            store.maintain()
        })
        .await;
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
    let config = Config::load(&args.config).map_err(|_| Error::Configuration)?;
    let tls = tls_config(&config, args.listen)?;
    let clock: crate::observe_collector_store::EpochClock =
        Arc::new(crate::storage::now_epoch_secs);
    let verifier =
        Verifier::new(config.auth.clone(), clock.clone()).map_err(|_| Error::Configuration)?;
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
    let directory = args.state_dir;
    let store =
        tokio::task::spawn_blocking(move || Store::open(Path::new(&directory), policies, clock))
            .await
            .map_err(|_| Error::Storage)?
            .map_err(|_| Error::Storage)?;
    let mut nodes = client
        .sources
        .iter()
        .map(|source| source.node.clone())
        .collect::<Vec<_>>();
    nodes.sort();
    let state = Arc::new(State {
        verifier,
        store: Arc::new(store),
        store_slots: Arc::new(Semaphore::new(1)),
        requests: request_slots(),
        nodes,
        denied: Mutex::new(BTreeSet::new()),
        scopes: Mutex::new(BTreeMap::new()),
        scope_hidden: Mutex::new(BTreeSet::new()),
    });
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|_| Error::Listener)?;
    let _tasks = background_tasks(client, state.clone());
    tokio::select! {
        result = serve(listener, state, tls) => result,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

#[cfg(test)]
#[path = "observe_collector_tests.rs"]
mod tests;
