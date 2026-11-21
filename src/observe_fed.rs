use crate::error::AppError;
use crate::fed::{AuthenticatedPeer, FedState, PeerConfig, PeersMap};
use crate::observe_export::{ExportQuery, Scope, SnapshotQuery};
use axum::extract::{Query, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

const MAX_QUERY: usize = 1024;
const MAX_READS: usize = 8;

pub(crate) fn read_slots(fed: &Arc<FedState>) -> Arc<Semaphore> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock, Weak};
    type Budgets = HashMap<usize, (Weak<FedState>, Weak<Semaphore>)>;
    static BUDGETS: OnceLock<Mutex<Budgets>> = OnceLock::new();
    let mut budgets = BUDGETS.get_or_init(Mutex::default).lock().unwrap();
    budgets.retain(|_, (fed, slots)| fed.strong_count() > 0 && slots.strong_count() > 0);
    let key = Arc::as_ptr(fed) as usize;
    if let Some(slots) = budgets.get(&key).and_then(|(_, slots)| slots.upgrade()) {
        return slots;
    }
    let slots = Arc::new(Semaphore::new(MAX_READS));
    budgets.insert(key, (Arc::downgrade(fed), Arc::downgrade(&slots)));
    slots
}
const REQUEST_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct TlsAdmission {
    pub(crate) peers: Arc<PeersMap>,
    pub(crate) config: PeerConfig,
}

struct ExportState {
    fed: Arc<FedState>,
    slots: Arc<Semaphore>,
    #[cfg(any(test, feature = "test-hooks"))]
    controls: Arc<test_hooks::Controls>,
}

struct Admission {
    peers: Arc<PeersMap>,
    peer: String,
    config: PeerConfig,
}

fn denied() -> AppError {
    AppError::Denied("observation requires an authenticated explicit observe grant".into())
}

fn unavailable() -> AppError {
    AppError::ServiceUnavailable("observation export unavailable".into())
}

fn bad_query() -> AppError {
    AppError::BadRequest("invalid observation export query or body".into())
}

fn admit(state: &ExportState, request: &Request) -> Result<Admission, AppError> {
    let peer = request
        .extensions()
        .get::<Arc<AuthenticatedPeer>>()
        .ok_or_else(denied)?;
    let tls = request
        .extensions()
        .get::<TlsAdmission>()
        .ok_or_else(denied)?;
    let peers = state.fed.current_peers();
    if !Arc::ptr_eq(&tls.peers, &peers) {
        return Err(denied());
    }
    let config = tls.config.clone();
    if config.name != peer.name {
        return Err(denied());
    }
    if !config.allow.iter().any(|right| right == "observe") {
        return Err(denied());
    }
    crate::fed::check_peer_source(&config, &peer.remote_ip).map_err(|_| denied())?;
    if !state
        .fed
        .rate_limiter
        .check_and_consume(&format!("observe:{}", peer.name), None)
    {
        return Err(AppError::RateLimited(
            "observation export rate limited".into(),
        ));
    }
    Ok(Admission {
        peers,
        peer: peer.name.clone(),
        config,
    })
}

fn query_shape(request: &Request) -> Result<(), AppError> {
    if request.uri().query().unwrap_or_default().len() > MAX_QUERY
        || request.headers().contains_key("transfer-encoding")
        || request
            .headers()
            .get("content-length")
            .is_some_and(|value| value.to_str().ok() != Some("0"))
    {
        return Err(bad_query());
    }
    Ok(())
}

fn current(state: &ExportState, admission: &Admission) -> Result<(), AppError> {
    if !Arc::ptr_eq(&state.fed.current_peers(), &admission.peers) {
        return Err(denied());
    }
    Ok(())
}

pub(crate) fn router(fed: Arc<FedState>) -> Router {
    let state = Arc::new(ExportState {
        #[cfg(any(test, feature = "test-hooks"))]
        controls: test_hooks::controls(&fed),
        slots: read_slots(&fed),
        fed,
    });
    Router::new()
        .route("/fed/v2/observe/events", get(events))
        .route("/fed/v2/observe/snapshot", get(snapshot))
        .with_state(state)
}

async fn events(State(state): State<Arc<ExportState>>, request: Request) -> Response {
    match tokio::time::timeout(REQUEST_BUDGET, events_inner(state, request)).await {
        Ok(result) => result.unwrap_or_else(IntoResponse::into_response),
        Err(_) => unavailable().into_response(),
    }
}

async fn events_inner(state: Arc<ExportState>, request: Request) -> Result<Response, AppError> {
    let admission = admit(&state, &request)?;
    query_shape(&request)?;
    let Query(query) =
        Query::<ExportQuery>::try_from_uri(request.uri()).map_err(|_| bad_query())?;
    query.validate().map_err(|_| bad_query())?;
    let scope = Scope::new(
        &state.fed.node_name,
        &admission.peer,
        admission.config.targets.as_deref(),
        query.labels && admission.config.observe_labels,
    )
    .map_err(|_| unavailable())?;
    let journal_query = query.journal_query(&scope).map_err(|_| bad_query())?;
    let reservation = state.slots.clone().try_acquire_owned();
    #[cfg(any(test, feature = "test-hooks"))]
    state.controls.read_decision(reservation.is_ok());
    let slot = reservation.map_err(|_| AppError::RateLimited("observation export busy".into()))?;
    #[cfg(any(test, feature = "test-hooks"))]
    state.controls.before_read.pause().await;
    let observer = crate::observe::for_db(&state.fed.db).ok_or_else(unavailable)?;
    #[cfg(any(test, feature = "test-hooks"))]
    let controls = state.controls.clone();
    let page = tokio::task::spawn_blocking(move || {
        #[cfg(any(test, feature = "test-hooks"))]
        let _completion = test_hooks::Completion(controls.clone());
        let _slot = slot;
        #[cfg(any(test, feature = "test-hooks"))]
        controls.before_io.pause_blocking();
        let source = observer.page(journal_query).map_err(|_| unavailable())?;
        crate::observe_export::project_page(
            source,
            &query,
            &scope,
            crate::storage::now_epoch_secs(),
        )
        .map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())??;
    let response = Json(page).into_response();
    #[cfg(any(test, feature = "test-hooks"))]
    state.controls.before_emit.pause().await;
    current(&state, &admission)?;
    Ok(response)
}

async fn snapshot(State(state): State<Arc<ExportState>>, request: Request) -> Response {
    match tokio::time::timeout(REQUEST_BUDGET, snapshot_inner(state, request)).await {
        Ok(result) => result.unwrap_or_else(IntoResponse::into_response),
        Err(_) => unavailable().into_response(),
    }
}

async fn snapshot_inner(state: Arc<ExportState>, request: Request) -> Result<Response, AppError> {
    let admission = admit(&state, &request)?;
    query_shape(&request)?;
    let Query(query) =
        Query::<SnapshotQuery>::try_from_uri(request.uri()).map_err(|_| bad_query())?;
    query.validate().map_err(|_| bad_query())?;
    let scope = Scope::new(
        &state.fed.node_name,
        &admission.peer,
        admission.config.targets.as_deref(),
        query.labels && admission.config.observe_labels,
    )
    .map_err(|_| unavailable())?;
    let reservation = state.slots.clone().try_acquire_owned();
    #[cfg(any(test, feature = "test-hooks"))]
    state.controls.read_decision(reservation.is_ok());
    let slot = reservation.map_err(|_| AppError::RateLimited("observation export busy".into()))?;
    #[cfg(any(test, feature = "test-hooks"))]
    state.controls.before_read.pause().await;
    let reader = state.fed.clone();
    #[cfg(any(test, feature = "test-hooks"))]
    let controls = state.controls.clone();
    let page = tokio::task::spawn_blocking(move || {
        #[cfg(any(test, feature = "test-hooks"))]
        let _completion = test_hooks::Completion(controls.clone());
        let _slot = slot;
        #[cfg(any(test, feature = "test-hooks"))]
        controls.before_io.pause_blocking();
        let (records, partial) = crate::observe_snapshot::collect(&reader);
        crate::observe_export::project_snapshot(
            &scope,
            records,
            crate::storage::now_epoch_secs(),
            partial,
        )
        .map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())??;
    let response = Json(page).into_response();
    #[cfg(any(test, feature = "test-hooks"))]
    state.controls.before_emit.pause().await;
    current(&state, &admission)?;
    Ok(response)
}

#[cfg(any(test, feature = "test-hooks"))]
pub mod test_hooks {
    use crate::fed::FedState;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock, Weak};
    use tokio::sync::Notify;

    #[derive(Default)]
    struct GateState {
        remaining: usize,
        arrived: usize,
        released: bool,
    }

    #[derive(Default)]
    pub struct Gate {
        state: Mutex<GateState>,
        changed: Notify,
        wake: std::sync::Condvar,
    }

    impl Gate {
        pub fn arm(&self, count: usize) {
            *self.state.lock().unwrap() = GateState {
                remaining: count,
                arrived: 0,
                released: false,
            };
        }

        pub async fn wait_for(&self, count: usize) {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.state.lock().unwrap().arrived >= count {
                    return;
                }
                changed.await;
            }
        }

        pub fn release(&self) {
            self.state.lock().unwrap().released = true;
            self.changed.notify_waiters();
            self.wake.notify_all();
        }

        pub(crate) fn pause_blocking(&self) {
            let mut state = self.state.lock().unwrap();
            if state.remaining == 0 {
                return;
            }
            state.remaining -= 1;
            state.arrived += 1;
            self.changed.notify_waiters();
            let (state, _) = self
                .wake
                .wait_timeout_while(state, std::time::Duration::from_secs(10), |state| {
                    !state.released
                })
                .unwrap();
            assert!(state.released, "blocking fixture gate was not released");
        }

        pub(crate) async fn pause(&self) {
            {
                let mut state = self.state.lock().unwrap();
                if state.remaining == 0 {
                    return;
                }
                state.remaining -= 1;
                state.arrived += 1;
            }
            self.changed.notify_waiters();
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.state.lock().unwrap().released {
                    return;
                }
                changed.await;
            }
        }
    }

    #[derive(Default)]
    pub struct Signal {
        count: std::sync::atomic::AtomicUsize,
        changed: Notify,
    }

    impl Signal {
        pub(crate) fn record(&self) {
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            self.changed.notify_waiters();
        }

        pub async fn wait_for(&self, count: usize) {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.count.load(std::sync::atomic::Ordering::Acquire) >= count {
                    return;
                }
                changed.await;
            }
        }

        pub fn count(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    #[derive(Default)]
    pub struct Controls {
        pub snapshot_candidates: std::sync::atomic::AtomicUsize,
        pub read_admissions: std::sync::atomic::AtomicUsize,
        pub read_decisions: std::sync::atomic::AtomicUsize,
        pub workers_done: Gate,
        pub before_handshake: Gate,
        pub before_read: Gate,
        pub before_io: Gate,
        pub before_emit: Gate,
        pub listener_ready: Signal,
        pub tls_handshake_done: Signal,
        pub tls_handshake_refusals: Signal,
    }
    impl Controls {
        pub(crate) fn read_decision(&self, admitted: bool) {
            if admitted {
                self.read_admissions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            self.read_decisions
                .fetch_add(1, std::sync::atomic::Ordering::Release);
        }
    }

    pub(crate) struct Completion(pub(crate) Arc<Controls>);

    impl Drop for Completion {
        fn drop(&mut self) {
            self.0.workers_done.state.lock().unwrap().arrived += 1;
            self.0.workers_done.changed.notify_waiters();
        }
    }

    pub fn controls(fed: &Arc<FedState>) -> Arc<Controls> {
        static CONTROLS: OnceLock<Mutex<HashMap<usize, Weak<Controls>>>> = OnceLock::new();
        let mut controls = CONTROLS.get_or_init(Mutex::default).lock().unwrap();
        controls.retain(|_, value| value.strong_count() > 0);
        let key = Arc::as_ptr(fed) as usize;
        if let Some(value) = controls.get(&key).and_then(Weak::upgrade) {
            return value;
        }
        let value = Arc::new(Controls::default());
        controls.insert(key, Arc::downgrade(&value));
        value
    }
}
