use crate::fed::{AuthenticatedPeer, FedState, PeersMap, RateLimiter};
use axum::body::{to_bytes, Body};
use axum::http::Request;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::Duration;
use tower::ServiceExt;

#[derive(Clone, Copy)]
enum Cache {
    Svc,
    Agy,
    Pi,
}

impl Cache {
    fn name(self) -> &'static str {
        match self {
            Self::Svc => "svc",
            Self::Agy => "agy",
            Self::Pi => "pi",
        }
    }
}

struct PostAuthFixture {
    state: Arc<FedState>,
    router: axum::Router,
    controls: Arc<crate::observe_fed::test_hooks::Controls>,
}

impl PostAuthFixture {
    fn new() -> Self {
        let pin = format!("sha256:{}", "a".repeat(64));
        let peers = Arc::new(
            PeersMap::load_from_json(
                &json!({"collector": {
                    "address":"127.0.0.1:1", "pin":pin, "allow":["observe"]
                }})
                .to_string(),
            )
            .unwrap(),
        );
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::init_db(&connection).unwrap();
        let state = Arc::new(FedState {
            node_name: "post-auth.node".into(),
            peers: peers.into(),
            cert_der: Vec::new(),
            cert_chain_der: Vec::new(),
            key_der: Vec::new(),
            rate_limiter: Arc::new(RateLimiter::new(60, 20)),
            db: Arc::new(Mutex::new(connection)),
            sessions_dirs: Vec::new(),
            agy_config: crate::agy::AgyConfig {
                presence_dir: "/synthetic-unused/presence".into(),
                proc_locks_path: "/synthetic-unused/locks".into(),
                proc_root: "/synthetic-unused/proc".into(),
                agy_bin: "unused".into(),
                trusted_agy_exes: Vec::new(),
                brain_dir: "/synthetic-unused/brain".into(),
                ..Default::default()
            },
            agy_store: crate::agy::new_agy_store(),
            pi_store: crate::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: crate::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            notify_tx: tokio::sync::broadcast::channel(16).0,
            max_body: 65536,
            max_attachment_bytes: 8 * 1024 * 1024,
            is_leaf: false,
            leaf_principal: None,
            outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
            dynamic_tls: Default::default(),
            reply_ttl: Duration::from_secs(7 * 86400),
            list_queries: Default::default(),
        });
        let router = crate::observe_fed::router(state.clone());
        let controls = crate::observe_fed::test_hooks::controls(&state);
        Self {
            state,
            router,
            controls,
        }
    }

    async fn snapshot(&self, query: &str) -> (u16, Value) {
        let peers = self.state.current_peers();
        let config = peers.get_peer_config("collector").unwrap();
        let peer = Arc::new(AuthenticatedPeer {
            leaf_authority: crate::fed::LeafAuthority {
                pin: config.pin.clone().unwrap(),
                uris: vec![],
                not_after: i64::MAX,
                mode: crate::fed::AdmissionMode::Pin,
            },
            name: config.name.clone(),
            pin: config.pin.clone().unwrap(),
            uri: None,
            certificate_has_uri: false,
            user: "fixture".into(),
            remote_ip: "127.0.0.1".parse().unwrap(),
        });
        let request = Request::builder()
            .uri(format!("/fed/v2/observe/snapshot{query}"))
            .extension(peer)
            .extension(crate::observe_fed::TlsAdmission { peers, config })
            .body(Body::empty())
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn populate(&self, cache: Cache) {
        let now = crate::storage::now_epoch_secs();
        match cache {
            Cache::Svc => {
                let mut store = self.state.svc_store.write().unwrap();
                for index in 0..300 {
                    let name = format!("service{index}");
                    store.insert(
                        name.clone(),
                        crate::svc::SvcSessionInfo {
                            session_id: name.clone(),
                            name,
                            pid: 0,
                            starttime: "fixture".into(),
                            cwd: String::new(),
                            registered_at: now,
                            token: 0,
                            liveness: None,
                        },
                    );
                }
            }
            Cache::Agy => {
                let mut store = self.state.agy_store.write().unwrap();
                for index in 0..300 {
                    let id = format!("{index:08x}-aaaa-4111-8111-111111111111");
                    store.insert(
                        id.clone(),
                        crate::agy::AgySessionInfo::new(id, 0, "fixture".into(), None),
                    );
                }
            }
            Cache::Pi => {
                let mut store = self.state.pi_store.write().unwrap();
                for index in 0..300 {
                    let id = format!("{index:08x}-bbbb-4111-8111-111111111111");
                    store.insert(
                        id.clone(),
                        crate::pi::PiSessionInfo {
                            session_id: id,
                            name: Some("fixture".into()),
                            pid: 0,
                            starttime: "fixture".into(),
                            cwd: String::new(),
                            registered_at: now,
                        },
                    );
                }
            }
        }
    }
}

fn hold_writer<T>(
    store: &RwLock<T>,
    ready: tokio::sync::oneshot::Sender<()>,
    release: mpsc::Receiver<()>,
) {
    let _guard = store.write().unwrap();
    ready.send(()).unwrap();
    release
        .recv_timeout(Duration::from_secs(7))
        .expect("fixture cache writer was not released");
}

async fn source_bound(cache: Cache) {
    let fixture = PostAuthFixture::new();
    fixture.populate(cache);
    let (status, page) = fixture.snapshot("?v=1").await;
    assert_eq!(
        status,
        200,
        "{} cache positive snapshot was refused",
        cache.name()
    );
    assert_eq!(page["available"], "partial");
    assert_eq!(page["endpoints"].as_array().unwrap().len(), 200);
    assert_eq!(page["truncated"], true);
    assert_eq!(
        fixture.controls.snapshot_candidates.load(Ordering::SeqCst),
        201,
        "{} cache source work exceeded 201 rows",
        cache.name()
    );
}

async fn nonblocking_cache(cache: Cache) {
    let fixture = PostAuthFixture::new();
    let state = fixture.state.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder = tokio::task::spawn_blocking(move || match cache {
        Cache::Svc => hold_writer(&state.svc_store, ready_tx, release_rx),
        Cache::Agy => hold_writer(&state.agy_store, ready_tx, release_rx),
        Cache::Pi => hold_writer(&state.pi_store, ready_tx, release_rx),
    });
    tokio::time::timeout(Duration::from_secs(2), ready_rx)
        .await
        .expect("fixture cache writer did not acquire its lock")
        .unwrap();
    let (status, page) = fixture.snapshot("?v=1").await;
    release_tx.send(()).unwrap();
    holder.await.unwrap();
    assert_eq!(
        status,
        200,
        "snapshot waited on {} cache write lock",
        cache.name()
    );
    assert_eq!(page["available"], "partial");
    assert_eq!(
        fixture.snapshot("?v=1").await.0,
        200,
        "released cache lock did not recover"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_rejects_unsupported_versions_after_auth() {
    let fixture = PostAuthFixture::new();
    let (status, page) = fixture.snapshot("?v=1").await;
    assert_eq!(status, 200);
    assert_eq!(page["v"], 1);
    assert_eq!(page["available"], "partial");
    assert_eq!(
        fixture.snapshot("?v=2").await.0,
        400,
        "snapshot accepted an unsupported version after authentication"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn svc_cache_source_work_is_bounded() {
    source_bound(Cache::Svc).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agy_cache_source_work_is_bounded() {
    source_bound(Cache::Agy).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pi_cache_source_work_is_bounded() {
    source_bound(Cache::Pi).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn svc_cache_read_is_nonblocking() {
    nonblocking_cache(Cache::Svc).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agy_cache_read_is_nonblocking() {
    nonblocking_cache(Cache::Agy).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pi_cache_read_is_nonblocking() {
    nonblocking_cache(Cache::Pi).await;
}
