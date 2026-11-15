use super::*;

#[test]
fn cli_has_a_separate_loopback_default() {
    use clap::Parser;
    let args = Args::try_parse_from([
        "observe-collector",
        "--config",
        "fixture.json",
        "--state-dir",
        "state",
    ])
    .unwrap();
    assert_eq!(args.listen, "127.0.0.1:9428".parse::<SocketAddr>().unwrap());
}
#[test]
fn fixed_response_policy_and_health_contain_no_metadata() {
    let reply = response(StatusCode::OK, "available\n", false);
    assert_eq!(
        reply.headers()["cache-control"],
        "no-store",
        "response caching enabled"
    );
    assert_eq!(
        reply.headers()["x-content-type-options"],
        "nosniff",
        "response sniffing enabled"
    );
    assert_eq!(
        reply.headers()["content-security-policy"],
        web::content_security_policy(),
        "response CSP omitted"
    );
}

use crate::observe_collector_auth::AuthConfig;
use crate::observe_export::{ExportSnapshot, SnapshotAvailability};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    state: Arc<State>,
    url: String,
    idp_calls: Arc<AtomicUsize>,
    active: Arc<AtomicBool>,
    hold_idp: Arc<AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    files: tempfile::TempDir,
    config: Config,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Fixture {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let files = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(files.path().join("cert.pem"), cert.cert.pem()).unwrap();
        std::fs::write(
            files.path().join("key.pem"),
            cert.signing_key.serialize_pem(),
        )
        .unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let idp_calls = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicBool::new(true));
        let hold_idp = Arc::new(AtomicBool::new(false));
        let (calls, status, hold) = (idp_calls.clone(), active.clone(), hold_idp.clone());
        let idp_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp,_) = accepted.unwrap();
                        let (tls,calls,status,hold) = (tls.clone(),calls.clone(),status.clone(),hold.clone());
                        tasks.spawn(async move {
                            let Ok(tls) = tls.accept(tcp).await else { return };
                            let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                                assert_eq!(request.uri().path(),"/introspect");
                                let (calls,status,hold) = (calls.clone(),status.clone(),hold.clone());
                                async move {
                                    calls.fetch_add(1,Ordering::SeqCst);
                                    while hold.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
                                    let body = json!({"active":status.load(Ordering::SeqCst),"iss":"https://owner.invalid","sub":"owner","aud":"collector","client_id":"hosted","exp":2000}).to_string();
                                    Ok::<_,Infallible>(Response::new(Full::new(Bytes::from(body))))
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls),service).await;
                        });
                    }
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        let config = Config {
            client_cert: files.path().join("cert.pem"),
            client_key: files.path().join("key.pem"),
            auth: AuthConfig {
                issuer: "https://owner.invalid".into(),
                introspection_url: format!("https://localhost:{}/introspect", address.port()),
                subjects: vec!["owner".into()],
                audience: "collector".into(),
                hosted_client: "hosted".into(),
                lookup_client: None,
                lookup_secret_file: None,
                provider_ca: Some(files.path().join("cert.pem")),
            },
            sources: vec![],
            web_tls: None,
        };
        let clock: crate::observe_collector_store::EpochClock = Arc::new(|| 1000);
        let store = Arc::new(
            Store::open(
                &files.path().join("state"),
                vec![NodePolicy {
                    node: "fixture.node".into(),
                    labels: true,
                    supported: true,
                }],
                clock.clone(),
            )
            .unwrap(),
        );
        let snapshot = ExportSnapshot {
            v: 1,
            node: "fixture.node".into(),
            scope: "a".repeat(64),
            observed_at: 1000,
            endpoints: vec![],
            truncated: false,
            available: SnapshotAvailability::Available,
        };
        store.ingest_snapshot("fixture.node", snapshot).unwrap();
        let state = Arc::new(State {
            verifier: Verifier::new(config.auth.clone(), clock).unwrap(),
            store,
            store_slots: Arc::new(Semaphore::new(1)),
            requests: Arc::new(Semaphore::new(8)),
            nodes: vec!["fixture.node".into()],
            denied: Mutex::new(BTreeSet::new()),
            scopes: Mutex::new(BTreeMap::from([("fixture.node".into(), "a".repeat(64))])),
            scope_hidden: Mutex::new(BTreeSet::new()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let serving = state.clone();
        let web_task = tokio::spawn(async move {
            serve(listener, serving, None).await.unwrap();
        });
        Self {
            state,
            url,
            idp_calls,
            active,
            hold_idp,
            tasks: vec![idp_task, web_task],
            files,
            config,
        }
    }
    fn get(&self, suffix: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .get(format!("{}{suffix}", self.url))
            .bearer_auth("synthetic-owner-fixture")
    }
}

async fn eventually(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn backend_reauthorizes_and_health_has_no_cache_data() {
    let fixture = Fixture::new().await;
    let reply = fixture.get("/?node=0").send().await.unwrap();
    assert_eq!(reply.status(), 200);
    assert!(reply.text().await.unwrap().contains("fixture.node"));
    fixture.active.store(false, Ordering::SeqCst);
    let reply = fixture.get("/?node=0").send().await.unwrap();
    assert_eq!(
        reply.status(),
        401,
        "inactive next request reached cached history"
    );
    assert!(!reply.text().await.unwrap().contains("fixture.node"));
    assert_eq!(
        fixture.idp_calls.load(Ordering::SeqCst),
        2,
        "backend reused owner authorization"
    );
    let reply = reqwest::Client::new()
        .get(format!("{}/?node=0", fixture.url))
        .header("x-auth-request-user", "owner")
        .header("x-forwarded-user", "owner")
        .send()
        .await
        .unwrap();
    assert_eq!(
        reply.status(),
        401,
        "forged ingress identity reached cached history"
    );
    assert!(!reply.text().await.unwrap().contains("fixture.node"));
    let held = fixture
        .state
        .store_slots
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let reply = reqwest::Client::new()
        .get(format!("{}/health", fixture.url))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(
        reply.text().await.unwrap(),
        "available\n",
        "health exposed metadata"
    );
    drop(held);
}
#[tokio::test]
async fn all_metadata_routes_require_owner_and_strict_filters() {
    let fixture = Fixture::new().await;
    for suffix in [
        "/?node=http://attacker.invalid",
        "/?address=1",
        "/?node=0&page=50",
    ] {
        let reply = fixture.get(suffix).send().await.unwrap();
        assert_eq!(reply.status(), 400, "browser network authority accepted");
        assert!(!reply.text().await.unwrap().contains("fixture.node"));
    }
    assert_eq!(fixture.get("/body").send().await.unwrap().status(), 404);
    assert_eq!(
        reqwest::Client::new()
            .post(format!("{}/", fixture.url))
            .bearer_auth("synthetic-owner-fixture")
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    assert_eq!(
        fixture.idp_calls.load(Ordering::SeqCst),
        5,
        "route bypassed owner verification"
    );
}
#[tokio::test]
async fn request_saturation_has_no_admission_waiters() {
    let fixture = Fixture::new().await;
    fixture.hold_idp.store(true, Ordering::SeqCst);
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let request = fixture.get("/");
        requests.spawn(async move { request.send().await.unwrap().status() });
    }
    eventually(|| fixture.idp_calls.load(Ordering::SeqCst) == 8).await;
    let reply = fixture.get("/").send().await.unwrap();
    assert_eq!(reply.status(), 503, "web request admission exceeded eight");
    assert!(!reply.text().await.unwrap().contains("fixture.node"));
    assert_eq!(
        fixture.idp_calls.load(Ordering::SeqCst),
        8,
        "saturated request entered owner lookup queue"
    );
    fixture.hold_idp.store(false, Ordering::SeqCst);
    while let Some(result) = requests.join_next().await {
        assert!([StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE].contains(&result.unwrap()));
    }
    assert_eq!(fixture.get("/").send().await.unwrap().status(), 200);
}
#[tokio::test]
async fn store_lease_outlives_cancelled_read_without_waiter_growth() {
    let fixture = Fixture::new().await;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let work = store_call(
        fixture.state.store.clone(),
        fixture.state.store_slots.clone(),
        move |_| {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        },
    );
    let task = tokio::spawn(work);
    started_rx.await.unwrap();
    task.abort();
    assert_eq!(
        fixture.state.store_slots.available_permits(),
        0,
        "cancelled SQLite work released its lease early"
    );
    assert!(
        store_call(
            fixture.state.store.clone(),
            fixture.state.store_slots.clone(),
            |_| Ok(())
        )
        .await
        .is_err(),
        "SQLite work gained an unbounded wait queue"
    );
    release_tx.send(()).unwrap();
    eventually(|| fixture.state.store_slots.available_permits() == 1).await;
    assert!(store_call(
        fixture.state.store.clone(),
        fixture.state.store_slots.clone(),
        |_| Ok(())
    )
    .await
    .is_ok());
}
#[tokio::test]
async fn denial_masks_before_busy_or_failed_purge() {
    let fixture = Fixture::new().await;
    let held = fixture
        .state
        .store_slots
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    mark_error(&fixture.state, "fixture.node".into(), net::Error::Denied).await;
    assert!(
        fixture
            .state
            .denied
            .lock()
            .unwrap()
            .contains("fixture.node"),
        "denial mask lost while storage busy"
    );
    drop(held);
    let reply = fixture.get("/?node=0").send().await.unwrap();
    let html = reply.text().await.unwrap();
    assert!(html.contains("denied"), "denial availability lost");
    assert!(html.contains("history hidden until this node answers"));
    assert!(
        !html.contains("Latest source inventory"),
        "denied node leaked retained snapshot"
    );
}
#[tokio::test]
async fn nonloopback_listener_requires_tls_and_tls_keeps_owner_boundary() {
    let mut fixture = Fixture::new().await;
    assert!(tls_config(&fixture.config, "127.0.0.1:0".parse().unwrap())
        .unwrap()
        .is_none());
    assert!(
        tls_config(&fixture.config, "0.0.0.0:0".parse().unwrap()).is_err(),
        "public plaintext listener accepted"
    );
    fixture.config.web_tls = Some(net::WebTls {
        cert: fixture.files.path().join("cert.pem"),
        key: fixture.files.path().join("key.pem"),
    });
    let tls = tls_config(&fixture.config, "0.0.0.0:0".parse().unwrap()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = fixture.state.clone();
    fixture.tasks.push(tokio::spawn(async move {
        serve(listener, state, tls).await.unwrap();
    }));
    let root = reqwest::Certificate::from_pem(
        &std::fs::read(fixture.files.path().join("cert.pem")).unwrap(),
    )
    .unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(root)
        .build()
        .unwrap();
    let url = format!("https://localhost:{port}/?node=0");
    assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
    assert_eq!(
        client
            .get(url)
            .bearer_auth("synthetic-owner-fixture")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}
#[tokio::test]
async fn oversized_headers_refuse_before_owner_lookup() {
    let fixture = Fixture::new().await;
    let reply = fixture
        .get("/")
        .header("x-large", "x".repeat(17 * 1024))
        .send()
        .await;
    assert!(
        reply.is_err() || reply.unwrap().status().is_client_error(),
        "oversized web headers accepted"
    );
    assert_eq!(fixture.idp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.get("/").send().await.unwrap().status(), 200);
}

#[tokio::test]
async fn scope_change_masks_before_busy_ingest() {
    let fixture = Fixture::new().await;
    let held = fixture
        .state
        .store_slots
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    observe_scope(&fixture.state, "fixture.node", &"b".repeat(64));
    assert!(
        fixture
            .state
            .scope_hidden
            .lock()
            .unwrap()
            .contains("fixture.node"),
        "scope mask lost while storage busy"
    );
    drop(held);
    let html = fixture
        .get("/?node=0")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("history hidden until this node answers"));
    assert!(
        !html.contains("Latest source inventory"),
        "old scope snapshot leaked before durable replacement"
    );
    accepted_scope(&fixture.state, "fixture.node", "b".repeat(64));
    assert!(!fixture
        .state
        .scope_hidden
        .lock()
        .unwrap()
        .contains("fixture.node"));
}
