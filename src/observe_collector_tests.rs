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
    idp_claims: Arc<Mutex<serde_json::Value>>,
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
        Self::with_relay(false).await
    }
    async fn with_relay(relay: bool) -> Self {
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
        let idp_claims = Arc::new(Mutex::new(
            json!({"active":true,"iss":"https://owner.invalid","sub":"owner","aud":"collector","client_id":"hosted","exp":2000}),
        ));
        let returned_claims = idp_claims.clone();
        let (calls, status, hold) = (idp_calls.clone(), active.clone(), hold_idp.clone());
        let idp_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp,_) = accepted.unwrap();
                        let (tls,calls,status,hold,claims) = (tls.clone(),calls.clone(),status.clone(),hold.clone(),returned_claims.clone());
                        tasks.spawn(async move {
                            let Ok(tls) = tls.accept(tcp).await else { return };
                            let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                                assert_eq!(request.uri().path(),"/introspect");
                                let (calls,status,hold,claims) = (calls.clone(),status.clone(),hold.clone(),claims.clone());
                                async move {
                                    calls.fetch_add(1,Ordering::SeqCst);
                                    while hold.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
                                    let mut body = claims.lock().unwrap().clone();
                                    body["active"] = json!(status.load(Ordering::SeqCst));
                                    let body = body.to_string();
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
                    relay: relay.then(|| crate::observe_collector_store::RelayOrigin {
                        hub: "spiffe://fleet/host/hub/user/owner".into(),
                        leaf: "spiffe://fleet/ns/node/sa/fixture".into(),
                    }),
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
            requests: request_slots(),
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
            idp_claims,
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
        "web request admission exceeded eight"
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
    let _ = task.await;
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

#[tokio::test]
async fn connection_saturation_refuses_without_an_accept_waiter() {
    let mut fixture = Fixture::new().await;
    let slots = connection_slots();
    assert_eq!(
        slots.available_permits(),
        64,
        "web connection reservation exceeded 64"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (state, admission) = (fixture.state.clone(), slots.clone());
    fixture.tasks.push(tokio::spawn(async move {
        serve_with_admission(listener, state, None, admission)
            .await
            .unwrap();
    }));
    let mut held = Vec::new();
    for _ in 0..63 {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(b"GET /health HTTP/1.1\r\n").await.unwrap();
        held.push(stream);
    }
    eventually(|| slots.available_permits() == 1).await;
    let mut last = tokio::net::TcpStream::connect(address).await.unwrap();
    last.write_all(b"GET /health HTTP/1.1\r\n").await.unwrap();
    held.push(last);
    eventually(|| slots.available_permits() == 0).await;
    eprintln!("forced accept transition: 63 occupied then 64 occupied");
    assert_eq!(
        slots.available_permits(),
        0,
        "web connection reservation exceeded 64"
    );
    let mut excess = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "saturated connection was queued instead of refused"
    );
    drop(held);
    eventually(|| slots.available_permits() == 64).await;
    assert_eq!(fixture.get("/").send().await.unwrap().status(), 200);
}
#[tokio::test]
async fn slow_headers_have_a_finite_read_deadline() {
    let fixture = Fixture::new().await;
    let address = fixture.url.strip_prefix("http://").unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nAuthorization: Bearer ")
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let mut bytes = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_millis(6500), stream.read_to_end(&mut bytes)).await;
    assert!(
        read.is_ok(),
        "slow request headers escaped their read deadline"
    );
    assert!(started.elapsed() < Duration::from_millis(6200));
    assert_eq!(
        fixture.idp_calls.load(Ordering::SeqCst),
        0,
        "partial headers reached provider"
    );
}

#[tokio::test]
async fn aggregate_header_accounting_has_an_exact_control() {
    let fixture = Fixture::new().await;
    let request = Request::builder()
        .uri("/health")
        .header("x-fixture", "x".repeat(16 * 1024 - 13))
        .body(())
        .unwrap();
    assert_eq!(fixture.state.prepare(request).await.status(), 200);
    let request = Request::builder()
        .uri("/health")
        .header("x-fixture", "x".repeat(16 * 1024 - 12))
        .body(())
        .unwrap();
    assert_eq!(
        fixture.state.prepare(request).await.status(),
        431,
        "aggregate web header cap bypassed"
    );
    assert_eq!(fixture.idp_calls.load(Ordering::SeqCst), 0);
}

struct BackpressureIo {
    stream: tokio::io::DuplexStream,
    blocked: Arc<AtomicBool>,
}
impl tokio::io::AsyncRead for BackpressureIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for BackpressureIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.stream).poll_write(cx, bytes);
        if result.is_pending() {
            self.blocked.store(true, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
async fn duplex_request(
    fixture: &Fixture,
) -> (
    tokio::io::DuplexStream,
    tokio::task::JoinHandle<()>,
    Arc<AtomicBool>,
) {
    let (mut client, server) = tokio::io::duplex(64);
    let blocked = Arc::new(AtomicBool::new(false));
    let io = BackpressureIo {
        stream: server,
        blocked: blocked.clone(),
    };
    let state = fixture.state.clone();
    let task = tokio::spawn(async move {
        serve_stream(io, state).await;
    });
    client.write_all(b"GET /?node=0 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-owner-fixture\r\n\r\n").await.unwrap();
    (client, task, blocked)
}

#[tokio::test]
async fn admitted_read_deadline_includes_backpressured_delivery() {
    let fixture = Fixture::new().await;
    let (mut draining, positive, _) = duplex_request(&fixture).await;
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), draining.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    positive.await.unwrap();
    assert!(
        String::from_utf8(bytes).unwrap().contains("fixture.node"),
        "draining delivery positive control failed"
    );
    let (_stalled, mut task, blocked) = duplex_request(&fixture).await;
    eventually(|| blocked.load(Ordering::SeqCst)).await;
    let permits = fixture.state.requests.available_permits();
    eprintln!("deterministic response backpressure observed; request permits={permits}");
    let finished = tokio::time::timeout(Duration::from_millis(5500), &mut task).await;
    if finished.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert!(
        finished.is_ok(),
        "response transport escaped admitted read budget"
    );
    assert_eq!(
        permits, 7,
        "response released request admission before delivery"
    );
    eventually(|| fixture.state.requests.available_permits() == 8).await;
}

#[tokio::test]
async fn admitted_read_deadline_includes_preparation() {
    let (mut client, server) = tokio::io::duplex(64);
    let requests = request_slots();
    let slots = requests.clone();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let mut task = tokio::spawn(serve_http(server, requests, move |_| async move {
        entered_tx.send(()).unwrap();
        let _ = release_rx.await;
        response(StatusCode::OK, "prepared", false)
    }));
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    entered_rx.await.unwrap();
    assert_eq!(
        slots.available_permits(),
        7,
        "held preparation did not own request admission"
    );
    let finished = tokio::time::timeout(Duration::from_millis(5500), &mut task).await;
    if finished.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert!(finished.is_ok(), "preparation escaped admitted read budget");
    assert!(
        release_tx.send(()).is_err(),
        "expired preparation kept running"
    );
    assert_eq!(
        slots.available_permits(),
        8,
        "expired read leaked request admission"
    );
}

fn scheduler_state(fixture: &Fixture, node: &str, store: Arc<Store>) -> Arc<State> {
    Arc::new(State {
        verifier: Verifier::new(fixture.config.auth.clone(), Arc::new(|| 1000)).unwrap(),
        store,
        store_slots: Arc::new(Semaphore::new(1)),
        requests: request_slots(),
        nodes: vec![node.into()],
        denied: Mutex::new(BTreeSet::new()),
        scopes: Mutex::new(BTreeMap::new()),
        scope_hidden: Mutex::new(BTreeSet::new()),
    })
}
fn scheduler_page(node: &str) -> crate::observe_export::ExportPage {
    serde_json::from_value(json!({"v":1,"node":node,"epoch":"fixture-epoch","scope":"a".repeat(64),"events":[{"sequence":1,"observed_at":1000,"persisted_at":1000,"kind":"message_recorded","available":"not_recorded"}],"next":1,"has_more":false,"gaps":[],"available":true})).unwrap()
}
async fn backoff_case(snapshot_limited: bool) {
    let fixture = Fixture::new().await;
    let exporter = net::tests::Fixture::new().await;
    let config = exporter.load().unwrap();
    let node = config.sources[0].node.clone();
    let store = Arc::new(
        Store::open(
            &fixture.files.path().join("scheduler"),
            vec![NodePolicy {
                relay: None,
                node: node.clone(),
                labels: false,
                supported: true,
            }],
            Arc::new(|| 1000),
        )
        .unwrap(),
    );
    let page = scheduler_page(&node);
    store
        .ingest_page(&node, &Default::default(), page.clone())
        .unwrap();
    let cursor = store.cursor(&node).unwrap();
    let state = scheduler_state(&fixture, &node, store.clone());
    if snapshot_limited {
        exporter.set_response("429 Too Many Requests", "Retry-After: 3\r\n", b"");
    } else {
        exporter.set_response(
            "200 OK",
            "",
            &serde_json::to_vec(&ExportSnapshot {
                v: 1,
                node: node.clone(),
                scope: "a".repeat(64),
                observed_at: 1000,
                endpoints: vec![],
                truncated: false,
                available: SnapshotAvailability::Available,
            })
            .unwrap(),
        );
    }
    let client = Arc::new(Client::new(&config).unwrap());
    let task = tokio::spawn(poll_source(client, state, 0));
    eventually(|| exporter.requests.load(Ordering::SeqCst) == 1).await;
    if !snapshot_limited {
        exporter.set_response("429 Too Many Requests", "Retry-After: 3\r\n", b"");
        tokio::time::timeout(Duration::from_secs(3), async {
            while exporter.requests.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    let limited_index = usize::from(!snapshot_limited);
    let mut empty = page;
    empty.events.clear();
    exporter.set_response("200 OK", "", &serde_json::to_vec(&empty).unwrap());
    let previous = exporter.starts.lock().unwrap()[limited_index];
    let limit = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        if exporter.requests.load(Ordering::SeqCst) > limited_index + 1
            || std::time::Instant::now() >= limit
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    task.abort();
    let _ = task.await;
    let starts = exporter.starts.lock().unwrap();
    assert!(
        starts.len() > limited_index + 1,
        "rate limited node stopped retrying"
    );
    assert!(
        starts[limited_index + 1].duration_since(previous) >= Duration::from_secs(3),
        "rate-limit backoff was not applied: snapshot={snapshot_limited}"
    );
    assert_eq!(
        store.cursor(&node).unwrap(),
        cursor,
        "rate-limit retry changed pending cursor"
    );
    assert_eq!(
        store.view(Some(&node), 200).unwrap()[0].events.len(),
        1,
        "rate limiting erased retained pending history"
    );
}
#[tokio::test]
async fn snapshot_backoff_is_applied_to_scheduler() {
    backoff_case(true).await;
}
#[tokio::test]
async fn events_backoff_is_applied_to_scheduler() {
    backoff_case(false).await;
}

#[tokio::test]
async fn runtime_preserves_original_future_kind() {
    let fixture = Fixture::new().await;
    let exporter = net::tests::Fixture::new().await;
    let config = exporter.load().unwrap();
    let node = config.sources[0].node.clone();
    let directory = fixture.files.path().join("future-runtime");
    let store = Arc::new(
        Store::open(
            &directory,
            vec![NodePolicy {
                relay: None,
                node: node.clone(),
                labels: false,
                supported: true,
            }],
            Arc::new(|| 1000),
        )
        .unwrap(),
    );
    exporter.set_response(
        "200 OK",
        "",
        &serde_json::to_vec(&ExportSnapshot {
            v: 1,
            node: node.clone(),
            scope: "a".repeat(64),
            observed_at: 1000,
            endpoints: vec![],
            truncated: false,
            available: SnapshotAvailability::Available,
        })
        .unwrap(),
    );
    let state = scheduler_state(&fixture, &node, store.clone());
    let task = tokio::spawn(poll_source(
        Arc::new(Client::new(&config).unwrap()),
        state,
        0,
    ));
    eventually(|| exporter.requests.load(Ordering::SeqCst) == 1).await;
    let mut packet = serde_json::to_value(scheduler_page(&node)).unwrap();
    packet["events"][0]["kind"] = json!("future_delivery");
    exporter.set_response("200 OK", "", &serde_json::to_vec(&packet).unwrap());
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while store.cursor(&node).unwrap().next == 0 && std::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    task.abort();
    let _ = task.await;
    assert_eq!(
        store.cursor(&node).unwrap().next,
        1,
        "runtime rejected future event page"
    );
    let connection = rusqlite::Connection::open_with_flags(
        directory.join("collector.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let bytes: Vec<u8> = connection
        .query_row("SELECT json FROM events WHERE sequence=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["kind"],
        "future_delivery",
        "runtime lost original kind identity"
    );
}

#[tokio::test]
async fn idle_background_maintenance_removes_persisted_rows() {
    use std::sync::atomic::AtomicI64;
    let fixture = Fixture::new().await;
    let mut exporter = net::tests::Fixture::new().await;
    exporter.config["sources"][0]["outbound_only"] = json!(true);
    let config = exporter.load().unwrap();
    let client = Arc::new(Client::new(&config).unwrap());
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let directory = fixture.files.path().join("maintenance");
    let store = Arc::new(
        Store::open(
            &directory,
            vec![NodePolicy {
                relay: None,
                node: "fixture.node".into(),
                labels: false,
                supported: true,
            }],
            Arc::new(move || clock.load(Ordering::SeqCst)),
        )
        .unwrap(),
    );
    store
        .ingest_page(
            "fixture.node",
            &Default::default(),
            scheduler_page("fixture.node"),
        )
        .unwrap();
    let count = || {
        rusqlite::Connection::open(directory.join("collector.sqlite"))
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    };
    assert_eq!(count(), 1, "physical-row positive control did not fire");
    now.store(1000 + 7 * 86400 + 1, Ordering::SeqCst);
    let state = scheduler_state(&fixture, "fixture.node", store);
    let tasks = background_tasks(client, state);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let remaining = loop {
        let remaining = count();
        if remaining == 0 || std::time::Instant::now() >= deadline {
            break remaining;
        }
        tokio::task::yield_now().await;
    };
    drop(tasks);
    assert_eq!(
        remaining, 0,
        "idle background maintenance left persisted event rows"
    );
    assert_eq!(
        exporter.requests.load(Ordering::SeqCst),
        0,
        "idle maintenance required exporter traffic"
    );
}

async fn relay_owner_claim_refusal(field: &str, value: serde_json::Value) {
    let fixture = Fixture::with_relay(true).await;
    let positive = fixture.get("/?node=0").send().await.unwrap();
    assert_eq!(positive.status(), 200);
    assert!(positive
        .text()
        .await
        .unwrap()
        .contains("via spiffe://fleet/host/hub/user/owner"));
    fixture.idp_claims.lock().unwrap()[field] = value;
    let refusal = fixture.get("/?node=0").send().await.unwrap();
    assert!(
        refusal.status() == 401 || refusal.status() == 403,
        "relay owner predicate bypassed: {field}"
    );
    assert!(!refusal
        .text()
        .await
        .unwrap()
        .contains("via spiffe://fleet/host/hub/user/owner"));
}
#[tokio::test]
async fn relay_owner_allowlist_refuses_valid_nonowner() {
    relay_owner_claim_refusal("sub", json!("nonowner")).await;
}
#[tokio::test]
async fn relay_owner_issuer_is_exact() {
    relay_owner_claim_refusal("iss", json!("https://foreign.invalid")).await;
}
#[tokio::test]
async fn relay_owner_audience_is_exact() {
    relay_owner_claim_refusal("aud", json!("other")).await;
}
#[tokio::test]
async fn relay_owner_client_is_exact() {
    relay_owner_claim_refusal("client_id", json!("other")).await;
}
#[tokio::test]
async fn relay_owner_expiry_is_current() {
    relay_owner_claim_refusal("exp", json!(999)).await;
}
#[tokio::test]
async fn relay_owner_headers_are_not_identity() {
    let fixture = Fixture::with_relay(true).await;
    assert_eq!(fixture.get("/?node=0").send().await.unwrap().status(), 200);
    let reply = reqwest::Client::new()
        .get(format!("{}/?node=0", fixture.url))
        .header("x-auth-request-user", "owner")
        .header("x-forwarded-user", "owner")
        .header("x-origin-hub", "forged")
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 401);
}
