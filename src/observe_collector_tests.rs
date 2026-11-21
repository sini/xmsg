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
        Self::with_validation(relay, true).await
    }
    async fn with_validation(relay: bool, validated: bool) -> Self {
        Self::with_issuer(relay, validated, None, None).await
    }
    async fn with_issuer(
        relay: bool,
        validated: bool,
        issuer: Option<Arc<crate::mission_control::Issuer>>,
        wire_probe: Option<Arc<crate::mission_control::stream::WireProbe>>,
    ) -> Self {
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
            auth: Some(AuthConfig {
                issuer: "https://owner.invalid".into(),
                introspection_url: format!("https://localhost:{}/introspect", address.port()),
                subjects: vec!["owner".into()],
                audience: "collector".into(),
                hosted_client: "hosted".into(),
                lookup_client: None,
                lookup_secret_file: None,
                provider_ca: Some(files.path().join("cert.pem")),
            }),
            mission_control: None,
            sources: vec![],
            web_tls: None,
            retention_after_inactive_secs:
                crate::observe_collector_net::DEFAULT_RETENTION_AFTER_INACTIVE_SECS,
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
            v: 2,
            node: "fixture.node".into(),
            scope: "a".repeat(64),
            observed_at: 1000,
            endpoints: vec![],
            truncated: false,
            available: SnapshotAvailability::Available,
            activity: crate::activity::SnapshotActivity {
                status: crate::activity::ActivityStatus::Disabled,
                complete: true,
            },
        };
        let mut initial_success = BTreeMap::new();
        if validated {
            let utc = store.epoch_now();
            store.ingest_snapshot("fixture.node", snapshot).unwrap();
            initial_success.insert("fixture.node".into(), (tokio::time::Instant::now(), utc));
        }
        let read_hub = issuer.as_ref().map(|_| {
            let hub = crate::mission_control::upstream::ReadHub::new().unwrap();
            for view in store.view(None, 200).unwrap() {
                hub.accept_poll(view, Some(store.epoch_now()), false, store.epoch_now())
                    .unwrap();
            }
            Arc::new(hub)
        });
        let state = Arc::new(State {
            verifier: Some(Verifier::new(config.auth.clone().unwrap(), clock).unwrap()),
            issuer,
            read_hub,
            wire_probe,
            store,
            store_slots: Arc::new(Semaphore::new(1)),
            requests: request_slots(),
            nodes: vec!["fixture.node".into()],
            denied: Mutex::new(BTreeSet::new()),
            failures: Mutex::new(BTreeMap::new()),
            scopes: Mutex::new(if validated {
                BTreeMap::from([("fixture.node".into(), "a".repeat(64))])
            } else {
                BTreeMap::new()
            }),
            scope_hidden: Mutex::new(BTreeSet::new()),
            success: Mutex::new(initial_success),
            pollers_alive: Arc::new(AtomicUsize::new(0)),
            supported_sources: 1,
            maintenance: Mutex::new(MaintenanceState::default()),
            store_slot_refusals: Arc::new(AtomicU64::new(0)),
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
        serve_stream(io, state, None).await;
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
    let mut task = tokio::spawn(serve_http(
        server,
        requests,
        WEB_BUDGET,
        move |_| async move {
            entered_tx.send(()).unwrap();
            let _ = release_rx.await;
            response(StatusCode::OK, "prepared", false)
        },
    ));
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
        verifier: Some(
            Verifier::new(fixture.config.auth.clone().unwrap(), Arc::new(|| 1000)).unwrap(),
        ),
        issuer: None,
        read_hub: None,
        wire_probe: None,
        store,
        store_slots: Arc::new(Semaphore::new(1)),
        requests: request_slots(),
        nodes: vec![node.into()],
        denied: Mutex::new(BTreeSet::new()),
        failures: Mutex::new(BTreeMap::new()),
        scopes: Mutex::new(BTreeMap::new()),
        scope_hidden: Mutex::new(BTreeSet::new()),
        success: Mutex::new(BTreeMap::new()),
        pollers_alive: Arc::new(AtomicUsize::new(0)),
        supported_sources: 1,
        maintenance: Mutex::new(MaintenanceState::default()),
        store_slot_refusals: Arc::new(AtomicU64::new(0)),
    })
}
fn scheduler_page(node: &str) -> crate::observe_export::ExportPage {
    serde_json::from_value(json!({"v":2,"node":node,"epoch":"fixture-epoch","scope":"a".repeat(64),"events":[{"sequence":1,"observed_at":1000,"persisted_at":1000,"kind":"message_recorded","available":"not_recorded"}],"next":1,"has_more":false,"gaps":[],"available":true})).unwrap()
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
                v: 2,
                node: node.clone(),
                scope: "a".repeat(64),
                observed_at: 1000,
                endpoints: vec![],
                truncated: false,
                available: SnapshotAvailability::Available,
                activity: crate::activity::SnapshotActivity {
                    status: crate::activity::ActivityStatus::Disabled,
                    complete: true,
                },
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
            v: 2,
            node: node.clone(),
            scope: "a".repeat(64),
            observed_at: 1000,
            endpoints: vec![],
            truncated: false,
            available: SnapshotAvailability::Available,
            activity: crate::activity::SnapshotActivity {
                status: crate::activity::ActivityStatus::Disabled,
                complete: true,
            },
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
    assert_eq!(
        positive.status(),
        200,
        "relay authorized owner positive refused before claim test: {field}"
    );
    assert!(
        positive
            .text()
            .await
            .unwrap()
            .contains("via spiffe://fleet/host/hub/user/owner"),
        "relay authorized owner positive lacked configured hub provenance: {field}"
    );
    fixture.idp_claims.lock().unwrap()[field] = value;
    let refusal = fixture.get("/?node=0").send().await.unwrap();
    assert!(
        refusal.status() == 401 || refusal.status() == 403,
        "relay owner predicate bypassed: {field}"
    );
    assert!(
        !refusal
            .text()
            .await
            .unwrap()
            .contains("via spiffe://fleet/host/hub/user/owner"),
        "refused relay owner received cached hub-attested metadata: {field}"
    );
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
    assert_eq!(
        fixture.get("/?node=0").send().await.unwrap().status(),
        200,
        "relay owner positive refused before forged-header control"
    );
    let reply = reqwest::Client::new()
        .get(format!("{}/?node=0", fixture.url))
        .header("x-auth-request-user", "owner")
        .header("x-forwarded-user", "owner")
        .header("x-origin-hub", "forged")
        .send()
        .await
        .unwrap();
    assert_eq!(
        reply.status(),
        401,
        "relay identity headers authorized owner view"
    );
}

#[tokio::test]
async fn relay_failure_overlay_survives_busy_store_slot_and_clears_on_fresh_ingest() {
    let fixture = Fixture::with_relay(true).await;
    for (error, caption) in [
        (net::Error::Timeout, "Observation request timed out."),
        (net::Error::Unavailable, "Observation exporter unavailable."),
        (net::Error::Malformed, "Invalid observation response."),
        (net::Error::RateLimited(2), "Observation rate limited."),
        (
            net::Error::Unsupported,
            "Observation transport unsupported.",
        ),
    ] {
        let held = fixture
            .state
            .store_slots
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        mark_error(&fixture.state, "fixture.node".into(), error).await;
        assert_eq!(
            fixture.state.store.view(None, 200).unwrap()[0].status,
            crate::observe_collector_store::NodeStatus::Healthy,
            "forced busy-slot control did not leave SQL status unchanged"
        );
        drop(held);
        let reply = fixture.get("/?node=0").send().await.unwrap();
        assert_eq!(
            reply.status(),
            200,
            "validated relay failure overlay view became unavailable: {error:?}"
        );
        let html = reply.text().await.unwrap();
        assert!(
            html.contains(caption),
            "busy store dropped known failure: {error:?}"
        );
        assert!(
            html.contains("Previously validated history is stale."),
            "busy-store relay failure omitted explicit stale-history caption: {error:?}"
        );
        assert!(
            !html.contains("<p>healthy</p>"),
            "known relay network failure remained healthy after busy store slot: {error:?}"
        );
        assert!(
            html.contains("via spiffe://fleet/host/hub/user/owner (hub-attested)"),
            "busy-store relay failure dropped validated hub provenance: {error:?}"
        );
        assert_eq!(
            fixture.state.failures.lock().unwrap().len(),
            1,
            "known relay network failure was not retained in bounded overlay: {error:?}"
        );
        fixture
            .state
            .store
            .ingest_snapshot(
                "fixture.node",
                ExportSnapshot {
                    v: 2,
                    node: "fixture.node".into(),
                    scope: "a".repeat(64),
                    observed_at: 1000,
                    endpoints: vec![],
                    truncated: false,
                    available: SnapshotAvailability::Available,
                    activity: crate::activity::SnapshotActivity {
                        status: crate::activity::ActivityStatus::Disabled,
                        complete: true,
                    },
                },
            )
            .unwrap();
        accepted_scope(&fixture.state, "fixture.node", "a".repeat(64));
        assert!(
            fixture.state.failures.lock().unwrap().is_empty(),
            "fresh relay ingest retained failure overlay"
        );
        let html = fixture
            .get("/?node=0")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            html.contains("<p>healthy</p>"),
            "fresh validated relay ingestion did not recover healthy view: {error:?}"
        );
        assert!(
            !html.contains(caption),
            "fresh validated relay ingestion retained obsolete failure caption: {error:?}"
        );
    }
    for (error, caption) in [
        (StoreError::Full, "Collector storage full."),
        (StoreError::Storage, "Invalid observation response."),
    ] {
        let held = fixture
            .state
            .store_slots
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        mark_storage_error(&fixture.state, "fixture.node".into(), error).await;
        drop(held);
        let html = fixture
            .get("/?node=0")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            html.contains(caption),
            "busy store dropped storage failure: {error:?}"
        );
        assert!(
            !html.contains("<p>healthy</p>"),
            "known relay storage failure remained healthy after busy store slot: {error:?}"
        );
    }
    remember_failure(&fixture.state, "unconfigured", UnavailableKind::Timeout);
    assert_eq!(
        fixture.state.failures.lock().unwrap().len(),
        1,
        "failure overlay grew beyond configured inventory"
    );
}
#[tokio::test]
async fn relay_failure_overlay_preserves_scope_and_denial_masks() {
    let fixture = Fixture::with_relay(true).await;
    let held = fixture
        .state
        .store_slots
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    mark_error(&fixture.state, "fixture.node".into(), net::Error::Timeout).await;
    observe_scope(&fixture.state, "fixture.node", &"b".repeat(64));
    drop(held);
    let html = fixture
        .get("/?node=0")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains("pending revalidation"),
        "failure overlay weakened relay scope-change pending-revalidation mask"
    );
    assert!(
        html.contains("history hidden until this node answers"),
        "failure overlay omitted relay scope-change hidden-history explanation"
    );
    assert!(
        !html.contains("Latest source inventory"),
        "failure overlay exposed snapshot despite relay scope-change mask"
    );
    let held = fixture
        .state
        .store_slots
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    mark_error(&fixture.state, "fixture.node".into(), net::Error::Denied).await;
    drop(held);
    fixture.state.scope_hidden.lock().unwrap().clear();
    let html = fixture
        .get("/?node=0")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains("<p>denied</p>"),
        "failure overlay overrode authenticated relay denial status"
    );
    assert!(
        !html.contains("Latest source inventory"),
        "failure overlay exposed snapshot despite authenticated relay denial mask"
    );
    assert!(
        !html.contains("Observation request timed out."),
        "failure overlay caption overrode authenticated relay denial caption"
    );
}

#[tokio::test]
async fn relay_failure_overlay_keeps_unvalidated_history_pending() {
    let fixture = Fixture::with_validation(true, false).await;
    assert!(
        fixture.state.store.view(None, 200).unwrap()[0].history_hidden,
        "unvalidated relay fixture unexpectedly began with validated history"
    );
    assert!(
        fixture.state.denied.lock().unwrap().is_empty(),
        "unvalidated relay fixture unexpectedly began with denial mask"
    );
    assert!(
        fixture.state.scope_hidden.lock().unwrap().is_empty(),
        "unvalidated relay fixture unexpectedly began with scope mask"
    );
    mark_error(&fixture.state, "fixture.node".into(), net::Error::Timeout).await;
    let reply = fixture.get("/?node=0").send().await.unwrap();
    assert_eq!(
        reply.status(),
        200,
        "unvalidated relay timeout view became unavailable"
    );
    let html = reply.text().await.unwrap();
    assert!(
        html.contains("<p>pending revalidation</p>"),
        "unvalidated relay failure overlay replaced pending revalidation with stale status"
    );
    assert!(
        html.contains("history hidden until this node answers"),
        "unvalidated relay timeout omitted hidden-history explanation"
    );
    assert!(
        html.contains("Observation request timed out."),
        "unvalidated relay timeout omitted fixed failure caption"
    );
    assert!(
        !html.contains("stale: exporter unavailable"),
        "unvalidated relay timeout invented validated stale history"
    );
    assert!(
        fixture.state.denied.lock().unwrap().is_empty(),
        "relay timeout added a denial mask instead of exercising natural unvalidated state"
    );
    assert!(
        fixture.state.scope_hidden.lock().unwrap().is_empty(),
        "relay timeout added a scope mask instead of exercising natural unvalidated state"
    );
    fixture
        .state
        .store
        .ingest_snapshot(
            "fixture.node",
            ExportSnapshot {
                v: 2,
                node: "fixture.node".into(),
                scope: "a".repeat(64),
                observed_at: 1000,
                endpoints: vec![],
                truncated: false,
                available: SnapshotAvailability::Available,
                activity: crate::activity::SnapshotActivity {
                    status: crate::activity::ActivityStatus::Disabled,
                    complete: true,
                },
            },
        )
        .expect("fresh relay snapshot validation positive refused");
    accepted_scope(&fixture.state, "fixture.node", "a".repeat(64));
    assert!(
        !fixture.state.store.view(None, 200).unwrap()[0].history_hidden,
        "fresh relay snapshot positive did not validate history"
    );
    mark_error(&fixture.state, "fixture.node".into(), net::Error::Timeout).await;
    let html = fixture
        .get("/?node=0")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains("<p>stale: exporter unavailable</p>"),
        "validated relay timeout neighbor failed to retain truthful stale state"
    );
    assert!(
        !html.contains("history hidden until this node answers"),
        "validated relay timeout neighbor incorrectly hid validated history"
    );
    assert!(
        html.contains("Latest source inventory"),
        "validated relay timeout neighbor lost retained snapshot"
    );
}

async fn body_text(resp: Response<Full<Bytes>>) -> String {
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn render_test_html(state: &State, node: Option<usize>) -> String {
    body_text(state.render_page(Filter { node, page: 0 }).await).await
}

fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[tokio::test(start_paused = true)]
async fn a1_stale_after_fresh_without_failure() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .store
        .ingest_snapshot(
            "fixture.node",
            ExportSnapshot {
                v: 2,
                node: "fixture.node".into(),
                scope: "a".repeat(64),
                observed_at: 1000,
                endpoints: vec![],
                truncated: false,
                available: SnapshotAvailability::Available,
                activity: crate::activity::SnapshotActivity {
                    status: crate::activity::ActivityStatus::Disabled,
                    complete: true,
                },
            },
        )
        .unwrap();
    accepted_scope(&fixture.state, "fixture.node", "a".repeat(64));
    tokio::time::advance(FRESH + Duration::from_secs(1)).await;

    let html = render_test_html(&fixture.state, None).await;
    assert!(
        html.contains("stale: no successful poll for 16 s"),
        "expected stale age 16 s, got:\n{html}"
    );
    assert!(
        html.contains("last successful poll 1970-01-01T00:16:40Z (16 s ago)"),
        "expected last successful poll UTC + age, got:\n{html}"
    );
    assert!(
        !html.contains("<p>healthy</p>"),
        "node must not read healthy after FRESH+1:\n{html}"
    );
}

#[tokio::test(start_paused = true)]
async fn a2_healthy_no_change_advances_last_success() {
    let clock_secs = Arc::new(std::sync::atomic::AtomicI64::new(1000));
    let clock: crate::observe_collector_store::EpochClock = {
        let clock_secs = clock_secs.clone();
        Arc::new(move || clock_secs.load(Ordering::Relaxed))
    };
    let dir = private_tempdir();
    let store = Arc::new(
        Store::open(
            dir.path(),
            vec![NodePolicy {
                node: "fixture.node".into(),
                supported: true,
                labels: false,
                relay: None,
            }],
            clock.clone(),
        )
        .unwrap(),
    );
    let fixture = Fixture::new().await;
    let state = Arc::new(State {
        verifier: Some(Verifier::new(fixture.config.auth.clone().unwrap(), clock).unwrap()),
        issuer: None,
        read_hub: None,
        wire_probe: None,
        store: store.clone(),
        store_slots: Arc::new(Semaphore::new(1)),
        requests: request_slots(),
        nodes: vec!["fixture.node".into()],
        denied: Mutex::new(BTreeSet::new()),
        failures: Mutex::new(BTreeMap::new()),
        scopes: Mutex::new(BTreeMap::new()),
        scope_hidden: Mutex::new(BTreeSet::new()),
        success: Mutex::new(BTreeMap::new()),
        pollers_alive: Arc::new(AtomicUsize::new(0)),
        supported_sources: 1,
        maintenance: Mutex::new(MaintenanceState::default()),
        store_slot_refusals: Arc::new(AtomicU64::new(0)),
    });

    let snap = ExportSnapshot {
        v: 2,
        node: "fixture.node".into(),
        scope: "a".repeat(64),
        observed_at: 1000,
        endpoints: vec![],
        truncated: false,
        available: SnapshotAvailability::Available,
        activity: crate::activity::SnapshotActivity {
            status: crate::activity::ActivityStatus::Disabled,
            complete: true,
        },
    };
    store.ingest_snapshot("fixture.node", snap.clone()).unwrap();
    accepted_scope(&state, "fixture.node", "a".repeat(64));

    let empty_page: crate::observe_export::ExportPage = serde_json::from_value(json!({
        "v": 2,
        "node": "fixture.node",
        "epoch": "fixture-epoch",
        "scope": "a".repeat(64),
        "events": [],
        "next": 0,
        "has_more": false,
        "gaps": [],
        "available": true
    }))
    .unwrap();
    for step in 1..=15 {
        tokio::time::advance(Duration::from_secs(2)).await;
        clock_secs.store(1000 + step * 2, Ordering::Relaxed);
        let cursor = store.cursor("fixture.node").unwrap();
        let outcome = store
            .ingest_page("fixture.node", &cursor, empty_page.clone())
            .unwrap();
        assert_eq!(outcome.inserted, 0);
        store.ingest_snapshot("fixture.node", snap.clone()).unwrap();
        on_page_ingested(&state, "fixture.node", "a".repeat(64), outcome.inserted);
    }

    let (_, last_utc) = state
        .success
        .lock()
        .unwrap()
        .get("fixture.node")
        .copied()
        .unwrap();
    assert_eq!(
        last_utc, 1030,
        "last_success UTC must advance on healthy no-change"
    );

    let html = render_test_html(&state, None).await;
    assert!(
        html.contains("<p>healthy</p>"),
        "healthy no-change must stay healthy over 30 s, got:\n{html}"
    );
}

#[tokio::test(start_paused = true)]
async fn a3_connection_without_ingest_is_not_success() {
    let fixture = Fixture::new().await;
    // Initial validated snapshot at t0.
    fixture
        .state
        .store
        .ingest_snapshot(
            "fixture.node",
            ExportSnapshot {
                v: 2,
                node: "fixture.node".into(),
                scope: "a".repeat(64),
                observed_at: 1000,
                endpoints: vec![],
                truncated: false,
                available: SnapshotAvailability::Available,
                activity: crate::activity::SnapshotActivity {
                    status: crate::activity::ActivityStatus::Disabled,
                    complete: true,
                },
            },
        )
        .unwrap();
    accepted_scope(&fixture.state, "fixture.node", "a".repeat(64));

    // Advance past FRESH while simulating HTTP 200 receipt whose ingest fails / is Pending (no accepted_scope).
    tokio::time::advance(FRESH + Duration::from_secs(1)).await;
    on_response_received(&fixture.state, "fixture.node");

    let html = render_test_html(&fixture.state, None).await;
    assert!(
        html.contains("stale: no successful poll for 16 s"),
        "expected stale after FRESH+1 without ingest, got:\n{html}"
    );
}

#[tokio::test(start_paused = true)]
async fn a4_permission_loss_and_scope_change_mask_last_success() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .store
        .ingest_snapshot(
            "fixture.node",
            ExportSnapshot {
                v: 2,
                node: "fixture.node".into(),
                scope: "a".repeat(64),
                observed_at: 1000,
                endpoints: vec![],
                truncated: false,
                available: SnapshotAvailability::Available,
                activity: crate::activity::SnapshotActivity {
                    status: crate::activity::ActivityStatus::Disabled,
                    complete: true,
                },
            },
        )
        .unwrap();
    accepted_scope(&fixture.state, "fixture.node", "a".repeat(64));

    mark_error(&fixture.state, "fixture.node".into(), net::Error::Denied).await;
    let html_denied = render_test_html(&fixture.state, Some(0)).await;
    assert!(html_denied.contains("<p>denied</p>"), "{html_denied}");
    assert!(
        !html_denied.contains("last successful poll")
            && !html_denied.contains("Latest source inventory")
            && !html_denied.contains("Source boundary:"),
        "denied mask leaked rows, gaps, or last-success:\n{html_denied}"
    );

    tokio::time::advance(FRESH + Duration::from_secs(1)).await;
    let html_denied_later = render_test_html(&fixture.state, Some(0)).await;
    assert!(
        !html_denied_later.contains("last successful poll")
            && !html_denied_later.contains("stale: no successful poll"),
        "denied mask must still hide last-success after FRESH+1:\n{html_denied_later}"
    );

    // Scope change mask also hides rows, gaps, and last-success.
    fixture.state.denied.lock().unwrap().clear();
    observe_scope(&fixture.state, "fixture.node", &"b".repeat(64));
    let html_scope = render_test_html(&fixture.state, Some(0)).await;
    assert!(
        html_scope.contains("<p>pending revalidation</p>")
            && !html_scope.contains("last successful poll")
            && !html_scope.contains("Latest source inventory"),
        "scope change leaked rows or last-success:\n{html_scope}"
    );
}

#[tokio::test(start_paused = true)]
async fn a5_restart_with_history_shows_hidden_and_none_since_start() {
    let dir = private_tempdir();
    let clock: crate::observe_collector_store::EpochClock = Arc::new(|| 1000);
    let policy = vec![NodePolicy {
        node: "fixture.node".into(),
        supported: true,
        labels: false,
        relay: None,
    }];
    {
        let store = Store::open(dir.path(), policy.clone(), clock.clone()).unwrap();
        store
            .ingest_snapshot(
                "fixture.node",
                ExportSnapshot {
                    v: 2,
                    node: "fixture.node".into(),
                    scope: "a".repeat(64),
                    observed_at: 1000,
                    endpoints: vec![],
                    truncated: false,
                    available: SnapshotAvailability::Available,
                    activity: crate::activity::SnapshotActivity {
                        status: crate::activity::ActivityStatus::Disabled,
                        complete: true,
                    },
                },
            )
            .unwrap();
    }

    let reopened = Arc::new(Store::open(dir.path(), policy, clock.clone()).unwrap());
    let fixture = Fixture::new().await;
    let initial_succ = initial_success(&reopened);
    let state = Arc::new(State {
        verifier: Some(Verifier::new(fixture.config.auth.clone().unwrap(), clock).unwrap()),
        issuer: None,
        read_hub: None,
        wire_probe: None,
        store: reopened,
        store_slots: Arc::new(Semaphore::new(1)),
        requests: request_slots(),
        nodes: vec!["fixture.node".into()],
        denied: Mutex::new(BTreeSet::new()),
        failures: Mutex::new(BTreeMap::new()),
        scopes: Mutex::new(BTreeMap::new()),
        scope_hidden: Mutex::new(BTreeSet::new()),
        success: Mutex::new(initial_succ),
        pollers_alive: Arc::new(AtomicUsize::new(0)),
        supported_sources: 1,
        maintenance: Mutex::new(MaintenanceState::default()),
        store_slot_refusals: Arc::new(AtomicU64::new(0)),
    });

    assert!(
        state.success.lock().unwrap().is_empty(),
        "fresh State after restart must not seed success from persisted receipt times"
    );
    let html_initial = render_test_html(&state, Some(0)).await;
    assert!(
        html_initial.contains("<p>pending revalidation</p>")
            && html_initial.contains("history hidden until this node answers")
            && !html_initial.contains("Latest source inventory"),
        "restart with fresh State must hide history:\n{html_initial}"
    );

    mark_error(&state, "fixture.node".into(), net::Error::Timeout).await;
    let html = render_test_html(&state, Some(0)).await;
    assert!(
        html.contains("Observation request timed out.")
            && html.contains("history hidden until this node answers")
            && !html.contains("Latest source inventory")
            && !html.contains("last successful poll 1970-"),
        "restart with fresh State must hide history and not seed last-success from disk:\n{html}"
    );
}

#[tokio::test(start_paused = true)]
async fn a6_monotonic_health_ignores_epoch_clock_shifts() {
    let clock_secs = Arc::new(std::sync::atomic::AtomicI64::new(10_000));
    let clock: crate::observe_collector_store::EpochClock = {
        let clock_secs = clock_secs.clone();
        Arc::new(move || clock_secs.load(Ordering::Relaxed))
    };
    let dir = private_tempdir();
    let store = Arc::new(
        Store::open(
            dir.path(),
            vec![NodePolicy {
                node: "fixture.node".into(),
                supported: true,
                labels: false,
                relay: None,
            }],
            clock.clone(),
        )
        .unwrap(),
    );
    let fixture = Fixture::new().await;
    let state = Arc::new(State {
        verifier: Some(Verifier::new(fixture.config.auth.clone().unwrap(), clock).unwrap()),
        issuer: None,
        read_hub: None,
        wire_probe: None,
        store: store.clone(),
        store_slots: Arc::new(Semaphore::new(1)),
        requests: request_slots(),
        nodes: vec!["fixture.node".into()],
        denied: Mutex::new(BTreeSet::new()),
        failures: Mutex::new(BTreeMap::new()),
        scopes: Mutex::new(BTreeMap::new()),
        scope_hidden: Mutex::new(BTreeSet::new()),
        success: Mutex::new(BTreeMap::new()),
        pollers_alive: Arc::new(AtomicUsize::new(0)),
        supported_sources: 1,
        maintenance: Mutex::new(MaintenanceState::default()),
        store_slot_refusals: Arc::new(AtomicU64::new(0)),
    });

    store
        .ingest_snapshot(
            "fixture.node",
            ExportSnapshot {
                v: 2,
                node: "fixture.node".into(),
                scope: "a".repeat(64),
                observed_at: 10_000,
                endpoints: vec![],
                truncated: false,
                available: SnapshotAvailability::Available,
                activity: crate::activity::SnapshotActivity {
                    status: crate::activity::ActivityStatus::Disabled,
                    complete: true,
                },
            },
        )
        .unwrap();
    accepted_scope(&state, "fixture.node", "a".repeat(64));

    // Shift wall clock +1h while monotonic clock does not advance.
    clock_secs.store(13_600, Ordering::Relaxed);
    let html_healthy = render_test_html(&state, None).await;
    assert!(
        html_healthy.contains("<p>healthy</p>"),
        "wall clock shift must not mark monotonic-fresh node stale:\n{html_healthy}"
    );

    // Shift wall clock -1h (before ingest), ingest again at shifted wall time, and advance monotonic FRESH+1.
    clock_secs.store(6_400, Ordering::Relaxed);
    accepted_scope(&state, "fixture.node", "a".repeat(64));
    tokio::time::advance(FRESH + Duration::from_secs(1)).await;
    let html_stale = render_test_html(&state, None).await;
    assert!(
        html_stale.contains("stale: no successful poll for 16 s")
            && html_stale.contains("last successful poll 1970-01-01T01:46:40Z (16 s ago)"),
        "UTC display must follow EpochClock while age is monotonic:\n{html_stale}"
    );
}

#[tokio::test(start_paused = true)]
async fn a7_failure_plus_panicked_poller_shows_zero_alive() {
    let fixture = Fixture::new().await;
    let mut tasks = tokio::task::JoinSet::new();
    let counter = fixture.state.pollers_alive.clone();
    tasks.spawn(async move {
        let _guard = PollerGuard::enter(counter);
        panic!("synthetic poller panic");
    });
    let _ = tasks.join_next().await;

    mark_error(&fixture.state, "fixture.node".into(), net::Error::Timeout).await;
    let html = render_test_html(&fixture.state, None).await;
    assert!(
        html.contains("Observation request timed out."),
        "expected timeout failure class:\n{html}"
    );
    assert!(
        html.contains("Collector: pollers alive 0/1"),
        "expected 0/1 pollers alive after poller panic:\n{html}"
    );
}

#[tokio::test(start_paused = true)]
async fn a8_failure_plus_maintenance_err_and_health_unchanged() {
    let fixture = Fixture::new().await;
    mark_error(&fixture.state, "fixture.node".into(), net::Error::Timeout).await;

    // Hold the single store slot so maintain_once gets a store-slot refusal (Err).
    let lease = fixture
        .state
        .store_slots
        .clone()
        .try_acquire_owned()
        .unwrap();
    maintain_once(&fixture.state).await;
    drop(lease);

    let html = render_test_html(&fixture.state, None).await;
    assert!(
        html.contains("Observation request timed out.")
            && html.contains("last maintenance FAILED (last ok never)")
            && html.contains("store-slot refusals 1"),
        "expected node failure + FAILED maintenance + store-slot refusal:\n{html}"
    );

    let health_resp = fixture
        .state
        .prepare(Request::builder().uri("/health").body(()).unwrap())
        .await;
    let health = body_text(health_resp).await;
    assert_eq!(health, "available\n");
}

#[tokio::test]
async fn r2a_direct_404_recovers_on_valid_response_and_403_stays_denied() {
    let fixture = Fixture::new().await;
    let exporter = net::tests::Fixture::new().await;
    let config = exporter.load().unwrap();
    let node = config.sources[0].node.clone();
    let store = Arc::new(
        Store::open(
            &fixture.files.path().join("r2a"),
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
    let state = scheduler_state(&fixture, &node, store.clone());

    exporter.set_response("404 Not Found", "", b"");
    let err_404 = Client::new(&config).unwrap().snapshot(0).await.unwrap_err();
    assert_eq!(err_404, net::Error::EndpointNotFound);
    mark_error(&state, node.clone(), err_404).await;

    let html_404 = render_test_html(&state, None).await;
    assert!(
        html_404.contains("observation endpoint not found/unsupported or misconfigured")
            && html_404.contains("1 endpoint not found/unsupported or misconfigured"),
        "expected EndpointNotFound surface on 404:\n{html_404}"
    );

    exporter.set_response(
        "200 OK",
        "",
        &serde_json::to_vec(&ExportSnapshot {
            v: 2,
            node: node.clone(),
            scope: "a".repeat(64),
            observed_at: 1000,
            endpoints: vec![],
            truncated: false,
            available: SnapshotAvailability::Available,
            activity: crate::activity::SnapshotActivity {
                status: crate::activity::ActivityStatus::Disabled,
                complete: true,
            },
        })
        .unwrap(),
    );
    // Drive a clean recovery poll via mark_error/ingest + accepted_scope or wait for next poll.
    // Since backoff on 404 is >1s, verify directly with net::Client + accepted_scope + clear failure,
    // and also verify 403 sets Denied and persists across subsequent 404.
    let direct_client = Client::new(&config).unwrap();
    let recovered = direct_client.snapshot(0).await.unwrap();
    state.store.ingest_snapshot(&node, recovered).unwrap();
    accepted_scope(&state, &node, "a".repeat(64));
    state.failures.lock().unwrap().remove(&node);
    let html_ok = render_test_html(&state, None).await;
    assert!(
        html_ok.contains("<p>healthy</p>") && html_ok.contains("1/1 configured nodes reporting"),
        "expected recovery to healthy after valid 200 response:\n{html_ok}"
    );

    exporter.set_response("403 Forbidden", "", b"");
    let err_403 = Client::new(&config).unwrap().snapshot(0).await.unwrap_err();
    assert_eq!(err_403, net::Error::Denied);
    mark_error(&state, node.clone(), err_403).await;
    exporter.set_response("404 Not Found", "", b"");
    let err_404 = Client::new(&config).unwrap().snapshot(0).await.unwrap_err();
    assert_eq!(err_404, net::Error::EndpointNotFound);
    mark_error(&state, node.clone(), err_404).await;
    assert!(
        state.denied.lock().unwrap().contains(&node),
        "404 cleared 403 denial mask"
    );
    let html_denied = render_test_html(&state, None).await;
    assert!(
        html_denied.contains("1 denied") && !html_denied.contains("Latest source inventory"),
        "denied mask lost after 404:\n{html_denied}"
    );
}

#[tokio::test]
async fn mission_control_three_transports_share_the_snapshot_and_cursor() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

    let oidc =
        crate::enroll_oidc::signed_fixture::Fixture::new_at(crate::storage::now_epoch_secs()).await;
    let directory = tempfile::tempdir().unwrap();
    let (issuer, issued) =
        crate::mission_control::tests::transport_fixture(&oidc, &directory).await;
    let f = Fixture::with_issuer(false, true, Some(issuer.clone()), None).await;
    f.state.read_hub.as_ref().unwrap().fill_snapshot_for_test();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let response = client
        .get(format!("{}/v1/mission-control/snapshot/fleet", f.url))
        .bearer_auth(&issued.handle)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let etag = response.headers()[hyper::header::ETAG].clone();
    let raw = response.bytes().await.unwrap();
    assert!(
        raw.len() > 1024 * 1024,
        "fixture must exceed the output queue"
    );
    let http: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(http["nodes"].as_array().unwrap().len(), 64);
    assert!(http["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|node| node["endpoints"].as_array().unwrap().len() == 200));
    let mut req = format!(
        "{}/v1/mission-control/session",
        f.url.replacen("http://", "ws://", 1)
    )
    .into_client_request()
    .unwrap();
    req.headers_mut().insert(
        hyper::header::SEC_WEBSOCKET_PROTOCOL,
        "xmsg.mission-control.v1".parse().unwrap(),
    );
    req.headers_mut().insert(
        hyper::header::AUTHORIZATION,
        format!("Bearer {}", issued.handle).parse().unwrap(),
    );
    let host = req.uri().authority().unwrap().as_str().to_owned();
    let tcp = tokio::net::TcpStream::connect(host).await.unwrap();
    let (mut socket, response) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::client_async(req, tcp),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    socket
        .send(Message::Text(
            r#"{"v":1,"type":"hello","id":1,"protocol":1,"capabilities":["observe","activity"]}"#
                .into(),
        ))
        .await
        .unwrap();
    let receive = async |socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>| {
        let frame = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_str::<serde_json::Value>(frame.to_text().unwrap()).unwrap()
    };
    assert_eq!(receive(&mut socket).await["type"], "hello");
    socket
        .send(Message::Text(
            r#"{"v":1,"type":"subscribe","id":2,"sub":"fleet","scope":{"kind":"fleet"}}"#.into(),
        ))
        .await
        .unwrap();
    assert_eq!(receive(&mut socket).await["type"], "subscribed");
    let mut nodes = Vec::new();
    let mut cursor = None;
    for _ in 0..65 {
        let ws = receive(&mut socket).await;
        assert_eq!(ws["type"], "snapshot");
        nodes.extend(ws["nodes"].as_array().unwrap().iter().cloned());
        if ws["final"] == true {
            assert_eq!(ws["truncated"], false);
            cursor = ws["cursor"].as_str().map(str::to_owned);
            break;
        }
    }
    assert_eq!(cursor.as_deref(), http["cursor"].as_str());
    assert_eq!(nodes, *http["nodes"].as_array().unwrap());

    let mut sse = client
        .get(format!("{}/v1/mission-control/stream/fleet", f.url))
        .bearer_auth(&issued.handle)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let mut bytes = Vec::new();
    let value = loop {
        bytes.extend(sse.chunk().await.unwrap().unwrap());
        let text = std::str::from_utf8(&bytes).unwrap();
        if let Some((_, tail)) = text.split_once("data: ") {
            if let Some((data, _)) = tail.split_once("\n\n") {
                break serde_json::from_str::<serde_json::Value>(data).unwrap();
            }
        }
    };
    assert_eq!(value["type"], "snapshot");
    assert_eq!(value["cursor"], http["cursor"]);
    assert_eq!(value["nodes"], http["nodes"]);
    let changed = crate::mission_control::tests::suppress_and_revoke(
        &issuer,
        &directory,
        &issued.record.record_id,
    )
    .await;
    let expires = tokio::time::Instant::from_std(changed + Duration::from_secs(1));
    let closed = tokio::time::timeout_at(expires, socket.next())
        .await
        .expect("revoked WebSocket missed cutoff");
    assert!(
        matches!(closed, None | Some(Err(_)) | Some(Ok(Message::Close(_)))),
        "revoked WebSocket received data"
    );
    let ended = tokio::time::timeout_at(expires, sse.chunk())
        .await
        .expect("revoked SSE missed cutoff");
    let Some(terminal) = ended.unwrap() else {
        panic!("idle SSE omitted revocation error");
    };
    let terminal = std::str::from_utf8(&terminal).unwrap();
    assert!(terminal.starts_with("event: error\n"));
    let data = terminal
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(data).unwrap();
    assert_eq!(value["code"], "revoked");
    assert!(tokio::time::timeout_at(expires, sse.chunk())
        .await
        .unwrap()
        .unwrap()
        .is_none());
    let revoked = client
        .get(format!("{}/v1/mission-control/snapshot/fleet", f.url))
        .header(hyper::header::IF_NONE_MATCH, etag)
        .bearer_auth(&issued.handle)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mission_control_blocked_writes_end_by_audited_cutoff() {
    use futures_util::{SinkExt, StreamExt};
    use std::io::Write as _;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

    let oidc =
        crate::enroll_oidc::signed_fixture::Fixture::new_at(crate::storage::now_epoch_secs()).await;
    for websocket in [true, false] {
        let mut samples = Vec::with_capacity(20);
        for _ in 0..20 {
            let probe = Arc::new(crate::mission_control::stream::WireProbe::default());
            let directory = tempfile::tempdir().unwrap();
            let (issuer, issued) =
                crate::mission_control::tests::transport_fixture(&oidc, &directory).await;
            let f =
                Fixture::with_issuer(false, true, Some(issuer.clone()), Some(probe.clone())).await;
            let address = f.url.strip_prefix("http://").unwrap();
            let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
            socket2::SockRef::from(&tcp)
                .set_recv_buffer_size(4096)
                .unwrap();
            let mut keep_ws = None;
            let mut keep_sse = None;
            if websocket {
                let mut req = format!("ws://{address}/v1/mission-control/session")
                    .into_client_request()
                    .unwrap();
                req.headers_mut().insert(
                    hyper::header::SEC_WEBSOCKET_PROTOCOL,
                    "xmsg.mission-control.v1".parse().unwrap(),
                );
                req.headers_mut().insert(
                    hyper::header::AUTHORIZATION,
                    format!("Bearer {}", issued.handle).parse().unwrap(),
                );
                let (mut socket, response) = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio_tungstenite::client_async(req, tcp),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
                socket
                    .send(Message::Text(
                        r#"{"v":1,"type":"hello","id":1,"protocol":1,"capabilities":["observe"]}"#
                            .into(),
                    ))
                    .await
                    .unwrap();
                assert!(tokio::time::timeout(Duration::from_secs(5), socket.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .to_text()
                    .unwrap()
                    .contains(r#""type":"hello""#));
                socket.send(Message::Text(r#"{"v":1,"type":"subscribe","id":2,"sub":"fleet","scope":{"kind":"fleet"}}"#.into())).await.unwrap();
                let mut subscribed = false;
                loop {
                    let frame = tokio::time::timeout(Duration::from_secs(5), socket.next())
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                    let body: serde_json::Value =
                        serde_json::from_str(frame.to_text().unwrap()).unwrap();
                    if !subscribed {
                        assert_eq!(body["type"], "subscribed");
                        subscribed = true;
                    } else {
                        assert_eq!(body["type"], "snapshot");
                        if body["final"] == true {
                            break;
                        }
                    }
                }
                keep_ws = Some(socket);
            } else {
                let mut tcp = tcp;
                tcp.write_all(format!("GET /v1/mission-control/stream/fleet HTTP/1.1\r\nHost: {address}\r\nAccept: text/event-stream\r\nAuthorization: Bearer {}\r\n\r\n", issued.handle).as_bytes()).await.unwrap();
                let mut socket = BufReader::new(tcp);
                tokio::time::timeout(Duration::from_secs(5), async {
                    let mut line = String::new();
                    socket.read_line(&mut line).await.unwrap();
                    assert!(line.starts_with("HTTP/1.1 200"));
                    loop {
                        line.clear();
                        assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
                        if line.starts_with("data: ") {
                            let body: serde_json::Value =
                                serde_json::from_str(line.trim_start_matches("data: ").trim_end())
                                    .unwrap();
                            assert_eq!(body["type"], "snapshot");
                            break;
                        }
                    }
                })
                .await
                .unwrap();
                keep_sse = Some(socket);
            }
            probe.armed.store(true, Ordering::SeqCst);
            f.state
                .read_hub
                .as_ref()
                .unwrap()
                .force_backlog_for_test("fixture.node");
            tokio::time::timeout(Duration::from_secs(5), probe.blocked.notified())
                .await
                .expect("real socket write must become pending");
            let change = crate::mission_control::tests::suppress_and_revoke(
                &issuer,
                &directory,
                &issued.record.record_id,
            )
            .await;
            let cutoff = tokio::time::Instant::from_std(change + Duration::from_millis(1000));
            tokio::time::timeout_at(cutoff, probe.closed.notified())
                .await
                .expect("blocked socket remained open past the recorded cutoff");
            let closed = probe.closed_at.lock().unwrap().unwrap();
            assert!(
                crate::mission_control::tests::last_handoff(&issuer).unwrap() <= change,
                "post-change payload admitted"
            );
            assert!(closed <= cutoff.into_std());
            samples.push(closed.saturating_duration_since(change));
            drop(keep_ws);
            drop(keep_sse);
        }
        samples.sort_unstable();
        let percentile =
            |percent: usize| samples[(samples.len() * percent).div_ceil(100) - 1].as_millis();
        writeln!(
            std::io::stderr().lock(),
            "SP5 {} blocked writes: runs=20 p50={}ms p95={}ms max={}ms (abort timer at T_change + SLO/2)",
            if websocket { "WebSocket" } else { "SSE" },
            percentile(50), percentile(95), percentile(100),
        ).unwrap();
    }
}

#[tokio::test]
async fn mission_control_upgrade_validates_carriers_and_version() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Error as WsError, Message};

    let oidc =
        crate::enroll_oidc::signed_fixture::Fixture::new_at(crate::storage::now_epoch_secs()).await;
    let directory = tempfile::tempdir().unwrap();
    let (issuer, machine) =
        crate::mission_control::tests::transport_fixture(&oidc, &directory).await;
    let (browser, native, delegated) =
        crate::mission_control::tests::transport_owner_records(&issuer, &oidc.issuer());
    let f = Fixture::with_issuer(false, true, Some(issuer.clone()), None).await;
    let address = f.url.strip_prefix("http://").unwrap();
    let request = |subprotocol: bool, target: &str| {
        let mut req = format!("ws://{address}{target}")
            .into_client_request()
            .unwrap();
        if subprotocol {
            req.headers_mut().insert(
                hyper::header::SEC_WEBSOCKET_PROTOCOL,
                "xmsg.mission-control.v1".parse().unwrap(),
            );
        }
        req
    };
    let with_origin = |headers: &mut hyper::HeaderMap, origin: &str| {
        headers.insert(hyper::header::ORIGIN, origin.parse().unwrap());
    };
    let cookie = |handle: &str| format!("__Host-mc_session={handle}");
    let session = "/v1/mission-control/session";
    let cases = [
        (
            false,
            session,
            Some(machine.handle.as_str()),
            None,
            None,
            400,
        ),
        (
            true,
            "/v1/mission-control/session?access_token=fixture",
            None,
            None,
            None,
            400,
        ),
        (true, session, None, None, None, 401),
        (true, session, Some("invalid-handle"), None, None, 401),
        (
            true,
            session,
            Some(&machine.handle),
            Some(browser.handle.as_str()),
            Some("https://collector.example"),
            401,
        ),
        (true, session, Some(&browser.handle), None, None, 401),
        (
            true,
            session,
            None,
            Some(native.handle.as_str()),
            Some("https://collector.example"),
            401,
        ),
        (true, session, Some(&delegated.handle), None, None, 401),
        (
            true,
            session,
            Some(&native.handle),
            None,
            Some("https://collector.example"),
            403,
        ),
        (
            true,
            session,
            None,
            Some(browser.handle.as_str()),
            None,
            403,
        ),
        (
            true,
            session,
            None,
            Some(browser.handle.as_str()),
            Some("http://collector.example"),
            403,
        ),
        (
            true,
            session,
            None,
            Some(browser.handle.as_str()),
            Some("https://collector.example:444"),
            403,
        ),
        (
            true,
            session,
            None,
            Some(browser.handle.as_str()),
            Some("https://other.collector.example"),
            403,
        ),
        (
            true,
            session,
            None,
            Some(browser.handle.as_str()),
            Some("null"),
            403,
        ),
    ];
    for (protocol, target, bearer, browser_cookie, origin, expected) in cases {
        let mut req = request(protocol, target);
        if let Some(origin) = origin {
            with_origin(req.headers_mut(), origin);
        }
        if let Some(bearer) = bearer {
            req.headers_mut().insert(
                hyper::header::AUTHORIZATION,
                format!("Bearer {bearer}").parse().unwrap(),
            );
        }
        if let Some(handle) = browser_cookie {
            req.headers_mut()
                .insert(hyper::header::COOKIE, cookie(handle).parse().unwrap());
        }
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_tungstenite::client_async(req, tcp),
        )
        .await
        .unwrap();
        assert!(
            matches!(result, Err(WsError::Http(response)) if response.status().as_u16() == expected),
            "unexpected refusal status {expected}"
        );
    }

    crate::mission_control::tests::synthetic_transport_record(&issuer, &delegated.handle);
    for (credential, from_cookie, class) in [
        (&browser, true, "browser"),
        (&native, false, "native"),
        (&machine, false, "machine"),
        (&delegated, false, "delegated"),
    ] {
        let mut req = request(true, session);
        if from_cookie {
            with_origin(req.headers_mut(), "https://collector.example");
            req.headers_mut().insert(
                hyper::header::COOKIE,
                cookie(&credential.handle).parse().unwrap(),
            );
        } else {
            req.headers_mut().insert(
                hyper::header::AUTHORIZATION,
                format!("Bearer {}", credential.handle).parse().unwrap(),
            );
        }
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut ws, response) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_tungstenite::client_async(req, tcp),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        ws.send(Message::Text(
            r#"{"v":1,"type":"hello","protocol":1,"id":1,"capabilities":["observe","commands"]}"#
                .into(),
        ))
        .await
        .unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
        assert_eq!(json["type"], "hello");
        assert_eq!(json["actor"]["class"], class);
        assert_eq!(json["actor"]["principal"], credential.record.principal);
        assert_eq!(json["capabilities"], serde_json::json!(["observe"]));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let snapshot = format!("{}/v1/mission-control/snapshot/fleet", f.url);
    for (origin, site, expect) in [
        (Some("https://collector.example"), None, 200),
        (None, Some("same-origin"), 200),
        (None, Some("cross-site"), 403),
        (None, Some("same-site"), 403),
        (None, None, 403),
        (
            Some("https://other.collector.example"),
            Some("same-origin"),
            403,
        ),
    ] {
        let mut req = client
            .get(&snapshot)
            .header(hyper::header::COOKIE, cookie(&browser.handle));
        if let Some(origin) = origin {
            req = req.header(hyper::header::ORIGIN, origin);
        }
        if let Some(site) = site {
            req = req.header("sec-fetch-site", site);
        }
        let response = req.send().await.unwrap();
        assert_eq!(response.status().as_u16(), expect);
        assert_eq!(response.headers()[hyper::header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[hyper::header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert!(!response
            .headers()
            .contains_key(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }
    let duplicated = client
        .head(&snapshot)
        .header(hyper::header::COOKIE, cookie(&browser.handle))
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .unwrap();
    assert_eq!(duplicated.status(), StatusCode::FORBIDDEN);
    let invalid = client
        .get(format!("{snapshot}?x=1"))
        .bearer_auth(&machine.handle)
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid.json::<serde_json::Value>().await.unwrap()["code"],
        "bad_message"
    );
    let refused = client.get(&snapshot).send().await.unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        refused.json::<serde_json::Value>().await.unwrap()["code"],
        "unauthenticated"
    );
    let cookie_stream = client
        .get(format!("{}/v1/mission-control/stream/fleet", f.url))
        .header(hyper::header::COOKIE, cookie(&browser.handle))
        .header(hyper::header::ORIGIN, "https://collector.example")
        .send()
        .await
        .unwrap();
    assert_eq!(cookie_stream.status(), StatusCode::UNAUTHORIZED);
    for route in ["commands/prepare", "commands/commit"] {
        let response = client
            .post(format!("{}/v1/mission-control/{route}", f.url))
            .bearer_auth(&machine.handle)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let receipt = client
        .get(format!("{}/v1/receipts/fixture", f.url))
        .bearer_auth(&machine.handle)
        .send()
        .await
        .unwrap();
    assert_eq!(receipt.status(), StatusCode::NOT_FOUND);

    f.state.read_hub.as_ref().unwrap().fill_snapshot_for_test();
    let narrow =
        crate::mission_control::tests::scoped_transport_machine(&issuer, &browser.record.principal);
    let mut denied = Vec::new();
    for node in ["node-01", "missing"] {
        let response = client
            .get(format!("{}/v1/mission-control/snapshot/node/{node}", f.url))
            .bearer_auth(&narrow.handle)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        denied.push(response.bytes().await.unwrap());
    }
    assert_eq!(denied[0], denied[1]);
    let fleet = client
        .get(&snapshot)
        .bearer_auth(&narrow.handle)
        .send()
        .await
        .unwrap();
    assert_eq!(fleet.status(), StatusCode::OK);
    let fleet: serde_json::Value = fleet.json().await.unwrap();
    assert_eq!(fleet["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(fleet["nodes"][0]["node"], "fixture.node");
    let over_budget = client
        .get(&snapshot)
        .bearer_auth(&narrow.handle)
        .send()
        .await
        .unwrap();
    assert_eq!(over_budget.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(over_budget
        .headers()
        .contains_key(hyper::header::RETRY_AFTER));
}

struct VectorSocket {
    io: tokio::io::BufReader<tokio::net::TcpStream>,
}

impl VectorSocket {
    async fn open(fixture: &Fixture, handle: &str) -> Self {
        use tokio::io::AsyncBufReadExt;
        let address = fixture.url.strip_prefix("http://").unwrap();
        let mut io = tokio::net::TcpStream::connect(address).await.unwrap();
        io.write_all(format!(
            "GET /v1/mission-control/session HTTP/1.1\r\nHost: {address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: xmsg.mission-control.v1\r\nSec-WebSocket-Extensions: permessage-deflate\r\nAuthorization: Bearer {handle}\r\n\r\n",
        ).as_bytes()).await.unwrap();
        let mut io = tokio::io::BufReader::new(io);
        let mut status = String::new();
        io.read_line(&mut status).await.unwrap();
        assert!(
            status.starts_with("HTTP/1.1 101"),
            "independent upgrade refused"
        );
        let mut selected = false;
        loop {
            let mut header = String::new();
            assert!(io.read_line(&mut header).await.unwrap() > 0);
            if header == "\r\n" {
                break;
            }
            let header = header.to_ascii_lowercase();
            assert!(!header.starts_with("sec-websocket-extensions:"));
            selected |= header == "sec-websocket-protocol: xmsg.mission-control.v1\r\n";
        }
        assert!(selected, "subprotocol was not selected");
        Self { io }
    }

    async fn send(&mut self, opcode: u8, payload: &[u8], masked: bool) {
        let mut wire = vec![0x80 | opcode];
        let mask_bit = if masked { 0x80 } else { 0 };
        if payload.len() < 126 {
            wire.push(mask_bit | payload.len() as u8);
        } else {
            wire.push(mask_bit | 126);
            wire.extend_from_slice(&(u16::try_from(payload.len()).unwrap()).to_be_bytes());
        }
        if masked {
            let mask = [0x61, 0x62, 0x63, 0x64];
            wire.extend_from_slice(&mask);
            wire.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % 4]),
            );
        } else {
            wire.extend_from_slice(payload);
        }
        self.io.get_mut().write_all(&wire).await.unwrap();
    }

    async fn frame(&mut self) -> (u8, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(6), async {
            let first = self.io.read_u8().await.unwrap();
            let second = self.io.read_u8().await.unwrap();
            assert_eq!(second & 0x80, 0);
            let length = match second & 0x7f {
                126 => self.io.read_u16().await.unwrap() as usize,
                127 => usize::try_from(self.io.read_u64().await.unwrap()).unwrap(),
                length => length as usize,
            };
            assert!(length <= 262_144);
            let mut bytes = vec![0; length];
            self.io.read_exact(&mut bytes).await.unwrap();
            (first & 0xf, bytes)
        })
        .await
        .unwrap()
    }

    async fn json(&mut self) -> serde_json::Value {
        let (opcode, bytes) = self.frame().await;
        assert_eq!(opcode, 1);
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn close_code(&mut self) -> u16 {
        let (opcode, bytes) = self.frame().await;
        assert_eq!(opcode, 8);
        u16::from_be_bytes(bytes[..2].try_into().unwrap())
    }

    async fn hello(&mut self) {
        self.send(
            1,
            include_bytes!("../tests/vectors/mission-control/v1/V-H1.json"),
            true,
        )
        .await;
        assert_eq!(self.json().await["type"], "hello");
    }
}

#[tokio::test]
async fn mission_control_independent_wire_client_exercises_read_vectors() {
    let oidc =
        crate::enroll_oidc::signed_fixture::Fixture::new_at(crate::storage::now_epoch_secs()).await;
    let directory = tempfile::tempdir().unwrap();
    let (issuer, issued) =
        crate::mission_control::tests::transport_fixture(&oidc, &directory).await;
    let f = Fixture::with_issuer(false, true, Some(issuer), None).await;

    let mut socket = VectorSocket::open(&f, &issued.handle).await;
    socket
        .send(
            1,
            include_bytes!("../tests/vectors/mission-control/v1/V-I2.json"),
            true,
        )
        .await;
    assert_eq!(socket.json().await["code"], "version_mismatch");
    assert_eq!(socket.close_code().await, 4409);

    let mut socket = VectorSocket::open(&f, &issued.handle).await;
    socket
        .send(
            1,
            include_bytes!("../tests/vectors/mission-control/v1/V-S1.json"),
            true,
        )
        .await;
    assert_eq!(socket.json().await["code"], "bad_message");
    assert_eq!(socket.close_code().await, 4400);

    let mut socket = VectorSocket::open(&f, &issued.handle).await;
    socket.hello().await;
    for (vector, code) in [
        ("V-I3", "bad_message"),
        ("V-I4", "bad_message"),
        ("V-I5", "bad_message"),
        ("V-I6", "not_found_or_denied"),
        ("V-I7", "bad_message"),
        ("V-I8", "bad_message"),
        ("V-I10", "unsupported_type"),
        ("V-I11", "unsupported"),
        ("V-I25", "bad_message"),
        ("V-I26", "bad_message"),
    ] {
        let bytes = std::fs::read(format!(
            "{}/tests/vectors/mission-control/v1/{vector}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        socket.send(1, &bytes, true).await;
        assert_eq!(socket.json().await["code"], code, "{vector}");
    }

    socket
        .send(
            1,
            include_bytes!("../tests/vectors/mission-control/v1/V-S1.json"),
            true,
        )
        .await;
    assert_eq!(socket.json().await["type"], "subscribed");
    let cursor = loop {
        let value = socket.json().await;
        assert_eq!(value["type"], "snapshot");
        if value["final"] == true {
            break value["cursor"].as_str().unwrap().to_owned();
        }
    };
    assert!(!cursor.is_empty());
    let source_event = f
        .state
        .read_hub
        .as_ref()
        .unwrap()
        .witness_activity_for_test("fixture.node");
    let observed = socket.json().await;
    assert_eq!(observed["type"], "event");
    assert!(observed.get("replayed").is_none());
    assert_eq!(
        observed["delta"]["event"],
        serde_json::to_value(source_event).unwrap()
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let mut sse = client
        .get(format!("{}/v1/mission-control/stream/fleet", f.url))
        .header("last-event-id", &cursor)
        .bearer_auth(&issued.handle)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let mut bytes = Vec::new();
    let replayed = loop {
        bytes.extend(sse.chunk().await.unwrap().unwrap());
        let text = std::str::from_utf8(&bytes).unwrap();
        if let Some((_, tail)) = text.split_once("data: ") {
            if let Some((data, _)) = tail.split_once("\n\n") {
                break serde_json::from_str::<serde_json::Value>(data).unwrap();
            }
        }
    };
    assert_eq!(replayed["type"], "event");
    assert_eq!(replayed["replayed"], true);
    assert_eq!(replayed["delta"], observed["delta"]);
    assert_eq!(replayed["cursor"], observed["cursor"]);
    drop(sse);

    socket
        .send(
            1,
            br#"{"v":1,"type":"unsubscribe","id":9,"sub":"fleet"}"#,
            true,
        )
        .await;
    assert_eq!(socket.json().await["type"], "unsubscribed");
    let replay = json!({"v":1,"type":"subscribe","id":10,"sub":"fleet","scope":{"kind":"fleet"},"cursor":cursor});
    socket.send(1, replay.to_string().as_bytes(), true).await;
    assert_eq!(socket.json().await["mode"], "resume");

    for (opcode, length, masked, code) in [
        (2, 1, true, 1003),
        (1, 1, false, 1002),
        (1, 16_385, true, 1009),
    ] {
        let mut socket = VectorSocket::open(&f, &issued.handle).await;
        socket.hello().await;
        socket.send(opcode, &vec![b'x'; length], masked).await;
        assert_eq!(socket.close_code().await, code);
    }
}
