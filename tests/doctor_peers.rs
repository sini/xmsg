use rustls::pki_types::CertificateDer;
use serde_json::Value;
use std::collections::HashMap;
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use xmsg::fed::{FedState, PeerConfig, PeersMap, RateLimiter};
use xmsg::http::{bind_ucred_unix_listener, build_router, build_unix_router, AppState, HttpPeer};

const NODE: &str = "doctor.example";

struct Identity {
    cert: Vec<u8>,
    key: Vec<u8>,
    pin: String,
}

impl Identity {
    fn new(name: &str, before_hours: i64, after_hours: i64) -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(before_hours);
        params.not_after = now + time::Duration::hours(after_hours);
        let cert = params.self_signed(&key).unwrap().der().to_vec();
        Self {
            pin: xmsg::fed::spki_sha256_from_der(&cert).unwrap(),
            cert,
            key: key.serialize_der(),
        }
    }
}

#[derive(Clone, Copy)]
enum Date {
    Present(i64),
    Missing,
}

struct Peer {
    config: PeerConfig,
    requests: Arc<Mutex<Vec<String>>>,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Peer {
    async fn tls(name: &str, identity: Identity, client_pin: &str, date: Date) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let allowed = PeerConfig {
            name: NODE.into(),
            pin: Some(client_pin.into()),
            allow: vec!["send".into()],
            ..Default::default()
        };
        let peers = Arc::new(PeersMap::new(HashMap::from([(NODE.into(), allowed)])));
        let acceptor = xmsg::fed::make_tls_acceptor(
            &[CertificateDer::from(identity.cert)],
            &identity.key,
            peers,
        )
        .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = requests.clone();
        let accepted = Arc::new(AtomicUsize::new(0));
        let connections = accepted.clone();
        let task = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let (socket, _) = connection.unwrap();
                        connections.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let received = received.clone();
                        handlers.spawn(async move {
                            let mut tls = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(socket)).await.unwrap().unwrap();
                            assert_eq!(tls.get_ref().1.peer_certificates().unwrap().len(), 1, "probe did not present the held node identity");
                            let mut request = String::new();
                            {
                                let mut reader = BufReader::new(&mut tls);
                                loop {
                                    let mut line = String::new();
                                    let bytes = tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line)).await.unwrap().unwrap();
                                    assert!(bytes > 0, "probe closed before HTTP headers");
                                    request.push_str(&line);
                                    if line == "\r\n" { break; }
                                    assert!(request.len() < 8192, "unbounded fixture request");
                                }
                            }
                            received.lock().unwrap().push(request);
                            let date = match date {
                                Date::Present(offset) => format!("Date: {}\r\n", (chrono::Utc::now() + chrono::Duration::seconds(offset)).format("%a, %d %b %Y %H:%M:%S GMT")),
                                Date::Missing => String::new(),
                            };
                            tls.write_all(format!("HTTP/1.1 404 Not Found\r\n{date}Content-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                            let _ = tls.shutdown().await;
                        });
                    }
                    Some(result) = handlers.join_next(), if !handlers.is_empty() => result.unwrap(),
                }
            }
        });
        Self {
            config: PeerConfig {
                name: name.into(),
                address,
                pin: Some(identity.pin),
                allow: vec!["send".into()],
                ..Default::default()
            },
            requests,
            accepted,
            task,
        }
    }

    async fn blackhole(name: &str) -> Self {
        let identity = Identity::new(name, 1, 2);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let connections = accepted.clone();
        let task = tokio::spawn(async move {
            let mut holders = JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                connections.fetch_add(1, Ordering::SeqCst);
                holders.spawn(async move {
                    let _socket = socket;
                    std::future::pending::<()>().await;
                });
            }
        });
        Self {
            config: PeerConfig {
                name: name.into(),
                address,
                pin: Some(identity.pin),
                allow: vec!["send".into()],
                ..Default::default()
            },
            accepted,
            requests: Default::default(),
            task,
        }
    }

    fn assert_head_only(&self, minimum: usize) {
        let requests = self.requests.lock().unwrap();
        assert!(requests.len() >= minimum, "TLS fixture was never probed");
        for request in requests.iter() {
            assert_eq!(request.lines().next(), Some("HEAD / HTTP/1.1"), "{request}");
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case(&format!(
                        "user-agent: xmsg-doctor/{}",
                        env!("CARGO_PKG_VERSION")
                    ))),
                "unrecognisable doctor probe: {request}"
            );
            assert!(
                !request.contains("/fed/") && !request.contains("/v1/"),
                "probe entered a mutating/rate-limited application endpoint"
            );
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Fixture {
    root: TempDir,
    state: Arc<AppState>,
    server: JoinHandle<()>,
    _sockets: Vec<UnixListener>,
}

impl Fixture {
    async fn new(identity: Identity, peers: Vec<PeerConfig>) -> Self {
        Self::with_ca_config(identity, peers, None).await
    }

    async fn with_ca_config(
        identity: Identity,
        peers: Vec<PeerConfig>,
        config: Option<xmsg::ca_health::Config>,
    ) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let run = root.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(root.path().join("sessions")).unwrap();
        let db_path = root.path().join("primary.sqlite");
        let connection = rusqlite::Connection::open(&db_path).unwrap();
        xmsg::storage::init_db(&connection).unwrap();
        std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let db = Arc::new(Mutex::new(connection));
        let mut peers_map = HashMap::new();
        for peer in peers {
            peers_map.insert(peer.name.clone(), peer);
        }
        let fed = Arc::new(FedState {
            node_name: NODE.into(),
            peers: Arc::new(PeersMap::new(peers_map)).into(),
            cert_der: identity.cert,
            cert_chain_der: vec![],
            key_der: identity.key,
            rate_limiter: Arc::new(RateLimiter::new(60, 20)),
            db: db.clone(),
            sessions_dirs: vec![root.path().join("sessions")],
            agy_config: xmsg::agy::AgyConfig::default(),
            agy_store: xmsg::agy::new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            notify_tx: tokio::sync::broadcast::channel(16).0,
            max_body: 65536,
            max_attachment_bytes: 8 * 1024 * 1024,
            is_leaf: false,
            leaf_principal: None,
            outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
            dynamic_tls: Default::default(),
            reply_ttl: Duration::from_secs(3600),
            list_queries: Default::default(),
        });
        let state = Arc::new(AppState {
            sessions_dirs: fed.sessions_dirs.clone(),
            agy_config: fed.agy_config.clone(),
            agy_store: fed.agy_store.clone(),
            pi_store: fed.pi_store.clone(),
            pi_notify_tx: fed.pi_notify_tx.clone(),
            svc_store: fed.svc_store.clone(),
            svc_notify_tx: fed.svc_notify_tx.clone(),
            node_name: NODE.into(),
            max_body: 65536,
            max_attachment_bytes: 8 * 1024 * 1024,
            request_counter: AtomicU64::new(0),
            db,
            notify_tx: fed.notify_tx.clone(),
            reply_ttl: Duration::from_secs(3600),
            idempotency_ttl: Duration::from_secs(86400),
            long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
            fed_state: Some(fed),
        });
        xmsg::codex::init_for_state(&state, xmsg::codex::CodexConfig::default());
        let mut sockets = Vec::new();
        for name in ["agent.sock", "register.sock"] {
            let socket = UnixListener::bind(run.join(name)).unwrap();
            std::fs::set_permissions(run.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            sockets.push(socket);
        }
        let listener =
            bind_ucred_unix_listener(&run.join("http.sock"), xmsg::agent::current_uid(), None)
                .unwrap();
        let router = match config {
            Some(config) => xmsg::http::build_unix_router_with_enrollment(state.clone(), config),
            None => build_unix_router(state.clone()),
        };
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<HttpPeer>(),
            )
            .await
            .unwrap();
        });
        Self {
            root,
            state,
            server,
            _sockets: sockets,
        }
    }

    async fn diagnostics(&self) -> Value {
        let response = reqwest::Client::builder()
            .unix_socket(self.root.path().join("run/http.sock"))
            .no_proxy()
            .timeout(Duration::from_secs(12))
            .build()
            .unwrap()
            .get("http://localhost/v1/diagnostics/federation")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        response.json().await.unwrap()
    }

    async fn doctor(&self) -> (Output, Value) {
        let root = self.root.path().to_owned();
        let output = tokio::task::spawn_blocking(move || {
            Command::new(env!("CARGO_BIN_EXE_xmsg"))
                .env_remove("XMSG_PEERS_FILE")
                .env_remove("XMSG_FED_CERT")
                .env("HOME", root.join("home"))
                .env("XDG_STATE_HOME", root.join("state"))
                .env("XDG_RUNTIME_DIR", root.join("run"))
                .args(["doctor", "--json", "--http-sock"])
                .arg(root.join("run/http.sock"))
                .arg("--agent-sock")
                .arg(root.join("run/agent.sock"))
                .arg("--register-sock")
                .arg(root.join("run/register.sock"))
                .arg("--db-path")
                .arg(root.join("primary.sqlite"))
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid doctor JSON: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output, value)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn peer<'a>(value: &'a Value, name: &str) -> &'a Value {
    value["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("missing peer {name}: {value}"))
}

fn check<'a>(value: &'a Value, id: &str) -> &'a Value {
    value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
        .unwrap_or_else(|| panic!("missing check {id}: {value}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_identity_probes_report_expiry_and_clock_offset_using_only_head() {
    let own = Identity::new(NODE, 1, 2);
    let valid = Peer::tls(
        "valid.example",
        Identity::new("valid.example", 1, 2),
        &own.pin,
        Date::Present(0),
    )
    .await;
    let expiring = Peer::tls(
        "expiring.example",
        Identity::new("expiring.example", 8, 1),
        &own.pin,
        Date::Present(0),
    )
    .await;
    let skewed = Peer::tls(
        "skewed.example",
        Identity::new("skewed.example", 1, 2),
        &own.pin,
        Date::Present(600),
    )
    .await;
    let missing = Peer::tls(
        "missing-date.example",
        Identity::new("missing-date.example", 1, 2),
        &own.pin,
        Date::Missing,
    )
    .await;
    let fixture = Fixture::new(
        own,
        vec![
            valid.config.clone(),
            expiring.config.clone(),
            skewed.config.clone(),
            missing.config.clone(),
        ],
    )
    .await;
    let before = std::fs::read(fixture.root.path().join("primary.sqlite")).unwrap();
    let changes = fixture.state.db.lock().unwrap().total_changes();
    let result = fixture.diagnostics().await;
    assert_eq!(result["available"], true);
    assert_eq!(result["own_expiry"], "valid");
    for name in [
        "valid.example",
        "expiring.example",
        "skewed.example",
        "missing-date.example",
    ] {
        assert_eq!(peer(&result, name)["reachability"], "reachable", "{result}");
    }
    assert_eq!(
        peer(&result, "valid.example")["expiry"],
        "valid",
        "short lifetime must use its one-third threshold"
    );
    assert_eq!(peer(&result, "expiring.example")["expiry"], "expiring");
    assert_eq!(
        peer(&result, "valid.example")["offset_state"],
        "within_tolerance"
    );
    assert_eq!(
        peer(&result, "skewed.example")["offset_state"],
        "beyond_tolerance"
    );
    assert!(
        peer(&result, "skewed.example")["observed_offset_seconds"]
            .as_f64()
            .unwrap()
            > 590.0
    );
    assert_eq!(
        peer(&result, "missing-date.example")["offset_state"],
        "unknown"
    );
    let (output, doctor) = fixture.doctor().await;
    assert!(output.status.success(), "{doctor}");
    assert_eq!(
        check(&doctor, "peer.federation.valid.example")["status"],
        "pass"
    );
    for name in ["expiring.example", "skewed.example", "missing-date.example"] {
        assert_eq!(
            check(&doctor, &format!("peer.federation.{name}"))["status"],
            "warn",
            "{doctor}"
        );
    }
    assert_eq!(
        fixture.state.db.lock().unwrap().total_changes(),
        changes,
        "federation probe wrote to the primary store"
    );
    assert_eq!(
        std::fs::read(fixture.root.path().join("primary.sqlite")).unwrap(),
        before
    );
    for server in [&valid, &expiring, &skewed, &missing] {
        server.assert_head_only(2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_peer_that_never_starts_tls_is_refused_within_three_seconds() {
    let blackhole = Peer::blackhole("blackhole.example").await;
    let fixture = Fixture::new(Identity::new(NODE, 1, 2), vec![blackhole.config.clone()]).await;
    let result = tokio::time::timeout(Duration::from_secs(3), fixture.diagnostics())
        .await
        .expect("per-peer TLS blackhole exceeded three seconds");
    assert_eq!(
        peer(&result, "blackhole.example")["reachability"],
        "unreachable"
    );
    assert!(
        blackhole.accepted.load(Ordering::SeqCst) > 0,
        "blackhole fixture was not reached"
    );
    assert!(blackhole.requests.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_own_leaf_is_reported_and_new_diagnostic_route_is_unix_only() {
    use tower::ServiceExt;
    let fixture = Fixture::new(Identity::new(NODE, 2, -1), vec![]).await;
    let result = fixture.diagnostics().await;
    assert_eq!(result["own_expiry"], "expired");
    let (output, doctor) = fixture.doctor().await;
    assert_eq!(output.status.code(), Some(1), "{doctor}");
    assert_eq!(
        check(&doctor, "federation.local_certificate")["status"],
        "fail"
    );
    let response = build_router(fixture.state.clone())
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/diagnostics/federation")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 404, "diagnostic route exposed on TCP");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn addressless_peers_are_unknown_and_the_peer_inventory_is_bounded() {
    let identity = Identity::new(NODE, 1, 2);
    let peers = (0..33)
        .map(|i| PeerConfig {
            name: format!("peer-{i:02}.example"),
            pin: Some(identity.pin.clone()),
            allow: vec!["send".into()],
            ..Default::default()
        })
        .collect();
    let fixture = Fixture::new(identity, peers).await;
    let result = fixture.diagnostics().await;
    assert_eq!(result["peers"].as_array().unwrap().len(), 32);
    assert_eq!(result["truncated"], true);
    assert_eq!(result["partial"], true);
    assert!(result["peers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|peer| peer["reachability"] == "unknown"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ca_diagnostics_is_unix_only_and_distinguishes_disabled_from_unknown() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    for enabled in [Some(false), Some(true), None] {
        let fixture = Fixture::with_ca_config(
            Identity::new(NODE, 24, 48),
            vec![],
            Some(xmsg::ca_health::Config {
                enabled,
                ca_dir: None,
            }),
        )
        .await;
        let client = reqwest::Client::builder()
            .unix_socket(fixture.root.path().join("run/http.sock"))
            .no_proxy()
            .build()
            .unwrap();
        let response = client
            .get("http://localhost/v1/diagnostics/enrollment")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let value: Value = response.json().await.unwrap();
        assert_eq!(value["enabled"], serde_json::to_value(enabled).unwrap());
        assert_eq!(value["pending_approvals"], Value::Null);
        if enabled == Some(false) {
            assert_eq!(value["checks"].as_array().unwrap().len(), 1);
            assert_eq!(value["checks"][0]["status"], "pass");
        } else {
            assert_eq!(check(&value, "ca.root_expiry")["status"], "warn");
        }
        let (_, report) = fixture.doctor().await;
        assert!(check(&report, "ca.source")["message"]
            .as_str()
            .unwrap()
            .contains("runtime"));
        let request = || {
            Request::builder()
                .uri("/v1/diagnostics/enrollment")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            build_router(fixture.state.clone())
                .oneshot(request())
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            build_unix_router(fixture.state.clone())
                .oneshot(request())
                .await
                .unwrap()
                .status(),
            403
        );
    }
}
