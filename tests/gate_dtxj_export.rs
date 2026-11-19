use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use xmsg::fed::{FedState, PeersMap, RateLimiter};
use xmsg::observe::{Config, Observation, Observer};

const BODY_CANARY: &str = "DTXJ_BODY_CANARY_NOT_METADATA";
const PATH_CANARY: &str = "/synthetic/dtxj/private/path";
const LABEL_CANARY: &str = "DTXJ_LABEL_CANARY";

struct Fixture {
    task: tokio::task::JoinHandle<()>,
    controls: Arc<xmsg::observe_fed::test_hooks::Controls>,
    observer: Arc<Observer>,
    state: Arc<FedState>,
    address: SocketAddr,
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
    server_pin: String,
    client_name: String,
    directory: TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    async fn new(rights: &[&str]) -> Self {
        Self::with_rate(rights, 60).await
    }

    async fn with_rate(rights: &[&str], rate: u32) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_cert = server.cert.der().to_vec();
        let client_cert = client.cert.der().to_vec();
        let server_pin = xmsg::fed::spki_sha256_from_der(&server_cert).unwrap();
        let client_pin = xmsg::fed::spki_sha256_from_der(&client_cert).unwrap();
        let server_name = xmsg::node::node_name_from_pin(&server_pin).unwrap();
        let client_name = xmsg::node::node_name_from_pin(&client_pin).unwrap();
        let config = json!({client_name.clone(): {
            "address": "127.0.0.1:1", "pin": client_pin, "allow": rights
        }});
        let peers = PeersMap::load_from_json(&config.to_string()).unwrap();
        let connection =
            rusqlite::Connection::open(directory.path().join("primary.sqlite")).unwrap();
        xmsg::storage::init_db(&connection).unwrap();
        connection.execute("INSERT INTO messages(id,created_at,session_id,from_name,bytes,outcome) VALUES('message-canary',?1,'receiver','sender',1,'queued')",[xmsg::storage::now_epoch_secs()]).unwrap();
        xmsg::storage::insert_reply(
            &connection,
            "message-canary",
            "sender",
            BODY_CANARY,
            Some("stored"),
            None,
        )
        .unwrap();
        connection.execute("INSERT INTO instance_seen(id,harness,last_live) VALUES('11111111-1111-4111-8111-111111111111','claude',?1)",[xmsg::storage::now_epoch_secs()]).unwrap();
        connection.execute("INSERT INTO codex_roots(root_id,codex_home,owner_pid,owner_starttime,generation,label,cwd,registered_at) VALUES('22222222-2222-4222-8222-222222222222',?1,0,'synthetic',1,?2,?1,?3)",rusqlite::params![PATH_CANARY,LABEL_CANARY,xmsg::storage::now_epoch_secs()]).unwrap();
        let state = Arc::new(FedState {
            node_name: server_name.clone(),
            peers: Arc::new(peers).into(),
            cert_der: server_cert.clone(),
            cert_chain_der: vec![server_cert],
            key_der: server.signing_key.serialize_der(),
            rate_limiter: Arc::new(RateLimiter::new(rate, 20)),
            db: Arc::new(Mutex::new(connection)),
            sessions_dirs: vec![directory.path().join("must-not-scan")],
            agy_config: xmsg::agy::AgyConfig {
                presence_dir: directory.path().join("presence"),
                proc_locks_path: directory.path().join("locks"),
                proc_root: directory.path().join("proc"),
                agy_bin: "synthetic-agy".into(),
                trusted_agy_exes: Vec::new(),
                brain_dir: directory.path().join("brain"),
                ..Default::default()
            },
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
            reply_ttl: Duration::from_secs(7 * 86400),
            list_queries: Default::default(),
        });
        let observer = Observer::start(
            &state.db,
            &directory.path().join("journal.sqlite"),
            &server_name,
            Config::default(),
        );
        let now = xmsg::storage::now_epoch_secs();
        observer.publish(vec![Observation {
            source_at: Some(now),
            kind: "message_recorded".into(),
            from: Some(format!("sender@{server_name}")),
            to: Some(format!("receiver@{server_name}")),
            message_id: Some("message-canary".into()),
            thread_id: Some("thread-canary".into()),
            outcome: Some("queued".into()),
            reason: Some(PATH_CANARY.into()),
            body_availability: "not_recorded".into(),
            ..Default::default()
        }]);
        assert!(
            observer.flush_for_test(Duration::from_secs(3)),
            "journal fixture did not initialize"
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let controls = xmsg::observe_fed::test_hooks::controls(&state);
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            xmsg::fed::run_fed_listener(listener, server_state)
                .await
                .unwrap();
        });
        Self {
            task,
            controls,
            observer,
            state,
            address,
            client_cert,
            client_key: client.signing_key.serialize_der(),
            server_pin,
            client_name,
            directory,
        }
    }

    async fn connect(
        &self,
    ) -> (
        hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        tokio::task::JoinHandle<()>,
    ) {
        self.connect_as(&self.client_cert, &self.client_key).await
    }

    async fn connect_as(
        &self,
        cert: &[u8],
        key: &[u8],
    ) -> (
        hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        tokio::task::JoinHandle<()>,
    ) {
        let connector = xmsg::fed::make_tls_connector(cert, key, &self.server_pin).unwrap();
        let tcp = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        (sender, connection)
    }

    async fn exchange(
        sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        uri: &str,
        content: &'static str,
    ) -> (u16, Value) {
        Self::exchange_with_encoding(sender, uri, content, false).await
    }

    async fn exchange_with_encoding(
        sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        uri: &str,
        content: &'static str,
        chunked: bool,
    ) -> (u16, Value) {
        tokio::time::timeout(Duration::from_secs(8), sender.ready())
            .await
            .unwrap()
            .unwrap();
        let mut request = hyper::Request::get(uri).header("host", "localhost");
        if chunked {
            request = request.header("transfer-encoding", "chunked");
        }
        let request = request
            .body(Full::new(Bytes::from_static(content.as_bytes())))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(8), sender.send_request(request))
            .await
            .unwrap()
            .unwrap();
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = tokio::time::timeout(Duration::from_secs(8), body.frame())
            .await
            .unwrap()
        {
            if let Ok(data) = frame.unwrap().into_data() {
                bytes.extend_from_slice(&data);
            }
            assert!(
                bytes.len() <= 1024 * 1024,
                "fixture response exceeded safety bound"
            );
        }
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn request(&self, uri: &str) -> (u16, Value) {
        let (mut sender, connection) = self.connect().await;
        let response = Self::exchange(&mut sender, uri, "").await;
        connection.abort();
        response
    }

    fn configure(&self, edit: impl FnOnce(&mut Value)) {
        let mut config = serde_json::to_value(
            self.state
                .current_peers()
                .get_peer_config(&self.client_name)
                .unwrap(),
        )
        .unwrap();
        edit(&mut config);
        self.replace_peers(json!({self.client_name.clone():config}));
    }

    fn replace_peers(&self, configs: Value) {
        let mut peers = PeersMap::load_from_json(&configs.to_string()).unwrap();
        peers.admitted_clients = self.state.current_peers().admitted_clients.clone();
        let peers = Arc::new(peers);
        let cert_chain = self.state.cert_chain();
        let key_der = self.state.key_der();
        let acceptor = xmsg::fed::make_tls_acceptor(&cert_chain, &key_der, peers.clone()).unwrap();
        *self.state.dynamic_tls.write().unwrap() = Some(xmsg::fed::DynamicTls {
            cert_der: self.state.cert_der.clone(),
            cert_chain_der: self.state.cert_chain_der.clone(),
            key_der,
            peers,
            ca_anchors: HashMap::new(),
            acceptor,
        });
    }

    fn ca_identity(&mut self) -> std::path::PathBuf {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_file = self.directory.path().join("synthetic-ca.pem");
        std::fs::write(&ca_file, ca.pem()).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://xmsg/host/collector/user/owner"
                .try_into()
                .unwrap(),
        )];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params
            .signed_by(&key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        self.client_name = "owner.collector".into();
        self.client_cert = cert.der().to_vec();
        self.client_key = key.serialize_der();
        ca_file
    }

    fn primary_state(&self) -> (u64, i64, String, i64) {
        let connection = self.state.db.lock().unwrap();
        (
            connection.total_changes(),
            connection
                .query_row("SELECT active FROM codex_roots", [], |r| r.get(0))
                .unwrap(),
            connection
                .query_row("SELECT text FROM replies", [], |r| r.get(0))
                .unwrap(),
            connection
                .query_row(
                    "SELECT count(*) FROM sqlite_temp_schema WHERE type='table'",
                    [],
                    |r| r.get(0),
                )
                .unwrap(),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observe_right_is_explicit_and_exports_only_metadata() {
    let denied = Fixture::new(&["list", "send", "reply"]).await;
    let (status, _) = denied.request("/fed/v2/observe/events?after=0").await;
    assert_eq!(
        status, 403,
        "peer without explicit observe right must be denied"
    );
    let granted = Fixture::new(&["observe"]).await;
    let (status, page) = granted.request("/fed/v2/observe/events?after=0").await;
    assert_eq!(
        status, 200,
        "explicit observe peer must read journal metadata"
    );
    assert_eq!(
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["message_id"] == "message-canary")
            .count(),
        1,
        "recorded event absent or duplicated"
    );
    let wire = page.to_string();
    assert!(
        !wire.contains(BODY_CANARY),
        "reply body crossed metadata export"
    );
    assert!(
        !wire.contains(PATH_CANARY),
        "raw reason/path crossed metadata export"
    );
    assert!(
        page.get("head").is_none() && page.get("floor").is_none() && page.get("losses").is_none(),
        "raw journal counters crossed dedicated export schema"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_is_cached_scoped_and_labels_need_both_opt_ins() {
    let fixture = Fixture::new(&["observe"]).await;
    let before = fixture.primary_state();
    let (status, snapshot) = fixture
        .request("/fed/v2/observe/snapshot?labels=true")
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        snapshot["available"], "partial",
        "cached catalog must not claim complete discovery"
    );
    assert!(
        snapshot["endpoints"].as_array().unwrap().len() >= 2,
        "stored registration metadata missing"
    );
    assert!(
        !snapshot.to_string().contains(LABEL_CANARY),
        "labels leaked without peer opt-in"
    );
    fixture.configure(|config| {
        config["observe_labels"] = json!(true);
    });
    let (status, snapshot) = fixture.request("/fed/v2/observe/snapshot").await;
    assert_eq!(status, 200);
    assert!(
        !snapshot.to_string().contains(LABEL_CANARY),
        "labels leaked without request opt-in"
    );
    let (status, snapshot) = fixture
        .request("/fed/v2/observe/snapshot?labels=true")
        .await;
    assert_eq!(status, 200);
    assert!(
        snapshot.to_string().contains(LABEL_CANARY),
        "explicit label opt-ins lost label"
    );
    assert!(
        !snapshot.to_string().contains(PATH_CANARY),
        "snapshot copied a private path"
    );
    assert!(
        !snapshot.to_string().contains(BODY_CANARY),
        "snapshot copied a reply body"
    );
    assert_eq!(
        fixture.primary_state(),
        before,
        "snapshot initialized or changed primary state"
    );
    assert!(!fixture.directory.path().join("must-not-scan").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn target_scope_omission_and_empty_are_distinct() {
    let fixture = Fixture::new(&["observe"]).await;
    fixture.configure(|config| {
        config["targets"] = json!(["sender"]);
    });
    let (_, page) = fixture.request("/fed/v2/observe/events?after=0").await;
    assert!(
        page["events"].as_array().unwrap().is_empty(),
        "excluded destination leaked through a correlation"
    );
    assert!(!page.to_string().contains("message-canary"));
    fixture.configure(|config| {
        config["targets"] = json!(["receiver"]);
    });
    let (_, page) = fixture.request("/fed/v2/observe/events?after=0").await;
    assert!(
        page["events"].as_array().unwrap().is_empty(),
        "excluded sender leaked through a correlation"
    );
    fixture.configure(|config| {
        config["targets"] = json!([]);
    });
    let (_, snapshot) = fixture.request("/fed/v2/observe/snapshot").await;
    assert!(
        snapshot["endpoints"].as_array().unwrap().is_empty(),
        "empty targets widened to all registrations"
    );
    fixture.configure(|config| {
        config.as_object_mut().unwrap().remove("targets");
    });
    let (_, page) = fixture.request("/fed/v2/observe/events?after=0").await;
    assert!(page["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["message_id"] == "message-canary"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_precedes_query_parsing_and_queries_are_bounded() {
    let denied = Fixture::new(&["list"]).await;
    assert_eq!(
        denied
            .request("/fed/v2/observe/events?after=not-a-number")
            .await
            .0,
        403,
        "query validation bypassed observe admission"
    );
    let fixture = Fixture::new(&["observe"]).await;
    for query in [
        "v=2",
        "after=-1",
        "after=1",
        "limit=0",
        "limit=201",
        "unexpected=1",
        "epoch=",
    ] {
        assert_eq!(
            fixture
                .request(&format!("/fed/v2/observe/events?{query}"))
                .await
                .0,
            400,
            "invalid cursor query accepted: {query}"
        );
    }
    let zeroes = "0".repeat(1100);
    assert_eq!(
        zeroes.parse::<i64>().unwrap(),
        0,
        "oversize query fixture must remain numerically valid"
    );
    assert_eq!(
        fixture
            .request(&format!("/fed/v2/observe/events?after={zeroes}"))
            .await
            .0,
        400,
        "oversized raw query accepted"
    );
    let version = format!("{zeroes}1");
    assert_eq!(
        version.parse::<u8>().unwrap(),
        1,
        "oversize snapshot fixture must remain a valid version"
    );
    assert_eq!(
        fixture
            .request(&format!("/fed/v2/observe/snapshot?v={version}"))
            .await
            .0,
        400,
        "oversized snapshot query accepted"
    );
    assert_eq!(
        fixture.request("/fed/v2/observe/snapshot?after=0").await.0,
        400,
        "snapshot accepted a cursor field"
    );
    assert_eq!(
        fixture.request("/fed/v2/observe/events?after=0").await.0,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_time_filter_does_not_depend_on_journal_maintenance() {
    let fixture = Fixture::new(&["observe"]).await;
    let old = xmsg::storage::now_epoch_secs() - 8 * 86400;
    fixture.observer.set_time_for_test(old);
    fixture.observer.publish(vec![Observation {
        kind: "message_recorded".into(),
        message_id: Some("expired-canary".into()),
        from: Some("sender".into()),
        to: Some("receiver".into()),
        body_availability: "not_recorded".into(),
        ..Default::default()
    }]);
    assert!(fixture.observer.flush_for_test(Duration::from_secs(3)));
    assert!(
        fixture
            .observer
            .page(xmsg::observe::Query {
                after: Some(0),
                ..Default::default()
            })
            .unwrap()
            .events
            .iter()
            .any(|v| v.observation.message_id.as_deref() == Some("expired-canary")),
        "expiry fixture was deleted before the export predicate"
    );
    let (_, page) = fixture.request("/fed/v2/observe/events?after=0").await;
    assert!(
        !page.to_string().contains("expired-canary"),
        "export leaked expired metadata before maintenance"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_invalidates_old_tls_but_fresh_handshake_succeeds() {
    let fixture = Fixture::new(&["observe"]).await;
    let (mut sender, connection) = fixture.connect().await;
    assert_eq!(
        Fixture::exchange(&mut sender, "/fed/v2/observe/events", "")
            .await
            .0,
        200
    );
    fixture.configure(|_| {});
    assert_eq!(
        Fixture::exchange(&mut sender, "/fed/v2/observe/events", "")
            .await
            .0,
        403,
        "old TLS policy survived reload"
    );
    assert_eq!(
        fixture.request("/fed/v2/observe/events").await.0,
        200,
        "fresh TLS did not recover after policy reload"
    );
    connection.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_during_prepared_response_refuses_events_and_snapshot() {
    let fixture = Fixture::new(&["observe"]).await;
    for uri in ["/fed/v2/observe/events", "/fed/v2/observe/snapshot"] {
        fixture.controls.before_emit.arm(1);
        let request = fixture.request(uri);
        let reload = async {
            tokio::time::timeout(
                Duration::from_secs(3),
                fixture.controls.before_emit.wait_for(1),
            )
            .await
            .unwrap();
            fixture.configure(|config| {
                config["allow"] = json!(["list"]);
            });
            fixture.controls.before_emit.release();
        };
        let ((status, page), ()) = tokio::join!(request, reload);
        assert_eq!(
            status, 403,
            "prepared metadata response survived policy revocation"
        );
        assert!(
            page.get("events").is_none() && page.get("endpoints").is_none(),
            "refusal contained prepared metadata"
        );
        fixture.configure(|config| {
            config["allow"] = json!(["observe"]);
        });
        assert_eq!(fixture.request(uri).await.0, 200);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_read_expires_inside_the_server_budget() {
    let fixture = Fixture::new(&["observe"]).await;
    for uri in ["/fed/v2/observe/events", "/fed/v2/observe/snapshot"] {
        fixture.controls.before_read.arm(1);
        let request = fixture.request(uri);
        let release = async {
            fixture.controls.before_read.wait_for(1).await;
            tokio::time::sleep(Duration::from_secs(6)).await;
            fixture.controls.before_read.release();
        };
        let ((status, _), ()) = tokio::join!(request, release);
        assert_eq!(
            status, 503,
            "held read bypassed the five-second server deadline"
        );
        assert_eq!(
            fixture.request(uri).await.0,
            200,
            "timed-out read leaked its permit"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_lock_contention_returns_partial_without_waiting() {
    let fixture = Fixture::new(&["observe"]).await;
    let db = fixture.state.db.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let holder = tokio::task::spawn_blocking(move || {
        let _guard = db.lock().unwrap();
        ready_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(7)).unwrap();
    });
    ready_rx.await.unwrap();
    let (status, page) = fixture.request("/fed/v2/observe/snapshot").await;
    release_tx.send(()).unwrap();
    holder.await.unwrap();
    assert_eq!(status, 200, "snapshot waited on primary bus lock");
    assert_eq!(page["available"], "partial");
    assert_eq!(fixture.request("/fed/v2/observe/snapshot").await.0, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_body_and_disallowed_source_are_refused() {
    let fixture = Fixture::new(&["observe"]).await;
    for uri in ["/fed/v2/observe/events", "/fed/v2/observe/snapshot"] {
        let (mut sender, connection) = fixture.connect().await;
        assert_eq!(
            Fixture::exchange(&mut sender, uri, "nonempty").await.0,
            400,
            "GET body accepted by metadata exporter"
        );
        assert_eq!(
            Fixture::exchange_with_encoding(&mut sender, uri, "nonempty", true)
                .await
                .0,
            400,
            "chunked GET body accepted by metadata exporter"
        );
        connection.abort();
    }
    fixture.configure(|config| {
        config["from"] = json!(["192.0.2.0/24"]);
    });
    assert_eq!(
        fixture.request("/fed/v2/observe/events").await.0,
        403,
        "observe ignored peer source policy"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observe_rate_bucket_is_separate_and_shared_by_both_export_routes() {
    let fixture = Fixture::with_rate(&["observe"], 1).await;
    assert!(fixture
        .state
        .rate_limiter
        .check_and_consume(&fixture.client_name, None));
    assert_eq!(
        fixture.request("/fed/v2/observe/events").await.0,
        200,
        "normal federation bucket throttled observation"
    );
    assert_eq!(
        fixture.request("/fed/v2/observe/events").await.0,
        429,
        "observation peer rate limit bypassed"
    );
    assert_eq!(
        fixture.request("/fed/v2/observe/snapshot").await.0,
        429,
        "snapshot bypassed shared observation bucket"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_slots_are_bounded_globally_across_peers_and_routes() {
    slot_bound_control(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timed_out_blocking_reads_keep_their_slots_until_io_finishes() {
    slot_bound_control(true).await;
}

async fn slot_bound_control(wait_for_timeout: bool) {
    let fixture = Arc::new(Fixture::new(&["observe"]).await);
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let second_cert = second.cert.der().to_vec();
    let second_pin = xmsg::fed::spki_sha256_from_der(&second_cert).unwrap();
    let second_name = xmsg::node::node_name_from_pin(&second_pin).unwrap();
    let first = serde_json::to_value(
        fixture
            .state
            .current_peers()
            .get_peer_config(&fixture.client_name)
            .unwrap(),
    )
    .unwrap();
    fixture.replace_peers(json!({fixture.client_name.clone():first,second_name:{"address":"127.0.0.1:1","pin":second_pin,"allow":["observe"]}}));
    fixture.controls.before_io.arm(8);
    let mut reads = Vec::new();
    for index in 0..8 {
        let fixture = fixture.clone();
        reads.push(tokio::spawn(async move {
            fixture
                .request(if index % 2 == 0 {
                    "/fed/v2/observe/events"
                } else {
                    "/fed/v2/observe/snapshot"
                })
                .await
                .0
        }));
    }
    tokio::time::timeout(
        Duration::from_secs(3),
        fixture.controls.before_io.wait_for(8),
    )
    .await
    .expect("eight baseline reads did not reach the forced gate");
    if wait_for_timeout {
        for read in reads.drain(..) {
            assert_eq!(
                read.await.unwrap(),
                503,
                "held blocking read did not reach its handler deadline"
            );
        }
    }
    let (mut sender, connection) = fixture
        .connect_as(&second_cert, &second.signing_key.serialize_der())
        .await;
    let ninth = Fixture::exchange(&mut sender, "/fed/v2/observe/events", "")
        .await
        .0;
    fixture.controls.before_io.release();
    tokio::time::timeout(
        Duration::from_secs(3),
        fixture.controls.workers_done.wait_for(8),
    )
    .await
    .expect("released blocking workers did not finish");
    for read in reads {
        assert_eq!(
            read.await.unwrap(),
            200,
            "admitted bounded read did not complete"
        );
    }
    assert_eq!(
        ninth, 429,
        "ninth cross-peer read bypassed the global eight-slot cap"
    );
    assert_eq!(
        Fixture::exchange(&mut sender, "/fed/v2/observe/snapshot", "")
            .await
            .0,
        200,
        "released read slots did not recover"
    );
    connection.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn literal_ca_identity_needs_its_own_observe_grant() {
    let mut fixture = Fixture::new(&["observe"]).await;
    let ca_file = fixture.ca_identity();
    fixture.replace_peers(json!({"owner.collector":{
        "address":"127.0.0.1:1","ca":ca_file,"identities":["spiffe://xmsg/host/collector/user/owner"],"allow":["list"]
    }}));
    assert_eq!(
        fixture
            .request("/fed/v2/observe/events?after=invalid")
            .await
            .0,
        403,
        "CA admission implied observation authority"
    );
    fixture.configure(|config| {
        config["allow"] = json!(["observe"]);
    });
    assert_eq!(
        fixture
            .request("/fed/v2/observe/events?v=1&after=0&limit=100")
            .await
            .0,
        200,
        "explicit literal CA observer did not export metadata"
    );
    assert_eq!(
        fixture
            .request("/fed/v2/observe/snapshot?v=1&labels=false")
            .await
            .0,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_spanning_reload_does_not_acquire_the_new_policy_witness() {
    let fixture = Fixture::new(&["observe"]).await;
    fixture.controls.before_handshake.arm(1);
    let request = fixture.request("/fed/v2/observe/events");
    let reload = async {
        tokio::time::timeout(
            Duration::from_secs(2),
            fixture.controls.before_handshake.wait_for(1),
        )
        .await
        .unwrap();
        fixture.configure(|_| {});
        fixture.controls.before_handshake.release();
    };
    let ((status, _), ()) = tokio::join!(request, reload);
    assert_eq!(
        status, 403,
        "handshake spanning reload acquired the new policy witness"
    );
    assert_eq!(fixture.request("/fed/v2/observe/events").await.0, 200);
}

async fn held_dispatcher_readiness_control() {
    let (client, server) = tokio::io::duplex(4096);
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(client))
            .await
            .unwrap();
    let requests = Arc::new(AtomicU64::new(0));
    let observed = requests.clone();
    let server = tokio::spawn(async move {
        let service =
            hyper::service::service_fn(move |_request: hyper::Request<hyper::body::Incoming>| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                        Bytes::from_static(b"{}"),
                    )))
                }
            });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(server), service)
            .await;
    });
    let first = sender.send_request(
        hyper::Request::get("/first")
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    );
    assert!(
        !sender.is_ready(),
        "forced control did not consume the buffered slot"
    );
    let second = Fixture::exchange(&mut sender, "/second", "");
    tokio::pin!(second);
    let initial = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(std::future::Future::poll(second.as_mut(), cx))
    })
    .await;
    assert!(
        initial.is_pending(),
        "fixture sent before the paused dispatcher was released"
    );
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = tokio::time::timeout(Duration::from_secs(8), first)
        .await
        .unwrap()
        .unwrap();
    response.into_body().collect().await.unwrap();
    assert_eq!(second.await.0, 200);
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "fixture retried or replaced a request"
    );
    driver.abort();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_hub_resolver_cannot_restore_revoked_observe_authority() {
    held_dispatcher_readiness_control().await;
    let mut fixture = Fixture::new(&["observe"]).await;
    let ca_file = fixture.ca_identity();
    let hub = |rights: Vec<&str>| {
        json!({"peers":{},"hub":{
            "patterns":[{"pattern":"spiffe://xmsg/host/*/user/*","ca":ca_file}],
            "rules":[{"pattern":"spiffe://xmsg/host/collector/user/owner","allow":rights}]
        }})
    };
    fixture.replace_peers(hub(vec!["observe"]));
    assert_eq!(fixture.request("/fed/v2/observe/events").await.0, 200);
    let old = fixture.state.current_peers();
    fixture.replace_peers(hub(vec!["list"]));
    let (mut sender, connection) = fixture.connect().await;
    assert_eq!(
        Fixture::exchange(&mut sender, "/fed/v2/observe/events", "")
            .await
            .0,
        403
    );
    old.resolve_incoming_peer(
        &rustls::pki_types::CertificateDer::from(fixture.client_cert.clone()),
        &[],
    )
    .unwrap();
    let current = fixture.state.current_peers();
    let uri = xmsg::fed::extract_uri_sans(&fixture.client_cert)
        .unwrap()
        .remove(0);
    assert!(
        current
            .admitted_clients
            .read()
            .unwrap()
            .get(&uri)
            .unwrap()
            .config
            .allow
            .iter()
            .any(|right| right == "observe"),
        "forced old resolver did not overwrite the shared cache"
    );
    assert!(
        !current
            .get_peer_config(&fixture.client_name)
            .unwrap()
            .allow
            .iter()
            .any(|right| right == "observe"),
        "current rule lookup restored a stale observe grant"
    );
    assert_eq!(
        Fixture::exchange(&mut sender, "/fed/v2/observe/events", "")
            .await
            .0,
        403,
        "old shared hub cache restored revoked observe authority"
    );
    assert_eq!(
        Fixture::exchange(&mut sender, "/fed/v2/observe/snapshot", "")
            .await
            .0,
        403
    );
    connection.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_database_lock_cannot_stall_the_primary_bus_mutex() {
    let fixture = Fixture::new(&["observe"]).await;
    let writer =
        rusqlite::Connection::open(fixture.directory.path().join("primary.sqlite")).unwrap();
    assert_eq!(
        writer
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "delete",
        "external lock control needs rollback-journal locking"
    );
    writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let (status, page) = fixture.request("/fed/v2/observe/snapshot").await;
    let primary_available = fixture
        .state
        .db
        .try_lock()
        .map(|connection| {
            connection
                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .unwrap()
                == 1
        })
        .unwrap_or(false);
    writer.execute_batch("ROLLBACK").unwrap();
    assert!(
        primary_available,
        "snapshot SQL retained the primary bus mutex while externally busy"
    );
    assert_eq!(
        status, 200,
        "snapshot did not return partial promptly under an external database lock"
    );
    assert_eq!(page["available"], "partial");
    assert_eq!(fixture.request("/fed/v2/observe/snapshot").await.0, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_bounds_source_work_before_projecting_the_catalog() {
    let fixture = Fixture::new(&["observe"]).await;
    {
        let connection = fixture.state.db.lock().unwrap();
        for index in 0..300 {
            let instance = format!("{index:08x}-aaaa-4111-8111-111111111111");
            let codex = format!("{index:08x}-bbbb-4111-8111-111111111111");
            connection
                .execute(
                    "INSERT INTO instance_seen(id,harness,last_live) VALUES(?1,'claude',?2)",
                    rusqlite::params![instance, xmsg::storage::now_epoch_secs()],
                )
                .unwrap();
            connection.execute("INSERT INTO codex_roots(root_id,codex_home,owner_pid,owner_starttime,generation,label,registered_at) VALUES(?1,'/synthetic',0,'synthetic',1,'synthetic',?2)",rusqlite::params![codex,xmsg::storage::now_epoch_secs()]).unwrap();
        }
    }
    let (status, page) = fixture.request("/fed/v2/observe/snapshot").await;
    assert_eq!(status, 200);
    assert_eq!(page["endpoints"].as_array().unwrap().len(), 200);
    assert_eq!(page["truncated"], true);
    assert_eq!(
        fixture
            .controls
            .snapshot_candidates
            .load(std::sync::atomic::Ordering::SeqCst),
        402,
        "snapshot exceeded bounded metadata-source work"
    );
    assert!(
        page["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["state"] == "seen"),
        "stored registration metadata was promoted to current liveness"
    );
}
