use xmsg::fed::PeersMap;

#[test]
fn reverse_routes_are_explicit_closed_and_exact() {
    let valid = r#"{"peers":{},"reverse_observe":{"hub_enabled":true,"leaf_enabled":false,"routes":[{"hub":"spiffe://test/host/hub/user/owner","leaf":"spiffe://test/ns/leaves/sa/leaf","collector":"spiffe://test/ns/observers/sa/collector"}]}}"#;
    assert!(
        PeersMap::load_from_json(valid).is_ok(),
        "exact reverse route is admitted"
    );
    for refused in [
        valid.replace("spiffe://test/host/hub/user/owner", "spiffe://test/ns/leaves/sa/*"),
        valid.replace("\"hub_enabled\":true", "\"hub_enabled\":true,\"hub_enabled\":false"),
        valid.replace("\"leaf\":\"spiffe://test/ns/leaves/sa/leaf\"", "\"leaf\":\"spiffe://test/ns/leaves/sa/leaf\",\"leaf\":\"other.test\""),
        valid.replace("\"collector\":", "\"unknown\":false,\"collector\":"),
        valid.replace("\"routes\":", "\"unknown\":false,\"routes\":"),
        valid.replace("}]", "},{\"hub\":\"spiffe://test/host/hub/user/owner\",\"leaf\":\"spiffe://test/ns/leaves/sa/leaf\",\"collector\":\"spiffe://test/ns/observers/sa/collector\"}]"),
    ] {
        assert!(PeersMap::load_from_json(&refused).is_err(), "invalid route must refuse: {refused}");
    }
}

fn literal_route_config() -> serde_json::Value {
    serde_json::json!({"peers":{},"reverse_observe":{"routes":[{"hub":"spiffe://test/host/hub/user/owner","leaf":"spiffe://test/ns/leaves/sa/leaf","collector":"spiffe://test/ns/observers/sa/collector"}]}})
}
#[test]
fn reverse_config_absent_fields_default_independently_off_and_empty() {
    let empty = PeersMap::load_from_json(r#"{"peers":{}}"#).unwrap();
    assert!(!empty.reverse_observe.hub_enabled);
    assert!(!empty.reverse_observe.leaf_enabled);
    assert!(empty.reverse_observe.routes.is_empty());
    let base = literal_route_config();
    let peers = PeersMap::load_from_json(&base.to_string()).unwrap();
    assert!(
        !peers.reverse_observe.hub_enabled,
        "missing hub flag defaults off"
    );
    assert!(
        !peers.reverse_observe.leaf_enabled,
        "missing leaf flag defaults off"
    );
    assert_eq!(
        peers.reverse_observe.routes.len(),
        1,
        "matching explicit route survives default-off flags"
    );
    let mut leaf_only = base.clone();
    leaf_only["reverse_observe"]["leaf_enabled"] = serde_json::json!(true);
    let peers = PeersMap::load_from_json(&leaf_only.to_string()).unwrap();
    assert!(peers.reverse_observe.leaf_enabled);
    assert!(
        !peers.reverse_observe.hub_enabled,
        "leaf opt-in never supplies absent hub opt-in"
    );
    let mut hub_only = base;
    hub_only["reverse_observe"]["hub_enabled"] = serde_json::json!(true);
    let peers = PeersMap::load_from_json(&hub_only.to_string()).unwrap();
    assert!(peers.reverse_observe.hub_enabled);
    assert!(
        !peers.reverse_observe.leaf_enabled,
        "hub opt-in never supplies absent leaf opt-in"
    );
    let peers = PeersMap::load_from_json(
        r#"{"peers":{},"reverse_observe":{"hub_enabled":true,"leaf_enabled":true}}"#,
    )
    .unwrap();
    assert!(peers.reverse_observe.hub_enabled && peers.reverse_observe.leaf_enabled);
    assert!(
        peers.reverse_observe.routes.is_empty(),
        "both opt-ins never supply absent routes"
    );
}
#[test]
fn each_route_identity_refuses_an_otherwise_valid_spiffe_wildcard() {
    for (field, wildcard) in [
        ("hub", "spiffe://test/host/*/user/owner"),
        ("leaf", "spiffe://test/ns/*/sa/leaf"),
        ("collector", "spiffe://test/ns/observers/sa/*"),
    ] {
        let mut config = literal_route_config();
        assert!(
            PeersMap::load_from_json(&config.to_string()).is_ok(),
            "literal {field} positive"
        );
        config["reverse_observe"]["routes"][0][field] = serde_json::json!(wildcard);
        assert!(
            PeersMap::load_from_json(&config.to_string()).is_err(),
            "wildcard {field} identity must refuse independently of URI grammar"
        );
    }
}

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use serde_json::{json, Value};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use xmsg::fed::{FedState, RateLimiter};

#[derive(Clone)]
struct Identity {
    cert: Vec<u8>,
    key: Vec<u8>,
    pin: String,
    node: String,
    ca_identity: Option<(String, std::path::PathBuf)>,
}
impl Identity {
    fn new() -> Self {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = key.cert.der().to_vec();
        let pin = xmsg::fed::spki_sha256_from_der(&cert).unwrap();
        Self {
            node: xmsg::node::node_name_from_pin(&pin).unwrap(),
            cert,
            key: key.signing_key.serialize_der(),
            pin,
            ca_identity: None,
        }
    }
    fn full(&self) -> String {
        self.ca_identity.as_ref().map_or_else(
            || format!("sha256:{}", self.pin),
            |(identity, _)| identity.clone(),
        )
    }
    fn peer(&self, address: &str, rights: &[&str], leaf: bool) -> Value {
        if let Some((identity, ca)) = &self.ca_identity {
            json!({"address":address,"ca":ca,"identities":[identity],"allow":rights,"leaf":leaf})
        } else {
            json!({"address":address,"pin":self.pin,"allow":rights,"leaf":leaf})
        }
    }
}
struct RelayFixture {
    _dir: tempfile::TempDir,
    hub: Identity,
    leaf: Identity,
    collector: Identity,
    state: Arc<FedState>,
    leaf_state: Arc<FedState>,
    _observer: Arc<xmsg::observe::Observer>,
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RelayFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn state(identity: &Identity, peers: PeersMap, database: &std::path::Path) -> Arc<FedState> {
    let db = rusqlite::Connection::open(database).unwrap();
    xmsg::storage::init_db(&db).unwrap();
    Arc::new(FedState {
        node_name: identity.node.clone(),
        peers: Arc::new(peers).into(),
        cert_der: identity.cert.clone(),
        cert_chain_der: vec![identity.cert.clone()],
        key_der: identity.key.clone(),
        rate_limiter: Arc::new(RateLimiter::new(600, 200)),
        db: Arc::new(Mutex::new(db)),
        sessions_dirs: vec![],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: database.parent().unwrap().join("presence"),
            brain_dir: database.parent().unwrap().join("brain"),
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
    })
}
impl RelayFixture {
    async fn new() -> Self {
        Self::with_hub(Identity::new()).await
    }
    async fn with_hub(hub: Identity) -> Self {
        Self::with_nodes(hub, Identity::new()).await
    }
    async fn with_nodes(hub: Identity, leaf: Identity) -> Self {
        Self::with_identities(hub, leaf, Identity::new()).await
    }
    async fn with_identities(hub: Identity, leaf: Identity, collector: Identity) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let route = json!({"hub":hub.full(),"leaf":leaf.full(),"collector":collector.full()});
        let hub_peers = PeersMap::load_from_json(
            &json!({"peers":{
            leaf.node.clone():leaf.peer("127.0.0.1:1",&["list"],true),
            collector.node.clone():collector.peer("127.0.0.1:1",&["observe"],false)
        },"reverse_observe":{"hub_enabled":true,"routes":[route.clone()]}})
            .to_string(),
        )
        .unwrap();
        let mut hp = hub.peer(&address.to_string(), &["list"], false);
        hp["dial"] = json!("outbound");
        let leaf_peers = PeersMap::load_from_json(
            &json!({"peers":{
            hub.node.clone():hp,
            collector.node.clone():collector.peer("127.0.0.1:1",&["observe"],false)
        },"reverse_observe":{"leaf_enabled":true,"routes":[route]}})
            .to_string(),
        )
        .unwrap();
        let state = state(&hub, hub_peers, &dir.path().join("hub.sqlite"));
        let leaf_state = self::state(&leaf, leaf_peers, &dir.path().join("leaf.sqlite"));
        let observer = xmsg::observe::Observer::start(
            &leaf_state.db,
            &dir.path().join("journal.sqlite"),
            &leaf.node,
            Default::default(),
        );
        observer.publish(vec![xmsg::observe::Observation {
            kind: "message_recorded".into(),
            from: Some(format!("sender@{}", leaf.node)),
            to: Some(format!("receiver@{}", leaf.node)),
            message_id: Some("synthetic-message".into()),
            reason: Some("/synthetic/private/PLANTED_TOKEN".into()),
            body_availability: "not_recorded".into(),
            ..Default::default()
        }]);
        leaf_state.db.lock().unwrap().execute("INSERT INTO codex_roots(root_id,codex_home,owner_pid,owner_starttime,generation,label,cwd,registered_at) VALUES('22222222-2222-4222-8222-222222222222','/synthetic/private',0,'synthetic',1,'PRIVATE_LABEL','/synthetic/private',?1)",[xmsg::storage::now_epoch_secs()]).unwrap();
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        let server = state.clone();
        let task = tokio::spawn(async move {
            xmsg::fed::run_fed_listener(listener, server).await.unwrap();
        });
        Self {
            _dir: dir,
            hub,
            leaf,
            collector,
            state,
            leaf_state,
            _observer: observer,
            address,
            task,
        }
    }
    async fn request(
        &self,
        caller: &Identity,
        method: &str,
        uri: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
    ) -> (u16, Vec<u8>) {
        request_to(self.address, &self.hub, caller, method, uri, body, headers).await
    }
    fn uri(&self, kind: &str) -> String {
        format!("/fed/v2/observe/relay/{}/{kind}", self.leaf.node)
    }
}
async fn request_to(
    address: std::net::SocketAddr,
    server: &Identity,
    caller: &Identity,
    method: &str,
    uri: &str,
    body: Vec<u8>,
    headers: &[(&str, &str)],
) -> (u16, Vec<u8>) {
    let connector = xmsg::fed::make_tls_connector(&caller.cert, &caller.key, &server.pin).unwrap();
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    let task = AbortTask(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let mut request = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        sender.send_request(request.body(Full::new(Bytes::from(body))).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    task.0.abort();
    (status, bytes)
}

#[tokio::test]
async fn hub_relays_exact_raw_snapshot_only_via_advertising_control_poll() {
    let f = RelayFixture::new().await;
    let uri = f.uri("snapshot");
    let collector = f.request(
        &f.collector,
        "GET",
        &uri,
        vec![],
        &[
            ("xmsg-origin", "forged-collector"),
            ("authorization", "Bearer SYNTHETIC_OWNER_CREDENTIAL"),
        ],
    );
    let leaf = async {
        let (status, body) = f
            .request(
                &f.leaf,
                "GET",
                "/fed/v2/inbox?control=true&wait=2&observe_relay=1",
                vec![],
                &[],
            )
            .await;
        assert_eq!(status, 200);
        let control: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            !String::from_utf8_lossy(&body).contains("SYNTHETIC_OWNER_CREDENTIAL"),
            "human bearer never crosses relay control wire"
        );
        assert_eq!(
            control["kind"], "observe",
            "only an advertising control poll receives Observe"
        );
        let request = &control["request"];
        assert_eq!(
            request["collector"],
            f.collector.full(),
            "attestation uses actual TLS collector"
        );
        let body=format!("{{ \"v\":1,\"node\":\"{}\",\"scope\":\"{}\",\"observed_at\":1,\"endpoints\":[],\"truncated\":false,\"available\":\"available\" }}",f.leaf.node,"a".repeat(64)).into_bytes();
        let (status, _) = f
            .request(
                &f.leaf,
                "POST",
                &format!(
                    "/fed/v2/observe/relay/answer/{}",
                    request["id"].as_str().unwrap()
                ),
                body.clone(),
                &[
                    ("xmsg-observe-kind", "snapshot"),
                    ("xmsg-observe-status", "ok"),
                ],
            )
            .await;
        assert_eq!(status, 200, "expected leaf answer admitted");
        body
    };
    let ((status, body), expected) = tokio::join!(collector, leaf);
    assert_eq!(status, 200);
    assert_eq!(body, expected, "hub preserves exact DTO bytes");
}

#[tokio::test]
async fn production_leaf_exports_events_and_snapshot_without_listener_or_custody() {
    let f = RelayFixture::new().await;
    let primary_before = [
        f.state.db.lock().unwrap().total_changes(),
        f.leaf_state.db.lock().unwrap().total_changes(),
    ];
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    for kind in ["events", "snapshot"] {
        let (status, body) = f
            .request(&f.collector, "GET", &f.uri(kind), vec![], &[])
            .await;
        assert_eq!(status, 200, "production leaf exports {kind}");
        let dto: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(dto["node"], f.leaf.node, "DTO comes from the outbound leaf");
        assert_eq!(dto["v"], 1);
        if kind == "events" {
            assert!(
                dto.get("events").is_some(),
                "events request returns an event page"
            );
            assert!(
                dto.get("endpoints").is_none(),
                "events request never becomes a snapshot"
            );
        } else {
            assert!(
                dto.get("endpoints").is_some(),
                "snapshot request returns an endpoint snapshot"
            );
            assert!(
                dto.get("events").is_none(),
                "snapshot request never becomes an event page"
            );
        }
        assert!(!String::from_utf8_lossy(&body).contains("bearer"));
        for canary in ["PLANTED_TOKEN", "/synthetic/private", "PRIVATE_LABEL"] {
            assert!(
                !String::from_utf8_lossy(&body).contains(canary),
                "minimized metadata excludes {canary}"
            );
        }
    }
    let hub = xmsg::observe_relay::test_hooks::controls(&f.state);
    let leaf = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(
        hub.listeners.load(Relaxed),
        1,
        "positive listener census sees hub"
    );
    assert_eq!(
        leaf.listeners.load(Relaxed),
        0,
        "reverse leaf never opens listener"
    );
    assert!(
        hub.control_polls.load(Relaxed) >= 2,
        "positive control-only poll census"
    );
    for c in [&hub, &leaf] {
        assert_eq!(c.custody_polls.load(Relaxed), 0, "no consuming inbox poll");
        assert_eq!(c.acks.load(Relaxed), 0, "no ACK wire activity");
        assert_eq!(
            c.delivery_posts.load(Relaxed),
            0,
            "no message/reply wire activity"
        );
    }
    for (index, fs) in [&f.state, &f.leaf_state].into_iter().enumerate() {
        let db = fs.db.lock().unwrap();
        assert_eq!(
            db.total_changes(),
            primary_before[index],
            "reverse observation never mutates bus primary storage"
        );
        let rows: i64 = db
            .query_row("SELECT count(*) FROM peer_mailbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "observation has no mailbox custody");
    }
}

fn current_config(fs: &Arc<FedState>) -> Value {
    let peers = fs.current_peers();
    let entries = peers
        .iter()
        .map(|(key, config)| (key.clone(), serde_json::to_value(config).unwrap()))
        .collect::<serde_json::Map<_, _>>();
    json!({"peers":entries,"reverse_observe":{"hub_enabled":peers.reverse_observe.hub_enabled,"leaf_enabled":peers.reverse_observe.leaf_enabled,"routes":peers.reverse_observe.routes}})
}
fn reload(fs: &Arc<FedState>, edit: impl FnOnce(&mut Value)) {
    let mut config = current_config(fs);
    edit(&mut config);
    let peers = Arc::new(PeersMap::load_from_json(&config.to_string()).unwrap());
    let certs = fs.cert_chain();
    let key = fs.key_der();
    let acceptor = xmsg::fed::make_tls_acceptor(&certs, &key, peers.clone()).unwrap();
    *fs.dynamic_tls.write().unwrap() = Some(xmsg::fed::DynamicTls {
        cert_der: fs.cert_der.clone(),
        cert_chain_der: fs.cert_chain_der.clone(),
        key_der: key,
        peers,
        ca_anchors: Default::default(),
        acceptor,
    });
}
async fn refusal(hub: bool, edit: impl FnOnce(&RelayFixture, &mut Value), query: &str) {
    let f = RelayFixture::new().await;
    reload(if hub { &f.state } else { &f.leaf_state }, |c| edit(&f, c));
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let (status, body) = f
        .request(
            &f.collector,
            "GET",
            &format!("{}{}", f.uri("snapshot"), query),
            vec![],
            &[("xmsg-origin", "forged"), ("x-forwarded-for", "127.0.0.1")],
        )
        .await;
    assert_eq!(
        status,
        403,
        "independent policy refusal: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["error"],
        "denied"
    );
}
#[tokio::test]
async fn hub_switch_is_required() {
    refusal(
        true,
        |_, c| c["reverse_observe"]["hub_enabled"] = json!(false),
        "",
    )
    .await;
}
#[tokio::test]
async fn hub_exact_route_is_required() {
    refusal(true, |_, c| c["reverse_observe"]["routes"] = json!([]), "").await;
    refusal(
        true,
        |_, c| {
            c["reverse_observe"]["routes"][0]["collector"] =
                json!(format!("sha256:{}", "a".repeat(64)))
        },
        "",
    )
    .await;
}
#[tokio::test]
async fn hub_observe_right_is_not_implied_by_list() {
    refusal(
        true,
        |f, c| c["peers"][&f.collector.node]["allow"] = json!(["list"]),
        "",
    )
    .await;
}
#[tokio::test]
async fn hub_checks_actual_collector_ip_not_forwarded_ip() {
    refusal(
        true,
        |f, c| c["peers"][&f.collector.node]["from"] = json!(["192.0.2.0/24"]),
        "",
    )
    .await;
}
#[tokio::test]
async fn hub_labels_require_policy_before_dispatch() {
    refusal(true, |_, _| {}, "?labels=true").await;
}
#[tokio::test]
async fn leaf_exact_route_is_required() {
    refusal(false, |_, c| c["reverse_observe"]["routes"] = json!([]), "").await;
}
#[tokio::test]
async fn leaf_observe_right_is_not_implied_by_list() {
    refusal(
        false,
        |f, c| c["peers"][&f.collector.node]["allow"] = json!(["list"]),
        "",
    )
    .await;
}
#[tokio::test]
async fn leaf_refuses_unwitnessed_collector_ip() {
    refusal(
        false,
        |f, c| c["peers"][&f.collector.node]["from"] = json!(["127.0.0.1/32"]),
        "",
    )
    .await;
}
#[tokio::test]
async fn leaf_checks_actual_hub_ip() {
    refusal(
        false,
        |f, c| c["peers"][&f.hub.node]["from"] = json!(["192.0.2.0/24"]),
        "",
    )
    .await;
}

#[tokio::test]
async fn hub_target_exclusion_refuses_whole_leaf_dto() {
    let f = RelayFixture::new().await;
    reload(&f.state, |c| {
        c["peers"][&f.collector.node]["targets"] = json!([])
    });
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let (status, _) = f
        .request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
        .await;
    assert_eq!(
        status, 403,
        "excluded returned endpoints refuse the complete DTO"
    );
}
#[tokio::test]
async fn both_label_opt_ins_and_leaf_target_projection_apply() {
    let f = RelayFixture::new().await;
    reload(&f.state, |c| {
        c["peers"][&f.collector.node]["observe_labels"] = json!(true)
    });
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let (status, body) = f
        .request(
            &f.collector,
            "GET",
            &format!("{}?labels=true", f.uri("snapshot")),
            vec![],
            &[],
        )
        .await;
    assert_eq!(status, 200);
    assert!(
        !String::from_utf8_lossy(&body).contains("PRIVATE_LABEL"),
        "leaf policy conjunction suppresses labels"
    );
    reload(&f.leaf_state, |c| {
        c["peers"][&f.collector.node]["observe_labels"] = json!(true)
    });
    // A poll already open at reload is refused; a fresh worker starts with current policy.
    drop(_worker);
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let (status, body) = f
        .request(
            &f.collector,
            "GET",
            &format!("{}?labels=true", f.uri("snapshot")),
            vec![],
            &[],
        )
        .await;
    assert_eq!(status, 200);
    assert!(
        String::from_utf8_lossy(&body).contains("PRIVATE_LABEL"),
        "both label opt-ins expose synthetic label"
    );
    let (status, body) = f
        .request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
        .await;
    assert_eq!(status, 200);
    assert!(
        !String::from_utf8_lossy(&body).contains("PRIVATE_LABEL"),
        "request opt-in remains required"
    );
    drop(_worker);
    reload(&f.leaf_state, |c| {
        c["peers"][&f.collector.node]["targets"] = json!([])
    });
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let (status, body) = f
        .request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["endpoints"],
        json!([]),
        "leaf narrows targets before export"
    );
}

async fn control(f: &RelayFixture) -> Value {
    let (status, body) = f
        .request(
            &f.leaf,
            "GET",
            "/fed/v2/inbox?control=true&wait=2&observe_relay=1",
            vec![],
            &[],
        )
        .await;
    assert_eq!(status, 200);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["kind"], "observe");
    value["request"].clone()
}
fn empty_snapshot(f: &RelayFixture) -> Vec<u8> {
    format!("{{\"v\":1,\"node\":\"{}\",\"scope\":\"{}\",\"observed_at\":1,\"endpoints\":[],\"truncated\":false,\"available\":\"available\"}}",f.leaf.node,"a".repeat(64)).into_bytes()
}
async fn submit(f: &RelayFixture, request: &Value, body: Vec<u8>) -> (u16, Vec<u8>) {
    f.request(
        &f.leaf,
        "POST",
        &format!(
            "/fed/v2/observe/relay/answer/{}",
            request["id"].as_str().unwrap()
        ),
        body,
        &[
            ("xmsg-observe-kind", request["read"].as_str().unwrap()),
            ("xmsg-observe-status", "ok"),
        ],
    )
    .await
}
#[tokio::test]
async fn pair_reservation_lasts_through_final_forward_check() {
    let f = RelayFixture::new().await;
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_forward.arm(1);
    let first = async {
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
    };
    let race = async {
        let request = control(&f).await;
        let (status, _) = submit(&f, &request, empty_snapshot(&f)).await;
        assert_eq!(status, 200);
        gates.before_forward.wait_for(1).await;
        let (status, _) = f
            .request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await;
        gates.before_forward.release();
        assert_eq!(
            status, 429,
            "same pair stays reserved while a completed DTO awaits forwarding"
        );
    };
    let (response, ()) = tokio::join!(first, race);
    assert_eq!(response.0, 200);
}
#[tokio::test]
async fn leaf_policy_revocation_after_projection_blocks_successful_post() {
    for at_send in [false, true] {
        let f = RelayFixture::new().await;
        let gates = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
        let gate = if at_send {
            &gates.before_send
        } else {
            &gates.before_post
        };
        gate.arm(1);
        let _worker =
            xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
        let request = async {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        };
        let revoke = async {
            gate.wait_for(1).await;
            reload(&f.leaf_state, |c| {
                c["reverse_observe"]["leaf_enabled"] = json!(false)
            });
            gate.release();
        };
        let ((status, _), ()) = tokio::join!(request, revoke);
        assert_eq!(
            status, 403,
            "old projection must never be admitted under a new policy at send={at_send}"
        );
    }
}

#[tokio::test]
async fn live_waiter_is_bound_to_expected_leaf_kind_and_id_and_consumed_once() {
    let f = RelayFixture::new().await;
    let caller = async {
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
    };
    let leaf = async {
        let request = control(&f).await;
        let id = request["id"].as_str().unwrap();
        let uri = format!("/fed/v2/observe/relay/answer/{id}");
        let headers = [
            ("xmsg-observe-kind", "snapshot"),
            ("xmsg-observe-status", "ok"),
        ];
        assert_eq!(
            f.request(&f.collector, "POST", &uri, empty_snapshot(&f), &headers)
                .await
                .0,
            400,
            "authenticated wrong leaf refuses without consuming live waiter"
        );
        assert_eq!(
            f.request(
                &f.leaf,
                "POST",
                &uri,
                empty_snapshot(&f),
                &[
                    ("xmsg-observe-kind", "events"),
                    ("xmsg-observe-status", "ok")
                ]
            )
            .await
            .0,
            400,
            "wrong read kind refuses without consuming waiter"
        );
        assert_eq!(
            f.request(
                &f.leaf,
                "POST",
                "/fed/v2/observe/relay/answer/not-a-live-id",
                empty_snapshot(&f),
                &headers
            )
            .await
            .0,
            400,
            "unknown id refuses"
        );
        assert_eq!(
            submit(&f, &request, empty_snapshot(&f)).await.0,
            200,
            "valid expected leaf succeeds"
        );
        assert_eq!(
            submit(&f, &request, empty_snapshot(&f)).await.0,
            400,
            "duplicate answer refuses"
        );
    };
    let (response, ()) = tokio::join!(caller, leaf);
    assert_eq!(response.0, 200);
    assert_eq!(
        xmsg::observe_relay::test_hooks::pending(&f.state),
        0,
        "consumed waiter is removed"
    );
}
async fn raw_answer(
    mut body: Vec<u8>,
    kind: &str,
    headers: Vec<(String, String)>,
) -> ((u16, Vec<u8>), u16) {
    let f = RelayFixture::new().await;
    let text = String::from_utf8(body)
        .unwrap()
        .replace("LEAF_NODE", &f.leaf.node);
    body = text.into_bytes();
    let uri = if kind == "events" {
        format!("{}?limit=200", f.uri(kind))
    } else {
        f.uri(kind)
    };
    let caller = async { f.request(&f.collector, "GET", &uri, vec![], &[]).await };
    let leaf = async {
        let request = control(&f).await;
        let mut all = vec![("xmsg-observe-kind", kind), ("xmsg-observe-status", "ok")];
        all.extend(headers.iter().map(|(a, b)| (a.as_str(), b.as_str())));
        f.request(
            &f.leaf,
            "POST",
            &format!(
                "/fed/v2/observe/relay/answer/{}",
                request["id"].as_str().unwrap()
            ),
            body,
            &all,
        )
        .await
        .0
    };
    tokio::join!(caller, leaf)
}
fn future_page() -> Vec<u8> {
    format!("{{ \"v\":1,\"node\":\"LEAF_NODE\",\"epoch\":\"epoch\",\"scope\":\"{}\",\"events\":[{{\"sequence\":1,\"observed_at\":1,\"persisted_at\":1,\"kind\":\"future_delivery\",\"available\":\"not_recorded\"}}],\"next\":1,\"has_more\":false,\"gaps\":[],\"available\":true }}","a".repeat(64)).into_bytes()
}
#[tokio::test]
async fn hub_preserves_future_kind_event_bytes_and_refuses_nonmetadata_fields() {
    let expected = future_page();
    let (response, status) = raw_answer(expected.clone(), "events", vec![]).await;
    assert_eq!(
        status, 200,
        "valid bounded future-kind page is accepted from the expected leaf"
    );
    assert_eq!(
        response.0, 200,
        "valid bounded future-kind page reaches the collector unchanged"
    );
    let normalized = String::from_utf8(response.1).unwrap();
    assert!(
        normalized.contains("\"kind\":\"future_delivery\""),
        "future kind survives unchanged"
    );
    assert!(
        normalized.starts_with("{ \"v\""),
        "raw whitespace remains unchanged"
    );
    for (name, changed) in [
        (
            "65-byte future kind",
            String::from_utf8(expected.clone())
                .unwrap()
                .replace("future_delivery", &"a".repeat(65)),
        ),
        (
            "malformed future kind",
            String::from_utf8(expected.clone())
                .unwrap()
                .replace("future_delivery", "Future_delivery"),
        ),
        (
            "body extra field",
            String::from_utf8(expected.clone()).unwrap().replace(
                "\"sequence\":1",
                "\"body\":\"PLANTED_TOKEN\",\"sequence\":1",
            ),
        ),
        (
            "path extra field",
            String::from_utf8(expected.clone()).unwrap().replace(
                "\"sequence\":1",
                "\"cwd\":\"/synthetic/private\",\"sequence\":1",
            ),
        ),
        (
            "unknown outcome",
            String::from_utf8(expected.clone()).unwrap().replace(
                "\"sequence\":1",
                "\"outcome\":\"future_outcome\",\"sequence\":1",
            ),
        ),
        (
            "duplicate field",
            String::from_utf8(expected.clone())
                .unwrap()
                .replace("\"sequence\":1", "\"sequence\":1,\"sequence\":2"),
        ),
        (
            "wrong node",
            String::from_utf8(expected.clone())
                .unwrap()
                .replace("LEAF_NODE", "unrelated.node"),
        ),
    ] {
        let (response, answer) = raw_answer(changed.into_bytes(), "events", vec![]).await;
        assert_eq!(answer, 400, "invalid {name} refuses at answer hop");
        assert_eq!(response.0, 400, "invalid {name} refuses whole caller DTO");
    }
}
fn snapshot_page(count: usize) -> Value {
    json!({"v":1,"node":"LEAF_NODE","scope":"a".repeat(64),"observed_at":1,"endpoints":(0..count).map(|index|json!({"id":format!("endpoint-{index}@LEAF_NODE"),"node":"LEAF_NODE","kind":"service","harness":"unknown","state":"registered"})).collect::<Vec<_>>(),"truncated":false,"available":"available"})
}
async fn assert_raw_dto_status(body: Vec<u8>, kind: &str, status: u16, name: &str) -> Value {
    assert!(
        body.len() < 64 * 1024,
        "{name} fixture remains well below the256KiB transport limit"
    );
    let (response, answer) = raw_answer(body, kind, vec![]).await;
    assert_eq!(answer, status, "{name} DTO answer-hop result");
    assert_eq!(response.0, status, "{name} DTO collector result");
    serde_json::from_slice(&response.1).unwrap()
}
#[tokio::test]
async fn snapshot_dto_node_version_count_and_closed_schema_are_independent() {
    let valid = snapshot_page(200);
    let response = assert_raw_dto_status(
        serde_json::to_vec(&valid).unwrap(),
        "snapshot",
        200,
        "valid200-endpoint snapshot",
    )
    .await;
    assert_eq!(
        response["endpoints"].as_array().unwrap().len(),
        200,
        "snapshot exact endpoint-limit neighbor retains all200 valid endpoints"
    );
    let mut wrong_node = valid.clone();
    wrong_node["node"] = json!("unrelated.node");
    let mut wrong_version = valid.clone();
    wrong_version["v"] = json!(2);
    let mut body_field = valid.clone();
    body_field["body"] = json!("SYNTHETIC_BODY_NOT_METADATA");
    let mut cwd_field = valid.clone();
    cwd_field["cwd"] = json!("/synthetic/private");
    let mut endpoint_cwd = valid.clone();
    endpoint_cwd["endpoints"][0]["cwd"] = json!("/synthetic/private");
    for (name, body) in [
        ("snapshot wrong node", wrong_node),
        ("snapshot version2", wrong_version),
        ("snapshot201 endpoints", snapshot_page(201)),
        ("snapshot body extra field", body_field),
        ("snapshot cwd extra field", cwd_field),
        ("snapshot endpoint cwd extra field", endpoint_cwd),
    ] {
        assert_raw_dto_status(serde_json::to_vec(&body).unwrap(), "snapshot", 400, name).await;
    }
    let duplicate =
        serde_json::to_string(&valid)
            .unwrap()
            .replacen("\"v\":1", "\"v\":1,\"v\":1", 1);
    assert_raw_dto_status(
        duplicate.into_bytes(),
        "snapshot",
        400,
        "snapshot duplicate known version field",
    )
    .await;
}
fn event_page(count: usize) -> Value {
    let mut page: Value = serde_json::from_slice(&future_page()).unwrap();
    let event = page["events"][0].clone();
    page["events"] = Value::Array(
        (1..=count)
            .map(|sequence| {
                let mut event = event.clone();
                event["sequence"] = json!(sequence);
                event
            })
            .collect(),
    );
    page["next"] = json!(count);
    page
}
#[tokio::test]
async fn events_dto_version_and_count_are_independent_of_transport_bounds() {
    let valid = event_page(200);
    let response = assert_raw_dto_status(
        serde_json::to_vec(&valid).unwrap(),
        "events",
        200,
        "valid200-event future-kind page",
    )
    .await;
    assert_eq!(
        response["events"].as_array().unwrap().len(),
        200,
        "event exact-count neighbor retains all200 sequenced events"
    );
    assert_eq!(
        response["next"], 200,
        "valid200-event neighbor preserves cursor"
    );
    let mut wrong_version = valid;
    wrong_version["v"] = json!(2);
    assert_raw_dto_status(
        serde_json::to_vec(&wrong_version).unwrap(),
        "events",
        400,
        "events version2",
    )
    .await;
    assert_raw_dto_status(
        serde_json::to_vec(&event_page(201)).unwrap(),
        "events",
        400,
        "events201 sequenced events",
    )
    .await;
    for (field, value) in [
        ("body", "SYNTHETIC_BODY_NOT_METADATA"),
        ("cwd", "/synthetic/private"),
    ] {
        let mut forbidden = event_page(1);
        forbidden[field] = json!(value);
        assert_raw_dto_status(
            serde_json::to_vec(&forbidden).unwrap(),
            "events",
            400,
            &format!("events root {field} extra field"),
        )
        .await;
    }
}
#[tokio::test]
async fn exact_query_bound_and_closed_query_fields_apply_before_dispatch() {
    let f = RelayFixture::new().await;
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let valid = format!("v={}1", "0".repeat(1021));
    assert_eq!(valid.len(), 1024);
    assert_eq!(
        f.request(
            &f.collector,
            "GET",
            &format!("{}?{valid}", f.uri("snapshot")),
            vec![],
            &[]
        )
        .await
        .0,
        200,
        "1024-byte query passes"
    );
    for invalid in [
        format!("v={}1", "0".repeat(1022)),
        "v=1&v=1".into(),
        "v=1&url=http://elsewhere".into(),
        "v=1&unknown=1".into(),
    ] {
        assert_eq!(
            f.request(
                &f.collector,
                "GET",
                &format!("{}?{invalid}", f.uri("snapshot")),
                vec![],
                &[]
            )
            .await
            .0,
            400,
            "oversized/duplicate/unknown query refuses"
        );
    }
}
#[tokio::test]
async fn declared_and_streaming_dto_bounds_allow_exact_limit_and_refuse_one_over() {
    for chunked in [false, true] {
        let f = RelayFixture::new().await;
        for size in [256 * 1024, 256 * 1024 + 1] {
            let measurements = xmsg::observe_relay::test_hooks::controls(&f.state);
            measurements
                .max_buffered_answer
                .store(0, std::sync::atomic::Ordering::Relaxed);
            measurements
                .answer_read_attempts
                .store(0, std::sync::atomic::Ordering::Relaxed);
            let caller = async {
                f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                    .await
            };
            let leaf = async {
                let request = control(&f).await;
                let mut body = empty_snapshot(&f);
                body.resize(size, b' ');
                let mut headers = vec![
                    ("xmsg-observe-kind", "snapshot"),
                    ("xmsg-observe-status", "ok"),
                ];
                if chunked {
                    headers.push(("transfer-encoding", "chunked"));
                }
                f.request(
                    &f.leaf,
                    "POST",
                    &format!(
                        "/fed/v2/observe/relay/answer/{}",
                        request["id"].as_str().unwrap()
                    ),
                    body,
                    &headers,
                )
                .await
                .0
            };
            let (response, answer) = tokio::join!(caller, leaf);
            assert!(measurements.max_buffered_answer.load(std::sync::atomic::Ordering::Relaxed)<=256*1024,"streaming reader never buffers an oversized answer even if semantic decoder refuses it");
            if size > 256 * 1024 && !chunked {
                assert_eq!(
                    measurements
                        .answer_read_attempts
                        .load(std::sync::atomic::Ordering::Relaxed),
                    0,
                    "declared oversize refuses before invoking body reader"
                );
            }
            if size == 256 * 1024 {
                assert_eq!(answer, 200, "exact body limit chunked={chunked}");
                assert_eq!(response.0, 200);
                assert_eq!(response.1.len(), size, "raw body bound unchanged");
            } else {
                assert_eq!(answer, 400, "one-over body limit chunked={chunked}");
                assert_ne!(response.0, 200, "oversized answer never reaches caller");
            }
        }
    }
}
#[tokio::test]
async fn concurrent_legacy_poll_cannot_take_observe_and_capability_is_not_cached() {
    let f = RelayFixture::new().await;
    let caller = async {
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
    };
    let old = async {
        let r = f
            .request(
                &f.leaf,
                "GET",
                "/fed/v2/inbox?control=true&wait=1",
                vec![],
                &[],
            )
            .await;
        assert_eq!(r.0, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&r.1).unwrap(),
            Value::Null,
            "legacy poll never gets new variant"
        );
    };
    let capable = async {
        let request = control(&f).await;
        assert_eq!(submit(&f, &request, empty_snapshot(&f)).await.0, 200);
    };
    let (response, (), ()) = tokio::join!(caller, old, capable);
    assert_eq!(response.0, 200);
    let caller = async {
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
    };
    let old = async {
        let r = f
            .request(
                &f.leaf,
                "GET",
                "/fed/v2/inbox?control=true&wait=1&observe_relay=0",
                vec![],
                &[],
            )
            .await;
        assert_eq!(serde_json::from_slice::<Value>(&r.1).unwrap(), Value::Null);
    };
    let (response, ()) = tokio::join!(caller, old);
    assert_eq!(
        response.0, 503,
        "completed capability does not authorize a later legacy poll"
    );
}
#[tokio::test]
async fn explicit_unsupported_is_distinct_from_no_capable_poll() {
    let f = RelayFixture::new().await;
    let caller = async {
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
    };
    let leaf = async {
        let request = control(&f).await;
        let r = f
            .request(
                &f.leaf,
                "POST",
                &format!(
                    "/fed/v2/observe/relay/answer/{}",
                    request["id"].as_str().unwrap()
                ),
                vec![],
                &[
                    ("xmsg-observe-kind", "snapshot"),
                    ("xmsg-observe-status", "unsupported"),
                ],
            )
            .await;
        assert_eq!(r.0, 501);
    };
    let (response, ()) = tokio::join!(caller, leaf);
    assert_eq!(response.0, 501);
    assert_eq!(
        serde_json::from_slice::<Value>(&response.1).unwrap()["error"],
        "unsupported"
    );
    assert_eq!(xmsg::observe_relay::test_hooks::pending(&f.state), 0);
}

#[tokio::test]
async fn ordinary_pinned_polling_keeps_accepting_non_spiffe_and_multiple_uri_certs() {
    for uris in [
        vec!["urn:synthetic:ordinary"],
        vec![
            "spiffe://test/host/one/user/u",
            "spiffe://test/host/two/user/u",
        ],
    ] {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        for uri in uris {
            params
                .subject_alt_names
                .push(rcgen::SanType::URI(uri.try_into().unwrap()));
        }
        let cert = params.self_signed(&key).unwrap().der().to_vec();
        let pin = xmsg::fed::spki_sha256_from_der(&cert).unwrap();
        let hub = Identity {
            node: xmsg::node::node_name_from_pin(&pin).unwrap(),
            cert,
            key: key.serialize_der(),
            pin,
            ca_identity: None,
        };
        let f = RelayFixture::with_hub(hub).await;
        reload(&f.leaf_state, |c| {
            c["reverse_observe"]["leaf_enabled"] = json!(false)
        });
        let result = xmsg::fed::get_federated_inbox(&f.leaf_state, &f.hub.node, 0).await;
        assert!(matches!(result,Ok(None)),"reverse-disabled ordinary pinned polling retains existing certificate acceptance: {result:?}");
    }
}
struct AbortTask(tokio::task::JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn leaf_listener(f: &RelayFixture) -> (std::net::SocketAddr, AbortTask) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fs = f.leaf_state.clone();
    (
        address,
        AbortTask(tokio::spawn(async move {
            xmsg::fed::run_fed_listener(listener, fs).await.unwrap();
        })),
    )
}
#[tokio::test]
async fn slow_busy_answer_does_not_block_list_or_attachment_controls() {
    {
        let f = RelayFixture::new().await;
        let occupied = xmsg::observe_relay::test_hooks::occupy_reads(&f.leaf_state, 8);
        let gates = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
        let reads = xmsg::observe_fed::test_hooks::controls(&f.leaf_state);
        gates.before_post.arm(1);
        let delivery = xmsg::observe_relay::test_hooks::deliver_control(
            &f.leaf_state,
            &f.hub.node,
            &f.hub.cert,
            "127.0.0.1".parse().unwrap(),
            policy_control(&f),
        );
        tokio::pin!(delivery);
        let ready = std::future::poll_fn(|context| {
            std::task::Poll::Ready(std::future::Future::poll(delivery.as_mut(), context).is_ready())
        })
        .await;
        if !ready {
            gates.before_post.release();
        }
        assert!(
            ready,
            "refusal scheduling must return without polling answer network I/O"
        );
        assert_eq!(
            reads
                .read_decisions
                .load(std::sync::atomic::Ordering::Acquire),
            1,
            "valid control reaches the actual saturated read budget"
        );
        assert_eq!(
            reads
                .read_admissions
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "saturated current-policy control is a real Busy refusal"
        );
        assert_eq!(
            gates
                .refusal_spawned
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one bounded refusal task is scheduled before network polling"
        );
        gates.before_post.wait_for(1).await;
        gates.before_post.release();
        drop(occupied);
    }
    let f = RelayFixture::new().await;
    let (address, _listener) = leaf_listener(&f).await;
    let reads = xmsg::observe_fed::test_hooks::controls(&f.leaf_state);
    reads.before_read.arm(8);
    let gates = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
    gates.before_send.arm(1);
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let direct = async {
        // Poll all requests concurrently without adding a runtime dependency.
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let state = f.leaf_state.clone();
            let server = f.leaf.clone();
            let caller = f.collector.clone();
            tasks.push(tokio::spawn(async move {
                let _ = state;
                request_to(
                    address,
                    &server,
                    &caller,
                    "GET",
                    "/fed/v2/observe/snapshot",
                    vec![],
                    &[],
                )
                .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap().0, 200);
        }
    };
    let pressure = async {
        reads.before_read.wait_for(8).await;
        let reverse = async {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        };
        let controls = async {
            assert_shared_read_bound(&reads).await;
            gates.before_send.wait_for(1).await;
            wait_for_control_poll(&f.state).await;
            let list = xmsg::fed::list_peer(&f.state, &f.leaf.node);
            let attachment = xmsg::fed::fetch_attachment_chunk(
                &f.state,
                &f.leaf.node,
                "missing-synthetic-item",
                0,
                0,
                16,
            );
            let progressed = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(list, attachment)
            })
            .await;
            gates.before_send.release();
            reads.before_read.release();
            let (list, attachment) = progressed
                .expect("slow observation Busy POST must leave both existing controls progressing");
            assert_eq!(
                list.1.status, "ok",
                "List progresses under observation saturation"
            );
            assert!(
                matches!(attachment, Err(xmsg::error::AppError::NotFoundDetail(_))),
                "Attachment reached leaf and returned its real missing-row result"
            );
        };
        let (response, ()) = tokio::join!(reverse, controls);
        assert_eq!(
            response.0, 429,
            "shared direct+relay budget refuses the ninth read as busy"
        );
    };
    tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(direct, pressure)
    })
    .await
    .unwrap();
}

async fn assert_shared_read_bound(reads: &xmsg::observe_fed::test_hooks::Controls) {
    let decided = tokio::time::timeout(Duration::from_secs(2), async {
        while reads
            .read_decisions
            .load(std::sync::atomic::Ordering::Acquire)
            < 9
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        decided.is_ok(),
        "ninth shared-budget permit decision must complete without waiting for projection or POST"
    );
    assert_eq!(
        reads
            .read_admissions
            .load(std::sync::atomic::Ordering::Relaxed),
        8,
        "full shared direct+relay budget must not admit a ninth metadata read"
    );
}

async fn wait_pending(fs: &Arc<FedState>, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while xmsg::observe_relay::test_hooks::pending(fs) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending state reached expected bounded count");
}
fn collectors(f: &RelayFixture, count: usize) -> Vec<Identity> {
    let mut identities = vec![f.collector.clone()];
    identities.extend((1..count).map(|_| Identity::new()));
    for fs in [&f.state, &f.leaf_state] {
        reload(fs, |c| {
            for identity in identities.iter().skip(1) {
                c["peers"][&identity.node] = identity.peer("127.0.0.1:1", &["observe"], false);
                c["reverse_observe"]["routes"].as_array_mut().unwrap().push(
                    json!({"hub":f.hub.full(),"leaf":f.leaf.full(),"collector":identity.full()}),
                );
            }
        });
    }
    identities
}
#[tokio::test]
async fn hub_last_slot_and_same_pair_races_reserve_atomically_and_cancel_cleanly() {
    let f = Arc::new(RelayFixture::new().await);
    let identities = collectors(&f, 9);
    let mut held = Vec::new();
    for identity in identities.iter().take(7) {
        let f = f.clone();
        let caller = identity.clone();
        held.push(tokio::spawn(async move {
            f.request(&caller, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        }));
    }
    wait_pending(&f.state, 7).await;
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_admission.arm(2);
    let mut race = Vec::new();
    for identity in identities.iter().skip(7) {
        let f = f.clone();
        let caller = identity.clone();
        race.push(tokio::spawn(async move {
            f.request(&caller, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        }));
    }
    gates.before_admission.wait_for(2).await;
    gates.before_admission.release();
    let mut right = race.pop().unwrap();
    let mut left = race.pop().unwrap();
    let busy = tokio::select! {r=&mut left=>{held.push(right);r.unwrap()},r=&mut right=>{held.push(left);r.unwrap()}};
    assert_eq!(busy.0, 429, "only one contender gets the eighth waiter");
    wait_pending(&f.state, 8).await;
    assert_eq!(
        f.request(&identities[0], "GET", &f.uri("snapshot"), vec![], &[])
            .await
            .0,
        429,
        "a second live request for the same pair refuses"
    );
    for task in held {
        task.abort();
        let _ = task.await;
    }
    wait_pending(&f.state, 0).await;
    assert_eq!(
        xmsg::observe_relay::test_hooks::pending(&f.state),
        0,
        "cancelled clients leave no pending waiters"
    );
}
#[tokio::test]
async fn answer_routing_header_limit_and_id_shape_are_enforced() {
    let f = RelayFixture::new().await;
    for over in [false, true] {
        let caller = async {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        };
        let leaf = async {
            let request = control(&f).await;
            let body = empty_snapshot(&f);
            let base = "host".len()
                + "localhost".len()
                + "content-length".len()
                + body.len().to_string().len()
                + "xmsg-observe-kind".len()
                + "snapshot".len()
                + "xmsg-observe-status".len()
                + "ok".len()
                + "x-padding".len();
            let padding = "x".repeat(1024 - base + usize::from(over));
            let response = f
                .request(
                    &f.leaf,
                    "POST",
                    &format!(
                        "/fed/v2/observe/relay/answer/{}",
                        request["id"].as_str().unwrap()
                    ),
                    body,
                    &[
                        ("xmsg-observe-kind", "snapshot"),
                        ("xmsg-observe-status", "ok"),
                        ("x-padding", &padding),
                    ],
                )
                .await;
            assert_eq!(
                response.0,
                if over { 400 } else { 200 },
                "exact routing-header limit over={over}"
            );
            if over {
                assert_eq!(
                    submit(&f, &request, empty_snapshot(&f)).await.0,
                    200,
                    "bad headers did not consume valid waiter"
                );
            }
        };
        let (response, ()) = tokio::join!(caller, leaf);
        assert_eq!(response.0, 200);
    }
    for id in [
        "a".repeat(65),
        "invalid%20id".into(),
        "nonascii%C3%A9".into(),
    ] {
        assert_eq!(
            f.request(
                &f.leaf,
                "POST",
                &format!("/fed/v2/observe/relay/answer/{id}"),
                vec![],
                &[
                    ("xmsg-observe-kind", "snapshot"),
                    ("xmsg-observe-status", "ok")
                ]
            )
            .await
            .0,
            400,
            "invalid routing ID shape refuses"
        );
    }
}
#[tokio::test]
async fn hub_rechecks_original_policy_at_admission_dispatch_and_forward() {
    for stage in ["admission", "dispatch", "forward"] {
        let f = RelayFixture::new().await;
        let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
        let gate = match stage {
            "admission" => &gates.before_admission,
            "dispatch" => &gates.before_dispatch,
            _ => &gates.before_forward,
        };
        gate.arm(1);
        let caller = async {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        };
        let revoke = async {
            if stage == "forward" {
                let request = control(&f).await;
                assert_eq!(submit(&f, &request, empty_snapshot(&f)).await.0, 200);
            }
            if stage == "dispatch" {
                let poll = async {
                    f.request(
                        &f.leaf,
                        "GET",
                        "/fed/v2/inbox?control=true&wait=1&observe_relay=1",
                        vec![],
                        &[],
                    )
                    .await
                };
                let change = async {
                    gate.wait_for(1).await;
                    reload(&f.state, |c| {
                        c["reverse_observe"]["hub_enabled"] = json!(false)
                    });
                    gate.release();
                };
                let (response, ()) = tokio::join!(poll, change);
                assert_eq!(
                    serde_json::from_slice::<Value>(&response.1).unwrap(),
                    Value::Null,
                    "revoked request never dispatched"
                );
            } else {
                gate.wait_for(1).await;
                reload(&f.state, |c| {
                    c["reverse_observe"]["hub_enabled"] = json!(false)
                });
                gate.release();
            }
        };
        let (response, ()) = tokio::join!(caller, revoke);
        assert_eq!(response.0, 403, "current hub policy at {stage}");
    }
}
#[tokio::test]
async fn injected_deadline_rejects_prepared_response_and_removes_pending() {
    let f = RelayFixture::new().await;
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_forward.arm(1);
    let caller = async {
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
    };
    let leaf = async {
        let request = control(&f).await;
        assert_eq!(submit(&f, &request, empty_snapshot(&f)).await.0, 200);
        gates.before_forward.wait_for(1).await;
        gates
            .clock_offset_ms
            .store(5001, std::sync::atomic::Ordering::Relaxed);
        gates.before_forward.release();
    };
    let (response, ()) = tokio::join!(caller, leaf);
    assert_eq!(
        response.0, 503,
        "expired prepared response is unreachable, never empty success"
    );
    assert_eq!(xmsg::observe_relay::test_hooks::pending(&f.state), 0);
}
#[tokio::test]
async fn returned_labels_and_targets_are_independently_refused() {
    for allow_labels in [false, true] {
        let f = RelayFixture::new().await;
        if allow_labels {
            reload(&f.state, |c| {
                c["peers"][&f.collector.node]["observe_labels"] = json!(true)
            });
        }
        let caller = async {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        };
        let leaf = async {
            let request = control(&f).await;
            let mut dto: Value = serde_json::from_slice(&empty_snapshot(&f)).unwrap();
            dto["endpoints"] = json!([{"id":format!("receiver@{}",f.leaf.node),"node":f.leaf.node,"kind":"service","harness":"unknown","state":"registered","label":"PRIVATE_LABEL"}]);
            assert_eq!(
                submit(&f, &request, serde_json::to_vec(&dto).unwrap())
                    .await
                    .0,
                403,
                "label-bearing DTO must satisfy policy and request opt-in separately"
            );
        };
        let (response, ()) = tokio::join!(caller, leaf);
        assert_eq!(response.0, 403, "whole DTO refused, no rewriting labels");
    }
}

async fn wait_for_control_poll(state: &std::sync::Arc<xmsg::fed::FedState>) {
    use std::sync::atomic::Ordering::Relaxed;
    let hub = xmsg::observe_relay::test_hooks::controls(state);
    tokio::time::timeout(Duration::from_secs(10), async {
        while hub.control_polls.load(Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("outbound worker completed initial TLS handshake and control poll");
}

#[tokio::test]
async fn reverse_enable_for_another_route_preserves_unrouted_ordinary_control() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::URI(
        "urn:synthetic:ordinary".try_into().unwrap(),
    ));
    let cert = params.self_signed(&key).unwrap().der().to_vec();
    let pin = xmsg::fed::spki_sha256_from_der(&cert).unwrap();
    let hub = Identity {
        node: xmsg::node::node_name_from_pin(&pin).unwrap(),
        cert,
        key: key.serialize_der(),
        pin,
        ca_identity: None,
    };
    let f = RelayFixture::with_hub(hub).await;
    let routed_hub = Identity::new();
    reload(&f.leaf_state, |c| {
        c["reverse_observe"]["routes"][0]["hub"] = json!(routed_hub.full())
    });
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    wait_for_control_poll(&f.state).await;
    let (_, status) = tokio::time::timeout(
        Duration::from_secs(1),
        xmsg::fed::list_peer(&f.state, &f.leaf.node),
    )
    .await
    .expect("unrouted pinned control still progresses with reverse enabled elsewhere");
    assert_eq!(status.status, "ok");
}

#[tokio::test]
async fn reverse_enable_for_another_route_survives_slow_worker_startup() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::URI(
        "urn:synthetic:ordinary".try_into().unwrap(),
    ));
    let cert = params.self_signed(&key).unwrap().der().to_vec();
    let pin = xmsg::fed::spki_sha256_from_der(&cert).unwrap();
    let hub = Identity {
        node: xmsg::node::node_name_from_pin(&pin).unwrap(),
        cert,
        key: key.serialize_der(),
        pin,
        ca_identity: None,
    };
    let f = RelayFixture::with_hub(hub).await;
    let routed_hub = Identity::new();
    reload(&f.leaf_state, |c| {
        c["reverse_observe"]["routes"][0]["hub"] = json!(routed_hub.full())
    });
    // Forced-race control: delay worker startup by 1100ms (would trip the 1s list_peer
    // bound without the handshake barrier, and passes once the 1s bound starts after
    // `wait_for_control_poll`).
    let leaf_state = f.leaf_state.clone();
    let hub_node = f.hub.node.clone();
    let delayed_worker = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        xmsg::observe_relay::test_hooks::start_worker(leaf_state, hub_node)
    });
    wait_for_control_poll(&f.state).await;
    let (_, status) = tokio::time::timeout(
        Duration::from_secs(1),
        xmsg::fed::list_peer(&f.state, &f.leaf.node),
    )
    .await
    .expect("unrouted pinned control still progresses after delayed worker handshake");
    assert_eq!(status.status, "ok");
    let _worker = delayed_worker.await.unwrap();
}

#[tokio::test]
async fn pinned_leaf_with_uri_san_is_explicitly_unsupported_but_ordinary_control_works() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::URI(
        "spiffe://test/ns/leaves/sa/leaf".try_into().unwrap(),
    ));
    let cert = params.self_signed(&key).unwrap().der().to_vec();
    let pin = xmsg::fed::spki_sha256_from_der(&cert).unwrap();
    let leaf = Identity {
        node: xmsg::node::node_name_from_pin(&pin).unwrap(),
        cert,
        key: key.serialize_der(),
        pin,
        ca_identity: None,
    };
    let f = RelayFixture::with_nodes(Identity::new(), leaf).await;
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let (status, body) = f
        .request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
        .await;
    assert_eq!(
        status, 501,
        "pinned leaf with any URI SAN is unsupported v1"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["error"],
        "unsupported"
    );
    let (_, status) = xmsg::fed::list_peer(&f.state, &f.leaf.node).await;
    assert_eq!(status.status, "ok", "ordinary pinned control is unchanged");
}

async fn poll_control_body(
    f: &mut RelayFixture,
    body: Vec<u8>,
    chunked: bool,
) -> Result<Option<xmsg::fed::FedInboxItem>, xmsg::error::AppError> {
    f.task.abort();
    let _ = (&mut f.task).await;
    let listener = tokio::net::TcpListener::bind(f.address).await.unwrap();
    let acceptor = xmsg::fed::make_tls_acceptor(
        &f.state.cert_chain(),
        &f.state.key_der(),
        f.state.current_peers(),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let service =
            hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                assert_eq!(request.uri().path(), "/fed/v2/inbox");
                assert!(
                    request
                        .uri()
                        .query()
                        .unwrap()
                        .contains("control=true&observe_relay=1"),
                    "wire poll advertises current capability"
                );
                let mut response = hyper::Response::builder().status(200);
                if chunked {
                    response = response.header("transfer-encoding", "chunked");
                }
                let response = response.body(Full::new(Bytes::from(body.clone()))).unwrap();
                async move { Ok::<_, std::convert::Infallible>(response) }
            });
        let _ = hyper::server::conn::http1::Builder::new()
            .keep_alive(false)
            .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
            .await;
    });
    let result = xmsg::observe_relay::test_hooks::poll(&f.leaf_state, &f.hub.node, true).await;
    server.await.unwrap();
    result
}
#[tokio::test]
async fn control_envelope_declared_and_streaming_bounds_are_independent_of_json_shape() {
    for chunked in [false, true] {
        for size in [8192, 8193] {
            let mut f = RelayFixture::new().await;
            let mut body=serde_json::to_vec(&json!({"kind":"observe","request":{"id":"opaque123","hub":f.hub.full(),"leaf":f.leaf.full(),"collector":f.collector.full(),"read":"snapshot","query":"","remaining_ms":5000}})).unwrap();
            body.resize(size, b' ');
            let metrics = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
            let result = poll_control_body(&mut f, body, chunked).await;
            if size == 8192 {
                assert!(
                    matches!(result, Ok(Some(xmsg::fed::FedInboxItem::Observe { .. }))),
                    "valid envelope at exact raw-byte boundary"
                );
            } else {
                assert!(result.is_err(), "one-over control envelope refuses");
            }
            assert!(
                metrics
                    .max_buffered_control
                    .load(std::sync::atomic::Ordering::Relaxed)
                    <= 8192,
                "raw control read never collects over8KiB before semantic validation"
            );
            if size > 8192 && !chunked {
                assert_eq!(
                    metrics
                        .control_read_attempts
                        .load(std::sync::atomic::Ordering::Relaxed),
                    0,
                    "declared control oversize never invokes body reader"
                );
            }
        }
    }
}

#[tokio::test]
async fn authenticated_hub_control_id_grammar_refuses_before_leaf_work() {
    for (id, valid) in [
        ("a".repeat(64), true),
        ("a".repeat(65), false),
        ("é".into(), false),
        ("abc/def".into(), false),
        ("../other".into(), false),
        (String::new(), false),
    ] {
        let mut f = RelayFixture::new().await;
        let mut request = policy_control(&f);
        request.id = id;
        let body = serde_json::to_vec(&json!({"kind":"observe","request":request})).unwrap();
        let metadata = xmsg::observe_fed::test_hooks::controls(&f.leaf_state);
        let relay = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
        let result = poll_control_body(&mut f, body, false).await;
        if valid {
            assert!(
                matches!(result, Ok(Some(xmsg::fed::FedInboxItem::Observe { .. }))),
                "valid64-ASCII-id matching control passes real authenticated poll parser"
            );
        } else {
            assert!(
                result.is_err(),
                "invalid hub control id {:?} refuses before leaf admission",
                request.id
            );
        }
        assert_eq!(
            metadata
                .snapshot_candidates
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "control parser refuses without metadata read"
        );
        assert_eq!(
            relay
                .controls_received
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "invalid control never enters answer scheduler"
        );
        assert_eq!(
            relay
                .post_entries
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "invalid control never starts answer POST"
        );
    }
}
#[tokio::test]
async fn authenticated_hub_control_schema_is_closed_and_duplicate_free_before_leaf_work() {
    for case in [
        "valid",
        "outer unknown",
        "nested unknown",
        "outer duplicate",
        "nested duplicate",
    ] {
        let mut f = RelayFixture::new().await;
        let request = policy_control(&f);
        let mut envelope = json!({"kind":"observe","request":request});
        match case {
            "outer unknown" => envelope["body"] = json!("SYNTHETIC_BODY_NOT_METADATA"),
            "nested unknown" => envelope["request"]["cwd"] = json!("/synthetic/private"),
            _ => {}
        }
        let raw = serde_json::to_string(&envelope).unwrap();
        let raw = match case {
            "outer duplicate" => raw.replacen(
                "\"kind\":\"observe\"",
                "\"kind\":\"observe\",\"kind\":\"observe\"",
                1,
            ),
            "nested duplicate" => raw.replacen(
                "\"id\":\"policy-probe\"",
                "\"id\":\"policy-probe\",\"id\":\"policy-probe\"",
                1,
            ),
            _ => raw,
        };
        assert!(
            raw.len() < 8192,
            "{case} control fixture stays below envelope bound"
        );
        let metadata = xmsg::observe_fed::test_hooks::controls(&f.leaf_state);
        let relay = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
        let result = poll_control_body(&mut f, raw.into_bytes(), false).await;
        if case == "valid" {
            assert!(
                matches!(result, Ok(Some(xmsg::fed::FedInboxItem::Observe { .. }))),
                "valid closed control matching neighbor passes authenticated TLS parser"
            );
        } else {
            assert!(
                result.is_err(),
                "{case} control schema refuses before leaf admission"
            );
        }
        assert_eq!(
            metadata
                .snapshot_candidates
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "{case} control validation performs no metadata read"
        );
        assert_eq!(
            relay
                .controls_received
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "{case} control validation never starts answer scheduler"
        );
        assert_eq!(
            relay
                .post_entries
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "{case} control validation never starts answer POST"
        );
    }
}

#[tokio::test]
async fn witnessed_matching_source_cidrs_allow_actual_connections() {
    let f = RelayFixture::new().await;
    reload(&f.state, |c| {
        c["peers"][&f.collector.node]["from"] = json!(["127.0.0.1/32"])
    });
    reload(&f.leaf_state, |c| {
        c["peers"][&f.hub.node]["from"] = json!(["127.0.0.1/32"])
    });
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    assert_eq!(
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
            .0,
        200,
        "both witnessed matching source CIDRs pass"
    );
}

#[tokio::test]
async fn leaf_scope_only_narrowing_after_projection_cannot_send_old_bytes() {
    for labels in [false, true] {
        let f = RelayFixture::new().await;
        reload(&f.state, |c| {
            c["peers"][&f.collector.node]["observe_labels"] = json!(true)
        });
        reload(&f.leaf_state, |c| {
            c["peers"][&f.collector.node]["observe_labels"] = json!(true)
        });
        let gates = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
        gates.before_post.arm(1);
        let _worker =
            xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
        let caller = async {
            f.request(
                &f.collector,
                "GET",
                &format!("{}?labels=true", f.uri("snapshot")),
                vec![],
                &[],
            )
            .await
        };
        let narrow = async {
            gates.before_post.wait_for(1).await;
            reload(&f.leaf_state, |c| {
                if labels {
                    c["peers"][&f.collector.node]["observe_labels"] = json!(false)
                } else {
                    c["peers"][&f.collector.node]["targets"] = json!([])
                }
            });
            gates.before_post.release();
        };
        let (response, ()) = tokio::join!(caller, narrow);
        assert_eq!(
            response.0, 403,
            "original generation blocks stale scope-only narrowing labels={labels}"
        );
    }
}

#[tokio::test]
async fn hub_scope_only_change_invalidates_prepared_even_empty_dto() {
    let f = RelayFixture::new().await;
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_forward.arm(1);
    let caller = async {
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
    };
    let narrow = async {
        let request = control(&f).await;
        assert_eq!(submit(&f, &request, empty_snapshot(&f)).await.0, 200);
        gates.before_forward.wait_for(1).await;
        reload(&f.state, |c| {
            c["peers"][&f.collector.node]["targets"] = json!([])
        });
        gates.before_forward.release();
    };
    let (response, ()) = tokio::join!(caller, narrow);
    assert_eq!(
        response.0, 403,
        "generation fence invalidates old scope even when fresh empty target validation would pass"
    );
}

#[tokio::test]
async fn relay_reads_fill_the_same_leaf_budget_seen_by_direct_export() {
    let f = Arc::new(RelayFixture::new().await);
    let identities = collectors(&f, 8);
    let (address, _listener) = leaf_listener(&f).await;
    let reads = xmsg::observe_fed::test_hooks::controls(&f.leaf_state);
    reads.before_read.arm(8);
    let posts = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
    posts.before_send.arm(1);
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let mut tasks = Vec::new();
    for (index, identity) in identities.into_iter().enumerate() {
        let f = f.clone();
        tasks.push(tokio::spawn(async move {
            f.request(&identity, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        }));
        tokio::time::timeout(
            Duration::from_secs(2),
            reads.before_read.wait_for(index + 1),
        )
        .await
        .expect("sequential TLS admissions reach shared-budget read gate");
    }
    reads.before_read.wait_for(8).await;
    let response = async {
        request_to(
            address,
            &f.leaf,
            &f.collector,
            "GET",
            "/fed/v2/observe/snapshot",
            vec![],
            &[],
        )
        .await
    };
    let (response, ()) = tokio::join!(response, assert_shared_read_bound(&reads));
    reads.before_read.release();
    assert_eq!(
        response.0, 429,
        "eight admitted relay reads leave no separate direct allowance"
    );
    posts.before_send.wait_for(1).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while posts
            .post_entries
            .load(std::sync::atomic::Ordering::Relaxed)
            < 8
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        posts.post_peak.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "all eight admitted answers queue behind exactly one observed POST connection"
    );
    posts.before_send.release();
    for task in tasks {
        assert_eq!(task.await.unwrap().0, 200);
    }
}

#[tokio::test]
async fn old_tls_poll_cannot_take_new_generation_observe_work() {
    let f = Arc::new(RelayFixture::new().await);
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_dispatch.arm(1);
    let old = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(
                &f.leaf,
                "GET",
                "/fed/v2/inbox?control=true&wait=1&observe_relay=1",
                vec![],
                &[],
            )
            .await
        })
    };
    gates.before_dispatch.wait_for(1).await;
    reload(&f.state, |_| {});
    let caller = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        })
    };
    wait_pending(&f.state, 1).await;
    gates.before_dispatch.release();
    let old = old.await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&old.1).unwrap(),
        Value::Null,
        "old TLS poll never receives new-generation collector attestation"
    );
    let request = control(&f).await;
    assert_eq!(submit(&f, &request, empty_snapshot(&f)).await.0, 200);
    assert_eq!(
        caller.await.unwrap().0,
        200,
        "fresh current TLS poll completes the same waiting request"
    );
}

fn ca_identity(
    uri: &str,
    bundle: &std::path::Path,
    issuer: &rcgen::Issuer<'_, &rcgen::KeyPair>,
) -> Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .subject_alt_names
        .push(rcgen::SanType::URI(uri.try_into().unwrap()));
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let cert = params.signed_by(&key, issuer).unwrap().der().to_vec();
    let pin = xmsg::fed::spki_sha256_from_der(&cert).unwrap();
    Identity {
        cert,
        key: key.serialize_der(),
        pin,
        node: xmsg::node::node_name_from_uri(uri).unwrap(),
        ca_identity: Some((uri.into(), bundle.to_owned())),
    }
}
async fn uri_fixture() -> (tempfile::TempDir, RelayFixture) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = params.self_signed(&key).unwrap();
    let bundle = directory.path().join("synthetic-ca.pem");
    std::fs::write(&bundle, certificate.pem()).unwrap();
    let issuer = rcgen::Issuer::from_params(&params, &key);
    let hub = ca_identity("spiffe://realm-one/host/hub/user/owner", &bundle, &issuer);
    let leaf = ca_identity("spiffe://realm-one/ns/leaves/sa/leaf", &bundle, &issuer);
    let collector = ca_identity(
        "spiffe://realm-one/host/collector/user/owner",
        &bundle,
        &issuer,
    );
    let f = RelayFixture::with_identities(hub, leaf, collector).await;
    (directory, f)
}
#[tokio::test]
async fn literal_ca_uri_routes_export_and_same_node_foreign_authority_refuses() {
    let (_directory, f) = uri_fixture().await;
    let worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    for kind in ["events", "snapshot"] {
        let (status, body) = f
            .request(&f.collector, "GET", &f.uri(kind), vec![], &[])
            .await;
        assert_eq!(status, 200, "real CA/URI reverse {kind}");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["node"],
            "leaf.leaves"
        );
    }
    drop(worker);
    reload(&f.state, |c| {
        c["reverse_observe"]["routes"][0]["leaf"] = json!("spiffe://realm-two/ns/leaves/sa/leaf")
    });
    assert_eq!(
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
            .0,
        403,
        "same-derived-node foreign authority cannot substitute configured leaf"
    );
}

#[tokio::test]
async fn refusal_budget_survives_worker_restart_and_full_lane_keeps_controls_progressing() {
    let f = Arc::new(RelayFixture::new().await);
    let identities = collectors(&f, 9);
    let occupied = xmsg::observe_relay::test_hooks::occupy_reads(&f.leaf_state, 8);
    let metrics = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
    metrics.before_post.arm(8);
    let worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let mut callers = Vec::new();
    for (index, identity) in identities.iter().take(8).enumerate() {
        let f = f.clone();
        let identity = identity.clone();
        callers.push(tokio::spawn(async move {
            f.request(&identity, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        }));
        tokio::time::timeout(
            Duration::from_secs(2),
            metrics.before_post.wait_for(index + 1),
        )
        .await
        .expect("empty refusal reached pre-POST barrier");
    }
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(
        metrics.refusal_active.load(Relaxed),
        8,
        "eight empty refusal tasks occupy the per-node lane"
    );
    wait_for_control_poll(&f.state).await;
    let (list, attachment) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            xmsg::fed::list_peer(&f.state, &f.leaf.node),
            xmsg::fed::fetch_attachment_chunk(
                &f.state,
                &f.leaf.node,
                "missing-synthetic-item",
                0,
                0,
                16
            )
        )
    })
    .await
    .expect("full stalled refusal lane leaves both ordinary controls progressing");
    assert_eq!(list.1.status, "ok");
    assert!(matches!(
        attachment,
        Err(xmsg::error::AppError::NotFoundDetail(_))
    ));
    xmsg::fed::queue_leaf_mailbox_message(
        &f.state,
        &f.leaf.node,
        "demo",
        &xmsg::fed::FedEnvelope {
            v: 2,
            id: "ordinary-positive".into(),
            origin: xmsg::storage::Origin::service("source", &f.hub.node),
            to: xmsg::fed::FedTarget {
                r#ref: "demo".into(),
            },
            body: "ordinary-positive-body".into(),
            thread_id: "ordinary-positive".into(),
            created_at: xmsg::storage::now_epoch_secs(),
            forwarded: None,
            attachments: vec![],
        },
        &format!("source@{}", f.hub.node),
    )
    .unwrap();
    let ordinary = f
        .request(
            &f.leaf,
            "GET",
            "/fed/v2/inbox?wait=0&control=false",
            vec![],
            &[],
        )
        .await;
    assert_eq!(ordinary.0, 200);
    let ordinary: Value = serde_json::from_slice(&ordinary.1).unwrap();
    assert_eq!(ordinary["kind"], "message");
    assert_eq!(
        ordinary["body"], "ordinary-positive-body",
        "ordinary delivery progresses with all refusal tasks stalled"
    );
    assert_eq!(
        f.request(
            &f.leaf,
            "POST",
            "/fed/v2/inbox/ordinary-positive/ack",
            vec![],
            &[]
        )
        .await
        .0,
        200,
        "ordinary ACK progresses outside observation lane"
    );
    drop(worker);
    for caller in callers {
        caller.abort();
        let _ = caller.await;
    }
    wait_pending(&f.state, 0).await;
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let last = {
        let f = f.clone();
        let identity = identities[8].clone();
        tokio::spawn(async move {
            f.request(&identity, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        while metrics.controls_received.load(Relaxed) < 9 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        metrics.refusal_spawned.load(Relaxed),
        8,
        "worker restart cannot create a ninth refusal task before the original eight finish"
    );
    assert_eq!(
        metrics.refusal_peak.load(Relaxed),
        8,
        "per-node refusal bound applies across worker generations"
    );
    metrics.before_post.release();
    drop(occupied);
    assert_eq!(last.await.unwrap().0,503,"full refusal lane gives truthful hub deadline, never fabricated Busy delivery or empty success");
    wait_pending(&f.state, 0).await;
}

#[tokio::test]
async fn control_scheduler_is_fair_with_observe_backlog_and_preserves_query_bindings() {
    let f = Arc::new(RelayFixture::new().await);
    let identities = collectors(&f, 3);
    let mut callers = Vec::new();
    for (index, identity) in identities.iter().enumerate() {
        let f = f.clone();
        let identity = identity.clone();
        callers.push(tokio::spawn(async move {
            f.request(
                &identity,
                "GET",
                &format!("{}?v=1&limit={}", f.uri("events"), index + 1),
                vec![],
                &[],
            )
            .await
        }));
    }
    wait_pending(&f.state, 3).await;
    let list = xmsg::fed::list_peer(&f.state, &f.leaf.node);
    let attachment =
        xmsg::fed::fetch_attachment_chunk(&f.state, &f.leaf.node, "synthetic-file", 0, 0, 16);
    let manual = async {
        let mut first = Vec::new();
        let mut observes = 0;
        for index in 0..5 {
            let (status, body) = f
                .request(
                    &f.leaf,
                    "GET",
                    "/fed/v2/inbox?control=true&wait=1&observe_relay=1",
                    vec![],
                    &[],
                )
                .await;
            assert_eq!(status, 200);
            let item: Value = serde_json::from_slice(&body).unwrap();
            let kind = item["kind"].as_str().unwrap();
            if index < 3 {
                first.push(kind.to_owned());
            }
            match kind {
                "observe" => {
                    observes += 1;
                    let request = &item["request"];
                    let collector = request["collector"].as_str().unwrap();
                    let index = identities
                        .iter()
                        .position(|i| i.full() == collector)
                        .unwrap();
                    assert_eq!(
                        request["query"],
                        format!("v=1&limit={}", index + 1),
                        "each actual collector retains its bound query and route"
                    );
                    let body = String::from_utf8(future_page())
                        .unwrap()
                        .replace("LEAF_NODE", &f.leaf.node)
                        .into_bytes();
                    assert_eq!(submit(&f, request, body).await.0, 200);
                }
                "list" => {
                    assert_eq!(
                        f.request(
                            &f.leaf,
                            "POST",
                            &format!("/fed/v2/list/{}", item["query"].as_str().unwrap()),
                            br#"{"status":"ok","entries":[]}"#.to_vec(),
                            &[("content-type", "application/json")]
                        )
                        .await
                        .0,
                        200
                    );
                }
                "attachment" => {
                    assert_eq!(
                        f.request(
                            &f.leaf,
                            "POST",
                            &format!("/fed/v2/attachment/{}", item["query"].as_str().unwrap()),
                            b"abc".to_vec(),
                            &[("content-type", "application/octet-stream")]
                        )
                        .await
                        .0,
                        200
                    );
                }
                _ => panic!("unexpected consuming control variant"),
            }
        }
        first.sort();
        assert_eq!(
            first,
            vec!["attachment", "list", "observe"],
            "all existing control classes progress within three dispatches despite observe backlog"
        );
        assert_eq!(observes, 3);
    };
    let (list, attachment, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(list, attachment, manual)
    })
    .await
    .unwrap();
    assert_eq!(list.1.status, "ok");
    assert_eq!(attachment.unwrap(), b"abc");
    for caller in callers {
        assert_eq!(caller.await.unwrap().0, 200);
    }
}

struct ChunkBody(tokio::sync::mpsc::Receiver<Bytes>);
impl hyper::body::Body for ChunkBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        self.0
            .poll_recv(context)
            .map(|chunk| chunk.map(|chunk| Ok(hyper::body::Frame::data(chunk))))
    }
}
fn streamed_answer(
    f: Arc<RelayFixture>,
    request: Value,
    receiver: tokio::sync::mpsc::Receiver<Bytes>,
) -> tokio::task::JoinHandle<(u16, Vec<u8>)> {
    tokio::spawn(async move {
        let connector =
            xmsg::fed::make_tls_connector(&f.leaf.cert, &f.leaf.key, &f.hub.pin).unwrap();
        let tcp = tokio::net::TcpStream::connect(f.address).await.unwrap();
        let tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .unwrap();
        let _connection = AbortTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let response = sender
            .send_request(
                hyper::Request::post(format!(
                    "/fed/v2/observe/relay/answer/{}",
                    request["id"].as_str().unwrap()
                ))
                .header("host", "localhost")
                .header("xmsg-observe-kind", request["read"].as_str().unwrap())
                .header("xmsg-observe-status", "ok")
                .body(ChunkBody(receiver))
                .unwrap(),
            )
            .await
            .unwrap();
        (
            response.status().as_u16(),
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    })
}
async fn wait_reservations(fs: &Arc<FedState>, expected: (usize, usize)) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while xmsg::observe_relay::test_hooks::reservations(fs) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded reader resource occupancy reached expected state");
}
async fn fresh_snapshot(f: &Arc<RelayFixture>) -> Vec<u8> {
    let caller = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        })
    };
    let request = control(f).await;
    let expected = empty_snapshot(f);
    assert_eq!(
        submit(f, &request, expected.clone()).await.0,
        200,
        "fresh expected-leaf answer succeeds"
    );
    let (status, body) = caller.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(body, expected, "fresh caller receives its exact DTO");
    wait_reservations(&f.state, (0, 0)).await;
    body
}

#[tokio::test]
async fn actual_streamed_answer_obeys_deadline_after_its_first_chunk() {
    for late in [false, true] {
        let f = Arc::new(RelayFixture::new().await);
        let before = f.state.db.lock().unwrap().total_changes();
        let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
        gates.after_answer_chunk.arm(1);
        let caller = {
            let f = f.clone();
            tokio::spawn(async move {
                f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                    .await
            })
        };
        let request = control(&f).await;
        let body = empty_snapshot(&f);
        let middle = body.len() / 2;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let answer = streamed_answer(f.clone(), request, receiver);
        sender
            .send(Bytes::copy_from_slice(&body[..middle]))
            .await
            .unwrap();
        gates.after_answer_chunk.wait_for(1).await;
        assert_eq!(
            xmsg::observe_relay::test_hooks::reservations(&f.state),
            (1, 512 * 1024),
            "first streamed chunk holds original bounded reservations"
        );
        assert_eq!(
            gates
                .max_buffered_answer
                .load(std::sync::atomic::Ordering::Relaxed),
            middle,
            "actual partial DTO reached the production reader"
        );
        if late {
            gates
                .clock_offset_ms
                .store(5001, std::sync::atomic::Ordering::Relaxed);
        }
        gates.after_answer_chunk.release();
        sender
            .send(Bytes::copy_from_slice(&body[middle..]))
            .await
            .unwrap();
        drop(sender);
        let answer = answer.await.unwrap();
        let response = caller.await.unwrap();
        if late {
            assert_eq!(
                answer.0, 400,
                "completed late stream is refused at the answer hop"
            );
            assert_eq!(response.0, 400, "late DTO never satisfies collector");
        } else {
            assert_eq!(answer.0, 200, "on-time neighboring stream succeeds");
            assert_eq!(response, (200, body), "on-time raw DTO remains unchanged");
        }
        assert_eq!(
            f.state.db.lock().unwrap().total_changes(),
            before,
            "late/on-time streaming never writes bus primary"
        );
        wait_pending(&f.state, 0).await;
        wait_reservations(&f.state, (0, 0)).await;
        gates
            .clock_offset_ms
            .store(0, std::sync::atomic::Ordering::Relaxed);
        fresh_snapshot(&f).await;
    }
}

#[tokio::test]
async fn stalled_partial_answer_terminates_at_original_five_second_deadline() {
    let f = Arc::new(RelayFixture::new().await);
    fresh_snapshot(&f).await;
    let before = f.state.db.lock().unwrap().total_changes();
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates
        .max_buffered_answer
        .store(0, std::sync::atomic::Ordering::Relaxed);
    gates.after_answer_chunk.arm(1);
    let caller = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        })
    };
    let request = control(&f).await;
    let body = empty_snapshot(&f);
    let middle = body.len() / 2;
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let wire_answer = streamed_answer(f.clone(), request, receiver);
    let (wire_ready, wire_observed) = tokio::sync::oneshot::channel();
    let (response_release, response_wait) = tokio::sync::oneshot::channel();
    let answer = tokio::spawn(async move {
        let response = wire_answer.await.unwrap();
        let _ = wire_ready.send(());
        let _ = response_wait.await;
        response
    });
    sender
        .send(Bytes::copy_from_slice(&body[..middle]))
        .await
        .unwrap();
    gates.after_answer_chunk.wait_for(1).await;
    assert_eq!(
        xmsg::observe_relay::test_hooks::reservations(&f.state),
        (1, 512 * 1024),
        "stalled partial reader owns its original slot and buffers"
    );
    tokio::time::pause();
    gates.after_answer_chunk.release();
    tokio::time::sleep(Duration::from_millis(4900)).await;
    assert_eq!(
        xmsg::observe_relay::test_hooks::reservations(&f.state),
        (1, 512 * 1024),
        "stalled partial reader must still hold its original slot shortly before the 5s deadline"
    );
    tokio::time::timeout(Duration::from_millis(2100), async {
        while xmsg::observe_relay::test_hooks::reservations(&f.state) != (0, 0) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("production read deadline releases original slot and buffers without producer EOF or client abort");
    assert_eq!(
        xmsg::observe_relay::test_hooks::pending(&f.state),
        0,
        "expired stalled answer leaves no pending waiter"
    );
    assert_eq!(
        gates
            .max_buffered_answer
            .load(std::sync::atomic::Ordering::Relaxed),
        middle,
        "producer supplied exactly one partial DTO chunk"
    );
    assert_eq!(
        gates
            .clock_offset_ms
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "deadline uses the production Tokio timer without an injected state-clock offset"
    );
    assert!(
        !answer.is_finished(),
        "server deadline does not depend on delayed client response completion"
    );
    tokio::time::resume();
    wire_observed.await.unwrap();
    assert!(!answer.is_finished(),"forced response-delay control keeps the old client-readiness predicate false after server cleanup");
    println!("FORCED_RESPONSE_DELAY server_slots=0 server_bytes=0 pending=0 wire_ready=true client_wrapper_ready=false");
    let _ = response_release.send(());
    let answer = answer.await.unwrap();
    assert_ne!(answer.0, 200, "partial stalled answer never succeeds");
    drop(sender);
    let response = caller.await.unwrap();
    assert_ne!(
        response.0, 200,
        "collector receives a fixed refusal, never a partial success"
    );
    assert_eq!(
        f.state.db.lock().unwrap().total_changes(),
        before,
        "stalled read never mutates bus primary"
    );
}

#[tokio::test]
async fn cancellation_during_answer_read_retains_reservations_until_stream_drops() {
    let f = Arc::new(RelayFixture::new().await);
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.after_answer_chunk.arm(1);
    let caller = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        })
    };
    let request = control(&f).await;
    let body = empty_snapshot(&f);
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let answer = streamed_answer(f.clone(), request.clone(), receiver);
    sender
        .send(Bytes::copy_from_slice(&body[..body.len() / 2]))
        .await
        .unwrap();
    gates.after_answer_chunk.wait_for(1).await;
    let cleanup_before = gates
        .waiter_cleanup_attempts
        .load(std::sync::atomic::Ordering::Acquire);
    caller.abort();
    let _ = caller.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while gates
            .waiter_cleanup_attempts
            .load(std::sync::atomic::Ordering::Acquire)
            == cleanup_before
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("real waiter cleanup attempt was not acknowledged");
    assert_eq!(
        xmsg::observe_relay::test_hooks::pending(&f.state),
        0,
        "cancelled collector cleanup must remove its pending waiter"
    );
    assert_eq!(
        xmsg::observe_relay::test_hooks::reservations(&f.state),
        (1, 512 * 1024),
        "cancelled collector cannot release resources still owned by its live answer read"
    );
    gates.after_answer_chunk.release();
    answer.abort();
    let _ = answer.await;
    drop(sender);
    wait_reservations(&f.state, (0, 0)).await;
    assert_eq!(
        submit(&f, &request, body).await.0,
        400,
        "cancelled id remains dead after answer stream drops"
    );
    fresh_snapshot(&f).await;
}

#[tokio::test]
async fn old_answer_after_worker_restart_cannot_satisfy_fresh_waiter() {
    let f = Arc::new(RelayFixture::new().await);
    let gates = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
    gates.before_post.arm(2);
    let worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let caller = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(&f.collector, "GET", &f.uri("events"), vec![], &[])
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), gates.before_post.wait_for(1))
        .await
        .unwrap();
    let old =
        serde_json::to_value(gates.received_control.lock().unwrap().clone().unwrap()).unwrap();
    caller.abort();
    let _ = caller.await;
    wait_pending(&f.state, 0).await;
    wait_reservations(&f.state, (0, 0)).await;
    tokio::time::timeout(Duration::from_secs(2), worker.stop())
        .await
        .unwrap();
    f._observer.publish(vec![xmsg::observe::Observation {
        kind: "message_recorded".into(),
        from: Some(format!("sender@{}", f.leaf.node)),
        to: Some(format!("receiver@{}", f.leaf.node)),
        message_id: Some("after-worker-restart".into()),
        body_availability: "not_recorded".into(),
        ..Default::default()
    }]);
    assert!(f._observer.flush_for_test(Duration::from_secs(3)));
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let fresh = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(&f.collector, "GET", &f.uri("events"), vec![], &[])
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), gates.before_post.wait_for(2))
        .await
        .unwrap();
    let current =
        serde_json::to_value(gates.received_control.lock().unwrap().clone().unwrap()).unwrap();
    assert_ne!(
        current["id"], old["id"],
        "fresh waiter gets a fresh opaque id"
    );
    assert_eq!(
        submit(
            &f,
            &old,
            String::from_utf8(future_page())
                .unwrap()
                .replace("LEAF_NODE", &f.leaf.node)
                .into_bytes()
        )
        .await
        .0,
        400,
        "old answer after worker/waiter restart is unsolicited"
    );
    assert!(
        !fresh.is_finished(),
        "old id cannot satisfy the fresh collector waiter"
    );
    assert_eq!(
        xmsg::observe_relay::test_hooks::pending(&f.state),
        1,
        "fresh waiter remains live after old answer refusal"
    );
    gates.before_post.release();
    let (status, body) = fresh.await.unwrap();
    assert_eq!(
        status, 200,
        "fresh production worker still completes its own bound answer"
    );
    let page: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["message_id"] == "after-worker-restart"),
        "fresh caller receives new projection rather than the old worker's already-prepared bytes"
    );
    wait_pending(&f.state, 0).await;
    wait_reservations(&f.state, (0, 0)).await;
}

#[tokio::test]
async fn leaf_default_off_refuses_current_direct_admission_before_any_metadata_read() {
    for enabled in [false, true] {
        let f = Arc::new(RelayFixture::new().await);
        reload(&f.leaf_state, |config| {
            config["reverse_observe"]["leaf_enabled"] = json!(enabled)
        });
        let reads = xmsg::observe_fed::test_hooks::controls(&f.leaf_state);
        assert_eq!(
            reads
                .snapshot_candidates
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        let caller = {
            let f = f.clone();
            tokio::spawn(async move {
                f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                    .await
            })
        };
        let request = control(&f).await;
        xmsg::observe_relay::test_hooks::deliver_control(
            &f.leaf_state,
            &f.hub.node,
            &f.hub.cert,
            "127.0.0.1".parse().unwrap(),
            serde_json::from_value(request).unwrap(),
        )
        .await;
        let (status, _) = caller.await.unwrap();
        assert_eq!(status,if enabled {200} else {403},"current-snapshot leaf enable guard is independent of poll capability and generation enabled={enabled}");
        let candidates = reads
            .snapshot_candidates
            .load(std::sync::atomic::Ordering::Relaxed);
        if enabled {
            assert!(
                candidates > 0,
                "enabled neighbor actually invokes production metadata projection"
            );
        } else {
            assert_eq!(
                candidates, 0,
                "disabled leaf never reads metadata before refusing"
            );
        }
        wait_pending(&f.state, 0).await;
        wait_reservations(&f.state, (0, 0)).await;
    }
}

fn policy_control(f: &RelayFixture) -> xmsg::observe_relay::Control {
    xmsg::observe_relay::Control {
        id: "policy-probe".into(),
        hub: f.hub.full(),
        leaf: f.leaf.full(),
        collector: f.collector.full(),
        read: xmsg::observe_relay::Kind::Snapshot,
        query: "".into(),
        remaining_ms: 5000,
    }
}
#[tokio::test]
async fn leaf_request_label_opt_in_is_applied_before_any_hub_filter() {
    let f = RelayFixture::new().await;
    reload(&f.leaf_state, |config| {
        config["peers"][&f.collector.node]["observe_labels"] = json!(true)
    });
    let mut control = policy_control(&f);
    for (query, labels) in [("", false), ("labels=false", false), ("labels=true", true)] {
        control.query = query.into();
        let bytes = xmsg::observe_relay::test_hooks::project_control(
            &f.leaf_state,
            &f.hub.node,
            &f.hub.cert,
            "127.0.0.1".parse().unwrap(),
            &control,
        )
        .await
        .expect("matching production leaf projection succeeds");
        let dto: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            !dto["endpoints"].as_array().unwrap().is_empty(),
            "projection probe actually reads planted registration"
        );
        assert_eq!(String::from_utf8_lossy(&bytes).contains("PRIVATE_LABEL"),labels,"leaf request-label suppression is measured before a hub can reject or rewrite it query={query}");
    }
}
#[tokio::test]
async fn leaf_current_admission_binds_full_collector_hub_and_self_before_reads() {
    for case in [
        "foreign collector authority",
        "wrong attested hub",
        "wrong leaf self",
        "unknown collector",
    ] {
        let (_directory, f) = uri_fixture().await;
        let reads = xmsg::observe_fed::test_hooks::controls(&f.leaf_state);
        let mut control = policy_control(&f);
        let ip = "127.0.0.1".parse().unwrap();
        assert_eq!(
            xmsg::observe_relay::test_hooks::admit_control(
                &f.leaf_state,
                &f.hub.node,
                &f.hub.cert,
                ip,
                &control
            ),
            200,
            "matching current-snapshot admission positive"
        );
        assert!(xmsg::observe_relay::test_hooks::project_control(
            &f.leaf_state,
            &f.hub.node,
            &f.hub.cert,
            ip,
            &control
        )
        .await
        .is_ok());
        assert!(
            reads
                .snapshot_candidates
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0,
            "matching projection proves metadata read counter"
        );
        reads
            .snapshot_candidates
            .store(0, std::sync::atomic::Ordering::Relaxed);
        reads
            .read_decisions
            .store(0, std::sync::atomic::Ordering::Relaxed);
        reads
            .read_admissions
            .store(0, std::sync::atomic::Ordering::Relaxed);
        match case {
            "foreign collector authority" => {
                control.collector = "spiffe://realm-two/host/collector/user/owner".into()
            }
            "wrong attested hub" => control.hub = "spiffe://realm-two/host/hub/user/owner".into(),
            "wrong leaf self" => control.leaf = "spiffe://realm-one/ns/leaves/sa/another".into(),
            _ => control.collector = "spiffe://realm-one/host/unconfigured/user/stranger".into(),
        }
        reload(&f.leaf_state, |config| {
            config["reverse_observe"]["routes"] =
                json!([{"hub":control.hub,"leaf":control.leaf,"collector":control.collector}])
        });
        assert_eq!(
            xmsg::observe_relay::test_hooks::admit_control(
                &f.leaf_state,
                &f.hub.node,
                &f.hub.cert,
                ip,
                &control
            ),
            403,
            "current valid route/grant must not erase {case} binding"
        );
        assert_eq!(
            reads
                .read_decisions
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "refused {case} never reserves a production read"
        );
        assert_eq!(
            reads
                .snapshot_candidates
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "refused {case} reads no metadata"
        );
    }
}
async fn hub_forward_generation_change(change: impl FnOnce(&RelayFixture, &mut Value)) {
    let f = RelayFixture::new().await;
    reload(&f.state, |config| {
        config["peers"][&f.collector.node]["observe_labels"] = json!(true)
    });
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_forward.arm(1);
    let caller = async {
        f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
            .await
    };
    let narrow = async {
        let request = control(&f).await;
        assert_eq!(submit(&f, &request, empty_snapshot(&f)).await.0, 200);
        gates.before_forward.wait_for(1).await;
        reload(&f.state, |config| change(&f, config));
        gates.before_forward.release();
    };
    let (response, ()) = tokio::join!(caller, narrow);
    assert_eq!(response.0,403,"original generation must invalidate prepared response even when fresh grant and empty DTO would permit it");
}
#[tokio::test]
async fn hub_route_removal_before_forward_is_enforced_by_original_generation() {
    hub_forward_generation_change(|_, config| config["reverse_observe"]["routes"] = json!([]))
        .await;
}
#[tokio::test]
async fn hub_labels_only_change_with_unlabeled_request_invalidates_original_generation() {
    hub_forward_generation_change(|f, config| {
        config["peers"][&f.collector.node]["observe_labels"] = json!(false)
    })
    .await;
}
#[tokio::test]
async fn authorized_collector_with_spoofed_origin_still_attests_actual_tls_identity() {
    let f = Arc::new(RelayFixture::new().await);
    let identities = collectors(&f, 2);
    let spoof = identities[1].full();
    for headers in [vec![], vec![("xmsg-origin", spoof.as_str())]] {
        let leaf_state = f.clone();
        let expected = identities[0].full();
        let other = spoof.clone();
        let leaf = tokio::spawn(async move {
            let request = control(&leaf_state).await;
            assert_eq!(
                request["collector"], expected,
                "origin header cannot substitute another valid authorized identity"
            );
            assert_ne!(request["collector"], other);
            assert_eq!(
                submit(&leaf_state, &request, empty_snapshot(&leaf_state))
                    .await
                    .0,
                200
            );
        });
        let response = f
            .request(&identities[0], "GET", &f.uri("snapshot"), vec![], &headers)
            .await;
        if response.0 != 200 {
            leaf.abort();
        }
        assert_eq!(
            response.0, 200,
            "spoofed origin must not falsely refuse an actual authorized collector"
        );
        leaf.await.unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_pair_race_refuses_duplicate_with_global_slots_available() {
    let f = Arc::new(RelayFixture::new().await);
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_admission.arm(2);
    let mut callers = Vec::new();
    for _ in 0..2 {
        let f = f.clone();
        callers.push(tokio::spawn(async move {
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
        }));
    }
    gates.before_admission.wait_for(2).await;
    gates.before_admission.release();
    let mut right = callers.pop().unwrap();
    let mut left = callers.pop().unwrap();
    let (response, waiting) = tokio::select! {response=&mut left=>(response.unwrap(),right),response=&mut right=>(response.unwrap(),left)};
    assert_eq!(
        response.0, 429,
        "same-pair duplicate refuses independently of the global eight-slot cap"
    );
    assert_eq!(xmsg::observe_relay::test_hooks::pending(&f.state), 1);
    assert_eq!(
        xmsg::observe_relay::test_hooks::reservations(&f.state),
        (1, 512 * 1024),
        "seven global slots remain available after pair refusal"
    );
    let request = control(&f).await;
    assert_eq!(submit(&f, &request, empty_snapshot(&f)).await.0, 200);
    assert_eq!(
        waiting.await.unwrap().0,
        200,
        "sole admitted pair still progresses"
    );
}

async fn persistent_caller(
    f: &RelayFixture,
    caller: &Identity,
) -> (
    hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    AbortTask,
) {
    let connector = xmsg::fed::make_tls_connector(&caller.cert, &caller.key, &f.hub.pin).unwrap();
    let tcp = tokio::net::TcpStream::connect(f.address).await.unwrap();
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let (sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    (
        sender,
        AbortTask(tokio::spawn(async move {
            let _ = connection.await;
        })),
    )
}

async fn persistent_request(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    uri: &str,
) -> (u16, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(12), async {
        let response = sender
            .send_request(
                hyper::Request::get(uri)
                    .header("host", "localhost")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        (
            response.status().as_u16(),
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    })
    .await
    .expect("bounded persistent request")
}

#[tokio::test]
async fn deny_reload_refuses_request_two_on_the_same_pinned_connection() {
    let f = RelayFixture::new().await;
    let (mut sender, _driver) = persistent_caller(&f, &f.leaf).await;
    assert_eq!(
        persistent_request(&mut sender, "/fed/v2/inbox?wait=0")
            .await
            .0,
        200
    );
    reload(&f.state, |config| {
        config["deny"] = json!({"spkis":[f.leaf.pin]})
    });
    let response = persistent_request(&mut sender, "/fed/v2/inbox?wait=0").await;
    assert_eq!(
        response.0, 403,
        "keep-alive request two must use current global deny"
    );
    assert!(String::from_utf8_lossy(&response.1).contains("denied"));
}

#[tokio::test]
async fn deny_reload_withholds_a_poll_already_parked_after_admission() {
    let f = Arc::new(RelayFixture::new().await);
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_dispatch.arm(1);
    let poll = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(&f.leaf, "GET", "/fed/v2/inbox?wait=10", vec![], &[])
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), gates.before_dispatch.wait_for(1))
        .await
        .expect("poll subscribed before deny");
    reload(&f.state, |config| {
        config["deny"] = json!({"spkis":[f.leaf.pin]})
    });
    f.state.notify_tx.send(f.leaf.node.clone()).unwrap();
    gates.before_dispatch.release();
    let response = poll.await.unwrap();
    assert_eq!(
        response.0, 403,
        "a request admitted before deny must not publish its parked answer"
    );
    assert!(String::from_utf8_lossy(&response.1).contains("denied"));
}

#[tokio::test]
async fn deny_mid_upload_refuses_the_next_frame_before_buffering_or_progress() {
    for denied in [false, true] {
        let f = Arc::new(RelayFixture::new().await);
        let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
        gates.after_answer_chunk.arm(1);
        let caller = {
            let f = f.clone();
            tokio::spawn(async move {
                f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                    .await
            })
        };
        let request = control(&f).await;
        let body = empty_snapshot(&f);
        let middle = body.len() / 2;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let answer = streamed_answer(f.clone(), request, receiver);
        sender
            .send(Bytes::copy_from_slice(&body[..middle]))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), gates.after_answer_chunk.wait_for(1))
            .await
            .expect("first frame actually appended");
        assert_eq!(
            gates
                .max_buffered_answer
                .load(std::sync::atomic::Ordering::Relaxed),
            middle
        );
        if denied {
            reload(&f.state, |config| {
                config["deny"] = json!({"spkis":[f.leaf.pin]})
            });
        }
        sender
            .send(Bytes::copy_from_slice(&body[middle..]))
            .await
            .unwrap();
        drop(sender);
        gates.after_answer_chunk.release();
        let answer = answer.await.unwrap();
        let response = caller.await.unwrap();
        if denied {
            assert_eq!(
                gates
                    .max_buffered_answer
                    .load(std::sync::atomic::Ordering::Relaxed),
                middle,
                "denied post-await frame must not append or advance the progress witness"
            );
            assert_ne!(answer.0, 200);
            assert_ne!(response.0, 200, "denied uploaded answer is withheld");
        } else {
            assert_eq!(answer.0, 200);
            assert_eq!(response, (200, body));
        }
    }
}

#[tokio::test]
async fn connector_uses_one_current_entry_for_stale_caller_trust_and_mode() {
    let f = RelayFixture::new().await;
    let mut stale = f
        .leaf_state
        .current_peers()
        .get(&f.hub.node)
        .unwrap()
        .clone();
    stale.pin = None;
    stale.ca = Some("obsolete-ca.pem".into());
    let connector = xmsg::fed::make_tls_connector_for_peer(&f.leaf_state, &stale)
        .expect("current configured pin must replace stale caller CA trust");
    let tcp = tokio::net::TcpStream::connect(f.address).await.unwrap();
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .expect("selected current verifier must authenticate the actual pinned server");
    let actual = tls.get_ref().1.peer_certificates().unwrap();
    assert_eq!(
        xmsg::fed::spki_sha256_from_der(actual[0].as_ref()).unwrap(),
        f.hub.pin
    );
}

#[tokio::test]
async fn expired_explicit_pin_still_authorizes_on_a_real_connection() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.not_after = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
    let cert = params.self_signed(&key).unwrap().der().to_vec();
    let pin = xmsg::fed::spki_sha256_from_der(&cert).unwrap();
    let caller = Identity {
        node: xmsg::node::node_name_from_pin(&pin).unwrap(),
        cert,
        key: key.serialize_der(),
        pin,
        ca_identity: None,
    };
    let f = RelayFixture::with_nodes(Identity::new(), caller).await;
    assert_eq!(
        f.request(&f.leaf, "GET", "/fed/v2/inbox?wait=0", vec![], &[])
            .await
            .0,
        200,
        "explicit pin remains date-independent at both handshake and request checks"
    );
}

#[tokio::test]
async fn actual_ca_leaf_expiry_refuses_keepalive_and_parked_poll_publication() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let bundle = directory.path().join("ca.pem");
    std::fs::write(&bundle, ca_params.self_signed(&ca_key).unwrap().pem()).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let uri = "spiffe://realm-one/ns/leaves/sa/leaf";
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let deadline = time::OffsetDateTime::now_utc().unix_timestamp() + 8;
    params.not_after = time::OffsetDateTime::from_unix_timestamp(deadline).unwrap();
    let cert = params.signed_by(&key, &issuer).unwrap().der().to_vec();
    let leaf = Identity {
        pin: xmsg::fed::spki_sha256_from_der(&cert).unwrap(),
        node: xmsg::node::node_name_from_uri(uri).unwrap(),
        cert,
        key: key.serialize_der(),
        ca_identity: Some((uri.into(), bundle.clone())),
    };
    let hub = ca_identity("spiffe://realm-one/host/hub/user/owner", &bundle, &issuer);
    let collector = ca_identity(
        "spiffe://realm-one/host/collector/user/owner",
        &bundle,
        &issuer,
    );
    let f = Arc::new(RelayFixture::with_identities(hub, leaf, collector).await);
    reload(&f.state, |config| {
        config["peers"]
            .as_object_mut()
            .unwrap()
            .remove(&f.leaf.node);
        config["hub"] = json!({
            "patterns":[{"pattern":uri,"ca":bundle}],
            "rules":[{"pattern":uri,"allow":["list"],"leaf":true}]
        });
    });
    let (mut persistent, _driver) = persistent_caller(&f, &f.leaf).await;
    assert_eq!(
        persistent_request(&mut persistent, "/fed/v2/inbox?wait=0")
            .await
            .0,
        200
    );
    let gates = xmsg::observe_relay::test_hooks::controls(&f.state);
    gates.before_dispatch.arm(1);
    let poll = {
        let f = f.clone();
        tokio::spawn(async move {
            f.request(&f.leaf, "GET", "/fed/v2/inbox?wait=10", vec![], &[])
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), gates.before_dispatch.wait_for(1))
        .await
        .expect("actual admitted CA poll reached the causal barrier before expiry");
    let renewed = ca_identity(uri, &bundle, &issuer);
    let renewed_cert = rustls::pki_types::CertificateDer::from(renewed.cert.clone());
    f.state
        .current_peers()
        .resolve_incoming_peer(&renewed_cert, &[])
        .unwrap();
    assert_eq!(
        f.state
            .current_peers()
            .admitted_clients
            .read()
            .unwrap()
            .get(uri)
            .unwrap()
            .pin,
        renewed.pin,
        "new actual CA leaf replaced the hub cache before the old socket expired"
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while time::OffsetDateTime::now_utc().unix_timestamp() < deadline {
            if time::OffsetDateTime::now_utc().unix_timestamp() < deadline - 1 {
                assert_eq!(
                    persistent_request(&mut persistent, "/fed/v2/inbox?wait=0")
                        .await
                        .0,
                    200,
                    "same admitted socket remains active before its actual deadline"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("real certificate notAfter elapsed");
    f.state.notify_tx.send(f.leaf.node.clone()).unwrap();
    gates.before_dispatch.release();
    let parked = poll.await.unwrap();
    assert_eq!(
        parked.0, 403,
        "CA poll crossing its actual leaf expiry must not publish"
    );
    assert!(String::from_utf8_lossy(&parked.1).contains("expired"));
    let second = persistent_request(&mut persistent, "/fed/v2/inbox?wait=0").await;
    assert_eq!(
        second.0, 403,
        "keepalive does not renew the old socket's actual expiry"
    );
    assert!(String::from_utf8_lossy(&second.1).contains("expired"));
}
