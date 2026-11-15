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
        }
    }
    fn full(&self) -> String {
        format!("sha256:{}", self.pin)
    }
    fn peer(&self, address: &str, rights: &[&str], leaf: bool) -> Value {
        json!({"address":address,"pin":self.pin,"allow":rights,"leaf":leaf})
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
        agy_config: Default::default(),
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
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let leaf = Identity::new();
        let collector = Identity::new();
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
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
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
    task.abort();
    (status, bytes)
}

#[tokio::test]
async fn hub_relays_exact_raw_snapshot_only_via_advertising_control_poll() {
    let f = RelayFixture::new().await;
    let uri = f.uri("snapshot");
    let collector = f.request(&f.collector, "GET", &uri, vec![], &[]);
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
        assert!(!String::from_utf8_lossy(&body).contains("bearer"));
    }
    for fs in [&f.state, &f.leaf_state] {
        let db = fs.db.lock().unwrap();
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
    let caller = async {
        f.request(&f.collector, "GET", &f.uri(kind), vec![], &[])
            .await
    };
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
    assert_eq!(status, 200);
    assert_eq!(response.0, 200);
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
        };
        let f = RelayFixture::with_hub(hub).await;
        reload(&f.leaf_state, |c| {
            c["reverse_observe"]["leaf_enabled"] = json!(false)
        });
        let result = xmsg::fed::get_federated_inbox(&f.leaf_state, &f.hub.node, 0).await;
        assert!(matches!(result,Ok(None)),"reverse-disabled ordinary pinned polling retains existing certificate acceptance: {result:?}");
        assert_eq!(
            f.request(&f.collector, "GET", &f.uri("snapshot"), vec![], &[])
                .await
                .0,
            403,
            "unsupported reverse identity does not weaken route binding"
        );
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
    let f = RelayFixture::new().await;
    let (address, _listener) = leaf_listener(&f).await;
    let reads = xmsg::observe_fed::test_hooks::controls(&f.leaf_state);
    reads.before_read.arm(8);
    let gates = xmsg::observe_relay::test_hooks::controls(&f.leaf_state);
    gates.before_send.arm(1);
    let _worker =
        xmsg::observe_relay::test_hooks::start_worker(f.leaf_state.clone(), f.hub.node.clone());
    let direct = async {
        let requests = (0..8)
            .map(|_| {
                request_to(
                    address,
                    &f.leaf,
                    &f.collector,
                    "GET",
                    "/fed/v2/observe/snapshot",
                    vec![],
                    &[],
                )
            })
            .collect::<Vec<_>>();
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
        drop(requests);
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
            gates.before_send.wait_for(1).await;
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
