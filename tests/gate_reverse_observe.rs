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
fn state(identity: &Identity, peers: PeersMap) -> Arc<FedState> {
    let db = rusqlite::Connection::open_in_memory().unwrap();
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
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let hub = Identity::new();
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
        let state = state(&hub, hub_peers);
        let leaf_state = self::state(&leaf, leaf_peers);
        let observer = xmsg::observe::Observer::start(
            &leaf_state.db,
            &dir.path().join("journal.sqlite"),
            &leaf.node,
            Default::default(),
        );
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
        let connector =
            xmsg::fed::make_tls_connector(&caller.cert, &caller.key, &self.hub.pin).unwrap();
        let tcp = tokio::net::TcpStream::connect(self.address).await.unwrap();
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
    fn uri(&self, kind: &str) -> String {
        format!("/fed/v2/observe/relay/{}/{kind}", self.leaf.node)
    }
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
    tokio::pin!(collector);
    tokio::pin!(leaf);
    let expected = tokio::select! {
        response=&mut collector => { assert_eq!(response.0,200,"hub relay request must wait for control answer"); panic!("collector completed before leaf"); }
        body=&mut leaf => body,
    };
    let (status, body) = collector.await;
    assert_eq!(status, 200);
    assert_eq!(body, expected, "hub preserves exact DTO bytes");
}
