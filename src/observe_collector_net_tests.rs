use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) struct Fixture {
    _directory: tempfile::TempDir,
    config_file: PathBuf,
    pub(crate) config: serde_json::Value,
    task: tokio::task::JoinHandle<()>,
    pub(crate) requests: Arc<AtomicUsize>,
    reply: Arc<Mutex<Vec<u8>>>,
    hold: Arc<AtomicBool>,
    pub(crate) ledger: Arc<Mutex<Vec<String>>>,
    closed: Arc<AtomicUsize>,
    pub(crate) starts: Arc<Mutex<Vec<Instant>>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    pub(crate) async fn new() -> Self {
        Self::with_server(rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap())
            .await
    }
    async fn with_server(server: rcgen::CertifiedKey<rcgen::KeyPair>) -> Self {
        Self::with_server_key(server, None).await
    }
    async fn with_server_key(
        server: rcgen::CertifiedKey<rcgen::KeyPair>,
        client_key: Option<rcgen::KeyPair>,
    ) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let client = match client_key {
            Some(signing_key) => rcgen::CertifiedKey {
                cert: rcgen::CertificateParams::new(vec!["localhost".into()])
                    .unwrap()
                    .self_signed(&signing_key)
                    .unwrap(),
                signing_key,
            },
            None => rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap(),
        };
        let server_pin = crate::fed::spki_sha256_from_der(server.cert.der()).unwrap();
        let client_pin = crate::fed::spki_sha256_from_der(client.cert.der()).unwrap();
        let server_name = crate::node::node_name_from_pin(&server_pin).unwrap();
        let client_name = crate::node::node_name_from_pin(&client_pin).unwrap();
        std::fs::write(directory.path().join("client.pem"), client.cert.pem()).unwrap();
        std::fs::write(
            directory.path().join("client.key"),
            client.signing_key.serialize_pem(),
        )
        .unwrap();
        let peer_json = json!({client_name.clone():{"address":"127.0.0.1:1","pin":client_pin,"allow":["observe"]}});
        let peers = Arc::new(PeersMap::load_from_json(&peer_json.to_string()).unwrap());
        let acceptor = crate::fed::make_tls_acceptor(
            &[server.cert.der().clone()],
            &server.signing_key.serialize_der(),
            peers,
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let scope =
            crate::observe_export::Scope::new(&server_name, &client_name, None, false).unwrap();
        let snapshot = crate::observe_export::project_snapshot(
            &scope,
            Vec::new(),
            crate::storage::now_epoch_secs(),
            true,
        )
        .unwrap();
        let body = serde_json::to_vec(&snapshot).unwrap();
        let reply = Arc::new(Mutex::new(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes()
            .into_iter()
            .chain(body)
            .collect::<Vec<_>>(),
        ));
        let hold = Arc::new(AtomicBool::new(false));
        let ledger = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let request_starts = starts.clone();
        let (responses, held, paths, disconnects) =
            (reply.clone(), hold.clone(), ledger.clone(), closed.clone());
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let observed = observed.clone();
                let starts = request_starts.clone();
                let (reply, hold, ledger, closed) = (
                    responses.clone(),
                    held.clone(),
                    paths.clone(),
                    disconnects.clone(),
                );
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut request = Vec::new();
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        let mut buf = [0; 1024];
                        let Ok(size) = tls.read(&mut buf).await else {
                            return;
                        };
                        if size == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..size]);
                    }
                    ledger
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(request).unwrap());
                    starts.lock().unwrap().push(Instant::now());
                    observed.fetch_add(1, Ordering::SeqCst);
                    while hold.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                    let response = reply.lock().unwrap().clone();
                    let _ = tls.write_all(&response).await;
                    let mut byte = [0];
                    let _ = tls.read(&mut byte).await;
                    closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        let config = json!({"client_cert":"client.pem","client_key":"client.key","auth":{
            "issuer":"https://idp.invalid/issuer","introspection_url":"https://idp.invalid/introspect","subjects":["owner"],"audience":"collector","hosted_client":"browser"
        },"sources":[{"node":server_name,"address":address.to_string(),"pin":server_pin}]});
        Self {
            config_file: directory.path().join("config.json"),
            _directory: directory,
            config,
            task,
            requests,
            reply,
            hold,
            ledger,
            closed,
            starts,
        }
    }
    pub(crate) fn set_response(&self, status: &str, headers: &str, body: &[u8]) {
        let mut response = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        *self.reply.lock().unwrap() = response;
    }
    pub(crate) fn load(&self) -> Result<Config, Error> {
        std::fs::write(&self.config_file, self.config.to_string()).unwrap();
        Config::load(&self.config_file)
    }
}

#[tokio::test]
async fn configured_pin_collects_without_any_bus_state_and_enforces_spacing() {
    let fixture = Fixture::new().await;
    let config = fixture.load().unwrap();
    let client = Client::new(&config).unwrap();
    let snapshot = client.snapshot(0).await.unwrap();
    assert_eq!(snapshot.node, config.sources[0].node);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Pending)),
        "minimum node spacing bypassed"
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn outbound_only_inventory_never_opens_a_connection() {
    let mut fixture = Fixture::new().await;
    fixture.config["sources"][0]["outbound_only"] = json!(true);
    let config = fixture.load().unwrap();
    let client = Client::new(&config).unwrap();
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Unsupported)),
        "outbound leaf became directly observable"
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn inventory_is_bounded_literal_and_unique() {
    let mut fixture = Fixture::new().await;
    assert!(fixture.load().is_ok());
    let entry = fixture.config["sources"][0].clone();
    fixture.config["sources"] = json!([entry.clone(), entry.clone()]);
    assert!(fixture.load().is_err(), "duplicate inventory node accepted");
    fixture.config["sources"] = json!((0..64)
        .map(|n| json!({"node":format!("node{n}"),"outbound_only":true}))
        .collect::<Vec<_>>());
    assert!(fixture.load().is_ok(), "exact inventory boundary refused");
    fixture.config["sources"]
        .as_array_mut()
        .unwrap()
        .push(json!({"node":"node64","outbound_only":true}));
    assert!(fixture.load().is_err(), "oversized inventory accepted");
    fixture.config["sources"] = json!([{"node":"owner.collector","address":"127.0.0.1:1","ca":"ca.pem","identity":"spiffe://xmsg/host/*/user/owner"}]);
    assert!(
        fixture.load().is_err(),
        "wildcard collector trust identity accepted"
    );
    fixture.config["sources"][0]["identity"] = json!("spiffe://xmsg/host/other/user/owner");
    assert!(
        fixture.load().is_err(),
        "foreign inventory identity accepted"
    );
    fixture.config["sources"] = json!([entry]);
    fixture.config["browser_address"] = json!("127.0.0.1:9");
    assert!(
        fixture.load().is_err(),
        "unrecognized configuration authority accepted"
    );
}

fn reset_spacing(client: &Client) {
    for source in &client.sources {
        *source.last_start.lock().unwrap() = None;
    }
}
async fn observed(fixture: &Fixture, count: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.requests.load(Ordering::SeqCst) < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn node_and_global_reservations_survive_forced_races() {
    let fixture = Fixture::new().await;
    fixture.hold.store(true, Ordering::SeqCst);
    let config = fixture.load().unwrap();
    let mut client = Client::new(&config).unwrap();
    for _ in 1..9 {
        let source = &client.sources[0];
        client.sources.push(Source {
            relay: None,
            server_name: source.server_name.clone(),
            node: source.node.clone(),
            labels: source.labels,
            supported: source.supported,
            peer: source.peer.clone(),
            connector: source.connector.clone(),
            slot: Arc::new(Semaphore::new(1)),
            last_start: Mutex::new(None),
        });
    }
    let client = Arc::new(client);
    let mut requests = tokio::task::JoinSet::new();
    for index in 0..8 {
        let client = client.clone();
        requests.spawn(async move { client.snapshot(index).await });
    }
    observed(&fixture, 8).await;
    assert_eq!(
        client.slots.available_permits(),
        0,
        "global request reservation exceeded eight"
    );
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Pending)),
        "per-node request reservation bypassed"
    );
    assert!(
        matches!(client.snapshot(8).await, Err(Error::Pending)),
        "global request reservation exceeded eight"
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 8);
    fixture.hold.store(false, Ordering::SeqCst);
    while let Some(reply) = requests.join_next().await {
        reply.unwrap().unwrap();
    }
    reset_spacing(&client);
    client.snapshot(8).await.unwrap();
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 9);
}
#[tokio::test]
async fn streamed_cap_encoding_status_and_closed_driver_are_independent() {
    let fixture = Fixture::new().await;
    let client = Client::new(&fixture.load().unwrap()).unwrap();
    let path = "/fed/v2/observe/snapshot".to_owned();
    fixture.set_response("200 OK", "", &vec![b' '; 256 * 1024]);
    assert_eq!(client.get(0, path.clone()).await.unwrap().len(), 256 * 1024);
    reset_spacing(&client);
    fixture.set_response("200 OK", "", &vec![b' '; 256 * 1024 + 1]);
    assert!(
        matches!(client.get(0, path.clone()).await, Err(Error::Malformed)),
        "stream byte cap bypassed"
    );
    reset_spacing(&client);
    *fixture.reply.lock().unwrap() = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        256 * 1024 + 1,
        " ".repeat(256 * 1024 + 1)
    )
    .into_bytes();
    assert!(
        matches!(client.get(0, path.clone()).await, Err(Error::Malformed)),
        "chunked byte cap bypassed"
    );
    reset_spacing(&client);
    fixture.set_response("200 OK", "Content-Encoding: gzip\r\n", b"{}");
    assert!(
        matches!(client.get(0, path.clone()).await, Err(Error::Malformed)),
        "compressed exporter response accepted"
    );
    reset_spacing(&client);
    fixture.set_response("403 Forbidden", "", b"do not expose producer errors");
    assert!(
        matches!(client.get(0, path.clone()).await, Err(Error::Denied)),
        "observe denial became unavailable"
    );
    reset_spacing(&client);
    fixture.set_response("429 Too Many Requests", "Retry-After: 999\r\n", b"");
    assert_eq!(
        client.get(0, path.clone()).await,
        Err(Error::RateLimited(60)),
        "rate limit upper bound bypassed"
    );
    reset_spacing(&client);
    fixture.set_response("429 Too Many Requests", "Retry-After: 0\r\n", b"");
    assert_eq!(
        client.get(0, path.clone()).await,
        Err(Error::RateLimited(2)),
        "rate limit lower bound bypassed"
    );
    reset_spacing(&client);
    fixture.set_response("302 Found", "Location: https://attacker.invalid/\r\n", b"");
    assert!(
        matches!(client.get(0, path).await, Err(Error::Unavailable)),
        "exporter redirect accepted"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.closed.load(Ordering::SeqCst) < 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(fixture
        .ledger
        .lock()
        .unwrap()
        .iter()
        .all(|request| request.starts_with("GET /fed/v2/observe/snapshot ")));
}
#[tokio::test]
async fn whole_rpc_deadline_aborts_header_and_body_drivers() {
    let fixture = Fixture::new().await;
    let client = Client::new(&fixture.load().unwrap()).unwrap();
    fixture.hold.store(true, Ordering::SeqCst);
    let started = Instant::now();
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Timeout)),
        "whole exporter RPC deadline bypassed"
    );
    assert!(
        started.elapsed() < Duration::from_millis(5700),
        "whole exporter request exceeded five-second deadline"
    );
    fixture.hold.store(false, Ordering::SeqCst);
    reset_spacing(&client);
    *fixture.reply.lock().unwrap() = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{".to_vec();
    let started = Instant::now();
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Timeout)),
        "exporter body escaped whole RPC deadline"
    );
    assert!(
        started.elapsed() < Duration::from_millis(5700),
        "whole exporter request exceeded five-second deadline"
    );
    reset_spacing(&client);
    fixture.set_response("200 OK", "", b"{}");
    assert!(matches!(client.snapshot(0).await, Err(Error::Malformed)));
    assert_eq!(
        client.slots.available_permits(),
        8,
        "timeout leaked exporter leases"
    );
}
#[tokio::test]
async fn wire_schema_and_fixed_paths_preserve_explicit_backfill() {
    let fixture = Fixture::new().await;
    let client = Client::new(&fixture.load().unwrap()).unwrap();
    fixture.set_response("200 OK","",br#"{"v":1,"node":"fixture.node","scope":"x","observed_at":100,"endpoints":[],"truncated":false,"available":"available","body":"synthetic-body-canary"}"#);
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Malformed)),
        "unknown exporter field accepted"
    );
    reset_spacing(&client);
    fixture.set_response("200 OK", "", br#"{}"#);
    let _ = client.events(0, None, None, 0).await;
    let ledger = fixture.ledger.lock().unwrap();
    assert!(ledger[0].starts_with("GET /fed/v2/observe/snapshot?v=1&labels=false "));
    assert!(
        ledger[1].starts_with("GET /fed/v2/observe/events?v=1&after=0&limit=200&labels=false "),
        "initial history did not use explicit zero cursor"
    );
    assert!(
        !ledger
            .iter()
            .any(|r| r.contains("inbox") || r.contains("ack") || r.contains("messages")),
        "collector fetched bus state"
    );
}

#[tokio::test]
async fn resolver_keeps_node_and_global_leases_after_cancellation() {
    let global = Arc::new(Semaphore::new(1));
    let node = Arc::new(Semaphore::new(1));
    let leases = Leases {
        _global: global.clone().try_acquire_owned().unwrap(),
        _node: node.clone().try_acquire_owned().unwrap(),
    };
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(resolve_with_leases(leases, move || {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        Ok(vec!["127.0.0.1:1".parse().unwrap()])
    }));
    started_rx.await.unwrap();
    task.abort();
    let _ = task.await;
    assert_eq!(
        global.available_permits(),
        0,
        "cancelled resolver released global permit early"
    );
    assert_eq!(
        node.available_permits(),
        0,
        "cancelled resolver released node permit early"
    );
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while global.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(node.available_permits(), 1);
}

#[tokio::test]
async fn connection_driver_is_aborted_on_owner_drop() {
    async fn scheduled() -> (
        Driver,
        Arc<tokio::sync::Notify>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let notify = Arc::new(tokio::sync::Notify::new());
        let task_notify = notify.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            task_notify.notified().await;
            let _ = done_tx.send(());
        });
        started_rx.await.unwrap();
        (Driver(task), notify, done_rx)
    }
    let (driver, notify, done) = scheduled().await;
    notify.notify_one();
    assert!(
        done.await.is_ok(),
        "driver completion positive control failed"
    );
    drop(driver);
    let (driver, notify, done) = scheduled().await;
    drop(driver);
    notify.notify_one();
    assert!(
        done.await.is_err(),
        "connection driver continued after its owner ended"
    );
}

#[tokio::test]
async fn one_node_reservation_is_independent_of_global_capacity() {
    let fixture = Fixture::new().await;
    let client = Arc::new(Client::new(&fixture.load().unwrap()).unwrap());
    fixture.hold.store(true, Ordering::SeqCst);
    let first_client = client.clone();
    let first = tokio::spawn(async move { first_client.snapshot(0).await });
    observed(&fixture, 1).await;
    assert_eq!(client.slots.available_permits(), 7);
    reset_spacing(&client);
    assert!(
        matches!(client.snapshot(0).await, Err(Error::Pending)),
        "per-node reservation bypassed with global capacity available"
    );
    fixture.hold.store(false, Ordering::SeqCst);
    first.await.unwrap().unwrap();
}

struct CaFixture {
    net: Fixture,
    ca_file: PathBuf,
    wrong_ca_file: PathBuf,
}
impl CaFixture {
    async fn new(uris: &[&str], kind: &str) -> Self {
        Self::with_client_key(uris, kind, None).await
    }
    async fn with_client_key(
        uris: &[&str],
        kind: &str,
        client_key: Option<rcgen::KeyPair>,
    ) -> Self {
        let mut ca = rcgen::CertificateParams::default();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
        let wrong_pem = ca
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem();
        let mut leaf = rcgen::CertificateParams::default();
        leaf.subject_alt_names = uris
            .iter()
            .map(|uri| rcgen::SanType::URI((*uri).try_into().unwrap()))
            .collect();
        leaf.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![if kind == "client-only" {
            rcgen::ExtendedKeyUsagePurpose::ClientAuth
        } else {
            rcgen::ExtendedKeyUsagePurpose::ServerAuth
        }];
        match kind {
            "expired" => {
                leaf.not_before = rcgen::date_time_ymd(2020, 1, 1);
                leaf.not_after = rcgen::date_time_ymd(2021, 1, 1);
            }
            "future" => {
                leaf.not_before = rcgen::date_time_ymd(2040, 1, 1);
                leaf.not_after = rcgen::date_time_ymd(2041, 1, 1);
            }
            _ => {}
        }
        let signing_key = rcgen::KeyPair::generate().unwrap();
        let cert = leaf
            .signed_by(&signing_key, &rcgen::Issuer::from_params(&ca, &ca_key))
            .unwrap();
        let net =
            Fixture::with_server_key(rcgen::CertifiedKey { cert, signing_key }, client_key).await;
        let ca_file = net._directory.path().join("ca.pem");
        let wrong_ca_file = net._directory.path().join("wrong-ca.pem");
        std::fs::write(&ca_file, ca_pem).unwrap();
        std::fs::write(&wrong_ca_file, wrong_pem).unwrap();
        Self {
            net,
            ca_file,
            wrong_ca_file,
        }
    }
    fn source(&self, identity: &str, foreign_ca: bool) -> serde_json::Value {
        json!({"node":crate::node::node_name_from_uri(identity).unwrap(),"address":self.net.config["sources"][0]["address"],"ca":if foreign_ca {&self.wrong_ca_file} else {&self.ca_file},"identity":identity})
    }
    fn ca_client(&self, identity: &str, foreign_ca: bool) -> Client {
        let mut config = self.net.config.clone();
        config["sources"] = json!([self.source(identity, foreign_ca)]);
        std::fs::write(&self.net.config_file, config.to_string()).unwrap();
        Client::new(&Config::load(&self.net.config_file).unwrap()).unwrap()
    }
}
const SERVER_IDENTITY: &str = "spiffe://xmsg/host/node/user/owner";
async fn trusted_ca_positive() {
    let fixture = CaFixture::new(&[SERVER_IDENTITY], "valid").await;
    fixture
        .ca_client(SERVER_IDENTITY, false)
        .get(0, "/fed/v2/observe/snapshot".into())
        .await
        .unwrap();
}
#[tokio::test]
async fn wrong_pin_refuses_after_valid_pin_control() {
    let mut fixture = Fixture::new().await;
    Client::new(&fixture.load().unwrap())
        .unwrap()
        .snapshot(0)
        .await
        .unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pin = crate::fed::spki_sha256_from_der(other.cert.der()).unwrap();
    fixture.config["sources"][0]["node"] = json!(crate::node::node_name_from_pin(&pin).unwrap());
    fixture.config["sources"][0]["pin"] = json!(pin);
    let result = Client::new(&fixture.load().unwrap())
        .unwrap()
        .snapshot(0)
        .await;
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "foreign pinned exporter was admitted"
    );
}
#[tokio::test]
async fn foreign_ca_refuses_after_trusted_chain_control() {
    trusted_ca_positive().await;
    let fixture = CaFixture::new(&[SERVER_IDENTITY], "valid").await;
    let result = fixture.ca_client(SERVER_IDENTITY, true).snapshot(0).await;
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "foreign CA exporter was admitted"
    );
}
#[tokio::test]
async fn invalid_ca_validity_and_eku_refuse() {
    trusted_ca_positive().await;
    for kind in ["expired", "future", "client-only"] {
        let fixture = CaFixture::new(&[SERVER_IDENTITY], kind).await;
        assert!(
            matches!(
                fixture.ca_client(SERVER_IDENTITY, false).snapshot(0).await,
                Err(Error::Unavailable)
            ),
            "invalid CA validity or server EKU admitted: {kind}"
        );
    }
}
#[tokio::test]
async fn ca_uri_cardinality_refuses_zero_and_multiple() {
    trusted_ca_positive().await;
    for uris in [
        vec![],
        vec![SERVER_IDENTITY, "spiffe://xmsg/host/other/user/owner"],
    ] {
        let fixture = CaFixture::new(&uris, "valid").await;
        assert!(
            matches!(
                fixture.ca_client(SERVER_IDENTITY, false).snapshot(0).await,
                Err(Error::Unavailable)
            ),
            "CA exporter with wrong URI cardinality was admitted"
        );
    }
}
#[tokio::test]
async fn ca_uri_match_is_literal() {
    trusted_ca_positive().await;
    let fixture = CaFixture::new(&[SERVER_IDENTITY], "valid").await;
    assert!(
        matches!(
            fixture
                .ca_client("spiffe://xmsg/host/other/user/owner", false)
                .snapshot(0)
                .await,
            Err(Error::Unavailable)
        ),
        "CA exporter with unlisted literal URI was admitted"
    );
}
async fn ambiguity(pin_first: bool) {
    let fixture = CaFixture::new(&[SERVER_IDENTITY], "valid").await;
    let pin = fixture.net.config["sources"][0].clone();
    let ca = fixture.source(SERVER_IDENTITY, false);
    Client::new(&fixture.net.load().unwrap())
        .unwrap()
        .snapshot(0)
        .await
        .unwrap();
    fixture
        .ca_client(SERVER_IDENTITY, false)
        .snapshot(0)
        .await
        .unwrap();
    let mut config = fixture.net.config.clone();
    config["sources"] = if pin_first {
        json!([pin, ca])
    } else {
        json!([ca, pin])
    };
    std::fs::write(&fixture.net.config_file, config.to_string()).unwrap();
    let result = Client::new(&Config::load(&fixture.net.config_file).unwrap())
        .unwrap()
        .snapshot(0)
        .await;
    assert!(
        matches!(result, Err(Error::Unavailable)),
        "outgoing collector pin/CA ambiguity was admitted"
    );
}
#[tokio::test]
async fn pinned_collector_dial_refuses_ca_membership() {
    ambiguity(true).await;
}
#[tokio::test]
async fn ca_collector_dial_refuses_pinned_membership() {
    ambiguity(false).await;
}

async fn closed_wire_object(which: &str) {
    let fixture = Fixture::new().await;
    let client = Client::new(&fixture.load().unwrap()).unwrap();
    let node = fixture.config["sources"][0]["node"].as_str().unwrap();
    let mut snapshot = json!({"v":1,"node":node,"scope":"a".repeat(64),"observed_at":1000,"endpoints":[{"id":format!("fixture@{node}"),"node":node,"kind":"service","harness":"unknown","state":"registered"}],"truncated":false,"available":"available"});
    let mut page = json!({"v":1,"node":node,"epoch":"fixture-epoch","scope":"a".repeat(64),"events":[{"sequence":1,"observed_at":1000,"persisted_at":1000,"kind":"message_recorded","available":"not_recorded"}],"next":1,"has_more":false,"gaps":[{"reason":"queue_loss","unknown_loss":true}],"available":true});
    let is_snapshot = matches!(which, "snapshot" | "endpoint");
    let positive = if is_snapshot { &snapshot } else { &page };
    fixture.set_response("200 OK", "", &serde_json::to_vec(positive).unwrap());
    if is_snapshot {
        client.snapshot(0).await.unwrap();
    } else {
        client.events(0, None, None, 0).await.unwrap();
    }
    match which {
        "event" => page["events"][0]["unexpected"] = json!("synthetic-wire-extra"),
        "gap" => page["gaps"][0]["unexpected"] = json!("synthetic-wire-extra"),
        "page" => page["unexpected"] = json!("synthetic-wire-extra"),
        "endpoint" => snapshot["endpoints"][0]["unexpected"] = json!("synthetic-wire-extra"),
        "snapshot" => snapshot["unexpected"] = json!("synthetic-wire-extra"),
        _ => panic!("unknown fixture object"),
    }
    reset_spacing(&client);
    fixture.set_response(
        "200 OK",
        "",
        &serde_json::to_vec(if is_snapshot { &snapshot } else { &page }).unwrap(),
    );
    let refused = if is_snapshot {
        matches!(client.snapshot(0).await, Err(Error::Malformed))
    } else {
        matches!(client.events(0, None, None, 0).await, Err(Error::Malformed))
    };
    assert!(refused, "incoming unknown field was accepted: {which}");
}
#[tokio::test]
async fn incoming_unknown_event_refuses() {
    closed_wire_object("event").await;
}
#[tokio::test]
async fn incoming_unknown_gap_refuses() {
    closed_wire_object("gap").await;
}
#[tokio::test]
async fn incoming_unknown_page_refuses() {
    closed_wire_object("page").await;
}
#[tokio::test]
async fn incoming_unknown_endpoint_refuses() {
    closed_wire_object("endpoint").await;
}
#[tokio::test]
async fn incoming_unknown_snapshot_refuses() {
    closed_wire_object("snapshot").await;
}
#[tokio::test]
async fn unknown_event_kinds_preserve_other_enum_refusals() {
    let fixture = Fixture::new().await;
    let client = Client::new(&fixture.load().unwrap()).unwrap();
    let mut page = json!({"v":1,"node":fixture.config["sources"][0]["node"],"epoch":"fixture-epoch","scope":"a".repeat(64),"events":[],"next":0,"has_more":false,"gaps":[],"available":true});
    fixture.set_response("200 OK", "", &serde_json::to_vec(&page).unwrap());
    client.events(0, None, None, 0).await.unwrap();
    page["events"] = json!([{"sequence":1,"observed_at":1000,"persisted_at":1000,"kind":"agent_read_completed","available":"not_recorded"}]);
    reset_spacing(&client);
    fixture.set_response("200 OK", "", &serde_json::to_vec(&page).unwrap());
    let decoded = client.events(0, None, None, 0).await.unwrap();
    assert_eq!(
        decoded.events[0].kind,
        crate::observe_export::EventKind::Unknown
    );
    page["events"][0]["outcome"] = json!("future_outcome");
    reset_spacing(&client);
    fixture.set_response("200 OK", "", &serde_json::to_vec(&page).unwrap());
    assert!(matches!(
        client.events(0, None, None, 0).await,
        Err(Error::Malformed)
    ));
}

fn use_relay(fixture: &mut Fixture) {
    let source = fixture.config["sources"][0].clone();
    fixture.config["sources"][0] = json!({"node":"leaf.fleet", "outbound_only":true,
        "relay":{"hub": format!("sha256:{}", crate::fed::normalize_pin(source["pin"].as_str().unwrap())),
        "leaf":"spiffe://fleet/ns/fleet/sa/leaf", "address":source["address"]}});
}
#[tokio::test]
async fn relay_config_closed_full_identity_and_no_mixed_mode() {
    let mut fixture = Fixture::new().await;
    use_relay(&mut fixture);
    assert!(fixture.load().is_ok());
    let valid = fixture.config.clone();
    for field in ["address", "pin", "ca", "identity"] {
        fixture.config = valid.clone();
        fixture.config["sources"][0][field] = json!("forbidden");
        assert!(
            fixture.load().is_err(),
            "mixed relay/direct {field} accepted"
        );
    }
    for field in ["hub", "leaf"] {
        for value in [
            "hub.node",
            "sha256:ABC",
            "spiffe://fleet/ns/*/sa/leaf",
            "sha256:00",
        ] {
            fixture.config = valid.clone();
            fixture.config["sources"][0]["relay"][field] = json!(value);
            assert!(
                fixture.load().is_err(),
                "noncanonical identity accepted: {field} {value}"
            );
        }
    }
    fixture.config = valid.clone();
    fixture.config["sources"][0]["relay"]["leaf"] = json!("spiffe://fleet/ns/other/sa/leaf");
    assert!(
        fixture.load().is_err(),
        "configured leaf was not bound to public node"
    );
    fixture.config = valid.clone();
    fixture.config["sources"][0]["relay"]["extra"] = json!(true);
    assert!(fixture.load().is_err());
    fixture.config = valid;
    fixture.config["sources"][0]["relay"]["hub"] = json!("spiffe://fleet/host/hub/user/owner");
    assert!(fixture.load().is_err(), "URI hub without CA accepted");
}
#[tokio::test]
async fn relay_transport_fixed_status_path_and_no_bearer() {
    let mut fixture = Fixture::new().await;
    use_relay(&mut fixture);
    for (status, expected) in [
        ("501 Not Implemented", Error::Unsupported),
        ("503 Service Unavailable", Error::Unavailable),
        ("400 Bad Request", Error::Malformed),
        ("403 Forbidden", Error::Denied),
        ("429 Too Many Requests", Error::RateLimited(2)),
    ] {
        fixture.set_response(status, "", b"");
        let client = Client::new(&fixture.load().unwrap()).unwrap();
        assert_eq!(client.snapshot(0).await.unwrap_err(), expected);
        let ledger = fixture.ledger.lock().unwrap();
        let request = ledger.last().unwrap();
        assert!(
            request.starts_with("GET /fed/v2/observe/relay/leaf.fleet/snapshot?v=1&labels=false ")
        );
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
        assert!(!request.to_ascii_lowercase().contains("origin"));
    }
    let calls = fixture.requests.load(Ordering::SeqCst);
    assert_eq!(calls, 5, "relay failure triggered direct/custody fallback");
}
#[tokio::test]
async fn relay_snapshot_and_event_share_source_admission() {
    let mut fixture = Fixture::new().await;
    use_relay(&mut fixture);
    fixture.set_response("503 Service Unavailable", "", b"");
    let client = Client::new(&fixture.load().unwrap()).unwrap();
    assert_eq!(client.snapshot(0).await.unwrap_err(), Error::Unavailable);
    assert_eq!(
        client.events(0, None, None, 0).await.unwrap_err(),
        Error::Pending
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_equal_display_hubs_keep_independent_full_identity_bindings() {
    let fixture = CaFixture::new(&[SERVER_IDENTITY], "valid").await;
    let mut config = fixture.net.config.clone();
    let route = |leaf: &str, hub: &str| {
        json!({"node":format!("{leaf}.fleet"),"relay":{
        "hub":hub,"leaf":format!("spiffe://fleet/ns/fleet/sa/{leaf}"),
        "address":fixture.net.config["sources"][0]["address"],"ca":fixture.ca_file}})
    };
    config["sources"] = json!([
        route("one", SERVER_IDENTITY),
        route("two", "spiffe://other/host/node/user/owner")
    ]);
    std::fs::write(&fixture.net.config_file, config.to_string()).unwrap();
    let client = Client::new(&Config::load(&fixture.net.config_file).unwrap()).unwrap();
    assert_eq!(client.sources[0].server_name, client.sources[1].server_name);
    assert!(
        client
            .get(0, "/fed/v2/observe/snapshot".into())
            .await
            .is_ok(),
        "second hub overwrote first full identity"
    );
    assert_eq!(
        client
            .get(1, "/fed/v2/observe/snapshot".into())
            .await
            .unwrap_err(),
        Error::Unavailable,
        "wrong full hub identity accepted"
    );
}
#[tokio::test]
async fn mixed_direct_and_relay_share_global_admission() {
    let mut direct = Fixture::new().await;
    let original = direct.config["sources"][0].clone();
    use_relay(&mut direct);
    let relay = direct.config["sources"][0].clone();
    direct.config["sources"] = json!([original, relay]);
    let mut client = Client::new(&direct.load().unwrap()).unwrap();
    for i in 2..9 {
        let source = &client.sources[i % 2];
        client.sources.push(Source {
            node: source.node.clone(),
            relay: source.relay.clone(),
            server_name: source.server_name.clone(),
            labels: false,
            supported: true,
            peer: source.peer.clone(),
            connector: source.connector.clone(),
            slot: Arc::new(Semaphore::new(1)),
            last_start: Mutex::new(None),
        });
    }
    direct.hold.store(true, Ordering::SeqCst);
    let client = Arc::new(client);
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..8 {
        let client = client.clone();
        tasks.spawn(async move { client.get(i, "/fed/v2/observe/snapshot".into()).await });
    }
    observed(&direct, 8).await;
    assert_eq!(client.snapshot(8).await.unwrap_err(), Error::Pending);
    assert_eq!(direct.requests.load(Ordering::SeqCst), 8);
    direct.hold.store(false, Ordering::SeqCst);
    while let Some(result) = tasks.join_next().await {
        assert!(result.unwrap().is_ok());
    }
}

#[tokio::test]
async fn relay_configured_pin_refuses_other_spki() {
    let mut fixture = Fixture::new().await;
    use_relay(&mut fixture);
    let good = Client::new(&fixture.load().unwrap()).unwrap();
    assert!(good.get(0, "/fed/v2/observe/snapshot".into()).await.is_ok());
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    fixture.config["sources"][0]["relay"]["hub"] = json!(format!(
        "sha256:{}",
        crate::fed::spki_sha256_from_der(other.cert.der()).unwrap()
    ));
    let wrong = Client::new(&fixture.load().unwrap()).unwrap();
    assert_eq!(wrong.snapshot(0).await.unwrap_err(), Error::Unavailable);
    assert_eq!(
        fixture.requests.load(Ordering::SeqCst),
        1,
        "wrong hub pin reached exporter"
    );
}
#[tokio::test]
async fn relay_dto_binding_and_future_kind_persist_configured_origin() {
    use crate::observe_collector_store::{NodePolicy, Store, StoreError};
    let mut fixture = Fixture::new().await;
    use_relay(&mut fixture);
    let client = Client::new(&fixture.load().unwrap()).unwrap();
    let node = "leaf.fleet";
    let origin = client.sources[0].relay.clone().unwrap();
    let store = Store::open(
        &fixture._directory.path().join("relay-state"),
        vec![NodePolicy {
            node: node.into(),
            relay: Some(origin.clone()),
            labels: false,
            supported: true,
        }],
        Arc::new(|| 1000),
    )
    .unwrap();
    let snapshot = json!({"v":1,"node":node,"scope":"a".repeat(64),"observed_at":1000,"endpoints":[],"truncated":false,"available":"available"});
    fixture.set_response("200 OK", "", &serde_json::to_vec(&snapshot).unwrap());
    store
        .ingest_snapshot(node, client.snapshot(0).await.unwrap())
        .unwrap();
    let page = json!({"v":1,"node":node,"epoch":"relay-fixture","scope":"a".repeat(64),"events":[{"sequence":1,"observed_at":1000,"persisted_at":1000,"kind":"future_relay_fixture","available":"not_recorded"}],"next":1,"has_more":false,"gaps":[],"available":true});
    fixture.set_response("200 OK", "", &serde_json::to_vec(&page).unwrap());
    reset_spacing(&client);
    store
        .ingest_decoded_page(
            node,
            &store.cursor(node).unwrap(),
            client.events_decoded(0, None, None, 0).await.unwrap(),
        )
        .unwrap();
    let view = store.view(Some(node), 200).unwrap().pop().unwrap();
    assert_eq!(
        view.events[0].event.kind,
        crate::observe_export::EventKind::Unknown
    );
    assert_eq!(
        view.events[0].origin_hub.as_deref(),
        Some(origin.hub.as_str())
    );
    assert_eq!(
        view.latest_snapshot.as_ref().unwrap().origin_hub.as_deref(),
        Some(origin.hub.as_str())
    );
    for actual in ["other.fleet", &client.sources[0].server_name] {
        let mut forged = snapshot.clone();
        forged["node"] = json!(actual);
        fixture.set_response("200 OK", "", &serde_json::to_vec(&forged).unwrap());
        reset_spacing(&client);
        assert_eq!(
            store
                .ingest_snapshot(node, client.snapshot(0).await.unwrap())
                .unwrap_err(),
            StoreError::Invalid,
            "snapshot DTO node substitution accepted"
        );
        let mut forged = page.clone();
        forged["node"] = json!(actual);
        fixture.set_response("200 OK", "", &serde_json::to_vec(&forged).unwrap());
        reset_spacing(&client);
        assert_eq!(
            store
                .ingest_decoded_page(
                    node,
                    &store.cursor(node).unwrap(),
                    client.events_decoded(0, None, None, 1).await.unwrap()
                )
                .unwrap_err(),
            StoreError::Invalid,
            "events DTO node substitution accepted"
        );
    }
    let mut extra = page.clone();
    extra["events"][0]["body"] = json!("synthetic-not-metadata");
    fixture.set_response("200 OK", "", &serde_json::to_vec(&extra).unwrap());
    reset_spacing(&client);
    assert!(
        client.events_decoded(0, None, None, 1).await.is_err(),
        "relay unknown kind admitted body field"
    );
    assert_eq!(store.cursor(node).unwrap().next, 1);
    assert_eq!(store.view(Some(node), 200).unwrap()[0].events.len(), 1);
    store
        .unavailable(
            node,
            crate::observe_collector_store::UnavailableKind::Timeout,
        )
        .unwrap();
    let stale = store.view(Some(node), 200).unwrap().pop().unwrap();
    assert_eq!(
        stale.status,
        crate::observe_collector_store::NodeStatus::Stale
    );
    assert_eq!(
        stale.events[0].origin_hub.as_deref(),
        Some(origin.hub.as_str())
    );
    let html = crate::observe_collector_web::render(
        std::slice::from_ref(&stale),
        Some(&stale),
        crate::observe_collector_web::Filter {
            node: Some(0),
            page: 0,
        },
    );
    assert!(html.contains(&format!("via {} (hub-attested)", origin.hub)));
    assert!(html.contains("unknown event kind (newer node)"));
}

#[tokio::test]
async fn relay_response_body_bound_has_exact_control() {
    let mut fixture = Fixture::new().await;
    use_relay(&mut fixture);
    let client = Client::new(&fixture.load().unwrap()).unwrap();
    fixture.set_response("200 OK", "", &vec![b'x'; 256 * 1024]);
    assert_eq!(
        client
            .get(0, "/fed/v2/observe/snapshot".into())
            .await
            .unwrap()
            .len(),
        256 * 1024
    );
    fixture.set_response("200 OK", "", &vec![b'x'; 256 * 1024 + 1]);
    reset_spacing(&client);
    assert_eq!(
        client
            .get(0, "/fed/v2/observe/snapshot".into())
            .await
            .unwrap_err(),
        Error::Malformed
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn relay_equal_display_hubs_at_distinct_addresses_both_succeed() {
    let identities = [SERVER_IDENTITY, "spiffe://other/host/node/user/owner"];
    let first = CaFixture::new(&[identities[0]], "valid").await;
    let key = rcgen::KeyPair::from_pem(
        &std::fs::read_to_string(first.net._directory.path().join("client.key")).unwrap(),
    )
    .unwrap();
    let second = CaFixture::with_client_key(&[identities[1]], "valid", Some(key)).await;
    let fixtures = [&first, &second];
    let mut config = first.net.config.clone();
    let mut sources = Vec::new();
    for (index, fixture) in fixtures.iter().enumerate() {
        let leaf = format!("leaf{index}.fleet");
        sources.push(json!({"node":leaf,"relay":{"hub":identities[index],"leaf":format!("spiffe://fleet/ns/fleet/sa/leaf{index}"),"address":fixture.net.config["sources"][0]["address"],"ca":fixture.ca_file}}));
        fixture.net.set_response("200 OK","",&serde_json::to_vec(&json!({"v":1,"node":leaf,"scope":"a".repeat(64),"observed_at":1000,"endpoints":[],"truncated":false,"available":"available"})).unwrap());
    }
    assert_ne!(
        sources[0]["relay"]["address"],
        sources[1]["relay"]["address"]
    );
    config["sources"] = json!(sources);
    std::fs::write(&first.net.config_file, config.to_string()).unwrap();
    let client = Client::new(&Config::load(&first.net.config_file).unwrap()).unwrap();
    assert_eq!(client.sources[0].server_name, client.sources[1].server_name);
    for (index, fixture) in fixtures.iter().enumerate() {
        assert_eq!(
            client.snapshot(index).await.unwrap().node,
            format!("leaf{index}.fleet"),
            "configured hub destination was overwritten"
        );
        assert_eq!(fixture.net.requests.load(Ordering::SeqCst), 1);
        assert!(fixture.net.ledger.lock().unwrap()[0].starts_with(&format!(
            "GET /fed/v2/observe/relay/leaf{index}.fleet/snapshot?v=1&labels=false "
        )));
    }
    config["sources"][0]["relay"]["hub"] = json!(identities[1]);
    std::fs::write(&first.net.config_file, config.to_string()).unwrap();
    let crossed = Client::new(&Config::load(&first.net.config_file).unwrap()).unwrap();
    assert_eq!(
        crossed.snapshot(0).await.unwrap_err(),
        Error::Unavailable,
        "crossed full hub URI accepted at first address"
    );
    assert_eq!(
        first.net.requests.load(Ordering::SeqCst),
        1,
        "crossed hub URI reached exporter"
    );
    assert_eq!(second.net.requests.load(Ordering::SeqCst), 1);
}
