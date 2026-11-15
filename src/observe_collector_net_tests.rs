use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    _directory: tempfile::TempDir,
    config_file: PathBuf,
    config: serde_json::Value,
    task: tokio::task::JoinHandle<()>,
    requests: Arc<AtomicUsize>,
    reply: Arc<Mutex<Vec<u8>>>,
    hold: Arc<AtomicBool>,
    ledger: Arc<Mutex<Vec<String>>>,
    closed: Arc<AtomicUsize>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
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
        let (responses, held, paths, disconnects) =
            (reply.clone(), hold.clone(), ledger.clone(), closed.clone());
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let observed = observed.clone();
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
        }
    }
    fn set_response(&self, status: &str, headers: &str, body: &[u8]) {
        let mut response = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        *self.reply.lock().unwrap() = response;
    }
    fn load(&self) -> Result<Config, Error> {
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
    assert_eq!(client.slots.available_permits(), 0);
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
