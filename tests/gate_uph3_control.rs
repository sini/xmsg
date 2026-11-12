#![cfg(unix)]
mod hop_client;
use serde_json::json;
use std::sync::{atomic::AtomicU64, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use xmsg::{
    fed::{self, FedState, PeerConfig, PeersMap, RateLimiter},
    storage,
};

struct Node {
    _directory: tempfile::TempDir,
    fs: Arc<FedState>,
    pin: String,
    port: u16,
    listener: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Node {
    fn drop(&mut self) {
        if let Some(task) = &self.listener {
            task.abort();
        }
    }
}
impl Node {
    fn new(name: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let (cert, key, pin) = fed::generate_self_signed_ed25519(name).unwrap();
        let db = Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap()));
        storage::init_db(&db.lock().unwrap()).unwrap();
        let (notify, _) = tokio::sync::broadcast::channel(64);
        let fs = Arc::new(FedState {
            node_name: name.into(),
            peers: Arc::new(PeersMap::empty()).into(),
            cert_der: cert,
            cert_chain_der: vec![],
            key_der: key,
            rate_limiter: Arc::new(RateLimiter::new(60, 20)),
            db,
            sessions_dirs: vec![],
            agy_config: xmsg::agy::AgyConfig {
                presence_dir: directory.path().join("presence"),
                proc_locks_path: directory.path().join("locks"),
                proc_root: directory.path().join("proc"),
                agy_bin: "agy".into(),
                trusted_agy_exes: vec![],
                brain_dir: Default::default(),
            },
            agy_store: xmsg::agy::new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx: notify.clone(),
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: notify.clone(),
            notify_tx: notify,
            max_body: 65536,
            max_attachment_bytes: 8 * 1024 * 1024,
            is_leaf: name == "leaf",
            leaf_principal: (name == "leaf").then(|| "demo".into()),
            outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
            dynamic_tls: Default::default(),
            reply_ttl: Duration::from_secs(604800),
            list_queries: Default::default(),
        });
        Self {
            _directory: directory,
            fs,
            pin,
            port: 0,
            listener: None,
        }
    }
    fn peer(&mut self, peer: &Node, leaf: bool, outbound: bool) {
        let fs = Arc::get_mut(&mut self.fs).unwrap();
        let mut peers = (*fs.current_peers()).clone();
        peers
            .insert(PeerConfig {
                name: peer.fs.node_name.clone(),
                address: format!("127.0.0.1:{}", peer.port),
                pin: Some(peer.pin.clone()),
                allow: vec!["send".into(), "reply".into(), "list".into()],
                leaf,
                dial: outbound.then(|| "outbound".into()),
                ..Default::default()
            })
            .unwrap();
        fs.peers = Arc::new(peers).into();
    }
    async fn listen(&mut self) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.port = listener.local_addr().unwrap().port();
        let fs = self.fs.clone();
        self.listener = Some(tokio::spawn(async move {
            fed::run_fed_listener(listener, fs).await.unwrap();
        }));
    }
    fn queue(&self, id: &str) {
        fed::queue_leaf_mailbox_message(
            &self.fs,
            "leaf",
            "demo",
            &fed::FedEnvelope {
                v: 2,
                id: id.into(),
                origin: storage::Origin::service("source", "hub"),
                to: fed::FedTarget {
                    r#ref: "demo".into(),
                },
                body: "ordinary message".into(),
                thread_id: id.into(),
                created_at: storage::now_epoch_secs(),
                forwarded: None,
                attachments: vec![],
            },
            "source@hub",
        )
        .unwrap();
    }
    fn holds(&self, id: &str) -> bool {
        storage::get_next_peer_mailbox_message(&self.fs.db.lock().unwrap(), "leaf")
            .unwrap()
            .is_some_and(|row| row.id == id)
    }
    async fn request(&self, hub: &Node, uri: &str) -> u16 {
        let identity = hop_client::Origin {
            cert_der: &self.fs.cert_der,
            key_der: &self.fs.key_der,
        };
        hop_client::request(&identity, &hub.pin, hub.port, "GET", uri, None)
            .await
            .0
    }
}
async fn pair() -> (Node, Node) {
    let mut hub = Node::new("hub");
    let mut leaf = Node::new("leaf");
    hub.peer(&leaf, true, false);
    hub.listen().await;
    leaf.peer(&hub, false, true);
    (hub, leaf)
}
async fn wait_until(mut condition: impl FnMut() -> bool, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consecutive_delayed_service_acks_do_not_starve_the_ordinary_inbox() {
    let (hub, leaf) = pair().await;
    let ids: Vec<_> = (0..6).map(|_| ulid::Ulid::new().to_string()).collect();
    for id in &ids {
        hub.queue(id);
    }
    let fs = leaf.fs.clone();
    let worker = tokio::spawn(async move {
        xmsg::svc::run_leaf_inbox_task(
            fs.clone(),
            "hub".into(),
            "demo".into(),
            fs.db.clone(),
            fs.svc_notify_tx.clone(),
        )
        .await;
    });
    for (index, id) in ids.iter().enumerate() {
        assert!(
            wait_until(
                || storage::has_svc_message(&leaf.fs.db.lock().unwrap(), id).unwrap(),
                Duration::from_secs(2)
            )
            .await,
            "message {index} never reached leaf custody"
        );
        tokio::time::sleep(Duration::from_millis(450)).await;
        assert!(
            hub.holds(id),
            "hub ACK preceded the local service ACK for message {index}"
        );
        storage::ack_svc_message(&leaf.fs.db.lock().unwrap(), "demo", id).unwrap();
        if !wait_until(|| !hub.holds(id), Duration::from_secs(2)).await {
            let mut statuses = Vec::new();
            for _ in 0..3 {
                statuses.push(leaf.request(&hub, "/fed/v2/inbox?wait=0").await);
            }
            worker.abort();
            let _ = worker.await;
            assert!(
                statuses.contains(&429),
                "stalled ACK did not reproduce inbox429: {statuses:?}"
            );
            panic!("UPH3: ordinary inbox quota starvation delayed service ACK {index}; observed HTTP statuses {statuses:?}");
        }
    }
    worker.abort();
    let _ = worker.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_only_inbox_never_returns_or_consumes_a_durable_message() {
    let (hub, leaf) = pair().await;
    let id = ulid::Ulid::new().to_string();
    hub.queue(&id);
    let origin = hop_client::Origin {
        cert_der: &leaf.fs.cert_der,
        key_der: &leaf.fs.key_der,
    };
    let (status, body) = hop_client::request(
        &origin,
        &hub.pin,
        hub.port,
        "GET",
        "/fed/v2/inbox?wait=0&control=true",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.is_null(),
        "UPH3: control-only request returned durable Message: {body}"
    );
    assert!(hub.holds(&id));
    let (status, body) = hop_client::request(
        &origin,
        &hub.pin,
        hub.port,
        "GET",
        "/fed/v2/inbox?wait=0",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["id"], id);
    assert!(hub.holds(&id));
}

#[test]
fn control_burst_is_bounded_and_does_not_spend_ordinary_quotas() {
    let limiter = RateLimiter::new(60, 20);
    for _ in 0..20 {
        assert!(limiter.check_control("peer"));
        assert!(limiter.check_and_consume("peer", Some("inbox:peer")));
    }
    assert!(
        !limiter.check_and_consume("peer", Some("inbox:peer")),
        "ordinary principal burst exceeds20"
    );
    for _ in 0..39 {
        assert!(limiter.check_and_consume("peer", None));
    }
    assert!(
        !limiter.check_and_consume("peer", None),
        "ordinary peer burst exceeds60"
    );
    for _ in 20..120 {
        assert!(
            limiter.check_control("peer"),
            "ordinary exhaustion starved own control bucket"
        );
    }
    assert!(!limiter.check_control("peer"), "control burst exceeds120");
    assert!(limiter.check_control("other-peer"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_chunks_and_local_ack_progress_despite_ordinary_exhaustion() {
    let (hub, leaf) = pair().await;
    let message = ulid::Ulid::new().to_string();
    hub.queue(&message);
    let file = "leaf-file";
    {
        let db = leaf.fs.db.lock().unwrap();
        let now = storage::now_epoch_secs();
        let reference = xmsg::attachments::stage(
            &db,
            "demo",
            "file.txt",
            Some("text/plain"),
            b"body",
            xmsg::attachments::Limits {
                max_bytes: 8 * 1024 * 1024,
                now,
                ttl_secs: 3600,
            },
        )
        .unwrap();
        xmsg::attachments::insert_rows(&db, file, &[reference], now + 3600, "", "hub").unwrap();
    }
    let fs = leaf.fs.clone();
    let worker = tokio::spawn(async move {
        xmsg::svc::run_leaf_inbox_task(
            fs.clone(),
            "hub".into(),
            "demo".into(),
            fs.db.clone(),
            fs.svc_notify_tx.clone(),
        )
        .await;
    });
    assert!(
        wait_until(
            || storage::has_svc_message(&leaf.fs.db.lock().unwrap(), &message).unwrap(),
            Duration::from_secs(2)
        )
        .await
    );
    for _ in 0..70 {
        leaf.request(&hub, "/fed/v2/inbox?wait=0").await;
    }
    assert_eq!(leaf.request(&hub, "/fed/v2/inbox?wait=0").await, 429);
    for offset in 0..4 {
        let chunk = tokio::time::timeout(
            Duration::from_secs(2),
            fed::fetch_attachment_chunk(&hub.fs, "leaf", file, 0, offset, 1),
        )
        .await
        .expect("UPH3: ordinary exhaustion starved reverse attachment control query")
        .unwrap();
        assert_eq!(chunk, vec![b"body"[offset as usize]]);
        assert!(
            hub.holds(&message),
            "attachment control handling ACKed message before service ACK"
        );
    }
    storage::ack_svc_message(&leaf.fs.db.lock().unwrap(), "demo", &message).unwrap();
    assert!(
        wait_until(|| !hub.holds(&message), Duration::from_secs(1)).await,
        "UPH3: local ACK waited for pending control request or control backoff"
    );
    worker.abort();
    let _ = worker.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_queries_remain_isolated_and_answers_bound_to_the_asked_peer() {
    let mut hub = Node::new("hub");
    let mut leaf = Node::new("leaf");
    let mut other = Node::new("other");
    hub.peer(&leaf, true, false);
    hub.peer(&other, true, false);
    hub.listen().await;
    leaf.peer(&hub, false, true);
    other.peer(&hub, false, true);
    let fs = hub.fs.clone();
    let fetch = tokio::spawn(async move {
        let _ = fed::fetch_attachment_chunk(&fs, "leaf", "item", 0, 0, 1).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    fn identity(node: &Node) -> hop_client::Origin<'_> {
        hop_client::Origin {
            cert_der: &node.fs.cert_der,
            key_der: &node.fs.key_der,
        }
    }
    let (status, answer) = hop_client::request(
        &identity(&other),
        &hub.pin,
        hub.port,
        "GET",
        "/fed/v2/inbox?control=true&wait=0",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(answer.is_null(), "other peer read leaf query");
    let (status, answer) = hop_client::request(
        &identity(&leaf),
        &hub.pin,
        hub.port,
        "GET",
        "/fed/v2/inbox?control=true&wait=1",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(answer["kind"], "attachment");
    let uri = format!("/fed/v2/attachment/{}", answer["query"].as_str().unwrap());
    let (status, _) = hop_client::request(
        &identity(&other),
        &hub.pin,
        hub.port,
        "POST",
        &uri,
        Some(json!({"error":"gone","detail":"wrong peer"})),
    )
    .await;
    assert_eq!(status, 404, "other peer answered leaf query");
    assert!(!fetch.is_finished());
    let (status, _) = hop_client::request(
        &identity(&leaf),
        &hub.pin,
        hub.port,
        "POST",
        &uri,
        Some(json!({"error":"gone","detail":"fixture unavailable"})),
    )
    .await;
    assert_eq!(status, 200);
    fetch.await.unwrap();
}

#[derive(Default)]
struct Counts {
    control: std::sync::atomic::AtomicUsize,
    ordinary: std::sync::atomic::AtomicUsize,
    acks: std::sync::atomic::AtomicUsize,
}
impl Node {
    async fn listen_observed(
        &mut self,
        legacy: bool,
        malformed_control: bool,
        control_delay: Duration,
        reject_mode: bool,
    ) -> Arc<Counts> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.port = listener.local_addr().unwrap().port();
        let fs = self.fs.clone();
        let counts = Arc::new(Counts::default());
        let observed = counts.clone();
        self.listener = Some(tokio::spawn(async move {
            let acceptor =
                fed::make_tls_acceptor(&fs.cert_chain(), &fs.key_der(), fs.current_peers())
                    .unwrap();
            let router = fed::build_fed_router(fs.clone());
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{
                        let (tcp,remote)=accepted.unwrap();let acceptor=acceptor.clone();let router=router.clone();let fs=fs.clone();let observed=observed.clone();
                        tasks.spawn(async move{
                            let tls=acceptor.accept(tcp).await.unwrap();
                            let certificates=tls.get_ref().1.peer_certificates().unwrap();
                            let (peer,uri)=fs.current_peers().resolve_incoming_peer(&certificates[0],&certificates[1..]).unwrap();
                            let authenticated=Arc::new(fed::AuthenticatedPeer{name:peer.name,pin:String::new(),uri,user:String::new(),remote_ip:remote.ip()});
                            let service=hyper::service::service_fn(move|mut request:hyper::Request<hyper::body::Incoming>|{
                                let router=router.clone();let authenticated=authenticated.clone();let observed=observed.clone();
                                async move{
                                    use axum::response::IntoResponse;
                                    let query=request.uri().query().unwrap_or("");
                                    let control=request.uri().path()=="/fed/v2/inbox" && query.contains("control=true");
                                    if request.uri().path()=="/fed/v2/inbox" {
                                        if control {observed.control.fetch_add(1,std::sync::atomic::Ordering::Relaxed);}else{observed.ordinary.fetch_add(1,std::sync::atomic::Ordering::Relaxed);}
                                    }
                                    if request.uri().path().ends_with("/ack"){observed.acks.fetch_add(1,std::sync::atomic::Ordering::Relaxed);}
                                    if control && !control_delay.is_zero(){tokio::time::sleep(control_delay).await;}
                                    if malformed_control && control {
                                        let body=json!({"kind":"message","id":"not-a-control","origin":{"service":"source","node":"hub"},"body":"ordinary","to":"demo"});
                                        return Ok::<_,std::convert::Infallible>(axum::Json(Some(body)).into_response());
                                    }
                                    if reject_mode && request.uri().path()=="/fed/v2/inbox" && query.contains("control="){
                                        return Ok::<_,std::convert::Infallible>((axum::http::StatusCode::BAD_REQUEST,axum::Json(json!({"error":"bad_request","detail":"unknown query control"}))).into_response());
                                    }
                                    if legacy && request.uri().path()=="/fed/v2/inbox" {
                                        let stripped=query.split('&').filter(|field|!field.starts_with("control=")).collect::<Vec<_>>().join("&");
                                        *request.uri_mut()=format!("/fed/v2/inbox?{stripped}").parse().unwrap();
                                    }
                                    let mut request=request.map(axum::body::Body::new);request.extensions_mut().insert(authenticated);
                                    use tower::ServiceExt;
                                    Ok(router.oneshot(request).await.unwrap())
                                }
                            });
                            let _=hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls),service).await;
                        });
                    }
                    _=tasks.join_next(),if !tasks.is_empty()=>{}
                }
            }
        }));
        counts
    }
}
fn plant_file(node: &Node, item: &str, data: &[u8]) -> xmsg::client::AttachmentRef {
    let db = node.fs.db.lock().unwrap();
    let now = storage::now_epoch_secs();
    let reference = xmsg::attachments::stage(
        &db,
        "demo",
        "file.bin",
        Some("application/octet-stream"),
        data,
        xmsg::attachments::Limits {
            max_bytes: 8 * 1024 * 1024,
            now,
            ttl_secs: 3600,
        },
    )
    .unwrap();
    xmsg::attachments::insert_rows(
        &db,
        item,
        std::slice::from_ref(&reference),
        now + 3600,
        "",
        "hub",
    )
    .unwrap();
    reference
}
fn start_leaf(leaf: &Node) -> tokio::task::JoinHandle<()> {
    let fs = leaf.fs.clone();
    tokio::spawn(async move {
        xmsg::svc::run_leaf_inbox_task(
            fs.clone(),
            "hub".into(),
            "demo".into(),
            fs.db.clone(),
            fs.svc_notify_tx.clone(),
        )
        .await;
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_controller_transfers_full_eight_mib_without_spending_ordinary_quota() {
    let mut hub = Node::new("hub");
    let mut leaf = Node::new("leaf");
    hub.peer(&leaf, true, false);
    let counts = hub
        .listen_observed(false, false, Duration::ZERO, false)
        .await;
    leaf.peer(&hub, false, true);
    let data: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let item = "full-eight-mib";
    let reference = plant_file(&leaf, item, &data);
    {
        let db = hub.fs.db.lock().unwrap();
        xmsg::attachments::insert_rows(
            &db,
            item,
            std::slice::from_ref(&reference),
            storage::now_epoch_secs() + 3600,
            "leaf",
            "",
        )
        .unwrap();
    }
    let worker = start_leaf(&leaf);
    assert!(
        wait_until(
            || counts.ordinary.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            Duration::from_secs(2)
        )
        .await
    );
    for _ in 0..70 {
        leaf.request(&hub, "/fed/v2/inbox?wait=0").await;
    }
    assert_eq!(leaf.request(&hub, "/fed/v2/inbox?wait=0").await, 429);
    let before = counts.ordinary.load(std::sync::atomic::Ordering::Relaxed);
    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(150),
        xmsg::federated_attachments::ensure_attachment(&hub.fs, item, 0),
    )
    .await
    .expect("full eightMiB transfer exceeded180sdeadline budget")
    .unwrap();
    let elapsed = started.elapsed();
    let controls = counts.control.load(std::sync::atomic::Ordering::Relaxed);
    let ordinary = counts.ordinary.load(std::sync::atomic::Ordering::Relaxed) - before;
    assert!(
        controls >= 128,
        "8MiB transfer didnot make128 bounded chunkqueries: {controls}"
    );
    assert!(
        ordinary <= elapsed.as_secs() as usize / 30 + 2,
        "controlnotifications consumedordinaryquota: {ordinary} requests in {elapsed:?}"
    );
    let bytes: Vec<u8> = hub
        .fs
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT data FROM blobs WHERE sha256=?1",
            [reference.sha256],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bytes, data, "full attachment data/hash was not preserved");
    println!("UPH3 fullsize: bytes={} control_requests={controls} ordinary_requests={ordinary} elapsed_ms={}",bytes.len(),elapsed.as_millis());
    worker.abort();
    let _ = worker.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_full_inbox_peer_interoperates_without_control_mode() {
    assert_legacy_peer(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_peer_rejecting_control_query_falls_back_for_messages_and_files() {
    assert_legacy_peer(true).await;
}
async fn assert_legacy_peer(reject_mode: bool) {
    let mut hub = Node::new("hub");
    let mut leaf = Node::new("leaf");
    hub.peer(&leaf, true, false);
    let counts = hub
        .listen_observed(true, false, Duration::ZERO, reject_mode)
        .await;
    leaf.peer(&hub, false, true);
    let ids: Vec<_> = (0..6).map(|_| ulid::Ulid::new().to_string()).collect();
    for id in &ids {
        hub.queue(id);
    }
    let reference = plant_file(&leaf, "legacy-file", b"small legacy file");
    let worker = start_leaf(&leaf);
    for (index, id) in ids.iter().enumerate() {
        assert!(
            wait_until(
                || storage::has_svc_message(&leaf.fs.db.lock().unwrap(), id).unwrap(),
                Duration::from_secs(2)
            )
            .await,
            "legacy message {index} starved"
        );
        if index == 2 {
            let chunk = tokio::time::timeout(
                Duration::from_secs(5),
                fed::fetch_attachment_chunk(&hub.fs, "leaf", "legacy-file", 0, 0, reference.size),
            )
            .await
            .expect("legacy reversefile query starved while awaitingserviceACK")
            .unwrap();
            assert_eq!(chunk, b"small legacy file");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(hub.holds(id), "legacy control worker ACKed durablemessage");
        storage::ack_svc_message(&leaf.fs.db.lock().unwrap(), "demo", id).unwrap();
        assert!(
            wait_until(|| !hub.holds(id), Duration::from_secs(1)).await,
            "legacy svcACK blocked bycontrolfallback"
        );
    }
    assert_eq!(
        counts.control.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "unsupportedcontrol path keptstealingordinaryquota"
    );
    worker.abort();
    let _ = worker.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_control_message_is_never_processed_or_acked() {
    let mut hub = Node::new("hub");
    let mut leaf = Node::new("leaf");
    hub.peer(&leaf, true, false);
    let counts = hub
        .listen_observed(false, true, Duration::ZERO, false)
        .await;
    leaf.peer(&hub, false, true);
    let worker = start_leaf(&leaf);
    assert!(
        wait_until(
            || counts.control.load(std::sync::atomic::Ordering::Relaxed) > 0,
            Duration::from_secs(2)
        )
        .await
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        counts.control.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "control worker keptpolling aftermalformed Message"
    );
    assert_eq!(
        counts.acks.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "control worker ACKed a durable Message"
    );
    assert!(
        !storage::has_svc_message(&leaf.fs.db.lock().unwrap(), "not-a-control").unwrap(),
        "control worker delivered a durable Message"
    );
    worker.abort();
    let _ = worker.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_control_notifications_do_not_restart_message_long_poll() {
    let mut hub = Node::new("hub");
    let mut leaf = Node::new("leaf");
    hub.peer(&leaf, true, false);
    let counts = hub
        .listen_observed(false, false, Duration::from_millis(100), false)
        .await;
    leaf.peer(&hub, false, true);
    plant_file(&leaf, "idle-file", b"body");
    let worker = start_leaf(&leaf);
    assert!(
        wait_until(
            || counts.ordinary.load(std::sync::atomic::Ordering::Relaxed) == 1
                && counts.control.load(std::sync::atomic::Ordering::Relaxed) == 1,
            Duration::from_secs(2)
        )
        .await
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    for offset in 0..4 {
        let bytes = tokio::time::timeout(
            Duration::from_secs(2),
            fed::fetch_attachment_chunk(&hub.fs, "leaf", "idle-file", 0, offset, 1),
        )
        .await
        .expect("idlecontroller didnot answer query")
        .unwrap();
        assert_eq!(bytes, vec![b"body"[offset as usize]]);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        counts.ordinary.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "UPH3: filecontrolnotifications reissuedordinaryinbox requests"
    );
    worker.abort();
    let _ = worker.await;
}
