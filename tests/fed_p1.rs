use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use rustls::pki_types::ServerName;
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::broadcast;

use xmsg::agent::run_agent_server;
use xmsg::agy::{flush_agy_queue, new_agy_store, AgyConfig, AgyCredentials, AgySessionInfo};
use xmsg::fed::{
    generate_self_signed_ed25519, generate_self_signed_ed25519_pem, make_tls_connector,
    run_fed_listener, send_federated_message, send_federated_reply, FedEnvelope, FedPrincipal,
    FedReplier, FedReplyEnvelope, FedState, FedTarget, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::{build_router, AppState};
use xmsg::pi::new_pi_store;
use xmsg::storage;
use xmsg::svc::new_svc_store;

pub struct TestNode {
    pub name: String,
    pub fed_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub agent_sock_path: PathBuf,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub pin: String,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub sessions_dir: PathBuf,
    pub fed_state: Arc<FedState>,
    pub inbox_rx: Arc<Mutex<Vec<String>>>,
    pub _tmp_dir: TempDir,
}

async fn create_test_node(
    name: &str,
    target_session_name: &str,
    peers: Vec<PeerConfig>,
) -> TestNode {
    create_test_node_full(name, target_session_name, peers, None, None).await
}

async fn create_test_node_full(
    name: &str,
    target_session_name: &str,
    peers: Vec<PeerConfig>,
    listener_opt: Option<TcpListener>,
    creds_opt: Option<(Vec<u8>, Vec<u8>, String)>,
) -> TestNode {
    create_test_node_full_inner(
        name,
        target_session_name,
        peers,
        listener_opt,
        creds_opt,
        None,
    )
    .await
}

async fn create_test_node_full_inner(
    name: &str,
    target_session_name: &str,
    peers: Vec<PeerConfig>,
    listener_opt: Option<TcpListener>,
    creds_opt: Option<(Vec<u8>, Vec<u8>, String)>,
    agy_bin_opt: Option<String>,
) -> TestNode {
    let tmp = TempDir::new().unwrap();
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let my_uid = xmsg::agent::current_uid();
    let sock_dir = tmp.path().join("run");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_sock_path = sock_dir.join(format!("agent-{name}.sock"));

    let target_inbox_sock = sock_dir.join(format!("inbox-{target_session_name}.sock"));
    let inbox_listener = UnixListener::bind(&target_inbox_sock).unwrap();
    let inbox_rx = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = inbox_rx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = inbox_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    let my_pid = std::process::id();
    let proc_root = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&proc_root, my_pid).unwrap_or_else(|_| "0".to_string());

    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": target_session_name,
        "name": target_session_name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": target_inbox_sock.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}.json")),
        session_json.to_string(),
    )
    .unwrap();

    let (cert_der, key_der, pin) = match creds_opt {
        Some(creds) => creds,
        None => generate_self_signed_ed25519(name).unwrap(),
    };

    let mut peers_map = HashMap::new();
    for p in peers {
        peers_map.insert(p.name.clone(), p);
    }
    let peers_arc = Arc::new(PeersMap::new(peers_map));

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));

    let (notify_tx, _) = broadcast::channel(16);
    let (pi_notify_tx, _) = broadcast::channel(16);
    let (svc_notify_tx, _) = broadcast::channel(16);

    let fed_state = Arc::new(FedState {
        host_label: name.to_string(),
        peers: peers_arc,
        cert_der: cert_der.clone(),
        key_der: key_der.clone(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: db.clone(),
        sessions_dir: sessions_dir.clone(),
        agy_config: AgyConfig {
            presence_dir: tmp.path().join("presence"),
            proc_locks_path: tmp.path().join("proc_locks"),
            proc_root: proc_root.clone(),
            agy_bin: agy_bin_opt.unwrap_or_else(|| "agy".to_string()),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: new_svc_store(),
        svc_notify_tx: svc_notify_tx.clone(),
        notify_tx: notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let fed_listener = match listener_opt {
        Some(l) => l,
        None => TcpListener::bind("127.0.0.1:0").await.unwrap(),
    };
    let fed_addr = fed_listener.local_addr().unwrap();
    let fs_clone = fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(fed_listener, fs_clone).await;
    });

    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: fed_state.agy_config.clone(),
        agy_store: fed_state.agy_store.clone(),
        pi_store: fed_state.pi_store.clone(),
        pi_notify_tx,
        svc_store: fed_state.svc_store.clone(),
        svc_notify_tx,
        host_label: name.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(fed_state.clone()),
    });

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let app = build_router(app_state.clone());
    tokio::spawn(async move {
        axum::serve(http_listener, app).await.unwrap();
    });

    let s_path = agent_sock_path.clone();
    let s_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    TestNode {
        name: name.to_string(),
        fed_addr,
        http_addr,
        agent_sock_path,
        cert_der,
        key_der,
        pin,
        db,
        sessions_dir,
        fed_state,
        inbox_rx,
        _tmp_dir: tmp,
    }
}

// =============================================================================
// Oracle 1: Attested cross-host send arrives with from-name and returns 202
// =============================================================================
#[tokio::test]
async fn test_oracle_1_attested_cross_host_send() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let fed_listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fed_addr_b = fed_listener_b.local_addr().unwrap();

    let node_a = create_test_node_full(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: fed_addr_b.to_string(),
            pin: pin_b.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        None,
        Some((cert_a, key_a, pin_a.clone())),
    )
    .await;

    let node_b = create_test_node_full(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: node_a.fed_addr.to_string(),
            pin: pin_a,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        Some(fed_listener_b),
        Some((cert_b, key_b, pin_b)),
    )
    .await;

    // Send via agent.sock from host-a to sess-b@host-b
    let stream = UnixStream::connect(&node_a.agent_sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let send_req = serde_json::json!({
        "action": "send",
        "ref": format!("sess-b@{}", node_b.name),
        "text": "Hello federated world from A",
        "push_replies": true,
    });
    writer
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["status"], "ok");
    assert_eq!(resp["delivery"]["outcome"], "delivered");

    // Wait for delivery to sess-b's inbox
    tokio::time::sleep(Duration::from_millis(100)).await;
    let inboxes = node_b.inbox_rx.lock().unwrap().clone();
    assert_eq!(inboxes.len(), 1);
    assert!(inboxes[0].contains("xmsg@host-a · claude:sess-a"));
    assert!(inboxes[0].contains("Hello federated world from A"));
}

// =============================================================================
// Oracle 2: Reply pushed back to sender stand-in and visible in GET /v1/messages/{id}
// =============================================================================
#[tokio::test]
async fn test_oracle_2_reply_pushed_back_and_recorded() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let fed_listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fed_addr_a = fed_listener_a.local_addr().unwrap();

    let fed_listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fed_addr_b = fed_listener_b.local_addr().unwrap();

    let node_a = create_test_node_full(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: fed_addr_b.to_string(),
            pin: pin_b.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        Some(fed_listener_a),
        Some((cert_a, key_a, pin_a.clone())),
    )
    .await;

    let node_b = create_test_node_full(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: fed_addr_a.to_string(),
            pin: pin_a,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        Some(fed_listener_b),
        Some((cert_b, key_b, pin_b)),
    )
    .await;

    // Send from A to B
    let stream_a = UnixStream::connect(&node_a.agent_sock_path).await.unwrap();
    let (reader_a, mut writer_a) = stream_a.into_split();
    let mut reader_a = BufReader::new(reader_a);

    let send_req = serde_json::json!({
        "action": "send",
        "ref": format!("sess-b@{}", node_b.name),
        "text": "Question from A",
        "push_replies": true,
    });
    writer_a
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();

    let mut line = String::new();
    reader_a.read_line(&mut line).await.unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    let message_id = resp["delivery"]["messageId"].as_str().unwrap().to_string();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Reply from B to A via agent_sock on B
    let stream_b = UnixStream::connect(&node_b.agent_sock_path).await.unwrap();
    let (reader_b, mut writer_b) = stream_b.into_split();
    let mut reader_b = BufReader::new(reader_b);

    let reply_req = serde_json::json!({
        "action": "reply",
        "messageId": message_id,
        "text": "Answer from B",
    });
    writer_b
        .write_all(format!("{reply_req}\n").as_bytes())
        .await
        .unwrap();

    let mut r_line = String::new();
    reader_b.read_line(&mut r_line).await.unwrap();
    let r_resp: serde_json::Value = serde_json::from_str(&r_line).unwrap();
    assert_eq!(r_resp["status"], "ok");

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Assert reply arrived at sess-a's inbox
    let inboxes_a = node_a.inbox_rx.lock().unwrap().clone();
    assert!(
        !inboxes_a.is_empty(),
        "Reply should be pushed to sess-a's inbox"
    );
    assert!(inboxes_a[0].contains("Answer from B"));

    // Check GET /v1/messages/{id} on Node A
    let client = reqwest::Client::new();
    let http_url = format!("http://{}/v1/messages/{}", node_a.http_addr, message_id);
    let msg_resp = client.get(&http_url).send().await.unwrap();
    assert_eq!(msg_resp.status(), 200);
    let msg_json: Value = msg_resp.json().await.unwrap();
    let replies = msg_json["replies"].as_array().unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["text"], "Answer from B");
    assert_eq!(replies[0]["pushOutcome"], "pushed");
}

// =============================================================================
// Oracle 3: Unpinned client certificate is refused at TLS handshake
// =============================================================================
#[tokio::test]
async fn test_oracle_3_unpinned_cert_refused_at_handshake() {
    let node_b = create_test_node("host-b", "sess-b", Vec::new()).await;

    // Generate untrusted cert/key
    let (bad_cert, bad_key, _) = generate_self_signed_ed25519("attacker").unwrap();

    let connector = make_tls_connector(&bad_cert, &bad_key, &node_b.pin).unwrap();
    let tcp_stream = tokio::net::TcpStream::connect(&node_b.fed_addr)
        .await
        .unwrap();
    let server_name = ServerName::try_from("host-b".to_string()).unwrap();

    let handshake_rejected = match connector.connect(server_name, tcp_stream).await {
        Err(_) => true,
        Ok(mut tls) => {
            let mut buf = [0u8; 1];
            tls.read(&mut buf).await.is_err()
        }
    };
    assert!(
        handshake_rejected,
        "Unpinned client certificate must be refused at handshake"
    );
}

// =============================================================================
// Oracle 4: Correct pin with WhoIs node mismatch gives 403 peer_rejected
// =============================================================================
// Unit X1.2 Oracle 1: from set, source inside -> accepted; source outside -> 403 with 0 bytes delivered
// =============================================================================
#[tokio::test]
async fn test_oracle_1_from_cidr_allowlist_enforced() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    // 1. Inside CIDR (127.0.0.1/32) -> Accepted (202) and delivered
    let node_b_allow = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: Some(vec!["127.0.0.1/32".to_string()]),
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let envelope1 = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "sess-a".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "Payload inside CIDR".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let fed_state_a1 = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b_allow.fed_addr.to_string(),
                    pin: node_b_allow.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a.clone(),
        key_der: key_a.clone(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b_allow.db.clone(),
        sessions_dir: node_b_allow.sessions_dir.clone(),
        agy_config: node_b_allow.fed_state.agy_config.clone(),
        agy_store: node_b_allow.fed_state.agy_store.clone(),
        pi_store: node_b_allow.fed_state.pi_store.clone(),
        pi_notify_tx: node_b_allow.fed_state.pi_notify_tx.clone(),
        svc_store: node_b_allow.fed_state.svc_store.clone(),
        svc_notify_tx: node_b_allow.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b_allow.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let res1 = send_federated_message(&fed_state_a1, "host-b", &envelope1).await;
    assert!(
        res1.is_ok(),
        "Expected success for source within from CIDR: {res1:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_b_allow.inbox_rx.lock().unwrap().len(), 1);

    // 2. Outside CIDR (10.0.0.0/8) -> 403 PeerRejected and 0 bytes in inbox
    let node_b_deny = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: Some(vec!["10.0.0.0/8".to_string()]),
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let envelope2 = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "sess-a".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "Payload outside CIDR".to_string(),
        push_replies: false,
        thread_id: "t2".to_string(),
        created_at: 2000,
    };

    let fed_state_a2 = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b_deny.fed_addr.to_string(),
                    pin: node_b_deny.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b_deny.db.clone(),
        sessions_dir: node_b_deny.sessions_dir.clone(),
        agy_config: node_b_deny.fed_state.agy_config.clone(),
        agy_store: node_b_deny.fed_state.agy_store.clone(),
        pi_store: node_b_deny.fed_state.pi_store.clone(),
        pi_notify_tx: node_b_deny.fed_state.pi_notify_tx.clone(),
        svc_store: node_b_deny.fed_state.svc_store.clone(),
        svc_notify_tx: node_b_deny.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b_deny.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let res2 = send_federated_message(&fed_state_a2, "host-b", &envelope2).await;
    match res2 {
        Err(xmsg::error::AppError::PeerRejected(detail)) => {
            assert!(
                detail.contains("not allowed by peer 'from' CIDR rules") || detail.contains("CIDR")
            );
        }
        other => panic!("Expected PeerRejected for source outside CIDR, got {other:?}"),
    }

    // Assert inbox received 0 bytes
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_b_deny.inbox_rx.lock().unwrap().len(), 0);
}

// =============================================================================
// Unit X1.2 Oracle 2: from absent -> accepted from any source (pin-only)
// =============================================================================
#[tokio::test]
async fn test_oracle_2_from_absent_pin_only_accepted() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let envelope = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "sess-a".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "Pin-only authenticated message".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let fed_state_a = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b.fed_addr.to_string(),
                    pin: node_b.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        svc_store: node_b.fed_state.svc_store.clone(),
        svc_notify_tx: node_b.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let res = send_federated_message(&fed_state_a, "host-b", &envelope).await;
    assert!(res.is_ok(), "Pin-only message should be accepted: {res:?}");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let inboxes = node_b.inbox_rx.lock().unwrap().clone();
    assert_eq!(inboxes.len(), 1);
    assert!(inboxes[0].contains("Pin-only authenticated message"));
}

// =============================================================================
// Unit X1.2 Oracle 3: from: [] -> refused at load with error naming peer
// =============================================================================
#[test]
fn test_oracle_3_empty_from_refused_at_load() {
    let json = r#"{
        "rogue-peer": {
            "address": "10.0.0.1:7788",
            "pin": "pin-12345",
            "allow": ["send"],
            "from": []
        }
    }"#;

    let res = PeersMap::load_from_json(json);
    assert!(
        res.is_err(),
        "empty from array must be refused at configuration load"
    );
    let err = res.unwrap_err();
    assert!(
        err.contains("rogue-peer"),
        "error must name the misconfigured peer, got: {err}"
    );
    assert!(
        err.contains("from"),
        "error must reference 'from', got: {err}"
    );
}

// =============================================================================
// Unit X1.2 Oracle 4: check applies on reply route too (reply outside from -> 403)
// =============================================================================
#[tokio::test]
async fn test_oracle_4_reply_route_source_check() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();

    // Node A only allows replies from host-b if source is in 10.0.0.0/8 (outside 127.0.0.1)
    let node_a = create_test_node(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_b.clone(),
            allow: vec!["reply".to_string()],
            from: Some(vec!["10.0.0.0/8".to_string()]),
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    // Insert an outbound record so in_reply_to is valid
    let orig_msg_id = ulid::Ulid::new().to_string();
    {
        let db = node_a.db.lock().unwrap();
        storage::insert_outbound(&db, &orig_msg_id, "host-b", "sess-b", "accepted", 1000).unwrap();
        storage::insert_message(
            &db,
            &storage::MessageRecord {
                id: orig_msg_id.clone(),
                created_at: 1000,
                session_id: "sess-a".to_string(),
                from_name: "xmsg@host-a · claude:sess-a".to_string(),
                bytes: 4,
                outcome: "accepted".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: Some("claude".to_string()),
                return_session_id: Some("sess-a".to_string()),
                return_host: None,
                push_replies: true,
                thread_id: "th1".to_string(),
            },
        )
        .unwrap();
    }

    let fed_state_b = Arc::new(FedState {
        host_label: "host-b".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-a".to_string(),
                PeerConfig {
                    name: "host-a".to_string(),
                    address: node_a.fed_addr.to_string(),
                    pin: node_a.pin.clone(),
                    allow: vec!["reply".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_b,
        key_der: key_b,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_a.db.clone(),
        sessions_dir: node_a.sessions_dir.clone(),
        agy_config: node_a.fed_state.agy_config.clone(),
        agy_store: node_a.fed_state.agy_store.clone(),
        pi_store: node_a.fed_state.pi_store.clone(),
        pi_notify_tx: node_a.fed_state.pi_notify_tx.clone(),
        svc_store: node_a.fed_state.svc_store.clone(),
        svc_notify_tx: node_a.fed_state.svc_notify_tx.clone(),
        notify_tx: node_a.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let reply = FedReplyEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        in_reply_to: orig_msg_id,
        replier: FedReplier {
            harness: "claude".to_string(),
            session_id: "sess-b".to_string(),
            name: "agent-b".to_string(),
        },
        text: "Valid reply from wrong source IP".to_string(),
        created_at: 1001,
    };

    let res = send_federated_reply(&fed_state_b, "host-a", &reply).await;
    match res {
        Err(xmsg::error::AppError::PeerRejected(detail)) => {
            assert!(
                detail.contains("not allowed by peer 'from' CIDR rules") || detail.contains("CIDR")
            );
        }
        other => panic!("Expected PeerRejected for reply from outside CIDR, got {other:?}"),
    }

    // Assert session inbox received 0 replies
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_a.inbox_rx.lock().unwrap().len(), 0);
}

// =============================================================================
// Unit X1.2 Oracle 5: no_whois present -> load error naming the field
// =============================================================================
#[test]
fn test_oracle_5_no_whois_rejected_at_load() {
    let json = r#"{
        "stale-peer": {
            "address": "10.0.0.1:7788",
            "pin": "pin-12345",
            "allow": ["send"],
            "no_whois": true
        }
    }"#;

    let res = PeersMap::load_from_json(json);
    assert!(
        res.is_err(),
        "stale no_whois field must be refused at configuration load"
    );
    let err = res.unwrap_err();
    assert!(
        err.contains("no_whois"),
        "error must name the stale field 'no_whois', got: {err}"
    );
    assert!(
        err.contains("stale-peer"),
        "error must name the peer, got: {err}"
    );
}

// =============================================================================
#[tokio::test]
async fn test_oracle_5_host_field_in_body_rejected() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let connector = make_tls_connector(&cert_a, &key_a, &node_b.pin).unwrap();
    let tcp_stream = tokio::net::TcpStream::connect(&node_b.fed_addr)
        .await
        .unwrap();
    let server_name = ServerName::try_from("host-b".to_string()).unwrap();
    let tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let body_with_host = serde_json::json!({
        "v": 1,
        "id": ulid::Ulid::new().to_string(),
        "host": "evil-host",
        "principal": {
            "kind": "session",
            "harness": "claude",
            "session_id": "s1",
            "name": "a1"
        },
        "to": { "ref": "sess-b" },
        "body": "test",
        "push_replies": false,
        "thread_id": "t1",
        "created_at": 1000
    });

    let req = hyper::Request::builder()
        .method("POST")
        .uri("/fed/v1/messages")
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            body_with_host.to_string(),
        )))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert!(
        resp.status().is_client_error(),
        "Unknown field 'host' must be rejected"
    );
}

// =============================================================================
// Oracle 6: Anonymous principal with from = "a:b" gives 400 at receiver
// =============================================================================
#[tokio::test]
async fn test_oracle_6_anonymous_from_with_colon_gives_400() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let envelope = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Anonymous {
            from: "bad:sender".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "test body".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let fed_state_a = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b.fed_addr.to_string(),
                    pin: node_b.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        svc_store: node_b.fed_state.svc_store.clone(),
        svc_notify_tx: node_b.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let res = send_federated_message(&fed_state_a, "host-b", &envelope).await;
    match res {
        Err(xmsg::error::AppError::BadRequest(msg)) => {
            assert!(msg.contains("colon") || msg.contains("invalid sender") || msg.contains(':'));
        }
        other => panic!("Expected BadRequest for anonymous sender with colon, got {other:?}"),
    }
}

// =============================================================================
// Oracle 7: harness = "root" gives 400; name with " · claude:y" is sanitized
// =============================================================================
#[tokio::test]
async fn test_oracle_7_root_harness_rejected_and_badge_spoof_sanitized() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let fed_state_a = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b.fed_addr.to_string(),
                    pin: node_b.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        svc_store: node_b.fed_state.svc_store.clone(),
        svc_notify_tx: node_b.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    // 1. harness = "root" gives 400
    let env_root = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "root".to_string(),
            session_id: "s1".to_string(),
            name: "admin".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "test".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };
    let res_root = send_federated_message(&fed_state_a, "host-b", &env_root).await;
    assert!(matches!(
        res_root,
        Err(xmsg::error::AppError::BadRequest(_))
    ));

    // 2. Name containing spoof badge separator " · claude:y"
    let env_spoof = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "x · claude:y".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "spoof attempt".to_string(),
        push_replies: false,
        thread_id: "t2".to_string(),
        created_at: 1000,
    };
    let res_spoof = send_federated_message(&fed_state_a, "host-b", &env_spoof).await;
    assert!(res_spoof.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;
    let inboxes = node_b.inbox_rx.lock().unwrap().clone();
    assert_eq!(
        res_spoof.unwrap().from_name,
        "xmsg@host-a · claude:x _ claude:y"
    );
    assert!(inboxes[0].contains("xmsg@host-a · claude:x _ claude:y"));
    assert!(!inboxes[0].contains(" · claude:y"));
}

#[tokio::test]
async fn test_n4_attested_name_ascii_only_u0387() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let fed_state_a = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b.fed_addr.to_string(),
                    pin: node_b.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        svc_store: node_b.fed_state.svc_store.clone(),
        svc_notify_tx: node_b.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let env_u0387 = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "x \u{0387} claude:y".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "homoglyph spoof attempt".to_string(),
        push_replies: false,
        thread_id: "t-u0387".to_string(),
        created_at: 1000,
    };
    let res = send_federated_message(&fed_state_a, "host-b", &env_u0387).await;
    assert!(res.is_ok());

    let resp = res.unwrap();
    assert_eq!(resp.from_name, "xmsg@host-a · claude:x _ claude:y");
}

// =============================================================================
// Oracle 8: to.ref = "x@C" gives 400 no_forward
// =============================================================================
#[tokio::test]
async fn test_oracle_8_no_forward_rejected() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let fed_state_a = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b.fed_addr.to_string(),
                    pin: node_b.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        svc_store: node_b.fed_state.svc_store.clone(),
        svc_notify_tx: node_b.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let env = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "user@host-c".to_string(),
        },
        body: "forward me".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let res = send_federated_message(&fed_state_a, "host-b", &env).await;
    match res {
        Err(xmsg::error::AppError::NoForward(_)) => {}
        other => panic!("Expected NoForward error, got {other:?}"),
    }
}

// =============================================================================
// Oracle 9: Forged reply id gives 403, and session receives 0 bytes
// =============================================================================
#[tokio::test]
async fn test_oracle_9_forged_reply_id_gives_403() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();

    let node_a = create_test_node(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_b.clone(),
            allow: vec!["reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let fed_state_b = Arc::new(FedState {
        host_label: "host-b".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-a".to_string(),
                PeerConfig {
                    name: "host-a".to_string(),
                    address: node_a.fed_addr.to_string(),
                    pin: node_a.pin.clone(),
                    allow: vec!["reply".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_b,
        key_der: key_b,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_a.db.clone(),
        sessions_dir: node_a.sessions_dir.clone(),
        agy_config: node_a.fed_state.agy_config.clone(),
        agy_store: node_a.fed_state.agy_store.clone(),
        pi_store: node_a.fed_state.pi_store.clone(),
        pi_notify_tx: node_a.fed_state.pi_notify_tx.clone(),
        svc_store: node_a.fed_state.svc_store.clone(),
        svc_notify_tx: node_a.fed_state.svc_notify_tx.clone(),
        notify_tx: node_a.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let forged_reply = FedReplyEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        in_reply_to: "01H000000000000000000FORGED".to_string(),
        replier: FedReplier {
            harness: "claude".to_string(),
            session_id: "sess-b".to_string(),
            name: "agent-b".to_string(),
        },
        text: "forged reply".to_string(),
        created_at: 1000,
    };

    let res = send_federated_reply(&fed_state_b, "host-a", &forged_reply).await;
    match res {
        Err(xmsg::error::AppError::NotRecipient(_)) => {}
        other => panic!("Expected NotRecipient on forged reply, got {other:?}"),
    }

    // Cross-peer reply: message sent by A to host-c, reply attempted by host-b -> 403 NotRecipient
    let msg_c_id = ulid::Ulid::new().to_string();
    {
        let db = node_a.db.lock().unwrap();
        storage::insert_outbound(&db, &msg_c_id, "host-c", "sess-c", "accepted", 1000).unwrap();
        storage::insert_message(
            &db,
            &storage::MessageRecord {
                id: msg_c_id.clone(),
                created_at: 1000,
                session_id: "sess-a".to_string(),
                from_name: "xmsg@host-a · claude:sess-a".to_string(),
                bytes: 4,
                outcome: "accepted".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: Some("claude".to_string()),
                return_session_id: Some("sess-a".to_string()),
                push_replies: true,
                thread_id: msg_c_id.clone(),
                return_host: Some("host-a".to_string()),
            },
        )
        .unwrap();
    }

    let cross_peer_reply = FedReplyEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        in_reply_to: msg_c_id,
        replier: FedReplier {
            harness: "claude".to_string(),
            session_id: "sess-b".to_string(),
            name: "agent-b".to_string(),
        },
        text: "cross-peer reply attempt".to_string(),
        created_at: 1000,
    };

    let res_cross = send_federated_reply(&fed_state_b, "host-a", &cross_peer_reply).await;
    match res_cross {
        Err(xmsg::error::AppError::NotRecipient(_)) => {}
        other => panic!("Expected NotRecipient on cross-peer reply, got {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        node_a.inbox_rx.lock().unwrap().len(),
        0,
        "Session inbox must receive 0 bytes"
    );
}

// =============================================================================
// Oracle 10: Duplicate message ID delivered once
// =============================================================================
#[tokio::test]
async fn test_oracle_10_duplicate_id_delivered_once() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let fed_state_a = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b.fed_addr.to_string(),
                    pin: node_b.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        svc_store: node_b.fed_state.svc_store.clone(),
        svc_notify_tx: node_b.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let dup_id = ulid::Ulid::new().to_string();
    let env = FedEnvelope {
        v: 1,
        id: dup_id.clone(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "deliver once only".to_string(),
        push_replies: false,
        thread_id: dup_id.clone(),
        created_at: 1000,
    };

    // First send
    let r1 = send_federated_message(&fed_state_a, "host-b", &env)
        .await
        .unwrap();
    assert_eq!(r1.message_id, dup_id);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_b.inbox_rx.lock().unwrap().len(), 1);

    // Second send (duplicate)
    let r2 = send_federated_message(&fed_state_a, "host-b", &env)
        .await
        .unwrap();
    assert_eq!(r2.message_id, dup_id);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        node_b.inbox_rx.lock().unwrap().len(),
        1,
        "Inbox must receive the message exactly once"
    );
}

// =============================================================================
// Oracle 11: Rate bucket returns 429 on message N+1
// =============================================================================
#[tokio::test]
async fn test_oracle_11_rate_limit_429() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let fed_state_a = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b.fed_addr.to_string(),
                    pin: node_b.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        svc_store: node_b.fed_state.svc_store.clone(),
        svc_notify_tx: node_b.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    // Send 20 messages (principal limit is 20/min)
    for _ in 0..20 {
        let env = FedEnvelope {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            principal: FedPrincipal::Session {
                harness: "claude".to_string(),
                session_id: "sess-flood".to_string(),
                name: "flooder".to_string(),
            },
            to: FedTarget {
                r#ref: "sess-b".to_string(),
            },
            body: "flood".to_string(),
            push_replies: false,
            thread_id: "t".to_string(),
            created_at: 1000,
        };
        send_federated_message(&fed_state_a, "host-b", &env)
            .await
            .unwrap();
    }

    // 21st message should exceed rate limit
    let env_exceeded = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "sess-flood".to_string(),
            name: "flooder".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "flood 21".to_string(),
        push_replies: false,
        thread_id: "t".to_string(),
        created_at: 1000,
    };
    let res = send_federated_message(&fed_state_a, "host-b", &env_exceeded).await;
    match res {
        Err(xmsg::error::AppError::RateLimited(_)) => {}
        other => panic!("Expected RateLimited error on message 21, got {other:?}"),
    }
}

// =============================================================================
// Oracle 12: Router isolation (no local route on fed router, no fed route on loopback)
// =============================================================================
#[tokio::test]
async fn test_oracle_12_router_isolation() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    // 1. Loopback HTTP router must NOT serve /fed/v1/messages
    let client = reqwest::Client::new();
    let loopback_resp = client
        .post(format!("http://{}/fed/v1/messages", node_b.http_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(
        loopback_resp.status(),
        StatusCode::NOT_FOUND,
        "Loopback router must NOT mount /fed routes"
    );

    // 2. Fed listener must NOT serve local routes (/healthz, /v1/sessions)
    let connector = make_tls_connector(&cert_a, &key_a, &node_b.pin).unwrap();
    let tcp_stream = tokio::net::TcpStream::connect(&node_b.fed_addr)
        .await
        .unwrap();
    let server_name = ServerName::try_from("host-b".to_string()).unwrap();
    let tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let healthz_req = hyper::Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    let healthz_resp = sender.send_request(healthz_req).await.unwrap();
    assert_eq!(
        healthz_resp.status(),
        hyper::StatusCode::NOT_FOUND,
        "Fed listener must NOT serve local routes"
    );
}

// =============================================================================
// Amendment (a): Peer without "send" gets 403 op_denied and inbox receives 0 bytes
// =============================================================================
#[tokio::test]
async fn test_amendment_a_peer_without_send_gets_403_op_denied() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["reply".to_string(), "list".to_string()], // NO "send"
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let fed_state_a = Arc::new(FedState {
        host_label: "host-a".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-b".to_string(),
                PeerConfig {
                    name: "host-b".to_string(),
                    address: node_b.fed_addr.to_string(),
                    pin: node_b.pin.clone(),
                    allow: vec!["send".to_string()],
                    from: None,
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        svc_store: node_b.fed_state.svc_store.clone(),
        svc_notify_tx: node_b.fed_state.svc_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let env = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "unauthorized send".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let res = send_federated_message(&fed_state_a, "host-b", &env).await;
    match res {
        Err(xmsg::error::AppError::OpDenied(_)) => {}
        other => panic!("Expected OpDenied when peer has no send permission, got {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        node_b.inbox_rx.lock().unwrap().len(),
        0,
        "Inbox must receive 0 bytes on op_denied"
    );
}

// =============================================================================
// Amendment (b): Unlinked well-formed cert refused at handshake
// =============================================================================
#[tokio::test]
async fn test_amendment_b_unlinked_well_formed_cert_refused() {
    let node_b = create_test_node("host-b", "sess-b", Vec::new()).await;

    // Well-formed ed25519 cert from unlinked node "host-c"
    let (cert_c, key_c, _) = generate_self_signed_ed25519("host-c").unwrap();

    let connector = make_tls_connector(&cert_c, &key_c, &node_b.pin).unwrap();
    let tcp_stream = tokio::net::TcpStream::connect(&node_b.fed_addr)
        .await
        .unwrap();
    let server_name = ServerName::try_from("host-b".to_string()).unwrap();

    let res = connector.connect(server_name, tcp_stream).await;
    let handshake_rejected = match res {
        Err(_) => true,
        Ok(mut tls) => {
            let mut buf = [0u8; 1];
            match tls.read(&mut buf).await {
                Err(e) => format!("{e:?}").contains("AlertReceived"),
                Ok(_) => false,
            }
        }
    };
    assert!(
        handshake_rejected,
        "Unlinked cert must be refused at handshake (AlertReceived)"
    );
}

// =============================================================================
// Amendment (c): unknown_peer opens no socket (listener accepted 0 connections)
// =============================================================================
#[tokio::test]
async fn test_amendment_c_unknown_peer_opens_no_socket() {
    // Stand-in listener that tracks connection attempts
    let stand_in = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stand_in_addr = stand_in.local_addr().unwrap();
    let conn_count = Arc::new(AtomicUsize::new(0));
    let cc_clone = conn_count.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = stand_in.accept().await {
            cc_clone.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let node_a = create_test_node("host-a", "sess-a", Vec::new()).await;

    // Send to unknown peer using the stand-in listener address as the host
    let unknown_ref = format!("sess-unknown@{stand_in_addr}");
    let stream = UnixStream::connect(&node_a.agent_sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let send_req = serde_json::json!({
        "action": "send",
        "ref": unknown_ref,
        "text": "test unknown peer",
        "push_replies": false,
    });
    writer
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();

    assert_eq!(resp["status"], "error");
    assert_eq!(resp["error"], "unknown_peer");

    // Also verify via HTTP API
    let client = reqwest::Client::new();
    let http_url = format!(
        "http://{}/v1/sessions/{unknown_ref}/messages",
        node_a.http_addr
    );
    let http_resp = client
        .post(&http_url)
        .json(&serde_json::json!({ "from": "caller", "text": "test unknown peer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(http_resp.status(), StatusCode::BAD_REQUEST);
    let err_body: serde_json::Value = http_resp.json().await.unwrap();
    assert_eq!(err_body["error"], "unknown_peer");

    // Assert stand-in listener accepted 0 connections
    assert_eq!(
        conn_count.load(Ordering::SeqCst),
        0,
        "Zero connections must be opened for unknown peer"
    );
}

// =============================================================================
// Amendment (d): Federated send to credential-less agy session is queued,
// then delivered once after credentials registered
// =============================================================================
#[tokio::test]
async fn test_amendment_d_federated_send_to_credential_less_agy_session_queued() {
    let tmp = TempDir::new().unwrap();
    let delivered_log = tmp.path().join("delivered.log");
    let fake_agy_bin = tmp.path().join("fake_agy.sh");
    let script_content = format!(
        r#"#!/bin/sh
echo "===DELIVERY===" >> "{}"
echo "$@" >> "{}"
exit 0
"#,
        delivered_log.display(),
        delivered_log.display()
    );
    fs::write(&fake_agy_bin, script_content).unwrap();
    fs::set_permissions(&fake_agy_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node_full_inner(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:0".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        None,
        Some((cert_b, key_b, pin_b)),
        Some(fake_agy_bin.to_string_lossy().to_string()),
    )
    .await;

    // Register credential-less agy session on node_b
    let my_pid = std::process::id();
    let proc_root = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&proc_root, my_pid).unwrap_or_else(|_| "0".to_string());
    let session_key = format!("agy:{my_pid}:{my_proc_start}");
    let conv_id = "conv-credless-1".to_string();

    let credless_session =
        AgySessionInfo::new(conv_id.clone(), my_pid, my_proc_start.clone(), None);
    node_b
        .fed_state
        .agy_store
        .write()
        .unwrap()
        .insert(session_key.clone(), credless_session);

    let node_a = create_test_node_full(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: node_b.fed_addr.to_string(),
            pin: node_b.pin.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        None,
        Some((cert_a, key_a, pin_a)),
    )
    .await;

    // 1. Send federated message from node_a targeting conv-credless-1@host-b via agent socket
    let stream = UnixStream::connect(&node_a.agent_sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let send_req = serde_json::json!({
        "action": "send",
        "ref": format!("{}@{}", conv_id, node_b.name),
        "text": "federated message to credential-less agy",
        "push_replies": false,
    });
    writer
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let resp: Value = serde_json::from_str(&line).unwrap();

    assert_eq!(resp["status"], "ok");
    assert_eq!(
        resp["delivery"]["outcome"], "queued",
        "federated message to credential-less agy session must be queued"
    );

    // 2. Verify nothing delivered yet to agy bin
    assert!(
        !delivered_log.exists(),
        "delivered.log must not exist before credentials registration"
    );

    // 3. Verify message is stored in SQLite agy_pending_messages on node_b
    let pending = {
        let db = node_b.db.lock().unwrap();
        storage::fetch_undelivered_agy_messages(&db, &[&session_key, &conv_id]).unwrap()
    };
    assert_eq!(pending.len(), 1, "exactly one pending agy message in db");
    assert_eq!(pending[0].text, "federated message to credential-less agy");

    // 4. Register credentials on node_b
    {
        let mut store_lock = node_b.fed_state.agy_store.write().unwrap();
        let entry = store_lock.get_mut(&session_key).unwrap();
        entry.credentials = Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "test-token".to_string(),
            is_stale: false,
        });
    }

    // 5. Trigger flush
    flush_agy_queue(
        &node_b.fed_state.agy_config,
        &node_b.fed_state.agy_store,
        &node_b.db,
        &session_key,
        &conv_id,
    )
    .await;

    // 6. Verify delivery
    assert!(
        delivered_log.exists(),
        "delivered.log must exist after credentials registration and flush"
    );
    let log_content = fs::read_to_string(&delivered_log).unwrap();
    assert!(
        log_content.contains("federated message to credential-less agy"),
        "delivery log must contain message body: {log_content}"
    );

    // 7. Verify no longer pending
    let pending_after = {
        let db = node_b.db.lock().unwrap();
        storage::fetch_undelivered_agy_messages(&db, &[&session_key, &conv_id]).unwrap()
    };
    assert_eq!(
        pending_after.len(),
        0,
        "pending agy messages must be empty after flush"
    );
}

// -----------------------------------------------------------------------------
// Helper to construct a client-side FedState for testing
// -----------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn make_client_fed_state(
    host_label: &str,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    peer_name: &str,
    peer_addr: String,
    peer_pin: String,
    allow: Vec<&str>,
    principals: Vec<&str>,
    base_node: &TestNode,
) -> Arc<FedState> {
    Arc::new(FedState {
        host_label: host_label.to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                peer_name.to_string(),
                PeerConfig {
                    name: peer_name.to_string(),
                    address: peer_addr,
                    pin: peer_pin,
                    allow: allow.into_iter().map(String::from).collect(),
                    from: None,
                    leaf: false,
                    principals: principals.into_iter().map(String::from).collect(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der,
        key_der,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: base_node.db.clone(),
        sessions_dir: base_node.sessions_dir.clone(),
        agy_config: base_node.fed_state.agy_config.clone(),
        agy_store: base_node.fed_state.agy_store.clone(),
        pi_store: base_node.fed_state.pi_store.clone(),
        pi_notify_tx: base_node.fed_state.pi_notify_tx.clone(),
        svc_store: base_node.fed_state.svc_store.clone(),
        svc_notify_tx: base_node.fed_state.svc_notify_tx.clone(),
        notify_tx: base_node.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    })
}

// =============================================================================
// Finding F2: Reply Fallback Removed & Origin Invariants Enforced
// =============================================================================

#[tokio::test]
async fn test_f2_anon_origin_reply_refused() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();

    let node_a = create_test_node(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_b.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    // Simulate an anonymous message that has no return_harness or return_session_id
    let anon_msg_id = ulid::Ulid::new().to_string();
    {
        let db = node_a.db.lock().unwrap();
        storage::insert_outbound(&db, &anon_msg_id, "host-b", "sess-b", "accepted", 1000).unwrap();
        storage::insert_message(
            &db,
            &storage::MessageRecord {
                id: anon_msg_id.clone(),
                created_at: 1000,
                session_id: "sess-b".to_string(),
                from_name: "xmsg@host-a · script".to_string(),
                bytes: 10,
                outcome: "accepted".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: None,
                return_session_id: None,
                push_replies: false,
                thread_id: anon_msg_id.clone(),
                return_host: Some("host-a".to_string()),
            },
        )
        .unwrap();
    }

    let fed_state_b = make_client_fed_state(
        "host-b",
        cert_b,
        key_b,
        "host-a",
        node_a.fed_addr.to_string(),
        node_a.pin.clone(),
        vec!["reply"],
        vec![],
        &node_a,
    );

    let reply = FedReplyEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        in_reply_to: anon_msg_id,
        replier: FedReplier {
            harness: "claude".to_string(),
            session_id: "sess-b".to_string(),
            name: "agent-b".to_string(),
        },
        text: "reply to anon message".to_string(),
        created_at: 1000,
    };

    let res = send_federated_reply(&fed_state_b, "host-a", &reply).await;
    assert!(matches!(res, Err(xmsg::error::AppError::NotRecipient(_))));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_a.inbox_rx.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn test_f2_push_replies_false_refused() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();

    let node_a = create_test_node(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_b.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let msg_id = ulid::Ulid::new().to_string();
    {
        let db = node_a.db.lock().unwrap();
        storage::insert_outbound(&db, &msg_id, "host-b", "sess-b", "accepted", 1000).unwrap();
        storage::insert_message(
            &db,
            &storage::MessageRecord {
                id: msg_id.clone(),
                created_at: 1000,
                session_id: "sess-a".to_string(),
                from_name: "xmsg@host-a · claude:sess-a".to_string(),
                bytes: 10,
                outcome: "accepted".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: Some("claude".to_string()),
                return_session_id: Some("sess-a".to_string()),
                push_replies: false,
                thread_id: msg_id.clone(),
                return_host: Some("host-a".to_string()),
            },
        )
        .unwrap();
    }

    let fed_state_b = make_client_fed_state(
        "host-b",
        cert_b,
        key_b,
        "host-a",
        node_a.fed_addr.to_string(),
        node_a.pin.clone(),
        vec!["reply"],
        vec![],
        &node_a,
    );

    let reply = FedReplyEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        in_reply_to: msg_id,
        replier: FedReplier {
            harness: "claude".to_string(),
            session_id: "sess-b".to_string(),
            name: "agent-b".to_string(),
        },
        text: "forced reply".to_string(),
        created_at: 1000,
    };

    let res = send_federated_reply(&fed_state_b, "host-a", &reply).await;
    assert!(matches!(res, Err(xmsg::error::AppError::NotRecipient(_))));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_a.inbox_rx.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn test_f2_unknown_harness_refused() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();

    let node_a = create_test_node(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_b.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let msg_id = ulid::Ulid::new().to_string();
    {
        let db = node_a.db.lock().unwrap();
        storage::insert_outbound(&db, &msg_id, "host-b", "sess-b", "accepted", 1000).unwrap();
        storage::insert_message(
            &db,
            &storage::MessageRecord {
                id: msg_id.clone(),
                created_at: 1000,
                session_id: "sess-a".to_string(),
                from_name: "xmsg@host-a · claude:sess-a".to_string(),
                bytes: 10,
                outcome: "accepted".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: Some("matrix_bridge".to_string()),
                return_session_id: Some("sess-a".to_string()),
                push_replies: true,
                thread_id: msg_id.clone(),
                return_host: Some("host-a".to_string()),
            },
        )
        .unwrap();
    }

    let fed_state_b = make_client_fed_state(
        "host-b",
        cert_b,
        key_b,
        "host-a",
        node_a.fed_addr.to_string(),
        node_a.pin.clone(),
        vec!["reply"],
        vec![],
        &node_a,
    );

    let reply = FedReplyEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        in_reply_to: msg_id,
        replier: FedReplier {
            harness: "claude".to_string(),
            session_id: "sess-b".to_string(),
            name: "agent-b".to_string(),
        },
        text: "reply to unknown harness".to_string(),
        created_at: 1000,
    };

    let res = send_federated_reply(&fed_state_b, "host-a", &reply).await;
    assert!(matches!(res, Err(xmsg::error::AppError::NotRecipient(_))));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_a.inbox_rx.lock().unwrap().len(), 0);
}

// =============================================================================
// Finding F3: Anonymous HTTP Cross-Host Send Delivers Valid Badge
// =============================================================================

#[tokio::test]
async fn test_f3_http_origin_federated_send() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let node_a = create_test_node_full(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: node_b.fed_addr.to_string(),
            pin: node_b.pin.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        None,
        Some((cert_a, key_a, pin_a)),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://{}/v1/sessions/sess-b@host-b/messages",
            node_a.http_addr
        ))
        .json(&serde_json::json!({
            "from": "script",
            "text": "anonymous hello"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let inboxes = node_b.inbox_rx.lock().unwrap().clone();
    assert_eq!(inboxes.len(), 1);
    assert!(inboxes[0].contains("xmsg@host-a · script"));
}

// =============================================================================
// Finding F4: allow=[] Pin Refused at Handshake & One-Way Links Supported
// =============================================================================

#[tokio::test]
async fn test_f4_empty_allow_pin_refused_at_handshake() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();
    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a,
            allow: vec![],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let connector = make_tls_connector(&cert_a, &key_a, &node_b.pin).unwrap();
    let tcp = tokio::net::TcpStream::connect(&node_b.fed_addr)
        .await
        .unwrap();
    let handshake_rejected = match connector
        .connect(ServerName::try_from("host-b".to_string()).unwrap(), tcp)
        .await
    {
        Err(_) => true,
        Ok(mut tls) => {
            let mut buf = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(500), tls.read(&mut buf)).await {
                Ok(read_res) => read_res.is_err() || matches!(read_res, Ok(0)),
                Err(_) => false, // Handshake accepted, socket held open: rejected = false
            }
        }
    };

    assert!(
        handshake_rejected,
        "Peer with allow=[] must be rejected at TLS handshake"
    );
}

#[tokio::test]
async fn test_f4_one_way_link() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let node_a = create_test_node_full(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: node_b.fed_addr.to_string(),
            pin: node_b.pin.clone(),
            allow: vec![], // allow = []: A does not allow inbound from B
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        None,
        Some((cert_a, key_a, pin_a)),
    )
    .await;

    let env = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "one-way message".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let res = send_federated_message(&node_a.fed_state, "host-b", &env).await;
    assert!(
        res.is_ok(),
        "A must be able to send to B on a one-way link: {res:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_b.inbox_rx.lock().unwrap().len(), 1);
}

// =============================================================================
// Finding F5: Fed Listener Handshake Timeout Closes Unauthenticated Sockets
// =============================================================================

#[tokio::test]
async fn test_f5_listener_handshake_timeout() {
    let node_b = create_test_node("host-b", "sess-b", Vec::new()).await;
    let mut idle_stream = tokio::net::TcpStream::connect(&node_b.fed_addr)
        .await
        .unwrap();

    // Sleep past the 3s handshake timeout
    tokio::time::sleep(Duration::from_millis(3500)).await;

    let mut buf = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_millis(500), idle_stream.read(&mut buf)).await;
    match res {
        Ok(Ok(0)) => {} // EOF: socket closed by server
        Ok(Err(e)) => panic!("Socket error: {e}"),
        Ok(Ok(n)) => panic!("Unexpected data read: {n} bytes"),
        Err(_) => panic!("Socket remained open without timing out"),
    }
}

// =============================================================================
// Finding F7: Outbound Timeouts on Silent Peer
// =============================================================================

#[tokio::test]
async fn test_f7_outbound_timeout_on_silent_peer() {
    let silent_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = silent_listener.accept().await {
            std::mem::forget(stream);
        }
    });

    let (cert_a, key_a, _) = generate_self_signed_ed25519("host-a").unwrap();
    let node_a = create_test_node("host-a", "sess-a", Vec::new()).await;

    let fed_state = make_client_fed_state(
        "host-a",
        cert_a,
        key_a,
        "host-silent",
        silent_addr.to_string(),
        "00".to_string(),
        vec!["send"],
        vec![],
        &node_a,
    );

    let env = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "test timeout".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let start = std::time::Instant::now();
    let res = send_federated_message(&fed_state, "host-silent", &env).await;
    let elapsed = start.elapsed();

    assert!(matches!(
        res,
        Err(xmsg::error::AppError::PeerUnreachable(_))
    ));
    assert!(
        elapsed < Duration::from_secs(8),
        "Outbound call took {elapsed:?}, expected <= 6s"
    );
}

// =============================================================================
// Finding F8: Verbatim Remote Outcome Relay & Retries Preserve Refusal
// =============================================================================

#[tokio::test]
async fn test_f8_verbatim_remote_outcome_relay_and_dedup() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let fed_state_a = make_client_fed_state(
        "host-a",
        cert_a,
        key_a,
        "host-b",
        node_b.fed_addr.to_string(),
        node_b.pin.clone(),
        vec!["send"],
        vec![],
        &node_b,
    );

    let env = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "alice".to_string(),
        },
        to: FedTarget {
            r#ref: "nobody".to_string(),
        },
        body: "hello nobody".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let r1 = send_federated_message(&fed_state_a, "host-b", &env).await;
    assert!(
        matches!(r1, Err(xmsg::error::AppError::NotFound(_))),
        "Expected NotFound, got: {r1:?}"
    );

    let r2 = send_federated_message(&fed_state_a, "host-b", &env).await;
    assert!(
        matches!(r2, Err(xmsg::error::AppError::NotFound(_))),
        "Retry must still be NotFound, got: {r2:?}"
    );
}

// =============================================================================
// Finding F9: Kind-Qualified Principal Filter
// =============================================================================

#[tokio::test]
async fn test_f9_kind_qualified_principal_filter() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a,
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: vec!["svc:matrix".to_string(), "anon:genie".to_string()],
            targets: None,
        }],
    )
    .await;

    let fed_state_a = make_client_fed_state(
        "host-a",
        cert_a,
        key_a,
        "host-b",
        node_b.fed_addr.to_string(),
        node_b.pin.clone(),
        vec!["send"],
        vec![],
        &node_b,
    );

    // 1. Control anon 'other' -> rejected with OpDenied
    let ctl = send_federated_message(
        &fed_state_a,
        "host-b",
        &FedEnvelope {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            principal: FedPrincipal::Anonymous {
                from: "other".into(),
            },
            to: FedTarget {
                r#ref: "sess-b".into(),
            },
            body: "ctl".into(),
            push_replies: false,
            thread_id: "t1".into(),
            created_at: 1000,
        },
    )
    .await;
    assert!(matches!(ctl, Err(xmsg::error::AppError::OpDenied(_))));

    // 2. Anonymous from="genie" matches filter "anon:genie" -> accepted
    let anon_ok = send_federated_message(
        &fed_state_a,
        "host-b",
        &FedEnvelope {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            principal: FedPrincipal::Anonymous {
                from: "genie".into(),
            },
            to: FedTarget {
                r#ref: "sess-b".into(),
            },
            body: "anon genie".into(),
            push_replies: false,
            thread_id: "t2".into(),
            created_at: 1000,
        },
    )
    .await;
    assert!(
        anon_ok.is_ok(),
        "Expected anon:genie to be admitted: {anon_ok:?}"
    );

    // 3. Claude session named "svc:matrix" -> MUST NOT match filter "svc:matrix"
    let fake_svc = send_federated_message(
        &fed_state_a,
        "host-b",
        &FedEnvelope {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            principal: FedPrincipal::Session {
                harness: "claude".into(),
                session_id: "s1".into(),
                name: "svc:matrix".into(),
            },
            to: FedTarget {
                r#ref: "sess-b".into(),
            },
            body: "spoofing service matrix".into(),
            push_replies: false,
            thread_id: "t3".into(),
            created_at: 1000,
        },
    )
    .await;
    assert!(matches!(fake_svc, Err(xmsg::error::AppError::OpDenied(_))));

    // 4. Genuine service named "matrix" matches "svc:matrix" -> accepted
    let real_svc = send_federated_message(
        &fed_state_a,
        "host-b",
        &FedEnvelope {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            principal: FedPrincipal::Service {
                name: "matrix".into(),
            },
            to: FedTarget {
                r#ref: "sess-b".into(),
            },
            body: "real service matrix".into(),
            push_replies: false,
            thread_id: "t4".into(),
            created_at: 1000,
        },
    )
    .await;
    assert!(
        real_svc.is_ok(),
        "Expected svc:matrix to be admitted: {real_svc:?}"
    );
}

// =============================================================================
// Finding F10: Reply Rate Limiting & Deduplication
// =============================================================================

#[tokio::test]
async fn test_f10_reply_deduplication_and_rate_limit() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();

    let node_a = create_test_node(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_b.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let msg_id = ulid::Ulid::new().to_string();
    {
        let db = node_a.db.lock().unwrap();
        storage::insert_outbound(&db, &msg_id, "host-b", "sess-b", "accepted", 1000).unwrap();
        storage::insert_message(
            &db,
            &storage::MessageRecord {
                id: msg_id.clone(),
                created_at: 1000,
                session_id: "sess-a".to_string(),
                from_name: "xmsg@host-a · claude:sess-a".to_string(),
                bytes: 4,
                outcome: "accepted".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: Some("claude".to_string()),
                return_session_id: Some("sess-a".to_string()),
                push_replies: true,
                thread_id: msg_id.clone(),
                return_host: Some("host-a".to_string()),
            },
        )
        .unwrap();
    }

    let fed_state_b = make_client_fed_state(
        "host-b",
        cert_b,
        key_b,
        "host-a",
        node_a.fed_addr.to_string(),
        node_a.pin.clone(),
        vec!["reply"],
        vec![],
        &node_a,
    );

    let reply_id = ulid::Ulid::new().to_string();
    let reply = FedReplyEnvelope {
        v: 1,
        id: reply_id.clone(),
        in_reply_to: msg_id.clone(),
        replier: FedReplier {
            harness: "claude".to_string(),
            session_id: "sess-b".to_string(),
            name: "agent-b".to_string(),
        },
        text: "reply dedup test".to_string(),
        created_at: 1000,
    };

    // First reply delivery
    let r1 = send_federated_reply(&fed_state_b, "host-a", &reply).await;
    assert!(r1.is_ok(), "First reply should succeed: {r1:?}");

    // Duplicate reply with same reply.id
    let r2 = send_federated_reply(&fed_state_b, "host-a", &reply).await;
    assert!(r2.is_ok(), "Duplicate reply should return 200 OK: {r2:?}");

    tokio::time::sleep(Duration::from_millis(100)).await;
    let inboxes = node_a.inbox_rx.lock().unwrap().clone();
    let delivered_count = inboxes.iter().filter(|l| l.contains(&reply_id)).count();
    assert_eq!(
        delivered_count, 1,
        "Duplicate reply must NOT be delivered twice to session"
    );

    // Flood replies to trigger rate limiter (peer bucket is 60 tokens)
    let mut rate_limited = false;
    for i in 0..70 {
        let flood_reply = FedReplyEnvelope {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            in_reply_to: msg_id.clone(),
            replier: FedReplier {
                harness: "claude".to_string(),
                session_id: "sess-b".to_string(),
                name: "agent-b".to_string(),
            },
            text: format!("flood reply {i}"),
            created_at: 1000,
        };
        if let Err(xmsg::error::AppError::RateLimited(_)) =
            send_federated_reply(&fed_state_b, "host-a", &flood_reply).await
        {
            rate_limited = true;
            break;
        }
    }
    assert!(rate_limited, "Flooding replies must trigger RateLimited");
}

// =============================================================================
// Mutants M3s & Mr: Discriminating Cells
// =============================================================================

#[tokio::test]
async fn test_oracle_server_pin_verified() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();
    let b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9".into(),
            pin: pin_a,
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let (_, _, other_pin) = generate_self_signed_ed25519("impostor").unwrap();
    let good_state = make_client_fed_state(
        "host-a",
        cert_a.clone(),
        key_a.clone(),
        "host-b",
        b.fed_addr.to_string(),
        b.pin.clone(),
        vec!["send"],
        vec![],
        &b,
    );
    let bad_state = make_client_fed_state(
        "host-a",
        cert_a,
        key_a,
        "host-b",
        b.fed_addr.to_string(),
        other_pin,
        vec!["send"],
        vec![],
        &b,
    );

    let e = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "test".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let rg = send_federated_message(&good_state, "host-b", &e).await;
    let rb = send_federated_message(&bad_state, "host-b", &e).await;

    assert!(rg.is_ok(), "Matching server pin must succeed: {rg:?}");
    assert!(
        matches!(rb, Err(xmsg::error::AppError::PeerRejected(_))),
        "Mismatched server pin must fail with PeerRejected, got: {rb:?}"
    );
}

#[tokio::test]
async fn test_oracle_reply_allow_check() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();

    let node_a = create_test_node_full(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: "127.0.0.1:9".into(),
            pin: pin_b.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        None,
        Some((cert_a.clone(), key_a.clone(), pin_a.clone())),
    )
    .await;

    let msg_id = ulid::Ulid::new().to_string();
    {
        let db = node_a.db.lock().unwrap();
        storage::insert_outbound(&db, &msg_id, "host-b", "sess-b", "accepted", 1000).unwrap();
        storage::insert_message(
            &db,
            &storage::MessageRecord {
                id: msg_id.clone(),
                created_at: 1000,
                session_id: "sess-a".to_string(),
                from_name: "xmsg@host-a · claude:sess-a".to_string(),
                bytes: 4,
                outcome: "accepted".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: Some("claude".to_string()),
                return_session_id: Some("sess-a".to_string()),
                push_replies: true,
                thread_id: msg_id.clone(),
                return_host: Some("host-a".to_string()),
            },
        )
        .unwrap();
    }

    let fed_state_b = make_client_fed_state(
        "host-b",
        cert_b,
        key_b,
        "host-a",
        node_a.fed_addr.to_string(),
        pin_a,
        vec!["reply"],
        vec![],
        &node_a,
    );

    let reply = FedReplyEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        in_reply_to: msg_id,
        replier: FedReplier {
            harness: "claude".to_string(),
            session_id: "sess-b".to_string(),
            name: "agent-b".to_string(),
        },
        text: "reply attempt without right".to_string(),
        created_at: 1000,
    };

    let r = send_federated_reply(&fed_state_b, "host-a", &reply).await;
    assert!(
        matches!(r, Err(xmsg::error::AppError::OpDenied(_))),
        "Peer without reply in allow must get OpDenied, got: {r:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_a.inbox_rx.lock().unwrap().len(), 0);
}

fn seed_origin(node: &TestNode, peer_name: &str) -> String {
    let id = ulid::Ulid::new().to_string();
    let db = node.db.lock().unwrap();
    storage::insert_outbound(&db, &id, peer_name, "sess-b", "accepted", 1000).unwrap();
    storage::insert_message(
        &db,
        &storage::MessageRecord {
            id: id.clone(),
            created_at: 1000,
            session_id: "sess-a".to_string(),
            from_name: "xmsg@host-a · claude:sess-a".to_string(),
            bytes: 4,
            outcome: "accepted".to_string(),
            recipient_harness: "claude".to_string(),
            return_harness: Some("claude".to_string()),
            return_session_id: Some("sess-a".to_string()),
            push_replies: true,
            thread_id: "th".to_string(),
            return_host: None,
        },
    )
    .unwrap();
    id
}

// =============================================================================
// Unit X1.3: Conditions N1, N2, N3, N5, N7 Tests
// =============================================================================

#[tokio::test]
async fn test_n1_offsource_replay_known_reply_id_rejected() {
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("host-b").unwrap();
    let node_a = create_test_node(
        "host-a",
        "sess-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: "127.0.0.1:9".to_string(),
            pin: pin_b.clone(),
            allow: vec!["reply".to_string()],
            from: Some(vec!["10.0.0.0/8".to_string()]),
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;
    let orig = seed_origin(&node_a, "host-b");
    let known = ulid::Ulid::new().to_string();
    {
        let db = node_a.db.lock().unwrap();
        storage::insert_reply(
            &db,
            &orig,
            "sess-a",
            "earlier",
            Some("pushed"),
            Some(&known),
        )
        .unwrap();
    }
    let b = make_client_fed_state(
        "host-b",
        cert_b,
        key_b,
        "host-a",
        node_a.fed_addr.to_string(),
        node_a.pin.clone(),
        vec!["reply"],
        vec![],
        &node_a,
    );
    let replay = send_federated_reply(
        &b,
        "host-a",
        &FedReplyEnvelope {
            v: 1,
            id: known,
            in_reply_to: orig,
            replier: FedReplier {
                harness: "claude".to_string(),
                session_id: "s2".to_string(),
                name: "agent-b".to_string(),
            },
            text: "r".to_string(),
            created_at: 1,
        },
    )
    .await;
    assert!(
        matches!(replay, Err(xmsg::error::AppError::PeerRejected(_))),
        "Off-source replay of known reply ID must return 403 PeerRejected, got: {replay:?}"
    );
}

#[tokio::test]
async fn test_n1_offsource_flood_leaves_legit_bucket_intact() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();
    let off = create_test_node(
        "host-r",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: Some(vec!["10.0.0.0/8".to_string()]),
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;
    let legit_state = Arc::new(FedState {
        host_label: "host-r".to_string(),
        peers: Arc::new(PeersMap::new(
            [(
                "host-a".to_string(),
                PeerConfig {
                    name: "host-a".to_string(),
                    address: "127.0.0.1:9".to_string(),
                    pin: pin_a.clone(),
                    allow: vec!["send".to_string(), "reply".to_string()],
                    from: Some(vec!["127.0.0.1/32".to_string()]),
                    leaf: false,
                    principals: Vec::new(),
                    targets: None,
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: off.cert_der.clone(),
        key_der: off.key_der.clone(),
        rate_limiter: off.fed_state.rate_limiter.clone(),
        db: off.db.clone(),
        sessions_dir: off.sessions_dir.clone(),
        agy_config: off.fed_state.agy_config.clone(),
        agy_store: off.fed_state.agy_store.clone(),
        pi_store: off.fed_state.pi_store.clone(),
        pi_notify_tx: off.fed_state.pi_notify_tx.clone(),
        svc_store: off.fed_state.svc_store.clone(),
        svc_notify_tx: off.fed_state.svc_notify_tx.clone(),
        notify_tx: off.fed_state.notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let legit_addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = run_fed_listener(l, legit_state).await;
    });

    let atk = make_client_fed_state(
        "host-a",
        cert_a.clone(),
        key_a.clone(),
        "host-r",
        off.fed_addr.to_string(),
        off.pin.clone(),
        vec!["reply"],
        vec![],
        &off,
    );
    let good = make_client_fed_state(
        "host-a",
        cert_a,
        key_a,
        "host-r",
        legit_addr.to_string(),
        off.pin.clone(),
        vec!["reply"],
        vec![],
        &off,
    );
    let orig = seed_origin(&off, "host-a");

    for i in 0..62 {
        let r = send_federated_reply(
            &atk,
            "host-r",
            &FedReplyEnvelope {
                v: 1,
                id: ulid::Ulid::new().to_string(),
                in_reply_to: orig.clone(),
                replier: FedReplier {
                    harness: "claude".to_string(),
                    session_id: format!("s{i}"),
                    name: "agent-a".to_string(),
                },
                text: "r".to_string(),
                created_at: 1,
            },
        )
        .await;
        assert!(
            matches!(r, Err(xmsg::error::AppError::PeerRejected(_))),
            "Off-source request {i} must be PeerRejected, got: {r:?}"
        );
    }

    let legit = send_federated_reply(
        &good,
        "host-r",
        &FedReplyEnvelope {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            in_reply_to: orig,
            replier: FedReplier {
                harness: "claude".to_string(),
                session_id: "legit".to_string(),
                name: "agent-a".to_string(),
            },
            text: "legit".to_string(),
            created_at: 1,
        },
    )
    .await;
    assert!(
        legit.is_ok(),
        "In-source legitimate reply must succeed, but got: {legit:?}"
    );
}

#[tokio::test]
async fn test_n2_idle_authenticated_connection_closed_within_timeout() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();
    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9".to_string(),
            pin: pin_a,
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let connector = make_tls_connector(&cert_a, &key_a, &node_b.pin).unwrap();
    let tcp = tokio::net::TcpStream::connect(&node_b.fed_addr)
        .await
        .unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("host-b").unwrap(), tcp)
        .await
        .unwrap();

    let mut buf = [0u8; 1];
    let read_res = tokio::time::timeout(Duration::from_secs(7), tls.read(&mut buf)).await;
    match read_res {
        Ok(Ok(0)) | Ok(Err(_)) => {} // Connection closed by server
        Ok(Ok(n)) => panic!("Unexpected data read from server: {n} bytes"),
        Err(_) => panic!("Idle authenticated connection was NOT closed within timeout"),
    }
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "needs 127.0.0.2-17 on lo0 (macOS lo0 only has 127.0.0.1); add with `sudo ifconfig lo0 alias 127.0.0.N up`"
)]
async fn test_n3_unauthenticated_socket_bound_leaves_slot_for_peer() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();
    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9".to_string(),
            pin: pin_a,
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let a = make_client_fed_state(
        "host-a",
        cert_a,
        key_a,
        "host-b",
        node_b.fed_addr.to_string(),
        node_b.pin.clone(),
        vec!["send"],
        vec![],
        &node_b,
    );

    let mut idle_sockets = Vec::new();
    for _ in 0..128 {
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        if let Ok(stream) = sock.connect(node_b.fed_addr).await {
            idle_sockets.push(stream);
        }
    }

    let env = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "agent-a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "hello".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };

    let send_res = send_federated_message(&a, "host-b", &env).await;
    assert!(
        send_res.is_ok(),
        "Legitimate send must succeed even when 128 idle sockets exist from one source, got: {send_res:?}"
    );
}

#[tokio::test]
async fn test_n5_tls_key_load_failure_fatal_at_startup() {
    let tmp = TempDir::new().unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    let (cert_pem, _, _) = generate_self_signed_ed25519_pem("host-test").unwrap();
    std::fs::write(&cert_file, cert_pem).unwrap();

    std::fs::write(
        &key_file,
        "-----BEGIN PRIVATE KEY-----\naW52YWxpZA==\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(&peers_file, "{}").unwrap();

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let mut child = tokio::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", tmp.path())
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--fed-listen",
            "127.0.0.1:0",
            "--peers-file",
            peers_file.to_str().unwrap(),
            "--fed-cert",
            cert_file.to_str().unwrap(),
            "--fed-key",
            key_file.to_str().unwrap(),
            "--db-path",
            tmp.path().join("test.db").to_str().unwrap(),
            "--sessions-dir",
            tmp.path().join("sessions").to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let res = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
    match res {
        Ok(Ok(status)) => {
            assert!(
                !status.success(),
                "Startup with invalid key must fail fatally, but succeeded!"
            );
        }
        Ok(Err(e)) => panic!("Child wait failed: {e}"),
        Err(_) => {
            let _ = child.kill().await;
            panic!(
                "Startup with invalid key did not exit fatally within 3s: server remained alive"
            );
        }
    }
}

#[tokio::test]
async fn test_n7_mf5_ipv4_mapped_canonicalisation() {
    use std::net::IpAddr;
    use xmsg::fed::IpCidr;
    let cidr = IpCidr::parse("127.0.0.1/32").unwrap();
    let mapped_ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert!(
        cidr.contains(&mapped_ip),
        "127.0.0.1/32 CIDR must contain ::ffff:127.0.0.1"
    );
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "needs 127.0.0.2-17 on lo0 (macOS lo0 only has 127.0.0.1); add with `sudo ifconfig lo0 alias 127.0.0.N up`"
)]
async fn test_n7_mf6_tcp_peer_address_source() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();
    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9".to_string(),
            pin: pin_a,
            allow: vec!["send".to_string()],
            from: Some(vec!["127.0.0.2/32".to_string()]),
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
    )
    .await;

    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let tcp_stream = socket.connect(node_b.fed_addr).await.unwrap();

    let connector = make_tls_connector(&cert_a, &key_a, &node_b.pin).unwrap();
    let tls_stream = connector
        .connect(ServerName::try_from("host-b").unwrap(), tcp_stream)
        .await
        .unwrap();

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let env = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "s1".to_string(),
            name: "a".to_string(),
        },
        to: FedTarget {
            r#ref: "sess-b".to_string(),
        },
        body: "from-127-0-0-2".to_string(),
        push_replies: false,
        thread_id: "t1".to_string(),
        created_at: 1000,
    };
    let body_bytes = serde_json::to_vec(&env).unwrap();
    let req = hyper::Request::builder()
        .method("POST")
        .uri("/fed/v1/messages")
        .header("content-type", "application/json")
        .header("host", "host-b")
        .body(http_body_util::Full::new(bytes::Bytes::from(body_bytes)))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "TCP peer address 127.0.0.2 must match from=['127.0.0.2/32']"
    );
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "needs 127.0.0.2-17 on lo0 (macOS lo0 only has 127.0.0.1); add with `sudo ifconfig lo0 alias 127.0.0.N up`"
)]
async fn test_n7_f5b_semaphore_bound() {
    let node_b = create_test_node("host-b", "sess-b", Vec::new()).await;

    let mut held_sockets = Vec::new();
    for i in 1..=16 {
        for _ in 0..8 {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            let bind_addr: SocketAddr = format!("127.0.0.{i}:0").parse().unwrap();
            socket.bind(bind_addr).unwrap();
            if let Ok(stream) = socket.connect(node_b.fed_addr).await {
                held_sockets.push(stream);
            }
        }
    }
    assert_eq!(held_sockets.len(), 128, "Must hold exactly 128 sockets");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let probe_socket = tokio::net::TcpSocket::new_v4().unwrap();
    probe_socket.bind("127.0.0.17:0".parse().unwrap()).unwrap();
    let mut stream129 = probe_socket.connect(node_b.fed_addr).await.unwrap();
    let mut buf = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_millis(500), stream129.read(&mut buf)).await;
    match res {
        Ok(Ok(0)) | Ok(Err(_)) => {} // Dropped by server because semaphore is full
        other => panic!("129th socket should be dropped at semaphore boundary, got: {other:?}"),
    }
}

#[test]
fn test_n7_f9_bare_principal_refused_at_load() {
    let json = r#"{
        "peer-a": {
            "address": "127.0.0.1:9",
            "pin": "sha256:1234",
            "allow": ["send"],
            "principals": ["alice"]
        }
    }"#;
    let res = PeersMap::load_from_json(json);
    assert!(
        res.is_err(),
        "Bare principal 'alice' must be refused at load time"
    );
    let err = res.unwrap_err();
    assert!(
        err.contains("principal filter entry 'alice'") && err.contains("kind-qualified"),
        "Error message must name the invalid principal, got: {err}"
    );
}

#[tokio::test]
async fn test_n7_f6_bind_fatal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound_addr = listener.local_addr().unwrap();

    let tmp = TempDir::new().unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    let (cert_pem, key_pem, _) = generate_self_signed_ed25519_pem("host-test").unwrap();
    std::fs::write(&cert_file, cert_pem).unwrap();
    std::fs::write(&key_file, key_pem).unwrap();
    std::fs::write(&peers_file, "{}").unwrap();

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let output = std::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", tmp.path())
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--fed-listen",
            &bound_addr.to_string(),
            "--peers-file",
            peers_file.to_str().unwrap(),
            "--fed-cert",
            cert_file.to_str().unwrap(),
            "--fed-key",
            key_file.to_str().unwrap(),
            "--db-path",
            tmp.path().join("test.db").to_str().unwrap(),
            "--sessions-dir",
            tmp.path().join("sessions").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "Binding to already-bound port must fail fatally"
    );
}

#[tokio::test]
async fn test_n7_f6_unspecified_address_refused() {
    let tmp = TempDir::new().unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    let (cert_pem, key_pem, _) = generate_self_signed_ed25519_pem("host-test").unwrap();
    std::fs::write(&cert_file, cert_pem).unwrap();
    std::fs::write(&key_file, key_pem).unwrap();
    std::fs::write(&peers_file, "{}").unwrap();

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let output = std::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", tmp.path())
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--fed-listen",
            "0.0.0.0:9999",
            "--peers-file",
            peers_file.to_str().unwrap(),
            "--fed-cert",
            cert_file.to_str().unwrap(),
            "--fed-key",
            key_file.to_str().unwrap(),
            "--db-path",
            tmp.path().join("test.db").to_str().unwrap(),
            "--sessions-dir",
            tmp.path().join("sessions").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "0.0.0.0 address must be refused for --fed-listen"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unspecified address") && stderr.contains("forbidden"),
        "Stderr must name unspecified address forbidden, got: {stderr}"
    );
}

#[tokio::test]
async fn test_n7_f6_cert_key_required() {
    let tmp = TempDir::new().unwrap();
    let peers_file = tmp.path().join("peers.json");
    std::fs::write(&peers_file, "{}").unwrap();

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let output = std::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", tmp.path())
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--fed-listen",
            "127.0.0.1:9999",
            "--peers-file",
            peers_file.to_str().unwrap(),
            "--db-path",
            tmp.path().join("test.db").to_str().unwrap(),
            "--sessions-dir",
            tmp.path().join("sessions").to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "--fed-listen without cert/key must fail fatally"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires both --fed-cert and --fed-key"),
        "Stderr must state cert/key requirement, got: {stderr}"
    );
}
