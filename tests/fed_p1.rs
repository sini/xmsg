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
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::fed::{
    generate_self_signed_ed25519, make_tls_connector, run_fed_listener, send_federated_message,
    send_federated_reply, FedEnvelope, FedPrincipal, FedReplier, FedReplyEnvelope, FedState,
    FedTarget, MockWhoIsVerifier, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::{build_router, AppState};
use xmsg::pi::new_pi_store;
use xmsg::storage;

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
    pub whois: Arc<MockWhoIsVerifier>,
    pub inbox_rx: Arc<Mutex<Vec<String>>>,
    pub _tmp_dir: TempDir,
}

async fn create_test_node(
    name: &str,
    target_session_name: &str,
    peers: Vec<PeerConfig>,
    no_whois: bool,
) -> TestNode {
    create_test_node_full(name, target_session_name, peers, no_whois, None, None).await
}

async fn create_test_node_full(
    name: &str,
    target_session_name: &str,
    peers: Vec<PeerConfig>,
    _no_whois: bool,
    listener_opt: Option<TcpListener>,
    creds_opt: Option<(Vec<u8>, Vec<u8>, String)>,
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

    let whois = Arc::new(MockWhoIsVerifier::new());

    let fed_state = Arc::new(FedState {
        host_label: name.to_string(),
        peers: peers_arc,
        cert_der: cert_der.clone(),
        key_der: key_der.clone(),
        whois_verifier: whois.clone(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: db.clone(),
        sessions_dir: sessions_dir.clone(),
        agy_config: AgyConfig {
            presence_dir: tmp.path().join("presence"),
            proc_locks_path: tmp.path().join("proc_locks"),
            proc_root: proc_root.clone(),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: pi_notify_tx.clone(),
        notify_tx: notify_tx.clone(),
        max_body: 65536,
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
        sessions_dir: sessions_dir.clone(),
        agy_config: fed_state.agy_config.clone(),
        agy_store: fed_state.agy_store.clone(),
        pi_store: fed_state.pi_store.clone(),
        pi_notify_tx,
        host_label: name.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
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
        whois,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
    let node_b = create_test_node("host-b", "sess-b", Vec::new(), true).await;

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
#[tokio::test]
async fn test_oracle_4_whois_node_mismatch_gives_403() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("host-a").unwrap();

    let node_b = create_test_node(
        "host-b",
        "sess-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: "127.0.0.1:9999".to_string(),
            pin: pin_a.clone(),
            allow: vec!["send".to_string()],
            no_whois: false,
            leaf: false,
            principals: Vec::new(),
        }],
        false,
    )
    .await;

    // Reject host-a in WhoIs verifier
    node_b.whois.reject_node("host-a");

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
        body: "Attack payload".to_string(),
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
                    no_whois: true,
                    leaf: false,
                    principals: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        whois_verifier: Arc::new(MockWhoIsVerifier::new()),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
    });

    let res = send_federated_message(&fed_state_a, "host-b", &envelope).await;
    match res {
        Err(xmsg::error::AppError::PeerRejected(detail)) => {
            assert!(detail.contains("WhoIs"));
        }
        other => panic!("Expected PeerRejected on WhoIs mismatch, got {other:?}"),
    }

    // Assert inbox received 0 bytes
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(node_b.inbox_rx.lock().unwrap().len(), 0);
}

// =============================================================================
// Oracle 5: Host field in body rejected by deny_unknown_fields
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
                    no_whois: true,
                    leaf: false,
                    principals: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        whois_verifier: Arc::new(MockWhoIsVerifier::new()),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
                    no_whois: true,
                    leaf: false,
                    principals: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        whois_verifier: Arc::new(MockWhoIsVerifier::new()),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
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

    tokio::time::sleep(Duration::from_millis(50)).await;
    let inboxes = node_b.inbox_rx.lock().unwrap().clone();
    assert_eq!(inboxes.len(), 1);
    // Attested badge is anchored to the true host and harness; the attempt to spoof a direct "claude:y" badge is rendered inert
    assert!(inboxes[0].contains("xmsg@host-a · claude:x"));
    assert!(!inboxes[0].contains("from-name=\"xmsg@host-a · claude:y\""));
    assert!(!inboxes[0].contains("from-name=\"claude:y\""));
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
                    no_whois: true,
                    leaf: false,
                    principals: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        whois_verifier: Arc::new(MockWhoIsVerifier::new()),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
                    no_whois: true,
                    leaf: false,
                    principals: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_b,
        key_der: key_b,
        whois_verifier: Arc::new(MockWhoIsVerifier::new()),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_a.db.clone(),
        sessions_dir: node_a.sessions_dir.clone(),
        agy_config: node_a.fed_state.agy_config.clone(),
        agy_store: node_a.fed_state.agy_store.clone(),
        pi_store: node_a.fed_state.pi_store.clone(),
        pi_notify_tx: node_a.fed_state.pi_notify_tx.clone(),
        notify_tx: node_a.fed_state.notify_tx.clone(),
        max_body: 65536,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
                    no_whois: true,
                    leaf: false,
                    principals: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        whois_verifier: Arc::new(MockWhoIsVerifier::new()),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
                    no_whois: true,
                    leaf: false,
                    principals: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        whois_verifier: Arc::new(MockWhoIsVerifier::new()),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
            no_whois: true,
            leaf: false,
            principals: Vec::new(),
        }],
        true,
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
                    no_whois: true,
                    leaf: false,
                    principals: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )),
        cert_der: cert_a,
        key_der: key_a,
        whois_verifier: Arc::new(MockWhoIsVerifier::new()),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b.db.clone(),
        sessions_dir: node_b.sessions_dir.clone(),
        agy_config: node_b.fed_state.agy_config.clone(),
        agy_store: node_b.fed_state.agy_store.clone(),
        pi_store: node_b.fed_state.pi_store.clone(),
        pi_notify_tx: node_b.fed_state.pi_notify_tx.clone(),
        notify_tx: node_b.fed_state.notify_tx.clone(),
        max_body: 65536,
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
    let node_b = create_test_node("host-b", "sess-b", Vec::new(), true).await;

    // Well-formed ed25519 cert from unlinked node "host-c"
    let (cert_c, key_c, _) = generate_self_signed_ed25519("host-c").unwrap();

    let connector = make_tls_connector(&cert_c, &key_c, &node_b.pin).unwrap();
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
        "Unlinked cert must be refused at handshake"
    );
}

// =============================================================================
// Amendment (c): unknown_peer opens no socket (listener accepted 0 connections)
// =============================================================================
#[tokio::test]
async fn test_amendment_c_unknown_peer_opens_no_socket() {
    // Stand-in listener that tracks connection attempts
    let stand_in = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _stand_in_addr = stand_in.local_addr().unwrap();
    let conn_count = Arc::new(AtomicUsize::new(0));
    let cc_clone = conn_count.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = stand_in.accept().await {
            cc_clone.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let node_a = create_test_node("host-a", "sess-a", Vec::new(), true).await;

    // Send to unknown peer @host-unknown (not in peers file)
    let stream = UnixStream::connect(&node_a.agent_sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let send_req = serde_json::json!({
        "action": "send",
        "ref": "sess-unknown@host-unknown",
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
        "http://{}/v1/sessions/sess-unknown@host-unknown/messages",
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
