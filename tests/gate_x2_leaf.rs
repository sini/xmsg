use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::broadcast;

use xmsg::agent::run_agent_server;
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::fed::{
    generate_self_signed_ed25519, generate_self_signed_ed25519_pem, run_fed_listener, FedState,
    PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::{build_router, AppState};
use xmsg::inbox::DeliveryResponse;
use xmsg::pi::new_pi_store;
use xmsg::storage::{self, MessageRecord, ReplyRecord};

fn get_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().expect("local addr").port()
}

// -----------------------------------------------------------------------------
// Oracle 1: --leaf binds no agent.sock/register.sock and no fed listener
// Mutant: bind register.sock => RED
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_1_leaf_binds_no_harness_sockets_or_fed_listener() {
    let tmp = TempDir::new().unwrap();
    let runtime_dir = tmp.path().join("run");
    fs::create_dir_all(&runtime_dir).unwrap();
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    let (cert_pem, key_pem, _) = generate_self_signed_ed25519_pem("leaf-node").unwrap();
    fs::write(&cert_file, cert_pem).unwrap();
    fs::write(&key_file, key_pem).unwrap();
    fs::write(&peers_file, "{}").unwrap();

    let port = get_free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let bin = env!("CARGO_BIN_EXE_xmsg");

    let register_sock = runtime_dir.join("xmsg/register.sock");
    let agent_sock = runtime_dir.join("xmsg/agent.sock");
    let http_sock = runtime_dir.join("xmsg/http.sock");

    let mut child = std::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .args([
            "serve",
            "--leaf",
            "--leaf-principal",
            "svc:matrix",
            "--listen",
            &listen_addr,
            "--peers-file",
            peers_file.to_str().unwrap(),
            "--fed-cert",
            cert_file.to_str().unwrap(),
            "--fed-key",
            key_file.to_str().unwrap(),
            "--db-path",
            tmp.path().join("leaf.db").to_str().unwrap(),
            "--sessions-dir",
            tmp.path().join("sessions").to_str().unwrap(),
        ])
        .spawn()
        .expect("spawn leaf serve");

    // Wait for HTTP server to become responsive
    let client = reqwest::Client::new();
    let healthz_url = format!("http://{listen_addr}/healthz");
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(&healthz_url).send().await {
            if resp.status().is_success() {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Leaf HTTP server should respond on --listen");

    // Oracle 1 assertions: no register.sock, no agent.sock, no http.sock
    assert!(
        !register_sock.exists(),
        "Oracle 1 violation: leaf mode must NOT bind register.sock (found: {})",
        register_sock.display()
    );
    assert!(
        !agent_sock.exists(),
        "Oracle 1 violation: leaf mode must NOT bind agent.sock (found: {})",
        agent_sock.display()
    );
    assert!(
        !http_sock.exists(),
        "Oracle 1 violation: leaf mode must NOT bind http.sock (found: {})",
        http_sock.display()
    );

    let _ = child.kill();
    let _ = child.wait();
}

// -----------------------------------------------------------------------------
// Oracle 2: Request with body `from` claiming another principal is attributed
// to configured --leaf-principal. Mutant: use body field => RED
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_2_body_from_ignored_and_attributed_to_leaf_principal() {
    let tmp = TempDir::new().unwrap();
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sess_dir).unwrap();

    let (node_b_cert, node_b_key, node_b_pin) =
        generate_self_signed_ed25519("target-node").unwrap();
    let (leaf_cert, leaf_key, leaf_pin) = generate_self_signed_ed25519("leaf-node").unwrap();

    // Setup target node (node-b)
    let node_b_fed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_b_fed_addr = node_b_fed_listener.local_addr().unwrap();

    let mut node_b_peers = HashMap::new();
    node_b_peers.insert(
        "leaf-node".to_string(),
        PeerConfig {
            name: "leaf-node".to_string(),
            address: "127.0.0.1:1".to_string(),
            pin: leaf_pin.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: true,
            principals: vec!["svc:matrix".to_string()],
        },
    );

    let node_b_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&node_b_conn).unwrap();
    let node_b_db = Arc::new(Mutex::new(node_b_conn));

    let (node_b_notify_tx, _) = broadcast::channel(16);
    let (node_b_pi_notify_tx, _) = broadcast::channel(16);

    let node_b_fed_state = Arc::new(FedState {
        host_label: "target-node".to_string(),
        peers: Arc::new(PeersMap::new(node_b_peers)),
        cert_der: node_b_cert.clone(),
        key_der: node_b_key.clone(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b_db.clone(),
        sessions_dir: sess_dir.clone(),
        agy_config: AgyConfig {
            presence_dir: tmp.path().join("presence"),
            proc_locks_path: tmp.path().join("proc_locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: node_b_pi_notify_tx,
        notify_tx: node_b_notify_tx,
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let fs_clone = node_b_fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(node_b_fed_listener, fs_clone).await;
    });

    // Mock target session on node-b
    let my_pid = std::process::id();
    let proc_root = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&proc_root, my_pid).unwrap_or_else(|_| "0".to_string());
    let target_inbox_sock = tmp.path().join("target_inbox.sock");
    let target_listener = UnixListener::bind(&target_inbox_sock).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(b"{\"status\":\"ok\"}\n").await;
        }
    });

    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": "agent-alice",
        "name": "agent-alice",
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": target_inbox_sock.display().to_string()
    });
    fs::write(
        sess_dir.join(format!("{my_pid}.json")),
        session_json.to_string(),
    )
    .unwrap();

    // Setup Leaf Node
    let mut leaf_peers = HashMap::new();
    leaf_peers.insert(
        "target-node".to_string(),
        PeerConfig {
            name: "target-node".to_string(),
            address: node_b_fed_addr.to_string(),
            pin: node_b_pin.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
        },
    );

    let leaf_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&leaf_conn).unwrap();
    let leaf_db = Arc::new(Mutex::new(leaf_conn));

    let (leaf_notify_tx, _) = broadcast::channel(16);
    let (leaf_pi_notify_tx, _) = broadcast::channel(16);
    let (leaf_svc_notify_tx, _) = broadcast::channel(16);

    let leaf_fed_state = Arc::new(FedState {
        host_label: "leaf-node".to_string(),
        peers: Arc::new(PeersMap::new(leaf_peers)),
        cert_der: leaf_cert,
        key_der: leaf_key,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: leaf_db.clone(),
        sessions_dir: sess_dir.clone(),
        agy_config: AgyConfig {
            presence_dir: tmp.path().join("leaf_presence"),
            proc_locks_path: tmp.path().join("leaf_proc_locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: leaf_pi_notify_tx.clone(),
        notify_tx: leaf_notify_tx.clone(),
        max_body: 65536,
        is_leaf: true,
        leaf_principal: Some("svc:matrix".to_string()),
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let leaf_app_state = Arc::new(AppState {
        sessions_dirs: vec![sess_dir.clone()],
        agy_config: leaf_fed_state.agy_config.clone(),
        agy_store: leaf_fed_state.agy_store.clone(),
        pi_store: leaf_fed_state.pi_store.clone(),
        pi_notify_tx: leaf_pi_notify_tx.clone(),
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: leaf_svc_notify_tx,
        host_label: "leaf-node".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: leaf_db.clone(),
        notify_tx: leaf_notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(leaf_fed_state),
    });

    let leaf_http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let leaf_http_addr = leaf_http_listener.local_addr().unwrap();
    let leaf_app = build_router(leaf_app_state);
    tokio::spawn(async move {
        axum::serve(leaf_http_listener, leaf_app).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send request with body claiming an impostor principal
    let client = reqwest::Client::new();
    let send_url = format!("http://{leaf_http_addr}/v1/sessions/agent-alice@target-node/messages");
    let resp = client
        .post(&send_url)
        .json(&serde_json::json!({
            "from": "claude:impostor",
            "text": "matrix alert",
            "idempotency_key": "idemp-leaf-1"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let delivery: DeliveryResponse = resp.json().await.unwrap();

    // Oracle 2 assertion: delivery from_name must be attributed to svc:matrix, NOT claude:impostor
    assert!(
        delivery.from_name.contains("svc:matrix"),
        "Oracle 2 violation: from_name must be attributed to svc:matrix, got: {}",
        delivery.from_name
    );
    assert!(
        !delivery.from_name.contains("impostor"),
        "Oracle 2 violation: from_name must NOT contain body from field 'impostor', got: {}",
        delivery.from_name
    );

    // Oracle 2 assertion: idempotency record must be scoped to svc:matrix in SQLite
    {
        let db = leaf_db.lock().unwrap();
        let record = storage::get_idempotency_record(&db, "svc:matrix", "idemp-leaf-1", 86400)
            .unwrap()
            .expect("Oracle 2 violation: idempotency record must be stored under principal 'svc:matrix'");
        assert_eq!(record.body, "matrix alert");

        let bad_record =
            storage::get_idempotency_record(&db, "http:claude:impostor", "idemp-leaf-1", 86400)
                .unwrap();
        assert!(
            bad_record.is_none(),
            "Oracle 2 violation: no record under http:claude:impostor"
        );
    }
}

// -----------------------------------------------------------------------------
// Oracle 3: End to end two nodes: leaf -> node send; node-side reply; leaf
// receives via long-poll; node made 0 outbound connections to leaf.
// Mutant: node pushes to origin => RED (0-connection assertion)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_3_leaf_pull_replies_node_zero_outbound_connections() {
    let tmp = TempDir::new().unwrap();
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sess_dir).unwrap();

    let (node_b_cert, node_b_key, node_b_pin) =
        generate_self_signed_ed25519("target-node").unwrap();
    let (leaf_cert, leaf_key, leaf_pin) = generate_self_signed_ed25519("leaf-node").unwrap();

    // Target node (node-b)
    let node_b_fed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_b_fed_addr = node_b_fed_listener.local_addr().unwrap();

    // Node B peer config marks leaf as leaf: true, pointing to non-listening port
    let mut node_b_peers = HashMap::new();
    node_b_peers.insert(
        "leaf-node".to_string(),
        PeerConfig {
            name: "leaf-node".to_string(),
            address: "127.0.0.1:54321".to_string(), // Unreachable / non-listening
            pin: leaf_pin.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: true,
            principals: vec!["svc:matrix".to_string()],
        },
    );

    let node_b_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&node_b_conn).unwrap();
    let node_b_db = Arc::new(Mutex::new(node_b_conn));

    let (node_b_notify_tx, _) = broadcast::channel(16);
    let (node_b_pi_notify_tx, _) = broadcast::channel(16);
    let (node_b_svc_notify_tx, _) = broadcast::channel(16);

    let node_b_fed_state = Arc::new(FedState {
        host_label: "target-node".to_string(),
        peers: Arc::new(PeersMap::new(node_b_peers)),
        cert_der: node_b_cert,
        key_der: node_b_key,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: node_b_db.clone(),
        sessions_dir: sess_dir.clone(),
        agy_config: AgyConfig {
            presence_dir: tmp.path().join("presence"),
            proc_locks_path: tmp.path().join("proc_locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: node_b_pi_notify_tx.clone(),
        notify_tx: node_b_notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let fs_clone = node_b_fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(node_b_fed_listener, fs_clone).await;
    });

    let node_b_app_state = Arc::new(AppState {
        sessions_dirs: vec![sess_dir.clone()],
        agy_config: node_b_fed_state.agy_config.clone(),
        agy_store: node_b_fed_state.agy_store.clone(),
        pi_store: node_b_fed_state.pi_store.clone(),
        pi_notify_tx: node_b_pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: node_b_svc_notify_tx,
        host_label: "target-node".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: node_b_db.clone(),
        notify_tx: node_b_notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(node_b_fed_state.clone()),
    });

    let sock_dir = tmp.path().join("run");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let node_b_agent_sock = sock_dir.join("node_b_agent.sock");
    let my_uid = xmsg::agent::current_uid();
    let s_path = node_b_agent_sock.clone();
    let s_state = node_b_app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Mock target session on node-b
    let my_pid = std::process::id();
    let proc_root = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&proc_root, my_pid).unwrap_or_else(|_| "0".to_string());
    let target_inbox_sock = tmp.path().join("target_inbox.sock");
    let target_listener = UnixListener::bind(&target_inbox_sock).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(b"{\"status\":\"ok\"}\n").await;
        }
    });

    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": "agent-bob",
        "name": "agent-bob",
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": target_inbox_sock.display().to_string()
    });
    fs::write(
        sess_dir.join(format!("{my_pid}.json")),
        session_json.to_string(),
    )
    .unwrap();

    // Setup Leaf Node
    let mut leaf_peers = HashMap::new();
    leaf_peers.insert(
        "target-node".to_string(),
        PeerConfig {
            name: "target-node".to_string(),
            address: node_b_fed_addr.to_string(),
            pin: node_b_pin.clone(),
            allow: vec!["send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
        },
    );

    let leaf_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&leaf_conn).unwrap();
    let leaf_db = Arc::new(Mutex::new(leaf_conn));

    let (leaf_notify_tx, _) = broadcast::channel(16);
    let (leaf_pi_notify_tx, _) = broadcast::channel(16);
    let (leaf_svc_notify_tx, _) = broadcast::channel(16);

    let leaf_fed_state = Arc::new(FedState {
        host_label: "leaf-node".to_string(),
        peers: Arc::new(PeersMap::new(leaf_peers)),
        cert_der: leaf_cert,
        key_der: leaf_key,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: leaf_db.clone(),
        sessions_dir: sess_dir.clone(),
        agy_config: AgyConfig {
            presence_dir: tmp.path().join("leaf_presence"),
            proc_locks_path: tmp.path().join("leaf_proc_locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: leaf_pi_notify_tx.clone(),
        notify_tx: leaf_notify_tx.clone(),
        max_body: 65536,
        is_leaf: true,
        leaf_principal: Some("svc:matrix".to_string()),
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
    });

    let leaf_app_state = Arc::new(AppState {
        sessions_dirs: vec![sess_dir.clone()],
        agy_config: leaf_fed_state.agy_config.clone(),
        agy_store: leaf_fed_state.agy_store.clone(),
        pi_store: leaf_fed_state.pi_store.clone(),
        pi_notify_tx: leaf_pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: leaf_svc_notify_tx,
        host_label: "leaf-node".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: leaf_db.clone(),
        notify_tx: leaf_notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(leaf_fed_state),
    });

    let leaf_http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let leaf_http_addr = leaf_http_listener.local_addr().unwrap();
    let leaf_app = build_router(leaf_app_state);
    tokio::spawn(async move {
        axum::serve(leaf_http_listener, leaf_app).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Leaf sends message to agent-bob@target-node (asks for push: envelope.push_replies=true)
    let client = reqwest::Client::new();
    let send_url = format!("http://{leaf_http_addr}/v1/sessions/agent-bob@target-node/messages");
    let resp = client
        .post(&send_url)
        .json(&serde_json::json!({
            "text": "ping from matrix leaf"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let delivery: DeliveryResponse = resp.json().await.unwrap();
    let msg_id = delivery.message_id;

    // Cell 3a: Verify target node's fed.rs:892 normalized push_replies to false for leaf peer
    let stored_msg = {
        let db = node_b_db.lock().unwrap();
        storage::get_message(&db, &msg_id).unwrap().unwrap()
    };
    assert!(
        !stored_msg.push_replies,
        "Oracle 3 cell 3a violation: target node fed.rs:892 must normalize push_replies to false for leaf peer"
    );

    // Cell 3b: Verify reply-side guard in agent.rs:540
    // Even if a message in target node's DB has push_replies=true and return_host is a leaf peer,
    // agent.rs:540 must refuse to push to origin.
    let push_msg_id = ulid::Ulid::new().to_string();
    {
        let db = node_b_db.lock().unwrap();
        let pre_record = MessageRecord {
            id: push_msg_id.clone(),
            created_at: storage::now_epoch_secs(),
            session_id: "agent-bob".to_string(),
            from_name: "xmsg@leaf-node · svc:matrix".to_string(),
            bytes: 10,
            outcome: "delivered".to_string(),
            recipient_harness: "claude".to_string(),
            return_harness: Some("svc".to_string()),
            return_session_id: Some("matrix".to_string()),
            return_host: Some("leaf-node".to_string()),
            push_replies: true,
            thread_id: push_msg_id.clone(),
        };
        storage::insert_message(&db, &pre_record).unwrap();
    }

    let mut stream2 = UnixStream::connect(&node_b_agent_sock).await.unwrap();
    let reply_req2 = serde_json::json!({
        "action": "reply",
        "message_id": push_msg_id,
        "text": "pong to push msg"
    });
    stream2
        .write_all(format!("{reply_req2}\n").as_bytes())
        .await
        .unwrap();
    stream2.flush().await.unwrap();

    let mut reader2 = BufReader::new(stream2);
    let mut line2 = String::new();
    reader2.read_line(&mut line2).await.unwrap();
    let reply_resp2: Value = serde_json::from_str(&line2).unwrap();
    assert_eq!(
        reply_resp2
            .get("reply")
            .and_then(|r| r.get("pushOutcome"))
            .and_then(|s| s.as_str()),
        Some("disabled"),
        "Oracle 3 cell 3b violation: agent.rs:540 must set pushOutcome=disabled for leaf peer"
    );
    assert_eq!(
        node_b_fed_state.outbound_replies_pushed.load(Ordering::SeqCst),
        0,
        "Oracle 3 cell 3b violation: agent.rs:540 must skip push to leaf peer even if push_replies=true"
    );

    // 2. Bob replies to msg_id on target-node via agent.sock
    let mut stream = UnixStream::connect(&node_b_agent_sock).await.unwrap();
    let reply_req = serde_json::json!({
        "action": "reply",
        "message_id": msg_id,
        "text": "pong from bob"
    });
    stream
        .write_all(format!("{reply_req}\n").as_bytes())
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let reply_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        reply_resp.get("status").and_then(|s| s.as_str()),
        Some("ok")
    );

    // 3. Oracle 3 core assertion: node-b made 0 outbound connections to leaf!
    assert_eq!(
        node_b_fed_state.outbound_replies_pushed.load(Ordering::SeqCst),
        0,
        "Oracle 3 violation: target node must NOT push replies to leaf (expected 0 outbound connections)"
    );

    // 4. Local client on leaf receives reply via long-poll
    let replies_url =
        format!("http://{leaf_http_addr}/v1/messages/{msg_id}/replies?after=0&wait=5");
    let replies_resp = client.get(&replies_url).send().await.unwrap();
    assert_eq!(replies_resp.status(), StatusCode::OK);

    let replies: Vec<ReplyRecord> = replies_resp.json().await.unwrap();
    assert_eq!(
        replies.len(),
        1,
        "Leaf must receive exactly 1 reply via long-poll"
    );
    assert_eq!(replies[0].text, "pong from bob");
}

// -----------------------------------------------------------------------------
// Oracle 4: --leaf with --fed-listen => refused at start
// Mutant: accept it => RED
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_4_leaf_with_fed_listen_refused_at_start() {
    let tmp = TempDir::new().unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    let (cert_pem, key_pem, _) = generate_self_signed_ed25519_pem("leaf-test").unwrap();
    fs::write(&cert_file, cert_pem).unwrap();
    fs::write(&key_file, key_pem).unwrap();
    fs::write(&peers_file, "{}").unwrap();

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let child = tokio::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", tmp.path())
        .args([
            "serve",
            "--leaf",
            "--leaf-principal",
            "svc:matrix",
            "--listen",
            "127.0.0.1:0",
            "--fed-listen",
            "127.0.0.1:9999",
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

    let output = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .expect("Oracle 4 violation: process should exit immediately with error when --leaf is used with --fed-listen")
        .unwrap();

    // Oracle 4 assertion: startup fails fatally
    assert!(
        !output.status.success(),
        "Oracle 4 violation: --leaf with --fed-listen must be refused at start"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--leaf") && stderr.contains("--fed-listen"),
        "Oracle 4 violation: stderr must mention conflict between --leaf and --fed-listen, got: {stderr}"
    );
}
