mod short_sock;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, UnixListener, UnixStream};

use axum::http::StatusCode;
use serde_json::Value;

use xmsg::agent::{current_uid, run_agent_server};
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::error::AppError;
use xmsg::fed::{
    generate_self_signed_ed25519, run_fed_listener, FedState, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::{bind_ucred_unix_listener, build_router, http_request_unix_within, AppState};
use xmsg::pi::new_pi_store;
use xmsg::svc::{new_svc_store, run_leaf_inbox_task, run_leaf_register_server};

async fn connect_svc(sock_path: &Path) -> (BufReader<OwnedReadHalf>, OwnedWriteHalf) {
    let stream = UnixStream::connect(sock_path).await.unwrap();
    let (reader, writer) = stream.into_split();
    (BufReader::new(reader), writer)
}

async fn read_json_line(reader: &mut BufReader<OwnedReadHalf>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

fn create_claude_session_fixture(
    proc_root: &Path,
    sessions_dir: &Path,
    session_id: &str,
    name: &str,
) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let sock_path = short_sock::sock_path(sessions_dir, "inbox");
    let listener = UnixListener::bind(&sock_path).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = received.clone();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    let my_pid = std::process::id();
    let live_proc = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&live_proc, my_pid).unwrap_or_else(|_| "1000".to_string());

    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    let stat_content = format!(
        "{my_pid} (agent_test) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {my_proc_start} 0 0\n"
    );
    fs::write(pid_dir.join("stat"), stat_content).unwrap();

    let session_uuid = if xmsg::claim::is_uuid_shaped(session_id) {
        session_id.to_string()
    } else {
        use sha2::{Digest, Sha256};
        let h = hex::encode(Sha256::digest(session_id.as_bytes()));
        format!(
            "{}-{}-4{}-a{}-{}",
            &h[0..8],
            &h[8..12],
            &h[13..16],
            &h[17..20],
            &h[20..32]
        )
    };
    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": session_uuid,
        "name": name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": sock_path.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}-{session_id}.json")),
        session_json.to_string(),
    )
    .unwrap();

    (sock_path, received)
}

async fn send_via_agent_sock(agent_sock: &Path, target_ref: &str, text: &str) -> Value {
    let stream = UnixStream::connect(agent_sock).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let send_req = serde_json::json!({
        "action": "send",
        "to": target_ref,
        "text": text,
    });
    writer
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();

    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(&resp_line).expect("valid json response from agent.sock")
}

#[allow(dead_code)]
struct HubTestNode {
    name: String,
    fed_addr: std::net::SocketAddr,
    agent_sock: PathBuf,
    http_sock: PathBuf,
    proc_root: PathBuf,
    app_state: Arc<AppState>,
    fed_state: Arc<FedState>,
    db: Arc<Mutex<rusqlite::Connection>>,
    sessions_dir: PathBuf,
    _temp: TempDir,
}

async fn create_hub_test_node(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: (Vec<u8>, Vec<u8>, String),
) -> HubTestNode {
    let fed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    create_hub_test_node_with_listener(name, peers, creds, fed_listener).await
}

async fn create_hub_test_node_with_listener(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: (Vec<u8>, Vec<u8>, String),
    fed_listener: TcpListener,
) -> HubTestNode {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_sock = sock_dir.join("agent.sock");
    let http_sock = sock_dir.join("http.sock");

    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = temp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_locks = temp.path().join("proc_locks");
    fs::write(&proc_locks, "").unwrap();

    let my_uid = current_uid();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: std::path::PathBuf::new(),
    };

    let agy_store = new_agy_store();
    let pi_store = new_pi_store();
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);

    let mut peers_map = PeersMap::empty();
    for p in peers {
        peers_map.insert(p).unwrap();
    }
    let peers_arc = Arc::new(peers_map);

    let db_path = temp.path().join("xmsg.db");
    let db = Arc::new(Mutex::new(
        rusqlite::Connection::open(&db_path).expect("open db"),
    ));
    {
        let conn = db.lock().unwrap();
        xmsg::storage::init_db(&conn).expect("init db");
    }

    let svc_store = new_svc_store();
    let (cert_der, key_der, _pin) = creds;
    let rate_limiter = Arc::new(RateLimiter::new(60, 20));

    let fed_state = Arc::new(FedState {
        max_attachment_bytes: xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        node_name: name.to_string(),
        peers: (peers_arc).into(),
        cert_der,
        cert_chain_der: Vec::new(),
        key_der,
        rate_limiter,
        db: db.clone(),
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: svc_store.clone(),
        svc_notify_tx: svc_notify_tx.clone(),
        notify_tx: notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: std::time::Duration::from_secs(7 * 24 * 3600),
        list_queries: Default::default(),
    });

    let fed_addr = fed_listener.local_addr().unwrap();
    let fs_clone = fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(fed_listener, fs_clone).await;
    });

    let app_state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config,
        agy_store,
        pi_store,
        pi_notify_tx,
        svc_store: svc_store.clone(),
        svc_notify_tx,
        node_name: name.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(fed_state.clone()),
    });

    let s_path = agent_sock.clone();
    let s_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    let http_router = build_router(app_state.clone());
    let ucred_listener = bind_ucred_unix_listener(&http_sock, my_uid, None).unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            ucred_listener,
            http_router.into_make_service_with_connect_info::<xmsg::http::HttpPeer>(),
        )
        .await;
    });

    for _ in 0..1500 {
        if std::os::unix::net::UnixStream::connect(&http_sock).is_ok()
            && std::os::unix::net::UnixStream::connect(&agent_sock).is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    HubTestNode {
        name: name.to_string(),
        fed_addr,
        agent_sock,
        http_sock,
        proc_root,
        app_state,
        fed_state,
        db,
        sessions_dir,
        _temp: temp,
    }
}

#[allow(dead_code)]
struct LeafTestNode {
    name: String,
    reg_sock: PathBuf,
    agent_sock: PathBuf,
    leaf_principal: String,
    fed_state: Arc<FedState>,
    db: Arc<Mutex<rusqlite::Connection>>,
    _temp: TempDir,
}

async fn create_leaf_test_node(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: (Vec<u8>, Vec<u8>, String),
    leaf_principal: &str,
) -> LeafTestNode {
    create_leaf_test_node_opts(name, peers, creds, leaf_principal, true).await
}

async fn create_leaf_test_node_opts(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: (Vec<u8>, Vec<u8>, String),
    leaf_principal: &str,
    spawn_inbox_task: bool,
) -> LeafTestNode {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let reg_sock = sock_dir.join("register.sock");
    let agent_sock = sock_dir.join("agent.sock");

    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = temp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_locks = temp.path().join("proc_locks");
    fs::write(&proc_locks, "").unwrap();

    let my_uid = current_uid();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: std::path::PathBuf::new(),
    };

    let agy_store = new_agy_store();
    let pi_store = new_pi_store();
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);

    let mut peers_map = PeersMap::empty();
    for p in peers {
        peers_map.insert(p).unwrap();
    }
    let peers_arc = Arc::new(peers_map);

    let db_path = temp.path().join("xmsg.db");
    let db = Arc::new(Mutex::new(
        rusqlite::Connection::open(&db_path).expect("open db"),
    ));
    {
        let conn = db.lock().unwrap();
        xmsg::storage::init_db(&conn).expect("init db");
    }

    let svc_store = new_svc_store();
    let (cert_der, key_der, _pin) = creds;
    let rate_limiter = Arc::new(RateLimiter::new(60, 20));

    let fed_state = Arc::new(FedState {
        max_attachment_bytes: xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        node_name: name.to_string(),
        peers: (peers_arc.clone()).into(),
        cert_der,
        cert_chain_der: Vec::new(),
        key_der,
        rate_limiter,
        db: db.clone(),
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: svc_store.clone(),
        svc_notify_tx: svc_notify_tx.clone(),
        notify_tx: notify_tx.clone(),
        max_body: 65536,
        is_leaf: true,
        leaf_principal: Some(leaf_principal.to_string()),
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: std::time::Duration::from_secs(7 * 24 * 3600),
        list_queries: Default::default(),
    });

    let r_sock = reg_sock.clone();
    let r_p = leaf_principal.to_string();
    let r_state = Arc::new(xmsg::http::AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: svc_store.clone(),
        svc_notify_tx: svc_notify_tx.clone(),
        node_name: name.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx: notify_tx.clone(),
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(fed_state.clone()),
    });

    let a_sock = agent_sock.clone();
    let a_state = r_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(a_sock, a_state, my_uid).await;
    });

    tokio::spawn(async move {
        let _ = run_leaf_register_server(r_sock, r_state, my_uid, r_p).await;
    });

    if spawn_inbox_task {
        for peer_name in peers_arc.keys() {
            let fs_clone = fed_state.clone();
            let peer_clone = peer_name.clone();
            let p_clone = leaf_principal.to_string();
            let db_clone = db.clone();
            let notify_clone = svc_notify_tx.clone();
            tokio::spawn(async move {
                run_leaf_inbox_task(fs_clone, peer_clone, p_clone, db_clone, notify_clone).await;
            });
        }
    }

    for _ in 0..1500 {
        if std::os::unix::net::UnixStream::connect(&reg_sock).is_ok()
            && std::os::unix::net::UnixStream::connect(&agent_sock).is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    LeafTestNode {
        name: name.to_string(),
        reg_sock,
        agent_sock,
        leaf_principal: leaf_principal.to_string(),
        fed_state,
        db,
        _temp: temp,
    }
}

// =============================================================================
// Oracle 1: End to end send to svc:guard@leaf, poll, ack, reply
// Mutant: hub pushes instead of queueing => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_end_to_end_leaf_svc() {
    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54321".to_string(), // Leaf doesn't listen on TCP
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, claude_rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // 1. Send from hub to svc:guard@leaf via agent.sock
    let resp = send_via_agent_sock(&hub.agent_sock, "guard@leaf", "Task request for guard").await;
    assert_eq!(resp["status"], "ok", "Send should succeed: {resp}");
    assert_eq!(resp["outcome"], "queued");
    let msg_id = resp["message_id"].as_str().unwrap().to_string();

    // Verify hub queued it in peer_mailbox
    {
        let conn = hub.db.lock().unwrap();
        let queued = xmsg::storage::count_peer_mailbox_messages(&conn, "leaf").unwrap();
        assert_eq!(queued, 1, "Message must be queued in hub peer_mailbox");
    }

    // 2. Connect daemon to leaf register.sock
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;

    // Send registration
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "guard",
    });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();

    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(reg_resp["status"], "ok");
    assert!(
        reg_resp["address"]
            .as_str()
            .is_some_and(|a| a.starts_with("guard@")),
        "{reg_resp}"
    );

    // Poll message from leaf
    let poll_frame = serde_json::json!({
        "action": "poll",
        "waitSecs": 10,
    });
    writer
        .write_all(format!("{poll_frame}\n").as_bytes())
        .await
        .unwrap();

    let deliver_resp = read_json_line(&mut reader).await;
    assert_eq!(deliver_resp["action"], "deliver");
    assert_eq!(deliver_resp["messageId"], msg_id);
    assert_eq!(deliver_resp["text"], "Task request for guard");
    let leaf_outcome = || {
        let conn = leaf.db.lock().unwrap();
        xmsg::storage::get_message(&conn, &msg_id)
            .unwrap()
            .map(|m| m.outcome)
    };
    // The leaf's record follows the service's ack, as a local service's does.
    assert_eq!(leaf_outcome().as_deref(), Some("queued"), "before the ack");

    // Ack message
    let ack_frame = serde_json::json!({
        "action": "ack",
        "messageId": msg_id,
    });
    writer
        .write_all(format!("{ack_frame}\n").as_bytes())
        .await
        .unwrap();

    let ack_resp = read_json_line(&mut reader).await;
    assert_eq!(ack_resp["status"], "ok");
    assert_eq!(
        leaf_outcome().as_deref(),
        Some("delivered"),
        "after the ack"
    );

    // Reply to message
    let reply_frame = serde_json::json!({
        "action": "reply",
        "messageId": msg_id,
        "text": "Task completed by guard",
    });
    writer
        .write_all(format!("{reply_frame}\n").as_bytes())
        .await
        .unwrap();

    let reply_resp = read_json_line(&mut reader).await;
    assert_eq!(reply_resp["status"], "ok");
    assert!(reply_resp["messageId"].is_string());

    // Verify Claude session on hub receives pushed reply
    let mut got_reply = false;
    for _ in 0..50 {
        let lines = claude_rx.lock().unwrap().clone();
        if let Some(line) = lines.iter().find(|l| l.contains("Task completed by guard")) {
            assert!(line.contains(&format!("reply to message_id={msg_id}")));
            assert!(line.contains("guard@leaf"), "{line}");
            got_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_reply,
        "Claude session on hub should receive federated reply"
    );
}

// =============================================================================
// Oracle 2: Redelivery if svc polls without acking, disconnects, reconnects
// Mutant: leaf acks the hub on receipt => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_redelivery_unacked_message() {
    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54322".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, _rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // 1. Send from hub to svc:guard@leaf
    let send_body = serde_json::json!({
        "to": "guard@leaf",
        "from": "alice",
        "text": "Unacked task",
    })
    .to_string();

    let (status, resp_body) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            http_request_unix_within(
                &http_sock,
                "POST",
                "/v1/messages",
                Some(&send_body),
                Duration::from_secs(30),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();

    assert_eq!(status, StatusCode::ACCEPTED);
    let resp: Value = serde_json::from_str(&resp_body).unwrap();
    let msg_id = resp["message_id"].as_str().unwrap().to_string();

    // 2. Connect daemon, register and poll without acking
    {
        let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
        let reg_frame = serde_json::json!({ "harness": "svc", "name": "guard" });
        writer
            .write_all(format!("{reg_frame}\n").as_bytes())
            .await
            .unwrap();
        let _ = read_json_line(&mut reader).await;

        let poll_frame = serde_json::json!({ "action": "poll", "waitSecs": 10 });
        writer
            .write_all(format!("{poll_frame}\n").as_bytes())
            .await
            .unwrap();

        let deliver_resp = read_json_line(&mut reader).await;
        assert_eq!(deliver_resp["action"], "deliver");
        assert_eq!(deliver_resp["messageId"], msg_id);

        // Disconnect immediately WITHOUT acking
        drop(reader);
        drop(writer);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Invariant: Before local svc acks, message MUST still be in hub's peer_mailbox
    {
        let conn = hub.db.lock().unwrap();
        let count = xmsg::storage::count_peer_mailbox_messages(&conn, "leaf").unwrap();
        assert_eq!(
            count, 1,
            "Hub mailbox must NOT be acked until local svc acks"
        );
    }

    // 3. Reconnect daemon and poll again -> same message must be redelivered
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
    let reg_frame = serde_json::json!({ "harness": "svc", "name": "guard" });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let _ = read_json_line(&mut reader).await;

    let poll_frame = serde_json::json!({ "action": "poll", "waitSecs": 10 });
    writer
        .write_all(format!("{poll_frame}\n").as_bytes())
        .await
        .unwrap();

    let deliver_resp2 = read_json_line(&mut reader).await;
    assert_eq!(
        deliver_resp2["action"], "deliver",
        "Redelivered message must be received"
    );
    assert_eq!(
        deliver_resp2["messageId"], msg_id,
        "Redelivered messageId must match"
    );

    // Now ack message
    let ack_frame = serde_json::json!({ "action": "ack", "messageId": msg_id });
    writer
        .write_all(format!("{ack_frame}\n").as_bytes())
        .await
        .unwrap();
    let ack_resp = read_json_line(&mut reader).await;
    assert_eq!(ack_resp["status"], "ok");

    // 4. Verify hub's mailbox count becomes 0 exactly once
    let mut hub_mailbox_empty = false;
    for _ in 0..50 {
        let count = {
            let conn = hub.db.lock().unwrap();
            xmsg::storage::count_peer_mailbox_messages(&conn, "leaf").unwrap()
        };
        if count == 0 {
            hub_mailbox_empty = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        hub_mailbox_empty,
        "Hub mailbox message must be removed after svc acks"
    );
}

// =============================================================================
// Oracle 3: Admission refusal for non-leaf principal name
// Mutant: accept any name => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_leaf_admission_refuses_non_leaf_principal() {
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();
    let leaf = create_leaf_test_node("leaf", Vec::new(), creds_leaf, "svc:guard").await;

    // 1. Attempt to register name other than configured leaf principal
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "other",
    });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();

    let resp = read_json_line(&mut reader).await;
    assert_eq!(
        resp["status"], "error",
        "Registering non-leaf principal name must be rejected"
    );
    assert!(
        resp["detail"]
            .as_str()
            .unwrap()
            .contains("does not match leaf principal"),
        "Error detail must mention mismatch: {resp}"
    );

    // 2. Registering with exact leaf principal must succeed
    let (mut reader2, mut writer2) = connect_svc(&leaf.reg_sock).await;
    let reg_frame2 = serde_json::json!({
        "harness": "svc",
        "name": "guard",
    });
    writer2
        .write_all(format!("{reg_frame2}\n").as_bytes())
        .await
        .unwrap();

    let resp2 = read_json_line(&mut reader2).await;
    assert_eq!(
        resp2["status"], "ok",
        "Registering matching leaf principal must succeed"
    );
    assert!(
        resp2["address"]
            .as_str()
            .is_some_and(|a| a.starts_with("guard@")),
        "{resp2}"
    );
}

// =============================================================================
// Oracle 4: Isolation across peer mailboxes; non-leaf 403
// Mutant: mailbox keyed by target ref instead of peer => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_peer_mailbox_isolation_and_non_leaf_denied() {
    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf1 = generate_self_signed_ed25519("leaf1").unwrap();
    let creds_leaf2 = generate_self_signed_ed25519("leaf2").unwrap();
    let creds_nonleaf = generate_self_signed_ed25519("nonleaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![
            PeerConfig {
                name: "leaf1".to_string(),
                address: "127.0.0.1:54323".to_string(),
                pin: Some(creds_leaf1.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["send".to_string(), "reply".to_string()],
                from: None,
                leaf: true,
                principals: Vec::new(),
                targets: None,
                dial: None,
            },
            PeerConfig {
                name: "leaf2".to_string(),
                address: "127.0.0.1:54324".to_string(),
                pin: Some(creds_leaf2.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["send".to_string(), "reply".to_string()],
                from: None,
                leaf: true,
                principals: Vec::new(),
                targets: None,
                dial: None,
            },
            PeerConfig {
                name: "nonleaf".to_string(),
                address: "127.0.0.1:54325".to_string(),
                pin: Some(creds_nonleaf.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["send".to_string(), "reply".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            },
        ],
        creds_hub.clone(),
    )
    .await;

    let (_sock, _rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // Queue message M1 for leaf1
    let (status1, resp1) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            let body =
                serde_json::json!({ "to": "guard@leaf1", "from": "alice", "text": "M1 for leaf1" })
                    .to_string();
            http_request_unix_within(
                &http_sock,
                "POST",
                "/v1/messages",
                Some(&body),
                Duration::from_secs(30),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(status1, StatusCode::ACCEPTED);
    let msg1_id = serde_json::from_str::<Value>(&resp1).unwrap()["message_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Queue message M2 for leaf2 (both targeting svc:guard)
    let (status2, resp2) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            let body =
                serde_json::json!({ "to": "guard@leaf2", "from": "alice", "text": "M2 for leaf2" })
                    .to_string();
            http_request_unix_within(
                &http_sock,
                "POST",
                "/v1/messages",
                Some(&body),
                Duration::from_secs(30),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(status2, StatusCode::ACCEPTED);
    let msg2_id = serde_json::from_str::<Value>(&resp2).unwrap()["message_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Build leaf1 client fed_state to call get_federated_inbox
    let mut leaf1_peers = PeersMap::empty();
    leaf1_peers
        .insert(PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        })
        .unwrap();

    let leaf1_fed_state = FedState {
        max_attachment_bytes: xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        node_name: "leaf1".to_string(),
        peers: (Arc::new(leaf1_peers)).into(),
        cert_der: creds_leaf1.0,
        cert_chain_der: Vec::new(),
        key_der: creds_leaf1.1,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: hub.db.clone(),
        sessions_dirs: vec![PathBuf::new()],
        agy_config: AgyConfig::default(),
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        notify_tx: tokio::sync::broadcast::channel(16).0,
        max_body: 65536,
        is_leaf: true,
        leaf_principal: Some("svc:guard".to_string()),
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: std::time::Duration::from_secs(7 * 24 * 3600),
        list_queries: Default::default(),
    };

    // Leaf 1 polls inbox: gets M1
    let poll1 = xmsg::fed::get_federated_inbox(&leaf1_fed_state, "hub", 0)
        .await
        .unwrap();
    assert!(poll1.is_some());
    let Some(xmsg::fed::FedInboxItem::Message(m)) = poll1 else {
        panic!("expected a message, got {poll1:?}");
    };
    assert_eq!(m.id, msg1_id);
    assert_eq!(m.body, "M1 for leaf1");

    // Leaf 1 acks M1
    xmsg::fed::ack_federated_inbox(&leaf1_fed_state, "hub", &msg1_id)
        .await
        .unwrap();

    // Leaf 1 polls again: gets None (MUST NOT receive M2 meant for leaf2!)
    let poll2 = xmsg::fed::get_federated_inbox(&leaf1_fed_state, "hub", 0)
        .await
        .unwrap();
    assert!(
        poll2.is_none(),
        "Leaf1 must NOT see M2 meant for Leaf2 in its mailbox"
    );

    // Leaf 1 attempts to ack M2 (meant for Leaf2): must return 404 NotFound
    let ack_cross = xmsg::fed::ack_federated_inbox(&leaf1_fed_state, "hub", &msg2_id).await;
    match ack_cross {
        Err(e) if e.code().1 == "not_found" => {}
        other => panic!("Acking another peer's mailbox id must return NotFound, got: {other:?}"),
    }

    // Non-leaf peer attempts to poll /fed/v2/inbox: must return 403 OpDenied
    let mut nonleaf_peers = PeersMap::empty();
    nonleaf_peers
        .insert(PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        })
        .unwrap();

    let nonleaf_fed_state = FedState {
        max_attachment_bytes: xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        node_name: "nonleaf".to_string(),
        peers: (Arc::new(nonleaf_peers)).into(),
        cert_der: creds_nonleaf.0,
        cert_chain_der: Vec::new(),
        key_der: creds_nonleaf.1,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: hub.db.clone(),
        sessions_dirs: vec![PathBuf::new()],
        agy_config: AgyConfig::default(),
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        notify_tx: tokio::sync::broadcast::channel(16).0,
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: std::time::Duration::from_secs(7 * 24 * 3600),
        list_queries: Default::default(),
    };

    let poll_nonleaf = xmsg::fed::get_federated_inbox(&nonleaf_fed_state, "hub", 0).await;
    match poll_nonleaf {
        Err(AppError::OpDenied(_)) => {}
        other => panic!("Non-leaf polling /fed/v2/inbox must return OpDenied, got: {other:?}"),
    }
}

// =============================================================================
// Oracle 5: Targets filter on queue path
// Mutant: skip targets check on queue path => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_targets_filter_on_queue_path() {
    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54326".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: Some(vec!["guard".to_string()]),
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let (_sock, _rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // 1. Send to disallowed target svc:other@leaf
    let (status_disallowed, resp_disallowed) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            let body =
                serde_json::json!({ "to": "other@leaf", "from": "alice", "text": "Disallowed" })
                    .to_string();
            http_request_unix_within(
                &http_sock,
                "POST",
                "/v1/messages",
                Some(&body),
                Duration::from_secs(30),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();

    assert_eq!(
        status_disallowed,
        StatusCode::FORBIDDEN,
        "Target not in targets allowlist must return 403 Forbidden: {resp_disallowed}"
    );

    // Verify nothing queued in mailbox
    {
        let conn = hub.db.lock().unwrap();
        let queued = xmsg::storage::count_peer_mailbox_messages(&conn, "leaf").unwrap();
        assert_eq!(
            queued, 0,
            "Disallowed target message must NEVER be queued in peer_mailbox"
        );
    }

    // 2. Send to allowed target svc:guard@leaf
    let (status_allowed, resp_allowed) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            let body =
                serde_json::json!({ "to": "guard@leaf", "from": "alice", "text": "Allowed" })
                    .to_string();
            http_request_unix_within(
                &http_sock,
                "POST",
                "/v1/messages",
                Some(&body),
                Duration::from_secs(30),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();

    assert_eq!(
        status_allowed,
        StatusCode::ACCEPTED,
        "Allowed target must succeed: {resp_allowed}"
    );

    {
        let conn = hub.db.lock().unwrap();
        let queued = xmsg::storage::count_peer_mailbox_messages(&conn, "leaf").unwrap();
        assert_eq!(
            queued, 1,
            "Allowed target message must be queued in peer_mailbox"
        );
    }
}

// =============================================================================
// Oracle 6: Delivered frame carries `principal` badge
// Mutant: omit principal => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_delivered_frame_carries_principal_badge() {
    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54327".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, _rx) = create_claude_session_fixture(
        &hub.proc_root,
        &hub.sessions_dir,
        "0199cecf-a11c-7000-8000-0000000a11ce",
        "alice",
    );

    // Send from hub via agent.sock
    let resp =
        send_via_agent_sock(&hub.agent_sock, "guard@leaf", "Message with principal test").await;
    assert_eq!(resp["status"], "ok", "Send should succeed: {resp}");
    assert_eq!(resp["outcome"], "queued");

    // Connect svc daemon and poll
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
    let reg_frame = serde_json::json!({ "harness": "svc", "name": "guard" });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let _ = read_json_line(&mut reader).await;

    let poll_frame = serde_json::json!({ "action": "poll", "waitSecs": 10 });
    writer
        .write_all(format!("{poll_frame}\n").as_bytes())
        .await
        .unwrap();

    let deliver_resp = read_json_line(&mut reader).await;
    assert_eq!(deliver_resp["action"], "deliver");

    // Invariant: the one origin shape (A12): the sender's instance ID, the node that
    // attests it (the hub, where alice sent from) and her own label
    let origin = &deliver_resp["origin"];
    assert_eq!(
        origin["id"], "0199cecf-a11c-7000-8000-0000000a11ce",
        "{origin}"
    );
    assert_eq!(origin["node"], "hub", "{origin}");
    assert_eq!(
        origin["label"], "alice",
        "Delivered origin must carry the sender's label apart from its id: {origin}"
    );
}

// =============================================================================
// Oracle 7: Startup refusal for --leaf + --svc-exe
// Mutant: allow => RED
// =============================================================================
#[tokio::test]
async fn test_oracle_7_startup_refusal_leaf_with_svc_exe() {
    let tmp = TempDir::new().unwrap();
    let bin = env!("CARGO_BIN_EXE_xmsg");

    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    let (cert_pem, key_pem, _) = xmsg::fed::generate_self_signed_ed25519_pem("leaf-node").unwrap();
    fs::write(&cert_file, cert_pem).unwrap();
    fs::write(&key_file, key_pem).unwrap();
    fs::write(&peers_file, "{}").unwrap();

    let output = std::process::Command::new(bin)
        .env("HOME", tmp.path())
        .args([
            "serve",
            "--leaf",
            "--leaf-principal",
            "svc:guard",
            "--listen",
            "127.0.0.1:0",
            "--peers-file",
            peers_file.to_str().unwrap(),
            "--fed-cert",
            cert_file.to_str().unwrap(),
            "--fed-key",
            key_file.to_str().unwrap(),
            "--svc-exe",
            "guard=/bin/true",
        ])
        .output()
        .expect("execute xmsg serve");

    assert!(
        !output.status.success(),
        "xmsg serve --leaf with --svc-exe must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--leaf"),
        "Error output must name '--leaf': {stderr}"
    );
    assert!(
        stderr.contains("--svc-exe"),
        "Error output must name '--svc-exe': {stderr}"
    );
}

// =============================================================================
// Oracle 8: Liveness: misaddressed send (to non-leaf principal) gets not_found reply
// and does NOT block the inbox; subsequent send to registered svc arrives promptly.
// Mutant: restore today's svc:<to> delivery => RED (timeout).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_8_misaddressed_message_does_not_stall_inbox() {
    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54328".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, claude_rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // 1. Connect svc:guard daemon to leaf
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
    let reg_frame = serde_json::json!({ "harness": "svc", "name": "guard" });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(reg_resp["status"], "ok");

    // 2. Hub session sends misaddressed message to svc:other@leaf
    let resp1 = send_via_agent_sock(&hub.agent_sock, "other@leaf", "Task for other").await;
    assert_eq!(resp1["status"], "ok");
    assert_eq!(resp1["outcome"], "queued");
    let msg1_id = resp1["message_id"].as_str().unwrap().to_string();

    // Verify Claude session on hub receives not_found reply for msg1
    let mut got_not_found_reply = false;
    for _ in 0..60 {
        let lines = claude_rx.lock().unwrap().clone();
        if let Some(line) = lines
            .iter()
            .find(|l| l.contains(&format!("reply to message_id={msg1_id}")))
        {
            assert!(line.contains("not_found"));
            assert!(line.contains("other is not served by this leaf"));
            got_not_found_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_not_found_reply,
        "Hub session should receive not_found reply for misaddressed message"
    );

    // 3. Hub session sends valid message to svc:guard@leaf
    let resp2 = send_via_agent_sock(&hub.agent_sock, "guard@leaf", "Task for guard").await;
    assert_eq!(resp2["status"], "ok");
    assert_eq!(resp2["outcome"], "queued");
    let msg2_id = resp2["message_id"].as_str().unwrap().to_string();

    // 4. Svc daemon on leaf polls: must receive msg2 within bounded test deadline!
    let poll_res = tokio::time::timeout(Duration::from_secs(3), async {
        let poll_frame = serde_json::json!({ "action": "poll", "waitSecs": 5 });
        writer
            .write_all(format!("{poll_frame}\n").as_bytes())
            .await
            .unwrap();
        read_json_line(&mut reader).await
    })
    .await;

    assert!(
        poll_res.is_ok(),
        "Daemon must receive msg2 without inbox stall"
    );
    let deliver_resp = poll_res.unwrap();
    assert_eq!(deliver_resp["action"], "deliver");
    assert_eq!(deliver_resp["messageId"], msg2_id);
    assert_eq!(deliver_resp["text"], "Task for guard");
}

// =============================================================================
// Oracle 9: F2: Storage error during inbox processing does NOT ack the hub and
// does NOT spin; upon store recovery, the unacked message is repolled and delivered.
// Mutant: ignore the store error => RED (task spins forever, message lost).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_9_storage_error_does_not_ack_and_recovers() {
    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54329".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, _rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // 1. Simulate a failing store by installing a trigger on svc_pending_messages that raises FAIL
    {
        let conn = leaf.db.lock().unwrap();
        conn.execute(
            "CREATE TRIGGER fail_insert BEFORE INSERT ON svc_pending_messages
             BEGIN
                 SELECT RAISE(FAIL, 'simulated disk error');
             END;",
            [],
        )
        .unwrap();
    }

    // 2. Hub queues a message for svc:guard@leaf
    let resp = send_via_agent_sock(&hub.agent_sock, "guard@leaf", "Message during failure").await;
    assert_eq!(resp["status"], "ok");
    let msg_id = resp["message_id"].as_str().unwrap().to_string();

    // 3. Wait 400ms: leaf task will try to store, fail, back off, and MUST NOT ack hub
    tokio::time::sleep(Duration::from_millis(400)).await;

    {
        let hub_conn = hub.db.lock().unwrap();
        let queued = xmsg::storage::count_peer_mailbox_messages(&hub_conn, "leaf").unwrap();
        assert_eq!(
            queued, 1,
            "Hub mailbox message MUST NOT be acked when leaf store fails"
        );
    }

    // 4. Recover the store by dropping the failing trigger
    {
        let conn = leaf.db.lock().unwrap();
        conn.execute("DROP TRIGGER fail_insert", []).unwrap();
    }

    // 5. Connect daemon to leaf register.sock
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
    let reg_frame = serde_json::json!({ "harness": "svc", "name": "guard" });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(reg_resp["status"], "ok");

    // 6. Daemon polls: leaf background task recovers, stores repolled message, delivers to svc
    let poll_res = tokio::time::timeout(Duration::from_secs(4), async {
        let poll_frame = serde_json::json!({ "action": "poll", "waitSecs": 5 });
        writer
            .write_all(format!("{poll_frame}\n").as_bytes())
            .await
            .unwrap();
        read_json_line(&mut reader).await
    })
    .await;

    assert!(poll_res.is_ok(), "Daemon must receive recovered message");
    let deliver_resp = poll_res.unwrap();
    assert_eq!(deliver_resp["action"], "deliver");
    assert_eq!(deliver_resp["messageId"], msg_id);
    assert_eq!(deliver_resp["text"], "Message during failure");
}

// =============================================================================
// Oracle 10 (G1): Leaf admission refuses a caller whose peer UID != server UID
// Mutant: disable `if peer_uid != my_uid` in `src/svc.rs` => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_10_leaf_admission_refuses_mismatched_uid() {
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();
    let leaf = create_leaf_test_node("leaf", Vec::new(), creds_leaf, "svc:gateway").await;

    let actual_uid = current_uid();
    let mismatched_uid = actual_uid.wrapping_add(1);
    let bad_sock = leaf.reg_sock.with_file_name("register-mismatch.sock");
    let bad_listener = xmsg::svc::bind_leaf_register_listener(&bad_sock, actual_uid).unwrap();

    let state = Arc::new(xmsg::http::AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: leaf.fed_state.sessions_dirs.clone(),
        agy_config: leaf.fed_state.agy_config.clone(),
        agy_store: leaf.fed_state.agy_store.clone(),
        pi_store: leaf.fed_state.pi_store.clone(),
        pi_notify_tx: leaf.fed_state.pi_notify_tx.clone(),
        svc_store: leaf.fed_state.svc_store.clone(),
        svc_notify_tx: leaf.fed_state.svc_notify_tx.clone(),
        node_name: leaf.name.clone(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: leaf.db.clone(),
        notify_tx: leaf.fed_state.notify_tx.clone(),
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(leaf.fed_state.clone()),
    });

    tokio::spawn(async move {
        let _ = xmsg::svc::run_leaf_register_server_with_listener(
            bad_listener,
            state,
            mismatched_uid,
            "svc:gateway".to_string(),
        )
        .await;
    });

    // 1. Mismatched server UID refuses the registration even when the principal name matches
    let (mut reader, mut writer) = connect_svc(&bad_sock).await;
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "gateway",
    });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let resp = read_json_line(&mut reader).await;
    assert_eq!(resp["status"], "error", "UID mismatch must fail: {resp}");
    assert_eq!(resp["error"], "denied", "{resp}");
    let detail = resp["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains(&format!(
            "peer UID {actual_uid} does not match server UID {mismatched_uid}"
        )),
        "Unexpected refusal detail: {detail}"
    );
    assert!(
        leaf.fed_state.svc_store.read().unwrap().is_empty(),
        "Refused caller must not populate svc_store"
    );

    // 2. Positive control: matching server UID on the leaf's register.sock admits "gateway"
    let (mut ok_reader, mut ok_writer) = connect_svc(&leaf.reg_sock).await;
    ok_writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let ok_resp = read_json_line(&mut ok_reader).await;
    assert_eq!(ok_resp["status"], "ok", "{ok_resp}");
    assert_eq!(ok_resp["address"], "gateway@leaf", "{ok_resp}");
}

// =============================================================================
// Oracle 11 (G2): Leaf-pod `svc` sends, replies, and lists end-to-end over P1 arm B
// Mutant: drop `idempotency_key` on `agent.sock` send in `src/agent.rs` => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_11_leaf_svc_send_and_reply() {
    use xmsg::client::{ClientError, ClientOptions, ListQuery, RegisteredService};

    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54321".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, claude_rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    let make_opts = |service: &str| ClientOptions {
        register_socket: leaf.reg_sock.clone(),
        agent_socket: leaf.agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: service.to_string(),
        expected_node: Some("leaf".to_string()),
        daemon_uid: current_uid(),
    };

    // 1. Name mismatch on leaf registration is refused
    let mismatch = RegisteredService::register(make_opts("other")).await;
    assert!(
        matches!(
            mismatch,
            Err(ClientError::Refused { ref code }) if code == "denied"
        ),
        "Expected denied refusal for wrong service name, got: {}",
        mismatch.err().unwrap()
    );

    // 2. Register as the leaf principal ("guard") via RegisteredService
    let mut service = RegisteredService::register(make_opts("guard"))
        .await
        .expect("leaf registration should succeed");
    assert_eq!(service.address(), Some("guard@leaf"));
    let agent = service.agent_client();

    // 3. Discovery over leaf agent.sock sees alice@hub
    let listed = agent
        .list(ListQuery {
            name: Some("alice".to_string()),
            node: Some("hub".to_string()),
            ..Default::default()
        })
        .await
        .expect("leaf list should succeed");
    assert!(
        listed
            .recipients
            .iter()
            .any(|r| r.label.as_deref() == Some("alice") && r.node == "hub"),
        "Expected alice@hub in list response: {listed:?}"
    );

    // 4. Leaf `svc` sends to alice@hub via leaf agent.sock with idempotency key
    let sent1 = agent
        .send(
            "alice@hub",
            "Alert from leaf guard",
            Some("idem-leaf-send-1"),
        )
        .await
        .expect("leaf send 1 should succeed");
    assert_eq!(sent1.outcome, "delivered");

    // 5. Resend with the same idempotency key is deduplicated
    let sent2 = agent
        .send(
            "alice@hub",
            "Alert from leaf guard",
            Some("idem-leaf-send-1"),
        )
        .await
        .expect("leaf send 2 (dedup) should succeed");
    assert_eq!(
        sent2.message_id, sent1.message_id,
        "Resend with same idempotency key must return the same message_id"
    );

    // Verify leaf recorded sender as local service ("svc", "guard") and hub received as guard@leaf
    {
        let leaf_conn = leaf.db.lock().unwrap();
        let leaf_stored = xmsg::storage::get_message(&leaf_conn, &sent1.message_id)
            .unwrap()
            .expect("leaf must store outbound message");
        assert_eq!(leaf_stored.return_harness.as_deref(), Some("svc"));
        assert_eq!(leaf_stored.return_session_id.as_deref(), Some("guard"));

        let conn = hub.db.lock().unwrap();
        let stored = xmsg::storage::get_message(&conn, &sent1.message_id)
            .unwrap()
            .expect("hub must store federated message from leaf");
        assert_eq!(stored.from_name, "guard@leaf");
        assert_eq!(stored.return_harness.as_deref(), Some("fed"));
        assert_eq!(stored.return_session_id.as_deref(), Some("guard"));
        assert_eq!(stored.return_host.as_deref(), Some("leaf"));
    }
    let delivered_alerts: Vec<String> = claude_rx
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("Alert from leaf guard"))
        .cloned()
        .collect();
    assert_eq!(
        delivered_alerts.len(),
        1,
        "Deduplicated send must deliver only once: {delivered_alerts:?}"
    );
    assert!(
        delivered_alerts[0].contains("from-name=\\\"guard@leaf\\\"")
            && delivered_alerts[0].contains("ref=guard@"),
        "Hub must observe sender as guard@leaf: {}",
        delivered_alerts[0]
    );

    // 7. Hub sends a message to guard@leaf; leaf polls, acks, and replies over SvcFrame::Reply
    let hub_send =
        send_via_agent_sock(&hub.agent_sock, "guard@leaf", "Question for leaf guard").await;
    assert_eq!(hub_send["status"], "ok", "{hub_send}");
    let inbound_id = hub_send["message_id"].as_str().unwrap().to_string();

    let delivery = service
        .poll(10)
        .await
        .expect("leaf poll should succeed")
        .expect("leaf should receive queued message from hub");
    assert_eq!(delivery.message_id(), inbound_id);
    assert_eq!(delivery.text(), "Question for leaf guard");
    service
        .ack(delivery.message_id())
        .await
        .expect("leaf ack should succeed");

    let reply1 = agent
        .reply(
            delivery.message_id(),
            "Answer from leaf guard",
            Some("idem-leaf-reply-1"),
        )
        .await
        .expect("leaf reply over svc stream should succeed");
    assert_eq!(reply1.replier_session_id, "guard");
    assert_eq!(reply1.text, "Answer from leaf guard");

    let reply2 = agent
        .reply(
            delivery.message_id(),
            "Answer from leaf guard",
            Some("idem-leaf-reply-1"),
        )
        .await
        .expect("idempotent leaf reply should succeed");
    assert_eq!(reply2.seq, reply1.seq);
    assert_eq!(reply2.pushed_message_id, reply1.pushed_message_id);

    let mut got_reply = false;
    for _ in 0..50 {
        let lines = claude_rx.lock().unwrap().clone();
        if let Some(line) = lines.iter().find(|l| l.contains("Answer from leaf guard")) {
            assert!(line.contains(&format!("reply to message_id={inbound_id}")));
            assert!(line.contains("guard@leaf"), "{line}");
            got_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_reply,
        "Claude session on hub must receive federated reply from leaf svc"
    );
}

// =============================================================================
// Oracle 12: Leaf `agent.sock` refuses a caller whose peer UID != daemon UID
// (and succeeds without `/proc` when peer UID == daemon UID)
// Mutant: `if !state.is_leaf() && peer_uid != my_uid` in `src/agent.rs` => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_12_leaf_agent_sock_refuses_mismatched_uid() {
    use xmsg::client::{ClientOptions, ListQuery, RegisteredService};

    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54321".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:gateway",
    )
    .await;

    let (_sock, claude_rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-bob", "bob");

    // Verify the leaf node's proc_root is completely empty (no /proc/<pid> entries)
    assert_eq!(
        std::fs::read_dir(&leaf.fed_state.agy_config.proc_root)
            .unwrap()
            .count(),
        0,
        "leaf proc_root must be empty to prove /proc-free leaf agent.sock operation"
    );

    let actual_uid = current_uid();
    let mismatched_uid = actual_uid.wrapping_add(1);
    let bad_agent_sock = leaf.agent_sock.with_file_name("agent-mismatch.sock");
    let bad_listener = xmsg::agent::bind_agent_listener(&bad_agent_sock, actual_uid)
        .await
        .unwrap();

    let state = Arc::new(xmsg::http::AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: leaf.fed_state.sessions_dirs.clone(),
        agy_config: leaf.fed_state.agy_config.clone(),
        agy_store: leaf.fed_state.agy_store.clone(),
        pi_store: leaf.fed_state.pi_store.clone(),
        pi_notify_tx: leaf.fed_state.pi_notify_tx.clone(),
        svc_store: leaf.fed_state.svc_store.clone(),
        svc_notify_tx: leaf.fed_state.svc_notify_tx.clone(),
        node_name: leaf.name.clone(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: leaf.db.clone(),
        notify_tx: leaf.fed_state.notify_tx.clone(),
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(leaf.fed_state.clone()),
    });
    assert!(state.is_leaf(), "AppState under test must be in leaf mode");

    tokio::spawn(async move {
        let _ =
            xmsg::agent::run_agent_server_with_listener(bad_listener, state, mismatched_uid).await;
    });

    // 1. Negative control (raw frame + RegisteredService): caller with peer_uid != my_uid is refused.
    // Exercise both immediate write after connect and forced-race write after the server has
    // already accepted, rejected `peer_uid != my_uid`, and closed its socket (`BrokenPipe`).
    for delay_ms in [0_u64, 25_u64] {
        let (mut raw_reader, mut raw_writer) = connect_svc(&bad_agent_sock).await;
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let _ = raw_writer.write_all(b"{\"action\":\"list\"}\n").await;
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(2), raw_reader.read_line(&mut line))
            .await
            .expect("raw read must not hang on UID-rejected leaf agent.sock")
            .unwrap_or(0);
        assert_eq!(
            n, 0,
            "mismatched peer UID on leaf agent.sock (delay_ms={delay_ms}) accepted raw frame: {line}"
        );
    }

    let bad_service = RegisteredService::register(ClientOptions {
        register_socket: leaf.reg_sock.clone(),
        agent_socket: bad_agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(3),
        service: "gateway".to_string(),
        expected_node: Some("leaf".to_string()),
        daemon_uid: actual_uid,
    })
    .await
    .expect("registration on valid leaf register.sock should succeed");
    let bad_agent = bad_service.agent_client();

    let bad_list = bad_agent.list(ListQuery::default()).await;
    assert!(
        bad_list.is_err(),
        "mismatched peer UID on leaf agent.sock accepted list: {bad_list:?}"
    );
    let bad_send = bad_agent
        .send("bob@hub", "Forged from wrong UID", Some("idem-bad-uid-1"))
        .await;
    assert!(
        bad_send.is_err(),
        "mismatched peer UID on leaf agent.sock accepted send: {bad_send:?}"
    );
    drop(bad_service);

    assert!(
        claude_rx.lock().unwrap().is_empty(),
        "Refused leaf agent.sock send must not deliver any message to hub"
    );

    // Wait briefly for the dropped registration socket to clear svc_store before positive control
    for _ in 0..50 {
        if leaf.fed_state.svc_store.read().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // 2. Positive control: matching UID on leaf.agent_sock (still with empty proc_root) succeeds
    let ok_service = RegisteredService::register(ClientOptions {
        register_socket: leaf.reg_sock.clone(),
        agent_socket: leaf.agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: "gateway".to_string(),
        expected_node: Some("leaf".to_string()),
        daemon_uid: actual_uid,
    })
    .await
    .expect("positive-control leaf registration should succeed");
    let ok_agent = ok_service.agent_client();

    let ok_listed = ok_agent
        .list(ListQuery {
            name: Some("bob".to_string()),
            node: Some("hub".to_string()),
            ..Default::default()
        })
        .await
        .expect("same-UID leaf list without /proc should succeed");
    assert!(
        ok_listed
            .recipients
            .iter()
            .any(|r| r.label.as_deref() == Some("bob") && r.node == "hub"),
        "Expected bob@hub in positive-control list: {ok_listed:?}"
    );

    let ok_sent = ok_agent
        .send(
            "bob@hub",
            "Hello from same-UID leaf without /proc",
            Some("idem-ok-uid-1"),
        )
        .await
        .expect("same-UID leaf send without /proc should succeed");
    assert_eq!(ok_sent.outcome, "delivered");
    assert!(
        claude_rx
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("Hello from same-UID leaf without /proc")),
        "Hub session must receive positive-control leaf message"
    );
}

async fn register_hub_service(
    hub: &HubTestNode,
    service_name: &str,
) -> xmsg::client::RegisteredService {
    use xmsg::client::{ClientOptions, RegisteredService};

    let my_pid = std::process::id();
    let live_proc = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&live_proc, my_pid).unwrap_or_else(|_| "1000".to_string());
    let pid_dir = hub.proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    let stat_content =
        format!("{my_pid} (svc_test) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {my_proc_start} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).unwrap();

    let reg_sock = hub
        .agent_sock
        .parent()
        .unwrap()
        .join(format!("register-{service_name}.sock"));
    let my_uid = current_uid();
    let listener = xmsg::svc::bind_leaf_register_listener(&reg_sock, my_uid).unwrap();
    let state_clone = hub.app_state.clone();
    let principal = format!("svc:{service_name}");
    tokio::spawn(async move {
        let _ = xmsg::svc::run_leaf_register_server_with_listener(
            listener,
            state_clone,
            my_uid,
            principal,
        )
        .await;
    });

    RegisteredService::register(ClientOptions {
        register_socket: reg_sock,
        agent_socket: hub.agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: service_name.to_string(),
        expected_node: Some(hub.name.clone()),
        daemon_uid: my_uid,
    })
    .await
    .expect("hub service registration should succeed")
}

// =============================================================================
// Leaf reply Oracle (1): Two-node hub + leaf: leaf svc sends to a hub agent,
// the agent replies, and the leaf svc receives it through normal service
// delivery (in_reply_to = original message id, plus the replier's attested
// origin), and acks it while keeping the stored reply row in `replies`.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leaf_reply_oracle_1_hub_agent_replies_to_leaf_svc() {
    use xmsg::client::{ClientOptions, RegisteredService};

    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54321".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, claude_rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    let mut leaf_svc = RegisteredService::register(ClientOptions {
        register_socket: leaf.reg_sock.clone(),
        agent_socket: leaf.agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: "guard".to_string(),
        expected_node: Some("leaf".to_string()),
        daemon_uid: current_uid(),
    })
    .await
    .expect("leaf svc registration should succeed");

    // 1. Leaf svc sends to alice@hub
    let sent = leaf_svc
        .send("alice@hub", "Ping from leaf guard", Some("idem-leaf-r1"))
        .await
        .expect("leaf send to hub agent should succeed");
    assert_eq!(sent.outcome, "delivered");
    assert!(
        claude_rx
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("Ping from leaf guard")),
        "alice@hub must receive message from guard@leaf"
    );

    // 2. Hub agent (alice) replies to the leaf message
    let reply_body = serde_json::json!({
        "text": "Pong from alice on hub",
    })
    .to_string();
    let reply_path = format!("/v1/messages/{}/replies", sent.message_id);
    let (status, resp_body) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            http_request_unix_within(
                &http_sock,
                "POST",
                &reply_path,
                Some(&reply_body),
                Duration::from_secs(10),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK, "hub reply failed: {resp_body}");
    let reply_json: Value = serde_json::from_str(&resp_body).unwrap();
    assert_eq!(reply_json["pushOutcome"], "stored");
    let reply_id = reply_json["pushedMessageId"]
        .as_str()
        .expect("stored leaf reply must have pushedMessageId")
        .to_string();

    // 3. Leaf svc receives the reply through normal service delivery (`poll`)
    let delivery = leaf_svc
        .poll(2)
        .await
        .expect("leaf poll should succeed")
        .expect("leaf svc must receive reply queued in hub peer_mailbox");
    assert_eq!(delivery.message_id(), reply_id);
    assert_eq!(delivery.text(), "Pong from alice on hub");
    assert_eq!(
        delivery.in_reply_to(),
        Some(sent.message_id.as_str()),
        "delivered reply must carry in_reply_to = original message id"
    );
    assert_eq!(delivery.origin().node, "hub");
    assert_eq!(delivery.origin().service, None);
    assert_eq!(delivery.origin().label.as_deref(), Some("alice"));
    assert!(
        delivery.origin().id.is_some(),
        "agent replier origin must carry attested instance id: {:?}",
        delivery.origin()
    );
    assert!(
        delivery
            .envelope()
            .starts_with("[xmsg] reply from=alice · "),
        "unexpected reply envelope: {}",
        delivery.envelope()
    );

    // 4. Ack the delivered reply on the leaf and verify hub peer_mailbox drains while
    //    the stored reply row remains in hub `replies`.
    leaf_svc
        .ack(delivery.message_id())
        .await
        .expect("leaf ack of reply should succeed");

    let mut mailbox_drained = false;
    for _ in 0..50 {
        let count = {
            let conn = hub.db.lock().unwrap();
            xmsg::storage::count_peer_mailbox_messages(&conn, "leaf").unwrap()
        };
        if count == 0 {
            mailbox_drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        mailbox_drained,
        "hub peer_mailbox for leaf must drain after leaf svc acks the reply"
    );

    {
        let conn = hub.db.lock().unwrap();
        let stored_replies = xmsg::storage::get_replies_after(&conn, &sent.message_id, 0).unwrap();
        assert_eq!(
            stored_replies.len(),
            1,
            "stored reply row in `replies` must remain after mailbox ack"
        );
        assert_eq!(stored_replies[0].push_outcome.as_deref(), Some("stored"));
        assert_eq!(
            stored_replies[0].pushed_message_id.as_deref(),
            Some(reply_id.as_str())
        );
    }
}

// =============================================================================
// Leaf reply Oracle (2): No duplicate delivery on a redelivered or retried reply
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leaf_reply_oracle_2_idempotent_redelivered_or_retried_reply() {
    use xmsg::client::{ClientOptions, RegisteredService};
    use xmsg::fed::FedEnvelope;
    use xmsg::storage::Origin;

    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54321".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, _claude_rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    let mut leaf_svc = RegisteredService::register(ClientOptions {
        register_socket: leaf.reg_sock.clone(),
        agent_socket: leaf.agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: "guard".to_string(),
        expected_node: Some("leaf".to_string()),
        daemon_uid: current_uid(),
    })
    .await
    .unwrap();

    let sent = leaf_svc
        .send("alice@hub", "Request from leaf", Some("idem-leaf-r2"))
        .await
        .unwrap();

    // 1. Retried reply with the same idempotency_key on hub + explicit duplicate
    //    `queue_leaf_mailbox_reply` call with the same `reply_id` before leaf pulls.
    let reply_body = serde_json::json!({
        "text": "Idempotent reply from alice",
        "idempotency_key": "idem-alice-reply-r2",
    })
    .to_string();
    let reply_path = format!("/v1/messages/{}/replies", sent.message_id);
    for _ in 0..2 {
        let (status, _) = tokio::task::spawn_blocking({
            let http_sock = hub.http_sock.clone();
            let path = reply_path.clone();
            let body = reply_body.clone();
            move || {
                http_request_unix_within(
                    &http_sock,
                    "POST",
                    &path,
                    Some(&body),
                    Duration::from_secs(10),
                )
                .unwrap()
            }
        })
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
    }

    let first_delivery = leaf_svc
        .poll(10)
        .await
        .unwrap()
        .expect("leaf svc must receive first delivery");
    let reply_id = first_delivery.message_id().to_string();
    assert_eq!(first_delivery.in_reply_to(), Some(sent.message_id.as_str()));

    // Re-queue the exact same reply envelope on the hub after ack to simulate a
    // redelivered/retried reply with the same `reply_id`.
    leaf_svc.ack(&reply_id).await.unwrap();

    let dup_env = FedEnvelope {
        attachments: vec![],
        v: xmsg::fed::WIRE_VERSION,
        id: reply_id.clone(),
        origin: Origin::service("genie", "hub"),
        to: xmsg::fed::FedTarget {
            r#ref: "guard".to_string(),
        },
        body: "Idempotent reply from alice".to_string(),
        thread_id: sent.message_id.clone(),
        created_at: xmsg::storage::now_epoch_secs(),
        forwarded: None,
    };
    xmsg::fed::queue_leaf_mailbox_reply(
        &hub.fed_state,
        "leaf",
        "guard",
        &dup_env,
        "genie@hub",
        &sent.message_id,
    )
    .unwrap();
    // Calling queue_leaf_mailbox_reply twice while unpulled must keep at most 1 row in peer_mailbox
    xmsg::fed::queue_leaf_mailbox_reply(
        &hub.fed_state,
        "leaf",
        "guard",
        &dup_env,
        "genie@hub",
        &sent.message_id,
    )
    .unwrap();

    // Wait for the leaf inbox task to pull and auto-ack the already-acked `reply_id`
    // without delivering a duplicate to `leaf_svc`.
    let second_poll = leaf_svc.poll(1).await.expect("second poll should succeed");
    assert!(
        second_poll.is_none(),
        "already-acked reply_id must not be delivered a second time: {second_poll:?}"
    );
}

// =============================================================================
// Leaf reply Oracle (3): A non-leaf origin behaves unchanged (push path)
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leaf_reply_oracle_3_non_leaf_origin_uses_push_path() {
    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_peer = generate_self_signed_ed25519("peer-b").unwrap();

    let peer_b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_b_addr = peer_b_listener.local_addr().unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "peer-b".to_string(),
            address: peer_b_addr.to_string(),
            pin: Some(creds_peer.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    let peer_b = create_hub_test_node_with_listener(
        "peer-b",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_peer.clone(),
        peer_b_listener,
    )
    .await;

    let (_alice_sock, _alice_rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");
    let (_bob_sock, bob_rx) =
        create_claude_session_fixture(&peer_b.proc_root, &peer_b.sessions_dir, "sess-bob", "bob");

    // 1. bob@peer-b sends to alice@hub
    let send_body = serde_json::json!({
        "to": "alice@hub",
        "from": "bob",
        "text": "Hello from non-leaf peer-b",
    })
    .to_string();
    let (status, resp_body) = tokio::task::spawn_blocking({
        let http_sock = peer_b.http_sock.clone();
        move || {
            http_request_unix_within(
                &http_sock,
                "POST",
                "/v1/messages",
                Some(&send_body),
                Duration::from_secs(10),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(status, StatusCode::ACCEPTED, "{resp_body}");
    let sent_json: Value = serde_json::from_str(&resp_body).unwrap();
    let msg_id = sent_json["message_id"].as_str().unwrap().to_string();

    // 2. alice@hub replies -> non-leaf origin must use push path (`push_outcome == "pushed"`)
    //    and queue 0 messages in `peer_mailbox`.
    let reply_body = serde_json::json!({
        "text": "Direct pushed reply to non-leaf peer-b",
    })
    .to_string();
    let reply_path = format!("/v1/messages/{msg_id}/replies");
    let (r_status, r_body) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            http_request_unix_within(
                &http_sock,
                "POST",
                &reply_path,
                Some(&reply_body),
                Duration::from_secs(10),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(r_status, StatusCode::OK, "{r_body}");
    let reply_json: Value = serde_json::from_str(&r_body).unwrap();
    assert_eq!(
        reply_json["pushOutcome"], "pushed",
        "non-leaf origin must use push path: {reply_json}"
    );

    {
        let conn = hub.db.lock().unwrap();
        let mailbox_count = xmsg::storage::count_peer_mailbox_messages(&conn, "peer-b").unwrap();
        assert_eq!(
            mailbox_count, 0,
            "non-leaf reply must not be queued into peer_mailbox"
        );
    }

    let mut bob_got_reply = false;
    for _ in 0..50 {
        if bob_rx
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("Direct pushed reply to non-leaf peer-b"))
        {
            bob_got_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        bob_got_reply,
        "bob@peer-b must receive pushed reply over /fed/v2/replies"
    );
}

// =============================================================================
// Leaf reply Oracle (4): The leaf peer's `targets` ceiling still applies to
// queued replies
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leaf_reply_oracle_4_targets_ceiling_applies_to_queued_replies() {
    use xmsg::fed::FedEnvelope;
    use xmsg::storage::Origin;

    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54321".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: Some(vec!["guard".to_string()]),
            dial: None,
        }],
        creds_hub,
    )
    .await;

    let env_disallowed = FedEnvelope {
        attachments: vec![],
        v: xmsg::fed::WIRE_VERSION,
        id: "01M72555555555555555555501".to_string(),
        origin: Origin::service("genie", "hub"),
        to: xmsg::fed::FedTarget {
            r#ref: "other".to_string(),
        },
        body: "Reply to disallowed target".to_string(),
        thread_id: "01M72555555555555555555500".to_string(),
        created_at: xmsg::storage::now_epoch_secs(),
        forwarded: None,
    };
    let disallowed_res = xmsg::fed::queue_leaf_mailbox_reply(
        &hub.fed_state,
        "leaf",
        "other",
        &env_disallowed,
        "genie@hub",
        "01M72555555555555555555500",
    );
    assert!(
        matches!(disallowed_res, Err(AppError::OpDenied(_))),
        "reply to target outside peer targets ceiling must be refused: {disallowed_res:?}"
    );
    {
        let conn = hub.db.lock().unwrap();
        assert_eq!(
            xmsg::storage::count_peer_mailbox_messages(&conn, "leaf").unwrap(),
            0,
            "refused reply must not be queued in peer_mailbox"
        );
    }

    let env_allowed = FedEnvelope {
        attachments: vec![],
        v: xmsg::fed::WIRE_VERSION,
        id: "01M72555555555555555555502".to_string(),
        origin: Origin::service("genie", "hub"),
        to: xmsg::fed::FedTarget {
            r#ref: "guard".to_string(),
        },
        body: "Reply to allowed target".to_string(),
        thread_id: "01M72555555555555555555500".to_string(),
        created_at: xmsg::storage::now_epoch_secs(),
        forwarded: None,
    };
    let allowed_res = xmsg::fed::queue_leaf_mailbox_reply(
        &hub.fed_state,
        "leaf",
        "guard",
        &env_allowed,
        "genie@hub",
        "01M72555555555555555555500",
    );
    assert!(
        allowed_res.is_ok(),
        "reply to target inside peer targets ceiling must succeed: {allowed_res:?}"
    );
    {
        let conn = hub.db.lock().unwrap();
        assert_eq!(
            xmsg::storage::count_peer_mailbox_messages(&conn, "leaf").unwrap(),
            1,
            "allowed reply must be queued in peer_mailbox"
        );
    }
}

// =============================================================================
// Leaf reply Oracle (5): A service reply arrives at the leaf `svc` with
// `origin.service` = the replier's service, by EITHER path (mailbox pull or
// outbound reply poller).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leaf_reply_oracle_5_service_reply_preserves_service_origin_either_path() {
    use xmsg::client::{ClientOptions, RegisteredService};
    use xmsg::storage::Origin;

    // --- Path 5a: Leaf mailbox pull path (no outbound reply poller) ---
    {
        let creds_hub = generate_self_signed_ed25519("hub").unwrap();
        let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

        let hub = create_hub_test_node(
            "hub",
            vec![PeerConfig {
                name: "leaf".to_string(),
                address: "127.0.0.1:54321".to_string(),
                pin: Some(creds_leaf.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
                from: None,
                leaf: true,
                principals: Vec::new(),
                targets: None,
                dial: None,
            }],
            creds_hub.clone(),
        )
        .await;

        let leaf = create_leaf_test_node(
            "leaf",
            vec![PeerConfig {
                name: "hub".to_string(),
                address: hub.fed_addr.to_string(),
                pin: Some(creds_hub.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            }],
            creds_leaf,
            "svc:guard",
        )
        .await;

        let mut genie_hub = register_hub_service(&hub, "genie").await;
        let mut guard_leaf = RegisteredService::register(ClientOptions {
            register_socket: leaf.reg_sock.clone(),
            agent_socket: leaf.agent_sock.clone(),
            max_frame_bytes: 65536,
            operation_timeout: Duration::from_secs(5),
            service: "guard".to_string(),
            expected_node: Some("leaf".to_string()),
            daemon_uid: current_uid(),
        })
        .await
        .unwrap();

        let sent = guard_leaf
            .send("genie@hub", "Hello genie via mailbox path", Some("idem-5a"))
            .await
            .unwrap();
        let hub_delivery = genie_hub
            .poll(10)
            .await
            .unwrap()
            .expect("genie@hub must receive message from guard@leaf");
        assert_eq!(hub_delivery.message_id(), sent.message_id);
        genie_hub.ack(hub_delivery.message_id()).await.unwrap();

        let reply_rec = genie_hub
            .reply(
                hub_delivery.message_id(),
                "Service reply via mailbox pull",
                Some("idem-5a-reply"),
            )
            .await
            .expect("genie@hub reply should succeed");
        let reply_id = reply_rec
            .pushed_message_id
            .expect("reply must carry pushed_message_id");

        let leaf_delivery = guard_leaf
            .poll(10)
            .await
            .unwrap()
            .expect("guard@leaf must receive service reply via mailbox pull");
        assert_eq!(leaf_delivery.message_id(), reply_id);
        assert_eq!(leaf_delivery.in_reply_to(), Some(sent.message_id.as_str()));
        assert_eq!(
            leaf_delivery.origin(),
            &Origin::service("genie", "hub"),
            "mailbox pull path must preserve service attestation on reply origin"
        );
        guard_leaf.ack(leaf_delivery.message_id()).await.unwrap();
    }

    // --- Path 5b: Outbound reply poller path (`spawn_outbound_reply_poller` without mailbox pull) ---
    {
        let creds_hub = generate_self_signed_ed25519("hub").unwrap();
        let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

        let hub = create_hub_test_node(
            "hub",
            vec![PeerConfig {
                name: "leaf".to_string(),
                address: "127.0.0.1:54321".to_string(),
                pin: Some(creds_leaf.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
                from: None,
                leaf: true,
                principals: Vec::new(),
                targets: None,
                dial: None,
            }],
            creds_hub.clone(),
        )
        .await;

        // Create leaf with `spawn_inbox_task = false` so `run_leaf_inbox_task` is NOT
        // spawned, and spawn ONLY `spawn_outbound_reply_poller`.
        let leaf = create_leaf_test_node_opts(
            "leaf",
            vec![PeerConfig {
                name: "hub".to_string(),
                address: hub.fed_addr.to_string(),
                pin: Some(creds_hub.2.clone()),
                ca: None,
                identities: None,
                allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            }],
            creds_leaf,
            "svc:guard",
            false,
        )
        .await;

        let mut genie_hub = register_hub_service(&hub, "genie").await;
        let mut guard_leaf = RegisteredService::register(ClientOptions {
            register_socket: leaf.reg_sock.clone(),
            agent_socket: leaf.agent_sock.clone(),
            max_frame_bytes: 65536,
            operation_timeout: Duration::from_secs(5),
            service: "guard".to_string(),
            expected_node: Some("leaf".to_string()),
            daemon_uid: current_uid(),
        })
        .await
        .unwrap();

        let sent = guard_leaf
            .send("genie@hub", "Hello genie via reply poller", Some("idem-5b"))
            .await
            .unwrap();
        xmsg::fed::spawn_outbound_reply_poller(
            leaf.fed_state.clone(),
            "hub".to_string(),
            sent.message_id.clone(),
        );

        let hub_delivery = genie_hub
            .poll(10)
            .await
            .unwrap()
            .expect("genie@hub must receive message from guard@leaf");
        assert_eq!(hub_delivery.message_id(), sent.message_id);
        genie_hub.ack(hub_delivery.message_id()).await.unwrap();

        let reply_rec = genie_hub
            .reply(
                hub_delivery.message_id(),
                "Service reply via outbound reply poller",
                Some("idem-5b-reply"),
            )
            .await
            .expect("genie@hub reply should succeed");
        let reply_id = reply_rec
            .pushed_message_id
            .expect("reply must carry pushed_message_id");

        let leaf_delivery = guard_leaf
            .poll(10)
            .await
            .unwrap()
            .expect("guard@leaf must receive service reply via outbound reply poller");
        assert_eq!(leaf_delivery.message_id(), reply_id);
        assert_eq!(leaf_delivery.in_reply_to(), Some(sent.message_id.as_str()));
        assert_eq!(
            leaf_delivery.origin(),
            &Origin::service("genie", "hub"),
            "outbound reply poller must preserve service attestation (never synthesize Origin::instance for a service)"
        );
        guard_leaf.ack(leaf_delivery.message_id()).await.unwrap();
    }
}

// =============================================================================
// Leaf reply Oracle (6): Both paths active => exactly one delivery per reply_id,
// with the attested service origin (and the attested-service copy wins over any
// reconstructed one).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leaf_reply_oracle_6_both_paths_deliver_once_with_attested_service_origin() {
    use xmsg::client::{ClientOptions, RegisteredService};
    use xmsg::storage::{Origin, SvcPendingMessage};

    let creds_hub = generate_self_signed_ed25519("hub").unwrap();
    let creds_leaf = generate_self_signed_ed25519("leaf").unwrap();

    let hub = create_hub_test_node(
        "hub",
        vec![PeerConfig {
            name: "leaf".to_string(),
            address: "127.0.0.1:54321".to_string(),
            pin: Some(creds_leaf.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: true,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        creds_hub.clone(),
    )
    .await;

    // Leaf has `dial: Some("outbound")` AND `run_leaf_inbox_task` running concurrently,
    // so sending from the leaf also spawns `spawn_outbound_reply_poller`!
    let leaf = create_leaf_test_node(
        "leaf",
        vec![PeerConfig {
            name: "hub".to_string(),
            address: hub.fed_addr.to_string(),
            pin: Some(creds_hub.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: Some("outbound".to_string()),
        }],
        creds_leaf,
        "svc:guard",
    )
    .await;

    let mut genie_hub = register_hub_service(&hub, "genie").await;
    let mut guard_leaf = RegisteredService::register(ClientOptions {
        register_socket: leaf.reg_sock.clone(),
        agent_socket: leaf.agent_sock.clone(),
        max_frame_bytes: 65536,
        operation_timeout: Duration::from_secs(5),
        service: "guard".to_string(),
        expected_node: Some("leaf".to_string()),
        daemon_uid: current_uid(),
    })
    .await
    .unwrap();

    // 1. Live race: both `run_leaf_inbox_task` and `spawn_outbound_reply_poller` active
    let sent = guard_leaf
        .send(
            "genie@hub",
            "Hello genie with both paths active",
            Some("idem-6a"),
        )
        .await
        .unwrap();

    let hub_delivery = genie_hub
        .poll(10)
        .await
        .unwrap()
        .expect("genie@hub must receive message");
    genie_hub.ack(hub_delivery.message_id()).await.unwrap();

    let reply_rec = genie_hub
        .reply(
            hub_delivery.message_id(),
            "Reply delivered with both paths active",
            Some("idem-6a-reply"),
        )
        .await
        .unwrap();
    let reply_id = reply_rec.pushed_message_id.unwrap();

    // Let both `run_leaf_inbox_task` and `spawn_outbound_reply_poller` run before polling
    tokio::time::sleep(Duration::from_millis(750)).await;

    let delivery = guard_leaf
        .poll(5)
        .await
        .unwrap()
        .expect("guard@leaf must receive reply");
    assert_eq!(delivery.message_id(), reply_id);
    assert_eq!(delivery.in_reply_to(), Some(sent.message_id.as_str()));
    assert_eq!(
        delivery.origin(),
        &Origin::service("genie", "hub"),
        "attested service origin must be delivered when both paths are active"
    );
    guard_leaf.ack(delivery.message_id()).await.unwrap();

    // Verify no second copy is delivered on subsequent poll
    let extra = guard_leaf.poll(1).await.unwrap();
    assert!(
        extra.is_none(),
        "same reply_id must be delivered exactly once when both paths are active, got extra: {extra:?}"
    );

    // 2. Forced-order verification for both arrival orders of a reconstructed instance
    //    origin vs an attested service origin for the same `reply_id`:
    //    Order A: reconstructed `Origin::instance("genie", "hub", None)` arrives FIRST,
    //             attested `Origin::service("genie", "hub")` arrives SECOND -> service wins, 1 delivery.
    //    Order B: attested `Origin::service("genie", "hub")` arrives FIRST,
    //             reconstructed `Origin::instance("genie", "hub", None)` arrives SECOND -> service wins, 1 delivery.
    for (idx, first_is_service) in [(1_u32, false), (2_u32, true)] {
        let race_id = format!("01M7266666666666666666660{idx}");
        let reconstructed = SvcPendingMessage {
            id: race_id.clone(),
            session_id: "guard".to_string(),
            created_at: xmsg::storage::now_epoch_secs(),
            from_name: "genie@hub".to_string(),
            bytes: 11,
            text: "race-check".to_string(),
            envelope: format!("[xmsg] reply from=genie@hub message_id={race_id}\n\nrace-check"),
            delivered_at: None,
            origin: Origin::instance("genie", "hub", None),
            in_reply_to: Some(sent.message_id.clone()),
        };
        let attested = SvcPendingMessage {
            origin: Origin::service("genie", "hub"),
            ..reconstructed.clone()
        };

        {
            let conn = leaf.db.lock().unwrap();
            if first_is_service {
                assert!(xmsg::storage::insert_svc_message_with_cap(&conn, &attested, 64).unwrap());
                assert!(
                    xmsg::storage::insert_svc_message_with_cap(&conn, &reconstructed, 64).unwrap()
                );
            } else {
                assert!(
                    xmsg::storage::insert_svc_message_with_cap(&conn, &reconstructed, 64).unwrap()
                );
                assert!(xmsg::storage::insert_svc_message_with_cap(&conn, &attested, 64).unwrap());
            }
        }

        let d = guard_leaf
            .poll(5)
            .await
            .unwrap()
            .expect("forced-race reply must be delivered once");
        assert_eq!(d.message_id(), race_id);
        assert_eq!(
            d.origin(),
            &Origin::service("genie", "hub"),
            "attested service origin must win in arrival order first_is_service={first_is_service}"
        );
        guard_leaf.ack(d.message_id()).await.unwrap();

        let dup = guard_leaf.poll(0).await.unwrap();
        assert!(
            dup.is_none(),
            "forced-race reply {race_id} must not be delivered twice: {dup:?}"
        );
    }
}
