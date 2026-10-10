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
use xmsg::http::{bind_ucred_unix_listener, build_router, http_request_unix, AppState};
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
    let sock_path = sessions_dir.join(format!("inbox-{session_id}.sock"));
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

    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": session_id,
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
        "ref": target_ref,
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
        host_label: name.to_string(),
        peers: peers_arc,
        cert_der,
        cert_chain_der: Vec::new(),
        key_der,
        rate_limiter,
        db: db.clone(),
        sessions_dir: sessions_dir.clone(),
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
    });

    let fed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fed_addr = fed_listener.local_addr().unwrap();
    let fs_clone = fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(fed_listener, fs_clone).await;
    });

    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config,
        agy_store,
        pi_store,
        pi_notify_tx,
        svc_store: svc_store.clone(),
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

    let s_path = agent_sock.clone();
    let s_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    let http_router = build_router(app_state);
    let ucred_listener = bind_ucred_unix_listener(&http_sock, my_uid, None).unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(ucred_listener, http_router).await;
    });

    for _ in 0..50 {
        if http_sock.exists() && agent_sock.exists() {
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
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let reg_sock = sock_dir.join("register.sock");

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
        host_label: name.to_string(),
        peers: peers_arc.clone(),
        cert_der,
        cert_chain_der: Vec::new(),
        key_der,
        rate_limiter,
        db: db.clone(),
        sessions_dir: sessions_dir.clone(),
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
    });

    let r_sock = reg_sock.clone();
    let r_proc = proc_root.clone();
    let r_store = svc_store.clone();
    let r_db = db.clone();
    let r_notify = svc_notify_tx.clone();
    let r_p = leaf_principal.to_string();
    let r_fs = fed_state.clone();

    tokio::spawn(async move {
        let _ = run_leaf_register_server(
            r_sock,
            r_proc,
            r_store,
            my_uid,
            r_db,
            r_notify,
            Duration::from_secs(3600),
            r_p,
            Some(r_fs),
        )
        .await;
    });

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

    for _ in 0..50 {
        if reg_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    LeafTestNode {
        name: name.to_string(),
        reg_sock,
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
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, claude_rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // 1. Send from hub to svc:guard@leaf via agent.sock
    let resp =
        send_via_agent_sock(&hub.agent_sock, "svc:guard@leaf", "Task request for guard").await;
    assert_eq!(resp["status"], "ok", "Send should succeed: {resp}");
    assert_eq!(resp["delivery"]["outcome"], "queued");
    let msg_id = resp["delivery"]["messageId"].as_str().unwrap().to_string();

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
    assert_eq!(reg_resp["sessionId"], "svc:guard");

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
            assert!(line.contains("xmsg@leaf · svc:guard"));
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
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, _rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // 1. Send from hub to svc:guard@leaf
    let send_body = serde_json::json!({
        "from": "alice",
        "text": "Unacked task",
    })
    .to_string();

    let (status, resp_body) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            http_request_unix(
                &http_sock,
                "POST",
                "/v1/sessions/svc:guard@leaf/messages",
                Some(&send_body),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();

    assert_eq!(status, StatusCode::ACCEPTED);
    let resp: Value = serde_json::from_str(&resp_body).unwrap();
    let msg_id = resp["messageId"].as_str().unwrap().to_string();

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
    assert_eq!(resp2["sessionId"], "svc:guard");
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
            let body = serde_json::json!({ "from": "alice", "text": "M1 for leaf1" }).to_string();
            http_request_unix(
                &http_sock,
                "POST",
                "/v1/sessions/svc:guard@leaf1/messages",
                Some(&body),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(status1, StatusCode::ACCEPTED);
    let msg1_id = serde_json::from_str::<Value>(&resp1).unwrap()["messageId"]
        .as_str()
        .unwrap()
        .to_string();

    // Queue message M2 for leaf2 (both targeting svc:guard)
    let (status2, resp2) = tokio::task::spawn_blocking({
        let http_sock = hub.http_sock.clone();
        move || {
            let body = serde_json::json!({ "from": "alice", "text": "M2 for leaf2" }).to_string();
            http_request_unix(
                &http_sock,
                "POST",
                "/v1/sessions/svc:guard@leaf2/messages",
                Some(&body),
            )
            .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(status2, StatusCode::ACCEPTED);
    let msg2_id = serde_json::from_str::<Value>(&resp2).unwrap()["messageId"]
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
        })
        .unwrap();

    let leaf1_fed_state = FedState {
        host_label: "leaf1".to_string(),
        peers: Arc::new(leaf1_peers),
        cert_der: creds_leaf1.0,
        cert_chain_der: Vec::new(),
        key_der: creds_leaf1.1,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: hub.db.clone(),
        sessions_dir: PathBuf::new(),
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
    };

    // Leaf 1 polls inbox: gets M1
    let poll1 = xmsg::fed::get_federated_inbox(&leaf1_fed_state, "hub", 0)
        .await
        .unwrap();
    assert!(poll1.is_some());
    let m = poll1.unwrap();
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
        Err(AppError::NotFound(_)) => {}
        other => panic!("Acking another peer's mailbox id must return NotFound, got: {other:?}"),
    }

    // Non-leaf peer attempts to poll /fed/v1/inbox: must return 403 OpDenied
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
        })
        .unwrap();

    let nonleaf_fed_state = FedState {
        host_label: "nonleaf".to_string(),
        peers: Arc::new(nonleaf_peers),
        cert_der: creds_nonleaf.0,
        cert_chain_der: Vec::new(),
        key_der: creds_nonleaf.1,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: hub.db.clone(),
        sessions_dir: PathBuf::new(),
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
    };

    let poll_nonleaf = xmsg::fed::get_federated_inbox(&nonleaf_fed_state, "hub", 0).await;
    match poll_nonleaf {
        Err(AppError::OpDenied(_)) => {}
        other => panic!("Non-leaf polling /fed/v1/inbox must return OpDenied, got: {other:?}"),
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
            targets: Some(vec!["svc:guard".to_string()]),
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
            let body = serde_json::json!({ "from": "alice", "text": "Disallowed" }).to_string();
            http_request_unix(
                &http_sock,
                "POST",
                "/v1/sessions/svc:other@leaf/messages",
                Some(&body),
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
            let body = serde_json::json!({ "from": "alice", "text": "Allowed" }).to_string();
            http_request_unix(
                &http_sock,
                "POST",
                "/v1/sessions/svc:guard@leaf/messages",
                Some(&body),
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
        }],
        creds_leaf.clone(),
        "svc:guard",
    )
    .await;

    let (_sock, _rx) =
        create_claude_session_fixture(&hub.proc_root, &hub.sessions_dir, "sess-alice", "alice");

    // Send from hub via agent.sock
    let resp = send_via_agent_sock(
        &hub.agent_sock,
        "svc:guard@leaf",
        "Message with principal test",
    )
    .await;
    assert_eq!(resp["status"], "ok", "Send should succeed: {resp}");
    assert_eq!(resp["delivery"]["outcome"], "queued");

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

    // Invariant: origin must carry kind: fed, host: hub, and principal: claude:alice
    let origin = &deliver_resp["origin"];
    assert_eq!(origin["kind"], "fed");
    assert_eq!(origin["host"], "hub");
    assert_eq!(
        origin["principal"], "claude:alice",
        "Delivered origin must carry sender's badge in principal field"
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
