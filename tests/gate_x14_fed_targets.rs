use serde_json::Value;
use std::collections::HashMap;
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

use xmsg::agent::{current_uid, run_agent_server};
use xmsg::agy::{new_agy_store, run_register_server, AgyConfig};
use xmsg::error::AppError;
use xmsg::fed::{
    generate_self_signed_ed25519, run_fed_listener, send_federated_message, FedEnvelope,
    FedPrincipal, FedState, FedTarget, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::AppState;
use xmsg::pi::new_pi_store;
use xmsg::storage;
use xmsg::svc::new_svc_store;

fn setup_mock_proc(proc_root: &Path, pid: u32, exe_target: &Path, starttime: &str) {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();

    let exe_link = pid_dir.join("exe");
    let _ = fs::remove_file(&exe_link);
    std::os::unix::fs::symlink(exe_target, &exe_link).unwrap();

    let stat_content =
        format!("{pid} (svc_test) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).unwrap();
}

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

#[allow(dead_code)]
struct FedTestNode {
    name: String,
    fed_addr: std::net::SocketAddr,
    agent_sock: PathBuf,
    reg_sock: PathBuf,
    fed_state: Arc<FedState>,
    db: Arc<Mutex<rusqlite::Connection>>,
    sessions_dir: PathBuf,
    _temp: TempDir,
}

async fn create_fed_test_node(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: (Vec<u8>, Vec<u8>, String),
    trusted_svc_exes: Vec<String>,
    listener_opt: Option<TcpListener>,
    rate_limiter_opt: Option<Arc<RateLimiter>>,
) -> FedTestNode {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_sock = sock_dir.join("agent.sock");
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

    let trusted_bin = temp.path().join("trusted_dispatcher");
    fs::write(&trusted_bin, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&trusted_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let mut trusted_svc_map: HashMap<String, PathBuf> = HashMap::new();
    for svc in &trusted_svc_exes {
        trusted_svc_map.insert(svc.clone(), trusted_bin.clone());
    }

    let my_pid = std::process::id();
    let live_proc = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&live_proc, my_pid).unwrap_or_else(|_| "1000".to_string());
    setup_mock_proc(&proc_root, my_pid, &trusted_bin, &my_proc_start);

    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": format!("sess-{name}"),
        "name": format!("agent-{name}"),
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": "/tmp/dummy.sock"
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}.json")),
        session_json.to_string(),
    )
    .unwrap();

    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));

    let mut peers_map = HashMap::new();
    for p in peers {
        peers_map.insert(p.name.clone(), p);
    }
    let peers_arc = Arc::new(PeersMap::new(peers_map));

    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

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
    let svc_store = new_svc_store();

    let (cert_der, key_der, _pin) = creds;

    let rate_limiter = rate_limiter_opt.unwrap_or_else(|| Arc::new(RateLimiter::new(60, 20)));

    let fed_state = Arc::new(FedState {
        host_label: name.to_string(),
        peers: peers_arc,
        cert_der,
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

    let reg_config = agy_config.clone();
    let reg_store = agy_store.clone();
    let reg_pi_store = pi_store.clone();
    let reg_svc_store = svc_store.clone();
    let reg_trusted_svc = trusted_svc_map;
    let r_sock = reg_sock.clone();
    let reg_db = db.clone();
    let reg_pi_notify = pi_notify_tx.clone();
    let reg_svc_notify = svc_notify_tx.clone();

    tokio::spawn(async move {
        let _ = run_register_server(
            r_sock,
            reg_config,
            reg_store,
            reg_pi_store,
            reg_db,
            reg_pi_notify,
            Duration::from_secs(3600),
            my_uid,
            reg_svc_store,
            reg_trusted_svc,
            reg_svc_notify,
        )
        .await;
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

    for _ in 0..50 {
        if reg_sock.exists() && agent_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    FedTestNode {
        name: name.to_string(),
        fed_addr,
        agent_sock,
        reg_sock,
        fed_state,
        db,
        sessions_dir,
        _temp: temp,
    }
}

fn create_claude_session_fixture(
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

// =============================================================================
// Oracle 1: A peer with targets = ["svc:genie-expert"] can deliver to svc:genie-expert.
// Mutant: refuse all => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_peer_with_targets_delivers_to_allowed_target() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: creds_b.2.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec![],
        None,
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: node_a.fed_addr.to_string(),
            pin: creds_a.2.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: Some(vec!["svc:genie-expert".to_string()]),
        }],
        creds_b,
        vec!["genie-expert".to_string()],
        Some(b_listener),
        None,
    )
    .await;

    // 1. Register daemon as svc:genie-expert on node_b
    let (mut daemon_reader, mut daemon_writer) = connect_svc(&node_b.reg_sock).await;
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "genie-expert",
        "cwd": "/workspace"
    });
    daemon_writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut daemon_reader).await;
    assert_eq!(reg_resp.get("status").and_then(|s| s.as_str()), Some("ok"));

    // 2. Node A sends to svc:genie-expert@host-b via agent.sock
    let stream_a = UnixStream::connect(&node_a.agent_sock).await.unwrap();
    let (reader_a, mut writer_a) = stream_a.into_split();
    let mut reader_a = BufReader::new(reader_a);

    let send_req = serde_json::json!({
        "action": "send",
        "ref": "svc:genie-expert@host-b",
        "text": "expert task 1",
    });
    writer_a
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();

    let mut send_resp_line = String::new();
    reader_a.read_line(&mut send_resp_line).await.unwrap();
    let send_resp: Value = serde_json::from_str(&send_resp_line).unwrap();
    assert_eq!(
        send_resp.get("status").and_then(|s| s.as_str()),
        Some("ok"),
        "send_resp: {:?}",
        send_resp
    );
    assert_eq!(
        send_resp
            .get("delivery")
            .and_then(|d| d.get("outcome"))
            .and_then(|o| o.as_str()),
        Some("delivered")
    );

    // 3. Verify daemon received the message
    let poll_req = serde_json::json!({
        "action": "poll",
        "waitSecs": 5
    });
    daemon_writer
        .write_all(format!("{poll_req}\n").as_bytes())
        .await
        .unwrap();

    let deliver_frame = read_json_line(&mut daemon_reader).await;
    assert_eq!(
        deliver_frame.get("action").and_then(|s| s.as_str()),
        Some("deliver")
    );
    assert_eq!(
        deliver_frame.get("text").and_then(|s| s.as_str()),
        Some("expert task 1")
    );
}

// =============================================================================
// Oracle 2: The same peer sending to another svc daemon, or to a Claude session,
// is refused with OpDenied, and nothing is queued.
// Mutant: ignore targets => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_peer_with_targets_refused_for_other_svc_and_claude_session() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: creds_b.2.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec![],
        None,
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: node_a.fed_addr.to_string(),
            pin: creds_a.2.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: Some(vec!["svc:genie-expert".to_string()]),
        }],
        creds_b,
        vec!["other-worker".to_string()],
        Some(b_listener),
        None,
    )
    .await;

    // 1. Register daemon as svc:other-worker on node_b
    let (mut daemon_reader, mut daemon_writer) = connect_svc(&node_b.reg_sock).await;
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "other-worker",
        "cwd": "/workspace"
    });
    daemon_writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut daemon_reader).await;
    assert_eq!(reg_resp.get("status").and_then(|s| s.as_str()), Some("ok"));

    // 2. Create Claude session on node_b
    let (_inbox_sock, claude_inbox) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-claude", "agent-claude");

    // 3. Node A attempts to send to svc:other-worker@host-b => refused with OpDenied
    let stream_a = UnixStream::connect(&node_a.agent_sock).await.unwrap();
    let (reader_a, mut writer_a) = stream_a.into_split();
    let mut reader_a = BufReader::new(reader_a);

    let send_req1 = serde_json::json!({
        "action": "send",
        "ref": "svc:other-worker@host-b",
        "text": "unauthorized svc payload",
    });
    writer_a
        .write_all(format!("{send_req1}\n").as_bytes())
        .await
        .unwrap();

    let mut send_resp_line1 = String::new();
    reader_a.read_line(&mut send_resp_line1).await.unwrap();
    let send_resp1: Value = serde_json::from_str(&send_resp_line1).unwrap();
    assert_eq!(
        send_resp1.get("status").and_then(|s| s.as_str()),
        Some("error")
    );
    assert_eq!(
        send_resp1.get("error").and_then(|s| s.as_str()),
        Some("op_denied")
    );
    assert_eq!(
        send_resp1.get("detail").and_then(|s| s.as_str()),
        Some("target not allowed for peer")
    );

    // Verify nothing queued for svc:other-worker
    {
        let db = node_b.db.lock().unwrap();
        let pending_svc_count =
            storage::count_pending_svc_messages(&db, "svc:other-worker").unwrap();
        assert_eq!(
            pending_svc_count, 0,
            "no messages should be queued for other-worker"
        );
    }

    // 4. Node A attempts to send to agent-claude@host-b => refused with OpDenied
    let send_req2 = serde_json::json!({
        "action": "send",
        "ref": "agent-claude@host-b",
        "text": "unauthorized claude payload",
    });
    writer_a
        .write_all(format!("{send_req2}\n").as_bytes())
        .await
        .unwrap();

    let mut send_resp_line2 = String::new();
    reader_a.read_line(&mut send_resp_line2).await.unwrap();
    let send_resp2: Value = serde_json::from_str(&send_resp_line2).unwrap();
    assert_eq!(
        send_resp2.get("status").and_then(|s| s.as_str()),
        Some("error")
    );
    assert_eq!(
        send_resp2.get("error").and_then(|s| s.as_str()),
        Some("op_denied")
    );
    assert_eq!(
        send_resp2.get("detail").and_then(|s| s.as_str()),
        Some("target not allowed for peer")
    );

    // Verify nothing delivered to Claude inbox
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        claude_inbox.lock().unwrap().is_empty(),
        "no messages should be delivered to claude inbox"
    );
}

// =============================================================================
// Oracle 3: A peer without targets keeps today's behaviour (reaches a session and a svc).
// Mutant: treat absent as empty => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_peer_without_targets_reaches_session_and_svc() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: creds_b.2.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec![],
        None,
        None,
    )
    .await;

    // Node B peer host-a has targets: None (absent list)
    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: node_a.fed_addr.to_string(),
            pin: creds_a.2.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_b,
        vec!["my-daemon".to_string()],
        Some(b_listener),
        None,
    )
    .await;

    // 1. Register svc:my-daemon
    let (mut daemon_reader, mut daemon_writer) = connect_svc(&node_b.reg_sock).await;
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "my-daemon",
        "cwd": "/workspace"
    });
    daemon_writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut daemon_reader).await;
    assert_eq!(reg_resp.get("status").and_then(|s| s.as_str()), Some("ok"));

    // 2. Create Claude session on node_b
    let (_inbox_sock, claude_inbox) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-claude", "agent-claude");

    // 3. Node A sends to svc:my-daemon@host-b => succeeds
    let stream_a = UnixStream::connect(&node_a.agent_sock).await.unwrap();
    let (reader_a, mut writer_a) = stream_a.into_split();
    let mut reader_a = BufReader::new(reader_a);

    let send_req1 = serde_json::json!({
        "action": "send",
        "ref": "svc:my-daemon@host-b",
        "text": "payload for daemon",
    });
    writer_a
        .write_all(format!("{send_req1}\n").as_bytes())
        .await
        .unwrap();

    let mut send_resp_line1 = String::new();
    reader_a.read_line(&mut send_resp_line1).await.unwrap();
    let send_resp1: Value = serde_json::from_str(&send_resp_line1).unwrap();
    assert_eq!(
        send_resp1.get("status").and_then(|s| s.as_str()),
        Some("ok"),
        "send_resp1: {:?}",
        send_resp1
    );

    let poll_req = serde_json::json!({
        "action": "poll",
        "waitSecs": 5
    });
    daemon_writer
        .write_all(format!("{poll_req}\n").as_bytes())
        .await
        .unwrap();

    let deliver_frame = read_json_line(&mut daemon_reader).await;
    assert_eq!(
        deliver_frame.get("action").and_then(|s| s.as_str()),
        Some("deliver")
    );
    assert_eq!(
        deliver_frame.get("text").and_then(|s| s.as_str()),
        Some("payload for daemon")
    );

    // 4. Node A sends to agent-claude@host-b => succeeds
    let send_req2 = serde_json::json!({
        "action": "send",
        "ref": "agent-claude@host-b",
        "text": "payload for claude",
    });
    writer_a
        .write_all(format!("{send_req2}\n").as_bytes())
        .await
        .unwrap();

    let mut send_resp_line2 = String::new();
    reader_a.read_line(&mut send_resp_line2).await.unwrap();
    let send_resp2: Value = serde_json::from_str(&send_resp_line2).unwrap();
    assert_eq!(
        send_resp2.get("status").and_then(|s| s.as_str()),
        Some("ok"),
        "send_resp2: {:?}",
        send_resp2
    );

    // Check delivered to Claude socket
    for _ in 0..50 {
        if !claude_inbox.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let inbox_content = claude_inbox.lock().unwrap();
    assert_eq!(inbox_content.len(), 1);
    assert!(inbox_content[0].contains("payload for claude"));
}

// =============================================================================
// Oracle 4: A refused target does not consume the rate-limit budget or create a stored message.
// Mutant: check after queueing => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_refused_target_does_not_consume_rate_limit_or_create_stored_message() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: creds_b.2.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec![],
        None,
        None,
    )
    .await;

    // Node B rate limiter: strictly 1 message capacity per 60 seconds (burst 1, refill 1/60)
    let strict_rate_limiter = Arc::new(RateLimiter::new(1, 1));

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: node_a.fed_addr.to_string(),
            pin: creds_a.2.clone(),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: Some(vec!["svc:genie-expert".to_string()]),
        }],
        creds_b,
        vec!["genie-expert".to_string(), "other-worker".to_string()],
        Some(b_listener),
        Some(strict_rate_limiter),
    )
    .await;

    // Register both daemons on node_b
    let (_expert_reader, mut expert_writer) = connect_svc(&node_b.reg_sock).await;
    expert_writer
        .write_all(
            format!(
                "{}\n",
                serde_json::json!({
                    "harness": "svc",
                    "name": "genie-expert",
                    "cwd": "/workspace"
                })
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let (_other_reader, mut other_writer) = connect_svc(&node_b.reg_sock).await;
    other_writer
        .write_all(
            format!(
                "{}\n",
                serde_json::json!({
                    "harness": "svc",
                    "name": "other-worker",
                    "cwd": "/workspace"
                })
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    // 1. Send to refused target directly via send_federated_message with known ID
    let refused_id = "01REFUSED_MSG_ID_ORACLE4";
    let envelope_refused = FedEnvelope {
        v: 1,
        id: refused_id.to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "sess-sender".to_string(),
            name: "sender-a".to_string(),
        },
        to: FedTarget {
            r#ref: "svc:other-worker".to_string(),
        },
        body: "Payload for refused target".to_string(),
        push_replies: false,
        thread_id: refused_id.to_string(),
        created_at: storage::now_epoch_secs(),
    };

    let res_refused = send_federated_message(&node_a.fed_state, "host-b", &envelope_refused).await;
    match res_refused {
        Err(AppError::OpDenied(d)) => assert_eq!(d, "target not allowed for peer"),
        other => panic!("expected OpDenied, got {:?}", other),
    }

    // Assert: refused target DID NOT create a stored message in node_b's DB
    {
        let db = node_b.db.lock().unwrap();
        let stored_refused = storage::get_message(&db, refused_id).unwrap();
        assert!(
            stored_refused.is_none(),
            "refused message must NOT be stored in the messages table"
        );
        let queued_other = storage::count_pending_svc_messages(&db, "svc:other-worker").unwrap();
        assert_eq!(
            queued_other, 0,
            "refused message must NOT be queued in svc_pending_messages"
        );
    }

    // 2. Send to allowed target: must succeed!
    // If the refused send had consumed the 1-capacity rate limit budget, this would return RateLimited.
    let allowed_id = "01ALLOWED_MSG_ID_ORACLE4";
    let envelope_allowed = FedEnvelope {
        v: 1,
        id: allowed_id.to_string(),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "sess-sender".to_string(),
            name: "sender-a".to_string(),
        },
        to: FedTarget {
            r#ref: "svc:genie-expert".to_string(),
        },
        body: "Payload for allowed target".to_string(),
        push_replies: false,
        thread_id: allowed_id.to_string(),
        created_at: storage::now_epoch_secs(),
    };

    let res_allowed = send_federated_message(&node_a.fed_state, "host-b", &envelope_allowed).await;
    assert!(
        res_allowed.is_ok(),
        "allowed message must succeed; if rate limit was consumed by refused target, this would fail with RateLimited: {:?}",
        res_allowed
    );

    // Assert: allowed message IS stored in DB with delivered outcome
    let db = node_b.db.lock().unwrap();
    let stored_allowed = storage::get_message(&db, allowed_id).unwrap();
    assert!(
        stored_allowed.is_some(),
        "allowed message must be stored in the messages table"
    );
    assert_eq!(stored_allowed.as_ref().unwrap().outcome, "delivered");

    // And refused message is STILL not in store
    assert!(storage::get_message(&db, refused_id).unwrap().is_none());
}
