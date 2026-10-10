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

use axum::http::StatusCode;
use serde_json::Value;

use xmsg::agent::{current_uid, run_agent_server};
use xmsg::agy::{new_agy_store, run_register_server, AgyConfig};
use xmsg::error::AppError;
use xmsg::fed::{
    generate_self_signed_ed25519, list_federated_sessions, run_fed_listener, FedState, PeerConfig,
    PeersMap, RateLimiter,
};
use xmsg::http::{bind_ucred_unix_listener, build_router, http_get_unix, AppState};
use xmsg::mcp::{execute_tool, McpConfig};
use xmsg::pi::new_pi_store;
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
    http_sock: PathBuf,
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

    let my_uid = current_uid();

    let agy_config = AgyConfig {
        presence_dir: presence_dir.clone(),
        proc_locks_path: proc_locks.clone(),
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
    let rate_limiter = rate_limiter_opt.unwrap_or_else(|| Arc::new(RateLimiter::new(60, 20)));

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

    let ucred_listener = bind_ucred_unix_listener(&http_sock, my_uid, None).unwrap();
    let router = build_router(app_state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(ucred_listener, router.into_make_service()).await;
    });

    for _ in 0..50 {
        if reg_sock.exists() && agent_sock.exists() && http_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    FedTestNode {
        name: name.to_string(),
        fed_addr,
        agent_sock,
        reg_sock,
        http_sock,
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
// Oracle 1: Peer B with allow: ["list"] lists A and gets A's sessions, each ref of form <id>@A.
// Mutant: route refuses all => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_peer_with_list_allowed() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: Some(creds_b.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec!["genie-expert".to_string()],
        Some(a_listener),
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: a_addr.to_string(),
            pin: Some(creds_a.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string(), "send".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_b,
        vec![],
        Some(b_listener),
        None,
    )
    .await;

    // Create a Claude session and a Svc daemon on Node A
    let (_sock, _rx) = create_claude_session_fixture(&node_a.sessions_dir, "sess-a", "agent-a");

    let (mut daemon_reader, mut daemon_writer) = connect_svc(&node_a.reg_sock).await;
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
    assert_eq!(reg_resp["status"], "ok");

    // Node B queries local /v1/sessions?peer=host-a over http.sock
    let (status, body) = http_get_unix(&node_b.http_sock, "/v1/sessions?peer=host-a").unwrap();
    assert_eq!(status, StatusCode::OK, "Body: {body}");

    let sessions: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert!(
        sessions.len() >= 2,
        "Expected at least 2 sessions from host-a, got {sessions:?}"
    );

    let claude_sess = sessions
        .iter()
        .find(|s| s["sessionId"] == "sess-a")
        .expect("sess-a found");
    assert_eq!(claude_sess["ref"], "sess-a@host-a");
    assert_eq!(claude_sess["harness"], "claude");

    let svc_sess = sessions
        .iter()
        .find(|s| s["name"] == "genie-expert" || s["sessionId"] == "svc:genie-expert")
        .expect("svc daemon found");
    let svc_id = svc_sess["sessionId"].as_str().unwrap();
    assert_eq!(svc_sess["ref"], format!("{svc_id}@host-a"));
}

// =============================================================================
// Oracle 2: Peer B without "list" in allow gets 403 op_denied and no entries.
// Mutant: skip the allow check => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_peer_without_list_allowed_403() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: Some(creds_b.2.clone()),
            ca: None,
            identities: None,
            // Only send and reply, NO "list"
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec![],
        Some(a_listener),
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: a_addr.to_string(),
            pin: Some(creds_a.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_b,
        vec![],
        Some(b_listener),
        None,
    )
    .await;

    // Create session on Node A
    let (_sock, _rx) = create_claude_session_fixture(&node_a.sessions_dir, "sess-a", "agent-a");

    // Node B queries /v1/sessions?peer=host-a
    let (status, body) = http_get_unix(&node_b.http_sock, "/v1/sessions?peer=host-a").unwrap();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Expected 403, got {status} with body: {body}"
    );

    let err: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(err["error"], "op_denied");
    let detail = err["detail"].as_str().unwrap();
    assert!(
        detail.contains("host-a") || detail.contains("list operation not allowed"),
        "Detail must name peer or indicate op denied: {detail}"
    );
}

// =============================================================================
// Oracle 3: Peer B with targets = ["svc:genie-expert"] sees only svc:genie-expert, not A's Claude session.
// Mutant: ignore targets on list => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_peer_with_targets() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: Some(creds_b.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: Some(vec!["svc:genie-expert".to_string()]),
        }],
        creds_a.clone(),
        vec!["genie-expert".to_string()],
        Some(a_listener),
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: a_addr.to_string(),
            pin: Some(creds_a.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_b,
        vec![],
        Some(b_listener),
        None,
    )
    .await;

    // Create Claude session AND svc daemon on Node A
    let (_sock, _rx) = create_claude_session_fixture(&node_a.sessions_dir, "sess-a", "agent-a");

    let (mut daemon_reader, mut daemon_writer) = connect_svc(&node_a.reg_sock).await;
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
    assert_eq!(reg_resp["status"], "ok");

    // Node B queries /v1/sessions?peer=host-a
    let (status, body) = http_get_unix(&node_b.http_sock, "/v1/sessions?peer=host-a").unwrap();
    assert_eq!(status, StatusCode::OK, "Body: {body}");

    let sessions: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(
        sessions.len(),
        1,
        "Expected exactly 1 filtered session, got: {sessions:?}"
    );

    let sess = &sessions[0];
    assert!(
        sess["name"] == "genie-expert" || sess["sessionId"] == "svc:genie-expert",
        "Expected svc:genie-expert, got {sess:?}"
    );
    assert_ne!(
        sess["sessionId"], "sess-a",
        "Claude session sess-a must be excluded by targets filter"
    );
}

// =============================================================================
// Oracle 4: No entry carries cwd or pid (assert the key set exactly).
// Mutant: return the local /v1/sessions entries unchanged => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_no_cwd_or_pid() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: Some(creds_b.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec!["genie-expert".to_string()],
        Some(a_listener),
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: a_addr.to_string(),
            pin: Some(creds_a.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_b,
        vec![],
        Some(b_listener),
        None,
    )
    .await;

    // Create session on Node A
    let (_sock, _rx) = create_claude_session_fixture(&node_a.sessions_dir, "sess-a", "agent-a");

    // Check direct /fed/v1/sessions output first
    let wire_entries = list_federated_sessions(&node_b.fed_state, "host-a")
        .await
        .unwrap();
    assert!(!wire_entries.is_empty());

    // Check via client route /v1/sessions?peer=host-a
    let (status, body) = http_get_unix(&node_b.http_sock, "/v1/sessions?peer=host-a").unwrap();
    assert_eq!(status, StatusCode::OK);

    let val: Value = serde_json::from_str(&body).unwrap();
    let arr = val.as_array().expect("array of sessions");
    assert!(!arr.is_empty());

    for entry in arr {
        let obj = entry.as_object().expect("session entry object");

        // Assert forbidden fields are absent
        assert!(
            !obj.contains_key("cwd"),
            "entry must NOT contain cwd: {entry:?}"
        );
        assert!(
            !obj.contains_key("pid"),
            "entry must NOT contain pid: {entry:?}"
        );
        assert!(
            !obj.contains_key("startedAt"),
            "entry must NOT contain startedAt: {entry:?}"
        );
        assert!(
            !obj.contains_key("updatedAt"),
            "entry must NOT contain updatedAt: {entry:?}"
        );
        assert!(
            !obj.contains_key("entrypoint"),
            "entry must NOT contain entrypoint: {entry:?}"
        );
        assert!(
            !obj.contains_key("version"),
            "entry must NOT contain version: {entry:?}"
        );
        assert!(
            !obj.contains_key("registered"),
            "entry must NOT contain registered: {entry:?}"
        );

        // Assert exact key set on client route: {"harness", "kind", "name", "ref", "sessionId", "status"}
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["harness", "kind", "name", "ref", "sessionId", "status"],
            "exact key set mismatch on entry: {entry:?}"
        );
    }
}

// =============================================================================
// Oracle 5: MCP list with host set returns remote entries; without host, local list byte-for-byte as before.
// Mutant: ignore host => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_mcp_list_host() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: Some(creds_b.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec![],
        Some(a_listener),
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: a_addr.to_string(),
            pin: Some(creds_a.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_b,
        vec![],
        Some(b_listener),
        None,
    )
    .await;

    // Node A has sess-a
    let (_sock_a, _rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "sess-a", "agent-a");
    // Node B has sess-b
    let (_sock_b, _rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "sess-b", "agent-b");

    let mcp_cfg = McpConfig {
        sessions_dirs: vec![node_b.sessions_dir.clone()],
        xmsg_url: "http://127.0.0.1:0".to_string(),
        http_sock: Some(node_b.http_sock.clone()),
        agent_sock: node_b.agent_sock.clone(),
        proc_root: node_b._temp.path().join("proc"),
        presence_dir: node_b._temp.path().join("presence"),
        proc_locks_path: node_b._temp.path().join("proc_locks"),
        reply_only: false,
    };

    let mcp_cfg_clone = mcp_cfg.clone();
    let (remote_call, local_call) = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::new();
        let remote = execute_tool(
            &mcp_cfg_clone,
            &client,
            "list",
            &serde_json::json!({ "host": "host-a" }),
        );
        let local = execute_tool(&mcp_cfg_clone, &client, "list", &serde_json::json!({}));
        (remote, local)
    })
    .await
    .unwrap();

    // 1. MCP list with host set to "host-a": must return remote entries (sess-a@host-a)
    assert_eq!(remote_call["isError"], false);
    let remote_text = remote_call["content"][0]["text"].as_str().unwrap();
    assert!(
        remote_text.contains("sess-a@host-a"),
        "MCP list with host=host-a must contain sess-a@host-a: {remote_text}"
    );
    assert!(
        !remote_text.contains("sess-b"),
        "MCP list with host=host-a must NOT contain local session sess-b: {remote_text}"
    );

    // 2. MCP list without host: must return local entries byte-for-byte identical to local /v1/sessions
    assert_eq!(local_call["isError"], false);
    let local_mcp_text = local_call["content"][0]["text"].as_str().unwrap();

    let (_status, local_direct_text) = http_get_unix(&node_b.http_sock, "/v1/sessions").unwrap();
    assert_eq!(
        local_mcp_text, local_direct_text,
        "MCP list without host must match local /v1/sessions byte-for-byte"
    );
}

// =============================================================================
// Oracle 6: /fed/v1/sessions from a source outside the peer's from CIDRs is refused.
// Mutant: skip the from check on this route => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_source_outside_from_cidr_refused() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    // Node A configures peer Node B with from: ["10.0.0.0/8"] (loopback 127.0.0.1 is outside)
    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: Some(creds_b.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: Some(vec!["10.0.0.0/8".to_string()]),
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        vec![],
        Some(a_listener),
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: a_addr.to_string(),
            pin: Some(creds_a.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["list".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_b,
        vec![],
        Some(b_listener),
        None,
    )
    .await;

    // Create session on Node A
    let (_sock, _rx) = create_claude_session_fixture(&node_a.sessions_dir, "sess-a", "agent-a");

    // Node B connects from 127.0.0.1 to Node A
    let res = list_federated_sessions(&node_b.fed_state, "host-a").await;
    match res {
        Err(AppError::PeerRejected(detail)) => {
            assert!(
                detail.contains("host-a")
                    || detail.contains("CIDR")
                    || detail.contains("peer_rejected"),
                "Detail must indicate source CIDR refusal: {detail}"
            );
        }
        other => panic!("Expected PeerRejected error, got: {other:?}"),
    }
}
