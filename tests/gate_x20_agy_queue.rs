use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::broadcast;

use axum::http::StatusCode;
use serde_json::Value;

use xmsg::agent::{current_uid, run_agent_server};
use xmsg::agy::{
    dev_major, dev_minor, flush_agy_queue, new_agy_store, AgyConfig, AgyCredentials,
    AgySessionInfo, AgyStore,
};
use xmsg::fed::{
    generate_self_signed_ed25519, run_fed_listener, FedState, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::{build_router, AppState};
use xmsg::storage;

fn setup_mock_process(
    proc_root: &Path,
    pid: u32,
    ppid: u32,
    exe: Option<&Path>,
    open_file: Option<&Path>,
    starttime: &str,
) {
    let pid_dir = proc_root.join(pid.to_string());
    let fd_dir = pid_dir.join("fd");
    fs::create_dir_all(&fd_dir).unwrap();

    let stat_content = format!(
        "{pid} (proc) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0 0 0 0 0 0 0 0 0\n"
    );
    fs::write(pid_dir.join("stat"), stat_content).unwrap();

    if let Some(e) = exe {
        let exe_link = pid_dir.join("exe");
        let _ = fs::remove_file(&exe_link);
        std::os::unix::fs::symlink(e, &exe_link).unwrap();
    }

    if let Some(target) = open_file {
        let fd_link = fd_dir.join("3");
        let _ = fs::remove_file(&fd_link);
        std::os::unix::fs::symlink(target, &fd_link).unwrap();
    }
}

fn setup_presence_lock(
    presence_dir: &Path,
    proc_locks: &Path,
    proc_root: &Path,
    conv_id: &str,
    pid: u32,
    starttime: &str,
    trusted_exe: &Path,
) {
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    let lock_line = format!(
        "1: FLOCK ADVISORY WRITE {pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(proc_locks)
        .unwrap();
    f.write_all(lock_line.as_bytes()).unwrap();

    setup_mock_process(
        proc_root,
        pid,
        1,
        Some(trusted_exe),
        Some(&lock_file),
        starttime,
    );
}

fn create_fake_agy_bin(dir: &Path, delivered_log: &Path) -> PathBuf {
    let fake_agy_bin = dir.join("fake_agy.sh");
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
    fake_agy_bin
}

struct TestHttpServer {
    base_url: String,
    db: Arc<Mutex<rusqlite::Connection>>,
    agy_store: AgyStore,
    agy_config: AgyConfig,
    _server_task: tokio::task::JoinHandle<()>,
}

async fn start_test_http_server(
    sessions_dir: PathBuf,
    proc_root: PathBuf,
    proc_locks: PathBuf,
    presence_dir: PathBuf,
    fake_agy_bin: PathBuf,
) -> TestHttpServer {
    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root,
        agy_bin: fake_agy_bin.to_string_lossy().to_string(),
        trusted_agy_exes: vec![fake_agy_bin],
    };
    let agy_store = new_agy_store();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let (notify_tx, _) = broadcast::channel(16);
    let (pi_notify_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: broadcast::channel(16).0,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");
    let _server_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestHttpServer {
        base_url,
        db,
        agy_store,
        agy_config,
        _server_task,
    }
}

// =============================================================================
// Oracle 1: Lock held, not registered: a send by conversation id => 202 queued;
// after registration, it is delivered exactly once.
// Mutant: refuse when unregistered => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread")]
async fn test_oracle_1_lock_held_unregistered_send_queues_and_flushes_once() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sess_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let delivered_log = tmp.path().join("delivered.log");
    let fake_agy_bin = create_fake_agy_bin(tmp.path(), &delivered_log);

    let conv_id = "conv-x20-oracle1";
    let holder_pid = 7001;
    let starttime = "100";

    setup_presence_lock(
        &presence_dir,
        &proc_locks,
        &proc_root,
        conv_id,
        holder_pid,
        starttime,
        &fake_agy_bin,
    );

    let server = start_test_http_server(
        sess_dir,
        proc_root,
        proc_locks,
        presence_dir,
        fake_agy_bin.clone(),
    )
    .await;

    let client = reqwest::Client::new();
    let send_url = format!("{}/v1/sessions/{conv_id}/messages", server.base_url);

    // 1. Send to unregistered session by conversation id => 202 Accepted, outcome: queued
    let resp = client
        .post(&send_url)
        .json(&serde_json::json!({
            "from": "claude-orch",
            "text": "first queued message for oracle 1"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "must accept message for live unregistered session"
    );
    let resp_body: Value = resp.json().await.unwrap();
    assert_eq!(resp_body["outcome"], "queued");
    assert_eq!(resp_body["sessionId"], conv_id);

    // Verify nothing delivered to fake agy yet
    assert!(
        !delivered_log.exists(),
        "delivered.log must not exist before registration"
    );

    // Verify in db: 1 undelivered agy message
    {
        let db = server.db.lock().unwrap();
        let count = storage::fetch_undelivered_agy_messages(&db, &[conv_id])
            .unwrap()
            .len();
        assert_eq!(count, 1, "exactly 1 undelivered agy message queued");
    }

    // 2. Register credentials for the session
    let info = AgySessionInfo::new(
        conv_id.to_string(),
        holder_pid,
        starttime.to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "secret-token-1".to_string(),
            is_stale: false,
        }),
    );
    let session_key = info.session_key.clone();
    server
        .agy_store
        .write()
        .unwrap()
        .insert(session_key.clone(), info);

    // 3. Flush agy queue
    flush_agy_queue(
        &server.agy_config,
        &server.agy_store,
        &server.db,
        &session_key,
        conv_id,
    )
    .await;

    // 4. Verify delivered exactly once
    assert!(
        delivered_log.exists(),
        "delivered.log must exist after queue flush"
    );
    let content = fs::read_to_string(&delivered_log).unwrap();
    let deliveries: Vec<&str> = content
        .split("===DELIVERY===\n")
        .filter(|s| !s.trim().is_empty())
        .collect();
    assert_eq!(
        deliveries.len(),
        1,
        "message must be delivered exactly once: {deliveries:?}"
    );
    assert!(
        deliveries[0].contains("first queued message for oracle 1"),
        "delivery payload must contain text: {}",
        deliveries[0]
    );

    // Verify in db: undelivered count is now 0
    {
        let db = server.db.lock().unwrap();
        let count = storage::fetch_undelivered_agy_messages(&db, &[conv_id])
            .unwrap()
            .len();
        assert_eq!(count, 0, "no undelivered agy messages remaining");
    }

    // 5. Subsequent flush does NOT deliver again (exactly once guarantee)
    flush_agy_queue(
        &server.agy_config,
        &server.agy_store,
        &server.db,
        &session_key,
        conv_id,
    )
    .await;

    let content_after = fs::read_to_string(&delivered_log).unwrap();
    let deliveries_after: Vec<&str> = content_after
        .split("===DELIVERY===\n")
        .filter(|s| !s.trim().is_empty())
        .collect();
    assert_eq!(
        deliveries_after.len(),
        1,
        "subsequent flush must not duplicate delivery"
    );
}

// =============================================================================
// Oracle 2: The old `agy:<pid>:<starttime>` key with matching pid+starttime =>
// queued under the conversation.
// Mutant: accept any starttime => RED via a recycled-pid case.
// =============================================================================
#[tokio::test(flavor = "multi_thread")]
async fn test_oracle_2_old_agy_key_with_matching_starttime_queues_recycled_fails() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sess_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let delivered_log = tmp.path().join("delivered.log");
    let fake_agy_bin = create_fake_agy_bin(tmp.path(), &delivered_log);

    let conv_id = "conv-x20-oracle2";
    let holder_pid = 7002;
    let actual_starttime = "200";

    setup_presence_lock(
        &presence_dir,
        &proc_locks,
        &proc_root,
        conv_id,
        holder_pid,
        actual_starttime,
        &fake_agy_bin,
    );

    let server = start_test_http_server(
        sess_dir,
        proc_root,
        proc_locks,
        presence_dir,
        fake_agy_bin.clone(),
    )
    .await;

    let client = reqwest::Client::new();

    // 2A. Matching key `agy:7002:200` => 202 Accepted, queued under conv-x20-oracle2
    let matching_key = format!("agy:{holder_pid}:{actual_starttime}");
    let matching_url = format!("{}/v1/sessions/{matching_key}/messages", server.base_url);
    let resp = client
        .post(&matching_url)
        .json(&serde_json::json!({
            "from": "claude-orch",
            "text": "matching key payload"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp_body: Value = resp.json().await.unwrap();
    assert_eq!(resp_body["outcome"], "queued");
    assert_eq!(resp_body["sessionId"], conv_id);

    // Verify stored under conversation id
    {
        let db = server.db.lock().unwrap();
        let msgs = storage::fetch_undelivered_agy_messages(&db, &[&matching_key, conv_id]).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].session_id, conv_id);
    }

    // 2B. Recycled PID with different starttime `agy:7002:999` => 404 Not Found
    let recycled_key = format!("agy:{holder_pid}:999");
    let recycled_url = format!("{}/v1/sessions/{recycled_key}/messages", server.base_url);
    let resp_recycled = client
        .post(&recycled_url)
        .json(&serde_json::json!({
            "from": "claude-orch",
            "text": "recycled pid payload"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp_recycled.status(),
        StatusCode::NOT_FOUND,
        "recycled PID with mismatched starttime must return 404 Not Found"
    );

    // Verify nothing additional stored in DB
    {
        let db = server.db.lock().unwrap();
        let count = storage::fetch_undelivered_agy_messages(&db, &[conv_id])
            .unwrap()
            .len();
        assert_eq!(count, 1, "recycled PID send must not be stored");
    }

    // 2C. Non-matching PID `agy:9999:200` => 404 Not Found
    let nonmatching_url = format!("{}/v1/sessions/agy:9999:200/messages", server.base_url);
    let resp_nonmatching = client
        .post(&nonmatching_url)
        .json(&serde_json::json!({
            "from": "claude-orch",
            "text": "nonmatching pid payload"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_nonmatching.status(), StatusCode::NOT_FOUND);
}

// =============================================================================
// Oracle 3: Lock not held => not_found, nothing stored.
// Mutant: queue regardless of the lock => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread")]
async fn test_oracle_3_lock_not_held_returns_not_found_nothing_stored() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sess_dir).unwrap();
    // proc_locks is EMPTY: no locks held by anyone!
    fs::write(&proc_locks, "").unwrap();

    let delivered_log = tmp.path().join("delivered.log");
    let fake_agy_bin = create_fake_agy_bin(tmp.path(), &delivered_log);

    let conv_id = "conv-x20-oracle3";
    // Create lock file, but no process holds a flock on it
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "stale-lock").unwrap();

    let server = start_test_http_server(
        sess_dir,
        proc_root,
        proc_locks,
        presence_dir,
        fake_agy_bin.clone(),
    )
    .await;

    let client = reqwest::Client::new();

    // 3A. Send to conversation id without lock held => 404 Not Found
    let url_conv = format!("{}/v1/sessions/{conv_id}/messages", server.base_url);
    let resp_conv = client
        .post(&url_conv)
        .json(&serde_json::json!({
            "from": "claude-orch",
            "text": "unheld lock payload"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp_conv.status(),
        StatusCode::NOT_FOUND,
        "send to conversation without active lock holder must return 404"
    );

    // 3B. Send with agy: prefix => 404 Not Found
    let url_agy_conv = format!("{}/v1/sessions/agy:{conv_id}/messages", server.base_url);
    let resp_agy_conv = client
        .post(&url_agy_conv)
        .json(&serde_json::json!({
            "from": "claude-orch",
            "text": "unheld lock payload with prefix"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_agy_conv.status(), StatusCode::NOT_FOUND);

    // 3C. Verify nothing stored in db
    {
        let db = server.db.lock().unwrap();
        let count = storage::fetch_undelivered_agy_messages(&db, &[conv_id])
            .unwrap()
            .len();
        assert_eq!(count, 0, "nothing must be stored for unheld lock");
        let msg = storage::get_message(&db, "any").unwrap();
        assert!(msg.is_none());
    }
}

// =============================================================================
// Oracle 4: A federated send to the same target queues the same way.
// Mutant: separate resolver for fed => RED.
// =============================================================================
#[allow(dead_code)]
struct FedTestNode {
    name: String,
    fed_addr: std::net::SocketAddr,
    agent_sock: PathBuf,
    db: Arc<Mutex<rusqlite::Connection>>,
    agy_store: AgyStore,
    agy_config: AgyConfig,
    _temp: TempDir,
}

type SetupAgyFn = Box<dyn FnOnce(&Path, &Path, &Path, &Path) -> (AgyConfig, AgyStore)>;

async fn create_fed_test_node(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: (Vec<u8>, Vec<u8>, String),
    setup_agy: Option<SetupAgyFn>,
    listener_opt: Option<TcpListener>,
) -> FedTestNode {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
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

    let my_pid = std::process::id();
    let live_proc = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&live_proc, my_pid).unwrap_or_else(|_| "1000".to_string());
    let caller_bin = temp.path().join("caller_bin");
    fs::write(&caller_bin, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&caller_bin, fs::Permissions::from_mode(0o755)).unwrap();
    setup_mock_process(
        &proc_root,
        my_pid,
        1,
        Some(&caller_bin),
        None,
        &my_proc_start,
    );

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

    let (agy_config, agy_store) = if let Some(setup) = setup_agy {
        setup(&presence_dir, &proc_locks, &proc_root, temp.path())
    } else {
        (
            AgyConfig {
                presence_dir,
                proc_locks_path: proc_locks,
                proc_root: proc_root.clone(),
                agy_bin: "agy".to_string(),
                trusted_agy_exes: Vec::new(),
            },
            new_agy_store(),
        )
    };

    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));

    let mut peers_map = HashMap::new();
    for p in peers {
        peers_map.insert(p.name.clone(), p);
    }
    let peers_arc = Arc::new(PeersMap::new(peers_map));

    let (notify_tx, _) = broadcast::channel(32);
    let (pi_notify_tx, _) = broadcast::channel(32);
    let (svc_notify_tx, _) = broadcast::channel(32);
    let my_uid = current_uid();
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
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: xmsg::svc::new_svc_store(),
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

    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
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
        if agent_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    FedTestNode {
        name: name.to_string(),
        fed_addr,
        agent_sock,
        db,
        agy_store,
        agy_config,
        _temp: temp,
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_federated_send_queues_unregistered_and_checks_starttime() {
    let creds_a = generate_self_signed_ed25519("host-a").unwrap();
    let creds_b = generate_self_signed_ed25519("host-b").unwrap();

    let b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b_listener.local_addr().unwrap();

    let conv_id = "conv-x20-oracle4".to_string();
    let holder_pid = 7004;
    let actual_starttime = "400".to_string();

    let delivered_log_b = Arc::new(Mutex::new(PathBuf::new()));
    let delivered_log_b_clone = delivered_log_b.clone();

    let node_a = create_fed_test_node(
        "host-a",
        vec![PeerConfig {
            name: "host-b".to_string(),
            address: b_addr.to_string(),
            pin: Some(creds_b.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_a.clone(),
        None,
        None,
    )
    .await;

    let node_b = create_fed_test_node(
        "host-b",
        vec![PeerConfig {
            name: "host-a".to_string(),
            address: node_a.fed_addr.to_string(),
            pin: Some(creds_a.2.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        }],
        creds_b.clone(),
        Some(Box::new(
            move |presence_dir, proc_locks, proc_root, tmp_path| {
                let delivered_log = tmp_path.join("delivered_b.log");
                *delivered_log_b_clone.lock().unwrap() = delivered_log.clone();
                let fake_agy_bin = create_fake_agy_bin(tmp_path, &delivered_log);

                setup_presence_lock(
                    presence_dir,
                    proc_locks,
                    proc_root,
                    "conv-x20-oracle4",
                    7004,
                    "400",
                    &fake_agy_bin,
                );

                (
                    AgyConfig {
                        presence_dir: presence_dir.to_path_buf(),
                        proc_locks_path: proc_locks.to_path_buf(),
                        proc_root: proc_root.to_path_buf(),
                        agy_bin: fake_agy_bin.to_string_lossy().to_string(),
                        trusted_agy_exes: vec![fake_agy_bin],
                    },
                    new_agy_store(),
                )
            },
        )),
        Some(b_listener),
    )
    .await;

    // 4A. Federated send to `agy:7004:400@host-b` => accepted and queued on node B
    let target_valid = format!("agy:{holder_pid}:{actual_starttime}@host-b");
    let resp1 = send_via_agent_sock(&node_a.agent_sock, &target_valid, "fed payload 1").await;

    assert_eq!(
        resp1.get("status").and_then(|s| s.as_str()),
        Some("ok"),
        "send to valid unregistered agy target over federation must succeed: {resp1:?}"
    );
    assert_eq!(
        resp1
            .get("delivery")
            .and_then(|d| d.get("outcome"))
            .and_then(|o| o.as_str()),
        Some("queued")
    );

    // Verify stored in Node B's db under conv_id
    {
        let db = node_b.db.lock().unwrap();
        let count = storage::fetch_undelivered_agy_messages(&db, &[&conv_id])
            .unwrap()
            .len();
        assert_eq!(
            count, 1,
            "message must be queued in node B agy_pending_messages"
        );
    }

    // 4B. Federated send to recycled PID `agy:7004:999@host-b` => refused (not_found)
    let target_recycled = format!("agy:{holder_pid}:999@host-b");
    let resp2 = send_via_agent_sock(&node_a.agent_sock, &target_recycled, "fed payload 2").await;

    assert_eq!(
        resp2.get("status").and_then(|s| s.as_str()),
        Some("error"),
        "send to recycled PID target over federation must fail: {resp2:?}"
    );

    // Verify node B db count still 1 (not queued)
    {
        let db = node_b.db.lock().unwrap();
        let count = storage::fetch_undelivered_agy_messages(&db, &[&conv_id])
            .unwrap()
            .len();
        assert_eq!(count, 1, "recycled PID send must not be queued in node B");
    }

    // 4C. Register credentials on Node B and flush queue => delivered exactly once
    let info = AgySessionInfo::new(
        conv_id.clone(),
        holder_pid,
        actual_starttime.clone(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "secret-token-b".to_string(),
            is_stale: false,
        }),
    );
    let session_key = info.session_key.clone();
    node_b
        .agy_store
        .write()
        .unwrap()
        .insert(session_key.clone(), info);

    flush_agy_queue(
        &node_b.agy_config,
        &node_b.agy_store,
        &node_b.db,
        &session_key,
        &conv_id,
    )
    .await;

    let delivered_path = delivered_log_b.lock().unwrap().clone();
    assert!(
        delivered_path.exists(),
        "delivered log must exist on node B after flush"
    );
    let content = fs::read_to_string(&delivered_path).unwrap();
    let deliveries: Vec<&str> = content
        .split("===DELIVERY===\n")
        .filter(|s| !s.trim().is_empty())
        .collect();
    assert_eq!(
        deliveries.len(),
        1,
        "federated queued message delivered exactly once: {deliveries:?}"
    );
    assert!(
        deliveries[0].contains("fed payload 1"),
        "delivery must contain federated message: {}",
        deliveries[0]
    );
}
