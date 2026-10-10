use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use xmsg::agy::{dev_major, dev_minor, new_agy_store, AgyConfig, AgyStore};
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

struct RunningServer {
    base_url: String,
    agent_sock: PathBuf,
    agy_store: AgyStore,
    #[allow(dead_code)]
    db: Arc<Mutex<rusqlite::Connection>>,
    agent_task: tokio::task::JoinHandle<()>,
    http_task: tokio::task::JoinHandle<()>,
}

impl RunningServer {
    async fn stop(self) {
        self.agent_task.abort();
        self.http_task.abort();
        let _ = self.agent_task.await;
        let _ = self.http_task.await;
        let _ = fs::remove_file(&self.agent_sock);
    }
}

async fn start_test_server(
    agent_sock: PathBuf,
    sessions_dir: PathBuf,
    proc_root: PathBuf,
    proc_locks: PathBuf,
    presence_dir: PathBuf,
    trusted_agy: PathBuf,
) -> RunningServer {
    let my_uid = xmsg::agent::current_uid();
    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root,
        agy_bin: "agy".to_string(),
        trusted_agy_exes: vec![trusted_agy],
    };
    let agy_store = new_agy_store();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let (notify_tx, _) = broadcast::channel(1024);
    let (pi_notify_tx, _) = broadcast::channel(1024);
    let (svc_notify_tx, _) = broadcast::channel(1024);

    let state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir],
        agy_config,
        agy_store: agy_store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(60),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(10)),
        fed_state: None,
    });

    let app = build_router(state.clone());
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let http_task = tokio::spawn(async move {
        let _ = axum::serve(tcp_listener, app).await;
    });

    let ag_sock = agent_sock.clone();
    let ag_state = state.clone();
    let agent_task = tokio::spawn(async move {
        let _ = xmsg::agent::run_agent_server(ag_sock, ag_state, my_uid).await;
    });

    // Wait briefly for agent_sock to exist
    for _ in 0..50 {
        if agent_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    RunningServer {
        base_url,
        agent_sock,
        agy_store,
        db,
        agent_task,
        http_task,
    }
}

fn spawn_mcp_child(agent_sock: &Path) -> Child {
    let bin = env!("CARGO_BIN_EXE_xmsg");
    Command::new(bin)
        .args(["mcp", "--agent-sock", agent_sock.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn xmsg mcp child")
}

// ---------------------------------------------------------------------------
// Oracle 1:
// Start a server, attach an agy-like xmsg mcp child, restart the server
// => within the bound, the session is listed again and a message to it
// is queued, not sender_gone.
// Mutant: no re-registration (prior code) => RED.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_1_restart_preserves_agy_addressability_and_queues() {
    let tmp = tempdir().unwrap();
    let sock_dir = tmp.path().join("sockets");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_sock = sock_dir.join("agent.sock");

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();
    let proc_locks = tmp.path().join("locks");
    let trusted_agy = tmp.path().join("trusted_agy");
    fs::write(&trusted_agy, "binary").unwrap();

    let conv_id = "conv-oracle1";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    let parent_pid = 7777;
    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {parent_pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    setup_mock_process(
        &proc_root,
        parent_pid,
        1,
        Some(&trusted_agy),
        Some(&lock_file),
        "100",
    );

    // 1. Start Server 1
    let server1 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        trusted_agy.clone(),
    )
    .await;

    // 2. Spawn agy-like xmsg mcp child
    let mut child = spawn_mcp_child(&agent_sock);
    let child_pid = child.id();

    // Configure ancestor hierarchy for child PID -> parent PID 7777
    setup_mock_process(&proc_root, child_pid, parent_pid, None, None, "200");

    let client = reqwest::Client::new();
    let expected_session_key = format!("agy:{parent_pid}:100");

    // 3. Verify stage-1 registration on Server 1
    let mut registered_s1 = false;
    for _ in 0..50 {
        let resp = client
            .get(format!("{}/v1/sessions", server1.base_url))
            .send()
            .await
            .unwrap();
        let sessions: Vec<Value> = resp.json().await.unwrap();
        if sessions
            .iter()
            .any(|s| s["sessionId"] == expected_session_key && s["registered"] == false)
        {
            registered_s1 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        registered_s1,
        "xmsg mcp child must register stage 1 with server 1"
    );

    // 4. Restart server: stop Server 1, start Server 2 on the same agent.sock
    server1.stop().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        trusted_agy.clone(),
    )
    .await;

    // Immediately after start, Server 2's in-memory agy_store is empty
    assert!(
        server2.agy_store.read().unwrap().is_empty(),
        "restarted server starts with empty agy_store"
    );

    // 5. Within bounded time, xmsg mcp child reconnects and re-registers stage 1
    let mut registered_s2 = false;
    for _ in 0..60 {
        let resp = client
            .get(format!("{}/v1/sessions", server2.base_url))
            .send()
            .await
            .unwrap();
        let sessions: Vec<Value> = resp.json().await.unwrap();
        if sessions
            .iter()
            .any(|s| s["sessionId"] == expected_session_key && s["registered"] == false)
        {
            registered_s2 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        registered_s2,
        "restarted server must re-list agy session with registered: false within bound"
    );

    // 6. Send a message to the re-registered session: outcome must be 'queued', not 'sender_gone'
    let post_resp = client
        .post(format!(
            "{}/v1/sessions/{conv_id}/messages",
            server2.base_url
        ))
        .json(&serde_json::json!({
            "from": "test-orchestrator",
            "text": "Task payload after restart"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        post_resp.status(),
        reqwest::StatusCode::ACCEPTED,
        "send to re-registered agy session must succeed with 202 Accepted"
    );
    let post_json: Value = post_resp.json().await.unwrap();
    assert_eq!(
        post_json["outcome"], "queued",
        "message sent to stage-1 re-registered session must have outcome=queued, got: {post_json}"
    );

    // Clean up
    server2.stop().await;
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Oracle 2:
// A restarted server does not list an agy session whose xmsg mcp child has exited (no ghost).
// Mutant: re-register from a stale record => RED.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_2_restarted_server_does_not_list_exited_agy_child() {
    let tmp = tempdir().unwrap();
    let sock_dir = tmp.path().join("sockets");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_sock = sock_dir.join("agent.sock");

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();
    let proc_locks = tmp.path().join("locks");
    let trusted_agy = tmp.path().join("trusted_agy");
    fs::write(&trusted_agy, "binary").unwrap();

    let conv_id = "conv-oracle2";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    let parent_pid = 8888;
    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {parent_pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    setup_mock_process(
        &proc_root,
        parent_pid,
        1,
        Some(&trusted_agy),
        Some(&lock_file),
        "200",
    );

    // 1. Start Server 1
    let server1 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        trusted_agy.clone(),
    )
    .await;

    // 2. Spawn agy-like xmsg mcp child
    let mut child = spawn_mcp_child(&agent_sock);
    let child_pid = child.id();
    setup_mock_process(&proc_root, child_pid, parent_pid, None, None, "300");

    let client = reqwest::Client::new();
    let expected_session_key = format!("agy:{parent_pid}:200");

    // Verify stage-1 registration on Server 1
    let mut registered_s1 = false;
    for _ in 0..50 {
        let resp = client
            .get(format!("{}/v1/sessions", server1.base_url))
            .send()
            .await
            .unwrap();
        let sessions: Vec<Value> = resp.json().await.unwrap();
        if sessions
            .iter()
            .any(|s| s["sessionId"] == expected_session_key)
        {
            registered_s1 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        registered_s1,
        "xmsg mcp child must register stage 1 with server 1"
    );

    // 3. Kill the xmsg mcp child process
    child.kill().expect("kill child");
    let exit_status = child.wait().expect("wait on child");
    assert!(!exit_status.success());

    // The xmsg mcp child has exited; remove its proc entry
    let _ = fs::remove_dir_all(proc_root.join(child_pid.to_string()));

    // 4. Restart server: stop Server 1, start Server 2
    server1.stop().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        trusted_agy.clone(),
    )
    .await;

    // 5. Wait past the reconnect bound
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 6. Assert Server 2 does NOT list the session (no ghost session)
    let resp = client
        .get(format!("{}/v1/sessions", server2.base_url))
        .send()
        .await
        .unwrap();
    let sessions: Vec<Value> = resp.json().await.unwrap();
    assert!(
        !sessions.iter().any(|s| s["sessionId"] == expected_session_key),
        "restarted server must NOT list an agy session whose xmsg mcp child has exited (found: {sessions:?})"
    );

    let get_resp = client
        .get(format!(
            "{}/v1/sessions/{}",
            server2.base_url, expected_session_key
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), reqwest::StatusCode::NOT_FOUND);

    server2.stop().await;
}
