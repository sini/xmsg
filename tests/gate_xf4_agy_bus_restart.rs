use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use xmsg::agy::{
    dev_major, dev_minor, new_agy_store, notify_agy_escrow, AgyConfig, AgyCredentials,
    AgySessionInfo,
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

struct RunningServer {
    base_url: String,
    state: Arc<AppState>,
    agent_sock: PathBuf,
    #[allow(dead_code)]
    db: Arc<Mutex<rusqlite::Connection>>,
    agent_task: tokio::task::JoinHandle<()>,
    http_task: tokio::task::JoinHandle<()>,
}

impl RunningServer {
    fn agy_listing(&self) -> Vec<Value> {
        xmsg::agy::list_agy_sessions(
            &self.state.agy_config,
            &self.state.agy_store,
            &xmsg::registry::SessionsQuery::default(),
        )
        .into_iter()
        .map(|s| serde_json::to_value(s).unwrap())
        .collect()
    }

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
    agy_bin: String,
) -> RunningServer {
    let my_uid = xmsg::agent::current_uid();
    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root,
        agy_bin,
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
        agy_store,
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx,
        node_name: "test-host".to_string(),
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

    for _ in 0..3000 {
        if agent_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    RunningServer {
        base_url,
        state: state.clone(),
        agent_sock,
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

fn create_fake_agy_bin(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let fake_agy = dir.join("fake-agy");
    let argv_log = dir.join("argv.log");
    let env_log = dir.join("env.log");
    let fail_file = dir.join("fail.flag");

    let script = format!(
        "#!/bin/sh\n\
         echo \"$@\" >> \"{}\"\n\
         echo \"ANTIGRAVITY_LS_ADDRESS=$ANTIGRAVITY_LS_ADDRESS\" >> \"{}\"\n\
         echo \"ANTIGRAVITY_CSRF_TOKEN=$ANTIGRAVITY_CSRF_TOKEN\" >> \"{}\"\n\
         if [ -f \"{}\" ]; then\n\
             echo \"Error: Unauthenticated\" >&2\n\
             exit 1\n\
         fi\n\
         exit 0\n",
        argv_log.display(),
        env_log.display(),
        env_log.display(),
        fail_file.display()
    );
    fs::write(&fake_agy, script).unwrap();
    fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();
    (fake_agy, argv_log, env_log, fail_file)
}

// ---------------------------------------------------------------------------
// Cell 1:
// Idle agy session with stage-2 credentials registered survives xmsg serve
// restart on the same socket dir without starting a new turn or running
// xmsg register agy; a send after restart immediately delivers
// (outcome: "delivered") and invokes agy agentapi send-message.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn c1_bus_restart_preserves_stage2_credentials_and_delivers_immediately() {
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
    let (fake_agy, argv_log, env_log, _fail_file) = create_fake_agy_bin(tmp.path());

    let conv_id = "conv-xf4-cell1";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = dev_major(meta.dev());
    let min = dev_minor(meta.dev());
    let ino = meta.ino();

    let parent_pid = 7101;
    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {parent_pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    setup_mock_process(
        &proc_root,
        parent_pid,
        1,
        Some(&fake_agy),
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
        fake_agy.clone(),
        fake_agy.to_str().unwrap().to_string(),
    )
    .await;

    // 2. Spawn xmsg mcp child
    let mut child = spawn_mcp_child(&agent_sock);
    let child_pid = child.id();
    setup_mock_process(&proc_root, child_pid, parent_pid, None, None, "200");

    // Wait for stage-1 registration on Server 1
    let mut stage1_ok = false;
    for _ in 0..60 {
        if server1
            .agy_listing()
            .iter()
            .any(|s| s["sessionId"] == conv_id && s["registered"] == false)
        {
            stage1_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(stage1_ok, "stage-1 registration must succeed on Server 1");

    // 3. Register stage-2 credentials on Server 1
    {
        let info = AgySessionInfo::new(
            conv_id.to_string(),
            parent_pid,
            "100".to_string(),
            Some(AgyCredentials {
                ls_address: "127.0.0.1:41999".to_string(),
                csrf_token: "secret-csrf-cell1".to_string(),
                is_stale: false,
            }),
        );
        server1
            .state
            .agy_store
            .write()
            .unwrap()
            .insert(conv_id.to_string(), info);
    }
    notify_agy_escrow();

    // Give xmsg mcp's held connection a moment to receive the agy_escrow event
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 4. Stop Server 1 and start Server 2 on the same agent_sock (bus restart while agy is idle)
    server1.stop().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        fake_agy.clone(),
        fake_agy.to_str().unwrap().to_string(),
    )
    .await;

    // 5. Within bounded time, xmsg mcp reconnects and restores stage-2 credentials on Server 2
    let mut stage2_restored = false;
    for _ in 0..60 {
        if server2
            .agy_listing()
            .iter()
            .any(|s| s["sessionId"] == conv_id && s["registered"] == true && s["status"] == "idle")
        {
            stage2_restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        stage2_restored,
        "restarted server must restore stage-2 credentials (registered: true) from xmsg mcp escrow"
    );

    // 6. Send a message on Server 2: must immediately deliver (outcome == "delivered"), NOT queue
    let client = reqwest::Client::new();
    let post_resp = client
        .post(format!("{}/v1/messages", server2.base_url))
        .json(&serde_json::json!({
            "to": conv_id,
            "from": "orchestrator",
            "text": "Immediate delivery after bus restart"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(post_resp.status(), reqwest::StatusCode::ACCEPTED);
    let post_json: Value = post_resp.json().await.unwrap();
    assert_eq!(
        post_json["outcome"], "delivered",
        "message after bus restart must be immediately delivered, got: {post_json}"
    );

    let captured_argv = fs::read_to_string(&argv_log).unwrap();
    assert!(captured_argv.contains(conv_id));
    assert!(!captured_argv.contains("secret-csrf-cell1"));
    let captured_env = fs::read_to_string(&env_log).unwrap();
    assert!(captured_env.contains("ANTIGRAVITY_LS_ADDRESS=127.0.0.1:41999"));
    assert!(captured_env.contains("ANTIGRAVITY_CSRF_TOKEN=secret-csrf-cell1"));

    server2.stop().await;
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Cell 2:
// Custom label and registered_at timestamp survive xmsg serve restart.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn c2_custom_label_and_registered_at_survive_bus_restart() {
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
    let (fake_agy, _argv_log, _env_log, _fail_file) = create_fake_agy_bin(tmp.path());

    let conv_id = "conv-xf4-cell2";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = dev_major(meta.dev());
    let min = dev_minor(meta.dev());
    let ino = meta.ino();

    let parent_pid = 7202;
    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {parent_pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    setup_mock_process(
        &proc_root,
        parent_pid,
        1,
        Some(&fake_agy),
        Some(&lock_file),
        "100",
    );

    let server1 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        fake_agy.clone(),
        fake_agy.to_str().unwrap().to_string(),
    )
    .await;

    let mut child = spawn_mcp_child(&agent_sock);
    let child_pid = child.id();
    setup_mock_process(&proc_root, child_pid, parent_pid, None, None, "200");

    for _ in 0..60 {
        if server1
            .agy_listing()
            .iter()
            .any(|s| s["sessionId"] == conv_id)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let custom_reg_at: i64 = 1_700_001_234;
    {
        let mut info = AgySessionInfo::new(
            conv_id.to_string(),
            parent_pid,
            "100".to_string(),
            Some(AgyCredentials {
                ls_address: "127.0.0.1:42999".to_string(),
                csrf_token: "secret-csrf-cell2".to_string(),
                is_stale: false,
            }),
        )
        .with_label(Some("agy-custom-worker"));
        info.registered_at = custom_reg_at;
        server1
            .state
            .agy_store
            .write()
            .unwrap()
            .insert(conv_id.to_string(), info);
    }
    notify_agy_escrow();
    tokio::time::sleep(Duration::from_millis(150)).await;

    server1.stop().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        fake_agy.clone(),
        fake_agy.to_str().unwrap().to_string(),
    )
    .await;

    let mut restored_entry = None;
    for _ in 0..60 {
        if let Some(entry) = server2
            .agy_listing()
            .into_iter()
            .find(|s| s["sessionId"] == conv_id && s["registered"] == true)
        {
            restored_entry = Some(entry);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let entry = restored_entry.expect("restored stage-2 session must appear on Server 2");
    assert_eq!(
        entry["name"], "agy-custom-worker",
        "custom label must survive server restart, got: {entry}"
    );
    assert_eq!(
        entry["startedAt"], custom_reg_at as u64,
        "registered_at must survive server restart, got: {entry}"
    );

    // Also verify sending by the custom label resolves and delivers
    let client = reqwest::Client::new();
    let post_resp = client
        .post(format!("{}/v1/messages", server2.base_url))
        .json(&serde_json::json!({
            "to": "agy-custom-worker",
            "from": "orchestrator",
            "text": "Addressed by custom label after restart"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(post_resp.status(), reqwest::StatusCode::ACCEPTED);
    let post_json: Value = post_resp.json().await.unwrap();
    assert_eq!(post_json["outcome"], "delivered");

    server2.stop().await;
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Cell 3:
// Accept escrow only from attested xmsg mcp: a mcp_start carrying credentials
// from an unattested process or from an attested Claude session is refused,
// and non-agy connections never receive agy_escrow push events.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn c3_escrow_refused_for_unattested_and_claude_callers() {
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
    fs::write(&proc_locks, "").unwrap();
    let (fake_agy, _argv_log, _env_log, _fail_file) = create_fake_agy_bin(tmp.path());

    let my_pid = std::process::id();
    let my_starttime = "555";
    setup_mock_process(&proc_root, my_pid, 1, None, None, my_starttime);

    let server = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        fake_agy.clone(),
        fake_agy.to_str().unwrap().to_string(),
    )
    .await;

    let send_frame = |payload: Value| -> Value {
        let stream = UnixStream::connect(&agent_sock).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut writer = &stream;
        let line = format!("{payload}\n");
        writer.write_all(line.as_bytes()).unwrap();
        writer.flush().unwrap();
        let mut reader = BufReader::new(&stream);
        let mut resp = String::new();
        reader.read_line(&mut resp).unwrap();
        serde_json::from_str(&resp).unwrap()
    };

    // 3a. Unattested process sending mcp_start with credentials -> refused
    let resp_unattested = send_frame(serde_json::json!({
        "action": "mcp_start",
        "schema_version": 2,
        "ls_address": "127.0.0.1:49999",
        "csrf_token": "forged-token",
        "label": "forged-label"
    }));
    assert_eq!(resp_unattested["status"], "error");
    assert_eq!(resp_unattested["error"], "unattested");
    assert!(
        server.state.agy_store.read().unwrap().is_empty(),
        "unattested mcp_start must not populate agy_store"
    );

    // 3b. Register a valid Claude Code session for `my_pid` so bare mcp_start succeeds
    let claude_session_file = sessions_dir.join(format!("{my_pid}.json"));
    fs::write(
        &claude_session_file,
        serde_json::json!({
            "pid": my_pid,
            "sessionId": "11111111-2222-3333-4444-555555555555",
            "procStart": my_starttime,
            "messagingSocketPath": "/tmp/claude.sock",
            "cwd": "/tmp",
            "startedAt": 1700000000u64,
            "updatedAt": 1700000000u64,
            "kind": "interactive",
            "entrypoint": "cli",
            "name": "claude-peer",
            "status": "idle"
        })
        .to_string(),
    )
    .unwrap();

    // Verify bare mcp_start from this Claude peer succeeds
    let resp_claude_bare = send_frame(serde_json::json!({
        "action": "mcp_start",
        "schema_version": 2
    }));
    assert_eq!(
        resp_claude_bare["status"], "ok",
        "bare mcp_start from attested Claude peer must succeed: {resp_claude_bare}"
    );

    // Now send mcp_start carrying agy escrow credentials from the same attested Claude peer -> MUST BE REFUSED
    let resp_claude_escrow = send_frame(serde_json::json!({
        "action": "mcp_start",
        "schema_version": 2,
        "ls_address": "127.0.0.1:49999",
        "csrf_token": "forged-from-claude"
    }));
    assert_eq!(
        resp_claude_escrow["status"], "error",
        "mcp_start carrying agy credentials from a Claude peer must be refused: {resp_claude_escrow}"
    );
    assert_eq!(resp_claude_escrow["error"], "unattested");
    assert!(
        server.state.agy_store.read().unwrap().is_empty(),
        "Claude peer sending agy credentials must not populate agy_store"
    );

    // 3c. Hold a bare mcp_start connection from the Claude peer and verify it never receives agy_escrow events
    let claude_held = UnixStream::connect(&agent_sock).unwrap();
    claude_held
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut claude_writer = &claude_held;
    claude_writer
        .write_all(b"{\"action\":\"mcp_start\",\"schema_version\":2}\n")
        .unwrap();
    claude_writer.flush().unwrap();
    let mut claude_reader = BufReader::new(&claude_held);
    let mut first_line = String::new();
    claude_reader.read_line(&mut first_line).unwrap();
    let first_val: Value = serde_json::from_str(&first_line).unwrap();
    assert_eq!(first_val["status"], "ok");

    // Populate agy_store and trigger notify_agy_escrow()
    server.state.agy_store.write().unwrap().insert(
        "conv-other".to_string(),
        AgySessionInfo::new(
            "conv-other".to_string(),
            9999,
            "100".to_string(),
            Some(AgyCredentials {
                ls_address: "127.0.0.1:45555".to_string(),
                csrf_token: "secret-never-sent-to-claude".to_string(),
                is_stale: false,
            }),
        ),
    );
    notify_agy_escrow();

    let mut leaked_line = String::new();
    let read_res = claude_reader.read_line(&mut leaked_line);
    assert!(
        read_res.is_err() && leaked_line.is_empty(),
        "Claude held connection must never receive agy_escrow push events, got: {leaked_line}"
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Cell 4:
// When credentials are marked stale (deliver_agy_envelope sets is_stale = true),
// the cache clears on both ends: a subsequent server restart does NOT restore
// the stale credentials.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn c4_stale_credentials_clear_escrow_on_both_ends() {
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
    let (fake_agy, _argv_log, _env_log, fail_file) = create_fake_agy_bin(tmp.path());

    let conv_id = "conv-xf4-cell4";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = dev_major(meta.dev());
    let min = dev_minor(meta.dev());
    let ino = meta.ino();

    let parent_pid = 7404;
    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {parent_pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    setup_mock_process(
        &proc_root,
        parent_pid,
        1,
        Some(&fake_agy),
        Some(&lock_file),
        "100",
    );

    let server1 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        fake_agy.clone(),
        fake_agy.to_str().unwrap().to_string(),
    )
    .await;

    let mut child = spawn_mcp_child(&agent_sock);
    let child_pid = child.id();
    setup_mock_process(&proc_root, child_pid, parent_pid, None, None, "200");

    for _ in 0..60 {
        if server1
            .agy_listing()
            .iter()
            .any(|s| s["sessionId"] == conv_id)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 1. Register stage-2 credentials and let xmsg mcp cache them
    server1.state.agy_store.write().unwrap().insert(
        conv_id.to_string(),
        AgySessionInfo::new(
            conv_id.to_string(),
            parent_pid,
            "100".to_string(),
            Some(AgyCredentials {
                ls_address: "127.0.0.1:44999".to_string(),
                csrf_token: "token-soon-stale".to_string(),
                is_stale: false,
            }),
        ),
    );
    notify_agy_escrow();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 2. Trigger auth failure on delivery so deliver_agy_envelope marks is_stale = true
    fs::write(&fail_file, "fail").unwrap();
    let client = reqwest::Client::new();
    let fail_resp = client
        .post(format!("{}/v1/messages", server1.base_url))
        .json(&serde_json::json!({
            "to": conv_id,
            "from": "orchestrator",
            "text": "Triggers Unauthenticated"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        fail_resp.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "delivery with failing agy must return 503"
    );

    // Wait briefly for xmsg mcp to receive agy_escrow_clear
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 3. Restart server: xmsg mcp must NOT re-supply the cleared stale credentials
    server1.stop().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        fake_agy.clone(),
        fake_agy.to_str().unwrap().to_string(),
    )
    .await;

    let mut stage1_on_s2 = false;
    for _ in 0..60 {
        if let Some(entry) = server2
            .agy_listing()
            .into_iter()
            .find(|s| s["sessionId"] == conv_id && s["status"] != "unregistered")
        {
            assert_eq!(
                entry["registered"], false,
                "stale credentials must have been cleared from xmsg mcp cache, got: {entry}"
            );
            stage1_on_s2 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        stage1_on_s2,
        "restarted server must list session at stage-1 (registered: false) after stale clear"
    );

    server2.stop().await;
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Cell 5:
// The store holds stage-2 credentials for session key K, registered by agy
// process P1 (pid1, start1). A different agy process P2 (pid2, start2) holds
// the presence lock for the same conversation ID K (agy-restarted-and-resumed).
// Its xmsg mcp connects and attests. It must get agy_escrow_clear or nothing,
// never P1's ls_address/csrf_token. After P2 registers its own stage 2, it
// gets its own.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn c5_restarted_agy_process_never_receives_prior_process_credentials() {
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
    let (fake_agy, _argv_log, _env_log, _fail_file) = create_fake_agy_bin(tmp.path());

    let conv_id = "conv-xf4-cell5";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = dev_major(meta.dev());
    let min = dev_minor(meta.dev());
    let ino = meta.ino();

    // P1 is the prior agy process (pid1, start1); P2 is the restarted agy process (pid2, start2)
    // currently holding the presence lock for conv_id.
    let pid1: u32 = 7501;
    let start1 = "101";
    let pid2: u32 = 7502;
    let start2 = "202";

    setup_mock_process(
        &proc_root,
        pid1,
        1,
        Some(&fake_agy),
        Some(&lock_file),
        start1,
    );
    setup_mock_process(
        &proc_root,
        pid2,
        1,
        Some(&fake_agy),
        Some(&lock_file),
        start2,
    );

    // P2 holds the presence lock for conv_id
    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {pid2} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    let server = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        proc_locks.clone(),
        presence_dir.clone(),
        fake_agy.clone(),
        fake_agy.to_str().unwrap().to_string(),
    )
    .await;

    // 1. Store initially holds stage-2 credentials for conv_id registered by P1 (pid1, start1)
    let p1_info = AgySessionInfo::new(
        conv_id.to_string(),
        pid1,
        start1.to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:45111".to_string(),
            csrf_token: "secret-csrf-p1-must-never-leak".to_string(),
            is_stale: false,
        }),
    );
    server
        .state
        .agy_store
        .write()
        .unwrap()
        .insert(conv_id.to_string(), p1_info.clone());

    // Place the test runner process under P2 so an agent.sock connection attests as P2 (pid2, start2)
    let self_pid = std::process::id();
    setup_mock_process(&proc_root, self_pid, pid2, None, None, "303");

    // 2. Connect as P2's xmsg mcp on agent.sock and attest via mcp_start
    let stream = std::os::unix::net::UnixStream::connect(&agent_sock).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    writeln!(writer, r#"{{"action":"mcp_start","schema_version":2}}"#).unwrap();
    writer.flush().unwrap();

    let mut start_line = String::new();
    reader.read_line(&mut start_line).unwrap();
    let start_resp: Value = serde_json::from_str(&start_line).unwrap();
    assert_eq!(start_resp["status"], "ok");
    assert_eq!(start_resp["sessionId"], conv_id);

    // Ensure that if the store holds P1's stage-2 credentials (pid1, start1) while P2's held
    // connection is attested as (pid2, start2), P2 gets agy_escrow_clear or nothing — NEVER P1's credentials.
    server
        .state
        .agy_store
        .write()
        .unwrap()
        .insert(conv_id.to_string(), p1_info);
    notify_agy_escrow();

    let mut maybe_frame = String::new();
    let _ = reader.read_line(&mut maybe_frame);
    if !maybe_frame.trim().is_empty() {
        let ev: Value = serde_json::from_str(maybe_frame.trim()).unwrap();
        assert_eq!(
            ev["event"], "agy_escrow_clear",
            "P2 must only ever receive agy_escrow_clear or nothing when store has P1's credentials, got: {ev}"
        );
        assert!(
            !maybe_frame.contains("secret-csrf-p1-must-never-leak")
                && !maybe_frame.contains("127.0.0.1:45111"),
            "P2 must NEVER receive P1's ls_address or csrf_token, got: {maybe_frame}"
        );
    }

    // 3. After P2 registers its own stage-2 credentials (pid2, start2), P2 gets its own
    let p2_info = AgySessionInfo::new(
        conv_id.to_string(),
        pid2,
        start2.to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:45222".to_string(),
            csrf_token: "secret-csrf-p2-own".to_string(),
            is_stale: false,
        }),
    );
    server
        .state
        .agy_store
        .write()
        .unwrap()
        .insert(conv_id.to_string(), p2_info);
    notify_agy_escrow();

    let mut p2_frame = String::new();
    reader
        .read_line(&mut p2_frame)
        .expect("P2 must receive its own stage-2 agy_escrow frame");
    assert!(
        !p2_frame.trim().is_empty(),
        "P2 must receive a frame after registering its own stage-2 credentials"
    );
    let p2_ev: Value = serde_json::from_str(p2_frame.trim()).unwrap();
    assert_eq!(p2_ev["event"], "agy_escrow");
    assert_eq!(p2_ev["ls_address"], "127.0.0.1:45222");
    assert_eq!(p2_ev["csrf_token"], "secret-csrf-p2-own");

    server.stop().await;
}
