use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;

use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::claim::{
    get_all_claims_for_id, is_uuid_shaped, sync_claims_db, sync_claims_entries,
    validate_service_name,
};
use xmsg::http::{build_router, AppState};
use xmsg::pi::new_pi_store;
use xmsg::registry::read_session_entries;
use xmsg::storage::init_db;

fn setup_mock_proc(proc_root: &Path, pid: u32, starttime: &str) {
    setup_mock_proc_with_parent(proc_root, pid, 1, starttime);
}

fn setup_mock_proc_with_parent(proc_root: &Path, pid: u32, ppid: u32, starttime: &str) {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    let stat = format!(
        "{pid} (test) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0 0 0 0 0 0 0 0 0\n"
    );
    fs::write(pid_dir.join("stat"), stat).unwrap();
}

fn remove_mock_proc(proc_root: &Path, pid: u32) {
    let _ = fs::remove_dir_all(proc_root.join(pid.to_string()));
}

fn write_claude_session_file(
    dir: &Path,
    pid: u32,
    session_id: &str,
    name: &str,
    proc_start: &str,
    sock_path: &Path,
) {
    let session_json = serde_json::json!({
        "pid": pid,
        "sessionId": session_id,
        "name": name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": proc_start,
        "messagingSocketPath": sock_path.display().to_string(),
    });
    fs::write(
        dir.join(format!("{pid}_{session_id}.json")),
        session_json.to_string(),
    )
    .unwrap();
}

fn remove_claude_session_file(dir: &Path, pid: u32, session_id: &str) {
    let _ = fs::remove_file(dir.join(format!("{pid}_{session_id}.json")));
}

struct SocketListener {
    _sock_dir: TempDir,
    sock_path: PathBuf,
    received_lines: Arc<Mutex<Vec<String>>>,
    stop_signal: Arc<AtomicBool>,
}

impl Drop for SocketListener {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

async fn start_socket_listener(name: &str) -> SocketListener {
    let sock_dir = tempdir().expect("tempdir for socket");
    let sock_path = sock_dir.path().join(format!("{name}.sock"));
    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    let received_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = received_lines.clone();
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_signal.clone();

    tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((mut stream, _)) = res {
                        let mut buf = Vec::new();
                        let mut temp = [0u8; 1024];
                        while let Ok(n) = stream.read(&mut temp).await {
                            if n == 0 { break; }
                            buf.extend_from_slice(&temp[..n]);
                            if buf.ends_with(b"\n") {
                                break;
                            }
                        }
                        if let Ok(s) = String::from_utf8(buf) {
                            received_clone.lock().await.push(s);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    });

    SocketListener {
        _sock_dir: sock_dir,
        sock_path,
        received_lines,
        stop_signal,
    }
}

struct RunningServer {
    base_url: String,
    agent_sock: PathBuf,
    state: Arc<AppState>,
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
    db_path: PathBuf,
) -> RunningServer {
    let agy_config = AgyConfig {
        presence_dir: proc_root.join("presence"),
        proc_locks_path: proc_root.join("locks"),
        proc_root,
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
    };
    start_server_with(agent_sock, sessions_dir, agy_config, db_path).await
}

async fn start_server_with(
    agent_sock: PathBuf,
    sessions_dir: PathBuf,
    agy_config: AgyConfig,
    db_path: PathBuf,
) -> RunningServer {
    let my_uid = xmsg::agent::current_uid();
    let agy_store = new_agy_store();
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    init_db(&conn).unwrap();
    let db = Arc::new(std::sync::Mutex::new(conn));
    let (notify_tx, _) = tokio::sync::broadcast::channel(1024);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(1024);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(1024);

    let state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir],
        agy_config,
        agy_store,
        pi_store: new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx,
        node_name: "test-node".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(60),
        idempotency_ttl: Duration::from_secs(60),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
        fed_state: None,
    });

    let router = build_router(state.clone());
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = http_listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let http_task = tokio::spawn(async move {
        axum::serve(http_listener, router).await.unwrap();
    });

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        agent_sock.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let st = state.clone();
    let asock = agent_sock.clone();
    let agent_task = tokio::spawn(async move {
        let _ = xmsg::agent::run_agent_server(asock, st, my_uid).await;
    });

    for _ in 0..3000 {
        if agent_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(agent_sock.exists(), "agent.sock never came up");

    RunningServer {
        base_url,
        agent_sock,
        state,
        agent_task,
        http_task,
    }
}

fn live_self_proc_start() -> String {
    xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), std::process::id())
        .expect("live starttime of the test process")
}

/// A real `xmsg mcp` child, killed on drop.
struct KillChild(std::process::Child);

impl Drop for KillChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_mcp(agent_sock: &Path) -> KillChild {
    KillChild(
        std::process::Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .arg("mcp")
            .arg("--agent-sock")
            .arg(agent_sock)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn xmsg mcp"),
    )
}

/// One frame over agent.sock from this test process, which the server
/// attests by its peer pid.
async fn agent_request(agent_sock: &Path, req: serde_json::Value) -> serde_json::Value {
    let stream = tokio::net::UnixStream::connect(agent_sock).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(format!("{req}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    tokio::io::BufReader::new(reader)
        .read_line(&mut line)
        .await
        .unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad response {line:?}: {e}"))
}

fn claude_message(id: &str, session_id: &str) -> xmsg::storage::MessageRecord {
    xmsg::storage::MessageRecord {
        id: id.to_string(),
        created_at: xmsg::storage::now_epoch_secs(),
        session_id: session_id.to_string(),
        from_name: "test@peer".to_string(),
        bytes: 10,
        outcome: "delivered".to_string(),
        recipient_harness: "claude".to_string(),
        return_harness: None,
        return_session_id: None,
        thread_id: id.to_string(),
        return_host: None,
    }
}

const NOTICE_MARK: &str = "is open in two processes";

async fn notice_count(l: &SocketListener) -> usize {
    l.received_lines
        .lock()
        .await
        .iter()
        .filter(|line| line.contains(NOTICE_MARK))
        .count()
}

/// Waits up to `wait` for both processes to hold a notice, then long enough
/// for a duplicate to land, and returns both counts.
async fn settle_notices(a: &SocketListener, b: &SocketListener, wait: Duration) -> (usize, usize) {
    let deadline = tokio::time::Instant::now() + wait;
    while tokio::time::Instant::now() < deadline
        && (notice_count(a).await == 0 || notice_count(b).await == 0)
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    (notice_count(a).await, notice_count(b).await)
}

/// Two live processes, 1001 (procStart 100) and 1002 (procStart 200), both
/// presenting `conv`, and nothing observed yet.
struct ForkFixture {
    _tmp: TempDir,
    proc_root: PathBuf,
    sessions_dir: PathBuf,
    db_path: PathBuf,
    agent_sock: PathBuf,
    p1: SocketListener,
    p2: SocketListener,
}

async fn fork_fixture(conv: &str) -> ForkFixture {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    let sock_dir = tmp.path().join("sockets");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&sock_dir).unwrap();
    let p1 = start_socket_listener("p1").await;
    let p2 = start_socket_listener("p2").await;
    setup_mock_proc(&proc_root, 1001, "100");
    setup_mock_proc(&proc_root, 1002, "200");
    write_claude_session_file(&sessions_dir, 1001, conv, "first", "100", &p1.sock_path);
    write_claude_session_file(&sessions_dir, 1002, conv, "second", "200", &p2.sock_path);
    ForkFixture {
        db_path: tmp.path().join("xmsg.db"),
        agent_sock: sock_dir.join("agent.sock"),
        _tmp: tmp,
        proc_root,
        sessions_dir,
        p1,
        p2,
    }
}

// =============================================================================
// Oracle 1: Order and persistence across server restart (X and X~2)
// Mutant M1a: re-order by procStart on every scan => RED
// Mutant M1b: memory-only claim table (CREATE TEMP TABLE) => RED
// =============================================================================
/// The claim table's view of the live Claude sessions, `{sessionId: <address>, pid}` per
/// process: what `list` showed before A13 dropped the pid from its entries (the claim
/// order is per process, so these oracles key on it).
async fn claims_listing(state: &AppState) -> Vec<serde_json::Value> {
    xmsg::claim::sync_claims(
        &state.db,
        &state.agy_config.proc_root,
        &state.sessions_dirs,
        &state.node_name,
    )
    .await
    .unwrap()
    .into_iter()
    .map(|(claim, entry)| serde_json::json!({ "sessionId": claim.address(), "pid": entry.pid }))
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_1_order_and_persistence_across_restart() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("xmsg.db");
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    let sock_dir = tmp.path().join("sockets");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&sock_dir).unwrap();

    let conv_id = "0199cecf-0001-7000-8000-000000000001";
    let sock1 = tmp.path().join("p1.sock");
    let sock2 = tmp.path().join("p2.sock");

    // P1 starts with procStart "200"
    setup_mock_proc(&proc_root, 1001, "200");
    write_claude_session_file(&sessions_dir, 1001, conv_id, "first", "200", &sock1);

    let agent_sock = sock_dir.join("agent.sock");
    let server1 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        db_path.clone(),
    )
    .await;

    // Scan 1: P1 is observed first, receives plain conv_id (suffix 1)
    let s1: Vec<serde_json::Value> = claims_listing(&server1.state).await;
    assert_eq!(s1.len(), 1);
    assert_eq!(s1[0]["sessionId"], conv_id);

    // Later: P2 arrives with an EARLIER procStart "100" presenting the same ID
    setup_mock_proc(&proc_root, 1002, "100");
    write_claude_session_file(&sessions_dir, 1002, conv_id, "second", "100", &sock2);

    // Scan 2: P1 must KEEP plain conv_id; P2 must receive X~2 despite starting earlier
    let s2: Vec<serde_json::Value> = claims_listing(&server1.state).await;
    assert_eq!(s2.len(), 2);
    let p1_entry = s2.iter().find(|s| s["pid"] == 1001).unwrap();
    let p2_entry = s2.iter().find(|s| s["pid"] == 1002).unwrap();
    assert_eq!(
        p1_entry["sessionId"], conv_id,
        "First observed process P1 MUST retain plain ID"
    );
    assert_eq!(
        p2_entry["sessionId"],
        format!("{conv_id}~2"),
        "Later observed process P2 MUST receive ~2 despite earlier procStart"
    );

    // Stop Server 1 and restart as Server 2 against the same DB file
    server1.stop().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = start_test_server(
        agent_sock.clone(),
        sessions_dir.clone(),
        proc_root.clone(),
        db_path.clone(),
    )
    .await;

    // Scan on restarted server: persistence preserves claims
    let s3: Vec<serde_json::Value> = claims_listing(&server2.state).await;
    assert_eq!(s3.len(), 2);
    let p1_after = s3.iter().find(|s| s["pid"] == 1001).unwrap();
    let p2_after = s3.iter().find(|s| s["pid"] == 1002).unwrap();
    assert_eq!(
        p1_after["sessionId"], conv_id,
        "Persistence across restart MUST preserve plain ID for P1"
    );
    assert_eq!(
        p2_after["sessionId"],
        format!("{conv_id}~2"),
        "Persistence across restart MUST preserve ~2 for P2"
    );

    server2.stop().await;
}

// =============================================================================
// Oracle 2: Release on session switch (<pid>.json stops naming ID)
// Mutant M2: session switch keeps claim active => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_2_release_on_session_switch() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("xmsg.db");
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    let id_x = "0199cecf-0002-7000-8000-000000000001";
    let id_y = "0199cecf-0002-7000-8000-000000000002";
    let sock1 = tmp.path().join("p1.sock");
    let sock2 = tmp.path().join("p2.sock");

    setup_mock_proc(&proc_root, 1001, "100");
    write_claude_session_file(&sessions_dir, 1001, id_x, "p1", "100", &sock1);

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    init_db(&conn).unwrap();

    // 1. Initial sync: pid 1001 gets plain id_x
    let (pairs, _) = sync_claims_db(&conn, &proc_root, &sessions_dir, "test-node").unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0.address(), id_x);
    assert_eq!(pairs[0].0.suffix, 1);

    // 2. Session switch: remove id_x file and write id_y file for pid 1001
    remove_claude_session_file(&sessions_dir, 1001, id_x);
    write_claude_session_file(&sessions_dir, 1001, id_y, "p1-switched", "100", &sock1);

    let (pairs2, _) = sync_claims_db(&conn, &proc_root, &sessions_dir, "test-node").unwrap();
    assert_eq!(pairs2.len(), 1);
    assert_eq!(pairs2[0].0.id, id_y);
    assert_eq!(pairs2[0].0.suffix, 1);

    // Verify in DB that claim on id_x is marked released
    let all_x_claims = get_all_claims_for_id(&conn, id_x).unwrap();
    assert_eq!(all_x_claims.len(), 1);
    assert!(
        all_x_claims[0].released,
        "id_x claim MUST be released on session switch"
    );

    // 3. Newly observed process pid 1002 starts presenting id_x
    setup_mock_proc(&proc_root, 1002, "200");
    write_claude_session_file(&sessions_dir, 1002, id_x, "p2", "200", &sock2);

    let (pairs3, _) = sync_claims_db(&conn, &proc_root, &sessions_dir, "test-node").unwrap();
    let p2_claim = pairs3
        .iter()
        .find(|(c, _)| c.pid == 1002)
        .unwrap()
        .0
        .clone();
    assert_eq!(
        p2_claim.suffix, 1,
        "Newly observed process MUST receive released plain ID (suffix 1)"
    );
    assert_eq!(p2_claim.address(), id_x);
}

// =============================================================================
// Oracle 3: No promotion while live, no reuse of suffixes while records exist
// Mutant M3a: promote ~2 when plain is free => RED
// Mutant M3b: reuse the lowest free suffix => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_3_no_promotion_while_live_no_reuse_of_suffixes() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("xmsg.db");
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    let id = "0199cecf-0003-7000-8000-000000000001";
    let sock1 = tmp.path().join("p1.sock");
    let sock2 = tmp.path().join("p2.sock");
    let sock3 = tmp.path().join("p3.sock");
    let sock4 = tmp.path().join("p4.sock");
    let sock5 = tmp.path().join("p5.sock");

    setup_mock_proc(&proc_root, 1001, "100");
    setup_mock_proc(&proc_root, 1002, "200");
    setup_mock_proc(&proc_root, 1003, "300");
    write_claude_session_file(&sessions_dir, 1001, id, "p1", "100", &sock1);
    write_claude_session_file(&sessions_dir, 1002, id, "p2", "200", &sock2);
    write_claude_session_file(&sessions_dir, 1003, id, "p3", "300", &sock3);

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    init_db(&conn).unwrap();

    // 1. Initial sync: P1 has suffix 1, P2 has suffix 2, P3 has suffix 3
    let (pairs, _) = sync_claims_db(&conn, &proc_root, &sessions_dir, "test-node").unwrap();
    assert_eq!(pairs.len(), 3);
    assert_eq!(
        pairs.iter().find(|(c, _)| c.pid == 1001).unwrap().0.suffix,
        1
    );
    assert_eq!(
        pairs.iter().find(|(c, _)| c.pid == 1002).unwrap().0.suffix,
        2
    );
    assert_eq!(
        pairs.iter().find(|(c, _)| c.pid == 1003).unwrap().0.suffix,
        3
    );

    // 2. P2 exits first, freeing suffix ~2 below the maximum suffix 3
    remove_mock_proc(&proc_root, 1002);
    remove_claude_session_file(&sessions_dir, 1002, id);
    let (pairs2, _) = sync_claims_db(&conn, &proc_root, &sessions_dir, "test-node").unwrap();
    assert_eq!(pairs2.len(), 2);

    // 3. P1 exits, freeing plain ID
    remove_mock_proc(&proc_root, 1001);
    remove_claude_session_file(&sessions_dir, 1001, id);
    let (pairs3, _) = sync_claims_db(&conn, &proc_root, &sessions_dir, "test-node").unwrap();
    assert_eq!(pairs3.len(), 1);
    let p3_claim = &pairs3[0].0;
    assert_eq!(p3_claim.pid, 1003);
    assert_eq!(
        p3_claim.suffix, 3,
        "P3 MUST NEVER be promoted to suffix 1 while live"
    );
    assert_eq!(p3_claim.address(), format!("{id}~3"));

    // 4. P4 arrives presenting ID: plain suffix 1 is free, so P4 gets suffix 1
    setup_mock_proc(&proc_root, 1004, "400");
    write_claude_session_file(&sessions_dir, 1004, id, "p4", "400", &sock4);

    let (pairs4, _) = sync_claims_db(&conn, &proc_root, &sessions_dir, "test-node").unwrap();
    let p4_claim = pairs4
        .iter()
        .find(|(c, _)| c.pid == 1004)
        .unwrap()
        .0
        .clone();
    assert_eq!(p4_claim.suffix, 1, "P4 takes free plain ID (suffix 1)");

    // 5. P5 arrives presenting ID: plain is held by P4, suffix 2 was released, suffix 3 is held by P3.
    // Production MUST assign suffix 4 (max_suffix + 1), and MUST NOT reuse freed suffix 2.
    setup_mock_proc(&proc_root, 1005, "500");
    write_claude_session_file(&sessions_dir, 1005, id, "p5", "500", &sock5);

    let (pairs5, _) = sync_claims_db(&conn, &proc_root, &sessions_dir, "test-node").unwrap();
    let p5_claim = pairs5
        .iter()
        .find(|(c, _)| c.pid == 1005)
        .unwrap()
        .0
        .clone();
    assert_eq!(
        p5_claim.suffix, 4,
        "P5 MUST get monotonic suffix 4 (max_suffix + 1), NOT reused suffix 2"
    );
    assert_ne!(
        p5_claim.suffix, 2,
        "Released suffix 2 MUST NOT be reused while record exists"
    );
    assert_eq!(p5_claim.address(), format!("{id}~4"));
}

// =============================================================================
// Oracle 4: Ties broken by (procStart, pid)
// The scan is fed its entries in an explicit order, so the fixture does not
// depend on the filesystem's read_dir order: one list inverts
// (procStart, pid), the other follows it, and both give the plain ID to the
// lower (procStart, pid).
// Mutant M4: take input order (no sort) => RED on the inverted list
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_4_ties_broken_by_proc_start_and_pid() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let id = "0199cecf-0004-7000-8000-000000000001";
    let sock = tmp.path().join("sock");

    setup_mock_proc(&proc_root, 2000, "200");
    setup_mock_proc(&proc_root, 1000, "100");

    let sd = tmp.path().join("sessions");
    fs::create_dir_all(&sd).unwrap();
    write_claude_session_file(&sd, 2000, id, "p2000", "200", &sock);
    write_claude_session_file(&sd, 1000, id, "p1000", "100", &sock);
    let entries = read_session_entries(&sd);
    assert_eq!(entries.len(), 2);

    let mut inverted = entries.clone();
    inverted.sort_by_key(|e| std::cmp::Reverse(e.pid));
    let mut in_order = entries;
    in_order.sort_by_key(|e| e.pid);
    let pids = |v: &[xmsg::registry::SessionFileEntry]| v.iter().map(|e| e.pid).collect::<Vec<_>>();
    assert_eq!(pids(&inverted), vec![2000, 1000]);
    assert_eq!(pids(&in_order), vec![1000, 2000]);

    for (order, list) in [("inverted", inverted), ("in-order", in_order)] {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let (pairs, _) = sync_claims_entries(&conn, &proc_root, list, "test-node").unwrap();
        assert_eq!(pairs.len(), 2);
        let p1000_claim = pairs.iter().find(|(c, _)| c.pid == 1000).unwrap().0.clone();
        let p2000_claim = pairs.iter().find(|(c, _)| c.pid == 2000).unwrap().0.clone();

        assert_eq!(
            p1000_claim.suffix, 1,
            "{order}: 1000 has the smaller (procStart, pid) and MUST hold the plain ID whatever the input order"
        );
        assert_eq!(p2000_claim.suffix, 2, "{order}");
    }
}

// =============================================================================
// Oracle 5: Fork identity in send/reply attribution and authorization (D-5)
// P2 is this test process, so its agent.sock frames are attested as P2 and
// go through the production send and reply paths.
// Mutant M5: caller identity from session file's sessionId => RED
// Mutant X-R5: reply authorization drops the recipient-address check => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_5_fork_identity_attribution_and_routing() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("xmsg.db");
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    let sock_dir = tmp.path().join("sockets");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&sock_dir).unwrap();

    let conv_id = "0199cecf-0005-7000-8000-000000000001";
    let fork_addr = format!("{conv_id}~2");
    let listener_p1 = start_socket_listener("p1").await;
    let listener_p2 = start_socket_listener("p2").await;

    // P1 (fake pid 1001) is observed first and holds plain X.
    setup_mock_proc(&proc_root, 1001, "100");
    write_claude_session_file(
        &sessions_dir,
        1001,
        conv_id,
        "first",
        "100",
        &listener_p1.sock_path,
    );
    let server = start_test_server(
        sock_dir.join("agent.sock"),
        sessions_dir.clone(),
        proc_root.clone(),
        db_path.clone(),
    )
    .await;
    let s1: Vec<serde_json::Value> = claims_listing(&server.state).await;
    assert_eq!(s1.len(), 1);
    assert_eq!(s1[0]["sessionId"], conv_id);

    // P2 (this test process) presents X later and gets X~2.
    let my_pid = std::process::id();
    let my_start = live_self_proc_start();
    setup_mock_proc(&proc_root, my_pid, &my_start);
    write_claude_session_file(
        &sessions_dir,
        my_pid,
        conv_id,
        "second",
        &my_start,
        &listener_p2.sock_path,
    );
    let s2: Vec<serde_json::Value> = claims_listing(&server.state).await;
    let p2_entry = s2.iter().find(|s| s["pid"] == my_pid).expect("P2 listed");
    assert_eq!(p2_entry["sessionId"], fork_addr);

    // 1. P2 sends to X: the message is attributed to X~2, the address a
    //    reply to it is routed back to.
    let sent = agent_request(
        &server.agent_sock,
        serde_json::json!({"action": "send", "to": conv_id, "text": "hello from the fork"}),
    )
    .await;
    assert_eq!(sent["status"], "ok", "send from P2 failed: {sent}");
    let sent_id = sent["message_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no messageId in {sent}"));
    let record = xmsg::storage::get_message(&server.state.db.lock().unwrap(), sent_id)
        .unwrap()
        .expect("P2's send is stored");
    assert_eq!(
        record.return_session_id.as_deref(),
        Some(fork_addr.as_str()),
        "P2's send MUST be attributed to X~2"
    );
    assert_eq!(record.return_harness.as_deref(), Some("claude"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        listener_p1
            .received_lines
            .lock()
            .await
            .iter()
            .any(|l| l.contains("hello from the fork")),
        "P1 (plain X) received P2's send"
    );

    // 2. Replies through the production reply path: P2 may reply to a message
    //    addressed to X~2 and is denied for one addressed to X.
    {
        let db = server.state.db.lock().unwrap();
        xmsg::storage::insert_message(&db, &claude_message("msg-fork-002", &fork_addr)).unwrap();
        xmsg::storage::insert_message(&db, &claude_message("msg-plain-001", conv_id)).unwrap();
    }
    let allowed = agent_request(
        &server.agent_sock,
        serde_json::json!({"action": "reply", "message_id": "msg-fork-002", "text": "reply as the fork"}),
    )
    .await;
    assert_eq!(
        allowed["status"], "ok",
        "P2 MUST be allowed to reply to a message addressed to X~2: {allowed}"
    );
    let denied = agent_request(
        &server.agent_sock,
        serde_json::json!({"action": "reply", "message_id": "msg-plain-001", "text": "reply as the fork"}),
    )
    .await;
    assert_eq!(
        denied["error"], "denied",
        "P2 MUST be denied a reply to a message addressed to plain X: {denied}"
    );

    server.stop().await;
}

// =============================================================================
// Oracle 6: Fork notice exact text and single delivery
// Mutant M6: notify only the newcomer => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6_fork_notice_exact_text_and_single_delivery() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("xmsg.db");
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    let conv_id = "0199cecf-0006-7000-8000-000000000001";
    let listener_p1 = start_socket_listener("p1").await;
    let listener_p2 = start_socket_listener("p2").await;

    setup_mock_proc(&proc_root, 1001, "100");
    write_claude_session_file(
        &sessions_dir,
        1001,
        conv_id,
        "first",
        "100",
        &listener_p1.sock_path,
    );

    let conn = Arc::new(std::sync::Mutex::new(
        rusqlite::Connection::open(&db_path).unwrap(),
    ));
    {
        let c = conn.lock().unwrap();
        init_db(&c).unwrap();
    }

    // First process starts: no fork notice
    let (_, notices) = sync_claims_db(
        &conn.lock().unwrap(),
        &proc_root,
        &sessions_dir,
        "test-node",
    )
    .unwrap();
    xmsg::claim::deliver_fork_notices(&conn, notices).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(listener_p1.received_lines.lock().await.len(), 0);

    // Second process starts for same conversation ID
    setup_mock_proc(&proc_root, 1002, "200");
    write_claude_session_file(
        &sessions_dir,
        1002,
        conv_id,
        "second",
        "200",
        &listener_p2.sock_path,
    );

    let (_, notices) = sync_claims_db(
        &conn.lock().unwrap(),
        &proc_root,
        &sessions_dir,
        "test-node",
    )
    .unwrap();
    xmsg::claim::deliver_fork_notices(&conn, notices).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify exact notice text received by P1
    let lines_p1 = listener_p1.received_lines.lock().await.clone();
    assert_eq!(lines_p1.len(), 1, "P1 must receive exactly one notice");
    let expected_p1_text = format!(
        "xmsg: conversation {} is open in two processes on test-node. This process is {}; the other is {}~2. A send to {} reaches {}.",
        conv_id, conv_id, conv_id, conv_id, conv_id
    );
    assert!(
        lines_p1[0].contains(&expected_p1_text),
        "P1 notice mismatch: expected text '{}', got: '{}'",
        expected_p1_text,
        lines_p1[0]
    );

    // Verify exact notice text received by P2
    let lines_p2 = listener_p2.received_lines.lock().await.clone();
    assert_eq!(lines_p2.len(), 1, "P2 must receive exactly one notice");
    let expected_p2_text = format!(
        "xmsg: conversation {} is open in two processes on test-node. This process is {}~2; the other is {}. A send to {} reaches {}.",
        conv_id, conv_id, conv_id, conv_id, conv_id
    );
    assert!(
        lines_p2[0].contains(&expected_p2_text),
        "P2 notice mismatch: expected text '{}', got: '{}'",
        expected_p2_text,
        lines_p2[0]
    );

    // Subsequent sync: NO duplicate notice delivered
    let (_, notices) = sync_claims_db(
        &conn.lock().unwrap(),
        &proc_root,
        &sessions_dir,
        "test-node",
    )
    .unwrap();
    xmsg::claim::deliver_fork_notices(&conn, notices).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        listener_p1.received_lines.lock().await.len(),
        1,
        "No duplicate notice to P1"
    );
    assert_eq!(
        listener_p2.received_lines.lock().await.len(),
        1,
        "No duplicate notice to P2"
    );
}

// =============================================================================
// Oracle 6b: two overlapping scans notice a fork pair once.
// Mutant B-N1: record the notice only after delivery, outside the lock => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6b_fork_notice_once_under_concurrent_scans() {
    let f = fork_fixture("0199cecf-0006-7000-8000-00000000000b").await;
    let conn = rusqlite::Connection::open(&f.db_path).unwrap();
    init_db(&conn).unwrap();
    let db = Arc::new(std::sync::Mutex::new(conn));

    let (a, b) = tokio::join!(
        xmsg::claim::sync_claims(&db, &f.proc_root, &f.sessions_dir, "test-node"),
        xmsg::claim::sync_claims(&db, &f.proc_root, &f.sessions_dir, "test-node"),
    );
    a.unwrap();
    b.unwrap();
    xmsg::claim::sync_claims(&db, &f.proc_root, &f.sessions_dir, "test-node")
        .await
        .unwrap();

    let (n1, n2) = settle_notices(&f.p1, &f.p2, Duration::from_secs(2)).await;
    assert_eq!(
        n1, 1,
        "P1 must receive exactly one notice under concurrent scans"
    );
    assert_eq!(
        n2, 1,
        "P2 must receive exactly one notice under concurrent scans"
    );
}

// =============================================================================
// Oracle 6e: a notice whose delivery fails is delivered once by a later scan.
// Mutant: keep the claim of a failed delivery => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6e_failed_fork_notice_retried_once() {
    let conv = "0199cecf-0006-7000-8000-00000000000e";
    let f = fork_fixture(conv).await;
    // P2's socket is not up yet.
    let missing = f.db_path.with_file_name("p2-not-yet.sock");
    write_claude_session_file(&f.sessions_dir, 1002, conv, "second", "200", &missing);
    let conn = rusqlite::Connection::open(&f.db_path).unwrap();
    init_db(&conn).unwrap();
    let db = Arc::new(std::sync::Mutex::new(conn));

    xmsg::claim::sync_claims(&db, &f.proc_root, &f.sessions_dir, "test-node")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(notice_count(&f.p1).await, 1);
    assert_eq!(notice_count(&f.p2).await, 0);

    // P2's socket comes up; the next scans deliver its notice once.
    write_claude_session_file(
        &f.sessions_dir,
        1002,
        conv,
        "second",
        "200",
        &f.p2.sock_path,
    );
    for _ in 0..2 {
        xmsg::claim::sync_claims(&db, &f.proc_root, &f.sessions_dir, "test-node")
            .await
            .unwrap();
    }
    let (n1, n2) = settle_notices(&f.p1, &f.p2, Duration::from_secs(2)).await;
    assert_eq!(n1, 1, "P1 must not be noticed again");
    assert_eq!(
        n2, 1,
        "P2's failed notice must be delivered exactly once later"
    );
}

// =============================================================================
// Oracle 6f: a scan whose future is dropped after its claims commit still
// delivers each notice once.
// Mutant: deliver on the caller's future (b537d10's with_claims) => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6f_fork_notice_survives_cancelled_scan() {
    let f = fork_fixture("0199cecf-0006-7000-8000-00000000000f").await;
    let conn = rusqlite::Connection::open(&f.db_path).unwrap();
    init_db(&conn).unwrap();
    let db = Arc::new(std::sync::Mutex::new(conn));

    // First poll commits the claims; the future is then dropped.
    let cancelled = tokio::time::timeout(
        Duration::ZERO,
        xmsg::claim::sync_claims(&db, &f.proc_root, &f.sessions_dir, "test-node"),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "the scan must be dropped before delivery"
    );
    for _ in 0..2 {
        xmsg::claim::sync_claims(&db, &f.proc_root, &f.sessions_dir, "test-node")
            .await
            .unwrap();
    }

    let (n1, n2) = settle_notices(&f.p1, &f.p2, Duration::from_secs(2)).await;
    assert_eq!(
        n1, 1,
        "P1 must receive exactly one notice after a cancelled scan"
    );
    assert_eq!(
        n2, 1,
        "P2 must receive exactly one notice after a cancelled scan"
    );
}

// =============================================================================
// Oracle 6g: a poisoned DB lock does not keep a failed notice's claim.
// Mutant: skip bookkeeping on a poisoned lock (b537d10) => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6g_poisoned_lock_releases_failed_claim() {
    let conv = "0199cecf-0006-7000-8000-000000000010";
    let f = fork_fixture(conv).await;
    let missing = f.db_path.with_file_name("p2-not-yet.sock");
    write_claude_session_file(&f.sessions_dir, 1002, conv, "second", "200", &missing);
    let conn = rusqlite::Connection::open(&f.db_path).unwrap();
    init_db(&conn).unwrap();
    let db = Arc::new(std::sync::Mutex::new(conn));

    let (_, notices) = sync_claims_db(
        &db.lock().unwrap(),
        &f.proc_root,
        &f.sessions_dir,
        "test-node",
    )
    .unwrap();
    assert_eq!(notices.len(), 2);
    let poison = Arc::clone(&db);
    let _ = std::thread::spawn(move || {
        let _g = poison.lock().unwrap();
        panic!("poison the DB lock");
    })
    .join();
    assert!(db.is_poisoned());

    xmsg::claim::deliver_fork_notices(&db, notices).await;
    let rows: i64 = db
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .query_row("SELECT COUNT(*) FROM fork_notices", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        rows, 1,
        "P2's failed claim must be released under a poisoned lock"
    );
}

// =============================================================================
// Oracle 6c: a fork first observed by Claude's mcp_start is noticed there,
// with no list.
// Mutant B-N2-mcp: the mcp_start Claude arm drops the notices => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6c_fork_notice_on_mcp_start_without_list() {
    let f = fork_fixture("0199cecf-0006-7000-8000-00000000000c").await;
    let server = start_test_server(
        f.agent_sock.clone(),
        f.sessions_dir.clone(),
        f.proc_root.clone(),
        f.db_path.clone(),
    )
    .await;

    // A real `xmsg mcp` under P2, as Claude runs its MCP.
    let child = spawn_mcp(&server.agent_sock);
    setup_mock_proc_with_parent(&f.proc_root, child.0.id(), 1002, "300");

    let (n1, n2) = settle_notices(&f.p1, &f.p2, Duration::from_secs(5)).await;
    drop(child);
    server.stop().await;
    assert_eq!(n1, 1, "P1 must receive exactly one notice from mcp_start");
    assert_eq!(n2, 1, "P2 must receive exactly one notice from mcp_start");
}

// =============================================================================
// Oracle 6d: a fork first observed by a send is noticed there, with no list.
// Mutant B-N2-send: the send path's resolution drops the notices => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6d_fork_notice_on_send_without_list() {
    let conv = "0199cecf-0006-7000-8000-00000000000d";
    let f = fork_fixture(conv).await;
    let server = start_test_server(
        f.agent_sock.clone(),
        f.sessions_dir.clone(),
        f.proc_root.clone(),
        f.db_path.clone(),
    )
    .await;

    let res = reqwest::Client::new()
        .post(format!("{}/v1/messages", server.base_url))
        .json(&serde_json::json!({"to": conv, "from": "tester", "text": "hello X"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);

    let (n1, n2) = settle_notices(&f.p1, &f.p2, Duration::from_secs(2)).await;
    server.stop().await;
    assert_eq!(n1, 1, "P1 must receive exactly one notice from the send");
    assert_eq!(n2, 1, "P2 must receive exactly one notice from the send");
}

// =============================================================================
// Oracle 7: agy conversation UUID across restart (PM1 arm), through the
// running server: real `xmsg mcp` children drive mcp_start, agy restarts with
// a new pid, and the restarted agy replies to a message received before.
// Mutant M7a: key on agy:{pid}:{starttime} in AgySessionInfo::new => RED
// Mutant M7b: key on agy:{pid}:{starttime} at registration sites => RED
// Mutant X-B2rev: mcp_start keeps the stale store entry => RED
// =============================================================================
fn setup_mock_agy(proc_root: &Path, pid: u32, starttime: &str, exe: &Path, lock: &Path) {
    setup_mock_proc(proc_root, pid, starttime);
    let dir = proc_root.join(pid.to_string());
    fs::create_dir_all(dir.join("fd")).unwrap();
    std::os::unix::fs::symlink(exe, dir.join("exe")).unwrap();
    std::os::unix::fs::symlink(lock, dir.join("fd").join("3")).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_7_agy_conversation_uuid_across_restart() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let presence_dir = tmp.path().join("presence");
    let proc_locks = tmp.path().join("proc_locks");
    let sessions_dir = tmp.path().join("sessions");
    let sock_dir = tmp.path().join("sockets");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&sock_dir).unwrap();

    let conv_uuid = "4a111111-2222-4333-8444-555555555555";
    let lock_file = presence_dir.join(format!("{conv_uuid}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    use std::os::unix::fs::MetadataExt;
    let (maj, min, ino) = (
        xmsg::agy::dev_major(meta.dev()),
        xmsg::agy::dev_minor(meta.dev()),
        meta.ino(),
    );
    let lock_line =
        |holder: u32| format!("1: FLOCK ADVISORY WRITE {holder} {maj:02x}:{min:02x}:{ino} 0 EOF\n");
    let trusted_agy = tmp.path().join("trusted_agy");
    fs::write(&trusted_agy, "binary").unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks.clone(),
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: vec![trusted_agy.clone()],
    };
    let server = start_server_with(
        sock_dir.join("agent.sock"),
        sessions_dir,
        agy_config,
        tmp.path().join("xmsg.db"),
    )
    .await;
    let store_entry = |pid: u32| {
        server
            .state
            .agy_store
            .read()
            .unwrap()
            .get(conv_uuid)
            .filter(|i| i.pid == pid)
            .cloned()
    };
    async fn wait_for<T>(mut f: impl FnMut() -> Option<T>) -> Option<T> {
        for _ in 0..250 {
            if let Some(v) = f() {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }

    // 1. agy 7777 holds conversation C; its `xmsg mcp` registers through mcp_start.
    fs::write(&proc_locks, lock_line(7777)).unwrap();
    setup_mock_agy(&proc_root, 7777, "100", &trusted_agy, &lock_file);
    let mcp1 = spawn_mcp(&server.agent_sock);
    setup_mock_proc_with_parent(&proc_root, mcp1.0.id(), 7777, "200");
    let before = wait_for(|| store_entry(7777))
        .await
        .expect("agy 7777 MUST be registered under conversation UUID C");
    assert_eq!(before.session_key, conv_uuid, "Session key MUST be C");
    assert_eq!(before.conversation_id, conv_uuid);
    let listed: Vec<serde_json::Value> = serde_json::from_value(
        reqwest::Client::new()
            .get(format!("{}/v1/recipients", server.base_url))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()["recipients"]
            .take(),
    )
    .unwrap();
    assert!(
        listed
            .iter()
            .any(|r| r["address"] == format!("{conv_uuid}@{}", server.state.node_name)),
        "agy MUST be addressed as C: {listed:?}"
    );

    // 2. A message addressed to C is received before the restart.
    {
        let mut msg = claude_message("msg-before-restart-1", conv_uuid);
        msg.recipient_harness = "agy".to_string();
        msg.outcome = "queued".to_string();
        xmsg::storage::insert_message(&server.state.db.lock().unwrap(), &msg).unwrap();
    }

    // 3. agy restarts: 7777 exits, 8888 resumes C and holds its lock, and a
    //    new `xmsg mcp` runs under it. No list runs in between.
    drop(mcp1);
    remove_mock_proc(&proc_root, 7777);
    fs::write(&proc_locks, lock_line(8888)).unwrap();
    setup_mock_agy(&proc_root, 8888, "300", &trusted_agy, &lock_file);
    let mcp2 = spawn_mcp(&server.agent_sock);
    setup_mock_proc_with_parent(&proc_root, mcp2.0.id(), 8888, "400");
    // Bounded wait for mcp_start; the reply below is the assertion.
    let _ = wait_for(|| store_entry(8888)).await;

    // 4. The restarted agy replies to the pre-restart message. This test
    //    process stands in as a process under agy 8888.
    setup_mock_proc_with_parent(
        &proc_root,
        std::process::id(),
        8888,
        &live_self_proc_start(),
    );
    let reply = agent_request(
        &server.agent_sock,
        serde_json::json!({"action": "reply", "message_id": "msg-before-restart-1", "text": "reply after restart"}),
    )
    .await;
    drop(mcp2);
    server.stop().await;
    assert_eq!(
        reply["status"], "ok",
        "restarted agy (new pid, same C) MUST reply to a message received before the restart: {reply}"
    );
}

// =============================================================================
// Oracle 8: pi server-minted UUID v4
// Mutant M8: honour the asserted pi ID => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_8_pi_server_minted_uuid_v4() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let pi_store = new_pi_store();
    let db = Arc::new(std::sync::Mutex::new(
        rusqlite::Connection::open_in_memory().unwrap(),
    ));
    init_db(&db.lock().unwrap()).unwrap();
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);

    let my_uid = xmsg::agent::current_uid();
    setup_mock_proc(&proc_root, 5555, "100");

    let req = xmsg::pi::PiRegisterRequest {
        harness: None,
        session_id: Some("asserted-custom-pi-id-z".to_string()),
        session_name: Some("pi-worker".to_string()),
        cwd: Some("/workspace".to_string()),
        reclaim: None,
    };

    let (client_read, server_write) = tokio::io::duplex(1024);
    let (server_read, _client_write) = tokio::io::duplex(1024);
    let reader = tokio::io::BufReader::new(server_read);

    let p_root = proc_root.clone();
    let p_store = pi_store.clone();
    let p_db = db.clone();
    let p_tx = pi_notify_tx.clone();
    tokio::spawn(async move {
        let _ = xmsg::pi::handle_pi_connection(
            reader,
            server_write,
            p_root,
            p_store,
            my_uid,
            my_uid,
            5555,
            req,
            p_db,
            p_tx,
            Duration::from_secs(60),
        )
        .await;
    });

    let mut resp_line = String::new();
    let mut buf_client = tokio::io::BufReader::new(client_read);
    buf_client.read_line(&mut resp_line).await.unwrap();

    let v: serde_json::Value = serde_json::from_str(&resp_line).expect("valid JSON response");
    assert_eq!(v["status"], "ok");
    let minted_id = v["sessionId"].as_str().expect("sessionId in response");

    // Must NOT honour the asserted custom ID
    assert_ne!(
        minted_id, "asserted-custom-pi-id-z",
        "Server MUST NOT honour asserted pi session ID"
    );
    assert!(
        is_uuid_shaped(minted_id),
        "Minted session ID must be UUID-shaped: {minted_id}"
    );

    // Must be UUID v4
    assert_eq!(minted_id.chars().nth(14).unwrap(), '4');
    let var = minted_id.chars().nth(19).unwrap();
    assert!(matches!(var, '8' | '9' | 'a' | 'b'));

    // Second registration on a new process must mint a DIFFERENT UUID
    setup_mock_proc(&proc_root, 6666, "200");
    let req2 = xmsg::pi::PiRegisterRequest {
        harness: None,
        session_id: Some("asserted-custom-pi-id-z".to_string()),
        session_name: Some("pi-worker".to_string()),
        cwd: Some("/workspace".to_string()),
        reclaim: None,
    };
    let (client_read2, server_write2) = tokio::io::duplex(1024);
    let (server_read2, _client_write2) = tokio::io::duplex(1024);
    let reader2 = tokio::io::BufReader::new(server_read2);

    let p_root2 = proc_root.clone();
    let p_store2 = pi_store.clone();
    let p_db2 = db.clone();
    let p_tx2 = pi_notify_tx.clone();
    tokio::spawn(async move {
        let _ = xmsg::pi::handle_pi_connection(
            reader2,
            server_write2,
            p_root2,
            p_store2,
            my_uid,
            my_uid,
            6666,
            req2,
            p_db2,
            p_tx2,
            Duration::from_secs(60),
        )
        .await;
    });

    let mut resp_line2 = String::new();
    let mut buf_client2 = tokio::io::BufReader::new(client_read2);
    buf_client2.read_line(&mut resp_line2).await.unwrap();

    let v2: serde_json::Value = serde_json::from_str(&resp_line2).expect("valid JSON response");
    assert_eq!(v2["status"], "ok");
    let minted_id2 = v2["sessionId"].as_str().expect("sessionId in response");
    assert_ne!(minted_id2, "asserted-custom-pi-id-z");
    assert_ne!(
        minted_id2, minted_id,
        "Subsequent registration must mint a fresh UUID v4"
    );
}

// =============================================================================
// Oracle 9: Service name validation refusals
// Mutant M9a-site: drop the check at registration => RED
// Mutant M9a-fn: drop the char and UUID checks => RED
// Mutant M9b: drop the xmsg reservation => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_9_service_name_validation_refusals() {
    // 1. Direct validation tests for validate_service_name (catches M9a-fn and M9b)
    assert!(
        validate_service_name("xmsg").is_err(),
        "Name 'xmsg' must be refused"
    );
    assert!(
        validate_service_name("worker@host").is_err(),
        "Name with '@' must be refused"
    );
    assert!(
        validate_service_name("worker·daemon").is_err(),
        "Name with '·' must be refused"
    );
    assert!(
        validate_service_name("worker~2").is_err(),
        "Name with '~' must be refused"
    );
    assert!(
        validate_service_name("worker.daemon").is_err(),
        "Name with '.' must be refused"
    );
    assert!(
        validate_service_name("550e8400-e29b-41d4-a716-446655440000").is_err(),
        "UUID-shaped service name must be refused"
    );
    assert!(validate_service_name("guard").is_ok());
    assert!(validate_service_name("dispatcher").is_ok());

    // 2. Registration site validation via handle_svc_connection (catches M9a-site)
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();
    let svc_store = xmsg::svc::new_svc_store();
    let db = Arc::new(std::sync::Mutex::new(
        rusqlite::Connection::open_in_memory().unwrap(),
    ));
    init_db(&db.lock().unwrap()).unwrap();
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let my_uid = xmsg::agent::current_uid();
    setup_mock_proc(&proc_root, 9991, "100");
    let exe_path = proc_root.join("mock_exe");
    fs::write(&exe_path, "exe").unwrap();
    let _ = std::os::unix::fs::symlink(&exe_path, proc_root.join("9991").join("exe"));

    let bad_names = [
        "xmsg",
        "worker@host",
        "550e8400-e29b-41d4-a716-446655440000",
        "worker.dot",
        "worker~tilde",
        "svc:worker",
    ];

    let mut trusted = std::collections::HashMap::new();
    for bad_name in bad_names {
        trusted.insert(bad_name.to_string(), exe_path.clone());
    }

    for bad_name in bad_names {
        let (client_read, server_write) = tokio::io::duplex(1024);
        let reader = tokio::io::BufReader::new(tokio::io::empty());

        let req = xmsg::svc::SvcRegisterRequest {
            harness: None,
            name: bad_name.to_string(),
            cwd: None,
        };

        let res = xmsg::svc::handle_svc_connection(
            reader,
            server_write,
            std::sync::Arc::new(xmsg::http::AppState {
                sessions_dirs: vec![],
                agy_config: xmsg::agy::AgyConfig {
                    proc_root: proc_root.clone(),
                    ..Default::default()
                },
                agy_store: xmsg::agy::new_agy_store(),
                pi_store: xmsg::pi::new_pi_store(),
                pi_notify_tx: tokio::sync::broadcast::channel(16).0,
                svc_store: svc_store.clone(),
                svc_notify_tx: svc_notify_tx.clone(),
                node_name: "test-node".to_string(),
                max_body: 65536,
                request_counter: std::sync::atomic::AtomicU64::new(1),
                db: db.clone(),
                notify_tx: tokio::sync::broadcast::channel(16).0,
                reply_ttl: Duration::from_secs(60),
                idempotency_ttl: Duration::from_secs(60),
                long_poll_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(8)),
                fed_state: None,
            }),
            &trusted,
            my_uid,
            my_uid,
            9991,
            req,
            false,
            None,
        )
        .await;

        assert!(
            res.is_err(),
            "Registration for invalid service name '{bad_name}' MUST fail"
        );

        let mut resp_line = String::new();
        let mut buf_client = tokio::io::BufReader::new(client_read);
        buf_client.read_line(&mut resp_line).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&resp_line).expect("valid JSON response");
        assert_eq!(
            v["status"], "error",
            "Registration response for '{bad_name}' must be error"
        );
    }
}
