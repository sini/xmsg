use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use xmsg::http::{build_router, AppState};
use xmsg::inbox::InboxLine;
use xmsg::registry::{list_sessions, resolve_session, resolve_sessions_dirs, SessionsQuery};

fn get_self_proc_start() -> String {
    xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), std::process::id())
        .expect("live starttime")
}

fn write_claude_session(
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
        "cwd": "/workspace/project",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": proc_start,
        "messagingSocketPath": sock_path.display().to_string()
    });
    fs::write(
        dir.join(format!("{pid}_{session_id}.json")),
        session_json.to_string(),
    )
    .expect("write session file");
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

struct TestHttpServer {
    base_url: String,
}

async fn start_test_server(sessions_dirs: Vec<PathBuf>) -> TestHttpServer {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);

    let state = Arc::new(AppState {
        sessions_dirs: sessions_dirs.clone(),
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: PathBuf::from("/tmp/nonexistent-presence"),
            proc_locks_path: PathBuf::from("/tmp/nonexistent-proc-locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: Arc::new(std::sync::Mutex::new(conn)),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestHttpServer {
        base_url: format!("http://{}", addr),
    }
}

/// Oracle 1: Sessions in two configured dirs are both listed and both deliverable.
/// (Mutant: only first dir read => RED)
#[tokio::test]
async fn test_oracle_1_multi_dir_listed_and_deliverable() {
    let dir_a = tempdir().expect("tempdir for dir_a");
    let dir_b = tempdir().expect("tempdir for dir_b");

    let listener_a = start_socket_listener("inbox_a").await;
    let listener_b = start_socket_listener("inbox_b").await;

    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();

    // Session A in dir_a
    write_claude_session(
        dir_a.path(),
        my_pid,
        "sess-alpha-001",
        "worker-alpha",
        &my_proc_start,
        &listener_a.sock_path,
    );

    // Session B in dir_b
    write_claude_session(
        dir_b.path(),
        my_pid,
        "sess-beta-002",
        "worker-beta",
        &my_proc_start,
        &listener_b.sock_path,
    );

    let configured_dirs = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];

    // 1. Registry list check across both dirs
    let sessions = list_sessions(&configured_dirs, &SessionsQuery::default());
    assert_eq!(
        sessions.len(),
        2,
        "Both sessions must be listed by registry"
    );
    let ids: Vec<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();
    assert!(
        ids.contains(&"sess-alpha-001"),
        "sess-alpha-001 must be listed"
    );
    assert!(
        ids.contains(&"sess-beta-002"),
        "sess-beta-002 must be listed"
    );

    // 2. HTTP Server GET /v1/sessions
    let server = start_test_server(configured_dirs).await;
    let client = reqwest::Client::new();

    let list_res = client
        .get(format!("{}/v1/sessions", server.base_url))
        .send()
        .await
        .expect("send get /v1/sessions");
    assert_eq!(list_res.status(), 200);
    let sessions_array: Vec<serde_json::Value> = list_res.json().await.unwrap();
    assert_eq!(
        sessions_array.len(),
        2,
        "HTTP /v1/sessions must return both sessions"
    );

    // 3. Deliverability to session in dir_a
    let post_a = client
        .post(format!(
            "{}/v1/sessions/sess-alpha-001/messages",
            server.base_url
        ))
        .json(&serde_json::json!({
            "from": "claude",
            "text": "Hello Alpha"
        }))
        .send()
        .await
        .expect("post to alpha");
    assert_eq!(post_a.status(), 202, "Message to sess-alpha-001 accepted");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let lines_a = listener_a.received_lines.lock().await;
    assert_eq!(lines_a.len(), 1, "Session A must receive message");
    let inbox_a: InboxLine = serde_json::from_str(lines_a[0].trim()).unwrap();
    assert!(inbox_a.message.content.contains("Hello Alpha"));
    drop(lines_a);

    // 4. Deliverability to session in dir_b
    let post_b = client
        .post(format!(
            "{}/v1/sessions/sess-beta-002/messages",
            server.base_url
        ))
        .json(&serde_json::json!({
            "from": "claude",
            "text": "Hello Beta"
        }))
        .send()
        .await
        .expect("post to beta");
    assert_eq!(post_b.status(), 202, "Message to sess-beta-002 accepted");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let lines_b = listener_b.received_lines.lock().await;
    assert_eq!(lines_b.len(), 1, "Session B must receive message");
    let inbox_b: InboxLine = serde_json::from_str(lines_b[0].trim()).unwrap();
    assert!(inbox_b.message.content.contains("Hello Beta"));
    drop(lines_b);
}

/// Oracle 2: No flag => behavior identical to today (default dir only).
#[test]
fn test_oracle_2_default_dir_resolution() {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let default_expected = PathBuf::from(&home).join(".claude").join("sessions");

    // When no dirs are provided and no env vars set, resolve to ~/.claude/sessions
    // Temporarily clear any XMSG_SESSIONS_DIR env var to simulate default run
    let orig_env = std::env::var("XMSG_SESSIONS_DIR").ok();
    let orig_env_dirs = std::env::var("XMSG_SESSIONS_DIRS").ok();
    std::env::remove_var("XMSG_SESSIONS_DIR");
    std::env::remove_var("XMSG_SESSIONS_DIRS");

    let resolved_default = resolve_sessions_dirs(vec![]);
    assert_eq!(
        resolved_default,
        vec![default_expected.clone()],
        "Default without flag/env must be ~/.claude/sessions"
    );

    // Test with colon-separated paths in env var
    let dir1 = "/tmp/claude_sess_1";
    let dir2 = "/tmp/claude_sess_2";
    std::env::set_var("XMSG_SESSIONS_DIR", format!("{dir1}:{dir2}"));
    let resolved_env = resolve_sessions_dirs(vec![]);
    assert_eq!(
        resolved_env,
        vec![PathBuf::from(dir1), PathBuf::from(dir2)],
        "Colon-separated env var must resolve both directories"
    );

    // Test with explicit flag vector
    let resolved_explicit = resolve_sessions_dirs(vec![
        PathBuf::from("/tmp/explicit_1"),
        PathBuf::from("/tmp/explicit_2"),
    ]);
    assert_eq!(
        resolved_explicit,
        vec![
            PathBuf::from("/tmp/explicit_1"),
            PathBuf::from("/tmp/explicit_2")
        ],
        "Explicit vector must resolve both directories"
    );

    // Restore env
    if let Some(val) = orig_env {
        std::env::set_var("XMSG_SESSIONS_DIR", val);
    } else {
        std::env::remove_var("XMSG_SESSIONS_DIR");
    }
    if let Some(val) = orig_env_dirs {
        std::env::set_var("XMSG_SESSIONS_DIRS", val);
    } else {
        std::env::remove_var("XMSG_SESSIONS_DIRS");
    }
}

/// Oracle 3: Duplicate sessionId across dirs => not listed, error logged.
/// (Mutant: last-wins => RED)
#[tokio::test]
async fn test_oracle_3_duplicate_session_across_dirs_excluded_fail_closed() {
    let dir_a = tempdir().expect("tempdir for dir_a");
    let dir_b = tempdir().expect("tempdir for dir_b");

    let listener = start_socket_listener("inbox_test").await;
    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();

    // Session with same ID in BOTH dir_a and dir_b
    let duplicate_id = "sess-colliding-dup-999";
    write_claude_session(
        dir_a.path(),
        my_pid,
        duplicate_id,
        "worker-dup-in-a",
        &my_proc_start,
        &listener.sock_path,
    );
    write_claude_session(
        dir_b.path(),
        my_pid,
        duplicate_id,
        "worker-dup-in-b",
        &my_proc_start,
        &listener.sock_path,
    );

    // Unique session in dir_b
    let unique_id = "sess-unique-legit-777";
    write_claude_session(
        dir_b.path(),
        my_pid,
        unique_id,
        "worker-unique-legit",
        &my_proc_start,
        &listener.sock_path,
    );

    let configured_dirs = vec![dir_a.path().to_path_buf(), dir_b.path().to_path_buf()];

    // 1. Registry list check: duplicate session must NOT be listed
    let sessions = list_sessions(&configured_dirs, &SessionsQuery::default());
    let listed_ids: Vec<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();
    assert!(
        !listed_ids.contains(&duplicate_id),
        "Duplicate session ID across dirs must NOT be listed (fail closed)"
    );
    assert!(
        listed_ids.contains(&unique_id),
        "Unique session must be listed normally"
    );

    // 2. Registry resolve check: duplicate session must fail to resolve
    let resolve_dup = resolve_session(&configured_dirs, duplicate_id);
    assert!(
        resolve_dup.is_err(),
        "Resolving duplicate session ID must fail closed"
    );
    let resolve_unique = resolve_session(&configured_dirs, unique_id);
    assert!(
        resolve_unique.is_ok(),
        "Resolving unique session ID must succeed"
    );

    // 3. HTTP Server behavior
    let server = start_test_server(configured_dirs).await;
    let client = reqwest::Client::new();

    let list_res = client
        .get(format!("{}/v1/sessions", server.base_url))
        .send()
        .await
        .unwrap();
    let returned_sessions: Vec<serde_json::Value> = list_res.json().await.unwrap();
    let returned_ids: Vec<&str> = returned_sessions
        .iter()
        .filter_map(|s| s["sessionId"].as_str())
        .collect();
    assert!(
        !returned_ids.contains(&duplicate_id),
        "HTTP /v1/sessions must NOT return duplicate session ID"
    );
    assert!(
        returned_ids.contains(&unique_id),
        "HTTP /v1/sessions must return unique session ID"
    );

    // 4. Delivery to duplicate session must fail 404 (fail closed)
    let post_dup = client
        .post(format!(
            "{}/v1/sessions/{duplicate_id}/messages",
            server.base_url
        ))
        .json(&serde_json::json!({
            "from": "claude",
            "text": "Message to duplicate"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        post_dup.status(),
        404,
        "Delivery to duplicate session must return 404 Not Found"
    );

    // 5. Delivery to unique session must succeed 202
    let post_unique = client
        .post(format!(
            "{}/v1/sessions/{unique_id}/messages",
            server.base_url
        ))
        .json(&serde_json::json!({
            "from": "claude",
            "text": "Message to unique"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        post_unique.status(),
        202,
        "Delivery to unique session must return 202 Accepted"
    );
}
