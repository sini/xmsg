use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use xmsg::agent::{
    current_uid, ensure_secure_socket_dir, resolve_caller_session, run_agent_server,
};
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::error::AppError;
use xmsg::http::AppState;
use xmsg::pi::new_pi_store;

mod reused_stat;

#[test]
fn test_ensure_secure_socket_dir_permissions_and_ownership() {
    let tmp = tempdir().unwrap();
    let my_uid = current_uid();
    let test_dir = tmp.path().join("secure_xmsg");

    // 1. Should create directory with mode 0700 if it does not exist
    assert!(ensure_secure_socket_dir(&test_dir, my_uid).is_ok());
    let meta = fs::metadata(&test_dir).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);

    // 2. Red Demo 3: Directory with mode 0755 fails with InsecureSocketDir
    fs::set_permissions(&test_dir, fs::Permissions::from_mode(0o755)).unwrap();
    match ensure_secure_socket_dir(&test_dir, my_uid) {
        Err(AppError::InsecureSocketDir(msg)) => {
            assert!(msg.contains("0700") || msg.contains("mode"));
        }
        other => panic!(
            "expected InsecureSocketDir error on mode 0755, got: {:?}",
            other
        ),
    }

    // Restore 0700
    fs::set_permissions(&test_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ensure_secure_socket_dir(&test_dir, my_uid).is_ok());

    // 3. Expected UID mismatch fails
    match ensure_secure_socket_dir(&test_dir, my_uid + 9999) {
        Err(AppError::InsecureSocketDir(msg)) => {
            assert!(msg.contains("UID"));
        }
        other => panic!(
            "expected InsecureSocketDir error on UID mismatch, got: {:?}",
            other
        ),
    }

    // 4. Symlink directory fails with InsecureSocketDir
    let symlink_path = tmp.path().join("symlink_dir");
    std::os::unix::fs::symlink(&test_dir, &symlink_path).unwrap();
    match ensure_secure_socket_dir(&symlink_path, my_uid) {
        Err(AppError::InsecureSocketDir(msg)) => {
            assert!(msg.contains("symlink"));
        }
        other => panic!(
            "expected InsecureSocketDir error on symlink, got: {:?}",
            other
        ),
    }
}

/// Concurrent socket servers create the socket dir at startup: every caller must see 0700,
/// never the umask-mode window between creation and chmod (OCI Image run 38359268103).
#[test]
fn test_ensure_secure_socket_dir_concurrent_create() {
    const THREADS: usize = 16;
    const ITERATIONS: usize = 5000;
    // SAFETY: umask is process-wide and has no failure mode; 022 is the CI default.
    unsafe { libc::umask(0o022) };
    let tmp = tempdir().unwrap();
    let my_uid = current_uid();
    let mut failures = Vec::new();
    for i in 0..ITERATIONS {
        let dir = tmp.path().join(format!("run{i}")).join("xmsg");
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let (dir, barrier) = (dir.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    ensure_secure_socket_dir(&dir, my_uid)
                })
            })
            .collect();
        for h in handles {
            if let Err(e) = h.join().unwrap() {
                failures.push(format!("iteration {i}: {e:?}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} calls failed; first: {}",
        failures.len(),
        THREADS * ITERATIONS,
        failures[0]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_missing_xdg_runtime_dir_returns_error() {
    let res = xmsg::agent::socket_dir_for_env(None);
    match res {
        Err(AppError::InsecureSocketDir(msg)) => {
            assert!(msg.contains("XDG_RUNTIME_DIR"));
        }
        other => {
            panic!(
                "expected InsecureSocketDir when XDG_RUNTIME_DIR is None, got: {:?}",
                other
            );
        }
    }

    let empty_res = xmsg::agent::socket_dir_for_env(Some("   "));
    assert!(matches!(empty_res, Err(AppError::InsecureSocketDir(_))));
}

#[cfg(target_os = "macos")]
#[test]
fn test_missing_xdg_runtime_dir_uses_darwin_user_temp_dir() {
    let out = std::process::Command::new("/usr/bin/getconf")
        .arg("DARWIN_USER_TEMP_DIR")
        .output()
        .expect("getconf DARWIN_USER_TEMP_DIR");
    let temp_dir = std::path::PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
    let expected = temp_dir.join("xmsg");

    assert_eq!(xmsg::agent::socket_dir_for_env(None).unwrap(), expected);
    assert_eq!(
        xmsg::agent::socket_dir_for_env(Some("   ")).unwrap(),
        expected
    );
    // sun_path is 104 bytes on macOS
    assert!(expected.join("register.sock").as_os_str().len() < 104);

    let meta = fs::metadata(&temp_dir).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
}

#[test]
fn test_xdg_runtime_dir_wins() {
    let valid_res = xmsg::agent::socket_dir_for_env(Some("/run/user/1000"));
    assert_eq!(
        valid_res.unwrap(),
        std::path::PathBuf::from("/run/user/1000/xmsg")
    );
}

#[test]
fn test_resolve_caller_session_ancestor_walk() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    let presence_dir = tmp.path().join("presence");
    let proc_locks_path = tmp.path().join("locks");

    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks_path, "").unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path,
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
            brain_dir: std::path::PathBuf::new(),
    };
    let agy_store = new_agy_store();
    let pi_store = new_pi_store();

    // Setup process hierarchy: PID 3000 -> PPID 2000 -> PPID 1000 -> PPID 1
    // PID 1000 holds a Claude session file
    let pid_3000_dir = proc_root.join("3000");
    let pid_2000_dir = proc_root.join("2000");
    let pid_1000_dir = proc_root.join("1000");
    fs::create_dir_all(&pid_3000_dir).unwrap();
    fs::create_dir_all(&pid_2000_dir).unwrap();
    fs::create_dir_all(&pid_1000_dir).unwrap();

    fs::write(
        pid_3000_dir.join("stat"),
        "3000 (child) S 2000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0\n",
    )
    .unwrap();
    fs::write(
        pid_2000_dir.join("stat"),
        "2000 (wrapper) S 1000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0\n",
    )
    .unwrap();
    fs::write(
        pid_1000_dir.join("stat"),
        "1000 (agent) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0\n",
    )
    .unwrap();

    let session_json = serde_json::json!({
        "pid": 1000,
        "sessionId": "claude-sess-alpha",
        "name": "alpha-agent",
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": "100",
        "messagingSocketPath": "/tmp/dummy.sock"
    });
    fs::write(sessions_dir.join("1000.json"), session_json.to_string()).unwrap();

    let svc_store = xmsg::svc::new_svc_store();

    // 1. Caller PID 3000 should resolve upwards to session claude-sess-alpha
    let resolved = resolve_caller_session(
        &proc_root,
        &sessions_dir,
        &agy_config,
        &agy_store,
        &pi_store,
        &svc_store,
        None,
        3000,
    )
    .unwrap();
    assert_eq!(resolved.session_id, "claude-sess-alpha");
    assert_eq!(resolved.name.as_deref(), Some("alpha-agent"));

    // 2. Caller PID 9999 (not descending from any session) should fail
    let pid_9999_dir = proc_root.join("9999");
    fs::create_dir_all(&pid_9999_dir).unwrap();
    fs::write(
        pid_9999_dir.join("stat"),
        "9999 (rogue) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0\n",
    )
    .unwrap();

    match resolve_caller_session(
        &proc_root,
        &sessions_dir,
        &agy_config,
        &agy_store,
        &pi_store,
        &svc_store,
        None,
        9999,
    ) {
        Err(AppError::NotRecipient(msg)) => {
            assert!(msg.contains("does not descend"));
        }
        other => panic!(
            "expected NotRecipient for unattached process, got: {:?}",
            other
        ),
    }
}

/// The A15 walk over a synthetic chain 3000 -> 2000 -> 1000 (a live Claude session), with
/// 2000's start time `parent_start`; 1000 started at 100 and 3000 at 300.
fn resolve_through_middle_link(parent_start: &str) -> Result<xmsg::registry::Session, AppError> {
    resolve_with_middle_link(|proc_root| {
        let dir = proc_root.join("2000");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("stat"),
            format!("2000 (p) S 1000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {parent_start} 0 0\n"),
        )
        .unwrap();
    })
}

/// The chain of [`resolve_through_middle_link`] with 2000's stat written by `middle`.
fn resolve_with_middle_link(
    middle: impl FnOnce(&std::path::Path),
) -> Result<xmsg::registry::Session, AppError> {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    let agy_config = AgyConfig {
        presence_dir: tmp.path().join("presence"),
        proc_locks_path: tmp.path().join("locks"),
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
            brain_dir: std::path::PathBuf::new(),
    };
    let stat = |pid: u32, ppid: u32, start: &str| {
        let dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("stat"),
            format!("{pid} (p) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start} 0 0\n"),
        )
        .unwrap();
    };
    stat(1000, 1, "100");
    middle(&proc_root);
    stat(3000, 2000, "300");
    let session = serde_json::json!({
        "pid": 1000, "sessionId": "sess-a", "cwd": "/", "status": "idle",
        "kind": "interactive", "startedAt": 1, "updatedAt": 1, "procStart": "100",
        "messagingSocketPath": "/tmp/dummy.sock",
    });
    fs::write(sessions_dir.join("1000.json"), session.to_string()).unwrap();
    resolve_caller_session(
        &proc_root,
        &sessions_dir,
        &agy_config,
        &new_agy_store(),
        &new_pi_store(),
        &xmsg::svc::new_svc_store(),
        None,
        3000,
    )
}

/// A15: a link whose parent started after its child is a PID reused mid-walk, so the walk
/// fails closed to anonymous instead of attributing the caller to whatever owns the new PID.
#[test]
fn test_resolve_caller_session_rejects_parent_younger_than_child() {
    // Control: 2000 started before its child 3000, so the chain is the session's.
    assert_eq!(
        resolve_through_middle_link("200").unwrap().session_id,
        "sess-a"
    );
    // 2000 "started" after its child 3000: a reused PID, so the caller is anonymous.
    match resolve_through_middle_link("400") {
        Err(AppError::NotRecipient(msg)) => assert!(msg.contains("not older"), "{msg}"),
        other => panic!("expected NotRecipient for a parent younger than its child: {other:?}"),
    }
}

/// A15: a start time that cannot be read as a number cannot show the parent is older, so the
/// walk fails closed rather than stepping past it.
#[test]
fn test_resolve_caller_session_fails_closed_on_unreadable_start() {
    match resolve_through_middle_link("unreadable") {
        Err(AppError::NotRecipient(msg)) => assert!(msg.contains("cannot be read"), "{msg}"),
        other => panic!("expected NotRecipient for an unreadable start time: {other:?}"),
    }
}

/// A15: 2000 is reused AFTER the step read its start time: 3000's genuine parent (under init)
/// when the step reads it, a child of session 1000 that started after 3000 when the walk
/// reaches it. The walk requires the start it recorded, so the caller stays anonymous.
#[test]
fn test_resolve_caller_session_refuses_parent_reused_after_its_step() {
    let reused = resolve_with_middle_link(|proc_root| {
        reused_stat::reused_stat(
            proc_root,
            2000,
            vec![
                reused_stat::stat_line(2000, 1, 200),
                reused_stat::stat_line(2000, 1000, 400),
            ],
        )
    });
    match reused {
        Err(AppError::NotRecipient(msg)) => assert!(msg.contains("reused"), "{msg}"),
        other => panic!("expected NotRecipient for a PID reused mid-walk: {other:?}"),
    }
}

fn get_self_proc_start() -> String {
    xmsg::process::starttime(
        std::path::Path::new(xmsg::process::LIVE_PROC_ROOT),
        std::process::id(),
    )
    .expect("live starttime")
}

#[tokio::test]
async fn test_agent_sock_reply_and_send_flow() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = tmp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock_path = sock_dir.join("agent.sock");
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    let presence_dir = tmp.path().join("presence");
    let proc_locks_path = tmp.path().join("locks");

    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks_path, "").unwrap();

    let my_pid = std::process::id();
    let my_uid = current_uid();
    let my_proc_start = get_self_proc_start();

    // Setup proc entry for current test process
    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        format!("{my_pid} (test) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {my_proc_start} 0 0\n"),
    )
    .unwrap();

    let target_sock = tmp.path().join("target.sock");
    let target_listener = tokio::net::UnixListener::bind(&target_sock).unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = target_listener.accept().await {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
        }
    });

    // Register current test process as session-sender
    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": "sess-caller-123",
        "name": "sender-session",
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": target_sock.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}.json")),
        session_json.to_string(),
    )
    .unwrap();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path,
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
            brain_dir: std::path::PathBuf::new(),
    };

    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config,
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        node_name: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let s_path = agent_sock_path.clone();
    let s_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    for _ in 0..1500 {
        if agent_sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        agent_sock_path.exists(),
        "the in-process server never bound its socket in 30s"
    );

    // Connect to agent.sock
    let stream = UnixStream::connect(&agent_sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // 1. Insert a message into DB addressed to sess-caller-123
    let msg_record = xmsg::storage::MessageRecord {
        id: "msg-001".to_string(),
        created_at: xmsg::storage::now_epoch_secs(),
        session_id: "sess-caller-123".to_string(),
        from_name: "orchestrator".to_string(),
        bytes: 20,
        outcome: "delivered".to_string(),
        recipient_harness: "claude".to_string(),
        return_harness: None,
        return_session_id: None,
        thread_id: "msg-001".to_string(),
        return_host: None,
    };
    {
        let db_lock = db.lock().unwrap();
        xmsg::storage::insert_message(&db_lock, &msg_record).unwrap();
    }

    // 2. Reply to msg-001 from sess-caller-123
    let reply_req = serde_json::json!({
        "action": "reply",
        "message_id": "msg-001",
        "text": "Attested reply over agent.sock"
    });
    writer
        .write_all(format!("{reply_req}\n").as_bytes())
        .await
        .unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["status"], "ok");
    assert_eq!(resp["reply"]["messageId"], "msg-001");
    assert_eq!(resp["reply"]["text"], "Attested reply over agent.sock");
    assert_eq!(resp["reply"]["replierSessionId"], "sess-caller-123");

    // 3. Insert a message addressed to a different session (sess-other-999)
    let other_msg_record = xmsg::storage::MessageRecord {
        id: "msg-002".to_string(),
        created_at: xmsg::storage::now_epoch_secs(),
        session_id: "sess-other-999".to_string(),
        from_name: "orchestrator".to_string(),
        bytes: 20,
        outcome: "delivered".to_string(),
        recipient_harness: "claude".to_string(),
        return_harness: None,
        return_session_id: None,
        thread_id: "msg-002".to_string(),
        return_host: None,
    };
    {
        let db_lock = db.lock().unwrap();
        xmsg::storage::insert_message(&db_lock, &other_msg_record).unwrap();
    }

    // 4. Try to reply to msg-002 -> not_recipient error
    let imposter_req = serde_json::json!({
        "action": "reply",
        "message_id": "msg-002",
        "text": "Imposter reply attempt"
    });
    writer
        .write_all(format!("{imposter_req}\n").as_bytes())
        .await
        .unwrap();

    line.clear();
    reader.read_line(&mut line).await.unwrap();
    let err_resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(err_resp["status"], "error");
    assert_eq!(err_resp["error"], "denied");

    // 5. Send message over agent.sock (targeting sess-caller-123)
    let send_req = serde_json::json!({
        "action": "send",
        "to": "sender-session",
        "text": "Hello self over agent.sock"
    });
    writer
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();

    line.clear();
    reader.read_line(&mut line).await.unwrap();
    let send_resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(send_resp["status"], "ok");
    assert_eq!(send_resp["address"], "sess-caller-123@test-host");
    let sent = {
        let db_lock = db.lock().unwrap();
        xmsg::storage::get_message(&db_lock, send_resp["message_id"].as_str().unwrap())
            .unwrap()
            .unwrap()
    };
    assert_eq!(sent.from_name, "sender-session · sess-caller-123@test-host");
}

/// XS2 (HB1 self-review C4a): `SvcStore` in `resolve_caller_session_peer` admits only hop 0
/// (`curr_pid == peer_pid`). A service daemon is attested by its own `--svc-exe` binary at
/// `peer_pid` (GI-9); a child or descendant process spawned by that service (such as a
/// tier-1 `pi --mode rpc` worker or `bash` subprocess under `genie-root`) must NOT inherit
/// the service's identity on `agent.sock`, while the service process itself (hop 0) still
/// resolves as `svc:<name>` and Claude/agy/pi ancestry walks remain unchanged.
#[tokio::test]
async fn test_xs2_svc_store_admits_only_hop0_while_refusing_child_of_svc() {
    if let Ok(sock) = std::env::var("XS2_CHILD_AGENT_SOCK") {
        let stream = UnixStream::connect(&sock).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let req = serde_json::json!({
            "action": "send",
            "schema_version": 2,
            "to": "genie",
            "text": "bypass from child"
        });
        writer
            .write_all(format!("{req}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        print!("XS2_CHILD_JSON:{line}");
        return;
    }

    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = tmp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock_path = sock_dir.join("agent.sock");
    let proc_root = std::path::PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let sessions_dir = tmp.path().join("sessions");
    let presence_dir = tmp.path().join("presence");
    let proc_locks_path = tmp.path().join("locks");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let my_uid = current_uid();
    let self_pid = std::process::id();
    let self_start = get_self_proc_start();

    let svc_store = xmsg::svc::new_svc_store();
    {
        let mut lock = svc_store.write().unwrap();
        lock.insert(
            "genie".to_string(),
            xmsg::svc::SvcSessionInfo {
                session_id: "genie".to_string(),
                name: "genie".to_string(),
                pid: self_pid,
                starttime: self_start.clone(),
                cwd: "/".to_string(),
                registered_at: 1000,
            },
        );
    }

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path,
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: std::path::PathBuf::new(),
    };

    // 1. Unit check over synthetic proc_root: hop 0 resolves to `svc:genie`, hop 1 and hop 2
    //    descending from `svc:genie` are refused (`NotRecipient`), while a Pi ancestor at hop 1
    //    still resolves via ancestry.
    {
        let synth_proc = tmp.path().join("synth_proc");
        let write_stat = |pid: u32, ppid: u32, start: &str| {
            let d = synth_proc.join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("stat"),
                format!("{pid} (p) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start} 0 0\n"),
            )
            .unwrap();
        };
        write_stat(5000, 1, "100");
        write_stat(5001, 5000, "200");
        write_stat(5002, 5001, "300");

        let synth_svc = xmsg::svc::new_svc_store();
        synth_svc.write().unwrap().insert(
            "genie".to_string(),
            xmsg::svc::SvcSessionInfo {
                session_id: "genie".to_string(),
                name: "genie".to_string(),
                pid: 5000,
                starttime: "100".to_string(),
                cwd: "/".to_string(),
                registered_at: 1000,
            },
        );

        // Hop 0 (PID 5000 itself) resolves as svc:genie
        let hop0 = resolve_caller_session(
            &synth_proc,
            &sessions_dir,
            &agy_config,
            &new_agy_store(),
            &new_pi_store(),
            &synth_svc,
            None,
            5000,
        )
        .expect("hop 0 svc process must resolve");
        assert_eq!(hop0.session_id, "genie");
        assert_eq!(hop0.harness, "svc");

        // Hop 1 (child PID 5001 of svc 5000) MUST NOT resolve as svc:genie
        let hop1 = resolve_caller_session(
            &synth_proc,
            &sessions_dir,
            &agy_config,
            &new_agy_store(),
            &new_pi_store(),
            &synth_svc,
            None,
            5001,
        );
        assert!(
            matches!(hop1, Err(AppError::NotRecipient(_))),
            "child of svc (hop 1) must be refused NotRecipient, got: {hop1:?}"
        );

        // Hop 2 (grandchild PID 5002 of svc 5000) MUST NOT resolve as svc:genie
        let hop2 = resolve_caller_session(
            &synth_proc,
            &sessions_dir,
            &agy_config,
            &new_agy_store(),
            &new_pi_store(),
            &synth_svc,
            None,
            5002,
        );
        assert!(
            matches!(hop2, Err(AppError::NotRecipient(_))),
            "grandchild of svc (hop 2) must be refused NotRecipient, got: {hop2:?}"
        );

        // Positive control: a Pi session at PID 5000 still resolves for child PID 5001 (hop 1)
        let synth_pi = new_pi_store();
        synth_pi.write().unwrap().insert(
            "pi-parent-id".to_string(),
            xmsg::pi::PiSessionInfo {
                session_id: "pi-parent-id".to_string(),
                name: Some("pi-parent".to_string()),
                pid: 5000,
                starttime: "100".to_string(),
                cwd: "/".to_string(),
                registered_at: 1000,
            },
        );
        let pi_hop1 = resolve_caller_session(
            &synth_proc,
            &sessions_dir,
            &agy_config,
            &new_agy_store(),
            &synth_pi,
            &synth_svc,
            None,
            5001,
        )
        .expect("child of pi session must still resolve via ancestry");
        assert_eq!(pi_hop1.session_id, "pi-parent-id");
        assert_eq!(pi_hop1.harness, "pi");
    }

    // 2. Live agent.sock check: this process (registered as svc:genie at self_pid) can send
    //    over agent.sock as genie@test-host, while a real child OS process spawned by self_pid
    //    is refused on agent.sock (`denied` / not a recipient).
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir],
        agy_config,
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx,
        svc_store,
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        node_name: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let s_path = agent_sock_path.clone();
    let s_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });
    for _ in 0..500 {
        if agent_sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Hop 0 (self_pid) sends to genie over agent.sock -> succeeds as genie@test-host
    {
        let stream = UnixStream::connect(&agent_sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let send_req = serde_json::json!({
            "action": "send",
            "schema_version": 2,
            "to": "genie",
            "text": "from genie hop 0"
        });
        writer
            .write_all(format!("{send_req}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["status"], "ok", "hop 0 svc send must succeed: {resp}");
        assert_eq!(resp["address"], "genie@test-host");
    }

    // Hop 1 (real OS child process of self_pid) attempts to send over agent.sock -> refused!
    let child_out = tokio::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("test_xs2_svc_store_admits_only_hop0_while_refusing_child_of_svc")
        .arg("--nocapture")
        .env("XS2_CHILD_AGENT_SOCK", &agent_sock_path)
        .output()
        .await
        .expect("spawn child test binary");
    assert!(
        child_out.status.success(),
        "child exited non-zero: {:?}",
        String::from_utf8_lossy(&child_out.stderr)
    );
    let stdout_str = String::from_utf8_lossy(&child_out.stdout);
    let json_line = stdout_str
        .lines()
        .find_map(|l| l.strip_prefix("XS2_CHILD_JSON:"))
        .unwrap_or_else(|| panic!("missing XS2_CHILD_JSON in stdout: {stdout_str}"));
    let child_resp: serde_json::Value =
        serde_json::from_str(json_line).expect("valid json from agent.sock");
    assert_eq!(
        child_resp["status"], "error",
        "child of svc must be refused on agent.sock, got: {child_resp}"
    );
    assert_eq!(child_resp["error"], "denied", "{child_resp}");
    assert!(
        child_resp["detail"]
            .as_str()
            .unwrap_or("")
            .contains("does not descend from an active agent session"),
        "unexpected error detail: {child_resp}"
    );
}
