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
    };
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

    // 1. Caller PID 3000 should resolve upwards to session claude-sess-alpha
    let resolved =
        resolve_caller_session(&proc_root, &sessions_dir, &agy_config, &pi_store, 3000).unwrap();
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

    match resolve_caller_session(&proc_root, &sessions_dir, &agy_config, &pi_store, 9999) {
        Err(AppError::NotRecipient(msg)) => {
            assert!(msg.contains("does not descend"));
        }
        other => panic!(
            "expected NotRecipient for unattached process, got: {:?}",
            other
        ),
    }
}

fn get_self_proc_start() -> String {
    let stat = fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    let rparen = stat.rfind(')').expect("closing paren in stat");
    let fields: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
    fields[19].to_string()
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
    };

    let app_state = Arc::new(AppState {
        sessions_dir: sessions_dir.clone(),
        agy_config,
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let s_path = agent_sock_path.clone();
    let s_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

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
        push_replies: false,
        thread_id: "msg-001".to_string(),
    };
    {
        let db_lock = db.lock().unwrap();
        xmsg::storage::insert_message(&db_lock, &msg_record).unwrap();
    }

    // 2. Reply to msg-001 from sess-caller-123
    let reply_req = serde_json::json!({
        "action": "reply",
        "messageId": "msg-001",
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
    assert_eq!(resp["reply"]["sessionRef"], "sess-caller-123");

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
        push_replies: false,
        thread_id: "msg-002".to_string(),
    };
    {
        let db_lock = db.lock().unwrap();
        xmsg::storage::insert_message(&db_lock, &other_msg_record).unwrap();
    }

    // 4. Try to reply to msg-002 -> not_recipient error
    let imposter_req = serde_json::json!({
        "action": "reply",
        "messageId": "msg-002",
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
    assert_eq!(err_resp["error"], "not_recipient");

    // 5. Send message over agent.sock (targeting sess-caller-123)
    let send_req = serde_json::json!({
        "action": "send",
        "ref": "sender-session",
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
    assert_eq!(
        send_resp["delivery"]["fromName"],
        "xmsg@test-host · claude:sender-session"
    );
}
