use axum::http::StatusCode;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

use xmsg::agy::{current_uid, new_agy_store, run_register_server, AgyConfig};
use xmsg::http::{build_router, AppState};
use xmsg::pi::new_pi_store;
use xmsg::svc::{new_svc_store, SvcStore};

struct SvcTestHarness {
    _temp: tempfile::TempDir,
    proc_root: PathBuf,
    sock_path: PathBuf,
    trusted_bin: PathBuf,
    untrusted_bin: PathBuf,
    http_port: u16,
    svc_store: SvcStore,
    #[allow(dead_code)]
    my_uid: u32,
    my_pid: u32,
}

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

async fn setup_harness(service_name: &str) -> SvcTestHarness {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = sock_dir.join("register.sock");

    let proc_root = temp.path().join("proc");
    let sessions_dir = temp.path().join("sessions");
    let presence_dir = temp.path().join("presence");
    let proc_locks = temp.path().join("locks");

    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let trusted_bin = temp.path().join("trusted_dispatcher");
    fs::write(&trusted_bin, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&trusted_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let untrusted_bin = temp.path().join("untrusted_binary");
    fs::write(&untrusted_bin, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&untrusted_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let mut trusted_svc_exes: HashMap<String, PathBuf> = HashMap::new();
    trusted_svc_exes.insert(service_name.to_string(), trusted_bin.clone());

    let my_pid = std::process::id();
    let my_uid = current_uid();

    // Default setup: current process is mocked as running trusted_bin
    setup_mock_proc(&proc_root, my_pid, &trusted_bin, "100000");

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);

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

    let reg_config = agy_config.clone();
    let reg_store = agy_store.clone();
    let reg_pi_store = pi_store.clone();
    let reg_svc_store = svc_store.clone();
    let reg_trusted_svc = trusted_svc_exes.clone();
    let reg_sock = sock_path.clone();
    let reg_db = db.clone();
    let reg_pi_notify = pi_notify_tx.clone();
    let reg_svc_notify = svc_notify_tx.clone();

    tokio::spawn(async move {
        let _ = run_register_server(
            reg_sock,
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
        sessions_dirs: vec![sessions_dir],
        agy_config,
        agy_store,
        pi_store,
        pi_notify_tx,
        svc_store: svc_store.clone(),
        svc_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db,
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let app = build_router(app_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Wait briefly for register.sock to exist
    for _ in 0..50 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    SvcTestHarness {
        _temp: temp,
        proc_root,
        sock_path,
        trusted_bin,
        untrusted_bin,
        http_port,
        svc_store,
        my_uid,
        my_pid,
    }
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

/// Oracle 1: A trusted executable with matching UID registers successfully and is addressable.
/// - Registers on register.sock as svc:<name>.
/// - Addressable in GET /v1/sessions as harness "svc" and status "idle".
/// - Addressable via both svc:<name> and <name> on GET /v1/sessions/:ref.
/// - Inbound message to svc:<name> is accepted and queued as delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_1_trusted_exe_registered_and_addressable() {
    let harness = setup_harness("dispatcher").await;
    let (mut reader, mut writer) = connect_svc(&harness.sock_path).await;

    // 1. Register with trusted exe
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "dispatcher",
        "cwd": "/workspace"
    });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();

    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(
        reg_resp.get("status").and_then(|s| s.as_str()),
        Some("ok"),
        "Registration with trusted exe must succeed: {:?}",
        reg_resp
    );
    assert_eq!(
        reg_resp.get("sessionId").and_then(|s| s.as_str()),
        Some("svc:dispatcher")
    );

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", harness.http_port);

    // 2. Query /v1/sessions: must list svc:dispatcher
    let sessions_resp: Value = client
        .get(format!("{base_url}/v1/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let sessions = sessions_resp.as_array().expect("sessions list");
    let svc_session = sessions
        .iter()
        .find(|s| s.get("sessionId").and_then(|v| v.as_str()) == Some("svc:dispatcher"))
        .expect("svc:dispatcher session must be present in /v1/sessions");

    assert_eq!(
        svc_session.get("harness").and_then(|v| v.as_str()),
        Some("svc")
    );
    assert_eq!(
        svc_session.get("status").and_then(|v| v.as_str()),
        Some("idle")
    );
    assert_eq!(
        svc_session.get("kind").and_then(|v| v.as_str()),
        Some("daemon")
    );
    assert_eq!(
        svc_session.get("registered").and_then(|v| v.as_bool()),
        Some(true)
    );

    // 3. Addressable as svc:dispatcher on /v1/sessions/:ref
    let get_prefixed = client
        .get(format!("{base_url}/v1/sessions/svc:dispatcher"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_prefixed.status(), StatusCode::OK);
    let session_val: Value = get_prefixed.json().await.unwrap();
    assert_eq!(
        session_val.get("sessionId").and_then(|v| v.as_str()),
        Some("svc:dispatcher")
    );

    // 4. Addressable as plain name (dispatcher) on /v1/sessions/:ref
    let get_unprefixed = client
        .get(format!("{base_url}/v1/sessions/dispatcher"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_unprefixed.status(), StatusCode::OK);

    // 5. Send message to svc:dispatcher via HTTP
    let send_resp = client
        .post(format!("{base_url}/v1/sessions/svc:dispatcher/messages"))
        .json(&serde_json::json!({
            "from": "user",
            "text": "ping dispatcher"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(send_resp.status(), StatusCode::ACCEPTED);
    let send_val: Value = send_resp.json().await.unwrap();
    assert_eq!(
        send_val.get("outcome").and_then(|v| v.as_str()),
        Some("delivered")
    );
    assert_eq!(
        send_val.get("sessionId").and_then(|v| v.as_str()),
        Some("svc:dispatcher")
    );
}

/// Oracle 2: An untrusted executable connecting to register.sock is refused.
/// - Mutant 2: skip the executable check => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_2_untrusted_exe_refused() {
    let harness = setup_harness("dispatcher").await;

    // Switch current process's mock exe to untrusted_binary
    setup_mock_proc(
        &harness.proc_root,
        harness.my_pid,
        &harness.untrusted_bin,
        "100000",
    );

    let (mut reader, mut writer) = connect_svc(&harness.sock_path).await;

    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "dispatcher",
        "cwd": "/workspace"
    });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();

    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(
        reg_resp.get("status").and_then(|s| s.as_str()),
        Some("error"),
        "Registration with untrusted exe MUST fail with error: {:?}",
        reg_resp
    );

    // Verify session was NOT registered
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", harness.http_port);
    let get_resp = client
        .get(format!("{base_url}/v1/sessions/svc:dispatcher"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        get_resp.status(),
        StatusCode::NOT_FOUND,
        "Untrusted service must not be addressable"
    );
}

/// Oracle 3: Messages sent to svc:<name> are delivered once, in order.
/// - Mutant 3: drop it => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_3_message_delivered_once_in_order() {
    let harness = setup_harness("order-test").await;
    let (mut reader, mut writer) = connect_svc(&harness.sock_path).await;

    // 1. Register daemon
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "order-test",
    });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(reg_resp.get("status").and_then(|s| s.as_str()), Some("ok"));

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", harness.http_port);

    // 2. Send 3 sequential messages
    for i in 1..=3 {
        let resp = client
            .post(format!("{base_url}/v1/sessions/svc:order-test/messages"))
            .json(&serde_json::json!({
                "from": "sender",
                "text": format!("payload-{i}")
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    // 3. Long-poll and ACK each message sequentially
    for i in 1..=3 {
        let poll_cmd = serde_json::json!({ "action": "poll", "waitSecs": 5 });
        writer
            .write_all(format!("{poll_cmd}\n").as_bytes())
            .await
            .unwrap();

        let msg_resp = read_json_line(&mut reader).await;
        assert_eq!(
            msg_resp.get("action").and_then(|a| a.as_str()),
            Some("deliver"),
            "Expected deliver for message {i}, got: {:?}",
            msg_resp
        );
        let text = msg_resp.get("text").and_then(|t| t.as_str()).unwrap();
        assert_eq!(
            text,
            format!("payload-{i}"),
            "Messages must be delivered in FIFO order"
        );

        let msg_id = msg_resp
            .get("messageId")
            .and_then(|m| m.as_str())
            .expect("messageId");
        let ack_cmd = serde_json::json!({ "action": "ack", "messageId": msg_id });
        writer
            .write_all(format!("{ack_cmd}\n").as_bytes())
            .await
            .unwrap();

        let ack_resp = read_json_line(&mut reader).await;
        assert_eq!(ack_resp.get("status").and_then(|s| s.as_str()), Some("ok"));
    }

    // 4. Next poll with waitSecs: 0 should timeout (all messages delivered once)
    let poll_empty = serde_json::json!({ "action": "poll", "waitSecs": 0 });
    writer
        .write_all(format!("{poll_empty}\n").as_bytes())
        .await
        .unwrap();
    let timeout_resp = read_json_line(&mut reader).await;
    assert_eq!(
        timeout_resp.get("action").and_then(|a| a.as_str()),
        Some("timeout"),
        "Queue must be empty after all messages are acknowledged"
    );
}

/// Oracle 4: The long-poll cursor advances ONLY on explicit acknowledgement.
/// If a daemon crashes/disconnects before acking, it receives the message again on next poll.
/// - Mutant 4: advance cursor on send rather than ack => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_4_cursor_advances_only_on_explicit_ack() {
    let harness = setup_harness("cursor-test").await;

    // 1. First connection: register and send message
    let (mut reader1, mut writer1) = connect_svc(&harness.sock_path).await;
    let reg_frame = serde_json::json!({ "harness": "svc", "name": "cursor-test" });
    writer1
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut reader1).await;
    assert_eq!(reg_resp.get("status").and_then(|s| s.as_str()), Some("ok"));

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", harness.http_port);
    let send_resp = client
        .post(format!("{base_url}/v1/sessions/svc:cursor-test/messages"))
        .json(&serde_json::json!({
            "from": "coordinator",
            "text": "critical-task-payload"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(send_resp.status(), StatusCode::ACCEPTED);

    // 2. Daemon polls and receives message
    let poll_cmd = serde_json::json!({ "action": "poll", "waitSecs": 5 });
    writer1
        .write_all(format!("{poll_cmd}\n").as_bytes())
        .await
        .unwrap();
    let msg_resp = read_json_line(&mut reader1).await;
    assert_eq!(
        msg_resp.get("action").and_then(|a| a.as_str()),
        Some("deliver")
    );
    let original_msg_id = msg_resp
        .get("messageId")
        .and_then(|m| m.as_str())
        .unwrap()
        .to_string();
    assert_eq!(
        msg_resp.get("text").and_then(|t| t.as_str()),
        Some("critical-task-payload")
    );

    // 3. Simulate daemon crash: DROP connection WITHOUT sending ack
    drop(reader1);
    drop(writer1);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Restarted daemon connects and registers again
    let (mut reader2, mut writer2) = connect_svc(&harness.sock_path).await;
    writer2
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp2 = read_json_line(&mut reader2).await;
    assert_eq!(reg_resp2.get("status").and_then(|s| s.as_str()), Some("ok"));

    // 5. Poll again: MUST receive the unacknowledged message again!
    writer2
        .write_all(format!("{poll_cmd}\n").as_bytes())
        .await
        .unwrap();
    let redelivery_resp = read_json_line(&mut reader2).await;
    assert_eq!(
        redelivery_resp.get("action").and_then(|a| a.as_str()),
        Some("deliver"),
        "Unacknowledged message must be redelivered upon daemon restart: {:?}",
        redelivery_resp
    );
    assert_eq!(
        redelivery_resp.get("messageId").and_then(|m| m.as_str()),
        Some(original_msg_id.as_str()),
        "Redelivered message ID must match original message ID"
    );
    assert_eq!(
        redelivery_resp.get("text").and_then(|t| t.as_str()),
        Some("critical-task-payload")
    );

    // 6. Explicitly ACK the message
    let ack_cmd = serde_json::json!({ "action": "ack", "messageId": original_msg_id });
    writer2
        .write_all(format!("{ack_cmd}\n").as_bytes())
        .await
        .unwrap();
    let ack_resp = read_json_line(&mut reader2).await;
    assert_eq!(ack_resp.get("status").and_then(|s| s.as_str()), Some("ok"));

    // 7. Verify queue is now empty
    let poll_empty = serde_json::json!({ "action": "poll", "waitSecs": 0 });
    writer2
        .write_all(format!("{poll_empty}\n").as_bytes())
        .await
        .unwrap();
    let timeout_resp = read_json_line(&mut reader2).await;
    assert_eq!(
        timeout_resp.get("action").and_then(|a| a.as_str()),
        Some("timeout")
    );
}

/// Oracle 5: (Gate r2 G5) A second live registration of an already-registered svc:<name>
/// is refused while the first is alive.
/// - Mutant 5: last-wins => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_5_second_live_registration_refused() {
    let harness = setup_harness("singleton-svc").await;

    // 1. Spawn a genuine live child process (sleep 60) to represent the first running daemon
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn live sleep child");
    let child_pid = child.id();
    let child_start = "1234567";

    // Set up mock proc for child process as trusted executable
    setup_mock_proc(
        &harness.proc_root,
        child_pid,
        &harness.trusted_bin,
        child_start,
    );

    // Register child_pid as active in svc_store
    {
        let mut store_lock = harness.svc_store.write().unwrap();
        store_lock.insert(
            "svc:singleton-svc".to_string(),
            xmsg::svc::SvcSessionInfo {
                session_id: "svc:singleton-svc".to_string(),
                name: "singleton-svc".to_string(),
                pid: child_pid,
                starttime: child_start.to_string(),
                cwd: "/workspace".to_string(),
                registered_at: xmsg::storage::now_epoch_secs(),
            },
        );
    }

    // 2. A second daemon (current test process with different PID) attempts to register svc:singleton-svc
    assert_ne!(harness.my_pid, child_pid);
    let (mut reader, mut writer) = connect_svc(&harness.sock_path).await;

    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "singleton-svc",
        "cwd": "/other-workspace"
    });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();

    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(
        reg_resp.get("status").and_then(|s| s.as_str()),
        Some("error"),
        "Second registration for live svc MUST be refused with error: {:?}",
        reg_resp
    );
    assert!(
        reg_resp
            .get("detail")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .contains("already has an active registration"),
        "Error detail must state service already has an active registration, got: {:?}",
        reg_resp
    );

    // Verify original registration is intact and not overwritten
    {
        let store_lock = harness.svc_store.read().unwrap();
        let current_info = store_lock.get("svc:singleton-svc").unwrap();
        assert_eq!(
            current_info.pid, child_pid,
            "Original active daemon PID must NOT be overwritten by second registration attempt"
        );
    }

    // 3. Positive control: Kill the first daemon, now registration MUST succeed!
    let _ = child.kill();
    let _ = child.wait();

    // Mark the mock stat as gone/dead or wait for OS kill
    let child_stat = harness.proc_root.join(child_pid.to_string()).join("stat");
    let _ = fs::remove_file(child_stat);

    let (mut reader2, mut writer2) = connect_svc(&harness.sock_path).await;
    writer2
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();

    let reg_resp2 = read_json_line(&mut reader2).await;
    assert_eq!(
        reg_resp2.get("status").and_then(|s| s.as_str()),
        Some("ok"),
        "Registration after first daemon dies MUST succeed: {:?}",
        reg_resp2
    );
    assert_eq!(
        reg_resp2.get("sessionId").and_then(|s| s.as_str()),
        Some("svc:singleton-svc")
    );
}
