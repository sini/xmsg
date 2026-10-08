use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use xmsg::agy::{
    attest_mcp_caller, dev_major, dev_minor, flush_agy_queue, new_agy_store, run_register_server,
    AgyConfig, AgyCredentials, AgySessionInfo,
};
use xmsg::error::AppError;
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

// ---------------------------------------------------------------------------
// Oracle 1:
// --hook: credential-less => exactly one ephemeralMessage naming absolute exe;
//         credentialed    => {};
//         malformed stdin => {} with exit 0.
// Mutant: always inject.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_1_hook_credential_less_and_credentialed_and_malformed() {
    let bin = env!("CARGO_BIN_EXE_xmsg");
    let sock_dir = tempdir().unwrap();
    fs::set_permissions(sock_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let reg_sock = sock_dir.path().join("register.sock");

    let agy_config = AgyConfig::default();
    let agy_store = new_agy_store();
    let pi_store = xmsg::pi::new_pi_store();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let (pi_notify_tx, _) = broadcast::channel(1024);
    let my_uid = xmsg::agent::current_uid();

    // Insert conv-credless: no credentials
    let credless_info =
        AgySessionInfo::new("conv-credless".to_string(), 1111, "100".to_string(), None);
    agy_store
        .write()
        .unwrap()
        .insert("agy:1111:100".to_string(), credless_info);

    // Insert conv-creds: has credentials
    let creds_info = AgySessionInfo::new(
        "conv-creds".to_string(),
        2222,
        "200".to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:4000".to_string(),
            csrf_token: "secret".to_string(),
            is_stale: false,
        }),
    );
    agy_store
        .write()
        .unwrap()
        .insert("agy:2222:200".to_string(), creds_info);

    let reg_sock_clone = reg_sock.clone();
    let store_clone = agy_store.clone();
    let db_clone = db.clone();
    let pi_tx = pi_notify_tx.clone();
    tokio::spawn(async move {
        let _ = run_register_server(
            reg_sock_clone,
            agy_config,
            store_clone,
            pi_store,
            Vec::new(),
            Vec::new(),
            db_clone,
            pi_tx,
            Duration::from_secs(60),
            my_uid,
        )
        .await;
    });

    // Wait for register.sock to exist
    for _ in 0..50 {
        if reg_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(reg_sock.exists(), "register.sock must be created");

    // Case 1A: credential-less session => exactly one ephemeralMessage naming absolute exe
    {
        use std::io::Write;
        let mut child = Command::new(bin)
            .args([
                "register",
                "agy",
                "--hook",
                "--sock",
                reg_sock.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let stdin_payload = serde_json::json!({
            "conversationId": "conv-credless"
        });
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin_payload.to_string().as_bytes())
            .unwrap();

        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).unwrap();
        let val: Value = serde_json::from_str(stdout.trim()).expect("valid json output");
        let steps = val["injectSteps"]
            .as_array()
            .expect("injectSteps array must exist");
        assert_eq!(
            steps.len(),
            1,
            "must inject exactly one step for credential-less session"
        );
        let msg = steps[0]["ephemeralMessage"]
            .as_str()
            .expect("ephemeralMessage string must exist");
        assert!(
            msg.contains("register agy"),
            "message must tell model to run register agy: {msg}"
        );
        assert!(
            msg.contains(bin),
            "message must name the absolute exe path: {bin} in {msg}"
        );
    }

    // Case 1B: credentialed session => prints {}
    {
        use std::io::Write;
        let mut child = Command::new(bin)
            .args([
                "register",
                "agy",
                "--hook",
                "--sock",
                reg_sock.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let stdin_payload = serde_json::json!({
            "conversationId": "conv-creds"
        });
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin_payload.to_string().as_bytes())
            .unwrap();

        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout.trim(),
            "{}",
            "credentialed session must return empty object {{}}"
        );
    }

    // Case 1C: malformed stdin => prints {} and exits 0
    {
        use std::io::Write;
        let mut child = Command::new(bin)
            .args([
                "register",
                "agy",
                "--hook",
                "--sock",
                reg_sock.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"not json at all!")
            .unwrap();

        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "must exit 0 on malformed stdin"
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout.trim(),
            "{}",
            "malformed stdin must print {{}} to stdout"
        );
    }

    // Case 1D: missing conversationId => prints {} and exits 0
    {
        use std::io::Write;
        let mut child = Command::new(bin)
            .args([
                "register",
                "agy",
                "--hook",
                "--sock",
                reg_sock.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        child.stdin.as_mut().unwrap().write_all(b"{}").unwrap();

        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "must exit 0 on missing conversationId"
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout.trim(),
            "{}",
            "missing conversationId must print {{}} to stdout"
        );
    }
}

// ---------------------------------------------------------------------------
// Oracle 2:
// A message sent before credentials arrive is queued, then delivered exactly
// once after register, in order across 2 messages.
// Mutants: drop the flush; flush twice.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_2_queued_then_delivered_in_order_once() {
    let tmp = tempdir().unwrap();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));

    let delivered_log = tmp.path().join("delivered.log");
    let fake_agy_bin = tmp.path().join("fake_agy.sh");
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

    let proc_root = tmp.path().join("proc");
    let pid_dir = proc_root.join("5555");
    fs::create_dir_all(&pid_dir).unwrap();
    let stat_content =
        "5555 (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0 0 0 0\n";
    fs::write(pid_dir.join("stat"), stat_content).unwrap();

    let agy_config = AgyConfig {
        agy_bin: fake_agy_bin.to_string_lossy().to_string(),
        proc_root,
        ..Default::default()
    };
    let agy_store = new_agy_store();
    let pi_store = xmsg::pi::new_pi_store();
    let (notify_tx, _) = broadcast::channel(1024);
    let (pi_notify_tx, _) = broadcast::channel(1024);

    let session_key = "agy:5555:100".to_string();
    let conv_id = "conv-queue-test".to_string();

    // Session has identity from MCP start, but NO credentials yet (credentials: None)
    let credless_session = AgySessionInfo::new(conv_id.clone(), 5555, "100".to_string(), None);
    agy_store
        .write()
        .unwrap()
        .insert(session_key.clone(), credless_session);

    let state = Arc::new(AppState {
        sessions_dir: tmp.path().join("claude_sessions"),
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store,
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(60),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(10)),
    });

    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();

    // 1. Send Message 1
    let resp1 = client
        .post(format!("{base_url}/v1/sessions/{conv_id}/messages"))
        .json(&serde_json::json!({
            "from": "test-sender",
            "text": "first message payload"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp1.status(), reqwest::StatusCode::ACCEPTED);
    let body1: Value = resp1.json().await.unwrap();
    assert_eq!(
        body1["outcome"], "queued",
        "message sent before credentials must return outcome=queued"
    );

    // 2. Send Message 2
    let resp2 = client
        .post(format!("{base_url}/v1/sessions/{conv_id}/messages"))
        .json(&serde_json::json!({
            "from": "test-sender",
            "text": "second message payload"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp2.status(), reqwest::StatusCode::ACCEPTED);
    let body2: Value = resp2.json().await.unwrap();
    assert_eq!(
        body2["outcome"], "queued",
        "second message before credentials must return outcome=queued"
    );

    // Verify nothing delivered yet
    assert!(
        !delivered_log.exists(),
        "delivered.log must not exist before registration"
    );

    // 3. Now provide credentials to the store (as if xmsg register agy completed)
    {
        let mut store_lock = agy_store.write().unwrap();
        let entry = store_lock.get_mut(&session_key).unwrap();
        entry.credentials = Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "test-token".to_string(),
            is_stale: false,
        });
    }

    // 4. Trigger queue flush
    flush_agy_queue(&agy_config, &agy_store, &db, &session_key, &conv_id).await;

    // 5. Verify delivered in FIFO order
    assert!(
        delivered_log.exists(),
        "delivered.log must exist after flush"
    );
    let log_content = fs::read_to_string(&delivered_log).unwrap();
    let deliveries: Vec<&str> = log_content
        .split("===DELIVERY===\n")
        .filter(|s| !s.trim().is_empty())
        .collect();
    assert_eq!(
        deliveries.len(),
        2,
        "must deliver exactly 2 messages: got {deliveries:?}"
    );

    assert!(
        deliveries[0].contains("first message payload"),
        "delivery 1 must be message 1 in FIFO order: {}",
        deliveries[0]
    );
    assert!(
        deliveries[1].contains("second message payload"),
        "delivery 2 must be message 2 in FIFO order: {}",
        deliveries[1]
    );

    // 6. Verify database records updated to delivered
    {
        let db_lock = db.lock().unwrap();
        let mut stmt = db_lock
            .prepare("SELECT a.text, m.outcome, a.delivered_at FROM messages m JOIN agy_pending_messages a ON m.id = a.id ORDER BY m.created_at ASC")
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })
            .unwrap();
        let records: Vec<_> = rows.map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].1, "delivered");
        assert!(records[0].2.is_some());
        assert_eq!(records[1].1, "delivered");
        assert!(records[1].2.is_some());
    }

    // 7. Flush again: must NOT deliver again (exactly once!)
    flush_agy_queue(&agy_config, &agy_store, &db, &session_key, &conv_id).await;
    let log_content_after = fs::read_to_string(&delivered_log).unwrap();
    let deliveries_after: Vec<&str> = log_content_after
        .split("===DELIVERY===\n")
        .filter(|s| !s.trim().is_empty())
        .collect();
    assert_eq!(
        deliveries_after.len(),
        2,
        "subsequent flush must not deliver again; got {deliveries_after:?}"
    );
}

// ---------------------------------------------------------------------------
// Oracle 3:
// A live but unattested pid returns `unregistered`; the old "exited" text
// appears nowhere.
// Mutant: restore the old message.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_3_live_unattested_pid_returns_unregistered_without_exited() {
    let tmp = tempdir().unwrap();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let (notify_tx, _) = broadcast::channel(1024);
    let (pi_notify_tx, _) = broadcast::channel(1024);

    let state = Arc::new(AppState {
        sessions_dir: tmp.path().join("claude_sessions"),
        agy_config: AgyConfig::default(),
        agy_store: new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db,
        notify_tx,
        reply_ttl: Duration::from_secs(60),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(10)),
    });

    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let live_pid = std::process::id();

    // 1. GET /v1/sessions/{live_pid}
    let get_resp = client
        .get(format!("{base_url}/v1/sessions/{live_pid}"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        get_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "live unattested pid must return 400 Bad Request"
    );

    let get_str = get_resp.text().await.unwrap();
    let get_json: Value = serde_json::from_str(&get_str).expect("valid JSON response");

    assert_eq!(
        get_json["error"], "unregistered",
        "error code must be 'unregistered'"
    );
    assert_eq!(
        get_json["detail"],
        format!("process {live_pid} has no attested agent session")
    );
    assert!(
        !get_str.to_lowercase().contains("exited"),
        "the old 'exited' text must appear nowhere in response: {get_str}"
    );

    // 2. POST /v1/sessions/{live_pid}/messages
    let post_resp = client
        .post(format!("{base_url}/v1/sessions/{live_pid}/messages"))
        .json(&serde_json::json!({
            "from": "someone",
            "text": "hello to unattested process"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        post_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "send to live unattested pid must return 400 Bad Request"
    );

    let post_str = post_resp.text().await.unwrap();
    let post_json: Value = serde_json::from_str(&post_str).expect("valid JSON response");

    assert_eq!(
        post_json["error"], "unregistered",
        "error code must be 'unregistered'"
    );
    assert_eq!(
        post_json["detail"],
        format!("process {live_pid} has no attested agent session")
    );
    assert!(
        !post_str.to_lowercase().contains("exited"),
        "the old 'exited' text must appear nowhere in send error response: {post_str}"
    );
}

// ---------------------------------------------------------------------------
// Oracle 4:
// A non-agy ancestor (the wrong exe, or no presence lock) gets no identity
// at MCP start.
// ---------------------------------------------------------------------------

#[test]
fn oracle_4_non_agy_ancestor_gets_no_identity_at_mcp_start() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let lock_file = presence_dir.join("conv-oracle4.lock");
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE 4000 {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    let trusted_agy = tmp.path().join("trusted_agy");
    fs::write(&trusted_agy, "binary").unwrap();
    let untrusted_exe = tmp.path().join("some_other_exe");
    fs::write(&untrusted_exe, "binary").unwrap();

    let trusted_exes = vec![trusted_agy.clone()];

    // Case 4A: Wrong exe (untrusted_exe), even with presence lock open
    setup_mock_process(
        &proc_root,
        4000,
        1,
        Some(&untrusted_exe),
        Some(&lock_file),
        "100",
    );
    setup_mock_process(&proc_root, 4001, 4000, None, None, "200");

    let res_wrong_exe = attest_mcp_caller(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        4001,
    );
    match res_wrong_exe {
        Err(AppError::NotRecipient(msg)) => {
            assert!(
                msg.contains("no ancestor matching a trusted agy executable"),
                "unexpected error message: {msg}"
            );
        }
        other => panic!("expected NotRecipient for wrong exe, got {other:?}"),
    }

    // Case 4B: Trusted exe, but presence lock NOT open
    setup_mock_process(
        &proc_root,
        5000,
        1,
        Some(&trusted_agy),
        None, // no open lock!
        "100",
    );
    setup_mock_process(&proc_root, 5001, 5000, None, None, "200");

    let res_no_lock = attest_mcp_caller(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        5001,
    );
    match res_no_lock {
        Err(AppError::NotRecipient(msg)) => {
            assert!(
                msg.contains(
                    "no ancestor matching a trusted agy executable with presence lock open"
                ),
                "unexpected error message: {msg}"
            );
        }
        other => panic!("expected NotRecipient for missing lock, got {other:?}"),
    }

    // Case 4C: Trusted exe, presence lock open, FLOCK holder equals ancestor PID (positive control)
    let locks_content_4c = format!(
        "1: FLOCK ADVISORY WRITE 6000 {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content_4c).unwrap();

    setup_mock_process(
        &proc_root,
        6000,
        1,
        Some(&trusted_agy),
        Some(&lock_file),
        "100",
    );
    setup_mock_process(&proc_root, 6001, 6000, None, None, "200");

    let res_ok = attest_mcp_caller(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        6001,
    );
    match res_ok {
        Ok((reg, conv_id)) => {
            assert_eq!(reg.pid, 6000);
            assert_eq!(reg.starttime, "100");
            assert_eq!(reg.session_key, "agy:6000:100");
            assert_eq!(conv_id, "conv-oracle4");
        }
        other => panic!("expected Ok for valid agy ancestor, got {other:?}"),
    }
}
