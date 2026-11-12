use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::broadcast;

use xmsg::agy::{dev_major, dev_minor, new_agy_store, AgyConfig, AgyCredentials};
use xmsg::http::{build_router, AppState};

#[tokio::test(flavor = "multi_thread")]
async fn test_agy_delivery_env_isolation_and_credentials_lifecycle() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sess_dir).unwrap();

    let my_pid = std::process::id();

    // 1. Create presence lock for c904fe8e-df56-5cf9-8285-e2d97512d4e7
    let conv_id = "c904fe8e-df56-5cf9-8285-e2d97512d4e7";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {my_pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    let stat_content =
        format!("{my_pid} (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0 0 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).unwrap();

    // 2. Create fake agy script
    let fake_agy_bin = tmp.path().join("fake_agy.sh");
    let argv_log = tmp.path().join("captured_argv.txt");
    let env_log = tmp.path().join("captured_env.txt");
    let fail_file = tmp.path().join("fail_unauth");

    let script_content = format!(
        r#"#!/bin/sh
echo "$@" > "{}"
env > "{}"
if [ -f "{}" ]; then
    printf '{{\n  "response": {{}},\n  "error": "rpc error: code = Unauthenticated desc = unauthenticated: invalid CSRF token"\n}}\n'
    exit 1
fi
escaped=$(printf '%s' "$7" | awk 'BEGIN {{ ORS="" }} {{ gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\r/, "\\r"); if (NR > 1) printf "\\n"; printf "%s", $0 }}')
printf '{{\n  "response": {{\n    "sendMessage": {{\n      "recipientId": "%s",\n      "content": "%s"\n    }}\n  }}\n}}\n' "$6" "$escaped"
exit 0
"#,
        argv_log.display(),
        env_log.display(),
        fail_file.display()
    );
    fs::write(&fake_agy_bin, script_content).unwrap();
    fs::set_permissions(&fake_agy_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root,
        agy_bin: fake_agy_bin.to_string_lossy().to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: std::path::PathBuf::new(),
    };
    let agy_store = new_agy_store();

    // Register initial credentials
    let initial_info = xmsg::agy::AgySessionInfo::new(
        conv_id.to_string(),
        my_pid,
        "100".to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "super-secret-token-xyz".to_string(),
            is_stale: false,
        }),
    );
    let initial_key = initial_info.session_key.clone();
    agy_store
        .write()
        .unwrap()
        .insert(initial_key.clone(), initial_info);

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let (notify_tx, _) = broadcast::channel(16);

    let (pi_notify_tx, _) = broadcast::channel(16);
    let state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![sess_dir],
        agy_config,
        agy_store: agy_store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: broadcast::channel(16).0,
        node_name: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: Arc::new(Mutex::new(conn)),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let send_url = format!("http://127.0.0.1:{port}/v1/messages");

    // --- Phase 1: Successful Delivery ---
    let resp = client
        .post(&send_url)
        .json(&serde_json::json!({"to": conv_id,
            "from": "claude-orch",
            "text": "Hello Antigravity session!"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(resp_body["address"], format!("{initial_key}@test-host"));
    let msg_id = resp_body["message_id"].as_str().unwrap().to_string();
    assert!(!msg_id.is_empty());

    // Verify argv: contains session, title, and envelope; NEVER contains csrf_token
    let captured_argv = fs::read_to_string(&argv_log).unwrap();
    assert!(captured_argv.contains("agentapi send-message --title claude-orch · anon@test-host"));
    assert!(captured_argv.contains(conv_id));
    assert!(captured_argv.contains(&format!("[xmsg] from=claude-orch · anon@test-host message_id={msg_id} — reply with the xmsg reply tool (tools: send, reply, list, replies)\n\nHello Antigravity session!")));
    assert!(
        !captured_argv.contains("super-secret-token-xyz"),
        "Security Invariant: CSRF token MUST NOT appear in argv"
    );

    // Verify env: credentials passed strictly via environment
    let captured_env = fs::read_to_string(&env_log).unwrap();
    assert!(captured_env.contains("ANTIGRAVITY_LS_ADDRESS=127.0.0.1:9999"));
    assert!(captured_env.contains("ANTIGRAVITY_CSRF_TOKEN=super-secret-token-xyz"));

    // --- Phase 2: Unauthenticated / Credentials Stale ---
    fs::write(&fail_file, "trigger fail").unwrap();

    let resp_fail = client
        .post(&send_url)
        .json(&serde_json::json!({
            "to": conv_id,
            "from": "claude-orch",
            "text": "This should fail with credentials_stale"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_fail.status(), reqwest::StatusCode::ACCEPTED);
    let fail_body: serde_json::Value = resp_fail.json().await.unwrap();
    assert_eq!(fail_body["outcome"], "queued");

    // Verify marked stale in memory store
    {
        let store = agy_store.read().unwrap();
        let creds = store.get(&initial_key).unwrap();
        assert!(
            creds.credentials.as_ref().unwrap().is_stale,
            "Store entry must be marked stale after Unauthenticated error"
        );
        assert!(
            !creds.has_credentials(),
            "has_credentials() must return false when credentials are marked stale"
        );
    }

    // Removing fail_file still queues in agy_pending_messages because store is stale
    fs::remove_file(&fail_file).unwrap();
    let resp_still_stale = client
        .post(&send_url)
        .json(&serde_json::json!({
            "to": conv_id,
            "from": "claude-orch",
            "text": "Still stale before re-registration"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_still_stale.status(), reqwest::StatusCode::ACCEPTED);
    let still_stale_body: serde_json::Value = resp_still_stale.json().await.unwrap();
    assert_eq!(still_stale_body["outcome"], "queued");

    // --- Phase 3: Re-registration Recovery ---
    let refreshed_info = xmsg::agy::AgySessionInfo::new(
        conv_id.to_string(),
        my_pid,
        "100".to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "refreshed-token-456".to_string(),
            is_stale: false,
        }),
    );
    agy_store
        .write()
        .unwrap()
        .insert(refreshed_info.session_key.clone(), refreshed_info);

    let resp_recovered = client
        .post(&send_url)
        .json(&serde_json::json!({
            "to": conv_id,
            "from": "claude-orch",
            "text": "Delivered after refreshed credentials"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_recovered.status(), reqwest::StatusCode::ACCEPTED);

    // Verify env updated to new token
    let captured_env2 = fs::read_to_string(&env_log).unwrap();
    assert!(captured_env2.contains("ANTIGRAVITY_CSRF_TOKEN=refreshed-token-456"));
}

#[tokio::test]
async fn xa6_exit_zero_body_with_trigger_phrases_delivers_without_stale_and_records_message() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sess_dir).unwrap();

    let my_pid = std::process::id();
    let conv_id = "d904fe8e-df56-5cf9-8285-e2d97512d4e8";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = dev_major(meta.dev());
    let min = dev_minor(meta.dev());
    let ino = meta.ino();

    fs::write(
        &proc_locks,
        format!("1: FLOCK ADVISORY WRITE {my_pid} {maj:02x}:{min:02x}:{ino} 0 EOF\n"),
    )
    .unwrap();

    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        format!("{my_pid} (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0 0 0 0\n"),
    )
    .unwrap();

    // Real `agy agentapi send-message` echoes the message body inside `response.sendMessage.content` on exit 0.
    let fake_agy_bin = tmp.path().join("fake_agy_echo.sh");
    let echo_script = r#"#!/bin/sh
escaped=$(printf '%s' "$7" | awk 'BEGIN { ORS="" } { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\r/, "\\r"); if (NR > 1) printf "\\n"; printf "%s", $0 }')
printf '{\n  "response": {\n    "sendMessage": {\n      "recipientId": "%s",\n      "content": "%s"\n    }\n  }\n}\n' "$6" "$escaped"
exit 0
"#;
    fs::write(&fake_agy_bin, echo_script).unwrap();
    fs::set_permissions(&fake_agy_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root,
        agy_bin: fake_agy_bin.to_string_lossy().to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: std::path::PathBuf::new(),
    };
    let agy_store = new_agy_store();
    let initial_info = xmsg::agy::AgySessionInfo::new(
        conv_id.to_string(),
        my_pid,
        "100".to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "token-xa6-ok".to_string(),
            is_stale: false,
        }),
    );
    let initial_key = initial_info.session_key.clone();
    agy_store
        .write()
        .unwrap()
        .insert(initial_key.clone(), initial_info);

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![sess_dir],
        agy_config,
        agy_store: agy_store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: broadcast::channel(16).0,
        node_name: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx: broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let recipient_session = xmsg::registry::Session {
        session_id: conv_id.to_string(),
        name: Some("agy".to_string()),
        pid: my_pid,
        cwd: "/tmp".to_string(),
        status: "live".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: 100,
        updated_at: 100,
        harness: "agy".to_string(),
        registered: Some(true),
    };
    let sender = xmsg::surface::Sender::Anonymous("claude-orch".to_string());

    for phrase in [
        "Investigating Unauthenticated error in logs",
        "Investigating connection refused on port 8787",
        "Failed to connect to bus: Connection refused (os error 111)",
        "rpc error: code = Unauthenticated desc = unauthenticated: invalid CSRF token",
        "rpc error: code = Unavailable desc = connection error",
    ] {
        let send_res = xmsg::surface::send(&state, &sender, conv_id, phrase, None)
            .await
            .expect("exit 0 delivery carrying trigger phrase must succeed");
        assert_eq!(send_res.outcome, "delivered", "phrase={phrase}");
        assert_eq!(send_res.address, format!("{initial_key}@test-host"));

        {
            let store = agy_store.read().unwrap();
            let info = store.get(&initial_key).unwrap();
            assert!(
                !info.credentials.as_ref().unwrap().is_stale,
                "exit 0 body phrase '{phrase}' must never mark credentials stale"
            );
            assert!(info.has_credentials());
        }

        // Verify the message record is present in `messages` and `reply` resolves it.
        {
            let db_lock = db.lock().unwrap();
            let rec = xmsg::storage::get_message(&db_lock, &send_res.message_id)
                .unwrap()
                .expect("messages row must exist after exit 0 delivery");
            assert_eq!(rec.outcome, "delivered");
            assert!(
                xmsg::storage::fetch_undelivered_agy_messages(&db_lock, &[conv_id])
                    .unwrap()
                    .is_empty()
            );
        }

        let reply_res = xmsg::surface::reply(
            &state,
            &recipient_session,
            &send_res.message_id,
            "ack",
            None,
        )
        .await
        .expect("reply must find message_id in messages table");
        assert_eq!(reply_res.message_id, send_res.message_id);
    }
}

#[tokio::test]
async fn xa6_genuine_auth_failure_marks_stale_queues_records_message_rearms_watcher_and_flushes() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sess_dir).unwrap();

    let my_pid = std::process::id();
    let conv_id = "e904fe8e-df56-5cf9-8285-e2d97512d4e9";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = dev_major(meta.dev());
    let min = dev_minor(meta.dev());
    let ino = meta.ino();

    fs::write(
        &proc_locks,
        format!("1: FLOCK ADVISORY WRITE {my_pid} {maj:02x}:{min:02x}:{ino} 0 EOF\n"),
    )
    .unwrap();

    let fake_agy_bin = tmp.path().join("fake_agy_xa6.sh");
    let delivered_log = tmp.path().join("delivered_xa6.log");
    let fail_unauth_file = tmp.path().join("fail_unauth_xa6");
    let fail_unavail_file = tmp.path().join("fail_unavail_xa6");

    let script_content = format!(
        r#"#!/bin/sh
if [ -f "{}" ]; then
    printf '{{\n  "response": {{}},\n  "error": "rpc error: code = Unauthenticated desc = unauthenticated: invalid CSRF token"\n}}\n'
    exit 1
fi
if [ -f "{}" ]; then
    printf '{{\n  "response": {{}},\n  "error": "rpc error: code = Unavailable desc = connection error: desc = \\"transport: Error while dialing: dial tcp 127.0.0.1:1: connect: connection refused\\""\n}}\n'
    exit 1
fi
echo "===DELIVERED===" >> "{}"
echo "$@" >> "{}"
escaped=$(printf '%s' "$7" | awk 'BEGIN {{ ORS="" }} {{ gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\r/, "\\r"); if (NR > 1) printf "\\n"; printf "%s", $0 }}')
printf '{{\n  "response": {{\n    "sendMessage": {{\n      "recipientId": "%s",\n      "content": "%s"\n    }}\n  }}\n}}\n' "$6" "$escaped"
exit 0
"#,
        fail_unauth_file.display(),
        fail_unavail_file.display(),
        delivered_log.display(),
        delivered_log.display()
    );
    fs::write(&fake_agy_bin, script_content).unwrap();
    fs::set_permissions(&fake_agy_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let pid_dir = proc_root.join(my_pid.to_string());
    let fd_dir = pid_dir.join("fd");
    let task_dir = pid_dir.join("task").join(my_pid.to_string());
    fs::create_dir_all(&fd_dir).unwrap();
    fs::create_dir_all(&task_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        format!("{my_pid} (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0 0 0 0\n"),
    )
    .unwrap();
    std::os::unix::fs::symlink(&fake_agy_bin, pid_dir.join("exe")).unwrap();
    std::os::unix::fs::symlink(&lock_file, fd_dir.join("3")).unwrap();
    fs::write(task_dir.join("children"), "").unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: proc_root.clone(),
        agy_bin: fake_agy_bin.to_string_lossy().to_string(),
        trusted_agy_exes: vec![fake_agy_bin.clone()],
        brain_dir: std::path::PathBuf::new(),
    };
    let agy_store = new_agy_store();
    let initial_info = xmsg::agy::AgySessionInfo::new(
        conv_id.to_string(),
        my_pid,
        "100".to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "stale-token-xa6".to_string(),
            is_stale: false,
        }),
    );
    let initial_key = initial_info.session_key.clone();
    agy_store
        .write()
        .unwrap()
        .insert(initial_key.clone(), initial_info);

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![sess_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: broadcast::channel(16).0,
        node_name: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx: broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    // Start `run_agy_proc_watcher` while credentials are non-stale so `armed` starts empty.
    let (_arm_tx, arm_rx) = tokio::sync::mpsc::unbounded_channel();
    let watcher_handle = tokio::spawn(xmsg::agy::run_agy_proc_watcher(
        agy_config.clone(),
        agy_store.clone(),
        db.clone(),
        xmsg::agent::current_uid(),
        arm_rx,
        Duration::from_secs(3600),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sender = xmsg::surface::Sender::Anonymous("claude-orch".to_string());
    let recipient_session = xmsg::registry::Session {
        session_id: conv_id.to_string(),
        name: Some("agy".to_string()),
        pid: my_pid,
        cwd: "/tmp".to_string(),
        status: "live".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: 100,
        updated_at: 100,
        harness: "agy".to_string(),
        registered: Some(true),
    };

    // 1. Trigger genuine auth failure (exit 1 + JSON `.error` with `code = Unauthenticated` on stdout, stderr empty).
    fs::write(&fail_unauth_file, "fail").unwrap();
    let send_m1 = xmsg::surface::send(
        &state,
        &sender,
        conv_id,
        "message 1 on stale transition",
        None,
    )
    .await
    .expect("genuine auth failure must fall through to agy_pending_messages, not fail send");
    assert_eq!(send_m1.outcome, "queued");
    assert_eq!(send_m1.address, format!("{initial_key}@test-host"));

    {
        let store = agy_store.read().unwrap();
        let info = store.get(&initial_key).unwrap();
        assert!(
            info.credentials.as_ref().unwrap().is_stale,
            "genuine auth failure must mark credentials stale"
        );
        assert!(
            !info.has_credentials(),
            "has_credentials() must be false when credentials are stale"
        );
    }

    // Verify `messages` table recorded `send_m1.message_id` with outcome `queued` so `reply` finds it.
    {
        let db_lock = db.lock().unwrap();
        let rec = xmsg::storage::get_message(&db_lock, &send_m1.message_id)
            .unwrap()
            .expect("messages row must exist when delivery falls through to agy_pending_messages");
        assert_eq!(rec.outcome, "queued");
        let pending = xmsg::storage::fetch_undelivered_agy_messages(&db_lock, &[conv_id]).unwrap();
        assert_eq!(pending.len(), 1);
    }

    let reply_m1 = xmsg::surface::reply(
        &state,
        &recipient_session,
        &send_m1.message_id,
        "reply to queued message",
        None,
    )
    .await
    .expect("reply must find message_id even when initial delivery fell back to queue");
    assert_eq!(reply_m1.message_id, send_m1.message_id);

    // 2. Also verify `push_reply` falls through to `agy_pending_messages` ("pushed") on `CredentialsStale`
    // when `agy_has_creds` is true and `deliver_agy_envelope` fails with JSON `.error` (`code = Unavailable`).
    fs::remove_file(&fail_unauth_file).unwrap();
    fs::write(&fail_unavail_file, "fail").unwrap();
    {
        let mut store = agy_store.write().unwrap();
        store
            .get_mut(&initial_key)
            .unwrap()
            .credentials
            .as_mut()
            .unwrap()
            .is_stale = false;
    }
    let push_outcome = xmsg::surface::push_reply(
        &state.local(),
        "agy",
        conv_id,
        &send_m1.message_id,
        "01M6XA6REPLYPUSH0000000001",
        "claude-orch",
        xmsg::client::Origin::anonymous("claude-orch", "test-host"),
        "pushed reply while stale",
    )
    .await;
    assert_eq!(
        push_outcome, "pushed",
        "push_reply must queue in agy_pending_messages rather than returning sender_gone"
    );
    assert!(
        !agy_store
            .read()
            .unwrap()
            .get(&initial_key)
            .unwrap()
            .has_credentials(),
        "push_reply Unavailable failure must mark credentials stale again"
    );

    // 3. Remove `fail_unavail_file` and expose a descendant process carrying refreshed credentials.
    // Because `deliver_agy_envelope` called `notify_agy_escrow()`, `run_agy_proc_watcher`
    // must wake from `escrow_rx.changed()`, re-arm `conv_id`, harvest the new token, and flush the queue.
    fs::remove_file(&fail_unavail_file).unwrap();
    let child_pid = 99001u32;
    let child_dir = proc_root.join(child_pid.to_string());
    fs::create_dir_all(child_dir.join("fd")).unwrap();
    fs::write(
        child_dir.join("stat"),
        format!("{child_pid} (sh) S {my_pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 500 0 0 0 0 0 0 0 0 0 0\n"),
    )
    .unwrap();
    fs::write(
        child_dir.join("environ"),
        b"ANTIGRAVITY_LS_ADDRESS=127.0.0.1:9999\0ANTIGRAVITY_CSRF_TOKEN=refreshed-token-xa6\0",
    )
    .unwrap();
    fs::write(task_dir.join("children"), format!("{child_pid} ")).unwrap();

    let mut flushed = false;
    for _ in 0..40 {
        let has_fresh = {
            let store = agy_store.read().unwrap();
            store.get(&initial_key).is_some_and(|info| {
                info.has_credentials()
                    && info
                        .credentials
                        .as_ref()
                        .is_some_and(|c| !c.is_stale && c.csrf_token == "refreshed-token-xa6")
            })
        };
        let undelivered = {
            let db_lock = db.lock().unwrap();
            xmsg::storage::fetch_undelivered_agy_messages(&db_lock, &[conv_id])
                .unwrap()
                .len()
        };
        if has_fresh && undelivered == 0 {
            flushed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    watcher_handle.abort();
    assert!(
        flushed,
        "run_agy_proc_watcher must re-arm on stale transition, refresh credentials, and flush agy_pending_messages"
    );

    let delivered_text = fs::read_to_string(&delivered_log).unwrap_or_default();
    assert!(delivered_text.contains("message 1 on stale transition"));
    assert!(delivered_text.contains("pushed reply while stale"));

    let db_lock = db.lock().unwrap();
    let rec_after = xmsg::storage::get_message(&db_lock, &send_m1.message_id)
        .unwrap()
        .unwrap();
    assert_eq!(rec_after.outcome, "delivered");
}

async fn assert_nonzero_exit_not_stale(stdout_payload: &str, stderr_payload: &str) {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sess_dir = tmp.path().join("sessions");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sess_dir).unwrap();

    let my_pid = std::process::id();
    let conv_id = "f904fe8e-df56-5cf9-8285-e2d97512d4ea";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = dev_major(meta.dev());
    let min = dev_minor(meta.dev());
    let ino = meta.ino();

    fs::write(
        &proc_locks,
        format!("1: FLOCK ADVISORY WRITE {my_pid} {maj:02x}:{min:02x}:{ino} 0 EOF\n"),
    )
    .unwrap();

    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        format!("{my_pid} (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0 0 0 0\n"),
    )
    .unwrap();

    let stdout_file = tmp.path().join("fake_stdout.txt");
    let stderr_file = tmp.path().join("fake_stderr.txt");
    fs::write(&stdout_file, stdout_payload).unwrap();
    fs::write(&stderr_file, stderr_payload).unwrap();

    let fake_agy_bin = tmp.path().join("fake_agy_nonzero.sh");
    let script = format!(
        "#!/bin/sh\ncat \"{}\"\ncat \"{}\" >&2\nexit 1\n",
        stdout_file.display(),
        stderr_file.display()
    );
    fs::write(&fake_agy_bin, script).unwrap();
    fs::set_permissions(&fake_agy_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root,
        agy_bin: fake_agy_bin.to_string_lossy().to_string(),
        trusted_agy_exes: Vec::new(),
        brain_dir: std::path::PathBuf::new(),
    };
    let agy_store = new_agy_store();
    let initial_info = xmsg::agy::AgySessionInfo::new(
        conv_id.to_string(),
        my_pid,
        "100".to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "token-xa6-nonzero".to_string(),
            is_stale: false,
        }),
    );
    let initial_key = initial_info.session_key.clone();
    agy_store
        .write()
        .unwrap()
        .insert(initial_key.clone(), initial_info);

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![sess_dir],
        agy_config,
        agy_store: agy_store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: broadcast::channel(16).0,
        node_name: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db,
        notify_tx: broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let sender = xmsg::surface::Sender::Anonymous("claude-orch".to_string());
    let err = xmsg::surface::send(&state, &sender, conv_id, "test body", None)
        .await
        .expect_err("non-auth non-zero exit must fail with InboxUnavailable");
    assert!(
        matches!(err, xmsg::error::AppError::InboxUnavailable(_)),
        "expected InboxUnavailable, got {err:?}"
    );
    let store = agy_store.read().unwrap();
    let info = store.get(&initial_key).unwrap();
    assert!(
        !info.credentials.as_ref().unwrap().is_stale,
        "non-zero exit without auth code in .error must NEVER mark credentials stale"
    );
    assert!(
        info.has_credentials(),
        "non-zero exit without auth code in .error must keep has_credentials() == true"
    );
}

#[tokio::test]
async fn xa6_nonzero_exit_phrases_in_response_without_error_field_not_stale() {
    assert_nonzero_exit_not_stale(
        r#"{
  "response": {
    "sendMessage": {
      "recipientId": "f904fe8e-df56-5cf9-8285-e2d97512d4ea",
      "content": "rpc error: code = Unauthenticated desc = unauthenticated: invalid CSRF token; code = Unavailable; connection refused; Connection refused"
    }
  }
}
"#,
        "",
    )
    .await;
}

#[tokio::test]
async fn xa6_nonzero_exit_non_json_stdout_with_phrases_not_stale() {
    assert_nonzero_exit_not_stale(
        "rpc error: code = Unauthenticated desc = unauthenticated: invalid CSRF token; code = Unavailable; connection refused; Connection refused\n",
        "",
    )
    .await;
}

#[tokio::test]
async fn xa6_nonzero_exit_phrases_on_stderr_with_non_auth_error_not_stale() {
    assert_nonzero_exit_not_stale(
        r#"{
  "response": {},
  "error": "rpc error: code = Internal desc = internal error"
}
"#,
        "rpc error: code = Unauthenticated desc = unauthenticated: invalid CSRF token; code = Unavailable; connection refused; Connection refused\n",
    )
    .await;
}
