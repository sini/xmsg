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

    // 1. Create presence lock for conv-agy-test
    let conv_id = "conv-agy-test";
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
    echo "Error: Unauthenticated. Invalid credentials." >&2
    exit 1
fi
echo "Message delivered successfully"
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
        sessions_dir: sess_dir,
        agy_config,
        agy_store: agy_store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: Arc::new(Mutex::new(conn)),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let send_url = format!("http://127.0.0.1:{port}/v1/sessions/{conv_id}/messages");

    // --- Phase 1: Successful Delivery ---
    let resp = client
        .post(&send_url)
        .json(&serde_json::json!({
            "from": "claude-orch",
            "text": "Hello Antigravity session!"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(resp_body["sessionId"], initial_key);
    assert_eq!(resp_body["fromName"], "xmsg@test-host · claude-orch");
    let msg_id = resp_body["messageId"].as_str().unwrap().to_string();
    assert!(!msg_id.is_empty());

    // Verify argv: contains session, title, and envelope; NEVER contains csrf_token
    let captured_argv = fs::read_to_string(&argv_log).unwrap();
    assert!(captured_argv.contains("agentapi send-message --title xmsg@test-host · claude-orch"));
    assert!(captured_argv.contains(conv_id));
    assert!(captured_argv.contains(&format!("[xmsg] from=xmsg@test-host · claude-orch message_id={msg_id} — reply with the xmsg reply tool\n\nHello Antigravity session!")));
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
            "from": "claude-orch",
            "text": "This should fail with credentials_stale"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp_fail.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let fail_body: serde_json::Value = resp_fail.json().await.unwrap();
    assert_eq!(fail_body["error"], "credentials_stale");

    // Verify marked stale in memory store
    {
        let store = agy_store.read().unwrap();
        let creds = store.get(&initial_key).unwrap();
        assert!(
            creds.credentials.as_ref().unwrap().is_stale,
            "Store entry must be marked stale after Unauthenticated error"
        );
    }

    // Removing fail_file still results in 503 because store is stale
    fs::remove_file(&fail_file).unwrap();
    let resp_still_stale = client
        .post(&send_url)
        .json(&serde_json::json!({
            "from": "claude-orch",
            "text": "Still stale before re-registration"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp_still_stale.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );

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
