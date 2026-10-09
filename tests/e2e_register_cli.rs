use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tempfile::tempdir;

use xmsg::agy::{current_uid, dev_major, dev_minor, new_agy_store, run_register_server, AgyConfig};

#[test]
fn test_register_cli_server_stopped_invariant() {
    let bin = env!("CARGO_BIN_EXE_xmsg");

    // Case A: Server not running, env vars missing
    let output = Command::new(bin)
        .args(["register", "agy"])
        .env_remove("ANTIGRAVITY_CONVERSATION_ID")
        .env_remove("ANTIGRAVITY_LS_ADDRESS")
        .env_remove("ANTIGRAVITY_CSRF_TOKEN")
        .output()
        .expect("execute xmsg register agy");

    assert_eq!(
        output.status.code(),
        Some(0),
        "CLI must exit 0 even if env vars missing"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        "{\"injectSteps\":[]}",
        "stdout must always output injectSteps:[]"
    );

    // Case B: Server not running, non-existent socket specified
    let output2 = Command::new(bin)
        .args([
            "register",
            "agy",
            "--sock",
            "/tmp/non-existent-xmsg-test.sock",
        ])
        .env("ANTIGRAVITY_CONVERSATION_ID", "test-conv")
        .env("ANTIGRAVITY_LS_ADDRESS", "localhost:1234")
        .env("ANTIGRAVITY_CSRF_TOKEN", "token")
        .output()
        .expect("execute xmsg register agy");

    assert_eq!(
        output2.status.code(),
        Some(0),
        "CLI must exit 0 even if server is down"
    );
    let stdout2 = String::from_utf8(output2.stdout).unwrap();
    assert_eq!(
        stdout2.trim(),
        "{\"injectSteps\":[]}",
        "stdout must always output injectSteps:[]"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_shipped_binary_register_cli_with_server() {
    let bin = env!("CARGO_BIN_EXE_xmsg");
    let tmp = tempdir().unwrap();
    let proc_root = PathBuf::from("/proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sock_dir = tempdir().unwrap();
    fs::set_permissions(sock_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = sock_dir.path().join("register.sock");
    fs::create_dir_all(&presence_dir).unwrap();

    let my_pid = std::process::id();
    let my_uid = current_uid();

    // Create presence lock for conv-cli-test
    let conv_id = "conv-cli-test";
    let lock_file = presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    // Current test process is the lock holder and must have lock file open
    let _open_lock = std::fs::File::open(&lock_file).unwrap();
    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {my_pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    let my_exe = std::env::current_exe().unwrap();
    let config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root,
        agy_bin: "agy".to_string(),
        trusted_agy_exes: vec![my_exe],
    };
    let store = new_agy_store();

    // Start registration server
    let s_path = sock_path.clone();
    let s_cfg = config;
    let s_store = store.clone();
    let s_pi = xmsg::pi::new_pi_store();
    let mem_conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&mem_conn).unwrap();
    let s_db = std::sync::Arc::new(std::sync::Mutex::new(mem_conn));
    let (s_tx, _) = tokio::sync::broadcast::channel(16);
    let s_ttl = Duration::from_secs(604800);
    tokio::spawn(async move {
        let _ = run_register_server(
            s_path,
            s_cfg,
            s_store,
            s_pi,
            s_db,
            s_tx,
            s_ttl,
            my_uid,
            xmsg::svc::new_svc_store(),
            std::collections::HashMap::new(),
            tokio::sync::broadcast::channel(16).0,
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Run xmsg register agy child process (child PID will be descendant of my_pid)
    let output = Command::new(bin)
        .args(["register", "agy", "--sock", sock_path.to_str().unwrap()])
        .env("ANTIGRAVITY_CONVERSATION_ID", conv_id)
        .env("ANTIGRAVITY_LS_ADDRESS", "localhost:33399")
        .env("ANTIGRAVITY_CSRF_TOKEN", "token-secret-cli-99")
        .output()
        .expect("execute xmsg register agy");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), "{\"injectSteps\":[]}");

    eprintln!("CLI stderr: {}", String::from_utf8_lossy(&output.stderr));

    // Verify server registered the credentials
    let creds_opt = store
        .read()
        .unwrap()
        .values()
        .find(|info| info.conversation_id == conv_id)
        .cloned();
    assert!(
        creds_opt.is_some(),
        "Credentials should be registered in store"
    );
    assert!(
        store.read().unwrap().get(conv_id).is_none(),
        "conversation_id must not be a direct store key"
    );
    let info = creds_opt.unwrap();
    let creds = info.credentials.as_ref().unwrap();
    assert_eq!(creds.ls_address, "localhost:33399");
    assert_eq!(creds.csrf_token, "token-secret-cli-99");
    assert!(!creds.is_stale);
}
