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
            brain_dir: std::path::PathBuf::new(),
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
            std::sync::Arc::new(xmsg::http::AppState {
                sessions_dirs: vec![],
                agy_config: s_cfg,
                agy_store: s_store,
                pi_store: s_pi,
                pi_notify_tx: s_tx,
                svc_store: xmsg::svc::new_svc_store(),
                svc_notify_tx: tokio::sync::broadcast::channel(16).0,
                node_name: xmsg::node::local_node_name(),
                max_body: 65536,
                request_counter: std::sync::atomic::AtomicU64::new(1),
                db: s_db,
                notify_tx: tokio::sync::broadcast::channel(16).0,
                reply_ttl: s_ttl,
                idempotency_ttl: std::time::Duration::from_secs(86400),
                long_poll_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(128)),
                fed_state: None,
            }),
            my_uid,
            std::collections::HashMap::new(),
        )
        .await;
    });

    for _ in 0..1500 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock_path.exists(), "register.sock never came up in 30s");

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
        store.read().unwrap().get(conv_id).is_some(),
        "conversation_id must be a direct store key"
    );
    let info = creds_opt.unwrap();
    let creds = info.credentials.as_ref().unwrap();
    assert_eq!(creds.ls_address, "localhost:33399");
    assert_eq!(creds.csrf_token, "token-secret-cli-99");
    assert!(!creds.is_stale);

    // XR1 Oracle 1: When the server refuses registration (e.g., conversation_id has no
    // presence lock file -> server answers `{"status":"error","detail":"..."}`),
    // `xmsg register agy` exits non-zero and prints the server's error text to stderr.
    let refused_out = Command::new(bin)
        .args(["register", "agy", "--sock", sock_path.to_str().unwrap()])
        .env("ANTIGRAVITY_CONVERSATION_ID", "conv-refused-no-lock")
        .env("ANTIGRAVITY_LS_ADDRESS", "localhost:33399")
        .env("ANTIGRAVITY_CSRF_TOKEN", "token-secret-cli-99")
        .output()
        .expect("execute xmsg register agy on refused conversation");
    assert!(
        !refused_out.status.success(),
        "XR1: xmsg register agy must exit non-zero on server refusal, got {:?}",
        refused_out.status.code()
    );
    let refused_stderr = String::from_utf8_lossy(&refused_out.stderr);
    assert!(
        refused_stderr.contains(
            "registration rejected by server: session conv-refused-no-lock process 0 exited"
        ),
        "XR1: stderr must contain the server's refusal error text, got: {refused_stderr}"
    );

    // XR1 Oracle 2: The agy PreInvocation hook (`xmsg register agy --hook`) must still not
    // break agy's turn (exits 0) even when the server returns a refusal on `register.sock`;
    // it surfaces the failure through the `ephemeralMessage` path instead.
    let refusal_sock_dir = tempdir().unwrap();
    fs::set_permissions(refusal_sock_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let refusal_sock = refusal_sock_dir.path().join("register.sock");
    let listener = tokio::net::UnixListener::bind(&refusal_sock).unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        if let Ok((stream, _)) = listener.accept().await {
            let (reader, mut writer) = stream.into_split();
            let mut line = String::new();
            let _ = BufReader::new(reader).read_line(&mut line).await;
            let _ = writer
                .write_all(b"{\"status\":\"error\",\"detail\":\"mock server refusal detail\"}\n")
                .await;
        }
    });

    let mut hook_child = Command::new(bin)
        .args([
            "register",
            "agy",
            "--hook",
            "--event",
            "pre-invocation",
            "--sock",
            refusal_sock.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    hook_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"conversationId\":\"conv-hook-refusal\"}")
        .unwrap();
    let hook_out = hook_child.wait_with_output().unwrap();
    assert_eq!(
        hook_out.status.code(),
        Some(0),
        "XR1: PreInvocation hook must exit 0 so it never breaks agy's turn"
    );
    let hook_json: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&hook_out.stdout).trim())
            .expect("PreInvocation hook stdout must be valid JSON");
    let eph = hook_json["injectSteps"][0]["ephemeralMessage"]
        .as_str()
        .expect("PreInvocation hook must surface failure via ephemeralMessage");
    assert!(
        eph.contains("mock server refusal detail") && eph.contains("register agy"),
        "XR1: ephemeralMessage must surface the refusal detail and registration command, got: {eph}"
    );
}
