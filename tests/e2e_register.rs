use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use xmsg::agy::{
    current_uid, dev_major, dev_minor, new_agy_store, run_register_server, verify_registration,
    AgyConfig, AgyRegisterRequest,
};
use xmsg::error::AppError;

fn setup_mock_proc_stat(proc_root: &Path, pid: u32, ppid: u32) {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    let stat_content = format!(
        "{pid} (test_proc) S {ppid} {pid} {pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    );
    fs::write(pid_dir.join("stat"), stat_content).unwrap();
}

#[test]
fn test_verify_registration_uid_mismatch() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let req = AgyRegisterRequest {
        conversation_id: "test-conv-1".to_string(),
        ls_address: "127.0.0.1:1234".to_string(),
        csrf_token: "secret".to_string(),
    };

    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        1000, // my_uid
        1001, // peer_uid mismatch!
        5000,
        &req,
    );

    assert!(matches!(res, Err(AppError::NotRecipient(_))));
}

#[test]
fn test_verify_registration_missing_or_dead_lock() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let req = AgyRegisterRequest {
        conversation_id: "test-conv-missing".to_string(),
        ls_address: "127.0.0.1:1234".to_string(),
        csrf_token: "secret".to_string(),
    };

    // 1. Missing lock file -> Err(Gone)
    let res1 = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        1000,
        1000,
        5000,
        &req,
    );
    assert!(matches!(res1, Err(AppError::Gone { .. })));

    // 2. Lock file exists, but no entry in /proc/locks -> Err(Gone)
    let lock_file = presence_dir.join("test-conv-dead.lock");
    fs::write(&lock_file, "").unwrap();

    let req_dead = AgyRegisterRequest {
        conversation_id: "test-conv-dead".to_string(),
        ls_address: "127.0.0.1:1234".to_string(),
        csrf_token: "secret".to_string(),
    };
    let res2 = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        1000,
        1000,
        5000,
        &req_dead,
    );
    assert!(matches!(res2, Err(AppError::Gone { .. })));
}

#[test]
fn test_verify_registration_ancestor_walk() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    // Create presence lock file
    let lock_file = presence_dir.join("conv-active.lock");
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    // Holder PID is 2000
    let locks_content = format!("1: FLOCK ADVISORY WRITE 2000 {:02x}:{:02x}:{} 0 EOF\n", maj, min, ino);
    fs::write(&proc_locks, locks_content).unwrap();

    // Setup process hierarchy: 4000 -> 3000 -> 2000 (holder) -> 1
    setup_mock_proc_stat(&proc_root, 4000, 3000);
    setup_mock_proc_stat(&proc_root, 3000, 2000);
    setup_mock_proc_stat(&proc_root, 2000, 1);

    // Also a disconnected process: 9000 -> 1
    setup_mock_proc_stat(&proc_root, 9000, 1);

    let req = AgyRegisterRequest {
        conversation_id: "conv-active".to_string(),
        ls_address: "127.0.0.1:1234".to_string(),
        csrf_token: "token1".to_string(),
    };

    // 1. Direct holder (peer_pid == holder_pid == 2000) -> OK
    let res_direct = verify_registration(&proc_root, &proc_locks, &presence_dir, 1000, 1000, 2000, &req);
    assert_eq!(res_direct.unwrap(), 2000);

    // 2. Descendant (peer_pid == 4000) -> OK
    let res_descendant = verify_registration(&proc_root, &proc_locks, &presence_dir, 1000, 1000, 4000, &req);
    assert_eq!(res_descendant.unwrap(), 2000);

    // 3. Non-descendant (peer_pid == 9000) -> Err(NotRecipient)
    let res_non = verify_registration(&proc_root, &proc_locks, &presence_dir, 1000, 1000, 9000, &req);
    assert!(matches!(res_non, Err(AppError::NotRecipient(_))));
}

#[tokio::test]
async fn test_registration_server_e2e_and_atomic_replacement() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sock_dir = tempdir().unwrap();
    let sock_path = sock_dir.path().join("register.sock");
    fs::create_dir_all(&presence_dir).unwrap();

    let my_pid = std::process::id();
    let my_uid = current_uid();

    // Create presence lock for conv-123
    let lock_file = presence_dir.join("conv-123.lock");
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    // Our process (my_pid) is the lock holder
    let locks_content = format!("1: FLOCK ADVISORY WRITE {my_pid} {:02x}:{:02x}:{} 0 EOF\n", maj, min, ino);
    fs::write(&proc_locks, locks_content).unwrap();

    let config = AgyConfig {
        presence_dir: presence_dir.clone(),
        proc_locks_path: proc_locks.clone(),
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
    };
    let store = new_agy_store();

    // Start registration server in background
    let s_path = sock_path.clone();
    let s_cfg = config.clone();
    let s_store = store.clone();
    tokio::spawn(async move {
        let _ = run_register_server(s_path, s_cfg, s_store, my_uid).await;
    });

    // Wait briefly for socket to become ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Connect and send initial registration
    let mut stream = UnixStream::connect(&sock_path).await.unwrap();
    let req1 = serde_json::json!({
        "conversation_id": "conv-123",
        "ls_address": "127.0.0.1:4000",
        "csrf_token": "token-initial"
    });
    stream.write_all(format!("{req1}\n").as_bytes()).await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    reader.read_line(&mut resp).await.unwrap();
    assert_eq!(resp.trim(), "{\"status\":\"ok\"}");

    // Verify in store
    {
        let map = store.read().unwrap();
        let creds = map.get("conv-123").unwrap();
        assert_eq!(creds.ls_address, "127.0.0.1:4000");
        assert_eq!(creds.csrf_token, "token-initial");
        assert!(!creds.is_stale);
    }

    // 2. Atomic replacement with new credentials
    let mut stream2 = UnixStream::connect(&sock_path).await.unwrap();
    let req2 = serde_json::json!({
        "conversation_id": "conv-123",
        "ls_address": "127.0.0.1:5000",
        "csrf_token": "token-replaced"
    });
    stream2.write_all(format!("{req2}\n").as_bytes()).await.unwrap();

    let mut reader2 = BufReader::new(stream2);
    let mut resp2 = String::new();
    reader2.read_line(&mut resp2).await.unwrap();
    assert_eq!(resp2.trim(), "{\"status\":\"ok\"}");

    // Verify atomic update in store
    {
        let map = store.read().unwrap();
        let creds = map.get("conv-123").unwrap();
        assert_eq!(creds.ls_address, "127.0.0.1:5000");
        assert_eq!(creds.csrf_token, "token-replaced");
        assert!(!creds.is_stale);
    }
}

#[test]
fn test_debug_redacts_csrf_token() {
    let creds = xmsg::agy::AgyCredentials {
        ls_address: "127.0.0.1:1234".to_string(),
        csrf_token: "super-secret-csrf-token-12345".to_string(),
        is_stale: false,
    };
    let creds_debug = format!("{creds:?}");
    assert!(
        !creds_debug.contains("super-secret-csrf-token-12345"),
        "Debug output must not leak csrf_token: {creds_debug}"
    );
    assert!(
        creds_debug.contains("<redacted>"),
        "Debug output must contain <redacted>: {creds_debug}"
    );

    let req = AgyRegisterRequest {
        conversation_id: "conv-redact".to_string(),
        ls_address: "127.0.0.1:5678".to_string(),
        csrf_token: "super-secret-request-token-67890".to_string(),
    };
    let req_debug = format!("{req:?}");
    assert!(
        !req_debug.contains("super-secret-request-token-67890"),
        "Debug output must not leak csrf_token: {req_debug}"
    );
    assert!(
        req_debug.contains("<redacted>"),
        "Debug output must contain <redacted>: {req_debug}"
    );
}
