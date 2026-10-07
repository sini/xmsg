use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use tempfile::tempdir;

use xmsg::agy::{
    dev_major, dev_minor, is_agy_session_alive, verify_registration, AgyCredentials,
    AgyRegisterRequest, AgySessionInfo,
};
use xmsg::error::AppError;
use xmsg::pi::verify_pi_process;

fn setup_mock_process(
    proc_root: &Path,
    pid: u32,
    ppid: u32,
    exe: Option<&Path>,
    open_file: Option<&Path>,
    starttime: &str,
    cmdline: Option<&str>,
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

    if let Some(cmd) = cmdline {
        fs::write(pid_dir.join("cmdline"), cmd).unwrap();
    }
}

/// Cell 1: Accept - ancestor is trusted exe AND has presence inode open.
#[test]
fn cell_1_accept_trusted_exe_and_lock_open() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let lock_file = presence_dir.join("conv-1.lock");
    fs::write(&lock_file, "lock").unwrap();

    let dummy_agy = tmp.path().join("trusted_agy");
    fs::write(&dummy_agy, "binary").unwrap();
    let trusted_exes = vec![dummy_agy.clone()];

    // Peer 3000 -> Ancestor 2000 -> 1
    // Ancestor 2000 has trusted_agy exe and lock_file open
    setup_mock_process(
        &proc_root,
        2000,
        1,
        Some(&dummy_agy),
        Some(&lock_file),
        "1000",
        None,
    );
    setup_mock_process(&proc_root, 3000, 2000, None, None, "2000", None);

    let req = AgyRegisterRequest {
        conversation_id: "conv-1".to_string(),
        ls_address: "127.0.0.1:4000".to_string(),
        csrf_token: "secret".to_string(),
    };

    let reg = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        3000,
        &req,
    )
    .expect("registration should be accepted");

    assert_eq!(reg.pid, 2000);
    assert_eq!(reg.starttime, "1000");
    assert_eq!(reg.session_key, "agy:2000:1000");
}

/// Cell 2: Refuse - ancestor has file open but untrusted exe (argv claims agy, exe differs).
#[test]
fn cell_2_refuse_untrusted_exe() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let lock_file = presence_dir.join("conv-2.lock");
    fs::write(&lock_file, "lock").unwrap();

    let trusted_agy = tmp.path().join("trusted_agy");
    fs::write(&trusted_agy, "binary").unwrap();
    let untrusted_exe = tmp.path().join("malicious_app");
    fs::write(&untrusted_exe, "evil").unwrap();

    let trusted_exes = vec![trusted_agy];

    // Ancestor 2000 has the file open, but its kernel exe is malicious_app
    setup_mock_process(
        &proc_root,
        2000,
        1,
        Some(&untrusted_exe),
        Some(&lock_file),
        "1000",
        Some("agy\0start\0"),
    );
    setup_mock_process(&proc_root, 3000, 2000, None, None, "2000", None);

    let req = AgyRegisterRequest {
        conversation_id: "conv-2".to_string(),
        ls_address: "127.0.0.1:4000".to_string(),
        csrf_token: "secret".to_string(),
    };

    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        3000,
        &req,
    );

    match res {
        Err(AppError::NotRecipient(msg)) => {
            assert!(msg.contains("no ancestor matching a trusted agy executable"));
        }
        other => panic!("expected NotRecipient, got: {other:?}"),
    }
}

/// Cell 3: Refuse - trusted exe without file open.
#[test]
fn cell_3_refuse_lock_not_open() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let lock_file = presence_dir.join("conv-3.lock");
    fs::write(&lock_file, "lock").unwrap();

    let dummy_agy = tmp.path().join("trusted_agy");
    fs::write(&dummy_agy, "binary").unwrap();
    let trusted_exes = vec![dummy_agy.clone()];

    // Ancestor 2000 has trusted exe, but does NOT have lock_file open in fd/
    setup_mock_process(&proc_root, 2000, 1, Some(&dummy_agy), None, "1000", None);
    setup_mock_process(&proc_root, 3000, 2000, None, None, "2000", None);

    let req = AgyRegisterRequest {
        conversation_id: "conv-3".to_string(),
        ls_address: "127.0.0.1:4000".to_string(),
        csrf_token: "secret".to_string(),
    };

    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        3000,
        &req,
    );

    match res {
        Err(AppError::NotRecipient(msg)) => {
            assert!(msg.contains("no ancestor matching a trusted agy executable"));
        }
        other => panic!("expected NotRecipient, got: {other:?}"),
    }
}

/// Cell 4: Refuse - non-ancestor process that has the file open.
#[test]
fn cell_4_refuse_non_ancestor_holder() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let lock_file = presence_dir.join("conv-4.lock");
    fs::write(&lock_file, "lock").unwrap();

    let dummy_agy = tmp.path().join("trusted_agy");
    fs::write(&dummy_agy, "binary").unwrap();
    let trusted_exes = vec![dummy_agy.clone()];

    // Process 9000 (disconnected from 3000) holds the file
    setup_mock_process(
        &proc_root,
        9000,
        1,
        Some(&dummy_agy),
        Some(&lock_file),
        "1000",
        None,
    );
    // Peer process 3000 -> 2000 -> 1 does not reach 9000
    setup_mock_process(&proc_root, 2000, 1, None, None, "1000", None);
    setup_mock_process(&proc_root, 3000, 2000, None, None, "2000", None);

    let req = AgyRegisterRequest {
        conversation_id: "conv-4".to_string(),
        ls_address: "127.0.0.1:4000".to_string(),
        csrf_token: "secret".to_string(),
    };

    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        3000,
        &req,
    );

    assert!(matches!(res, Err(AppError::NotRecipient(_))));
}

/// Cell 5: Refuse - no trusted exe configured.
#[test]
fn cell_5_refuse_no_trusted_exe_configured() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let lock_file = presence_dir.join("conv-5.lock");
    fs::write(&lock_file, "lock").unwrap();

    let req = AgyRegisterRequest {
        conversation_id: "conv-5".to_string(),
        ls_address: "127.0.0.1:4000".to_string(),
        csrf_token: "secret".to_string(),
    };

    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &[], // Empty trusted exes!
        1000,
        1000,
        3000,
        &req,
    );

    match res {
        Err(AppError::BadRequest(msg)) => {
            assert!(msg.contains("no trusted agy executable configured"));
        }
        other => panic!("expected BadRequest for empty trusted exes, got: {other:?}"),
    }
}

/// Cell 6: Refuse - symlinked presence path pointing elsewhere (inode differs).
#[test]
fn cell_6_refuse_symlinked_presence_path_inode_mismatch() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let real_presence_file = presence_dir.join("conv-6.lock");
    fs::write(&real_presence_file, "lock").unwrap();

    let different_file = tmp.path().join("unrelated_file.txt");
    fs::write(&different_file, "other").unwrap();

    let dummy_agy = tmp.path().join("trusted_agy");
    fs::write(&dummy_agy, "binary").unwrap();
    let trusted_exes = vec![dummy_agy.clone()];

    // Process 2000 has different_file open, NOT real_presence_file
    setup_mock_process(
        &proc_root,
        2000,
        1,
        Some(&dummy_agy),
        Some(&different_file),
        "1000",
        None,
    );
    setup_mock_process(&proc_root, 3000, 2000, None, None, "2000", None);

    let req = AgyRegisterRequest {
        conversation_id: "conv-6".to_string(),
        ls_address: "127.0.0.1:4000".to_string(),
        csrf_token: "secret".to_string(),
    };

    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        3000,
        &req,
    );

    match res {
        Err(AppError::NotRecipient(_)) => {}
        other => panic!("expected NotRecipient on inode mismatch, got: {other:?}"),
    }
}

/// Cell 7: Refuse - Linux FLOCK mismatch in /proc/locks.
#[test]
fn cell_7_refuse_linux_flock_mismatch() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let lock_file = presence_dir.join("conv-7.lock");
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    // FLOCK in table is held by rogue PID 9999, NOT ancestor 2000
    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE 9999 {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&proc_locks, locks_content).unwrap();

    let dummy_agy = tmp.path().join("trusted_agy");
    fs::write(&dummy_agy, "binary").unwrap();
    let trusted_exes = vec![dummy_agy.clone()];

    setup_mock_process(
        &proc_root,
        2000,
        1,
        Some(&dummy_agy),
        Some(&lock_file),
        "1000",
        None,
    );
    setup_mock_process(&proc_root, 3000, 2000, None, None, "2000", None);

    let req = AgyRegisterRequest {
        conversation_id: "conv-7".to_string(),
        ls_address: "127.0.0.1:4000".to_string(),
        csrf_token: "secret".to_string(),
    };

    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        3000,
        &req,
    );

    match res {
        Err(AppError::NotRecipient(msg)) => {
            assert!(msg.contains("FLOCK holder PID 9999 does not match chosen ancestor PID 2000"));
        }
        other => panic!("expected NotRecipient due to FLOCK mismatch, got: {other:?}"),
    }
}

/// Cell 8: Liveness - reused PID with different starttime is gone.
#[tokio::test]
async fn cell_8_liveness_reused_pid_different_starttime() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    let info = AgySessionInfo::new(
        "conv-8".to_string(),
        5000,
        "1000".to_string(),
        AgyCredentials {
            ls_address: "127.0.0.1:8888".to_string(),
            csrf_token: "secret".to_string(),
            is_stale: false,
        },
    );

    // Initial state: PID 5000 has starttime 1000
    setup_mock_process(&proc_root, 5000, 1, None, None, "1000", None);
    assert!(is_agy_session_alive(&proc_root, &info));

    // Later: Process died, PID 5000 was reused by a new process with starttime 9999
    setup_mock_process(&proc_root, 5000, 1, None, None, "9999", None);
    assert!(
        !is_agy_session_alive(&proc_root, &info),
        "reused PID with different starttime must NOT be considered alive"
    );

    // Process totally dead (stat file removed)
    let _ = fs::remove_dir_all(proc_root.join("5000"));
    assert!(
        !is_agy_session_alive(&proc_root, &info),
        "dead process must NOT be considered alive"
    );
}

/// Cell 9: Pi verification - untrusted script path refused when entrypoint configured.
#[test]
fn cell_9_pi_untrusted_script_path_refused() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    let node_bin = tmp.path().join("node");
    fs::write(&node_bin, "node_binary").unwrap();

    let trusted_script = tmp.path().join("dist/cli.js");
    fs::create_dir_all(trusted_script.parent().unwrap()).unwrap();
    fs::write(&trusted_script, "console.log('pi');").unwrap();

    let untrusted_script = tmp.path().join("evil.js");
    fs::write(&untrusted_script, "console.log('evil');").unwrap();

    let trusted_entrypoints = vec![trusted_script];

    // Peer 12345 running node evil.js
    let cmdline = format!("node\0{}\0", untrusted_script.display());
    setup_mock_process(
        &proc_root,
        12345,
        1,
        Some(&node_bin),
        None,
        "1000",
        Some(&cmdline),
    );

    let res = verify_pi_process(&proc_root, &trusted_entrypoints, 1000, 1000, 12345);
    match res {
        Err(AppError::BadRequest(msg)) => {
            assert!(
                msg.contains("script does not match any trusted pi entrypoint"),
                "expected script mismatch error, got: {msg}"
            );
        }
        other => panic!("expected BadRequest for untrusted script, got: {other:?}"),
    }
}

/// Cell 10: Pi verification - trusted script path accepted when entrypoint configured.
#[test]
fn cell_10_pi_trusted_script_path_accepted() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    let node_bin = tmp.path().join("node");
    fs::write(&node_bin, "node_binary").unwrap();

    let trusted_script = tmp.path().join("dist/cli.js");
    fs::create_dir_all(trusted_script.parent().unwrap()).unwrap();
    fs::write(&trusted_script, "console.log('pi');").unwrap();

    let trusted_entrypoints = vec![trusted_script.clone()];

    // Peer 12345 running node dist/cli.js --opt
    let cmdline = format!("node\0{}\0--opt\0", trusted_script.display());
    setup_mock_process(
        &proc_root,
        12345,
        1,
        Some(&node_bin),
        None,
        "1000",
        Some(&cmdline),
    );

    let res = verify_pi_process(&proc_root, &trusted_entrypoints, 1000, 1000, 12345);
    assert_eq!(res.expect("trusted pi script should be accepted"), "1000");
}

/// Live macOS probe verification test (runnable on macOS hosts with `-- --ignored`).
#[test]
#[ignore]
fn test_live_macos_agy_probe() {
    let me = std::process::id();
    let proc_root = Path::new(xmsg::process::LIVE_PROC_ROOT);

    let exe = xmsg::process::exe_path(proc_root, me).expect("resolve self exe");
    println!("Self PID: {me}");
    println!("Self exe: {}", exe.display());
    assert!(exe.exists());

    let tmp_file = tempfile::NamedTempFile::new().unwrap();
    let meta = fs::metadata(tmp_file.path()).unwrap();
    let expected_id = (meta.dev(), meta.ino());

    let open_ids = xmsg::process::open_file_ids(proc_root, me).expect("read open file ids");
    println!("Found {} open file descriptors", open_ids.len());
    assert!(
        open_ids.contains(&expected_id),
        "open_file_ids must contain temp file (dev={}, ino={})",
        expected_id.0,
        expected_id.1
    );
}
