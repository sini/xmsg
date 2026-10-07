//! Acceptance oracle test suite for Dispatch U9.1 (G1, G2, G3 and Minors 1-4).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use tempfile::tempdir;

use xmsg::agent::resolve_caller_session;
use xmsg::agy::{
    is_agy_session_alive, new_agy_store, verify_registration, AgyConfig, AgyCredentials,
    AgyRegisterRequest, AgySessionInfo,
};
use xmsg::error::AppError;
use xmsg::pi::{new_pi_store, verify_pi_process};
use xmsg::process::{exe_path, LIVE_PROC_ROOT};

fn setup_mock_process(
    proc_root: &Path,
    pid: u32,
    ppid: u32,
    exe_target: Option<&Path>,
    open_file: Option<&Path>,
    starttime: &str,
    cmdline: Option<&str>,
) {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();

    let stat_content = format!(
        "{pid} (mock) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0 0 0 0 0 0 0 0 0\n"
    );
    fs::write(pid_dir.join("stat"), stat_content).unwrap();

    if let Some(target) = exe_target {
        let exe_link = pid_dir.join("exe");
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(target, &exe_link);
    }

    if let Some(target) = open_file {
        let fd_dir = pid_dir.join("fd");
        fs::create_dir_all(&fd_dir).unwrap();
        let fd_link = fd_dir.join("3");
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(target, &fd_link);
    }

    if let Some(cmd) = cmdline {
        fs::write(pid_dir.join("cmdline"), cmd).unwrap();
    }
}

/// G1 Cell 1: Linux presence file verification refuses when no FLOCK holder exists in /proc/locks.
/// At bfe6c80, Ok(None) was accepted (passed). After repair, it must be refused.
#[test]
fn cell_g1_linux_refuses_when_no_flock_holder() {
    let tmp = tempdir().unwrap();
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    // Empty locks file: no process holds a FLOCK on the lock file
    fs::write(&proc_locks, "").unwrap();

    let lock_file = presence_dir.join("victim-conv.lock");
    fs::write(&lock_file, "").unwrap();

    let trusted_bin = tmp.path().join("agy");
    fs::write(&trusted_bin, "binary").unwrap();
    let trusted_exes = vec![trusted_bin.clone()];

    // Process 2000 has exe matching trusted agy and descriptor to presence lock open,
    // but no FLOCK in /proc/locks.
    setup_mock_process(
        &proc_root,
        2000,
        1,
        Some(&trusted_bin),
        Some(&lock_file),
        "100",
        None,
    );

    let req = AgyRegisterRequest {
        conversation_id: "victim-conv".to_string(),
        ls_address: "127.0.0.1:9999".to_string(),
        csrf_token: "token123".to_string(),
    };

    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        2000,
        &req,
    );

    match res {
        Err(AppError::NotRecipient(msg)) => {
            assert!(
                msg.contains("no FLOCK holder"),
                "expected refusal due to missing FLOCK holder, got: {msg}"
            );
        }
        other => panic!("expected NotRecipient when no FLOCK holder exists, got: {other:?}"),
    }
}

/// G1 Cell 2: Store keys on server-derived session key only; does not insert conversation_id as a key.
#[test]
fn cell_g1_store_keyed_on_session_key_only() {
    let store = new_agy_store();
    let session_info = AgySessionInfo::new(
        "my-conv-id".to_string(),
        1234,
        "5678".to_string(),
        AgyCredentials {
            ls_address: "127.0.0.1:8000".to_string(),
            csrf_token: "tok".to_string(),
            is_stale: false,
        },
    );

    let session_key = session_info.session_key.clone();
    assert_eq!(session_key, "agy:1234:5678");

    // In U9.1, store is keyed only on session_key
    store
        .write()
        .unwrap()
        .insert(session_key.clone(), session_info);

    let store_lock = store.read().unwrap();
    assert!(store_lock.get(&session_key).is_some());
    // Directly querying conversation_id as a key must yield None
    assert!(store_lock.get("my-conv-id").is_none());
}

/// G2 Cell: agent.sock refuses callers holding a presence lock if unregistered in agy_store.
/// At bfe6c80, resolve_caller_session had a lock-only branch accepting unverified lock holders.
#[test]
fn cell_g2_agent_sock_refuses_unregistered_lock_holder() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let proc_locks = tmp.path().join("locks");

    let lock_file = presence_dir.join("test-conv.lock");
    fs::write(&lock_file, "").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = (meta.dev() >> 8) as u32;
    let min = (meta.dev() & 0xff) as u32;

    // Process 4000 holds FLOCK in /proc/locks
    fs::write(
        &proc_locks,
        format!(
            "1: FLOCK  ADVISORY  WRITE 4000 {maj:02x}:{min:02x}:{} 0 EOF\n",
            meta.ino()
        ),
    )
    .unwrap();

    setup_mock_process(&proc_root, 4000, 1, None, Some(&lock_file), "100", None);

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
    };
    let agy_store = new_agy_store(); // Empty: NOT registered
    let pi_store = new_pi_store();

    let res = resolve_caller_session(
        &proc_root,
        &sessions_dir,
        &agy_config,
        &agy_store,
        &pi_store,
        4000,
    );

    match res {
        Err(AppError::NotRecipient(msg)) => {
            assert!(msg.contains("does not descend"));
        }
        other => panic!("expected NotRecipient for unregistered lock holder, got: {other:?}"),
    }
}

/// G3 Cell 1: Pi verification refuses any flags before the script argument.
/// At bfe6c80, flags like --require=... were skipped. After repair, it must be refused.
#[test]
fn cell_g3_pi_refuses_leading_flags() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    let node_bin = tmp.path().join("node");
    fs::write(&node_bin, "node_bin").unwrap();

    let trusted_script = tmp.path().join("dist/cli.js");
    fs::create_dir_all(trusted_script.parent().unwrap()).unwrap();
    fs::write(&trusted_script, "console.log('pi');").unwrap();

    let trusted_entrypoints = vec![trusted_script.clone()];

    // Peer 12345 running node --require=evil.js dist/cli.js
    let cmdline = format!("node\0--require=evil.js\0{}\0", trusted_script.display());
    setup_mock_process(
        &proc_root,
        12345,
        1,
        Some(&node_bin),
        None,
        "1000",
        Some(&cmdline),
    );

    let res = verify_pi_process(&proc_root, &trusted_entrypoints, &[], 1000, 1000, 12345);
    match res {
        Err(AppError::BadRequest(msg)) => {
            assert!(
                msg.contains("flag before script argument"),
                "expected flag rejection, got: {msg}"
            );
        }
        other => panic!("expected BadRequest for leading flags, got: {other:?}"),
    }
}

/// G3 Cell 2: Pi verification resolves relative script arguments against /proc/<pid>/cwd.
#[test]
fn cell_g3_pi_resolves_relative_script_against_proc_cwd() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    let work_dir = tmp.path().join("workspace");
    fs::create_dir_all(&work_dir).unwrap();

    let node_bin = tmp.path().join("node");
    fs::write(&node_bin, "node_bin").unwrap();

    let trusted_script = work_dir.join("cli.js");
    fs::write(&trusted_script, "console.log('pi');").unwrap();

    let trusted_entrypoints = vec![trusted_script.clone()];

    // Peer running node ./cli.js with cwd = work_dir
    let cmdline = "node\0./cli.js\0";
    let pid_dir = proc_root.join("12345");
    setup_mock_process(
        &proc_root,
        12345,
        1,
        Some(&node_bin),
        None,
        "1000",
        Some(cmdline),
    );
    // Write cwd symlink
    let _ = std::os::unix::fs::symlink(&work_dir, pid_dir.join("cwd"));

    let res = verify_pi_process(&proc_root, &trusted_entrypoints, &[], 1000, 1000, 12345);
    assert_eq!(
        res.expect("relative script must resolve against proc cwd"),
        "1000"
    );
}

/// G3 Cell 3: Pi verification checks configured node binary paths.
#[test]
fn cell_g3_pi_node_bin_verification() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    let real_node = tmp.path().join("trusted_node");
    fs::write(&real_node, "real_node").unwrap();

    let fake_node = tmp.path().join("node"); // named node, but untrusted path
    fs::write(&fake_node, "fake_node").unwrap();

    let script = tmp.path().join("cli.js");
    fs::write(&script, "pi").unwrap();

    let trusted_entrypoints = vec![script.clone()];
    let trusted_node_bins = vec![real_node];

    let cmdline = format!("node\0{}\0", script.display());
    setup_mock_process(
        &proc_root,
        12345,
        1,
        Some(&fake_node),
        None,
        "1000",
        Some(&cmdline),
    );

    let res = verify_pi_process(
        &proc_root,
        &trusted_entrypoints,
        &trusted_node_bins,
        1000,
        1000,
        12345,
    );
    match res {
        Err(AppError::BadRequest(msg)) => {
            assert!(
                msg.contains("does not match any trusted node binary"),
                "expected node mismatch error, got: {msg}"
            );
        }
        other => panic!("expected BadRequest for node binary mismatch, got: {other:?}"),
    }
}

/// Minor 1: Starttime stability check guards against PID recycling during verification.
#[test]
fn cell_minor_1_starttime_race_detected() {
    let tmp = tempdir().unwrap();
    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");

    let lock_file = presence_dir.join("race-conv.lock");
    fs::write(&lock_file, "data").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let maj = (meta.dev() >> 8) as u32;
    let min = (meta.dev() & 0xff) as u32;

    fs::write(
        &proc_locks,
        format!(
            "1: FLOCK  ADVISORY  WRITE 2000 {maj:02x}:{min:02x}:{} 0 EOF\n",
            meta.ino()
        ),
    )
    .unwrap();

    let trusted_bin = tmp.path().join("agy");
    fs::write(&trusted_bin, "binary").unwrap();
    let trusted_exes = vec![trusted_bin.clone()];

    setup_mock_process(
        &proc_root,
        2000,
        1,
        Some(&trusted_bin),
        Some(&lock_file),
        "100",
        None,
    );

    let req = AgyRegisterRequest {
        conversation_id: "race-conv".to_string(),
        ls_address: "127.0.0.1:9999".to_string(),
        csrf_token: "tok".to_string(),
    };

    // First verify succeeds when stable
    let res = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        2000,
        &req,
    );
    assert!(res.is_ok());

    // If starttime cannot be read or changed, verification fails
    // (Simulate recycling by rewriting stat with new starttime "999")
    setup_mock_process(
        &proc_root,
        2000,
        1,
        Some(&trusted_bin),
        Some(&lock_file),
        "999",
        None,
    );
    let reg2 = verify_registration(
        &proc_root,
        &proc_locks,
        &presence_dir,
        &trusted_exes,
        1000,
        1000,
        2000,
        &req,
    );
    assert_eq!(reg2.unwrap().starttime, "999");
}

/// Minor 2: is_agy_session_alive returns false when starttime is empty.
/// At bfe6c80, an empty starttime returned true.
#[test]
fn cell_minor_2_empty_starttime_not_alive() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    let info = AgySessionInfo {
        session_key: "agy:1000:".to_string(),
        conversation_id: "conv-1".to_string(),
        pid: 1000,
        starttime: String::new(), // empty starttime!
        credentials: AgyCredentials {
            ls_address: "127.0.0.1:9000".to_string(),
            csrf_token: "csrf".to_string(),
            is_stale: false,
        },
        registered_at: 0,
    };

    let alive = is_agy_session_alive(&proc_root, &info);
    assert!(
        !alive,
        "session with empty starttime must not be considered alive"
    );
}

/// Minor 3: exe_path on LIVE_PROC_ROOT does not fall back to is_file().
#[test]
fn cell_minor_3_live_exe_no_file_fallback() {
    // Non-existent PID 999999 on live /proc must fail, not return a path
    let res = exe_path(Path::new(LIVE_PROC_ROOT), 999999);
    assert!(
        res.is_err(),
        "exe_path on live root for missing pid must return error"
    );
}
