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
use xmsg::pi::new_pi_store;
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
    let svc_store = xmsg::svc::new_svc_store();

    let res = resolve_caller_session(
        &proc_root,
        &sessions_dir,
        &agy_config,
        &agy_store,
        &pi_store,
        &svc_store,
        4000,
    );

    match res {
        Err(AppError::NotRecipient(msg)) => {
            assert!(msg.contains("does not descend"));
        }
        other => panic!("expected NotRecipient for unregistered lock holder, got: {other:?}"),
    }
}

/// Minor 1: Starttime stability check guards against PID recycling during verification.
fn stat_line_fifo(st: &str) -> String {
    format!("2000 (mock) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {st} 0 0 0 0 0 0 0 0 0 0\n")
}

/// Minor 1 discriminating cell: starttime changes between the two reads.
/// <pid>/stat is a FIFO that serves "100" on the first open and "999" on the second.
/// A single-read implementation returns Ok; a bracketed one must refuse.
#[test]
fn delta_minor_1_starttime_changes_between_reads() {
    let tmp = tempdir().unwrap();
    let presence = tmp.path().join("presence");
    fs::create_dir_all(&presence).unwrap();
    let lock = presence.join("c.lock");
    fs::write(&lock, "x").unwrap();
    let m = fs::metadata(&lock).unwrap();
    let locks = tmp.path().join("locks");
    fs::write(
        &locks,
        format!(
            "1: FLOCK  ADVISORY  WRITE 2000 {:02x}:{:02x}:{} 0 EOF\n",
            xmsg::agy::dev_major(m.dev()),
            xmsg::agy::dev_minor(m.dev()),
            m.ino()
        ),
    )
    .unwrap();
    let agy = tmp.path().join("agy");
    fs::write(&agy, "bin").unwrap();
    let proc_root = tmp.path().join("proc");
    let pd = proc_root.join("2000");
    fs::create_dir_all(pd.join("fd")).unwrap();
    std::os::unix::fs::symlink(&agy, pd.join("exe")).unwrap();
    std::os::unix::fs::symlink(&lock, pd.join("fd/3")).unwrap();
    let fifo = pd.join("stat");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let f2 = fifo.clone();
    std::thread::spawn(move || {
        for st in ["100", "999"] {
            let mut w = fs::OpenOptions::new().write(true).open(&f2).unwrap();
            use std::io::Write;
            w.write_all(stat_line_fifo(st).as_bytes()).unwrap();
            drop(w);
            // let the reader hit EOF and close before the next open, so the two
            // contents can never coalesce into one read
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    });
    let req = AgyRegisterRequest {
        conversation_id: "c".into(),
        ls_address: "127.0.0.1:1".into(),
        csrf_token: "t".into(),
    };
    let res = verify_registration(
        &proc_root,
        &locks,
        &presence,
        &[agy],
        1000,
        1000,
        2000,
        &req,
    );
    match res {
        Err(e) => assert!(
            format!("{e:?}").contains("starttime changed"),
            "wrong refusal: {e:?}"
        ),
        Ok(r) => panic!(
            "accepted despite starttime change; pinned starttime={}",
            r.starttime
        ),
    }
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
        credentials: Some(AgyCredentials {
            ls_address: "127.0.0.1:9000".to_string(),
            csrf_token: "csrf".to_string(),
            is_stale: false,
        }),
        registered_at: 0,
    };

    let alive = is_agy_session_alive(&proc_root, &info);
    assert!(
        !alive,
        "session with empty starttime must not be considered alive"
    );
}

/// Minor 3 discriminating cell. Meaningful only when run inside a mount namespace whose
/// /proc is a tmpfs holding a REGULAR FILE at /proc/777/exe (see tests/run-minor3.sh).
/// Outside that namespace it asserts nothing useful, so it is gated on XMSG_DELTA_NS=1.
#[test]
#[ignore = "requires user namespace mount, run via tests/run-minor3.sh"]
fn delta_minor_3_live_root_no_file_fallback() {
    if std::env::var("XMSG_DELTA_NS").as_deref() != Ok("1") {
        panic!("run only inside the namespace harness");
    }
    assert!(
        Path::new("/proc/777/exe").is_file(),
        "harness precondition: regular file planted"
    );
    let res = exe_path(Path::new(LIVE_PROC_ROOT), 777);
    assert!(
        res.is_err(),
        "live root fell back to the literal link path: {res:?}"
    );
}
