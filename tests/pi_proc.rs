use std::fs;
use std::path::Path;
use tempfile::tempdir;

use xmsg::error::AppError;
use xmsg::pi::{get_proc_starttime, is_pi_session_alive, verify_pi_process, PiSessionInfo};

fn setup_mock_proc(proc_root: &Path, pid: u32, cmdline: &str, starttime: &str) {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(pid_dir.join("cmdline"), cmdline).unwrap();

    let stat_content =
        format!("{pid} (pi_agent) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).unwrap();
}

#[test]
fn test_verify_pi_process_success() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    setup_mock_proc(&proc_root, 12345, "pi\0", "987654321");

    let res = verify_pi_process(&proc_root, 1000, 1000, 12345);
    assert_eq!(res.unwrap(), "987654321");

    let st = get_proc_starttime(&proc_root, 12345).unwrap();
    assert_eq!(st, "987654321");
}

/// Oracle 1: A pi-like peer whose cmdline is just `pi` (no script arg; e.g. process.title overwrite)
/// and matching UID registers successfully.
#[test]
fn test_oracle_1_pi_title_overwritten_no_script_arg() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    // Overwritten title where cmdline is just "pi\0" (no script argument at all)
    setup_mock_proc(&proc_root, 12345, "pi\0", "987654321");

    let res = verify_pi_process(&proc_root, 1000, 1000, 12345);
    assert_eq!(
        res.expect("pi with overwritten title and no script arg must register"),
        "987654321"
    );
}

/// Oracle 2: A peer with a different UID is refused.
#[test]
fn test_oracle_2_peer_different_uid_refused() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    setup_mock_proc(&proc_root, 12345, "pi\0", "987654321");

    let res = verify_pi_process(&proc_root, 1000, 1001, 12345);
    assert!(
        matches!(res, Err(AppError::NotRecipient(_))),
        "peer with mismatched UID must be refused: {res:?}"
    );
}

#[test]
fn test_verify_pi_process_uid_mismatch() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    setup_mock_proc(&proc_root, 12345, "pi\0", "987654321");

    let res = verify_pi_process(&proc_root, 1000, 1001, 12345);
    assert!(matches!(res, Err(AppError::NotRecipient(_))));
}

#[test]
fn test_verify_pi_process_not_found() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let res = verify_pi_process(&proc_root, 1000, 1000, 99999);
    assert!(matches!(res, Err(AppError::NotFound(_))));
}

#[test]
fn test_is_pi_session_alive_and_pid_recycling() {
    let tmp = tempdir().unwrap();
    let proc_root = tmp.path().join("proc");

    setup_mock_proc(&proc_root, 54321, "pi", "11223344");

    let info = PiSessionInfo {
        session_id: "pi-sess-1".to_string(),
        name: Some("test-session".to_string()),
        pid: 54321,
        starttime: "11223344".to_string(),
        cwd: "/tmp".to_string(),
        registered_at: 1000,
    };

    assert!(is_pi_session_alive(&proc_root, &info));

    // Simulate PID recycling: process replaced with different starttime
    setup_mock_proc(&proc_root, 54321, "pi", "99887766");
    assert!(!is_pi_session_alive(&proc_root, &info));

    // Simulate process death (dir removed)
    fs::remove_dir_all(proc_root.join("54321")).unwrap();
    assert!(!is_pi_session_alive(&proc_root, &info));
}
