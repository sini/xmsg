use std::fs;
use tempfile::tempdir;
use xmsg::registry::find_ancestor_session_in;

fn write_proc_stat(proc_dir: &std::path::Path, pid: u32, ppid: u32, proc_start: &str) {
    let pid_dir = proc_dir.join(pid.to_string());
    fs::create_dir_all(&pid_dir).expect("create pid dir");
    // Format: pid (comm) state ppid ... [17 dummy fields] ... proc_start
    // fields[0]=state, fields[1]=ppid, ..., fields[19]=proc_start
    let stat_content =
        format!("{pid} (proc_{pid}) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {proc_start} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).expect("write stat file");
}

fn write_session_file(
    sessions_dir: &std::path::Path,
    pid: u32,
    session_id: &str,
    name: &str,
    proc_start: &str,
) {
    let session_json = serde_json::json!({
        "pid": pid,
        "sessionId": session_id,
        "name": name,
        "cwd": "/workspace/test",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": proc_start,
        "messagingSocketPath": "/tmp/test.sock"
    });
    fs::write(
        sessions_dir.join(format!("{pid}.json")),
        session_json.to_string(),
    )
    .expect("write session file");
}

#[test]
fn test_ancestor_walk_skips_intermediate_wrappers() {
    let temp = tempdir().expect("tempdir");
    let proc_root = temp.path().join("proc");
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();

    // PID 100: Session process (parent is init / 1)
    write_proc_stat(&proc_root, 100, 1, "start_100");
    write_session_file(
        &sessions_dir,
        100,
        "sess-alpha-100",
        "worker-1",
        "start_100",
    );

    // PID 101: Wrapper process (parent is 100), no session file
    write_proc_stat(&proc_root, 101, 100, "start_101");

    // PID 102: MCP process (parent is 101)
    write_proc_stat(&proc_root, 102, 101, "start_102");

    let result = find_ancestor_session_in(&proc_root, &sessions_dir, 102);
    assert!(result.is_ok(), "expected ancestor session found");
    let session = result.unwrap();
    assert_eq!(session.session_id, "sess-alpha-100");
    assert_eq!(session.pid, 100);
    assert_eq!(session.name.as_deref(), Some("worker-1"));
}

#[test]
fn test_ancestor_walk_terminates_at_pid_1() {
    let temp = tempdir().expect("tempdir");
    let proc_root = temp.path().join("proc");
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();

    // PID 50: Process whose parent is 1, no session file for 1 or 50
    write_proc_stat(&proc_root, 50, 1, "start_50");

    let result = find_ancestor_session_in(&proc_root, &sessions_dir, 50);
    assert!(result.is_err(), "expected error when reaching PID 1");
}

#[test]
fn test_ancestor_walk_rejects_recycled_or_dead_session() {
    let temp = tempdir().expect("tempdir");
    let proc_root = temp.path().join("proc");
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();

    // PID 200: Session file says procStart="start_old", but proc stat has "start_recycled"
    write_proc_stat(&proc_root, 200, 1, "start_recycled");
    write_session_file(
        &sessions_dir,
        200,
        "sess-dead-200",
        "dead-worker",
        "start_old",
    );

    // PID 201: MCP process whose parent is 200
    write_proc_stat(&proc_root, 201, 200, "start_201");

    let result = find_ancestor_session_in(&proc_root, &sessions_dir, 201);
    assert!(result.is_err(), "expected dead ancestor to not match");
}

#[test]
fn test_ancestor_walk_multi_level_intermediate_wrappers() {
    let temp = tempdir().expect("tempdir");
    let proc_root = temp.path().join("proc");
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();

    // PID 300: Session process
    write_proc_stat(&proc_root, 300, 1, "start_300");
    write_session_file(
        &sessions_dir,
        300,
        "sess-root-300",
        "root-agent",
        "start_300",
    );

    // PID 301 -> PID 300 (e.g. bash subshell)
    write_proc_stat(&proc_root, 301, 300, "start_301");
    // PID 302 -> PID 301 (e.g. nix-shell wrapper)
    write_proc_stat(&proc_root, 302, 301, "start_302");
    // PID 303 -> PID 302 (e.g. env wrapper)
    write_proc_stat(&proc_root, 303, 302, "start_303");
    // PID 304 -> PID 303 (actual xmsg mcp process)
    write_proc_stat(&proc_root, 304, 303, "start_304");

    let result = find_ancestor_session_in(&proc_root, &sessions_dir, 304);
    assert!(result.is_ok());
    let session = result.unwrap();
    assert_eq!(session.session_id, "sess-root-300");
    assert_eq!(session.pid, 300);
}
