use std::fs;

mod reused_stat;
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
    write_proc_stat(&proc_root, 100, 1, "100");
    write_session_file(
        &sessions_dir,
        100,
        "0199cecf-0100-7000-8000-000000000100",
        "worker-1",
        "100",
    );

    // PID 101: Wrapper process (parent is 100), no session file
    write_proc_stat(&proc_root, 101, 100, "101");

    // PID 102: MCP process (parent is 101)
    write_proc_stat(&proc_root, 102, 101, "102");

    let result = find_ancestor_session_in(&proc_root, &sessions_dir, 102);
    assert!(result.is_ok(), "expected ancestor session found");
    let session = result.unwrap();
    assert_eq!(session.session_id, "0199cecf-0100-7000-8000-000000000100");
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
    write_proc_stat(&proc_root, 50, 1, "50");

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

    // PID 200: Session file says procStart="150", but proc stat has "250"
    write_proc_stat(&proc_root, 200, 1, "250");
    write_session_file(
        &sessions_dir,
        200,
        "0199cecf-0200-7000-8000-000000000200",
        "dead-worker",
        "150",
    );

    // PID 201: MCP process whose parent is 200
    write_proc_stat(&proc_root, 201, 200, "260");

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
    write_proc_stat(&proc_root, 300, 1, "300");
    write_session_file(
        &sessions_dir,
        300,
        "0199cecf-0300-7000-8000-000000000300",
        "root-agent",
        "300",
    );

    // PID 301 -> PID 300 (e.g. bash subshell)
    write_proc_stat(&proc_root, 301, 300, "301");
    // PID 302 -> PID 301 (e.g. nix-shell wrapper)
    write_proc_stat(&proc_root, 302, 301, "302");
    // PID 303 -> PID 302 (e.g. env wrapper)
    write_proc_stat(&proc_root, 303, 302, "303");
    // PID 304 -> PID 303 (actual xmsg mcp process)
    write_proc_stat(&proc_root, 304, 303, "304");

    let result = find_ancestor_session_in(&proc_root, &sessions_dir, 304);
    assert!(result.is_ok());
    let session = result.unwrap();
    assert_eq!(session.session_id, "0199cecf-0300-7000-8000-000000000300");
    assert_eq!(session.pid, 300);
}

/// A link whose parent started after its child is a PID reused between the two reads, so the
/// walk stops there instead of attributing the caller to the session that owns the new PID.
#[test]
fn test_ancestor_walk_refuses_parent_younger_than_child() {
    let temp = tempdir().expect("tempdir");
    let proc_root = temp.path().join("proc");
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();

    // 402 -> 401 -> 400 (a live session)
    write_proc_stat(&proc_root, 400, 1, "400");
    write_session_file(
        &sessions_dir,
        400,
        "0199cecf-0400-7000-8000-000000000400",
        "worker",
        "400",
    );
    write_proc_stat(&proc_root, 402, 401, "402");

    // Control: 401 started before its child 402.
    write_proc_stat(&proc_root, 401, 400, "401");
    let found = find_ancestor_session_in(&proc_root, &sessions_dir, 402);
    assert_eq!(
        found.expect("ordered chain").session_id,
        "0199cecf-0400-7000-8000-000000000400"
    );

    // 401 "started" after its child 402.
    write_proc_stat(&proc_root, 401, 400, "403");
    let refused = find_ancestor_session_in(&proc_root, &sessions_dir, 402);
    assert!(
        refused.is_err(),
        "a younger parent must end the walk: {refused:?}"
    );

    // An unreadable start proves nothing either.
    write_proc_stat(&proc_root, 401, 400, "unreadable");
    let refused = find_ancestor_session_in(&proc_root, &sessions_dir, 402);
    assert!(
        refused.is_err(),
        "an unreadable start must end the walk: {refused:?}"
    );
}

/// A15: a parent PID reused AFTER the step read its start time. The walk re-reads each link it
/// reaches and requires the start it recorded, so it stops at 401 instead of continuing from
/// the new process's parent, session 400.
#[test]
fn test_ancestor_walk_refuses_parent_reused_after_its_step() {
    let temp = tempdir().expect("tempdir");
    let proc_root = temp.path().join("proc");
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    write_proc_stat(&proc_root, 400, 1, "400");
    write_session_file(
        &sessions_dir,
        400,
        "0199cecf-0400-7000-8000-000000000400",
        "worker",
        "400",
    );
    write_proc_stat(&proc_root, 402, 401, "402");

    // Control: had 401 been session 400's child all along, the walk reaches the session.
    write_proc_stat(&proc_root, 401, 400, "401");
    let found = find_ancestor_session_in(&proc_root, &sessions_dir, 402);
    assert_eq!(
        found.expect("ordered chain").session_id,
        "0199cecf-0400-7000-8000-000000000400"
    );

    // 401 is 402's genuine parent (under init) when the step reads it, and a child of
    // session 400 that started after 402 when the walk reaches it.
    reused_stat::reused_stat(
        &proc_root,
        401,
        vec![
            reused_stat::stat_line(401, 1, 401),
            reused_stat::stat_line(401, 400, 450),
        ],
    );
    let refused = find_ancestor_session_in(&proc_root, &sessions_dir, 402);
    assert!(
        refused.is_err(),
        "a PID reused after its step must end the walk: {refused:?}"
    );
}
