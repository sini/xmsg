use std::fs;
use std::path::Path;
use tempfile::tempdir;
use xmsg::error::AppError;
use xmsg::registry::{list_sessions, resolve_session, SessionsQuery};

fn get_self_proc_start() -> String {
    xmsg::process::starttime(
        std::path::Path::new(xmsg::process::LIVE_PROC_ROOT),
        std::process::id(),
    )
    .expect("live starttime")
}

#[test]
fn test_registry_fixtures() {
    let dir = tempdir().expect("tempdir");
    let dir_path = dir.path();

    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();

    // 1. Live session entry
    let live_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "live-session-1111",
            "name": "live-agent",
            "cwd": "/workspace/live",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "/tmp/live.sock"
        }}"#
    );
    fs::write(dir_path.join(format!("{my_pid}.json")), live_json).unwrap();

    // 2. Dead PID session entry (high unallocated PID)
    let dead_pid = 4194301;
    let dead_json = format!(
        r#"{{
            "pid": {dead_pid},
            "sessionId": "dead-session-2222",
            "name": "dead-agent",
            "cwd": "/workspace/dead",
            "status": "busy",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "12345",
            "messagingSocketPath": "/tmp/dead.sock"
        }}"#
    );
    fs::write(dir_path.join(format!("{dead_pid}.json")), dead_json).unwrap();

    // 3. Reused PID session entry (my_pid but mismatched procStart)
    // Put it in another file
    let reused_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "reused-session-3333",
            "name": "reused-agent",
            "cwd": "/workspace/reused",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "99999999",
            "messagingSocketPath": "/tmp/reused.sock"
        }}"#
    );
    fs::write(dir_path.join("reused.json"), reused_json).unwrap();

    // 4. Malformed JSON file
    fs::write(dir_path.join("malformed.json"), "{ invalid json [").unwrap();

    // 5. Valid session JSON in a .key file for the test runner's real PID (proving .key is ignored)
    let key_file = dir_path.join(format!("{my_pid}.key"));
    let key_leak_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "key-leak-session",
            "name": "KEY-LEAK",
            "cwd": "/workspace/leak",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "/tmp/leak.sock"
        }}"#
    );
    fs::write(&key_file, key_leak_json).unwrap();

    // Test list_sessions
    let live_list = list_sessions(dir_path, &SessionsQuery::default());
    assert_eq!(live_list.len(), 1, "Only live session should be listed");
    assert_eq!(live_list[0].session_id, "live-session-1111");
    assert_eq!(live_list[0].pid, my_pid);
    assert_eq!(live_list[0].name.as_deref(), Some("live-agent"));
    assert!(!live_list
        .iter()
        .any(|s| s.name.as_deref() == Some("KEY-LEAK")));
    assert!(!live_list.iter().any(|s| s.session_id == "key-leak-session"));

    // Test resolve_session on live session (by id, pid, and name)
    let (s_by_id, sock) = resolve_session(dir_path, "live-session-1111").unwrap();
    assert_eq!(s_by_id.pid, my_pid);
    assert_eq!(sock, Path::new("/tmp/live.sock"));

    let (s_by_pid, _) = resolve_session(dir_path, &my_pid.to_string()).unwrap();
    assert_eq!(s_by_pid.session_id, "live-session-1111");

    let (s_by_name, _) = resolve_session(dir_path, "live-agent").unwrap();
    assert_eq!(s_by_name.session_id, "live-session-1111");

    // Test resolve_session on dead session -> 410 Gone
    let dead_res = resolve_session(dir_path, "dead-session-2222");
    assert!(
        matches!(dead_res, Err(AppError::Gone { ref session_id, pid }) if session_id == "dead-session-2222" && pid == dead_pid),
        "Expected Gone error for dead PID, got: {:?}",
        dead_res
    );

    // Test resolve_session on reused session -> 410 Gone
    let reused_res = resolve_session(dir_path, "reused-session-3333");
    assert!(
        matches!(reused_res, Err(AppError::Gone { ref session_id, pid }) if session_id == "reused-session-3333" && pid == my_pid),
        "Expected Gone error for reused PID, got: {:?}",
        reused_res
    );

    // Test resolve_session on unknown ref -> 404 NotFound
    let not_found_res = resolve_session(dir_path, "non-existent-agent");
    assert!(
        matches!(not_found_res, Err(AppError::NotFound(_))),
        "Expected NotFound error, got: {:?}",
        not_found_res
    );

    // Test resolve_session on KEY-LEAK (.key file) -> 404 NotFound
    let key_leak_res = resolve_session(dir_path, "KEY-LEAK");
    assert!(
        matches!(key_leak_res, Err(AppError::NotFound(_))),
        "Expected NotFound error for .key file entry, got: {:?}",
        key_leak_res
    );
}
