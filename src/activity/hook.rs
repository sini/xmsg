use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::model::{
    ActivityFrame, ActivityHarness, BackgroundPresence, BlockKind, OwnerProof, WakePresence,
    ACTIVITY_HOOK_DEADLINE_MS, ACTIVITY_HOOK_MAX_FRAME_BYTES, ACTIVITY_HOOK_MAX_JSON_DEPTH,
    ACTIVITY_HOOK_MAX_STDIN_BYTES,
};

pub fn check_json_depth(bytes: &[u8], max_depth: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape = false;
    for &b in bytes {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    return false;
                }
            }
            b'}' | b']' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    !in_string && depth == 0
}

pub fn read_bounded_stdin_with_deadline(
    fd: i32,
    max_bytes: usize,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let orig_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if orig_flags < 0 {
        return None;
    }
    let set_nonblock = (orig_flags & libc::O_NONBLOCK) == 0;
    if set_nonblock && unsafe { libc::fcntl(fd, libc::F_SETFL, orig_flags | libc::O_NONBLOCK) } < 0
    {
        return None;
    }

    let result = (|| {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 8192];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let rem_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
            if rc <= 0 {
                return None;
            }
            loop {
                let n = unsafe {
                    libc::read(
                        fd,
                        chunk.as_mut_ptr().cast::<libc::c_void>(),
                        chunk.len().min(max_bytes - buf.len() + 1),
                    )
                };
                if n > 0 {
                    let n = n as usize;
                    if buf.len() + n > max_bytes {
                        return None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                } else if n == 0 {
                    return Some(buf);
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    return None;
                }
            }
        }
    })();

    if set_nonblock {
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, orig_flags) };
    }
    result
}

fn non_empty_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn opaque_id(v: &Value, key: &str) -> Option<String> {
    non_empty_str(v, key)
        .filter(|s| s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic()))
        .map(ToOwned::to_owned)
}

fn normalize_claude(v: &Value, correlated: bool) -> Option<ActivityFrame> {
    let raw_event = non_empty_str(v, "hook_event_name")?;
    let session = non_empty_str(v, "session_id")?.to_owned();
    let event_id = opaque_id(v, "event_id").or_else(|| opaque_id(v, "uuid"));

    let mut block = None;
    let mut correlation = None;
    let mut background = BackgroundPresence::Absent;
    let mut wake = WakePresence::Absent;

    let event = match raw_event {
        "UserPromptSubmit" => "user_prompt_submit",
        "Stop" => {
            if let Some(tasks) = v.get("background_tasks").and_then(Value::as_array) {
                let active = tasks.iter().any(|t| {
                    let st = t.get("status").and_then(Value::as_str).unwrap_or("running");
                    !matches!(st, "completed" | "failed")
                });
                background = if active {
                    BackgroundPresence::Active
                } else {
                    BackgroundPresence::None
                };
            }
            if let Some(crons) = v.get("session_crons").and_then(Value::as_array) {
                wake = if crons.is_empty() {
                    WakePresence::None
                } else {
                    WakePresence::Pending
                };
            }
            "stop"
        }
        "StopFailure" => "stop_failure",
        "SessionStart" => "session_start",
        "SessionEnd" => "session_end",
        "PermissionRequest" => {
            let tool_name = non_empty_str(v, "tool_name").unwrap_or("");
            block = Some(if matches!(tool_name, "AskUserQuestion" | "ExitPlanMode") {
                BlockKind::Input
            } else {
                BlockKind::Permission
            });
            correlation = opaque_id(v, "tool_use_id");
            "permission_request"
        }
        "PostToolUse" => {
            if !correlated {
                return None;
            }
            correlation = opaque_id(v, "tool_use_id");
            "post_tool_use"
        }
        "Notification" => {
            let ntype = non_empty_str(v, "notification_type").unwrap_or("");
            if !matches!(ntype, "elicitation_dialog" | "agent_needs_input") {
                return None;
            }
            block = Some(BlockKind::Input);
            "notification"
        }
        _ => return None,
    };

    Some(ActivityFrame {
        action: "activity".to_owned(),
        schema_version: 1,
        harness: ActivityHarness::Claude,
        event: event.to_owned(),
        session,
        owner: None,
        native_seq: None,
        event_id,
        correlation,
        block,
        background,
        wake,
        failed: None,
    })
}

fn normalize_codex(v: &Value) -> Option<ActivityFrame> {
    let raw_event = non_empty_str(v, "hook_event_name")?;
    let session = non_empty_str(v, "session_id")?.to_owned();
    let event_id = opaque_id(v, "event_id");

    let mut block = None;
    let event = match raw_event {
        "UserPromptSubmit" => "user_prompt_submit",
        "PreModelRequest" => "pre_model_request",
        "Stop" => "stop",
        "PermissionRequest" => {
            block = Some(BlockKind::Permission);
            "permission_request"
        }
        "Interrupt" => "interrupt",
        "SessionStart" => "session_start",
        _ => return None,
    };

    Some(ActivityFrame {
        action: "activity".to_owned(),
        schema_version: 1,
        harness: ActivityHarness::Codex,
        event: event.to_owned(),
        session,
        owner: None,
        native_seq: None,
        event_id,
        correlation: None,
        block,
        background: BackgroundPresence::Absent,
        wake: WakePresence::Absent,
        failed: None,
    })
}

fn normalize_agy(v: &Value) -> Option<ActivityFrame> {
    let raw_event = non_empty_str(v, "hook_event_name")?;
    let session = non_empty_str(v, "trajectory_id")
        .or_else(|| non_empty_str(v, "session_id"))?
        .to_owned();
    let event_id = opaque_id(v, "event_id");

    let mut background = BackgroundPresence::Absent;
    let event = match raw_event {
        "PreInvocation" => "pre_invocation",
        "PostInvocation" => "post_invocation",
        "PreToolUse" => "pre_tool_use",
        "PostToolUse" => "post_tool_use",
        "Stop" => {
            if let Some(fully_idle) = v.get("fullyIdle").and_then(Value::as_bool) {
                background = if fully_idle {
                    BackgroundPresence::None
                } else {
                    BackgroundPresence::Active
                };
            }
            "stop"
        }
        _ => return None,
    };

    Some(ActivityFrame {
        action: "activity".to_owned(),
        schema_version: 1,
        harness: ActivityHarness::Agy,
        event: event.to_owned(),
        session,
        owner: None,
        native_seq: None,
        event_id,
        correlation: None,
        block: None,
        background,
        wake: WakePresence::Absent,
        failed: None,
    })
}

pub fn normalize_hook_payload(
    harness: ActivityHarness,
    bytes: &[u8],
    correlated: bool,
    owner: Option<OwnerProof>,
) -> Option<ActivityFrame> {
    if bytes.len() > ACTIVITY_HOOK_MAX_STDIN_BYTES {
        return None;
    }
    if !check_json_depth(bytes, ACTIVITY_HOOK_MAX_JSON_DEPTH) {
        return None;
    }
    let val: Value = serde_json::from_slice(bytes).ok()?;
    let mut frame = match harness {
        ActivityHarness::Claude => normalize_claude(&val, correlated)?,
        ActivityHarness::Codex => normalize_codex(&val)?,
        ActivityHarness::Agy => normalize_agy(&val)?,
        _ => return None,
    };
    frame.owner = owner;
    Some(frame)
}

fn detect_process_owner() -> Option<OwnerProof> {
    let (pid, started_at) = crate::process::Ancestry::new(
        Path::new(crate::process::LIVE_PROC_ROOT),
        std::process::id(),
    )
    .nth(1)?;
    let started_at = started_at.parse::<u64>().ok()?;
    Some(OwnerProof { pid, started_at })
}

pub fn send_frame_with_deadline(
    sock_path: &Path,
    frame: &ActivityFrame,
    deadline: Instant,
) -> bool {
    let mut encoded = match serde_json::to_vec(frame) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if encoded.len() + 1 > ACTIVITY_HOOK_MAX_FRAME_BYTES {
        return false;
    }
    encoded.push(b'\n');

    let now = Instant::now();
    if now >= deadline {
        return false;
    }
    let rem = deadline - now;

    // Use non-blocking connect/write via UnixStream + socket timeouts bounded by `rem`.
    let stream = match UnixStream::connect(sock_path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_write_timeout(Some(rem));
    let _ = stream.set_read_timeout(Some(rem));
    let mut stream = stream;
    let now2 = Instant::now();
    if now2 >= deadline {
        return false;
    }
    let rem2 = deadline - now2;
    let _ = stream.set_write_timeout(Some(rem2));
    if stream.write_all(&encoded).is_err() {
        return false;
    }
    let _ = stream.flush();
    let _ = stream.as_raw_fd();
    true
}

pub fn run_activity_hook(
    harness_name: &str,
    agent_sock: Option<&Path>,
    correlated: bool,
) -> (i32, &'static str) {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(ACTIVITY_HOOK_DEADLINE_MS);
    let harness = ActivityHarness::parse(harness_name);
    let stdout_str = if harness == Some(ActivityHarness::Agy) {
        "{}"
    } else {
        ""
    };

    let Some(harness) = harness else {
        return (0, stdout_str);
    };
    let Some(sock) = agent_sock else {
        return (0, stdout_str);
    };
    let Some(stdin_bytes) = read_bounded_stdin_with_deadline(
        libc::STDIN_FILENO,
        ACTIVITY_HOOK_MAX_STDIN_BYTES,
        deadline,
    ) else {
        return (0, stdout_str);
    };

    let owner = detect_process_owner();
    if let Some(frame) = normalize_hook_payload(harness, &stdin_bytes, correlated, owner) {
        let _ = send_frame_with_deadline(sock, &frame, deadline);
    }
    (0, stdout_str)
}
