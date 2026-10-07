use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::agy::{self, AgyConfig};
use crate::error::AppError;
use crate::http::{resolve_target_session, AppState, ResolvedTarget};
use crate::inbox;
use crate::pi::PiStore;
use crate::registry::{self, Session};
use crate::storage;

pub fn current_uid() -> u32 {
    unsafe {
        extern "C" {
            fn getuid() -> u32;
        }
        getuid()
    }
}

pub fn ensure_secure_socket_dir(dir: &Path, expected_uid: u32) -> Result<(), AppError> {
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| {
            AppError::InsecureSocketDir(format!(
                "failed to create directory {}: {e}",
                dir.display()
            ))
        })?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            AppError::InsecureSocketDir(format!(
                "failed to set permissions on {}: {e}",
                dir.display()
            ))
        })?;
    }

    let meta = fs::symlink_metadata(dir).map_err(|e| {
        AppError::InsecureSocketDir(format!("failed to inspect {}: {e}", dir.display()))
    })?;

    if meta.file_type().is_symlink() {
        return Err(AppError::InsecureSocketDir(format!(
            "path {} is a symlink",
            dir.display()
        )));
    }

    if !meta.is_dir() {
        return Err(AppError::InsecureSocketDir(format!(
            "path {} is not a directory",
            dir.display()
        )));
    }

    let actual_uid = meta.uid();
    if actual_uid != expected_uid {
        return Err(AppError::InsecureSocketDir(format!(
            "directory {} is owned by UID {}, expected UID {}",
            dir.display(),
            actual_uid,
            expected_uid
        )));
    }

    let actual_mode = meta.permissions().mode() & 0o777;
    if actual_mode != 0o700 {
        return Err(AppError::InsecureSocketDir(format!(
            "directory {} has mode {:o}, expected 0700",
            dir.display(),
            actual_mode
        )));
    }

    Ok(())
}

pub fn socket_dir_for_env(xdg_var: Option<&str>) -> Result<PathBuf, AppError> {
    match xdg_var {
        Some(val) if !val.trim().is_empty() => Ok(PathBuf::from(val).join("xmsg")),
        _ => Err(AppError::InsecureSocketDir(
            "XDG_RUNTIME_DIR environment variable is not set. Sockets cannot be safely created without a secure runtime directory."
                .to_string(),
        )),
    }
}

pub fn default_socket_dir() -> Result<PathBuf, AppError> {
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    socket_dir_for_env(xdg.as_deref())
}

pub fn default_register_sock_path() -> Result<PathBuf, AppError> {
    default_socket_dir().map(|d| d.join("register.sock"))
}

pub fn default_agent_sock_path() -> Result<PathBuf, AppError> {
    default_socket_dir().map(|d| d.join("agent.sock"))
}

pub fn resolve_caller_session(
    proc_root: &Path,
    sessions_dir: &Path,
    agy_config: &AgyConfig,
    pi_store: &PiStore,
    peer_pid: u32,
) -> Result<Session, AppError> {
    let mut curr_pid = peer_pid;

    for _ in 0..32 {
        // 1. Check Claude sessions
        let claude_sessions = registry::read_session_entries(sessions_dir);
        for entry in claude_sessions {
            if entry.pid == curr_pid
                && registry::is_pid_live_in(proc_root, curr_pid, &entry.proc_start)
            {
                return Ok(entry.into());
            }
        }

        // 2. Check Antigravity presence lock holders
        if let Ok(entries) = fs::read_dir(&agy_config.presence_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("lock") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(Some(holder)) = agy::get_presence_lock_holder(
                            &agy_config.presence_dir,
                            &agy_config.proc_locks_path,
                            stem,
                        ) {
                            if holder == curr_pid {
                                return Ok(Session {
                                    session_id: stem.to_string(),
                                    name: Some(stem.to_string()),
                                    pid: curr_pid,
                                    cwd: "/".to_string(),
                                    status: "idle".to_string(),
                                    kind: "interactive".to_string(),
                                    entrypoint: None,
                                    version: None,
                                    started_at: 0,
                                    updated_at: 0,
                                    harness: "agy".to_string(),
                                    registered: Some(true),
                                });
                            }
                        }
                    }
                }
            }
        }

        // 3. Check Pi sessions
        {
            let pi_lock = pi_store.read().unwrap();
            for info in pi_lock.values() {
                if info.pid == curr_pid && crate::pi::is_pi_session_alive(proc_root, info) {
                    return Ok(Session {
                        session_id: info.session_id.clone(),
                        name: info.name.clone().or_else(|| Some(info.session_id.clone())),
                        pid: info.pid,
                        cwd: info.cwd.clone(),
                        status: "idle".to_string(),
                        kind: "interactive".to_string(),
                        entrypoint: None,
                        version: None,
                        started_at: info.registered_at as u64,
                        updated_at: info.registered_at as u64,
                        harness: "pi".to_string(),
                        registered: Some(true),
                    });
                }
            }
        }

        // Step up to PPID
        let stat_path = proc_root.join(curr_pid.to_string()).join("stat");
        let content = match fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => break,
        };

        let Some(rparen) = content.rfind(')') else {
            break;
        };
        let remainder = &content[rparen + 1..];
        let fields: Vec<&str> = remainder.split_whitespace().collect();
        if fields.len() < 2 {
            break;
        }

        let Ok(ppid) = fields[1].parse::<u32>() else {
            break;
        };
        if ppid <= 1 {
            break;
        }

        curr_pid = ppid;
    }

    Err(AppError::NotRecipient(format!(
        "peer PID {peer_pid} does not descend from an active agent session"
    )))
}

pub async fn run_agent_server(
    sock_path: PathBuf,
    state: Arc<AppState>,
    my_uid: u32,
) -> io::Result<()> {
    if let Some(parent) = sock_path.parent() {
        if let Err(e) = ensure_secure_socket_dir(parent, my_uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                e.to_string(),
            ));
        }
    }
    if sock_path.exists() {
        if tokio::net::UnixStream::connect(&sock_path).await.is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "another server instance is actively listening on {}",
                    sock_path.display()
                ),
            ));
        }
        let _ = fs::remove_file(&sock_path);
    }

    let listener = UnixListener::bind(&sock_path)?;

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("agent server accept error: {e}");
                continue;
            }
        };

        let ucred = match stream.peer_cred() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("failed to get peer creds on agent.sock: {e}");
                continue;
            }
        };

        let peer_uid = ucred.uid();
        let peer_pid = ucred.pid().map(|p| p as u32).unwrap_or(0);

        if peer_uid != my_uid {
            tracing::warn!("agent.sock rejected connection: UID mismatch {peer_uid} != {my_uid}");
            continue;
        }

        let initial_starttime =
            match crate::pi::get_proc_starttime(&state.agy_config.proc_root, peer_pid) {
                Ok(st) => st,
                Err(e) => {
                    tracing::warn!("failed to get starttime for peer PID {peer_pid}: {e}");
                    continue;
                }
            };

        let state_clone = state.clone();

        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            let max_line = state_clone.max_body + 4096;

            loop {
                line.clear();
                let n = (&mut buf_reader)
                    .take(max_line as u64)
                    .read_line(&mut line)
                    .await
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                if n >= max_line && !line.ends_with('\n') {
                    let err_resp = serde_json::json!({
                        "status": "error",
                        "error": "bad_request",
                        "detail": "frame exceeds maximum allowed size"
                    });
                    let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                    break;
                }

                // Verify peer PID is still live and starttime has not changed
                if crate::pi::get_proc_starttime(&state_clone.agy_config.proc_root, peer_pid)
                    .ok()
                    .as_deref()
                    != Some(initial_starttime.as_str())
                {
                    tracing::warn!("peer PID {peer_pid} died or starttime changed");
                    break;
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    line.clear();
                    continue;
                }

                let req_val: serde_json::Value = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(_) => {
                        let err_resp = serde_json::json!({
                            "status": "error",
                            "error": "bad_request",
                            "detail": "invalid json"
                        });
                        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                        line.clear();
                        continue;
                    }
                };

                let action = req_val.get("action").and_then(|a| a.as_str()).unwrap_or("");

                // Resolve caller session via ancestor walk
                let caller = match resolve_caller_session(
                    &state_clone.agy_config.proc_root,
                    &state_clone.sessions_dir,
                    &state_clone.agy_config,
                    &state_clone.pi_store,
                    peer_pid,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        let err_resp = serde_json::json!({
                            "status": "error",
                            "error": "not_recipient",
                            "detail": e.to_string()
                        });
                        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                        line.clear();
                        continue;
                    }
                };

                match action {
                    "reply" => {
                        let message_id = req_val
                            .get("messageId")
                            .or_else(|| req_val.get("message_id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let text = req_val.get("text").and_then(|v| v.as_str()).unwrap_or("");

                        if message_id.is_empty() || text.is_empty() {
                            let err_resp = serde_json::json!({
                                "status": "error",
                                "error": "bad_request",
                                "detail": "messageId and text are required"
                            });
                            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            line.clear();
                            continue;
                        }

                        let res: Result<storage::ReplyRecord, AppError> = (|| {
                            let db = state_clone
                                .db
                                .lock()
                                .map_err(|e| AppError::Internal(e.to_string()))?;
                            let msg = storage::get_message(&db, message_id)
                                .map_err(|e| AppError::Internal(e.to_string()))?
                                .ok_or_else(|| {
                                    AppError::NotFound(format!("message '{message_id}'"))
                                })?;

                            if caller.harness != msg.recipient_harness
                                || caller.session_id != msg.session_id
                            {
                                Err(AppError::NotRecipient(format!(
                                    "caller session '{}:{}' is not recipient of message '{}' (expected '{}:{}')",
                                    caller.harness, caller.session_id, message_id, msg.recipient_harness, msg.session_id
                                )))
                            } else {
                                let reply = storage::insert_reply(
                                    &db,
                                    message_id,
                                    &caller.session_id,
                                    text,
                                )
                                .map_err(|e| AppError::Internal(e.to_string()))?;
                                let _ =
                                    storage::purge_replies(&db, state_clone.reply_ttl.as_secs());
                                let _ =
                                    storage::purge_messages(&db, state_clone.reply_ttl.as_secs());
                                Ok(reply)
                            }
                        })(
                        );

                        match res {
                            Ok(reply) => {
                                let _ = state_clone.notify_tx.send(message_id.to_string());
                                let ok_resp = serde_json::json!({
                                    "status": "ok",
                                    "reply": {
                                        "messageId": reply.message_id,
                                        "seq": reply.seq,
                                        "sessionRef": reply.replier_session_id,
                                        "replierSessionId": reply.replier_session_id,
                                        "createdAt": reply.created_at,
                                        "text": reply.text
                                    }
                                });
                                let _ = writer.write_all(format!("{ok_resp}\n").as_bytes()).await;
                            }
                            Err(e) => {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "error": match &e {
                                        AppError::NotRecipient(_) => "not_recipient",
                                        AppError::NotFound(_) => "not_found",
                                        _ => "internal"
                                    },
                                    "detail": e.to_string()
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            }
                        }
                    }
                    "send" => {
                        let target_ref = req_val.get("ref").and_then(|v| v.as_str()).unwrap_or("");
                        let text = req_val.get("text").and_then(|v| v.as_str()).unwrap_or("");

                        if target_ref.is_empty() || text.is_empty() {
                            let err_resp = serde_json::json!({
                                "status": "error",
                                "error": "bad_request",
                                "detail": "ref and text are required"
                            });
                            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            line.clear();
                            continue;
                        }

                        if text.len() > state_clone.max_body {
                            let err_resp = serde_json::json!({
                                "status": "error",
                                "error": "body_too_large",
                                "detail": format!(
                                    "message body length {} exceeds maximum allowed {}",
                                    text.len(),
                                    state_clone.max_body
                                )
                            });
                            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            line.clear();
                            continue;
                        }

                        // Derive from_name: xmsg@<host> · session:<name> (sanitized and capped to 64)
                        let caller_name = caller.name.as_deref().unwrap_or(&caller.session_id);
                        let from_name =
                            inbox::sanitize_attested_from(&state_clone.host_label, caller_name);

                        let target_res = resolve_target_session(&state_clone, target_ref);
                        match target_res {
                            Ok(target) => {
                                let message_id = ulid::Ulid::new().to_string();
                                let body_len = text.len();

                                let deliver_res = match target {
                                    ResolvedTarget::Claude(session, socket_path) => {
                                        let body_with_footer = format!(
                                            "{text}\n\n[xmsg] message_id={message_id} — reply with the xmsg reply tool"
                                        );
                                        match inbox::encode_transport_line(
                                            &from_name,
                                            &body_with_footer,
                                        ) {
                                            Ok(line) => {
                                                inbox::deliver_to_socket(&socket_path, &line)
                                                    .await
                                                    .map(|_| {
                                                        (session.session_id, "claude".to_string())
                                                    })
                                            }
                                            Err(e) => Err(e),
                                        }
                                    }
                                    ResolvedTarget::Agy(session) => crate::agy::deliver_agy(
                                        &state_clone.agy_config,
                                        &state_clone.agy_store,
                                        &session,
                                        &from_name,
                                        &message_id,
                                        text,
                                    )
                                    .await
                                    .map(|_| (session.session_id, "agy".to_string())),
                                    ResolvedTarget::Pi(session) => {
                                        let envelope = format!(
                                            "[xmsg] from={from_name} message_id={message_id} — reply with the xmsg reply tool\n\n{text}"
                                        );
                                        let pi_msg = storage::PiPendingMessage {
                                            id: message_id.clone(),
                                            session_id: session.session_id.clone(),
                                            created_at: storage::now_epoch_secs(),
                                            from_name: from_name.clone(),
                                            bytes: body_len,
                                            text: text.to_string(),
                                            envelope,
                                            delivered_at: None,
                                        };
                                        let db_res = (|| -> Result<(), AppError> {
                                            let db = state_clone
                                                .db
                                                .lock()
                                                .map_err(|e| AppError::Internal(e.to_string()))?;
                                            let inserted = storage::insert_pi_message(&db, &pi_msg)
                                                .map_err(|e| AppError::Internal(e.to_string()))?;
                                            if !inserted {
                                                return Err(AppError::InboxUnavailable(
                                                    "pi session queue is full".to_string(),
                                                ));
                                            }
                                            Ok(())
                                        })();
                                        match db_res {
                                            Ok(_) => {
                                                let _ = state_clone
                                                    .pi_notify_tx
                                                    .send(session.session_id.clone());
                                                Ok((session.session_id, "pi".to_string()))
                                            }
                                            Err(e) => Err(e),
                                        }
                                    }
                                };

                                match deliver_res {
                                    Ok((delivered_session_id, target_harness)) => {
                                        let msg_record = storage::MessageRecord {
                                            id: message_id.clone(),
                                            created_at: storage::now_epoch_secs(),
                                            session_id: delivered_session_id.clone(),
                                            from_name: from_name.clone(),
                                            bytes: body_len,
                                            outcome: "delivered".to_string(),
                                            recipient_harness: target_harness,
                                        };
                                        if let Ok(db) = state_clone.db.lock() {
                                            let _ = storage::insert_message(&db, &msg_record);
                                        }
                                        let ok_resp = serde_json::json!({
                                            "status": "ok",
                                            "delivery": {
                                                "sessionId": delivered_session_id,
                                                "fromName": from_name,
                                                "bytes": body_len,
                                                "messageId": message_id
                                            }
                                        });
                                        let _ = writer
                                            .write_all(format!("{ok_resp}\n").as_bytes())
                                            .await;
                                    }
                                    Err(e) => {
                                        let err_resp = serde_json::json!({
                                            "status": "error",
                                            "error": "delivery_failed",
                                            "detail": e.to_string()
                                        });
                                        let _ = writer
                                            .write_all(format!("{err_resp}\n").as_bytes())
                                            .await;
                                    }
                                }
                            }
                            Err(e) => {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "error": "not_found",
                                    "detail": e.to_string()
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            }
                        }
                    }
                    _ => {
                        let err_resp = serde_json::json!({
                            "status": "error",
                            "error": "bad_request",
                            "detail": format!("unknown action: '{action}'")
                        });
                        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                    }
                }

                line.clear();
            }
        });
    }
}
