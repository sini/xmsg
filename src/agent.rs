use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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

/// Resolves `<runtime dir>/xmsg`: `$XDG_RUNTIME_DIR` when set, otherwise the
/// platform's per-user runtime dir (the Darwin user temp dir on macOS).
pub fn socket_dir_for_env(xdg_var: Option<&str>) -> Result<PathBuf, AppError> {
    match xdg_var {
        Some(val) if !val.trim().is_empty() => Ok(PathBuf::from(val).join("xmsg")),
        _ => crate::process::fallback_runtime_dir()
            .map(|d| d.join("xmsg"))
            .ok_or_else(|| AppError::InsecureSocketDir(
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
    sessions_dirs: &(impl crate::registry::SessionDirs + ?Sized),
    _agy_config: &AgyConfig,
    agy_store: &crate::agy::AgyStore,
    pi_store: &PiStore,
    svc_store: &crate::svc::SvcStore,
    peer_pid: u32,
) -> Result<Session, AppError> {
    let mut curr_pid = peer_pid;

    for _ in 0..32 {
        // 1. Check Claude sessions
        let claude_sessions = registry::read_session_entries(sessions_dirs);
        for entry in claude_sessions {
            if entry.pid == curr_pid
                && registry::is_pid_live_in(proc_root, curr_pid, &entry.proc_start)
            {
                return Ok(entry.into());
            }
        }

        // 2. Check Antigravity registered sessions
        {
            let agy_lock = agy_store.read().unwrap();
            for info in agy_lock.values() {
                if info.pid > 0
                    && info.pid == curr_pid
                    && agy::is_agy_session_alive(proc_root, info)
                {
                    return Ok(Session {
                        session_id: if !info.session_key.is_empty() {
                            info.session_key.clone()
                        } else {
                            info.conversation_id.clone()
                        },
                        name: if !info.conversation_id.is_empty() {
                            Some(info.conversation_id.clone())
                        } else {
                            None
                        },
                        pid: info.pid,
                        cwd: "/".to_string(),
                        status: "idle".to_string(),
                        kind: "interactive".to_string(),
                        entrypoint: None,
                        version: None,
                        started_at: info.registered_at.max(0) as u64,
                        updated_at: info.registered_at.max(0) as u64,
                        harness: "agy".to_string(),
                        registered: Some(info.has_credentials()),
                    });
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

        // 4. Check Svc sessions
        {
            let svc_lock = svc_store.read().unwrap();
            for info in svc_lock.values() {
                if info.pid == curr_pid && crate::svc::is_svc_session_alive(proc_root, info) {
                    return Ok(Session {
                        session_id: info.session_id.clone(),
                        name: Some(info.name.clone()),
                        pid: info.pid,
                        cwd: info.cwd.clone(),
                        status: "idle".to_string(),
                        kind: "daemon".to_string(),
                        entrypoint: None,
                        version: None,
                        started_at: info.registered_at as u64,
                        updated_at: info.registered_at as u64,
                        harness: "svc".to_string(),
                        registered: Some(true),
                    });
                }
            }
        }

        // Step up to PPID
        let Some(ppid) = crate::process::parent_pid(proc_root, curr_pid) else {
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
    fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("failed to set permissions on {}: {e}", sock_path.display()),
        )
    })?;

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
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut byte_buf = Vec::new();
            let max_frame = state_clone.max_body * 6 + 4096;

            loop {
                byte_buf.clear();
                let n = (&mut buf_reader)
                    .take((max_frame + 1) as u64)
                    .read_until(b'\n', &mut byte_buf)
                    .await
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                if byte_buf.len() > max_frame || (n >= max_frame && !byte_buf.ends_with(b"\n")) {
                    let err_resp = serde_json::json!({
                        "status": "error",
                        "error": "bad_request",
                        "detail": "frame exceeds maximum allowed size"
                    });
                    let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                    break;
                }
                if !byte_buf.ends_with(b"\n") {
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

                let line = match std::str::from_utf8(&byte_buf) {
                    Ok(s) => s,
                    Err(_) => {
                        let err_resp = serde_json::json!({
                            "status": "error",
                            "error": "bad_request",
                            "detail": "invalid utf-8"
                        });
                        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                        break;
                    }
                };

                let trimmed = line.trim();
                if trimmed.is_empty() {
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
                        continue;
                    }
                };

                let action = req_val.get("action").and_then(|a| a.as_str()).unwrap_or("");

                if action == "mcp_start" {
                    match crate::agy::attest_mcp_caller(
                        &state_clone.agy_config.proc_root,
                        &state_clone.agy_config.proc_locks_path,
                        &state_clone.agy_config.presence_dir,
                        &state_clone.agy_config.trusted_agy_exes,
                        my_uid,
                        peer_uid,
                        peer_pid,
                    ) {
                        Ok((reg, conv_id)) => {
                            let session_key = reg.session_key.clone();
                            {
                                let mut store_lock = state_clone.agy_store.write().unwrap();
                                store_lock.entry(session_key.clone()).or_insert_with(|| {
                                    crate::agy::AgySessionInfo::new(
                                        conv_id,
                                        reg.pid,
                                        reg.starttime,
                                        None,
                                    )
                                });
                            }
                            let resp = serde_json::json!({
                                "status": "ok",
                                "sessionId": session_key,
                            });
                            let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                        }
                        Err(e) => {
                            let err_resp = serde_json::json!({
                                "status": "error",
                                "error": "unattested",
                                "detail": e.to_string()
                            });
                            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                        }
                    }
                    continue;
                }

                // Resolve caller session via ancestor walk
                let caller = match resolve_caller_session(
                    &state_clone.agy_config.proc_root,
                    &state_clone.sessions_dirs,
                    &state_clone.agy_config,
                    &state_clone.agy_store,
                    &state_clone.pi_store,
                    &state_clone.svc_store,
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
                            continue;
                        }

                        if text.len() > state_clone.max_body {
                            let err_resp = serde_json::json!({
                                "status": "error",
                                "error": "body_too_large",
                                "detail": format!(
                                    "reply body length {} exceeds maximum allowed {}",
                                    text.len(),
                                    state_clone.max_body
                                )
                            });
                            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            continue;
                        }

                        let msg_res: Result<storage::MessageRecord, (String, String)> = {
                            match state_clone.db.lock() {
                                Ok(db) => match storage::get_message(&db, message_id) {
                                    Ok(Some(m)) => Ok(m),
                                    Ok(None) => Err((
                                        "not_found".to_string(),
                                        format!("message '{message_id}'"),
                                    )),
                                    Err(e) => Err(("internal".to_string(), e.to_string())),
                                },
                                Err(e) => Err(("internal".to_string(), e.to_string())),
                            }
                        };

                        let msg = match msg_res {
                            Ok(m) => m,
                            Err((err_kind, detail)) => {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "error": err_kind,
                                    "detail": detail
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                                continue;
                            }
                        };

                        if caller.harness != msg.recipient_harness
                            || caller.session_id != msg.session_id
                        {
                            let caller_display = if let Some(stripped) = caller
                                .session_id
                                .strip_prefix(&format!("{}:", caller.harness))
                            {
                                format!("{}:{}", caller.harness, stripped)
                            } else {
                                format!("{}:{}", caller.harness, caller.session_id)
                            };
                            let msg_display = if let Some(stripped) = msg
                                .session_id
                                .strip_prefix(&format!("{}:", msg.recipient_harness))
                            {
                                format!("{}:{}", msg.recipient_harness, stripped)
                            } else {
                                format!("{}:{}", msg.recipient_harness, msg.session_id)
                            };
                            let err_resp = serde_json::json!({
                                "status": "error",
                                "error": "not_recipient",
                                "detail": format!(
                                    "caller session '{caller_display}' is not recipient of message '{message_id}' (expected '{msg_display}')"
                                )
                            });
                            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            continue;
                        }

                        let is_leaf_peer = if let Some(ret_host) = msg.return_host.as_deref() {
                            state_clone
                                .fed_state
                                .as_ref()
                                .and_then(|fs| fs.peers.get(ret_host))
                                .map(|p| p.leaf)
                                .unwrap_or(false)
                        } else {
                            false
                        };

                        let (push_outcome, pushed_message_id) = if let (
                            Some(ret_harness),
                            Some(ret_session_id),
                        ) = (
                            msg.return_harness.as_deref(),
                            msg.return_session_id.as_deref(),
                        ) {
                            if !msg.push_replies || is_leaf_peer {
                                (Some("disabled".to_string()), None)
                            } else if let Some(ret_host) = msg
                                .return_host
                                .as_deref()
                                .filter(|h| !h.is_empty() && *h != state_clone.host_label)
                            {
                                let new_message_id = ulid::Ulid::new().to_string();
                                let replier_name =
                                    caller.name.as_deref().unwrap_or(&caller.session_id);
                                let replier = crate::fed::FedReplier {
                                    harness: caller.harness.clone(),
                                    session_id: caller.session_id.clone(),
                                    name: replier_name.to_string(),
                                };
                                let reply_envelope = crate::fed::FedReplyEnvelope {
                                    v: 1,
                                    id: new_message_id.clone(),
                                    in_reply_to: message_id.to_string(),
                                    replier,
                                    text: text.to_string(),
                                    created_at: storage::now_epoch_secs(),
                                };
                                let push_res: Result<(), &'static str> =
                                    match &state_clone.fed_state {
                                        Some(fed_state) => {
                                            match crate::fed::send_federated_reply(
                                                fed_state,
                                                ret_host,
                                                &reply_envelope,
                                            )
                                            .await
                                            {
                                                Ok(_) => Ok(()),
                                                Err(AppError::Gone { .. }) => Err("sender_gone"),
                                                Err(_) => Err("push_failed"),
                                            }
                                        }
                                        None => Err("push_failed"),
                                    };
                                let outcome_str = match push_res {
                                    Ok(()) => "pushed",
                                    Err(e) => e,
                                };
                                (Some(outcome_str.to_string()), Some(new_message_id))
                            } else {
                                let new_message_id = ulid::Ulid::new().to_string();
                                let replier_name =
                                    caller.name.as_deref().unwrap_or(&caller.session_id);
                                let replier_badge = inbox::sanitize_attested_from(
                                    &state_clone.host_label,
                                    &caller.harness,
                                    replier_name,
                                );

                                let push_res: Result<(), &'static str> = match ret_harness {
                                    "claude" => {
                                        match registry::resolve_session(
                                            &state_clone.sessions_dirs,
                                            ret_session_id,
                                        ) {
                                            Ok((_session, socket_path)) => {
                                                if !socket_path.exists() {
                                                    Err("sender_gone")
                                                } else {
                                                    let body_with_header = format!(
                                                        "[xmsg] reply to message_id={message_id} — message_id={new_message_id}; reply with the xmsg reply tool\n\n{text}"
                                                    );
                                                    match inbox::encode_transport_line(
                                                        &replier_badge,
                                                        &body_with_header,
                                                    ) {
                                                        Ok(line) => match inbox::deliver_to_socket(
                                                            &socket_path,
                                                            &line,
                                                        )
                                                        .await
                                                        {
                                                            Ok(()) => Ok(()),
                                                            Err(e) => {
                                                                let err_str = e.to_string();
                                                                if err_str
                                                                    .contains("Connection refused")
                                                                    || err_str.contains(
                                                                        "No such file or directory",
                                                                    )
                                                                {
                                                                    Err("sender_gone")
                                                                } else {
                                                                    Err("push_failed")
                                                                }
                                                            }
                                                        },
                                                        Err(_) => Err("push_failed"),
                                                    }
                                                }
                                            }
                                            Err(AppError::Gone { .. })
                                            | Err(AppError::NotFound(_)) => Err("sender_gone"),
                                            Err(_) => Err("push_failed"),
                                        }
                                    }
                                    "agy" => {
                                        match crate::agy::resolve_agy_session(
                                            &state_clone.agy_config,
                                            &state_clone.agy_store,
                                            ret_session_id,
                                        ) {
                                            Ok(Some(session)) => {
                                                let envelope = format!(
                                                    "[xmsg] reply to message_id={message_id} — message_id={new_message_id}; reply with the xmsg reply tool\n\n{text}"
                                                );
                                                match crate::agy::deliver_agy_envelope(
                                                    &state_clone.agy_config,
                                                    &state_clone.agy_store,
                                                    &session,
                                                    &replier_badge,
                                                    &envelope,
                                                )
                                                .await
                                                {
                                                    Ok(()) => Ok(()),
                                                    Err(AppError::Gone { .. })
                                                    | Err(AppError::CredentialsStale(_)) => {
                                                        Err("sender_gone")
                                                    }
                                                    Err(_) => Err("push_failed"),
                                                }
                                            }
                                            Ok(None) => Err("sender_gone"),
                                            Err(_) => Err("push_failed"),
                                        }
                                    }
                                    "pi" => {
                                        match crate::pi::resolve_pi_session(
                                            &state_clone.agy_config.proc_root,
                                            &state_clone.pi_store,
                                            ret_session_id,
                                        ) {
                                            Ok(Some(session)) => {
                                                let envelope = format!(
                                                    "[xmsg] reply to message_id={message_id} — message_id={new_message_id}; reply with the xmsg reply tool\n\n{text}"
                                                );
                                                let pi_msg = storage::PiPendingMessage {
                                                    id: new_message_id.clone(),
                                                    session_id: session.session_id.clone(),
                                                    created_at: storage::now_epoch_secs(),
                                                    from_name: replier_badge.clone(),
                                                    bytes: text.len(),
                                                    text: text.to_string(),
                                                    envelope,
                                                    delivered_at: None,
                                                };
                                                let insert_res = (|| -> Result<bool, AppError> {
                                                    let db =
                                                        state_clone.db.lock().map_err(|e| {
                                                            AppError::Internal(e.to_string())
                                                        })?;
                                                    storage::insert_pi_message(&db, &pi_msg)
                                                        .map_err(|e| {
                                                            AppError::Internal(e.to_string())
                                                        })
                                                })(
                                                );
                                                match insert_res {
                                                    Ok(true) => {
                                                        let _ = state_clone
                                                            .pi_notify_tx
                                                            .send(session.session_id.clone());
                                                        Ok(())
                                                    }
                                                    Ok(false) => Err("push_failed"),
                                                    Err(_) => Err("push_failed"),
                                                }
                                            }
                                            Ok(None) => Err("sender_gone"),
                                            Err(_) => Err("push_failed"),
                                        }
                                    }
                                    "svc" => {
                                        match crate::svc::resolve_svc_session(
                                            &state_clone.agy_config.proc_root,
                                            &state_clone.svc_store,
                                            ret_session_id,
                                        ) {
                                            Ok(Some(session)) => {
                                                let envelope = format!(
                                                    "[xmsg] reply to message_id={message_id} — message_id={new_message_id}; reply with the xmsg reply tool\n\n{text}"
                                                );
                                                let svc_msg = storage::SvcPendingMessage {
                                                    id: new_message_id.clone(),
                                                    session_id: session.session_id.clone(),
                                                    created_at: storage::now_epoch_secs(),
                                                    from_name: replier_badge.clone(),
                                                    bytes: text.len(),
                                                    text: text.to_string(),
                                                    envelope,
                                                    delivered_at: None,
                                                };
                                                let insert_res = (|| -> Result<bool, AppError> {
                                                    let db =
                                                        state_clone.db.lock().map_err(|e| {
                                                            AppError::Internal(e.to_string())
                                                        })?;
                                                    storage::insert_svc_message(&db, &svc_msg)
                                                        .map_err(|e| {
                                                            AppError::Internal(e.to_string())
                                                        })
                                                })(
                                                );
                                                match insert_res {
                                                    Ok(true) => {
                                                        let _ = state_clone
                                                            .svc_notify_tx
                                                            .send(session.session_id.clone());
                                                        Ok(())
                                                    }
                                                    Ok(false) => Err("push_failed"),
                                                    Err(_) => Err("push_failed"),
                                                }
                                            }
                                            Ok(None) => Err("sender_gone"),
                                            Err(_) => Err("push_failed"),
                                        }
                                    }
                                    _ => Err("sender_gone"),
                                };

                                match push_res {
                                    Ok(()) => {
                                        let pushed_record = storage::MessageRecord {
                                            id: new_message_id.clone(),
                                            created_at: storage::now_epoch_secs(),
                                            session_id: ret_session_id.to_string(),
                                            from_name: replier_badge,
                                            bytes: text.len(),
                                            outcome: "delivered".to_string(),
                                            recipient_harness: ret_harness.to_string(),
                                            return_harness: Some(caller.harness.clone()),
                                            return_session_id: Some(caller.session_id.clone()),
                                            push_replies: true,
                                            thread_id: if msg.thread_id.is_empty() {
                                                msg.id.clone()
                                            } else {
                                                msg.thread_id.clone()
                                            },
                                            return_host: None,
                                        };
                                        if let Ok(db) = state_clone.db.lock() {
                                            let _ = storage::insert_message(&db, &pushed_record);
                                        }
                                        (Some("pushed".to_string()), Some(new_message_id))
                                    }
                                    Err(outcome) => (Some(outcome.to_string()), None),
                                }
                            }
                        } else {
                            (None, None)
                        };

                        let res: Result<storage::ReplyRecord, AppError> = (|| {
                            let db = state_clone
                                .db
                                .lock()
                                .map_err(|e| AppError::Internal(e.to_string()))?;
                            let reply = storage::insert_reply(
                                &db,
                                message_id,
                                &caller.session_id,
                                text,
                                push_outcome.as_deref(),
                                pushed_message_id.as_deref(),
                            )
                            .map_err(|e| AppError::Internal(e.to_string()))?;
                            let _ = storage::purge_replies(&db, state_clone.reply_ttl.as_secs());
                            let _ = storage::purge_messages(&db, state_clone.reply_ttl.as_secs());
                            Ok(reply)
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
                                        "text": reply.text,
                                        "pushOutcome": reply.push_outcome,
                                        "pushedMessageId": reply.pushed_message_id,
                                    }
                                });
                                let _ = writer.write_all(format!("{ok_resp}\n").as_bytes()).await;
                            }
                            Err(e) => {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "error": "internal",
                                    "detail": e.to_string()
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            }
                        }
                    }
                    "send" => {
                        let target_ref = req_val.get("ref").and_then(|v| v.as_str()).unwrap_or("");
                        let text = req_val.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let push_replies = req_val
                            .get("push_replies")
                            .or_else(|| req_val.get("pushReplies"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                        let idempotency_key = req_val
                            .get("idempotency_key")
                            .or_else(|| req_val.get("idempotencyKey"))
                            .and_then(|v| v.as_str());

                        if target_ref.is_empty() || text.is_empty() {
                            let err_resp = serde_json::json!({
                                "status": "error",
                                "error": "bad_request",
                                "detail": "ref and text are required"
                            });
                            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            continue;
                        }

                        if let Some(key) = idempotency_key {
                            if key.is_empty()
                                || key.len() > 128
                                || key.chars().any(|c| c.is_control())
                            {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "error": "bad_request",
                                    "detail": "invalid idempotency_key: must be 1..128 non-control chars"
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                                continue;
                            }

                            let principal = format!("session:{}", caller.session_id);
                            let existing = {
                                if let Ok(db) = state_clone.db.lock() {
                                    storage::get_idempotency_record(
                                        &db,
                                        &principal,
                                        key,
                                        state_clone.idempotency_ttl.as_secs(),
                                    )
                                    .ok()
                                    .flatten()
                                } else {
                                    None
                                }
                            };

                            if let Some(record) = existing {
                                if record.body != text {
                                    let err_resp = serde_json::json!({
                                        "status": "error",
                                        "error": "conflict",
                                        "detail": format!(
                                            "idempotency key '{key}' was already used with a different message body"
                                        )
                                    });
                                    let _ =
                                        writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                                    continue;
                                }

                                let ok_resp = serde_json::json!({
                                    "status": "ok",
                                    "delivery": {
                                        "sessionId": record.session_id,
                                        "fromName": record.from_name,
                                        "bytes": record.bytes,
                                        "messageId": record.message_id,
                                        "outcome": record.outcome,
                                    }
                                });
                                let _ = writer.write_all(format!("{ok_resp}\n").as_bytes()).await;
                                continue;
                            }
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
                            continue;
                        }

                        // Derive from_name: xmsg@<host> · <harness>:<name> (sanitized and capped to 64)
                        let caller_name = caller.name.as_deref().unwrap_or(&caller.session_id);
                        let from_name = inbox::sanitize_attested_from(
                            &state_clone.host_label,
                            &caller.harness,
                            caller_name,
                        );

                        // Check if target is cross-host
                        let (local_ref, remote_host) = match crate::fed::split_peer_ref(target_ref)
                        {
                            Some((r, h)) if h != state_clone.host_label => (r, Some(h)),
                            Some((r, _)) => (r, None),
                            None => (target_ref, None),
                        };

                        if let Some(target_host) = remote_host {
                            let fed_state = match &state_clone.fed_state {
                                Some(fs) if fs.peers.contains_name(target_host) => fs.clone(),
                                _ => {
                                    let err_resp = serde_json::json!({
                                        "status": "error",
                                        "error": "unknown_peer",
                                        "detail": format!("unknown peer host '{target_host}'")
                                    });
                                    let _ =
                                        writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                                    continue;
                                }
                            };

                            let message_id = ulid::Ulid::new().to_string();
                            let principal = crate::fed::FedPrincipal::Session {
                                harness: caller.harness.clone(),
                                session_id: caller.session_id.clone(),
                                name: caller_name.to_string(),
                            };
                            let envelope = crate::fed::FedEnvelope {
                                v: 1,
                                id: message_id.clone(),
                                principal,
                                to: crate::fed::FedTarget {
                                    r#ref: local_ref.to_string(),
                                },
                                body: text.to_string(),
                                push_replies,
                                thread_id: message_id.clone(),
                                created_at: storage::now_epoch_secs(),
                            };

                            match crate::fed::send_federated_message(
                                &fed_state,
                                target_host,
                                &envelope,
                            )
                            .await
                            {
                                Ok(delivery_resp) => {
                                    let outcome =
                                        delivery_resp.outcome.as_deref().unwrap_or("delivered");
                                    if let Ok(db) = state_clone.db.lock() {
                                        let _ = storage::insert_outbound(
                                            &db,
                                            &message_id,
                                            target_host,
                                            local_ref,
                                            outcome,
                                            storage::now_epoch_secs(),
                                        );
                                        let msg_record = storage::MessageRecord {
                                            id: message_id.clone(),
                                            created_at: storage::now_epoch_secs(),
                                            session_id: local_ref.to_string(),
                                            from_name: from_name.clone(),
                                            bytes: text.len(),
                                            outcome: outcome.to_string(),
                                            recipient_harness: "claude".to_string(),
                                            return_harness: Some(caller.harness.clone()),
                                            return_session_id: Some(caller.session_id.clone()),
                                            push_replies,
                                            thread_id: message_id.clone(),
                                            return_host: Some(state_clone.host_label.clone()),
                                        };
                                        let _ = storage::insert_message(&db, &msg_record);
                                        if let Some(key) = idempotency_key {
                                            let record = storage::IdempotencyRecord {
                                                principal: format!("session:{}", caller.session_id),
                                                key: key.to_string(),
                                                body: text.to_string(),
                                                message_id: message_id.clone(),
                                                session_id: delivery_resp.session_id.clone(),
                                                from_name: from_name.clone(),
                                                bytes: delivery_resp.bytes,
                                                outcome: outcome.to_string(),
                                                created_at: storage::now_epoch_secs(),
                                            };
                                            let _ =
                                                storage::insert_idempotency_record(&db, &record);
                                            let _ = storage::purge_idempotency_keys(
                                                &db,
                                                state_clone.idempotency_ttl.as_secs(),
                                            );
                                        }
                                    }
                                    let resp = serde_json::json!({
                                        "status": "ok",
                                        "delivery": {
                                            "messageId": message_id,
                                            "outcome": outcome,
                                            "bytes": delivery_resp.bytes,
                                        }
                                    });
                                    let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                                }
                                Err(e) => {
                                    let (err_code, detail) = match e {
                                        AppError::NoForward(d) => ("no_forward", d),
                                        AppError::OpDenied(d) => ("op_denied", d),
                                        AppError::PeerRejected(d) => ("peer_rejected", d),
                                        AppError::UnknownPeer(d) => ("unknown_peer", d),
                                        AppError::RateLimited(d) => ("rate_limited", d),
                                        AppError::NotRecipient(d) => ("not_recipient", d),
                                        other => ("service_unavailable", other.to_string()),
                                    };
                                    let err_resp = serde_json::json!({
                                        "status": "error",
                                        "error": err_code,
                                        "detail": detail,
                                    });
                                    let _ =
                                        writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                                }
                            }
                            continue;
                        }

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
                                                        (
                                                            session.session_id,
                                                            "claude".to_string(),
                                                            "delivered",
                                                        )
                                                    })
                                            }
                                            Err(e) => Err(e),
                                        }
                                    }
                                    ResolvedTarget::Agy(session) => {
                                        let has_creds = {
                                            let store_lock = state_clone.agy_store.read().unwrap();
                                            store_lock
                                                .get(&session.session_id)
                                                .or_else(|| {
                                                    store_lock.values().find(|info| {
                                                        info.conversation_id == session.session_id
                                                            || session.name.as_deref()
                                                                == Some(&info.conversation_id)
                                                    })
                                                })
                                                .map(|info| info.has_credentials())
                                                .unwrap_or(false)
                                        };

                                        if has_creds {
                                            crate::agy::deliver_agy(
                                                &state_clone.agy_config,
                                                &state_clone.agy_store,
                                                &session,
                                                &from_name,
                                                &message_id,
                                                text,
                                            )
                                            .await
                                            .map(
                                                |_| {
                                                    (
                                                        session.session_id,
                                                        "agy".to_string(),
                                                        "delivered",
                                                    )
                                                },
                                            )
                                        } else {
                                            let envelope = format!(
                                                "[xmsg] from={from_name} message_id={message_id} — reply with the xmsg reply tool\n\n{text}"
                                            );
                                            let agy_msg = storage::AgyPendingMessage {
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
                                                let db = state_clone.db.lock().map_err(|e| {
                                                    AppError::Internal(e.to_string())
                                                })?;
                                                storage::insert_agy_message(&db, &agy_msg)
                                                    .map_err(|e| {
                                                        AppError::Internal(e.to_string())
                                                    })?;
                                                Ok(())
                                            })(
                                            );
                                            match db_res {
                                                Ok(_) => Ok((
                                                    session.session_id,
                                                    "agy".to_string(),
                                                    "queued",
                                                )),
                                                Err(e) => Err(e),
                                            }
                                        }
                                    }
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
                                                return Err(AppError::ServiceUnavailable(
                                                    "pi session message queue is full".to_string(),
                                                ));
                                            }
                                            Ok(())
                                        })();
                                        match db_res {
                                            Ok(_) => {
                                                let _ = state_clone
                                                    .pi_notify_tx
                                                    .send(session.session_id.clone());
                                                Ok((
                                                    session.session_id,
                                                    "pi".to_string(),
                                                    "delivered",
                                                ))
                                            }
                                            Err(e) => Err(e),
                                        }
                                    }
                                    ResolvedTarget::Svc(session) => {
                                        let envelope = format!(
                                            "[xmsg] from={from_name} message_id={message_id} — reply with the xmsg reply tool\n\n{text}"
                                        );
                                        let svc_msg = storage::SvcPendingMessage {
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
                                            let inserted =
                                                storage::insert_svc_message(&db, &svc_msg)
                                                    .map_err(|e| {
                                                        AppError::Internal(e.to_string())
                                                    })?;
                                            if !inserted {
                                                return Err(AppError::ServiceUnavailable(
                                                    "svc session message queue is full".to_string(),
                                                ));
                                            }
                                            Ok(())
                                        })();
                                        match db_res {
                                            Ok(_) => {
                                                let _ = state_clone
                                                    .svc_notify_tx
                                                    .send(session.session_id.clone());
                                                Ok((
                                                    session.session_id,
                                                    "svc".to_string(),
                                                    "delivered",
                                                ))
                                            }
                                            Err(e) => Err(e),
                                        }
                                    }
                                };

                                match deliver_res {
                                    Ok((delivered_session_id, target_harness, outcome_str)) => {
                                        let msg_record = storage::MessageRecord {
                                            id: message_id.clone(),
                                            created_at: storage::now_epoch_secs(),
                                            session_id: delivered_session_id.clone(),
                                            from_name: from_name.clone(),
                                            bytes: body_len,
                                            outcome: outcome_str.to_string(),
                                            recipient_harness: target_harness,
                                            return_harness: Some(caller.harness.clone()),
                                            return_session_id: Some(caller.session_id.clone()),
                                            push_replies,
                                            thread_id: message_id.clone(),
                                            return_host: None,
                                        };
                                        if let Ok(db) = state_clone.db.lock() {
                                            let _ = storage::insert_message(&db, &msg_record);
                                            if let Some(key) = idempotency_key {
                                                let record = storage::IdempotencyRecord {
                                                    principal: format!(
                                                        "session:{}",
                                                        caller.session_id
                                                    ),
                                                    key: key.to_string(),
                                                    body: text.to_string(),
                                                    message_id: message_id.clone(),
                                                    session_id: delivered_session_id.clone(),
                                                    from_name: from_name.clone(),
                                                    bytes: body_len,
                                                    outcome: outcome_str.to_string(),
                                                    created_at: storage::now_epoch_secs(),
                                                };
                                                let _ = storage::insert_idempotency_record(
                                                    &db, &record,
                                                );
                                                let _ = storage::purge_idempotency_keys(
                                                    &db,
                                                    state_clone.idempotency_ttl.as_secs(),
                                                );
                                            }
                                        }
                                        let ok_resp = serde_json::json!({
                                            "status": "ok",
                                            "delivery": {
                                                "sessionId": delivered_session_id,
                                                "fromName": from_name,
                                                "bytes": body_len,
                                                "messageId": message_id,
                                                "outcome": outcome_str,
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
                            Err(AppError::Unregistered(pid)) => {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "error": "unregistered",
                                    "detail": format!("pid {pid} is unregistered")
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
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
            }
        });
    }
}
