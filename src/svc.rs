use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;

use crate::error::AppError;
use crate::registry::{Session, SessionsQuery};
use crate::storage::{self, now_epoch_secs};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SvcRegisterRequest {
    pub name: String,
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SvcSessionInfo {
    pub session_id: String,
    pub name: String,
    pub pid: u32,
    pub starttime: String,
    pub cwd: String,
    pub registered_at: i64,
}

pub type SvcStore = Arc<RwLock<HashMap<String, SvcSessionInfo>>>;

pub fn new_svc_store() -> SvcStore {
    Arc::new(RwLock::new(HashMap::new()))
}

pub fn is_svc_session_alive(proc_root: &Path, info: &SvcSessionInfo) -> bool {
    match crate::process::starttime(proc_root, info.pid) {
        Ok(st) => st == info.starttime,
        Err(_) => false,
    }
}

pub fn verify_svc_process(
    proc_root: &Path,
    trusted_exes: &HashMap<String, PathBuf>,
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
    name: &str,
) -> Result<String, AppError> {
    if peer_uid != my_uid {
        return Err(AppError::NotRecipient(format!(
            "peer UID {peer_uid} does not match server UID {my_uid}"
        )));
    }

    let trusted_path = match trusted_exes.get(name) {
        Some(p) => p,
        None => {
            return Err(AppError::BadRequest(format!(
                "no trusted executable configured for service '{name}'"
            )));
        }
    };

    let exe = crate::process::exe_path(proc_root, peer_pid)
        .map_err(|e| AppError::NotFound(format!("process {peer_pid} exe not found: {e}")))?;

    let exe_canon = std::fs::canonicalize(&exe).unwrap_or_else(|_| exe.clone());
    let trusted_canon =
        std::fs::canonicalize(trusted_path).unwrap_or_else(|_| trusted_path.clone());

    if exe_canon != trusted_canon {
        return Err(AppError::BadRequest(format!(
            "peer process {peer_pid} executable does not match trusted executable for service '{name}'"
        )));
    }

    let starttime = crate::process::starttime(proc_root, peer_pid).map_err(|e| {
        AppError::Internal(format!("failed to read starttime for PID {peer_pid}: {e}"))
    })?;

    Ok(starttime)
}

pub fn list_svc_sessions(
    proc_root: &Path,
    store: &SvcStore,
    query: &SessionsQuery,
) -> Vec<Session> {
    let mut store_lock = store.write().unwrap();
    let mut dead = Vec::new();
    let mut sessions = Vec::new();

    for (id, info) in store_lock.iter() {
        if !is_svc_session_alive(proc_root, info) {
            dead.push(id.clone());
            continue;
        }
        let session = Session {
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
        };

        if let Some(ref q_status) = query.status {
            if session.status != *q_status {
                continue;
            }
        }
        sessions.push(session);
    }

    for d in dead {
        store_lock.remove(&d);
    }

    sessions
}

pub fn resolve_svc_session(
    proc_root: &Path,
    store: &SvcStore,
    ref_str: &str,
) -> Result<Option<Session>, AppError> {
    let query = SessionsQuery::default();
    let all = list_svc_sessions(proc_root, store, &query);
    let ref_lower = ref_str.to_ascii_lowercase();
    let ref_unprefixed = ref_lower.strip_prefix("svc:").unwrap_or(&ref_lower);
    let ref_pid = ref_str.parse::<u32>().ok();

    let matched: Vec<Session> = all
        .into_iter()
        .filter(|s| {
            if s.session_id.to_ascii_lowercase() == ref_lower {
                return true;
            }
            if let Some(ref name) = s.name {
                if name.to_ascii_lowercase() == ref_lower
                    || name.to_ascii_lowercase() == ref_unprefixed
                {
                    return true;
                }
            }
            if s.session_id
                .to_ascii_lowercase()
                .strip_prefix("svc:")
                .unwrap_or("")
                == ref_unprefixed
            {
                return true;
            }
            if let Some(pid) = ref_pid {
                if s.pid == pid {
                    return true;
                }
            }
            false
        })
        .collect();

    if matched.is_empty() {
        Ok(None)
    } else if matched.len() > 1 {
        let ids: Vec<String> = matched.into_iter().map(|s| s.session_id).collect();
        Err(AppError::Ambiguous(ids.join(", ")))
    } else {
        Ok(Some(matched.into_iter().next().unwrap()))
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_svc_connection<
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    mut buf_reader: R,
    mut writer: W,
    proc_root: std::path::PathBuf,
    store: SvcStore,
    trusted_svc_exes: &HashMap<String, PathBuf>,
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
    req: SvcRegisterRequest,
    db: Arc<Mutex<rusqlite::Connection>>,
    svc_notify_tx: broadcast::Sender<String>,
    reply_ttl: Duration,
    leaf_mode: bool,
    leaf_principal: Option<String>,
    fed_state: Option<Arc<crate::fed::FedState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let raw_name = req.name.trim();
    let name = raw_name
        .strip_prefix("svc:")
        .unwrap_or(raw_name)
        .to_string();
    if name.is_empty() {
        let err_resp = serde_json::json!({
            "status": "error",
            "detail": "service name must not be empty",
        });
        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
        return Err(AppError::BadRequest("service name must not be empty".to_string()).into());
    }

    let starttime = if leaf_mode {
        let expected_name = leaf_principal
            .as_deref()
            .unwrap_or("")
            .strip_prefix("svc:")
            .unwrap_or("");
        if name != expected_name {
            let err_resp = serde_json::json!({
                "status": "error",
                "detail": format!("service name '{raw_name}' does not match leaf principal"),
            });
            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
            return Err(AppError::NotRecipient(format!(
                "service name '{raw_name}' does not match leaf principal"
            ))
            .into());
        }

        if peer_uid != my_uid {
            let err_resp = serde_json::json!({
                "status": "error",
                "detail": format!("peer UID {peer_uid} does not match server UID {my_uid}"),
            });
            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
            return Err(AppError::NotRecipient(format!(
                "peer UID {peer_uid} does not match server UID {my_uid}"
            ))
            .into());
        }

        crate::process::starttime(&proc_root, peer_pid).unwrap_or_else(|_| "0".to_string())
    } else {
        match verify_svc_process(
            &proc_root,
            trusted_svc_exes,
            my_uid,
            peer_uid,
            peer_pid,
            &name,
        ) {
            Ok(st) => st,
            Err(e) => {
                let err_resp = serde_json::json!({
                    "status": "error",
                    "detail": e.to_string(),
                });
                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                return Err(e.into());
            }
        }
    };

    let session_id = format!("svc:{name}");

    // Single live registration check (Gate r2 G5 / Oracle 5)
    let conflict = {
        let store_lock = store.read().unwrap();
        if let Some(existing) = store_lock.get(&session_id) {
            (existing.pid != peer_pid || existing.starttime != starttime)
                && is_svc_session_alive(&proc_root, existing)
        } else {
            false
        }
    };
    if conflict {
        let err_resp = serde_json::json!({
            "status": "error",
            "detail": format!("service '{session_id}' already has an active registration"),
        });
        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
        return Err(AppError::BadRequest(format!(
            "service '{session_id}' already has an active registration"
        ))
        .into());
    }

    {
        let info = SvcSessionInfo {
            session_id: session_id.clone(),
            name: name.clone(),
            pid: peer_pid,
            starttime: starttime.clone(),
            cwd: req.cwd.unwrap_or_else(|| "/".to_string()),
            registered_at: now_epoch_secs(),
        };
        store.write().unwrap().insert(session_id.clone(), info);
    }

    // Write initial registration ok with server-derived sessionId
    let ok_resp = serde_json::json!({
        "status": "ok",
        "sessionId": session_id,
    });
    writer.write_all(format!("{ok_resp}\n").as_bytes()).await?;

    // Handle commands from daemon
    let mut byte_buf = Vec::new();
    let max_frame = 65536 * 6 + 4096;
    loop {
        byte_buf.clear();
        let n = (&mut buf_reader)
            .take((max_frame + 1) as u64)
            .read_until(b'\n', &mut byte_buf)
            .await?;
        if n == 0 {
            break;
        }
        if byte_buf.len() > max_frame || (n >= max_frame && !byte_buf.ends_with(b"\n")) {
            let err = serde_json::json!({ "status": "error", "detail": "frame exceeds maximum allowed size" });
            let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
            break;
        }
        if !byte_buf.ends_with(b"\n") {
            break;
        }

        let line = match std::str::from_utf8(&byte_buf) {
            Ok(s) => s,
            Err(_) => {
                let err = serde_json::json!({ "status": "error", "detail": "invalid utf-8" });
                let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let cmd: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                let err = serde_json::json!({ "status": "error", "detail": "invalid json" });
                writer.write_all(format!("{err}\n").as_bytes()).await?;
                continue;
            }
        };

        let action = cmd.get("action").and_then(|a| a.as_str()).unwrap_or("");

        match action {
            "poll" => {
                let wait_secs = cmd
                    .get("waitSecs")
                    .and_then(|w| w.as_u64())
                    .unwrap_or(30)
                    .min(60);

                // Run TTL purge on queue
                {
                    if let Ok(conn) = db.lock() {
                        let _ = storage::purge_svc_messages(&conn, reply_ttl.as_secs());
                    }
                }

                // Subscribe before checking DB to prevent race condition
                let mut rx = svc_notify_tx.subscribe();

                let pending = {
                    let conn = db.lock().unwrap();
                    storage::get_next_pending_svc_message(&conn, &session_id)?
                };

                if let Some(msg) = pending {
                    let resp = serde_json::json!({
                        "action": "deliver",
                        "messageId": msg.id,
                        "fromName": msg.from_name,
                        "text": msg.text,
                        "envelope": msg.envelope,
                        "origin": msg.origin,
                    });
                    writer.write_all(format!("{resp}\n").as_bytes()).await?;
                } else if wait_secs == 0 {
                    let resp = serde_json::json!({ "action": "timeout" });
                    writer.write_all(format!("{resp}\n").as_bytes()).await?;
                } else {
                    let sess_clone = session_id.clone();
                    let wait_fut = async {
                        loop {
                            match rx.recv().await {
                                Ok(ref id) if id == &sess_clone => break,
                                Err(broadcast::error::RecvError::Lagged(_)) => break,
                                Err(_) => break,
                                _ => {}
                            }
                        }
                    };

                    let _ = tokio::time::timeout(Duration::from_secs(wait_secs), wait_fut).await;

                    let pending_after = {
                        let conn = db.lock().unwrap();
                        storage::get_next_pending_svc_message(&conn, &session_id)?
                    };

                    if let Some(msg) = pending_after {
                        let resp = serde_json::json!({
                            "action": "deliver",
                            "messageId": msg.id,
                            "fromName": msg.from_name,
                            "text": msg.text,
                            "envelope": msg.envelope,
                            "origin": msg.origin,
                        });
                        writer.write_all(format!("{resp}\n").as_bytes()).await?;
                    } else {
                        let resp = serde_json::json!({ "action": "timeout" });
                        writer.write_all(format!("{resp}\n").as_bytes()).await?;
                    }
                }
            }
            "ack" => {
                if let Some(msg_id) = cmd.get("messageId").and_then(|m| m.as_str()) {
                    let conn = db.lock().unwrap();
                    let _ = storage::ack_svc_message(&conn, &session_id, msg_id);
                }
                let resp = serde_json::json!({ "status": "ok" });
                writer.write_all(format!("{resp}\n").as_bytes()).await?;
            }
            "reply" => {
                let msg_id = match cmd.get("messageId").and_then(|m| m.as_str()) {
                    Some(id) => id,
                    None => {
                        let err =
                            serde_json::json!({ "status": "error", "detail": "missing messageId" });
                        writer.write_all(format!("{err}\n").as_bytes()).await?;
                        continue;
                    }
                };
                let text = match cmd.get("text").and_then(|t| t.as_str()) {
                    Some(t) => t,
                    None => {
                        let err =
                            serde_json::json!({ "status": "error", "detail": "missing text" });
                        writer.write_all(format!("{err}\n").as_bytes()).await?;
                        continue;
                    }
                };

                let orig_msg = {
                    let conn = db.lock().unwrap();
                    storage::get_message(&conn, msg_id)?
                };

                match orig_msg {
                    Some(orig) => {
                        let new_message_id = ulid::Ulid::new().to_string();
                        let push_res: Result<(), AppError> = if let Some(ret_host) =
                            orig.return_host.as_deref().filter(|h| !h.is_empty())
                        {
                            if let Some(ref fs) = fed_state {
                                let replier_name = if leaf_mode {
                                    leaf_principal
                                        .as_deref()
                                        .unwrap_or(&session_id)
                                        .strip_prefix("svc:")
                                        .unwrap_or(&session_id)
                                } else {
                                    &name
                                };
                                let replier = crate::fed::FedReplier {
                                    harness: "svc".to_string(),
                                    session_id: format!("svc:{replier_name}"),
                                    name: replier_name.to_string(),
                                };
                                let reply_envelope = crate::fed::FedReplyEnvelope {
                                    v: 1,
                                    id: new_message_id.clone(),
                                    in_reply_to: msg_id.to_string(),
                                    replier,
                                    text: text.to_string(),
                                    created_at: storage::now_epoch_secs(),
                                };
                                crate::fed::send_federated_reply(fs, ret_host, &reply_envelope)
                                    .await
                                    .map(|_| ())
                            } else {
                                Err(AppError::Internal("federation not configured".to_string()))
                            }
                        } else {
                            Ok(())
                        };

                        let outcome = match push_res {
                            Ok(()) => "pushed",
                            Err(e) => {
                                tracing::warn!("failed to send federated reply: {e}");
                                "push_failed"
                            }
                        };

                        {
                            let conn = db.lock().unwrap();
                            let _ = storage::insert_reply(
                                &conn,
                                msg_id,
                                &session_id,
                                text,
                                Some(outcome),
                                Some(&new_message_id),
                            );
                            let _ = storage::purge_replies(&conn, reply_ttl.as_secs());
                        }

                        let resp = serde_json::json!({
                            "status": "ok",
                            "messageId": new_message_id,
                        });
                        writer.write_all(format!("{resp}\n").as_bytes()).await?;
                    }
                    None => {
                        let err = serde_json::json!({ "status": "error", "detail": format!("message '{msg_id}' not found") });
                        writer.write_all(format!("{err}\n").as_bytes()).await?;
                    }
                }
            }
            _ => {
                let err = serde_json::json!({ "status": "error", "detail": format!("unknown action: {action}") });
                writer.write_all(format!("{err}\n").as_bytes()).await?;
            }
        }
    }

    {
        let mut store_lock = store.write().unwrap();
        if let Some(info) = store_lock.get(&session_id) {
            if info.pid == peer_pid && info.starttime == starttime {
                store_lock.remove(&session_id);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_leaf_register_server(
    sock_path: PathBuf,
    proc_root: PathBuf,
    store: SvcStore,
    my_uid: u32,
    db: Arc<Mutex<rusqlite::Connection>>,
    svc_notify_tx: broadcast::Sender<String>,
    reply_ttl: Duration,
    leaf_principal: String,
    fed_state: Option<Arc<crate::fed::FedState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = sock_path.parent() {
        crate::agent::ensure_secure_socket_dir(parent, my_uid)?;
    }
    if sock_path.exists() {
        let _ = std::fs::remove_file(&sock_path);
    }

    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));

    tracing::info!(path = %sock_path.display(), "bound leaf register socket (mode 0600)");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("leaf register accept error: {e}");
                continue;
            }
        };

        let ucred = match stream.peer_cred() {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("failed to get peer cred: {e}");
                continue;
            }
        };

        let peer_uid = ucred.uid();
        let peer_pid = ucred.pid().unwrap_or(0) as u32;

        let proc_root_clone = proc_root.clone();
        let store_clone = store.clone();
        let db_clone = db.clone();
        let svc_notify_tx_clone = svc_notify_tx.clone();
        let leaf_principal_clone = leaf_principal.clone();
        let fed_state_clone = fed_state.clone();

        tokio::spawn(async move {
            let (reader, writer) = stream.into_split();
            let mut buf_reader = tokio::io::BufReader::new(reader);
            let mut line = String::new();
            if let Err(e) = buf_reader.read_line(&mut line).await {
                tracing::warn!("failed to read registration frame: {e}");
                return;
            }

            let val: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let mut w = writer;
                    let err = serde_json::json!({ "status": "error", "detail": format!("invalid json: {e}") });
                    let _ = w.write_all(format!("{err}\n").as_bytes()).await;
                    return;
                }
            };

            let req: SvcRegisterRequest = match serde_json::from_value(val) {
                Ok(r) => r,
                Err(e) => {
                    let mut w = writer;
                    let err = serde_json::json!({ "status": "error", "detail": format!("invalid svc registration: {e}") });
                    let _ = w.write_all(format!("{err}\n").as_bytes()).await;
                    return;
                }
            };

            let empty_map = HashMap::new();
            if let Err(e) = handle_svc_connection(
                buf_reader,
                writer,
                proc_root_clone,
                store_clone,
                &empty_map,
                my_uid,
                peer_uid,
                peer_pid,
                req,
                db_clone,
                svc_notify_tx_clone,
                reply_ttl,
                true,
                Some(leaf_principal_clone),
                fed_state_clone,
            )
            .await
            {
                tracing::warn!("leaf svc connection ended: {e}");
            }
        });
    }
}

pub async fn run_leaf_inbox_task(
    fed_state: Arc<crate::fed::FedState>,
    peer_name: String,
    leaf_principal: String,
    db: Arc<Mutex<rusqlite::Connection>>,
    svc_notify_tx: broadcast::Sender<String>,
) {
    let mut backoff_millis = 100u64;
    let max_backoff_millis = 5000u64;
    let wait_secs = 30u64;

    loop {
        match crate::fed::get_federated_inbox(&fed_state, &peer_name, wait_secs).await {
            Ok(Some(msg)) => {
                backoff_millis = 100;

                let target_session_id = if let Some(ref to) = msg.to {
                    if to.starts_with("svc:") {
                        to.clone()
                    } else {
                        format!("svc:{to}")
                    }
                } else {
                    leaf_principal.clone()
                };

                let from_name = match &msg.origin {
                    storage::SvcOrigin::Fed { host, principal } => match principal {
                        Some(p) => format!("xmsg@{host} · {p}"),
                        None => format!("xmsg@{host}"),
                    },
                    _ => format!("xmsg@{peer_name}"),
                };

                let envelope = format!(
                    "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                    from_name, msg.id, msg.body
                );

                let ret_host = match &msg.origin {
                    storage::SvcOrigin::Fed { host, .. } => host.clone(),
                    _ => peer_name.clone(),
                };

                let msg_record = storage::MessageRecord {
                    id: msg.id.clone(),
                    created_at: storage::now_epoch_secs(),
                    session_id: target_session_id.clone(),
                    from_name: from_name.clone(),
                    bytes: msg.body.len(),
                    outcome: "delivered".to_string(),
                    recipient_harness: "svc".to_string(),
                    return_harness: None,
                    return_session_id: None,
                    push_replies: true,
                    thread_id: msg.id.clone(),
                    return_host: Some(ret_host),
                };

                let svc_msg = storage::SvcPendingMessage {
                    id: msg.id.clone(),
                    session_id: target_session_id.clone(),
                    created_at: storage::now_epoch_secs(),
                    from_name,
                    bytes: msg.body.len(),
                    text: msg.body.clone(),
                    envelope,
                    delivered_at: None,
                    origin: msg.origin.clone(),
                };

                let already_acked = {
                    if let Ok(conn) = db.lock() {
                        let _ = storage::insert_message(&conn, &msg_record);
                        let _ = storage::insert_svc_message(&conn, &svc_msg);
                        storage::is_svc_message_acked(&conn, &msg.id).unwrap_or(false)
                    } else {
                        false
                    }
                };

                let _ = svc_notify_tx.send(target_session_id.clone());

                if !already_acked {
                    loop {
                        let is_acked = {
                            if let Ok(conn) = db.lock() {
                                storage::is_svc_message_acked(&conn, &msg.id).unwrap_or(false)
                            } else {
                                false
                            }
                        };

                        if is_acked {
                            break;
                        }

                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }

                let mut ack_backoff = 100u64;
                loop {
                    match crate::fed::ack_federated_inbox(&fed_state, &peer_name, &msg.id).await {
                        Ok(()) => break,
                        Err(e) => {
                            tracing::warn!(
                                "Failed to ack message {} to hub {}: {e}, retrying",
                                msg.id,
                                peer_name
                            );
                            tokio::time::sleep(Duration::from_millis(ack_backoff)).await;
                            ack_backoff = (ack_backoff * 2).min(5000);
                        }
                    }
                }
            }
            Ok(None) => {
                backoff_millis = 100;
            }
            Err(e) => {
                tracing::warn!("Leaf inbox poll error for peer {}: {e}", peer_name);
                tokio::time::sleep(Duration::from_millis(backoff_millis)).await;
                backoff_millis = (backoff_millis * 2).min(max_backoff_millis);
            }
        }
    }
}
