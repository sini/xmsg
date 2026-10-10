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

    let starttime = match verify_svc_process(
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
