use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;

use crate::error::AppError;
use crate::registry::{Session, SessionsQuery};
use crate::storage::{self, now_epoch_secs};

/// A pi registration frame on `register.sock`. Unknown fields are refused (plan §6 D3);
/// `harness` is the multiplexer's tag.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PiRegisterRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(default, alias = "session_id")]
    pub session_id: Option<String>,
    #[serde(alias = "session_name")]
    pub session_name: Option<String>,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PiSessionInfo {
    pub session_id: String,
    pub name: Option<String>,
    pub pid: u32,
    pub starttime: String,
    pub cwd: String,
    pub registered_at: i64,
}

pub type PiStore = Arc<RwLock<HashMap<String, PiSessionInfo>>>;

pub fn new_pi_store() -> PiStore {
    Arc::new(RwLock::new(HashMap::new()))
}

pub fn get_proc_starttime(proc_root: &Path, pid: u32) -> io::Result<String> {
    crate::process::starttime(proc_root, pid)
}

pub fn verify_pi_process(
    proc_root: &Path,
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
) -> Result<String, AppError> {
    let peer = crate::process::PeerCred::unpinned(peer_uid, peer_pid);
    verify_pi_process_peer(proc_root, my_uid, &peer)
}

pub fn verify_pi_process_peer(
    proc_root: &Path,
    my_uid: u32,
    peer: &crate::process::PeerCred,
) -> Result<String, AppError> {
    let peer_uid = peer.uid;
    let peer_pid = peer.pid.unwrap_or(0);
    if peer_uid != my_uid {
        return Err(AppError::NotRecipient(format!(
            "peer UID {peer_uid} does not match server UID {my_uid}"
        )));
    }
    let starttime = peer.starttime(proc_root).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => AppError::NotFound(format!("process {peer_pid} not found: {e}")),
        _ => AppError::Internal(format!("failed to read starttime for PID {peer_pid}: {e}")),
    })?;
    Ok(starttime)
}

pub fn is_pi_session_alive(proc_root: &Path, info: &PiSessionInfo) -> bool {
    match get_proc_starttime(proc_root, info.pid) {
        Ok(st) => st == info.starttime,
        Err(_) => false,
    }
}

pub fn list_pi_sessions(proc_root: &Path, store: &PiStore, query: &SessionsQuery) -> Vec<Session> {
    let mut store_lock = store.write().unwrap();
    let mut dead = Vec::new();
    let mut sessions = Vec::new();

    for (id, info) in store_lock.iter() {
        if !is_pi_session_alive(proc_root, info) {
            dead.push(id.clone());
            continue;
        }
        let session = Session {
            session_id: info.session_id.clone(),
            name: info
                .name
                .as_deref()
                .and_then(crate::inbox::clean_label)
                .or_else(|| Some(info.session_id.clone())),
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

pub fn resolve_pi_session(
    proc_root: &Path,
    store: &PiStore,
    ref_str: &str,
) -> Result<Option<Session>, AppError> {
    let query = SessionsQuery::default();
    let all = list_pi_sessions(proc_root, store, &query);
    let ref_pid = ref_str.parse::<u32>().ok();

    let matched: Vec<Session> = all
        .into_iter()
        .filter(|s| {
            if s.session_id == ref_str {
                return true;
            }
            if let Some(pid) = ref_pid {
                if s.pid == pid {
                    return true;
                }
            }
            if let Some(ref name) = s.name {
                if name == ref_str {
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
pub async fn handle_pi_connection<
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    buf_reader: R,
    writer: W,
    proc_root: std::path::PathBuf,
    store: PiStore,
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
    req: PiRegisterRequest,
    db: Arc<Mutex<rusqlite::Connection>>,
    pi_notify_tx: broadcast::Sender<String>,
    reply_ttl: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer = crate::process::PeerCred::unpinned(peer_uid, peer_pid);
    handle_pi_connection_peer(
        buf_reader,
        writer,
        proc_root,
        store,
        my_uid,
        peer,
        req,
        db,
        pi_notify_tx,
        reply_ttl,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_pi_connection_peer<
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    mut buf_reader: R,
    mut writer: W,
    proc_root: std::path::PathBuf,
    store: PiStore,
    my_uid: u32,
    peer: crate::process::PeerCred,
    req: PiRegisterRequest,
    db: Arc<Mutex<rusqlite::Connection>>,
    pi_notify_tx: broadcast::Sender<String>,
    reply_ttl: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer_pid = peer.pid.unwrap_or(0);
    let starttime = match verify_pi_process_peer(&proc_root, my_uid, &peer) {
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

    let session_id = crate::claim::mint_uuid_v4();
    let conflict = {
        let store_lock = store.read().unwrap();
        if let Some(existing) = store_lock.get(&session_id) {
            existing.pid != peer_pid || existing.starttime != starttime
        } else {
            false
        }
    };
    if conflict {
        let err_resp = serde_json::json!({
            "status": "error",
            "detail": "session already registered under different process",
        });
        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
        return Err(AppError::BadRequest(
            "session already registered under different process".to_string(),
        )
        .into());
    }

    {
        let info = PiSessionInfo {
            session_id: session_id.clone(),
            name: req.session_name,
            pid: peer_pid,
            starttime: starttime.clone(),
            cwd: req.cwd.unwrap_or_else(|| "/".to_string()),
            registered_at: now_epoch_secs(),
        };
        store.write().unwrap().insert(session_id.clone(), info);
    }
    // The ever-observed record, so that once this process exits its ID answers `gone`
    // (AM-9, AM-10); stamped again when the connection ends, however it ends.
    struct MarkLive(Arc<Mutex<rusqlite::Connection>>, String);
    impl Drop for MarkLive {
        fn drop(&mut self) {
            if let Ok(conn) = self.0.lock() {
                let _ = storage::mark_live(&conn, &self.1, "pi", now_epoch_secs());
            }
        }
    }
    drop(MarkLive(db.clone(), session_id.clone()));
    let _mark_on_end = MarkLive(db.clone(), session_id.clone());

    // Write initial registration ok with server-derived sessionId
    let ok_resp = serde_json::json!({
        "status": "ok",
        "sessionId": session_id,
    });
    writer.write_all(format!("{ok_resp}\n").as_bytes()).await?;

    // Handle commands from extension
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
        // Every frame refuses a field it does not know (plan §6 D3).
        let known: &[&str] = match action {
            "poll" => &["action", "sessionId", "waitSecs"],
            "ack" => &["action", "messageId"],
            _ => &["action"],
        };
        if let Some(field) = cmd
            .as_object()
            .and_then(|o| o.keys().find(|k| !known.contains(&k.as_str())))
        {
            let err = AppError::BadRequest(format!("unknown field `{field}` in '{action}' frame"))
                .frame();
            writer.write_all(format!("{err}\n").as_bytes()).await?;
            continue;
        }

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
                        let _ = storage::purge_pi_messages(&conn, reply_ttl.as_secs());
                    }
                }

                // Subscribe before checking DB to prevent race condition
                let mut rx = pi_notify_tx.subscribe();

                let pending = {
                    let conn = db.lock().unwrap();
                    storage::get_next_pending_pi_message(&conn, &session_id)?
                };

                if let Some(msg) = pending {
                    let resp = serde_json::json!({
                        "action": "deliver",
                        "messageId": msg.id,
                        "fromName": msg.from_name,
                        "text": msg.text,
                        "envelope": msg.envelope,
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
                        storage::get_next_pending_pi_message(&conn, &session_id)?
                    };

                    if let Some(msg) = pending_after {
                        let resp = serde_json::json!({
                            "action": "deliver",
                            "messageId": msg.id,
                            "fromName": msg.from_name,
                            "text": msg.text,
                            "envelope": msg.envelope,
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
                    let _ = storage::ack_pi_message(&conn, &session_id, msg_id);
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
