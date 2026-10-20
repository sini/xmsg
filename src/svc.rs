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

/// A service's registration frame on `register.sock`. Unknown fields are refused (plan
/// §6 D3); `harness` is the multiplexer's tag.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SvcRegisterRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    pub name: String,
    #[serde(default)]
    pub cwd: Option<String>,
}

/// A registered service's frames on `register.sock`: `poll`, `ack` and `reply`. It runs
/// `list`, `send` and `replies` over `agent.sock` (AM-4; plan §6 D15).
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum SvcFrame {
    Poll {
        #[serde(default, rename = "waitSecs")]
        wait_secs: Option<u64>,
    },
    Ack {
        #[serde(rename = "messageId")]
        message_id: String,
    },
    Reply {
        #[serde(rename = "messageId")]
        message_id: String,
        text: String,
        #[serde(default, rename = "idempotencyKey")]
        idempotency_key: Option<String>,
    },
}

fn deliver_frame(msg: &storage::SvcPendingMessage) -> serde_json::Value {
    serde_json::json!({
        "action": "deliver",
        "messageId": msg.id,
        "fromName": msg.from_name,
        "text": msg.text,
        "envelope": msg.envelope,
        "origin": msg.origin,
        "inReplyTo": msg.in_reply_to,
    })
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
    let peer = crate::process::PeerCred::unpinned(peer_uid, peer_pid);
    verify_svc_process_peer(proc_root, trusted_exes, my_uid, &peer, name)
}

pub fn verify_svc_process_peer(
    proc_root: &Path,
    trusted_exes: &HashMap<String, PathBuf>,
    my_uid: u32,
    peer: &crate::process::PeerCred,
    name: &str,
) -> Result<String, AppError> {
    let peer_uid = peer.uid;
    let peer_pid = peer.pid.unwrap_or(0);
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

    let exe = peer
        .exe_path(proc_root)
        .map_err(|e| AppError::NotFound(format!("process {peer_pid} exe not found: {e}")))?;

    let exe_canon = std::fs::canonicalize(&exe).unwrap_or_else(|_| exe.clone());
    let trusted_canon =
        std::fs::canonicalize(trusted_path).unwrap_or_else(|_| trusted_path.clone());

    if exe_canon != trusted_canon {
        return Err(AppError::BadRequest(format!(
            "peer process {peer_pid} executable does not match trusted executable for service '{name}'"
        )));
    }

    let starttime = peer.starttime(proc_root).map_err(|e| {
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

/// The live service named exactly `name`. A name is unique per node (A2).
pub fn resolve_svc_session(
    proc_root: &Path,
    store: &SvcStore,
    name: &str,
) -> Result<Option<Session>, AppError> {
    Ok(
        list_svc_sessions(proc_root, store, &SessionsQuery::default())
            .into_iter()
            .find(|s| s.session_id == name),
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_svc_connection<
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    buf_reader: R,
    writer: W,
    state: Arc<crate::http::AppState>,
    trusted_svc_exes: &HashMap<String, PathBuf>,
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
    req: SvcRegisterRequest,
    leaf_mode: bool,
    leaf_principal: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer = crate::process::PeerCred::unpinned(peer_uid, peer_pid);
    handle_svc_connection_peer(
        buf_reader,
        writer,
        state,
        trusted_svc_exes,
        my_uid,
        peer,
        req,
        leaf_mode,
        leaf_principal,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_svc_connection_peer<
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    mut buf_reader: R,
    mut writer: W,
    state: Arc<crate::http::AppState>,
    trusted_svc_exes: &HashMap<String, PathBuf>,
    my_uid: u32,
    peer: crate::process::PeerCred,
    req: SvcRegisterRequest,
    leaf_mode: bool,
    leaf_principal: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer_uid = peer.uid;
    let peer_pid = peer.pid.unwrap_or(0);
    let proc_root = state.agy_config.proc_root.clone();
    let store = state.svc_store.clone();
    let db = state.db.clone();
    let svc_notify_tx = state.svc_notify_tx.clone();
    let reply_ttl = state.reply_ttl;
    let raw_name = req.name.trim();
    let name = raw_name.to_string();
    if name.is_empty() {
        let err_resp = serde_json::json!({
            "status": "error",
            "detail": "service name must not be empty",
        });
        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
        return Err(AppError::BadRequest("service name must not be empty".to_string()).into());
    }

    if let Err(e) = crate::claim::validate_service_name(&name) {
        let err_resp = serde_json::json!({
            "status": "error",
            "detail": e.to_string(),
        });
        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
        return Err(e.into());
    }

    let starttime = if leaf_mode {
        let expected_name =
            crate::surface::leaf_service_name(leaf_principal.as_deref().unwrap_or(""));
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

        if !peer.is_pin_alive() {
            let err_resp = serde_json::json!({
                "status": "error",
                "detail": format!("peer process {peer_pid} is no longer alive"),
            });
            let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
            return Err(
                AppError::NotFound(format!("peer process {peer_pid} is no longer alive")).into(),
            );
        }

        peer.starttime(&proc_root)
            .unwrap_or_else(|_| "0".to_string())
    } else {
        match verify_svc_process_peer(&proc_root, trusted_svc_exes, my_uid, &peer, &name) {
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

    let session_id = name.clone();

    // Single live registration check (Gate r2 G5 / Oracle 5)
    let conflict = {
        let store_lock = store.read().unwrap();
        let existing = store_lock.get(&session_id);
        if let Some(existing) = existing {
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

    // The registration's address and this node's name (AM-4); MA's origin check reads
    // the node.
    let ok_resp = serde_json::json!({
        "status": "ok",
        "address": format!("{session_id}@{}", state.node_name),
        "node": state.node_name,
    });
    writer.write_all(format!("{ok_resp}\n").as_bytes()).await?;

    // Handle commands from daemon
    let mut byte_buf = Vec::new();
    let max_frame = 65536 * 6 + 4096;
    let mut in_flight: std::collections::HashSet<String> = std::collections::HashSet::new();
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

        let cmd: SvcFrame = match crate::surface::parse_frame(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = e.frame();
                writer.write_all(format!("{err}\n").as_bytes()).await?;
                continue;
            }
        };

        match cmd {
            SvcFrame::Poll { wait_secs } => {
                let wait_secs = wait_secs.unwrap_or(30).min(60);

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
                    storage::get_next_pending_svc_message_excluding(&conn, &session_id, &in_flight)?
                };

                if let Some(msg) = pending {
                    let resp = deliver_frame(&msg);
                    writer.write_all(format!("{resp}\n").as_bytes()).await?;
                    in_flight.insert(msg.id);
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
                        storage::get_next_pending_svc_message_excluding(
                            &conn,
                            &session_id,
                            &in_flight,
                        )?
                    };

                    if let Some(msg) = pending_after {
                        let resp = deliver_frame(&msg);
                        writer.write_all(format!("{resp}\n").as_bytes()).await?;
                        in_flight.insert(msg.id);
                    } else {
                        let resp = serde_json::json!({ "action": "timeout" });
                        writer.write_all(format!("{resp}\n").as_bytes()).await?;
                    }
                }
            }
            SvcFrame::Ack { message_id } => {
                {
                    let conn = db.lock().unwrap();
                    let _ = storage::ack_svc_message(&conn, &session_id, &message_id);
                }
                in_flight.remove(&message_id);
                let resp = serde_json::json!({ "status": "ok" });
                writer.write_all(format!("{resp}\n").as_bytes()).await?;
            }
            SvcFrame::Reply {
                message_id,
                text,
                idempotency_key,
            } => {
                let caller = crate::surface::service_session(&name);
                let resp = match crate::surface::reply(
                    &state,
                    &caller,
                    &message_id,
                    &text,
                    idempotency_key.as_deref(),
                )
                .await
                {
                    Ok(reply) => serde_json::json!({
                        "status": "ok",
                        "messageId": reply.pushed_message_id,
                    }),
                    Err(e) => e.frame(),
                };
                writer.write_all(format!("{resp}\n").as_bytes()).await?;
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
    state: Arc<crate::http::AppState>,
    my_uid: u32,
    leaf_principal: String,
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

        let peer = match crate::process::peer_cred(&stream) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("failed to get peer cred: {e}");
                continue;
            }
        };

        let state_clone = state.clone();
        let leaf_principal_clone = leaf_principal.clone();

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
            if let Err(e) = handle_svc_connection_peer(
                buf_reader,
                writer,
                state_clone,
                &empty_map,
                my_uid,
                peer,
                req,
                true,
                Some(leaf_principal_clone),
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
            Ok(Some(crate::fed::FedInboxItem::List { query, v })) => {
                backoff_millis = 100;
                crate::fed::answer_list_query(&fed_state, &peer_name, &query, v.unwrap_or(1) >= 2)
                    .await;
            }
            Ok(Some(crate::fed::FedInboxItem::Message(msg))) => {
                backoff_millis = 100;

                let leaf_name = crate::surface::leaf_service_name(&leaf_principal);
                let target_session_id = msg.to.clone().unwrap_or_else(|| leaf_name.to_string());
                // Replies go back to the hub this message came from (A-2).
                let ret_host = peer_name.clone();

                // F1 (liveness): If target is not the leaf principal, do not enqueue it locally.
                // Ack at the hub and reply not_found to the sender.
                if target_session_id != leaf_name {
                    tracing::warn!(
                        "message {} target '{target_session_id}' does not match leaf principal '{leaf_principal}'; rejecting and acking at hub",
                        msg.id
                    );

                    let replier = storage::Origin::service(leaf_name, &fed_state.node_name);

                    let reply_text = serde_json::json!({
                        "error": "not_found",
                        "detail": format!("{target_session_id} is not served by this leaf"),
                    })
                    .to_string();

                    let reply_envelope = crate::fed::FedReplyEnvelope {
                        v: crate::fed::WIRE_VERSION,
                        id: ulid::Ulid::new().to_string(),
                        in_reply_to: msg.id.clone(),
                        replier,
                        text: reply_text,
                        created_at: storage::now_epoch_secs(),
                    };

                    let _ =
                        crate::fed::send_federated_reply(&fed_state, &ret_host, &reply_envelope)
                            .await;

                    let mut ack_backoff = 100u64;
                    loop {
                        match crate::fed::ack_federated_inbox(&fed_state, &peer_name, &msg.id).await
                        {
                            Ok(()) => break,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to ack rejected message {} to hub {}: {e}, retrying",
                                    msg.id,
                                    peer_name
                                );
                                tokio::time::sleep(Duration::from_millis(ack_backoff)).await;
                                ack_backoff = (ack_backoff * 2).min(5000);
                            }
                        }
                    }
                    continue;
                }

                // A12: one render, from the origin the hub attests.
                let from_name = msg
                    .origin
                    .render(fed_state.peers.display_name(&msg.origin.node));
                // A sender with an inbox gets its reply pushed back through the hub.
                let (return_harness, return_session_id) = match msg.origin.key() {
                    Some(key) => (Some("fed".to_string()), Some(key.to_string())),
                    None => (None, None),
                };

                let ref_part = match msg.origin.machine_ref() {
                    Some(r) => format!(" ref={r}"),
                    None => String::new(),
                };
                let envelope = format!(
                    "[xmsg] from={}{ref_part} message_id={} — reply with the xmsg reply tool (tools: send, reply, list, replies)\n\n{}",
                    from_name, msg.id, msg.body
                );

                let msg_record = storage::MessageRecord {
                    id: msg.id.clone(),
                    created_at: storage::now_epoch_secs(),
                    session_id: target_session_id.clone(),
                    from_name: from_name.clone(),
                    bytes: msg.body.len(),
                    // `delivered` once the service acks it: `storage::ack_svc_message`.
                    outcome: "queued".to_string(),
                    recipient_harness: "svc".to_string(),
                    return_harness,
                    return_session_id,
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
                    in_reply_to: None,
                };

                // F2 (no silent loss or spin): propagate storage errors, do not ack hub, back off and repoll
                let store_res = (|| -> Result<bool, AppError> {
                    let mut conn = db.lock().map_err(|e| AppError::Internal(e.to_string()))?;
                    let tx = conn
                        .transaction()
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    storage::insert_message(&tx, &msg_record)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    let queued = storage::insert_svc_message(&tx, &svc_msg)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    if !queued {
                        return Err(AppError::ServiceUnavailable(
                            "svc message queue is full".to_string(),
                        ));
                    }
                    let is_acked = storage::is_svc_message_acked(&tx, &msg.id)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    tx.commit().map_err(|e| AppError::Internal(e.to_string()))?;
                    Ok(is_acked)
                })();

                let already_acked = match store_res {
                    Ok(acked) => acked,
                    Err(e) => {
                        tracing::error!(
                            "Failed to store message {} locally: {e}; backing off without acking hub",
                            msg.id
                        );
                        tokio::time::sleep(Duration::from_millis(backoff_millis)).await;
                        backoff_millis = (backoff_millis * 2).min(max_backoff_millis);
                        continue;
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
