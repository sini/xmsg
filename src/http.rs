use axum::{
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::info;

use crate::error::AppError;
use crate::inbox::{self, DeliveryResponse, SendMessageRequest};
use crate::registry::{self, SessionsQuery};
use crate::storage::{self, MessageRecord, ReplyRecord};

pub struct AppState {
    pub sessions_dirs: Vec<PathBuf>,
    pub agy_config: crate::agy::AgyConfig,
    pub agy_store: crate::agy::AgyStore,
    pub pi_store: crate::pi::PiStore,
    pub pi_notify_tx: broadcast::Sender<String>,
    pub svc_store: crate::svc::SvcStore,
    pub svc_notify_tx: broadcast::Sender<String>,
    pub host_label: String,
    pub max_body: usize,
    pub request_counter: AtomicU64,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub notify_tx: broadcast::Sender<String>,
    pub reply_ttl: Duration,
    pub idempotency_ttl: Duration,
    pub long_poll_semaphore: Arc<tokio::sync::Semaphore>,
    pub fed_state: Option<Arc<crate::fed::FedState>>,
}

impl AppState {
    pub fn is_leaf(&self) -> bool {
        self.fed_state.as_ref().map(|f| f.is_leaf).unwrap_or(false)
    }

    pub fn leaf_principal(&self) -> Option<&str> {
        self.fed_state
            .as_ref()
            .and_then(|f| f.leaf_principal.as_deref())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessageDetailResponse {
    pub id: String,
    pub created_at: i64,
    pub session_id: String,
    pub from_name: String,
    pub bytes: usize,
    pub outcome: String,
    #[serde(default = "default_recipient_harness")]
    pub recipient_harness: String,
    #[serde(default)]
    pub return_harness: Option<String>,
    #[serde(default)]
    pub return_session_id: Option<String>,
    #[serde(default = "default_true")]
    pub push_replies: bool,
    #[serde(default)]
    pub thread_id: String,
    pub replies: Vec<ReplyRecord>,
}

fn default_recipient_harness() -> String {
    "claude".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct LongPollQuery {
    pub after: Option<i64>,
    pub wait: Option<u64>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/v1/sessions", get(list_sessions_handler))
        .route("/v1/sessions/{ref}", get(get_session_handler))
        .route("/v1/sessions/{ref}/messages", post(send_message_handler))
        .route("/v1/messages/{id}", get(get_message_handler))
        .route("/v1/messages/{id}/replies", get(get_replies_handler))
        .with_state(state)
}

async fn healthz_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dir_ok = !state.sessions_dirs.is_empty()
        && state.sessions_dirs.iter().any(|d| d.exists() && d.is_dir());
    let status_str = if dir_ok { "ok" } else { "sessions_dir_missing" };
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "sessions_dir": status_str,
        })),
    )
}

pub(crate) enum ResolvedTarget {
    Claude(registry::Session, PathBuf),
    Agy(registry::Session),
    Pi(registry::Session),
    Svc(registry::Session),
}

pub(crate) fn resolve_target_session(
    state: &AppState,
    ref_str: &str,
) -> Result<ResolvedTarget, AppError> {
    match registry::resolve_session(&state.sessions_dirs, ref_str) {
        Ok((session, socket_path)) => Ok(ResolvedTarget::Claude(session, socket_path)),
        Err(AppError::Gone { session_id, pid }) => {
            if crate::process::starttime(&state.agy_config.proc_root, pid).is_ok() {
                if let Some(session) =
                    crate::agy::resolve_agy_session(&state.agy_config, &state.agy_store, ref_str)?
                {
                    return Ok(ResolvedTarget::Agy(session));
                }
                if let Some(session) = crate::pi::resolve_pi_session(
                    &state.agy_config.proc_root,
                    &state.pi_store,
                    ref_str,
                )? {
                    return Ok(ResolvedTarget::Pi(session));
                }
                if let Some(session) = crate::svc::resolve_svc_session(
                    &state.agy_config.proc_root,
                    &state.svc_store,
                    ref_str,
                )? {
                    return Ok(ResolvedTarget::Svc(session));
                }
                return Err(AppError::Unregistered(pid));
            }
            Err(AppError::Gone { session_id, pid })
        }
        Err(AppError::Ambiguous(ids)) => Err(AppError::Ambiguous(ids)),
        Err(AppError::NotFound(_)) => {
            match crate::agy::resolve_agy_session(&state.agy_config, &state.agy_store, ref_str)? {
                Some(session) => Ok(ResolvedTarget::Agy(session)),
                None => {
                    match crate::pi::resolve_pi_session(
                        &state.agy_config.proc_root,
                        &state.pi_store,
                        ref_str,
                    )? {
                        Some(session) => Ok(ResolvedTarget::Pi(session)),
                        None => {
                            match crate::svc::resolve_svc_session(
                                &state.agy_config.proc_root,
                                &state.svc_store,
                                ref_str,
                            )? {
                                Some(session) => Ok(ResolvedTarget::Svc(session)),
                                None => {
                                    if let Ok(pid) = ref_str.parse::<u32>() {
                                        if crate::process::starttime(
                                            &state.agy_config.proc_root,
                                            pid,
                                        )
                                        .is_ok()
                                        {
                                            return Err(AppError::Unregistered(pid));
                                        }
                                    }
                                    Err(AppError::NotFound(ref_str.to_string()))
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(err) => Err(err),
    }
}

async fn list_sessions_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionsQuery>,
) -> impl IntoResponse {
    let mut sessions = registry::list_sessions(&state.sessions_dirs, &query);
    let mut agy_sessions =
        crate::agy::list_agy_sessions(&state.agy_config, &state.agy_store, &query);
    sessions.append(&mut agy_sessions);
    let mut pi_sessions =
        crate::pi::list_pi_sessions(&state.agy_config.proc_root, &state.pi_store, &query);
    sessions.append(&mut pi_sessions);
    let mut svc_sessions =
        crate::svc::list_svc_sessions(&state.agy_config.proc_root, &state.svc_store, &query);
    sessions.append(&mut svc_sessions);
    (StatusCode::OK, Json(sessions))
}

async fn get_session_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(ref_str): AxumPath<String>,
) -> Result<Response, AppError> {
    let target = resolve_target_session(&state, &ref_str)?;
    let session = match target {
        ResolvedTarget::Claude(s, _) => s,
        ResolvedTarget::Agy(s) => s,
        ResolvedTarget::Pi(s) => s,
        ResolvedTarget::Svc(s) => s,
    };
    Ok((StatusCode::OK, Json(session)).into_response())
}

async fn send_message_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(ref_str): AxumPath<String>,
    body_bytes: Bytes,
) -> Result<Response, AppError> {
    let req_id = state.request_counter.fetch_add(1, Ordering::Relaxed);
    let body_len = body_bytes.len();

    // Check payload size limit
    if body_len > state.max_body {
        eprintln!(
            "req_id={} ref={} bytes={} outcome=payload_too_large",
            req_id, ref_str, body_len
        );
        return Err(AppError::PayloadTooLarge {
            size: body_len,
            limit: state.max_body,
        });
    }

    // Parse JSON request
    let req: SendMessageRequest = serde_json::from_slice(&body_bytes).map_err(|e| {
        eprintln!(
            "req_id={} ref={} bytes={} outcome=bad_request detail=\"{}\"",
            req_id, ref_str, body_len, e
        );
        AppError::BadRequest(e.to_string())
    })?;

    if req.text.is_empty() {
        eprintln!(
            "req_id={} ref={} bytes={} outcome=bad_request detail=\"empty text\"",
            req_id, ref_str, body_len
        );
        return Err(AppError::BadRequest("text must not be empty".to_string()));
    }

    // In leaf mode: ignore req.from, attribute strictly to leaf_principal
    let (from_name, fed_principal, idempotency_principal) = if state.is_leaf() {
        let p_str = state.leaf_principal().expect("leaf_principal in leaf mode");
        let p = crate::fed::parse_fed_principal(p_str)?;
        let name = format!("xmsg@{} · {}", state.host_label, p_str);
        (name, p, p_str.to_string())
    } else {
        // Sanitize sender name (enforces printable ASCII and rejects ':' and '/')
        let name = match inbox::sanitize_from(&state.host_label, &req.from) {
            Ok(name) => name,
            Err(err) => {
                eprintln!(
                    "req_id={} ref={} bytes={} outcome=bad_sender detail=\"{}\"",
                    req_id, ref_str, body_len, err
                );
                return Err(err);
            }
        };
        let p = crate::fed::FedPrincipal::Anonymous {
            from: req.from.clone(),
        };
        let idemp = format!("http:{name}");
        (name, p, idemp)
    };

    // Check idempotency key if supplied
    if let Some(ref key) = req.idempotency_key {
        if key.is_empty() || key.len() > 128 || key.chars().any(|c| c.is_control()) {
            eprintln!(
                "req_id={} ref={} bytes={} outcome=bad_request detail=\"invalid idempotency_key\"",
                req_id, ref_str, body_len
            );
            return Err(AppError::BadRequest(
                "invalid idempotency_key: must be 1..128 non-control chars".to_string(),
            ));
        }

        let existing = {
            let db = state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            storage::get_idempotency_record(
                &db,
                &idempotency_principal,
                key,
                state.idempotency_ttl.as_secs(),
            )
            .map_err(|e| AppError::Internal(e.to_string()))?
        };

        if let Some(record) = existing {
            if record.body != req.text {
                eprintln!(
                    "req_id={} ref={} bytes={} outcome=conflict detail=\"idempotency body mismatch\"",
                    req_id, ref_str, body_len
                );
                return Err(AppError::Conflict(format!(
                    "idempotency key '{key}' was already used with a different message body"
                )));
            }

            eprintln!(
                "req_id={} message_id={} session_id={} from=\"{}\" bytes={} outcome=idempotent_replay",
                req_id, record.message_id, record.session_id, record.from_name, record.bytes
            );
            return Ok((
                StatusCode::ACCEPTED,
                Json(DeliveryResponse {
                    session_id: record.session_id,
                    from_name: record.from_name,
                    bytes: record.bytes,
                    message_id: record.message_id,
                    outcome: Some(record.outcome),
                }),
            )
                .into_response());
        }
    }

    // Check if target is cross-host
    let (ref_str, remote_host) = match crate::fed::split_peer_ref(&ref_str) {
        Some((r, h)) if h != state.host_label => (r.to_string(), Some(h)),
        Some((r, _)) => (r.to_string(), None),
        None => (ref_str, None),
    };

    if let Some(target_host) = remote_host {
        let fed_state = match &state.fed_state {
            Some(fs) if fs.peers.contains_name(target_host) => fs.clone(),
            _ => {
                return Err(AppError::UnknownPeer(format!(
                    "Unknown peer host: {target_host}"
                )))
            }
        };

        let message_id = ulid::Ulid::new().to_string();
        let envelope = crate::fed::FedEnvelope {
            v: 1,
            id: message_id.clone(),
            principal: fed_principal.clone(),
            to: crate::fed::FedTarget {
                r#ref: ref_str.clone(),
            },
            body: req.text.clone(),
            push_replies: true,
            thread_id: message_id.clone(),
            created_at: storage::now_epoch_secs(),
        };

        let delivery_resp =
            crate::fed::send_federated_message(&fed_state, target_host, &envelope).await?;

        let outcome = delivery_resp.outcome.as_deref().unwrap_or("delivered");
        {
            let db = state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let _ = storage::insert_outbound(
                &db,
                &message_id,
                target_host,
                &ref_str,
                outcome,
                storage::now_epoch_secs(),
            );
            let msg_record = MessageRecord {
                id: message_id.clone(),
                created_at: envelope.created_at,
                session_id: ref_str.clone(),
                from_name: from_name.clone(),
                bytes: body_len,
                outcome: outcome.to_string(),
                recipient_harness: "fed".to_string(),
                return_harness: Some("svc".to_string()),
                return_session_id: state.leaf_principal().map(|s| s.to_string()),
                return_host: Some(state.host_label.clone()),
                push_replies: true,
                thread_id: message_id.clone(),
            };
            let _ = storage::insert_message(&db, &msg_record);

            if let Some(ref key) = req.idempotency_key {
                let record = storage::IdempotencyRecord {
                    principal: idempotency_principal.clone(),
                    key: key.clone(),
                    body: req.text.clone(),
                    message_id: message_id.clone(),
                    session_id: delivery_resp.session_id.clone(),
                    from_name: from_name.clone(),
                    bytes: body_len,
                    outcome: outcome.to_string(),
                    created_at: storage::now_epoch_secs(),
                };
                let _ = storage::insert_idempotency_record(&db, &record);
                let _ = storage::purge_idempotency_keys(&db, state.idempotency_ttl.as_secs());
            }
        }

        return Ok((
            StatusCode::ACCEPTED,
            Json(DeliveryResponse {
                session_id: delivery_resp.session_id,
                from_name,
                bytes: body_len,
                message_id,
                outcome: delivery_resp.outcome,
            }),
        )
            .into_response());
    }

    // Resolve target session
    let target = resolve_target_session(&state, &ref_str).map_err(|err| {
        eprintln!(
            "req_id={} ref={} from=\"{}\" bytes={} outcome=resolve_error detail=\"{}\"",
            req_id, ref_str, from_name, body_len, err
        );
        err
    })?;

    // Generate ULID message ID
    let message_id = ulid::Ulid::new().to_string();

    let (session_id, recipient_harness, outcome_str) = match target {
        ResolvedTarget::Claude(session, socket_path) => {
            let body_with_footer = format!(
                "{}\n\n[xmsg] message_id={} — reply with the xmsg reply tool",
                req.text, message_id
            );
            let line = inbox::encode_transport_line(&from_name, &body_with_footer)?;
            if let Err(err) = inbox::deliver_to_socket(&socket_path, &line).await {
                eprintln!(
                    "req_id={} session_id={} from=\"{}\" bytes={} outcome=delivery_failed detail=\"{}\"",
                    req_id, session.session_id, from_name, body_len, err
                );
                return Err(err);
            }
            (session.session_id, "claude".to_string(), "delivered")
        }
        ResolvedTarget::Agy(session) => {
            let has_creds = {
                let store_lock = state.agy_store.read().unwrap();
                store_lock
                    .get(&session.session_id)
                    .or_else(|| {
                        store_lock.values().find(|info| {
                            info.conversation_id == session.session_id
                                || session.name.as_deref() == Some(&info.conversation_id)
                        })
                    })
                    .map(|info| info.has_credentials())
                    .unwrap_or(false)
            };

            if has_creds {
                crate::agy::deliver_agy(
                    &state.agy_config,
                    &state.agy_store,
                    &session,
                    &from_name,
                    &message_id,
                    &req.text,
                )
                .await?;
                (session.session_id, "agy".to_string(), "delivered")
            } else {
                let envelope = format!(
                    "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                    from_name, message_id, req.text
                );
                let agy_msg = storage::AgyPendingMessage {
                    id: message_id.clone(),
                    session_id: session.session_id.clone(),
                    created_at: storage::now_epoch_secs(),
                    from_name: from_name.clone(),
                    bytes: body_len,
                    text: req.text.clone(),
                    envelope,
                    delivered_at: None,
                };
                {
                    let db = state
                        .db
                        .lock()
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    storage::insert_agy_message(&db, &agy_msg)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                }
                (session.session_id, "agy".to_string(), "queued")
            }
        }
        ResolvedTarget::Pi(session) => {
            let envelope = format!(
                "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                from_name, message_id, req.text
            );
            let pi_msg = storage::PiPendingMessage {
                id: message_id.clone(),
                session_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                from_name: from_name.clone(),
                bytes: body_len,
                text: req.text.clone(),
                envelope,
                delivered_at: None,
            };
            {
                let db = state
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
            }
            let _ = state.pi_notify_tx.send(session.session_id.clone());
            (session.session_id, "pi".to_string(), "delivered")
        }
        ResolvedTarget::Svc(session) => {
            let envelope = format!(
                "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                from_name, message_id, req.text
            );
            let svc_msg = storage::SvcPendingMessage {
                id: message_id.clone(),
                session_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                from_name: from_name.clone(),
                bytes: body_len,
                text: req.text.clone(),
                envelope,
                delivered_at: None,
            };
            {
                let db = state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                let inserted = storage::insert_svc_message(&db, &svc_msg)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                if !inserted {
                    return Err(AppError::ServiceUnavailable(
                        "svc session message queue is full".to_string(),
                    ));
                }
            }
            let _ = state.svc_notify_tx.send(session.session_id.clone());
            (session.session_id, "svc".to_string(), "delivered")
        }
    };

    // Record message in SQLite
    let msg_record = MessageRecord {
        id: message_id.clone(),
        created_at: storage::now_epoch_secs(),
        session_id: session_id.clone(),
        from_name: from_name.clone(),
        bytes: body_len,
        outcome: outcome_str.to_string(),
        recipient_harness,
        return_harness: None,
        return_session_id: None,
        push_replies: false,
        thread_id: message_id.clone(),
        return_host: None,
    };

    {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::insert_message(&db, &msg_record).map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(ref key) = req.idempotency_key {
            let record = storage::IdempotencyRecord {
                principal: format!("http:{from_name}"),
                key: key.clone(),
                body: req.text.clone(),
                message_id: message_id.clone(),
                session_id: session_id.clone(),
                from_name: from_name.clone(),
                bytes: body_len,
                outcome: outcome_str.to_string(),
                created_at: storage::now_epoch_secs(),
            };
            let _ = storage::insert_idempotency_record(&db, &record);
            let _ = storage::purge_idempotency_keys(&db, state.idempotency_ttl.as_secs());
        }
        let _ = storage::purge_messages(&db, state.reply_ttl.as_secs());
        let _ = storage::purge_replies(&db, state.reply_ttl.as_secs());
        let _ = storage::purge_pi_messages(&db, state.reply_ttl.as_secs());
        let _ = storage::purge_agy_messages(&db, state.reply_ttl.as_secs());
        let _ = storage::purge_svc_messages(&db, state.reply_ttl.as_secs());
    }

    // Invariant: Message bodies are NEVER logged under any circumstances
    eprintln!(
        "req_id={} message_id={} session_id={} from=\"{}\" bytes={} outcome={}",
        req_id, message_id, session_id, from_name, body_len, outcome_str
    );
    info!(
        target: "xmsg",
        req_id = req_id,
        message_id = %message_id,
        session_id = %session_id,
        from = %from_name,
        bytes = body_len,
        outcome = outcome_str
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(DeliveryResponse {
            session_id,
            from_name,
            bytes: body_len,
            message_id,
            outcome: Some(outcome_str.to_string()),
        }),
    )
        .into_response())
}

async fn get_message_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, AppError> {
    let (msg, replies) = {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let msg = storage::get_message(&db, &id)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("message '{id}'")))?;
        let replies =
            storage::get_all_replies(&db, &id).map_err(|e| AppError::Internal(e.to_string()))?;
        (msg, replies)
    };

    Ok((
        StatusCode::OK,
        Json(MessageDetailResponse {
            id: msg.id,
            created_at: msg.created_at,
            session_id: msg.session_id,
            from_name: msg.from_name,
            bytes: msg.bytes,
            outcome: msg.outcome,
            recipient_harness: msg.recipient_harness,
            return_harness: msg.return_harness,
            return_session_id: msg.return_session_id,
            push_replies: msg.push_replies,
            thread_id: msg.thread_id,
            replies,
        }),
    )
        .into_response())
}

async fn get_replies_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<LongPollQuery>,
) -> Result<Response, AppError> {
    // 1. Verify message exists (check both messages and outbound tables)
    let outbound = {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let msg = storage::get_message(&db, &id).map_err(|e| AppError::Internal(e.to_string()))?;
        let out = storage::get_outbound(&db, &id).map_err(|e| AppError::Internal(e.to_string()))?;
        if msg.is_none() && out.is_none() {
            return Err(AppError::NotFound(format!("message '{id}'")));
        }
        out
    };

    let after_seq = query.after.unwrap_or(0);
    let wait_secs = query.wait.unwrap_or(0).min(60);

    let _permit = if wait_secs > 0 {
        match state.long_poll_semaphore.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                return Err(AppError::ServiceUnavailable(
                    "too many concurrent long-poll requests".to_string(),
                ));
            }
            Err(e) => {
                return Err(AppError::Internal(e.to_string()));
            }
        }
    } else {
        None
    };

    // 2. If outbound federated message, poll remote peer
    if let Some(outbound) = outbound {
        if let Some(ref fed_state) = state.fed_state {
            let local_existing = {
                let db = state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                storage::get_replies_after(&db, &id, after_seq)
                    .map_err(|e| AppError::Internal(e.to_string()))?
            };
            if !local_existing.is_empty() {
                return Ok((StatusCode::OK, Json(local_existing)).into_response());
            }

            let remote_replies = crate::fed::poll_federated_replies(
                fed_state,
                &outbound.peer,
                &id,
                after_seq,
                wait_secs,
            )
            .await?;

            {
                let db = state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                for r in &remote_replies {
                    let existing_all = storage::get_replies_after(&db, &id, 0)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    if !existing_all.iter().any(|ex| {
                        ex.text == r.text && ex.replier_session_id == r.replier_session_id
                    }) {
                        let _ = storage::insert_reply(
                            &db,
                            &id,
                            &r.replier_session_id,
                            &r.text,
                            r.push_outcome.as_deref(),
                            r.pushed_message_id.as_deref(),
                        );
                    }
                }
            }

            return Ok((StatusCode::OK, Json(remote_replies)).into_response());
        }
    }

    // 3. Fall back to standard local long-poll for inbound/local messages
    let rx = if wait_secs > 0 {
        Some(state.notify_tx.subscribe())
    } else {
        None
    };

    let existing = {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_replies_after(&db, &id, after_seq)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    if !existing.is_empty() || wait_secs == 0 {
        return Ok((StatusCode::OK, Json(existing)).into_response());
    }

    // Wait for notification or timeout
    let mut receiver = rx.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(wait_secs), async {
        loop {
            match receiver.recv().await {
                Ok(msg_id) if msg_id == id => break,
                Err(broadcast::error::RecvError::Lagged(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    })
    .await;

    let replies = {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_replies_after(&db, &id, after_seq)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    Ok((StatusCode::OK, Json(replies)).into_response())
}

pub fn default_http_sock_path() -> Result<PathBuf, AppError> {
    crate::agent::default_socket_dir().map(|d| d.join("http.sock"))
}

pub type PeerUidChecker = Arc<dyn Fn(&tokio::net::UnixStream) -> io::Result<u32> + Send + Sync>;

pub struct UcredUnixListener {
    pub listener: tokio::net::UnixListener,
    pub expected_uid: u32,
    pub peer_uid_checker: Option<PeerUidChecker>,
}

impl axum::serve::Listener for UcredUnixListener {
    type Io = tokio::net::UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    tracing::warn!("http unix socket accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            let peer_uid = if let Some(ref checker) = self.peer_uid_checker {
                match checker(&stream) {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::warn!("http.sock peer cred check failed (seam): {e}");
                        continue;
                    }
                }
            } else {
                match stream.peer_cred() {
                    Ok(c) => c.uid(),
                    Err(e) => {
                        tracing::warn!("failed to get peer creds on http.sock: {e}");
                        continue;
                    }
                }
            };

            if peer_uid != self.expected_uid {
                tracing::warn!(
                    "http.sock rejected connection: UID mismatch {peer_uid} != {}",
                    self.expected_uid
                );
                continue;
            }

            return (stream, addr);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

pub fn bind_ucred_unix_listener(
    sock_path: &Path,
    expected_uid: u32,
    peer_uid_checker: Option<PeerUidChecker>,
) -> io::Result<UcredUnixListener> {
    if let Some(parent) = sock_path.parent() {
        if let Err(e) = crate::agent::ensure_secure_socket_dir(parent, expected_uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                e.to_string(),
            ));
        }
    }
    if sock_path.exists() {
        if std::os::unix::net::UnixStream::connect(sock_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "another server instance is actively listening on {}",
                    sock_path.display()
                ),
            ));
        }
        let _ = fs::remove_file(sock_path);
    }

    let listener = tokio::net::UnixListener::bind(sock_path)?;
    fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("failed to set permissions on {}: {e}", sock_path.display()),
        )
    })?;

    Ok(UcredUnixListener {
        listener,
        expected_uid,
        peer_uid_checker,
    })
}

pub fn http_request_unix(
    sock_path: &Path,
    method: &str,
    path_and_query: &str,
    body: Option<&str>,
) -> io::Result<(StatusCode, String)> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let req = if let Some(b) = body {
        format!(
            "{method} {path_and_query} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        )
    } else {
        format!(
            "{method} {path_and_query} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
    };
    stream.write_all(req.as_bytes())?;

    let mut resp_bytes = Vec::new();
    let mut buf = [0u8; 4096];
    let mut expected_len: Option<usize> = None;
    let mut header_len = 0;

    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        resp_bytes.extend_from_slice(&buf[..n]);

        if expected_len.is_none() {
            if let Some(idx) = resp_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                header_len = idx + 4;
                let header_str = String::from_utf8_lossy(&resp_bytes[..header_len]);
                for line in header_str.lines() {
                    let lower = line.to_ascii_lowercase();
                    if lower.starts_with("content-length:") {
                        if let Some(val_str) = line.split(':').nth(1) {
                            if let Ok(cl) = val_str.trim().parse::<usize>() {
                                expected_len = Some(cl);
                            }
                        }
                    }
                }
            }
        }

        if let Some(cl) = expected_len {
            if resp_bytes.len() >= header_len + cl {
                break;
            }
        }
    }

    if resp_bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed by server without response",
        ));
    }

    let resp_str = String::from_utf8_lossy(&resp_bytes);
    let status = if let Some(line) = resp_str.lines().next() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let code = parts[1].parse::<u16>().unwrap_or(500);
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    let body = if let Some(idx) = resp_str.find("\r\n\r\n") {
        resp_str[idx + 4..].to_string()
    } else if let Some(idx) = resp_str.find("\n\n") {
        resp_str[idx + 2..].to_string()
    } else {
        resp_str.to_string()
    };

    Ok((status, body))
}

pub fn http_get_unix(sock_path: &Path, path_and_query: &str) -> io::Result<(StatusCode, String)> {
    http_request_unix(sock_path, "GET", path_and_query, None)
}
