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
use std::path::PathBuf;
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
    pub sessions_dir: PathBuf,
    pub agy_config: crate::agy::AgyConfig,
    pub agy_store: crate::agy::AgyStore,
    pub pi_store: crate::pi::PiStore,
    pub pi_notify_tx: broadcast::Sender<String>,
    pub host_label: String,
    pub max_body: usize,
    pub request_counter: AtomicU64,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub notify_tx: broadcast::Sender<String>,
    pub reply_ttl: Duration,
    pub long_poll_semaphore: Arc<tokio::sync::Semaphore>,
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
    let dir_ok = state.sessions_dir.exists() && state.sessions_dir.is_dir();
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
}

pub(crate) fn resolve_target_session(
    state: &AppState,
    ref_str: &str,
) -> Result<ResolvedTarget, AppError> {
    match registry::resolve_session(&state.sessions_dir, ref_str) {
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
                            if let Ok(pid) = ref_str.parse::<u32>() {
                                if crate::process::starttime(&state.agy_config.proc_root, pid)
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
        Err(err) => Err(err),
    }
}

async fn list_sessions_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionsQuery>,
) -> impl IntoResponse {
    let mut sessions = registry::list_sessions(&state.sessions_dir, &query);
    let mut agy_sessions =
        crate::agy::list_agy_sessions(&state.agy_config, &state.agy_store, &query);
    sessions.append(&mut agy_sessions);
    let mut pi_sessions =
        crate::pi::list_pi_sessions(&state.agy_config.proc_root, &state.pi_store, &query);
    sessions.append(&mut pi_sessions);
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

    // Sanitize sender name (enforces printable ASCII and rejects ':' and '/')
    let from_name = match inbox::sanitize_from(&state.host_label, &req.from) {
        Ok(name) => name,
        Err(err) => {
            eprintln!(
                "req_id={} ref={} bytes={} outcome=bad_sender detail=\"{}\"",
                req_id, ref_str, body_len, err
            );
            return Err(err);
        }
    };

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
    };

    {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::insert_message(&db, &msg_record).map_err(|e| AppError::Internal(e.to_string()))?;
        let _ = storage::purge_messages(&db, state.reply_ttl.as_secs());
        let _ = storage::purge_replies(&db, state.reply_ttl.as_secs());
        let _ = storage::purge_pi_messages(&db, state.reply_ttl.as_secs());
        let _ = storage::purge_agy_messages(&db, state.reply_ttl.as_secs());
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
    // Verify message exists
    {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if storage::get_message(&db, &id)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .is_none()
        {
            return Err(AppError::NotFound(format!("message '{id}'")));
        }
    }

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

    // Subscribe to notifications BEFORE checking database to eliminate race conditions
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
