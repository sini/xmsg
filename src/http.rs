use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use axum::{
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tracing::info;

use crate::error::AppError;
use crate::inbox::{
    self, DeliveryResponse, SendMessageRequest,
};
use crate::registry::{self, SessionsQuery};

pub struct AppState {
    pub sessions_dir: PathBuf,
    pub host_label: String,
    pub max_body: usize,
    pub request_counter: AtomicU64,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/v1/sessions", get(list_sessions_handler))
        .route("/v1/sessions/{ref}", get(get_session_handler))
        .route("/v1/sessions/{ref}/messages", post(send_message_handler))
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

async fn list_sessions_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionsQuery>,
) -> impl IntoResponse {
    let sessions = registry::list_sessions(&state.sessions_dir, &query);
    (StatusCode::OK, Json(sessions))
}

async fn get_session_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(ref_str): AxumPath<String>,
) -> Result<Response, AppError> {
    let (session, _socket_path) = registry::resolve_session(&state.sessions_dir, &ref_str)?;
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

    // Sanitize sender name
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
    let (session, socket_path) = match registry::resolve_session(&state.sessions_dir, &ref_str) {
        Ok(res) => res,
        Err(err) => {
            eprintln!(
                "req_id={} ref={} from=\"{}\" bytes={} outcome=resolve_error detail=\"{}\"",
                req_id, ref_str, from_name, body_len, err
            );
            return Err(err);
        }
    };

    // Encode transport line
    let line = inbox::encode_transport_line(&from_name, &req.text)?;

    // Deliver to socket
    if let Err(err) = inbox::deliver_to_socket(&socket_path, &line).await {
        eprintln!(
            "req_id={} session_id={} from=\"{}\" bytes={} outcome=delivery_failed detail=\"{}\"",
            req_id, session.session_id, from_name, body_len, err
        );
        return Err(err);
    }

    // Invariant: Message bodies are NEVER logged under any circumstances
    eprintln!(
        "req_id={} session_id={} from=\"{}\" bytes={} outcome=delivered",
        req_id, session.session_id, from_name, body_len
    );
    info!(
        target: "xmsg",
        req_id = req_id,
        session_id = %session.session_id,
        from = %from_name,
        bytes = body_len,
        outcome = "delivered"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(DeliveryResponse {
            session_id: session.session_id,
            from_name,
            bytes: body_len,
        }),
    )
        .into_response())
}
