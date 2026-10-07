use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ErrorResponse {
    pub error: &'static str,
    pub detail: String,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("bad sender: {0}")]
    BadSender(String),

    #[error("not found: no live session matches '{0}'")]
    NotFound(String),

    #[error("ambiguous session ref: matches {0}")]
    Ambiguous(String),

    #[error("session {session_id} process {pid} exited")]
    Gone { session_id: String, pid: u32 },

    #[error("body {size} exceeds limit {limit}")]
    PayloadTooLarge { size: usize, limit: usize },

    #[error("inbox unavailable: {0}")]
    InboxUnavailable(String),

    #[error("inbox write timed out after 5s")]
    InboxTimeout,

    #[error("not recipient: {0}")]
    NotRecipient(String),

    #[error("credentials stale: {0}")]
    CredentialsStale(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("internal server error: {0}")]
    Internal(String),

    #[error("insecure socket directory: {0}")]
    InsecureSocketDir(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code, detail) = match self {
            AppError::BadRequest(d) => (StatusCode::BAD_REQUEST, "bad_request", d),
            AppError::BadSender(d) => (StatusCode::BAD_REQUEST, "bad_sender", d),
            AppError::NotFound(r) => (
                StatusCode::NOT_FOUND,
                "not_found",
                format!("no live session matches '{r}'"),
            ),
            AppError::Ambiguous(d) => (StatusCode::CONFLICT, "ambiguous", d),
            AppError::Gone { session_id, pid } => (
                StatusCode::GONE,
                "gone",
                format!("session {session_id} process {pid} exited"),
            ),
            AppError::PayloadTooLarge { size, limit } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!("body {size} exceeds limit {limit}"),
            ),
            AppError::InboxUnavailable(d) => (StatusCode::BAD_GATEWAY, "inbox_unavailable", d),
            AppError::InboxTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "inbox_timeout",
                "inbox write timed out after 5s".to_string(),
            ),
            AppError::NotRecipient(d) => (StatusCode::FORBIDDEN, "not_recipient", d),
            AppError::CredentialsStale(d) => {
                (StatusCode::SERVICE_UNAVAILABLE, "credentials_stale", d)
            }
            AppError::ServiceUnavailable(d) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", d)
            }
            AppError::Internal(d) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", d),
            AppError::InsecureSocketDir(d) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "insecure_socket_dir", d)
            }
        };

        (
            status,
            Json(ErrorResponse {
                error: error_code,
                detail,
            }),
        )
            .into_response()
    }
}
