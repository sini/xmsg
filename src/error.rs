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

    /// A `not_found` whose detail is already a sentence, such as a peer's answer.
    #[error("not found: {0}")]
    NotFoundDetail(String),

    #[error("ambiguous session ref: matches {0}")]
    Ambiguous(String),

    /// A bare reference with a node on the path that could not be asked (A-9, D-6).
    #[error("unavailable: {0}")]
    Unavailable(String),

    /// A send routed by a cached location reached a node that holds the ID only parked
    /// (gate v0 C9): not queued there.
    #[error("not live here: {0}")]
    NotLive(String),

    /// A reclaim token was presented for an instance ID that is currently live on another
    /// connection (HA8).
    #[error("live elsewhere: {0}")]
    LiveElsewhere(String),

    #[error("session {session_id} process {pid} exited")]
    Gone { session_id: String, pid: u32 },

    #[error("unregistered: process {0} has no attested agent session")]
    Unregistered(u32),

    #[error("body {size} exceeds limit {limit}")]
    PayloadTooLarge { size: usize, limit: usize },

    #[error("inbox unavailable: {0}")]
    InboxUnavailable(String),

    #[error("inbox write timed out after 5s")]
    InboxTimeout,

    #[error("denied: {0}")]
    Denied(String),

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

    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unknown peer: {0}")]
    UnknownPeer(String),
    #[error("no forward: {0}")]
    NoForward(String),
    #[error("op denied: {0}")]
    OpDenied(String),
    #[error("peer rejected: {0}")]
    PeerRejected(String),
    #[error("peer unreachable: {0}")]
    PeerUnreachable(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
}

impl AppError {
    /// The wire code and HTTP status, one vocabulary on every surface (A13): the
    /// addressing errors `not_found`, `ambiguous`, `denied`, `gone`, `unavailable` and a
    /// cache-routed send's `not_live`, and the transport errors. `unknown_peer` and `unregistered` fold into `not_found`; a refusal by a
    /// peer's rights, a reply by a non-recipient and a forward the hub refuses are `denied`.
    pub fn code(&self) -> (StatusCode, &'static str) {
        match self {
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::BadSender(_) => (StatusCode::BAD_REQUEST, "bad_sender"),
            AppError::NotFound(_)
            | AppError::NotFoundDetail(_)
            | AppError::UnknownPeer(_)
            | AppError::Unregistered(_) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::Ambiguous(_) => (StatusCode::CONFLICT, "ambiguous"),
            AppError::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            AppError::NotLive(_) => (StatusCode::CONFLICT, "not_live"),
            AppError::LiveElsewhere(_) => (StatusCode::CONFLICT, "live_elsewhere"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::Gone { .. } => (StatusCode::GONE, "gone"),
            AppError::PayloadTooLarge { .. } => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
            }
            AppError::InboxUnavailable(_) => (StatusCode::BAD_GATEWAY, "inbox_unavailable"),
            AppError::InboxTimeout => (StatusCode::GATEWAY_TIMEOUT, "inbox_timeout"),
            AppError::Denied(_)
            | AppError::NotRecipient(_)
            | AppError::OpDenied(_)
            | AppError::PeerRejected(_)
            | AppError::NoForward(_) => (StatusCode::FORBIDDEN, "denied"),
            AppError::CredentialsStale(_) => (StatusCode::SERVICE_UNAVAILABLE, "credentials_stale"),
            AppError::ServiceUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            AppError::InsecureSocketDir(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "insecure_socket_dir")
            }
            AppError::PeerUnreachable(_) => (StatusCode::SERVICE_UNAVAILABLE, "peer_unreachable"),
            AppError::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        }
    }

    /// The human-readable detail that goes with the code.
    pub fn detail(&self) -> String {
        match self {
            AppError::NotFound(r) => format!("no live recipient matches '{r}'"),
            AppError::UnknownPeer(n) => {
                format!("unknown node '{n}' (omit 'node' to list all nodes)")
            }
            AppError::Unregistered(pid) => format!("process {pid} has no attested agent session"),
            // pid 0: no process is known, as for a released plugin address or a peer's `gone`.
            AppError::Gone { session_id, pid: 0 } => format!("session {session_id} is gone"),
            AppError::Gone { session_id, pid } => {
                format!("session {session_id} process {pid} exited")
            }
            AppError::PayloadTooLarge { size, limit } => {
                format!("body {size} exceeds limit {limit}")
            }
            AppError::InboxTimeout => "inbox write timed out after 5s".to_string(),
            AppError::BadRequest(d)
            | AppError::NotFoundDetail(d)
            | AppError::BadSender(d)
            | AppError::Ambiguous(d)
            | AppError::Unavailable(d)
            | AppError::NotLive(d)
            | AppError::LiveElsewhere(d)
            | AppError::Conflict(d)
            | AppError::InboxUnavailable(d)
            | AppError::Denied(d)
            | AppError::NotRecipient(d)
            | AppError::OpDenied(d)
            | AppError::PeerRejected(d)
            | AppError::NoForward(d)
            | AppError::CredentialsStale(d)
            | AppError::ServiceUnavailable(d)
            | AppError::Internal(d)
            | AppError::InsecureSocketDir(d)
            | AppError::PeerUnreachable(d)
            | AppError::RateLimited(d) => d.clone(),
        }
    }

    /// A socket frame's error reply, `{status: error, error, detail}`.
    pub fn frame(&self) -> serde_json::Value {
        serde_json::json!({
            "status": "error",
            "error": self.code().1,
            "detail": self.detail(),
        })
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code) = self.code();
        (
            status,
            Json(ErrorResponse {
                error: error_code,
                detail: self.detail(),
            }),
        )
            .into_response()
    }
}
