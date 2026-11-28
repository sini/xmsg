use std::{io, sync::Arc};

use http_body_util::{BodyExt, Limited};
use hyper::{body::Incoming, Method, Request, StatusCode};

use super::admission::{self, Refusal, Route};
use super::authority::Class;
use super::command_wire::{self, Carrier, CommandRequest, PreparedRequest};
use super::stream::Fence;
use super::{transport, Issuer, WebResponse};

const PREPARE: &str = "/v1/mission-control/commands/prepare";
const COMMIT: &str = "/v1/mission-control/commands/commit";
const RECEIPTS: &str = "/v1/receipts/";

pub(super) struct ReceiptFence {
    issuer: Arc<Issuer>,
    record_id: String,
    request: Option<PreparedRequest>,
}

impl ReceiptFence {
    pub(super) fn handoff<T>(&self, write: impl FnOnce() -> T) -> io::Result<T> {
        fn denied() -> io::Error {
            io::Error::new(io::ErrorKind::PermissionDenied, "command receipt fenced")
        }

        let state = self.issuer.authority.locked().map_err(|_| denied())?;
        if let Some(request) = &self.request {
            self.issuer
                .command_entitled(&state, &self.record_id, request)
                .map_err(|_| denied())?;
        } else {
            state
                .command_record(&self.record_id)
                .map_err(|_| denied())?;
        }
        Ok(write())
    }
}

pub(crate) fn is_command(path: &str) -> bool {
    matches!(path, PREPARE | COMMIT) || path.starts_with(RECEIPTS)
}

pub(crate) async fn response(
    issuer: &Arc<Issuer>,
    request: Request<Incoming>,
    fence: Arc<Fence>,
) -> WebResponse {
    inner(issuer, request, fence)
        .await
        .unwrap_or_else(transport::error)
}

async fn inner(
    issuer: &Arc<Issuer>,
    request: Request<Incoming>,
    fence: Arc<Fence>,
) -> Result<WebResponse, Refusal> {
    let record = admission::authenticate(issuer, Route::Command, request.headers()).await?;
    if record.class == Class::Machine {
        return Err(Refusal::FORBIDDEN);
    }
    let path = request.uri().path();
    let method = if matches!(path, PREPARE | COMMIT) {
        Method::POST
    } else {
        Method::GET
    };
    if request.method() != method || request.uri().query().is_some() {
        return Err(Refusal::INVALID);
    }
    if !issuer.commands.available() {
        return Err(Refusal::UNAVAILABLE);
    }
    let command = if let Some(request_id) = path.strip_prefix(RECEIPTS) {
        if !command_wire::valid_request_id(request_id) {
            return Err(Refusal::INVALID);
        }
        CommandRequest::Lookup {
            id: None,
            request_id: request_id.to_owned(),
        }
    } else {
        let prepare = path == PREPARE;
        let limits = &issuer.config.session_limits;
        let body = Limited::new(request.into_body(), limits.max_client_message_bytes)
            .collect()
            .await
            .map_err(|_| Refusal::INVALID)?
            .to_bytes();
        let command = command_wire::decode(
            &body,
            limits.max_json_depth,
            limits.max_string_bytes,
            Carrier::Http,
        )
        .map_err(|_| Refusal::INVALID)?;
        match (&command, prepare) {
            (CommandRequest::Prepare { .. }, true) | (CommandRequest::Commit { .. }, false) => {
                command
            }
            _ => return Err(Refusal::INVALID),
        }
    };
    let reply = issuer.command(&record, "http", command)?;
    {
        let state = issuer.authority.locked()?;
        if let Some(request) = &reply.request {
            issuer.command_entitled(&state, &record.record_id, request)?;
        } else {
            state.command_record(&record.record_id)?;
        }
    }
    fence.set_command(ReceiptFence {
        issuer: issuer.clone(),
        record_id: record.record_id,
        request: reply.request,
    })?;
    #[cfg(test)]
    let _ = issuer.commands.before_handoff().await;
    Ok(super::response(
        StatusCode::OK,
        "application/json",
        reply.body.to_string(),
    ))
}
