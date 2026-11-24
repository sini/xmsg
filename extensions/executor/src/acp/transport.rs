use super::*;
use crate::{
    framing::{Failure, Frame, Notification, Request, Success, MAX_FRAME_BYTES},
    protocol::MAX_TEXT_BYTES,
};

#[derive(Clone)]
enum Operation {
    Initialize,
    NewSession,
    LoadSession(String),
    SetMode(String),
    Prompt(String),
    Steer(String),
}
impl Operation {
    fn name(&self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::NewSession => "new_session",
            Self::LoadSession(_) => "load_session",
            Self::SetMode(_) => "set_mode",
            Self::Prompt(_) => "prompt",
            Self::Steer(_) => "steer",
        }
    }
    fn turn(&self) -> Option<String> {
        match self {
            Self::Prompt(t) | Self::Steer(t) => Some(t.clone()),
            _ => None,
        }
    }
}
struct Pending {
    id: RequestId,
    operation: Operation,
}
struct Permission {
    id: RequestId,
    params: Value,
    options: Vec<PermissionOption>,
}

/// A single-session mapping state machine; it never reads, writes, spawns or grants authority.
pub struct Driver {
    adapter: Adapter,
    initialized: bool,
    unavailable: bool,
    next_id: i64,
    pending: Vec<Pending>,
    permissions: Vec<Permission>,
    session: Option<String>,
    active_turn: Option<String>,
    turn_unknown: bool,
    requested_mode: Option<String>,
    mode_observed: bool,
    steering_advertised: bool,
    load_advertised: bool,
}

impl Driver {
    pub fn new(adapter: Adapter) -> Self {
        Self {
            adapter,
            initialized: false,
            unavailable: false,
            next_id: 1,
            pending: Vec::new(),
            permissions: Vec::new(),
            session: None,
            active_turn: None,
            turn_unknown: false,
            requested_mode: None,
            mode_observed: false,
            steering_advertised: false,
            load_advertised: false,
        }
    }
    pub fn native_session_id(&self) -> Option<&str> {
        self.session.as_deref()
    }
    pub fn active_turn_id(&self) -> Option<&str> {
        self.active_turn.as_deref()
    }
    pub fn turn_is_unknown(&self) -> bool {
        self.turn_unknown
    }
    /// The host supplies a separately qualified quiescence witness, never a caller RPC.
    pub fn confirm_turn_quiescent(&mut self, session: &str, turn: &str) -> Result<(), Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        self.session_matches(session)?;
        if !self.turn_unknown
            || self.active_turn.as_deref() != Some(turn)
            || self
                .pending
                .iter()
                .any(|pending| pending.operation.turn().as_deref() == Some(turn))
        {
            return Err(Error::Turn);
        }
        self.active_turn = None;
        self.turn_unknown = false;
        Ok(())
    }
    pub fn human_mode_observed(&self) -> bool {
        self.mode_observed
    }

    /// An uncertain transport cannot be reused or replayed through this state machine.
    pub fn transport_lost(&mut self) {
        self.unavailable = true;
        self.permissions.clear();
        self.pending.clear();
    }

    pub fn begin(&mut self, command: Command) -> Result<Frame, Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        if !matches!(command, Command::Initialize { .. }) && !self.initialized {
            return Err(Error::NotInitialized);
        }
        let (method, params, operation) = match command {
            Command::Initialize { client_name } => {
                if self.initialized || !self.pending.is_empty() || !field(&client_name) {
                    return Err(Error::Protocol);
                }
                (
                    "initialize",
                    json!({"protocolVersion":1,"clientInfo":{"name":client_name,"version":env!("CARGO_PKG_VERSION")},
                    "clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false}}),
                    Operation::Initialize,
                )
            }
            Command::NewSession { cwd, mcp_servers } => {
                self.session_start(&cwd, &mcp_servers)?;
                (
                    "session/new",
                    self.adapter.session_params(None, &cwd, &mcp_servers),
                    Operation::NewSession,
                )
            }
            Command::LoadSession {
                native_session_id,
                cwd,
                mcp_servers,
            } => {
                self.session_start(&cwd, &mcp_servers)?;
                if !field(&native_session_id) || !self.load_advertised {
                    return Err(Error::Session);
                }
                (
                    "session/load",
                    self.adapter
                        .session_params(Some(&native_session_id), &cwd, &mcp_servers),
                    Operation::LoadSession(native_session_id),
                )
            }
            Command::SetMode {
                native_session_id,
                mode_id,
            } => {
                self.session_matches(&native_session_id)?;
                if self.active_turn.is_some()
                    || !self.adapter.human_mode(&mode_id)
                    || self
                        .pending
                        .iter()
                        .any(|p| matches!(p.operation, Operation::SetMode(_)))
                {
                    return Err(Error::Mode);
                }
                (
                    "session/set_mode",
                    json!({"sessionId":native_session_id,"modeId":mode_id}),
                    Operation::SetMode(mode_id),
                )
            }
            Command::Prompt {
                native_session_id,
                turn_id,
                text,
            } => {
                self.session_matches(&native_session_id)?;
                if !self.mode_observed {
                    return Err(Error::Mode);
                }
                if self.active_turn.is_some()
                    || !field(&turn_id)
                    || self
                        .pending
                        .iter()
                        .any(|p| matches!(p.operation, Operation::Steer(_)))
                {
                    return Err(Error::Turn);
                }
                text_field(&text)?;
                (
                    "session/prompt",
                    json!({"sessionId":native_session_id,"prompt":[{"type":"text","text":text}]}),
                    Operation::Prompt(turn_id),
                )
            }
            Command::Steer {
                native_session_id,
                turn_id,
                text,
            } => {
                self.turn_matches(&native_session_id, &turn_id)?;
                if !self.mode_observed
                    || !self.steering_advertised
                    || !matches!(self.adapter.harness(), Harness::Claude | Harness::Codex)
                {
                    return Err(Error::Turn);
                }
                text_field(&text)?;
                (
                    "_session/steering",
                    json!({"sessionId":native_session_id,"prompt":[{"type":"text","text":text}],
                    "_meta":{"steering":{"idleBehavior":"promptRequired"}}}),
                    Operation::Steer(turn_id),
                )
            }
            Command::Cancel {
                native_session_id,
                turn_id,
            } => {
                self.turn_matches(&native_session_id, &turn_id)?;
                return Ok(Frame::Notification(Notification {
                    jsonrpc: "2.0".into(),
                    method: "session/cancel".into(),
                    params: Some(json!({"sessionId":native_session_id})),
                }));
            }
        };
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(Error::PendingLimit);
        }
        let id = RequestId::Number(self.next_id);
        let frame = Frame::Request(Request {
            jsonrpc: "2.0".into(),
            id: id.clone(),
            method: method.into(),
            params: Some(params),
        });
        bounded(&frame)?;
        self.next_id = self.next_id.checked_add(1).ok_or(Error::PendingLimit)?;
        match &operation {
            Operation::Prompt(turn) => self.active_turn = Some(turn.clone()),
            Operation::SetMode(mode) => {
                self.requested_mode = Some(mode.clone());
                self.mode_observed = false;
            }
            _ => {}
        }
        self.pending.push(Pending { id, operation });
        Ok(frame)
    }

    pub fn observe(&mut self, frame: Frame) -> Result<Vec<Event>, Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        if frame.validate().is_err() || bounded(&frame).is_err() {
            self.transport_lost();
            return Err(Error::Protocol);
        }
        let result = match frame {
            Frame::Success(reply) => self.success(reply),
            Frame::Failure(reply) => self.failure(reply),
            Frame::Request(request) => self.request(request),
            Frame::Notification(notification) => self.notification(notification),
        };
        if result.is_err() {
            self.transport_lost();
        }
        result
    }

    pub fn answer_permission(
        &mut self,
        id: RequestId,
        decision: PermissionDecision,
    ) -> Result<Frame, Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        let position = self
            .permissions
            .iter()
            .position(|p| p.id == id)
            .ok_or(Error::Protocol)?;
        let permission = &self.permissions[position];
        let outcome = match decision {
            PermissionDecision::Cancel => json!({"outcome":"cancelled"}),
            PermissionDecision::SelectOnce { option_id } => {
                if !permission.options.iter().any(|p| {
                    p.option_id == option_id
                        && matches!(
                            p.kind,
                            PermissionKind::AllowOnce | PermissionKind::RejectOnce
                        )
                }) {
                    return Err(Error::Protocol);
                }
                json!({"outcome":"selected","optionId":option_id})
            }
        };
        let frame = Frame::Success(Success {
            jsonrpc: "2.0".into(),
            id,
            result: json!({"outcome":outcome}),
        });
        bounded(&frame)?;
        self.permissions.remove(position);
        Ok(frame)
    }

    fn session_start(&self, cwd: &str, servers: &[Value]) -> Result<(), Error> {
        if self.session.is_some()
            || !self.pending.is_empty()
            || !std::path::Path::new(cwd).is_absolute()
            || cwd.contains('\0')
            || servers.len() > 16
        {
            return Err(Error::Session);
        }
        Ok(())
    }
    fn session_matches(&self, session: &str) -> Result<(), Error> {
        if self.session.as_deref() == Some(session) {
            Ok(())
        } else {
            Err(Error::Session)
        }
    }
    fn turn_matches(&self, session: &str, turn: &str) -> Result<(), Error> {
        self.session_matches(session)?;
        if !self.turn_unknown && self.active_turn.as_deref() == Some(turn) {
            Ok(())
        } else {
            Err(Error::Turn)
        }
    }
    fn take(&mut self, id: &RequestId) -> Result<Operation, Error> {
        let position = self
            .pending
            .iter()
            .position(|p| p.id == *id)
            .ok_or(Error::Protocol)?;
        Ok(self.pending.remove(position).operation)
    }
    fn success(&mut self, reply: Success) -> Result<Vec<Event>, Error> {
        let operation = self.take(&reply.id)?;
        Ok(vec![match operation {
            Operation::Initialize => {
                if reply.result.get("protocolVersion").and_then(Value::as_u64) != Some(1) {
                    return Err(Error::Protocol);
                }
                let capabilities = reply
                    .result
                    .get("agentCapabilities")
                    .filter(|v| v.is_object())
                    .ok_or(Error::Protocol)?
                    .clone();
                self.steering_advertised = reply
                    .result
                    .pointer("/_meta/steering/supported")
                    .and_then(Value::as_bool)
                    == Some(true);
                self.load_advertised =
                    capabilities.get("loadSession").and_then(Value::as_bool) == Some(true);
                self.initialized = true;
                Event::Initialized {
                    advertised_capabilities: reply.result,
                }
            }
            Operation::NewSession | Operation::LoadSession(_) => {
                let session = match operation {
                    Operation::LoadSession(session) => session,
                    _ => string(&reply.result, "sessionId")?,
                };
                if let Some(echo) = reply.result.get("sessionId") {
                    if echo.as_str() != Some(session.as_str()) {
                        return Err(Error::Session);
                    }
                }
                let current_mode = reply
                    .result
                    .pointer("/modes/currentModeId")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                self.session = Some(session.clone());
                self.requested_mode = None;
                self.mode_observed = false;
                Event::SessionReady {
                    native_session_id: session,
                    current_mode,
                    raw: reply.result,
                }
            }
            Operation::SetMode(mode_id) => Event::ModeRequested {
                native_session_id: self.session.clone().ok_or(Error::Session)?,
                mode_id,
            },
            Operation::Prompt(turn_id) => {
                if self.active_turn.as_deref() != Some(&turn_id) {
                    return Err(Error::Turn);
                }
                let stop_reason = string(&reply.result, "stopReason")?;
                if !matches!(
                    stop_reason.as_str(),
                    "end_turn" | "max_tokens" | "max_turn_requests" | "refusal" | "cancelled"
                ) {
                    return Err(Error::Protocol);
                }
                let quiescence_unproven = stop_reason == "cancelled";
                if quiescence_unproven {
                    self.turn_unknown = true;
                } else {
                    self.active_turn = None;
                }
                self.permissions.clear();
                Event::PromptFinished {
                    turn_id,
                    stop_reason,
                    quiescence_unproven,
                }
            }
            Operation::Steer(turn_id) => {
                if self.turn_unknown || self.active_turn.as_deref() != Some(&turn_id) {
                    return Err(Error::Turn);
                }
                let outcome = match string(&reply.result, "outcome")?.as_str() {
                    "injected" => SteeringOutcome::Injected,
                    "promptRequired" => SteeringOutcome::PromptRequired,
                    "startedNewTurn" => return Err(Error::Protocol),
                    _ => SteeringOutcome::Unknown,
                };
                Event::SteeringOutcome {
                    turn_id,
                    outcome,
                    raw: reply.result,
                }
            }
        }])
    }
    fn failure(&mut self, reply: Failure) -> Result<Vec<Event>, Error> {
        let operation = self.take(&reply.id)?;
        if let Operation::Prompt(turn) = &operation {
            if self.active_turn.as_ref() == Some(turn) {
                self.permissions.clear();
                self.turn_unknown = true;
            }
        }
        if matches!(operation, Operation::SetMode(_)) {
            self.mode_observed = false;
            self.requested_mode = None;
        }
        Ok(vec![Event::RequestFailed {
            operation: operation.name().into(),
            turn_id: operation.turn(),
            code: reply.error.code,
        }])
    }
    fn request(&mut self, request: Request) -> Result<Vec<Event>, Error> {
        if matches!(request.id, RequestId::Null(())) {
            return Err(Error::Protocol);
        }
        if request.method != "session/request_permission" {
            return Ok(vec![Event::UnsupportedRequest {
                request_id: request.id,
                method: request.method,
            }]);
        }
        let params = request.params.ok_or(Error::Protocol)?;
        let session = string(&params, "sessionId")?;
        self.session_matches(&session)?;
        let turn = self.active_turn.clone().ok_or(Error::Turn)?;
        let call = params
            .get("toolCall")
            .filter(|v| v.is_object())
            .ok_or(Error::Protocol)?;
        let tool_call_id = string(call, "toolCallId")?;
        let options = params
            .get("options")
            .and_then(Value::as_array)
            .ok_or(Error::Protocol)?;
        if options.is_empty() || options.len() > 16 {
            return Err(Error::Protocol);
        }
        let mut selected = Vec::<PermissionOption>::new();
        for value in options {
            let option_id = string(value, "optionId")?;
            if selected.iter().any(|p| p.option_id == option_id) {
                return Err(Error::Protocol);
            }
            let kind = match string(value, "kind")?.as_str() {
                "allow_once" => PermissionKind::AllowOnce,
                "reject_once" => PermissionKind::RejectOnce,
                "allow_always" => PermissionKind::AllowAlways,
                "reject_always" => PermissionKind::RejectAlways,
                _ => return Err(Error::Protocol),
            };
            selected.push(PermissionOption {
                option_id,
                kind,
                name: string(value, "name")?,
            });
        }
        if let Some(prior) = self.permissions.iter().find(|p| p.id == request.id) {
            return if prior.params == params {
                Ok(Vec::new())
            } else {
                Err(Error::Protocol)
            };
        }
        if self.permissions.len() >= MAX_PENDING_PERMISSIONS {
            return Err(Error::PendingLimit);
        }
        self.permissions.push(Permission {
            id: request.id.clone(),
            params: params.clone(),
            options: selected.clone(),
        });
        Ok(vec![Event::PendingPermission {
            request_id: request.id,
            native_session_id: session,
            turn_id: turn,
            tool_call_id,
            options: selected,
            raw: params,
            human_mandatory_provenance: HumanMandatoryProvenance::Unproven,
        }])
    }
    fn notification(&mut self, notification: Notification) -> Result<Vec<Event>, Error> {
        let Some(params) = notification.params else {
            return Ok(vec![Event::UnknownNotification {
                method: notification.method,
                raw: None,
            }]);
        };
        if notification.method != "session/update" {
            return Ok(vec![Event::UnknownNotification {
                method: notification.method,
                raw: Some(params),
            }]);
        }
        let session = string(&params, "sessionId")?;
        if self.session.is_none() {
            return Ok(vec![Event::UnknownNotification {
                method: notification.method,
                raw: Some(params),
            }]);
        }
        let update = params
            .get("update")
            .filter(|v| v.is_object())
            .ok_or(Error::Protocol)?;
        let kind = string(update, "sessionUpdate")?;
        if self.session.as_deref() != Some(&session) {
            return Ok(vec![Event::NativeChildObserved { raw: params }]);
        }
        self.session_matches(&session)?;
        let event = match kind.as_str() {
            "current_mode_update" => {
                let mode_id = string(update, "currentModeId")?;
                self.mode_observed = self.requested_mode.as_ref() == Some(&mode_id)
                    && self.adapter.human_mode(&mode_id);
                Event::ModeObserved {
                    native_session_id: session,
                    mode_id,
                }
            }
            "config_option_update" => {
                let options = update
                    .get("configOptions")
                    .and_then(Value::as_array)
                    .ok_or(Error::Protocol)?;
                if options.len() > 64 {
                    return Err(Error::Protocol);
                }
                let modes: Vec<_> = options
                    .iter()
                    .filter(|option| option.get("id").and_then(Value::as_str) == Some("mode"))
                    .collect();
                if modes.len() > 1 {
                    return Err(Error::Protocol);
                }
                if let Some(mode) = modes.first() {
                    if mode.get("type").and_then(Value::as_str) != Some("select") {
                        return Err(Error::Protocol);
                    }
                    let mode_id = string(mode, "currentValue")?;
                    self.mode_observed = self.requested_mode.as_ref() == Some(&mode_id)
                        && self.adapter.human_mode(&mode_id);
                    Event::ModeObserved {
                        native_session_id: session,
                        mode_id,
                    }
                } else {
                    Event::UnknownNotification {
                        method: notification.method,
                        raw: Some(params),
                    }
                }
            }
            "tool_call" | "tool_call_update" => Event::ToolUpdate {
                native_session_id: session,
                raw: params,
            },
            "agent_message_chunk" | "agent_thought_chunk" | "user_message_chunk" => {
                Event::Content {
                    native_session_id: session,
                    raw: params,
                }
            }
            "session_message" | "session_info_update" => Event::NativeChildObserved { raw: params },
            _ => Event::UnknownNotification {
                method: notification.method,
                raw: Some(params),
            },
        };
        Ok(vec![event])
    }
}

fn field(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.contains('\0')
}
fn string(value: &Value, key: &str) -> Result<String, Error> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| field(s))
        .map(str::to_owned)
        .ok_or(Error::Protocol)
}
fn text_field(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        Err(Error::Protocol)
    } else {
        Ok(())
    }
}
fn bounded(frame: &Frame) -> Result<(), Error> {
    if serde_json::to_vec(frame)
        .map_err(|_| Error::Protocol)?
        .len()
        + 1
        > MAX_FRAME_BYTES
    {
        Err(Error::Protocol)
    } else {
        Ok(())
    }
}
