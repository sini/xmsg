//! Pure ACP-v1 mapping; the supervisor owns I/O, authority and effect qualification.

mod agy;
mod claude;
mod codex;
#[cfg(test)]
mod tests;
mod transport;

pub use transport::Driver;

use crate::{capability::HarnessPin, framing::RequestId, protocol::Harness};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MAX_PENDING_REQUESTS: usize = 32;
pub const MAX_PENDING_PERMISSIONS: usize = 32;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("unsupported pinned adapter tuple")]
    Pin,
    #[error("invalid ACP frame or payload")]
    Protocol,
    #[error("ACP pending request bound exceeded")]
    PendingLimit,
    #[error("ACP driver is unavailable after a protocol or transport failure")]
    Unavailable,
    #[error("ACP initialization is required")]
    NotInitialized,
    #[error("native session does not match this driver")]
    Session,
    #[error("an active native turn does not match the requested turn")]
    Turn,
    #[error("native human mode has not been selected and observed")]
    Mode,
    #[error("the selected native model has not been applied and observed")]
    Model,
    #[error("native capability is unsupported or unadvertised")]
    Unsupported,
    #[error("native response does not match an outstanding request")]
    UnknownReply,
    #[error("permission response is not a genuine one-use option")]
    Permission,
}

#[derive(Debug, Clone)]
pub struct Adapter {
    harness: Harness,
}
impl Adapter {
    pub fn for_pin(pin: &HarnessPin) -> Result<Self, Error> {
        let matches = pin.protocol_version == 1
            && match pin.harness {
                Harness::Claude => {
                    pin.adapter == "claude-agent-acp"
                        && pin.adapter_version == claude::ADAPTER_VERSION
                        && pin.runtime_version == claude::RUNTIME_VERSION
                        && pin.source_revision.as_deref() == Some(claude::REVISION)
                }
                Harness::Codex => {
                    pin.adapter == "codex-acp"
                        && pin.adapter_version == codex::ADAPTER_VERSION
                        && pin.runtime_version == codex::RUNTIME_VERSION
                        && pin.source_revision.as_deref() == Some(codex::REVISION)
                }
                Harness::Agy => {
                    pin.adapter == "agy acp"
                        && pin.adapter_version == agy::VERSION
                        && pin.runtime_version == agy::VERSION
                        && pin.source_revision.is_none()
                }
            };
        if !matches {
            return Err(Error::Pin);
        }
        Ok(Self {
            harness: pin.harness.clone(),
        })
    }
    pub fn harness(&self) -> &Harness {
        &self.harness
    }
    pub fn human_mode(&self, mode: &str) -> bool {
        match self.harness {
            Harness::Claude => claude::human_mode(mode),
            Harness::Codex => codex::human_mode(mode),
            Harness::Agy => false,
        }
    }
    pub(crate) fn session_params(
        &self,
        session: Option<&str>,
        cwd: &str,
        servers: &[Value],
    ) -> Value {
        let mut params = json!({"cwd":cwd,"mcpServers":servers});
        if let Some(session) = session {
            params["sessionId"] = json!(session);
        }
        if self.harness == Harness::Claude {
            params["_meta"] = claude::session_meta();
        }
        params
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Initialize {
        client_name: String,
    },
    NewSession {
        cwd: String,
        mcp_servers: Vec<Value>,
    },
    LoadSession {
        native_session_id: String,
        cwd: String,
        mcp_servers: Vec<Value>,
    },
    SetMode {
        native_session_id: String,
        mode_id: String,
    },
    SetModel {
        native_session_id: String,
        model_id: String,
    },
    Prompt {
        native_session_id: String,
        turn_id: String,
        text: String,
    },
    Steer {
        native_session_id: String,
        turn_id: String,
        text: String,
    },
    Cancel {
        native_session_id: String,
        turn_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionKind {
    AllowOnce,
    RejectOnce,
    AllowAlways,
    RejectAlways,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionOption {
    pub option_id: String,
    pub kind: PermissionKind,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum PermissionDecision {
    SelectOnce { option_id: String },
    Cancel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SteeringOutcome {
    Injected,
    PromptRequired,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HumanMandatoryProvenance {
    Unproven,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Initialized {
        advertised_capabilities: Value,
    },
    SessionReady {
        native_session_id: String,
        current_mode: Option<String>,
        raw: Value,
    },
    ModeRequested {
        native_session_id: String,
        mode_id: String,
    },
    ModeObserved {
        native_session_id: String,
        mode_id: String,
    },
    ModelObserved {
        native_session_id: String,
        model_id: String,
    },
    PromptFinished {
        turn_id: String,
        stop_reason: String,
        quiescence_unproven: bool,
    },
    SteeringOutcome {
        turn_id: String,
        outcome: SteeringOutcome,
        raw: Value,
    },
    CancellationSubmitted {
        turn_id: String,
    },
    PendingPermission {
        request_id: RequestId,
        native_session_id: String,
        turn_id: String,
        tool_call_id: String,
        options: Vec<PermissionOption>,
        raw: Value,
        human_mandatory_provenance: HumanMandatoryProvenance,
    },
    PermissionAutoCancelled {
        request_id: RequestId,
        response: crate::framing::Frame,
    },
    ToolUpdate {
        native_session_id: String,
        raw: Value,
    },
    NativeChildObserved {
        raw: Value,
    },
    Content {
        native_session_id: String,
        raw: Value,
    },
    UnsupportedRequest {
        request_id: RequestId,
        method: String,
    },
    RequestFailed {
        operation: String,
        turn_id: Option<String>,
        code: i64,
    },
    UnknownNotification {
        method: String,
        raw: Option<Value>,
    },
}
