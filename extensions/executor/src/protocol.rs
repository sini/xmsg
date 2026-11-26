use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

pub const CONTROL_VERSION: u16 = 1;
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unsupported control version {0}")]
    Version(u16),
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("verb and target do not match")]
    Target,
    #[error("receipt layers contradict each other")]
    Receipt,
}

fn token(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn text(value: &str) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(ContractError::Invalid("text"));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Harness {
    Claude,
    Codex,
    Agy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub provider: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentBackend {
    Headless,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentDescriptor {
    pub id: String,
    pub executor: String,
    pub host: String,
    pub backend: EnvironmentBackend,
    pub project: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Team {
        team_id: String,
    },
    Session {
        session_id: String,
    },
    Execution {
        session_id: String,
        generation: u64,
    },
    Turn {
        session_id: String,
        generation: u64,
        turn_id: String,
    },
}

impl Target {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Team { team_id } => token(team_id, "team_id"),
            Self::Session { session_id } => token(session_id, "session_id"),
            Self::Execution {
                session_id,
                generation,
            } => {
                token(session_id, "session_id")?;
                if *generation == 0 {
                    return Err(ContractError::Invalid("generation"));
                }
                Ok(())
            }
            Self::Turn {
                session_id,
                generation,
                turn_id,
            } => {
                token(session_id, "session_id")?;
                token(turn_id, "turn_id")?;
                if *generation == 0 {
                    return Err(ContractError::Invalid("generation"));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DigestRef {
    pub reference: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSpec {
    pub repo_identity: String,
    pub base_revision: String,
    pub destination_selector: String,
    pub context_refs: Vec<DigestRef>,
    pub patch_ref: Option<DigestRef>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub worker_slots: u16,
    pub reviewer_slots: u16,
    pub max_wall_ms: u64,
    pub max_content_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct DispatchOptions {
    pub executor_selector: Option<String>,
    pub harness: Option<Harness>,
    pub model: Option<Model>,
    pub environment_selector: Option<String>,
    pub workspace: Option<WorkspaceSpec>,
    #[serde(default)]
    pub required_capabilities: Vec<crate::capability::Capability>,
    pub budget: Option<ResourceBudget>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchArgs {
    pub brief: String,
    #[serde(default)]
    pub requested: DispatchOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreferLive {
    pub expected_generation: u64,
    pub deadline: i64,
    pub next_turn_allowance: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SendArgs {
    pub text: String,
    pub prefer_live: Option<PreferLive>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SteerArgs {
    pub text: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct EmptyArgs {}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResumeKind {
    Reconnect,
    LoadStoredConversation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResumeArgs {
    pub kind: ResumeKind,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    pub max_events: u16,
    pub max_text_bytes: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    AllowOnce,
    Deny,
    Escalate,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApproveArgs {
    pub approval_id: String,
    pub operation_digest: String,
    pub policy_revision: String,
    pub expires_at: i64,
    pub option_id: String,
    pub decision: Decision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    Dispatch,
    Send,
    Steer,
    Interrupt,
    Resume,
    Stop,
    Status,
    Result,
    Approve,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Dispatch(Box<DispatchArgs>),
    Send(SendArgs),
    Steer(SteerArgs),
    Interrupt(EmptyArgs),
    Resume(ResumeArgs),
    Stop(EmptyArgs),
    Status(ReadArgs),
    Result(ReadArgs),
    Approve(ApproveArgs),
}

impl Action {
    pub fn verb(&self) -> Verb {
        match self {
            Self::Dispatch(_) => Verb::Dispatch,
            Self::Send(_) => Verb::Send,
            Self::Steer(_) => Verb::Steer,
            Self::Interrupt(_) => Verb::Interrupt,
            Self::Resume(_) => Verb::Resume,
            Self::Stop(_) => Verb::Stop,
            Self::Status(_) => Verb::Status,
            Self::Result(_) => Verb::Result,
            Self::Approve(_) => Verb::Approve,
        }
    }
    fn args(&self) -> Result<Box<serde_json::value::RawValue>, serde_json::Error> {
        match self {
            Self::Dispatch(a) => serde_json::value::to_raw_value(a),
            Self::Send(a) => serde_json::value::to_raw_value(a),
            Self::Steer(a) => serde_json::value::to_raw_value(a),
            Self::Interrupt(a) | Self::Stop(a) => serde_json::value::to_raw_value(a),
            Self::Resume(a) => serde_json::value::to_raw_value(a),
            Self::Status(a) | Self::Result(a) => serde_json::value::to_raw_value(a),
            Self::Approve(a) => serde_json::value::to_raw_value(a),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRequest {
    pub version: u16,
    pub request_id: String,
    pub target: Option<Target>,
    pub action: Action,
    pub deadline: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    version: u16,
    request_id: String,
    verb: Verb,
    target: Option<Target>,
    args: Box<serde_json::value::RawValue>,
    deadline: Option<i64>,
}

impl ControlRequest {
    pub fn dispatch(request_id: String, brief: String) -> Self {
        Self {
            version: CONTROL_VERSION,
            request_id,
            target: None,
            action: Action::Dispatch(Box::new(DispatchArgs {
                brief,
                requested: DispatchOptions::default(),
            })),
            deadline: None,
        }
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != CONTROL_VERSION {
            return Err(ContractError::Version(self.version));
        }
        token(&self.request_id, "request_id")?;
        if let Some(t) = &self.target {
            t.validate()?;
        }
        if self.deadline.is_some_and(|d| d <= 0) {
            return Err(ContractError::Invalid("deadline"));
        }
        match &self.action {
            Action::Dispatch(a) => {
                text(&a.brief)?;
                if let Some(w) = &a.requested.workspace {
                    token(&w.repo_identity, "repo_identity")?;
                    token(&w.destination_selector, "destination_selector")?;
                    if !matches!(w.base_revision.len(), 40 | 64)
                        || !w.base_revision.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(ContractError::Invalid("base_revision"));
                    }
                    for r in w.context_refs.iter().chain(w.patch_ref.iter()) {
                        token(&r.reference, "context_ref")?;
                        if r.sha256.len() != 64 || !r.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            return Err(ContractError::Invalid("context_digest"));
                        }
                    }
                }
                if let Some(b) = &a.requested.budget {
                    if b.worker_slots == 0 || b.max_wall_ms == 0 || b.max_content_bytes == 0 {
                        return Err(ContractError::Invalid("budget"));
                    }
                }
                if self
                    .target
                    .as_ref()
                    .is_some_and(|t| !matches!(t, Target::Team { .. }))
                {
                    return Err(ContractError::Target);
                }
            }
            Action::Send(a) => {
                text(&a.text)?;
                if !matches!(
                    self.target,
                    Some(Target::Session { .. } | Target::Execution { .. })
                ) {
                    return Err(ContractError::Target);
                }
                if let Some(live) = &a.prefer_live {
                    if let Some(Target::Execution { generation, .. }) = &self.target {
                        if *generation != live.expected_generation {
                            return Err(ContractError::Invalid("prefer_live_generation"));
                        }
                    }
                    if self.deadline.is_some_and(|d| live.deadline > d) {
                        return Err(ContractError::Invalid("prefer_live_deadline"));
                    }
                    if live.expected_generation == 0
                        || live.deadline <= 0
                        || live.next_turn_allowance == 0
                    {
                        return Err(ContractError::Invalid("prefer_live"));
                    }
                }
            }
            Action::Steer(a) => {
                text(&a.text)?;
                if !matches!(self.target, Some(Target::Turn { .. })) {
                    return Err(ContractError::Target);
                }
            }
            Action::Interrupt(_) | Action::Approve(_) => {
                if !matches!(self.target, Some(Target::Turn { .. })) {
                    return Err(ContractError::Target);
                }
            }
            Action::Resume(_) => {
                if !matches!(
                    self.target,
                    Some(Target::Session { .. } | Target::Execution { .. })
                ) {
                    return Err(ContractError::Target);
                }
            }
            Action::Stop(_) => {
                if !matches!(self.target, Some(Target::Execution { .. })) {
                    return Err(ContractError::Target);
                }
            }
            Action::Status(a) | Action::Result(a) => {
                if self.target.is_none() {
                    return Err(ContractError::Target);
                }
                if a.max_events == 0
                    || a.max_events > 1000
                    || a.max_text_bytes == 0
                    || a.max_text_bytes as usize > MAX_TEXT_BYTES
                {
                    return Err(ContractError::Invalid("read_limit"));
                }
            }
        }
        if let Action::Approve(a) = &self.action {
            token(&a.approval_id, "approval_id")?;
            token(&a.operation_digest, "operation_digest")?;
            token(&a.policy_revision, "policy_revision")?;
            token(&a.option_id, "option_id")?;
            if a.expires_at <= 0 {
                return Err(ContractError::Invalid("expires_at"));
            }
        }
        Ok(())
    }
}

impl Serialize for ControlRequest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        RawRequest {
            version: self.version,
            request_id: self.request_id.clone(),
            verb: self.action.verb(),
            target: self.target.clone(),
            args: self.action.args().map_err(serde::ser::Error::custom)?,
            deadline: self.deadline,
        }
        .serialize(s)
    }
}
impl<'de> Deserialize<'de> for ControlRequest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = RawRequest::deserialize(d)?;
        let action = match r.verb {
            Verb::Dispatch => {
                Action::Dispatch(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
            Verb::Send => {
                Action::Send(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
            Verb::Steer => {
                Action::Steer(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
            Verb::Interrupt => {
                Action::Interrupt(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
            Verb::Resume => {
                Action::Resume(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
            Verb::Stop => {
                Action::Stop(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
            Verb::Status => {
                Action::Status(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
            Verb::Result => {
                Action::Result(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
            Verb::Approve => {
                Action::Approve(serde_json::from_str(r.args.get()).map_err(D::Error::custom)?)
            }
        };
        let request = Self {
            version: r.version,
            request_id: r.request_id,
            target: r.target,
            action,
            deadline: r.deadline,
        };
        request.validate().map_err(D::Error::custom)?;
        Ok(request)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authorization {
    Unassessed,
    Allowed { policy_revision: String },
    Denied { code: String },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Admission {
    NotAdmitted,
    Durable {
        admission_id: String,
        generation: u64,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Submission {
    NotAttempted,
    Submitted,
    Unknown,
    NotSupported,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedEffect {
    NotObserved,
    Injected { turn_id: String },
    Interrupted { turn_id: String },
    Ended,
    Unknown { reason: String },
    NotSupported { reason: String },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationReceipt {
    pub request_id: String,
    pub target: Option<Target>,
    pub authorization: Authorization,
    pub admission: Admission,
    pub submission: Submission,
    pub observed_effect: ObservedEffect,
}
impl OperationReceipt {
    pub fn validate(&self) -> Result<(), ContractError> {
        token(&self.request_id, "request_id")?;
        if let Some(t) = &self.target {
            t.validate()?;
        }
        if !matches!(self.authorization, Authorization::Allowed { .. })
            && (!matches!(self.admission, Admission::NotAdmitted)
                || self.submission != Submission::NotAttempted
                || self.observed_effect != ObservedEffect::NotObserved)
        {
            return Err(ContractError::Receipt);
        }
        if matches!(self.admission, Admission::NotAdmitted)
            && (self.submission != Submission::NotAttempted
                || self.observed_effect != ObservedEffect::NotObserved)
        {
            return Err(ContractError::Receipt);
        }
        if let Admission::Durable {
            admission_id,
            generation,
        } = &self.admission
        {
            token(admission_id, "admission_id")?;
            if *generation == 0 {
                return Err(ContractError::Invalid("generation"));
            }
        }
        if let (
            Some(Target::Execution { generation, .. } | Target::Turn { generation, .. }),
            Admission::Durable {
                generation: admitted,
                ..
            },
        ) = (&self.target, &self.admission)
        {
            if generation != admitted {
                return Err(ContractError::Receipt);
            }
        }
        match &self.observed_effect {
            ObservedEffect::Injected { turn_id } => {
                token(turn_id, "observed_turn_id")?;
                if self.submission != Submission::Submitted {
                    return Err(ContractError::Receipt);
                }
                match &self.target {
                    Some(Target::Turn {
                        turn_id: addressed, ..
                    }) if addressed == turn_id => {}
                    Some(Target::Session { .. } | Target::Execution { .. }) => {}
                    _ => return Err(ContractError::Receipt),
                }
            }
            ObservedEffect::Interrupted { turn_id }
                if !matches!(&self.target,Some(Target::Turn {turn_id:addressed,..}) if turn_id==addressed)
                    || self.submission != Submission::Submitted =>
            {
                return Err(ContractError::Receipt);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentEnvelope {
    pub message_id: String,
    pub origin: xmsg::client::Origin,
    pub text: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    Failed,
    Cancelled,
    Working,
    NeedsHuman,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedResult {
    pub session_id: String,
    pub generation: u64,
    pub turn_id: Option<String>,
    pub outcome: Outcome,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub base_revision: Option<String>,
    pub result_revision: Option<String>,
    pub remaining_work: Vec<String>,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Starting,
    Working,
    Background,
    NeedsHuman,
    Stopped,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    Supervisor,
    NativeFrame,
    Journal,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusReport {
    pub session_id: String,
    pub generation: u64,
    pub turn_id: Option<String>,
    pub state: SessionState,
    pub observed_at: i64,
    pub source: ObservationSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconnectState {
    SameOwnedExecution,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconnectReport {
    pub session_id: String,
    pub generation: u64,
    pub native_session_id: String,
    pub transport_epoch: String,
    pub state: ReconnectState,
    pub observed_at: i64,
    pub source: ObservationSource,
}
