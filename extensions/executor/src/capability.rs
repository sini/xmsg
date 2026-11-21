use crate::protocol::{EnvironmentDescriptor, Harness, Model};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustProfile {
    #[default]
    Safe,
    Unsafe,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReviewMode {
    #[default]
    HumanOnly,
    QualifiedOverseer,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub trust: TrustProfile,
    pub review: ReviewMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HarnessPin {
    pub id: String,
    pub harness: Harness,
    pub adapter: String,
    pub adapter_version: String,
    pub runtime_version: String,
    pub protocol_version: u16,
    pub source_revision: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualificationKey {
    pub pin_id: String,
    pub adapter_version: String,
    pub runtime_version: String,
    pub protocol_version: u16,
    pub profile: TrustProfile,
    pub native_mode: String,
    pub review_mode: ReviewMode,
    pub protocol_schema: String,
    pub model: Model,
    pub effective_config_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    FakeOnly,
    PinnedRuntime,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub class: EvidenceClass,
    pub key: QualificationKey,
    pub reference: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityState {
    Unproven { reason: String },
    NotSupported { reason: String },
    Proven { evidence: Box<Evidence> },
}
impl CapabilityState {
    /// Matches trusted record metadata only; it does not verify evidence provenance.
    pub fn matches_pinned_metadata(&self, key: &QualificationKey) -> bool {
        matches!(self,Self::Proven {evidence} if evidence.class==EvidenceClass::PinnedRuntime && evidence.key==*key && !evidence.reference.is_empty())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    StrictSteer,
    ConfirmedInterrupt,
    Reconnect,
    StoredResume,
    PendingApproval,
    HumanMandatoryProvenance,
    NativeChildren,
    PerCallControlBinding,
    ReviewerIsolation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEntry {
    pub capability: Capability,
    pub state: CapabilityState,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtectionState {
    ProvedRetained { evidence: Box<Evidence> },
    Unknown { reason: String },
    Lost { reason: String },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectionReport {
    pub hard_denials: ProtectionState,
    pub human_checkpoints: ProtectionState,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileContract {
    pub mode: TrustProfile,
    pub owner_selection_required: bool,
    pub protections: ProtectionReport,
}
impl ProfileContract {
    /// Structural trusted-config metadata, not caller authentication or a grant.
    pub fn validate_metadata(&self) -> Result<(), &'static str> {
        if self.mode == TrustProfile::Unsafe && !self.owner_selection_required {
            return Err("UNSAFE requires owner selection");
        }
        for state in [
            &self.protections.hard_denials,
            &self.protections.human_checkpoints,
        ] {
            if let ProtectionState::ProvedRetained { evidence } = state {
                if evidence.class != EvidenceClass::PinnedRuntime || evidence.reference.is_empty() {
                    return Err("retained protection requires pinned-runtime evidence metadata");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinContract {
    pub pin: HarnessPin,
    pub capabilities: Vec<CapabilityEntry>,
    pub profiles: Vec<ProfileContract>,
    pub qualification_backlog: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinManifest {
    pub version: u16,
    pub pins: Vec<PinContract>,
}

pub fn builtin_pins() -> Result<PinManifest, serde_json::Error> {
    serde_json::from_str(include_str!("../fixtures/pins.json"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDispatch {
    pub harness: Harness,
    pub model: Model,
    pub environment: EnvironmentDescriptor,
    pub profile: ProfileContract,
    pub qualification: QualificationKey,
    pub workspace: crate::protocol::WorkspaceSpec,
    pub required_capabilities: Vec<Capability>,
    pub budget: crate::protocol::ResourceBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchReceipt {
    pub operation: crate::protocol::OperationReceipt,
    pub requested: crate::protocol::DispatchOptions,
    pub resolved: Option<ResolvedDispatch>,
    pub observed: Option<QualificationKey>,
}
