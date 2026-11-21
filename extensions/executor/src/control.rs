use crate::{
    auth::{self, CallBinding, CredentialRole, HostAttestor, PeerWitness, ProvisionedCredentials},
    capability::{ResolvedDispatch, TrustProfile},
    journal::Journal,
    protocol::{ControlRequest, OperationReceipt, Target},
};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    #[error("peer_uid")]
    PeerUid,
    #[error("attestation_unavailable")]
    AttestationUnavailable,
    #[error("attestation_binding")]
    AttestationBinding,
    #[error("grant_denied")]
    GrantDenied,
    #[error("request_conflict")]
    RequestConflict,
    #[error("stale_generation")]
    StaleGeneration,
    #[error("stale_turn")]
    StaleTurn,
    #[error("deadline_expired")]
    DeadlineExpired,
    #[error("profile_denied")]
    ProfileDenied,
    #[error("invalid_configuration")]
    InvalidConfiguration,
    #[error("unknown_target")]
    UnknownTarget,
    #[error("credential_denied")]
    CredentialDenied,
    #[error("human_required")]
    HumanRequired,
    #[error("pending_mismatch")]
    PendingMismatch,
    #[error("already_consumed")]
    AlreadyConsumed,
    #[error("not_supported")]
    NotSupported,
    #[error("resource_limit")]
    ResourceLimit,
    #[error("storage")]
    Storage,
    #[error("malformed_frame")]
    MalformedFrame,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerProfile {
    pub id: String,
    pub revision: String,
    pub project: String,
    pub harness: crate::protocol::Harness,
    pub environment: String,
    pub mode: TrustProfile,
    pub enabled: bool,
    pub owner_selected: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchTemplate {
    pub team_id: String,
    pub profile_id: String,
    pub resolved: ResolvedDispatch,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfig {
    pub revision: u64,
    pub local_host: String,
    pub grants: Vec<crate::auth::Grant>,
    pub profiles: Vec<OwnerProfile>,
    pub defaults: Vec<DispatchTemplate>,
}
impl OwnerConfig {
    pub(crate) fn validate(&self) -> Result<(), ErrorCode> {
        if self.revision == 0 || self.local_host.is_empty() {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let mut ids = std::collections::HashSet::new();
        for p in &self.profiles {
            if p.id.is_empty()
                || p.revision.is_empty()
                || !ids.insert(&p.id)
                || p.mode == TrustProfile::Unsafe && !p.owner_selected
            {
                return Err(ErrorCode::InvalidConfiguration);
            }
        }
        for d in &self.defaults {
            let p = self
                .profiles
                .iter()
                .find(|p| p.id == d.profile_id)
                .ok_or(ErrorCode::InvalidConfiguration)?;
            if d.resolved.environment.host != self.local_host
                || p.project != d.resolved.environment.project
                || p.harness != d.resolved.harness
                || p.environment != d.resolved.environment.id
                || p.id != d.resolved.environment.profile
                || p.mode != d.resolved.profile.mode
                || d.resolved.profile.validate_metadata().is_err()
                || d.resolved.budget.worker_slots == 0
            {
                return Err(ErrorCode::InvalidConfiguration);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminCommand {
    ReplacePolicy {
        request_id: String,
        expected_revision: u64,
        configuration: OwnerConfig,
    },
    RevokeProfile {
        request_id: String,
        expected_revision: u64,
        profile_id: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlReply {
    pub request_id: String,
    pub replayed: bool,
    pub historical: bool,
    pub receipt: OperationReceipt,
    pub dispatch: Option<AdmittedDispatch>,
    pub decision: Option<crate::protocol::ApproveArgs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedDispatch {
    pub session_id: String,
    pub resolved: ResolvedDispatch,
}

pub struct ControlService {
    journal: Mutex<Journal>,
    uid: u32,
    credentials: ProvisionedCredentials,
    attestor: Box<dyn HostAttestor>,
    next_call: AtomicU64,
}
impl ControlService {
    pub fn open(
        path: &Path,
        uid: u32,
        configuration: OwnerConfig,
        credentials: ProvisionedCredentials,
    ) -> Result<Self, ErrorCode> {
        configuration.validate()?;
        let database_path = crate::unix::private_parent(path, uid)?;
        Ok(Self {
            journal: Mutex::new(Journal::open(&database_path, &configuration)?),
            uid,
            credentials,
            attestor: Box::new(auth::Unavailable),
            next_call: AtomicU64::new(1),
        })
    }
    pub(crate) fn lifecycle(
        &self,
        peer: PeerWitness,
        request: ControlRequest,
        now: i64,
    ) -> Result<ControlReply, ErrorCode> {
        request.validate().map_err(|_| ErrorCode::MalformedFrame)?;
        let input = crate::journal::input_digest(&request)?;
        let binding = CallBinding {
            peer,
            call_nonce: self.next_call.fetch_add(1, Ordering::Relaxed),
            input_digest: input.clone(),
        };
        let principal = auth::principal(self.attestor.as_ref(), &binding, self.uid)?;
        self.journal.lock().map_err(|_| ErrorCode::Storage)?.admit(
            principal.id(),
            &input,
            &request,
            now,
        )
    }
    pub(crate) fn admin(
        &self,
        peer: PeerWitness,
        credential: &[u8],
        command: AdminCommand,
        now: i64,
    ) -> Result<u64, ErrorCode> {
        if peer.uid != self.uid {
            return Err(ErrorCode::PeerUid);
        }
        if !self.credentials.verify(credential, CredentialRole::Owner) {
            return Err(ErrorCode::CredentialDenied);
        }
        self.journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .admin(command, now)
    }
    pub(crate) fn human(
        &self,
        peer: PeerWitness,
        credential: &[u8],
        request: ControlRequest,
        now: i64,
    ) -> Result<ControlReply, ErrorCode> {
        if peer.uid != self.uid {
            return Err(ErrorCode::PeerUid);
        }
        if !self.credentials.verify(credential, CredentialRole::Human) {
            return Err(ErrorCode::CredentialDenied);
        }
        self.journal
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .human(request, now)
    }
}

pub(crate) fn resolved_target(target: &Target, generation: u64) -> Target {
    match target {
        Target::Session { session_id } => Target::Execution {
            session_id: session_id.clone(),
            generation,
        },
        other => other.clone(),
    }
}
