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
    pub(crate) journal: Mutex<Journal>,
    uid: u32,
    credentials: ProvisionedCredentials,
    attestor: Box<dyn HostAttestor>,
    next_call: AtomicU64,
    bridge: Option<DaemonAttributionConfig>,
    runtime_epoch: String,
    clock: Box<dyn WallClock>,
}
pub use crate::auth::daemon::DaemonAttributionConfig;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCall {
    pub request: ControlRequest,
    #[serde(default)]
    pub caller_context: Option<xmsg::client::caller_attribution::CallerContext>,
}
pub(crate) trait WallClock: Send + Sync {
    fn now(&self) -> i64;
}
struct SystemClock;
impl WallClock for SystemClock {
    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}
impl ControlService {
    #[cfg(test)]
    pub(crate) fn fixture_attributed(mut self, principal: &str) -> Self {
        self.attestor = Box::new(auth::fake::FakeAttestor {
            principal: principal.into(),
            wrong_binding: false,
        });
        self
    }
    #[cfg(test)]
    pub(crate) fn fixture_call_count(&self) -> u64 {
        self.next_call.load(Ordering::Relaxed)
    }
    pub fn open(
        path: &Path,
        uid: u32,
        configuration: OwnerConfig,
        credentials: ProvisionedCredentials,
    ) -> Result<Self, ErrorCode> {
        configuration.validate()?;
        let database_path = crate::unix::private_parent(path, uid)?;
        let mut epoch = [0u8; 16];
        getrandom::fill(&mut epoch).map_err(|_| ErrorCode::Storage)?;
        Ok(Self {
            journal: Mutex::new(Journal::open(&database_path, &configuration)?),
            uid,
            credentials,
            attestor: Box::new(auth::Unavailable),
            next_call: AtomicU64::new(1),
            bridge: None,
            runtime_epoch: hex::encode(epoch),
            clock: Box::new(SystemClock),
        })
    }
    pub fn open_with_daemon_attribution(
        path: &Path,
        uid: u32,
        configuration: OwnerConfig,
        credentials: ProvisionedCredentials,
        bridge: DaemonAttributionConfig,
    ) -> Result<Self, ErrorCode> {
        bridge.validate(uid)?;
        let mut service = Self::open(path, uid, configuration, credentials)?;
        service.bridge = Some(bridge);
        Ok(service)
    }
    pub(crate) fn bridge_configured(&self) -> bool {
        self.bridge.is_some()
    }
    fn call_nonce(&self) -> Result<u64, ErrorCode> {
        let mut value = self.next_call.load(Ordering::Relaxed);
        loop {
            let next = value.checked_add(1).ok_or(ErrorCode::ResourceLimit)?;
            match self.next_call.compare_exchange_weak(
                value,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(previous) => return Ok(previous),
                Err(current) => value = current,
            }
        }
    }
    pub(crate) fn lifecycle_from_stream(
        &self,
        stream: &std::os::unix::net::UnixStream,
        call: LifecycleCall,
    ) -> Result<ControlReply, ErrorCode> {
        call.request
            .validate()
            .map_err(|_| ErrorCode::MalformedFrame)?;
        let bridge = self
            .bridge
            .clone()
            .ok_or(ErrorCode::AttestationUnavailable)?;
        let peer = crate::unix::peer(stream)?;
        let input = crate::journal::input_digest(&call.request)?;
        let binding = auth::CallBinding {
            peer,
            call_nonce: self.call_nonce()?,
            input_digest: input.clone(),
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let duplicate =
            xmsg::client::caller_attribution::with_fd_inheritance_gate(|| stream.try_clone())
                .map_err(|_| ErrorCode::Storage)?;
        let attestor = auth::daemon::ScopedDaemonAttestor::new(
            bridge,
            duplicate.into(),
            self.runtime_epoch.clone(),
            call.caller_context,
            deadline,
        )?;
        let principal = auth::principal(&attestor, &binding, self.uid)?;
        let mut journal = loop {
            match self.journal.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(ErrorCode::Storage),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(ErrorCode::DeadlineExpired);
                    }
                    std::thread::yield_now();
                }
            }
        };
        if std::time::Instant::now() >= deadline {
            return Err(ErrorCode::DeadlineExpired);
        }
        let old_timeout: u32 = journal
            .db
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .map_err(|_| ErrorCode::Storage)?;
        journal
            .db
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(|_| ErrorCode::Storage)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            journal.admit_bound(
                principal.id(),
                &input,
                &call.request,
                &|| self.clock.now(),
                deadline,
            )
        }));
        let restored = journal
            .db
            .busy_timeout(std::time::Duration::from_millis(u64::from(old_timeout)))
            .map_err(|_| ErrorCode::Storage);
        restored?;
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
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
            call_nonce: self.call_nonce()?,
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
