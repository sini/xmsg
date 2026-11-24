use crate::{
    control::ErrorCode,
    journal::Journal,
    lifecycle::NativeBinding,
    membership::{
        CommitOutcome, ContentOperation, ContentRecord, ContentStore, MembershipError, ProxyBinding,
    },
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::time::Instant;

pub(crate) struct BoundContentJournal {
    journal: Journal,
    native: NativeBinding,
    expires: Instant,
    #[cfg(test)]
    clock: Option<i64>,
}
impl BoundContentJournal {
    pub(crate) fn new(journal: Journal, native: NativeBinding, expires: Instant) -> Self {
        Self {
            journal,
            native,
            expires,
            #[cfg(test)]
            clock: None,
        }
    }
    fn now(&self) -> Result<i64, ErrorCode> {
        #[cfg(test)]
        if let Some(now) = self.clock {
            return Ok(now);
        }
        crate::runtime_process::unix_now()
    }
}
impl ContentStore for BoundContentJournal {
    fn commit(
        &mut self,
        binding: &ProxyBinding,
        content: &ContentRecord,
    ) -> Result<CommitOutcome, MembershipError> {
        self.journal.commit(binding, content)
    }
    fn admit_outgoing(
        &mut self,
        binding: &ProxyBinding,
        operation: ContentOperation,
        key: &str,
    ) -> Result<(), MembershipError> {
        if key.len() != 64
            || !key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(MembershipError::ManagedEffectDenied);
        }
        let now = self
            .now()
            .map_err(|_| MembershipError::ManagedEffectDenied)?;
        let policy = self.journal.runtime_policy.clone();
        let tx = self
            .journal
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| MembershipError::Storage)?;
        let result = (|| {
            if Instant::now() >= self.expires || self.native.expires_at <= now {
                return Err(ErrorCode::DeadlineExpired);
            }
            if !policy
                .as_deref()
                .is_some_and(|p| p.configuration.bus.is_some())
            {
                return Err(ErrorCode::NotSupported);
            }
            if binding.session_id() != self.native.identity.session_id
                || binding.generation() != self.native.identity.generation
                || crate::lifecycle::binding(&tx, binding.session_id(), binding.generation())?
                    != self.native
            {
                return Err(ErrorCode::PendingMismatch);
            }
            let (admission,service,raw):(i64,String,String)=tx.query_row("SELECT e.admission_id,e.service_id,a.resolved FROM executions e JOIN admissions a ON a.id=e.admission_id JOIN sessions s ON s.id=e.session_id WHERE e.session_id=?1 AND e.generation=?2 AND e.identity=?3 AND e.state='running' AND s.generation=e.generation",params![binding.session_id(),i64::try_from(binding.generation()).map_err(|_|ErrorCode::Storage)?,serde_json::to_string(&self.native.identity).map_err(|_|ErrorCode::Storage)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_|ErrorCode::Storage)?.ok_or(ErrorCode::StaleGeneration)?;
            let resolved: crate::capability::ResolvedDispatch =
                serde_json::from_str(&raw).map_err(|_| ErrorCode::Storage)?;
            let service: [u8; 16] = hex::decode(service)
                .map_err(|_| ErrorCode::Storage)?
                .try_into()
                .map_err(|_| ErrorCode::Storage)?;
            let expected = ProxyBinding::new(
                binding.session_id().to_owned(),
                binding.generation(),
                service,
                resolved.budget.max_content_bytes as usize,
            )
            .map_err(|_| ErrorCode::Storage)?;
            if expected != *binding {
                return Err(ErrorCode::PendingMismatch);
            }
            let (principal, request, target) = crate::lifecycle::effect_request(&tx, admission)?;
            Journal::require_native_effect(
                policy.as_deref(),
                &tx,
                &principal,
                &request,
                &target,
                admission,
                &|| Ok(now),
            )?;
            Ok(())
        })();
        let event = match result {
            Ok(()) => format!("content_admitted:{}", operation.name()),
            Err(code) => format!("content_denied:{}:{code}", operation.name()),
        };
        tx.execute(
            "INSERT INTO audit(principal,request_id,event,at) VALUES('managed-content',?1,?2,?3)",
            params![key, event, now],
        )
        .map_err(|_| MembershipError::Storage)?;
        tx.commit().map_err(|_| MembershipError::Storage)?;
        result.map_err(|_| MembershipError::ManagedEffectDenied)
    }
}

#[cfg(test)]
pub(crate) struct ManagedContentFixture {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) service: crate::control::ControlService,
    pub(crate) store: crate::membership::SharedContentStore<BoundContentJournal>,
    pub(crate) binding: ProxyBinding,
    pub(crate) configuration: crate::runtime_config::RuntimeConfig,
    pub(crate) record: crate::eligibility::AdapterQualification,
    pub(crate) executor: std::sync::Arc<crate::runtime_config::ExecutableArtifact>,
}
#[cfg(test)]
impl ManagedContentFixture {
    fn peer(&self) -> crate::auth::PeerWitness {
        crate::auth::PeerWitness {
            uid: xmsg::client::current_uid(),
            pid: Some(std::process::id()),
        }
    }
    pub(crate) fn revoke(&self) -> Result<(), ErrorCode> {
        self.service
            .admin(
                self.peer(),
                b"synthetic-owner-only-proof-0000000000",
                crate::control::AdminCommand::RevokeCallerQualification {
                    request_id: "content-revoke".into(),
                    expected_revision: 1,
                    record_id: "fixture-caller".into(),
                    record_revision: 1,
                },
                103,
            )
            .map(|_| ())
    }
    pub(crate) fn disable(&mut self) -> Result<(), ErrorCode> {
        self.service.admin(
            self.peer(),
            b"synthetic-owner-only-proof-0000000000",
            crate::control::AdminCommand::DisableRuntime {
                request_id: "content-disable".into(),
                expected_revision: 1,
            },
            103,
        )?;
        self.record.policy_revision = 2;
        let current = self
            .service
            .journal
            .lock()
            .unwrap()
            .runtime_policy
            .clone()
            .unwrap();
        let updated = std::sync::Arc::new(current.fixture_with_adapter_records(
            self.configuration.clone(),
            vec![self.record.clone()],
            self.executor.clone(),
        ));
        self.service.journal.lock().unwrap().runtime_policy = Some(updated.clone());
        self.store
            .fixture_with_mut(|store| store.journal.runtime_policy = Some(updated));
        Ok(())
    }
    pub(crate) fn adapter_is_current(&self) -> bool {
        let mut journal = self.service.journal.lock().unwrap();
        let policy = journal.runtime_policy.clone().unwrap();
        let tx = journal.db.transaction().unwrap();
        let revision = crate::journal::config(&tx).unwrap().revision;
        policy
            .require(
                &self.configuration.control.defaults[0].resolved,
                revision,
                103,
                false,
            )
            .is_ok()
    }
}
#[cfg(test)]
pub(crate) fn fixture() -> ManagedContentFixture {
    crate::lifecycle::fixture_content_gate()
}

#[cfg(test)]
pub(crate) fn fixture_store(journal: Journal, native: NativeBinding) -> BoundContentJournal {
    journal.db.busy_timeout(std::time::Duration::ZERO).unwrap();
    let mut store = BoundContentJournal::new(
        journal,
        native,
        Instant::now() + std::time::Duration::from_secs(60),
    );
    store.clock = Some(103);
    store
}
