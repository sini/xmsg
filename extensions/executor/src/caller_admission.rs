use crate::{
    caller_policy::{
        CallerEligibility, CallerRecordReference, CallerRuntimeFacts, MissingTrustProperty,
        TrustedCallerContext,
    },
    control::ErrorCode,
};
use rusqlite::OptionalExtension;
use std::{collections::HashMap, sync::Mutex};

pub(crate) struct CallerAdmission {
    context: TrustedCallerContext,
    reference: CallerRecordReference,
}
impl CallerAdmission {
    pub(crate) fn receipt(&self) -> serde_json::Value {
        self.reference.journal_receipt()
    }
}
struct State {
    provider: CallerEligibility,
    facts: Option<CallerRuntimeFacts>,
    references: HashMap<i64, CallerAdmission>,
}
pub(crate) struct CallerAuthority {
    state: Mutex<State>,
}
fn error(property: MissingTrustProperty) -> ErrorCode {
    match property {
        MissingTrustProperty::ScopedCallerEvidence => ErrorCode::CallerScopeUnproven,
        MissingTrustProperty::ProtectedPolicyStore => ErrorCode::CallerPolicyStoreUnproven,
        MissingTrustProperty::ExactCallerQualification => ErrorCode::CallerQualificationUnavailable,
    }
}
fn storage(_: impl std::fmt::Display) -> ErrorCode {
    ErrorCode::Storage
}

impl CallerAuthority {
    pub(crate) fn reviewed() -> Self {
        Self {
            state: Mutex::new(State {
                provider: CallerEligibility::reviewed(),
                facts: None,
                references: HashMap::new(),
            }),
        }
    }
    pub(crate) fn qualify(
        &self,
        db: &rusqlite::Connection,
        context: TrustedCallerContext,
        revision: u64,
        now: i64,
    ) -> Result<CallerAdmission, ErrorCode> {
        let state = self.state.lock().map_err(storage)?;
        state.provider.require_protected_store().map_err(error)?;
        let facts = current_facts(
            state
                .facts
                .as_ref()
                .ok_or(ErrorCode::CallerArtifactUnproven)?,
        )?;
        let reference = state
            .provider
            .qualify(&context, &facts, revision, now)
            .map_err(error)?;
        require_not_revoked(db, &reference)?;
        Ok(CallerAdmission { context, reference })
    }
    pub(crate) fn bind(&self, id: i64, admission: CallerAdmission) -> Result<(), ErrorCode> {
        let mut state = self.state.lock().map_err(storage)?;
        if state.references.contains_key(&id) {
            return Err(ErrorCode::RequestConflict);
        }
        state.references.insert(id, admission);
        Ok(())
    }
    pub(crate) fn discard(&self, id: i64) {
        if let Ok(mut state) = self.state.lock() {
            state.references.remove(&id);
        }
    }
    pub(crate) fn require(
        &self,
        db: &rusqlite::Connection,
        id: i64,
        revision: u64,
        now: i64,
    ) -> Result<(), ErrorCode> {
        let state = self.state.lock().map_err(storage)?;
        state.provider.require_protected_store().map_err(error)?;
        let facts = current_facts(
            state
                .facts
                .as_ref()
                .ok_or(ErrorCode::CallerArtifactUnproven)?,
        )?;
        let reference = state
            .references
            .get(&id)
            .ok_or(ErrorCode::CallerReferenceUnavailable)?;
        let (principal,payload,receipt):(String,String,String)=db.query_row("SELECT a.principal,a.payload,c.receipt FROM admissions a JOIN caller_receipts c ON c.admission_id=a.id WHERE a.id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(storage)?.ok_or(ErrorCode::CallerReferenceUnavailable)?;
        let receipt: serde_json::Value = serde_json::from_str(&receipt).map_err(storage)?;
        let request: crate::protocol::ControlRequest =
            serde_json::from_str(&payload).map_err(storage)?;
        let digest = crate::journal::input_digest(&request)?;
        if principal != reference.context.principal()
            || receipt != reference.receipt()
            || receipt["context"]["binding"]["input_digest"] != digest
            || receipt["context"]["principal"] != principal
        {
            return Err(ErrorCode::AttestationBinding);
        }
        require_not_revoked(db, &reference.reference)?;
        state
            .provider
            .revalidate(
                &reference.reference,
                &reference.context,
                &facts,
                revision,
                now,
            )
            .map_err(error)
    }
    #[cfg(test)]
    pub(crate) fn fixture(executor_sha256: &str) -> Self {
        let (host, kernel) = crate::runtime_policy::runtime_envelope().unwrap();
        let facts = CallerRuntimeFacts {
            host,
            uid: xmsg::client::current_uid(),
            operating_system: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            kernel,
            executor_sha256: executor_sha256.into(),
            caller_artifact_sha256: "f".repeat(64),
            caller_configuration_sha256: "d".repeat(64),
            caller_pin_id: "fixture-caller-pin".into(),
            caller_runtime_version: "fixture-runtime".into(),
            caller_mode: "fixture-human-only".into(),
            caller_protocol: "fixture-cli-v1".into(),
        };
        let (provider, _, _) =
            CallerEligibility::fixture_integration("worker", facts.clone()).unwrap();
        Self {
            state: Mutex::new(State {
                provider,
                facts: Some(facts),
                references: HashMap::new(),
            }),
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture_add_principal(&self, principal: &str) -> Result<(), ErrorCode> {
        let mut state = self.state.lock().map_err(storage)?;
        let facts = state
            .facts
            .clone()
            .ok_or(ErrorCode::CallerArtifactUnproven)?;
        state
            .provider
            .fixture_add_principal(principal, facts)
            .map_err(error)
    }
    #[cfg(test)]
    pub(crate) fn fixture_policy_revision(
        &self,
        db: &rusqlite::Connection,
        revision: u64,
    ) -> Result<(), ErrorCode> {
        let mut state = self.state.lock().map_err(storage)?;
        let State {
            provider,
            references,
            ..
        } = &mut *state;
        for (id, admission) in references {
            provider
                .fixture_policy_revision(&mut admission.reference, revision)
                .map_err(error)?;
            let changed = db
                .execute(
                    "UPDATE caller_receipts SET receipt=?1 WHERE admission_id=?2",
                    rusqlite::params![
                        serde_json::to_string(&admission.receipt()).map_err(storage)?,
                        id
                    ],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(ErrorCode::CallerReferenceUnavailable);
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn fixture_expiry_before_admission(&self, expires_at: i64) -> Result<(), ErrorCode> {
        let mut state = self.state.lock().map_err(storage)?;
        if !state.references.is_empty() {
            return Err(ErrorCode::RequestConflict);
        }
        state
            .provider
            .fixture_expiry_before_admission(expires_at)
            .map_err(error)
    }
    #[cfg(test)]
    pub(crate) fn fixture_forget_references(&self) {
        self.state.lock().unwrap().references.clear();
    }
    #[cfg(test)]
    pub(crate) fn fixture_replace_reference_record(&self, id: i64) -> Result<(), ErrorCode> {
        let mut state = self.state.lock().map_err(storage)?;
        let reference = state
            .references
            .get(&id)
            .ok_or(ErrorCode::CallerReferenceUnavailable)?
            .reference
            .clone();
        state.provider.fixture_replace(&reference).map_err(error)
    }
    #[cfg(test)]
    pub(crate) fn restore_fixture(&self, db: &rusqlite::Connection) -> Result<(), ErrorCode> {
        let rows = {
            let mut query=db.prepare("SELECT a.id,a.principal,a.payload,c.receipt FROM admissions a JOIN caller_receipts c ON c.admission_id=a.id").map_err(crate::journal::metadata_error)?;
            let rows = query
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })
                .map_err(crate::journal::metadata_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(crate::journal::metadata_error)?;
            rows
        };
        let mut state = self.state.lock().map_err(storage)?;
        let facts = current_facts(
            state
                .facts
                .as_ref()
                .ok_or(ErrorCode::CallerArtifactUnproven)?,
        )?;
        for (id, principal, payload, raw) in rows {
            if state.references.contains_key(&id) {
                continue;
            }
            let request: crate::protocol::ControlRequest =
                serde_json::from_str(&payload).map_err(storage)?;
            let digest = crate::journal::input_digest(&request)?;
            let receipt: serde_json::Value = serde_json::from_str(&raw).map_err(storage)?;
            let revision = receipt["policy_revision"]
                .as_u64()
                .ok_or(ErrorCode::AttestationBinding)?;
            let (context, reference) = state
                .provider
                .fixture_restore(
                    &receipt,
                    &principal,
                    &digest,
                    &facts,
                    revision,
                    crate::runtime_process::unix_now()?,
                )
                .map_err(error)?;
            state
                .references
                .insert(id, CallerAdmission { context, reference });
        }
        Ok(())
    }
}

fn require_not_revoked(
    db: &rusqlite::Connection,
    reference: &CallerRecordReference,
) -> Result<(), ErrorCode> {
    let revoked:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM caller_revocations WHERE record_id=?1 AND record_revision=?2)",rusqlite::params![reference.id(),i64::try_from(reference.revision()).map_err(storage)?],|r|r.get(0)).map_err(storage)?;
    if revoked {
        Err(ErrorCode::CallerQualificationUnavailable)
    } else {
        Ok(())
    }
}

fn current_facts(template: &CallerRuntimeFacts) -> Result<CallerRuntimeFacts, ErrorCode> {
    let mut facts = template.clone();
    let (host, kernel) = crate::runtime_policy::runtime_envelope()?;
    facts.host = host;
    facts.kernel = kernel;
    facts.uid = xmsg::client::current_uid();
    facts.operating_system = std::env::consts::OS.into();
    facts.architecture = std::env::consts::ARCH.into();
    Ok(facts)
}
