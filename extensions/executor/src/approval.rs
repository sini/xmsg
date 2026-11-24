use crate::{
    acp::{HumanMandatoryProvenance, PermissionOption},
    control::ErrorCode,
    framing::RequestId,
    lifecycle::NativeBinding,
    protocol::{Action, ControlRequest},
};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanConfirmation {
    pub approval_id: String,
    pub operation_digest: String,
    pub confirmed_at: i64,
}
impl HumanConfirmation {
    pub(crate) fn validate(&self, request: &ControlRequest, now: i64) -> Result<(), ErrorCode> {
        let Action::Approve(args) = &request.action else {
            return Err(ErrorCode::HumanRequired);
        };
        if self.approval_id != args.approval_id
            || self.operation_digest != args.operation_digest
            || !now
                .checked_sub(self.confirmed_at)
                .is_some_and(|age| (0..=30).contains(&age))
        {
            return Err(ErrorCode::HumanRequired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDecisionCall {
    pub request: ControlRequest,
    pub confirmation: HumanConfirmation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativePending {
    pub(crate) approval_id: String,
    pub(crate) admission_id: i64,
    pub(crate) request_id: RequestId,
    pub(crate) binding: NativeBinding,
    pub(crate) turn_id: String,
    pub(crate) tool_call_id: String,
    pub(crate) operation_digest: String,
    pub(crate) policy_revision: u64,
    pub(crate) expires_at: i64,
    pub(crate) options: Vec<PermissionOption>,
    pub(crate) raw: serde_json::Value,
    pub(crate) human_mandatory_provenance: HumanMandatoryProvenance,
}

pub(crate) fn initialize(db: &rusqlite::Connection) -> Result<(), ErrorCode> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS native_pending(approval_id TEXT PRIMARY KEY,session_id TEXT NOT NULL,generation INTEGER NOT NULL,transport_epoch TEXT NOT NULL,turn_id TEXT NOT NULL,native_request_id TEXT NOT NULL,tool_call_id TEXT NOT NULL,record TEXT NOT NULL,state TEXT NOT NULL,UNIQUE(session_id,generation,transport_epoch,turn_id,native_request_id,tool_call_id));").map_err(|_|ErrorCode::Storage)
}

pub(crate) fn cancel_turn(
    tx: &Transaction<'_>,
    target: &crate::protocol::Target,
) -> Result<(), ErrorCode> {
    let crate::protocol::Target::Turn {
        session_id,
        generation,
        turn_id,
    } = target
    else {
        return Err(ErrorCode::StaleTurn);
    };
    let generation = i64::try_from(*generation).map_err(|_| ErrorCode::Storage)?;
    tx.execute(
        "UPDATE approvals SET consumed=1 WHERE session_id=?1 AND generation=?2 AND turn_id=?3",
        params![session_id, generation, turn_id],
    )
    .map_err(|_| ErrorCode::Storage)?;
    tx.execute("UPDATE native_pending SET state='cancelled' WHERE session_id=?1 AND generation=?2 AND turn_id=?3 AND state IN('pending','decision_recorded')",params![session_id,generation,turn_id]).map_err(|_|ErrorCode::Storage)?;
    let changed=tx.execute("UPDATE sessions SET state='cancelling' WHERE id=?1 AND generation=?2 AND active_turn=?3",params![session_id,generation,turn_id]).map_err(|_|ErrorCode::Storage)?;
    if changed != 1 {
        return Err(ErrorCode::StaleTurn);
    }
    Ok(())
}

pub(crate) fn disable_pending(tx: &Transaction<'_>) -> Result<(), ErrorCode> {
    tx.execute("UPDATE approvals SET consumed=1 WHERE consumed=0", [])
        .map_err(|_| ErrorCode::Storage)?;
    tx.execute(
        "UPDATE native_pending SET state='cancelled' WHERE state IN('pending','decision_recorded')",
        [],
    )
    .map_err(|_| ErrorCode::Storage)?;
    Ok(())
}

pub(crate) fn prepare_confirmation(
    tx: &Transaction<'_>,
    request: &ControlRequest,
    confirmation: Option<&HumanConfirmation>,
    clock: &dyn Fn() -> Result<i64, ErrorCode>,
    policy: Option<&crate::runtime_policy::RuntimePolicy>,
) -> Result<bool, ErrorCode> {
    let now = clock()?;
    let Action::Approve(args) = &request.action else {
        return Err(ErrorCode::HumanRequired);
    };
    let stored: Option<(String, String)> = tx
        .query_row(
            "SELECT record,state FROM native_pending WHERE approval_id=?1",
            [&args.approval_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| ErrorCode::Storage)?;
    let Some((raw, state)) = stored else {
        return if confirmation.is_some() {
            Err(ErrorCode::PendingMismatch)
        } else {
            Ok(false)
        };
    };
    confirmation
        .ok_or(ErrorCode::HumanRequired)?
        .validate(request, now)?;
    if state != "pending" {
        return Err(ErrorCode::AlreadyConsumed);
    }
    let pending: NativePending = serde_json::from_str(&raw).map_err(|_| ErrorCode::Storage)?;
    let Some(crate::protocol::Target::Turn {
        session_id,
        generation,
        turn_id,
    }) = &request.target
    else {
        return Err(ErrorCode::PendingMismatch);
    };
    let current = crate::lifecycle::binding(tx, session_id, *generation)?;
    let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=?1 AND generation=?2 AND active_turn=?3 AND state NOT IN('unknown','cancelling','ended'))",params![session_id,i64::try_from(*generation).map_err(|_|ErrorCode::Storage)?,turn_id],|r|r.get(0)).map_err(|_|ErrorCode::Storage)?;
    if !active {
        return Err(ErrorCode::StaleTurn);
    }
    if current != pending.binding
        || pending.turn_id != *turn_id
        || pending.approval_id != args.approval_id
        || pending.operation_digest != args.operation_digest
        || pending.expires_at != args.expires_at
        || pending.expires_at <= now
        || pending.policy_revision.to_string() != args.policy_revision
    {
        return Err(ErrorCode::PendingMismatch);
    }
    let (principal, original, target) = crate::lifecycle::effect_request(tx, pending.admission_id)?;
    let mut selected = crate::journal::Journal::require_native_effect(
        policy,
        tx,
        &principal,
        &original,
        &target,
        pending.admission_id,
        clock,
    )?;
    if !selected
        .required_capabilities
        .contains(&crate::capability::Capability::PendingApproval)
    {
        selected
            .required_capabilities
            .push(crate::capability::Capability::PendingApproval);
    }
    let configuration = crate::journal::config(tx)?;
    if pending.policy_revision != configuration.revision {
        return Err(ErrorCode::PendingMismatch);
    }
    policy.ok_or(ErrorCode::NotSupported)?.require_at(
        &selected,
        configuration.revision,
        clock,
        crate::journal::runtime_disabled(tx)?,
    )?;
    let valid = match args.decision {
        crate::protocol::Decision::AllowOnce => pending.options.iter().any(|p| {
            p.option_id == args.option_id && p.kind == crate::acp::PermissionKind::AllowOnce
        }),
        crate::protocol::Decision::Deny => {
            args.option_id == "@cancel"
                || pending.options.iter().any(|p| {
                    p.option_id == args.option_id
                        && p.kind == crate::acp::PermissionKind::RejectOnce
                })
        }
        crate::protocol::Decision::Escalate => false,
    };
    if !valid {
        return Err(ErrorCode::PendingMismatch);
    }
    let changed = tx
        .execute(
            "UPDATE approvals SET option_id=?1 WHERE id=?2 AND consumed=0",
            params![args.option_id, args.approval_id],
        )
        .map_err(|_| ErrorCode::Storage)?;
    if changed != 1 {
        return Err(ErrorCode::AlreadyConsumed);
    }
    Ok(true)
}

// Callback ingress stays internal until the supervisor pump is wired.
#[allow(dead_code)]
impl crate::journal::Journal {
    pub(crate) fn permission_event(
        &mut self,
        native: &NativeBinding,
        driver: &crate::acp::Driver,
        event: &crate::acp::Event,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<Option<NativePending>, ErrorCode> {
        if let crate::acp::Event::PendingPermission { request_id, .. } = event {
            self.record_native_pending(native, driver, request_id, clock)
                .map(Some)
        } else {
            Ok(None)
        }
    }
    pub(crate) fn record_native_pending(
        &mut self,
        native: &NativeBinding,
        driver: &crate::acp::Driver,
        id: &RequestId,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<NativePending, ErrorCode> {
        let Some(crate::acp::Event::PendingPermission {
            request_id,
            native_session_id,
            turn_id,
            tool_call_id,
            options,
            raw,
            human_mandatory_provenance,
        }) = driver.outstanding_permission(id)
        else {
            return Err(ErrorCode::PendingMismatch);
        };
        if native_session_id != native.native_session_id
            || driver.observed_model_id() != Some(native.native_model_id.as_str())
            || !driver.human_mode_observed()
        {
            return Err(ErrorCode::PendingMismatch);
        }
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
        if crate::lifecycle::binding(&tx, &native.identity.session_id, native.identity.generation)?
            != *native
        {
            return Err(ErrorCode::PendingMismatch);
        }
        let generation =
            i64::try_from(native.identity.generation).map_err(|_| ErrorCode::Storage)?;
        let (state, active): (String, Option<String>) = tx
            .query_row(
                "SELECT state,active_turn FROM sessions WHERE id=?1 AND generation=?2",
                params![native.identity.session_id, generation],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| ErrorCode::Storage)?
            .ok_or(ErrorCode::StaleGeneration)?;
        if matches!(state.as_str(), "cancelling" | "unknown" | "ended")
            || active.as_deref() != Some(turn_id.as_str())
        {
            return Err(ErrorCode::StaleTurn);
        }
        let admission:i64=tx.query_row("SELECT admission_id FROM native_operations WHERE session_id=?1 AND generation=?2 AND transport_epoch=?3 AND state='submitted' AND json_extract(command,'$.command')='prompt' AND json_extract(command,'$.turn_id')=?4 ORDER BY admission_id DESC LIMIT 1",params![native.identity.session_id,generation,native.transport_epoch,turn_id],|r|r.get(0)).optional().map_err(|_|ErrorCode::Storage)?.ok_or(ErrorCode::PendingMismatch)?;
        let (principal, original, target) = crate::lifecycle::effect_request(&tx, admission)?;
        let mut selected = crate::journal::Journal::require_native_effect(
            policy.as_deref(),
            &tx,
            &principal,
            &original,
            &target,
            admission,
            clock,
        )?;
        if !selected
            .required_capabilities
            .contains(&crate::capability::Capability::PendingApproval)
        {
            selected
                .required_capabilities
                .push(crate::capability::Capability::PendingApproval);
        }
        let configuration = crate::journal::config(&tx)?;
        policy
            .as_deref()
            .ok_or(ErrorCode::NotSupported)?
            .require_at(
                &selected,
                configuration.revision,
                clock,
                crate::journal::runtime_disabled(&tx)?,
            )?;
        let now = clock()?;
        let expires_at = original
            .deadline
            .unwrap_or(native.expires_at)
            .min(native.expires_at);
        if expires_at <= now {
            return Err(ErrorCode::DeadlineExpired);
        }
        let operation_digest = hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&raw).map_err(|_| ErrorCode::Storage)?,
        ));
        let rpc = serde_json::to_string(&request_id).map_err(|_| ErrorCode::Storage)?;
        let prior:Option<(String,String)>=tx.query_row("SELECT record,state FROM native_pending WHERE session_id=?1 AND generation=?2 AND transport_epoch=?3 AND turn_id=?4 AND native_request_id=?5 AND tool_call_id=?6",params![native.identity.session_id,generation,native.transport_epoch,turn_id,rpc,tool_call_id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|ErrorCode::Storage)?;
        if let Some((record, state)) = prior {
            let previous: NativePending =
                serde_json::from_str(&record).map_err(|_| ErrorCode::Storage)?;
            if previous.operation_digest != operation_digest {
                return Err(ErrorCode::RequestConflict);
            }
            if state != "pending" {
                return Err(ErrorCode::AlreadyConsumed);
            }
            return Ok(previous);
        }
        let (count,prior_bytes):(i64,i64)=tx.query_row("SELECT COALESCE(SUM(CASE WHEN state IN('pending','decision_recorded') THEN 1 ELSE 0 END),0),COALESCE(SUM(length(CAST(record AS BLOB))),0) FROM native_pending WHERE session_id=?1 AND generation=?2",params![native.identity.session_id,generation],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|ErrorCode::Storage)?;
        if count >= 32 {
            return Err(ErrorCode::ResourceLimit);
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| ErrorCode::Storage)?;
        let pending = NativePending {
            approval_id: hex::encode(random),
            admission_id: admission,
            request_id,
            binding: native.clone(),
            turn_id,
            tool_call_id,
            operation_digest,
            policy_revision: configuration.revision,
            expires_at,
            options,
            raw,
            human_mandatory_provenance,
        };
        let encoded = serde_json::to_string(&pending).map_err(|_| ErrorCode::Storage)?;
        if encoded.len() > crate::framing::MAX_FRAME_BYTES / 2
            || prior_bytes
                .checked_add(i64::try_from(encoded.len()).map_err(|_| ErrorCode::Storage)?)
                .is_none_or(|n| n > i64::from(selected.budget.max_content_bytes))
        {
            return Err(ErrorCode::ResourceLimit);
        }
        tx.execute(
            "INSERT INTO native_pending VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'pending')",
            params![
                pending.approval_id,
                native.identity.session_id,
                generation,
                native.transport_epoch,
                pending.turn_id,
                rpc,
                pending.tool_call_id,
                encoded
            ],
        )
        .map_err(|_| ErrorCode::Storage)?;
        tx.execute(
            "INSERT INTO approvals VALUES(?1,?2,?3,?4,?5,?6,?7,'',0)",
            params![
                pending.approval_id,
                native.identity.session_id,
                generation,
                pending.turn_id,
                pending.operation_digest,
                configuration.revision.to_string(),
                expires_at
            ],
        )
        .map_err(|_| ErrorCode::Storage)?;
        tx.execute(
            "UPDATE sessions SET state='needs_human' WHERE id=?1 AND generation=?2",
            params![native.identity.session_id, generation],
        )
        .map_err(|_| ErrorCode::Storage)?;
        tx.execute("INSERT INTO audit(principal,request_id,event,at) VALUES(?1,?2,'native_pending_created',?3)",params![principal,pending.approval_id,now]).map_err(|_|ErrorCode::Storage)?;
        tx.commit().map_err(|_| ErrorCode::Storage)?;
        Ok(pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ApproveArgs, Decision, Target};
    #[test]
    fn confirmation_is_exact_fresh_and_not_an_optional_yes_flag() {
        let request = ControlRequest {
            version: 1,
            request_id: "decision".into(),
            target: Some(Target::Turn {
                session_id: "session".into(),
                generation: 1,
                turn_id: "turn".into(),
            }),
            action: Action::Approve(ApproveArgs {
                approval_id: "approval".into(),
                operation_digest: "digest".into(),
                policy_revision: "1".into(),
                expires_at: 200,
                option_id: "once".into(),
                decision: Decision::AllowOnce,
            }),
            deadline: Some(200),
        };
        let mut confirmation = HumanConfirmation {
            approval_id: "approval".into(),
            operation_digest: "digest".into(),
            confirmed_at: 100,
        };
        assert_eq!(confirmation.validate(&request, 100), Ok(()));
        confirmation.operation_digest = "other".into();
        assert_eq!(
            confirmation.validate(&request, 100),
            Err(ErrorCode::HumanRequired)
        );
        confirmation.operation_digest = "digest".into();
        assert!(confirmation.validate(&request, 131).is_err());
        assert!(confirmation.validate(&request, 99).is_err());
        assert!(serde_json::from_value::<HumanDecisionCall>(
            serde_json::json!({"request":request,"yes":true})
        )
        .is_err());
    }
}
