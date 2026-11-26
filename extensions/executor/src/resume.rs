use crate::{
    control::{ControlService, ErrorCode},
    journal::Journal,
    lifecycle::NativeBinding,
    protocol::{Action, ObservationSource, ReconnectReport, ReconnectState, ResumeKind},
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
fn storage(_: impl std::fmt::Display) -> ErrorCode {
    ErrorCode::Storage
}

impl Journal {
    pub(crate) fn reserve_reconnect(
        &mut self,
        id: i64,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<Option<NativeBinding>, ErrorCode> {
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (principal, request, target) = crate::lifecycle::effect_request(&tx, id)?;
        if !matches!(
            request.action,
            Action::Resume(crate::protocol::ResumeArgs {
                kind: ResumeKind::Reconnect
            })
        ) {
            return Err(ErrorCode::NotSupported);
        }
        Self::require_native_effect(
            policy.as_deref(),
            &tx,
            &principal,
            &request,
            &target,
            id,
            clock,
        )?;
        let (session, generation) = match target {
            crate::protocol::Target::Execution {
                session_id,
                generation,
            } => (session_id, generation),
            _ => return Err(ErrorCode::StaleGeneration),
        };
        let native = crate::lifecycle::binding(&tx, &session, generation)?;
        if native.expires_at <= clock()? {
            return Err(ErrorCode::DeadlineExpired);
        }
        let existing: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM native_operations WHERE admission_id=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if existing {
            return Ok(None);
        }
        let current:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM executions WHERE session_id=?1 AND generation=?2 AND identity=?3 AND state IN('running','unknown'))",params![session,i64::try_from(generation).map_err(storage)?,serde_json::to_string(&native.identity).map_err(storage)?],|r|r.get(0)).map_err(storage)?;
        if !current {
            return Err(ErrorCode::UnknownTarget);
        }
        tx.execute(
            "INSERT INTO native_operations VALUES(?1,?2,?3,?4,0,'reconnecting',NULL,NULL)",
            params![
                id,
                session,
                i64::try_from(generation).map_err(storage)?,
                native.transport_epoch
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(Some(native))
    }
    pub(crate) fn finish_reconnect(
        &mut self,
        id: i64,
        native: &NativeBinding,
        live: bool,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<(), ErrorCode> {
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (principal, request, target) = crate::lifecycle::effect_request(&tx, id)?;
        let allowed = Self::require_native_effect(
            policy.as_deref(),
            &tx,
            &principal,
            &request,
            &target,
            id,
            clock,
        )
        .is_ok()
            && crate::lifecycle::binding(
                &tx,
                &native.identity.session_id,
                native.identity.generation,
            )? == *native;
        let running:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM executions e JOIN sessions s ON s.id=e.session_id WHERE e.session_id=?1 AND e.generation=?2 AND e.identity=?3 AND e.state='running' AND s.state NOT IN('unknown','cancelling','ended','failed'))",params![native.identity.session_id,i64::try_from(native.identity.generation).map_err(storage)?,serde_json::to_string(&native.identity).map_err(storage)?],|r|r.get(0)).map_err(storage)?;
        let confirmed = allowed && live && running && native.expires_at > clock()?;
        let report = ReconnectReport {
            session_id: native.identity.session_id.clone(),
            generation: native.identity.generation,
            native_session_id: native.native_session_id.clone(),
            transport_epoch: native.transport_epoch.clone(),
            state: if confirmed {
                ReconnectState::SameOwnedExecution
            } else {
                ReconnectState::Unknown
            },
            observed_at: clock()?,
            source: if live {
                ObservationSource::Supervisor
            } else {
                ObservationSource::Unknown
            },
        };
        let changed=tx.execute("UPDATE native_operations SET state=?1,command=?2 WHERE admission_id=?3 AND session_id=?4 AND generation=?5 AND transport_epoch=?6 AND state='reconnecting'",params![if confirmed {"reconnected"} else {"reconnect_unknown"},serde_json::to_string(&report).map_err(storage)?,id,native.identity.session_id,i64::try_from(native.identity.generation).map_err(storage)?,native.transport_epoch]).map_err(storage)?;
        if changed != 1 {
            return Err(ErrorCode::RequestConflict);
        }
        tx.execute("INSERT INTO audit(principal,request_id,event,at) SELECT principal,request_id,?2,?3 FROM admissions WHERE id=?1",params![id,if confirmed {"same_lease_reconnected"} else {"reconnect_unknown"},report.observed_at]).map_err(storage)?;
        tx.commit().map_err(storage)
    }
}

pub(crate) fn process_one(
    service: &ControlService,
    configuration: &crate::runtime_config::RuntimeConfig,
    clock: &dyn Fn() -> Result<i64, ErrorCode>,
) -> Result<(), ErrorCode> {
    let id: Option<i64> = {
        let journal = service.journal.lock().map_err(storage)?;
        journal.db.query_row("SELECT a.id FROM admissions a WHERE a.verb='\"resume\"' AND NOT EXISTS(SELECT 1 FROM native_operations n WHERE n.admission_id=a.id) ORDER BY a.id LIMIT 1",[],|r|r.get(0)).optional().map_err(storage)?
    };
    let Some(id) = id else { return Ok(()) };
    let Some(native) = service
        .journal
        .lock()
        .map_err(storage)?
        .reserve_reconnect(id, clock)?
    else {
        return Ok(());
    };
    let live =
        crate::supervisor::attach_existing(&configuration.paths.runtime_root, &native.identity)
            .is_ok_and(|hello| hello.running);
    service
        .journal
        .lock()
        .map_err(storage)?
        .finish_reconnect(id, &native, live, clock)
}
