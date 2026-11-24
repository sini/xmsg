use crate::{
    acp::{Command, Driver},
    capability::{Capability, ResolvedDispatch},
    control::ErrorCode,
    execution::ExecutionIdentity,
    journal::{self, Journal},
    protocol::{Action, ControlRequest, Target},
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

const MAX_QUEUED: i64 = 32;

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeBinding {
    pub(crate) identity: ExecutionIdentity,
    pub(crate) native_session_id: String,
    pub(crate) transport_epoch: String,
    pub(crate) native_mode: String,
    pub(crate) expires_at: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeSubmission {
    pub(crate) admission_id: i64,
    pub(crate) binding: NativeBinding,
    pub(crate) command: Command,
}

pub(crate) fn initialize(db: &Connection) -> Result<(), ErrorCode> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS native_bindings(session_id TEXT NOT NULL,generation INTEGER NOT NULL,binding TEXT NOT NULL,turn_sequence INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(session_id,generation));
      CREATE TABLE IF NOT EXISTS native_operations(admission_id INTEGER PRIMARY KEY,session_id TEXT NOT NULL,generation INTEGER NOT NULL,transport_epoch TEXT NOT NULL,enqueued_sequence INTEGER NOT NULL,state TEXT NOT NULL,command TEXT);").map_err(storage)
}

fn storage(_: impl std::fmt::Display) -> ErrorCode {
    ErrorCode::Storage
}
fn integer(value: u64) -> Result<i64, ErrorCode> {
    i64::try_from(value).map_err(storage)
}

fn binding(db: &Connection, session: &str, generation: u64) -> Result<NativeBinding, ErrorCode> {
    let raw: String = db
        .query_row(
            "SELECT binding FROM native_bindings WHERE session_id=?1 AND generation=?2",
            params![session, integer(generation)?],
            |r| r.get(0),
        )
        .optional()
        .map_err(storage)?
        .ok_or(ErrorCode::UnknownTarget)?;
    serde_json::from_str(&raw).map_err(storage)
}

fn effect_request(db: &Connection, id: i64) -> Result<(String, ControlRequest, Target), ErrorCode> {
    let row: Option<(String, String, String, Option<String>)> = db
        .query_row(
            "SELECT principal,payload,target,session_id FROM admissions WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(storage)?;
    let (principal, request, target, session) = row.ok_or(ErrorCode::UnknownTarget)?;
    let request: ControlRequest = serde_json::from_str(&request).map_err(storage)?;
    let target = if matches!(request.action, Action::Dispatch(_)) {
        let session_id = session.ok_or(ErrorCode::UnknownTarget)?;
        let generation: i64 = db
            .query_row(
                "SELECT generation FROM executions WHERE admission_id=?1 AND session_id=?2",
                params![id, session_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or(ErrorCode::UnknownTarget)?;
        Target::Execution {
            session_id,
            generation: u64::try_from(generation).map_err(storage)?,
        }
    } else {
        serde_json::from_str(&target).map_err(storage)?
    };
    Ok((principal, request, target))
}

fn addressed(target: &Target) -> Result<(&str, u64), ErrorCode> {
    match target {
        Target::Execution {
            session_id,
            generation,
        }
        | Target::Turn {
            session_id,
            generation,
            ..
        } => Ok((session_id, *generation)),
        _ => Err(ErrorCode::UnknownTarget),
    }
}

impl Journal {
    pub(crate) fn submit_native(
        &mut self,
        id: i64,
        driver: &mut Driver,
        epoch: &str,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
        writer: &mut crate::supervisor::DeadlineIo<'_, impl std::io::Write + std::os::fd::AsRawFd>,
    ) -> Result<bool, ErrorCode> {
        let Some(submission) = self.reserve_native(id, driver, epoch, clock)? else {
            return Ok(false);
        };
        let frame = match driver.begin(submission.command.clone()) {
            Ok(frame) => frame,
            Err(_) => {
                self.db.execute("UPDATE native_operations SET state='not_supported' WHERE admission_id=?1 AND state='submitting'",[id]).map_err(storage)?;
                if let Command::Prompt { turn_id, .. } = &submission.command {
                    if driver.active_turn_id() != Some(turn_id.as_str()) {
                        self.db.execute("UPDATE sessions SET active_turn=NULL WHERE id=?1 AND generation=?2 AND active_turn=?3",params![submission.binding.identity.session_id,integer(submission.binding.identity.generation)?,turn_id]).map_err(storage)?;
                    }
                }
                return Err(ErrorCode::NotSupported);
            }
        };
        let policy = self.runtime_policy.clone();
        let result = (|| {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let (principal, request, target) = effect_request(&tx, id)?;
            Self::require_native_effect(
                policy.as_deref(),
                &tx,
                &principal,
                &request,
                &target,
                id,
                clock,
            )?;
            let current = binding(
                &tx,
                &submission.binding.identity.session_id,
                submission.binding.identity.generation,
            )?;
            if current != submission.binding || current.transport_epoch != epoch {
                return Err(ErrorCode::PendingMismatch);
            }
            let now = clock()?;
            if current.expires_at <= now || request.deadline.is_some_and(|at| at <= now) {
                return Err(ErrorCode::DeadlineExpired);
            }
            let submitting:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM native_operations WHERE admission_id=?1 AND state='submitting' AND transport_epoch=?2)",params![id,epoch],|r|r.get(0)).map_err(storage)?;
            if !submitting {
                return Err(ErrorCode::RequestConflict);
            }
            crate::framing::write_frame(writer, &frame).map_err(|_| ErrorCode::Storage)?;
            tx.execute("UPDATE native_operations SET state='submitted' WHERE admission_id=?1 AND state='submitting'",[id]).map_err(storage)?;
            tx.commit().map_err(storage)
        })();
        if let Err(error) = result {
            driver.transport_lost();
            self.native_write_unknown(&submission)?;
            return Err(error);
        }
        Ok(true)
    }

    fn native_write_unknown(&self, submission: &NativeSubmission) -> Result<(), ErrorCode> {
        self.db
            .execute(
                "UPDATE native_operations SET state='unknown' WHERE admission_id=?1",
                [submission.admission_id],
            )
            .map_err(storage)?;
        self.db
            .execute(
                "UPDATE sessions SET state='unknown' WHERE id=?1 AND generation=?2",
                params![
                    submission.binding.identity.session_id,
                    integer(submission.binding.identity.generation)?
                ],
            )
            .map_err(storage)?;
        Ok(())
    }

    fn require_native_effect(
        policy: Option<&crate::runtime_policy::RuntimePolicy>,
        db: &rusqlite::Transaction<'_>,
        principal: &str,
        request: &ControlRequest,
        target: &Target,
        admission_id: i64,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<ResolvedDispatch, ErrorCode> {
        let now = clock()?;
        let configuration = journal::config(db)?;
        let mut selected = if matches!(request.action, Action::Dispatch(_)) {
            let (session, generation) = addressed(target)?;
            let current: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sessions WHERE id=?1 AND generation=?2)",
                    params![session, integer(generation)?],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if !current {
                return Err(ErrorCode::StaleGeneration);
            }
            crate::execution::revalidate_dispatch(db, admission_id, now)?
        } else {
            let (current, _) =
                journal::admit_new(db, &configuration, principal, request, now, true)?;
            if current != *target {
                return Err(ErrorCode::StaleGeneration);
            }
            journal::resolved_for_target(db, target)?
        };
        if matches!(request.action, Action::Steer(_))
            && !selected
                .required_capabilities
                .contains(&Capability::StrictSteer)
        {
            selected.required_capabilities.push(Capability::StrictSteer);
        }
        policy.ok_or(ErrorCode::NotSupported)?.require_at(
            &selected,
            configuration.revision,
            clock,
            journal::runtime_disabled(db)?,
        )?;
        let at = clock()?;
        if request.deadline.is_some_and(|deadline| deadline <= at) {
            return Err(ErrorCode::DeadlineExpired);
        }
        Ok(selected)
    }

    pub(crate) fn bind_native(
        &mut self,
        native: &NativeBinding,
        now: i64,
    ) -> Result<(), ErrorCode> {
        if native.native_session_id.is_empty()
            || native.native_session_id.len() > 128
            || native.transport_epoch.len() != 32
            || !native
                .transport_epoch
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || native.expires_at <= now
        {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let identity = serde_json::to_string(&native.identity).map_err(storage)?;
        let id: i64 = tx.query_row("SELECT admission_id FROM executions WHERE session_id=?1 AND generation=?2 AND identity=?3 AND state IN('spawn_intent','running')",params![native.identity.session_id,integer(native.identity.generation)?,identity],|r|r.get(0)).optional().map_err(storage)?.ok_or(ErrorCode::StaleGeneration)?;
        let selected = crate::execution::revalidate_dispatch(&tx, id, now)?;
        let configuration = journal::config(&tx)?;
        if native.native_mode != selected.qualification.native_mode {
            return Err(ErrorCode::ProfileDenied);
        }
        self.runtime_policy
            .as_deref()
            .ok_or(ErrorCode::NotSupported)?
            .require(
                &selected,
                configuration.revision,
                now,
                journal::runtime_disabled(&tx)?,
            )?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT binding FROM native_bindings WHERE session_id=?1 AND generation=?2",
                params![
                    native.identity.session_id,
                    integer(native.identity.generation)?
                ],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        let raw = serde_json::to_string(native).map_err(storage)?;
        if prior.as_ref().is_some_and(|p| p != &raw) {
            return Err(ErrorCode::RequestConflict);
        }
        tx.execute(
            "INSERT OR IGNORE INTO native_bindings(session_id,generation,binding) VALUES(?1,?2,?3)",
            params![
                native.identity.session_id,
                integer(native.identity.generation)?,
                raw
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    pub(crate) fn queue_native(
        &mut self,
        id: i64,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<(), ErrorCode> {
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (principal, request, target) = effect_request(&tx, id)?;
        if !matches!(
            request.action,
            Action::Dispatch(_) | Action::Send(_) | Action::Steer(_) | Action::Interrupt(_)
        ) {
            return Err(ErrorCode::NotSupported);
        }
        let selected = Self::require_native_effect(
            policy.as_deref(),
            &tx,
            &principal,
            &request,
            &target,
            id,
            clock,
        )?;
        let now = clock()?;
        let (session, generation) = addressed(&target)?;
        let native = binding(&tx, session, generation)?;
        if native.expires_at <= now {
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
            return Ok(());
        }
        let (count,bytes):(i64,i64) = tx.query_row("SELECT COUNT(*),COALESCE(SUM(length(CAST(a.payload AS BLOB))),0) FROM native_operations n JOIN admissions a ON a.id=n.admission_id WHERE n.session_id=?1 AND n.generation=?2 AND n.state='queued'",params![session,integer(generation)?],|r|Ok((r.get(0)?,r.get(1)?))).map_err(storage)?;
        let content: i64 = tx.query_row("SELECT COALESCE(SUM(bytes),0) FROM execution_content WHERE session_id=?1 AND generation=?2",params![session,integer(generation)?],|r|r.get(0)).map_err(storage)?;
        let size =
            i64::try_from(serde_json::to_vec(&request).map_err(storage)?.len()).map_err(storage)?;
        if count >= MAX_QUEUED
            || bytes
                .checked_add(content)
                .and_then(|n| n.checked_add(size))
                .is_none_or(|n| n > i64::from(selected.budget.max_content_bytes))
        {
            return Err(ErrorCode::ResourceLimit);
        }
        let sequence: i64 = tx
            .query_row(
                "SELECT turn_sequence FROM native_bindings WHERE session_id=?1 AND generation=?2",
                params![session, integer(generation)?],
                |r| r.get(0),
            )
            .map_err(storage)?;
        tx.execute(
            "INSERT INTO native_operations VALUES(?1,?2,?3,?4,?5,'queued',NULL)",
            params![
                id,
                session,
                integer(generation)?,
                native.transport_epoch,
                sequence
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    pub(crate) fn reserve_native(
        &mut self,
        id: i64,
        driver: &Driver,
        transport_epoch: &str,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<Option<NativeSubmission>, ErrorCode> {
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (principal, request, target) = effect_request(&tx, id)?;
        let selected = Self::require_native_effect(
            policy.as_deref(),
            &tx,
            &principal,
            &request,
            &target,
            id,
            clock,
        )?;
        let now = clock()?;
        let (session, generation) = addressed(&target)?;
        let native = binding(&tx, session, generation)?;
        let running:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM executions WHERE session_id=?1 AND generation=?2 AND identity=?3 AND state='running')",params![session,integer(generation)?,serde_json::to_string(&native.identity).map_err(storage)?],|r|r.get(0)).map_err(storage)?;
        if !running {
            return Err(ErrorCode::UnknownTarget);
        }
        let (epoch,sequence,state):(String,i64,String) = tx.query_row("SELECT transport_epoch,enqueued_sequence,state FROM native_operations WHERE admission_id=?1 AND session_id=?2 AND generation=?3",params![id,session,integer(generation)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(storage)?.ok_or(ErrorCode::UnknownTarget)?;
        if state != "queued" {
            return Err(ErrorCode::RequestConflict);
        }
        if epoch != native.transport_epoch
            || transport_epoch != native.transport_epoch
            || driver.native_session_id() != Some(native.native_session_id.as_str())
            || driver.turn_is_unknown()
        {
            return Err(ErrorCode::PendingMismatch);
        }
        if native.expires_at <= now {
            return Err(ErrorCode::DeadlineExpired);
        }
        if native.native_mode != selected.qualification.native_mode || !driver.human_mode_observed()
        {
            return Err(ErrorCode::ProfileDenied);
        }
        let active: Option<String> = tx
            .query_row(
                "SELECT active_turn FROM sessions WHERE id=?1 AND generation=?2",
                params![session, integer(generation)?],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if active.as_deref() != driver.active_turn_id() {
            return Err(ErrorCode::StaleTurn);
        }
        let command = match &request.action {
            Action::Dispatch(args) => {
                if active.is_some() {
                    return Ok(None);
                }
                Command::Prompt {
                    native_session_id: native.native_session_id.clone(),
                    turn_id: format!("turn-{id}"),
                    text: args.brief.clone(),
                }
            }
            Action::Send(args) => {
                if let Some(prefer) = &args.prefer_live {
                    if prefer.deadline <= now {
                        return Err(ErrorCode::DeadlineExpired);
                    }
                    if active.is_some() {
                        let mut live = selected.clone();
                        if !live
                            .required_capabilities
                            .contains(&Capability::StrictSteer)
                        {
                            live.required_capabilities.push(Capability::StrictSteer);
                        }
                        let configuration = journal::config(&tx)?;
                        match policy
                            .as_deref()
                            .ok_or(ErrorCode::NotSupported)?
                            .require_at(
                                &live,
                                configuration.revision,
                                clock,
                                journal::runtime_disabled(&tx)?,
                            ) {
                            Ok(()) => Command::Steer {
                                native_session_id: native.native_session_id.clone(),
                                turn_id: active.clone().ok_or(ErrorCode::StaleTurn)?,
                                text: args.text.clone(),
                            },
                            Err(ErrorCode::NotSupported) if prefer.next_turn_allowance > 0 => {
                                return Ok(None)
                            }
                            Err(error) => return Err(error),
                        }
                    } else {
                        let current:i64=tx.query_row("SELECT turn_sequence FROM native_bindings WHERE session_id=?1 AND generation=?2",params![session,integer(generation)?],|r|r.get(0)).map_err(storage)?;
                        if current.saturating_sub(sequence) >= i64::from(prefer.next_turn_allowance)
                        {
                            return Err(ErrorCode::DeadlineExpired);
                        }
                        Command::Prompt {
                            native_session_id: native.native_session_id.clone(),
                            turn_id: format!("turn-{id}"),
                            text: args.text.clone(),
                        }
                    }
                } else if active.is_some() {
                    return Ok(None);
                } else {
                    Command::Prompt {
                        native_session_id: native.native_session_id.clone(),
                        turn_id: format!("turn-{id}"),
                        text: args.text.clone(),
                    }
                }
            }
            Action::Steer(args) => Command::Steer {
                native_session_id: native.native_session_id.clone(),
                turn_id: active.clone().ok_or(ErrorCode::StaleTurn)?,
                text: args.text.clone(),
            },
            Action::Interrupt(_) => Command::Cancel {
                native_session_id: native.native_session_id.clone(),
                turn_id: active.clone().ok_or(ErrorCode::StaleTurn)?,
            },
            _ => return Err(ErrorCode::NotSupported),
        };
        if let Command::Prompt { turn_id, .. } = &command {
            tx.execute(
                "UPDATE sessions SET active_turn=?1,state='working' WHERE id=?2 AND generation=?3",
                params![turn_id, session, integer(generation)?],
            )
            .map_err(storage)?;
            tx.execute("UPDATE native_bindings SET turn_sequence=turn_sequence+1 WHERE session_id=?1 AND generation=?2",params![session,integer(generation)?]).map_err(storage)?;
        }
        tx.execute("UPDATE native_operations SET state='submitting',command=?1 WHERE admission_id=?2 AND state='queued'",params![serde_json::to_string(&command).map_err(storage)?,id]).map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(Some(NativeSubmission {
            admission_id: id,
            binding: native,
            command,
        }))
    }
}
