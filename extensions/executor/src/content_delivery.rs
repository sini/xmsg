use crate::{
    acp::{Command, Driver},
    capability::ResolvedDispatch,
    control::ErrorCode,
    journal::Journal,
    lifecycle::NativeBinding,
    membership::ContentRecord,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

fn storage(_: impl std::fmt::Display) -> ErrorCode {
    ErrorCode::Storage
}
fn generation(native: &NativeBinding) -> Result<i64, ErrorCode> {
    i64::try_from(native.identity.generation).map_err(storage)
}

pub(crate) fn initialize(db: &rusqlite::Connection) -> Result<(), ErrorCode> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS native_content(message_id TEXT NOT NULL,session_id TEXT NOT NULL,generation INTEGER NOT NULL,transport_epoch TEXT NOT NULL,origin_admission INTEGER NOT NULL,state TEXT NOT NULL,command TEXT NOT NULL,rpc_id TEXT,PRIMARY KEY(session_id,generation,message_id));").map_err(storage)
}

pub(crate) fn prompt_admission(
    db: &rusqlite::Connection,
    native: &NativeBinding,
    turn: &str,
) -> Result<i64, ErrorCode> {
    let mut query=db.prepare("SELECT admission_id FROM native_operations WHERE session_id=?1 AND generation=?2 AND transport_epoch=?3 AND state='submitted' AND json_extract(command,'$.command')='prompt' AND json_extract(command,'$.turn_id')=?4 UNION ALL SELECT origin_admission FROM native_content WHERE session_id=?1 AND generation=?2 AND transport_epoch=?3 AND state='submitted' AND json_extract(command,'$.command')='prompt' AND json_extract(command,'$.turn_id')=?4").map_err(storage)?;
    let rows = query
        .query_map(
            params![
                native.identity.session_id,
                generation(native)?,
                native.transport_epoch,
                turn
            ],
            |r| r.get::<_, i64>(0),
        )
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    if rows.len() != 1 {
        return Err(ErrorCode::PendingMismatch);
    }
    Ok(rows[0])
}

fn require_content(
    tx: &Transaction<'_>,
    native: &NativeBinding,
    policy: Option<&crate::runtime_policy::RuntimePolicy>,
    active: Option<&str>,
    clock: &dyn Fn() -> Result<i64, ErrorCode>,
) -> Result<(i64, ResolvedDispatch), ErrorCode> {
    let policy = policy.ok_or(ErrorCode::NotSupported)?;
    if !policy
        .configuration
        .bus
        .as_ref()
        .is_some_and(|bus| bus.auto_input)
    {
        return Err(ErrorCode::NotSupported);
    }
    if crate::lifecycle::binding(tx, &native.identity.session_id, native.identity.generation)?
        != *native
    {
        return Err(ErrorCode::PendingMismatch);
    }
    if native.expires_at <= clock()? {
        return Err(ErrorCode::DeadlineExpired);
    }
    let id:i64=tx.query_row("SELECT admission_id FROM executions WHERE session_id=?1 AND generation=?2 AND identity=?3 AND state='running'",params![native.identity.session_id,generation(native)?,serde_json::to_string(&native.identity).map_err(storage)?],|r|r.get(0)).optional().map_err(storage)?.ok_or(ErrorCode::StaleGeneration)?;
    let (state, current): (String, Option<String>) = tx
        .query_row(
            "SELECT state,active_turn FROM sessions WHERE id=?1 AND generation=?2",
            params![native.identity.session_id, generation(native)?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(storage)?;
    if matches!(
        state.as_str(),
        "unknown" | "cancelling" | "ended" | "failed"
    ) || current.as_deref() != active
    {
        return Err(ErrorCode::StaleTurn);
    }
    let (principal, request, target) = crate::lifecycle::effect_request(tx, id)?;
    let resolved =
        Journal::require_native_effect(Some(policy), tx, &principal, &request, &target, id, clock)?;
    Ok((id, resolved))
}

impl Journal {
    pub(crate) fn submit_content(
        &mut self,
        native: &NativeBinding,
        driver: &mut Driver,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
        writer: &mut crate::supervisor::DeadlineIo<'_, impl std::io::Write + std::os::fd::AsRawFd>,
    ) -> Result<bool, ErrorCode> {
        if driver.active_turn_id().is_some() || !driver.human_mode_observed() {
            return Ok(false);
        }
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (origin, _) = require_content(&tx, native, policy.as_deref(), None, clock)?;
        let brief_ended:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM native_operations WHERE admission_id=?1 AND state='turn_ended')",[origin],|r|r.get(0)).map_err(storage)?;
        if !brief_ended {
            return Ok(false);
        }
        let next:Option<(String,String)>=tx.query_row("SELECT c.message_id,c.record FROM execution_content c WHERE c.session_id=?1 AND c.generation=?2 AND NOT EXISTS(SELECT 1 FROM native_content n WHERE n.session_id=c.session_id AND n.generation=c.generation AND n.message_id=c.message_id) ORDER BY c.rowid LIMIT 1",params![native.identity.session_id,generation(native)?],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage)?;
        let Some((message_id, raw)) = next else {
            return Ok(false);
        };
        let content: ContentRecord = serde_json::from_str(&raw).map_err(storage)?;
        if content.message_id != message_id {
            return Err(ErrorCode::RequestConflict);
        }
        let sequence: i64 = tx
            .query_row(
                "SELECT turn_sequence FROM native_bindings WHERE session_id=?1 AND generation=?2",
                params![native.identity.session_id, generation(native)?],
                |r| r.get(0),
            )
            .map_err(storage)?;
        let sequence = sequence.checked_add(1).ok_or(ErrorCode::ResourceLimit)?;
        let turn_id = format!("content-{}-{sequence}", native.identity.generation);
        let command = Command::Prompt {
            native_session_id: native.native_session_id.clone(),
            turn_id: turn_id.clone(),
            text: content.text,
        };
        let encoded = serde_json::to_string(&command).map_err(storage)?;
        tx.execute(
            "INSERT INTO native_content VALUES(?1,?2,?3,?4,?5,'submitting',?6,NULL)",
            params![
                message_id,
                native.identity.session_id,
                generation(native)?,
                native.transport_epoch,
                origin,
                encoded
            ],
        )
        .map_err(storage)?;
        tx.execute(
            "UPDATE native_bindings SET turn_sequence=?1 WHERE session_id=?2 AND generation=?3",
            params![sequence, native.identity.session_id, generation(native)?],
        )
        .map_err(storage)?;
        tx.execute(
            "UPDATE sessions SET active_turn=?1,state='foreground' WHERE id=?2 AND generation=?3",
            params![turn_id, native.identity.session_id, generation(native)?],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        let frame = match driver.begin(command) {
            Ok(frame) => frame,
            Err(_) => {
                self.db.execute("UPDATE native_content SET state='not_supported' WHERE session_id=?1 AND generation=?2 AND message_id=?3",params![native.identity.session_id,generation(native)?,message_id]).map_err(storage)?;
                self.db.execute("UPDATE sessions SET active_turn=NULL,state='background' WHERE id=?1 AND generation=?2 AND active_turn=?3",params![native.identity.session_id,generation(native)?,turn_id]).map_err(storage)?;
                return Err(ErrorCode::NotSupported);
            }
        };
        let result = (|| {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            require_content(&tx, native, policy.as_deref(), Some(&turn_id), clock)?;
            let still_submitting:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM native_content WHERE session_id=?1 AND generation=?2 AND message_id=?3 AND transport_epoch=?4 AND state='submitting')",params![native.identity.session_id,generation(native)?,message_id,native.transport_epoch],|r|r.get(0)).map_err(storage)?;
            if !still_submitting {
                return Err(ErrorCode::RequestConflict);
            }
            writer.limit_to(std::time::Instant::now() + std::time::Duration::from_secs(2));
            crate::framing::write_frame(writer, &frame).map_err(storage)?;
            let crate::framing::Frame::Request(request) = &frame else {
                return Err(ErrorCode::RequestConflict);
            };
            tx.execute("UPDATE native_content SET state='submitted',rpc_id=?1 WHERE session_id=?2 AND generation=?3 AND message_id=?4 AND state='submitting'",params![serde_json::to_string(&request.id).map_err(storage)?,native.identity.session_id,generation(native)?,message_id]).map_err(storage)?;
            tx.commit().map_err(storage)
        })();
        if let Err(error) = result {
            driver.transport_lost();
            self.db.execute("UPDATE native_content SET state='unknown' WHERE session_id=?1 AND generation=?2 AND message_id=?3",params![native.identity.session_id,generation(native)?,message_id]).map_err(storage)?;
            self.native_transport_unknown(native)?;
            return Err(error);
        }
        Ok(true)
    }
}
