use crate::{
    capability::ResolvedDispatch,
    control::ErrorCode,
    journal::{self, Journal},
    membership::{CommitOutcome, ContentRecord, ContentStore, MembershipError, ProxyBinding},
    protocol::{Action, ControlRequest, Target, Verb},
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

pub(crate) const SUPERVISOR_PROTOCOL_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIdentity {
    pub session_id: String,
    pub generation: u64,
    pub launch_nonce: String,
    pub policy_revision: u64,
    pub protocol_version: u16,
    pub build_version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Reserved,
    SpawnIntent,
    Running,
    Unknown,
    Stopped,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionObservation {
    pub identity: ExecutionIdentity,
    pub state: ExecutionState,
    pub cursor: u64,
    pub diagnostic_pid: Option<u32>,
}

pub(crate) struct LaunchLease {
    pub(crate) admission_id: i64,
    pub(crate) identity: ExecutionIdentity,
    pub(crate) resolved: ResolvedDispatch,
    pub(crate) service_id: [u8; 16],
}
fn storage(_: impl std::fmt::Debug) -> ErrorCode {
    ErrorCode::Storage
}
fn nonce() -> Result<[u8; 16], ErrorCode> {
    let mut n = [0; 16];
    getrandom::fill(&mut n).map_err(storage)?;
    Ok(n)
}
fn integer(n: u64) -> Result<i64, ErrorCode> {
    i64::try_from(n).map_err(|_| ErrorCode::InvalidConfiguration)
}

pub(crate) fn initialize(db: &rusqlite::Connection) -> Result<(), ErrorCode> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS executions(session_id TEXT NOT NULL,generation INTEGER NOT NULL,admission_id INTEGER NOT NULL UNIQUE,identity TEXT NOT NULL,service_id TEXT NOT NULL,state TEXT NOT NULL,cursor INTEGER NOT NULL DEFAULT 0,diagnostic_pid INTEGER,workspace TEXT,PRIMARY KEY(session_id,generation));
      CREATE TABLE IF NOT EXISTS execution_effects(admission_id INTEGER PRIMARY KEY,operation TEXT NOT NULL,identity TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS execution_content(session_id TEXT NOT NULL,generation INTEGER NOT NULL,message_id TEXT NOT NULL,record TEXT NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(session_id,generation,message_id));
      CREATE TABLE IF NOT EXISTS execution_events(session_id TEXT NOT NULL,generation INTEGER NOT NULL,cursor INTEGER NOT NULL,event TEXT NOT NULL,PRIMARY KEY(session_id,generation,cursor));
      CREATE TABLE IF NOT EXISTS pre_launch_failures(admission_id INTEGER PRIMARY KEY,code TEXT NOT NULL,observed_at INTEGER NOT NULL);").map_err(storage)
}

impl Journal {
    pub(crate) fn fail_before_launch(
        &mut self,
        admission: i64,
        code: ErrorCode,
        now: i64,
    ) -> Result<(), ErrorCode> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let eligible:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM admissions a WHERE a.id=?1 AND a.verb='\"dispatch\"' AND NOT EXISTS(SELECT 1 FROM executions e WHERE e.admission_id=a.id))",[admission],|r|r.get(0)).map_err(storage)?;
        if eligible {
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO pre_launch_failures VALUES(?1,?2,?3)",
                    params![
                        admission,
                        serde_json::to_string(&code).map_err(storage)?,
                        now
                    ],
                )
                .map_err(storage)?;
            if changed == 1 {
                tx.execute("INSERT INTO audit(principal,request_id,event,at) SELECT principal,request_id,'pre_launch_failed',?2 FROM admissions WHERE id=?1",params![admission,now]).map_err(storage)?;
                tx.execute("UPDATE sessions SET state='failed' WHERE id=(SELECT session_id FROM admissions WHERE id=?1)",[admission]).map_err(storage)?;
            }
        }
        tx.commit().map_err(storage)
    }
}

pub(crate) fn pre_launch_failure(
    db: &rusqlite::Connection,
    session: &str,
) -> Result<Option<crate::control::PreLaunchFailure>, ErrorCode> {
    let row:Option<(i64,String)>=db.query_row("SELECT f.admission_id,f.code FROM pre_launch_failures f JOIN admissions a ON a.id=f.admission_id WHERE a.session_id=?1",[session],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage)?;
    row.map(|(admission_id, code)| {
        Ok(crate::control::PreLaunchFailure::Failed {
            admission_id,
            code: serde_json::from_str(&code).map_err(storage)?,
            submission: crate::control::PreLaunchSubmission::NotAttempted,
        })
    })
    .transpose()
}
struct DispatchRecord {
    principal: String,
    request: ControlRequest,
    resolved: ResolvedDispatch,
    session_id: String,
    generation: u64,
}
fn dispatch(tx: &Transaction<'_>, id: i64) -> Result<DispatchRecord, ErrorCode> {
    let failed: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pre_launch_failures WHERE admission_id=?1)",
            [id],
            |r| r.get(0),
        )
        .map_err(storage)?;
    if failed {
        return Err(ErrorCode::PreLaunchFailed);
    }
    let row:Option<(String,String,String,String)>=tx.query_row("SELECT principal,payload,resolved,session_id FROM admissions WHERE id=?1 AND verb='\"dispatch\"'",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(storage)?;
    let (principal, payload, resolved, session_id) = row.ok_or(ErrorCode::UnknownTarget)?;
    let generation: i64 = tx
        .query_row(
            "SELECT generation FROM sessions WHERE id=?1",
            [&session_id],
            |r| r.get(0),
        )
        .map_err(storage)?;
    Ok(DispatchRecord {
        principal,
        request: serde_json::from_str(&payload).map_err(storage)?,
        resolved: serde_json::from_str(&resolved).map_err(storage)?,
        session_id,
        generation: u64::try_from(generation).map_err(storage)?,
    })
}
fn authorize(tx: &Transaction<'_>, record: &DispatchRecord, now: i64) -> Result<u64, ErrorCode> {
    if record.request.deadline.is_some_and(|d| d <= now) {
        return Err(ErrorCode::DeadlineExpired);
    }
    if !matches!(record.request.action, Action::Dispatch(_)) {
        return Err(ErrorCode::GrantDenied);
    }
    let cfg = journal::config(tx)?;
    let (team, profile_id): (String, String) = tx
        .query_row(
            "SELECT team_id,profile_id FROM sessions WHERE id=?1 AND generation=?2",
            params![record.session_id, integer(record.generation)?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(storage)?
        .ok_or(ErrorCode::StaleGeneration)?;
    let profile = journal::profile(&cfg, &profile_id)?;
    if profile.project != record.resolved.environment.project
        || profile.harness != record.resolved.harness
        || profile.environment != record.resolved.environment.id
        || profile.mode != record.resolved.profile.mode
    {
        return Err(ErrorCode::ProfileDenied);
    }
    let current = cfg
        .defaults
        .iter()
        .find(|d| d.team_id == team && d.profile_id == profile_id)
        .ok_or(ErrorCode::ProfileDenied)?;
    let mut permitted = current.resolved.clone();
    permitted.budget = record.resolved.budget.clone();
    permitted.required_capabilities = record.resolved.required_capabilities.clone();
    if permitted != record.resolved
        || !current
            .resolved
            .required_capabilities
            .iter()
            .all(|c| record.resolved.required_capabilities.contains(c))
        || record.resolved.budget.worker_slots > current.resolved.budget.worker_slots
        || record.resolved.budget.reviewer_slots > current.resolved.budget.reviewer_slots
        || record.resolved.budget.max_wall_ms > current.resolved.budget.max_wall_ms
        || record.resolved.budget.max_content_bytes > current.resolved.budget.max_content_bytes
    {
        return Err(ErrorCode::ProfileDenied);
    }
    let target = Target::Team { team_id: team };
    if !cfg.grants.iter().any(|g| {
        g.principal == record.principal && g.verb == Verb::Dispatch && g.target.matches(&target)
    }) {
        return Err(ErrorCode::GrantDenied);
    }
    let slots: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE state NOT IN('ended','failed')",
            [],
            |r| r.get(0),
        )
        .map_err(storage)?;
    if slots > i64::from(record.resolved.budget.worker_slots) {
        return Err(ErrorCode::ResourceLimit);
    }
    Ok(cfg.revision)
}

fn require_launch_eligibility(
    policy: Option<&crate::runtime_policy::RuntimePolicy>,
    tx: &Transaction<'_>,
    record: &DispatchRecord,
    revision: u64,
    now: i64,
) -> Result<(), ErrorCode> {
    if let Some(policy) = policy {
        policy.require(
            &record.resolved,
            revision,
            now,
            journal::runtime_disabled(tx)?,
        )?;
    }
    Ok(())
}

pub(crate) fn revalidate_dispatch(
    tx: &Transaction<'_>,
    admission_id: i64,
    now: i64,
) -> Result<ResolvedDispatch, ErrorCode> {
    let record = dispatch(tx, admission_id)?;
    authorize(tx, &record, now)?;
    Ok(record.resolved)
}
impl Journal {
    pub(crate) fn spawn_native_backend(
        &mut self,
        admission: i64,
        identity: &ExecutionIdentity,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
        command: &mut std::process::Command,
    ) -> Result<std::process::Child, ErrorCode> {
        let policy = self.runtime_policy.clone().ok_or(ErrorCode::NotSupported)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM executions WHERE admission_id=?1 AND identity=?2 AND state='spawn_intent')",params![admission,serde_json::to_string(identity).map_err(storage)?],|r|r.get(0)).map_err(storage)?;
        if !valid {
            return Err(ErrorCode::RequestConflict);
        }
        let row = dispatch(&tx, admission)?;
        let revision = authorize(&tx, &row, clock()?)?;
        if revision != identity.policy_revision {
            return Err(ErrorCode::RequestConflict);
        }
        policy.require_at(
            &row.resolved,
            revision,
            clock,
            journal::runtime_disabled(&tx)?,
        )?;
        let mut child =
            xmsg::client::caller_attribution::with_fd_inheritance_gate(|| command.spawn())
                .map_err(storage)?;
        if tx.commit().is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ErrorCode::Storage);
        }
        Ok(child)
    }
    pub(crate) fn write_bootstrap_frame(
        &mut self,
        admission: i64,
        identity: &ExecutionIdentity,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
        frame: &crate::framing::Frame,
        writer: &mut crate::supervisor::DeadlineIo<'_, impl std::io::Write + std::os::fd::AsRawFd>,
    ) -> Result<(), ErrorCode> {
        writer.limit_to(std::time::Instant::now() + std::time::Duration::from_secs(2));
        let policy = self.runtime_policy.clone().ok_or(ErrorCode::NotSupported)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let current:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM executions WHERE admission_id=?1 AND identity=?2 AND state='spawn_intent')",params![admission,serde_json::to_string(identity).map_err(storage)?],|r|r.get(0)).map_err(storage)?;
        if !current {
            return Err(ErrorCode::RequestConflict);
        }
        let row = dispatch(&tx, admission)?;
        let revision = authorize(&tx, &row, clock()?)?;
        if revision != identity.policy_revision {
            return Err(ErrorCode::RequestConflict);
        }
        policy.require_at(
            &row.resolved,
            revision,
            clock,
            journal::runtime_disabled(&tx)?,
        )?;
        let at = clock()?;
        if row.request.deadline.is_some_and(|d| d <= at) {
            return Err(ErrorCode::DeadlineExpired);
        }
        crate::framing::write_frame(writer, frame).map_err(|_| ErrorCode::Storage)?;
        tx.commit().map_err(storage)
    }
    pub(crate) fn dispatch_identity(
        &mut self,
        id: i64,
        now: i64,
    ) -> Result<(String, u64), ErrorCode> {
        let tx = self.db.transaction().map_err(storage)?;
        let row = dispatch(&tx, id)?;
        authorize(&tx, &row, now)?;
        Ok((row.session_id, row.generation))
    }
    pub(crate) fn reserve_launch(&mut self, id: i64, now: i64) -> Result<LaunchLease, ErrorCode> {
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row = dispatch(&tx, id)?;
        let revision = authorize(&tx, &row, now)?;
        require_launch_eligibility(policy.as_deref(), &tx, &row, revision, now)?;
        let existing: Option<(String, String, String)> = tx
            .query_row(
                "SELECT identity,service_id,state FROM executions WHERE admission_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        let (identity, service_id) = if let Some((identity, service, state)) = existing {
            if state != "reserved" {
                return Err(ErrorCode::RequestConflict);
            }
            let mut identity: ExecutionIdentity =
                serde_json::from_str(&identity).map_err(storage)?;
            if identity.session_id != row.session_id || identity.generation != row.generation {
                return Err(ErrorCode::StaleGeneration);
            }
            identity.policy_revision = revision;
            let raw = hex::decode(service).map_err(storage)?;
            let service_id = raw.try_into().map_err(storage)?;
            (identity, service_id)
        } else {
            (
                ExecutionIdentity {
                    session_id: row.session_id.clone(),
                    generation: row.generation,
                    launch_nonce: hex::encode(nonce()?),
                    policy_revision: revision,
                    protocol_version: SUPERVISOR_PROTOCOL_VERSION,
                    build_version: env!("CARGO_PKG_VERSION").into(),
                },
                nonce()?,
            )
        };
        tx.execute("INSERT INTO executions(session_id,generation,admission_id,identity,service_id,state) VALUES(?1,?2,?3,?4,?5,'reserved') ON CONFLICT(session_id,generation) DO UPDATE SET identity=excluded.identity",params![identity.session_id,integer(identity.generation)?,id,serde_json::to_string(&identity).map_err(storage)?,hex::encode(service_id)]).map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(LaunchLease {
            admission_id: id,
            identity,
            resolved: row.resolved,
            service_id,
        })
    }
    pub(crate) fn commit_spawn_intent(
        &mut self,
        lease: &LaunchLease,
        now: i64,
    ) -> Result<(), ErrorCode> {
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row = dispatch(&tx, lease.admission_id)?;
        let revision = authorize(&tx, &row, now)?;
        require_launch_eligibility(policy.as_deref(), &tx, &row, revision, now)?;
        if row.session_id != lease.identity.session_id
            || row.generation != lease.identity.generation
            || revision != lease.identity.policy_revision
            || row.resolved != lease.resolved
        {
            return Err(ErrorCode::RequestConflict);
        }
        let changed=tx.execute("UPDATE executions SET state='spawn_intent' WHERE session_id=?1 AND generation=?2 AND identity=?3 AND state='reserved'",params![lease.identity.session_id,integer(lease.identity.generation)?,serde_json::to_string(&lease.identity).map_err(storage)?]).map_err(storage)?;
        if changed != 1 {
            return Err(ErrorCode::RequestConflict);
        }
        tx.execute(
            "UPDATE sessions SET state='unknown' WHERE id=?1",
            [&lease.identity.session_id],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }
    pub(crate) fn mark_running(
        &mut self,
        id: &ExecutionIdentity,
        pid: u32,
        cursor: u64,
        now: i64,
    ) -> Result<(), ErrorCode> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let admission:i64=tx.query_row("SELECT admission_id FROM executions WHERE session_id=?1 AND generation=?2 AND identity=?3",params![id.session_id,integer(id.generation)?,serde_json::to_string(id).map_err(storage)?],|r|r.get(0)).map_err(storage)?;
        let mut record = dispatch(&tx, admission)?;
        record.request.deadline = None;
        if authorize(&tx, &record, now)? != id.policy_revision {
            return Err(ErrorCode::RequestConflict);
        }
        let changed=tx.execute("UPDATE executions SET state='running',diagnostic_pid=?1,cursor=?2 WHERE session_id=?3 AND generation=?4 AND identity=?5 AND state IN('spawn_intent','running','unknown') AND cursor<=?2",params![i64::from(pid),integer(cursor)?,id.session_id,integer(id.generation)?,serde_json::to_string(id).map_err(storage)?]).map_err(storage)?;
        if changed != 1 {
            return Err(ErrorCode::StaleGeneration);
        }
        tx.execute(
            "UPDATE sessions SET state='running' WHERE id=?1 AND generation=?2",
            params![id.session_id, integer(id.generation)?],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }
    pub(crate) fn mark_execution(
        &mut self,
        id: &ExecutionIdentity,
        stopped: bool,
    ) -> Result<(), ErrorCode> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            "UPDATE executions SET state=?1 WHERE session_id=?2 AND generation=?3 AND identity=?4",
            params![
                if stopped { "stopped" } else { "unknown" },
                id.session_id,
                integer(id.generation)?,
                serde_json::to_string(id).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        tx.execute(
            "UPDATE sessions SET state=?1 WHERE id=?2 AND generation=?3",
            params![
                if stopped { "ended" } else { "unknown" },
                id.session_id,
                integer(id.generation)?
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }
    pub(crate) fn execution(
        &self,
        session: &str,
        generation: u64,
    ) -> Result<Option<ExecutionObservation>, ErrorCode> {
        let row:Option<(String,String,i64,Option<u32>)>=self.db.query_row("SELECT identity,state,cursor,diagnostic_pid FROM executions WHERE session_id=?1 AND generation=?2",params![session,integer(generation)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(storage)?;
        row.map(|(id, state, cursor, pid)| {
            Ok(ExecutionObservation {
                identity: serde_json::from_str(&id).map_err(storage)?,
                state: serde_json::from_value(serde_json::Value::String(state)).map_err(storage)?,
                cursor: u64::try_from(cursor).map_err(storage)?,
                diagnostic_pid: pid,
            })
        })
        .transpose()
    }
    pub(crate) fn proxy_binding(&self, id: &ExecutionIdentity) -> Result<ProxyBinding, ErrorCode> {
        let (service,resolved):(String,String)=self.db.query_row("SELECT e.service_id,a.resolved FROM executions e JOIN admissions a ON a.id=e.admission_id WHERE e.session_id=?1 AND e.generation=?2 AND e.identity=?3 AND e.state='running'",params![id.session_id,integer(id.generation)?,serde_json::to_string(id).map_err(storage)?],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage)?.ok_or(ErrorCode::StaleGeneration)?;
        let resolved: ResolvedDispatch = serde_json::from_str(&resolved).map_err(storage)?;
        ProxyBinding::new(
            id.session_id.clone(),
            id.generation,
            hex::decode(service)
                .map_err(storage)?
                .try_into()
                .map_err(storage)?,
            resolved.budget.max_content_bytes as usize,
        )
        .map_err(storage)
    }
}
impl ContentStore for &crate::control::ControlService {
    fn commit(
        &mut self,
        binding: &ProxyBinding,
        content: &ContentRecord,
    ) -> Result<CommitOutcome, MembershipError> {
        let mut journal = self.journal.lock().map_err(|_| MembershipError::Storage)?;
        let tx = journal
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| MembershipError::Storage)?;
        let limit:Option<i64>=tx.query_row("SELECT json_extract(a.resolved,'$.budget.max_content_bytes') FROM executions e JOIN admissions a ON a.id=e.admission_id JOIN sessions s ON s.id=e.session_id WHERE e.session_id=?1 AND e.generation=?2 AND s.generation=e.generation AND e.state='running'",params![binding.session_id(),i64::try_from(binding.generation()).map_err(|_|MembershipError::InvalidBinding)?],|r|r.get(0)).optional().map_err(|_|MembershipError::Storage)?;
        let limit = limit.ok_or(MembershipError::StaleGeneration)?;
        let serialized =
            serde_json::to_string(content).map_err(|_| MembershipError::InvalidContent)?;
        let prior:Option<String>=tx.query_row("SELECT record FROM execution_content WHERE session_id=?1 AND generation=?2 AND message_id=?3",params![binding.session_id(),i64::try_from(binding.generation()).map_err(|_|MembershipError::InvalidBinding)?,content.message_id],|r|r.get(0)).optional().map_err(|_|MembershipError::Storage)?;
        if let Some(prior) = prior {
            if prior != serialized {
                return Err(MembershipError::MessageConflict);
            }
            tx.commit().map_err(|_| MembershipError::Storage)?;
            return Ok(CommitOutcome::Duplicate);
        }
        let total:i64=tx.query_row("SELECT COALESCE(SUM(bytes),0) FROM execution_content WHERE session_id=?1 AND generation=?2",params![binding.session_id(),i64::try_from(binding.generation()).map_err(|_|MembershipError::InvalidBinding)?],|r|r.get(0)).map_err(|_|MembershipError::Storage)?;
        let bytes = i64::try_from(serialized.len()).map_err(|_| MembershipError::ContentLimit)?;
        if total.checked_add(bytes).is_none_or(|n| n > limit) {
            return Err(MembershipError::ContentLimit);
        }
        tx.execute(
            "INSERT INTO execution_content VALUES(?1,?2,?3,?4,?5)",
            params![
                binding.session_id(),
                i64::try_from(binding.generation()).map_err(|_| MembershipError::InvalidBinding)?,
                content.message_id,
                serialized,
                bytes
            ],
        )
        .map_err(|_| MembershipError::Storage)?;
        tx.commit().map_err(|_| MembershipError::Storage)?;
        Ok(CommitOutcome::Inserted)
    }
}

impl Journal {
    pub(crate) fn validate_bootstrap(
        &mut self,
        admission: i64,
        identity: &ExecutionIdentity,
        workspace: &std::path::Path,
        now: i64,
    ) -> Result<ResolvedDispatch, ErrorCode> {
        let policy = self.runtime_policy.clone().ok_or(ErrorCode::NotSupported)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let raw:Option<String>=tx.query_row("SELECT workspace FROM executions WHERE admission_id=?1 AND identity=?2 AND state='spawn_intent'",params![admission,serde_json::to_string(identity).map_err(storage)?],|r|r.get(0)).optional().map_err(storage)?.ok_or(ErrorCode::UnknownTarget)?;
        let stored: crate::workspace::OwnedWorkspaceIdentity =
            serde_json::from_str(&raw.ok_or(ErrorCode::UnknownTarget)?).map_err(storage)?;
        if stored.path() != workspace || identity.protocol_version != SUPERVISOR_PROTOCOL_VERSION {
            return Err(ErrorCode::RequestConflict);
        }
        let selected = revalidate_dispatch(&tx, admission, now)?;
        let configuration = journal::config(&tx)?;
        if configuration.revision != identity.policy_revision {
            return Err(ErrorCode::RequestConflict);
        }
        policy.require(
            &selected,
            configuration.revision,
            now,
            journal::runtime_disabled(&tx)?,
        )?;
        Ok(selected)
    }
    pub(crate) fn validate_reserved(
        &mut self,
        lease: &LaunchLease,
        now: i64,
    ) -> Result<(), ErrorCode> {
        let policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row = dispatch(&tx, lease.admission_id)?;
        let rev = authorize(&tx, &row, now)?;
        require_launch_eligibility(policy.as_deref(), &tx, &row, rev, now)?;
        if row.session_id != lease.identity.session_id
            || row.generation != lease.identity.generation
            || rev != lease.identity.policy_revision
            || row.resolved != lease.resolved
        {
            return Err(ErrorCode::RequestConflict);
        }
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM executions WHERE session_id=?1 AND generation=?2 AND identity=?3 AND state='reserved')",params![lease.identity.session_id,integer(lease.identity.generation)?,serde_json::to_string(&lease.identity).map_err(storage)?],|r|r.get(0)).map_err(storage)?;
        if !exists {
            return Err(ErrorCode::RequestConflict);
        }
        Ok(())
    }
    pub(crate) fn authorize_stop(
        &mut self,
        id: i64,
        now: i64,
    ) -> Result<ExecutionIdentity, ErrorCode> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let row: Option<(String, String, String)> = tx
            .query_row(
                "SELECT principal,payload,target FROM admissions WHERE id=?1 AND verb='\"stop\"'",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        let (principal, payload, target) = row.ok_or(ErrorCode::UnknownTarget)?;
        let request: ControlRequest = serde_json::from_str(&payload).map_err(storage)?;
        let target: Target = serde_json::from_str(&target).map_err(storage)?;
        if request.deadline.is_some_and(|d| d <= now) {
            return Err(ErrorCode::DeadlineExpired);
        }
        let Target::Execution {
            session_id,
            generation,
        } = &target
        else {
            return Err(ErrorCode::StaleGeneration);
        };
        let profile_id: Option<String> = tx
            .query_row(
                "SELECT profile_id FROM sessions WHERE id=?1 AND generation=?2",
                params![session_id, integer(*generation)?],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        let cfg = journal::config(&tx)?;
        journal::profile(&cfg, &profile_id.ok_or(ErrorCode::StaleGeneration)?)?;
        if !journal::has_current_grant(&tx, &cfg, &principal, Verb::Stop, &target)? {
            return Err(ErrorCode::GrantDenied);
        }
        let identity:String=tx.query_row("SELECT identity FROM executions WHERE session_id=?1 AND generation=?2 AND state IN('running','unknown','spawn_intent')",params![session_id,integer(*generation)?],|r|r.get(0)).optional().map_err(storage)?.ok_or(ErrorCode::UnknownTarget)?;
        tx.execute(
            "INSERT INTO execution_effects(admission_id,operation,identity) VALUES(?1,'stop',?2)",
            params![id, identity],
        )
        .map_err(|_| ErrorCode::RequestConflict)?;
        tx.commit().map_err(storage)?;
        serde_json::from_str(&identity).map_err(storage)
    }
}

impl Journal {
    pub(crate) fn administrative_stop_needed(
        &mut self,
        id: &ExecutionIdentity,
    ) -> Result<bool, ErrorCode> {
        if journal::runtime_disabled(&self.db)? {
            return Ok(true);
        }
        let tx = self.db.transaction().map_err(storage)?;
        let cfg = journal::config(&tx)?;
        let profile: Option<String> = tx
            .query_row(
                "SELECT profile_id FROM sessions WHERE id=?1 AND generation=?2",
                params![id.session_id, integer(id.generation)?],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        let profile = profile.ok_or(ErrorCode::StaleGeneration)?;
        Ok(!cfg.profiles.iter().any(|p| p.id == profile && p.enabled))
    }
}

impl Journal {
    pub(crate) fn mark_stopped(
        &mut self,
        id: &ExecutionIdentity,
        cursor: u64,
    ) -> Result<(), ErrorCode> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let changed=tx.execute("UPDATE executions SET state='stopped',cursor=?1 WHERE session_id=?2 AND generation=?3 AND identity=?4 AND cursor<=?1",params![integer(cursor)?,id.session_id,integer(id.generation)?,serde_json::to_string(id).map_err(storage)?]).map_err(storage)?;
        if changed != 1 {
            return Err(ErrorCode::RequestConflict);
        }
        tx.execute(
            "UPDATE sessions SET state='ended' WHERE id=?1 AND generation=?2",
            params![id.session_id, integer(id.generation)?],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }
}
