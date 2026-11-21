use crate::{
    control::{AdminCommand, AdmittedDispatch, ControlReply, ErrorCode, OwnerConfig},
    protocol::{
        Action, Admission, Authorization, ControlRequest, ObservedEffect, OperationReceipt,
        Submission, Target,
    },
};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

type PendingRecord = (String, i64, String, String, String, i64, String, bool);

pub(crate) struct Journal {
    pub(crate) db: Connection,
}
fn sql_u64(value: u64) -> Result<i64, ErrorCode> {
    i64::try_from(value).map_err(|_| ErrorCode::InvalidConfiguration)
}
fn storage(_: impl std::fmt::Display) -> ErrorCode {
    ErrorCode::Storage
}
pub(crate) fn input_digest(request: &ControlRequest) -> Result<String, ErrorCode> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(request).map_err(storage)?,
    )))
}
fn fingerprint(principal: &str, input: &str, resolved: &str) -> String {
    hex::encode(Sha256::digest(format!(
        "executor-admission-v1\0{principal}\0{input}\0{resolved}"
    )))
}
impl Journal {
    pub(crate) fn open(path: &Path, configuration: &OwnerConfig) -> Result<Self, ErrorCode> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(storage)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
          CREATE TABLE IF NOT EXISTS configuration(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL,body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS requests(principal TEXT NOT NULL,request_id TEXT NOT NULL,input_digest TEXT NOT NULL,fingerprint TEXT NOT NULL,reply TEXT NOT NULL,PRIMARY KEY(principal,request_id));
          CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,team_id TEXT NOT NULL,generation INTEGER NOT NULL,active_turn TEXT,state TEXT NOT NULL,profile_id TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS admissions(id INTEGER PRIMARY KEY AUTOINCREMENT,principal TEXT NOT NULL,request_id TEXT NOT NULL,verb TEXT NOT NULL,target TEXT NOT NULL,policy_revision INTEGER NOT NULL,payload TEXT NOT NULL,resolved TEXT NOT NULL,session_id TEXT,UNIQUE(principal,request_id));
          CREATE TABLE IF NOT EXISTS decisions(approval_id TEXT PRIMARY KEY,request_id TEXT NOT NULL,session_id TEXT NOT NULL,generation INTEGER NOT NULL,turn_id TEXT NOT NULL,decision TEXT NOT NULL,payload TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,principal TEXT,request_id TEXT NOT NULL,event TEXT NOT NULL,at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,session_id TEXT NOT NULL,generation INTEGER NOT NULL,turn_id TEXT NOT NULL,operation_digest TEXT NOT NULL,policy_revision TEXT NOT NULL,expires_at INTEGER NOT NULL,option_id TEXT NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);").map_err(storage)?;
        db.execute(
            "INSERT OR IGNORE INTO configuration VALUES(1,?1,?2)",
            params![
                sql_u64(configuration.revision)?,
                serde_json::to_string(configuration).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        crate::execution::initialize(&db)?;
        Ok(Self { db })
    }
    pub(crate) fn admit(
        &mut self,
        principal: &str,
        input: &str,
        request: &ControlRequest,
        now: i64,
    ) -> Result<ControlReply, ErrorCode> {
        self.admit_clock(principal, input, request, &|| Ok(now))
    }
    pub(crate) fn admit_bound(
        &mut self,
        principal: &str,
        input: &str,
        request: &ControlRequest,
        clock: &dyn Fn() -> i64,
        deadline: std::time::Instant,
    ) -> Result<ControlReply, ErrorCode> {
        self.admit_clock(principal, input, request, &|| {
            if std::time::Instant::now() >= deadline {
                return Err(ErrorCode::DeadlineExpired);
            }
            Ok(clock())
        })
    }
    fn admit_clock(
        &mut self,
        principal: &str,
        input: &str,
        request: &ControlRequest,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<ControlReply, ErrorCode> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let now = clock()?;
        if let Some(reply) = replay(&tx, principal, &request.request_id, input)? {
            audit(
                &tx,
                principal,
                &request.request_id,
                "historical_replay",
                now,
            )?;
            tx.commit().map_err(storage)?;
            return Ok(reply);
        }
        let configuration = config(&tx)?;
        let outcome = admit_new(&tx, &configuration, principal, request, now);
        let (target, resolved, denial) = match outcome {
            Ok((target, resolved)) => (Some(target), resolved, None),
            Err(code) => (request.target.clone(), String::new(), Some(code)),
        };
        let mut dispatch = None;
        let admission = if denial.is_none() {
            let target = target.as_ref().ok_or(ErrorCode::UnknownTarget)?;
            tx.execute("INSERT INTO admissions(principal,request_id,verb,target,policy_revision,payload,resolved) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![principal,request.request_id,serde_json::to_string(&request.action.verb()).map_err(storage)?,serde_json::to_string(target).map_err(storage)?,sql_u64(configuration.revision)?,serde_json::to_string(request).map_err(storage)?,resolved]).map_err(storage)?;
            let id = tx.last_insert_rowid();
            let generation = match target {
                Target::Execution { generation, .. } | Target::Turn { generation, .. } => {
                    *generation
                }
                _ => 1,
            };
            if let Action::Dispatch(_) = request.action {
                let template = configuration
                    .defaults
                    .iter()
                    .find(|d| matches!(target,Target::Team {team_id} if d.team_id==*team_id))
                    .ok_or(ErrorCode::InvalidConfiguration)?;
                let session_id = format!("session-{id}");
                tx.execute(
                    "INSERT INTO sessions VALUES(?1,?2,1,NULL,'admitted',?3)",
                    params![&session_id, template.team_id, template.profile_id],
                )
                .map_err(storage)?;
                tx.execute(
                    "UPDATE admissions SET session_id=?1 WHERE id=?2",
                    params![session_id, id],
                )
                .map_err(storage)?;
                dispatch = Some(AdmittedDispatch {
                    session_id,
                    resolved: serde_json::from_str(&resolved).map_err(storage)?,
                });
            }
            Admission::Durable {
                admission_id: format!("admission-{id}"),
                generation,
            }
        } else {
            Admission::NotAdmitted
        };
        let receipt = OperationReceipt {
            request_id: request.request_id.clone(),
            target,
            authorization: match denial {
                Some(code) => Authorization::Denied {
                    code: code.to_string(),
                },
                None => Authorization::Allowed {
                    policy_revision: configuration.revision.to_string(),
                },
            },
            admission,
            submission: Submission::NotAttempted,
            observed_effect: ObservedEffect::NotObserved,
        };
        let reply = ControlReply {
            request_id: request.request_id.clone(),
            replayed: false,
            historical: false,
            receipt,
            dispatch,
            decision: None,
        };
        tx.execute(
            "INSERT INTO requests VALUES(?1,?2,?3,?4,?5)",
            params![
                principal,
                request.request_id,
                input,
                fingerprint(principal, input, &resolved),
                serde_json::to_string(&reply).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        audit(
            &tx,
            principal,
            &request.request_id,
            if denial.is_some() {
                "denied"
            } else {
                "admitted"
            },
            now,
        )?;
        tx.commit().map_err(storage)?;
        Ok(reply)
    }
    pub(crate) fn admin(&mut self, command: AdminCommand, now: i64) -> Result<u64, ErrorCode> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut configuration = config(&tx)?;
        let (id, expected) = match &command {
            AdminCommand::ReplacePolicy {
                request_id,
                expected_revision,
                ..
            }
            | AdminCommand::RevokeProfile {
                request_id,
                expected_revision,
                ..
            } => (request_id.clone(), *expected_revision),
        };
        if expected != configuration.revision {
            return Err(ErrorCode::RequestConflict);
        }
        match command {
            AdminCommand::ReplacePolicy {
                configuration: new, ..
            } => {
                new.validate()?;
                if new.revision != configuration.revision + 1 {
                    return Err(ErrorCode::InvalidConfiguration);
                }
                configuration = new;
            }
            AdminCommand::RevokeProfile { profile_id, .. } => {
                let profile = configuration
                    .profiles
                    .iter_mut()
                    .find(|p| p.id == profile_id)
                    .ok_or(ErrorCode::ProfileDenied)?;
                profile.enabled = false;
                configuration.revision += 1;
                tx.execute(
                    "UPDATE sessions SET state='unknown' WHERE profile_id=?1",
                    [profile_id],
                )
                .map_err(storage)?;
            }
        }
        tx.execute(
            "UPDATE configuration SET revision=?1,body=?2 WHERE singleton=1",
            params![
                sql_u64(configuration.revision)?,
                serde_json::to_string(&configuration).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        audit(&tx, "owner-admin", &id, "policy_changed", now)?;
        tx.commit().map_err(storage)?;
        Ok(configuration.revision)
    }
    pub(crate) fn human(
        &mut self,
        request: ControlRequest,
        now: i64,
    ) -> Result<ControlReply, ErrorCode> {
        request.validate().map_err(|_| ErrorCode::MalformedFrame)?;
        let input = input_digest(&request)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if let Some(reply) = replay(&tx, "human-channel", &request.request_id, &input)? {
            audit(
                &tx,
                "human-channel",
                &request.request_id,
                "historical_replay",
                now,
            )?;
            tx.commit().map_err(storage)?;
            return Ok(reply);
        }
        let Action::Approve(args) = &request.action else {
            return Err(ErrorCode::HumanRequired);
        };
        let Some(Target::Turn {
            session_id,
            generation,
            turn_id,
        }) = &request.target
        else {
            return Err(ErrorCode::PendingMismatch);
        };
        if request.deadline.is_some_and(|d| d <= now) || args.expires_at <= now {
            return Err(ErrorCode::DeadlineExpired);
        }
        let configuration = config(&tx)?;
        let current = session(&tx, session_id)?;
        if current.0 != *generation {
            return Err(ErrorCode::StaleGeneration);
        }
        if current.1.as_deref() != Some(turn_id) {
            return Err(ErrorCode::StaleTurn);
        }
        profile(&configuration, &current.2)?;
        let pending:Option<PendingRecord>=tx.query_row("SELECT session_id,generation,turn_id,operation_digest,policy_revision,expires_at,option_id,consumed FROM approvals WHERE id=?1",[&args.approval_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional().map_err(storage)?;
        let p = pending.ok_or(ErrorCode::PendingMismatch)?;
        if p.7 {
            return Err(ErrorCode::AlreadyConsumed);
        }
        if p.0 != *session_id
            || p.1 != sql_u64(*generation)?
            || p.2 != *turn_id
            || p.3 != args.operation_digest
            || p.4 != args.policy_revision
            || p.4 != configuration.revision.to_string()
            || p.5 != args.expires_at
            || p.6 != args.option_id
        {
            return Err(ErrorCode::PendingMismatch);
        }
        tx.execute(
            "UPDATE approvals SET consumed=1 WHERE id=?1",
            [&args.approval_id],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO decisions VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                args.approval_id,
                request.request_id,
                session_id,
                sql_u64(*generation)?,
                turn_id,
                serde_json::to_string(&args.decision).map_err(storage)?,
                serde_json::to_string(&request).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        let reply = ControlReply {
            request_id: request.request_id.clone(),
            replayed: false,
            historical: false,
            dispatch: None,
            decision: Some(args.clone()),
            receipt: OperationReceipt {
                request_id: request.request_id.clone(),
                target: request.target.clone(),
                authorization: Authorization::Allowed {
                    policy_revision: configuration.revision.to_string(),
                },
                admission: Admission::Durable {
                    admission_id: format!("decision-{}", args.approval_id),
                    generation: *generation,
                },
                submission: Submission::NotAttempted,
                observed_effect: ObservedEffect::NotObserved,
            },
        };
        tx.execute(
            "INSERT INTO requests VALUES('human-channel',?1,?2,?3,?4)",
            params![
                request.request_id,
                input,
                fingerprint("human-channel", &input, &args.operation_digest),
                serde_json::to_string(&reply).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        audit(
            &tx,
            "human-channel",
            &request.request_id,
            "fake_pending_decision_consumed",
            now,
        )?;
        tx.commit().map_err(storage)?;
        Ok(reply)
    }
}
pub(crate) fn config(tx: &Transaction<'_>) -> Result<OwnerConfig, ErrorCode> {
    let body: String = tx
        .query_row(
            "SELECT body FROM configuration WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(storage)?;
    serde_json::from_str(&body).map_err(storage)
}
fn replay(
    tx: &Transaction<'_>,
    principal: &str,
    id: &str,
    input: &str,
) -> Result<Option<ControlReply>, ErrorCode> {
    let row: Option<(String, String)> = tx
        .query_row(
            "SELECT input_digest,reply FROM requests WHERE principal=?1 AND request_id=?2",
            params![principal, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    match row {
        None => Ok(None),
        Some((prior, body)) => {
            if prior != input {
                return Err(ErrorCode::RequestConflict);
            }
            let mut reply: ControlReply = serde_json::from_str(&body).map_err(storage)?;
            reply.replayed = true;
            reply.historical = true;
            Ok(Some(reply))
        }
    }
}
fn audit(
    tx: &Transaction<'_>,
    principal: &str,
    id: &str,
    event: &str,
    now: i64,
) -> Result<(), ErrorCode> {
    tx.execute(
        "INSERT INTO audit(principal,request_id,event,at) VALUES(?1,?2,?3,?4)",
        params![principal, id, event, now],
    )
    .map_err(storage)?;
    Ok(())
}
fn session(tx: &Transaction<'_>, id: &str) -> Result<(u64, Option<String>, String), ErrorCode> {
    tx.query_row(
        "SELECT generation,active_turn,profile_id FROM sessions WHERE id=?1",
        [id],
        |r| {
            let generation: i64 = r.get(0)?;
            Ok((
                u64::try_from(generation)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, generation))?,
                r.get(1)?,
                r.get(2)?,
            ))
        },
    )
    .optional()
    .map_err(storage)?
    .ok_or(ErrorCode::UnknownTarget)
}
pub(crate) fn profile<'a>(
    config: &'a OwnerConfig,
    id: &str,
) -> Result<&'a crate::control::OwnerProfile, ErrorCode> {
    let p = config
        .profiles
        .iter()
        .find(|p| p.id == id && p.enabled)
        .ok_or(ErrorCode::ProfileDenied)?;
    if p.mode == crate::capability::TrustProfile::Unsafe && !p.owner_selected {
        return Err(ErrorCode::ProfileDenied);
    }
    Ok(p)
}
fn admit_new(
    tx: &Transaction<'_>,
    config: &OwnerConfig,
    principal: &str,
    request: &ControlRequest,
    now: i64,
) -> Result<(Target, String), ErrorCode> {
    if request.deadline.is_some_and(|d| d <= now) {
        return Err(ErrorCode::DeadlineExpired);
    }
    let (target, resolved) = if let Action::Dispatch(args) = &request.action {
        let candidates: Vec<_> = config
            .defaults
            .iter()
            .filter(|d| {
                request
                    .target
                    .as_ref()
                    .is_none_or(|t| matches!(t,Target::Team {team_id} if *team_id==d.team_id))
            })
            .collect();
        if candidates.len() != 1 {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let d = candidates[0];
        let p = profile(config, &d.profile_id)?;
        if d.resolved.environment.host != config.local_host
            || p.project != d.resolved.environment.project
            || p.harness != d.resolved.harness
            || p.environment != d.resolved.environment.id
            || p.mode != d.resolved.profile.mode
        {
            return Err(ErrorCode::ProfileDenied);
        }
        if args
            .requested
            .harness
            .as_ref()
            .is_some_and(|h| *h != d.resolved.harness)
            || args
                .requested
                .model
                .as_ref()
                .is_some_and(|m| *m != d.resolved.model)
            || args
                .requested
                .executor_selector
                .as_ref()
                .is_some_and(|s| *s != d.resolved.environment.executor)
            || args
                .requested
                .environment_selector
                .as_ref()
                .is_some_and(|s| *s != d.resolved.environment.id)
            || args
                .requested
                .workspace
                .as_ref()
                .is_some_and(|w| *w != d.resolved.workspace)
        {
            return Err(ErrorCode::InvalidConfiguration);
        }
        if !args.requested.required_capabilities.is_empty()
            || !d.resolved.required_capabilities.is_empty()
        {
            return Err(ErrorCode::NotSupported);
        }
        if args.requested.budget.as_ref().is_some_and(|b| {
            b.worker_slots > d.resolved.budget.worker_slots
                || b.reviewer_slots > d.resolved.budget.reviewer_slots
                || b.max_wall_ms > d.resolved.budget.max_wall_ms
                || b.max_content_bytes > d.resolved.budget.max_content_bytes
        }) {
            return Err(ErrorCode::ResourceLimit);
        }
        let mut resolved = d.resolved.clone();
        if let Some(budget) = &args.requested.budget {
            resolved.budget = budget.clone();
        }
        let live: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE state!='ended'",
                [],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if live >= i64::from(resolved.budget.worker_slots) {
            return Err(ErrorCode::ResourceLimit);
        }
        (
            Target::Team {
                team_id: d.team_id.clone(),
            },
            serde_json::to_string(&resolved).map_err(storage)?,
        )
    } else {
        let target = request.target.as_ref().ok_or(ErrorCode::UnknownTarget)?;
        let id = match target {
            Target::Session { session_id }
            | Target::Execution { session_id, .. }
            | Target::Turn { session_id, .. } => session_id,
            _ => return Err(ErrorCode::UnknownTarget),
        };
        let current = session(tx, id)?;
        profile(config, &current.2)?;
        if let Target::Execution { generation, .. } | Target::Turn { generation, .. } = target {
            if *generation != current.0 {
                return Err(ErrorCode::StaleGeneration);
            }
        }
        if let Target::Turn { turn_id, .. } = target {
            if current.1.as_ref() != Some(turn_id) {
                return Err(ErrorCode::StaleTurn);
            }
        }
        if let Action::Send(args) = &request.action {
            if args
                .prefer_live
                .as_ref()
                .is_some_and(|p| p.expected_generation != current.0 || p.deadline <= now)
            {
                return Err(ErrorCode::StaleGeneration);
            }
        }
        if matches!(request.action, Action::Approve(_)) {
            return Err(ErrorCode::HumanRequired);
        }
        (
            crate::control::resolved_target(target, current.0),
            String::new(),
        )
    };
    if !config.grants.iter().any(|g| {
        g.principal == principal && g.verb == request.action.verb() && g.target.matches(&target)
    }) {
        return Err(ErrorCode::GrantDenied);
    }
    Ok((target, resolved))
}
