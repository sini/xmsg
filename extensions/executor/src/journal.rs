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
    pub(crate) runtime_policy: Option<std::sync::Arc<crate::runtime_policy::RuntimePolicy>>,
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
    pub(crate) fn open_existing(path: &Path) -> Result<Self, ErrorCode> {
        use std::os::unix::fs::MetadataExt;
        let path = crate::unix::private_parent(path, xmsg::client::current_uid())?;
        let metadata = std::fs::symlink_metadata(&path).map_err(storage)?;
        if !metadata.is_file()
            || metadata.uid() != xmsg::client::current_uid()
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(storage)?;
        db.busy_timeout(std::time::Duration::ZERO)
            .map_err(storage)?;
        let after = std::fs::symlink_metadata(&path).map_err(storage)?;
        if after.dev() != metadata.dev() || after.ino() != metadata.ino() {
            return Err(ErrorCode::InvalidConfiguration);
        }
        let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='native_operations')",[],|r|r.get(0)).map_err(storage)?;
        if !exists {
            return Err(ErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            db,
            runtime_policy: None,
        })
    }
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
        db.execute_batch("CREATE TABLE IF NOT EXISTS runtime_control(singleton INTEGER PRIMARY KEY CHECK(singleton=1),disabled INTEGER NOT NULL CHECK(disabled IN(0,1))); INSERT OR IGNORE INTO runtime_control VALUES(1,0);").map_err(storage)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS caller_receipts(admission_id INTEGER PRIMARY KEY,receipt TEXT NOT NULL); CREATE TABLE IF NOT EXISTS caller_revocations(record_id TEXT NOT NULL,record_revision INTEGER NOT NULL,revoked_at INTEGER NOT NULL,PRIMARY KEY(record_id,record_revision));").map_err(storage)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS owner_record_requests(request_id TEXT PRIMARY KEY,input_digest TEXT NOT NULL,response_revision INTEGER NOT NULL);").map_err(storage)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS session_delegations(principal TEXT NOT NULL,session_id TEXT NOT NULL,generation INTEGER NOT NULL,verb TEXT NOT NULL,team_id TEXT NOT NULL,profile_id TEXT NOT NULL,policy_revision INTEGER NOT NULL,dispatch_admission INTEGER NOT NULL,PRIMARY KEY(principal,session_id,generation,verb));").map_err(storage)?;
        db.execute(
            "INSERT OR IGNORE INTO configuration VALUES(1,?1,?2)",
            params![
                sql_u64(configuration.revision)?,
                serde_json::to_string(configuration).map_err(storage)?
            ],
        )
        .map_err(storage)?;
        crate::execution::initialize(&db)?;
        crate::lifecycle::initialize(&db)?;
        crate::content_delivery::initialize(&db)?;
        crate::approval::initialize(&db)?;
        Ok(Self {
            db,
            runtime_policy: None,
        })
    }
    pub(crate) fn admit(
        &mut self,
        principal: &str,
        input: &str,
        request: &ControlRequest,
        now: i64,
    ) -> Result<ControlReply, ErrorCode> {
        self.admit_clock(principal, input, request, &|| Ok(now), None)
    }
    pub(crate) fn admit_bound(
        &mut self,
        principal: &str,
        input: &str,
        request: &ControlRequest,
        clock: &dyn Fn() -> i64,
        deadline: std::time::Instant,
    ) -> Result<ControlReply, ErrorCode> {
        self.admit_clock(
            principal,
            input,
            request,
            &|| {
                if std::time::Instant::now() >= deadline {
                    return Err(ErrorCode::DeadlineExpired);
                }
                Ok(clock())
            },
            None,
        )
    }
    pub(crate) fn admit_attested(
        &mut self,
        principal: &crate::auth::TrustedPrincipal,
        input: &str,
        request: &ControlRequest,
        now: i64,
    ) -> Result<ControlReply, ErrorCode> {
        if self.runtime_policy.is_none() {
            return self.admit(principal.id(), input, request, now);
        }
        self.admit_clock(
            principal.id(),
            input,
            request,
            &|| Ok(now),
            Some(
                crate::caller_policy::TrustedCallerContext::from_attestation(principal)
                    .map_err(|_| ErrorCode::CallerScopeUnproven),
            ),
        )
    }
    pub(crate) fn admit_attested_bound(
        &mut self,
        principal: &crate::auth::TrustedPrincipal,
        input: &str,
        request: &ControlRequest,
        clock: &dyn Fn() -> i64,
        deadline: std::time::Instant,
    ) -> Result<ControlReply, ErrorCode> {
        if self.runtime_policy.is_none() {
            return self.admit_bound(principal.id(), input, request, clock, deadline);
        }
        self.admit_clock(
            principal.id(),
            input,
            request,
            &|| {
                if std::time::Instant::now() >= deadline {
                    Err(ErrorCode::DeadlineExpired)
                } else {
                    Ok(clock())
                }
            },
            Some(
                crate::caller_policy::TrustedCallerContext::from_attestation(principal)
                    .map_err(|_| ErrorCode::CallerScopeUnproven),
            ),
        )
    }
    fn admit_clock(
        &mut self,
        principal: &str,
        input: &str,
        request: &ControlRequest,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
        caller: Option<Result<crate::caller_policy::TrustedCallerContext, ErrorCode>>,
    ) -> Result<ControlReply, ErrorCode> {
        let runtime_policy = self.runtime_policy.clone();
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
        let mut caller_admission = None;
        let outcome = admit_new(
            &tx,
            &configuration,
            principal,
            request,
            now,
            runtime_policy.is_some(),
        )
        .and_then(|(target, resolved)| {
            if let Some(policy) = &runtime_policy {
                if !matches!(
                    request.action,
                    Action::Status(_) | Action::Result(_) | Action::Stop(_)
                ) {
                    let mut selected = if matches!(request.action, Action::Dispatch(_)) {
                        serde_json::from_str(&resolved).map_err(storage)?
                    } else {
                        resolved_for_target(&tx, &target)?
                    };
                    crate::lifecycle::require_action_capability(request, &mut selected)?;
                    policy.require_at(
                        &selected,
                        configuration.revision,
                        clock,
                        runtime_disabled(&tx)?,
                    )?;
                    let context = caller
                        .as_ref()
                        .ok_or(ErrorCode::CallerScopeUnproven)?
                        .as_ref()
                        .map_err(|code| *code)?
                        .clone();
                    caller_admission = Some(policy.callers.qualify(
                        &tx,
                        context,
                        configuration.revision,
                        clock()?,
                    )?);
                    let at = clock()?;
                    if request.deadline.is_some_and(|deadline| deadline <= at) {
                        return Err(ErrorCode::DeadlineExpired);
                    }
                }
            }
            Ok((target, resolved))
        });
        let (target, resolved, denial) = match outcome {
            Ok((target, resolved)) => (Some(target), resolved, None),
            Err(code) => (request.target.clone(), String::new(), Some(code)),
        };
        let mut dispatch = None;
        let mut caller_id = None;
        let admission = if denial.is_none() {
            let target = target.as_ref().ok_or(ErrorCode::UnknownTarget)?;
            tx.execute("INSERT INTO admissions(principal,request_id,verb,target,policy_revision,payload,resolved) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![principal,request.request_id,serde_json::to_string(&request.action.verb()).map_err(storage)?,serde_json::to_string(target).map_err(storage)?,sql_u64(configuration.revision)?,serde_json::to_string(request).map_err(storage)?,resolved]).map_err(storage)?;
            let id = tx.last_insert_rowid();
            if caller_admission.is_some() {
                caller_id = Some(id);
            }
            if matches!(request.action, Action::Interrupt(_)) {
                crate::approval::cancel_turn(&tx, target)?;
            }
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
                for verb in &template.lifecycle_verbs {
                    tx.execute(
                        "INSERT INTO session_delegations VALUES(?1,?2,1,?3,?4,?5,?6,?7)",
                        params![
                            principal,
                            session_id,
                            serde_json::to_string(verb).map_err(storage)?,
                            template.team_id,
                            template.profile_id,
                            sql_u64(configuration.revision)?,
                            id,
                        ],
                    )
                    .map_err(storage)?;
                }
                dispatch = Some(AdmittedDispatch {
                    session_id,
                    resolved: serde_json::from_str(&resolved).map_err(storage)?,
                    delegated_verbs: template.lifecycle_verbs.clone(),
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
        let pre_launch_failure = if matches!(request.action, Action::Status(_) | Action::Result(_))
        {
            match &receipt.target {
                Some(Target::Execution { session_id, .. } | Target::Turn { session_id, .. }) => {
                    crate::execution::pre_launch_failure(&tx, session_id)?
                }
                _ => None,
            }
        } else {
            None
        };
        let reports = if denial.is_none()
            && matches!(request.action, Action::Status(_) | Action::Result(_))
        {
            Some(crate::execution::journal_reports(
                &tx,
                receipt.target.as_ref().ok_or(ErrorCode::UnknownTarget)?,
                clock()?,
            )?)
        } else {
            None
        };
        let (status, result) = match reports {
            Some((status, result)) => (
                matches!(request.action, Action::Status(_)).then_some(status),
                matches!(request.action, Action::Result(_)).then_some(result),
            ),
            None => (None, None),
        };
        let reply = ControlReply {
            request_id: request.request_id.clone(),
            replayed: false,
            historical: false,
            receipt,
            dispatch,
            decision: None,
            pre_launch_failure,
            status,
            result,
            reconnect: None,
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
        if let (Some(id), Some(caller)) = (caller_id, caller_admission) {
            tx.execute(
                "INSERT INTO caller_receipts VALUES(?1,?2)",
                params![
                    id,
                    serde_json::to_string(&caller.receipt()).map_err(storage)?
                ],
            )
            .map_err(storage)?;
            let policy = runtime_policy
                .as_deref()
                .ok_or(ErrorCode::CallerReferenceUnavailable)?;
            policy.callers.bind(id, caller)?;
            if let Err(error) = tx.commit() {
                policy.callers.discard(id);
                return Err(storage(error));
            }
        } else {
            tx.commit().map_err(storage)?;
        }
        Ok(reply)
    }
    pub(crate) fn admin(&mut self, command: AdminCommand, now: i64) -> Result<u64, ErrorCode> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut configuration = config(&tx)?;
        let record_command = matches!(command, AdminCommand::RevokeCallerQualification { .. });
        let command_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&command).map_err(storage)?,
        ));
        let (id, expected) = match &command {
            AdminCommand::RevokeCallerQualification {
                request_id,
                expected_revision,
                ..
            }
            | AdminCommand::DisableRuntime {
                request_id,
                expected_revision,
            }
            | AdminCommand::ReplacePolicy {
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
        if record_command {
            let prior:Option<(String,i64)>=tx.query_row("SELECT input_digest,response_revision FROM owner_record_requests WHERE request_id=?1",[&id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage)?;
            if let Some((digest, revision)) = prior {
                if digest != command_digest {
                    return Err(ErrorCode::RequestConflict);
                }
                tx.commit().map_err(storage)?;
                return u64::try_from(revision).map_err(storage);
            }
        }
        if expected != configuration.revision {
            return Err(ErrorCode::RequestConflict);
        }
        match command {
            AdminCommand::RevokeCallerQualification {
                record_id,
                record_revision,
                ..
            } => {
                if id.is_empty()
                    || id.len() > 128
                    || id.chars().any(char::is_control)
                    || record_id.is_empty()
                    || record_id.len() > 128
                    || record_id.chars().any(char::is_control)
                    || record_revision == 0
                {
                    return Err(ErrorCode::MalformedFrame);
                }
                tx.execute(
                    "INSERT OR IGNORE INTO caller_revocations VALUES(?1,?2,?3)",
                    params![record_id, sql_u64(record_revision)?, now],
                )
                .map_err(storage)?;
                tx.execute(
                    "INSERT INTO owner_record_requests VALUES(?1,?2,?3)",
                    params![id, command_digest, sql_u64(configuration.revision)?],
                )
                .map_err(storage)?;
            }
            AdminCommand::DisableRuntime { .. } => {
                crate::approval::disable_pending(&tx)?;
                tx.execute(
                    "UPDATE runtime_control SET disabled=1 WHERE singleton=1",
                    [],
                )
                .map_err(storage)?;
                audit(&tx, "owner-admin", &id, "runtime_disabled", now)?;
                configuration.revision += 1;
            }
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
        audit(
            &tx,
            "owner-admin",
            &id,
            if record_command {
                "caller_record_revoked"
            } else {
                "policy_changed"
            },
            now,
        )?;
        tx.commit().map_err(storage)?;
        Ok(configuration.revision)
    }
    pub(crate) fn human(
        &mut self,
        request: ControlRequest,
        now: i64,
    ) -> Result<ControlReply, ErrorCode> {
        self.human_with_confirmation(request, now, None)
    }
    pub(crate) fn human_with_confirmation(
        &mut self,
        request: ControlRequest,
        now: i64,
        confirmation: Option<crate::approval::HumanConfirmation>,
    ) -> Result<ControlReply, ErrorCode> {
        self.human_at(request, confirmation, &|| Ok(now))
    }
    pub(crate) fn human_at(
        &mut self,
        request: ControlRequest,
        confirmation: Option<crate::approval::HumanConfirmation>,
        clock: &dyn Fn() -> Result<i64, ErrorCode>,
    ) -> Result<ControlReply, ErrorCode> {
        request.validate().map_err(|_| ErrorCode::MalformedFrame)?;
        let input = input_digest(&request)?;
        let runtime_policy = self.runtime_policy.clone();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let now = clock()?;
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
        if runtime_disabled(&tx)? {
            return Err(ErrorCode::ProfileDenied);
        }
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
        let native = crate::approval::prepare_confirmation(
            &tx,
            &request,
            confirmation.as_ref(),
            clock,
            runtime_policy.as_deref(),
            crate::approval::DecisionPhase::Human,
        )?;
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
        let at = clock()?;
        if request.deadline.is_some_and(|deadline| deadline <= at) || args.expires_at <= at {
            return Err(ErrorCode::DeadlineExpired);
        }
        if native {
            crate::approval::prepare_confirmation(
                &tx,
                &request,
                confirmation.as_ref(),
                clock,
                runtime_policy.as_deref(),
                crate::approval::DecisionPhase::Human,
            )?;
        }
        tx.execute(
            "UPDATE approvals SET consumed=1 WHERE id=?1",
            [&args.approval_id],
        )
        .map_err(storage)?;
        if native {
            let changed=tx.execute("UPDATE native_pending SET state='decision_recorded' WHERE approval_id=?1 AND state='pending'",[&args.approval_id]).map_err(storage)?;
            if changed != 1 {
                return Err(ErrorCode::AlreadyConsumed);
            }
        }
        tx.execute(
            "INSERT INTO decisions VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                args.approval_id,
                request.request_id,
                session_id,
                sql_u64(*generation)?,
                turn_id,
                serde_json::to_string(&args.decision).map_err(storage)?,
                if native {
                    serde_json::to_string(&crate::approval::HumanDecisionCall {
                        request: request.clone(),
                        confirmation: confirmation.clone().ok_or(ErrorCode::HumanRequired)?,
                    })
                    .map_err(storage)?
                } else {
                    serde_json::to_string(&request).map_err(storage)?
                }
            ],
        )
        .map_err(storage)?;
        let reply = ControlReply {
            request_id: request.request_id.clone(),
            replayed: false,
            historical: false,
            dispatch: None,
            decision: Some(args.clone()),
            pre_launch_failure: None,
            status: None,
            result: None,
            reconnect: None,
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
            if native {
                "native_pending_decision_consumed"
            } else {
                "fake_pending_decision_consumed"
            },
            at,
        )?;
        tx.commit().map_err(storage)?;
        Ok(reply)
    }
}
pub(crate) fn runtime_disabled(db: &Connection) -> Result<bool, ErrorCode> {
    db.query_row(
        "SELECT disabled FROM runtime_control WHERE singleton=1",
        [],
        |r| r.get(0),
    )
    .map_err(storage)
}

pub(crate) fn resolved_for_target(
    db: &Connection,
    target: &Target,
) -> Result<crate::capability::ResolvedDispatch, ErrorCode> {
    let session = match target {
        Target::Session { session_id }
        | Target::Execution { session_id, .. }
        | Target::Turn { session_id, .. } => session_id,
        _ => return Err(ErrorCode::UnknownTarget),
    };
    let raw: String = db.query_row("SELECT resolved FROM admissions WHERE session_id=?1 AND verb='\"dispatch\"' ORDER BY id DESC LIMIT 1", [session], |r| r.get(0))
        .optional().map_err(storage)?.ok_or(ErrorCode::UnknownTarget)?;
    serde_json::from_str(&raw).map_err(storage)
}

pub(crate) fn has_current_grant(
    tx: &Transaction<'_>,
    configuration: &OwnerConfig,
    principal: &str,
    verb: crate::protocol::Verb,
    target: &Target,
) -> Result<bool, ErrorCode> {
    if configuration
        .grants
        .iter()
        .any(|g| g.principal == principal && g.verb == verb && g.target.matches(target))
    {
        return Ok(true);
    }
    let (session_id, generation) = match target {
        Target::Execution {
            session_id,
            generation,
        }
        | Target::Turn {
            session_id,
            generation,
            ..
        } => (session_id, *generation),
        _ => return Ok(false),
    };
    let mut query = tx.prepare("SELECT d.principal,d.generation,d.team_id,d.profile_id FROM session_delegations d JOIN sessions s ON s.id=d.session_id WHERE d.session_id=?1 AND d.verb=?2 AND s.team_id=d.team_id AND s.profile_id=d.profile_id").map_err(storage)?;
    let rows = query
        .query_map(
            params![session_id, serde_json::to_string(&verb).map_err(storage)?],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(storage)?;
    for row in rows {
        let (holder, delegated_generation, team, profile) = row.map_err(storage)?;
        if holder == principal
            && delegated_generation == sql_u64(generation)?
            && configuration.grants.iter().any(|g| {
                g.principal == holder
                    && g.verb == crate::protocol::Verb::Dispatch
                    && g.target.matches(&Target::Team {
                        team_id: team.clone(),
                    })
            })
            && configuration.defaults.iter().any(|d| {
                d.team_id == team && d.profile_id == profile && d.lifecycle_verbs.contains(&verb)
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
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
            let reconnect:Option<String>=tx.query_row("SELECT n.command FROM admissions a JOIN native_operations n ON n.admission_id=a.id WHERE a.principal=?1 AND a.request_id=?2 AND a.verb='\"resume\"' AND n.state IN('reconnected','reconnect_unknown')",params![principal,id],|r|r.get(0)).optional().map_err(storage)?;
            if let Some(raw) = reconnect {
                reply.reconnect = Some(serde_json::from_str(&raw).map_err(storage)?);
            }
            if let Some(dispatch) = &reply.dispatch {
                reply.pre_launch_failure =
                    crate::execution::pre_launch_failure(tx, &dispatch.session_id)?;
            }
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
pub(crate) fn admit_new(
    tx: &Transaction<'_>,
    config: &OwnerConfig,
    principal: &str,
    request: &ControlRequest,
    now: i64,
    runtime_capabilities: bool,
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
        if !runtime_capabilities
            && (!args.requested.required_capabilities.is_empty()
                || !d.resolved.required_capabilities.is_empty())
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
        for capability in &args.requested.required_capabilities {
            if !resolved.required_capabilities.contains(capability) {
                resolved.required_capabilities.push(capability.clone());
            }
        }
        if let Some(budget) = &args.requested.budget {
            resolved.budget = budget.clone();
        }
        let live: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE state NOT IN('ended','failed')",
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
    if !has_current_grant(tx, config, principal, request.action.verb(), &target)? {
        return Err(ErrorCode::GrantDenied);
    }
    if !matches!(
        request.action,
        Action::Status(_) | Action::Result(_) | Action::Stop(_)
    ) && runtime_disabled(tx)?
    {
        return Err(ErrorCode::ProfileDenied);
    }
    Ok((target, resolved))
}
