use crate::{
    client::caller_attribution::{AuthorityStamp, CallerContext, FailureReason},
    http::AppState,
    process::{strict_process_link, PeerCred, StrictProcessLink},
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::TryLockError;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCaller {
    pub principal: String,
    pub stamp: AuthorityStamp,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    id: String,
    source: String,
    binding: Value,
    root_generation: Option<u64>,
    child_generation: Option<u64>,
}
impl Candidate {
    fn plain(id: String, source: &str, binding: Value) -> Self {
        Self {
            id,
            source: source.into(),
            binding,
            root_generation: None,
            child_generation: None,
        }
    }
    fn resolved(
        self,
        node: &str,
        step: &StrictProcessLink,
    ) -> Result<ResolvedCaller, FailureReason> {
        if self.id.is_empty()
            || self.id.len() > 1024
            || self.id.contains('@')
            || self.id.chars().any(char::is_control)
            || node.is_empty()
            || node.contains('@')
            || node.chars().any(char::is_whitespace)
        {
            return Err(FailureReason::AuthorityUnavailable);
        }
        let registration_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&self.binding).map_err(|_| FailureReason::Internal)?,
        ));
        Ok(ResolvedCaller {
            principal: format!("{}@{node}", self.id),
            stamp: AuthorityStamp {
                source: self.source,
                matched_pid: step.pid,
                matched_start: step.start.clone(),
                registration_digest,
                root_generation: self.root_generation,
                child_generation: self.child_generation,
            },
        })
    }
}

type CodexSqlRoot = (u32, String, i64, bool, bool, String, i64, i64);

struct ReadTimeout<'a> {
    connection: &'a Connection,
    old: u64,
    restored: bool,
}
impl<'a> ReadTimeout<'a> {
    fn enter(connection: &'a Connection) -> Result<Self, FailureReason> {
        let old: i64 = connection
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .map_err(|_| FailureReason::AuthorityUnavailable)?;
        let old = u64::try_from(old).map_err(|_| FailureReason::AuthorityUnavailable)?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(|_| FailureReason::AuthorityUnavailable)?;
        Ok(Self {
            connection,
            old,
            restored: false,
        })
    }
    fn finish(mut self) -> Result<(), FailureReason> {
        self.connection
            .busy_timeout(Duration::from_millis(self.old))
            .map_err(|_| FailureReason::AuthorityUnavailable)?;
        self.restored = true;
        Ok(())
    }
}
impl Drop for ReadTimeout<'_> {
    fn drop(&mut self) {
        if !self.restored {
            let _ = self
                .connection
                .busy_timeout(Duration::from_millis(self.old));
        }
    }
}

fn deadline_check(deadline: Instant) -> Result<(), FailureReason> {
    if Instant::now() >= deadline {
        Err(FailureReason::Deadline)
    } else {
        Ok(())
    }
}
fn active_claude_claims(
    connection: &Connection,
    pid: u32,
    start: &str,
) -> Result<Vec<crate::claim::InstanceClaim>, FailureReason> {
    let mut statement=connection.prepare("SELECT id,pid,proc_start,suffix,released,created_at FROM instance_claims WHERE pid=?1 AND proc_start=?2 AND released=0").map_err(|_|FailureReason::AuthorityUnavailable)?;
    let values = statement
        .query_map(params![pid, start], |row| {
            Ok(crate::claim::InstanceClaim {
                id: row.get(0)?,
                pid: row.get(1)?,
                proc_start: row.get(2)?,
                suffix: row.get(3)?,
                released: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            })
        })
        .map_err(|_| FailureReason::AuthorityUnavailable)?;
    values
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| FailureReason::AuthorityUnavailable)
}

fn capture_step(
    state: &AppState,
    step: &StrictProcessLink,
    original_pid: u32,
    context: Option<&CallerContext>,
    deadline: Instant,
) -> Result<Vec<Candidate>, FailureReason> {
    let entries = crate::registry::read_session_entries_checked(&state.sessions_dirs, deadline)?;
    let runtime = crate::codex::readonly_runtime_for_db(&state.db, deadline)?;
    macro_rules! guard {
        ($value:expr) => {
            match $value {
                Ok(guard) => guard,
                Err(TryLockError::WouldBlock) => {
                    std::thread::yield_now();
                    continue 'retry;
                }
                Err(TryLockError::Poisoned(_)) => return Err(FailureReason::AuthorityUnavailable),
            }
        };
    }
    'retry: loop {
        deadline_check(deadline)?;
        let connection = guard!(state.db.try_lock());
        let agy = guard!(state.agy_store.try_read());
        let pi = guard!(state.pi_store.try_read());
        let services = guard!(state.svc_store.try_read());
        let codex = guard!(runtime.try_lock());
        let timeout = ReadTimeout::enter(&connection)?;
        let captured = (|| {
            if crate::plugin::is_plugin_process(&connection, step.pid, &step.start)
                .map_err(|_| FailureReason::AuthorityUnavailable)?
            {
                return Err(FailureReason::Context);
            }
            let mut candidates = Vec::new();
            for entry in &entries {
                deadline_check(deadline)?;
                if entry.pid != step.pid
                    || !crate::process::claude_start_token_matches(
                        &state.agy_config.proc_root,
                        &step.start,
                        &entry.proc_start,
                    )
                {
                    continue;
                }
                if crate::claim::is_non_claude_instance(&connection, &entry.session_id)
                    .map_err(|_| FailureReason::AuthorityUnavailable)?
                {
                    continue;
                }
                let claims = active_claude_claims(&connection, entry.pid, &entry.proc_start)?;
                if claims.len() > 1 {
                    return Err(FailureReason::Ambiguous);
                }
                let claim = claims.first();
                if claim.is_some_and(|claim| claim.id != entry.session_id || claim.suffix == 0) {
                    return Err(FailureReason::Changed);
                }
                let id = claim
                    .map(crate::claim::InstanceClaim::address)
                    .unwrap_or_else(|| entry.session_id.clone());
                let claim_stamp = claim.map(|claim| {
                    json!([
                        claim.id,
                        claim.pid,
                        claim.proc_start,
                        claim.suffix,
                        claim.released,
                        claim.created_at
                    ])
                });
                candidates.push(Candidate::plain(
                    id,
                    "claude",
                    json!([
                        entry.session_id,
                        entry.pid,
                        entry.proc_start,
                        entry.started_at,
                        entry.messaging_socket_path,
                        claim_stamp
                    ]),
                ));
            }
            for (key, info) in agy.iter() {
                deadline_check(deadline)?;
                if info.pid == step.pid && info.starttime.is_empty() {
                    return Err(FailureReason::AuthorityUnavailable);
                }
                if info.pid == step.pid && info.starttime == step.start {
                    candidates.push(Candidate::plain(
                        info.conversation_id.clone(),
                        "agy",
                        json!([
                            key,
                            info.session_key,
                            info.conversation_id,
                            info.pid,
                            info.starttime,
                            info.registered_at,
                            info.has_credentials()
                        ]),
                    ));
                }
            }
            for (key, info) in pi.iter() {
                deadline_check(deadline)?;
                if info.pid == step.pid && info.starttime.is_empty() {
                    return Err(FailureReason::AuthorityUnavailable);
                }
                if info.pid == step.pid && info.starttime == step.start {
                    candidates.push(Candidate::plain(
                        info.session_id.clone(),
                        "pi",
                        json!([
                            key,
                            info.session_id,
                            info.pid,
                            info.starttime,
                            info.registered_at
                        ]),
                    ));
                }
            }
            if step.pid == original_pid {
                for (key, info) in services.iter() {
                    deadline_check(deadline)?;
                    if info.pid == step.pid && info.starttime.is_empty() {
                        return Err(FailureReason::AuthorityUnavailable);
                    }
                    if info.pid == step.pid && info.starttime == step.start {
                        if !crate::svc::strict_registration_connected(info) {
                            return Err(FailureReason::AuthorityUnavailable);
                        }
                        candidates.push(Candidate::plain(
                            info.session_id.clone(),
                            "svc",
                            json!([
                                key,
                                info.session_id,
                                info.pid,
                                info.starttime,
                                info.registered_at,
                                info.token
                            ]),
                        ));
                    }
                }
            }
            let mut config = codex.config.clone();
            config.proc_root = state.agy_config.proc_root.clone();
            let is_owner =
                crate::codex::readonly_codex_owner_step(&config, step.pid, &step.start, deadline)?;
            if candidates.len() + usize::from(is_owner) > 1 {
                return Err(FailureReason::Ambiguous);
            }
            if is_owner {
                let Some(CallerContext::Codex {
                    session_id,
                    thread_id,
                    turn_id,
                }) = context
                else {
                    return Err(FailureReason::Context);
                };
                let selected = codex.store.readonly_attribution_binding(
                    &config,
                    step.pid,
                    &step.start,
                    session_id,
                    thread_id,
                    turn_id.as_deref(),
                    deadline,
                )?;
                let row:Option<(u32,String,i64,bool,bool,String,i64,i64)>=connection.query_row("SELECT owner_pid,owner_starttime,generation,active,revoked,codex_home,rollout_dev,rollout_ino FROM codex_roots WHERE root_id=?1",[session_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional().map_err(|_|FailureReason::AuthorityUnavailable)?;
                let row = row.ok_or(FailureReason::Context)?;
                if row.0 != step.pid
                    || row.1 != step.start
                    || u64::try_from(row.2).ok() != Some(selected.root_generation)
                    || !row.3
                    || row.4
                    || row.5 != selected.codex_home
                    || (row.6 as u64, row.7 as u64) != selected.root_rollout
                {
                    return Err(FailureReason::Changed);
                }
                let harness: Option<String> = connection
                    .query_row(
                        "SELECT harness FROM instance_seen WHERE id=?1",
                        [session_id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|_| FailureReason::AuthorityUnavailable)?;
                if harness.as_deref() != Some("codex") {
                    return Err(FailureReason::Context);
                }
                let mut data = json!([
                    selected, row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, harness
                ]);
                if thread_id != session_id {
                    let binding = crate::storage::get_subagent(&connection, session_id, thread_id)
                        .map_err(|_| FailureReason::AuthorityUnavailable)?
                        .ok_or(FailureReason::Context)?;
                    if binding.parent != *session_id
                        || binding.agent_id != *thread_id
                        || binding.turn_pid != Some(step.pid)
                        || binding.turn_start.as_deref() != Some(step.start.as_str())
                        || binding.stopped_at.is_some()
                    {
                        return Err(FailureReason::Context);
                    }
                    data.as_array_mut()
                        .ok_or(FailureReason::Internal)?
                        .push(json!([
                            binding.parent,
                            binding.agent_id,
                            binding.bound_at,
                            binding.turn_pid,
                            binding.turn_start,
                            binding.stopped_at
                        ]));
                }
                candidates.push(Candidate {
                    id: selected.principal_id.clone(),
                    source: "codex".into(),
                    binding: data,
                    root_generation: Some(selected.root_generation),
                    child_generation: selected.child_generation,
                });
            } else if !candidates.is_empty() && context.is_some() {
                return Err(FailureReason::Context);
            }
            deadline_check(deadline)?;
            Ok(candidates)
        })();
        timeout.finish()?;
        return captured;
    }
}

pub fn resolve(
    state: &AppState,
    original: &PeerCred,
    query: &PeerCred,
    context: Option<&CallerContext>,
    deadline: Instant,
) -> Result<ResolvedCaller, FailureReason> {
    deadline_check(deadline)?;
    let original_pid = original
        .pid
        .filter(|p| *p > 0)
        .ok_or(FailureReason::MissingPid)?;
    let query_pid = query
        .pid
        .filter(|p| *p > 0)
        .ok_or(FailureReason::MissingPid)?;
    let query_start = strict_process_link(&state.agy_config.proc_root, query_pid)?.start;
    let normalized = context.cloned().map(CallerContext::normalize).transpose()?;
    let mut current = original_pid;
    let mut expected_start = None;
    let mut previous_steps: Vec<StrictProcessLink> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    for _ in 0..32 {
        deadline_check(deadline)?;
        if !visited.insert(current) {
            return Err(FailureReason::AuthorityUnavailable);
        }
        let step = strict_process_link(&state.agy_config.proc_root, current)?;
        if expected_start
            .as_ref()
            .is_some_and(|start| *start != step.start)
        {
            return Err(FailureReason::Changed);
        }
        if step.pid == query_pid && step.start == query_start {
            return Err(FailureReason::ExecutorLineage);
        }
        let candidates = capture_step(state, &step, original_pid, normalized.as_ref(), deadline)?;
        if candidates.len() > 1 {
            return Err(FailureReason::Ambiguous);
        }
        if let Some(candidate) = candidates.into_iter().next() {
            for prior in &previous_steps {
                if strict_process_link(&state.agy_config.proc_root, prior.pid)? != *prior {
                    return Err(FailureReason::Changed);
                }
                if !capture_step(state, prior, original_pid, normalized.as_ref(), deadline)?
                    .is_empty()
                {
                    return Err(FailureReason::Changed);
                }
            }
            let repeated = strict_process_link(&state.agy_config.proc_root, current)?;
            if repeated != step {
                return Err(FailureReason::Changed);
            }
            let after = capture_step(state, &step, original_pid, normalized.as_ref(), deadline)?;
            if after.as_slice() != std::slice::from_ref(&candidate) {
                return Err(FailureReason::Changed);
            }
            if strict_process_link(&state.agy_config.proc_root, query_pid)?.start != query_start {
                return Err(FailureReason::Changed);
            }
            deadline_check(deadline)?;
            return candidate.resolved(&state.node_name, &step);
        }
        if step.parent_pid == 0 {
            return Err(FailureReason::AuthorityUnavailable);
        }
        let parent = strict_process_link(&state.agy_config.proc_root, step.parent_pid)?;
        if parent.order > step.order {
            return Err(FailureReason::Changed);
        }
        expected_start = Some(parent.start);
        current = step.parent_pid;
        previous_steps.push(step);
    }
    Err(FailureReason::Limit)
}
