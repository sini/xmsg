use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use super::model::{
    ActivityDescriptor, ActivityFrame, ActivityHarness, ActivityReason, ActivityState,
    ActivityStatus, BackgroundPresence, BlockKind, OwnerProof, SnapshotActivity, WakePresence,
    ACTIVITY_FRESH_PERSIST_INTERVAL_SECS, ACTIVITY_INGEST_QUEUE_CAP, ACTIVITY_MAX_CORRELATIONS,
    ACTIVITY_STALE_BLOCKED_SECS, ACTIVITY_STALE_WORKING_SECS,
};
use super::store::{
    apply_restart_policy, commit_row, ensure_meta, load_all, reset_meta, update_fresh_at,
    StoredActivityRow,
};

#[derive(Clone, Debug)]
pub struct ProofFlags {
    pub claude_permission_request_proven: bool,
    pub claude_notification_proven: bool,
    pub claude_session_start_ready: bool,
    pub codex_permission_request_proven: bool,
    pub hermes_post_llm_call_turn_final: bool,
    pub hermes_on_session_end_proven: bool,
    pub correlated_mode: bool,
}

impl Default for ProofFlags {
    fn default() -> Self {
        Self {
            claude_permission_request_proven: true,
            claude_notification_proven: true,
            claude_session_start_ready: false,
            codex_permission_request_proven: true,
            hermes_post_llm_call_turn_final: false,
            hermes_on_session_end_proven: true,
            correlated_mode: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingOutcome {
    Verified {
        address: String,
        incarnation: u64,
        owner: OwnerProof,
        has_pending_wake: bool,
    },
    StaleOwner,
    Unverified {
        identified_address: Option<String>,
    },
    AmbiguousOwners {
        address: String,
    },
    RegistryUnavailable {
        identified_address: Option<String>,
    },
}

pub trait OwnerResolver {
    fn resolve(&self, frame: &ActivityFrame) -> BindingOutcome;
    fn is_owner_live(&self, owner: OwnerProof) -> bool;
}

/// Separate bounded 256-frame ingest queue that coalesces by endpoint key (latest kept).
#[derive(Debug, Default)]
pub struct ActivityIngestQueue {
    order: VecDeque<String>,
    pending: HashMap<String, ActivityFrame>,
}

impl ActivityIngestQueue {
    pub fn push(&mut self, key: String, frame: ActivityFrame) -> Option<String> {
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.pending.entry(key.clone())
        {
            e.insert(frame);
            return None;
        }
        let dropped = if self.order.len() >= ACTIVITY_INGEST_QUEUE_CAP {
            let old = self.order.pop_front();
            if let Some(ref k) = old {
                self.pending.remove(k);
            }
            old
        } else {
            None
        };
        self.order.push_back(key.clone());
        self.pending.insert(key, frame);
        dropped
    }

    pub fn pop(&mut self) -> Option<(String, ActivityFrame)> {
        let key = self.order.pop_front()?;
        let frame = self.pending.remove(&key)?;
        Some((key, frame))
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityTransition {
    pub address: String,
    pub descriptor: ActivityDescriptor,
}

fn frame_digest(frame: &ActivityFrame) -> String {
    let mut hasher = Sha256::new();
    hasher.update(frame.harness.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(frame.event.as_bytes());
    hasher.update(b"\0");
    hasher.update(frame.session.as_bytes());
    hasher.update(b"\0");
    hasher.update(frame.block.map_or("", BlockKind::as_str).as_bytes());
    hasher.update(b"\0");
    hasher.update(match frame.background {
        BackgroundPresence::Absent => b"absent" as &[u8],
        BackgroundPresence::None => b"none",
        BackgroundPresence::Active => b"active",
    });
    hasher.update(b"\0");
    hasher.update(match frame.wake {
        WakePresence::Absent => b"absent" as &[u8],
        WakePresence::None => b"none",
        WakePresence::Pending => b"pending",
    });
    hasher.update(b"\0");
    hasher.update(frame.correlation.as_deref().unwrap_or("").as_bytes());
    hex::encode(hasher.finalize())
}

pub struct ActivityEngine {
    pub enabled: bool,
    pub complete: bool,
    pub proofs: ProofFlags,
    pub state_epoch: String,
    pub revision: u64,
    pub rows: HashMap<String, StoredActivityRow>,
    pub fresh_mono: HashMap<String, Instant>,
    pub last_fresh_persist: HashMap<String, i64>,
}

impl ActivityEngine {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            complete: true,
            proofs: ProofFlags::default(),
            state_epoch: String::new(),
            revision: 0,
            rows: HashMap::new(),
            fresh_mono: HashMap::new(),
            last_fresh_persist: HashMap::new(),
        }
    }

    pub fn load_or_init(
        conn: &mut Connection,
        enabled: bool,
        proofs: ProofFlags,
        resolver: &dyn OwnerResolver,
        now_secs: i64,
        now_mono: Instant,
    ) -> rusqlite::Result<(Self, Vec<ActivityTransition>, bool)> {
        if !enabled {
            return Ok((Self::disabled(), Vec::new(), false));
        }
        let (epoch, rev, mut changed) =
            apply_restart_policy(conn, |owner| resolver.is_owner_live(owner), now_secs)?;
        let (_, _, all_rows) = load_all(conn)?;
        let mut rows = HashMap::with_capacity(all_rows.len());
        let mut fresh_mono = HashMap::with_capacity(all_rows.len());
        let mut last_fresh_persist = HashMap::with_capacity(all_rows.len());
        let had_rows = !all_rows.is_empty();
        for r in all_rows {
            fresh_mono.insert(r.address.clone(), now_mono);
            last_fresh_persist.insert(r.address.clone(), r.fresh_at);
            rows.insert(r.address.clone(), r);
        }
        let transitions = changed
            .drain(..)
            .map(|r| ActivityTransition {
                address: r.address.clone(),
                descriptor: r.to_descriptor(&epoch),
            })
            .collect();
        Ok((
            Self {
                enabled: true,
                complete: true,
                proofs,
                state_epoch: epoch,
                revision: rev,
                rows,
                fresh_mono,
                last_fresh_persist,
            },
            transitions,
            had_rows,
        ))
    }

    pub fn snapshot_activity(&self) -> SnapshotActivity {
        if !self.enabled {
            SnapshotActivity {
                status: ActivityStatus::Disabled,
                complete: true,
            }
        } else {
            SnapshotActivity {
                status: ActivityStatus::Enabled,
                complete: self.complete,
            }
        }
    }

    pub fn descriptor_for(&self, address: &str) -> Option<ActivityDescriptor> {
        if !self.enabled {
            return None;
        }
        self.rows
            .get(address)
            .map(|r| r.to_descriptor(&self.state_epoch))
    }

    pub fn reset_store(&mut self, conn: &mut Connection) -> rusqlite::Result<()> {
        let epoch = reset_meta(conn)?;
        self.state_epoch = epoch;
        self.revision = 0;
        self.complete = true;
        self.rows.clear();
        self.fresh_mono.clear();
        self.last_fresh_persist.clear();
        Ok(())
    }

    pub fn mark_evidence_lost(
        &mut self,
        conn: &mut Connection,
        address: &str,
        now_secs: i64,
        now_mono: Instant,
    ) -> rusqlite::Result<Option<ActivityTransition>> {
        if !self.enabled {
            return Ok(None);
        }
        let Some(mut row) = self.rows.get(address).cloned() else {
            return Ok(None);
        };
        if row.state == ActivityState::Unknown && row.reason == Some(ActivityReason::EvidenceLost) {
            return Ok(None);
        }
        row.state = ActivityState::Unknown;
        row.block = None;
        row.reason = Some(ActivityReason::EvidenceLost);
        row.open_correlations.clear();
        row.last_payload_digest = None;
        row.changed_at = now_secs;
        row.fresh_at = now_secs;
        self.commit_transition(conn, row, now_mono)
    }

    pub fn ingest(
        &mut self,
        conn: &mut Connection,
        frame: &ActivityFrame,
        resolver: &dyn OwnerResolver,
        now_secs: i64,
        now_mono: Instant,
    ) -> rusqlite::Result<Option<ActivityTransition>> {
        if !self.enabled {
            return Ok(None);
        }

        let binding = resolver.resolve(frame);
        let (address, incarnation, owner, has_pending_wake) = match binding {
            BindingOutcome::Verified {
                address,
                incarnation,
                owner,
                has_pending_wake,
            } => (address, incarnation, owner, has_pending_wake),
            BindingOutcome::StaleOwner => return Ok(None),
            BindingOutcome::AmbiguousOwners { address } => {
                return self.set_uncertainty(
                    conn,
                    &address,
                    frame.harness,
                    None,
                    ActivityReason::Contradictory,
                    now_secs,
                    now_mono,
                );
            }
            BindingOutcome::Unverified { identified_address } => {
                let Some(addr) = identified_address else {
                    return Ok(None);
                };
                return self.set_uncertainty(
                    conn,
                    &addr,
                    frame.harness,
                    None,
                    ActivityReason::Unverified,
                    now_secs,
                    now_mono,
                );
            }
            BindingOutcome::RegistryUnavailable { identified_address } => {
                let Some(addr) = identified_address else {
                    return Ok(None);
                };
                return self.set_uncertainty(
                    conn,
                    &addr,
                    frame.harness,
                    None,
                    ActivityReason::RegistryUnavailable,
                    now_secs,
                    now_mono,
                );
            }
        };

        let digest = frame_digest(frame);
        let existing = self.rows.get(&address).cloned();

        // Ordering & AE22 replay / conflict detection.
        if let Some(ref row) = existing {
            if row.incarnation == incarnation {
                if frame.harness.is_in_process() {
                    if let (Some(incoming_seq), Some(last_seq)) =
                        (frame.native_seq, row.last_native_seq)
                    {
                        if incoming_seq < last_seq {
                            return Ok(None);
                        }
                        if incoming_seq == last_seq {
                            if row.last_payload_digest.as_deref() == Some(digest.as_str()) {
                                // Exact replay: drop, NO transition and NO freshness.
                                return Ok(None);
                            }
                            // Conflict on same native_seq.
                            return self.set_uncertainty(
                                conn,
                                &address,
                                frame.harness,
                                Some(owner),
                                ActivityReason::Contradictory,
                                now_secs,
                                now_mono,
                            );
                        }
                    }
                } else if let Some(ref eid) = frame.event_id {
                    if row.last_event_id.as_deref() == Some(eid.as_str()) {
                        if row.last_payload_digest.as_deref() == Some(digest.as_str()) {
                            // Exact replay across same or different connection: drop, NO freshness.
                            return Ok(None);
                        }
                        return self.set_uncertainty(
                            conn,
                            &address,
                            frame.harness,
                            Some(owner),
                            ActivityReason::Contradictory,
                            now_secs,
                            now_mono,
                        );
                    }
                } else if !frame.harness.is_in_process()
                    && frame.event_id.is_none()
                    && row.last_payload_digest.as_deref() == Some(digest.as_str())
                {
                    // AE22: Command hooks without a stable event_id cannot prove a repeated
                    // indistinguishable frame across reconnects is independent evidence.
                    // Do not extend freshness.
                    return Ok(None);
                }
            }
        }

        let mut row = existing.unwrap_or(StoredActivityRow {
            address: address.clone(),
            harness: frame.harness,
            incarnation,
            owner: Some(owner),
            state: ActivityState::Unknown,
            block: None,
            reason: Some(ActivityReason::Unreported),
            open_correlations: Vec::new(),
            last_native_seq: None,
            last_event_id: None,
            last_payload_digest: None,
            changed_at: now_secs,
            fresh_at: now_secs,
            ended_at: None,
            revision: self.revision,
        });

        let is_new_row = !self.rows.contains_key(&address);
        if row.incarnation != incarnation {
            row.incarnation = incarnation;
            row.open_correlations.clear();
            row.last_native_seq = None;
            row.last_event_id = None;
            row.ended_at = None;
        }
        row.harness = frame.harness;
        row.owner = Some(owner);
        if let Some(seq) = frame.native_seq {
            row.last_native_seq = Some(seq);
        }
        if let Some(ref eid) = frame.event_id {
            row.last_event_id = Some(eid.clone());
        }
        row.last_payload_digest = Some(digest);

        let prev_tuple = (row.state, row.block, row.reason);
        let reduced = self.reduce_frame(&mut row, frame, has_pending_wake, now_secs);
        let Some((new_state, new_block, new_reason)) = reduced else {
            // Unmapped/no-op event that didn't change state; update digest/seq if needed.
            self.rows.insert(address, row);
            return Ok(None);
        };

        let next_tuple = (new_state, new_block, new_reason);
        if !is_new_row && prev_tuple == next_tuple {
            // Independent reaffirmation: update freshness without bumping revision or journaling.
            row.fresh_at = now_secs;
            self.fresh_mono.insert(address.clone(), now_mono);
            let should_persist = self
                .last_fresh_persist
                .get(&address)
                .is_none_or(|&last| now_secs - last >= ACTIVITY_FRESH_PERSIST_INTERVAL_SECS);
            if should_persist {
                update_fresh_at(conn, &address, now_secs)?;
                self.last_fresh_persist.insert(address.clone(), now_secs);
            }
            self.rows.insert(address, row);
            return Ok(None);
        }

        row.state = new_state;
        row.block = new_block;
        row.reason = new_reason;
        row.changed_at = now_secs;
        row.fresh_at = now_secs;
        self.last_fresh_persist.insert(address.clone(), now_secs);
        self.commit_transition(conn, row, now_mono)
    }

    #[allow(clippy::too_many_arguments)]
    fn set_uncertainty(
        &mut self,
        conn: &mut Connection,
        address: &str,
        harness: ActivityHarness,
        owner: Option<OwnerProof>,
        reason: ActivityReason,
        now_secs: i64,
        now_mono: Instant,
    ) -> rusqlite::Result<Option<ActivityTransition>> {
        let mut row = self
            .rows
            .get(address)
            .cloned()
            .unwrap_or(StoredActivityRow {
                address: address.to_owned(),
                harness,
                incarnation: 1,
                owner,
                state: ActivityState::Unknown,
                block: None,
                reason: Some(reason),
                open_correlations: Vec::new(),
                last_native_seq: None,
                last_event_id: None,
                last_payload_digest: None,
                changed_at: now_secs,
                fresh_at: now_secs,
                ended_at: None,
                revision: self.revision,
            });
        let is_new = !self.rows.contains_key(address);
        if !is_new && row.state == ActivityState::Unknown && row.reason == Some(reason) {
            return Ok(None);
        }
        row.state = ActivityState::Unknown;
        row.block = None;
        row.reason = Some(reason);
        row.open_correlations.clear();
        row.last_payload_digest = None;
        row.changed_at = now_secs;
        row.fresh_at = now_secs;
        self.commit_transition(conn, row, now_mono)
    }

    fn commit_transition(
        &mut self,
        conn: &mut Connection,
        mut row: StoredActivityRow,
        now_mono: Instant,
    ) -> rusqlite::Result<Option<ActivityTransition>> {
        let Some((epoch, rev)) = commit_row(conn, &mut row, true)? else {
            self.complete = false;
            return Ok(None);
        };
        self.state_epoch = epoch.clone();
        self.revision = rev;
        let addr = row.address.clone();
        let desc = row.to_descriptor(&epoch);
        self.fresh_mono.insert(addr.clone(), now_mono);
        self.rows.insert(addr.clone(), row);
        Ok(Some(ActivityTransition {
            address: addr,
            descriptor: desc,
        }))
    }

    fn reduce_frame(
        &self,
        row: &mut StoredActivityRow,
        frame: &ActivityFrame,
        has_pending_wake: bool,
        now_secs: i64,
    ) -> Option<(ActivityState, Option<BlockKind>, Option<ActivityReason>)> {
        let wake_pending = has_pending_wake || frame.wake == WakePresence::Pending;
        match frame.harness {
            ActivityHarness::Claude => match frame.event.as_str() {
                "user_prompt_submit" => {
                    if !self.proofs.correlated_mode {
                        row.open_correlations.clear();
                    }
                    if !row.open_correlations.is_empty() {
                        return Some((
                            ActivityState::Blocked,
                            row.block.or(Some(BlockKind::Permission)),
                            None,
                        ));
                    }
                    Some((ActivityState::Working, None, None))
                }
                "stop" => {
                    if !self.proofs.correlated_mode {
                        row.open_correlations.clear();
                    }
                    if !row.open_correlations.is_empty() {
                        return Some((
                            ActivityState::Blocked,
                            row.block.or(Some(BlockKind::Permission)),
                            None,
                        ));
                    }
                    match frame.background {
                        BackgroundPresence::Absent => Some((
                            ActivityState::Unknown,
                            None,
                            Some(ActivityReason::Unreported),
                        )),
                        BackgroundPresence::Active => Some((
                            ActivityState::Working,
                            None,
                            Some(ActivityReason::Background),
                        )),
                        BackgroundPresence::None => {
                            if wake_pending {
                                Some((
                                    ActivityState::Idle,
                                    None,
                                    Some(ActivityReason::ScheduledWake),
                                ))
                            } else {
                                Some((ActivityState::Idle, None, None))
                            }
                        }
                    }
                }
                "stop_failure" => {
                    row.open_correlations.clear();
                    Some((ActivityState::Idle, None, None))
                }
                "session_start" => {
                    row.open_correlations.clear();
                    row.ended_at = None;
                    if self.proofs.claude_session_start_ready {
                        Some((ActivityState::Idle, None, None))
                    } else {
                        Some((
                            ActivityState::Unknown,
                            None,
                            Some(ActivityReason::Unreported),
                        ))
                    }
                }
                "session_end" => {
                    row.open_correlations.clear();
                    row.ended_at = Some(now_secs);
                    Some((
                        ActivityState::Unknown,
                        None,
                        Some(ActivityReason::IncarnationEnded),
                    ))
                }
                "permission_request" => {
                    if !self.proofs.claude_permission_request_proven {
                        return Some((
                            ActivityState::Unknown,
                            None,
                            Some(ActivityReason::Unreported),
                        ));
                    }
                    if let Some(ref cid) = frame.correlation {
                        if !row.open_correlations.contains(cid)
                            && row.open_correlations.len() < ACTIVITY_MAX_CORRELATIONS
                        {
                            row.open_correlations.push(cid.clone());
                        }
                    }
                    Some((
                        ActivityState::Blocked,
                        Some(frame.block.unwrap_or(BlockKind::Permission)),
                        None,
                    ))
                }
                "post_tool_use" => {
                    if !self.proofs.correlated_mode {
                        return None;
                    }
                    let Some(ref cid) = frame.correlation else {
                        // Tool completion without native id never clears a prompt (AE8).
                        return None;
                    };
                    if let Some(pos) = row.open_correlations.iter().position(|x| x == cid) {
                        row.open_correlations.remove(pos);
                        if row.open_correlations.is_empty() {
                            return Some((ActivityState::Working, None, None));
                        }
                    }
                    None
                }
                "notification" => {
                    if !self.proofs.claude_notification_proven {
                        return Some((
                            ActivityState::Unknown,
                            None,
                            Some(ActivityReason::Unreported),
                        ));
                    }
                    Some((ActivityState::Blocked, Some(BlockKind::Input), None))
                }
                _ => None,
            },
            ActivityHarness::Codex => match frame.event.as_str() {
                "user_prompt_submit" | "pre_model_request" => {
                    row.open_correlations.clear();
                    Some((ActivityState::Working, None, None))
                }
                "stop" => {
                    row.open_correlations.clear();
                    if frame.background == BackgroundPresence::Active {
                        Some((ActivityState::Working, None, None))
                    } else {
                        Some((ActivityState::Idle, None, None))
                    }
                }
                "permission_request" => {
                    if !self.proofs.codex_permission_request_proven {
                        return Some((
                            ActivityState::Unknown,
                            None,
                            Some(ActivityReason::Unreported),
                        ));
                    }
                    Some((ActivityState::Blocked, Some(BlockKind::Permission), None))
                }
                "interrupt" => {
                    row.open_correlations.clear();
                    Some((ActivityState::Idle, None, None))
                }
                "session_start" => {
                    row.ended_at = None;
                    Some((
                        ActivityState::Unknown,
                        None,
                        Some(ActivityReason::Unreported),
                    ))
                }
                _ => None,
            },
            ActivityHarness::Agy => match frame.event.as_str() {
                "pre_invocation" | "post_invocation" | "pre_tool_use" | "post_tool_use" => {
                    // Never map agy ask_* tools to blocked (AE10).
                    Some((ActivityState::Working, None, None))
                }
                "stop" => match frame.background {
                    BackgroundPresence::Absent => Some((
                        ActivityState::Unknown,
                        None,
                        Some(ActivityReason::Unreported),
                    )),
                    BackgroundPresence::Active => Some((
                        ActivityState::Working,
                        None,
                        Some(ActivityReason::Background),
                    )),
                    BackgroundPresence::None => Some((ActivityState::Idle, None, None)),
                },
                _ => None,
            },
            ActivityHarness::Opencode => match frame.event.as_str() {
                "session.status.busy"
                | "session.status.retry"
                | "tool.execute.before"
                | "tool.execute.after"
                | "session.execution.started" => {
                    if row.open_correlations.is_empty() {
                        Some((ActivityState::Working, None, None))
                    } else {
                        None
                    }
                }
                "permission.asked" => {
                    if let Some(ref cid) = frame.correlation {
                        if !row.open_correlations.contains(cid)
                            && row.open_correlations.len() < ACTIVITY_MAX_CORRELATIONS
                        {
                            row.open_correlations.push(cid.clone());
                        }
                    }
                    Some((ActivityState::Blocked, Some(BlockKind::Permission), None))
                }
                "question.asked" => {
                    if let Some(ref cid) = frame.correlation {
                        if !row.open_correlations.contains(cid)
                            && row.open_correlations.len() < ACTIVITY_MAX_CORRELATIONS
                        {
                            row.open_correlations.push(cid.clone());
                        }
                    }
                    Some((ActivityState::Blocked, Some(BlockKind::Input), None))
                }
                "permission.replied" | "question.replied" => {
                    if let Some(ref cid) = frame.correlation {
                        if let Some(pos) = row.open_correlations.iter().position(|x| x == cid) {
                            row.open_correlations.remove(pos);
                        }
                    }
                    if row.open_correlations.is_empty() {
                        Some((ActivityState::Working, None, None))
                    } else {
                        None
                    }
                }
                "session.idle"
                | "session.status.idle"
                | "session.execution.succeeded"
                | "session.execution.failed" => {
                    row.open_correlations.clear();
                    Some((ActivityState::Idle, None, None))
                }
                _ => None,
            },
            ActivityHarness::Pi => match frame.event.as_str() {
                "agent_start" | "turn_start" => {
                    if row.open_correlations.is_empty() {
                        Some((ActivityState::Working, None, None))
                    } else {
                        None
                    }
                }
                "ui_prompt_start" => {
                    if let Some(ref cid) = frame.correlation {
                        if !row.open_correlations.contains(cid)
                            && row.open_correlations.len() < ACTIVITY_MAX_CORRELATIONS
                        {
                            row.open_correlations.push(cid.clone());
                        }
                    }
                    Some((ActivityState::Blocked, Some(BlockKind::Input), None))
                }
                "ui_prompt_end" => {
                    if let Some(ref cid) = frame.correlation {
                        if let Some(pos) = row.open_correlations.iter().position(|x| x == cid) {
                            row.open_correlations.remove(pos);
                        }
                    }
                    if row.open_correlations.is_empty() {
                        Some((ActivityState::Working, None, None))
                    } else {
                        None
                    }
                }
                "agent_settled" => {
                    row.open_correlations.clear();
                    Some((ActivityState::Idle, None, None))
                }
                // `agent_end` is explicitly NOT idle (§2.4).
                "agent_end" => Some((
                    ActivityState::Unknown,
                    None,
                    Some(ActivityReason::Unreported),
                )),
                _ => None,
            },
            ActivityHarness::Hermes => match frame.event.as_str() {
                "pre_llm_call" => {
                    // Clarify resolves on next pre_llm_call; approval waits for post_approval_response.
                    if row.block == Some(BlockKind::Input) {
                        row.open_correlations.clear();
                    }
                    if row.open_correlations.is_empty() {
                        Some((ActivityState::Working, None, None))
                    } else {
                        None
                    }
                }
                "pre_tool_call" => {
                    if row.open_correlations.is_empty() {
                        Some((ActivityState::Working, None, None))
                    } else {
                        None
                    }
                }
                "on_human_input_request" => {
                    let blk = frame.block.unwrap_or(BlockKind::Permission);
                    if blk != BlockKind::Input {
                        if let Some(ref cid) = frame.correlation {
                            if !row.open_correlations.contains(cid)
                                && row.open_correlations.len() < ACTIVITY_MAX_CORRELATIONS
                            {
                                row.open_correlations.push(cid.clone());
                            }
                        }
                    }
                    Some((ActivityState::Blocked, Some(blk), None))
                }
                "post_approval_response" => {
                    if let Some(ref cid) = frame.correlation {
                        if let Some(pos) = row.open_correlations.iter().position(|x| x == cid) {
                            row.open_correlations.remove(pos);
                        }
                    }
                    if row.open_correlations.is_empty() {
                        Some((ActivityState::Working, None, None))
                    } else {
                        None
                    }
                }
                "post_llm_call" => {
                    // AE15: post_llm_call is only idle if proven turn-final.
                    if self.proofs.hermes_post_llm_call_turn_final {
                        row.open_correlations.clear();
                        Some((ActivityState::Idle, None, None))
                    } else {
                        Some((ActivityState::Working, None, None))
                    }
                }
                "on_session_end" => {
                    row.open_correlations.clear();
                    if self.proofs.hermes_on_session_end_proven {
                        Some((ActivityState::Idle, None, None))
                    } else {
                        Some((
                            ActivityState::Unknown,
                            None,
                            Some(ActivityReason::Unreported),
                        ))
                    }
                }
                _ => None,
            },
        }
    }

    pub fn tick_aging(
        &mut self,
        conn: &mut Connection,
        resolver: &dyn OwnerResolver,
        now_secs: i64,
        now_mono: Instant,
    ) -> rusqlite::Result<Vec<ActivityTransition>> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        let addrs: Vec<String> = self.rows.keys().cloned().collect();
        let mut transitions = Vec::new();
        for addr in addrs {
            let Some(mut row) = self.rows.get(&addr).cloned() else {
                continue;
            };
            let fresh_at_mono = self.fresh_mono.get(&addr).copied().unwrap_or(now_mono);
            let elapsed = now_mono.saturating_duration_since(fresh_at_mono);
            let next = match row.state {
                ActivityState::Working => {
                    if elapsed >= Duration::from_secs(ACTIVITY_STALE_WORKING_SECS) {
                        Some((ActivityState::Unknown, None, Some(ActivityReason::Aged)))
                    } else {
                        None
                    }
                }
                ActivityState::Blocked => {
                    if elapsed >= Duration::from_secs(ACTIVITY_STALE_BLOCKED_SECS) {
                        Some((ActivityState::Unknown, None, Some(ActivityReason::Aged)))
                    } else {
                        None
                    }
                }
                ActivityState::Idle => {
                    let live = row.owner.is_some_and(|o| resolver.is_owner_live(o));
                    if live {
                        None
                    } else {
                        row.ended_at = Some(now_secs);
                        Some((
                            ActivityState::Unknown,
                            None,
                            Some(ActivityReason::IncarnationEnded),
                        ))
                    }
                }
                ActivityState::Unknown => None,
            };
            if let Some((st, blk, rsn)) = next {
                row.state = st;
                row.block = blk;
                row.reason = rsn;
                row.open_correlations.clear();
                row.last_payload_digest = None;
                row.changed_at = now_secs;
                if let Some(tr) = self.commit_transition(conn, row, now_mono)? {
                    transitions.push(tr);
                }
            }
        }
        let _ = ensure_meta(conn)?;
        Ok(transitions)
    }
}
