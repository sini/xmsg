use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{params, Connection, OptionalExtension};

use super::model::{
    ActivityDescriptor, ActivityHarness, ActivityReason, ActivityState, BlockKind, OwnerProof,
    ACTIVITY_ENDED_RETENTION_SECS, ACTIVITY_MAX_ENDPOINTS,
};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS session_activity_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    state_epoch TEXT NOT NULL,
    revision INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_activity (
    address TEXT PRIMARY KEY,
    harness TEXT NOT NULL,
    incarnation INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    owner_pid INTEGER,
    owner_started_at INTEGER,
    state TEXT NOT NULL,
    block TEXT,
    reason TEXT,
    open_correlations TEXT NOT NULL,
    last_native_seq INTEGER,
    last_event_id TEXT,
    last_payload_digest TEXT,
    changed_at INTEGER NOT NULL,
    fresh_at INTEGER NOT NULL,
    ended_at INTEGER
);
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredActivityRow {
    pub address: String,
    pub harness: ActivityHarness,
    pub incarnation: u64,
    pub owner: Option<OwnerProof>,
    pub state: ActivityState,
    pub block: Option<BlockKind>,
    pub reason: Option<ActivityReason>,
    pub open_correlations: Vec<String>,
    pub last_native_seq: Option<u64>,
    pub last_event_id: Option<String>,
    pub last_payload_digest: Option<String>,
    pub changed_at: i64,
    pub fresh_at: i64,
    pub ended_at: Option<i64>,
    pub revision: u64,
}

impl StoredActivityRow {
    pub fn to_descriptor(&self, state_epoch: &str) -> ActivityDescriptor {
        ActivityDescriptor {
            state: self.state,
            block: self.block,
            reason: self.reason,
            state_epoch: state_epoch.to_owned(),
            incarnation: self.incarnation,
            revision: self.revision,
            changed_at: self.changed_at,
            fresh_at: self.fresh_at,
        }
    }
}

pub fn mint_state_epoch() -> String {
    let mut bytes = [0u8; 16];
    let rng = SystemRandom::new();
    let _ = rng.fill(&mut bytes);
    hex::encode(bytes)
}

pub fn ensure_meta(conn: &Connection) -> rusqlite::Result<(String, u64)> {
    if let Some((epoch, rev)) = conn
        .query_row(
            "SELECT state_epoch, revision FROM session_activity_meta WHERE singleton = 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)),
        )
        .optional()?
    {
        return Ok((epoch, rev));
    }
    let epoch = mint_state_epoch();
    conn.execute(
        "INSERT OR IGNORE INTO session_activity_meta (singleton, state_epoch, revision) VALUES (1, ?1, 0)",
        params![epoch],
    )?;
    conn.query_row(
        "SELECT state_epoch, revision FROM session_activity_meta WHERE singleton = 1",
        [],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)),
    )
}

pub fn reset_meta(conn: &mut Connection) -> rusqlite::Result<String> {
    let tx = conn.transaction()?;
    let epoch = mint_state_epoch();
    tx.execute("DELETE FROM session_activity", [])?;
    tx.execute("DELETE FROM session_activity_meta", [])?;
    tx.execute(
        "INSERT INTO session_activity_meta (singleton, state_epoch, revision) VALUES (1, ?1, 0)",
        params![epoch],
    )?;
    tx.commit()?;
    Ok(epoch)
}

pub fn load_all(conn: &Connection) -> rusqlite::Result<(String, u64, Vec<StoredActivityRow>)> {
    let (epoch, rev) = ensure_meta(conn)?;
    let mut stmt = conn.prepare(
        "SELECT address, harness, incarnation, revision, owner_pid, owner_started_at, state, block, reason,
                open_correlations, last_native_seq, last_event_id, last_payload_digest,
                changed_at, fresh_at, ended_at
         FROM session_activity
         ORDER BY address ASC",
    )?;
    let mut rows = Vec::new();
    let mapped = stmt.query_map([], |r| {
        let address: String = r.get(0)?;
        let harness_s: String = r.get(1)?;
        let incarnation: i64 = r.get(2)?;
        let row_rev: i64 = r.get(3)?;
        let owner_pid: Option<i64> = r.get(4)?;
        let owner_started: Option<i64> = r.get(5)?;
        let state_s: String = r.get(6)?;
        let block_s: Option<String> = r.get(7)?;
        let reason_s: Option<String> = r.get(8)?;
        let corr_s: String = r.get(9)?;
        let last_seq: Option<i64> = r.get(10)?;
        let last_event_id: Option<String> = r.get(11)?;
        let last_payload_digest: Option<String> = r.get(12)?;
        let changed_at: i64 = r.get(13)?;
        let fresh_at: i64 = r.get(14)?;
        let ended_at: Option<i64> = r.get(15)?;
        Ok((
            address,
            harness_s,
            incarnation,
            row_rev,
            owner_pid,
            owner_started,
            state_s,
            block_s,
            reason_s,
            corr_s,
            last_seq,
            last_event_id,
            last_payload_digest,
            changed_at,
            fresh_at,
            ended_at,
        ))
    })?;
    for item in mapped {
        let (
            address,
            harness_s,
            incarnation,
            row_rev,
            owner_pid,
            owner_started,
            state_s,
            block_s,
            reason_s,
            corr_s,
            last_seq,
            last_event_id,
            last_payload_digest,
            changed_at,
            fresh_at,
            ended_at,
        ) = item?;
        let Some(harness) = ActivityHarness::parse(&harness_s) else {
            continue;
        };
        let Some(state) = ActivityState::parse(&state_s) else {
            continue;
        };
        let block = block_s.as_deref().and_then(BlockKind::parse);
        let reason = reason_s.as_deref().and_then(ActivityReason::parse);
        let open_correlations: Vec<String> = serde_json::from_str(&corr_s).unwrap_or_default();
        let owner = match (owner_pid, owner_started) {
            (Some(p), Some(s)) if p >= 0 && s >= 0 => Some(OwnerProof {
                pid: p as u32,
                started_at: s as u64,
            }),
            _ => None,
        };
        rows.push(StoredActivityRow {
            address,
            harness,
            incarnation: incarnation.max(0) as u64,
            owner,
            state,
            block,
            reason,
            open_correlations,
            last_native_seq: last_seq.map(|v| v.max(0) as u64),
            last_event_id,
            last_payload_digest,
            changed_at,
            fresh_at,
            ended_at,
            revision: row_rev.max(0) as u64,
        });
    }
    Ok((epoch, rev, rows))
}

/// Persist a transition and bump the node-wide `revision` in one transaction.
/// Returns `Ok(None)` if adding a new row would exceed `ACTIVITY_MAX_ENDPOINTS` (1024).
pub fn commit_row(
    conn: &mut Connection,
    row: &mut StoredActivityRow,
    bump_revision: bool,
) -> rusqlite::Result<Option<(String, u64)>> {
    let tx = conn.transaction()?;
    let (epoch, cur_rev) = ensure_meta(&tx)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_activity WHERE address = ?1)",
        params![row.address],
        |r| r.get(0),
    )?;
    if !exists {
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM session_activity", [], |r| r.get(0))?;
        if count as usize >= ACTIVITY_MAX_ENDPOINTS {
            tx.rollback()?;
            return Ok(None);
        }
    }

    let next_rev = if bump_revision { cur_rev + 1 } else { cur_rev };
    if bump_revision {
        tx.execute(
            "UPDATE session_activity_meta SET revision = ?1 WHERE singleton = 1",
            params![next_rev as i64],
        )?;
    }
    row.revision = next_rev;

    let corr_json = serde_json::to_string(&row.open_correlations).unwrap_or_else(|_| "[]".into());
    tx.execute(
        "INSERT INTO session_activity (
            address, harness, incarnation, revision, owner_pid, owner_started_at,
            state, block, reason, open_correlations, last_native_seq,
            last_event_id, last_payload_digest, changed_at, fresh_at, ended_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
         ON CONFLICT(address) DO UPDATE SET
            harness = excluded.harness,
            incarnation = excluded.incarnation,
            revision = excluded.revision,
            owner_pid = excluded.owner_pid,
            owner_started_at = excluded.owner_started_at,
            state = excluded.state,
            block = excluded.block,
            reason = excluded.reason,
            open_correlations = excluded.open_correlations,
            last_native_seq = excluded.last_native_seq,
            last_event_id = excluded.last_event_id,
            last_payload_digest = excluded.last_payload_digest,
            changed_at = excluded.changed_at,
            fresh_at = excluded.fresh_at,
            ended_at = excluded.ended_at",
        params![
            row.address,
            row.harness.as_str(),
            row.incarnation as i64,
            row.revision as i64,
            row.owner.map(|o| o.pid as i64),
            row.owner.map(|o| o.started_at as i64),
            row.state.as_str(),
            row.block.map(BlockKind::as_str),
            row.reason.map(ActivityReason::as_str),
            corr_json,
            row.last_native_seq.map(|s| s as i64),
            row.last_event_id,
            row.last_payload_digest,
            row.changed_at,
            row.fresh_at,
            row.ended_at,
        ],
    )?;
    tx.commit()?;
    Ok(Some((epoch, next_rev)))
}

pub fn update_fresh_at(conn: &Connection, address: &str, fresh_at: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE session_activity SET fresh_at = ?2 WHERE address = ?1",
        params![address, fresh_at],
    )?;
    Ok(())
}

pub fn prune_ended_incarnations(conn: &Connection, now_secs: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM session_activity WHERE ended_at IS NOT NULL AND (?1 - ended_at) >= ?2",
        params![now_secs, ACTIVITY_ENDED_RETENTION_SECS],
    )
}

pub fn apply_restart_policy<F>(
    conn: &mut Connection,
    mut is_owner_live: F,
    now_secs: i64,
) -> rusqlite::Result<(String, u64, Vec<StoredActivityRow>)>
where
    F: FnMut(OwnerProof) -> bool,
{
    let (epoch, _, mut rows) = load_all(conn)?;
    let mut changed = Vec::new();
    for row in &mut rows {
        let next = match row.state {
            ActivityState::Working | ActivityState::Blocked => Some((
                ActivityState::Unknown,
                None,
                Some(ActivityReason::Restarted),
            )),
            ActivityState::Idle => {
                let live = row.owner.is_some_and(&mut is_owner_live);
                if live {
                    None
                } else {
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
            if commit_row(conn, row, true)?.is_some() {
                changed.push(row.clone());
            }
        }
    }
    let (_, final_rev) = ensure_meta(conn)?;
    Ok((epoch, final_rev, changed))
}
