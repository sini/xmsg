use rusqlite::{params, Connection, Result};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::warn;

use crate::error::AppError;
use crate::inbox;
use crate::process;
use crate::registry::{self, Session, SessionDirs, SessionFileEntry};
use crate::storage::{self, now_epoch_secs, MessageRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceClaim {
    pub id: String,
    pub pid: u32,
    pub proc_start: String,
    pub suffix: u32,
    pub released: bool,
    pub created_at: i64,
}

impl InstanceClaim {
    pub fn address(&self) -> String {
        if self.suffix == 1 {
            self.id.clone()
        } else {
            format!("{}~{}", self.id, self.suffix)
        }
    }
}

pub fn cmp_proc_start(a: &str, b: &str) -> Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(n1), Ok(n2)) => n1.cmp(&n2),
        _ => a.cmp(b),
    }
}

pub fn is_uuid_shaped(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// A11: a UUID, optionally followed by `~<n>`, is an instance ID; anything else is a name.
pub fn is_instance_ref(s: &str) -> bool {
    match s.split_once('~') {
        Some((base, n)) => n.parse::<u32>().is_ok() && is_uuid_shaped(base),
        None => is_uuid_shaped(s),
    }
}

pub fn mint_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    } else {
        let u = ulid::Ulid::new();
        let ub = u.to_bytes();
        bytes.copy_from_slice(&ub);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub fn validate_service_name(name: &str) -> Result<(), AppError> {
    if name == "xmsg" {
        return Err(AppError::BadRequest(
            "service name 'xmsg' is reserved".to_string(),
        ));
    }
    if name.contains('@')
        || name.contains('·')
        || name.contains('~')
        || name.contains('.')
        || name.contains(':')
    {
        return Err(AppError::BadRequest(format!(
            "service name '{name}' contains forbidden character (@, ·, ~, . or :)"
        )));
    }
    if is_uuid_shaped(name) {
        return Err(AppError::BadRequest(format!(
            "service name '{name}' is UUID-shaped"
        )));
    }
    Ok(())
}

/// HA9-A §2.1 & E3: splits a `<parent>/<child>` reference when the part before the first `/`
/// is an instance reference (`is_instance_ref`, A11). Any other reference containing `/`
/// (such as a label `"fix/x"` or a service name `"a/b"`) returns `None` and takes the
/// existing service/label lookup unchanged.
pub fn split_subaddress(ref_str: &str) -> Option<(&str, &str)> {
    let (parent, child) = ref_str.split_once('/')?;
    if is_instance_ref(parent) {
        Some((parent, child))
    } else {
        None
    }
}

/// HA9-A §2.1: measured Claude subagent `agent_id` shapes:
/// - 17 lowercase hex characters (`measure-v0` §2.1);
/// - `a<name>-<16hex>` (`spike v0.1` §2, in-process teammates).
pub fn is_subagent_id_shaped(s: &str) -> bool {
    let is_lower_hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    if s.len() == 17 && s.bytes().all(is_lower_hex) {
        return true;
    }
    if let Some((prefix, hex_part)) = s.rsplit_once('-') {
        if prefix.starts_with('a')
            && prefix.len() > 1
            && hex_part.len() == 16
            && hex_part.bytes().all(is_lower_hex)
        {
            return true;
        }
    }
    false
}

/// HA9-A §2.1: a subagent name is accepted only if it passes `validate_service_name`,
/// contains no `/`, and is not agent-id-shaped.
pub fn validate_subagent_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::BadRequest(
            "subagent name must not be empty".to_string(),
        ));
    }
    validate_service_name(name)?;
    if name.contains('/') {
        return Err(AppError::BadRequest(format!(
            "subagent name '{name}' contains forbidden character '/'"
        )));
    }
    if is_subagent_id_shaped(name) {
        return Err(AppError::BadRequest(format!(
            "subagent name '{name}' is agent-id-shaped"
        )));
    }
    Ok(())
}

/// HA9-A §2.4: whether a bound subagent is currently in an active turn (`turn_pid` and
/// `turn_start` match a live parent process in `proc_root`).
pub fn is_subagent_in_turn(proc_root: &Path, row: &storage::SubagentBinding) -> bool {
    let (Some(pid), Some(start)) = (row.turn_pid, row.turn_start.as_deref()) else {
        return false;
    };
    if pid == 0 || start.is_empty() {
        return false;
    }
    match process::starttime(proc_root, pid) {
        Ok(st) => process::claude_start_token_matches(proc_root, &st, start),
        Err(_) => false,
    }
}

pub fn get_active_claim_for_proc(
    conn: &Connection,
    pid: u32,
    proc_start: &str,
) -> Result<Option<InstanceClaim>> {
    let mut stmt = conn.prepare(
        "SELECT id, pid, proc_start, suffix, released, created_at FROM instance_claims WHERE pid = ?1 AND proc_start = ?2 AND released = 0 LIMIT 1",
    )?;
    let mut rows = stmt.query(params![pid, proc_start])?;
    if let Some(row) = rows.next()? {
        Ok(Some(InstanceClaim {
            id: row.get(0)?,
            pid: row.get(1)?,
            proc_start: row.get(2)?,
            suffix: row.get(3)?,
            released: row.get::<_, i64>(4)? != 0,
            created_at: row.get(5)?,
        }))
    } else {
        Ok(None)
    }
}

pub fn get_active_claims_for_id(conn: &Connection, id: &str) -> Result<Vec<InstanceClaim>> {
    let mut stmt = conn.prepare(
        "SELECT id, pid, proc_start, suffix, released, created_at FROM instance_claims WHERE id = ?1 AND released = 0 ORDER BY suffix ASC",
    )?;
    let mut rows = stmt.query(params![id])?;
    let mut claims = Vec::new();
    while let Some(row) = rows.next()? {
        claims.push(InstanceClaim {
            id: row.get(0)?,
            pid: row.get(1)?,
            proc_start: row.get(2)?,
            suffix: row.get(3)?,
            released: row.get::<_, i64>(4)? != 0,
            created_at: row.get(5)?,
        });
    }
    Ok(claims)
}

pub fn get_all_claims_for_id(conn: &Connection, id: &str) -> Result<Vec<InstanceClaim>> {
    let mut stmt = conn.prepare(
        "SELECT id, pid, proc_start, suffix, released, created_at FROM instance_claims WHERE id = ?1 ORDER BY created_at ASC, suffix ASC",
    )?;
    let mut rows = stmt.query(params![id])?;
    let mut claims = Vec::new();
    while let Some(row) = rows.next()? {
        claims.push(InstanceClaim {
            id: row.get(0)?,
            pid: row.get(1)?,
            proc_start: row.get(2)?,
            suffix: row.get(3)?,
            released: row.get::<_, i64>(4)? != 0,
            created_at: row.get(5)?,
        });
    }
    Ok(claims)
}

#[derive(Debug, Clone)]
pub struct ForkNoticeToSend {
    pub id: String,
    pub pid1: u32,
    pub proc_start1: String,
    pub pid2: u32,
    pub proc_start2: String,
    pub recipient_pid: u32,
    pub recipient_proc_start: String,
    pub target_session_id: String,
    pub socket_path: PathBuf,
    pub from_name: String,
    pub text: String,
}

pub fn is_claude_proc_live(proc_root: &Path, pid: u32, expected: &str) -> bool {
    process::claude_proc_start_matches(proc_root, pid, expected)
}

/// XS3: whether `id` is recorded in `instance_seen` (or active `plugin_sessions`) as a
/// non-Claude instance (`harness != "claude"`), in which case a `~/.claude/sessions/<pid>.json`
/// file must not claim or overwrite it.
pub fn is_non_claude_instance(conn: &Connection, id: &str) -> Result<bool> {
    let seen_non_claude: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM instance_seen WHERE id = ?1 AND harness != 'claude') \
         OR EXISTS(SELECT 1 FROM plugin_sessions WHERE address = ?1)",
        params![id],
        |r| r.get(0),
    )?;
    Ok(seen_non_claude)
}

#[allow(clippy::type_complexity)]
pub fn sync_claims_db(
    conn: &Connection,
    proc_root: &Path,
    sessions_dirs: &(impl SessionDirs + ?Sized),
    node_name: &str,
) -> Result<
    (
        Vec<(InstanceClaim, SessionFileEntry)>,
        Vec<ForkNoticeToSend>,
    ),
    AppError,
> {
    let raw_entries = registry::read_session_entries(sessions_dirs);
    sync_claims_entries(conn, proc_root, raw_entries, node_name)
}

/// One claim scan over session file entries in the order given. The scan
/// itself orders new observations by `(procStart, pid)`, so the result does
/// not depend on the order of `raw_entries` (which is `read_dir` order in
/// production).
#[allow(clippy::type_complexity)]
pub fn sync_claims_entries(
    conn: &Connection,
    proc_root: &Path,
    raw_entries: Vec<SessionFileEntry>,
    node_name: &str,
) -> Result<
    (
        Vec<(InstanceClaim, SessionFileEntry)>,
        Vec<ForkNoticeToSend>,
    ),
    AppError,
> {
    // One transaction per scan: an error part-way rolls back every claim and
    // every notice claim it made, so none is recorded without being returned.
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Filter to live entries where process is still alive, proc_start matches, and the
    // presented session_id is not already recorded for a non-Claude harness (XS3).
    let mut live_entries = Vec::new();
    for e in raw_entries {
        if !is_claude_proc_live(proc_root, e.pid, &e.proc_start) {
            continue;
        }
        if is_non_claude_instance(conn, &e.session_id)
            .map_err(|err| AppError::Internal(err.to_string()))?
        {
            continue;
        }
        live_entries.push(e);
    }

    let now = now_epoch_secs();

    // 1. Recheck all active claims (released = 0)
    let mut stmt = conn
        .prepare("SELECT id, pid, proc_start, suffix, released, created_at FROM instance_claims WHERE released = 0")
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let active_claim_rows = stmt
        .query_map([], |row| {
            Ok(InstanceClaim {
                id: row.get(0)?,
                pid: row.get(1)?,
                proc_start: row.get(2)?,
                suffix: row.get(3)?,
                released: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            })
        })
        .map_err(|e| AppError::Internal(e.to_string()))?;

    for claim_res in active_claim_rows {
        let claim = claim_res.map_err(|e| AppError::Internal(e.to_string()))?;
        let still_presented = live_entries.iter().any(|e| {
            e.pid == claim.pid && e.proc_start == claim.proc_start && e.session_id == claim.id
        });

        if !still_presented {
            conn.execute(
                "UPDATE instance_claims SET released = 1 WHERE id = ?1 AND pid = ?2 AND proc_start = ?3",
                params![claim.id, claim.pid, claim.proc_start],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
            // Discovery is on demand, so the release is the latest moment X is known to
            // have been live: its parked lifetime runs from here (A14, D-1).
            if !is_non_claude_instance(conn, &claim.id)
                .map_err(|err| AppError::Internal(err.to_string()))?
            {
                storage::mark_live(conn, &claim.id, "claude", now)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
            }
        }
    }
    storage::purge_instance_seen(conn, now, 604_800)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // 2. Discover newly observed processes. A released (ID, process) row is not a holder:
    //    a process that presents X again after switching away is a new observation (D-2).
    let mut new_observations_by_id: HashMap<String, Vec<SessionFileEntry>> = HashMap::new();
    for entry in &live_entries {
        let mut check_stmt = conn
            .prepare("SELECT COUNT(*) FROM instance_claims WHERE id = ?1 AND pid = ?2 AND proc_start = ?3 AND released = 0")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let count: i64 = check_stmt
            .query_row(
                params![entry.session_id, entry.pid, entry.proc_start],
                |r| r.get(0),
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if count == 0 {
            new_observations_by_id
                .entry(entry.session_id.clone())
                .or_default()
                .push(entry.clone());
        }
    }

    // 3. For each ID with new observations, sort by (procStart, pid) and assign suffixes
    let mut newly_plain = Vec::new();
    for (id, mut entries) in new_observations_by_id {
        entries.sort_by(|a, b| {
            cmp_proc_start(&a.proc_start, &b.proc_start).then_with(|| a.pid.cmp(&b.pid))
        });

        for entry in entries {
            // Is plain ID (suffix 1) currently held by a live process?
            let mut plain_held_stmt = conn
                .prepare("SELECT COUNT(*) FROM instance_claims WHERE id = ?1 AND suffix = 1 AND released = 0")
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let plain_held_count: i64 = plain_held_stmt
                .query_row(params![id], |r| r.get(0))
                .map_err(|e| AppError::Internal(e.to_string()))?;

            let suffix = if plain_held_count == 0 {
                1
            } else {
                let mut max_suffix_stmt = conn
                    .prepare("SELECT COALESCE(MAX(suffix), 1) FROM instance_claims WHERE id = ?1")
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                let max_suffix: u32 = max_suffix_stmt
                    .query_row(params![id], |r| r.get(0))
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                std::cmp::max(2, max_suffix + 1)
            };
            if suffix == 1 {
                newly_plain.push(id.clone());
            }

            // The key is (id, pid, proc_start), so a released row of this process is
            // re-claimed in place, under the suffix just assigned.
            conn.execute(
                "INSERT INTO instance_claims (id, pid, proc_start, suffix, released, created_at) VALUES (?1, ?2, ?3, ?4, 0, ?5) ON CONFLICT(id, pid, proc_start) DO UPDATE SET suffix = excluded.suffix, released = 0, created_at = excluded.created_at",
                params![id, entry.pid, entry.proc_start, suffix, now],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        }
    }

    // 4. Gather all currently active claims paired with their live session file entries
    let mut active_pairs = Vec::new();
    let mut claims_by_id: HashMap<String, Vec<InstanceClaim>> = HashMap::new();

    let mut stmt = conn
        .prepare("SELECT id, pid, proc_start, suffix, released, created_at FROM instance_claims WHERE released = 0 ORDER BY suffix ASC")
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let active_claim_rows = stmt
        .query_map([], |row| {
            Ok(InstanceClaim {
                id: row.get(0)?,
                pid: row.get(1)?,
                proc_start: row.get(2)?,
                suffix: row.get(3)?,
                released: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            })
        })
        .map_err(|e| AppError::Internal(e.to_string()))?;

    for claim_res in active_claim_rows {
        let claim = claim_res.map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(entry) = live_entries.iter().find(|e| {
            e.pid == claim.pid && e.proc_start == claim.proc_start && e.session_id == claim.id
        }) {
            active_pairs.push((claim.clone(), entry.clone()));
            claims_by_id
                .entry(claim.id.clone())
                .or_default()
                .push(claim);
        }
    }

    // 5. Fork notices: one per (pair, recipient process). Each notice is
    //    claimed here, inside this scan's transaction and under the caller's
    //    DB lock, so two overlapping scans cannot both send it.
    //    `deliver_fork_notices` releases the claim if delivery fails, so a
    //    later scan sends it once.
    let mut notices_to_send = Vec::new();
    for (id, claims) in &claims_by_id {
        if claims.len() < 2 {
            continue;
        }
        let plain_addr = claims
            .iter()
            .find(|c| c.suffix == 1)
            .map_or_else(|| id.clone(), |c| c.address());

        for i in 0..claims.len() {
            for j in (i + 1)..claims.len() {
                let (c1, c2) = if (claims[i].pid, &claims[i].proc_start)
                    <= (claims[j].pid, &claims[j].proc_start)
                {
                    (&claims[i], &claims[j])
                } else {
                    (&claims[j], &claims[i])
                };

                for (me, other) in [(c1, c2), (c2, c1)] {
                    let Some(entry) = live_entries.iter().find(|e| {
                        e.pid == me.pid && e.proc_start == me.proc_start && e.session_id == me.id
                    }) else {
                        continue;
                    };
                    let claimed = conn
                        .execute(
                            "INSERT OR IGNORE INTO fork_notices (id, pid1, proc_start1, pid2, proc_start2, recipient_pid, recipient_proc_start, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![id, c1.pid, c1.proc_start, c2.pid, c2.proc_start, me.pid, me.proc_start, now],
                        )
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    if claimed == 0 {
                        continue;
                    }
                    notices_to_send.push(ForkNoticeToSend {
                        id: id.clone(),
                        pid1: c1.pid,
                        proc_start1: c1.proc_start.clone(),
                        pid2: c2.pid,
                        proc_start2: c2.proc_start.clone(),
                        recipient_pid: me.pid,
                        recipient_proc_start: me.proc_start.clone(),
                        target_session_id: me.address(),
                        socket_path: PathBuf::from(&entry.messaging_socket_path),
                        from_name: format!("xmsg@{node_name}"),
                        text: format!(
                            "xmsg: conversation {} is open in two processes on {}. This process is {}; the other is {}. A send to {} reaches {}.",
                            id, node_name, me.address(), other.address(), id, plain_addr
                        ),
                    });
                }
            }
        }
    }

    tx.commit().map_err(|e| AppError::Internal(e.to_string()))?;
    // D-1: a node that newly observes X holding its plain ID asks for X's queue.
    for id in &newly_plain {
        crate::handoff::observed(id);
    }
    Ok((active_pairs, notices_to_send))
}

/// Delivers notices claimed by `sync_claims_db`. A delivered notice is
/// stored as a message; a failed one has its claim released so a later scan
/// delivers it.
pub async fn deliver_fork_notices(
    db: &std::sync::Mutex<Connection>,
    notices: Vec<ForkNoticeToSend>,
) {
    if notices.is_empty() {
        return;
    }

    let mut outcomes = Vec::new();
    for notice in notices {
        let res = match inbox::encode_transport_line(&notice.from_name, &notice.text) {
            Ok(line) => inbox::deliver_to_socket(&notice.socket_path, &line).await,
            Err(e) => Err(e),
        };
        if let Err(e) = &res {
            warn!(
                "Failed delivering fork notice to {}: {}",
                notice.socket_path.display(),
                e
            );
        }
        outcomes.push((notice, res.is_ok()));
    }

    // A poisoned lock still holds a usable connection; recover it so a failed
    // notice's claim is released rather than kept forever.
    let conn = db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for (notice, delivered) in outcomes {
        let res = if delivered {
            let msg_id = ulid::Ulid::new().to_string();
            storage::insert_message(
                &conn,
                &MessageRecord {
                    id: msg_id.clone(),
                    created_at: now_epoch_secs(),
                    session_id: notice.target_session_id.clone(),
                    from_name: notice.from_name.clone(),
                    bytes: notice.text.len(),
                    outcome: "delivered".to_string(),
                    recipient_harness: "claude".to_string(),
                    return_harness: None,
                    return_session_id: None,
                    thread_id: msg_id,
                    return_host: None,
                },
            )
        } else {
            conn.execute(
                "DELETE FROM fork_notices WHERE id = ?1 AND pid1 = ?2 AND proc_start1 = ?3 AND pid2 = ?4 AND proc_start2 = ?5 AND recipient_pid = ?6 AND recipient_proc_start = ?7",
                params![notice.id, notice.pid1, notice.proc_start1, notice.pid2, notice.proc_start2, notice.recipient_pid, notice.recipient_proc_start],
            )
            .map(|_| ())
        };
        if let Err(e) = res {
            warn!(
                "Fork notice bookkeeping failed for {}: {}",
                notice.target_session_id, e
            );
        }
    }
}

/// A queued message taken for a live holder of its plain ID (A14) or a not-in-turn
/// subagent falling back to its live parent (HA9-A §2.4, E4).
#[derive(Debug, Clone)]
pub struct QueuedDelivery {
    pub message: storage::QueuedMessage,
    pub socket_path: PathBuf,
    pub subagent_header: Option<String>,
}

/// Takes what is queued for every live plain-ID holder in one scan's pairs, and for every
/// not-in-turn subagent of any active parent claim (regardless of suffix; HA9-A §2.4, E4).
/// A queue drains when its conversation is next observed, and a taken message is marked
/// delivered, so the observation after that delivers nothing again.
pub fn take_queued_for(
    conn: &Connection,
    proc_root: &Path,
    active_pairs: &[(InstanceClaim, SessionFileEntry)],
) -> Result<Vec<QueuedDelivery>, AppError> {
    let now = now_epoch_secs();
    let mut out = Vec::new();
    for (claim, entry) in active_pairs.iter().filter(|(c, _)| c.suffix == 1) {
        for message in storage::take_queued(conn, &claim.id, now)
            .map_err(|e| AppError::Internal(e.to_string()))?
        {
            out.push(QueuedDelivery {
                message,
                socket_path: PathBuf::from(&entry.messaging_socket_path),
                subagent_header: None,
            });
        }
    }
    // OQ2 (recommended arm: fallback) + E4 + D3: sweep every not-in-turn child (`turn_pid`
    // NULL or dead) across all `subagents` rows, whatever the parent's harness.
    let all_subagents =
        storage::list_all_subagents(conn).map_err(|e| AppError::Internal(e.to_string()))?;
    for sub in all_subagents {
        if is_subagent_in_turn(proc_root, &sub) {
            continue;
        }
        let sub_queue_id = format!("{}/{}", sub.parent, sub.agent_id);
        let child_part = sub.name.as_deref().unwrap_or(&sub.agent_id);
        let header = format!("to={}/{} agent_id={}", sub.parent, child_part, sub.agent_id);
        if let Some((_, entry)) = active_pairs.iter().find(|(c, _)| c.address() == sub.parent) {
            for message in storage::take_queued(conn, &sub_queue_id, now)
                .map_err(|e| AppError::Internal(e.to_string()))?
            {
                out.push(QueuedDelivery {
                    message,
                    socket_path: PathBuf::from(&entry.messaging_socket_path),
                    subagent_header: Some(header.clone()),
                });
            }
        } else {
            let is_plugin_or_pi = crate::plugin::session(conn, &sub.parent)
                .map_err(|e| AppError::Internal(e.to_string()))?
                .is_some()
                || storage::seen_instance(conn, &sub.parent, now, 604_800)
                    .map_err(|e| AppError::Internal(e.to_string()))?
                    .is_some_and(|s| {
                        (s.harness == "pi" || crate::plugin::harness(&s.harness).is_some())
                            && s.reclaimable
                            && now < s.last_live + 604_800
                    });
            if is_plugin_or_pi {
                for message in storage::take_queued(conn, &sub_queue_id, now)
                    .map_err(|e| AppError::Internal(e.to_string()))?
                {
                    let body_with_header = format!("{header}\n{}", message.body);
                    let pi_msg = storage::PiPendingMessage {
                        id: message.id.clone(),
                        session_id: sub.parent.clone(),
                        created_at: message.created_at,
                        from_name: message.from_name.clone(),
                        bytes: message.body.len(),
                        text: body_with_header,
                        envelope: format!(
                            "[xmsg] from={} message_id={}\n{header}\n\n{}",
                            message.from_name, message.id, message.body
                        ),
                        delivered_at: None,
                    };
                    if !storage::insert_pi_message(conn, &pi_msg)
                        .map_err(|e| AppError::Internal(e.to_string()))?
                    {
                        storage::untake_queued(conn, &message.id)
                            .map_err(|e| AppError::Internal(e.to_string()))?;
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Delivers messages taken by `take_queued_for`, in order. A delivered message's outcome
/// becomes `delivered`; a failed one is put back for the next observation.
pub async fn deliver_queued(db: &std::sync::Mutex<Connection>, deliveries: Vec<QueuedDelivery>) {
    let mut outcomes = Vec::new();
    for d in deliveries {
        let body = match &d.subagent_header {
            Some(hdr) => format!("{hdr}\n{}", d.message.body),
            None => d.message.body.clone(),
        };
        let res = match inbox::encode_transport_line(&d.message.from_name, &body) {
            Ok(line) => inbox::deliver_to_socket(&d.socket_path, &line).await,
            Err(e) => Err(e),
        };
        if let Err(e) = &res {
            warn!(
                "Failed delivering queued message {} to {}: {}",
                d.message.id,
                d.socket_path.display(),
                e
            );
        }
        outcomes.push((d.message.id, res.is_ok()));
    }
    let conn = db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for (id, delivered) in outcomes {
        let res = if delivered {
            storage::update_message_outcome(&conn, &id, "delivered").map(|_| ())
        } else {
            storage::untake_queued(&conn, &id)
        };
        if let Err(e) = res {
            warn!("Queued message bookkeeping failed for {}: {}", id, e);
        }
    }
}

/// Runs one claim scan, then `f` over its live (claim, session file) pairs,
/// under the DB lock; then delivers the fork notices that scan claimed and the
/// queued messages it took (A14).
/// Every surface that observes the claim table goes through here, so none can
/// observe a fork and drop its notice.
///
/// Delivery runs on its own task, so dropping this future (a client that
/// disconnects mid-request) neither loses a claimed notice nor keeps its
/// claim. A caller that runs to completion returns after delivery.
pub async fn with_claims<T>(
    db: &Arc<Mutex<Connection>>,
    proc_root: &Path,
    sessions_dirs: &(impl SessionDirs + ?Sized),
    node_name: &str,
    f: impl FnOnce(&Connection, &[(InstanceClaim, SessionFileEntry)]) -> T,
) -> Result<T, AppError> {
    let (out, notices, queued) = {
        let conn = db.lock().map_err(|e| AppError::Internal(e.to_string()))?;
        let (pairs, notices) = sync_claims_db(&conn, proc_root, sessions_dirs, node_name)?;
        let queued = take_queued_for(&conn, proc_root, &pairs)?;
        (f(&conn, &pairs), notices, queued)
    };
    if !notices.is_empty() || !queued.is_empty() {
        let db = Arc::clone(db);
        let delivery = tokio::spawn(async move {
            deliver_fork_notices(&db, notices).await;
            deliver_queued(&db, queued).await;
        });
        if let Err(e) = delivery.await {
            warn!("Fork notice delivery task failed: {}", e);
        }
    }
    Ok(out)
}

pub async fn sync_claims(
    db: &Arc<Mutex<Connection>>,
    proc_root: &Path,
    sessions_dirs: &(impl SessionDirs + ?Sized),
    node_name: &str,
) -> Result<Vec<(InstanceClaim, SessionFileEntry)>, AppError> {
    with_claims(db, proc_root, sessions_dirs, node_name, |_, pairs| {
        pairs.to_vec()
    })
    .await
}

/// One live Claude instance, as resolution returns it: its session under its instance
/// address, and its messaging socket.
pub type ClaudeTarget = (Session, PathBuf);

fn claude_target(claim: &InstanceClaim, entry: &SessionFileEntry) -> ClaudeTarget {
    let mut session: Session = entry.clone().into();
    session.session_id = claim.address();
    (session, PathBuf::from(&entry.messaging_socket_path))
}

/// Resolves `ref_str` as a Claude instance ID against one scan's live pairs: `X~n` or a
/// bare `X`. `None` when it names no live or recorded Claude instance by ID.
///
/// A bare X while the plain ID is free and only `X~n` forks are live is `ambiguous`,
/// listing each fork as `X~n@node` (D-4); it is never taken as not running.
pub fn resolve_claude_id_in(
    conn: &Connection,
    active_pairs: &[(InstanceClaim, SessionFileEntry)],
    node_name: &str,
    ref_str: &str,
) -> Option<Result<ClaudeTarget, AppError>> {
    // 1. A fork address, "X~n".
    if let Some((base_id, suffix_str)) = ref_str.split_once('~') {
        if let Ok(suffix) = suffix_str.parse::<u32>() {
            if let Some((claim, entry)) = active_pairs
                .iter()
                .find(|(c, _)| c.id == base_id && c.suffix == suffix)
            {
                return Some(Ok(claude_target(claim, entry)));
            }
            // Recorded and released: the fork is gone.
            let recorded = conn
                .query_row(
                    "SELECT pid FROM instance_claims WHERE id = ?1 AND suffix = ?2 ORDER BY created_at DESC LIMIT 1",
                    params![base_id, suffix],
                    |r| r.get::<_, u32>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(AppError::Internal(e.to_string())),
                });
            return match recorded {
                Ok(Some(pid)) => Some(Err(AppError::Gone {
                    session_id: ref_str.to_string(),
                    pid,
                })),
                Ok(None) => Some(Err(AppError::NotFound(ref_str.to_string()))),
                Err(e) => Some(Err(e)),
            };
        }
    }

    // 2. A bare ID.
    let id_matches: Vec<&(InstanceClaim, SessionFileEntry)> = active_pairs
        .iter()
        .filter(|(claim, entry)| claim.id == ref_str || entry.session_id == ref_str)
        .collect();
    if !id_matches.is_empty() {
        if let Some((claim, entry)) = id_matches.iter().find(|(c, _)| c.suffix == 1) {
            return Some(Ok(claude_target(claim, entry)));
        }
        let candidates: Vec<String> = id_matches
            .iter()
            .map(|(c, _)| format!("{}@{node_name}", c.address()))
            .collect();
        return Some(Err(AppError::Ambiguous(candidates.join(", "))));
    }

    None
}

/// The live Claude instances whose label is `ref_str`. A label `inbox::clean_label`
/// drops carries no name, so nothing resolves by it (AM-8).
pub fn claude_label_matches(
    active_pairs: &[(InstanceClaim, SessionFileEntry)],
    ref_str: &str,
) -> Vec<ClaudeTarget> {
    active_pairs
        .iter()
        .filter(|(_, entry)| {
            entry
                .name
                .as_deref()
                .and_then(inbox::clean_label)
                .as_deref()
                == Some(ref_str)
        })
        .map(|(claim, entry)| claude_target(claim, entry))
        .collect()
}

/// Why `ref_str` names no live Claude instance: `Gone` when it was claimed before, or when
/// it was observed before and a dead session file still names it; `NotFound` otherwise.
pub fn claude_absence_in(
    conn: &Connection,
    sessions_dirs: &(impl SessionDirs + ?Sized),
    ref_str: &str,
) -> AppError {
    let recorded = conn.query_row(
        "SELECT pid FROM instance_claims WHERE id = ?1 ORDER BY created_at DESC LIMIT 1",
        params![ref_str],
        |r| r.get::<_, u32>(0),
    );
    match recorded {
        Ok(pid) => {
            return AppError::Gone {
                session_id: ref_str.to_string(),
                pid,
            }
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(e) => return AppError::Internal(e.to_string()),
    }
    // A bare ID no Claude process here was ever observed presenting is `not_found` (A14, XS3),
    // even when a session file still names it.
    match storage::seen_instance(conn, ref_str, 0, 0) {
        Ok(Some(seen)) if seen.harness == "claude" => {}
        Ok(_) => return AppError::NotFound(ref_str.to_string()),
        Err(e) => return AppError::Internal(e.to_string()),
    }

    for entry in registry::read_session_entries(sessions_dirs) {
        if entry.session_id == ref_str || entry.name.as_deref() == Some(ref_str) {
            return AppError::Gone {
                session_id: entry.session_id,
                pid: entry.pid,
            };
        }
    }

    AppError::NotFound(ref_str.to_string())
}

/// Resolves a Claude session reference against one scan's live pairs: by instance ID,
/// then by a unique label, else why it is absent.
pub fn resolve_claude_in(
    conn: &Connection,
    sessions_dirs: &(impl SessionDirs + ?Sized),
    active_pairs: &[(InstanceClaim, SessionFileEntry)],
    node_name: &str,
    ref_str: &str,
) -> Result<ClaudeTarget, AppError> {
    if let Some(res) = resolve_claude_id_in(conn, active_pairs, node_name, ref_str) {
        return res;
    }
    let mut labelled = claude_label_matches(active_pairs, ref_str);
    match labelled.len() {
        0 => Err(claude_absence_in(conn, sessions_dirs, ref_str)),
        1 => Ok(labelled.remove(0)),
        _ => Err(AppError::Ambiguous(
            labelled
                .iter()
                .map(|(s, _)| format!("{}@{node_name}", s.session_id))
                .collect::<Vec<_>>()
                .join(", "),
        )),
    }
}

pub async fn resolve_claude_session_and_deliver(
    db: &Arc<Mutex<Connection>>,
    proc_root: &Path,
    sessions_dirs: &(impl SessionDirs + ?Sized),
    node_name: &str,
    ref_str: &str,
) -> Result<(Session, PathBuf), AppError> {
    with_claims(db, proc_root, sessions_dirs, node_name, |conn, pairs| {
        resolve_claude_in(conn, sessions_dirs, pairs, node_name, ref_str)
    })
    .await?
}
