use rusqlite::{params, Connection, OptionalExtension, Result, Transaction};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessageRecord {
    pub id: String,
    pub created_at: i64,
    pub session_id: String,
    pub from_name: String,
    pub bytes: usize,
    pub outcome: String,
    #[serde(default = "default_recipient_harness")]
    pub recipient_harness: String,
    #[serde(default)]
    pub return_harness: Option<String>,
    #[serde(default)]
    pub return_session_id: Option<String>,
    #[serde(default)]
    pub thread_id: String,
    #[serde(default)]
    pub return_host: Option<String>,
}

fn default_recipient_harness() -> String {
    "claude".to_string()
}

pub use crate::client::wire::ReplyRecord;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PiPendingMessage {
    pub id: String,
    pub session_id: String,
    pub created_at: i64,
    pub from_name: String,
    pub bytes: usize,
    pub text: String,
    pub envelope: String,
    pub delivered_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgyPendingMessage {
    pub id: String,
    pub session_id: String,
    pub created_at: i64,
    pub from_name: String,
    pub bytes: usize,
    pub text: String,
    pub envelope: String,
    pub delivered_at: Option<i64>,
}

pub use crate::client::Origin;

fn origin_from_sql(s: String) -> Result<Origin> {
    serde_json::from_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SvcPendingMessage {
    pub id: String,
    pub session_id: String,
    pub created_at: i64,
    pub from_name: String,
    pub bytes: usize,
    pub text: String,
    pub envelope: String,
    pub delivered_at: Option<i64>,
    pub origin: Origin,
    /// The message this one answers, when it is a pushed reply (A10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdempotencyRecord {
    #[serde(default)]
    pub refs_digest: Option<String>,
    pub principal: String,
    pub key: String,
    pub body: String,
    /// The send's `to`, as given: one key names one body to one recipient.
    pub to_ref: String,
    pub message_id: String,
    pub session_id: String,
    pub from_name: String,
    pub bytes: usize,
    pub outcome: String,
    pub created_at: i64,
}

pub fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Schema N: the first schema that records its version (`PRAGMA user_version`).
/// Neither the deployed `ee1b6ca` nor any build before it set one, so they read 0.
pub const SCHEMA_VERSION: i64 = 3;

/// The tables that hold message state. A database below schema N has them in an
/// older shape, and the migration drops them with their rows (limited release).
/// `replies` references `messages`, so it is dropped first: with foreign keys on, dropping
/// a parent that still has child rows fails.
const MESSAGE_STATE_TABLES: &[&str] = &[
    "attachment_verified",
    "attachments",
    "staged_blobs",
    "blob_chunks",
    "blobs",
    "replies",
    "messages",
    "outbound",
    "pi_pending_messages",
    "agy_pending_messages",
    "svc_pending_messages",
    "idempotency_keys",
    "reply_idempotency_keys",
    "peer_mailbox",
    "forwarded_messages",
    "instance_queue",
    "location_cache",
    "handoff_owed",
    "codex_handoff",
    "codex_roots",
];

const SCHEMA_N: &str = r#"
        CREATE TABLE IF NOT EXISTS blobs (
            sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, utf8 INTEGER NOT NULL,
            data BLOB NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attachments (
            item_id TEXT NOT NULL, idx INTEGER NOT NULL, sha256 TEXT NOT NULL,
            name TEXT NOT NULL, size INTEGER NOT NULL, media_type TEXT NOT NULL,
            expires_at INTEGER NOT NULL, upstream TEXT NOT NULL DEFAULT '',
            downstream TEXT NOT NULL DEFAULT '', PRIMARY KEY (item_id, idx)
        );
        CREATE INDEX IF NOT EXISTS idx_attachments_sha256 ON attachments(sha256);
        CREATE TABLE IF NOT EXISTS attachment_verified (
            item_id TEXT NOT NULL, idx INTEGER NOT NULL, sha256 TEXT NOT NULL,
            upstream TEXT NOT NULL, PRIMARY KEY (item_id, idx)
        );
        CREATE TABLE IF NOT EXISTS staged_blobs (
            principal TEXT NOT NULL, sha256 TEXT NOT NULL, expires_at INTEGER NOT NULL,
            PRIMARY KEY (principal, sha256)
        );
        CREATE TABLE IF NOT EXISTS blob_chunks (
            owner TEXT NOT NULL, upload TEXT NOT NULL, offset INTEGER NOT NULL,
            data BLOB NOT NULL, created_at INTEGER NOT NULL,
            PRIMARY KEY (owner, upload, offset)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            session_id TEXT NOT NULL,
            from_name TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            outcome TEXT NOT NULL,
            recipient_harness TEXT NOT NULL DEFAULT 'claude',
            return_harness TEXT,
            return_session_id TEXT,
            thread_id TEXT NOT NULL DEFAULT '',
            return_host TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS outbound (
            id TEXT PRIMARY KEY,
            peer TEXT NOT NULL,
            target_ref TEXT NOT NULL,
            outcome TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0,
            via_mailbox INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_outbound_created_at ON outbound(created_at);

        CREATE TABLE IF NOT EXISTS replies (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL REFERENCES messages(id),
            created_at INTEGER NOT NULL,
            replier_session_id TEXT NOT NULL,
            text TEXT NOT NULL,
            push_outcome TEXT,
            pushed_message_id TEXT
        );

        CREATE TABLE IF NOT EXISTS pi_pending_messages (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            from_name TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            text TEXT NOT NULL,
            envelope TEXT NOT NULL,
            delivered_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS agy_pending_messages (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            from_name TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            text TEXT NOT NULL,
            envelope TEXT NOT NULL,
            delivered_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS svc_pending_messages (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            from_name TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            text TEXT NOT NULL,
            envelope TEXT NOT NULL,
            delivered_at INTEGER,
            origin TEXT NOT NULL,
            in_reply_to TEXT
        );

        CREATE TABLE IF NOT EXISTS idempotency_keys (
            principal TEXT NOT NULL,
            key TEXT NOT NULL,
            body TEXT NOT NULL,
            message_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            from_name TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            outcome TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            to_ref TEXT NOT NULL DEFAULT '',
            refs_digest TEXT,
            PRIMARY KEY (principal, key)
        );

        CREATE INDEX IF NOT EXISTS idx_replies_message_seq ON replies(message_id, seq);
        CREATE INDEX IF NOT EXISTS idx_replies_created_at ON replies(created_at);
        CREATE INDEX IF NOT EXISTS idx_pi_pending_session ON pi_pending_messages(session_id, delivered_at);
        CREATE INDEX IF NOT EXISTS idx_pi_pending_created_at ON pi_pending_messages(created_at);
        CREATE INDEX IF NOT EXISTS idx_agy_pending_session ON agy_pending_messages(session_id, delivered_at);
        CREATE INDEX IF NOT EXISTS idx_agy_pending_created_at ON agy_pending_messages(created_at);
        CREATE INDEX IF NOT EXISTS idx_svc_pending_session ON svc_pending_messages(session_id, delivered_at);
        CREATE INDEX IF NOT EXISTS idx_svc_pending_created_at ON svc_pending_messages(created_at);
        CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys(created_at);

        CREATE TABLE IF NOT EXISTS reply_idempotency_keys (
            principal TEXT NOT NULL,
            key TEXT NOT NULL,
            in_reply_to TEXT NOT NULL,
            body TEXT NOT NULL,
            reply_id TEXT NOT NULL,
            state TEXT NOT NULL,
            seq INTEGER,
            created_at INTEGER NOT NULL,
            refs_digest TEXT,
            PRIMARY KEY (principal, key)
        );

        CREATE TABLE IF NOT EXISTS peer_mailbox (
            id TEXT PRIMARY KEY,
            peer TEXT NOT NULL,
            target_ref TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            from_name TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            body TEXT NOT NULL,
            envelope TEXT NOT NULL,
            origin TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_peer_mailbox_peer_created ON peer_mailbox(peer, created_at);

        CREATE TABLE IF NOT EXISTS forwarded_messages (
            id TEXT PRIMARY KEY,
            origin_peer TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_forwarded_messages_created_at ON forwarded_messages(created_at);

        CREATE TABLE IF NOT EXISTS instance_claims (
            id TEXT NOT NULL,
            pid INTEGER NOT NULL,
            proc_start TEXT NOT NULL,
            suffix INTEGER NOT NULL,
            released INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (id, pid, proc_start)
        );
        CREATE INDEX IF NOT EXISTS idx_instance_claims_id ON instance_claims(id);
        CREATE INDEX IF NOT EXISTS idx_instance_claims_proc ON instance_claims(pid, proc_start);

        CREATE TABLE IF NOT EXISTS subagents (
            parent      TEXT NOT NULL,
            agent_id    TEXT NOT NULL,
            name        TEXT,
            agent_type  TEXT,
            tool_use_id TEXT,
            bound_at    INTEGER NOT NULL,
            turn_pid    INTEGER,
            turn_start  TEXT,
            last_active INTEGER NOT NULL DEFAULT 0,
            stopped_at  INTEGER,
            PRIMARY KEY (parent, agent_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_subagents_name ON subagents(parent, name) WHERE name IS NOT NULL;

        CREATE TABLE IF NOT EXISTS instance_queue (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            from_name TEXT NOT NULL,
            body TEXT NOT NULL,
            delivered_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_instance_queue_instance ON instance_queue(instance_id, delivered_at);

        CREATE TABLE IF NOT EXISTS handoff_owed (
            id TEXT NOT NULL,
            holder TEXT NOT NULL,
            acks TEXT NOT NULL DEFAULT '[]',
            until INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (id, holder)
        );

        CREATE TABLE IF NOT EXISTS location_cache (
            id TEXT PRIMARY KEY,
            node TEXT NOT NULL,
            cached_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS instance_seen (
            id TEXT PRIMARY KEY,
            harness TEXT NOT NULL,
            last_live INTEGER NOT NULL,
            reclaim_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS fork_notices (
            id TEXT NOT NULL,
            pid1 INTEGER NOT NULL,
            proc_start1 TEXT NOT NULL,
            pid2 INTEGER NOT NULL,
            proc_start2 TEXT NOT NULL,
            recipient_pid INTEGER NOT NULL,
            recipient_proc_start TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (id, pid1, proc_start1, pid2, proc_start2, recipient_pid, recipient_proc_start)
        );

        CREATE TABLE IF NOT EXISTS codex_roots (
            root_id TEXT PRIMARY KEY,
            codex_home TEXT NOT NULL,
            owner_pid INTEGER NOT NULL,
            owner_starttime TEXT NOT NULL,
            generation INTEGER NOT NULL,
            label TEXT NOT NULL,
            cwd TEXT,
            registered_at INTEGER NOT NULL,
            rollout_dev INTEGER NOT NULL DEFAULT 0,
            rollout_ino INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            revoked INTEGER NOT NULL DEFAULT 0,
            restart_pending INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS codex_handoff (
            message_id TEXT PRIMARY KEY,
            root_id TEXT NOT NULL,
            root_generation INTEGER NOT NULL,
            carrier TEXT NOT NULL,
            state TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_codex_handoff_root ON codex_handoff(root_id, root_generation, state);
        "#;

/// Opens a database at schema N. A database already at N keeps its rows, and gains any
/// table schema N has since been extended with in place (plan §6 D12); one below N (the
/// deployed `ee1b6ca` schema, or none at all) has its message state dropped and is created
/// at N in one transaction; one above N is refused.
pub fn init_db(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    // Plugin registrations end with this connection, so their tables are not schema N's.
    conn.execute_batch(crate::plugin::SCHEMA)?;
    if version == SCHEMA_VERSION {
        conn.execute_batch(SCHEMA_N)?;
        // A column schema N has since been extended with. A key recorded before it binds
        // no recipient, so its replay with any `to` is a conflict, never a second delivery.
        let has_to_ref: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('idempotency_keys') WHERE name = 'to_ref'",
            [],
            |r| r.get(0),
        )?;
        if !has_to_ref {
            conn.execute_batch(
                "ALTER TABLE idempotency_keys ADD COLUMN to_ref TEXT NOT NULL DEFAULT ''",
            )?;
        }
        for table in ["idempotency_keys", "reply_idempotency_keys"] {
            let has_refs_digest: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info(?1) WHERE name = 'refs_digest'",
                [table],
                |r| r.get(0),
            )?;
            if !has_refs_digest {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN refs_digest TEXT"))?;
            }
        }
        // A send recorded before it is not known to be in a dial-out mailbox, so it takes
        // replies strictly (fail closed).
        let has_via_mailbox: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('outbound') WHERE name = 'via_mailbox'",
            [],
            |r| r.get(0),
        )?;
        if !has_via_mailbox {
            conn.execute_batch(
                "ALTER TABLE outbound ADD COLUMN via_mailbox INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        let has_reclaim_hash: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('instance_seen') WHERE name = 'reclaim_hash'",
            [],
            |r| r.get(0),
        )?;
        if !has_reclaim_hash {
            conn.execute_batch("ALTER TABLE instance_seen ADD COLUMN reclaim_hash TEXT")?;
        }
        for (col, ddl) in [
            ("rollout_dev", "INTEGER NOT NULL DEFAULT 0"),
            ("rollout_ino", "INTEGER NOT NULL DEFAULT 0"),
            ("active", "INTEGER NOT NULL DEFAULT 1"),
            ("restart_pending", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let has_col: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('codex_roots') WHERE name = ?1",
                params![col],
                |r| r.get(0),
            )?;
            if !has_col {
                conn.execute_batch(&format!("ALTER TABLE codex_roots ADD COLUMN {col} {ddl}"))?;
                if col == "active" {
                    // C1: In pre-resume databases (which lack the `active` column), every
                    // unloaded, ended, or restarted root had `revoked = 1` because `revoked`
                    // was the only non-live column. Clear `revoked = 0` when adding `active`
                    // so pre-existing rows upgrade as `StaleAfterResume` rather than
                    // sticky `RevokedByOperator`.
                    conn.execute_batch("UPDATE codex_roots SET revoked = 0")?;
                }
            }
        }
        for (col, ddl) in [
            ("last_active", "INTEGER NOT NULL DEFAULT 0"),
            ("stopped_at", "INTEGER"),
        ] {
            let has_col: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('subagents') WHERE name = ?1",
                params![col],
                |r| r.get(0),
            )?;
            if !has_col {
                conn.execute_batch(&format!("ALTER TABLE subagents ADD COLUMN {col} {ddl}"))?;
                if col == "last_active" {
                    conn.execute_batch(
                        "UPDATE subagents SET last_active = bound_at WHERE last_active = 0",
                    )?;
                }
            }
        }
        return Ok(());
    }
    if version > SCHEMA_VERSION {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
            Some(format!(
                "database schema version {version} is newer than this xmsg (schema {SCHEMA_VERSION})"
            )),
        ));
    }
    let tx = conn.unchecked_transaction()?;
    for table in MESSAGE_STATE_TABLES {
        tx.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))?;
    }
    tx.execute_batch(SCHEMA_N)?;
    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
    tx.commit()
}

pub fn insert_message(conn: &Connection, msg: &MessageRecord) -> Result<()> {
    write_message(conn, msg, "")
}

/// `insert_message`, replacing the record of an earlier attempt under the same ID (a
/// keyed send's takeover, or a redelivery after a recorded failure).
pub fn upsert_message(conn: &Connection, msg: &MessageRecord) -> Result<()> {
    write_message(
        conn,
        msg,
        " ON CONFLICT (id) DO UPDATE SET created_at = excluded.created_at,
         session_id = excluded.session_id, from_name = excluded.from_name,
         bytes = excluded.bytes, outcome = excluded.outcome,
         recipient_harness = excluded.recipient_harness,
         return_harness = excluded.return_harness,
         return_session_id = excluded.return_session_id,
         thread_id = excluded.thread_id, return_host = excluded.return_host",
    )
}

/// Records the resolved recipient on a `pending` message row before `deliver` wakes the
/// recipient (XF2), so a recipient that replies immediately finds its own `session_id`
/// and `recipient_harness` on the row before `deliver_send` returns.
pub fn record_message_recipient(
    conn: &Connection,
    id: &str,
    session_id: &str,
    recipient_harness: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE messages SET session_id = ?2, recipient_harness = ?3 WHERE id = ?1",
        params![id, session_id, recipient_harness],
    )?;
    Ok(())
}

/// A send's record is written, with the outcome `pending`, before it is delivered, and its
/// recipient is recorded before `deliver` wakes the recipient; once delivered it is
/// completed with the outcome and return host.
pub fn complete_message(
    conn: &Connection,
    id: &str,
    outcome: &str,
    return_host: Option<&str>,
) -> Result<()> {
    conn.execute(
        // `queued` never replaces `delivered`: the ack can land before this send's record.
        "UPDATE messages SET
         outcome = CASE WHEN outcome = 'delivered' AND ?2 = 'queued' THEN outcome ELSE ?2 END,
         return_host = ?3 WHERE id = ?1",
        params![id, outcome, return_host.unwrap_or("")],
    )?;
    Ok(())
}

pub fn delete_message(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM messages WHERE id = ?1", params![id])?;
    Ok(())
}

/// Whether a message record says its message reached the recipient, or is being
/// delivered there: `delivered`, `queued`, `accepted`. Message-ID deduplication answers
/// from such a record. A recorded failure (`not_found`, `gone`, `ambiguous`, `failed`,
/// `delivery_failed`) says the message was not delivered, so its ID may be delivered again.
pub fn outcome_reached(outcome: &str) -> bool {
    matches!(
        outcome,
        "delivered" | "queued" | "accepted" | "delivery_unknown"
    )
}

fn write_message(conn: &Connection, msg: &MessageRecord, on_conflict: &str) -> Result<()> {
    conn.execute(
        &format!("INSERT INTO messages (id, created_at, session_id, from_name, bytes, outcome, recipient_harness, return_harness, return_session_id, thread_id, return_host) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11){on_conflict}"),
        params![
            msg.id,
            msg.created_at,
            msg.session_id,
            msg.from_name,
            msg.bytes as i64,
            msg.outcome,
            msg.recipient_harness,
            msg.return_harness,
            msg.return_session_id,
            msg.thread_id,
            msg.return_host.as_deref().unwrap_or(""),
        ],
    )?;
    Ok(())
}

pub fn get_message(conn: &Connection, id: &str) -> Result<Option<MessageRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, created_at, session_id, from_name, bytes, outcome, recipient_harness, return_harness, return_session_id, thread_id, return_host FROM messages WHERE id = ?1",
    )?;
    let mut rows = stmt.query(params![id])?;

    if let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(4)?;
        let ret_host: String = row.get(10)?;
        let return_host = if ret_host.is_empty() {
            None
        } else {
            Some(ret_host)
        };
        Ok(Some(MessageRecord {
            id: row.get(0)?,
            created_at: row.get(1)?,
            session_id: row.get(2)?,
            from_name: row.get(3)?,
            bytes: bytes_i64 as usize,
            outcome: row.get(5)?,
            recipient_harness: row.get(6)?,
            return_harness: row.get(7)?,
            return_session_id: row.get(8)?,
            thread_id: row.get(9)?,
            return_host,
        }))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OutboundRecord {
    pub id: String,
    pub peer: String,
    pub target_ref: String,
    pub outcome: String,
    pub created_at: i64,
    /// The sending node resolved `target_ref` over its view (XA6), so it is the
    /// recipient's own ID or service name, not a reference as typed.
    pub resolved: bool,
    /// The send waits in a dial-out client's mailbox here, to be resolved by that client
    /// when it pulls it; not a send the peer resolved and holds for its recipient's ack.
    pub via_mailbox: bool,
}

pub fn insert_outbound(
    conn: &Connection,
    id: &str,
    peer: &str,
    target_ref: &str,
    outcome: &str,
    created_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO outbound (id, peer, target_ref, outcome, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, peer, target_ref, outcome, created_at],
    )?;
    Ok(())
}

pub fn get_outbound(conn: &Connection, id: &str) -> Result<Option<OutboundRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, peer, target_ref, outcome, created_at, resolved, via_mailbox FROM outbound WHERE id = ?1",
    )?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(OutboundRecord {
            id: row.get(0)?,
            peer: row.get(1)?,
            target_ref: row.get(2)?,
            outcome: row.get(3)?,
            created_at: row.get(4)?,
            resolved: row.get(5)?,
            via_mailbox: row.get(6)?,
        }))
    } else {
        Ok(None)
    }
}

pub fn mark_outbound_resolved(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE outbound SET resolved = 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

pub fn mark_outbound_via_mailbox(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE outbound SET via_mailbox = 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

/// The node an instance ID was last resolved to, if cached within `ttl_secs` (A-12).
pub fn cached_location(
    conn: &Connection,
    id: &str,
    now: i64,
    ttl_secs: i64,
) -> Result<Option<String>> {
    match conn.query_row(
        "SELECT node FROM location_cache WHERE id = ?1 AND cached_at + ?3 > ?2",
        params![id, now, ttl_secs],
        |r| r.get(0),
    ) {
        Ok(node) => Ok(Some(node)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn cache_location(conn: &Connection, id: &str, node: &str, now: i64) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO location_cache (id, node, cached_at) VALUES (?1, ?2, ?3)",
        params![id, node, now],
    )?;
    Ok(())
}

pub fn forget_location(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM location_cache WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn update_outbound_outcome(conn: &Connection, id: &str, outcome: &str) -> Result<()> {
    conn.execute(
        "UPDATE outbound SET outcome = ?1 WHERE id = ?2",
        params![outcome, id],
    )?;
    Ok(())
}

pub fn update_outbound_target(conn: &Connection, id: &str, target_ref: &str) -> Result<()> {
    conn.execute(
        "UPDATE outbound SET target_ref = ?1 WHERE id = ?2",
        params![target_ref, id],
    )?;
    Ok(())
}

pub fn delete_outbound(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM outbound WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn insert_reply(
    conn: &Connection,
    message_id: &str,
    replier_session_id: &str,
    text: &str,
    push_outcome: Option<&str>,
    pushed_message_id: Option<&str>,
) -> Result<ReplyRecord> {
    let created_at = now_epoch_secs();
    conn.execute(
        "INSERT INTO replies (message_id, created_at, replier_session_id, text, push_outcome, pushed_message_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            message_id,
            created_at,
            replier_session_id,
            text,
            push_outcome,
            pushed_message_id
        ],
    )?;
    let seq = conn.last_insert_rowid();

    Ok(ReplyRecord {
        seq,
        message_id: message_id.to_string(),
        created_at,
        replier_session_id: replier_session_id.to_string(),
        text: text.to_string(),
        push_outcome: push_outcome.map(|s| s.to_string()),
        pushed_message_id: pushed_message_id.map(|s| s.to_string()),
        replier: None,
        attachments: Vec::new(),
    })
}

pub fn get_replies_after(
    conn: &Connection,
    message_id: &str,
    after_seq: i64,
) -> Result<Vec<ReplyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT seq, message_id, created_at, replier_session_id, text, push_outcome, pushed_message_id FROM replies WHERE message_id = ?1 AND seq > ?2 ORDER BY seq ASC",
    )?;
    let rows = stmt.query_map(params![message_id, after_seq], |row| {
        Ok(ReplyRecord {
            seq: row.get(0)?,
            message_id: row.get(1)?,
            created_at: row.get(2)?,
            replier_session_id: row.get(3)?,
            text: row.get(4)?,
            push_outcome: row.get(5)?,
            pushed_message_id: row.get(6)?,
            replier: None,
            attachments: Vec::new(),
        })
    })?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn get_all_replies(conn: &Connection, message_id: &str) -> Result<Vec<ReplyRecord>> {
    get_replies_after(conn, message_id, 0)
}

pub fn get_reply_by_pushed_id(
    conn: &Connection,
    pushed_message_id: &str,
) -> Result<Option<ReplyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT seq, message_id, created_at, replier_session_id, text, push_outcome, pushed_message_id FROM replies WHERE pushed_message_id = ?1 LIMIT 1",
    )?;
    let mut rows = stmt.query(params![pushed_message_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(ReplyRecord {
            seq: row.get(0)?,
            message_id: row.get(1)?,
            created_at: row.get(2)?,
            replier_session_id: row.get(3)?,
            text: row.get(4)?,
            push_outcome: row.get(5)?,
            pushed_message_id: row.get(6)?,
            replier: None,
            attachments: Vec::new(),
        }))
    } else {
        Ok(None)
    }
}

pub fn update_reply_push_outcome(
    conn: &Connection,
    pushed_message_id: &str,
    push_outcome: &str,
) -> Result<bool> {
    let count = conn.execute(
        "UPDATE replies SET push_outcome = ?1 WHERE pushed_message_id = ?2",
        params![push_outcome, pushed_message_id],
    )?;
    Ok(count > 0)
}

pub fn purge_replies(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let cutoff = now_epoch_secs() - (ttl_secs as i64);
    conn.execute("DELETE FROM replies WHERE created_at < ?1", params![cutoff])
}

pub fn purge_messages(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let cutoff = now_epoch_secs() - (ttl_secs as i64);
    conn.execute(
        "DELETE FROM messages WHERE created_at < ?1",
        params![cutoff],
    )
}

pub const MAX_PI_QUEUE_PER_SESSION: usize = 100;

pub fn count_pending_pi_messages(conn: &Connection, session_id: &str) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM pi_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL",
    )?;
    let count: i64 = stmt.query_row(params![session_id], |row| row.get(0))?;
    Ok(count as usize)
}

pub fn insert_pi_message(conn: &Connection, msg: &PiPendingMessage) -> Result<bool> {
    let pending = count_pending_pi_messages(conn, &msg.session_id)?;
    if pending >= MAX_PI_QUEUE_PER_SESSION {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO pi_pending_messages (id, session_id, created_at, from_name, bytes, text, envelope, delivered_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            msg.id,
            msg.session_id,
            msg.created_at,
            msg.from_name,
            msg.bytes as i64,
            msg.text,
            msg.envelope,
            msg.delivered_at,
        ],
    )?;
    Ok(true)
}

pub fn get_next_pending_pi_message(
    conn: &Connection,
    session_id: &str,
) -> Result<Option<PiPendingMessage>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, created_at, from_name, bytes, text, envelope, delivered_at FROM pi_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL ORDER BY created_at ASC, rowid ASC LIMIT 1",
    )?;
    let mut rows = stmt.query(params![session_id])?;

    if let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(4)?;
        Ok(Some(PiPendingMessage {
            id: row.get(0)?,
            session_id: row.get(1)?,
            created_at: row.get(2)?,
            from_name: row.get(3)?,
            bytes: bytes_i64 as usize,
            text: row.get(5)?,
            envelope: row.get(6)?,
            delivered_at: row.get(7)?,
        }))
    } else {
        Ok(None)
    }
}

/// The harness took the message (HA3): its queue row is stamped and its record reads
/// `delivered`.
pub fn ack_pi_message(conn: &Connection, session_id: &str, message_id: &str) -> Result<bool> {
    let now = now_epoch_secs();
    let count = conn.execute(
        "UPDATE pi_pending_messages SET delivered_at = ?1 WHERE id = ?2 AND session_id = ?3 AND delivered_at IS NULL",
        params![now, message_id, session_id],
    )?;
    if count > 0 {
        update_message_outcome(conn, message_id, "delivered")?;
    }
    Ok(count > 0)
}

pub fn purge_pi_messages(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let cutoff = now_epoch_secs() - (ttl_secs as i64);
    conn.execute(
        "DELETE FROM pi_pending_messages WHERE created_at < ?1",
        params![cutoff],
    )
}

pub fn insert_agy_message(conn: &Connection, msg: &AgyPendingMessage) -> Result<bool> {
    conn.execute(
        "INSERT INTO agy_pending_messages (id, session_id, created_at, from_name, bytes, text, envelope, delivered_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            msg.id,
            msg.session_id,
            msg.created_at,
            msg.from_name,
            msg.bytes as i64,
            msg.text,
            msg.envelope,
            msg.delivered_at,
        ],
    )?;
    Ok(true)
}

pub fn fetch_undelivered_agy_messages(
    conn: &Connection,
    session_keys: &[&str],
) -> Result<Vec<AgyPendingMessage>> {
    if session_keys.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders: Vec<String> = (1..=session_keys.len()).map(|i| format!("?{i}")).collect();
    let query_str = format!(
        "SELECT id, session_id, created_at, from_name, bytes, text, envelope, delivered_at FROM agy_pending_messages WHERE session_id IN ({}) AND delivered_at IS NULL ORDER BY created_at ASC, rowid ASC",
        placeholders.join(", ")
    );
    let mut stmt = conn.prepare(&query_str)?;
    let rusqlite_params: Vec<&dyn rusqlite::ToSql> = session_keys
        .iter()
        .map(|s| s as &dyn rusqlite::ToSql)
        .collect();
    let mut rows = stmt.query(rusqlite_params.as_slice())?;

    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(4)?;
        result.push(AgyPendingMessage {
            id: row.get(0)?,
            session_id: row.get(1)?,
            created_at: row.get(2)?,
            from_name: row.get(3)?,
            bytes: bytes_i64 as usize,
            text: row.get(5)?,
            envelope: row.get(6)?,
            delivered_at: row.get(7)?,
        });
    }
    Ok(result)
}

pub fn mark_agy_message_delivered(conn: &Connection, id: &str, delivered_at: i64) -> Result<bool> {
    let count = conn.execute(
        "UPDATE agy_pending_messages SET delivered_at = ?1 WHERE id = ?2 AND delivered_at IS NULL",
        params![delivered_at, id],
    )?;
    Ok(count > 0)
}

/// `queued` never replaces `delivered`: an ack can land before the send that queued the
/// message records its own outcome.
pub fn update_message_outcome(conn: &Connection, id: &str, outcome: &str) -> Result<bool> {
    let count = conn.execute(
        "UPDATE messages
         SET outcome = CASE WHEN outcome = 'delivered' AND ?1 = 'queued' THEN outcome ELSE ?1 END
         WHERE id = ?2",
        params![outcome, id],
    )?;
    Ok(count > 0)
}

pub fn purge_agy_messages(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let cutoff = now_epoch_secs() - (ttl_secs as i64);
    conn.execute(
        "DELETE FROM agy_pending_messages WHERE created_at < ?1",
        params![cutoff],
    )
}

pub const MAX_SVC_QUEUE_PER_SESSION: usize = 100;
pub const DEFAULT_REPLY_TTL_SECS: u64 = 604_800;
pub const DEFAULT_IDEMPOTENCY_TTL_SECS: u64 = 86_400;
pub const DEFAULT_MAX_BODY_BYTES: usize = 65_536;

type SvcQueueCapEntry = (std::sync::Weak<std::sync::Mutex<Connection>>, usize);

fn svc_queue_cap_registry(
) -> &'static std::sync::Mutex<std::collections::HashMap<usize, SvcQueueCapEntry>> {
    static REGISTRY: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, SvcQueueCapEntry>>,
    > = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

pub fn set_svc_queue_cap(db: &std::sync::Arc<std::sync::Mutex<Connection>>, cap: usize) {
    let key = std::sync::Arc::as_ptr(db) as usize;
    let weak = std::sync::Arc::downgrade(db);
    let mut map = svc_queue_cap_registry().lock().unwrap();
    map.retain(|_, (w, _)| w.strong_count() > 0);
    map.insert(key, (weak, cap));
}

pub fn svc_queue_cap_for_db(db: &std::sync::Arc<std::sync::Mutex<Connection>>) -> usize {
    let key = std::sync::Arc::as_ptr(db) as usize;
    let weak = std::sync::Arc::downgrade(db);
    let map = svc_queue_cap_registry().lock().unwrap();
    if let Some((w, cap)) = map.get(&key) {
        if std::sync::Weak::ptr_eq(w, &weak) {
            return *cap;
        }
    }
    MAX_SVC_QUEUE_PER_SESSION
}

pub fn count_pending_svc_messages(conn: &Connection, session_id: &str) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM svc_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL",
    )?;
    let count: i64 = stmt.query_row(params![session_id], |row| row.get(0))?;
    Ok(count as usize)
}

pub fn insert_svc_message(conn: &Connection, msg: &SvcPendingMessage) -> Result<bool> {
    insert_svc_message_with_cap(conn, msg, MAX_SVC_QUEUE_PER_SESSION)
}

pub fn insert_svc_message_with_cap(
    conn: &Connection,
    msg: &SvcPendingMessage,
    cap: usize,
) -> Result<bool> {
    if has_svc_message(conn, &msg.id)? {
        let _ = upgrade_svc_message_origin(
            conn,
            &msg.id,
            &msg.from_name,
            &msg.origin,
            msg.in_reply_to.as_deref(),
        )?;
        return Ok(true);
    }
    let pending = count_pending_svc_messages(conn, &msg.session_id)?;
    if pending >= cap {
        return Ok(false);
    }
    let origin_json = serde_json::to_string(&msg.origin)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    conn.execute(
        "INSERT INTO svc_pending_messages (id, session_id, created_at, from_name, bytes, text, envelope, delivered_at, origin, in_reply_to) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            msg.id,
            msg.session_id,
            msg.created_at,
            msg.from_name,
            msg.bytes as i64,
            msg.text,
            msg.envelope,
            msg.delivered_at,
            origin_json,
            msg.in_reply_to,
        ],
    )?;
    Ok(true)
}

pub fn has_svc_message(conn: &Connection, id: &str) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT 1 FROM svc_pending_messages WHERE id = ?1 LIMIT 1")?;
    let mut rows = stmt.query(params![id])?;
    Ok(rows.next()?.is_some())
}

/// If `id` is already in `svc_pending_messages` with a non-service `origin` and `origin`
/// carries a service attestation (`origin.service.is_some()`), upgrades the row's `origin`
/// and `from_name` in place so the attested-service copy wins without duplicating delivery.
pub fn upgrade_svc_message_origin(
    conn: &Connection,
    id: &str,
    from_name: &str,
    origin: &Origin,
    in_reply_to: Option<&str>,
) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT origin FROM svc_pending_messages WHERE id = ?1 LIMIT 1")?;
    let mut rows = stmt.query(params![id])?;
    let Some(row) = rows.next()? else {
        return Ok(false);
    };
    let existing = origin_from_sql(row.get(0)?)?;
    if origin.service.is_some() && existing.service.is_none() {
        let origin_json = serde_json::to_string(origin)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let updated = conn.execute(
            "UPDATE svc_pending_messages SET from_name = ?2, origin = ?3, in_reply_to = COALESCE(in_reply_to, ?4) WHERE id = ?1",
            params![id, from_name, origin_json, in_reply_to],
        )?;
        Ok(updated > 0)
    } else if in_reply_to.is_some() {
        let updated = conn.execute(
            "UPDATE svc_pending_messages SET in_reply_to = COALESCE(in_reply_to, ?2) WHERE id = ?1",
            params![id, in_reply_to],
        )?;
        Ok(updated > 0)
    } else {
        Ok(false)
    }
}

pub fn get_next_pending_svc_message(
    conn: &Connection,
    session_id: &str,
) -> Result<Option<SvcPendingMessage>> {
    get_next_pending_svc_message_excluding(conn, session_id, &std::collections::HashSet::new())
}

pub fn get_next_pending_svc_message_excluding(
    conn: &Connection,
    session_id: &str,
    in_flight: &std::collections::HashSet<String>,
) -> Result<Option<SvcPendingMessage>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, created_at, from_name, bytes, text, envelope, delivered_at, origin, in_reply_to FROM svc_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL ORDER BY created_at ASC, rowid ASC",
    )?;
    let mut rows = stmt.query(params![session_id])?;

    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        if in_flight.contains(&id) {
            continue;
        }
        let bytes_i64: i64 = row.get(4)?;
        let origin = origin_from_sql(row.get(8)?)?;
        return Ok(Some(SvcPendingMessage {
            id,
            session_id: row.get(1)?,
            created_at: row.get(2)?,
            from_name: row.get(3)?,
            bytes: bytes_i64 as usize,
            text: row.get(5)?,
            envelope: row.get(6)?,
            delivered_at: row.get(7)?,
            origin,
            in_reply_to: row.get(9)?,
        }));
    }
    Ok(None)
}

/// The service took the message: its queue row is stamped and its record reads `delivered`.
pub fn ack_svc_message(conn: &Connection, session_id: &str, message_id: &str) -> Result<bool> {
    let now = now_epoch_secs();
    let count = conn.execute(
        "UPDATE svc_pending_messages SET delivered_at = ?1 WHERE id = ?2 AND session_id = ?3 AND delivered_at IS NULL",
        params![now, message_id, session_id],
    )?;
    if count > 0 {
        update_message_outcome(conn, message_id, "delivered")?;
    }
    Ok(count > 0)
}

pub fn purge_svc_messages(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let cutoff = now_epoch_secs() - (ttl_secs as i64);
    conn.execute(
        "DELETE FROM svc_pending_messages WHERE created_at < ?1",
        params![cutoff],
    )
}

pub fn get_idempotency_record(
    conn: &Connection,
    principal: &str,
    key: &str,
    ttl_secs: u64,
) -> Result<Option<IdempotencyRecord>> {
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(ttl_secs as i64);
    let mut stmt = conn.prepare(
        "SELECT principal, key, body, message_id, session_id, from_name, bytes, outcome, created_at, to_ref, refs_digest
         FROM idempotency_keys
         WHERE principal = ?1 AND key = ?2 AND created_at >= ?3",
    )?;
    let mut rows = stmt.query(params![principal, key, cutoff])?;
    if let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(6)?;
        Ok(Some(IdempotencyRecord {
            principal: row.get(0)?,
            key: row.get(1)?,
            body: row.get(2)?,
            message_id: row.get(3)?,
            session_id: row.get(4)?,
            from_name: row.get(5)?,
            bytes: bytes_i64 as usize,
            outcome: row.get(7)?,
            created_at: row.get(8)?,
            to_ref: row.get(9)?,
            refs_digest: row.get(10)?,
        }))
    } else {
        Ok(None)
    }
}

/// A key's state while its send is delivered: `pending` until the send settles, `failed`
/// once it failed (the next send with the key delivers again, under the same message ID).
pub const KEY_PENDING: &str = "pending";
pub const KEY_FAILED: &str = "failed";
/// A reply key's state once its reply is stored.
pub const KEY_DONE: &str = "done";

/// The holder of an idempotency key: this caller, which delivers under the given ID, or
/// an earlier send or reply whose record is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reservation<T> {
    Mine(String),
    Held(T),
}

/// Reserves `(principal, key)` for a send of `body` to `to` in one transaction, before
/// anything is delivered. A new or expired key is minted `fresh_id`; a key whose send of
/// the same body to the same `to` failed is taken over with its own message ID, so a peer
/// that did receive it deduplicates it.
#[allow(clippy::too_many_arguments)]
pub fn reserve_idempotency_key(
    conn: &Connection,
    principal: &str,
    key: &str,
    body: &str,
    to: &str,
    from_name: &str,
    fresh_id: &str,
    ttl_secs: u64,
) -> Result<Reservation<IdempotencyRecord>> {
    reserve_idempotency_key_with_refs(
        conn, principal, key, body, None, to, from_name, fresh_id, ttl_secs,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reserve_idempotency_key_with_refs(
    conn: &Connection,
    principal: &str,
    key: &str,
    body: &str,
    refs_digest: Option<&str>,
    to: &str,
    from_name: &str,
    fresh_id: &str,
    ttl_secs: u64,
) -> Result<Reservation<IdempotencyRecord>> {
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(ttl_secs as i64);
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "DELETE FROM idempotency_keys WHERE principal = ?1 AND key = ?2 AND created_at < ?3",
        params![principal, key, cutoff],
    )?;
    let inserted = tx.execute(
        "INSERT INTO idempotency_keys
         (principal, key, body, message_id, session_id, from_name, bytes, outcome, created_at, to_ref, refs_digest)
         VALUES (?1, ?2, ?3, ?4, '', ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT (principal, key) DO NOTHING",
        params![
            principal,
            key,
            body,
            fresh_id,
            from_name,
            body.len() as i64,
            KEY_PENDING,
            now,
            to,
            refs_digest
        ],
    )?;
    let taken_over = inserted == 0
        && tx.execute(
            "UPDATE idempotency_keys SET outcome = ?4, created_at = ?5
             WHERE principal = ?1 AND key = ?2 AND body = ?3 AND outcome = ?6 AND to_ref = ?7 AND refs_digest IS ?8",
            params![principal, key, body, KEY_PENDING, now, KEY_FAILED, to, refs_digest],
        )? == 1;
    let record = get_idempotency_record(&tx, principal, key, ttl_secs)?;
    tx.commit()?;
    let record = record.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    Ok(if inserted == 1 || taken_over {
        Reservation::Mine(record.message_id)
    } else {
        Reservation::Held(record)
    })
}

/// Settles a reserved key: its send's address and outcome, or `KEY_FAILED`.
pub fn settle_idempotency_key(
    conn: &Connection,
    principal: &str,
    key: &str,
    address: &str,
    outcome: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE idempotency_keys SET session_id = ?3, outcome = ?4 WHERE principal = ?1 AND key = ?2",
        params![principal, key, address, outcome],
    )?;
    Ok(())
}

/// Settles every key a stopped server left `pending` (run at startup, before any send).
/// A send key whose message record shows it reached its recipient takes that record's
/// outcome and address; any other (its delivery was interrupted, or never began) is
/// `failed`, so the next send with it delivers. A reply key whose reply was stored is
/// `done` with it; any other is `failed`. Returns the number of keys settled.
pub fn reconcile_pending_keys(conn: &Connection, node_name: &str) -> Result<usize> {
    let tx = conn.unchecked_transaction()?;
    let pending: Vec<(String, String, String)> = tx
        .prepare("SELECT principal, key, message_id FROM idempotency_keys WHERE outcome = ?1")?
        .query_map(params![KEY_PENDING], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<Result<_>>()?;
    let mut settled = pending.len();
    for (principal, key, message_id) in pending {
        let (address, outcome) = match get_message(&tx, &message_id)? {
            Some(m) if outcome_reached(&m.outcome) => {
                let address = if m.recipient_harness == "fed" {
                    get_outbound(&tx, &message_id)?.map_or(String::new(), |o| o.target_ref)
                } else {
                    format!("{}@{node_name}", m.session_id)
                };
                (address, m.outcome)
            }
            _ => (String::new(), KEY_FAILED.to_string()),
        };
        settle_idempotency_key(&tx, &principal, &key, &address, &outcome)?;
    }
    let pending: Vec<(String, String, String)> = tx
        .prepare("SELECT principal, key, reply_id FROM reply_idempotency_keys WHERE state = ?1")?
        .query_map(params![KEY_PENDING], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<Result<_>>()?;
    settled += pending.len();
    for (principal, key, reply_id) in pending {
        match get_reply_by_pushed_id(&tx, &reply_id)? {
            Some(r) => settle_reply_key(&tx, &principal, &key, KEY_DONE, Some(r.seq))?,
            None => {
                delete_message(&tx, &reply_id)?;
                delete_outbound(&tx, &reply_id)?;
                settle_reply_key(&tx, &principal, &key, KEY_FAILED, None)?;
            }
        }
    }
    tx.commit()?;
    Ok(settled)
}

pub fn purge_idempotency_keys(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(ttl_secs as i64);
    conn.execute(
        "DELETE FROM reply_idempotency_keys WHERE created_at < ?1",
        params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM idempotency_keys WHERE created_at < ?1",
        params![cutoff],
    )
}

/// A reply's idempotency record: its reply ID, and the stored reply's `seq` once settled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplyKeyRecord {
    #[serde(default)]
    pub refs_digest: Option<String>,
    pub in_reply_to: String,
    pub body: String,
    pub reply_id: String,
    pub state: String,
    pub seq: Option<i64>,
    pub created_at: i64,
}

/// `reserve_idempotency_key` for a reply to `in_reply_to`: the key names one reply, its
/// reply ID minted here; a key whose reply failed is taken over with that reply ID.
pub fn reserve_reply_key(
    conn: &Connection,
    principal: &str,
    key: &str,
    in_reply_to: &str,
    body: &str,
    fresh_id: &str,
    ttl_secs: u64,
) -> Result<Reservation<ReplyKeyRecord>> {
    reserve_reply_key_with_refs(
        conn,
        principal,
        key,
        in_reply_to,
        body,
        None,
        fresh_id,
        ttl_secs,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reserve_reply_key_with_refs(
    conn: &Connection,
    principal: &str,
    key: &str,
    in_reply_to: &str,
    body: &str,
    refs_digest: Option<&str>,
    fresh_id: &str,
    ttl_secs: u64,
) -> Result<Reservation<ReplyKeyRecord>> {
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(ttl_secs as i64);
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "DELETE FROM reply_idempotency_keys WHERE principal = ?1 AND key = ?2 AND created_at < ?3",
        params![principal, key, cutoff],
    )?;
    let inserted = tx.execute(
        "INSERT INTO reply_idempotency_keys
         (principal, key, in_reply_to, body, reply_id, state, seq, created_at, refs_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8)
         ON CONFLICT (principal, key) DO NOTHING",
        params![
            principal,
            key,
            in_reply_to,
            body,
            fresh_id,
            KEY_PENDING,
            now,
            refs_digest
        ],
    )?;
    let taken_over = inserted == 0
        && tx.execute(
            "UPDATE reply_idempotency_keys SET state = ?5, created_at = ?6
             WHERE principal = ?1 AND key = ?2 AND in_reply_to = ?3 AND body = ?4 AND state = ?7 AND refs_digest IS ?8",
            params![
                principal,
                key,
                in_reply_to,
                body,
                KEY_PENDING,
                now,
                KEY_FAILED,
                refs_digest
            ],
        )? == 1;
    let record = tx.query_row(
        "SELECT in_reply_to, body, reply_id, state, seq, created_at, refs_digest
         FROM reply_idempotency_keys WHERE principal = ?1 AND key = ?2",
        params![principal, key],
        |row| {
            Ok(ReplyKeyRecord {
                in_reply_to: row.get(0)?,
                body: row.get(1)?,
                reply_id: row.get(2)?,
                state: row.get(3)?,
                seq: row.get(4)?,
                created_at: row.get(5)?,
                refs_digest: row.get(6)?,
            })
        },
    )?;
    tx.commit()?;
    Ok(if inserted == 1 || taken_over {
        Reservation::Mine(record.reply_id)
    } else {
        Reservation::Held(record)
    })
}

/// Settles a reserved reply key: `done` with the stored reply's `seq`, or `KEY_FAILED`.
pub fn settle_reply_key(
    conn: &Connection,
    principal: &str,
    key: &str,
    state: &str,
    seq: Option<i64>,
) -> Result<()> {
    conn.execute(
        "UPDATE reply_idempotency_keys SET state = ?3, seq = ?4 WHERE principal = ?1 AND key = ?2",
        params![principal, key, state, seq],
    )?;
    Ok(())
}

pub fn get_reply_by_seq(conn: &Connection, seq: i64) -> Result<Option<ReplyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT seq, message_id, created_at, replier_session_id, text, push_outcome, pushed_message_id FROM replies WHERE seq = ?1",
    )?;
    let mut rows = stmt.query(params![seq])?;
    if let Some(row) = rows.next()? {
        Ok(Some(ReplyRecord {
            seq: row.get(0)?,
            message_id: row.get(1)?,
            created_at: row.get(2)?,
            replier_session_id: row.get(3)?,
            text: row.get(4)?,
            push_outcome: row.get(5)?,
            pushed_message_id: row.get(6)?,
            replier: None,
            attachments: Vec::new(),
        }))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerMailboxMessage {
    pub id: String,
    pub peer: String,
    pub target_ref: String,
    pub created_at: i64,
    pub from_name: String,
    pub bytes: usize,
    pub body: String,
    pub envelope: String,
    pub origin: Origin,
}

pub const DEFAULT_PEER_MAILBOX_MAX_ROWS: u64 = 10_000;
pub const DEFAULT_PEER_MAILBOX_MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerMailboxLimits {
    pub max_rows: u64,
    pub max_bytes: u64,
}
impl Default for PeerMailboxLimits {
    fn default() -> Self {
        Self {
            max_rows: DEFAULT_PEER_MAILBOX_MAX_ROWS,
            max_bytes: DEFAULT_PEER_MAILBOX_MAX_BYTES,
        }
    }
}

type PeerMailboxLimitEntry = (
    std::sync::Weak<std::sync::Mutex<Connection>>,
    PeerMailboxLimits,
);
fn peer_mailbox_limits_registry(
) -> &'static std::sync::Mutex<std::collections::HashMap<usize, PeerMailboxLimitEntry>> {
    static REGISTRY: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, PeerMailboxLimitEntry>>,
    > = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}
pub fn set_peer_mailbox_limits(
    db: &std::sync::Arc<std::sync::Mutex<Connection>>,
    limits: PeerMailboxLimits,
) {
    let mut registry = peer_mailbox_limits_registry().lock().unwrap();
    registry.retain(|_, (weak, _)| weak.strong_count() > 0);
    registry.insert(
        std::sync::Arc::as_ptr(db) as usize,
        (std::sync::Arc::downgrade(db), limits),
    );
}
pub fn peer_mailbox_limits_for_db(
    db: &std::sync::Arc<std::sync::Mutex<Connection>>,
) -> PeerMailboxLimits {
    peer_mailbox_limits_registry()
        .lock()
        .unwrap()
        .get(&(std::sync::Arc::as_ptr(db) as usize))
        .filter(|(weak, _)| std::sync::Weak::ptr_eq(weak, &std::sync::Arc::downgrade(db)))
        .map(|(_, limits)| *limits)
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerMailboxInsert {
    Inserted,
    Duplicate,
    Full,
}

pub fn insert_peer_mailbox(
    conn: &Connection,
    msg: &PeerMailboxMessage,
) -> Result<PeerMailboxInsert> {
    insert_peer_mailbox_with_limits(conn, msg, PeerMailboxLimits::default())
}

pub fn insert_peer_mailbox_with_limits(
    conn: &Connection,
    msg: &PeerMailboxMessage,
    limits: PeerMailboxLimits,
) -> Result<PeerMailboxInsert> {
    let origin_json = serde_json::to_string(&msg.origin)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    if conn
        .query_row("SELECT 1 FROM peer_mailbox WHERE id=?1", [&msg.id], |_| {
            Ok(())
        })
        .optional()?
        .is_some()
    {
        return Ok(PeerMailboxInsert::Duplicate);
    }
    let stored_bytes = 16u64
        + msg.id.len() as u64
        + msg.peer.len() as u64
        + msg.target_ref.len() as u64
        + msg.from_name.len() as u64
        + msg.body.len() as u64
        + msg.envelope.len() as u64
        + origin_json.len() as u64;
    let max_rows = i64::try_from(limits.max_rows).unwrap_or(i64::MAX);
    let max_bytes = i64::try_from(limits.max_bytes).unwrap_or(i64::MAX);
    let stored_bytes = i64::try_from(stored_bytes).unwrap_or(i64::MAX);
    let count = conn.execute(
        "WITH usage AS (
           SELECT COUNT(*) AS rows, COALESCE(SUM(16 + length(CAST(id AS BLOB)) + length(CAST(peer AS BLOB))
             + length(CAST(target_ref AS BLOB)) + length(CAST(from_name AS BLOB)) + length(CAST(body AS BLOB))
             + length(CAST(envelope AS BLOB)) + length(CAST(origin AS BLOB))),0) AS stored_bytes
           FROM peer_mailbox WHERE peer=?2
         )
         INSERT OR IGNORE INTO peer_mailbox (id, peer, target_ref, created_at, from_name, bytes, body, envelope, origin)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 FROM usage
         WHERE rows < ?10 AND stored_bytes <= ?11 - ?12",
        params![
            msg.id,
            msg.peer,
            msg.target_ref,
            msg.created_at,
            msg.from_name,
            msg.bytes as i64,
            msg.body,
            msg.envelope,
            origin_json,
            max_rows,
            max_bytes,
            stored_bytes,
        ],
    )?;
    if count > 0 {
        Ok(PeerMailboxInsert::Inserted)
    } else if conn
        .query_row("SELECT 1 FROM peer_mailbox WHERE id=?1", [&msg.id], |_| {
            Ok(())
        })
        .optional()?
        .is_some()
    {
        Ok(PeerMailboxInsert::Duplicate)
    } else {
        Ok(PeerMailboxInsert::Full)
    }
}

pub fn get_next_peer_mailbox_message(
    conn: &Connection,
    peer: &str,
) -> Result<Option<PeerMailboxMessage>> {
    let mut stmt = conn.prepare(
        "SELECT id, peer, target_ref, created_at, from_name, bytes, body, envelope, origin
         FROM peer_mailbox
         WHERE peer = ?1
         ORDER BY created_at ASC, rowid ASC
         LIMIT 1",
    )?;
    let mut rows = stmt.query(params![peer])?;
    if let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(5)?;
        let origin = origin_from_sql(row.get(8)?)?;
        Ok(Some(PeerMailboxMessage {
            id: row.get(0)?,
            peer: row.get(1)?,
            target_ref: row.get(2)?,
            created_at: row.get(3)?,
            from_name: row.get(4)?,
            bytes: bytes_i64 as usize,
            body: row.get(6)?,
            envelope: row.get(7)?,
            origin,
        }))
    } else {
        Ok(None)
    }
}

pub fn delete_peer_mailbox_message(conn: &Connection, peer: &str, id: &str) -> Result<bool> {
    let count = conn.execute(
        "DELETE FROM peer_mailbox WHERE peer = ?1 AND id = ?2",
        params![peer, id],
    )?;
    Ok(count > 0)
}

pub fn count_peer_mailbox_messages(conn: &Connection, peer: &str) -> Result<usize> {
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM peer_mailbox WHERE peer = ?1")?;
    let count: i64 = stmt.query_row(params![peer], |row| row.get(0))?;
    Ok(count as usize)
}

pub fn purge_peer_mailbox(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(i64::try_from(ttl_secs).unwrap_or(i64::MAX));
    conn.execute(
        "DELETE FROM peer_mailbox WHERE created_at < ?1",
        params![cutoff],
    )
}

pub fn is_svc_message_acked(conn: &Connection, id: &str) -> Result<bool> {
    let mut stmt =
        conn.prepare("SELECT delivered_at FROM svc_pending_messages WHERE id = ?1 LIMIT 1")?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        let delivered_at: Option<i64> = row.get(0)?;
        Ok(delivered_at.is_some())
    } else {
        Ok(false)
    }
}

#[derive(Debug, Clone)]
pub struct ForwardedMessageRecord {
    pub id: String,
    pub origin_peer: String,
    pub created_at: i64,
}

pub fn insert_forwarded_message(
    conn: &Connection,
    id: &str,
    origin_peer: &str,
    created_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO forwarded_messages (id, origin_peer, created_at) VALUES (?1, ?2, ?3)",
        params![id, origin_peer, created_at],
    )?;
    Ok(())
}

pub fn get_forwarded_message(
    conn: &Connection,
    id: &str,
) -> Result<Option<ForwardedMessageRecord>> {
    let mut stmt =
        conn.prepare("SELECT id, origin_peer, created_at FROM forwarded_messages WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(ForwardedMessageRecord {
            id: row.get(0)?,
            origin_peer: row.get(1)?,
            created_at: row.get(2)?,
        }))
    } else {
        Ok(None)
    }
}

pub fn purge_forwarded_messages(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(ttl_secs as i64);
    conn.execute(
        "DELETE FROM forwarded_messages WHERE created_at < ?1",
        params![cutoff],
    )
}

pub fn delete_forwarded_message(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM forwarded_messages WHERE id = ?1", params![id])?;
    Ok(())
}

// -----------------------------------------------------------------------------
// A14's local queue: instances observed before and not running now
// -----------------------------------------------------------------------------

/// A message held for a Claude instance that is not running (A14). `body` is what its inbox
/// receives, the send time included. It crosses the wire as is in a hand-off (D-1), its
/// expiry with it, so the queue's lifetime holds across nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedMessage {
    pub id: String,
    pub instance_id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub from_name: String,
    pub body: String,
}

pub fn insert_queued(conn: &Connection, msg: &QueuedMessage) -> Result<()> {
    conn.execute(
        "INSERT INTO instance_queue (id, instance_id, created_at, expires_at, from_name, body) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![msg.id, msg.instance_id, msg.created_at, msg.expires_at, msg.from_name, msg.body],
    )?;
    Ok(())
}

/// Stores a message handed over from another of the user's nodes (D-1). A message this node
/// already holds, delivered or not, is left as it is: a transfer repeated after a lost
/// acknowledgement delivers nothing twice (X1). Returns whether it was new.
pub fn insert_handed_over(conn: &Connection, msg: &QueuedMessage) -> Result<bool> {
    if crate::fed::validate_no_control_chars("id", &msg.id).is_err()
        || crate::fed::check_rendered_from_name(&msg.from_name).is_err()
    {
        return Err(rusqlite::Error::InvalidParameterName(
            "invalid handed-over message".to_string(),
        ));
    }
    let n = conn.execute(
        "INSERT OR IGNORE INTO instance_queue (id, instance_id, created_at, expires_at, from_name, body) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![msg.id, msg.instance_id, msg.created_at, msg.expires_at, msg.from_name, msg.body],
    )?;
    Ok(n == 1)
}

/// Drops what a hand-off to `peer` acknowledged (D-1): the messages `ids` queued for
/// `instance_id`, and then, unless a message for it arrived since the transfer, this node's
/// parked listing of it. Each dropped message is recorded as forwarded to `peer`, as a hub
/// records a forward (X26), so its recipient's reply there is authorized and travels on to
/// its origin: a reply travels by message ID (A8a). Returns how many unexpired messages
/// for `instance_id` are still held here at `now`.
pub fn drop_handed_over(
    conn: &Connection,
    instance_id: &str,
    ids: &[String],
    peer: &str,
    now: i64,
) -> Result<usize> {
    let tx = conn.unchecked_transaction()?;
    for id in ids {
        let dropped = tx.execute(
            "DELETE FROM instance_queue WHERE id = ?1 AND instance_id = ?2",
            params![id, instance_id],
        )?;
        if dropped == 0 {
            continue;
        }
        tx.execute(
            "UPDATE attachments SET downstream=?1 WHERE item_id=?2",
            params![peer, id],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO outbound (id, peer, target_ref, outcome, created_at, resolved) VALUES (?1, ?2, ?3, 'queued', ?4, 1)",
            params![id, peer, instance_id, now],
        )?;
        // A remote sender's reply goes on to its node; a local one's is pushed here.
        if let Some(origin) = get_message(&tx, id)?
            .and_then(|m| m.return_host)
            .filter(|h| !h.is_empty())
        {
            insert_forwarded_message(&tx, id, &origin, now)?;
        }
    }
    tx.execute(
        "DELETE FROM instance_seen WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM instance_queue WHERE instance_id = ?1 AND delivered_at IS NULL)",
        params![instance_id],
    )?;
    let remaining = queued_for(&tx, instance_id, now)?.len();
    tx.commit()?;
    Ok(remaining)
}

/// A hand-off this node owes or is owed (D-1): it has asked `holder` for `id`'s queue and
/// not yet settled, and holds `acks`, handed over and not yet acknowledged, until `until`,
/// their latest expiry (after which the holder hands them to nobody).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedHandoff {
    pub id: String,
    pub holder: String,
    pub acks: Vec<String>,
    pub until: i64,
}

pub fn owe_handoff(conn: &Connection, id: &str, holder: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO handoff_owed (id, holder) VALUES (?1, ?2)",
        params![id, holder],
    )?;
    Ok(())
}

pub fn get_owed_handoff(conn: &Connection, id: &str, holder: &str) -> Result<Option<OwedHandoff>> {
    Ok(owed_handoffs(conn)?
        .into_iter()
        .find(|o| o.id == id && o.holder == holder))
}

pub fn owed_handoffs(conn: &Connection) -> Result<Vec<OwedHandoff>> {
    let mut stmt =
        conn.prepare("SELECT id, holder, acks, until FROM handoff_owed ORDER BY id, holder")?;
    let rows = stmt
        .query_map([], |r| {
            let acks: String = r.get(2)?;
            Ok(OwedHandoff {
                id: r.get(0)?,
                holder: r.get(1)?,
                acks: serde_json::from_str(&acks).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                until: r.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows)
}

/// Records the acknowledgement owed to `holder` for `acks` (empty once it landed).
pub fn set_owed_acks(
    conn: &Connection,
    id: &str,
    holder: &str,
    acks: &[String],
    until: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE handoff_owed SET acks = ?3, until = ?4 WHERE id = ?1 AND holder = ?2",
        params![
            id,
            holder,
            serde_json::Value::from(acks.to_vec()).to_string(),
            until
        ],
    )?;
    Ok(())
}

pub fn settle_handoff(conn: &Connection, id: &str, holder: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM handoff_owed WHERE id = ?1 AND holder = ?2",
        params![id, holder],
    )?;
    Ok(())
}

/// The unexpired, undelivered messages queued for `instance_id`, oldest first.
pub fn queued_for(conn: &Connection, instance_id: &str, now: i64) -> Result<Vec<QueuedMessage>> {
    let mut stmt = conn.prepare(
        "SELECT id, instance_id, created_at, expires_at, from_name, body FROM instance_queue WHERE instance_id = ?1 AND delivered_at IS NULL AND expires_at > ?2 ORDER BY created_at ASC, id ASC",
    )?;
    let msgs = stmt
        .query_map(params![instance_id, now], |row| {
            Ok(QueuedMessage {
                id: row.get(0)?,
                instance_id: row.get(1)?,
                created_at: row.get(2)?,
                expires_at: row.get(3)?,
                from_name: row.get(4)?,
                body: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;
    Ok(msgs)
}

/// Takes the unexpired, undelivered messages queued for `instance_id`, oldest first, and
/// marks them delivered, so a later observation does not deliver them again.
pub fn take_queued(conn: &Connection, instance_id: &str, now: i64) -> Result<Vec<QueuedMessage>> {
    let msgs = queued_for(conn, instance_id, now)?;
    for m in &msgs {
        conn.execute(
            "UPDATE instance_queue SET delivered_at = ?1 WHERE id = ?2",
            params![now, m.id],
        )?;
    }
    Ok(msgs)
}

/// Puts back a message whose delivery failed, for the next observation.
pub fn untake_queued(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE instance_queue SET delivered_at = NULL WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

pub fn purge_instance_queue(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let now = now_epoch_secs();
    conn.execute(
        "DELETE FROM instance_queue WHERE expires_at <= ?1 OR (delivered_at IS NOT NULL AND delivered_at < ?2)",
        params![now, now - ttl_secs as i64],
    )
}

/// Records that instance `id` of `harness` was live at `now`: the "ever observed" record
/// A14's queue and D-1's lifetime read. Preserves any existing `reclaim_hash` (HA8).
pub fn mark_live(conn: &Connection, id: &str, harness: &str, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO instance_seen (id, harness, last_live) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET harness = excluded.harness, last_live = MAX(last_live, excluded.last_live)",
        params![id, harness, now],
    )?;
    Ok(())
}

/// A reclaim token presented on `register.sock` (HA8): `{id, secret}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimToken {
    pub id: String,
    pub secret: String,
}

/// Mints a fresh 128-bit (16-byte) secret using `getrandom`, returning `(secret_hex, sha256_hex)`.
/// Only `sha256_hex` is ever stored in SQLite (HA8).
pub fn mint_reclaim_secret() -> std::result::Result<(String, String), crate::error::AppError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| crate::error::AppError::Internal(format!("getrandom failed: {e}")))?;
    let secret = hex::encode(bytes);
    let hash = hash_reclaim_secret(&secret);
    Ok((secret, hash))
}

pub fn hash_reclaim_secret(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode(digest)
}

/// Verifies `secret` against `stored_hash_hex` in constant time over the 32-byte SHA-256
/// digests using `subtle::ConstantTimeEq` (HA8).
pub fn verify_reclaim_secret(secret: &str, stored_hash_hex: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let Ok(stored_bytes) = hex::decode(stored_hash_hex) else {
        return false;
    };
    if stored_bytes.len() != 32 {
        return false;
    }
    let candidate = Sha256::digest(secret.as_bytes());
    bool::from(candidate.as_slice().ct_eq(stored_bytes.as_slice()))
}

/// Records a freshly minted reclaimable instance `id` of `harness` at `now`, storing only
/// the SHA-256 hash of the newly minted 128-bit secret and returning the secret (HA8).
pub fn mint_reclaimable_instance(
    conn: &Connection,
    id: &str,
    harness: &str,
    now: i64,
) -> std::result::Result<String, crate::error::AppError> {
    let (secret, hash) = mint_reclaim_secret()?;
    conn.execute(
        "INSERT INTO instance_seen (id, harness, last_live, reclaim_hash) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(id) DO UPDATE SET harness = excluded.harness, last_live = MAX(last_live, excluded.last_live), reclaim_hash = excluded.reclaim_hash",
        params![id, harness, now, hash],
    )
    .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    Ok(secret)
}

/// Permanently releases `id` (`Frame::Release`): clears `reclaim_hash` so the address
/// cannot be reclaimed, answers `gone` on send, and lists as `closed` in inactive `list` (HA8).
pub fn clear_reclaim_hash(conn: &Connection, id: &str, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE instance_seen SET reclaim_hash = NULL, last_live = MAX(last_live, ?2) WHERE id = ?1",
        params![id, now],
    )?;
    Ok(())
}

/// Validates a reclaim request `(raw_id, secret)` for `calling_harness` at `now` within
/// `ttl_secs`, checking the secret in constant time BEFORE checking liveness so a wrong
/// secret reveals nothing about whether `id` exists or is live (HA8). On success, rotates
/// the secret and returns `(bare_id, new_secret)`.
#[allow(clippy::too_many_arguments)]
pub fn reclaim_instance<F>(
    conn: &Connection,
    raw_id: &str,
    node_name: &str,
    calling_harness: &str,
    secret: &str,
    now: i64,
    ttl_secs: i64,
    is_live_elsewhere: F,
) -> std::result::Result<(String, String), crate::error::AppError>
where
    F: FnOnce(&Connection, &str) -> std::result::Result<bool, crate::error::AppError>,
{
    use crate::error::AppError;
    let denied = || AppError::Denied("reclaim refused".to_string());

    let bare_id = match raw_id.split_once('@') {
        Some((id, node)) if node == node_name => id,
        Some(_) => return Err(denied()),
        None => raw_id,
    };
    if !crate::claim::is_instance_ref(bare_id) || bare_id.contains('~') {
        return Err(denied());
    }

    let row: Option<(String, i64, Option<String>)> = match conn.query_row(
        "SELECT harness, last_live, reclaim_hash FROM instance_seen WHERE id = ?1",
        params![bare_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ) {
        Ok(r) => Some(r),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(AppError::Internal(e.to_string())),
    };

    let Some((stored_harness, last_live, Some(stored_hash))) = row else {
        // Run a dummy hash verification so the timing matches a present row.
        let _ = verify_reclaim_secret(
            secret,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        return Err(denied());
    };

    let secret_ok = verify_reclaim_secret(secret, &stored_hash);
    let harness_ok = stored_harness == calling_harness;
    let within_window = now < last_live.saturating_add(ttl_secs);
    if !secret_ok || !harness_ok || !within_window {
        return Err(denied());
    }

    if is_live_elsewhere(conn, bare_id)? {
        return Err(AppError::LiveElsewhere(format!(
            "instance {bare_id}@{node_name} is already live"
        )));
    }

    let (new_secret, new_hash) = mint_reclaim_secret()?;
    conn.execute(
        "UPDATE instance_seen SET last_live = MAX(last_live, ?1), reclaim_hash = ?2 WHERE id = ?3",
        params![now, new_hash, bare_id],
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok((bare_id.to_string(), new_secret))
}

/// An instance observed before: its harness, when it was last live, whether it has an
/// unexpired queued message at `now` (in A14's queue, agy's queue, or pi/plugin's queue
/// within `ttl_secs` of its send; D-1: a parked listing lasts as long as its queue), and
/// whether it holds a reclaim hash (HA8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenInstance {
    pub harness: String,
    pub last_live: i64,
    pub queued: bool,
    pub reclaimable: bool,
}

pub fn seen_instance(
    conn: &Connection,
    id: &str,
    now: i64,
    ttl_secs: i64,
) -> Result<Option<SeenInstance>> {
    let row = conn.query_row(
        "SELECT harness, last_live, reclaim_hash IS NOT NULL FROM instance_seen WHERE id = ?1",
        params![id],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, bool>(2)?,
            ))
        },
    );
    let (harness, last_live, reclaimable) = match row {
        Ok(r) => r,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e),
    };
    let queued: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM instance_queue WHERE instance_id = ?1 AND delivered_at IS NULL AND expires_at > ?2) \
         + (SELECT COUNT(*) FROM agy_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL AND created_at >= ?2 - ?3) \
         + (SELECT COUNT(*) FROM pi_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL AND created_at >= ?2 - ?3)",
        params![id, now, ttl_secs],
        |r| r.get(0),
    )?;
    Ok(Some(SeenInstance {
        harness,
        last_live,
        queued: queued > 0,
        reclaimable,
    }))
}

/// The instances that may be parked here at `now` (A14, D-1, HA8): observed before and
/// within their parked lifetime (`ttl_secs` after last live, or as long as their queue for
/// Claude/agy; for pi/plugin sessions, inside the reclaim window with `reclaim_hash` set).
/// The caller leaves out the ones live now.
pub fn parked_instances(
    conn: &Connection,
    now: i64,
    ttl_secs: i64,
) -> Result<Vec<(String, String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT id, harness, last_live, reclaim_hash IS NOT NULL, (last_live + ?2 > ?1) \
         FROM instance_seen s WHERE (last_live + ?2 > ?1 \
         OR EXISTS (SELECT 1 FROM instance_queue q WHERE q.instance_id = s.id AND q.delivered_at IS NULL AND q.expires_at > ?1) \
         OR EXISTS (SELECT 1 FROM agy_pending_messages a WHERE a.session_id = s.id AND a.delivered_at IS NULL AND a.created_at >= ?1 - ?2) \
         OR EXISTS (SELECT 1 FROM pi_pending_messages p WHERE p.session_id = s.id AND p.delivered_at IS NULL AND p.created_at >= ?1 - ?2)) \
         ORDER BY id",
    )?;
    let rows = stmt
        .query_map(params![now, ttl_secs], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, harness, last_live, has_reclaim, within_window)| {
            let is_reclaim_harness =
                harness == "pi" || harness == "codex" || crate::plugin::harness(&harness).is_some();
            if is_reclaim_harness {
                if has_reclaim && within_window {
                    Some((id, harness, last_live))
                } else {
                    None
                }
            } else {
                Some((id, harness, last_live))
            }
        })
        .collect())
}

/// Prunes `instance_seen` rows whose `last_live` is older than `ttl_secs` (the longest
/// `within` window accepted) and which hold no unexpired queued messages. When a parent's
/// `instance_seen` row is purged, its `subagents` rows (and any subagent queue rows) go
/// with it in the same batch (HA9-A §2.5, E7 O10).
pub fn purge_instance_seen(conn: &Connection, now: i64, ttl_secs: i64) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT id FROM instance_seen WHERE last_live + ?2 <= ?1 \
         AND NOT EXISTS (SELECT 1 FROM instance_queue q WHERE q.instance_id = instance_seen.id AND q.delivered_at IS NULL AND q.expires_at > ?1) \
         AND NOT EXISTS (SELECT 1 FROM agy_pending_messages a WHERE a.session_id = instance_seen.id AND a.delivered_at IS NULL AND a.created_at >= ?1 - ?2) \
         AND NOT EXISTS (SELECT 1 FROM pi_pending_messages p WHERE p.session_id = instance_seen.id AND p.delivered_at IS NULL AND p.created_at >= ?1 - ?2)",
    )?;
    let purged_ids: Vec<String> = stmt
        .query_map(params![now, ttl_secs], |r| r.get(0))?
        .collect::<Result<Vec<_>>>()?;
    for id in &purged_ids {
        conn.execute("DELETE FROM instance_seen WHERE id = ?1", params![id])?;
        conn.execute(
            "DELETE FROM subagents WHERE parent = ?1 OR parent LIKE ?1 || '~%'",
            params![id],
        )?;
        conn.execute(
            "DELETE FROM instance_queue WHERE instance_id LIKE ?1 || '/%' OR instance_id LIKE ?1 || '~%/%'",
            params![id],
        )?;
    }
    Ok(purged_ids.len())
}

// -----------------------------------------------------------------------------
// HA9-A: Delegated sub-addresses for in-process Claude subagents
// -----------------------------------------------------------------------------

/// Idle TTL (in seconds) after which a subagent that has not stopped and has had no
/// activity is treated as inactive (`parked`) rather than remaining `live` forever.
pub const SUBAGENT_IDLE_TTL_SECS: i64 = 900;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubagentBinding {
    pub parent: String,
    pub agent_id: String,
    pub name: Option<String>,
    pub agent_type: Option<String>,
    pub tool_use_id: Option<String>,
    pub bound_at: i64,
    pub turn_pid: Option<u32>,
    pub turn_start: Option<String>,
    pub last_active: i64,
    pub stopped_at: Option<i64>,
}

impl SubagentBinding {
    /// Display label per D5: `name ?? agent_type`.
    pub fn display_label(&self) -> Option<&str> {
        self.name.as_deref().or(self.agent_type.as_deref())
    }

    /// Most recent activity timestamp (`last_active`, or `bound_at` for legacy/zero rows).
    pub fn effective_last_active(&self) -> i64 {
        if self.last_active > 0 {
            self.last_active
        } else {
            self.bound_at
        }
    }

    /// Whether this subagent is currently live at `now`: not marked stopped (`stopped_at IS NULL`)
    /// and active within [`SUBAGENT_IDLE_TTL_SECS`].
    pub fn is_live(&self, now: i64) -> bool {
        self.stopped_at.is_none()
            && now.saturating_sub(self.effective_last_active()) < SUBAGENT_IDLE_TTL_SECS
    }

    /// Timestamp when an inactive subagent was last seen (`stopped_at` if stopped, else
    /// `effective_last_active()`).
    pub fn last_seen(&self) -> i64 {
        self.stopped_at
            .unwrap_or_else(|| self.effective_last_active())
    }
}

fn map_subagent_row(row: &rusqlite::Row<'_>) -> Result<SubagentBinding> {
    Ok(SubagentBinding {
        parent: row.get(0)?,
        agent_id: row.get(1)?,
        name: row.get(2)?,
        agent_type: row.get(3)?,
        tool_use_id: row.get(4)?,
        bound_at: row.get(5)?,
        turn_pid: row.get(6)?,
        turn_start: row.get(7)?,
        last_active: row.get(8)?,
        stopped_at: row.get(9)?,
    })
}

pub fn get_subagent(
    conn: &Connection,
    parent: &str,
    agent_id: &str,
) -> Result<Option<SubagentBinding>> {
    conn.query_row(
        "SELECT parent, agent_id, name, agent_type, tool_use_id, bound_at, turn_pid, turn_start, last_active, stopped_at FROM subagents WHERE parent = ?1 AND agent_id = ?2",
        params![parent, agent_id],
        map_subagent_row,
    )
    .optional()
}

pub fn resolve_subagent_in(
    conn: &Connection,
    parent: &str,
    child_ref: &str,
) -> Result<Option<SubagentBinding>> {
    conn.query_row(
        "SELECT parent, agent_id, name, agent_type, tool_use_id, bound_at, turn_pid, turn_start, last_active, stopped_at FROM subagents WHERE parent = ?1 AND (name = ?2 OR agent_id = ?2) LIMIT 1",
        params![parent, child_ref],
        map_subagent_row,
    )
    .optional()
}

pub fn list_subagents_for_parent(conn: &Connection, parent: &str) -> Result<Vec<SubagentBinding>> {
    let mut stmt = conn.prepare(
        "SELECT parent, agent_id, name, agent_type, tool_use_id, bound_at, turn_pid, turn_start, last_active, stopped_at FROM subagents WHERE parent = ?1 ORDER BY bound_at ASC, agent_id ASC",
    )?;
    let rows = stmt
        .query_map(params![parent], map_subagent_row)?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn list_all_subagents(conn: &Connection) -> Result<Vec<SubagentBinding>> {
    let mut stmt = conn.prepare(
        "SELECT parent, agent_id, name, agent_type, tool_use_id, bound_at, turn_pid, turn_start, last_active, stopped_at FROM subagents ORDER BY parent ASC, bound_at ASC, agent_id ASC",
    )?;
    let rows = stmt
        .query_map([], map_subagent_row)?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows)
}

/// Upserts `(parent, agent_id)` at `SubagentStart`, setting `turn_pid` and `turn_start` to
/// the parent process, refreshing `last_active`, and clearing `stopped_at`. On a resume with
/// `meta_name`, binds the name only when no other row under `parent` holds it (HA9-A §2.2, E5).
/// `agent_type` is stored when supplied (D5).
#[allow(clippy::too_many_arguments)]
pub fn subagent_start_turn(
    conn: &Connection,
    parent: &str,
    agent_id: &str,
    turn_pid: u32,
    turn_start: &str,
    meta_name: Option<&str>,
    agent_type: Option<&str>,
    tool_use_id: Option<&str>,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO subagents (parent, agent_id, name, agent_type, tool_use_id, bound_at, turn_pid, turn_start, last_active, stopped_at) \
         VALUES (?1, ?2, NULL, ?7, ?5, ?6, ?3, ?4, ?6, NULL) \
         ON CONFLICT(parent, agent_id) DO UPDATE SET \
             agent_type = COALESCE(subagents.agent_type, ?7), \
             tool_use_id = COALESCE(?5, subagents.tool_use_id), \
             turn_pid = ?3, \
             turn_start = ?4, \
             last_active = ?6, \
             stopped_at = NULL",
        params![parent, agent_id, turn_pid, turn_start, tool_use_id, now, agent_type],
    )?;
    if let Some(n) = meta_name {
        conn.execute(
            "UPDATE subagents SET name = ?3, bound_at = ?4, last_active = ?4, stopped_at = NULL \
             WHERE parent = ?1 AND agent_id = ?2 \
               AND NOT EXISTS (SELECT 1 FROM subagents s2 WHERE s2.parent = ?1 AND s2.name = ?3 AND s2.agent_id != ?2)",
            params![parent, agent_id, n, now],
        )?;
    }
    Ok(())
}

/// Binds `(parent, agent_id)` from a spawn event (`PostToolUse(Agent)` or `teammate_spawned`).
/// By OQ1 (recommended arm) and E5, a spawn bind takes over a held name: any earlier holder's
/// `name` becomes `NULL`, and that child stays reachable by `<parent>/<agent_id>`.
/// Preserves `stopped_at` on conflict so a `PostToolUse(Agent)` arriving after synchronous
/// `SubagentStop` does not resurrect a finished subagent.
pub fn subagent_bind_spawn(
    conn: &Connection,
    parent: &str,
    agent_id: &str,
    name: Option<&str>,
    tool_use_id: Option<&str>,
    now: i64,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    if let Some(n) = name {
        tx.execute(
            "UPDATE subagents SET name = NULL WHERE parent = ?1 AND name = ?2 AND agent_id != ?3",
            params![parent, n, agent_id],
        )?;
    }
    tx.execute(
        "INSERT INTO subagents (parent, agent_id, name, tool_use_id, bound_at, turn_pid, turn_start, last_active, stopped_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?5, NULL) \
         ON CONFLICT(parent, agent_id) DO UPDATE SET \
             name = COALESCE(?3, subagents.name), \
             tool_use_id = COALESCE(?4, subagents.tool_use_id), \
             bound_at = CASE WHEN ?3 IS NOT NULL THEN ?5 ELSE subagents.bound_at END",
        params![parent, agent_id, name, tool_use_id, now],
    )?;
    tx.commit()?;
    Ok(())
}

/// Re-asserts `(parent, resumed_agent_id)` from `PostToolUse(SendMessage)`. When `name` is
/// supplied (`tool_input.to` was not id-shaped), binds it without displacing another holder (E5).
pub fn subagent_reassert_resume(
    conn: &Connection,
    parent: &str,
    agent_id: &str,
    name: Option<&str>,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO subagents (parent, agent_id, name, tool_use_id, bound_at, turn_pid, turn_start, last_active, stopped_at) \
         VALUES (?1, ?2, NULL, NULL, ?3, NULL, NULL, ?3, NULL) \
         ON CONFLICT(parent, agent_id) DO NOTHING",
        params![parent, agent_id, now],
    )?;
    if let Some(n) = name {
        conn.execute(
            "UPDATE subagents SET name = ?3, bound_at = ?4 \
             WHERE parent = ?1 AND agent_id = ?2 \
               AND NOT EXISTS (SELECT 1 FROM subagents s2 WHERE s2.parent = ?1 AND s2.name = ?3 AND s2.agent_id != ?2)",
            params![parent, agent_id, n, now],
        )?;
    }
    Ok(())
}

/// Sets `turn_pid` and `turn_start` on an existing `(parent, agent_id)` row (HA9-A.agy §2.4),
/// refreshing `last_active` and clearing `stopped_at`.
pub fn subagent_set_turn(
    conn: &Connection,
    parent: &str,
    agent_id: &str,
    turn_pid: u32,
    turn_start: &str,
) -> Result<()> {
    let now = now_epoch_secs();
    conn.execute(
        "UPDATE subagents SET turn_pid = ?3, turn_start = ?4, last_active = ?5, stopped_at = NULL WHERE parent = ?1 AND agent_id = ?2",
        params![parent, agent_id, turn_pid, turn_start, now],
    )?;
    Ok(())
}

/// Refreshes `last_active` on a running (`stopped_at IS NULL`) subagent when it makes an
/// attributed tool call (`send`, `reply`, `inbox`).
pub fn subagent_touch_activity(
    conn: &Connection,
    parent: &str,
    agent_id: &str,
    now: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE subagents SET last_active = MAX(last_active, ?3) WHERE parent = ?1 AND agent_id = ?2 AND stopped_at IS NULL",
        params![parent, agent_id, now],
    )?;
    Ok(())
}

/// Upserts an agy subagent row `(parent, agent_id)` with its descriptor-computed `name`
/// and `agent_type`, displacing any other row under `parent` that previously held `name`
/// without altering `turn_pid` / `turn_start` / `stopped_at` (HA9-A.agy §2.2, §2.3).
pub fn subagent_upsert_agy(
    conn: &Connection,
    parent: &str,
    agent_id: &str,
    name: Option<&str>,
    agent_type: Option<&str>,
    now: i64,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    if let Some(n) = name {
        tx.execute(
            "UPDATE subagents SET name = NULL WHERE parent = ?1 AND name = ?2 AND agent_id != ?3",
            params![parent, n, agent_id],
        )?;
    }
    tx.execute(
        "INSERT INTO subagents (parent, agent_id, name, agent_type, tool_use_id, bound_at, turn_pid, turn_start, last_active, stopped_at) \
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, NULL, NULL, ?5, NULL) \
         ON CONFLICT(parent, agent_id) DO UPDATE SET \
             name = ?3, \
             agent_type = COALESCE(?4, subagents.agent_type)",
        params![parent, agent_id, name, agent_type, now],
    )?;
    tx.commit()?;
    Ok(())
}

/// Clears `turn_pid` and `turn_start` and marks the subagent stopped on `SubagentStop` (§2.2).
pub fn subagent_stop_turn(conn: &Connection, parent: &str, agent_id: &str) -> Result<()> {
    let now = now_epoch_secs();
    conn.execute(
        "UPDATE subagents SET turn_pid = NULL, turn_start = NULL, stopped_at = COALESCE(stopped_at, ?3) WHERE parent = ?1 AND agent_id = ?2",
        params![parent, agent_id, now],
    )?;
    Ok(())
}

/// Clears `turn_pid` and `turn_start` on `(parent, agent_id)` without marking it stopped
/// (used when a lazily admitted Codex subagent has no active hook turn and has not stopped).
pub fn subagent_clear_turn_only(conn: &Connection, parent: &str, agent_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE subagents SET turn_pid = NULL, turn_start = NULL WHERE parent = ?1 AND agent_id = ?2",
        params![parent, agent_id],
    )?;
    Ok(())
}

/// Parks every subagent row under `parent` when `parent` goes gone or parks (`turn_pid = NULL`,
/// `turn_start = NULL`, `stopped_at = COALESCE(stopped_at, ?2)`).
pub fn subagent_park_for_parent(conn: &Connection, parent: &str, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE subagents SET turn_pid = NULL, turn_start = NULL, stopped_at = COALESCE(stopped_at, ?2) WHERE parent = ?1",
        params![parent, now],
    )?;
    Ok(())
}

/// Clears `turn_pid`, `turn_start`, and `stopped_at` for every subagent row under `parent`
/// when an OpenCode parent session registers or reclaims `parent` (HA9-A.oc §2.2, C6, C7).
pub fn subagent_unpark_for_parent(conn: &Connection, parent: &str) -> Result<()> {
    conn.execute(
        "UPDATE subagents SET turn_pid = NULL, turn_start = NULL, stopped_at = NULL WHERE parent = ?1",
        params![parent],
    )?;
    Ok(())
}

/// Clears `turn_pid` and `turn_start` for every subagent row under `parent` (HA9-A.oc §2.2, C7,
/// HA9-A.agy D9: re-attestation of `parent` clears stale turn columns in the same batch).
pub fn subagent_clear_turns_for_parent(conn: &Connection, parent: &str) -> Result<()> {
    conn.execute(
        "UPDATE subagents SET turn_pid = NULL, turn_start = NULL WHERE parent = ?1",
        params![parent],
    )?;
    Ok(())
}

/// Deletes only the `subagents` rows under `parent`, sparing `instance_queue` rows
/// (HA9-A.agy §2.4, D9, E1: eviction of an agy parent deletes `subagents` rows only, never
/// `instance_queue` rows).
pub fn subagent_delete_rows_only_for_parent(conn: &Connection, parent: &str) -> Result<()> {
    conn.execute("DELETE FROM subagents WHERE parent = ?1", params![parent])?;
    Ok(())
}

/// Deletes `(parent, agent_id)` from `subagents` (HA9-A.oc §2.2 `end`, C9).
pub fn subagent_delete_row(conn: &Connection, parent: &str, agent_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM subagents WHERE parent = ?1 AND agent_id = ?2",
        params![parent, agent_id],
    )?;
    Ok(())
}

/// Deletes every `subagents` row and subagent queue entry under `parent` (HA9-A.oc §2.5:
/// `release` of `parent`).
pub fn subagent_delete_for_parent(conn: &Connection, parent: &str) -> Result<()> {
    conn.execute("DELETE FROM subagents WHERE parent = ?1", params![parent])?;
    conn.execute(
        "DELETE FROM instance_queue WHERE instance_id LIKE ?1 || '/%'",
        params![parent],
    )?;
    Ok(())
}

/// An inactive instance in `instance_seen` within `within_secs` of `now` (XL1, HA8): its ID,
/// its harness, its status (`parked` for a Claude or agy instance within its parked
/// lifetime or a reclaimable pi/plugin session inside the reclaim window with `reclaim_hash`
/// set; `closed` for a released or expired pi or plugin session), and when it was last seen
/// live. The caller leaves out the ones live now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InactiveInstance {
    pub id: String,
    pub harness: String,
    pub status: String,
    pub last_seen: i64,
}

pub fn inactive_instances(
    conn: &Connection,
    now: i64,
    ttl_secs: i64,
    within_secs: i64,
) -> Result<Vec<InactiveInstance>> {
    let cutoff = now.saturating_sub(within_secs);
    let mut stmt = conn.prepare(
        "SELECT id, harness, last_live, \
         (last_live + ?2 > ?1 \
          OR EXISTS (SELECT 1 FROM instance_queue q WHERE q.instance_id = s.id AND q.delivered_at IS NULL AND q.expires_at > ?1) \
          OR EXISTS (SELECT 1 FROM agy_pending_messages a WHERE a.session_id = s.id AND a.delivered_at IS NULL AND a.created_at >= ?1 - ?2)), \
         reclaim_hash IS NOT NULL, \
         (last_live + ?2 > ?1) \
         FROM instance_seen s WHERE last_live >= ?3 ORDER BY id",
    )?;
    let rows = stmt
        .query_map(params![now, ttl_secs, cutoff], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, bool>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .filter_map(
            |(id, harness, last_seen, within_parked_ttl, has_reclaim, within_reclaim_window)| {
                let is_reclaim_harness = harness == "pi"
                    || harness == "codex"
                    || crate::plugin::harness(&harness).is_some();
                if is_reclaim_harness {
                    let status = if has_reclaim && within_reclaim_window {
                        "parked"
                    } else {
                        "closed"
                    };
                    Some(InactiveInstance {
                        id,
                        harness,
                        status: status.to_string(),
                        last_seen,
                    })
                } else if within_parked_ttl {
                    Some(InactiveInstance {
                        id,
                        harness,
                        status: "parked".to_string(),
                        last_seen,
                    })
                } else {
                    None
                }
            },
        )
        .collect())
}

// -----------------------------------------------------------------------------
// HA9-A.codex: Codex root persistence, startup invalidation, and handoff state
// -----------------------------------------------------------------------------

/// Persisted record of a parked (`StaleAfterResume`) Codex root loaded at startup or
/// retained when a root's writer lease closes cleanly (§6.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedStaleCodexRoot {
    pub root_id: String,
    pub owner_pid: u32,
    pub owner_starttime: String,
    pub restart_pending: bool,
    pub codex_home: std::path::PathBuf,
    pub rollout_dev: u64,
    pub rollout_ino: u64,
    pub label: String,
    pub cwd: Option<String>,
    pub generation: u64,
}

/// On bus startup, any persisted `codex_roots` loses its continuous writer-lease witness
/// (§2.1, §6.2.1): mark all existing rows `active = 0`, preserving `revoked = 0` rows in
/// `StaleAfterResume` (`stale_roots`) and `revoked = 1` rows in `RevokedByOperator`,
/// migrate any unread child queue messages to their parent root queue before deleting
/// child `subagents` rows, and transition any `inflight` rows in `codex_handoff` to
/// `unknown` with message outcome `delivery_unknown` (§2.5).
pub fn startup_invalidate_codex(
    conn: &Connection,
) -> Result<(
    u64,
    std::collections::HashSet<String>,
    std::collections::HashMap<String, PersistedStaleCodexRoot>,
)> {
    let tx = conn.unchecked_transaction()?;
    let now = now_epoch_secs();
    let max_gen: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(generation), 0) FROM codex_roots",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let mut revoked = std::collections::HashSet::new();
    let mut stale = std::collections::HashMap::new();
    tx.execute(
        "UPDATE codex_roots SET restart_pending = CASE WHEN revoked != 0 THEN 0 ELSE restart_pending OR active END",
        [],
    )?;
    type CodexRootRow = (
        String,
        String,
        i64,
        i64,
        String,
        Option<String>,
        i64,
        i64,
        u32,
        String,
        bool,
    );
    let rows: Vec<CodexRootRow> = {
        let mut stmt = tx.prepare(
            "SELECT root_id, codex_home, rollout_dev, rollout_ino, label, cwd, generation, revoked, owner_pid, owner_starttime, restart_pending FROM codex_roots",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2).unwrap_or(0),
                r.get::<_, i64>(3).unwrap_or(0),
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6).unwrap_or(0),
                r.get::<_, i64>(7).unwrap_or(0),
                r.get::<_, u32>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, bool>(10)?,
            ))
        })?;
        mapped.collect::<Result<Vec<_>>>()?
    };
    for (
        id,
        home,
        r_dev,
        r_ino,
        label,
        cwd,
        gen,
        rev,
        owner_pid,
        owner_starttime,
        restart_pending,
    ) in rows
    {
        if rev == 0 {
            let child_ids: Vec<String> = {
                let mut cstmt = tx.prepare("SELECT agent_id FROM subagents WHERE parent = ?1")?;
                let c_rows = cstmt.query_map(params![id], |r| r.get::<_, String>(0))?;
                c_rows.collect::<Result<Vec<_>>>()?
            };
            for agent_id in child_ids {
                let _ = take_codex_subagent_queue_to_parent(
                    &tx,
                    &id,
                    gen.max(0) as u64,
                    &agent_id,
                    now,
                );
            }
        }
        tx.execute("DELETE FROM subagents WHERE parent = ?1", params![id])?;
        tx.execute(
            "DELETE FROM instance_queue WHERE instance_id LIKE ?1 || '/%' AND delivered_at IS NULL",
            params![id],
        )?;
        if rev != 0 {
            revoked.insert(id.clone());
        }
        if !home.is_empty() {
            stale.insert(
                id.clone(),
                PersistedStaleCodexRoot {
                    root_id: id,
                    owner_pid,
                    owner_starttime,
                    restart_pending,
                    codex_home: std::path::PathBuf::from(home),
                    rollout_dev: r_dev.max(0) as u64,
                    rollout_ino: r_ino.max(0) as u64,
                    label,
                    cwd,
                    generation: gen.max(0) as u64,
                },
            );
        }
    }
    tx.execute("UPDATE codex_roots SET active = 0", [])?;

    // Any handoff left `inflight` when the bus stopped becomes `unknown` (§2.5).
    let inflight_ids: Vec<String> = {
        let mut stmt =
            tx.prepare("SELECT message_id FROM codex_handoff WHERE state = 'inflight'")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>>>()?;
        rows
    };
    for msg_id in inflight_ids {
        tx.execute(
            "UPDATE codex_handoff SET state = 'unknown', updated_at = ?2 WHERE message_id = ?1",
            params![msg_id, now],
        )?;
        tx.execute(
            "UPDATE messages SET outcome = 'delivery_unknown' WHERE id = ?1",
            params![msg_id],
        )?;
        update_reply_push_outcome(&tx, &msg_id, "push_failed")?;
    }

    tx.commit()?;
    Ok((max_gen.max(0) as u64, revoked, stale))
}

/// Persist an admitted Codex root generation in `codex_roots` and `instance_seen` (§2.1, §6.2.1).
pub fn upsert_codex_root(conn: &Connection, snap: &crate::codex::CodexRootSnapshot) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let now = now_epoch_secs();
    tx.execute(
        "INSERT INTO codex_roots (root_id, codex_home, owner_pid, owner_starttime, generation, label, cwd, registered_at, rollout_dev, rollout_ino, active, revoked) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, 0) \
         ON CONFLICT(root_id) DO UPDATE SET \
             codex_home = excluded.codex_home, \
             owner_pid = excluded.owner_pid, \
             owner_starttime = excluded.owner_starttime, \
             generation = excluded.generation, \
             label = excluded.label, \
             cwd = excluded.cwd, \
             registered_at = excluded.registered_at, \
             rollout_dev = excluded.rollout_dev, \
             rollout_ino = excluded.rollout_ino, \
             active = 1, \
             revoked = 0, \
             restart_pending = 0",
        params![
            snap.root_id,
            snap.codex_home.to_string_lossy().as_ref(),
            snap.owner_pid,
            snap.owner_starttime,
            snap.generation as i64,
            snap.label,
            snap.cwd,
            snap.registered_at,
            snap.rollout_dev as i64,
            snap.rollout_ino as i64,
        ],
    )?;
    mark_live(&tx, &snap.root_id, "codex", now)?;
    rebind_pending_codex_handoffs(&tx, snap, now)?;
    tx.commit()
}

fn rebind_pending_codex_handoffs(
    conn: &Connection,
    snap: &crate::codex::CodexRootSnapshot,
    now: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE codex_handoff SET root_generation = ?2, updated_at = ?3 \
         WHERE root_id = ?1 AND state = 'pending'",
        params![snap.root_id, snap.generation as i64, now],
    )?;
    Ok(())
}

/// Atomically rebind a resumed Codex root to `(owner_pid, owner_starttime, generation)`,
/// migrating any unread `pending` root handoff rows from prior generations to the new
/// generation and folding any unread child queue messages from prior-generation subagents
/// back into the root queue with the §2.3 fallback header (§6.2.2 step 6).
pub fn rebind_codex_root(conn: &Connection, snap: &crate::codex::CodexRootSnapshot) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    rebind_codex_root_in(&tx, snap)?;
    tx.commit()
}

fn rebind_codex_root_in(
    tx: &Transaction<'_>,
    snap: &crate::codex::CodexRootSnapshot,
) -> Result<()> {
    let now = now_epoch_secs();
    tx.execute(
        "INSERT INTO codex_roots (root_id, codex_home, owner_pid, owner_starttime, generation, label, cwd, registered_at, rollout_dev, rollout_ino, active, revoked) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, 0) \
         ON CONFLICT(root_id) DO UPDATE SET \
             codex_home = excluded.codex_home, \
             owner_pid = excluded.owner_pid, \
             owner_starttime = excluded.owner_starttime, \
             generation = excluded.generation, \
             label = excluded.label, \
             cwd = excluded.cwd, \
             registered_at = excluded.registered_at, \
             rollout_dev = excluded.rollout_dev, \
             rollout_ino = excluded.rollout_ino, \
             active = 1, \
             revoked = 0, \
             restart_pending = 0",
        params![
            snap.root_id,
            snap.codex_home.to_string_lossy().as_ref(),
            snap.owner_pid,
            snap.owner_starttime,
            snap.generation as i64,
            snap.label,
            snap.cwd,
            snap.registered_at,
            snap.rollout_dev as i64,
            snap.rollout_ino as i64,
        ],
    )?;
    mark_live(tx, &snap.root_id, "codex", now)?;
    rebind_pending_codex_handoffs(tx, snap, now)?;
    let child_ids: Vec<String> = {
        let mut stmt = tx.prepare("SELECT agent_id FROM subagents WHERE parent = ?1")?;
        let rows = stmt.query_map(params![snap.root_id], |r| r.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>>>()?
    };
    for agent_id in child_ids {
        let _ =
            take_codex_subagent_queue_to_parent(tx, &snap.root_id, snap.generation, &agent_id, now);
    }
    tx.execute(
        "DELETE FROM subagents WHERE parent = ?1",
        params![snap.root_id],
    )?;
    Ok(())
}

pub fn rebind_startup_codex_root(
    conn: &Connection,
    snap: &crate::codex::CodexRootSnapshot,
    old_generation: u64,
) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let eligible: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM codex_roots WHERE root_id = ?1 AND owner_pid = ?2 AND owner_starttime = ?3 AND generation = ?4 AND revoked = 0 AND restart_pending = 1)",
        params![snap.root_id, snap.owner_pid, snap.owner_starttime, old_generation as i64],
        |r| r.get(0),
    )?;
    if !eligible {
        return Ok(false);
    }
    rebind_codex_root_in(&tx, snap)?;
    tx.execute(
        "UPDATE codex_roots SET restart_pending = 1 WHERE root_id = ?1",
        [&snap.root_id],
    )?;
    tx.commit()?;
    Ok(true)
}

pub fn finish_codex_startup_recovery(
    conn: &Connection,
    root_id: &str,
    owner_pid: u32,
    owner_starttime: &str,
    generation: u64,
    park: bool,
) -> Result<()> {
    conn.execute(
        "UPDATE codex_roots SET restart_pending = 0, active = CASE WHEN ?5 THEN 0 ELSE active END WHERE root_id = ?1 AND owner_pid = ?2 AND owner_starttime = ?3 AND generation = ?4",
        params![root_id, owner_pid, owner_starttime, generation as i64, park],
    )?;
    Ok(())
}

pub fn codex_startup_pending_generation(
    conn: &Connection,
    root_id: &str,
    owner_pid: u32,
    owner_starttime: &str,
) -> Result<Option<u64>> {
    conn.query_row(
        "SELECT generation FROM codex_roots WHERE root_id = ?1 AND owner_pid = ?2 AND owner_starttime = ?3 AND revoked = 0 AND restart_pending = 1",
        params![root_id, owner_pid, owner_starttime], |r| r.get::<_, i64>(0),
    ).optional().map(|g| g.map(|g| g.max(0) as u64))
}

pub fn codex_startup_has_pending(conn: &Connection, root_id: &str, ttl: u64) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM codex_handoff h JOIN pi_pending_messages p ON p.id = h.message_id WHERE h.root_id = ?1 AND h.state = 'pending' AND p.delivered_at IS NULL AND p.created_at > ?2)",
        params![root_id, now_epoch_secs().saturating_sub(ttl.min(i64::MAX as u64) as i64)], |r| r.get(0),
    )
}

/// Park an admitted Codex root into `StaleAfterResume` (`active = 0, revoked = 0`),
/// moving any unread child queue messages to the parent root queue and clearing
/// stale `subagents` rows so child bindings must re-attest on resume (§6.2.1).
pub fn park_codex_root(conn: &Connection, root_id: &str) -> Result<()> {
    park_codex_root_with_restart(conn, root_id, false)
}

pub(crate) fn park_codex_root_preserving_startup(conn: &Connection, root_id: &str) -> Result<()> {
    park_codex_root_with_restart(conn, root_id, true)
}

fn park_codex_root_with_restart(conn: &Connection, root_id: &str, preserve: bool) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let now = now_epoch_secs();
    let gen: i64 = tx
        .query_row(
            "SELECT generation FROM codex_roots WHERE root_id = ?1",
            params![root_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let child_ids: Vec<String> = {
        let mut stmt = tx.prepare("SELECT agent_id FROM subagents WHERE parent = ?1")?;
        let rows = stmt.query_map(params![root_id], |r| r.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>>>()?
    };
    for agent_id in child_ids {
        let _ =
            take_codex_subagent_queue_to_parent(&tx, root_id, gen.max(0) as u64, &agent_id, now);
    }
    tx.execute(
        "UPDATE codex_roots SET active = 0, restart_pending = CASE WHEN ?2 THEN restart_pending ELSE 0 END WHERE root_id = ?1",
        params![root_id, preserve],
    )?;
    tx.execute("DELETE FROM subagents WHERE parent = ?1", params![root_id])?;
    tx.commit()
}

/// Mark a Codex root `RevokedByOperator` (`active = 0, revoked = 1`) in `codex_roots`
/// and delete its child bindings and child queue entries (§2.1, §2.3, §6.2.1).
pub fn invalidate_codex_root(conn: &Connection, root_id: &str) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let now = now_epoch_secs();
    tx.execute(
        "INSERT INTO codex_roots (root_id, codex_home, owner_pid, owner_starttime, generation, label, cwd, registered_at, rollout_dev, rollout_ino, active, revoked) \
         VALUES (?1, '', 0, '', 0, 'codex', NULL, ?2, 0, 0, 0, 1) \
         ON CONFLICT(root_id) DO UPDATE SET active = 0, revoked = 1, restart_pending = 0",
        params![root_id, now],
    )?;
    tx.execute("DELETE FROM subagents WHERE parent = ?1", params![root_id])?;
    tx.execute(
        "DELETE FROM instance_queue WHERE instance_id LIKE ?1 || '/%'",
        params![root_id],
    )?;
    tx.commit()
}

/// Explicitly clear `RevokedByOperator` (`revoked = 0, active = 0`) for `root_id`
/// so a subsequent `SessionStart(resume)` or hook with a valid witness can rebind it (§6.2.1).
pub fn unrevoke_codex_root_by_operator(conn: &Connection, root_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE codex_roots SET revoked = 0, active = 0, restart_pending = 0 WHERE root_id = ?1",
        params![root_id],
    )?;
    Ok(())
}

/// A known, nonrevoked root may receive queue custody while awaiting re-attestation.
/// This is not admission and does not make the root a live delivery carrier.
pub fn parked_codex_generation(
    conn: &Connection,
    root_id: &str,
    now: i64,
    ttl: i64,
) -> Result<Option<u64>> {
    conn.query_row(
        "SELECT r.generation FROM codex_roots r JOIN instance_seen s ON s.id = r.root_id \
         WHERE r.root_id = ?1 AND r.revoked = 0 AND r.active = 0 AND s.harness = 'codex' AND s.last_live > ?2",
        params![root_id, now.saturating_sub(ttl)],
        |row| row.get::<_, i64>(0),
    ).optional().map(|generation| generation.map(|g| g.max(0) as u64))
}

pub fn enqueue_parked_codex_message(
    conn: &Connection,
    root_id: &str,
    generation: u64,
    msg: &PiPendingMessage,
    ttl: i64,
) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    if parked_codex_generation(&tx, root_id, now_epoch_secs(), ttl)? != Some(generation) {
        return Ok(false);
    }
    if !enqueue_codex_root_message_in(&tx, root_id, generation, msg)? {
        return Ok(false);
    }
    tx.commit()?;
    Ok(true)
}

/// Insert a root delivery into `pi_pending_messages` accompanied by a `codex_handoff` row
/// in state `pending` (§2.5).
pub fn enqueue_codex_root_message(
    conn: &Connection,
    root_id: &str,
    root_generation: u64,
    msg: &PiPendingMessage,
) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    if !enqueue_codex_root_message_in(&tx, root_id, root_generation, msg)? {
        return Ok(false);
    }
    tx.commit()?;
    Ok(true)
}

pub(crate) fn enqueue_codex_root_message_in(
    conn: &Connection,
    root_id: &str,
    root_generation: u64,
    msg: &PiPendingMessage,
) -> Result<bool> {
    if !insert_pi_message(conn, msg)? {
        return Ok(false);
    }
    conn.execute(
        "INSERT OR REPLACE INTO codex_handoff (message_id, root_id, root_generation, carrier, state, updated_at) \
         VALUES (?1, ?2, ?3, 'none', 'pending', ?4)",
        params![msg.id, root_id, root_generation as i64, msg.created_at],
    )?;
    Ok(true)
}

/// Atomically transition a single message from `pending` to `inflight` with `carrier = 'push'`
/// for `root_id` at `root_generation` (§2.5). Returns `false` if another worker/hook already
/// reserved it or its generation changed.
pub fn reserve_codex_single_for_push(
    conn: &Connection,
    root_id: &str,
    root_generation: u64,
    message_id: &str,
) -> Result<bool> {
    let now = now_epoch_secs();
    let count = conn.execute(
        "UPDATE codex_handoff SET state = 'inflight', carrier = 'push', updated_at = ?4 \
         WHERE message_id = ?1 AND root_id = ?2 AND root_generation = ?3 AND state = 'pending' \
           AND EXISTS (SELECT 1 FROM pi_pending_messages p WHERE p.id = ?1 AND p.session_id = ?2 AND p.delivered_at IS NULL)",
        params![message_id, root_id, root_generation as i64, now],
    )?;
    Ok(count > 0)
}

/// Select the oldest eligible head without reserving it. An in-flight head blocks
/// another MCP drain; the existing push CAS arbitrates with hook and relay carriers.
pub fn next_codex_relay_pending(
    conn: &Connection,
    root_id: &str,
    generation: u64,
    ttl_secs: u64,
) -> Result<Option<(String, String)>> {
    let head = conn.query_row(
        "SELECT p.id, p.envelope, h.state FROM pi_pending_messages p JOIN codex_handoff h ON h.message_id=p.id \
         WHERE p.session_id=?1 AND h.root_id=?1 AND h.root_generation=?2 AND p.delivered_at IS NULL \
         AND p.created_at>?3 AND h.state IN ('pending','inflight') ORDER BY p.created_at,p.rowid LIMIT 1",
        params![root_id,generation as i64,now_epoch_secs().saturating_sub(ttl_secs.min(i64::MAX as u64) as i64)],
        |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)),
    ).optional()?;
    Ok(head.and_then(|(id, body, state)| (state == "pending").then_some((id, body))))
}

/// Atomically select and reserve up to 8 envelopes / 6,000 UTF-8 bytes (or a single oversized
/// head envelope) in creation order for a hook drain on `(root_id, root_generation)` (§2.5).
/// Transitions the selected rows to `state = 'inflight'`, `carrier = 'hook'`.
pub fn reserve_codex_hook_batch(
    conn: &Connection,
    root_id: &str,
    root_generation: u64,
    ttl_secs: u64,
) -> Result<Option<(Vec<String>, String)>> {
    let tx = conn.unchecked_transaction()?;
    let candidates: Vec<(String, String)> = {
        let mut stmt = tx.prepare(
            "SELECT p.id, p.envelope \
             FROM pi_pending_messages p \
             JOIN codex_handoff h ON h.message_id = p.id \
             WHERE p.session_id = ?1 \
               AND p.delivered_at IS NULL \
               AND h.root_id = ?1 \
               AND h.root_generation = ?2 \
               AND h.state = 'pending' AND p.created_at > ?3 \
             ORDER BY p.created_at ASC, p.rowid ASC",
        )?;
        let rows = stmt.query_map(
            params![
                root_id,
                root_generation as i64,
                now_epoch_secs().saturating_sub(ttl_secs.min(i64::MAX as u64) as i64)
            ],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )?;
        rows.collect::<Result<Vec<_>>>()?
    };

    let Some((selected_ids, formatted)) =
        crate::codex::select_and_format_codex_drain_batch(&candidates)
    else {
        return Ok(None);
    };

    let now = now_epoch_secs();
    for msg_id in &selected_ids {
        let updated = tx.execute(
            "UPDATE codex_handoff SET state = 'inflight', carrier = 'hook', updated_at = ?2 \
             WHERE message_id = ?1 AND state = 'pending'",
            params![msg_id, now],
        )?;
        if updated == 0 {
            return Ok(None);
        }
    }
    tx.commit()?;
    Ok(Some((selected_ids, formatted)))
}

/// Atomically select and reserve a hook drain batch (at most 8 envelopes / 6,000 UTF-8 bytes)
/// for an admitted Codex child `subagent_address = "<P>/<X>"` from `instance_queue` (§2.5).
pub fn reserve_codex_child_hook_batch(
    conn: &Connection,
    subagent_address: &str,
    root_generation: u64,
) -> Result<Option<(Vec<String>, String)>> {
    let tx = conn.unchecked_transaction()?;
    let now = now_epoch_secs();
    let raw_rows: Vec<(String, String, String)> = {
        let mut stmt = tx.prepare(
            "SELECT q.id, q.from_name, q.body \
             FROM instance_queue q \
             LEFT JOIN codex_handoff h ON h.message_id = q.id \
             WHERE q.instance_id = ?1 \
               AND q.delivered_at IS NULL \
               AND q.expires_at > ?2 \
               AND (h.state IS NULL OR h.state = 'pending') \
             ORDER BY q.created_at ASC, q.id ASC",
        )?;
        let rows = stmt.query_map(params![subagent_address, now], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>>>()?
    };

    let candidates: Vec<(String, String)> = raw_rows
        .into_iter()
        .map(|(id, from_name, body)| {
            let env =
                crate::inbox::assemble_envelope(&from_name, &crate::inbox::sanitize_body(&body));
            (id, env)
        })
        .collect();

    let Some((selected_ids, formatted)) =
        crate::codex::select_and_format_codex_drain_batch(&candidates)
    else {
        return Ok(None);
    };

    for msg_id in &selected_ids {
        tx.execute(
            "INSERT INTO codex_handoff (message_id, root_id, root_generation, carrier, state, updated_at) \
             VALUES (?1, ?2, ?3, 'hook', 'inflight', ?4) \
             ON CONFLICT(message_id) DO UPDATE SET \
                 root_id = excluded.root_id, \
                 root_generation = excluded.root_generation, \
                 carrier = 'hook', \
                 state = 'inflight', \
                 updated_at = excluded.updated_at",
            params![msg_id, subagent_address, root_generation as i64, now],
        )?;
    }
    tx.commit()?;
    Ok(Some((selected_ids, formatted)))
}

/// Mark a reserved handoff batch (`push` or `hook`) as `accepted`, stamping `delivered_at`
/// on `pi_pending_messages` (or `instance_queue` for a child drain) and updating
/// `messages.outcome` to `delivered` atomically (§2.5).
pub fn complete_codex_handoff_accepted(
    conn: &Connection,
    root_id: &str,
    message_ids: &[String],
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let now = now_epoch_secs();
    for msg_id in message_ids {
        tx.execute(
            "UPDATE codex_handoff SET state = 'accepted', updated_at = ?2 WHERE message_id = ?1",
            params![msg_id, now],
        )?;
        tx.execute(
            "UPDATE pi_pending_messages SET delivered_at = ?1 WHERE id = ?2 AND session_id = ?3 AND delivered_at IS NULL",
            params![now, msg_id, root_id],
        )?;
        tx.execute(
            "UPDATE instance_queue SET delivered_at = ?1 WHERE id = ?2 AND instance_id = ?3 AND delivered_at IS NULL",
            params![now, msg_id, root_id],
        )?;
        update_message_outcome(&tx, msg_id, "delivered")?;
        update_reply_push_outcome(&tx, msg_id, "pushed")?;
    }
    tx.commit()
}

/// Return a reserved handoff batch from `inflight` back to `pending` when a known pre-write
/// refusal/peer mismatch occurred before any possible transfer (§2.5).
pub fn release_codex_handoff_to_pending(conn: &Connection, message_ids: &[String]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let now = now_epoch_secs();
    for msg_id in message_ids {
        tx.execute(
            "UPDATE codex_handoff SET state = 'pending', carrier = 'none', updated_at = ?2 \
             WHERE message_id = ?1 AND state = 'inflight'",
            params![msg_id, now],
        )?;
    }
    tx.commit()
}

/// Transition a reserved handoff batch from `inflight` to `unknown` after a post-write timeout,
/// EOF, or partial hook socket write, setting `messages.outcome` to `delivery_unknown` so it is
/// never automatically retried (§2.5).
pub fn mark_codex_handoff_unknown(conn: &Connection, message_ids: &[String]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let now = now_epoch_secs();
    for msg_id in message_ids {
        tx.execute(
            "UPDATE codex_handoff SET state = 'unknown', updated_at = ?2 WHERE message_id = ?1",
            params![msg_id, now],
        )?;
        tx.execute(
            "UPDATE messages SET outcome = 'delivery_unknown' WHERE id = ?1",
            params![msg_id],
        )?;
        update_reply_push_outcome(&tx, msg_id, "push_failed")?;
    }
    tx.commit()
}

pub(crate) fn mark_owned_codex_push_unknown(
    conn: &Connection,
    root_id: &str,
    generation: u64,
    message_id: &str,
) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let changed = tx.execute(
        "UPDATE codex_handoff SET state = 'unknown', updated_at = ?4 WHERE message_id = ?1 AND root_id = ?2 AND root_generation = ?3 AND carrier = 'push' AND state = 'inflight'",
        params![message_id, root_id, generation as i64, now_epoch_secs()],
    )?;
    if changed != 0 {
        tx.execute(
            "UPDATE messages SET outcome = 'delivery_unknown' WHERE id = ?1",
            [message_id],
        )?;
        update_reply_push_outcome(&tx, message_id, "push_failed")?;
    }
    tx.commit()?;
    Ok(changed != 0)
}

/// Inspect a message's `(state, carrier, root_generation)` in `codex_handoff`.
pub fn get_codex_handoff_state(
    conn: &Connection,
    message_id: &str,
) -> Result<Option<(String, String, u64)>> {
    conn.query_row(
        "SELECT state, carrier, root_generation FROM codex_handoff WHERE message_id = ?1",
        params![message_id],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?.max(0) as u64,
            ))
        },
    )
    .optional()
}

/// Move any undelivered messages queued for `<parent_id>/<agent_id>` in `instance_queue`
/// into `parent_id`'s `pi_pending_messages` + `codex_handoff` queue with `to=<P>/<X> agent_id=<X>`
/// header when `X`'s turn stops (§2.3, §2.5), returning the messages moved so the caller can
/// attempt immediate relay push to `parent_id`.
pub fn take_codex_subagent_queue_to_parent(
    conn: &Connection,
    parent_id: &str,
    root_generation: u64,
    agent_id: &str,
    now: i64,
) -> Result<Vec<PiPendingMessage>> {
    let sub_queue_id = format!("{parent_id}/{agent_id}");
    let header = format!("to={parent_id}/{agent_id} agent_id={agent_id}");
    let taken = take_queued(conn, &sub_queue_id, now)?;
    let mut moved = Vec::new();
    for message in taken {
        let body_with_header = format!("{header}\n{}", message.body);
        let pi_msg = PiPendingMessage {
            id: message.id.clone(),
            session_id: parent_id.to_string(),
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
        if enqueue_codex_root_message(conn, parent_id, root_generation, &pi_msg)? {
            moved.push(pi_msg);
        } else {
            untake_queued(conn, &message.id)?;
        }
    }
    Ok(moved)
}

/// `secs` since the epoch as an RFC 3339 UTC time, `2026-10-12T08:30:00Z`.
pub fn utc_rfc3339(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    fn msg(id: &str, session_id: &str, outcome: &str, harness: &str) -> MessageRecord {
        MessageRecord {
            id: id.into(),
            created_at: now_epoch_secs(),
            session_id: session_id.into(),
            from_name: "f".into(),
            bytes: 1,
            outcome: outcome.into(),
            recipient_harness: harness.into(),
            return_harness: None,
            return_session_id: None,
            thread_id: id.into(),
            return_host: None,
        }
    }

    /// A schema-N database whose `outbound` predates `via_mailbox` gains it, and a send
    /// recorded before it reads as not in a mailbox (fail closed).
    #[test]
    fn outbound_gains_via_mailbox_unset() {
        let c = Connection::open_in_memory().unwrap();
        init_db(&c).unwrap();
        c.execute_batch("ALTER TABLE outbound DROP COLUMN via_mailbox")
            .unwrap();
        c.execute(
            "INSERT INTO outbound (id, peer, target_ref, outcome, created_at) VALUES ('O', 'p', 't', 'queued', 0)",
            [],
        )
        .unwrap();
        init_db(&c).unwrap();
        assert!(!get_outbound(&c, "O").unwrap().unwrap().via_mailbox);
        mark_outbound_via_mailbox(&c, "O").unwrap();
        assert!(get_outbound(&c, "O").unwrap().unwrap().via_mailbox);
    }

    /// HA3: an ack that lands before the send (or the federated receiver) records its own
    /// `queued` leaves the record `delivered`; any other outcome is recorded as given.
    #[test]
    fn an_early_ack_is_not_undone_by_queued() {
        let c = Connection::open_in_memory().unwrap();
        init_db(&c).unwrap();
        let outcome = |id: &str| get_message(&c, id).unwrap().unwrap().outcome;
        let pi = |id: &str| PiPendingMessage {
            id: id.into(),
            session_id: "s".into(),
            created_at: now_epoch_secs(),
            from_name: "f".into(),
            bytes: 1,
            text: "t".into(),
            envelope: "e".into(),
            delivered_at: None,
        };
        for id in ["L", "F"] {
            upsert_message(&c, &msg(id, "", KEY_PENDING, "")).unwrap();
            record_message_recipient(&c, id, "s", "opencode").unwrap();
            insert_pi_message(&c, &pi(id)).unwrap();
            assert!(ack_pi_message(&c, "s", id).unwrap());
            assert_eq!(outcome(id), "delivered", "{id}: the ack");
        }
        complete_message(&c, "L", "queued", None).unwrap();
        update_message_outcome(&c, "F", "queued").unwrap();
        assert_eq!(outcome("L"), "delivered", "the send's own record");
        assert_eq!(outcome("F"), "delivered", "the federated receiver's record");
        update_message_outcome(&c, "F", "delivery_failed").unwrap();
        assert_eq!(
            outcome("F"),
            "delivery_failed",
            "only `queued` is held back"
        );
    }

    /// F2: keys left `pending` settle from what the database says reached the recipient.
    #[test]
    fn reconcile_settles_pending_keys_from_their_records() {
        let c = Connection::open_in_memory().unwrap();
        init_db(&c).unwrap();
        let reserve = |key: &str, id: &str| {
            reserve_idempotency_key(&c, "p", key, "b", "t", "f", id, 60).unwrap()
        };
        reserve("none", "M0"); // no record: delivery never began
        reserve("mid", "M1"); // record written, delivery interrupted
        upsert_message(&c, &msg("M1", "", KEY_PENDING, "")).unwrap();
        reserve("local", "M2");
        insert_message(&c, &msg("M2", "s2", "delivered", "claude")).unwrap();
        reserve("fed", "M3");
        insert_message(&c, &msg("M3", "s3", "queued", "fed")).unwrap();
        insert_outbound(&c, "M3", "peer", "s3@peer", "queued", 0).unwrap();
        reserve_reply_key(&c, "p", "rdone", "M2", "r", "R1", 60).unwrap();
        insert_reply(&c, "M2", "s", "r", Some("pushed"), Some("R1")).unwrap();
        reserve_reply_key(&c, "p", "rnone", "M2", "r", "R2", 60).unwrap();

        assert_eq!(reconcile_pending_keys(&c, "n").unwrap(), 6);
        let got = |key: &str| {
            let r = get_idempotency_record(&c, "p", key, 60).unwrap().unwrap();
            (r.session_id, r.outcome)
        };
        assert_eq!(got("none"), (String::new(), KEY_FAILED.into()));
        assert_eq!(got("mid"), (String::new(), KEY_FAILED.into()));
        assert_eq!(got("local"), ("s2@n".into(), "delivered".into()));
        assert_eq!(got("fed"), ("s3@peer".into(), "queued".into()));
        let state = |key: &str| -> (String, Option<i64>) {
            c.query_row(
                "SELECT state, seq FROM reply_idempotency_keys WHERE key = ?1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        };
        assert_eq!(state("rdone").0, KEY_DONE);
        assert!(state("rdone").1.is_some());
        assert_eq!(state("rnone"), (KEY_FAILED.into(), None));
        assert_eq!(
            reconcile_pending_keys(&c, "n").unwrap(),
            0,
            "nothing left pending"
        );
    }

    #[test]
    fn failed_send_key_requires_matching_attachment_digest() {
        let c = Connection::open_in_memory().unwrap();
        init_db(&c).unwrap();
        assert!(
            matches!(reserve_idempotency_key_with_refs(&c, "p", "k", "text", Some("refs-a"), "to", "from", "M1", 60).unwrap(), Reservation::Mine(id) if id == "M1")
        );
        settle_idempotency_key(&c, "p", "k", "", KEY_FAILED).unwrap();
        for digest in [None, Some("refs-b")] {
            let held = reserve_idempotency_key_with_refs(
                &c, "p", "k", "text", digest, "to", "from", "M2", 60,
            )
            .unwrap();
            assert!(
                matches!(held, Reservation::Held(r) if r.refs_digest.as_deref() == Some("refs-a") && r.outcome == KEY_FAILED)
            );
        }
        assert!(
            matches!(reserve_idempotency_key_with_refs(&c, "p", "k", "text", Some("refs-a"), "to", "from", "M2", 60).unwrap(), Reservation::Mine(id) if id == "M1")
        );
    }

    #[test]
    fn failed_reply_key_requires_matching_attachment_digest() {
        let c = Connection::open_in_memory().unwrap();
        init_db(&c).unwrap();
        assert!(
            matches!(reserve_reply_key_with_refs(&c, "p", "k", "message", "text", Some("refs-a"), "R1", 60).unwrap(), Reservation::Mine(id) if id == "R1")
        );
        settle_reply_key(&c, "p", "k", KEY_FAILED, None).unwrap();
        for digest in [None, Some("refs-b")] {
            let held =
                reserve_reply_key_with_refs(&c, "p", "k", "message", "text", digest, "R2", 60)
                    .unwrap();
            assert!(
                matches!(held, Reservation::Held(r) if r.refs_digest.as_deref() == Some("refs-a") && r.state == KEY_FAILED)
            );
        }
        assert!(
            matches!(reserve_reply_key_with_refs(&c, "p", "k", "message", "text", Some("refs-a"), "R2", 60).unwrap(), Reservation::Mine(id) if id == "R1")
        );
    }

    #[test]
    fn legacy_key_upgrade_preserves_null_digest_and_arbitrary_text() {
        let c = Connection::open_in_memory().unwrap();
        init_db(&c).unwrap();
        let body = "text\0[{\"sha256\":\"hash\"}]";
        reserve_idempotency_key(&c, "p", "send", body, "to", "from", "M1", 60).unwrap();
        reserve_reply_key(&c, "p", "reply", "message", body, "R1", 60).unwrap();
        c.execute_batch("ALTER TABLE idempotency_keys DROP COLUMN refs_digest; ALTER TABLE reply_idempotency_keys DROP COLUMN refs_digest;").unwrap();
        init_db(&c).unwrap();
        init_db(&c).unwrap();
        let send = get_idempotency_record(&c, "p", "send", 60)
            .unwrap()
            .unwrap();
        assert_eq!((send.body.as_str(), send.refs_digest), (body, None));
        assert!(
            matches!(reserve_reply_key(&c, "p", "reply", "message", body, "R2", 60).unwrap(), Reservation::Held(r) if r.body == body && r.refs_digest.is_none())
        );
        assert!(
            matches!(reserve_idempotency_key_with_refs(&c, "p", "send", body, Some("digest"), "to", "from", "M2", 60).unwrap(), Reservation::Held(r) if r.refs_digest.is_none())
        );
        assert!(
            matches!(reserve_reply_key_with_refs(&c, "p", "reply", "message", body, Some("digest"), "R2", 60).unwrap(), Reservation::Held(r) if r.refs_digest.is_none())
        );
    }

    #[test]
    fn handoff_ack_changes_attachment_downstream_only_for_owned_queue_rows() {
        let c = Connection::open_in_memory().unwrap();
        init_db(&c).unwrap();
        let attachment = crate::client::wire::AttachmentRef {
            name: "file".into(),
            size: 1,
            media_type: "application/octet-stream".into(),
            sha256: "a".repeat(64),
        };
        crate::attachments::insert_rows(&c, "message", &[attachment], 200, "origin", "").unwrap();
        c.execute("INSERT INTO instance_queue (id,instance_id,body,from_name,created_at,expires_at) VALUES ('message','instance','body','sender',100,200)", []).unwrap();
        drop_handed_over(&c, "wrong-instance", &["message".into()], "wrong-peer", 101).unwrap();
        assert_eq!(
            crate::attachments::get_row(&c, "message", 0)
                .unwrap()
                .unwrap()
                .downstream,
            ""
        );
        drop_handed_over(&c, "instance", &["message".into()], "recipient", 101).unwrap();
        assert_eq!(
            crate::attachments::get_row(&c, "message", 0)
                .unwrap()
                .unwrap()
                .downstream,
            "recipient"
        );
        drop_handed_over(&c, "instance", &["message".into()], "another-peer", 101).unwrap();
        assert_eq!(
            crate::attachments::get_row(&c, "message", 0)
                .unwrap()
                .unwrap()
                .downstream,
            "recipient"
        );
    }

    #[test]
    fn utc_rfc3339_known_instants() {
        assert_eq!(utc_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_rfc3339(1_791_801_000), "2026-10-12T10:30:00Z");
    }
}
