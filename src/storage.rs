use rusqlite::{params, Connection, Result};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReplyRecord {
    pub seq: i64,
    pub message_id: String,
    pub created_at: i64,
    pub replier_session_id: String,
    pub text: String,
    #[serde(default)]
    pub push_outcome: Option<String>,
    #[serde(default)]
    pub pushed_message_id: Option<String>,
}

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

/// Where a message came from, one shape for every sender (A12): an instance's `id` or a
/// service's name, the `node` that attests it, and the sender's own `label`. An anonymous
/// sender has neither `id` nor `service`; its `label` is its unattested `from`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Origin {
    pub fn instance(id: &str, node: &str, label: Option<&str>) -> Origin {
        Origin {
            id: Some(id.to_string()),
            service: None,
            node: node.to_string(),
            label: label.map(str::to_string),
        }
    }

    pub fn service(name: &str, node: &str) -> Origin {
        Origin {
            id: None,
            service: Some(name.to_string()),
            node: node.to_string(),
            label: None,
        }
    }

    pub fn anonymous(from: &str, node: &str) -> Origin {
        Origin {
            id: None,
            service: None,
            node: node.to_string(),
            label: Some(from.to_string()),
        }
    }

    /// A12's one render, with `node` shown as `shown_node` (a reader's nickname for it):
    /// `name@node` for a service, `label · id@node` for an instance, and
    /// `<from> · anon@node` for an anonymous sender.
    pub fn render(&self, shown_node: &str) -> String {
        match (&self.service, &self.id) {
            (Some(name), _) => crate::inbox::sender_label(shown_node, "svc", name, None),
            (None, Some(id)) => {
                crate::inbox::sender_label(shown_node, "", id, self.label.as_deref())
            }
            (None, None) => {
                let from = self
                    .label
                    .as_deref()
                    .and_then(crate::inbox::clean_label)
                    .unwrap_or_default();
                format!("{from} · anon@{shown_node}")
            }
        }
    }

    /// The sender's attested key: its instance ID or service name, `None` when anonymous.
    pub fn key(&self) -> Option<&str> {
        self.service.as_deref().or(self.id.as_deref())
    }

    /// The literal machine address `id@node` or `service@node`, built only from the
    /// attested identifier and node, never from the label (XU1 Gate 2).
    pub fn machine_ref(&self) -> Option<String> {
        self.key().map(|k| format!("{k}@{}", self.node))
    }
}

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
];

const SCHEMA_N: &str = r#"
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
            last_live INTEGER NOT NULL
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
    matches!(outcome, "delivered" | "queued" | "accepted")
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
        "INSERT INTO outbound (id, peer, target_ref, outcome, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
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

pub fn count_pending_svc_messages(conn: &Connection, session_id: &str) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM svc_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL",
    )?;
    let count: i64 = stmt.query_row(params![session_id], |row| row.get(0))?;
    Ok(count as usize)
}

pub fn insert_svc_message(conn: &Connection, msg: &SvcPendingMessage) -> Result<bool> {
    let pending = count_pending_svc_messages(conn, &msg.session_id)?;
    if pending >= MAX_SVC_QUEUE_PER_SESSION {
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

pub fn get_next_pending_svc_message(
    conn: &Connection,
    session_id: &str,
) -> Result<Option<SvcPendingMessage>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, created_at, from_name, bytes, text, envelope, delivered_at, origin, in_reply_to FROM svc_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL ORDER BY created_at ASC, rowid ASC LIMIT 1",
    )?;
    let mut rows = stmt.query(params![session_id])?;

    if let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(4)?;
        let origin = origin_from_sql(row.get(8)?)?;
        Ok(Some(SvcPendingMessage {
            id: row.get(0)?,
            session_id: row.get(1)?,
            created_at: row.get(2)?,
            from_name: row.get(3)?,
            bytes: bytes_i64 as usize,
            text: row.get(5)?,
            envelope: row.get(6)?,
            delivered_at: row.get(7)?,
            origin,
            in_reply_to: row.get(9)?,
        }))
    } else {
        Ok(None)
    }
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
        "SELECT principal, key, body, message_id, session_id, from_name, bytes, outcome, created_at, to_ref
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
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(ttl_secs as i64);
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "DELETE FROM idempotency_keys WHERE principal = ?1 AND key = ?2 AND created_at < ?3",
        params![principal, key, cutoff],
    )?;
    let inserted = tx.execute(
        "INSERT INTO idempotency_keys
         (principal, key, body, message_id, session_id, from_name, bytes, outcome, created_at, to_ref)
         VALUES (?1, ?2, ?3, ?4, '', ?5, ?6, ?7, ?8, ?9)
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
            to
        ],
    )?;
    let taken_over = inserted == 0
        && tx.execute(
            "UPDATE idempotency_keys SET outcome = ?4, created_at = ?5
             WHERE principal = ?1 AND key = ?2 AND body = ?3 AND outcome = ?6 AND to_ref = ?7",
            params![principal, key, body, KEY_PENDING, now, KEY_FAILED, to],
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyKeyRecord {
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
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(ttl_secs as i64);
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "DELETE FROM reply_idempotency_keys WHERE principal = ?1 AND key = ?2 AND created_at < ?3",
        params![principal, key, cutoff],
    )?;
    let inserted = tx.execute(
        "INSERT INTO reply_idempotency_keys
         (principal, key, in_reply_to, body, reply_id, state, seq, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)
         ON CONFLICT (principal, key) DO NOTHING",
        params![
            principal,
            key,
            in_reply_to,
            body,
            fresh_id,
            KEY_PENDING,
            now
        ],
    )?;
    let taken_over = inserted == 0
        && tx.execute(
            "UPDATE reply_idempotency_keys SET state = ?5, created_at = ?6
             WHERE principal = ?1 AND key = ?2 AND in_reply_to = ?3 AND body = ?4 AND state = ?7",
            params![
                principal,
                key,
                in_reply_to,
                body,
                KEY_PENDING,
                now,
                KEY_FAILED
            ],
        )? == 1;
    let record = tx.query_row(
        "SELECT in_reply_to, body, reply_id, state, seq, created_at
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

pub fn insert_peer_mailbox(conn: &Connection, msg: &PeerMailboxMessage) -> Result<bool> {
    let origin_json = serde_json::to_string(&msg.origin)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    conn.execute(
        "INSERT INTO peer_mailbox (id, peer, target_ref, created_at, from_name, bytes, body, envelope, origin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        ],
    )?;
    Ok(true)
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
    let cutoff = now.saturating_sub(ttl_secs as i64);
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
/// A14's queue and D-1's lifetime read.
pub fn mark_live(conn: &Connection, id: &str, harness: &str, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO instance_seen (id, harness, last_live) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET harness = excluded.harness, last_live = MAX(last_live, excluded.last_live)",
        params![id, harness, now],
    )?;
    Ok(())
}

/// An instance observed before: its harness, when it was last live, and whether it has an
/// unexpired queued message at `now`: in A14's queue, or in agy's queue within `ttl_secs`
/// of its send (D-1: a parked listing lasts as long as its queue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenInstance {
    pub harness: String,
    pub last_live: i64,
    pub queued: bool,
}

pub fn seen_instance(
    conn: &Connection,
    id: &str,
    now: i64,
    ttl_secs: i64,
) -> Result<Option<SeenInstance>> {
    let row = conn.query_row(
        "SELECT harness, last_live FROM instance_seen WHERE id = ?1",
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
    );
    let (harness, last_live) = match row {
        Ok(r) => r,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e),
    };
    let queued: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM instance_queue WHERE instance_id = ?1 AND delivered_at IS NULL AND expires_at > ?2) + (SELECT COUNT(*) FROM agy_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL AND created_at >= ?2 - ?3)",
        params![id, now, ttl_secs],
        |r| r.get(0),
    )?;
    Ok(Some(SeenInstance {
        harness,
        last_live,
        queued: queued > 0,
    }))
}

/// The instances that may be parked here at `now` (A14, D-1): observed before, not a pi
/// or a plugin session (AM-9: both are bound to their process or registration), and
/// within their parked lifetime: `ttl_secs` after last live, or as long as their queue.
/// The caller leaves out the ones live now.
pub fn parked_instances(conn: &Connection, now: i64, ttl_secs: i64) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT id, harness, last_live FROM instance_seen s WHERE harness != 'pi' AND (last_live + ?2 > ?1 \
         OR EXISTS (SELECT 1 FROM instance_queue q WHERE q.instance_id = s.id AND q.delivered_at IS NULL AND q.expires_at > ?1) \
         OR EXISTS (SELECT 1 FROM agy_pending_messages a WHERE a.session_id = s.id AND a.delivered_at IS NULL AND a.created_at >= ?1 - ?2)) \
         ORDER BY id",
    )?;
    let rows = stmt
        .query_map(params![now, ttl_secs], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .filter(|(_, harness, _)| crate::plugin::harness(harness).is_none())
        .map(|(id, _, last_live)| (id, last_live))
        .collect())
}

/// Prunes `instance_seen` rows whose `last_live` is older than `ttl_secs` (the longest
/// `within` window accepted) and which hold no unexpired queued messages.
pub fn purge_instance_seen(conn: &Connection, now: i64, ttl_secs: i64) -> Result<usize> {
    conn.execute(
        "DELETE FROM instance_seen WHERE last_live + ?2 <= ?1 \
         AND NOT EXISTS (SELECT 1 FROM instance_queue q WHERE q.instance_id = instance_seen.id AND q.delivered_at IS NULL AND q.expires_at > ?1) \
         AND NOT EXISTS (SELECT 1 FROM agy_pending_messages a WHERE a.session_id = instance_seen.id AND a.delivered_at IS NULL AND a.created_at >= ?1 - ?2)",
        params![now, ttl_secs],
    )
}

/// An inactive instance in `instance_seen` within `within_secs` of `now` (XL1): its ID,
/// its status (`parked` for a Claude or agy instance within its parked lifetime, `closed`
/// for a pi or plugin session), and when it was last seen live. The caller leaves out the
/// ones live now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InactiveInstance {
    pub id: String,
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
          OR EXISTS (SELECT 1 FROM agy_pending_messages a WHERE a.session_id = s.id AND a.delivered_at IS NULL AND a.created_at >= ?1 - ?2)) \
         FROM instance_seen s WHERE last_live >= ?3 ORDER BY id",
    )?;
    let rows = stmt
        .query_map(params![now, ttl_secs, cutoff], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, bool>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, harness, last_seen, within_parked_ttl)| {
            let is_ephemeral = harness == "pi" || crate::plugin::harness(&harness).is_some();
            if is_ephemeral {
                Some(InactiveInstance {
                    id,
                    status: "closed".to_string(),
                    last_seen,
                })
            } else if within_parked_ttl {
                Some(InactiveInstance {
                    id,
                    status: "parked".to_string(),
                    last_seen,
                })
            } else {
                None
            }
        })
        .collect())
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
    fn utc_rfc3339_known_instants() {
        assert_eq!(utc_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_rfc3339(1_791_801_000), "2026-10-12T10:30:00Z");
    }
}
