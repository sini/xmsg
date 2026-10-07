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

pub fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            session_id TEXT NOT NULL,
            from_name TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            outcome TEXT NOT NULL,
            recipient_harness TEXT NOT NULL DEFAULT 'claude'
        );

        CREATE TABLE IF NOT EXISTS replies (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL REFERENCES messages(id),
            created_at INTEGER NOT NULL,
            replier_session_id TEXT NOT NULL,
            text TEXT NOT NULL
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

        CREATE INDEX IF NOT EXISTS idx_replies_message_seq ON replies(message_id, seq);
        CREATE INDEX IF NOT EXISTS idx_replies_created_at ON replies(created_at);
        CREATE INDEX IF NOT EXISTS idx_pi_pending_session ON pi_pending_messages(session_id, delivered_at);
        CREATE INDEX IF NOT EXISTS idx_pi_pending_created_at ON pi_pending_messages(created_at);
        "#,
    )?;

    // Migration check: ensure recipient_harness column exists on existing messages tables
    let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
    let mut rows = stmt.query([])?;
    let mut has_recipient_harness = false;
    let mut has_columns = false;
    while let Some(row) = rows.next()? {
        has_columns = true;
        let col_name: String = row.get(1)?;
        if col_name == "recipient_harness" {
            has_recipient_harness = true;
            break;
        }
    }
    if has_columns && !has_recipient_harness {
        conn.execute(
            "ALTER TABLE messages ADD COLUMN recipient_harness TEXT NOT NULL DEFAULT 'claude'",
            [],
        )?;
    }

    Ok(())
}

pub fn insert_message(conn: &Connection, msg: &MessageRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO messages (id, created_at, session_id, from_name, bytes, outcome, recipient_harness) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            msg.id,
            msg.created_at,
            msg.session_id,
            msg.from_name,
            msg.bytes as i64,
            msg.outcome,
            msg.recipient_harness,
        ],
    )?;
    Ok(())
}

pub fn get_message(conn: &Connection, id: &str) -> Result<Option<MessageRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, created_at, session_id, from_name, bytes, outcome, recipient_harness FROM messages WHERE id = ?1",
    )?;
    let mut rows = stmt.query(params![id])?;

    if let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(4)?;
        Ok(Some(MessageRecord {
            id: row.get(0)?,
            created_at: row.get(1)?,
            session_id: row.get(2)?,
            from_name: row.get(3)?,
            bytes: bytes_i64 as usize,
            outcome: row.get(5)?,
            recipient_harness: row.get(6)?,
        }))
    } else {
        Ok(None)
    }
}

pub fn insert_reply(
    conn: &Connection,
    message_id: &str,
    replier_session_id: &str,
    text: &str,
) -> Result<ReplyRecord> {
    let created_at = now_epoch_secs();
    conn.execute(
        "INSERT INTO replies (message_id, created_at, replier_session_id, text) VALUES (?1, ?2, ?3, ?4)",
        params![message_id, created_at, replier_session_id, text],
    )?;
    let seq = conn.last_insert_rowid();

    Ok(ReplyRecord {
        seq,
        message_id: message_id.to_string(),
        created_at,
        replier_session_id: replier_session_id.to_string(),
        text: text.to_string(),
    })
}

pub fn get_replies_after(
    conn: &Connection,
    message_id: &str,
    after_seq: i64,
) -> Result<Vec<ReplyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT seq, message_id, created_at, replier_session_id, text FROM replies WHERE message_id = ?1 AND seq > ?2 ORDER BY seq ASC",
    )?;
    let rows = stmt.query_map(params![message_id, after_seq], |row| {
        Ok(ReplyRecord {
            seq: row.get(0)?,
            message_id: row.get(1)?,
            created_at: row.get(2)?,
            replier_session_id: row.get(3)?,
            text: row.get(4)?,
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

pub fn ack_pi_message(conn: &Connection, session_id: &str, message_id: &str) -> Result<bool> {
    let now = now_epoch_secs();
    let count = conn.execute(
        "UPDATE pi_pending_messages SET delivered_at = ?1 WHERE id = ?2 AND session_id = ?3 AND delivered_at IS NULL",
        params![now, message_id, session_id],
    )?;
    Ok(count > 0)
}

pub fn purge_pi_messages(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let cutoff = now_epoch_secs() - (ttl_secs as i64);
    conn.execute(
        "DELETE FROM pi_pending_messages WHERE created_at < ?1",
        params![cutoff],
    )
}
