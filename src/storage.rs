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
    #[serde(default = "default_true")]
    pub push_replies: bool,
    #[serde(default)]
    pub thread_id: String,
    #[serde(default)]
    pub return_host: Option<String>,
}

fn default_recipient_harness() -> String {
    "claude".to_string()
}

fn default_true() -> bool {
    true
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SvcOrigin {
    #[serde(rename = "local", rename_all = "camelCase")]
    Local { harness: String, session_id: String },
    #[serde(rename = "fed", rename_all = "camelCase")]
    Fed {
        host: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<String>,
    },
    #[serde(rename = "anonymous")]
    Anonymous,
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
    pub origin: SvcOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdempotencyRecord {
    pub principal: String,
    pub key: String,
    pub body: String,
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
            recipient_harness TEXT NOT NULL DEFAULT 'claude',
            return_harness TEXT,
            return_session_id TEXT,
            push_replies INTEGER NOT NULL DEFAULT 1,
            thread_id TEXT NOT NULL DEFAULT '',
            return_host TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS outbound (
            id TEXT PRIMARY KEY,
            peer TEXT NOT NULL,
            target_ref TEXT NOT NULL,
            outcome TEXT NOT NULL,
            created_at INTEGER NOT NULL
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
            origin TEXT NOT NULL DEFAULT '{"kind":"anonymous"}'
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
        "#,
    )?;

    // Migration check: ensure recipient_harness and return_address columns exist on existing messages tables
    let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
    let mut rows = stmt.query([])?;
    let mut has_recipient_harness = false;
    let mut has_return_harness = false;
    let mut has_return_session_id = false;
    let mut has_push_replies = false;
    let mut has_thread_id = false;
    let mut has_return_host = false;
    let mut has_columns = false;
    while let Some(row) = rows.next()? {
        has_columns = true;
        let col_name: String = row.get(1)?;
        match col_name.as_str() {
            "recipient_harness" => has_recipient_harness = true,
            "return_harness" => has_return_harness = true,
            "return_session_id" => has_return_session_id = true,
            "push_replies" => has_push_replies = true,
            "thread_id" => has_thread_id = true,
            "return_host" => has_return_host = true,
            _ => {}
        }
    }
    if has_columns {
        if !has_recipient_harness {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN recipient_harness TEXT NOT NULL DEFAULT 'claude'",
                [],
            )?;
        }
        if !has_return_harness {
            conn.execute("ALTER TABLE messages ADD COLUMN return_harness TEXT", [])?;
        }
        if !has_return_session_id {
            conn.execute("ALTER TABLE messages ADD COLUMN return_session_id TEXT", [])?;
        }
        if !has_push_replies {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN push_replies INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        if !has_thread_id {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN thread_id TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        if !has_return_host {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN return_host TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
    }

    // Migration check: ensure push_outcome and pushed_message_id exist on replies table
    let mut stmt = conn.prepare("PRAGMA table_info(replies)")?;
    let mut rows = stmt.query([])?;
    let mut has_push_outcome = false;
    let mut has_pushed_message_id = false;
    let mut has_reply_columns = false;
    while let Some(row) = rows.next()? {
        has_reply_columns = true;
        let col_name: String = row.get(1)?;
        match col_name.as_str() {
            "push_outcome" => has_push_outcome = true,
            "pushed_message_id" => has_pushed_message_id = true,
            _ => {}
        }
    }
    if has_reply_columns {
        if !has_push_outcome {
            conn.execute("ALTER TABLE replies ADD COLUMN push_outcome TEXT", [])?;
        }
        if !has_pushed_message_id {
            conn.execute("ALTER TABLE replies ADD COLUMN pushed_message_id TEXT", [])?;
        }
    }

    // Migration check: ensure origin exists on svc_pending_messages table
    let mut stmt = conn.prepare("PRAGMA table_info(svc_pending_messages)")?;
    let mut rows = stmt.query([])?;
    let mut has_origin = false;
    let mut has_svc_pending_columns = false;
    while let Some(row) = rows.next()? {
        has_svc_pending_columns = true;
        let col_name: String = row.get(1)?;
        if col_name == "origin" {
            has_origin = true;
        }
    }
    if has_svc_pending_columns && !has_origin {
        conn.execute(
            "ALTER TABLE svc_pending_messages ADD COLUMN origin TEXT NOT NULL DEFAULT '{\"kind\":\"anonymous\"}'",
            [],
        )?;
    }

    Ok(())
}

pub fn insert_message(conn: &Connection, msg: &MessageRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO messages (id, created_at, session_id, from_name, bytes, outcome, recipient_harness, return_harness, return_session_id, push_replies, thread_id, return_host) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
            if msg.push_replies { 1i64 } else { 0i64 },
            msg.thread_id,
            msg.return_host.as_deref().unwrap_or(""),
        ],
    )?;
    Ok(())
}

pub fn get_message(conn: &Connection, id: &str) -> Result<Option<MessageRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, created_at, session_id, from_name, bytes, outcome, recipient_harness, return_harness, return_session_id, push_replies, thread_id, return_host FROM messages WHERE id = ?1",
    )?;
    let mut rows = stmt.query(params![id])?;

    if let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(4)?;
        let push_replies_i64: i64 = row.get(9)?;
        let ret_host: String = row.get(11)?;
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
            push_replies: push_replies_i64 != 0,
            thread_id: row.get(10)?,
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
    let mut stmt = conn
        .prepare("SELECT id, peer, target_ref, outcome, created_at FROM outbound WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(OutboundRecord {
            id: row.get(0)?,
            peer: row.get(1)?,
            target_ref: row.get(2)?,
            outcome: row.get(3)?,
            created_at: row.get(4)?,
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

pub fn update_message_outcome(conn: &Connection, id: &str, outcome: &str) -> Result<bool> {
    let count = conn.execute(
        "UPDATE messages SET outcome = ?1 WHERE id = ?2",
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
        .unwrap_or_else(|_| "{\"kind\":\"anonymous\"}".to_string());
    conn.execute(
        "INSERT INTO svc_pending_messages (id, session_id, created_at, from_name, bytes, text, envelope, delivered_at, origin) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        ],
    )?;
    Ok(true)
}

pub fn get_next_pending_svc_message(
    conn: &Connection,
    session_id: &str,
) -> Result<Option<SvcPendingMessage>> {
    let mut stmt = conn.prepare(
        "SELECT id, session_id, created_at, from_name, bytes, text, envelope, delivered_at, origin FROM svc_pending_messages WHERE session_id = ?1 AND delivered_at IS NULL ORDER BY created_at ASC, rowid ASC LIMIT 1",
    )?;
    let mut rows = stmt.query(params![session_id])?;

    if let Some(row) = rows.next()? {
        let bytes_i64: i64 = row.get(4)?;
        let origin_str: String = row.get(8)?;
        let origin: SvcOrigin = serde_json::from_str(&origin_str).unwrap_or(SvcOrigin::Anonymous);
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
        }))
    } else {
        Ok(None)
    }
}

pub fn ack_svc_message(conn: &Connection, session_id: &str, message_id: &str) -> Result<bool> {
    let now = now_epoch_secs();
    let count = conn.execute(
        "UPDATE svc_pending_messages SET delivered_at = ?1 WHERE id = ?2 AND session_id = ?3 AND delivered_at IS NULL",
        params![now, message_id, session_id],
    )?;
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
        "SELECT principal, key, body, message_id, session_id, from_name, bytes, outcome, created_at
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
        }))
    } else {
        Ok(None)
    }
}

pub fn insert_idempotency_record(conn: &Connection, record: &IdempotencyRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO idempotency_keys
         (principal, key, body, message_id, session_id, from_name, bytes, outcome, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            record.principal,
            record.key,
            record.body,
            record.message_id,
            record.session_id,
            record.from_name,
            record.bytes as i64,
            record.outcome,
            record.created_at,
        ],
    )?;
    Ok(())
}

pub fn purge_idempotency_keys(conn: &Connection, ttl_secs: u64) -> Result<usize> {
    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(ttl_secs as i64);
    conn.execute(
        "DELETE FROM idempotency_keys WHERE created_at < ?1",
        params![cutoff],
    )
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
    pub origin: SvcOrigin,
}

pub fn insert_peer_mailbox(conn: &Connection, msg: &PeerMailboxMessage) -> Result<bool> {
    let origin_json = serde_json::to_string(&msg.origin)
        .unwrap_or_else(|_| "{\"kind\":\"anonymous\"}".to_string());
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
        let origin_str: String = row.get(8)?;
        let origin: SvcOrigin = serde_json::from_str(&origin_str).unwrap_or(SvcOrigin::Anonymous);
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
