//! Plugin registrations on `register.sock` (HA2, HA4, A18, A19; plan XH2): one connection
//! per plugin process, many sessions on it, each with a server-minted address.
//!
//! The connection opens with `{"harness":"opencode"}` (or `"hermes"`), answered
//! `{"status":"ok","node":N}`. Every later frame carries a `request_id`, and its answer
//! carries it back, so an answer
//! to a tool frame and a delivery to the pending `poll` are told apart on the one
//! connection. Tool frames are answered while a `poll` is pending.
//!
//! - `register {session, reclaim?}` → `{address, reclaim}`; `detach {session}`;
//!   `release {session}`; `continues {from, to}` → `{address}`, `from`'s address moved to `to`.
//! - `list`, `send`, `reply`, `replies`: `agent.sock`'s frames field for field, plus the
//!   `session` they act as. A frame naming a session this connection does not hold is
//!   refused `denied`.
//! - `poll {wait?}` → a `deliver` naming its session and address, or `timeout`; one `poll`
//!   is pending per connection, and a second is refused `conflict`. `ack {session,
//!   message_id}` after the harness accepted it.
//!
//! A detached session (via `detach` or a closed connection) stays parked and reclaimable
//! inside the `reply_ttl` window so messages queue for it (HA8). A permanently released
//! session (`release`) clears `reclaim_hash`, answers `gone`, and is `closed` in inactive
//! `list`. A plugin process maps to no address, so a caller whose ancestry reaches it is
//! anonymous (A15, harness gate v0 C2).
//!
//! The registrations live in temporary tables of the server's one database connection, so
//! they end with the server; a plugin session's queue is `pi_pending_messages`, keyed by
//! its address.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

use crate::error::AppError;
use crate::http::AppState;
use crate::registry::Session;
use crate::storage::{self, now_epoch_secs};
use crate::surface;

/// The harnesses that register by plugin.
pub const HARNESSES: &[&str] = &["opencode", "hermes"];

/// `name` as a plugin harness, if it is one.
pub fn harness(name: &str) -> Option<&'static str> {
    HARNESSES.iter().copied().find(|h| *h == name)
}

/// The tables, created with the server's database connection and gone with it.
pub const SCHEMA: &str = r#"
        CREATE TEMP TABLE IF NOT EXISTS plugin_procs (
            conn TEXT PRIMARY KEY,
            pid INTEGER NOT NULL,
            starttime TEXT NOT NULL
        );
        CREATE TEMP TABLE IF NOT EXISTS plugin_sessions (
            address TEXT PRIMARY KEY,
            conn TEXT NOT NULL,
            harness TEXT NOT NULL,
            session TEXT NOT NULL,
            registered_at INTEGER NOT NULL,
            pid INTEGER NOT NULL,
            UNIQUE (conn, session)
        );
        "#;

/// A connection's opening frame. `harness` is the multiplexer's tag.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginHello {
    pub harness: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Frame {
    Register {
        request_id: String,
        session: String,
        #[serde(default)]
        reclaim: Option<storage::ReclaimToken>,
    },
    Detach {
        request_id: String,
        session: String,
    },
    Release {
        request_id: String,
        session: String,
    },
    Continues {
        request_id: String,
        from: String,
        to: String,
    },
    Poll {
        request_id: String,
        #[serde(default)]
        wait: Option<u64>,
    },
    Ack {
        request_id: String,
        session: String,
        message_id: String,
    },
    List {
        request_id: String,
        session: String,
        #[serde(default)]
        as_agent: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        node: Option<String>,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        within: Option<u64>,
    },
    Send {
        request_id: String,
        session: String,
        #[serde(default)]
        as_agent: Option<String>,
        to: String,
        text: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Reply {
        request_id: String,
        session: String,
        #[serde(default)]
        as_agent: Option<String>,
        message_id: String,
        text: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Replies {
        request_id: String,
        session: String,
        #[serde(default)]
        as_agent: Option<String>,
        message_id: String,
        #[serde(default)]
        wait: Option<u64>,
        #[serde(default)]
        after: Option<i64>,
    },
    Inbox {
        request_id: String,
        session: String,
        #[serde(default)]
        as_agent: Option<String>,
        #[serde(default)]
        wait: Option<u64>,
    },
    Subagent {
        request_id: String,
        event: String,
        #[serde(default)]
        session: Option<String>,
        agent_id: String,
        #[serde(default)]
        agent_type: Option<String>,
    },
}

fn db_err(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

const COLUMNS: &str = "address, harness, session, registered_at, pid";

fn row_session(r: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    let registered_at: i64 = r.get(3)?;
    Ok(Session {
        session_id: r.get(0)?,
        name: Some(r.get(2)?),
        pid: r.get(4)?,
        cwd: "/".to_string(),
        status: "idle".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: registered_at.max(0) as u64,
        updated_at: registered_at.max(0) as u64,
        harness: r.get(1)?,
        registered: Some(true),
    })
}

/// Every registered plugin session: its address is `session_id`, its native session ID
/// the label.
pub fn sessions(conn: &Connection) -> rusqlite::Result<Vec<Session>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM plugin_sessions ORDER BY registered_at, rowid"
    ))?;
    let rows = stmt.query_map([], row_session)?;
    rows.collect()
}

/// The plugin session at `address`.
pub fn session(conn: &Connection, address: &str) -> rusqlite::Result<Option<Session>> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM plugin_sessions WHERE address = ?1"),
        params![address],
        row_session,
    )
    .optional()
}

/// The session `label` held on connection `conn_id`.
fn held(conn: &Connection, conn_id: &str, label: &str) -> rusqlite::Result<Option<Session>> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM plugin_sessions WHERE conn = ?1 AND session = ?2"),
        params![conn_id, label],
        row_session,
    )
    .optional()
}

/// All session addresses held on connection `conn_id`.
fn held_addresses(conn: &Connection, conn_id: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT address FROM plugin_sessions WHERE conn = ?1 ORDER BY registered_at, rowid",
    )?;
    let rows = stmt.query_map(params![conn_id], |r| r.get(0))?;
    rows.collect()
}

/// Whether `pid` (started at `starttime`) holds a plugin connection.
pub fn is_plugin_process(conn: &Connection, pid: u32, starttime: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM plugin_procs WHERE pid = ?1 AND starttime = ?2",
        params![pid, starttime],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
}

/// Detaches `address` from live `plugin_sessions` while keeping `reclaim_hash` intact
/// so the session remains parked and reclaimable inside the `reply_ttl` window (HA8).
fn detach(conn: &Connection, address: &str, harness: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM plugin_sessions WHERE address = ?1",
        params![address],
    )?;
    storage::mark_live(conn, address, harness, now_epoch_secs())
}

/// Permanently releases `address`: clears `reclaim_hash` so it answers `gone` from now on
/// and shows as `closed` in inactive `list` (HA8 §3.1), and deletes its `subagents` rows
/// in the same batch (HA9-A.oc §2.5).
fn release(conn: &Connection, address: &str, harness: &str) -> rusqlite::Result<()> {
    detach(conn, address, harness)?;
    storage::subagent_delete_for_parent(conn, address)?;
    storage::clear_reclaim_hash(conn, address, now_epoch_secs())
}

/// Ends a connection however it ends: every address on it is detached (stays reclaimable).
struct Closing(Arc<Mutex<Connection>>, String);

impl Drop for Closing {
    fn drop(&mut self) {
        let Ok(conn) = self.0.lock() else {
            return;
        };
        let held: Vec<(String, String)> = conn
            .prepare("SELECT address, harness FROM plugin_sessions WHERE conn = ?1")
            .and_then(|mut s| {
                s.query_map(params![self.1], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect()
            })
            .unwrap_or_default();
        for (address, harness) in held {
            if let Err(e) = detach(&conn, &address, &harness) {
                tracing::warn!("detaching plugin address {address}: {e}");
            }
        }
        let _ = conn.execute("DELETE FROM plugin_procs WHERE conn = ?1", params![self.1]);
    }
}

fn with_id(mut v: Value, request_id: Option<&str>) -> Value {
    if let (Some(o), Some(id)) = (v.as_object_mut(), request_id) {
        o.insert("request_id".to_string(), Value::String(id.to_string()));
    }
    v
}

fn answer(res: Result<Value, AppError>, request_id: &str) -> Value {
    with_id(res.unwrap_or_else(|e| e.frame()), Some(request_id))
}

fn not_held(session: &str) -> AppError {
    AppError::NotRecipient(format!(
        "session '{session}' is not registered on this connection"
    ))
}

/// The next message pending for a session `conn_id` holds, as a `deliver` frame. The
/// sessions take turns, starting after `last`, the session served last on this connection:
/// a head that is never acked (its injection refused) is offered again only after every
/// other session's head, so it cannot starve them.
fn next_delivery(
    conn: &Connection,
    conn_id: &str,
    node: &str,
    last: &Mutex<Option<String>>,
) -> rusqlite::Result<Option<Value>> {
    let mut stmt = conn.prepare(
        "SELECT address, session FROM plugin_sessions WHERE conn = ?1 ORDER BY registered_at, rowid",
    )?;
    let mut held: Vec<(String, String)> = stmt
        .query_map(params![conn_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = last
        .as_ref()
        .and_then(|l| held.iter().position(|(a, _)| a == l))
    {
        held.rotate_left(i + 1);
    }
    for (address, session) in held {
        if let Some(msg) = storage::get_next_pending_pi_message(conn, &address)? {
            *last = Some(address.clone());
            return Ok(Some(json!({
                "action": "deliver",
                "session": session,
                "address": format!("{address}@{node}"),
                "message_id": msg.id,
                "from_name": msg.from_name,
                "text": msg.text,
                "envelope": msg.envelope,
            })));
        }
    }
    Ok(None)
}

async fn poll(
    state: &AppState,
    conn_id: &str,
    wait: u64,
    last: &Mutex<Option<String>>,
) -> Result<Value, AppError> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(wait.min(surface::MAX_WAIT_SECS));
    // Subscribed before the first read, so no delivery between the two is missed.
    let mut rx = state.pi_notify_tx.subscribe();
    loop {
        if let Some(frame) = next_delivery(
            &*state.db.lock().map_err(db_err)?,
            conn_id,
            &state.node_name,
            last,
        )
        .map_err(db_err)?
        {
            return Ok(frame);
        }
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Err(_) => return Ok(json!({ "action": "timeout" })),
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return Ok(json!({ "action": "timeout" }))
            }
            Ok(_) => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_plugin_connection<R, W>(
    reader: R,
    writer: W,
    state: Arc<AppState>,
    harness: &'static str,
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
) -> Result<(), AppError>
where
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let peer = crate::process::PeerCred::unpinned(peer_uid, peer_pid);
    handle_plugin_connection_peer(reader, writer, state, harness, my_uid, peer).await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_plugin_connection_peer<R, W>(
    mut reader: R,
    mut writer: W,
    state: Arc<AppState>,
    harness: &'static str,
    my_uid: u32,
    peer: crate::process::PeerCred,
) -> Result<(), AppError>
where
    R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let peer_pid = peer.pid.unwrap_or(0);
    let starttime =
        match crate::pi::verify_pi_process_peer(&state.agy_config.proc_root, my_uid, &peer) {
            Ok(st) => st,
            Err(e) => {
                let _ = writer
                    .write_all(format!("{}\n", e.frame()).as_bytes())
                    .await;
                return Err(e);
            }
        };
    let conn_id = crate::claim::mint_uuid_v4();
    state
        .db
        .lock()
        .map_err(db_err)?
        .execute(
            "INSERT INTO plugin_procs (conn, pid, starttime) VALUES (?1, ?2, ?3)",
            params![conn_id, peer_pid, starttime],
        )
        .map_err(db_err)?;
    let _closing = Closing(state.db.clone(), conn_id.clone());

    // One writer: answers and deliveries are written whole, in the order they are ready.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let writer_task = tokio::spawn(async move {
        while let Some(v) = rx.recv().await {
            if writer.write_all(format!("{v}\n").as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let _ = tx.send(json!({ "status": "ok", "node": state.node_name }));

    let mut tasks = tokio::task::JoinSet::new();
    // At most one pending `poll` per connection, so a message is delivered to one of them.
    let polling = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The session whose message this connection was served last (`next_delivery`).
    let last_served = Arc::new(Mutex::new(None));
    let mut buf = Vec::new();
    let max_frame = state.max_body * 6 + 4096;
    loop {
        while tasks.try_join_next().is_some() {}
        buf.clear();
        let n = match (&mut reader)
            .take((max_frame + 1) as u64)
            .read_until(b'\n', &mut buf)
            .await
        {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 || !buf.ends_with(b"\n") {
            if buf.len() > max_frame {
                let _ = tx.send(
                    AppError::BadRequest("frame exceeds maximum allowed size".into()).frame(),
                );
            }
            break;
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            let _ = tx.send(AppError::BadRequest("invalid utf-8".into()).frame());
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let frame: Frame = match surface::parse_frame(line) {
            Ok(f) => f,
            Err(e) => {
                let rid = serde_json::from_str::<Value>(line).ok().and_then(|v| {
                    v.get("request_id")
                        .and_then(|r| r.as_str())
                        .map(str::to_string)
                });
                let _ = tx.send(with_id(e.frame(), rid.as_deref()));
                continue;
            }
        };

        // Registration frames are answered in order; tool frames and `poll` run
        // concurrently, each answered with its request id when it is done.
        let db = &state.db;
        let node = state.node_name.as_str();
        let address_of = |id: &str| format!("{id}@{node}");
        match frame {
            Frame::Register {
                request_id,
                session,
                reclaim,
            } => {
                let res = (|| {
                    if session.trim().is_empty() {
                        return Err(AppError::BadRequest("'session' must not be empty".into()));
                    }
                    let c = db.lock().map_err(db_err)?;
                    if held(&c, &conn_id, &session).map_err(db_err)?.is_some() {
                        return Err(AppError::Conflict(format!(
                            "session '{session}' is already registered on this connection"
                        )));
                    }
                    let now = now_epoch_secs();
                    let (address, secret) = if let Some(r) = reclaim {
                        storage::reclaim_instance(
                            &c,
                            &r.id,
                            node,
                            harness,
                            &r.secret,
                            now,
                            state.reply_ttl.as_secs() as i64,
                            |conn, id| {
                                Ok(crate::plugin::session(conn, id).map_err(db_err)?.is_some())
                            },
                        )?
                    } else {
                        let id = crate::claim::mint_uuid_v4();
                        let sec = storage::mint_reclaimable_instance(&c, &id, harness, now)
                            .map_err(db_err)?;
                        (id, sec)
                    };
                    c.execute(
                        "INSERT INTO plugin_sessions (address, conn, harness, session, registered_at, pid) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![address, conn_id, harness, session, now, peer_pid],
                    )
                    .map_err(db_err)?;
                    // HA9-A.oc §2.2, C7: a register of P (fresh or reclaimed) clears the turn
                    // columns of every subagent row under P in the same batch.
                    storage::subagent_clear_turns_for_parent(&c, &address).map_err(db_err)?;
                    let _ = crate::claim::take_queued_for(&c, &state.agy_config.proc_root, &[]);
                    let _ = state.pi_notify_tx.send(address.clone());
                    Ok(json!({
                        "status": "ok",
                        "address": address_of(&address),
                        "reclaim": secret,
                    }))
                })();
                let _ = tx.send(answer(res, &request_id));
            }
            Frame::Detach {
                request_id,
                session,
            } => {
                let res = (|| {
                    let c = db.lock().map_err(db_err)?;
                    let s = held(&c, &conn_id, &session)
                        .map_err(db_err)?
                        .ok_or_else(|| not_held(&session))?;
                    detach(&c, &s.session_id, harness).map_err(db_err)?;
                    Ok(json!({ "status": "ok" }))
                })();
                let _ = tx.send(answer(res, &request_id));
            }
            Frame::Release {
                request_id,
                session,
            } => {
                let res = (|| {
                    let c = db.lock().map_err(db_err)?;
                    let s = held(&c, &conn_id, &session)
                        .map_err(db_err)?
                        .ok_or_else(|| not_held(&session))?;
                    release(&c, &s.session_id, harness).map_err(db_err)?;
                    Ok(json!({ "status": "ok" }))
                })();
                let _ = tx.send(answer(res, &request_id));
            }
            Frame::Continues {
                request_id,
                from,
                to,
            } => {
                let res = (|| {
                    let c = db.lock().map_err(db_err)?;
                    let s = held(&c, &conn_id, &from)
                        .map_err(db_err)?
                        .ok_or_else(|| not_held(&from))?;
                    if held(&c, &conn_id, &to).map_err(db_err)?.is_some() {
                        return Err(AppError::Conflict(format!(
                            "session '{to}' is already registered on this connection"
                        )));
                    }
                    // A19: the address moves; `to` is now its label.
                    c.execute(
                        "UPDATE plugin_sessions SET session = ?1 WHERE address = ?2",
                        params![to, s.session_id],
                    )
                    .map_err(db_err)?;
                    Ok(json!({ "status": "ok", "address": address_of(&s.session_id) }))
                })();
                let _ = tx.send(answer(res, &request_id));
            }
            Frame::Ack {
                request_id,
                session,
                message_id,
            } => {
                let res = (|| {
                    let c = db.lock().map_err(db_err)?;
                    let s = held(&c, &conn_id, &session)
                        .map_err(db_err)?
                        .ok_or_else(|| not_held(&session))?;
                    if storage::ack_pi_message(&c, &s.session_id, &message_id).map_err(db_err)? {
                        Ok(json!({ "status": "ok" }))
                    } else {
                        Err(AppError::NotFoundDetail(format!(
                            "no pending message '{message_id}' for session '{session}'"
                        )))
                    }
                })();
                let _ = tx.send(answer(res, &request_id));
            }
            Frame::Poll { request_id, wait } => {
                if polling.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    let e =
                        AppError::Conflict("a poll is already pending on this connection".into());
                    let _ = tx.send(answer(Err(e), &request_id));
                    continue;
                }
                let (state, tx, conn_id, polling, last) = (
                    state.clone(),
                    tx.clone(),
                    conn_id.clone(),
                    polling.clone(),
                    last_served.clone(),
                );
                tasks.spawn(async move {
                    let res = poll(&state, &conn_id, wait.unwrap_or(30), &last).await;
                    // Free before answering, so a poll sent on this answer is accepted.
                    polling.store(false, std::sync::atomic::Ordering::SeqCst);
                    let _ = tx.send(answer(res, &request_id));
                });
            }
            Frame::List {
                request_id,
                session,
                as_agent,
                name,
                node,
                kind,
                status,
                within,
            } => {
                let _ = as_agent;
                let caller =
                    held(&*db.lock().map_err(db_err)?, &conn_id, &session).map_err(db_err)?;
                let Some(_) = caller else {
                    let _ = tx.send(answer(Err(not_held(&session)), &request_id));
                    continue;
                };
                let (state, tx) = (state.clone(), tx.clone());
                tasks.spawn(async move {
                    let query = surface::ListQuery {
                        name,
                        node,
                        kind,
                        status,
                        within,
                        host: None,
                    };
                    let res = surface::list(&state, &query).await.map(
                        |r| json!({ "status": "ok", "recipients": r.recipients, "nodes": r.nodes }),
                    );
                    let _ = tx.send(answer(res, &request_id));
                });
            }
            Frame::Send {
                request_id,
                session,
                as_agent,
                to,
                text,
                idempotency_key,
            } => {
                let caller =
                    held(&*db.lock().map_err(db_err)?, &conn_id, &session).map_err(db_err)?;
                let Some(caller) = caller else {
                    let _ = tx.send(answer(Err(not_held(&session)), &request_id));
                    continue;
                };
                let caller = match crate::agent::resolve_as_agent(
                    &state,
                    caller,
                    as_agent.as_deref(),
                    false,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx.send(answer(Err(e), &request_id));
                        continue;
                    }
                };
                let (state, tx) = (state.clone(), tx.clone());
                tasks.spawn(async move {
                    let sender = surface::Sender::Session(caller);
                    let res =
                        surface::send(&state, &sender, &to, &text, idempotency_key.as_deref())
                            .await
                            .map(|r| {
                                json!({
                                    "status": "ok",
                                    "message_id": r.message_id,
                                    "address": r.address,
                                    "outcome": r.outcome,
                                })
                            });
                    let _ = tx.send(answer(res, &request_id));
                });
            }
            Frame::Reply {
                request_id,
                session,
                as_agent,
                message_id,
                text,
                idempotency_key,
            } => {
                let caller =
                    held(&*db.lock().map_err(db_err)?, &conn_id, &session).map_err(db_err)?;
                let Some(caller) = caller else {
                    let _ = tx.send(answer(Err(not_held(&session)), &request_id));
                    continue;
                };
                let caller = match crate::agent::resolve_as_agent(
                    &state,
                    caller,
                    as_agent.as_deref(),
                    false,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx.send(answer(Err(e), &request_id));
                        continue;
                    }
                };
                let (state, tx) = (state.clone(), tx.clone());
                tasks.spawn(async move {
                    let res = surface::reply(
                        &state,
                        &caller,
                        &message_id,
                        &text,
                        idempotency_key.as_deref(),
                    )
                    .await
                    .map(|r| json!({ "status": "ok", "reply": r }));
                    let _ = tx.send(answer(res, &request_id));
                });
            }
            Frame::Replies {
                request_id,
                session,
                as_agent,
                message_id,
                wait,
                after,
            } => {
                let _ = as_agent;
                let caller =
                    held(&*db.lock().map_err(db_err)?, &conn_id, &session).map_err(db_err)?;
                let Some(_) = caller else {
                    let _ = tx.send(answer(Err(not_held(&session)), &request_id));
                    continue;
                };
                let (state, tx) = (state.clone(), tx.clone());
                tasks.spawn(async move {
                    let res = surface::replies(
                        &state,
                        &message_id,
                        after.unwrap_or(0),
                        wait.unwrap_or(0),
                    )
                    .await
                    .map(|r| json!({ "status": "ok", "replies": r }));
                    let _ = tx.send(answer(res, &request_id));
                });
            }
            Frame::Inbox {
                request_id,
                session,
                as_agent,
                wait,
            } => {
                let caller =
                    held(&*db.lock().map_err(db_err)?, &conn_id, &session).map_err(db_err)?;
                let Some(caller) = caller else {
                    let _ = tx.send(answer(Err(not_held(&session)), &request_id));
                    continue;
                };
                let caller =
                    match crate::agent::resolve_as_agent(&state, caller, as_agent.as_deref(), true)
                    {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(answer(Err(e), &request_id));
                            continue;
                        }
                    };
                let (state, tx) = (state.clone(), tx.clone());
                tasks.spawn(async move {
                    let res = surface::inbox(&state, &caller, wait.unwrap_or(0))
                        .await
                        .map(|r| {
                            json!({
                                "status": "ok",
                                "address": r.address,
                                "messages": r.messages,
                            })
                        });
                    let _ = tx.send(answer(res, &request_id));
                });
            }
            Frame::Subagent {
                request_id,
                event,
                session,
                agent_id,
                agent_type,
            } => {
                let res = (|| {
                    if harness != "opencode" {
                        return Err(AppError::BadRequest(
                            "subagent frame on register.sock is only valid for opencode".into(),
                        ));
                    }
                    let agent_id = agent_id.trim();
                    if agent_id.is_empty()
                        || agent_id.contains('/')
                        || agent_id.contains('@')
                        || agent_id.contains(char::is_whitespace)
                    {
                        return Err(AppError::BadRequest(
                            "agent_id must be non-empty and must not contain '/', '@' or whitespace"
                                .into(),
                        ));
                    }
                    let c = db.lock().map_err(db_err)?;
                    match event.as_str() {
                        "start" => {
                            let session = session.as_deref().ok_or_else(|| {
                                AppError::BadRequest("subagent start requires 'session'".into())
                            })?;
                            let parent = held(&c, &conn_id, session)
                                .map_err(db_err)?
                                .ok_or_else(|| not_held(session))?;
                            let now = now_epoch_secs();
                            let effective_type = agent_type
                                .as_deref()
                                .map(str::trim)
                                .filter(|s| !s.is_empty());
                            storage::subagent_start_turn(
                                &c,
                                &parent.session_id,
                                agent_id,
                                peer_pid,
                                &starttime,
                                None,
                                effective_type,
                                None,
                                now,
                            )
                            .map_err(db_err)?;
                            Ok(json!({ "status": "ok" }))
                        }
                        "stop" => {
                            let parents = match session.as_deref() {
                                Some(s) => vec![
                                    held(&c, &conn_id, s)
                                        .map_err(db_err)?
                                        .ok_or_else(|| not_held(s))?
                                        .session_id,
                                ],
                                None => held_addresses(&c, &conn_id).map_err(db_err)?,
                            };
                            for p in &parents {
                                storage::subagent_stop_turn(&c, p, agent_id).map_err(db_err)?;
                            }
                            let _ =
                                crate::claim::take_queued_for(&c, &state.agy_config.proc_root, &[]);
                            for p in &parents {
                                let _ = state.pi_notify_tx.send(p.clone());
                            }
                            Ok(json!({ "status": "ok" }))
                        }
                        "end" => {
                            let parents = match session.as_deref() {
                                Some(s) => vec![
                                    held(&c, &conn_id, s)
                                        .map_err(db_err)?
                                        .ok_or_else(|| not_held(s))?
                                        .session_id,
                                ],
                                None => held_addresses(&c, &conn_id).map_err(db_err)?,
                            };
                            for p in &parents {
                                storage::subagent_stop_turn(&c, p, agent_id).map_err(db_err)?;
                            }
                            let _ =
                                crate::claim::take_queued_for(&c, &state.agy_config.proc_root, &[]);
                            for p in &parents {
                                storage::subagent_delete_row(&c, p, agent_id).map_err(db_err)?;
                                let _ = state.pi_notify_tx.send(p.clone());
                            }
                            Ok(json!({ "status": "ok" }))
                        }
                        other => Err(AppError::BadRequest(format!(
                            "unknown subagent event '{other}'"
                        ))),
                    }
                })();
                let _ = tx.send(answer(res, &request_id));
            }
        }
    }
    tasks.abort_all();
    drop(tx);
    let _ = writer_task.await;
    Ok(())
}
