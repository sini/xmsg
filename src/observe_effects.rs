use crate::observe::{Observation, Observer};
use rusqlite::{Connection, OptionalExtension};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

const MAX_ROWS: usize = 256;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_PROJECTION_BYTES: usize = 4096;

thread_local! {
    static ACTIVE: RefCell<BTreeMap<usize, Vec<Rc<RefCell<Capture>>>>> = const { RefCell::new(BTreeMap::new()) };
}

trait Sink: Send + Sync {
    fn publish(&self, events: Vec<Observation>);
}

impl Sink for Observer {
    fn publish(&self, events: Vec<Observation>) {
        Observer::publish(self, events);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Message {
    id: String,
    created_at: i64,
    recipient: String,
    recipient_harness: String,
    return_session: Option<String>,
    return_host: Option<String>,
    thread: String,
    outcome: String,
    remote_target: Option<String>,
    peer: Option<String>,
    outbound_outcome: Option<String>,
    has_outbound: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Reply {
    seq: i64,
    message_id: String,
    created_at: i64,
    replier: String,
    outcome: Option<String>,
    pushed_id: Option<String>,
    source_session: Option<String>,
    source_host: Option<String>,
    destination_session: Option<String>,
    destination_host: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Transfer {
    id: String,
    message: Option<Message>,
    instance: Option<(String, Option<i64>)>,
    root: Option<(String, Option<i64>)>,
    outbound: Option<(String, String)>,
}

impl Transfer {
    fn owner(&self, node: &str) -> Option<String> {
        self.root
            .as_ref()
            .filter(|(_, delivered)| delivered.is_none())
            .and_then(|(id, _)| endpoint(id, node))
            .or_else(|| {
                self.instance
                    .as_ref()
                    .filter(|(_, delivered)| delivered.is_none())
                    .and_then(|(id, _)| endpoint(id, node))
            })
            .or_else(|| {
                self.outbound
                    .as_ref()
                    .and_then(|(id, peer)| endpoint(id, peer))
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Message(String),
    Reply(i64),
    Transfer(String),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum Projection {
    Message(Message),
    Reply(Reply),
    Transfer(Transfer),
}

#[derive(Clone)]
struct Change {
    before: Option<Projection>,
    after: Option<Projection>,
}

struct Capture {
    sink: Arc<dyn Sink>,
    node: String,
    changes: BTreeMap<Key, Change>,
    bytes: usize,
    overflowed: bool,
    unavailable: bool,
}

impl Capture {
    fn record(&mut self, key: Key, before: Option<Projection>, after: Option<Projection>) {
        if self.overflowed || self.unavailable {
            return;
        }
        if [&before, &after].into_iter().flatten().any(|projection| {
            serde_json::to_vec(projection).map_or(true, |bytes| bytes.len() > MAX_PROJECTION_BYTES)
        }) {
            self.changes.clear();
            self.bytes = 0;
            self.overflowed = true;
            return;
        }
        let size = |change: &Change| {
            [&change.before, &change.after]
                .into_iter()
                .flatten()
                .map(|p| serde_json::to_vec(p).map_or(MAX_BYTES + 1, |v| v.len()))
                .sum::<usize>()
        };
        let old_size = self.changes.get(&key).map_or(0, size);
        let change = self.changes.entry(key).or_insert(Change {
            before,
            after: None,
        });
        change.after = after;
        self.bytes = self
            .bytes
            .saturating_sub(old_size)
            .saturating_add(size(change));
        if self.changes.len() > MAX_ROWS || self.bytes > MAX_BYTES {
            self.changes.clear();
            self.bytes = 0;
            self.overflowed = true;
        }
    }

    fn events(&self) -> Vec<Observation> {
        if self.overflowed || self.unavailable {
            return vec![Observation {
                kind: "gap".into(),
                reason: Some(
                    if self.unavailable {
                        "capture_unavailable"
                    } else {
                        "capture_overflow"
                    }
                    .into(),
                ),
                body_availability: "not_recorded".into(),
                ..Default::default()
            }];
        }
        let mut events = Vec::new();
        for change in self.changes.values() {
            if change.before == change.after {
                continue;
            }
            match (&change.before, &change.after) {
                (before, Some(Projection::Message(after))) => {
                    let before = match before {
                        Some(Projection::Message(before)) => Some(before),
                        _ => None,
                    };
                    if before.is_none() {
                        events.push(after.event(&self.node, "message_recorded"));
                    } else if let Some(before) = before {
                        if before.recipient(&self.node) != after.recipient(&self.node)
                            && after.recipient(&self.node).is_some()
                        {
                            events.push(after.event(&self.node, "recipient_resolved"));
                        }
                        if before.outcome != after.outcome {
                            events.push(after.event(&self.node, "outcome_changed"));
                        }
                        if before.outbound_outcome != after.outbound_outcome {
                            if let Some(outcome) = &after.outbound_outcome {
                                let mut event = after.event(&self.node, "outcome_changed");
                                event.outcome = Some(outcome.clone());
                                event.reason = Some("outbound".into());
                                events.push(event);
                            }
                        }
                    }
                }
                (before, Some(Projection::Reply(after))) => {
                    let before = match before {
                        Some(Projection::Reply(before)) => Some(before),
                        _ => None,
                    };
                    if before.is_none() {
                        events.push(after.event(&self.node, "reply_recorded"));
                    } else if before.is_some_and(|before| before.outcome != after.outcome) {
                        events.push(after.event(&self.node, "reply_push_outcome_changed"));
                    }
                }
                (Some(Projection::Message(before)), None) => {
                    events.push(before.event(&self.node, "record_removed"));
                }
                (Some(Projection::Reply(before)), None) => {
                    events.push(before.event(&self.node, "record_removed"));
                }
                (Some(Projection::Transfer(before)), Some(Projection::Transfer(after))) => {
                    let from = before.owner(&self.node);
                    let to = after.owner(&self.node);
                    if from != to && to.is_some() {
                        let mut event = after
                            .message
                            .as_ref()
                            .map(|m| m.event(&self.node, "record_transferred"))
                            .unwrap_or_else(|| Observation {
                                kind: "record_transferred".into(),
                                message_id: Some(after.id.clone()),
                                body_availability: "not_recorded".into(),
                                ..Default::default()
                            });
                        event.from = from;
                        event.to = to;
                        event.reason = Some("queue_transfer".into());
                        events.push(event);
                    }
                }
                _ => {}
            }
        }
        events
    }
}

fn endpoint(id: &str, node: &str) -> Option<String> {
    if id.is_empty() {
        None
    } else if id.contains('@') {
        Some(id.to_string())
    } else {
        Some(format!("{id}@{node}"))
    }
}

impl Message {
    fn recipient(&self, node: &str) -> Option<String> {
        if self.has_outbound || matches!(self.recipient_harness.as_str(), "fed" | "system") {
            self.remote_target
                .as_deref()
                .and_then(|target| endpoint(target, self.peer.as_deref().unwrap_or(node)))
        } else {
            endpoint(&self.recipient, node)
        }
    }

    fn event(&self, node: &str, kind: &str) -> Observation {
        Observation {
            source_at: Some(self.created_at),
            kind: kind.to_string(),
            from: self.return_session.as_deref().and_then(|id| {
                endpoint(
                    id,
                    self.return_host
                        .as_deref()
                        .filter(|h| !h.is_empty())
                        .unwrap_or(node),
                )
            }),
            to: self.recipient(node),
            message_id: Some(self.id.clone()),
            thread_id: (!self.thread.is_empty()).then(|| self.thread.clone()),
            outcome: Some(self.outcome.clone()),
            body_availability: "not_recorded".into(),
            ..Default::default()
        }
    }
}

impl Reply {
    fn event(&self, node: &str, kind: &str) -> Observation {
        Observation {
            source_at: Some(self.created_at),
            kind: kind.to_string(),
            from: self
                .source_session
                .as_deref()
                .and_then(|id| {
                    endpoint(
                        id,
                        self.source_host
                            .as_deref()
                            .filter(|h| !h.is_empty())
                            .unwrap_or(node),
                    )
                })
                .or_else(|| self.replier.contains('@').then(|| self.replier.clone())),
            to: self.destination_session.as_deref().and_then(|id| {
                endpoint(
                    id,
                    self.destination_host
                        .as_deref()
                        .filter(|h| !h.is_empty())
                        .unwrap_or(node),
                )
            }),
            message_id: Some(self.message_id.clone()),
            reply_id: Some(self.seq),
            thread_id: Some(self.message_id.clone()),
            outcome: self.outcome.clone(),
            body_availability: "retained_at_capture".into(),
            ..Default::default()
        }
    }
}

fn key(conn: &Connection) -> usize {
    conn as *const Connection as usize
}

fn active(conn: &Connection) -> Option<Rc<RefCell<Capture>>> {
    ACTIVE.with(|active| {
        active
            .borrow()
            .get(&key(conn))
            .and_then(|v| v.last())
            .cloned()
    })
}

/// A capture is published only when its owner confirms a successful outer commit.
pub struct Batch {
    key: usize,
    capture: Option<Rc<RefCell<Capture>>>,
}

impl Batch {
    pub fn begin(primary: &Arc<Mutex<Connection>>, conn: &Connection) -> Self {
        match crate::observe::for_db(primary) {
            Some(observer) => Self::with_sink(conn, observer.node().to_owned(), observer.clone()),
            None => Self {
                key: key(conn),
                capture: None,
            },
        }
    }

    pub(crate) fn registered(conn: &Connection) -> Self {
        match crate::observe::for_connection(conn) {
            Some(observer) => Self::with_sink(conn, observer.node().to_owned(), observer.clone()),
            None => Self {
                key: key(conn),
                capture: None,
            },
        }
    }

    fn with_sink(conn: &Connection, node: String, sink: Arc<dyn Sink>) -> Self {
        let capture = Rc::new(RefCell::new(Capture {
            sink,
            node,
            changes: BTreeMap::new(),
            bytes: 0,
            overflowed: false,
            unavailable: false,
        }));
        ACTIVE.with(|active| {
            active
                .borrow_mut()
                .entry(key(conn))
                .or_default()
                .push(capture.clone());
        });
        Self {
            key: key(conn),
            capture: Some(capture),
        }
    }

    pub fn committed(mut self, conn: &Connection) {
        let Some(capture) = self.remove() else { return };
        if self.key != key(conn) {
            return;
        }
        if let Some(parent) = active(conn) {
            let capture = capture.borrow();
            let mut parent = parent.borrow_mut();
            if capture.overflowed {
                parent.changes.clear();
                parent.bytes = 0;
                parent.overflowed = true;
            } else {
                for (key, change) in &capture.changes {
                    parent.record(key.clone(), change.before.clone(), change.after.clone());
                }
            }
            parent.unavailable |= capture.unavailable;
        } else if conn.is_autocommit() {
            let capture = capture.borrow();
            capture.sink.publish(capture.events());
        }
    }

    fn remove(&mut self) -> Option<Rc<RefCell<Capture>>> {
        let capture = self.capture.take()?;
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if let Some(stack) = active.get_mut(&self.key) {
                if let Some(index) = stack.iter().position(|entry| Rc::ptr_eq(entry, &capture)) {
                    stack.remove(index);
                }
                if stack.is_empty() {
                    active.remove(&self.key);
                }
            }
        });
        Some(capture)
    }

    fn refresh(&self, conn: &Connection) {
        if let Some(pending) = &self.capture {
            let mut pending = pending.borrow_mut();
            let mut unavailable = false;
            for (key, change) in &mut pending.changes {
                let actual = match key {
                    Key::Message(id) => read_message(conn, id).map(|m| m.map(Projection::Message)),
                    Key::Reply(seq) => read_reply(conn, *seq).map(|r| r.map(Projection::Reply)),
                    Key::Transfer(id) => {
                        read_transfer(conn, id).map(|t| Some(Projection::Transfer(t)))
                    }
                };
                match actual {
                    Ok(actual) => change.after = actual,
                    Err(_) => {
                        unavailable = true;
                        break;
                    }
                }
            }
            pending.unavailable |= unavailable;
        }
    }

    pub(crate) fn settled(self, conn: &Connection) {
        self.refresh(conn);
        self.committed(conn);
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        self.remove();
    }
}

pub struct Transaction<'a> {
    transaction: rusqlite::Transaction<'a>,
    capture: Batch,
    connection: &'a Connection,
}

impl<'a> std::ops::Deref for Transaction<'a> {
    type Target = rusqlite::Transaction<'a>;
    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl Transaction<'_> {
    pub fn commit(self) -> rusqlite::Result<()> {
        self.capture.refresh(self.connection);
        self.transaction.commit()?;
        self.capture.committed(self.connection);
        Ok(())
    }
}

pub fn transaction<'a>(
    primary: &Arc<Mutex<Connection>>,
    conn: &'a Connection,
) -> rusqlite::Result<Transaction<'a>> {
    let capture = Batch::begin(primary, conn);
    let transaction = conn.unchecked_transaction()?;
    Ok(Transaction {
        transaction,
        capture,
        connection: conn,
    })
}

pub fn autocommit<T, E>(
    primary: &Arc<Mutex<Connection>>,
    conn: &Connection,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let capture = Batch::begin(primary, conn);
    settle_operation(capture, conn, operation)
}

pub fn autocommit_registered<T>(conn: &Connection, operation: impl FnOnce(&Connection) -> T) -> T {
    let capture = Batch::registered(conn);
    settle_operation(capture, conn, || operation(conn))
}

fn settle_operation<T>(capture: Batch, conn: &Connection, operation: impl FnOnce() -> T) -> T {
    let result = operation();
    capture.settled(conn);
    result
}

pub(crate) fn message_before(conn: &Connection, id: &str) -> Option<Option<Message>> {
    let capture = active(conn)?;
    match read_message(conn, id) {
        Ok(message) => Some(message),
        Err(_) => {
            capture.borrow_mut().unavailable = true;
            None
        }
    }
}

fn read_message(conn: &Connection, id: &str) -> rusqlite::Result<Option<Message>> {
    conn.query_row(
        "SELECT m.id,m.created_at,CASE WHEN m.recipient_harness IN ('fed','system') OR o.id IS NOT NULL THEN '' ELSE m.session_id END,m.recipient_harness,m.return_session_id,m.return_host,m.thread_id,m.outcome,CASE WHEN o.resolved!=0 THEN o.target_ref ELSE NULL END,o.peer,o.outcome,o.id IS NOT NULL FROM messages m LEFT JOIN outbound o ON o.id=m.id WHERE m.id=?1",
        [id],
        |row| Ok(Message {
            id: row.get(0)?, created_at: row.get(1)?, recipient: row.get(2)?,
            recipient_harness: row.get(3)?, return_session: row.get(4)?,
            return_host: row.get(5)?, thread: row.get(6)?, outcome: row.get(7)?,
            remote_target: row.get(8)?, peer: row.get(9)?, outbound_outcome: row.get(10)?,
            has_outbound: row.get(11)?,
        }),
    ).optional()
}

pub(crate) fn message_after(conn: &Connection, id: &str, before: Option<Option<Message>>) {
    let (Some(before), Some(capture)) = (before, active(conn)) else {
        return;
    };
    match read_message(conn, id) {
        Ok(after) => capture.borrow_mut().record(
            Key::Message(id.to_owned()),
            before.map(Projection::Message),
            after.map(Projection::Message),
        ),
        Err(_) => capture.borrow_mut().unavailable = true,
    }
}

pub(crate) fn reply_inserted(conn: &Connection, seq: i64) {
    let Some(capture) = active(conn) else { return };
    match read_reply(conn, seq) {
        Ok(Some(reply)) => {
            capture
                .borrow_mut()
                .record(Key::Reply(seq), None, Some(Projection::Reply(reply)))
        }
        Ok(None) | Err(_) => capture.borrow_mut().unavailable = true,
    }
}

fn read_reply(conn: &Connection, seq: i64) -> rusqlite::Result<Option<Reply>> {
    conn.query_row(
        "SELECT r.seq,r.message_id,r.created_at,r.replier_session_id,r.push_outcome,r.pushed_message_id,p.return_session_id,p.return_host,m.return_session_id,m.return_host FROM replies r LEFT JOIN messages p ON p.id=r.pushed_message_id LEFT JOIN messages m ON m.id=r.message_id WHERE r.seq=?1",
        [seq],
        |row| Ok(Reply { seq: row.get(0)?, message_id: row.get(1)?, created_at: row.get(2)?, replier: row.get(3)?, outcome: row.get(4)?, pushed_id: row.get(5)?, source_session: row.get(6)?, source_host: row.get(7)?, destination_session: row.get(8)?, destination_host: row.get(9)? }),
    ).optional()
}

pub(crate) fn replies_before(conn: &Connection, pushed_id: &str) -> Option<Vec<Reply>> {
    let capture = active(conn)?;
    let result: rusqlite::Result<Vec<Reply>> = (|| {
        let mut statement = conn.prepare("SELECT r.seq,r.message_id,r.created_at,r.replier_session_id,r.push_outcome,r.pushed_message_id,p.return_session_id,p.return_host,m.return_session_id,m.return_host FROM replies r LEFT JOIN messages p ON p.id=r.pushed_message_id LEFT JOIN messages m ON m.id=r.message_id WHERE r.pushed_message_id=?1 LIMIT 257")?;
        let rows = statement.query_map([pushed_id], |row| {
            Ok(Reply {
                seq: row.get(0)?,
                message_id: row.get(1)?,
                created_at: row.get(2)?,
                replier: row.get(3)?,
                outcome: row.get(4)?,
                pushed_id: row.get(5)?,
                source_session: row.get(6)?,
                source_host: row.get(7)?,
                destination_session: row.get(8)?,
                destination_host: row.get(9)?,
            })
        })?;
        let mut replies = Vec::new();
        let mut bytes = 0;
        for row in rows {
            let reply = row?;
            let size = serde_json::to_vec(&reply).map_or(MAX_BYTES + 1, |bytes| bytes.len());
            bytes += size;
            if size > MAX_PROJECTION_BYTES || bytes > MAX_BYTES {
                let mut capture = capture.borrow_mut();
                capture.changes.clear();
                capture.bytes = 0;
                capture.overflowed = true;
                return Ok(Vec::new());
            }
            replies.push(reply);
        }
        Ok(replies)
    })();
    match result {
        Ok(replies) => Some(replies),
        Err(_) => {
            capture.borrow_mut().unavailable = true;
            None
        }
    }
}

pub(crate) fn replies_after(conn: &Connection, before: Option<Vec<Reply>>) {
    let (Some(before), Some(capture)) = (before, active(conn)) else {
        return;
    };
    if before.len() > MAX_ROWS {
        let mut capture = capture.borrow_mut();
        capture.changes.clear();
        capture.bytes = 0;
        capture.overflowed = true;
        return;
    }
    for before in before {
        match read_reply(conn, before.seq) {
            Ok(after) => capture.borrow_mut().record(
                Key::Reply(before.seq),
                Some(Projection::Reply(before)),
                after.map(Projection::Reply),
            ),
            Err(_) => capture.borrow_mut().unavailable = true,
        }
    }
}

fn read_transfer(conn: &Connection, id: &str) -> rusqlite::Result<Transfer> {
    Ok(Transfer {
        id: id.to_owned(),
        message: read_message(conn, id)?,
        instance: conn
            .query_row(
                "SELECT instance_id,delivered_at FROM instance_queue WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?,
        root: conn
            .query_row(
                "SELECT session_id,delivered_at FROM pi_pending_messages WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?,
        outbound: conn
            .query_row(
                "SELECT target_ref,peer FROM outbound WHERE id=?1 AND resolved!=0",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?,
    })
}

pub(crate) fn transfer_before(conn: &Connection, id: &str) -> Option<Transfer> {
    let capture = active(conn)?;
    match read_transfer(conn, id) {
        Ok(transfer) => Some(transfer),
        Err(_) => {
            capture.borrow_mut().unavailable = true;
            None
        }
    }
}

pub(crate) fn transfers_for_instance(
    conn: &Connection,
    instance: &str,
    now: i64,
) -> Option<BTreeMap<String, Transfer>> {
    let capture = active(conn)?;
    let result: rusqlite::Result<_> = (|| {
        let mut statement = conn.prepare("SELECT id FROM instance_queue WHERE instance_id=?1 AND delivered_at IS NULL AND expires_at>?2 LIMIT 257")?;
        let mut rows = statement.query(rusqlite::params![instance, now])?;
        let mut before = BTreeMap::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let transfer = read_transfer(conn, &id)?;
            let size = serde_json::to_vec(&transfer).map_or(MAX_BYTES + 1, |bytes| bytes.len());
            bytes += size;
            if size > MAX_PROJECTION_BYTES || bytes > MAX_BYTES || before.len() == MAX_ROWS {
                let mut capture = capture.borrow_mut();
                capture.changes.clear();
                capture.bytes = 0;
                capture.overflowed = true;
                return Ok(BTreeMap::new());
            }
            before.insert(id, transfer);
        }
        Ok(before)
    })();
    match result {
        Ok(before) => Some(before),
        Err(_) => {
            capture.borrow_mut().unavailable = true;
            None
        }
    }
}

pub(crate) fn transfer_after(conn: &Connection, id: &str, before: Option<Transfer>) {
    let (Some(before), Some(capture)) = (before, active(conn)) else {
        return;
    };
    match read_transfer(conn, id) {
        Ok(after) => capture.borrow_mut().record(
            Key::Transfer(id.to_owned()),
            Some(Projection::Transfer(before)),
            Some(Projection::Transfer(after)),
        ),
        Err(_) => capture.borrow_mut().unavailable = true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{self, MessageRecord};

    #[derive(Default)]
    struct Recording(Mutex<Vec<Observation>>);
    impl Sink for Recording {
        fn publish(&self, events: Vec<Observation>) {
            self.0.lock().unwrap().extend(events);
        }
    }

    fn fixture() -> (Connection, Arc<Recording>) {
        let conn = Connection::open_in_memory().unwrap();
        storage::init_db(&conn).unwrap();
        (conn, Arc::new(Recording::default()))
    }

    fn batch(conn: &Connection, sink: &Arc<Recording>) -> Batch {
        Batch::with_sink(conn, "local.example".into(), sink.clone())
    }

    fn message(id: &str, outcome: &str) -> MessageRecord {
        MessageRecord {
            id: id.into(),
            created_at: 1,
            session_id: "recipient".into(),
            from_name: "BODY_LABEL_CANARY".into(),
            bytes: 17,
            outcome: outcome.into(),
            recipient_harness: "claude".into(),
            return_harness: Some("claude".into()),
            return_session_id: Some("sender".into()),
            thread_id: id.into(),
            return_host: None,
        }
    }

    #[test]
    fn committed_only_and_rollback_discard_frozen_metadata() {
        let (conn, sink) = fixture();
        {
            let capture = batch(&conn, &sink);
            let tx = conn.unchecked_transaction().unwrap();
            storage::insert_message(&tx, &message("rolled-back", "pending")).unwrap();
            assert!(sink.0.lock().unwrap().is_empty());
            tx.rollback().unwrap();
            drop(capture);
        }
        let tx = Transaction {
            transaction: conn.unchecked_transaction().unwrap(),
            capture: batch(&conn, &sink),
            connection: &conn,
        };
        storage::insert_message(&tx, &message("committed", "pending")).unwrap();
        assert!(sink.0.lock().unwrap().is_empty());
        tx.commit().unwrap();
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message_id.as_deref(), Some("committed"));
        assert_eq!(events[0].kind, "message_recorded");
        let json = serde_json::to_string(&*events).unwrap();
        assert!(!json.contains("BODY_LABEL_CANARY"));
        assert_eq!(events[0].body_availability, "not_recorded");
    }

    #[test]
    fn failed_commit_and_wrong_connection_never_publish() {
        let (conn, sink) = fixture();
        conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE deferred_fk(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);").unwrap();
        let tx = Transaction {
            transaction: conn.unchecked_transaction().unwrap(),
            capture: batch(&conn, &sink),
            connection: &conn,
        };
        storage::insert_message(&tx, &message("failed-commit", "pending")).unwrap();
        tx.execute("INSERT INTO deferred_fk VALUES(42)", [])
            .unwrap();
        assert!(tx.commit().is_err());
        assert!(sink.0.lock().unwrap().is_empty());

        let capture = batch(&conn, &sink);
        storage::insert_message(&conn, &message("wrong-connection", "pending")).unwrap();
        let other = Connection::open_in_memory().unwrap();
        capture.committed(&other);
        assert!(sink.0.lock().unwrap().is_empty());
        assert!(active(&conn).is_none());
    }

    #[test]
    fn coalescing_reports_actual_final_outcome_and_ignores_noops() {
        let (conn, sink) = fixture();
        let record = message("same", "delivered");
        storage::insert_message(&conn, &record).unwrap();
        let capture = batch(&conn, &sink);
        let tx = conn.unchecked_transaction().unwrap();
        storage::upsert_message(&tx, &record).unwrap();
        storage::complete_message(&tx, "same", "queued", None).unwrap();
        capture.refresh(&tx);
        tx.commit().unwrap();
        capture.committed(&conn);
        assert!(sink.0.lock().unwrap().is_empty());

        let capture = batch(&conn, &sink);
        let tx = conn.unchecked_transaction().unwrap();
        storage::insert_message(&tx, &message("net", "pending")).unwrap();
        storage::complete_message(&tx, "net", "delivered", None).unwrap();
        storage::complete_message(&tx, "net", "queued", None).unwrap();
        capture.refresh(&tx);
        tx.commit().unwrap();
        capture.committed(&conn);
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome.as_deref(), Some("delivered"));
    }

    #[test]
    fn nested_batch_merges_until_outer_commit_and_cannot_escape_rollback() {
        let (conn, sink) = fixture();
        let outer = batch(&conn, &sink);
        let tx = conn.unchecked_transaction().unwrap();
        let inner = batch(&conn, &sink);
        storage::insert_message(&tx, &message("nested", "pending")).unwrap();
        inner.committed(&tx);
        assert!(sink.0.lock().unwrap().is_empty());
        tx.rollback().unwrap();
        drop(outer);
        assert!(sink.0.lock().unwrap().is_empty());

        let outer = batch(&conn, &sink);
        let tx = conn.unchecked_transaction().unwrap();
        let inner = batch(&conn, &sink);
        storage::insert_message(&tx, &message("nested-ok", "pending")).unwrap();
        inner.committed(&tx);
        outer.refresh(&tx);
        tx.commit().unwrap();
        outer.committed(&conn);
        assert_eq!(sink.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn premature_commit_is_discarded_and_capture_overflow_is_an_unknown_gap() {
        let (conn, sink) = fixture();
        let capture = batch(&conn, &sink);
        let tx = conn.unchecked_transaction().unwrap();
        storage::insert_message(&tx, &message("premature", "pending")).unwrap();
        capture.committed(&tx);
        tx.commit().unwrap();
        assert!(sink.0.lock().unwrap().is_empty());

        let capture = batch(&conn, &sink);
        let tx = conn.unchecked_transaction().unwrap();
        for i in 0..=MAX_ROWS {
            storage::insert_message(&tx, &message(&format!("overflow-{i}"), "pending")).unwrap();
        }
        assert!(capture
            .capture
            .as_ref()
            .unwrap()
            .borrow()
            .changes
            .is_empty());
        assert!(capture.capture.as_ref().unwrap().borrow().overflowed);
        tx.commit().unwrap();
        capture.committed(&conn);
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "gap");
        assert_eq!(events[0].reason.as_deref(), Some("capture_overflow"));
    }

    #[test]
    fn settled_partial_autocommit_survives_error_but_internal_rollback_does_not() {
        let (conn, sink) = fixture();
        let capture = batch(&conn, &sink);
        let result: Result<(), ()> = settle_operation(capture, &conn, || {
            storage::insert_message(&conn, &message("partial-success", "pending")).unwrap();
            Err(())
        });
        assert_eq!(result, Err(()));
        assert_eq!(sink.0.lock().unwrap().len(), 1);
        sink.0.lock().unwrap().clear();

        let capture = batch(&conn, &sink);
        let result: Result<(), ()> = settle_operation(capture, &conn, || {
            let tx = conn.unchecked_transaction().unwrap();
            storage::insert_message(&tx, &message("internally-rolled-back", "pending")).unwrap();
            tx.rollback().unwrap();
            Err(())
        });
        assert_eq!(result, Err(()));
        assert!(sink.0.lock().unwrap().is_empty());
    }

    #[test]
    fn reply_correlations_use_stored_links_and_never_guess_a_remote_node() {
        let (conn, sink) = fixture();
        let mut parent = message("original", "delivered");
        parent.return_host = Some("sender.example".into());
        storage::insert_message(&conn, &parent).unwrap();
        let capture = batch(&conn, &sink);
        let tx = conn.unchecked_transaction().unwrap();
        storage::insert_reply(
            &tx,
            "original",
            "remote-replier",
            "BODY_REPLY_CANARY",
            Some("pushed"),
            Some("pushed"),
        )
        .unwrap();
        let mut pushed = message("pushed", "delivered");
        pushed.return_session_id = Some("remote-replier".into());
        pushed.return_host = Some("remote.example".into());
        storage::insert_message(&tx, &pushed).unwrap();
        capture.refresh(&tx);
        tx.commit().unwrap();
        capture.committed(&conn);
        let events = sink.0.lock().unwrap();
        let reply = events.iter().find(|e| e.kind == "reply_recorded").unwrap();
        assert_eq!(reply.from.as_deref(), Some("remote-replier@remote.example"));
        assert_eq!(reply.to.as_deref(), Some("sender@sender.example"));
        assert!(!serde_json::to_string(&*events)
            .unwrap()
            .contains("BODY_REPLY_CANARY"));
    }

    #[test]
    fn explicit_removal_and_handoff_transfer_use_actual_committed_rows() {
        let (conn, sink) = fixture();
        storage::insert_message(&conn, &message("handoff", "queued")).unwrap();
        storage::insert_queued(
            &conn,
            &storage::QueuedMessage {
                id: "handoff".into(),
                instance_id: "recipient".into(),
                created_at: 1,
                expires_at: i64::MAX,
                from_name: "LABEL_TRANSFER_CANARY".into(),
                body: "BODY_TRANSFER_CANARY".into(),
            },
        )
        .unwrap();
        let result = settle_operation(batch(&conn, &sink), &conn, || {
            storage::drop_handed_over(&conn, "recipient", &["handoff".into()], "remote.example", 2)
        });
        assert_eq!(result.unwrap(), 0);
        {
            let events = sink.0.lock().unwrap();
            let transfer = events
                .iter()
                .find(|e| e.kind == "record_transferred")
                .unwrap();
            assert_eq!(transfer.from.as_deref(), Some("recipient@local.example"));
            assert_eq!(transfer.to.as_deref(), Some("recipient@remote.example"));
            assert!(!serde_json::to_string(&*events).unwrap().contains("CANARY"));
        }
        sink.0.lock().unwrap().clear();
        settle_operation(batch(&conn, &sink), &conn, || {
            storage::drop_handed_over(&conn, "recipient", &["handoff".into()], "remote.example", 2)
        })
        .unwrap();
        assert!(sink.0.lock().unwrap().is_empty());

        storage::insert_message(&conn, &message("expire", "delivered")).unwrap();
        settle_operation(batch(&conn, &sink), &conn, || {
            storage::delete_message(&conn, "expire").unwrap();
        });
        let events = sink.0.lock().unwrap();
        assert_eq!(
            events.iter().filter(|e| e.kind == "record_removed").count(),
            1
        );
        assert!(!serde_json::to_string(&*events).unwrap().contains("CANARY"));
    }

    #[test]
    fn unresolved_references_are_absent_until_a_stored_resolution_exists() {
        let (conn, sink) = fixture();
        let capture = batch(&conn, &sink);
        let tx = conn.unchecked_transaction().unwrap();
        let mut record = message("remote", "pending");
        record.recipient_harness = "fed".into();
        record.session_id = "LABEL_REFERENCE_CANARY".into();
        storage::insert_message(&tx, &record).unwrap();
        storage::insert_outbound(
            &tx,
            "remote",
            "remote.example",
            "LABEL_REFERENCE_CANARY",
            "pending",
            1,
        )
        .unwrap();
        capture.refresh(&tx);
        tx.commit().unwrap();
        capture.committed(&conn);
        assert_eq!(sink.0.lock().unwrap()[0].to, None);
        assert!(!serde_json::to_string(&*sink.0.lock().unwrap())
            .unwrap()
            .contains("CANARY"));
        sink.0.lock().unwrap().clear();
        settle_operation(batch(&conn, &sink), &conn, || {
            storage::update_outbound_target(&conn, "remote", "recipient@remote.example").unwrap();
            storage::mark_outbound_resolved(&conn, "remote").unwrap();
        });
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "recipient_resolved");
        assert_eq!(events[0].to.as_deref(), Some("recipient@remote.example"));
    }

    #[test]
    fn unavailable_full_observer_never_changes_codex_committed_transitions() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.path().join("observe.sqlite");
        std::fs::write(&file, b"corrupt observer fixture").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let primary = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        {
            let conn = primary.lock().unwrap();
            storage::init_db(&conn).unwrap();
            storage::insert_message(&conn, &message("original", "delivered")).unwrap();
            for id in ["accepted", "unknown", "cancel", "startup"] {
                storage::insert_message(&conn, &message(id, "queued")).unwrap();
                conn.execute("INSERT INTO codex_handoff(message_id,root_id,root_generation,carrier,state,updated_at) VALUES(?1,'root',1,'push','inflight',1)", [id]).unwrap();
                conn.execute("INSERT INTO pi_pending_messages(id,session_id,created_at,from_name,bytes,text,envelope) VALUES(?1,'root',1,'label',4,'body','envelope')", [id]).unwrap();
                storage::insert_reply(
                    &conn,
                    "original",
                    "replier",
                    "CODEX_BODY_CANARY",
                    Some("pending"),
                    Some(id),
                )
                .unwrap();
            }
        }
        let observer = Observer::start(
            &primary,
            &file,
            "local.example",
            crate::observe::Config {
                queue_events: 1,
                ..Default::default()
            },
        );
        assert!(observer.page(Default::default()).is_err());
        assert!(observer.set_paused_for_test(true));
        observer.publish(vec![Observation {
            kind: "message_recorded".into(),
            message_id: Some("queue-control".into()),
            body_availability: "not_recorded".into(),
            ..Default::default()
        }]);
        assert_eq!(observer.queue_stats_for_test().0, 1);
        let started = Instant::now();
        let conn = primary.lock().unwrap();
        let mut dropped = observer.queue_stats_for_test().2;
        for (id, expected) in [
            ("accepted", "delivered"),
            ("unknown", "delivery_unknown"),
            ("cancel", "delivery_unknown"),
            ("startup", "delivery_unknown"),
        ] {
            autocommit_registered(&conn, |conn| -> rusqlite::Result<()> {
                match id {
                    "accepted" => {
                        storage::complete_codex_handoff_accepted(conn, "root", &[id.into()])?
                    }
                    "unknown" => storage::mark_codex_handoff_unknown(conn, &[id.into()])?,
                    "cancel" => {
                        assert!(storage::mark_owned_codex_push_unknown(conn, "root", 1, id)?)
                    }
                    "startup" => {
                        storage::startup_invalidate_codex(conn)?;
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(
                storage::get_message(&conn, id).unwrap().unwrap().outcome,
                expected
            );
            assert!(
                observer.queue_stats_for_test().2 > dropped,
                "each real transition must reach the full observer queue"
            );
            dropped = observer.queue_stats_for_test().2;
            assert_eq!(observer.queue_stats_for_test().0, 1);
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(observer.page(Default::default()).is_err());
        assert_eq!(
            storage::get_reply_by_pushed_id(&conn, "accepted")
                .unwrap()
                .unwrap()
                .push_outcome
                .as_deref(),
            Some("pushed")
        );
        for id in ["unknown", "cancel", "startup"] {
            assert_eq!(
                storage::get_reply_by_pushed_id(&conn, id)
                    .unwrap()
                    .unwrap()
                    .push_outcome
                    .as_deref(),
                Some("push_failed")
            );
        }
    }
}
