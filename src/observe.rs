use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_EVENT_BYTES: usize = 4096;
pub const MAX_PAGE_BYTES: usize = 256 * 1024;
pub const MAX_PAGE_EVENTS: usize = 200;

#[derive(Clone, Debug)]
pub struct Config {
    pub max_rows: usize,
    pub max_bytes: usize,
    pub ttl: Duration,
    pub queue_events: usize,
    pub queue_bytes: usize,
    pub maintenance_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_rows: 10_000,
            max_bytes: 16 * 1024 * 1024,
            ttl: Duration::from_secs(7 * 86400),
            queue_events: 256,
            queue_bytes: 1024 * 1024,
            maintenance_interval: Duration::from_secs(600),
        }
    }
}

impl Config {
    fn bounded(mut self) -> Self {
        self.max_rows = self.max_rows.clamp(1, 10_000);
        self.max_bytes = self.max_bytes.clamp(MAX_EVENT_BYTES, 16 * 1024 * 1024);
        self.queue_events = self.queue_events.clamp(1, 256);
        self.queue_bytes = self.queue_bytes.clamp(MAX_EVENT_BYTES, 1024 * 1024);
        self.maintenance_interval = self
            .maintenance_interval
            .clamp(Duration::from_millis(5), Duration::from_secs(600));
        self
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub source_at: Option<i64>,
    pub kind: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub message_id: Option<String>,
    pub reply_id: Option<i64>,
    pub thread_id: Option<String>,
    pub outcome: Option<String>,
    pub reason: Option<String>,
    pub body_availability: String,
}

impl Observation {
    fn bounded(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "message_recorded"
                | "recipient_resolved"
                | "outcome_changed"
                | "reply_recorded"
                | "reply_push_outcome_changed"
                | "record_removed"
                | "record_transferred"
                | "gap"
        ) && [
            self.from.as_deref(),
            self.to.as_deref(),
            self.message_id.as_deref(),
            self.thread_id.as_deref(),
            self.outcome.as_deref(),
            self.reason.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(|value| value.len() <= 512)
            && matches!(
                self.body_availability.as_str(),
                "not_recorded" | "retained_at_capture"
            )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub node: String,
    pub epoch: String,
    pub sequence: i64,
    pub observed_at: i64,
    pub persisted_at: i64,
    #[serde(flatten)]
    pub observation: Observation,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub epoch: Option<String>,
    pub after: Option<i64>,
    pub limit: Option<usize>,
}

impl Query {
    pub fn validate(&self) -> Result<(), Error> {
        if self.after.is_some_and(|after| after < 0)
            || self
                .limit
                .is_some_and(|limit| !(1..=MAX_PAGE_EVENTS).contains(&limit))
            || self
                .epoch
                .as_ref()
                .is_some_and(|epoch| epoch.is_empty() || epoch.len() > 128)
        {
            return Err(Error::BadQuery);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LossCounters {
    pub capacity: u64,
    pub ttl: u64,
    pub queue: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    pub reason: String,
    pub unknown_loss: bool,
    pub count: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub node: String,
    pub epoch: String,
    pub events: Vec<Event>,
    pub next: i64,
    pub floor: i64,
    pub head: i64,
    pub has_more: bool,
    pub gaps: Vec<Gap>,
    pub losses: LossCounters,
    pub available: bool,
    pub initial_omitted: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid observation cursor or page bound")]
    BadQuery,
    #[error("observation journal unavailable")]
    Unavailable,
}

#[derive(Clone)]
struct Pending {
    value: Observation,
    observed_at: i64,
    bytes: usize,
    ticket: u64,
}

#[derive(Default)]
struct Queue {
    events: VecDeque<Pending>,
    bytes: usize,
    next_ticket: u64,
}

struct Shared {
    queue: Mutex<Queue>,
    wake: Condvar,
    stopped: AtomicBool,
    available: AtomicBool,
    dropped: AtomicU64,
    drop_base: AtomicU64,
    persisted_drop: AtomicU64,
    persisted_ticket: AtomicU64,
    clock: AtomicI64,
    paused: AtomicBool,
    paused_ack: AtomicBool,
    maintenance: AtomicU64,
    maintained: AtomicU64,
    maintenance_runs: AtomicU64,
    #[cfg(test)]
    before_wait: Mutex<Option<BeforeWait>>,
    #[cfg(test)]
    exited: AtomicBool,
}

#[cfg(test)]
struct BeforeWait {
    ticket: u64,
    entered: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
fn before_wait(shared: &Shared) {
    let barrier = {
        let mut slot = shared.before_wait.lock().unwrap();
        if slot.as_ref().is_some_and(|barrier| {
            shared.persisted_ticket.load(Ordering::Acquire) >= barrier.ticket
        }) {
            slot.take()
        } else {
            None
        }
    };
    if let Some(barrier) = barrier {
        let _ = barrier.entered.send(());
        let _ = barrier.resume.recv_timeout(Duration::from_secs(5));
    }
}

impl Shared {
    fn update_control<R>(&self, update: impl FnOnce() -> R) -> R {
        let _queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
        let result = update();
        self.wake.notify_all();
        result
    }

    fn now(&self) -> i64 {
        let override_time = self.clock.load(Ordering::Relaxed);
        if override_time != i64::MIN {
            return override_time;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .min(i64::MAX as u64) as i64
    }

    fn lost(&self, count: u64) {
        let _ = self
            .dropped
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(old.saturating_add(count))
            });
    }
}

pub struct Observer {
    shared: Arc<Shared>,
    path: PathBuf,
    config: Config,
    node: String,
}

struct Registration {
    primary: Weak<Mutex<Connection>>,
    observer: Weak<Observer>,
    connection: usize,
}

static REGISTRY: LazyLock<Mutex<HashMap<usize, Registration>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn for_db(primary: &Arc<Mutex<Connection>>) -> Option<Arc<Observer>> {
    let registry = REGISTRY.lock().ok()?;
    let entry = registry.get(&(Arc::as_ptr(primary) as usize))?;
    if !Arc::ptr_eq(&entry.primary.upgrade()?, primary) {
        return None;
    }
    entry.observer.upgrade()
}

pub fn for_connection(connection: &Connection) -> Option<Arc<Observer>> {
    let address = connection as *const Connection as usize;
    let registry = REGISTRY.lock().ok()?;
    registry.values().find_map(|entry| {
        if entry.connection == address && entry.primary.upgrade().is_some() {
            entry.observer.upgrade()
        } else {
            None
        }
    })
}

impl Observer {
    pub fn start(
        primary: &Arc<Mutex<Connection>>,
        sidecar: &Path,
        node: &str,
        config: Config,
    ) -> Arc<Self> {
        let config = config.bounded();
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue::default()),
            wake: Condvar::new(),
            stopped: AtomicBool::new(false),
            available: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            drop_base: AtomicU64::new(0),
            persisted_drop: AtomicU64::new(0),
            persisted_ticket: AtomicU64::new(0),
            clock: AtomicI64::new(i64::MIN),
            paused: AtomicBool::new(false),
            paused_ack: AtomicBool::new(false),
            maintenance: AtomicU64::new(0),
            maintained: AtomicU64::new(0),
            maintenance_runs: AtomicU64::new(0),
            #[cfg(test)]
            before_wait: Mutex::new(None),
            #[cfg(test)]
            exited: AtomicBool::new(false),
        });
        let observer = Arc::new(Self {
            shared: shared.clone(),
            path: sidecar.to_path_buf(),
            config: config.clone(),
            node: node.to_owned(),
        });
        let connection = primary
            .lock()
            .map(|connection| &*connection as *const Connection as usize)
            .unwrap_or(0);
        if let Ok(mut registry) = REGISTRY.lock() {
            registry.retain(|_, entry| {
                entry.primary.strong_count() > 0 && entry.observer.strong_count() > 0
            });
            registry.insert(
                Arc::as_ptr(primary) as usize,
                Registration {
                    primary: Arc::downgrade(primary),
                    observer: Arc::downgrade(&observer),
                    connection,
                },
            );
        }
        let path = sidecar.to_path_buf();
        let node = node.to_owned();
        if std::thread::Builder::new()
            .name("xmsg-observe".into())
            .spawn(move || writer(shared, path, node, config))
            .is_err()
        {
            tracing::warn!(class = "worker_start", "observation journal unavailable");
        }
        observer
    }

    pub fn publish(&self, observations: Vec<Observation>) {
        for value in observations {
            if !value.bounded() {
                self.lost(1);
                continue;
            }
            let Ok(bytes) = serde_json::to_vec(&value) else {
                self.lost(1);
                continue;
            };
            if bytes.len() > MAX_EVENT_BYTES - 512 {
                self.lost(1);
                continue;
            }
            let pending_bytes = bytes.len() + 512;
            let mut queue = match self.shared.queue.lock() {
                Ok(queue) => queue,
                Err(error) => {
                    drop(error);
                    self.lost(1);
                    continue;
                }
            };
            while queue.events.len() >= self.config.queue_events
                || queue.bytes + pending_bytes > self.config.queue_bytes
            {
                if let Some(old) = queue.events.pop_front() {
                    queue.bytes -= old.bytes;
                    self.shared.lost(1);
                } else {
                    break;
                }
            }
            queue.next_ticket = queue.next_ticket.saturating_add(1);
            let ticket = queue.next_ticket;
            queue.bytes += pending_bytes;
            queue.events.push_back(Pending {
                value,
                observed_at: self.shared.now(),
                bytes: pending_bytes,
                ticket,
            });
        }
        self.shared.wake.notify_one();
    }

    pub fn lost(&self, count: u64) {
        self.shared.update_control(|| self.shared.lost(count));
    }

    pub fn node(&self) -> &str {
        &self.node
    }

    pub fn page(&self, query: Query) -> Result<Page, Error> {
        query.validate()?;
        if !self.shared.available.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        read_page(&self.path, &self.shared, query).map_err(|_| Error::Unavailable)
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.shared
            .update_control(|| self.shared.stopped.store(true, Ordering::Release));
    }
}

type JournalResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn open_journal(
    path: &Path,
    node: &str,
    now: i64,
    config: &Config,
) -> JournalResult<(Connection, u64)> {
    if node.is_empty() || node.len() > 128 || serde_json::to_string(node)?.len() > 256 {
        return Err("invalid_node".into());
    }
    let parent = path.parent().ok_or("missing_parent")?;
    let directory = fs::symlink_metadata(parent)?;
    if !directory.is_dir()
        || directory.uid() != crate::agent::current_uid()
        || directory.mode() & 0o077 != 0
    {
        return Err("private_directory_required".into());
    }
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != crate::agent::current_uid()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err("private_file_required".into());
    }
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.busy_timeout(Duration::from_millis(50))?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != 0 && version != 1 {
        return Err("unsupported_journal".into());
    }
    if version == 0 {
        let tables: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if tables != 0 {
            return Err("unrecognized_journal".into());
        }
    }
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS observer_meta (
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             epoch TEXT NOT NULL, node TEXT NOT NULL,
             capacity INTEGER NOT NULL, ttl INTEGER NOT NULL, queue INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS observer_events (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             observed_at INTEGER NOT NULL, bytes INTEGER NOT NULL, payload TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS observer_events_age ON observer_events(observed_at);
         PRAGMA user_version=1;",
    )?;
    let existing: Option<(String, i64)> = tx
        .query_row(
            "SELECT node,queue FROM observer_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if existing.as_ref().is_some_and(|(old, _)| old != node) {
        tx.execute("DELETE FROM observer_events", [])?;
        tx.execute(
            "DELETE FROM sqlite_sequence WHERE name='observer_events'",
            [],
        )?;
        tx.execute("DELETE FROM observer_meta", [])?;
    }
    tx.execute(
        "INSERT OR IGNORE INTO observer_meta VALUES(1,?1,?2,0,0,0)",
        params![ulid::Ulid::new().to_string(), node],
    )?;
    let epoch: String = tx.query_row(
        "SELECT epoch FROM observer_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let base: i64 = tx.query_row(
        "SELECT queue FROM observer_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    insert_event(
        &tx,
        node,
        &epoch,
        now,
        now,
        Observation {
            kind: "gap".into(),
            reason: Some("writer_restart".into()),
            body_availability: "not_recorded".into(),
            ..Default::default()
        },
    )?;
    retain(&tx, config, now)?;
    tx.commit()?;
    Ok((conn, u64::try_from(base)?))
}

fn insert_event(
    conn: &Connection,
    node: &str,
    epoch: &str,
    observed_at: i64,
    persisted_at: i64,
    observation: Observation,
) -> JournalResult<()> {
    conn.execute(
        "INSERT INTO observer_events(observed_at,bytes,payload) VALUES(?1,0,'')",
        [observed_at],
    )?;
    let sequence = conn.last_insert_rowid();
    let event = Event {
        node: node.into(),
        epoch: epoch.into(),
        sequence,
        observed_at,
        persisted_at,
        observation,
    };
    let payload = serde_json::to_string(&event)?;
    if payload.len() > MAX_EVENT_BYTES {
        return Err("oversized_event".into());
    }
    // The logical budget includes the complete JSON and three stored integer columns.
    let bytes = payload.len() + 24;
    conn.execute(
        "UPDATE observer_events SET bytes=?2,payload=?3 WHERE sequence=?1",
        params![sequence, bytes as i64, payload],
    )?;
    Ok(())
}

fn retain(conn: &Connection, config: &Config, now: i64) -> JournalResult<()> {
    let cutoff = now.saturating_sub(config.ttl.as_secs().min(i64::MAX as u64) as i64);
    let expired = conn.execute(
        "DELETE FROM observer_events WHERE observed_at < ?1",
        [cutoff],
    )?;
    conn.execute(
        "UPDATE observer_meta SET ttl=ttl+?1 WHERE singleton=1",
        [expired as i64],
    )?;
    let (mut rows, mut bytes): (i64, i64) = conn.query_row(
        "SELECT count(*),COALESCE(sum(bytes),0) FROM observer_events",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut evicted = 0usize;
    while rows > config.max_rows as i64 || bytes > config.max_bytes as i64 {
        let (sequence, size): (i64, i64) = conn.query_row(
            "SELECT sequence,bytes FROM observer_events ORDER BY sequence LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        conn.execute("DELETE FROM observer_events WHERE sequence=?1", [sequence])?;
        rows -= 1;
        bytes = bytes.saturating_sub(size);
        evicted += 1;
    }
    conn.execute(
        "UPDATE observer_meta SET capacity=capacity+?1 WHERE singleton=1",
        [evicted as i64],
    )?;
    Ok(())
}

fn persist(
    conn: &mut Connection,
    node: &str,
    config: &Config,
    now: i64,
    batch: &[Pending],
    dropped: u64,
) -> JournalResult<()> {
    let tx = conn.transaction()?;
    let epoch: String = tx.query_row(
        "SELECT epoch FROM observer_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    for pending in batch {
        insert_event(
            &tx,
            node,
            &epoch,
            pending.observed_at,
            now,
            pending.value.clone(),
        )?;
    }
    retain(&tx, config, now)?;
    tx.execute(
        "UPDATE observer_meta SET queue=?1 WHERE singleton=1",
        [dropped.min(i64::MAX as u64) as i64],
    )?;
    tx.commit()?;
    Ok(())
}

fn writer(shared: Arc<Shared>, path: PathBuf, node: String, config: Config) {
    let mut connection = None;
    let mut retry = Instant::now();
    let mut backoff = Duration::from_secs(1);
    let mut maintenance = Instant::now();
    let mut class = None;
    let mut loaded_base = false;
    while !shared.stopped.load(Ordering::Acquire) {
        if !controls_ready(&shared) {
            break;
        }
        if connection.is_none() {
            if Instant::now() < retry {
                if let Ok(queue) = shared.queue.lock() {
                    if shared.stopped.load(Ordering::Acquire)
                        || shared.paused.load(Ordering::Acquire)
                    {
                        continue;
                    }
                    let _ = shared
                        .wake
                        .wait_timeout(queue, retry.saturating_duration_since(Instant::now()));
                }
                continue;
            }
            match open_journal(&path, &node, shared.now(), &config) {
                Ok((conn, base)) => {
                    if !loaded_base {
                        shared.drop_base.store(base, Ordering::Release);
                        loaded_base = true;
                    }
                    connection = Some(conn);
                    backoff = Duration::from_secs(1);
                    maintenance = Instant::now();
                }
                Err(_) => {
                    if class != Some("open") {
                        tracing::warn!(class = "open", "observation journal unavailable");
                        class = Some("open");
                    }
                    retry = Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            }
        }
        let requested = shared.maintenance.load(Ordering::Acquire);
        let due =
            Instant::now() >= maintenance || requested != shared.maintained.load(Ordering::Acquire);
        let mut batch = Vec::new();
        if let Ok(mut queue) = shared.queue.lock() {
            for _ in 0..64 {
                let Some(pending) = queue.events.pop_front() else {
                    break;
                };
                queue.bytes -= pending.bytes;
                batch.push(pending);
            }
        }
        let dropped = shared.dropped.load(Ordering::Acquire);
        if !batch.is_empty() || due || shared.persisted_drop.load(Ordering::Acquire) != dropped {
            let persisted_dropped = shared
                .drop_base
                .load(Ordering::Acquire)
                .saturating_add(dropped);
            let result = persist(
                connection.as_mut().unwrap(),
                &node,
                &config,
                shared.now(),
                &batch,
                persisted_dropped,
            );
            if result.is_err() {
                shared.available.store(false, Ordering::Release);
                if let Ok(mut queue) = shared.queue.lock() {
                    for pending in batch.into_iter().rev() {
                        queue.bytes += pending.bytes;
                        queue.events.push_front(pending);
                    }
                    while queue.events.len() > config.queue_events
                        || queue.bytes > config.queue_bytes
                    {
                        if let Some(old) = queue.events.pop_front() {
                            queue.bytes -= old.bytes;
                            shared.lost(1);
                        }
                    }
                }
                connection = None;
                if class != Some("persist") {
                    tracing::warn!(class = "persist", "observation journal unavailable");
                    class = Some("persist");
                }
                retry = Instant::now() + backoff;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
            if let Some(last) = batch.last() {
                shared
                    .persisted_ticket
                    .store(last.ticket, Ordering::Release);
            }
            shared.persisted_drop.store(dropped, Ordering::Release);
            shared.maintained.store(requested, Ordering::Release);
            shared.maintenance_runs.fetch_add(1, Ordering::AcqRel);
            if class.take().is_some() {
                tracing::info!(class = "recovered", "observation journal available");
            }
            shared.available.store(true, Ordering::Release);
            maintenance = Instant::now() + config.maintenance_interval;
            shared.wake.notify_all();
        }
        #[cfg(test)]
        before_wait(&shared);
        let Ok(queue) = shared.queue.lock() else {
            break;
        };
        if !queue.events.is_empty()
            || shared.stopped.load(Ordering::Acquire)
            || shared.paused.load(Ordering::Acquire)
            || shared.maintenance.load(Ordering::Acquire)
                != shared.maintained.load(Ordering::Acquire)
            || shared.dropped.load(Ordering::Acquire)
                != shared.persisted_drop.load(Ordering::Acquire)
        {
            continue;
        }
        let _ = shared
            .wake
            .wait_timeout(queue, maintenance.saturating_duration_since(Instant::now()));
    }
    shared.available.store(false, Ordering::Release);
    #[cfg(test)]
    shared.exited.store(true, Ordering::Release);
}

fn controls_ready(shared: &Shared) -> bool {
    let Ok(mut queue) = shared.queue.lock() else {
        return false;
    };
    while shared.paused.load(Ordering::Acquire) && !shared.stopped.load(Ordering::Acquire) {
        shared.paused_ack.store(true, Ordering::Release);
        shared.wake.notify_all();
        queue = match shared.wake.wait(queue) {
            Ok(queue) => queue,
            Err(_) => return false,
        };
    }
    shared.paused_ack.store(false, Ordering::Release);
    !shared.stopped.load(Ordering::Acquire)
}

fn read_page(path: &Path, shared: &Shared, query: Query) -> JournalResult<Page> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_millis(50))?;
    let tx = conn.unchecked_transaction()?;
    let (node, epoch, capacity, ttl, queue): (String, String, i64, i64, i64) = tx.query_row(
        "SELECT node,epoch,capacity,ttl,queue FROM observer_meta WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let head: i64 = tx.query_row(
        "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='observer_events'),0)",
        [],
        |row| row.get(0),
    )?;
    let (minimum, retained): (Option<i64>, i64) = tx.query_row(
        "SELECT min(sequence),count(*) FROM observer_events",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let floor = minimum.unwrap_or_else(|| head.saturating_add(1));
    let limit = query.limit.unwrap_or(100);
    let mut after = query.after.unwrap_or(0);
    let mut gaps = Vec::new();
    let reset = if query.epoch.as_ref().is_some_and(|value| value != &epoch) {
        Some("epoch_changed")
    } else if after > head {
        Some("cursor_ahead")
    } else {
        None
    };
    if let Some(reason) = reset {
        after = 0;
        gaps.push(Gap {
            reason: reason.into(),
            unknown_loss: true,
            count: None,
        });
    } else if query.after.is_some() && after < floor.saturating_sub(1) {
        gaps.push(Gap {
            reason: "cursor_evicted".into(),
            unknown_loss: false,
            count: Some((floor.saturating_sub(1) - after) as u64),
        });
    }
    let initial = query.after.is_none() && reset.is_none();
    let sql = if initial {
        "SELECT payload FROM (SELECT sequence,payload FROM observer_events ORDER BY sequence DESC LIMIT ?1) ORDER BY sequence"
    } else {
        "SELECT payload FROM observer_events WHERE sequence>?2 AND sequence<=?3 ORDER BY sequence LIMIT ?1"
    };
    let mut statement = tx.prepare(sql)?;
    let mut rows = if initial {
        statement.query([limit as i64])?
    } else {
        statement.query(params![(limit + 1) as i64, after, head])?
    };
    let retained = u64::try_from(retained)?;
    let queue_loss = u64::try_from(queue)?.max(
        shared
            .drop_base
            .load(Ordering::Acquire)
            .saturating_add(shared.dropped.load(Ordering::Acquire)),
    );
    if queue_loss > 0 {
        gaps.push(Gap {
            reason: "queue_loss".into(),
            unknown_loss: false,
            count: Some(queue_loss),
        });
    }
    let base_gaps = gaps.clone();
    let mut page = Page {
        node,
        epoch,
        events: Vec::new(),
        next: after.min(head),
        floor,
        head,
        has_more: false,
        gaps,
        losses: LossCounters {
            capacity: u64::try_from(capacity)?,
            ttl: u64::try_from(ttl)?,
            queue: queue_loss,
        },
        available: true,
        initial_omitted: if initial {
            retained.saturating_sub(limit as u64)
        } else {
            0
        },
    };
    let mut estimated = serde_json::to_vec(&page)?.len() + 256;
    while let Some(row) = rows.next()? {
        let payload: String = row.get(0)?;
        if payload.len() > MAX_EVENT_BYTES {
            return Err("oversized_stored_event".into());
        }
        if page.events.len() >= limit || estimated + payload.len() + 1 > MAX_PAGE_BYTES {
            page.has_more = true;
            break;
        }
        let event: Event = serde_json::from_str(&payload)?;
        if event.node != page.node || event.epoch != page.epoch || event.sequence <= page.next {
            return Err("invalid_stored_event".into());
        }
        estimated += payload.len() + 1;
        page.next = event.sequence;
        page.events.push(event);
    }
    drop(rows);
    drop(statement);
    tx.commit()?;
    loop {
        page.gaps = base_gaps.clone();
        for event in &page.events {
            if event.observation.kind == "gap" {
                if let Some(reason) = &event.observation.reason {
                    page.gaps.push(Gap {
                        reason: reason.clone(),
                        unknown_loss: true,
                        count: None,
                    });
                }
            }
        }
        let missing = sequence_gap_count(&page, after, initial);
        if missing != 0 {
            page.gaps.push(Gap {
                reason: "sequence_gap".into(),
                unknown_loss: false,
                count: Some(missing),
            });
        }
        if serde_json::to_vec(&page)?.len() <= MAX_PAGE_BYTES {
            break;
        }
        page.events.pop().ok_or("oversized_page_metadata")?;
        page.next = page
            .events
            .last()
            .map_or(after.min(head), |event| event.sequence);
        page.has_more = true;
    }
    Ok(page)
}

fn sequence_gap_count(page: &Page, after: i64, initial: bool) -> u64 {
    let mut previous = if initial {
        page.events
            .first()
            .map_or(page.head, |event| event.sequence.saturating_sub(1))
    } else {
        after.max(page.floor.saturating_sub(1)).min(page.head)
    };
    let mut missing = 0u64;
    for event in &page.events {
        missing = missing
            .saturating_add(event.sequence.saturating_sub(previous.saturating_add(1)) as u64);
        previous = event.sequence;
    }
    if !page.has_more {
        missing = missing.saturating_add(page.head.saturating_sub(previous) as u64);
    }
    missing
}

#[cfg(any(test, feature = "test-hooks"))]
impl Observer {
    pub fn flush_for_test(&self, timeout: Duration) -> bool {
        let target = self.shared.queue.lock().unwrap().next_ticket;
        let deadline = Instant::now() + timeout;
        self.shared.wake.notify_one();
        while Instant::now() < deadline {
            if self.shared.available.load(Ordering::Acquire)
                && self.shared.persisted_ticket.load(Ordering::Acquire) >= target
                && self.shared.persisted_drop.load(Ordering::Acquire)
                    == self.shared.dropped.load(Ordering::Acquire)
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    pub fn set_paused_for_test(&self, paused: bool) -> bool {
        self.shared
            .update_control(|| self.shared.paused.store(paused, Ordering::Release));
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.shared.paused_ack.load(Ordering::Acquire) == paused {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    pub fn queue_stats_for_test(&self) -> (usize, usize, u64) {
        let queue = self.shared.queue.lock().unwrap();
        (
            queue.events.len(),
            queue.bytes,
            self.shared.dropped.load(Ordering::Acquire),
        )
    }

    pub fn set_time_for_test(&self, timestamp: i64) {
        self.shared.clock.store(timestamp, Ordering::Release);
    }

    pub fn maintenance_now_for_test(&self) -> bool {
        let requested = self
            .shared
            .update_control(|| self.shared.maintenance.fetch_add(1, Ordering::AcqRel) + 1);
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.shared.maintained.load(Ordering::Acquire) >= requested {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture(config: Config) -> (TempDir, Arc<Mutex<Connection>>, Arc<Observer>) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let primary = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        primary.lock().unwrap().execute_batch("PRAGMA user_version=3; CREATE TABLE unchanged(value TEXT); INSERT INTO unchanged VALUES('committed');").unwrap();
        let observer = Observer::start(
            &primary,
            &directory.path().join("observe.sqlite"),
            "test.node",
            config,
        );
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        (directory, primary, observer)
    }

    fn value(index: usize) -> Observation {
        Observation {
            source_at: Some(100),
            kind: "message_recorded".into(),
            message_id: Some(format!("message-{index}")),
            from: Some("source@test.node".into()),
            to: Some("target@test.node".into()),
            outcome: Some("queued".into()),
            body_availability: "not_recorded".into(),
            ..Default::default()
        }
    }

    fn all(observer: &Observer) -> Page {
        observer
            .page(Query {
                after: Some(0),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap()
    }

    fn force_before_wait(observer: &Observer) -> std::sync::mpsc::SyncSender<()> {
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        *observer.shared.before_wait.lock().unwrap() = Some(BeforeWait {
            ticket: observer.shared.queue.lock().unwrap().next_ticket + 1,
            entered: entered_tx,
            resume: resume_rx,
        });
        observer.publish(vec![value(9000)]);
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        resume_tx
    }

    fn wait_for(predicate: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    #[test]
    fn control_changes_before_empty_wait_cannot_lose_notifications() {
        let mut failed = Vec::new();
        {
            let (_directory, _primary, observer) = fixture(Config::default());
            let resume = force_before_wait(&observer);
            let setter = observer.clone();
            let control = std::thread::spawn(move || setter.set_paused_for_test(true));
            assert!(wait_for(|| observer.shared.paused.load(Ordering::Acquire)));
            resume.send(()).unwrap();
            if !control.join().unwrap() {
                failed.push("pause");
            }
            observer.shared.wake.notify_all();
            let _ = observer.set_paused_for_test(false);
        }
        {
            let (_directory, _primary, observer) = fixture(Config::default());
            let resume = force_before_wait(&observer);
            let setter = observer.clone();
            let before = observer.shared.maintenance.load(Ordering::Acquire);
            let control = std::thread::spawn(move || setter.maintenance_now_for_test());
            assert!(wait_for(|| observer
                .shared
                .maintenance
                .load(Ordering::Acquire)
                > before));
            resume.send(()).unwrap();
            if !control.join().unwrap() {
                failed.push("maintenance");
            }
            observer.shared.wake.notify_all();
        }
        {
            let (_directory, _primary, observer) = fixture(Config::default());
            let resume = force_before_wait(&observer);
            observer.publish(vec![Observation::default()]);
            assert_eq!(observer.shared.dropped.load(Ordering::Acquire), 1);
            resume.send(()).unwrap();
            if !wait_for(|| observer.shared.persisted_drop.load(Ordering::Acquire) == 1) {
                failed.push("invalid_event_loss");
            }
            observer.shared.wake.notify_all();
        }
        {
            let (_directory, _primary, observer) = fixture(Config::default());
            let resume = force_before_wait(&observer);
            let shared = observer.shared.clone();
            drop(observer);
            assert!(shared.stopped.load(Ordering::Acquire));
            resume.send(()).unwrap();
            if !wait_for(|| shared.exited.load(Ordering::Acquire)) {
                failed.push("shutdown");
            }
            shared.wake.notify_all();
        }
        assert!(
            failed.is_empty(),
            "control notifications lost at forced pre-wait boundary: {failed:?}"
        );
    }

    #[test]
    fn registry_page_and_private_storage_never_lock_or_migrate_primary() {
        let (directory, primary, observer) = fixture(Config::default());
        let primary_guard = primary.lock().unwrap();
        assert!(Arc::ptr_eq(&for_db(&primary).unwrap(), &observer));
        let startup = all(&observer);
        assert_eq!(startup.events.len(), 1);
        assert_eq!(
            startup.events[0].observation.reason.as_deref(),
            Some("writer_restart")
        );
        assert!(startup
            .gaps
            .iter()
            .any(|gap| gap.reason == "writer_restart" && gap.unknown_loss));
        assert_eq!(
            fs::metadata(directory.path().join("observe.sqlite"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            primary_guard
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            primary_guard
                .query_row("SELECT value FROM unchanged", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "committed"
        );
        assert_eq!(
            primary_guard
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name LIKE 'observer_%'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn connection_registry_isolates_connections_and_does_not_keep_primary_alive() {
        let (_directory, primary, observer) = fixture(Config::default());
        let guard = primary.lock().unwrap();
        assert!(Arc::ptr_eq(&for_connection(&guard).unwrap(), &observer));
        let unrelated = Connection::open_in_memory().unwrap();
        assert!(for_connection(&unrelated).is_none());
        drop(guard);
        let weak = Arc::downgrade(&primary);
        drop(primary);
        assert!(weak.upgrade().is_none());
        assert!(for_connection(&unrelated).is_none());
        let (_directory2, primary2, observer2) = fixture(Config::default());
        assert!(Arc::ptr_eq(
            &for_connection(&primary2.lock().unwrap()).unwrap(),
            &observer2
        ));
        assert!(!Arc::ptr_eq(&observer, &observer2));
    }

    #[test]
    fn restart_preserves_epoch_and_sequence_and_explicitly_resets_stale_cursors() {
        let (directory, primary, observer) = fixture(Config::default());
        observer.publish(vec![value(1)]);
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        let first = all(&observer);
        drop(observer);
        std::thread::sleep(Duration::from_millis(50));
        let next = Observer::start(
            &primary,
            &directory.path().join("observe.sqlite"),
            "test.node",
            Config::default(),
        );
        assert!(next.flush_for_test(Duration::from_secs(3)));
        let restarted = all(&next);
        assert_eq!(first.epoch, restarted.epoch);
        assert!(restarted.head > first.head);
        assert_eq!(
            restarted
                .events
                .last()
                .unwrap()
                .observation
                .reason
                .as_deref(),
            Some("writer_restart")
        );
        let ahead = next
            .page(Query {
                after: Some(restarted.head + 1),
                ..Default::default()
            })
            .unwrap();
        assert!(ahead
            .gaps
            .iter()
            .any(|gap| gap.reason == "cursor_ahead" && gap.unknown_loss));
        assert!(!ahead.events.is_empty());
        let changed = next
            .page(Query {
                epoch: Some("old-epoch".into()),
                after: Some(first.head),
                ..Default::default()
            })
            .unwrap();
        assert!(changed.gaps.iter().any(|gap| gap.reason == "epoch_changed"));
        drop(next);
        std::thread::sleep(Duration::from_millis(50));
        let identity = Observer::start(
            &primary,
            &directory.path().join("observe.sqlite"),
            "new.node",
            Config::default(),
        );
        assert!(identity.flush_for_test(Duration::from_secs(3)));
        assert_ne!(all(&identity).epoch, first.epoch);
        assert_eq!(all(&identity).head, 1);
    }

    #[test]
    fn paused_queue_drops_oldest_and_reports_exact_loss_without_io() {
        let (_directory, _primary, observer) = fixture(Config {
            queue_events: 2,
            ..Default::default()
        });
        assert!(observer.set_paused_for_test(true));
        observer.publish((0..5).map(value).collect());
        let (rows, bytes, dropped) = observer.queue_stats_for_test();
        assert_eq!(rows, 2);
        assert!(bytes <= 1024 * 1024);
        assert_eq!(dropped, 3);
        assert_eq!(all(&observer).head, 1);
        assert_eq!(all(&observer).losses.queue, 3);
        assert!(observer.set_paused_for_test(false));
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        let page = all(&observer);
        assert_eq!(
            page.events
                .iter()
                .filter_map(|event| event.observation.message_id.as_deref())
                .collect::<Vec<_>>(),
            ["message-3", "message-4"]
        );
        assert!(page
            .gaps
            .iter()
            .any(|gap| gap.reason == "queue_loss" && gap.count == Some(3)));
    }

    #[test]
    fn retained_row_and_complete_metadata_byte_caps_drop_oldest_with_counter() {
        let (_directory, _primary, observer) = fixture(Config {
            max_rows: 3,
            ..Default::default()
        });
        observer.publish((0..6).map(value).collect());
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        let page = all(&observer);
        assert_eq!(page.events.len(), 3);
        assert_eq!(page.losses.capacity, 4);
        assert_eq!(
            page.events[0].observation.message_id.as_deref(),
            Some("message-3")
        );
        assert!(page
            .gaps
            .iter()
            .any(|gap| gap.reason == "cursor_evicted" && gap.count == Some(4)));

        let (directory, _primary, observer) = fixture(Config {
            max_bytes: 4096,
            ..Default::default()
        });
        let values = (0..10)
            .map(|index| {
                let mut event = value(index);
                event.thread_id = Some("x".repeat(512));
                event.from = Some("f".repeat(512));
                event.to = Some("t".repeat(512));
                event
            })
            .collect();
        observer.publish(values);
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        let conn = Connection::open(directory.path().join("observe.sqlite")).unwrap();
        let size: i64 = conn
            .query_row(
                "SELECT COALESCE(sum(bytes),0) FROM observer_events",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(size <= 4096);
        assert!(all(&observer).losses.capacity >= 8);
    }

    #[test]
    fn idle_timer_expires_rows_without_publication_or_page_queries() {
        let (directory, _primary, observer) = fixture(Config {
            ttl: Duration::from_secs(1),
            maintenance_interval: Duration::from_millis(10),
            ..Default::default()
        });
        let now = observer.shared.now();
        observer.set_time_for_test(now + 2);
        let before = observer.shared.maintenance_runs.load(Ordering::Acquire);
        let deadline = Instant::now() + Duration::from_secs(3);
        while observer.shared.maintenance_runs.load(Ordering::Acquire) < before + 2 {
            assert!(
                Instant::now() < deadline,
                "idle maintenance timer did not run"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let conn = Connection::open(directory.path().join("observe.sqlite")).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM observer_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let page = all(&observer);
        assert_eq!(page.losses.ttl, 1);
        assert_eq!(page.head, 1);
        assert_eq!(page.floor, 2);
        assert!(page.gaps.iter().any(|gap| gap.reason == "cursor_evicted"));
    }

    #[test]
    fn ttl_clock_backstep_reports_internal_sequence_holes() {
        let (_directory, _primary, observer) = fixture(Config {
            ttl: Duration::from_secs(50),
            ..Default::default()
        });
        let now = observer.shared.now();
        observer.set_time_for_test(now - 100);
        observer.publish(vec![value(2)]);
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        assert_eq!(all(&observer).head, 2);
        observer.set_time_for_test(now);
        observer.publish(vec![value(3)]);
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        for after in [Some(0), Some(1), None] {
            let page = observer
                .page(Query {
                    after,
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(page.losses.ttl, 1);
            assert_eq!(page.head, 3);
            assert_eq!(page.floor, 1);
            assert_eq!(page.events.last().unwrap().sequence, 3);
            assert!(
                page.gaps.iter().any(|gap| gap.reason == "sequence_gap"
                    && !gap.unknown_loss
                    && gap.count == Some(1)),
                "missing persisted sequence2 must be explicit for after={after:?}"
            );
        }
        let tail = observer
            .page(Query {
                limit: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(tail.events[0].sequence, 3);
        assert_eq!(tail.initial_omitted, 1);
        assert!(
            !tail.gaps.iter().any(|gap| gap.reason == "sequence_gap"),
            "intentional initial prefix omission is not a sequence discontinuity in this page"
        );
        let limited = observer
            .page(Query {
                after: Some(0),
                limit: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(limited.events[0].sequence, 1);
        assert!(limited.has_more);
        assert!(
            !limited.gaps.iter().any(|gap| gap.reason == "sequence_gap"),
            "a row outside the returned page must not contribute a gap"
        );
        observer.set_time_for_test(now - 100);
        observer.publish(vec![value(4)]);
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        observer.set_time_for_test(now);
        assert!(observer.maintenance_now_for_test());
        let empty = observer
            .page(Query {
                after: Some(3),
                ..Default::default()
            })
            .unwrap();
        assert!(empty.events.is_empty());
        assert_eq!(empty.head, 4);
        assert_eq!(empty.next, 3);
        assert!(
            empty
                .gaps
                .iter()
                .any(|gap| gap.reason == "sequence_gap" && gap.count == Some(1)),
            "an expired head is still a known persisted sequence gap"
        );
        observer.publish(
            (5..105)
                .map(|index| {
                    let mut event = value(index);
                    event.from = Some("f".repeat(512));
                    event.to = Some("t".repeat(512));
                    event.thread_id = Some("h".repeat(512));
                    event.outcome = Some("o".repeat(512));
                    event.reason = Some("r".repeat(512));
                    event
                })
                .collect(),
        );
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        observer.set_time_for_test(now - 100);
        observer.publish(vec![value(105)]);
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        observer.set_time_for_test(now);
        assert!(observer.maintenance_now_for_test());
        let clamped = observer
            .page(Query {
                after: Some(4),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap();
        assert!(clamped.has_more);
        assert!(clamped.events.len() < 100);
        assert!(
            !clamped.gaps.iter().any(|gap| gap.reason == "sequence_gap"),
            "byte-clamped pages must not count a later expired head"
        );
    }

    #[test]
    fn startup_marker_commit_itself_enforces_row_and_byte_budgets() {
        for config in [
            Config {
                max_rows: 1,
                ..Default::default()
            },
            Config {
                max_bytes: 4096,
                ..Default::default()
            },
        ] {
            let (directory, _primary, observer) = fixture(config.clone());
            let mut first = value(1);
            first.from = Some("f".repeat(512));
            first.to = Some("t".repeat(512));
            first.thread_id = Some("h".repeat(512));
            observer.publish(vec![
                first.clone(),
                Observation {
                    message_id: Some("message-2".into()),
                    ..first
                },
            ]);
            assert!(observer.flush_for_test(Duration::from_secs(3)));
            assert!(observer.set_paused_for_test(true));
            let path = directory.path().join("observe.sqlite");
            let before = all(&observer);
            let (connection, _) =
                open_journal(&path, "test.node", observer.shared.now(), &config).unwrap();
            let (rows, bytes): (i64, i64) = connection
                .query_row(
                    "SELECT count(*),sum(bytes) FROM observer_events",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert!(
                rows <= config.max_rows as i64,
                "startup transaction committed row budget overage: {rows}"
            );
            assert!(
                bytes <= config.max_bytes as i64,
                "startup transaction committed byte budget overage: {bytes}"
            );
            let evicted: i64 = connection
                .query_row(
                    "SELECT capacity FROM observer_meta WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(evicted, before.losses.capacity as i64 + 1);
        }
    }

    #[test]
    fn cursor_pages_bound_rows_bytes_and_preserve_append_order() {
        let (_directory, _primary, observer) = fixture(Config::default());
        for start in [0, 100, 200] {
            observer.publish((start..start + 100).map(value).collect());
            assert!(observer.flush_for_test(Duration::from_secs(3)));
        }
        let tail = observer.page(Query::default()).unwrap();
        assert_eq!(tail.events.len(), 100);
        assert_eq!(tail.initial_omitted, 201);
        assert_eq!(tail.next, tail.head);
        let first = observer
            .page(Query {
                after: Some(0),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(first.events.len(), 200);
        assert!(first.has_more);
        observer.publish(vec![value(300)]);
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        let second = observer
            .page(Query {
                epoch: Some(first.epoch.clone()),
                after: Some(first.next),
                limit: Some(200),
            })
            .unwrap();
        let sequences: Vec<_> = first
            .events
            .iter()
            .chain(&second.events)
            .map(|event| event.sequence)
            .collect();
        assert_eq!(sequences, (1..=302).collect::<Vec<_>>());
        assert!(!second.has_more);
        let empty = observer
            .page(Query {
                epoch: Some(second.epoch),
                after: Some(second.next),
                ..Default::default()
            })
            .unwrap();
        assert!(empty.events.is_empty());
        assert_eq!(empty.next, second.next);
        for index in 0..100 {
            let mut event = value(index + 1000);
            event.from = Some("f".repeat(512));
            event.to = Some("t".repeat(512));
            event.thread_id = Some("h".repeat(512));
            event.outcome = Some("o".repeat(512));
            event.reason = Some("r".repeat(512));
            observer.publish(vec![event]);
        }
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        let bounded = observer
            .page(Query {
                after: Some(302),
                limit: Some(200),
                ..Default::default()
            })
            .unwrap();
        assert!(bounded.events.len() < 100);
        assert!(bounded.has_more);
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= MAX_PAGE_BYTES);
    }

    #[test]
    fn invalid_cursors_and_metadata_are_refused_and_corruption_never_resets_primary() {
        let (directory, primary, observer) = fixture(Config::default());
        for query in [
            Query {
                after: Some(-1),
                ..Default::default()
            },
            Query {
                limit: Some(0),
                ..Default::default()
            },
            Query {
                limit: Some(201),
                ..Default::default()
            },
            Query {
                epoch: Some("x".repeat(129)),
                ..Default::default()
            },
        ] {
            assert!(matches!(observer.page(query), Err(Error::BadQuery)));
        }
        assert!(serde_json::from_value::<Query>(serde_json::json!({"unknown": 1})).is_err());
        assert!(serde_json::from_value::<Query>(serde_json::json!({"after": u64::MAX})).is_err());
        let mut oversized = value(1);
        oversized.message_id = Some("x".repeat(513));
        observer.publish(vec![oversized]);
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        assert_eq!(all(&observer).events.len(), 1);
        assert_eq!(all(&observer).losses.queue, 1);
        let corrupt = directory.path().join("corrupt.sqlite");
        fs::write(&corrupt, b"not SQLite; retain as found").unwrap();
        fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o600)).unwrap();
        let broken = Observer::start(&primary, &corrupt, "test.node", Config::default());
        assert!(!broken.flush_for_test(Duration::from_millis(100)));
        assert!(matches!(
            broken.page(Query::default()),
            Err(Error::Unavailable)
        ));
        assert_eq!(fs::read(corrupt).unwrap(), b"not SQLite; retain as found");
        assert_eq!(
            primary
                .lock()
                .unwrap()
                .query_row("SELECT value FROM unchanged", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "committed"
        );
    }
}
