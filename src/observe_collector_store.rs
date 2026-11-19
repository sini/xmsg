use crate::observe_export::{ExportEvent, ExportGap, ExportPage, ExportSnapshot, Reason, Scope};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

pub type EpochClock = Arc<dyn Fn() -> i64 + Send + Sync>;
const TTL: i64 = 7 * 86400;
const MAX_TIME: i64 = 253_402_300_799;
const ROWS: usize = 10_000;
const BYTES: usize = 16 * 1024 * 1024;
const PAGE_BYTES: usize = 256 * 1024;
/// SQLite engine used for the collector's measured journal bound.
pub const REQUIRED_SQLITE_ENGINE: &str = "3.53.2";
#[derive(Clone, Debug)]
pub struct NodePolicy {
    pub node: String,
    pub labels: bool,
    pub supported: bool,
    pub relay: Option<RelayOrigin>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayOrigin {
    pub hub: String,
    pub leaf: String,
}
impl NodePolicy {
    fn storage_key(&self) -> String {
        match &self.relay {
            Some(origin) => format!(
                "reverse-v1:{}:{}",
                hex::encode(Sha256::digest(origin.hub.as_bytes())),
                hex::encode(Sha256::digest(origin.leaf.as_bytes()))
            ),
            None => self.node.clone(),
        }
    }
    fn origin_hub(&self) -> Option<&str> {
        self.relay.as_ref().map(|r| r.hub.as_str())
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub epoch: Option<String>,
    pub scope: Option<String>,
    pub next: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    HiddenPendingRevalidation,
    Healthy,
    Stale,
    Denied,
    Unsupported,
    StorageFull,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnavailableKind {
    Unreachable,
    Timeout,
    Malformed,
    RateLimited,
    StorageFull,
    Unsupported,
}
#[derive(Clone, Debug)]
pub struct CachedEvent {
    pub origin_hub: Option<String>,
    pub epoch: String,
    pub event: ExportEvent,
    pub received_at: i64,
    pub source_age_seconds: i64,
    pub receipt_age_seconds: i64,
}
#[derive(Clone, Debug)]
pub struct CachedSnapshot {
    pub origin_hub: Option<String>,
    pub snapshot: ExportSnapshot,
    pub received_at: i64,
    pub source_age_seconds: i64,
    pub receipt_age_seconds: i64,
}
#[derive(Clone, Debug)]
pub struct NodeView {
    pub failure: Option<UnavailableKind>,
    pub origin_hub: Option<String>,
    pub history_hidden: bool,
    pub node: String,
    pub status: NodeStatus,
    pub events: Vec<CachedEvent>,
    pub latest_snapshot: Option<CachedSnapshot>,
    pub cursor: Option<Cursor>,
    pub gaps: Vec<ExportGap>,
    pub truncated: bool,
    pub backfill: bool,
}
#[derive(Clone, Debug)]
pub struct CommitOutcome {
    pub cursor: Cursor,
    pub inserted: usize,
    pub scope_changed: bool,
    pub epoch_changed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("invalid observation metadata")]
    Invalid,
    #[error("unknown or unsupported observation node")]
    Node,
    #[error("unsafe observation storage")]
    UnsafePath,
    #[error("observation storage unavailable")]
    Storage,
    #[error("unsupported collector SQLite engine: required {required}, found {found}")]
    UnsupportedEngine {
        required: &'static str,
        found: &'static str,
    },
    #[error("observation storage full")]
    Full,
    #[error("observation cursor changed")]
    Cursor,
}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        if e.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) {
            Self::Full
        } else {
            Self::Storage
        }
    }
}

fn check_engine(found: &'static str) -> Result<(), StoreError> {
    if found != REQUIRED_SQLITE_ENGINE {
        Err(StoreError::UnsupportedEngine {
            required: REQUIRED_SQLITE_ENGINE,
            found,
        })
    } else {
        Ok(())
    }
}
struct NodeState {
    policy: NodePolicy,
    validated: bool,
    status: NodeStatus,
    failure: Option<UnavailableKind>,
}
struct Inner {
    connection: Option<Connection>,
    nodes: BTreeMap<String, NodeState>,
}
pub struct Store {
    inner: Mutex<Inner>,
    clock: EpochClock,
    limits: Limits,
}
#[derive(Clone, Copy)]
struct Limits {
    rows: usize,
    bytes: usize,
    pages: i64,
}
fn valid_time(value: i64) -> bool {
    (0..=MAX_TIME).contains(&value)
}
fn valid_epoch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn valid_scope(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn encoded<T: Serialize>(value: &T, cap: usize) -> Result<Vec<u8>, StoreError> {
    struct Writer {
        data: Vec<u8>,
        cap: usize,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.cap.saturating_sub(self.data.len()) {
                return Err(std::io::Error::other("metadata limit"));
            }
            self.data.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        data: Vec::new(),
        cap,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| StoreError::Invalid)?;
    Ok(writer.data)
}
fn identity(scope: &Scope, value: &str) -> bool {
    scope.canonical_endpoint(value).as_deref() == Some(value)
}
fn correlation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn validate_page(
    policy: &NodePolicy,
    requested: &Cursor,
    page: &ExportPage,
) -> Result<(), StoreError> {
    if page.v != 1
        || page.node != policy.node
        || !valid_epoch(&page.epoch)
        || !valid_scope(&page.scope)
        || page.next < 0
        || page.events.len() > 200
        || page.gaps.len() > 36
        || !page.available
    {
        return Err(StoreError::Invalid);
    }
    encoded(page, PAGE_BYTES)?;
    let scope = Scope::new(&policy.node, "collector", None, policy.labels)
        .map_err(|_| StoreError::Invalid)?;
    let reset = requested.epoch.as_deref().is_some_and(|v| v != page.epoch)
        || requested.scope.as_deref().is_some_and(|v| v != page.scope)
        || page.gaps.iter().any(|g| g.reason == Reason::CursorAhead);
    let after = if reset { 0 } else { requested.next };
    let mut previous = after;
    for event in &page.events {
        if event.sequence <= previous
            || !valid_time(event.observed_at)
            || !valid_time(event.persisted_at)
            || event.source_at.is_some_and(|t| !valid_time(t))
            || event.reply_id.is_some_and(|id| id <= 0)
            || event
                .from
                .as_deref()
                .is_some_and(|id| !identity(&scope, id))
            || event.to.as_deref().is_some_and(|id| !identity(&scope, id))
            || event
                .message_id
                .as_deref()
                .is_some_and(|id| !correlation(id))
            || event
                .thread_id
                .as_deref()
                .is_some_and(|id| !correlation(id))
        {
            return Err(StoreError::Invalid);
        }
        encoded(event, 4096)?;
        previous = event.sequence;
    }
    if page.next < previous || (page.has_more && page.next <= after) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn validate_snapshot(policy: &NodePolicy, snapshot: &ExportSnapshot) -> Result<(), StoreError> {
    if snapshot.v != 1
        || snapshot.node != policy.node
        || !valid_scope(&snapshot.scope)
        || !valid_time(snapshot.observed_at)
        || snapshot.endpoints.len() > 200
    {
        return Err(StoreError::Invalid);
    }
    encoded(snapshot, PAGE_BYTES)?;
    let scope = Scope::new(&policy.node, "collector", None, policy.labels)
        .map_err(|_| StoreError::Invalid)?;
    let mut ids = BTreeSet::new();
    for e in &snapshot.endpoints {
        if !identity(&scope, &e.id)
            || e.id.split_once('@').map(|p| p.1) != Some(e.node.as_str())
            || e.source_at
                .is_some_and(|t| !valid_time(t) || t > snapshot.observed_at)
            || e.label
                .as_ref()
                .is_some_and(|s| !policy.labels || s.len() > 256)
            || !ids.insert(&e.id)
        {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}
fn private_file_metadata(m: &fs::Metadata, expected_uid: u32, cap: u64) -> Result<(), StoreError> {
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.uid() != expected_uid
        || m.mode() & 0o7777 != 0o600
        || m.len() > cap
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}
fn private_file(file: &Path, cap: u64, required: bool) -> Result<(), StoreError> {
    match fs::symlink_metadata(file) {
        Ok(m) => private_file_metadata(&m, unsafe { libc::geteuid() }, cap)?,
        Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(StoreError::UnsafePath),
    }
    Ok(())
}
fn read_cursor(c: &Connection, node: &str) -> Result<Cursor, StoreError> {
    Ok(c.query_row(
        "SELECT epoch,scope,next FROM nodes WHERE node=?1",
        [node],
        |r| {
            Ok(Cursor {
                epoch: r.get(0)?,
                scope: r.get(1)?,
                next: r.get(2)?,
            })
        },
    )?)
}
fn purge(c: &Connection, node: &str) -> Result<(), StoreError> {
    c.execute("DELETE FROM events WHERE node=?1", [node])?;
    c.execute("UPDATE nodes SET epoch=NULL,scope=NULL,next=0,snapshot=NULL,snapshot_receipt=NULL,snapshot_base=NULL,snapshot_fingerprint=NULL,snapshot_origin_hub=NULL,gaps='[]',truncated=1,backfill=1 WHERE node=?1",[node])?;
    Ok(())
}
fn accounted_bytes(c: &Connection, node: &str) -> Result<i64, StoreError> {
    let (metadata,events):(i64,i64)=c.query_row("SELECT coalesce(length(snapshot),0)+coalesce(length(snapshot_fingerprint),0)+coalesce(length(CAST(snapshot_origin_hub AS BLOB)),0)+CASE WHEN node LIKE 'reverse-v1:%' THEN length(node) ELSE 0 END+coalesce(length(epoch),0)+coalesce(length(scope),0)+length(gaps)+192,(SELECT coalesce(sum(bytes),0) FROM events WHERE node=?1) FROM nodes WHERE node=?1",[node],|r|Ok((r.get(0)?,r.get(1)?)))?;
    metadata.checked_add(events).ok_or(StoreError::Full)
}
fn validate_origins(c: &Connection, key: &str, origin: Option<&str>) -> Result<(), StoreError> {
    let invalid: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE node=?1 AND origin_hub IS NOT ?2) OR EXISTS(SELECT 1 FROM nodes WHERE node=?1 AND snapshot IS NOT NULL AND snapshot_origin_hub IS NOT ?2)", params![key, origin], |r| r.get(0))?;
    if invalid {
        Err(StoreError::Storage)
    } else {
        Ok(())
    }
}
fn transaction<T>(
    inner: &mut Inner,
    f: impl FnOnce(&Connection) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let c = inner.connection.as_ref().ok_or(StoreError::Storage)?;
    c.execute_batch("BEGIN IMMEDIATE")?;
    let result = f(c).and_then(|v| {
        c.execute_batch("COMMIT")?;
        Ok(v)
    });
    if result.is_err() && !c.is_autocommit() && c.execute_batch("ROLLBACK").is_err() {
        inner.connection.take();
    }
    result
}
impl Store {
    pub fn open(
        state_dir: &Path,
        nodes: Vec<NodePolicy>,
        clock: EpochClock,
    ) -> Result<Self, StoreError> {
        let pages = (nodes.len() as u64)
            .checked_mul(32 * 1024 * 1024)
            .and_then(|v| v.checked_add(64 * 1024 * 1024))
            .ok_or(StoreError::Invalid)?
            / 4096;
        Self::open_limits(
            state_dir,
            nodes,
            clock,
            Limits {
                rows: ROWS,
                bytes: BYTES,
                pages: i64::try_from(pages).map_err(|_| StoreError::Invalid)?,
            },
        )
    }
    fn open_limits(
        state_dir: &Path,
        nodes: Vec<NodePolicy>,
        clock: EpochClock,
        limits: Limits,
    ) -> Result<Self, StoreError> {
        if nodes.is_empty()
            || nodes.len() > 64
            || limits.rows > ROWS
            || limits.bytes > BYTES
            || limits.pages < 8
        {
            return Err(StoreError::Invalid);
        }
        let mut inventory = BTreeMap::new();
        for policy in nodes {
            Scope::new(&policy.node, "collector", None, policy.labels)
                .map_err(|_| StoreError::Invalid)?;
            if let Some(origin) = &policy.relay {
                if crate::observe_relay::identity_node(&origin.hub).is_none()
                    || crate::observe_relay::identity_node(&origin.leaf).as_deref()
                        != Some(policy.node.as_str())
                    || origin.hub == origin.leaf
                {
                    return Err(StoreError::Invalid);
                }
            }
            let status = if policy.supported {
                NodeStatus::HiddenPendingRevalidation
            } else {
                NodeStatus::Unsupported
            };
            if inventory
                .insert(
                    policy.node.clone(),
                    NodeState {
                        policy,
                        validated: false,
                        status,
                        failure: None,
                    },
                )
                .is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        crate::agent::ensure_secure_socket_dir(state_dir, unsafe { libc::geteuid() })
            .map_err(|_| StoreError::UnsafePath)?;
        let m = fs::symlink_metadata(state_dir).map_err(|_| StoreError::UnsafePath)?;
        if m.mode() & 0o7777 != 0o700 {
            return Err(StoreError::UnsafePath);
        }
        let db = state_dir.join("collector.sqlite");
        let journal = state_dir.join("collector.sqlite-journal");
        let db_cap = (limits.pages as u64)
            .checked_mul(4096)
            .ok_or(StoreError::Invalid)?;
        let journal_cap = (limits.pages as u64)
            .checked_mul(4104)
            .and_then(|v| v.checked_add(131072))
            .ok_or(StoreError::Invalid)?;
        private_file(&db, db_cap, false)?;
        private_file(&journal, journal_cap, false)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&db)
            .map_err(|_| StoreError::UnsafePath)?;
        private_file(&db, db_cap, true)?;
        let c = Connection::open_with_flags(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        drop(file);
        c.execute_batch("PRAGMA page_size=4096; PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_spill=OFF; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=ON;")?;
        c.pragma_update(None, "max_page_count", limits.pages)?;
        for (name, expected) in [
            ("page_size", 4096),
            ("synchronous", 2),
            ("cache_spill", 0),
            ("auto_vacuum", 2),
            ("secure_delete", 1),
            ("temp_store", 2),
            ("max_page_count", limits.pages),
        ] {
            let value: i64 = c.pragma_query_value(None, name, |r| r.get(0))?;
            if value != expected {
                return Err(StoreError::Storage);
            }
        }
        let mode: String = c.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        if mode != "delete" {
            return Err(StoreError::Storage);
        }
        check_engine(rusqlite::version())?;
        c.execute_batch("CREATE TABLE IF NOT EXISTS nodes(node TEXT PRIMARY KEY,epoch TEXT,scope TEXT,next INTEGER NOT NULL DEFAULT 0,snapshot BLOB,snapshot_receipt INTEGER,snapshot_base INTEGER,snapshot_fingerprint BLOB,gaps TEXT NOT NULL DEFAULT '[]',truncated INTEGER NOT NULL DEFAULT 0,backfill INTEGER NOT NULL DEFAULT 1); CREATE TABLE IF NOT EXISTS events(node TEXT NOT NULL,epoch TEXT NOT NULL,sequence INTEGER NOT NULL,json BLOB NOT NULL,receipt INTEGER NOT NULL,base INTEGER NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(node,epoch,sequence)); CREATE INDEX IF NOT EXISTS retention ON events(node,base,receipt,epoch,sequence);")?;
        c.execute_batch("BEGIN IMMEDIATE")?;
        let migration = (|| -> Result<(), StoreError> {
            for (table, column) in [("events", "origin_hub"), ("nodes", "snapshot_origin_hub")] {
                let columns = c
                    .prepare(&format!("PRAGMA table_info({table})"))?
                    .query_map([], |r| r.get::<_, String>(1))?
                    .collect::<Result<Vec<_>, _>>()?;
                if !columns.iter().any(|name| name == column) {
                    c.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} TEXT"))?;
                }
            }
            c.execute_batch("COMMIT")?;
            Ok(())
        })();
        if migration.is_err() {
            let _ = c.execute_batch("ROLLBACK");
        }
        migration?;
        c.prepare("SELECT snapshot_fingerprint FROM nodes LIMIT 0")?;
        let persisted = c
            .prepare("SELECT node FROM nodes ORDER BY node LIMIT 65")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        // a valid previous inventory has at most 64 rows, including removed nodes.
        if persisted.len() > 64 {
            return Err(StoreError::Storage);
        }
        let mut inner = Inner {
            connection: Some(c),
            nodes: inventory,
        };
        let configured: BTreeSet<String> = inner
            .nodes
            .values()
            .map(|s| s.policy.storage_key())
            .collect();
        for node in persisted {
            if !configured.contains(&node) {
                transaction(&mut inner, |c| {
                    c.execute("DELETE FROM events WHERE node=?1", [&node])?;
                    c.execute("DELETE FROM nodes WHERE node=?1", [&node])?;
                    Ok(())
                })?;
            }
        }
        for node in configured {
            transaction(&mut inner, |c| {
                c.execute("INSERT OR IGNORE INTO nodes(node) VALUES(?1)", [node])?;
                Ok(())
            })?;
        }
        let store = Self {
            inner: Mutex::new(inner),
            clock,
            limits,
        };
        store.maintain()?;
        Ok(store)
    }
    fn lock(&self) -> Result<MutexGuard<'_, Inner>, StoreError> {
        self.inner.lock().map_err(|_| StoreError::Storage)
    }
    pub fn epoch_now(&self) -> i64 {
        (self.clock)()
    }
    fn now(&self) -> Result<i64, StoreError> {
        let now = (self.clock)();
        if valid_time(now) {
            Ok(now)
        } else {
            Err(StoreError::Invalid)
        }
    }
    pub fn cursor(&self, node: &str) -> Result<Cursor, StoreError> {
        let inner = self.lock()?;
        let key = Self::policy(&inner, node)?.storage_key();
        read_cursor(inner.connection.as_ref().ok_or(StoreError::Storage)?, &key)
    }
    fn policy<'a>(inner: &'a Inner, node: &str) -> Result<&'a NodePolicy, StoreError> {
        inner
            .nodes
            .get(node)
            .filter(|s| s.policy.supported)
            .map(|s| &s.policy)
            .ok_or(StoreError::Node)
    }
    pub fn ingest_page(
        &self,
        node: &str,
        requested: &Cursor,
        page: ExportPage,
    ) -> Result<CommitOutcome, StoreError> {
        let decoded = crate::observe_collector_decode::from_typed_page(page)
            .map_err(|_| StoreError::Invalid)?;
        self.ingest_decoded_page(node, requested, decoded)
    }

    pub(crate) fn ingest_decoded_page(
        &self,
        node: &str,
        requested: &Cursor,
        decoded: crate::observe_collector_decode::DecodedPage,
    ) -> Result<CommitOutcome, StoreError> {
        if decoded.canonical_len > PAGE_BYTES || decoded.events.len() != decoded.page.events.len() {
            return Err(StoreError::Invalid);
        }
        let page = decoded.page;
        let now = self.now()?;
        let mut inner = self.lock()?;
        validate_page(Self::policy(&inner, node)?, requested, &page)?;
        let policy = Self::policy(&inner, node)?.clone();
        let key = policy.storage_key();
        let origin = policy.origin_hub();
        let old = read_cursor(inner.connection.as_ref().ok_or(StoreError::Storage)?, &key)?;
        if old != *requested {
            return Err(StoreError::Cursor);
        }
        let scope_changed = old.scope.as_deref().is_some_and(|s| s != page.scope);
        let epoch_changed = old.epoch.as_deref().is_some_and(|e| e != page.epoch);
        if scope_changed {
            let state = inner.nodes.get_mut(node).ok_or(StoreError::Node)?;
            state.validated = false;
            state.status = NodeStatus::HiddenPendingRevalidation;
        }
        validate_origins(
            inner.connection.as_ref().ok_or(StoreError::Storage)?,
            &key,
            origin,
        )?;
        let result = transaction(&mut inner, |c| {
            let node = key.as_str();
            if scope_changed {
                purge(c, node)?;
            }
            let mut inserted = 0;
            for (event, original) in page.events.iter().zip(&decoded.events) {
                let json = &original.canonical;
                let existing: Option<Vec<u8>> = c
                    .query_row(
                        "SELECT json FROM events WHERE node=?1 AND epoch=?2 AND sequence=?3",
                        params![node, page.epoch, event.sequence],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(old) = existing {
                    let previous = crate::observe_collector_decode::decode_event(&old)
                        .map_err(|_| StoreError::Storage)?;
                    if previous.canonical != *json {
                        return Err(StoreError::Invalid);
                    }
                }
                inserted += c.execute("INSERT OR IGNORE INTO events(node,epoch,sequence,json,receipt,base,bytes,origin_hub) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![node,page.epoch,event.sequence,json,now,event.observed_at.min(now),(json.len()+page.epoch.len()+node.len()+128+origin.map_or(0,str::len)) as i64,origin])?;
            }
            let old_gaps: Vec<u8> = c.query_row(
                "SELECT CAST(gaps AS BLOB) FROM nodes WHERE node=?1",
                [node],
                |r| r.get(0),
            )?;
            let mut gaps: Vec<ExportGap> =
                serde_json::from_slice(&old_gaps).map_err(|_| StoreError::Storage)?;
            for gap in page
                .gaps
                .iter()
                .cloned()
                .chain(epoch_changed.then_some(ExportGap {
                    reason: Reason::EpochChanged,
                    unknown_loss: false,
                }))
            {
                if !gaps.contains(&gap) {
                    gaps.push(gap);
                }
            }
            c.execute(
                "UPDATE nodes SET epoch=?2,scope=?3,next=?4,gaps=?5,backfill=?6 WHERE node=?1",
                params![
                    node,
                    page.epoch,
                    page.scope,
                    page.next,
                    encoded(&gaps, 4096)?,
                    page.has_more
                ],
            )?;
            self.retain(c, node, now)?;
            Ok(CommitOutcome {
                cursor: Cursor {
                    epoch: Some(page.epoch.clone()),
                    scope: Some(page.scope.clone()),
                    next: page.next,
                },
                inserted,
                scope_changed,
                epoch_changed,
            })
        });
        self.finish(&mut inner, node, &result);
        result
    }
    fn finish<T>(&self, inner: &mut Inner, node: &str, result: &Result<T, StoreError>) {
        if let Some(state) = inner.nodes.get_mut(node) {
            if result.is_ok() {
                state.validated = true;
                state.status = NodeStatus::Healthy;
                state.failure = None;
            } else if matches!(result, Err(StoreError::Full)) {
                state.status = NodeStatus::StorageFull;
            }
        }
    }
    pub fn ingest_snapshot(
        &self,
        node: &str,
        snapshot: ExportSnapshot,
    ) -> Result<CommitOutcome, StoreError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        validate_snapshot(Self::policy(&inner, node)?, &snapshot)?;
        let bytes = encoded(&snapshot, PAGE_BYTES)?;
        let fingerprint = Sha256::digest(&bytes).to_vec();
        let policy = Self::policy(&inner, node)?.clone();
        let key = policy.storage_key();
        let origin = policy.origin_hub();
        let old = read_cursor(inner.connection.as_ref().ok_or(StoreError::Storage)?, &key)?;
        let scope_changed = old.scope.as_deref().is_some_and(|s| s != snapshot.scope);
        if scope_changed {
            let s = inner.nodes.get_mut(node).ok_or(StoreError::Node)?;
            s.validated = false;
            s.status = NodeStatus::HiddenPendingRevalidation;
        }
        validate_origins(
            inner.connection.as_ref().ok_or(StoreError::Storage)?,
            &key,
            origin,
        )?;
        let result = transaction(&mut inner, |c| {
            let node = key.as_str();
            if scope_changed {
                purge(c, node)?;
            }
            let (old_fingerprint,old_receipt,old_base):(Option<Vec<u8>>,Option<i64>,Option<i64>)=c.query_row("SELECT snapshot_fingerprint,snapshot_receipt,snapshot_base FROM nodes WHERE node=?1",[node],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            // retain first capture age even after the snapshot blob expires or is evicted.
            let (receipt, base) = if old_fingerprint.as_ref() == Some(&fingerprint) {
                (
                    old_receipt.ok_or(StoreError::Storage)?,
                    old_base.ok_or(StoreError::Storage)?,
                )
            } else {
                (now, snapshot.observed_at.min(now))
            };
            c.execute("UPDATE nodes SET scope=?2,snapshot=?3,snapshot_receipt=?4,snapshot_base=?5,snapshot_fingerprint=?6,snapshot_origin_hub=?7 WHERE node=?1",params![node,snapshot.scope,bytes,receipt,base,fingerprint,origin])?;
            self.retain(c, node, now)?;
            Ok(CommitOutcome {
                cursor: read_cursor(c, node)?,
                inserted: 0,
                scope_changed,
                epoch_changed: false,
            })
        });
        self.finish(&mut inner, node, &result);
        result
    }
    pub fn deny(&self, node: &str) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let key = Self::policy(&inner, node)?.storage_key();
        let state = inner.nodes.get_mut(node).ok_or(StoreError::Node)?;
        state.validated = false;
        state.status = NodeStatus::Denied;
        transaction(&mut inner, |c| purge(c, &key))
    }
    pub fn unavailable(&self, node: &str, kind: UnavailableKind) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let state = inner.nodes.get_mut(node).ok_or(StoreError::Node)?;
        if state.policy.supported {
            state.failure = Some(kind);
            if kind == UnavailableKind::Unsupported {
                state.status = NodeStatus::Unsupported;
            } else if state.validated || kind == UnavailableKind::StorageFull {
                state.status = if kind == UnavailableKind::StorageFull {
                    NodeStatus::StorageFull
                } else {
                    NodeStatus::Stale
                };
            }
        }
        Ok(())
    }
    fn retain(&self, c: &Connection, node: &str, now: i64) -> Result<(), StoreError> {
        let cutoff = now.checked_sub(TTL).ok_or(StoreError::Invalid)?;
        let mut removed = c.execute(
            "DELETE FROM events WHERE node=?1 AND base<?2",
            params![node, cutoff],
        )?;
        removed += c.execute("UPDATE nodes SET snapshot=NULL WHERE node=?1 AND snapshot IS NOT NULL AND snapshot_base<?2",params![node,cutoff])?;
        let rows: i64 = c.query_row("SELECT count(*) FROM events WHERE node=?1", [node], |r| {
            r.get(0)
        })?;
        if rows > self.limits.rows as i64 {
            removed += c.execute("DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE node=?1 ORDER BY base,receipt,epoch,sequence LIMIT ?2)",params![node,rows-self.limits.rows as i64])?;
        }
        let mut total = accounted_bytes(c, node)?;
        if total > self.limits.bytes as i64 {
            let mut statement = c.prepare("SELECT rowid,bytes FROM events WHERE node=?1 ORDER BY base,receipt,epoch,sequence LIMIT 10200")?;
            let rows = statement
                .query_map([node], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            for (rowid, bytes) in rows {
                if total <= self.limits.bytes as i64 {
                    break;
                }
                removed += c.execute("DELETE FROM events WHERE rowid=?1", [rowid])?;
                total = total.saturating_sub(bytes);
            }
            if total > self.limits.bytes as i64 {
                removed += c.execute(
                    "UPDATE nodes SET snapshot=NULL WHERE node=?1 AND snapshot IS NOT NULL",
                    [node],
                )?;
            }
        }
        if accounted_bytes(c, node)? > self.limits.bytes as i64 {
            return Err(StoreError::Full);
        }
        if removed > 0 {
            c.execute("UPDATE nodes SET truncated=1 WHERE node=?1", [node])?;
        }
        Ok(())
    }
    pub fn maintain(&self) -> Result<(), StoreError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        let nodes: Vec<String> = inner
            .nodes
            .values()
            .map(|s| s.policy.storage_key())
            .collect();
        for node in nodes {
            transaction(&mut inner, |c| self.retain(c, &node, now))?;
        }
        transaction(&mut inner, |c| {
            c.execute_batch("PRAGMA incremental_vacuum(64)")?;
            Ok(())
        })?;
        Ok(())
    }
    pub fn view(&self, node: Option<&str>, limit: usize) -> Result<Vec<NodeView>, StoreError> {
        let now = self.now()?;
        let cutoff = now.checked_sub(TTL).ok_or(StoreError::Invalid)?;
        let inner = self.lock()?;
        let c = inner.connection.as_ref().ok_or(StoreError::Storage)?;
        let mut views = Vec::new();
        for (name, state) in &inner.nodes {
            if node.is_some_and(|n| n != name) {
                continue;
            }
            let key = state.policy.storage_key();
            let origin = state.policy.origin_hub();
            let mut v = NodeView {
                failure: state.failure,
                origin_hub: origin.map(str::to_owned),
                history_hidden: !state.validated,
                node: name.clone(),
                status: state.status,
                events: Vec::new(),
                latest_snapshot: None,
                cursor: None,
                gaps: Vec::new(),
                truncated: false,
                backfill: false,
            };
            if state.validated {
                let name = key.as_str();
                validate_origins(c, name, origin)?;
                v.cursor = Some(read_cursor(c, name)?);
                let (snapshot,receipt,gaps,truncated,backfill,snapshot_origin)=c.query_row("SELECT CASE WHEN snapshot_base>=?2 THEN snapshot END,CASE WHEN snapshot_base>=?2 THEN snapshot_receipt END,CAST(gaps AS BLOB),truncated,backfill,snapshot_origin_hub FROM nodes WHERE node=?1",params![name,cutoff],|r|Ok((r.get::<_,Option<Vec<u8>>>(0)?,r.get::<_,Option<i64>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,bool>(3)?,r.get::<_,bool>(4)?,r.get::<_,Option<String>>(5)?)))?;
                v.gaps = serde_json::from_slice(&gaps).map_err(|_| StoreError::Storage)?;
                v.truncated = truncated;
                v.truncated |= c.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE node=?1 AND base<?3) OR (SELECT count(*) FROM events WHERE node=?1 AND base>=?3)>?2 OR EXISTS(SELECT 1 FROM nodes WHERE node=?1 AND snapshot_base<?3)",params![name,limit.min(ROWS) as i64,cutoff],|r|r.get::<_,bool>(0))?;
                v.backfill = backfill;
                if let (Some(bytes), Some(received_at)) = (snapshot, receipt) {
                    let snapshot: ExportSnapshot =
                        serde_json::from_slice(&bytes).map_err(|_| StoreError::Storage)?;
                    v.latest_snapshot = Some(CachedSnapshot {
                        origin_hub: snapshot_origin,
                        source_age_seconds: now.saturating_sub(snapshot.observed_at).max(0),
                        receipt_age_seconds: now.saturating_sub(received_at).max(0),
                        snapshot,
                        received_at,
                    });
                }
                let mut statement=c.prepare("SELECT epoch,json,receipt,origin_hub FROM events WHERE node=?1 AND base>=?3 ORDER BY receipt DESC,epoch DESC,sequence DESC LIMIT ?2")?;
                let events =
                    statement.query_map(params![name, limit.min(ROWS) as i64, cutoff], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, i64>(2)?,
                            r.get::<_, Option<String>>(3)?,
                        ))
                    })?;
                for e in events {
                    let (epoch, json, received_at, event_origin) = e?;
                    let event = crate::observe_collector_decode::decode_event(&json)
                        .map_err(|_| StoreError::Storage)?
                        .event;
                    v.events.push(CachedEvent {
                        origin_hub: event_origin,
                        epoch,
                        source_age_seconds: now.saturating_sub(event.observed_at).max(0),
                        receipt_age_seconds: now.saturating_sub(received_at).max(0),
                        event,
                        received_at,
                    });
                }
            }
            views.push(v);
        }
        Ok(views)
    }
}
#[cfg(test)]
#[path = "observe_collector_store_tests.rs"]
mod tests;
