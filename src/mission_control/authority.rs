use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io,
    net::{Shutdown, TcpStream},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthorityError {
    #[error("invalid authority request or configuration")]
    Invalid,
    #[error("authority request refused")]
    Denied,
    #[error("authority principal no longer entitled")]
    Forbidden,
    #[error("authority lock held")]
    Busy,
    #[error("authority storage unavailable")]
    Storage,
}

impl From<rusqlite::Error> for AuthorityError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

type Result<T> = std::result::Result<T, AuthorityError>;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AuthorityConfig {
    pub allowlist: Vec<String>,
    pub nodes: Vec<String>,
    pub session_idle_secs: u64,
    pub session_absolute_secs: u64,
    pub native_idle_secs: u64,
    pub native_absolute_secs: u64,
    pub machine_token_default_secs: u64,
    pub machine_token_max_secs: u64,
    pub delegated_grant_max_secs: u64,
    pub revocation_slo_ms: u64,
    pub authority_watchdog_ms: u64,
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            nodes: Vec::new(),
            session_idle_secs: 604_800,
            session_absolute_secs: 2_592_000,
            native_idle_secs: 2_592_000,
            native_absolute_secs: 7_776_000,
            machine_token_default_secs: 7_776_000,
            machine_token_max_secs: 31_536_000,
            delegated_grant_max_secs: 7_776_000,
            revocation_slo_ms: 1_000,
            authority_watchdog_ms: 250,
        }
    }
}

impl AuthorityConfig {
    fn validate(&self) -> Result<()> {
        if self.session_idle_secs == 0
            || self.session_absolute_secs < self.session_idle_secs
            || self.native_idle_secs == 0
            || self.native_absolute_secs < self.native_idle_secs
            || self.machine_token_default_secs == 0
            || self.machine_token_max_secs < self.machine_token_default_secs
            || self.delegated_grant_max_secs == 0
            || self.authority_watchdog_ms == 0
            || self.authority_watchdog_ms.saturating_mul(2) >= self.revocation_slo_ms
            || self.revocation_slo_ms > 86_400_000
            || self.allowlist.iter().any(|email| !bounded(email, 320))
            || self.nodes.iter().any(|node| !valid_node(node))
        {
            return Err(AuthorityError::Invalid);
        }
        for seconds in [
            self.session_absolute_secs,
            self.native_absolute_secs,
            self.machine_token_max_secs,
            self.delegated_grant_max_secs,
        ] {
            if seconds > i64::MAX as u64 / 2 {
                return Err(AuthorityError::Invalid);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Class {
    Browser,
    Native,
    Machine,
    Delegated,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Carrier {
    Cookie,
    #[allow(dead_code, reason = "Mission Control transport carrier")]
    Bearer,
}

impl Class {
    pub(super) fn matches_carrier(self, carrier: Carrier) -> bool {
        (self == Self::Browser) == (carrier == Carrier::Cookie)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Scope {
    Fleet,
    Node { node: String },
    Session { node: String, endpoint: String },
    Attention,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub node: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DelegatedGrant {
    pub holder: String,
    pub verbs: Vec<String>,
    pub targets: Vec<Target>,
    pub presenter: Option<String>,
    pub expires_at: i64,
    pub rate: u32,
    pub read_scope: Option<Vec<Scope>>,
    #[serde(default)]
    pub confirm_verbs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Grants {
    Owner,
    Machine {
        name: String,
        scope: Vec<Scope>,
        rate: u32,
    },
    Delegated {
        grant: DelegatedGrant,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub record_id: String,
    pub class: Class,
    pub session_id: String,
    pub principal: String,
    pub on_behalf_of: Option<String>,
    pub parent_record: Option<String>,
    pub grants: Grants,
    pub policy_generation: i64,
    pub created_at: i64,
    pub last_used_at: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
    pub revoked: bool,
}

pub(crate) struct Issued {
    pub handle: String,
    pub record: Record,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Audit {
    pub at: i64,
    pub action: String,
    pub principal: Option<String>,
    pub record_id: Option<String>,
}

pub(crate) struct Refresh {
    pub encrypted: Vec<u8>,
    pub checked_at: i64,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs().min(i64::MAX as u64) as i64)
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

pub(super) fn valid_node(node: &str) -> bool {
    !node.is_empty()
        && node.len() <= 128
        && node
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

pub(super) fn valid_endpoint(node: &str, endpoint: &str) -> bool {
    if !valid_node(node) || endpoint.len() > 512 {
        return false;
    }
    endpoint.rsplit_once('@').is_some_and(|(key, suffix)| {
        suffix == node
            && if let Some((_, child)) = crate::client::split_subaddress(key) {
                crate::claim::validate_subagent_id(child).is_ok_and(|checked| checked == child)
            } else {
                crate::client::is_instance_ref(key)
                    || crate::client::validate_service_name(key).is_ok()
            }
    })
}

fn opaque() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthorityError::Storage)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn handle_digest(handle: &str) -> Result<[u8; 32]> {
    if handle.len() != 43
        || URL_SAFE_NO_PAD
            .decode(handle)
            .map_or(true, |decoded| decoded.len() != 32)
    {
        return Err(AuthorityError::Denied);
    }
    Ok(Sha256::digest(handle.as_bytes()).into())
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| AuthorityError::Storage)
}

fn decode<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| AuthorityError::Storage)
}

fn private_file(name: &Path, create: bool) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(name);
    let file = match file {
        Ok(file) => file,
        Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AuthorityError::Storage),
    };
    let metadata = file.metadata().map_err(|_| AuthorityError::Storage)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(AuthorityError::Storage);
    }
    Ok(Some(file))
}

fn authority_lock(dir: &Path) -> Result<File> {
    let uid = unsafe { libc::geteuid() };
    crate::agent::ensure_secure_socket_dir(dir, uid).map_err(|_| AuthorityError::Storage)?;
    let metadata = fs::symlink_metadata(dir).map_err(|_| AuthorityError::Storage)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(AuthorityError::Storage);
    }
    let file = private_file(&dir.join("authority.lock"), true)?.ok_or(AuthorityError::Storage)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(match io::Error::last_os_error().kind() {
            io::ErrorKind::WouldBlock => AuthorityError::Busy,
            _ => AuthorityError::Storage,
        });
    }
    Ok(file)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY CHECK(id = 1), generation INTEGER NOT NULL, allowlist TEXT NOT NULL,
    nodes TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS owners (
    principal TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, issuer TEXT NOT NULL,
    subject TEXT NOT NULL, entitled INTEGER NOT NULL, UNIQUE(issuer, subject)
);
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY, digest BLOB UNIQUE NOT NULL, record TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    owner TEXT PRIMARY KEY REFERENCES owners(principal), ciphertext BLOB NOT NULL,
    checked_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL, action TEXT NOT NULL,
    principal TEXT, record_id TEXT
);
";

struct Stored {
    digest: [u8; 32],
    record: Record,
}

struct State {
    conn: Connection,
    generation: i64,
    records: HashMap<String, Stored>,
    by_digest: HashMap<[u8; 32], String>,
    #[cfg(test)]
    suppress_push: bool,
    #[cfg(test)]
    last_revoke: Option<(i64, Instant)>,
    masked_nodes: HashSet<String>,
    live: HashMap<u64, Registration>,
    #[allow(dead_code, reason = "Mission Control transport registry")]
    next_live_id: u64,
}

pub(crate) struct Authority {
    state: Mutex<State>,
    config: AuthorityConfig,
    allowlist: HashSet<String>,
    _lock: File,
}

fn audit(
    tx: &Transaction<'_>,
    at: i64,
    action: &str,
    principal: Option<&str>,
    record_id: Option<&str>,
) -> Result<()> {
    tx.execute(
        "INSERT INTO audit(at, action, principal, record_id) VALUES (?1, ?2, ?3, ?4)",
        params![at, action, principal, record_id],
    )?;
    Ok(())
}

fn persist_record(tx: &Transaction<'_>, digest: &[u8; 32], record: &Record) -> Result<()> {
    let changed = tx.execute(
        "UPDATE records SET record=?3 WHERE id=?1 AND digest=?2",
        params![record.record_id, digest.as_slice(), encode(record)?],
    )?;
    if changed != 1 {
        return Err(AuthorityError::Storage);
    }
    Ok(())
}

fn affected(record: &Record, principal: &str) -> bool {
    record.principal == principal || record.on_behalf_of.as_deref() == Some(principal)
}

fn owner_for(record: &Record) -> &str {
    record.on_behalf_of.as_deref().unwrap_or(&record.principal)
}

fn entitled(conn: &Connection, owner: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM owners WHERE principal = ?1 AND entitled = 1)",
        [owner],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

fn generation_after(generation: i64) -> Result<i64> {
    generation.checked_add(1).ok_or(AuthorityError::Storage)
}

fn set_generation(tx: &Transaction<'_>, generation: i64) -> Result<()> {
    tx.execute(
        "UPDATE metadata SET generation = ?1 WHERE id = 1",
        [generation],
    )?;
    Ok(())
}

impl Authority {
    pub(crate) fn open(state_dir: &Path, config: AuthorityConfig) -> Result<Arc<Self>> {
        Self::open_with_config(state_dir, || Ok(config))
    }

    pub(crate) fn open_with_config(
        state_dir: &Path,
        config: impl FnOnce() -> Result<AuthorityConfig>,
    ) -> Result<Arc<Self>> {
        let lock = authority_lock(state_dir)?;
        let mut config = config()?;
        config.validate()?;
        config.allowlist.sort_unstable();
        config.allowlist.dedup();
        config.nodes.sort_unstable();
        config.nodes.dedup();
        let path = state_dir.join("authority.sqlite");
        let file = private_file(&path, true)?;
        for suffix in [
            "authority.sqlite-journal",
            "authority.sqlite-wal",
            "authority.sqlite-shm",
        ] {
            private_file(&state_dir.join(suffix), false)?;
        }
        let mut conn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        drop(file);
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
             PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;",
        )?;
        conn.execute_batch(SCHEMA)?;
        let mut records = HashMap::new();
        let mut by_digest = HashMap::new();
        {
            let mut stmt = conn.prepare("SELECT id, digest, record FROM records")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (id, digest, serialized) = row?;
                let record: Record = decode(&serialized)?;
                let digest = digest.try_into().map_err(|_| AuthorityError::Storage)?;
                if record.record_id != id {
                    return Err(AuthorityError::Storage);
                }
                by_digest.insert(digest, id.clone());
                records.insert(id, Stored { digest, record });
            }
        }
        let allowlist = config.allowlist.iter().cloned().collect::<HashSet<_>>();
        let tx = conn.transaction()?;
        let configured = (encode(&config.allowlist)?, encode(&config.nodes)?);
        let existing: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT generation, allowlist, nodes FROM metadata WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let mut generation = match existing {
            None => {
                tx.execute(
                    "INSERT INTO metadata VALUES (1, 0, ?1, ?2)",
                    params![configured.0, configured.1],
                )?;
                0
            }
            Some((value, ref previous_allowlist, ref previous_nodes))
                if previous_allowlist != &configured.0 || previous_nodes != &configured.1 =>
            {
                let next = generation_after(value)?;
                tx.execute(
                    "UPDATE metadata SET generation=?1, allowlist=?2, nodes=?3 WHERE id=1",
                    params![next, configured.0, configured.1],
                )?;
                audit(&tx, now(), "configured_policy_changed", None, None)?;
                next
            }
            Some((value, _, _)) => value,
        };
        let removed = {
            let mut stmt = tx.prepare("SELECT principal, email FROM owners WHERE entitled = 1")?;
            let mut rows = stmt.query([])?;
            let mut removed = Vec::new();
            while let Some(row) = rows.next()? {
                let email: String = row.get(1)?;
                if !allowlist.contains(&email) {
                    removed.push(row.get::<_, String>(0)?);
                }
            }
            removed
        };
        if !removed.is_empty() {
            generation = generation_after(generation)?;
            set_generation(&tx, generation)?;
        }
        for principal in removed {
            tx.execute(
                "UPDATE owners SET entitled=0 WHERE principal=?1",
                [&principal],
            )?;
            tx.execute("DELETE FROM refresh_tokens WHERE owner=?1", [&principal])?;
            for entry in records.values_mut() {
                if affected(&entry.record, &principal) && !entry.record.revoked {
                    entry.record.revoked = true;
                    persist_record(&tx, &entry.digest, &entry.record)?;
                }
            }
            audit(&tx, now(), "owner_removed", Some(&principal), None)?;
        }
        tx.commit()?;
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                conn,
                generation,
                records,
                by_digest,
                #[cfg(test)]
                suppress_push: false,
                #[cfg(test)]
                last_revoke: None,
                masked_nodes: HashSet::new(),
                live: HashMap::new(),
                next_live_id: 0,
            }),
            config,
            allowlist,
            _lock: lock,
        }))
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| AuthorityError::Storage)
    }
}

struct NewRecord {
    class: Class,
    parent_record: Option<String>,
    grants: Grants,
    idle: i64,
    absolute: i64,
}

fn issue(
    tx: &Transaction<'_>,
    owner: &str,
    generation: i64,
    at: i64,
    new: NewRecord,
) -> Result<(Issued, [u8; 32])> {
    let attributed = matches!(new.class, Class::Machine | Class::Delegated);
    let record = Record {
        record_id: opaque()?,
        class: new.class,
        session_id: opaque()?,
        principal: if attributed { opaque()? } else { owner.into() },
        on_behalf_of: attributed.then(|| owner.into()),
        parent_record: new.parent_record,
        grants: new.grants,
        policy_generation: generation,
        created_at: at,
        last_used_at: at,
        idle_expires_at: new.idle,
        absolute_expires_at: new.absolute,
        revoked: false,
    };
    let handle = opaque()?;
    let digest = handle_digest(&handle)?;
    tx.execute(
        "INSERT INTO records(id, digest, record) VALUES (?1, ?2, ?3)",
        params![record.record_id, digest.as_slice(), encode(&record)?],
    )?;
    audit(tx, at, "issue", Some(owner), Some(&record.record_id))?;
    Ok((Issued { handle, record }, digest))
}

impl State {
    fn install(&mut self, (issued, digest): (Issued, [u8; 32])) -> Issued {
        let record = issued.record.clone();
        let id = record.record_id.clone();
        self.by_digest.insert(digest, id.clone());
        self.records.insert(id, Stored { digest, record });
        issued
    }
}

impl Authority {
    pub(crate) fn login(
        &self,
        email: &str,
        iss: &str,
        sub: &str,
        refresh: Option<&[u8]>,
    ) -> Result<Issued> {
        self.login_at(email, iss, sub, refresh, now())
    }

    fn login_at(
        &self,
        email: &str,
        iss: &str,
        sub: &str,
        refresh: Option<&[u8]>,
        at: i64,
    ) -> Result<Issued> {
        if !bounded(email, 320) || !bounded(iss, 2_048) || !bounded(sub, 512) {
            return Err(AuthorityError::Denied);
        }
        let mut state = self.locked()?;
        let mut generation = state.generation;
        let tx = state.conn.transaction()?;
        let bound: Option<(String, String, bool)> = tx
            .query_row(
                "SELECT principal, email, entitled FROM owners WHERE issuer=?1 AND subject=?2",
                params![iss, sub],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let owner = if let Some((principal, original_email, was_entitled)) = bound {
            if !self.allowlist.contains(&original_email) {
                audit(&tx, at, "login_refused", Some(&principal), None)?;
                tx.commit()?;
                return Err(AuthorityError::Denied);
            }
            if !was_entitled {
                tx.execute(
                    "UPDATE owners SET entitled=1 WHERE principal=?1",
                    [&principal],
                )?;
                generation = generation_after(generation)?;
                set_generation(&tx, generation)?;
                audit(&tx, at, "owner_restored", Some(&principal), None)?;
            }
            principal
        } else {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT principal FROM owners WHERE email=?1",
                    [email],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.is_some() || !self.allowlist.contains(email) {
                audit(&tx, at, "login_refused", existing.as_deref(), None)?;
                tx.commit()?;
                return Err(AuthorityError::Denied);
            }
            let principal = opaque()?;
            tx.execute(
                "INSERT INTO owners VALUES (?1, ?2, ?3, ?4, 1)",
                params![principal, email, iss, sub],
            )?;
            generation = generation_after(generation)?;
            set_generation(&tx, generation)?;
            audit(&tx, at, "owner_bound", Some(&principal), None)?;
            principal
        };
        if let Some(refresh) = refresh {
            save_refresh(&tx, &owner, refresh, at)?;
        }
        let issued = issue(
            &tx,
            &owner,
            generation,
            at,
            NewRecord {
                class: Class::Browser,
                parent_record: None,
                grants: Grants::Owner,
                idle: at.saturating_add(self.config.session_idle_secs as i64),
                absolute: at.saturating_add(self.config.session_absolute_secs as i64),
            },
        )?;
        tx.commit()?;
        let change = Instant::now();
        state.set_generation(generation, change, self.cutoff());
        Ok(state.install(issued))
    }

    pub(crate) fn issue_native(&self, parent: &str) -> Result<Issued> {
        let at = now();
        let mut state = self.locked()?;
        let owner = state
            .records
            .get(parent)
            .map(|entry| &entry.record)
            .filter(|record| record.class == Class::Browser && fresh(record, at))
            .ok_or(AuthorityError::Denied)?
            .principal
            .clone();
        self.issue_for_owner(
            &mut state,
            &owner,
            at,
            NewRecord {
                class: Class::Native,
                parent_record: Some(parent.into()),
                grants: Grants::Owner,
                idle: at.saturating_add(self.config.native_idle_secs as i64),
                absolute: at.saturating_add(self.config.native_absolute_secs as i64),
            },
        )
    }

    pub(crate) fn mint_machine(
        &self,
        owner: &str,
        name: &str,
        scope: Vec<Scope>,
        expires_at: Option<i64>,
        rate: u32,
    ) -> Result<Issued> {
        let at = now();
        let expires_at = expires_at
            .unwrap_or_else(|| at.saturating_add(self.config.machine_token_default_secs as i64));
        if !bounded(name, 128)
            || rate == 0
            || !self.valid_scope(&scope)
            || expires_at <= at
            || expires_at > at.saturating_add(self.config.machine_token_max_secs as i64)
        {
            return Err(AuthorityError::Invalid);
        }
        let mut state = self.locked()?;
        self.issue_for_owner(
            &mut state,
            owner,
            at,
            NewRecord {
                class: Class::Machine,
                parent_record: None,
                grants: Grants::Machine {
                    name: name.into(),
                    scope,
                    rate,
                },
                idle: expires_at,
                absolute: expires_at,
            },
        )
    }

    pub(crate) fn mint_delegated(&self, owner: &str, grant: DelegatedGrant) -> Result<Issued> {
        let at = now();
        if !bounded(&grant.holder, 128)
            || grant.targets.is_empty()
            || grant.targets.len() > 256
            || grant.targets.iter().any(|target| {
                !self.config.nodes.contains(&target.node)
                    || !valid_endpoint(&target.node, &target.endpoint)
            })
            || grant.verbs.is_empty()
            || grant.verbs.len() > 32
            || grant.verbs.iter().any(|verb| {
                !bounded(verb, 64)
                    || !verb
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            })
            || !grant.confirm_verbs.is_empty()
            || grant.presenter.is_some()
            || !(1..=5).contains(&grant.rate)
            || grant
                .read_scope
                .as_ref()
                .is_some_and(|scope| !self.valid_scope(scope))
            || grant.expires_at <= at
            || grant.expires_at > at.saturating_add(self.config.delegated_grant_max_secs as i64)
        {
            return Err(AuthorityError::Invalid);
        }
        let expires_at = grant.expires_at;
        let mut state = self.locked()?;
        self.issue_for_owner(
            &mut state,
            owner,
            at,
            NewRecord {
                class: Class::Delegated,
                parent_record: None,
                grants: Grants::Delegated { grant },
                idle: expires_at,
                absolute: expires_at,
            },
        )
    }

    fn issue_for_owner(
        &self,
        state: &mut State,
        owner: &str,
        at: i64,
        new: NewRecord,
    ) -> Result<Issued> {
        let generation = state.generation;
        let tx = state.conn.transaction()?;
        if !entitled(&tx, owner)? {
            return Err(AuthorityError::Denied);
        }
        let issued = issue(&tx, owner, generation, at, new)?;
        tx.commit()?;
        Ok(state.install(issued))
    }

    fn valid_scope(&self, scopes: &[Scope]) -> bool {
        !scopes.is_empty()
            && scopes.len() <= 256
            && scopes.iter().all(|scope| match scope {
                Scope::Fleet | Scope::Attention => true,
                Scope::Node { node } => self.config.nodes.contains(node),
                Scope::Session { node, endpoint } => {
                    self.config.nodes.contains(node) && valid_endpoint(node, endpoint)
                }
            })
    }

    pub(crate) fn admit(&self, handle: &str, carrier: Carrier) -> Result<Record> {
        self.admit_at(handle, carrier, now())
    }

    fn admit_at(&self, handle: &str, carrier: Carrier, at: i64) -> Result<Record> {
        let digest = handle_digest(handle)?;
        let mut state = self.locked()?;
        let entry = state
            .by_digest
            .get(&digest)
            .and_then(|id| state.records.get(id))
            .ok_or(AuthorityError::Denied)?;
        let mut record = entry.record.clone();
        if !fresh(&record, at)
            || !record.class.matches_carrier(carrier)
            || record.class == Class::Delegated
        {
            return Err(AuthorityError::Denied);
        }
        if !entitled(&state.conn, owner_for(&record))? {
            return Err(match record.class {
                Class::Browser | Class::Native => AuthorityError::Forbidden,
                Class::Machine | Class::Delegated => AuthorityError::Denied,
            });
        }
        let idle = match record.class {
            Class::Browser => self.config.session_idle_secs as i64,
            Class::Native => self.config.native_idle_secs as i64,
            Class::Machine | Class::Delegated => record.absolute_expires_at.saturating_sub(at),
        };
        record.last_used_at = record.last_used_at.max(at);
        record.idle_expires_at = at.saturating_add(idle).min(record.absolute_expires_at);
        record.policy_generation = state.generation;
        let tx = state.conn.transaction()?;
        persist_record(&tx, &digest, &record)?;
        tx.commit()?;
        state
            .records
            .get_mut(&record.record_id)
            .ok_or(AuthorityError::Storage)?
            .record = record.clone();
        Ok(record)
    }

    pub(crate) fn list(&self) -> Result<Vec<Record>> {
        let mut state = self.locked()?;
        let mut records: Vec<Record> = state
            .records
            .values()
            .map(|entry| entry.record.clone())
            .collect();
        records.sort_unstable_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then(a.record_id.cmp(&b.record_id))
        });
        let tx = state.conn.transaction()?;
        audit(&tx, now(), "list", None, None)?;
        tx.commit()?;
        Ok(records)
    }

    pub(crate) fn audit_records(&self) -> Result<Vec<Audit>> {
        let mut state = self.locked()?;
        let tx = state.conn.transaction()?;
        audit(&tx, now(), "audit_list", None, None)?;
        let rows = {
            let mut stmt = tx.prepare(
                "SELECT at, action, principal, record_id FROM audit ORDER BY sequence DESC LIMIT 1000",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(Audit {
                    at: row.get(0)?,
                    action: row.get(1)?,
                    principal: row.get(2)?,
                    record_id: row.get(3)?,
                })
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn audit_admin_refusal(&self, action: &'static str) -> Result<()> {
        let mut state = self.locked()?;
        let tx = state.conn.transaction()?;
        audit(&tx, now(), action, None, None)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn revoke(&self, id: &str) -> Result<()> {
        let mut state = self.locked()?;
        let entry = state.records.get(id).ok_or(AuthorityError::Denied)?;
        let mut record = entry.record.clone();
        let digest = entry.digest;
        record.revoked = true;
        let tx = state.conn.transaction()?;
        persist_record(&tx, &digest, &record)?;
        audit(&tx, now(), "revoke", Some(owner_for(&record)), Some(id))?;
        tx.commit()?;
        let change = Instant::now();
        #[cfg(test)]
        {
            state.last_revoke = Some((state.conn.last_insert_rowid(), change));
        }
        state
            .records
            .get_mut(id)
            .ok_or(AuthorityError::Storage)?
            .record = record;
        state.invalidate(
            |registration| (registration.record_id == id).then_some(InvalidationReason::Revoked),
            change,
            self.cutoff(),
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn suppress_push_for_test(&self) {
        self.locked().unwrap().suppress_push = true;
    }

    #[cfg(test)]
    pub(crate) fn last_revoke_for_test(&self) -> (i64, Instant) {
        self.locked().unwrap().last_revoke.unwrap()
    }

    pub(crate) fn rebind(&self, owner: &str, issuer: &str, subject: &str) -> Result<()> {
        if !bounded(issuer, 2_048) || !bounded(subject, 512) {
            return Err(AuthorityError::Invalid);
        }
        self.revoke_owner_records(owner, RevokeOwner::Rebind { issuer, subject })
    }

    pub(crate) fn invalidate_owner_refresh(&self, owner: &str, expected: &Refresh) -> Result<()> {
        self.revoke_owner_records(owner, RevokeOwner::Upstream(expected))
    }

    fn revoke_owner_records(&self, owner: &str, action: RevokeOwner<'_>) -> Result<()> {
        let mut state = self.locked()?;
        let generation = generation_after(state.generation)?;
        let changed: Vec<_> = state
            .records
            .values()
            .filter(|entry| affected(&entry.record, owner) && !entry.record.revoked)
            .map(|entry| {
                let mut record = entry.record.clone();
                record.revoked = true;
                (entry.digest, record)
            })
            .collect();
        let tx = state.conn.transaction()?;
        let action_name = match action {
            RevokeOwner::Rebind { issuer, subject } => {
                let email = tx
                    .query_row(
                        "SELECT email FROM owners WHERE principal=?1",
                        [owner],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                if !email.is_some_and(|email| self.allowlist.contains(&email))
                    || tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM owners WHERE issuer=?1 AND subject=?2 AND principal<>?3)",
                        params![issuer, subject, owner],
                        |row| row.get::<_, bool>(0),
                    )?
                {
                    return Err(AuthorityError::Denied);
                }
                tx.execute(
                    "UPDATE owners SET issuer=?1, subject=?2, entitled=1 WHERE principal=?3",
                    params![issuer, subject, owner],
                )?;
                "owner_rebound"
            }
            RevokeOwner::Upstream(expected) => {
                if !entitled(&tx, owner)? || !refresh_matches(&tx, owner, expected)? {
                    return Err(AuthorityError::Denied);
                }
                "upstream_refused"
            }
        };
        tx.execute("DELETE FROM refresh_tokens WHERE owner=?1", [owner])?;
        for (digest, record) in &changed {
            persist_record(&tx, digest, record)?;
        }
        set_generation(&tx, generation)?;
        audit(&tx, now(), action_name, Some(owner), None)?;
        tx.commit()?;
        let change = Instant::now();
        for (_, record) in changed {
            state
                .records
                .get_mut(&record.record_id)
                .ok_or(AuthorityError::Storage)?
                .record = record.clone();
        }
        state.set_generation(generation, change, self.cutoff());
        Ok(())
    }

    pub(crate) fn refresh(&self, owner: &str) -> Result<Option<Refresh>> {
        read_refresh(&self.locked()?.conn, owner)
    }

    pub(crate) fn record_refresh(
        &self,
        owner: &str,
        expected: &Refresh,
        encrypted: Option<&[u8]>,
    ) -> Result<()> {
        let mut state = self.locked()?;
        let tx = state.conn.transaction()?;
        if !refresh_matches(&tx, owner, expected)? {
            return Err(AuthorityError::Denied);
        }
        save_refresh(&tx, owner, encrypted.unwrap_or(&expected.encrypted), now())?;
        tx.commit()?;
        Ok(())
    }

    fn cutoff(&self) -> Duration {
        Duration::from_millis(self.config.revocation_slo_ms)
    }
}

enum RevokeOwner<'a> {
    Rebind { issuer: &'a str, subject: &'a str },
    Upstream(&'a Refresh),
}

fn fresh(record: &Record, at: i64) -> bool {
    !record.revoked && at < record.idle_expires_at && at < record.absolute_expires_at
}

fn save_refresh(tx: &Transaction<'_>, owner: &str, ciphertext: &[u8], at: i64) -> Result<()> {
    if ciphertext.is_empty() || ciphertext.len() > 32 * 1024 {
        return Err(AuthorityError::Invalid);
    }
    tx.execute(
        "INSERT INTO refresh_tokens VALUES (?1, ?2, ?3)
         ON CONFLICT(owner) DO UPDATE SET ciphertext=excluded.ciphertext, checked_at=excluded.checked_at",
        params![owner, ciphertext, at],
    )?;
    Ok(())
}

fn read_refresh(conn: &Connection, owner: &str) -> Result<Option<Refresh>> {
    Ok(conn
        .query_row(
            "SELECT ciphertext, checked_at FROM refresh_tokens WHERE owner=?1",
            [owner],
            |row| {
                Ok(Refresh {
                    encrypted: row.get(0)?,
                    checked_at: row.get(1)?,
                })
            },
        )
        .optional()?)
}

fn refresh_matches(conn: &Connection, owner: &str, expected: &Refresh) -> Result<bool> {
    Ok(read_refresh(conn, owner)?.is_some_and(|stored| {
        stored.checked_at == expected.checked_at && stored.encrypted == expected.encrypted
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvalidationReason {
    LeaseExpired,
    Revoked,
    PolicyChanged,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Invalidation {
    #[allow(dead_code, reason = "Mission Control transport close reason")]
    pub reason: InvalidationReason,
    #[allow(dead_code, reason = "Mission Control transport revocation clock")]
    pub changed_at: Instant,
    pub cutoff: Instant,
}

struct Registration {
    record_id: String,
    #[allow(dead_code, reason = "Mission Control transport dequeue fence")]
    generation: i64,
    lease: Instant,
    abort: Arc<TcpStream>,
    runtime: tokio::runtime::Handle,
    sender: watch::Sender<Option<Invalidation>>,
    invalidation: Option<Invalidation>,
}

#[allow(dead_code, reason = "Mission Control transport registration handle")]
pub(crate) struct Live {
    authority: Weak<Authority>,
    id: u64,
    receiver: watch::Receiver<Option<Invalidation>>,
}

impl Registration {
    fn invalidate(
        &mut self,
        reason: InvalidationReason,
        changed_at: Instant,
        slo: Duration,
        push: bool,
    ) {
        if self.invalidation.is_some() {
            return;
        }
        self.invalidation = Some(Invalidation {
            reason,
            changed_at,
            cutoff: changed_at + slo,
        });
        if push {
            self.dispatch();
        }
    }

    fn dispatch(&mut self) {
        let Some(change) = self.invalidation else {
            return;
        };
        if self.sender.borrow().is_some() {
            return;
        }
        self.sender.send_replace(Some(change));
        let socket = Arc::clone(&self.abort);
        let slo = change.cutoff - change.changed_at;
        let abort_at = change.cutoff - (slo / 10).min(Duration::from_millis(25));
        self.runtime.spawn(async move {
            tokio::time::sleep_until(abort_at.into()).await;
            let _ = socket.shutdown(Shutdown::Both);
        });
    }
}

impl State {
    fn invalidate(
        &mut self,
        mut reason: impl FnMut(&Registration) -> Option<InvalidationReason>,
        changed_at: Instant,
        slo: Duration,
    ) {
        #[cfg(test)]
        let push = !self.suppress_push;
        #[cfg(not(test))]
        let push = true;
        for registration in self.live.values_mut() {
            if let Some(reason) = reason(registration) {
                registration.invalidate(reason, changed_at, slo, push);
            }
        }
    }

    fn set_generation(&mut self, generation: i64, changed_at: Instant, slo: Duration) {
        if generation == self.generation {
            return;
        }
        self.generation = generation;
        self.invalidate(|_| Some(InvalidationReason::PolicyChanged), changed_at, slo);
    }
}

impl Authority {
    #[allow(dead_code, reason = "Mission Control transport registration entry")]
    pub(crate) fn register(
        self: &Arc<Self>,
        record: &Record,
        lease: Instant,
        abort: TcpStream,
    ) -> Result<Live> {
        let mut state = self.locked()?;
        let current = state
            .records
            .get(&record.record_id)
            .ok_or(AuthorityError::Denied)?;
        let wall_since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthorityError::Denied)?;
        let monotonic = Instant::now();
        if record.policy_generation != state.generation
            || !fresh(&current.record, wall_since_epoch.as_secs() as i64)
            || lease <= monotonic
        {
            return Err(AuthorityError::Denied);
        }
        let wall_expiry = current
            .record
            .absolute_expires_at
            .min(current.record.idle_expires_at);
        let wall_remaining =
            Duration::from_secs(wall_expiry as u64).saturating_sub(wall_since_epoch);
        let lease = monotonic
            .checked_add(wall_remaining)
            .map_or(lease, |expiry| expiry.min(lease));
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| AuthorityError::Invalid)?;
        let (sender, receiver) = watch::channel(None);
        let id = state.next_live_id;
        state.next_live_id = id.checked_add(1).ok_or(AuthorityError::Storage)?;
        state.live.insert(
            id,
            Registration {
                record_id: record.record_id.clone(),
                generation: record.policy_generation,
                lease,
                abort: Arc::new(abort),
                runtime,
                sender,
                invalidation: None,
            },
        );
        Ok(Live {
            authority: Arc::downgrade(self),
            id,
            receiver,
        })
    }

    pub(super) fn masked_nodes(&self) -> Result<HashSet<String>> {
        Ok(self.locked()?.masked_nodes.clone())
    }

    pub(crate) fn set_node_masked(&self, node: &str, masked: bool) -> Result<()> {
        if !self
            .config
            .nodes
            .iter()
            .any(|configured| configured == node)
        {
            return Err(AuthorityError::Invalid);
        }
        let mut state = self.locked()?;
        if masked {
            state.masked_nodes.insert(node.into());
        } else {
            state.masked_nodes.remove(node);
        }
        Ok(())
    }

    pub(crate) async fn watchdog(self: Arc<Self>) -> Result<()> {
        let interval = Duration::from_millis(self.config.authority_watchdog_ms);
        let authority = Arc::downgrade(&self);
        drop(self);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(authority) = authority.upgrade() else {
                return Ok(());
            };
            let mut state = authority.locked()?;
            let now = Instant::now();
            for registration in state.live.values_mut() {
                if let Some(change) = registration.invalidation {
                    registration.dispatch();
                    if now >= change.cutoff {
                        let _ = registration.abort.shutdown(Shutdown::Both);
                    }
                } else if now >= registration.lease {
                    registration.invalidate(
                        InvalidationReason::LeaseExpired,
                        registration.lease,
                        authority.cutoff(),
                        true,
                    );
                }
            }
        }
    }
}

impl Live {
    #[allow(dead_code, reason = "Mission Control transport cancellation signal")]
    pub(crate) async fn invalidated(&mut self) -> Option<Invalidation> {
        loop {
            if let Some(change) = *self.receiver.borrow_and_update() {
                return Some(change);
            }
            self.receiver.changed().await.ok()?;
        }
    }

    pub(super) async fn change(&self) -> Option<Invalidation> {
        let mut receiver = self.receiver.clone();
        loop {
            if let Some(change) = *receiver.borrow_and_update() {
                return Some(change);
            }
            receiver.changed().await.ok()?;
        }
    }

    #[allow(dead_code, reason = "Mission Control transport dequeue fence")]
    pub(crate) fn authorize_send<T>(
        &self,
        node: Option<&str>,
        handoff: impl FnOnce() -> T,
    ) -> Result<T> {
        self.authorize_payload(node, || true, handoff)
    }

    pub(super) fn authorize_payload<'a, T>(
        &self,
        nodes: impl IntoIterator<Item = &'a str>,
        current: impl FnOnce() -> bool,
        handoff: impl FnOnce() -> T,
    ) -> Result<T> {
        let authority = self.authority.upgrade().ok_or(AuthorityError::Denied)?;
        let state = authority.locked()?;
        let reg = state.live.get(&self.id).ok_or(AuthorityError::Denied)?;
        if reg.invalidation.is_some()
            || reg.generation != state.generation
            || Instant::now() >= reg.lease
            || !state
                .records
                .get(&reg.record_id)
                .is_some_and(|entry| !entry.record.revoked)
            || nodes
                .into_iter()
                .any(|name| state.masked_nodes.contains(name))
            || !current()
        {
            return Err(AuthorityError::Denied);
        }
        // Serialize the caller's nonblocking socket handoff with authority changes.
        Ok(handoff())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(authority) = self.authority.upgrade() {
            if let Ok(mut state) = authority.state.lock() {
                state.live.remove(&self.id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener, sync::Barrier};

    fn state_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn configured() -> AuthorityConfig {
        AuthorityConfig {
            allowlist: vec!["owner@example.test".into()],
            nodes: vec!["here".into()],
            ..AuthorityConfig::default()
        }
    }

    const EMAIL: &str = "owner@example.test";
    const ISSUER: &str = "https://issuer.example.test";

    #[test]
    fn sl3_concurrent_first_subject_binding_has_one_winner() {
        let directory = state_dir();
        let authority = Authority::open(directory.path(), configured()).unwrap();
        let gate = Arc::new(Barrier::new(2));

        let threads = ["first", "second"].map(|subject| {
            let authority = Arc::clone(&authority);
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                gate.wait();
                (subject, authority.login(EMAIL, ISSUER, subject, None))
            })
        });
        let results = threads.map(|thread| thread.join().unwrap());
        let winners = results
            .iter()
            .filter(|(_, result)| result.is_ok())
            .collect::<Vec<_>>();
        assert_eq!(winners.len(), 1, "only one binding may succeed");
        let winner = winners[0].0;
        assert!(authority
            .login("new@example.test", ISSUER, winner, None)
            .is_ok());
        assert!(matches!(
            authority.login(EMAIL, "https://new-issuer.example.test", winner, None),
            Err(AuthorityError::Denied)
        ));
        let losing_subject = if winner == "first" { "second" } else { "first" };
        assert!(matches!(
            authority.login(EMAIL, ISSUER, losing_subject, None),
            Err(AuthorityError::Denied)
        ));
        assert!(authority
            .audit_records()
            .unwrap()
            .iter()
            .any(|row| row.action == "login_refused"));
    }

    #[test]
    fn owner_credential_lifetime_and_carrier_are_distinct() {
        let directory = state_dir();
        let config = AuthorityConfig {
            session_idle_secs: 10,
            session_absolute_secs: 15,
            ..configured()
        };
        let authority = Authority::open(directory.path(), config).unwrap();
        let at = now();
        let browser = authority
            .login_at(EMAIL, ISSUER, "subject", None, at)
            .unwrap();
        assert!(matches!(
            authority.admit_at(&browser.handle, Carrier::Bearer, at),
            Err(AuthorityError::Denied)
        ));
        let admitted = authority
            .admit_at(&browser.handle, Carrier::Cookie, at + 9)
            .unwrap();
        assert_eq!(admitted.idle_expires_at, at + 15);
        assert!(matches!(
            authority.admit_at(&browser.handle, Carrier::Cookie, at + 15),
            Err(AuthorityError::Denied)
        ));
    }

    #[test]
    fn sl5_upstream_refusal_invalidates_every_owned_record() {
        let directory = state_dir();
        let authority = Authority::open(directory.path(), configured()).unwrap();
        let browser = authority
            .login(EMAIL, ISSUER, "subject", Some(b"ciphertext"))
            .unwrap();
        let owner = &browser.record.principal;
        let native = authority.issue_native(&browser.record.record_id).unwrap();
        let machine = authority
            .mint_machine(owner, "poller", vec![Scope::Fleet], None, 1)
            .unwrap();
        let old = authority.refresh(owner).unwrap().unwrap();
        authority
            .record_refresh(owner, &old, Some(b"rotated ciphertext"))
            .unwrap();
        assert!(matches!(
            authority.invalidate_owner_refresh(owner, &old),
            Err(AuthorityError::Denied)
        ));
        let current = authority.refresh(owner).unwrap().unwrap();
        authority.invalidate_owner_refresh(owner, &current).unwrap();
        for (issued, carrier) in [
            (browser, Carrier::Cookie),
            (native, Carrier::Bearer),
            (machine, Carrier::Bearer),
        ] {
            assert!(matches!(
                authority.admit(&issued.handle, carrier),
                Err(AuthorityError::Denied)
            ));
        }
    }

    #[test]
    fn sl7_owner_entitlement_is_rechecked_even_for_an_unrevoked_record() {
        let directory = state_dir();
        let authority = Authority::open(directory.path(), configured()).unwrap();
        let browser = authority.login(EMAIL, ISSUER, "subject", None).unwrap();
        let machine = authority
            .mint_machine(
                &browser.record.principal,
                "poller",
                vec![Scope::Attention],
                None,
                1,
            )
            .unwrap();
        assert!(authority.admit(&machine.handle, Carrier::Bearer).is_ok());
        {
            let state = authority.locked().unwrap();
            state
                .conn
                .execute("UPDATE owners SET entitled=0", [])
                .unwrap();
        }
        assert!(matches!(
            authority.admit(&machine.handle, Carrier::Bearer),
            Err(AuthorityError::Denied)
        ));
    }

    #[test]
    fn sl7_removing_the_owner_persists_revocation_across_restart() {
        let directory = state_dir();
        let authority = Authority::open(directory.path(), configured()).unwrap();
        let browser = authority.login(EMAIL, ISSUER, "subject", None).unwrap();
        let machine = authority
            .mint_machine(
                &browser.record.principal,
                "poller",
                vec![Scope::Fleet],
                None,
                1,
            )
            .unwrap();
        drop(authority);
        let removed = Authority::open(directory.path(), AuthorityConfig::default()).unwrap();
        assert!(matches!(
            removed.admit(&machine.handle, Carrier::Bearer),
            Err(AuthorityError::Denied)
        ));
        assert!(removed
            .list()
            .unwrap()
            .into_iter()
            .all(|record| record.revoked));
        drop(removed);
        let restored = Authority::open(directory.path(), configured()).unwrap();
        restored
            .rebind(&browser.record.principal, ISSUER, "replacement")
            .unwrap();
        assert!(restored.login(EMAIL, ISSUER, "replacement", None).is_ok());
        assert!(matches!(
            restored.admit(&machine.handle, Carrier::Bearer),
            Err(AuthorityError::Denied)
        ));
    }

    fn stalled_socket() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut writer, _) = listener.accept().unwrap();
        writer.set_nonblocking(true).unwrap();
        let chunk = [0; 16 * 1024];
        let stalled = (0..4096).any(|_| match writer.write(&chunk) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
            Ok(_) => false,
            Err(error) => panic!("cannot fill loopback send buffer: {error}"),
        });
        assert!(stalled, "would-block positive control");
        writer.set_nonblocking(false).unwrap();
        (writer, reader)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sl6_sl7_revocation_aborts_a_blocked_production_registration_by_cutoff() {
        for rebind in [false, true] {
            let directory = state_dir();
            let authority = Authority::open(directory.path(), configured()).unwrap();
            let browser = authority.login(EMAIL, ISSUER, "subject", None).unwrap();
            let owner = browser.record.principal;
            let machine = authority
                .mint_machine(&owner, "poller", vec![Scope::Attention], None, 1)
                .unwrap();
            let (mut writer, _reader) = stalled_socket();
            let mut live = authority
                .register(
                    &machine.record,
                    Instant::now() + Duration::from_secs(10),
                    writer.try_clone().unwrap(),
                )
                .unwrap();
            assert_eq!(live.authorize_send(None, || 1).unwrap(), 1);
            authority.set_node_masked("here", true).unwrap();
            assert!(live
                .authorize_send(Some("here"), || panic!("masked write admitted"))
                .is_err());
            assert_eq!(live.authorize_send(None, || 1).unwrap(), 1);
            let (entered_send, entered) = tokio::sync::oneshot::channel();
            let mut block = tokio::task::spawn_blocking(move || {
                entered_send.send(()).unwrap();
                let result = writer.write_all(&vec![0; 8 * 1024 * 1024]);
                (Instant::now(), result)
            });
            entered.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut block)
                    .await
                    .is_err(),
                "blocking write control"
            );
            if rebind {
                authority.rebind(&owner, ISSUER, "replacement").unwrap();
            } else {
                authority.revoke(&machine.record.record_id).unwrap();
            }
            assert!(live
                .authorize_send(None, || panic!("revoked write admitted"))
                .is_err());
            let invalidation = live.invalidated().await.unwrap();
            assert_eq!(
                invalidation.reason,
                if rebind {
                    InvalidationReason::PolicyChanged
                } else {
                    InvalidationReason::Revoked
                }
            );
            assert_eq!(
                invalidation.cutoff - invalidation.changed_at,
                Duration::from_secs(1)
            );
            let (completed, result) = tokio::time::timeout_at(invalidation.cutoff.into(), block)
                .await
                .expect("blocked writer should exit within the recorded cutoff")
                .unwrap();
            assert!(result.is_err() && completed <= invalidation.cutoff);
            assert!(matches!(
                authority.admit(&machine.handle, Carrier::Bearer),
                Err(AuthorityError::Denied)
            ));
        }
    }
}
