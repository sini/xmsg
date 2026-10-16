use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::error::AppError;
use crate::inbox::DeliveryResponse;
use crate::registry::{Session, SessionsQuery};

#[derive(Clone)]
pub struct AgyCredentials {
    pub ls_address: String,
    pub csrf_token: String,
    pub is_stale: bool,
}

impl std::fmt::Debug for AgyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgyCredentials")
            .field("ls_address", &self.ls_address)
            .field("csrf_token", &"<redacted>")
            .field("is_stale", &self.is_stale)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct AgySessionInfo {
    pub session_key: String,
    pub conversation_id: String,
    pub pid: u32,
    pub starttime: String,
    pub credentials: Option<AgyCredentials>,
    pub registered_at: i64,
}

impl AgySessionInfo {
    pub fn new(
        conversation_id: String,
        pid: u32,
        starttime: String,
        credentials: Option<AgyCredentials>,
    ) -> Self {
        let session_key = conversation_id.clone();
        Self {
            session_key,
            conversation_id,
            pid,
            starttime,
            credentials,
            registered_at: crate::storage::now_epoch_secs(),
        }
    }

    pub fn new_with_credentials(
        conversation_id: String,
        pid: u32,
        starttime: String,
        credentials: AgyCredentials,
    ) -> Self {
        Self::new(conversation_id, pid, starttime, Some(credentials))
    }

    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }
}

#[cfg(test)]
impl From<AgyCredentials> for AgySessionInfo {
    fn from(c: AgyCredentials) -> Self {
        Self {
            session_key: String::new(),
            conversation_id: String::new(),
            pid: 0,
            starttime: String::new(),
            credentials: Some(c),
            registered_at: 0,
        }
    }
}

pub type AgyStore = Arc<RwLock<HashMap<String, AgySessionInfo>>>;

pub fn new_agy_store() -> AgyStore {
    Arc::new(RwLock::new(HashMap::new()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgyRegistration {
    pub pid: u32,
    pub starttime: String,
    pub session_key: String,
}

impl PartialEq<u32> for AgyRegistration {
    fn eq(&self, other: &u32) -> bool {
        self.pid == *other
    }
}

impl PartialEq<AgyRegistration> for u32 {
    fn eq(&self, other: &AgyRegistration) -> bool {
        *self == other.pid
    }
}

pub fn is_agy_session_alive(proc_root: &Path, info: &AgySessionInfo) -> bool {
    if info.starttime.is_empty() {
        return false;
    }
    match crate::process::starttime(proc_root, info.pid) {
        Ok(st) => st == info.starttime,
        Err(_) => false,
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgyRegisterRequest {
    #[serde(alias = "conversation_id")]
    pub conversation_id: String,
    #[serde(alias = "ls_address")]
    pub ls_address: String,
    #[serde(alias = "csrf_token")]
    pub csrf_token: String,
}

impl std::fmt::Debug for AgyRegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgyRegisterRequest")
            .field("conversation_id", &self.conversation_id)
            .field("ls_address", &self.ls_address)
            .field("csrf_token", &"<redacted>")
            .finish()
    }
}

/// The kernel's lock table. Only Linux has it; a fixture file at another path
/// is parsed in the same format on every platform.
pub const LIVE_PROC_LOCKS: &str = "/proc/locks";

/// Whether presence locks can be checked through `proc_locks_path`: always on
/// Linux, and elsewhere only against a fixture. macOS has no way to read
/// another process's `flock` holders, so agy is Linux only there.
pub fn locks_supported(proc_locks_path: &Path) -> bool {
    cfg!(target_os = "linux") || proc_locks_path != Path::new(LIVE_PROC_LOCKS)
}

#[derive(Debug, Clone)]
pub struct AgyConfig {
    pub presence_dir: PathBuf,
    pub proc_locks_path: PathBuf,
    pub proc_root: PathBuf,
    pub agy_bin: String,
    pub trusted_agy_exes: Vec<PathBuf>,
}

impl Default for AgyConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Self {
            presence_dir: PathBuf::from(home).join(".gemini/antigravity-cli/presence"),
            proc_locks_path: PathBuf::from(LIVE_PROC_LOCKS),
            proc_root: PathBuf::from(crate::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        }
    }
}

pub fn dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

pub fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// Parses a single line from /proc/locks.
/// Format: "22: FLOCK ADVISORY WRITE 2739763 00:2e:1148992 0 EOF"
pub fn parse_locks_line(line: &str) -> Option<(u32, u32, u32, u64)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 7 {
        return None;
    }
    let lock_type = parts[1];
    let access = parts[3];
    if lock_type != "FLOCK" {
        return None;
    }
    if access != "WRITE" {
        return None;
    }
    let pid: u32 = parts[4].parse().ok()?;
    let dev_ino = parts[5];
    let di_parts: Vec<&str> = dev_ino.split(':').collect();
    if di_parts.len() != 3 {
        return None;
    }
    let maj = u32::from_str_radix(di_parts[0], 16).ok()?;
    let min = u32::from_str_radix(di_parts[1], 16).ok()?;
    let ino: u64 = di_parts[2].parse().ok()?;
    Some((pid, maj, min, ino))
}

/// Finds the holder PID of an exclusive write lock for a given (dev_major, dev_minor, inode).
/// READ-ONLY: Never acquires, opens, or flocks the file.
/// If multiple distinct PIDs match the target inode, returns an ambiguity error.
pub fn find_lock_holder(
    proc_locks_path: &Path,
    dev_major: u32,
    dev_minor: u32,
    target_inode: u64,
) -> io::Result<Option<u32>> {
    let content = match fs::read_to_string(proc_locks_path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound && !cfg!(target_os = "linux") => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "agy presence locks need {} (Linux only)",
                    proc_locks_path.display()
                ),
            ));
        }
        Err(e) => return Err(e),
    };
    let mut matching_pids = std::collections::HashSet::new();
    for line in content.lines() {
        if let Some((pid, maj, min, ino)) = parse_locks_line(line) {
            if maj == dev_major && min == dev_minor && ino == target_inode {
                matching_pids.insert(pid);
            }
        }
    }
    if matching_pids.is_empty() {
        Ok(None)
    } else if matching_pids.len() == 1 {
        Ok(matching_pids.into_iter().next())
    } else {
        Err(io::Error::other(
            "multiple lock holders detected for presence lock",
        ))
    }
}

/// Finds the holder PID of a conversation's presence lock file.
pub fn get_presence_lock_holder(
    presence_dir: &Path,
    proc_locks_path: &Path,
    conversation_id: &str,
) -> io::Result<Option<u32>> {
    let lock_path = presence_dir.join(format!("{conversation_id}.lock"));
    let meta = match fs::metadata(&lock_path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    use std::os::unix::fs::MetadataExt;
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    find_lock_holder(proc_locks_path, maj, min, ino)
}

/// Lists all active agy sessions: registered sessions from store (live via starttime),
/// plus on Linux any unregistered presence lock holders.
pub fn list_agy_sessions(
    config: &AgyConfig,
    store: &AgyStore,
    query: &SessionsQuery,
) -> Vec<Session> {
    let mut sessions = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    let mut seen_convs = std::collections::HashSet::new();
    let mut dead = Vec::new();

    // 1. Registered sessions in store
    {
        let store_lock = store.read().unwrap();
        for (id, info) in store_lock.iter() {
            if !is_agy_session_alive(&config.proc_root, info) {
                dead.push(id.clone());
                continue;
            }
            if !seen_keys.insert(info.session_key.clone()) {
                continue;
            }
            if !info.conversation_id.is_empty() {
                seen_convs.insert(info.conversation_id.clone());
            }

            let session = Session {
                session_id: if info.session_key.is_empty() {
                    info.conversation_id.clone()
                } else {
                    info.session_key.clone()
                },
                name: if info.conversation_id.is_empty() {
                    None
                } else {
                    Some(info.conversation_id.clone())
                },
                pid: info.pid,
                cwd: "/".to_string(),
                status: match &info.credentials {
                    None => "idle".to_string(),
                    Some(c) if c.is_stale => "stale".to_string(),
                    Some(_) => "idle".to_string(),
                },
                kind: "interactive".to_string(),
                entrypoint: None,
                version: None,
                started_at: info.registered_at as u64,
                updated_at: info.registered_at as u64,
                harness: "agy".to_string(),
                registered: Some(info.credentials.is_some()),
            };

            if let Some(ref q_status) = query.status {
                if session.status != *q_status {
                    continue;
                }
            }
            sessions.push(session);
        }
    }
    if !dead.is_empty() {
        let mut store_lock = store.write().unwrap();
        for d in dead {
            store_lock.remove(&d);
        }
    }

    // 2. Unregistered sessions in presence_dir (on Linux where /proc/locks is supported)
    if locks_supported(&config.proc_locks_path) {
        if let Ok(entries) = fs::read_dir(&config.presence_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("lock") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                let conversation_id = stem.to_string();
                if seen_convs.contains(&conversation_id) {
                    continue;
                }
                let holder_pid = match get_presence_lock_holder(
                    &config.presence_dir,
                    &config.proc_locks_path,
                    &conversation_id,
                ) {
                    Ok(Some(pid)) => pid,
                    _ => continue,
                };
                if crate::process::starttime(&config.proc_root, holder_pid).is_err() {
                    continue;
                }
                let lock_mtime = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let session = Session {
                    session_id: conversation_id.clone(),
                    name: Some(conversation_id.clone()),
                    pid: holder_pid,
                    cwd: "/".to_string(),
                    status: "unregistered".to_string(),
                    kind: "interactive".to_string(),
                    entrypoint: None,
                    version: None,
                    started_at: lock_mtime,
                    updated_at: lock_mtime,
                    harness: "agy".to_string(),
                    registered: Some(false),
                };
                if let Some(ref q_status) = query.status {
                    if session.status != *q_status {
                        continue;
                    }
                }
                sessions.push(session);
            }
        }
    }

    sessions
}

/// Resolves an agy session reference (by conversation_id/session_id or holder PID).
pub fn resolve_agy_session(
    config: &AgyConfig,
    store: &AgyStore,
    ref_str: &str,
) -> Result<Option<Session>, AppError> {
    let query = SessionsQuery::default();
    let all = list_agy_sessions(config, store, &query);

    let raw = ref_str.strip_prefix("agy:").unwrap_or(ref_str);
    let ref_pid = raw.parse::<u32>().ok();

    let pid_starttime = raw
        .split_once(':')
        .and_then(|(p, st)| p.parse::<u32>().ok().map(|pid| (pid, st)));

    let matched: Vec<Session> = all
        .into_iter()
        .filter(|s| {
            if s.status == "unregistered" {
                // 1. By conversation id (as listed)
                if s.session_id == raw {
                    return true;
                }
                if let Some(ref name) = s.name {
                    if name == raw {
                        return true;
                    }
                }
                // 2. By agy:<pid>:<starttime> key where pid AND starttime match the lock holder
                if let Some((target_pid, expected_st)) = pid_starttime {
                    if s.pid == target_pid {
                        if let Ok(actual_st) = crate::process::starttime(&config.proc_root, s.pid) {
                            return actual_st == expected_st;
                        }
                    }
                }
                false
            } else {
                // Registered session in store
                if s.session_id == ref_str {
                    return true;
                }
                if s.session_id.strip_prefix("agy:").unwrap_or(&s.session_id) == raw {
                    return true;
                }
                if let Some(pid) = ref_pid {
                    if s.pid == pid {
                        return true;
                    }
                }
                if let Some(ref name) = s.name {
                    if name == ref_str || name == raw {
                        return true;
                    }
                }
                false
            }
        })
        .collect();

    if matched.is_empty() {
        Ok(None)
    } else if matched.len() > 1 {
        let ids: Vec<String> = matched.into_iter().map(|s| s.session_id).collect();
        Err(AppError::Ambiguous(ids.join(", ")))
    } else {
        Ok(Some(matched.into_iter().next().unwrap()))
    }
}

/// Verifies registration parameters decoupled from socket I/O for direct testability.
#[allow(clippy::too_many_arguments)]
pub fn verify_registration(
    proc_root: &Path,
    proc_locks: &Path,
    presence_dir: &Path,
    trusted_exes: &[PathBuf],
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
    req: &AgyRegisterRequest,
) -> Result<AgyRegistration, AppError> {
    let peer = crate::process::PeerCred::unpinned(peer_uid, peer_pid);
    verify_registration_peer(proc_root, proc_locks, presence_dir, trusted_exes, my_uid, &peer, req)
}

/// Like [`verify_registration`], starting from a [`crate::process::PeerCred`] whose root
/// pid may be pinned by an `SO_PEERPIDFD` file descriptor.
#[allow(clippy::too_many_arguments)]
pub fn verify_registration_peer(
    proc_root: &Path,
    proc_locks: &Path,
    presence_dir: &Path,
    trusted_exes: &[PathBuf],
    my_uid: u32,
    peer: &crate::process::PeerCred,
    req: &AgyRegisterRequest,
) -> Result<AgyRegistration, AppError> {
    let peer_uid = peer.uid;
    let peer_pid = peer.pid.unwrap_or(0);
    // 1. Peer UID verification
    if peer_uid != my_uid {
        return Err(AppError::NotRecipient(format!(
            "peer UID {peer_uid} does not match server UID {my_uid}"
        )));
    }

    // 2. Configuration requirement: refuse if no trusted agy executable configured
    if trusted_exes.is_empty() {
        return Err(AppError::BadRequest(
            "no trusted agy executable configured; set --agy-exe or XMSG_AGY_EXE".to_string(),
        ));
    }

    // 3. Resolve presence lock file and canonical (dev, inode)
    let lock_file = presence_dir.join(format!("{}.lock", req.conversation_id));
    let meta = match fs::metadata(&lock_file) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(AppError::Gone {
                session_id: req.conversation_id.clone(),
                pid: 0,
            });
        }
        Err(e) => {
            return Err(AppError::Internal(format!(
                "failed to stat presence lock file: {e}"
            )));
        }
    };
    use std::os::unix::fs::MetadataExt;
    let target_dev = meta.dev();
    let target_ino = meta.ino();

    // 4. Canonicalize trusted exes
    let trusted_canons: Vec<PathBuf> = trusted_exes
        .iter()
        .map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();

    // 5. Ancestor walk from peer to find an ancestor satisfying BOTH (a) and (b)
    let mut chosen_ancestor = None;

    // `st1` is the start the walk read; the step 7 re-read must still equal it.
    for (curr_pid, st1) in crate::process::Ancestry::from_peer(proc_root, peer).take(32) {
        if curr_pid <= 1 {
            break;
        }

        // (a) EXECUTABLE check: kernel-reported executable path matches a trusted exe
        let exe_matches = match crate::process::exe_path(proc_root, curr_pid) {
            Ok(exe) => {
                let exe_canon = fs::canonicalize(&exe).unwrap_or(exe);
                trusted_canons.contains(&exe_canon)
            }
            Err(_) => false,
        };

        if exe_matches {
            // (b) OPEN FILE check: ancestor has presence lock (target_dev, target_ino) open
            let has_file_open = match crate::process::open_file_ids(proc_root, curr_pid) {
                Ok(ids) => ids.contains(&(target_dev, target_ino)),
                Err(_) => false,
            };

            if has_file_open {
                chosen_ancestor = Some((curr_pid, st1));
                break;
            }
        }
    }

    let (chosen_pid, initial_starttime) = match chosen_ancestor {
        Some(pair) => pair,
        None => {
            return Err(AppError::NotRecipient(format!(
                "peer PID {peer_pid} has no ancestor matching a trusted agy executable with presence lock open"
            )));
        }
    };

    // 6. Linux additional check: a FLOCK holder line must exist in /proc/locks AND equal chosen_pid
    if locks_supported(proc_locks) {
        let maj = dev_major(target_dev);
        let min = dev_minor(target_dev);
        match find_lock_holder(proc_locks, maj, min, target_ino) {
            Ok(Some(flock_holder)) => {
                if flock_holder != chosen_pid {
                    return Err(AppError::NotRecipient(format!(
                        "FLOCK holder PID {flock_holder} does not match chosen ancestor PID {chosen_pid}"
                    )));
                }
            }
            Ok(None) => {
                return Err(AppError::NotRecipient(format!(
                    "presence lock file has no FLOCK holder in {proc_locks:?}"
                )));
            }
            Err(e) => {
                return Err(AppError::Ambiguous(format!(
                    "ambiguous presence lock in /proc/locks: {e}"
                )));
            }
        }
    }

    // 7. Verify starttime stability to guard against PID recycling race
    let st2 = crate::process::starttime(proc_root, chosen_pid).map_err(|e| {
        AppError::Internal(format!(
            "failed to read starttime for PID {chosen_pid}: {e}"
        ))
    })?;
    if initial_starttime != st2 {
        return Err(AppError::Internal(format!(
            "process starttime changed during verification for PID {chosen_pid}"
        )));
    }
    let session_key = req.conversation_id.clone();

    Ok(AgyRegistration {
        pid: chosen_pid,
        starttime: st2,
        session_key,
    })
}

/// Attests that a connecting peer (e.g. `xmsg mcp`) descends from an Antigravity process
/// holding a valid presence lock.
pub fn attest_mcp_caller(
    proc_root: &Path,
    proc_locks: &Path,
    presence_dir: &Path,
    trusted_exes: &[PathBuf],
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
) -> Result<(AgyRegistration, String), AppError> {
    let peer = crate::process::PeerCred::unpinned(peer_uid, peer_pid);
    attest_mcp_caller_peer(proc_root, proc_locks, presence_dir, trusted_exes, my_uid, &peer)
}

/// Like [`attest_mcp_caller`], starting from a [`crate::process::PeerCred`] whose root pid
/// may be pinned by an `SO_PEERPIDFD` file descriptor.
pub fn attest_mcp_caller_peer(
    proc_root: &Path,
    proc_locks: &Path,
    presence_dir: &Path,
    trusted_exes: &[PathBuf],
    my_uid: u32,
    peer: &crate::process::PeerCred,
) -> Result<(AgyRegistration, String), AppError> {
    let peer_uid = peer.uid;
    let peer_pid = peer.pid.unwrap_or(0);
    // 1. Peer UID verification
    if peer_uid != my_uid {
        return Err(AppError::NotRecipient(format!(
            "peer UID {peer_uid} does not match server UID {my_uid}"
        )));
    }

    // 2. Configuration requirement: refuse if no trusted agy executable configured
    if trusted_exes.is_empty() {
        return Err(AppError::BadRequest(
            "no trusted agy executable configured; set --agy-exe or XMSG_AGY_EXE".to_string(),
        ));
    }

    // 3. Canonicalize trusted exes
    let trusted_canons: Vec<PathBuf> = trusted_exes
        .iter()
        .map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();

    // 4. Read presence directory entries to know target locks
    let mut presence_locks = Vec::new();
    if let Ok(entries) = fs::read_dir(presence_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("lock") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(meta) = fs::metadata(&path) {
                        use std::os::unix::fs::MetadataExt;
                        presence_locks.push((stem.to_string(), meta.dev(), meta.ino()));
                    }
                }
            }
        }
    }

    if presence_locks.is_empty() {
        return Err(AppError::NotRecipient(
            "no presence lock files found in presence directory".to_string(),
        ));
    }

    // 5. Ancestor walk from peer to find an ancestor satisfying BOTH (a) and (b)
    let mut chosen = None;

    // `st1` is the start the walk read; the final re-read must still equal it.
    for (curr_pid, st1) in crate::process::Ancestry::from_peer(proc_root, peer).take(32) {
        if curr_pid <= 1 {
            break;
        }

        // (a) EXECUTABLE check: kernel-reported executable path matches a trusted exe
        let exe_matches = match crate::process::exe_path(proc_root, curr_pid) {
            Ok(exe) => {
                let exe_canon = fs::canonicalize(&exe).unwrap_or(exe);
                trusted_canons.contains(&exe_canon)
            }
            Err(_) => false,
        };

        if exe_matches {
            // (b) OPEN FILE check: ancestor has presence lock open
            let open_ids = crate::process::open_file_ids(proc_root, curr_pid).unwrap_or_default();
            for (conv_id, target_dev, target_ino) in &presence_locks {
                if open_ids.contains(&(*target_dev, *target_ino)) {
                    let flock_ok = if locks_supported(proc_locks) {
                        let maj = dev_major(*target_dev);
                        let min = dev_minor(*target_dev);
                        match find_lock_holder(proc_locks, maj, min, *target_ino) {
                            Ok(Some(holder)) => holder == curr_pid,
                            _ => false,
                        }
                    } else {
                        true
                    };

                    if flock_ok {
                        chosen = Some((curr_pid, st1, conv_id.clone()));
                        break;
                    }
                }
            }
            if chosen.is_some() {
                break;
            }
        }
    }

    let (chosen_pid, initial_starttime, conv_id) = match chosen {
        Some(triple) => triple,
        None => {
            return Err(AppError::NotRecipient(format!(
                "peer PID {peer_pid} has no ancestor matching a trusted agy executable with presence lock open"
            )));
        }
    };

    // Verify starttime stability
    let st2 = crate::process::starttime(proc_root, chosen_pid).map_err(|e| {
        AppError::Internal(format!(
            "failed to read starttime for PID {chosen_pid}: {e}"
        ))
    })?;
    if initial_starttime != st2 {
        return Err(AppError::Internal(format!(
            "process starttime changed during verification for PID {chosen_pid}"
        )));
    }
    let session_key = conv_id.clone();

    Ok((
        AgyRegistration {
            pid: chosen_pid,
            starttime: st2,
            session_key,
        },
        conv_id,
    ))
}

/// Delivers what is queued for a conversation that has just registered. A message older
/// than `reply_ttl` is dropped unread, never delivered (A14).
pub async fn flush_agy_queue(
    config: &AgyConfig,
    store: &AgyStore,
    db: &Arc<Mutex<rusqlite::Connection>>,
    session_key: &str,
    conv_id: &str,
    reply_ttl: Duration,
) {
    let pending_msgs = {
        let db_lock = match db.lock() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("failed to lock db for agy queue flush: {e}");
                return;
            }
        };
        // A registration is an observation: the conversation is live now (A14).
        let _ =
            crate::storage::mark_live(&db_lock, conv_id, "agy", crate::storage::now_epoch_secs());
        if let Err(e) = crate::storage::purge_agy_messages(&db_lock, reply_ttl.as_secs()) {
            tracing::error!("failed to purge expired agy messages: {e}");
            return;
        }
        match crate::storage::fetch_undelivered_agy_messages(&db_lock, &[session_key, conv_id]) {
            Ok(msgs) => msgs,
            Err(e) => {
                tracing::error!("failed to fetch undelivered agy messages: {e}");
                return;
            }
        }
    };

    if pending_msgs.is_empty() {
        return;
    }

    let session = Session {
        session_id: session_key.to_string(),
        name: Some(conv_id.to_string()),
        pid: 0,
        cwd: "/".to_string(),
        status: "idle".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: 0,
        updated_at: 0,
        harness: "agy".to_string(),
        registered: Some(true),
    };

    for msg in pending_msgs {
        match deliver_agy_envelope(config, store, &session, &msg.from_name, &msg.envelope).await {
            Ok(()) => {
                let now = crate::storage::now_epoch_secs();
                if let Ok(db_lock) = db.lock() {
                    let _ = crate::storage::mark_agy_message_delivered(&db_lock, &msg.id, now);
                    let _ = crate::storage::update_message_outcome(&db_lock, &msg.id, "delivered");
                }
            }
            Err(e) => {
                tracing::error!("failed to deliver queued agy message {}: {e}", msg.id);
                break;
            }
        }
    }
}

/// Delivers a message to an Antigravity session.
pub async fn deliver_agy(
    config: &AgyConfig,
    store: &AgyStore,
    session: &Session,
    from_name: &str,
    ref_address: Option<&str>,
    message_id: &str,
    body_text: &str,
) -> Result<DeliveryResponse, AppError> {
    let ref_part = match ref_address {
        Some(r) => format!(" ref={r}"),
        None => String::new(),
    };
    // Format envelope (§9.4)
    let envelope = format!(
        "[xmsg] from={from_name}{ref_part} message_id={message_id} — reply with the xmsg reply tool (tools: send, reply, list, replies)\n\n{body_text}"
    );
    deliver_agy_envelope(config, store, session, from_name, &envelope).await?;

    Ok(DeliveryResponse {
        session_id: session.session_id.clone(),
        from_name: from_name.to_string(),
        bytes: body_text.len(),
        message_id: message_id.to_string(),
        outcome: None,
    })
}

/// Delivers a raw envelope string to an Antigravity session.
pub async fn deliver_agy_envelope(
    config: &AgyConfig,
    store: &AgyStore,
    session: &Session,
    title: &str,
    envelope: &str,
) -> Result<(), AppError> {
    // 1. Liveness check via pid + starttime (no per-message lock check)
    let (is_alive, conv_target, creds) = {
        let store_lock = store.read().unwrap();
        let maybe_info = store_lock.get(&session.session_id).cloned().or_else(|| {
            store_lock
                .values()
                .find(|info| {
                    info.conversation_id == session.session_id
                        || session.name.as_deref() == Some(&info.conversation_id)
                })
                .cloned()
        });
        match maybe_info {
            Some(info) => {
                let alive = is_agy_session_alive(&config.proc_root, &info);
                let target = if !info.conversation_id.is_empty() {
                    info.conversation_id.clone()
                } else {
                    session.session_id.clone()
                };
                (alive, target, info.credentials.clone())
            }
            None => {
                let alive = if session.pid > 0 {
                    crate::process::starttime(&config.proc_root, session.pid).is_ok()
                } else {
                    false
                };
                (alive, session.session_id.clone(), None)
            }
        }
    };

    if !is_alive {
        {
            let mut store_lock = store.write().unwrap();
            store_lock
                .retain(|k, v| k != &session.session_id && v.conversation_id != session.session_id);
        }
        return Err(AppError::Gone {
            session_id: session.session_id.clone(),
            pid: session.pid,
        });
    }

    let creds = match creds {
        Some(c) => c,
        None => {
            return Err(AppError::CredentialsStale(format!(
                "session '{}' has not registered credentials; run xmsg register agy",
                session.session_id
            )));
        }
    };

    if creds.is_stale {
        return Err(AppError::CredentialsStale(format!(
            "credentials for session '{}' are stale",
            session.session_id
        )));
    }

    // 2. Spawn agy agentapi send-message directly as argv vector with NO shell
    let mut cmd = tokio::process::Command::new(&config.agy_bin);
    cmd.arg("agentapi")
        .arg("send-message")
        .arg("--title")
        .arg(title)
        .arg("--")
        .arg(&conv_target)
        .arg(envelope)
        .env("ANTIGRAVITY_LS_ADDRESS", &creds.ls_address)
        .env("ANTIGRAVITY_CSRF_TOKEN", &creds.csrf_token)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            return Err(AppError::InboxUnavailable(format!(
                "failed to execute {}: {e}",
                config.agy_bin
            )));
        }
        Err(_) => return Err(AppError::InboxTimeout),
    };

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout_str} {stderr_str}");

    if combined.contains("Unauthenticated")
        || combined.contains("connection refused")
        || combined.contains("Connection refused")
    {
        {
            let mut store_lock = store.write().unwrap();
            if let Some(entry) = store_lock.get_mut(&session.session_id) {
                if let Some(ref mut c) = entry.credentials {
                    c.is_stale = true;
                }
            } else if let Some(entry) = store_lock.values_mut().find(|e| {
                e.conversation_id == session.session_id
                    || session.name.as_deref() == Some(&e.conversation_id)
            }) {
                if let Some(ref mut c) = entry.credentials {
                    c.is_stale = true;
                }
            }
        }
        let excerpt: String = combined.chars().take(200).collect();
        tracing::warn!("agy delivery auth failure: {excerpt}");
        return Err(AppError::CredentialsStale(
            "authentication failed".to_string(),
        ));
    }

    if !output.status.success() {
        let excerpt: String = combined.chars().take(200).collect();
        tracing::warn!(
            "agy delivery failure (code {:?}): {excerpt}",
            output.status.code()
        );
        return Err(AppError::InboxUnavailable("delivery failed".to_string()));
    }

    Ok(())
}

/// Returns current process UID.
pub fn current_uid() -> u32 {
    unsafe {
        extern "C" {
            fn getuid() -> u32;
        }
        getuid()
    }
}

/// Returns the default registration socket path (see [`crate::agent::socket_dir_for_env`]).
pub fn default_register_sock_path() -> Result<PathBuf, AppError> {
    crate::agent::default_register_sock_path()
}

/// Interval between subtree scans of an ARMED conversation (live, presence lock held by the
/// attested agy, no credentials); nothing is scanned while no conversation is armed.
///
/// The credentials exist only while one of agy's `run_command` commands is running, so the
/// interval bounds the shortest command that is always seen: 100ms catches every command that
/// runs 100ms or longer, and a shorter one with probability (duration / 100ms). A missed command
/// costs one turn, because the hook request then fires. One scan of a live agy subtree measures
/// well under a millisecond, so 100ms keeps an armed conversation's cost below 1% of a core.
pub const AGY_PROC_WATCH_INTERVAL: Duration = Duration::from_millis(100);

/// Checks whether Arm A is actively watching `conv_id` (Linux, locks supported, presence lock
/// held by an attested agy process, and that process's `task/*/children` readable). Without the
/// `children` file the watcher reads nothing, so B′'s hook fires from the first turn.
pub fn is_conversation_proc_watched(config: &AgyConfig, conv_id: &str) -> bool {
    if !locks_supported(&config.proc_locks_path) {
        return false;
    }
    if config.trusted_agy_exes.is_empty() {
        return false;
    }
    let lock_path = config.presence_dir.join(format!("{conv_id}.lock"));
    let Ok(meta) = fs::metadata(&lock_path) else {
        return false;
    };
    use std::os::unix::fs::MetadataExt;
    let target_dev = meta.dev();
    let target_ino = meta.ino();
    let maj = dev_major(target_dev);
    let min = dev_minor(target_dev);

    let Ok(Some(holder_pid)) = find_lock_holder(&config.proc_locks_path, maj, min, target_ino)
    else {
        return false;
    };

    let trusted_canons: Vec<PathBuf> = config
        .trusted_agy_exes
        .iter()
        .map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();

    let exe_matches = match crate::process::exe_path(&config.proc_root, holder_pid) {
        Ok(exe) => {
            let exe_canon = fs::canonicalize(&exe).unwrap_or(exe);
            trusted_canons.contains(&exe_canon)
        }
        Err(_) => false,
    };
    if !exe_matches {
        return false;
    }

    let has_file_open = match crate::process::open_file_ids(&config.proc_root, holder_pid) {
        Ok(ids) => ids.contains(&(target_dev, target_ino)),
        Err(_) => false,
    };
    if !has_file_open {
        return false;
    }

    proc_children(&config.proc_root, holder_pid).is_some()
}

/// Per-watcher memory. Holds conversation ids only, never a credential value.
#[derive(Debug, Default)]
pub struct AgyProcWatch {
    /// Conversations whose unreadable `environ` has already been logged.
    unreadable_logged: HashSet<String>,
}

fn trusted_canons(config: &AgyConfig) -> Vec<PathBuf> {
    config
        .trusted_agy_exes
        .iter()
        .map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect()
}

/// The attested agy holding `conv_id`'s presence lock, with its start time, when the conversation
/// is eligible for the watcher: no non-stale credentials registered, and the lock held by a trusted
/// agy executable that has the lock file open.
fn eligible_holder(
    config: &AgyConfig,
    trusted_canons: &[PathBuf],
    store: &AgyStore,
    conv_id: &str,
) -> Option<(u32, String)> {
    let already_registered = store.read().unwrap().values().any(|info| {
        (info.conversation_id == conv_id || info.session_key == conv_id)
            && info.credentials.as_ref().is_some_and(|c| !c.is_stale)
    });
    if already_registered {
        return None;
    }

    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(config.presence_dir.join(format!("{conv_id}.lock"))).ok()?;
    let (target_dev, target_ino) = (meta.dev(), meta.ino());
    let holder_pid = find_lock_holder(
        &config.proc_locks_path,
        dev_major(target_dev),
        dev_minor(target_dev),
        target_ino,
    )
    .ok()??;

    let exe = crate::process::exe_path(&config.proc_root, holder_pid).ok()?;
    if !trusted_canons.contains(&fs::canonicalize(&exe).unwrap_or(exe)) {
        return None;
    }
    let ids = crate::process::open_file_ids(&config.proc_root, holder_pid).ok()?;
    if !ids.contains(&(target_dev, target_ino)) {
        return None;
    }
    let st = crate::process::starttime(&config.proc_root, holder_pid).ok()?;
    Some((holder_pid, st))
}

/// Every conversation in `presence_dir` that is eligible for the watcher now. The watcher runs this
/// once at start, so a conversation already live when `xmsg serve` (re)starts is watched without
/// waiting for its next turn.
pub fn eligible_agy_conversations(config: &AgyConfig, store: &AgyStore) -> Vec<String> {
    let canons = trusted_canons(config);
    let Ok(entries) = fs::read_dir(&config.presence_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("lock") {
                return None;
            }
            let conv_id = path.file_stem()?.to_str()?.to_string();
            eligible_holder(config, &canons, store, &conv_id).map(|_| conv_id)
        })
        .collect()
}

/// The children of `pid`, from `/proc/<pid>/task/<tid>/children` over all of its threads (a child
/// is listed under the thread that forked it). `None` where the kernel provides no such file
/// (`CONFIG_PROC_CHILDREN` off) or the process is gone.
fn proc_children(proc_root: &Path, pid: u32) -> Option<Vec<u32>> {
    let tasks = fs::read_dir(proc_root.join(pid.to_string()).join("task")).ok()?;
    let mut found = false;
    let mut kids = Vec::new();
    for task in tasks.flatten() {
        if let Ok(s) = fs::read_to_string(task.path().join("children")) {
            found = true;
            kids.extend(s.split_whitespace().filter_map(|t| t.parse::<u32>().ok()));
        }
    }
    found.then_some(kids)
}

/// Reads ONLY `ANTIGRAVITY_LS_ADDRESS` and `ANTIGRAVITY_CSRF_TOKEN` from an `environ` image.
fn agy_credentials_from_environ(bytes: &[u8]) -> Option<(String, String)> {
    let mut ls_address = None;
    let mut csrf_token = None;
    for chunk in bytes.split(|&b| b == 0) {
        if let Some(val) = chunk.strip_prefix(b"ANTIGRAVITY_LS_ADDRESS=") {
            ls_address = std::str::from_utf8(val).ok().filter(|v| !v.is_empty());
        } else if let Some(val) = chunk.strip_prefix(b"ANTIGRAVITY_CSRF_TOKEN=") {
            csrf_token = std::str::from_utf8(val).ok().filter(|v| !v.is_empty());
        }
    }
    Some((ls_address?.to_string(), csrf_token?.to_string()))
}

/// Looks for the credentials in the subtree of the attested agy `holder_pid` and registers
/// `conv_id` from the first process carrying both. Returns whether it registered.
///
/// Only the subtree is read: the walk descends from the holder through
/// `/proc/<pid>/task/<tid>/children`, and each listing is trusted only if its owner's start time
/// still matches its pin after the read. Where the holder has no `children` file (the kernel lacks
/// `CONFIG_PROC_CHILDREN`, or the holder is gone) nothing is read and the hook request covers the
/// conversation.
#[allow(clippy::too_many_arguments)]
async fn register_from_subtree(
    config: &AgyConfig,
    store: &AgyStore,
    db: &Arc<Mutex<rusqlite::Connection>>,
    my_uid: u32,
    conv_id: &str,
    holder_pid: u32,
    holder_st: &str,
    watch: &mut AgyProcWatch,
    reply_ttl: Duration,
) -> Result<bool, AppError> {
    let proc_root = &config.proc_root;
    let st_of = |pid: u32| crate::process::starttime(proc_root, pid).ok();

    // (pid, the parent it was listed under, that parent's pinned start time)
    let mut queue: VecDeque<(u32, u32, String)> = VecDeque::new();
    let Some(kids) = proc_children(proc_root, holder_pid) else {
        return Ok(false);
    };
    // The listing is the attested holder's only if the holder's start time still matches its pin:
    // a recycled holder pid's children are never read.
    if st_of(holder_pid).as_deref() != Some(holder_st) {
        return Ok(false);
    }
    queue.extend(
        kids.into_iter()
            .map(|c| (c, holder_pid, holder_st.to_string())),
    );

    let mut seen = HashSet::new();
    while let Some((p, parent, parent_st)) = queue.pop_front() {
        if p <= 1 || p == holder_pid || !seen.insert(p) {
            continue;
        }

        // Pin p's start time BEFORE the ancestry check, so one bracket covers the ancestry
        // check, the environ read and the re-read: a pid recycled anywhere inside it fails the
        // re-read and is never trusted.
        let Some(st_before) = st_of(p) else {
            continue;
        };

        // Scope rule: p must be in the attested agy's subtree.
        let in_subtree = crate::process::parent_pid(proc_root, p) == Some(parent)
            && st_of(parent).as_deref() == Some(parent_st.as_str());
        if !in_subtree {
            continue;
        }

        let creds = match fs::read(proc_root.join(p.to_string()).join("environ")) {
            Ok(bytes) => agy_credentials_from_environ(&bytes),
            Err(e) => {
                // Fallback rule: an unreadable environ leaves the conversation to the hook
                // request. Logged once per conversation, never with values.
                if watch.unreadable_logged.insert(conv_id.to_string()) {
                    tracing::debug!(
                        conversation_id = %conv_id,
                        pid = p,
                        "cannot read environ of an agy descendant ({e}); the hook request covers this conversation"
                    );
                }
                None
            }
        };

        // Start-time re-read: a recycled pid is never trusted, nor descended into.
        if st_of(p).as_deref() != Some(st_before.as_str()) {
            continue;
        }
        if st_of(holder_pid).as_deref() != Some(holder_st) {
            return Ok(false);
        }

        if let Some((ls_address, csrf_token)) = creds {
            let req = AgyRegisterRequest {
                conversation_id: conv_id.to_string(),
                ls_address,
                csrf_token,
            };
            // The same verification `xmsg register agy` gets, with the process that supplied the
            // credentials as the peer: its ancestry must reach the lock-holding agy.
            match verify_registration(
                proc_root,
                &config.proc_locks_path,
                &config.presence_dir,
                &config.trusted_agy_exes,
                my_uid,
                my_uid,
                p,
                &req,
            ) {
                Ok(reg) => {
                    let session_info = AgySessionInfo::new_with_credentials(
                        conv_id.to_string(),
                        reg.pid,
                        reg.starttime,
                        AgyCredentials {
                            ls_address: req.ls_address,
                            csrf_token: req.csrf_token,
                            is_stale: false,
                        },
                    );
                    store
                        .write()
                        .unwrap()
                        .insert(reg.session_key.clone(), session_info);
                    flush_agy_queue(config, store, db, &reg.session_key, conv_id, reply_ttl).await;
                    return Ok(true);
                }
                Err(e) => {
                    tracing::debug!(
                        conversation_id = %conv_id,
                        "verify_registration failed during proc scan: {e}"
                    );
                }
            }
        }

        if let Some(kids) = proc_children(proc_root, p) {
            if st_of(p).as_deref() == Some(st_before.as_str()) {
                queue.extend(kids.into_iter().map(|c| (c, p, st_before.clone())));
            }
        }
    }
    Ok(false)
}

/// Scans the attested agy's process subtree for each conversation in `conv_ids` that is eligible
/// (presence lock held by the attested agy, no credentials), reading ONLY `ANTIGRAVITY_LS_ADDRESS`
/// and `ANTIGRAVITY_CSRF_TOKEN` from `/proc/<pid>/environ`, and registers each one found through
/// [`verify_registration`]. Returns the conversations still eligible after the scan, which the
/// watcher keeps watching; a registered or ineligible conversation drops out.
pub async fn scan_and_register_agy_proc(
    config: &AgyConfig,
    store: &AgyStore,
    db: &Arc<Mutex<rusqlite::Connection>>,
    my_uid: u32,
    conv_ids: &[String],
    watch: &mut AgyProcWatch,
    reply_ttl: Duration,
) -> Result<Vec<String>, AppError> {
    if !locks_supported(&config.proc_locks_path) || config.trusted_agy_exes.is_empty() {
        return Ok(Vec::new());
    }
    let canons = trusted_canons(config);
    let mut still_eligible = Vec::new();
    for conv_id in conv_ids {
        let Some((holder_pid, holder_st)) = eligible_holder(config, &canons, store, conv_id) else {
            continue;
        };
        if !register_from_subtree(
            config, store, db, my_uid, conv_id, holder_pid, &holder_st, watch, reply_ttl,
        )
        .await?
        {
            still_eligible.push(conv_id.clone());
        }
    }
    Ok(still_eligible)
}

/// The watcher behind [`run_register_server`]. It watches only ARMED conversations: those eligible
/// when it starts, and those the hook's `check` reports as watched. With nothing armed it blocks on
/// `arm_rx` and does no work at all; an armed conversation is scanned every
/// [`AGY_PROC_WATCH_INTERVAL`] until it registers or stops being eligible.
pub async fn run_agy_proc_watcher(
    config: AgyConfig,
    store: AgyStore,
    db: Arc<Mutex<rusqlite::Connection>>,
    my_uid: u32,
    mut arm_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    reply_ttl: Duration,
) {
    if !locks_supported(&config.proc_locks_path) || config.trusted_agy_exes.is_empty() {
        tracing::info!(
            "agy proc watcher off (no /proc/locks on this platform, or no trusted agy executable); agy conversations register through the hook request"
        );
        return;
    }
    let mut watch = AgyProcWatch::default();
    let mut armed: HashSet<String> = eligible_agy_conversations(&config, &store)
        .into_iter()
        .collect();
    loop {
        if armed.is_empty() {
            let Some(conv_id) = arm_rx.recv().await else {
                return;
            };
            armed.insert(conv_id);
        } else {
            tokio::time::sleep(AGY_PROC_WATCH_INTERVAL).await;
        }
        while let Ok(conv_id) = arm_rx.try_recv() {
            armed.insert(conv_id);
        }
        let ids: Vec<String> = armed.drain().collect();
        match scan_and_register_agy_proc(&config, &store, &db, my_uid, &ids, &mut watch, reply_ttl)
            .await
        {
            Ok(still) => armed.extend(still),
            Err(e) => {
                tracing::debug!("agy proc scan failed: {e}");
                armed.extend(ids);
            }
        }
    }
}

/// Runs the registration Unix domain socket server multiplexing agy and pi harnesses.
#[allow(clippy::too_many_arguments)]
pub async fn run_register_server(
    sock_path: PathBuf,
    state: Arc<crate::http::AppState>,
    my_uid: u32,
    trusted_svc_exes: HashMap<String, PathBuf>,
) -> io::Result<()> {
    let config = state.agy_config.clone();
    let store = state.agy_store.clone();
    let pi_store = state.pi_store.clone();
    let db = state.db.clone();
    let pi_notify_tx = state.pi_notify_tx.clone();
    let reply_ttl = state.reply_ttl;
    if let Some(parent) = sock_path.parent() {
        if let Err(e) = crate::agent::ensure_secure_socket_dir(parent, my_uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                e.to_string(),
            ));
        }
    }
    if sock_path.exists() {
        if tokio::net::UnixStream::connect(&sock_path).await.is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "another server instance is actively listening on {}",
                    sock_path.display()
                ),
            ));
        }
        let _ = fs::remove_file(&sock_path);
    }

    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    fs::set_permissions(
        &sock_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("failed to set permissions on {}: {e}", sock_path.display()),
        )
    })?;

    let stand_down_counts: Arc<tokio::sync::RwLock<HashMap<String, u32>>> =
        Arc::new(tokio::sync::RwLock::new(HashMap::new()));

    let (arm_tx, arm_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let watcher_config = config.clone();
    let watcher_store = store.clone();
    let watcher_db = db.clone();
    tokio::spawn(async move {
        run_agy_proc_watcher(
            watcher_config,
            watcher_store,
            watcher_db,
            my_uid,
            arm_rx,
            reply_ttl,
        )
        .await;
    });

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("register server accept error: {e}");
                continue;
            }
        };

        let peer = match crate::process::peer_cred(&stream) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("failed to get peer creds: {e}");
                continue;
            }
        };

        let config_clone = config.clone();
        let store_clone = store.clone();
        let pi_store_clone = pi_store.clone();
        let db_clone = db.clone();
        let pi_notify_tx_clone = pi_notify_tx.clone();
        let state_clone = state.clone();
        let trusted_svc_exes_clone = trusted_svc_exes.clone();
        let stand_down_counts_clone = stand_down_counts.clone();
        let arm_tx_clone = arm_tx.clone();

        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut byte_buf = Vec::new();
            let max_frame = 65536;

            let read_res = tokio::time::timeout(
                Duration::from_secs(30),
                (&mut buf_reader)
                    .take((max_frame + 1) as u64)
                    .read_until(b'\n', &mut byte_buf),
            )
            .await;

            let n = match read_res {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    tracing::warn!("register.sock read error: {e}");
                    return;
                }
                Err(_) => {
                    tracing::warn!("register.sock connection timed out waiting for initial frame");
                    return;
                }
            };

            if n == 0 {
                return;
            }

            if byte_buf.len() > max_frame || (n >= max_frame && !byte_buf.ends_with(b"\n")) {
                let err = serde_json::json!({
                    "status": "error",
                    "detail": "frame exceeds maximum allowed size"
                });
                let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
                return;
            }

            if !byte_buf.ends_with(b"\n") {
                return;
            }

            let line = match std::str::from_utf8(&byte_buf) {
                Ok(s) => s,
                Err(_) => {
                    let err = serde_json::json!({
                        "status": "error",
                        "detail": "invalid utf-8"
                    });
                    let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
                    return;
                }
            };

            if !line.trim().is_empty() {
                let val: Result<serde_json::Value, _> = serde_json::from_str(line.trim());
                match val {
                    Ok(ref v)
                        if v.get("action").and_then(|a| a.as_str()) == Some("check")
                            || v.get("action").and_then(|a| a.as_str())
                                == Some("has_credentials") =>
                    {
                        let conv_id = v
                            .get("conversation_id")
                            .or_else(|| v.get("conversationId"))
                            .and_then(|c| c.as_str())
                            .unwrap_or("");
                        let has_creds = {
                            let store_lock = store_clone.read().unwrap();
                            store_lock.values().any(|info| {
                                (info.conversation_id == conv_id || info.session_key == conv_id)
                                    && info
                                        .credentials
                                        .as_ref()
                                        .map(|c| !c.is_stale)
                                        .unwrap_or(false)
                            })
                        };
                        let (watching, stand_down) = if has_creds {
                            stand_down_counts_clone.write().await.remove(conv_id);
                            (false, false)
                        } else {
                            let is_watched = is_conversation_proc_watched(&config_clone, conv_id);
                            if is_watched {
                                // Arm the watcher: this turn's commands are where the
                                // credentials appear.
                                let _ = arm_tx_clone.send(conv_id.to_string());
                                let mut counts = stand_down_counts_clone.write().await;
                                let count = counts.entry(conv_id.to_string()).or_insert(0);
                                *count += 1;
                                (true, *count == 1)
                            } else {
                                stand_down_counts_clone.write().await.remove(conv_id);
                                (false, false)
                            }
                        };
                        let resp = serde_json::json!({
                            "status": "ok",
                            "hasCredentials": has_creds,
                            "has_credentials": has_creds,
                            "watching": watching,
                            "stand_down": stand_down,
                            "standDown": stand_down,
                        });
                        let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                    }
                    Ok(ref v) if v.get("harness").and_then(|h| h.as_str()) == Some("pi") => {
                        match serde_json::from_value::<crate::pi::PiRegisterRequest>(v.clone()) {
                            Ok(req) => {
                                if let Err(e) = crate::pi::handle_pi_connection_peer(
                                    buf_reader,
                                    writer,
                                    config_clone.proc_root.clone(),
                                    pi_store_clone,
                                    my_uid,
                                    peer,
                                    req,
                                    db_clone,
                                    pi_notify_tx_clone,
                                    reply_ttl,
                                )
                                .await
                                {
                                    tracing::warn!("pi connection ended with error: {e}");
                                }
                            }
                            Err(e) => {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "detail": format!("invalid pi request: {e}")
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            }
                        }
                    }
                    Ok(ref v)
                        if v.get("harness")
                            .and_then(|h| h.as_str())
                            .and_then(crate::plugin::harness)
                            .is_some() =>
                    {
                        match serde_json::from_value::<crate::plugin::PluginHello>(v.clone()) {
                            Ok(hello) => {
                                let harness = crate::plugin::harness(&hello.harness)
                                    .expect("matched a plugin harness");
                                if let Err(e) = crate::plugin::handle_plugin_connection_peer(
                                    buf_reader,
                                    writer,
                                    state_clone,
                                    harness,
                                    my_uid,
                                    peer,
                                )
                                .await
                                {
                                    tracing::warn!("plugin connection ended with error: {e}");
                                }
                            }
                            Err(e) => {
                                let err = crate::error::AppError::BadRequest(e.to_string()).frame();
                                let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
                            }
                        }
                    }
                    Ok(ref v) if v.get("harness").and_then(|h| h.as_str()) == Some("svc") => {
                        match serde_json::from_value::<crate::svc::SvcRegisterRequest>(v.clone()) {
                            Ok(req) => {
                                if let Err(e) = crate::svc::handle_svc_connection_peer(
                                    buf_reader,
                                    writer,
                                    state_clone,
                                    &trusted_svc_exes_clone,
                                    my_uid,
                                    peer,
                                    req,
                                    false,
                                    None,
                                )
                                .await
                                {
                                    tracing::warn!("svc connection ended with error: {e}");
                                }
                            }
                            Err(e) => {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "detail": format!("invalid svc request: {e}")
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            }
                        }
                    }
                    Ok(v) => match serde_json::from_value::<AgyRegisterRequest>(v) {
                        Ok(req) => {
                            match verify_registration_peer(
                                &config_clone.proc_root,
                                &config_clone.proc_locks_path,
                                &config_clone.presence_dir,
                                &config_clone.trusted_agy_exes,
                                my_uid,
                                &peer,
                                &req,
                            ) {
                                Ok(reg) => {
                                    let session_info = AgySessionInfo::new_with_credentials(
                                        req.conversation_id.clone(),
                                        reg.pid,
                                        reg.starttime.clone(),
                                        AgyCredentials {
                                            ls_address: req.ls_address,
                                            csrf_token: req.csrf_token,
                                            is_stale: false,
                                        },
                                    );
                                    {
                                        let mut store_lock = store_clone.write().unwrap();
                                        store_lock.insert(reg.session_key.clone(), session_info);
                                    }
                                    stand_down_counts_clone
                                        .write()
                                        .await
                                        .remove(&req.conversation_id);
                                    let resp = serde_json::json!({
                                        "status": "ok",
                                        "sessionId": reg.session_key,
                                    });
                                    let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;

                                    flush_agy_queue(
                                        &config_clone,
                                        &store_clone,
                                        &db_clone,
                                        &reg.session_key,
                                        &req.conversation_id,
                                        reply_ttl,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    tracing::warn!("registration rejected: {e}");
                                    let err_resp = serde_json::json!({
                                        "status": "error",
                                        "detail": e.to_string()
                                    });
                                    let _ =
                                        writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                                }
                            }
                        }
                        Err(_) => {
                            let _ = writer
                                .write_all(b"{\"status\":\"error\",\"detail\":\"invalid json\"}\n")
                                .await;
                        }
                    },
                    Err(_) => {
                        let _ = writer
                            .write_all(b"{\"status\":\"error\",\"detail\":\"invalid json\"}\n")
                            .await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_locks_are_supported_everywhere() {
        assert!(locks_supported(Path::new("/tmp/fixture/locks")));
        assert_eq!(
            locks_supported(Path::new(LIVE_PROC_LOCKS)),
            cfg!(target_os = "linux")
        );
    }

    #[test]
    fn registration_without_trusted_exes_is_rejected() {
        let req = AgyRegisterRequest {
            conversation_id: "c".to_string(),
            ls_address: "127.0.0.1:1".to_string(),
            csrf_token: "t".to_string(),
        };
        let uid = current_uid();
        let err = verify_registration(
            Path::new(crate::process::LIVE_PROC_ROOT),
            Path::new(LIVE_PROC_LOCKS),
            Path::new("/nonexistent"),
            &[],
            uid,
            uid,
            std::process::id(),
            &req,
        )
        .unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(ref d) if d.contains("no trusted agy executable configured"))
        );
    }
}
