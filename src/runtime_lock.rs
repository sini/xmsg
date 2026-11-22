use crate::install_paths::{
    canonicalize_best_effort, validate_private_dir, validate_socket_path, BindingKind,
    InstallError, NamespaceIdentity,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UnixListener;

#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(any(test, feature = "test-hooks"))]
static STATE_LOCK_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "test-hooks"))]
pub fn state_lock_attempts() -> usize {
    STATE_LOCK_ATTEMPTS.load(Ordering::SeqCst)
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn reset_state_lock_attempts() {
    STATE_LOCK_ATTEMPTS.store(0, Ordering::SeqCst);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishPrimitive {
    RenameNoReplace,
    LinkUnlink,
}

#[cfg(any(test, feature = "test-hooks"))]
pub mod publish_control {
    use super::PublishPrimitive;
    use std::sync::Mutex;

    static FORCED_PRIMITIVE: Mutex<Option<PublishPrimitive>> = Mutex::new(None);

    pub fn force_primitive(primitive: Option<PublishPrimitive>) {
        *FORCED_PRIMITIVE.lock().unwrap() = primitive;
    }

    pub(crate) fn forced() -> Option<PublishPrimitive> {
        *FORCED_PRIMITIVE.lock().unwrap()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeLockError {
    #[error(transparent)]
    Install(#[from] InstallError),
    #[error("state lock {path} is already held by another live daemon")]
    StateLockHeld { path: PathBuf },
    #[error("endpoint lock {path} is already held by another owner")]
    EndpointLockHeld { path: PathBuf },
    #[error("runtime directory {path} lacks matching durable identity proof: {detail}")]
    UnprovenRuntimeDir { path: PathBuf, detail: String },
    #[error("endpoint {path} is occupied by a live listener")]
    EndpointOccupied { path: PathBuf },
    #[error("refusing to unlink unproven existing socket at {path}: {detail}")]
    UnprovenExistingSocket { path: PathBuf, detail: String },
    #[error("temporary socket name exhausted in {parent} for final basename {final_name}")]
    TempNameExhausted { parent: PathBuf, final_name: String },
    #[error("atomic socket publication collision at {path}: an incumbent already exists")]
    PublishCollision { path: PathBuf },
    #[error("no supported atomic no-replace publication primitive is available for {path}")]
    NoReplaceUnsupported { path: PathBuf },
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Exclusive non-blocking per-state lock (`<state_root>/serve.lock`), held for the daemon lifetime.
#[derive(Debug)]
pub struct StateLock {
    _file: File,
    pub path: PathBuf,
}

impl StateLock {
    pub fn try_acquire(state_root: &Path) -> Result<Self, RuntimeLockError> {
        let path = state_root.join("serve.lock");
        #[cfg(any(test, feature = "test-hooks"))]
        STATE_LOCK_ATTEMPTS.fetch_add(1, Ordering::SeqCst);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| RuntimeLockError::Io {
                path: path.clone(),
                source,
            })?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                || err.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(RuntimeLockError::StateLockHeld { path });
            }
            return Err(RuntimeLockError::Io { path, source: err });
        }
        Ok(Self { _file: file, path })
    }
}

/// Exclusive non-blocking per-endpoint lock (`<parent>/.<basename>.lock`), held for daemon lifetime.
#[derive(Debug)]
pub struct EndpointLock {
    _file: File,
    pub path: PathBuf,
}

impl EndpointLock {
    pub fn lock_path_for(endpoint_path: &Path) -> Result<PathBuf, RuntimeLockError> {
        let parent = endpoint_path.parent().ok_or_else(|| RuntimeLockError::Io {
            path: endpoint_path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no parent"),
        })?;
        let name = endpoint_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RuntimeLockError::Io {
                path: endpoint_path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "endpoint has invalid basename",
                ),
            })?;
        Ok(parent.join(format!(".{name}.lock")))
    }

    pub fn try_acquire(endpoint_path: &Path, expected_uid: u32) -> Result<Self, RuntimeLockError> {
        let parent = endpoint_path.parent().ok_or_else(|| RuntimeLockError::Io {
            path: endpoint_path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no parent"),
        })?;
        let canon_parent = validate_private_dir(parent, expected_uid)?;
        let name = endpoint_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RuntimeLockError::Io {
                path: endpoint_path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "endpoint has invalid basename",
                ),
            })?;
        let path = canon_parent.join(format!(".{name}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| RuntimeLockError::Io {
                path: path.clone(),
                source,
            })?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                || err.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(RuntimeLockError::EndpointLockHeld { path });
            }
            return Err(RuntimeLockError::Io { path, source: err });
        }
        Ok(Self { _file: file, path })
    }
}

/// Acquires per-endpoint locks in deterministic sorted `(canonical_parent, basename)` order.
pub fn acquire_endpoint_locks_sorted(
    endpoints: &[PathBuf],
    expected_uid: u32,
) -> Result<Vec<EndpointLock>, RuntimeLockError> {
    let mut keyed: Vec<(PathBuf, String, PathBuf)> = Vec::with_capacity(endpoints.len());
    for ep in endpoints {
        let parent = ep.parent().ok_or_else(|| RuntimeLockError::Io {
            path: ep.clone(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no parent"),
        })?;
        let canon_parent = validate_private_dir(parent, expected_uid)?;
        let name = ep
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        keyed.push((canon_parent, name, ep.clone()));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    keyed.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    let mut locks = Vec::with_capacity(keyed.len());
    for (_, _, ep) in keyed {
        locks.push(EndpointLock::try_acquire(&ep, expected_uid)?);
    }
    Ok(locks)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDirRecord {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub identity_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundEndpointRecord {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub kind: BindingKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEndpointRecord {
    pub final_path: PathBuf,
    pub tmp_path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub kind: BindingKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerRecord {
    pub version: u32,
    pub pid: u32,
    pub uid: u32,
    pub started_at_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_dir: Option<RuntimeDirRecord>,
    #[serde(default)]
    pub endpoints: BTreeMap<String, BoundEndpointRecord>,
    #[serde(default)]
    pub pending: BTreeMap<String, PendingEndpointRecord>,
}

impl OwnerRecord {
    pub fn new(uid: u32, manager_hint: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self {
            version: 1,
            pid: std::process::id(),
            uid,
            started_at_unix: now,
            manager_hint,
            runtime_dir: None,
            endpoints: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }

    pub fn load(state_root: &Path) -> Result<Option<Self>, RuntimeLockError> {
        let path = state_root.join("owner.json");
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(RuntimeLockError::Install(InstallError::SymlinkNotAllowed {
                        path,
                    }));
                }
                let bytes = fs::read(&path).map_err(|source| RuntimeLockError::Io {
                    path: path.clone(),
                    source,
                })?;
                let rec = serde_json::from_slice(&bytes).map_err(|e| RuntimeLockError::Io {
                    path,
                    source: io::Error::new(io::ErrorKind::InvalidData, e),
                })?;
                Ok(Some(rec))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(RuntimeLockError::Io { path, source }),
        }
    }

    pub fn save(&self, state_root: &Path) -> Result<(), RuntimeLockError> {
        let path = state_root.join("owner.json");
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| RuntimeLockError::Io {
            path: path.clone(),
            source: io::Error::other(e),
        })?;
        atomic_write_private(&path, &bytes)
    }
}

fn atomic_write_private(target: &Path, bytes: &[u8]) -> Result<(), RuntimeLockError> {
    let parent = target.parent().ok_or_else(|| RuntimeLockError::Io {
        path: target.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "target has no parent"),
    })?;
    let mut rand = [0u8; 4];
    getrandom::fill(&mut rand).map_err(|e| RuntimeLockError::Io {
        path: target.to_path_buf(),
        source: io::Error::other(e),
    })?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".into());
    let tmp = parent.join(format!(
        ".{name}.{:x}.{:08x}.tmp",
        std::process::id(),
        u32::from_ne_bytes(rand)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|source| RuntimeLockError::Io {
            path: tmp.clone(),
            source,
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| {
            let _ = fs::remove_file(&tmp);
            RuntimeLockError::Io {
                path: tmp.clone(),
                source,
            }
        })?;
    drop(file);
    fs::rename(&tmp, target).map_err(|source| {
        let _ = fs::remove_file(&tmp);
        RuntimeLockError::Io {
            path: target.to_path_buf(),
            source,
        }
    })?;
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Establishes or reuses the managed runtime directory under the held `StateLock`.
///
/// - New directory: created exclusively at `0700`; `owner.runtime_dir` is persisted to `owner.json`
///   **before** `identity.json` is written.
/// - Existing directory: validated at `0700`/UID; reused ONLY when durable proof in `owner.json`
///   matches `(canon_path, dev, ino, uid)` AND `identity.json` either matches or is missing (re-stamped
///   atomically from durable proof). An unproven directory (even if empty) or mismatched marker refuses.
pub fn ensure_managed_runtime_dir(
    _state_lock: &StateLock,
    state_root: &Path,
    runtime_dir: &Path,
    ns_identity: &NamespaceIdentity,
    owner: &mut OwnerRecord,
    expected_uid: u32,
) -> Result<PathBuf, RuntimeLockError> {
    let created = match DirBuilder::new()
        .recursive(false)
        .mode(0o700)
        .create(runtime_dir)
    {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(source) => {
            return Err(RuntimeLockError::Io {
                path: runtime_dir.to_path_buf(),
                source,
            });
        }
    };

    let canon = validate_private_dir(runtime_dir, expected_uid)?;
    let meta = fs::symlink_metadata(&canon).map_err(|source| RuntimeLockError::Io {
        path: canon.clone(),
        source,
    })?;
    let marker_path = canon.join("identity.json");

    if created {
        owner.runtime_dir = Some(RuntimeDirRecord {
            path: canon.clone(),
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            identity_bytes: ns_identity.marker_bytes.clone(),
        });
        owner.save(state_root)?;
        atomic_write_private(&marker_path, &ns_identity.marker_bytes)?;
        return Ok(canon);
    }

    // Existing directory: require durable identity proof in owner.json!
    let Some(recorded) = owner.runtime_dir.as_ref() else {
        return Err(RuntimeLockError::UnprovenRuntimeDir {
            path: canon,
            detail: "no durable runtime_dir proof in owner.json (offline ownership reconciliation required)".into(),
        });
    };
    let rec_canon =
        canonicalize_best_effort(&recorded.path).unwrap_or_else(|_| recorded.path.clone());
    if rec_canon != canon
        || recorded.dev != meta.dev()
        || recorded.ino != meta.ino()
        || recorded.uid != meta.uid()
        || recorded.identity_bytes != ns_identity.marker_bytes
    {
        return Err(RuntimeLockError::UnprovenRuntimeDir {
            path: canon,
            detail: "existing runtime directory identity does not match durable owner.json record"
                .into(),
        });
    }

    match fs::symlink_metadata(&marker_path) {
        Ok(m) => {
            if m.file_type().is_symlink() || !m.is_file() {
                return Err(RuntimeLockError::UnprovenRuntimeDir {
                    path: marker_path,
                    detail: "identity.json is not a regular file".into(),
                });
            }
            if m.uid() != expected_uid || (m.mode() & 0o777) != 0o600 {
                return Err(RuntimeLockError::UnprovenRuntimeDir {
                    path: marker_path,
                    detail: format!(
                        "identity.json has unsafe owner/mode (uid={}, mode={:04o})",
                        m.uid(),
                        m.mode() & 0o777
                    ),
                });
            }
            let actual = fs::read(&marker_path).map_err(|source| RuntimeLockError::Io {
                path: marker_path.clone(),
                source,
            })?;
            if actual != ns_identity.marker_bytes {
                return Err(RuntimeLockError::UnprovenRuntimeDir {
                    path: marker_path,
                    detail: "identity.json bytes mismatch expected state identity".into(),
                });
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Cleaner removed only identity.json: re-stamp atomically under held state lock
            // because durable owner.json proved this exact (path, dev, ino, uid).
            atomic_write_private(&marker_path, &ns_identity.marker_bytes)?;
        }
        Err(source) => {
            return Err(RuntimeLockError::Io {
                path: marker_path,
                source,
            });
        }
    }

    Ok(canon)
}

/// Periodic maintenance check for a running daemon: re-verifies the managed runtime directory
/// against the durable record and atomically re-stamps `identity.json` if a cleaner removed it.
/// Refuses without overwriting if the directory was replaced or the marker mismatches.
pub fn verify_and_restamp_runtime_marker(
    _state_lock: &StateLock,
    recorded: &RuntimeDirRecord,
    expected_uid: u32,
) -> Result<bool, RuntimeLockError> {
    let canon = validate_private_dir(&recorded.path, expected_uid)?;
    let meta = fs::symlink_metadata(&canon).map_err(|source| RuntimeLockError::Io {
        path: canon.clone(),
        source,
    })?;
    let rec_canon =
        canonicalize_best_effort(&recorded.path).unwrap_or_else(|_| recorded.path.clone());
    if rec_canon != canon
        || recorded.dev != meta.dev()
        || recorded.ino != meta.ino()
        || recorded.uid != meta.uid()
    {
        return Err(RuntimeLockError::UnprovenRuntimeDir {
            path: canon,
            detail: "live runtime directory no longer matches durable owner record".into(),
        });
    }
    let marker_path = canon.join("identity.json");
    match fs::symlink_metadata(&marker_path) {
        Ok(m) => {
            if m.file_type().is_symlink() || !m.is_file() || m.uid() != expected_uid {
                return Err(RuntimeLockError::UnprovenRuntimeDir {
                    path: marker_path,
                    detail: "live identity.json has unexpected type or owner".into(),
                });
            }
            let bytes = fs::read(&marker_path).map_err(|source| RuntimeLockError::Io {
                path: marker_path.clone(),
                source,
            })?;
            if bytes != recorded.identity_bytes {
                return Err(RuntimeLockError::UnprovenRuntimeDir {
                    path: marker_path,
                    detail: "live identity.json content mismatch".into(),
                });
            }
            Ok(false)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            atomic_write_private(&marker_path, &recorded.identity_bytes)?;
            Ok(true)
        }
        Err(source) => Err(RuntimeLockError::Io {
            path: marker_path,
            source,
        }),
    }
}

/// Validates a managed runtime directory for read-only clients (never creates or writes anything).
pub fn verify_runtime_dir_readonly(
    runtime_dir: &Path,
    ns_identity: &NamespaceIdentity,
    expected_uid: u32,
) -> Result<PathBuf, RuntimeLockError> {
    let canon = validate_private_dir(runtime_dir, expected_uid)?;
    let marker_path = canon.join("identity.json");
    let m = fs::symlink_metadata(&marker_path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            RuntimeLockError::UnprovenRuntimeDir {
                path: marker_path.clone(),
                detail: "identity.json is missing".into(),
            }
        } else {
            RuntimeLockError::Io {
                path: marker_path.clone(),
                source: e,
            }
        }
    })?;
    if m.file_type().is_symlink()
        || !m.is_file()
        || m.uid() != expected_uid
        || (m.mode() & 0o777) != 0o600
    {
        return Err(RuntimeLockError::UnprovenRuntimeDir {
            path: marker_path,
            detail: "identity.json failed ownership/type/mode validation".into(),
        });
    }
    let bytes = fs::read(&marker_path).map_err(|source| RuntimeLockError::Io {
        path: marker_path.clone(),
        source,
    })?;
    if bytes != ns_identity.marker_bytes {
        return Err(RuntimeLockError::UnprovenRuntimeDir {
            path: marker_path,
            detail: "identity.json mismatch".into(),
        });
    }
    Ok(canon)
}

/// Proof-authorized stale unlink + byte-bounded temporary bind + pending persistence + atomic
/// no-replace socket publication + record promotion.
///
/// Caller must hold `StateLock` (and `EndpointLock` for `BindingKind::Manual`).
#[allow(clippy::too_many_arguments)]
pub fn bind_and_publish_socket(
    _state_lock: &StateLock,
    endpoint_lock: Option<&EndpointLock>,
    state_root: &Path,
    endpoint_name: &str,
    final_path: &Path,
    kind: BindingKind,
    owner: &mut OwnerRecord,
    expected_uid: u32,
) -> Result<(UnixListener, PublishPrimitive), RuntimeLockError> {
    if kind == BindingKind::Manual && endpoint_lock.is_none() {
        return Err(RuntimeLockError::EndpointLockHeld {
            path: final_path.to_path_buf(),
        });
    }
    validate_socket_path(final_path)?;

    let parent = final_path.parent().ok_or_else(|| RuntimeLockError::Io {
        path: final_path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "socket path has no parent"),
    })?;
    let canon_parent = validate_private_dir(parent, expected_uid)?;
    let final_basename = final_path.file_name().ok_or_else(|| RuntimeLockError::Io {
        path: final_path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "socket path has no basename"),
    })?;
    let canon_final = canon_parent.join(final_basename);
    validate_socket_path(&canon_final)?;

    // Step 1: Proof-authorized stale unlink BEFORE replacing any existing record.
    reclaim_proven_stale_socket(endpoint_name, &canon_final, owner, expected_uid)?;
    // Clean up any leftover temp socket from a previous crashed attempt.
    if let Some(prev_pending) = owner.pending.remove(endpoint_name) {
        if prev_pending.tmp_path != canon_final {
            if let Ok(m) = fs::symlink_metadata(&prev_pending.tmp_path) {
                if m.file_type().is_socket()
                    && m.dev() == prev_pending.dev
                    && m.ino() == prev_pending.ino
                    && m.uid() == expected_uid
                {
                    let _ = fs::remove_file(&prev_pending.tmp_path);
                }
            }
        }
        owner.save(state_root)?;
    }

    // Step 2: Bind a private temporary socket in canon_parent with basename length <= final basename.
    let (listener, tmp_path) = bind_bounded_temp_socket(&canon_parent, final_basename)?;
    if let Err(source) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(&tmp_path);
        return Err(RuntimeLockError::Io {
            path: tmp_path,
            source,
        });
    }
    let tmp_meta = fs::symlink_metadata(&tmp_path).map_err(|source| {
        let _ = fs::remove_file(&tmp_path);
        RuntimeLockError::Io {
            path: tmp_path.clone(),
            source,
        }
    })?;

    // Step 3: Persist pending publication record BEFORE publishing.
    owner.pending.insert(
        endpoint_name.to_string(),
        PendingEndpointRecord {
            final_path: canon_final.clone(),
            tmp_path: tmp_path.clone(),
            dev: tmp_meta.dev(),
            ino: tmp_meta.ino(),
            uid: tmp_meta.uid(),
            kind,
        },
    );
    if let Err(e) = owner.save(state_root) {
        let _ = fs::remove_file(&tmp_path);
        owner.pending.remove(endpoint_name);
        return Err(e);
    }

    // Step 4: Test-only barrier immediately before atomic publication (H5).
    #[cfg(any(test, feature = "test-hooks"))]
    {
        crate::agent::socket_publish_hook::hit(&canon_final);
        if canon_final != final_path {
            crate::agent::socket_publish_hook::hit(final_path);
        }
    }

    // Step 5: Atomic no-replace publication.
    let primitive = match publish_no_replace(&tmp_path, &canon_final) {
        Ok(prim) => prim,
        Err(err) => {
            // Collision or publication error: remove ONLY candidate's temp node and pending record.
            let _ = fs::remove_file(&tmp_path);
            owner.pending.remove(endpoint_name);
            let _ = owner.save(state_root);
            return Err(err);
        }
    };

    // Step 6: Promote pending record to durable bound endpoint record.
    let bound_meta = fs::symlink_metadata(&canon_final).unwrap_or(tmp_meta);
    owner.pending.remove(endpoint_name);
    owner.endpoints.insert(
        endpoint_name.to_string(),
        BoundEndpointRecord {
            path: canon_final,
            dev: bound_meta.dev(),
            ino: bound_meta.ino(),
            uid: bound_meta.uid(),
            kind,
        },
    );
    owner.save(state_root)?;

    Ok((listener, primitive))
}

fn reclaim_proven_stale_socket(
    endpoint_name: &str,
    canon_final: &Path,
    owner: &mut OwnerRecord,
    expected_uid: u32,
) -> Result<(), RuntimeLockError> {
    let meta = match fs::symlink_metadata(canon_final) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(RuntimeLockError::Io {
                path: canon_final.to_path_buf(),
                source,
            });
        }
    };

    if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
        return Err(RuntimeLockError::UnprovenExistingSocket {
            path: canon_final.to_path_buf(),
            detail: "existing node is not a Unix domain socket".into(),
        });
    }
    if meta.uid() != expected_uid {
        return Err(RuntimeLockError::UnprovenExistingSocket {
            path: canon_final.to_path_buf(),
            detail: format!(
                "existing socket owned by UID {}, expected {expected_uid}",
                meta.uid()
            ),
        });
    }

    // Match against either durable bound record OR pending publication record (crash after
    // publication and before promotion, B1).
    let matches_bound = owner.endpoints.get(endpoint_name).is_some_and(|rec| {
        let rec_canon = canonicalize_best_effort(&rec.path).unwrap_or_else(|_| rec.path.clone());
        rec_canon == canon_final
            && rec.dev == meta.dev()
            && rec.ino == meta.ino()
            && rec.uid == expected_uid
    });
    let matches_pending = owner.pending.get(endpoint_name).is_some_and(|rec| {
        let rec_canon =
            canonicalize_best_effort(&rec.final_path).unwrap_or_else(|_| rec.final_path.clone());
        rec_canon == canon_final
            && rec.dev == meta.dev()
            && rec.ino == meta.ino()
            && rec.uid == expected_uid
    });
    if !matches_bound && !matches_pending {
        return Err(RuntimeLockError::UnprovenExistingSocket {
            path: canon_final.to_path_buf(),
            detail: "no matching recorded (path, dev, ino, uid) proof in owner.json".into(),
        });
    }

    // Check liveness: a live listener always refuses.
    if StdUnixStream::connect(canon_final).is_ok() {
        return Err(RuntimeLockError::EndpointOccupied {
            path: canon_final.to_path_buf(),
        });
    }

    fs::remove_file(canon_final).map_err(|source| RuntimeLockError::Io {
        path: canon_final.to_path_buf(),
        source,
    })?;
    if matches_bound {
        owner.endpoints.remove(endpoint_name);
    }
    if matches_pending {
        owner.pending.remove(endpoint_name);
    }
    Ok(())
}

fn bind_bounded_temp_socket(
    canon_parent: &Path,
    final_basename: &std::ffi::OsStr,
) -> Result<(UnixListener, PathBuf), RuntimeLockError> {
    let final_bytes = final_basename.as_bytes();
    let max_len = final_bytes.len();
    if max_len == 0 {
        return Err(RuntimeLockError::TempNameExhausted {
            parent: canon_parent.to_path_buf(),
            final_name: String::new(),
        });
    }

    // For multi-byte basenames (>= 2 bytes), try random dot-prefixed names of length <= max_len.
    if max_len >= 2 {
        let hex_chars = (max_len - 1).min(12);
        for _ in 0..64 {
            let mut rand = [0u8; 6];
            getrandom::fill(&mut rand).map_err(|e| RuntimeLockError::Io {
                path: canon_parent.to_path_buf(),
                source: io::Error::other(e),
            })?;
            let encoded = hex::encode(rand);
            let candidate_name = format!(".{}", &encoded[..hex_chars]);
            if candidate_name.as_bytes() == final_bytes {
                continue;
            }
            let tmp_path = canon_parent.join(&candidate_name);
            if validate_socket_path(&tmp_path).is_err() {
                continue;
            }
            match UnixListener::bind(&tmp_path) {
                Ok(listener) => return Ok((listener, tmp_path)),
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
                Err(source) => {
                    return Err(RuntimeLockError::Io {
                        path: tmp_path,
                        source,
                    });
                }
            }
        }
    }

    // Exact 1-byte fallback / exhaustive scan over all admissible 1-byte POSIX basenames
    // (1..=127 excluding '/' and '.' and the final basename itself).
    // Supports Q1's one-byte temporary-name exhaustion fixture deterministically without ever
    // falling back to binding `final_path` directly (`M-S8f`).
    for byte in 1u8..=127u8 {
        if byte == b'/' || byte == b'.' {
            continue;
        }
        let slice = [byte];
        if slice.as_slice() == final_bytes {
            continue;
        }
        // On case-insensitive filesystems (default APFS on macOS), an ASCII case-folded 1-byte
        // name would bind the final basename itself.
        if cfg!(target_os = "macos")
            && final_bytes.len() == 1
            && byte.eq_ignore_ascii_case(&final_bytes[0])
        {
            continue;
        }
        let name = std::ffi::OsStr::from_bytes(&slice);
        let tmp_path = canon_parent.join(name);
        if validate_socket_path(&tmp_path).is_err() {
            continue;
        }
        if fs::symlink_metadata(&tmp_path).is_ok() {
            continue;
        }
        match UnixListener::bind(&tmp_path) {
            Ok(listener) => return Ok((listener, tmp_path)),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(source) => {
                return Err(RuntimeLockError::Io {
                    path: tmp_path,
                    source,
                });
            }
        }
    }

    Err(RuntimeLockError::TempNameExhausted {
        parent: canon_parent.to_path_buf(),
        final_name: final_basename.to_string_lossy().into_owned(),
    })
}

fn cstring_path(path: &Path) -> Result<CString, RuntimeLockError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        RuntimeLockError::Install(InstallError::SocketPathNul {
            path: path.to_path_buf(),
        })
    })
}

fn is_unsupported_errno(errno: Option<i32>) -> bool {
    errno == Some(libc::ENOSYS)
        || errno == Some(libc::EOPNOTSUPP)
        || errno == Some(libc::ENOTSUP)
        || errno == Some(libc::EINVAL)
}

fn publish_via_link_unlink(tmp: &Path, dst: &Path) -> Result<PublishPrimitive, RuntimeLockError> {
    let src_c = cstring_path(tmp)?;
    let dst_c = cstring_path(dst)?;
    let rc = unsafe { libc::link(src_c.as_ptr(), dst_c.as_ptr()) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Err(RuntimeLockError::PublishCollision {
                path: dst.to_path_buf(),
            });
        }
        if is_unsupported_errno(err.raw_os_error()) {
            return Err(RuntimeLockError::NoReplaceUnsupported {
                path: dst.to_path_buf(),
            });
        }
        return Err(RuntimeLockError::Io {
            path: dst.to_path_buf(),
            source: err,
        });
    }
    let _ = fs::remove_file(tmp);
    Ok(PublishPrimitive::LinkUnlink)
}

fn publish_via_rename_noreplace(
    tmp: &Path,
    dst: &Path,
) -> Result<PublishPrimitive, RuntimeLockError> {
    let src_c = cstring_path(tmp)?;
    let dst_c = cstring_path(dst)?;

    #[cfg(target_os = "macos")]
    let rc = unsafe { libc::renamex_np(src_c.as_ptr(), dst_c.as_ptr(), libc::RENAME_EXCL) };

    #[cfg(target_os = "linux")]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dst_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        ) as libc::c_int
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let rc = {
        let _ = (&src_c, &dst_c);
        return Err(RuntimeLockError::NoReplaceUnsupported {
            path: dst.to_path_buf(),
        });
    };

    if rc == 0 {
        return Ok(PublishPrimitive::RenameNoReplace);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        return Err(RuntimeLockError::PublishCollision {
            path: dst.to_path_buf(),
        });
    }
    if is_unsupported_errno(err.raw_os_error()) {
        return Err(RuntimeLockError::NoReplaceUnsupported {
            path: dst.to_path_buf(),
        });
    }
    Err(RuntimeLockError::Io {
        path: dst.to_path_buf(),
        source: err,
    })
}

/// Publishes `tmp` at `dst` atomically without replacing any existing file/socket.
/// Falls through to `link()` + `unlink()` ONLY if the primary rename-noreplace syscall reports
/// unsupported (`ENOSYS`/`ENOTSUP`/`EOPNOTSUPP`/`EINVAL`). Never falls through on collision.
pub fn publish_no_replace(tmp: &Path, dst: &Path) -> Result<PublishPrimitive, RuntimeLockError> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(forced) = publish_control::forced() {
        return match forced {
            PublishPrimitive::RenameNoReplace => publish_via_rename_noreplace(tmp, dst),
            PublishPrimitive::LinkUnlink => publish_via_link_unlink(tmp, dst),
        };
    }

    match publish_via_rename_noreplace(tmp, dst) {
        Ok(prim) => Ok(prim),
        Err(RuntimeLockError::NoReplaceUnsupported { .. }) => publish_via_link_unlink(tmp, dst),
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_paths::compute_namespace_identity;
    use tempfile::tempdir;

    #[tokio::test]
    async fn state_lock_and_attempt_counter() {
        let tmp = tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let b0 = state_lock_attempts();
        let lock1 = StateLock::try_acquire(tmp.path()).unwrap();
        let b1 = state_lock_attempts();
        assert!(b1 > b0, "first acquire must increment attempt counter");
        assert!(matches!(
            StateLock::try_acquire(tmp.path()),
            Err(RuntimeLockError::StateLockHeld { .. })
        ));
        let b2 = state_lock_attempts();
        assert!(
            b2 > b1,
            "failed nonblocking acquire must increment attempt counter"
        );
        drop(lock1);
        let _lock2 = StateLock::try_acquire(tmp.path()).unwrap();
        assert!(state_lock_attempts() > b2);
    }

    #[tokio::test]
    async fn managed_runtime_dir_unproven_refused_and_marker_restamp_recovers() {
        let tmp = tempfile::Builder::new()
            .prefix("rl-")
            .tempdir_in("/tmp")
            .unwrap();
        let state = tmp.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let canon_state = fs::canonicalize(&state).unwrap();
        let ns_id = compute_namespace_identity(&canon_state).unwrap();
        let uid = unsafe { libc::geteuid() };

        // Unproven pre-existing empty runtime directory refuses!
        let ns_dir = tmp.path().join(&ns_id.dir_name);
        fs::create_dir(&ns_dir).unwrap();
        fs::set_permissions(&ns_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = StateLock::try_acquire(&canon_state).unwrap();
        let mut owner = OwnerRecord::new(uid, None);
        assert!(matches!(
            ensure_managed_runtime_dir(&lock, &canon_state, &ns_dir, &ns_id, &mut owner, uid),
            Err(RuntimeLockError::UnprovenRuntimeDir { .. })
        ));

        // Clean creation establishes durable proof + identity.json, then live marker removal recovers.
        fs::remove_dir(&ns_dir).unwrap();
        let canon_ns =
            ensure_managed_runtime_dir(&lock, &canon_state, &ns_dir, &ns_id, &mut owner, uid)
                .unwrap();
        assert!(canon_ns.join("identity.json").is_file());
        fs::remove_file(canon_ns.join("identity.json")).unwrap();
        assert!(verify_runtime_dir_readonly(&canon_ns, &ns_id, uid).is_err());
        let restamped =
            verify_and_restamp_runtime_marker(&lock, owner.runtime_dir.as_ref().unwrap(), uid)
                .unwrap();
        assert!(restamped);
        assert!(verify_runtime_dir_readonly(&canon_ns, &ns_id, uid).is_ok());
    }

    #[tokio::test]
    async fn publish_no_replace_both_arms_refuse_incumbent_and_exhaustion_refuses_without_bind() {
        let tmp = tempfile::Builder::new()
            .prefix("pub-")
            .tempdir_in("/tmp")
            .unwrap();
        let state = tmp.path().join("s");
        let socks = tmp.path().join("k");
        for d in [&state, &socks] {
            fs::create_dir(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let uid = unsafe { libc::geteuid() };
        let slock = StateLock::try_acquire(&state).unwrap();
        let mut owner = OwnerRecord::new(uid, None);

        for prim in [
            PublishPrimitive::RenameNoReplace,
            PublishPrimitive::LinkUnlink,
        ] {
            publish_control::force_primitive(Some(prim));
            let name = match prim {
                PublishPrimitive::RenameNoReplace => "a.sock",
                PublishPrimitive::LinkUnlink => "b.sock",
            };
            let ep = socks.join(name);
            let elock = EndpointLock::try_acquire(&ep, uid).unwrap();
            let (listener, used) = bind_and_publish_socket(
                &slock,
                Some(&elock),
                &state,
                name,
                &ep,
                BindingKind::Manual,
                &mut owner,
                uid,
            )
            .unwrap();
            assert_eq!(used, prim);
            assert!(StdUnixStream::connect(&ep).is_ok());
            drop(listener);

            // Recorded stale socket can be reclaimed under held locks.
            let (listener2, _) = bind_and_publish_socket(
                &slock,
                Some(&elock),
                &state,
                name,
                &ep,
                BindingKind::Manual,
                &mut owner,
                uid,
            )
            .unwrap();
            drop(listener2);

            // Unrecorded stale socket (deleted owner proof) is refused!
            owner.endpoints.remove(name);
            assert!(matches!(
                bind_and_publish_socket(
                    &slock,
                    Some(&elock),
                    &state,
                    name,
                    &ep,
                    BindingKind::Manual,
                    &mut owner,
                    uid,
                ),
                Err(RuntimeLockError::UnprovenExistingSocket { .. })
            ));
            fs::remove_file(&ep).unwrap();
        }
        publish_control::force_primitive(None);

        // One-byte temporary-name exhaustion fixture (Q1 / M-S8f): occupy every admissible 1-byte
        // name except 'z', leave 'z' absent, assert TempNameExhausted and 'z' remains absent!
        let exh = tmp.path().join("x");
        fs::create_dir(&exh).unwrap();
        fs::set_permissions(&exh, fs::Permissions::from_mode(0o700)).unwrap();
        for b in 1u8..=127u8 {
            if b == b'/' || b == b'.' || b == b'z' || (cfg!(target_os = "macos") && b == b'Z') {
                continue;
            }
            let p = exh.join(std::ffi::OsStr::from_bytes(&[b]));
            let _ = fs::write(&p, b"");
        }
        let target = exh.join("z");
        let elock = EndpointLock::try_acquire(&target, uid).unwrap();
        let err = bind_and_publish_socket(
            &slock,
            Some(&elock),
            &state,
            "z",
            &target,
            BindingKind::Manual,
            &mut owner,
            uid,
        )
        .unwrap_err();
        assert!(matches!(err, RuntimeLockError::TempNameExhausted { .. }));
        assert!(
            !target.exists(),
            "final name must never be bound directly on temporary-name exhaustion"
        );
    }
}
