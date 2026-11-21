use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};

/// Restricts newly created files/dirs/sockets to owner-only before any xmsg writer runs.
pub fn apply_process_umask() {
    unsafe {
        libc::umask(0o077);
    }
}

/// Samples the actual effective kernel umask via a round-trip and immediately restores it.
/// Must be called before spawning concurrent work so the temporary mask is unobservable.
pub fn sample_effective_umask() -> u32 {
    unsafe {
        let current = libc::umask(0o077);
        libc::umask(current);
        current as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    MacOs,
    Linux,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

pub trait HomeLookup: Send + Sync {
    fn account_home(&self, euid: u32) -> Option<PathBuf>;
}

#[derive(Default)]
pub struct SystemHomeLookup;

impl HomeLookup for SystemHomeLookup {
    fn account_home(&self, euid: u32) -> Option<PathBuf> {
        unsafe {
            let pw = libc::getpwuid(euid);
            if pw.is_null() || (*pw).pw_dir.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr((*pw).pw_dir).to_bytes();
            if bytes.is_empty() {
                return None;
            }
            Some(PathBuf::from(OsStr::from_bytes(bytes)))
        }
    }
}

pub struct FixtureHomeLookup(pub Option<PathBuf>);

impl HomeLookup for FixtureHomeLookup {
    fn account_home(&self, _euid: u32) -> Option<PathBuf> {
        self.0.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("account home directory is unavailable for effective UID {euid}")]
    AccountHomeUnavailable { euid: u32 },
    #[error("account home directory {path} is not absolute")]
    NonAbsoluteAccountHome { path: PathBuf },
    #[error(
        "HOME ({env_home}) does not match authoritative account home ({account_home}); unset HOME or match the account home"
    )]
    HomeMismatch {
        env_home: PathBuf,
        account_home: PathBuf,
    },
    #[error("{var} must be an absolute path (got {value:?})")]
    RelativeXdgRoot { var: &'static str, value: OsString },
    #[error("path {path} must not be a symlink")]
    SymlinkNotAllowed { path: PathBuf },
    #[error("path {path} is not a directory")]
    NotADirectory { path: PathBuf },
    #[error("directory {path} is owned by UID {actual}, expected UID {expected}")]
    UnsafeOwner {
        path: PathBuf,
        actual: u32,
        expected: u32,
    },
    #[error("directory {path} has permission bits {actual:04o}, expected 0700")]
    UnsafeMode { path: PathBuf, actual: u32 },
    #[error(
        "shared temporary parent {path} is unsafe (expected root-owned sticky directory, got uid={uid} mode={mode:04o})"
    )]
    UnsafeSharedTmp { path: PathBuf, uid: u32, mode: u32 },
    #[error("explicit parent directory {parent} does not exist for {target}")]
    MissingParent { parent: PathBuf, target: PathBuf },
    #[error("state root {path} does not exist (read-only lookup does not create state)")]
    MissingStateRoot { path: PathBuf },
    #[error(
        "socket path {path} ({bytes} OS bytes) exceeds {platform} sun_path limit ({max} bytes before NUL)"
    )]
    SocketPathTooLong {
        path: PathBuf,
        bytes: usize,
        max: usize,
        platform: &'static str,
    },
    #[error("socket path {path} contains an embedded NUL byte")]
    SocketPathNul { path: PathBuf },
    #[error("socket path {path} cannot be placed under another managed namespace")]
    InvalidEndpointPath { path: PathBuf, detail: String },
    #[error("legacy state conflict: {summary}")]
    LegacyConflict {
        summary: String,
        conflicts: Vec<LegacyConflict>,
    },
    #[error("live legacy listener detected at {path}; stop the legacy daemon or pin compatible explicit endpoints")]
    LegacyListenerActive { path: PathBuf },
    #[error("inconclusive metadata at {path}: {detail}")]
    InconclusiveMetadata { path: PathBuf, detail: String },
    #[error("filesystem error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

pub struct ResolveEnv<'a> {
    pub home: Option<OsString>,
    pub xdg_config_home: Option<OsString>,
    pub xdg_state_home: Option<OsString>,
    pub xdg_runtime_dir: Option<OsString>,
    pub darwin_user_temp_dir: Option<PathBuf>,
    pub system_tmp: PathBuf,
    pub platform: Platform,
    pub euid: u32,
    pub home_lookup: &'a dyn HomeLookup,
}

impl<'a> ResolveEnv<'a> {
    pub fn from_process(home_lookup: &'a dyn HomeLookup) -> Self {
        Self {
            home: std::env::var_os("HOME"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
            xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR"),
            darwin_user_temp_dir: crate::process::fallback_runtime_dir(),
            system_tmp: PathBuf::from("/tmp"),
            platform: Platform::current(),
            euid: unsafe { libc::geteuid() },
            home_lookup,
        }
    }
}

/// Normalizes a path by canonicalizing its longest existing ancestor and appending the remaining
/// lexical components. Used for comparing paths that may not yet exist on disk.
pub fn canonicalize_best_effort(path: &Path) -> Result<PathBuf, io::Error> {
    if let Ok(c) = fs::canonicalize(path) {
        return Ok(c);
    }
    let mut existing = path.to_path_buf();
    let mut tail = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            break;
        };
        tail.push(name.to_os_string());
        if !existing.pop() {
            break;
        }
    }
    let mut base = if existing.as_os_str().is_empty() {
        PathBuf::new()
    } else {
        fs::canonicalize(&existing).unwrap_or(existing)
    };
    for part in tail.into_iter().rev() {
        base.push(part);
    }
    Ok(normalize_lexical(&base))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolves the authoritative account home from `getpwuid(geteuid())`.
/// Refuses missing/non-absolute account homes or a set `HOME` that canonicalizes elsewhere.
pub fn resolve_account_home(env: &ResolveEnv<'_>) -> Result<PathBuf, InstallError> {
    let account = env
        .home_lookup
        .account_home(env.euid)
        .ok_or(InstallError::AccountHomeUnavailable { euid: env.euid })?;
    if !account.is_absolute() {
        return Err(InstallError::NonAbsoluteAccountHome { path: account });
    }
    let canon_account = canonicalize_best_effort(&account).unwrap_or_else(|_| account.clone());
    if let Some(raw_home) = env.home.as_deref() {
        if !raw_home.is_empty() {
            let env_path = PathBuf::from(raw_home);
            if !env_path.is_absolute() {
                return Err(InstallError::HomeMismatch {
                    env_home: env_path,
                    account_home: canon_account,
                });
            }
            let canon_env =
                canonicalize_best_effort(&env_path).unwrap_or_else(|_| env_path.clone());
            if canon_env != canon_account {
                return Err(InstallError::HomeMismatch {
                    env_home: env_path,
                    account_home: canon_account,
                });
            }
        }
    }
    Ok(canon_account)
}

/// Resolves the account home for optional harness discovery inputs.
/// Returns `None` when the account home is unavailable or `HOME` mismatches — never falls back to CWD.
pub fn resolve_optional_home(env: &ResolveEnv<'_>) -> Option<PathBuf> {
    resolve_account_home(env).ok()
}

/// Expands a literal `~` or `~/` prefix using the authoritative account home rule.
/// Literal non-tilde paths never resolve the account home.
pub fn expand_explicit_path(raw: &Path, env: &ResolveEnv<'_>) -> Result<PathBuf, InstallError> {
    if raw == Path::new("~") {
        return resolve_account_home(env);
    }
    if let Ok(stripped) = raw.strip_prefix("~/") {
        return Ok(resolve_account_home(env)?.join(stripped));
    }
    Ok(raw.to_path_buf())
}

pub fn validated_xdg(
    var: &'static str,
    raw: Option<&OsStr>,
) -> Result<Option<PathBuf>, InstallError> {
    let Some(val) = raw else {
        return Ok(None);
    };
    if val.is_empty() {
        return Ok(None);
    }
    let p = PathBuf::from(val);
    if !p.is_absolute() {
        return Err(InstallError::RelativeXdgRoot {
            var,
            value: val.to_os_string(),
        });
    }
    Ok(Some(p))
}

pub fn sun_path_capacity() -> usize {
    unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len()
}

/// Validates that a Unix socket path contains no NUL byte and fits within `sockaddr_un.sun_path`
/// measured in OS bytes (not Unicode scalar characters).
pub fn validate_socket_path(path: &Path) -> Result<(), InstallError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(InstallError::SocketPathNul {
            path: path.to_path_buf(),
        });
    }
    let capacity = sun_path_capacity();
    if bytes.len() >= capacity {
        return Err(InstallError::SocketPathTooLong {
            path: path.to_path_buf(),
            bytes: bytes.len(),
            max: capacity - 1,
            platform: if cfg!(target_os = "macos") {
                "macOS"
            } else {
                std::env::consts::OS
            },
        });
    }
    Ok(())
}

/// Validates an existing owner-private directory without modifying or repairing it.
/// Masks permission bits with `0o777` so an inherited setgid bit (`0o2000`) is permitted.
pub fn validate_private_dir(dir: &Path, expected_uid: u32) -> Result<PathBuf, InstallError> {
    let meta = fs::symlink_metadata(dir).map_err(|source| InstallError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    if meta.file_type().is_symlink() {
        return Err(InstallError::SymlinkNotAllowed {
            path: dir.to_path_buf(),
        });
    }
    if !meta.is_dir() {
        return Err(InstallError::NotADirectory {
            path: dir.to_path_buf(),
        });
    }
    let actual_uid = meta.uid();
    if actual_uid != expected_uid {
        return Err(InstallError::UnsafeOwner {
            path: dir.to_path_buf(),
            actual: actual_uid,
            expected: expected_uid,
        });
    }
    let perm_bits = meta.mode() & 0o777;
    if perm_bits != 0o700 {
        return Err(InstallError::UnsafeMode {
            path: dir.to_path_buf(),
            actual: perm_bits,
        });
    }
    let canon = fs::canonicalize(dir).map_err(|source| InstallError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let cmeta = fs::symlink_metadata(&canon).map_err(|source| InstallError::Io {
        path: canon.clone(),
        source,
    })?;
    if !cmeta.is_dir() {
        return Err(InstallError::NotADirectory { path: canon });
    }
    if cmeta.uid() != expected_uid {
        return Err(InstallError::UnsafeOwner {
            path: canon,
            actual: cmeta.uid(),
            expected: expected_uid,
        });
    }
    let cperm = cmeta.mode() & 0o777;
    if cperm != 0o700 {
        return Err(InstallError::UnsafeMode {
            path: canon,
            actual: cperm,
        });
    }
    Ok(canon)
}

/// Validates an existing explicit directory or creates a missing final directory exclusively at
/// mode `0700` under its canonicalized existing parent. Never repairs unsafe existing directories.
pub fn ensure_explicit_private_dir(dir: &Path, expected_uid: u32) -> Result<PathBuf, InstallError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => validate_private_dir(dir, expected_uid),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = dir.parent().ok_or_else(|| InstallError::MissingParent {
                parent: PathBuf::new(),
                target: dir.to_path_buf(),
            })?;
            let name = dir.file_name().ok_or_else(|| InstallError::MissingParent {
                parent: parent.to_path_buf(),
                target: dir.to_path_buf(),
            })?;
            let canon_parent = fs::canonicalize(parent).map_err(|source| {
                if source.kind() == io::ErrorKind::NotFound {
                    InstallError::MissingParent {
                        parent: parent.to_path_buf(),
                        target: dir.to_path_buf(),
                    }
                } else {
                    InstallError::Io {
                        path: parent.to_path_buf(),
                        source,
                    }
                }
            })?;
            let target = canon_parent.join(name);
            DirBuilder::new()
                .recursive(false)
                .mode(0o700)
                .create(&target)
                .map_err(|source| InstallError::Io {
                    path: target.clone(),
                    source,
                })?;
            validate_private_dir(&target, expected_uid)
        }
        Err(source) => Err(InstallError::Io {
            path: dir.to_path_buf(),
            source,
        }),
    }
}

/// Creates a default platform directory chain (e.g., `~/Library/Application Support/xmsg/state`),
/// ensuring intermediate directories exist and the final xmsg-owned directory is a validated
/// owner-private 0700 directory with no symlinks in the created tail.
pub fn ensure_default_private_dir(dir: &Path, expected_uid: u32) -> Result<PathBuf, InstallError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => validate_private_dir(dir, expected_uid),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                if !parent.exists() {
                    DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(parent)
                        .map_err(|source| InstallError::Io {
                            path: parent.to_path_buf(),
                            source,
                        })?;
                }
            }
            ensure_explicit_private_dir(dir, expected_uid)
        }
        Err(source) => Err(InstallError::Io {
            path: dir.to_path_buf(),
            source,
        }),
    }
}

/// Validates a shared temporary parent directory (e.g. canonical `/tmp`):
/// must be a directory owned by root (UID 0) with the sticky bit set.
pub fn validate_shared_tmp_parent(tmp: &Path) -> Result<PathBuf, InstallError> {
    let canon = fs::canonicalize(tmp).map_err(|source| InstallError::Io {
        path: tmp.to_path_buf(),
        source,
    })?;
    let meta = fs::symlink_metadata(&canon).map_err(|source| InstallError::Io {
        path: canon.clone(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(InstallError::NotADirectory { path: canon });
    }
    let uid = meta.uid();
    let mode = meta.mode() & 0o7777;
    if uid != 0 || (mode & 0o1000) == 0 {
        return Err(InstallError::UnsafeSharedTmp {
            path: canon,
            uid,
            mode,
        });
    }
    Ok(canon)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceIdentity {
    pub state_root: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub digest: String,
    pub dir_name: String,
    /// Exact serialized JSON tuple `(state_root_bytes, dev, ino, uid)` stored in `identity.json`.
    pub marker_bytes: Vec<u8>,
}

/// Derives the deterministic runtime namespace `xmsg-<uid>-<12hex>` from the canonical durable
/// state root and its `(dev, ino, uid)` metadata, matching the executor PR3 JSON tuple format.
pub fn compute_namespace_identity(
    canonical_state_root: &Path,
) -> Result<NamespaceIdentity, InstallError> {
    let meta = fs::symlink_metadata(canonical_state_root).map_err(|source| InstallError::Io {
        path: canonical_state_root.to_path_buf(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(InstallError::NotADirectory {
            path: canonical_state_root.to_path_buf(),
        });
    }
    let dev = meta.dev();
    let ino = meta.ino();
    let uid = meta.uid();
    let marker_bytes = serde_json::to_vec(&(
        canonical_state_root.as_os_str().as_bytes(),
        dev,
        ino,
        uid,
    ))
    .map_err(|e| InstallError::Io {
        path: canonical_state_root.to_path_buf(),
        source: io::Error::other(e),
    })?;
    let digest = hex::encode(&Sha256::digest(&marker_bytes)[..6]);
    let dir_name = format!("xmsg-{uid}-{digest}");
    Ok(NamespaceIdentity {
        state_root: canonical_state_root.to_path_buf(),
        dev,
        ino,
        uid,
        digest,
        dir_name,
        marker_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeParentKind {
    XdgRuntimeDir,
    SystemTmp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeParent {
    pub path: PathBuf,
    pub kind: RuntimeParentKind,
}

/// Selects the runtime parent for managed sockets.
/// - macOS: always canonical system `/tmp` (ignores `TMPDIR` and `XDG_RUNTIME_DIR`).
/// - Linux: owner-private `$XDG_RUNTIME_DIR` if set and within socket byte budget; falls back to
///   canonical `/tmp` when unset or when a valid XDG parent exceeds the byte budget; refuses an
///   unsafe configured `$XDG_RUNTIME_DIR`.
pub fn select_runtime_parent(
    env: &ResolveEnv<'_>,
    dir_name: &str,
    longest_socket_name: &str,
) -> Result<RuntimeParent, InstallError> {
    if env.platform == Platform::Linux {
        if let Some(xdg_rt) = validated_xdg("XDG_RUNTIME_DIR", env.xdg_runtime_dir.as_deref())? {
            let valid_xdg = validate_private_dir(&xdg_rt, env.euid)?;
            let probe = valid_xdg.join(dir_name).join(longest_socket_name);
            if validate_socket_path(&probe).is_ok() {
                return Ok(RuntimeParent {
                    path: valid_xdg,
                    kind: RuntimeParentKind::XdgRuntimeDir,
                });
            }
            // Valid XDG parent exceeded sun_path budget: fall back to verified system /tmp.
        }
    }
    let tmp = validate_shared_tmp_parent(&env.system_tmp)?;
    Ok(RuntimeParent {
        path: tmp,
        kind: RuntimeParentKind::SystemTmp,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindingKind {
    Managed,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    pub name: &'static str,
    pub path: PathBuf,
    pub kind: BindingKind,
    pub explicit: bool,
}

#[derive(Debug, Clone)]
pub struct ResolveRequest {
    pub leaf: bool,
    pub db_path: Option<PathBuf>,
    pub enroll_state: Option<PathBuf>,
    pub peers_file: Option<PathBuf>,
    pub http_sock: Option<PathBuf>,
    pub agent_sock: Option<PathBuf>,
    pub register_sock: Option<PathBuf>,
    pub leaf_register_sock: Option<PathBuf>,
    /// True for writers (`serve`, `enroll`, `enroll-ca`); false for read-only callers (`doctor`, CLI).
    pub writable: bool,
    /// When true (default for writers), runs the legacy component guard BEFORE creating any
    /// state directory or runtime namespace so no replacement state is ever created on refusal.
    pub enforce_legacy_guard: bool,
}

impl Default for ResolveRequest {
    fn default() -> Self {
        Self {
            leaf: false,
            db_path: None,
            enroll_state: None,
            peers_file: None,
            http_sock: None,
            agent_sock: None,
            register_sock: None,
            leaf_register_sock: None,
            writable: false,
            enforce_legacy_guard: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedInstall {
    pub platform: Platform,
    pub leaf: bool,
    pub state_root: PathBuf,
    pub state_root_explicit: bool,
    pub config_root: Option<PathBuf>,
    pub logs_dir: Option<PathBuf>,
    pub staging_cache_dir: PathBuf,
    pub db_path: PathBuf,
    pub db_explicit: bool,
    pub enroll_state_dir: PathBuf,
    pub enroll_explicit: bool,
    pub peers_file: Option<PathBuf>,
    pub peers_explicit: bool,
    pub runtime_namespace: Option<PathBuf>,
    pub namespace_identity: Option<NamespaceIdentity>,
    pub runtime_parent: Option<RuntimeParent>,
    pub http_sock: Option<ResolvedEndpoint>,
    pub agent_sock: Option<ResolvedEndpoint>,
    pub register_sock: Option<ResolvedEndpoint>,
    pub leaf_register_sock: Option<ResolvedEndpoint>,
}

impl ResolvedInstall {
    pub fn enabled_endpoints(&self) -> Vec<&ResolvedEndpoint> {
        let mut out = Vec::new();
        if let Some(ep) = &self.http_sock {
            out.push(ep);
        }
        if let Some(ep) = &self.agent_sock {
            out.push(ep);
        }
        if let Some(ep) = &self.register_sock {
            out.push(ep);
        }
        if let Some(ep) = &self.leaf_register_sock {
            out.push(ep);
        }
        out
    }

    pub fn all_enabled_pinned(&self) -> bool {
        self.enabled_endpoints().iter().all(|ep| ep.explicit)
    }
}

pub fn default_state_root(env: &ResolveEnv<'_>) -> Result<PathBuf, InstallError> {
    if let Some(xdg) = validated_xdg("XDG_STATE_HOME", env.xdg_state_home.as_deref())? {
        return Ok(xdg.join("xmsg"));
    }
    let home = resolve_account_home(env)?;
    Ok(match env.platform {
        Platform::MacOs => home.join("Library/Application Support/xmsg/state"),
        Platform::Linux => home.join(".local/state/xmsg"),
    })
}

pub fn default_config_root(env: &ResolveEnv<'_>) -> Result<PathBuf, InstallError> {
    if let Some(xdg) = validated_xdg("XDG_CONFIG_HOME", env.xdg_config_home.as_deref())? {
        return Ok(xdg.join("xmsg"));
    }
    let home = resolve_account_home(env)?;
    Ok(match env.platform {
        Platform::MacOs => home.join("Library/Application Support/xmsg/config"),
        Platform::Linux => home.join(".config/xmsg"),
    })
}

pub fn default_logs_dir(env: &ResolveEnv<'_>, state_root: &Path) -> Result<PathBuf, InstallError> {
    Ok(match env.platform {
        Platform::MacOs => resolve_account_home(env)?.join("Library/Logs/xmsg"),
        Platform::Linux => state_root.join("logs"),
    })
}

/// Resolves the complete installation state and enabled Unix endpoint set for a given request.
/// Read-only callers (`writable = false`) never create directories or files.
pub fn resolve_install(
    req: &ResolveRequest,
    env: &ResolveEnv<'_>,
) -> Result<ResolvedInstall, InstallError> {
    // 1. Resolve DB path and durable state root.
    let (db_path, state_root, db_explicit) = match &req.db_path {
        Some(raw) => {
            let expanded = expand_explicit_path(raw, env)?;
            let parent = expanded
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or_else(|| InstallError::MissingParent {
                    parent: PathBuf::new(),
                    target: expanded.clone(),
                })?
                .to_path_buf();
            (expanded, parent, true)
        }
        None => {
            let sr = default_state_root(env)?;
            (sr.join("xmsg.db"), sr, false)
        }
    };

    // 2. Resolve enrollment state dir and optional explicit peers file.
    let (enroll_state_dir, enroll_explicit) = match &req.enroll_state {
        Some(raw) => (expand_explicit_path(raw, env)?, true),
        None => (state_root.join("enroll"), false),
    };
    let (peers_file, peers_explicit) = match &req.peers_file {
        Some(raw) => (Some(expand_explicit_path(raw, env)?), true),
        None => (None, false),
    };

    // Optional roots (config / logs): do not force account home if everything required is pinned.
    let config_root = default_config_root(env).ok();
    let logs_dir = default_logs_dir(env, &state_root).ok();

    // 2b. Run the legacy component guard BEFORE creating any state directory or runtime namespace
    // so a refused start never leaves replacement state behind.
    if req.enforce_legacy_guard {
        let conflicts = check_legacy_components_raw(
            &db_path,
            db_explicit,
            &enroll_state_dir,
            enroll_explicit,
            peers_file.as_deref(),
            peers_explicit,
            env,
            &LegacyInventory::default(),
        )?;
        if !conflicts.is_empty() {
            let summary = format_legacy_conflicts(&conflicts);
            return Err(InstallError::LegacyConflict { summary, conflicts });
        }
    }

    // 3. Expand explicit endpoint pins per mode (H3, V1, V2).
    let http_pin = if req.leaf {
        None
    } else {
        req.http_sock
            .as_deref()
            .map(|p| expand_explicit_path(p, env))
            .transpose()?
    };
    let agent_pin = req
        .agent_sock
        .as_deref()
        .map(|p| expand_explicit_path(p, env))
        .transpose()?;
    let reg_pin = if req.leaf {
        None
    } else {
        req.register_sock
            .as_deref()
            .map(|p| expand_explicit_path(p, env))
            .transpose()?
    };
    // V1: in leaf mode, --leaf-register-sock / XMSG_LEAF_REGISTER_SOCK takes precedence;
    // when unset, --register-sock / XMSG_REGISTER_SOCK remains an alias.
    let leaf_reg_pin = if req.leaf {
        let chosen = req
            .leaf_register_sock
            .as_deref()
            .or(req.register_sock.as_deref());
        chosen.map(|p| expand_explicit_path(p, env)).transpose()?
    } else {
        None
    };

    let all_pinned = if req.leaf {
        agent_pin.is_some() && leaf_reg_pin.is_some()
    } else {
        http_pin.is_some() && agent_pin.is_some() && reg_pin.is_some()
    };

    // 4. Derive managed runtime namespace ONLY when at least one enabled endpoint is unpinned (H4).
    let (runtime_namespace, namespace_identity, runtime_parent) = if all_pinned {
        (None, None, None)
    } else {
        let canon_state = if state_root.exists() {
            validate_private_dir(&state_root, env.euid)?
        } else if req.writable {
            if db_explicit {
                ensure_explicit_private_dir(&state_root, env.euid)?
            } else {
                ensure_default_private_dir(&state_root, env.euid)?
            }
        } else {
            return Err(InstallError::MissingStateRoot {
                path: state_root.clone(),
            });
        };
        let ns_id = compute_namespace_identity(&canon_state)?;
        let longest = if req.leaf {
            "register.sock"
        } else {
            "register.sock"
        };
        let parent = select_runtime_parent(env, &ns_id.dir_name, longest)?;
        let ns_dir = parent.path.join(&ns_id.dir_name);
        (Some(ns_dir), Some(ns_id), Some(parent))
    };

    let classify = |name: &'static str,
                    pin: Option<PathBuf>,
                    default_leaf: &'static str|
     -> Result<ResolvedEndpoint, InstallError> {
        let (path, explicit) = match pin {
            Some(p) => (p, true),
            None => (
                runtime_namespace
                    .as_ref()
                    .expect("runtime namespace derived when unpinned")
                    .join(default_leaf),
                false,
            ),
        };
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(InstallError::SymlinkNotAllowed { path });
            }
        }
        validate_socket_path(&path)?;
        let kind = classify_binding(&path, runtime_namespace.as_deref())?;
        Ok(ResolvedEndpoint {
            name,
            path,
            kind,
            explicit,
        })
    };

    let (http_sock, agent_sock, register_sock, leaf_register_sock) = if req.leaf {
        (
            None,
            Some(classify("agent", agent_pin, "agent.sock")?),
            None,
            Some(classify("leaf_register", leaf_reg_pin, "register.sock")?),
        )
    } else {
        (
            Some(classify("http", http_pin, "http.sock")?),
            Some(classify("agent", agent_pin, "agent.sock")?),
            Some(classify("register", reg_pin, "register.sock")?),
            None,
        )
    };

    let staging_cache_dir = state_root.join("staging-cache");
    Ok(ResolvedInstall {
        platform: env.platform,
        leaf: req.leaf,
        state_root,
        state_root_explicit: db_explicit,
        config_root,
        logs_dir,
        staging_cache_dir,
        db_path,
        db_explicit,
        enroll_state_dir,
        enroll_explicit,
        peers_file,
        peers_explicit,
        runtime_namespace,
        namespace_identity,
        runtime_parent,
        http_sock,
        agent_sock,
        register_sock,
        leaf_register_sock,
    })
}

fn classify_binding(
    sock_path: &Path,
    managed_namespace: Option<&Path>,
) -> Result<BindingKind, InstallError> {
    let parent = sock_path
        .parent()
        .ok_or_else(|| InstallError::InvalidEndpointPath {
            path: sock_path.to_path_buf(),
            detail: "socket path has no parent directory".into(),
        })?;
    let canon_parent = canonicalize_best_effort(parent).unwrap_or_else(|_| parent.to_path_buf());
    if let Some(ns) = managed_namespace {
        let canon_ns = canonicalize_best_effort(ns).unwrap_or_else(|_| ns.to_path_buf());
        if canon_parent == canon_ns {
            return Ok(BindingKind::Managed);
        }
        // Reject pointing into another xmsg-<uid>-<12hex> managed namespace.
        if let Some(fname) = canon_parent.file_name().and_then(|f| f.to_str()) {
            if is_managed_namespace_dirname(fname) && canon_parent != canon_ns {
                return Err(InstallError::InvalidEndpointPath {
                    path: sock_path.to_path_buf(),
                    detail: format!(
                        "endpoint parent {} belongs to a different managed runtime namespace",
                        canon_parent.display()
                    ),
                });
            }
        }
    }
    Ok(BindingKind::Manual)
}

pub fn is_managed_namespace_dirname(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("xmsg-") else {
        return false;
    };
    let Some((uid_part, hex_part)) = rest.split_once('-') else {
        return false;
    };
    !uid_part.is_empty()
        && uid_part.bytes().all(|b| b.is_ascii_digit())
        && hex_part.len() == 12
        && hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyConflict {
    pub component: String,
    pub legacy_path: PathBuf,
    pub compatible_pin: String,
}

#[derive(Debug, Clone, Default)]
pub struct LegacyInventory {
    /// Additional prior service homes (populated ONLY by preparation and doctor, empty at startup).
    pub prior_homes: Vec<PathBuf>,
    /// Prior service working directory when prior service had HOME unset (preparation/doctor only).
    pub prior_cwd: Option<PathBuf>,
}

/// Checks legacy default locations for every component that is NOT explicitly pinned.
/// Metadata-only: never opens secrets, never silently selects an old path, and fails closed on
/// inconclusive metadata.
pub fn check_legacy_components(
    resolved: &ResolvedInstall,
    env: &ResolveEnv<'_>,
    inventory: &LegacyInventory,
) -> Result<Vec<LegacyConflict>, InstallError> {
    check_legacy_components_raw(
        &resolved.db_path,
        resolved.db_explicit,
        &resolved.enroll_state_dir,
        resolved.enroll_explicit,
        resolved.peers_file.as_deref(),
        resolved.peers_explicit,
        env,
        inventory,
    )
}

#[allow(clippy::too_many_arguments)]
fn check_legacy_components_raw(
    db_path: &Path,
    db_explicit: bool,
    enroll_state_dir: &Path,
    enroll_explicit: bool,
    peers_file: Option<&Path>,
    peers_explicit: bool,
    env: &ResolveEnv<'_>,
    inventory: &LegacyInventory,
) -> Result<Vec<LegacyConflict>, InstallError> {
    let mut candidate_roots: Vec<PathBuf> = Vec::new();
    // 1. XDG_STATE_HOME/xmsg when set
    if let Some(xdg) = validated_xdg("XDG_STATE_HOME", env.xdg_state_home.as_deref())? {
        candidate_roots.push(xdg.join("xmsg"));
    }
    // 2. Account home ~/.local/state/xmsg when account home resolves
    if let Ok(home) = resolve_account_home(env) {
        candidate_roots.push(home.join(".local/state/xmsg"));
    }
    // 3. Prior service inventory (doctor / preparation only)
    for ph in &inventory.prior_homes {
        if ph.is_absolute() {
            candidate_roots.push(ph.join(".local/state/xmsg"));
        }
    }
    if let Some(cwd) = &inventory.prior_cwd {
        if cwd.is_absolute() {
            candidate_roots.push(cwd.join(".local/state/xmsg"));
        }
    }

    // Deduplicate roots by canonical path.
    let mut seen_roots = HashSet::new();
    let mut roots = Vec::new();
    for root in candidate_roots {
        let key = canonicalize_best_effort(&root).unwrap_or_else(|_| root.clone());
        if seen_roots.insert(key) {
            roots.push(root);
        }
    }

    let resolved_db_canon =
        canonicalize_best_effort(db_path).unwrap_or_else(|_| db_path.to_path_buf());
    let resolved_enroll_canon = canonicalize_best_effort(enroll_state_dir)
        .unwrap_or_else(|_| enroll_state_dir.to_path_buf());
    let resolved_peers_canon =
        peers_file.map(|p| canonicalize_best_effort(p).unwrap_or_else(|_| p.to_path_buf()));

    let mut conflicts = Vec::new();
    let mut seen_db = HashSet::new();
    let mut seen_enroll = HashSet::new();
    let mut seen_peers = HashSet::new();

    for root in &roots {
        // Inspect root metadata first; non-existent root has no legacy data.
        match fs::symlink_metadata(root) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(InstallError::InconclusiveMetadata {
                        path: root.clone(),
                        detail: "legacy state root is a symlink".into(),
                    });
                }
                if !meta.is_dir() {
                    continue;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(InstallError::InconclusiveMetadata {
                    path: root.clone(),
                    detail: e.to_string(),
                });
            }
        }

        // Database check (only when DB is unpinned).
        if !db_explicit {
            let legacy_db = root.join("xmsg.db");
            let canon =
                canonicalize_best_effort(&legacy_db).unwrap_or_else(|_| legacy_db.clone());
            if canon != resolved_db_canon && seen_db.insert(canon) {
                match inspect_regular_file(&legacy_db)? {
                    FilePresence::Present => {
                        conflicts.push(LegacyConflict {
                            component: "database".into(),
                            legacy_path: legacy_db.clone(),
                            compatible_pin: format!(
                                "--db-path {} (or XMSG_DB_PATH)",
                                legacy_db.display()
                            ),
                        });
                    }
                    FilePresence::Absent => {}
                }
            }
        }

        // Enrollment identity & peers checks (metadata only, never reading secrets).
        let legacy_enroll_dir = root.join("enroll");
        let canon_enroll = canonicalize_best_effort(&legacy_enroll_dir)
            .unwrap_or_else(|_| legacy_enroll_dir.clone());
        let enroll_dir_exists = match fs::symlink_metadata(&legacy_enroll_dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(InstallError::InconclusiveMetadata {
                        path: legacy_enroll_dir,
                        detail: "legacy enrollment directory is a symlink".into(),
                    });
                }
                meta.is_dir()
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(InstallError::InconclusiveMetadata {
                    path: legacy_enroll_dir,
                    detail: e.to_string(),
                });
            }
        };

        if enroll_dir_exists {
            if !enroll_explicit
                && canon_enroll != resolved_enroll_canon
                && seen_enroll.insert(canon_enroll.clone())
            {
                let mut found_identity = false;
                for fname in ["enroll.json", "fed.crt", "fed.key"] {
                    if matches!(
                        inspect_regular_file(&legacy_enroll_dir.join(fname))?,
                        FilePresence::Present
                    ) {
                        found_identity = true;
                        break;
                    }
                }
                if found_identity {
                    conflicts.push(LegacyConflict {
                        component: "enrollment".into(),
                        legacy_path: legacy_enroll_dir.clone(),
                        compatible_pin: format!(
                            "--enroll-state {} (and xmsg enroll --state-dir {})",
                            legacy_enroll_dir.display(),
                            legacy_enroll_dir.display()
                        ),
                    });
                }
            }

            // Peers-only detection: detect peers.json beside legacy enrollment state even without
            // DB or identity files, unless peers or that enrollment dir is explicitly pinned.
            if !peers_explicit && !enroll_explicit {
                let legacy_peers = legacy_enroll_dir.join("peers.json");
                let canon_peers = canonicalize_best_effort(&legacy_peers)
                    .unwrap_or_else(|_| legacy_peers.clone());
                let same_as_resolved = canon_enroll == resolved_enroll_canon
                    || resolved_peers_canon
                        .as_ref()
                        .is_some_and(|rp| rp == &canon_peers);
                if !same_as_resolved && seen_peers.insert(canon_peers) {
                    if matches!(inspect_regular_file(&legacy_peers)?, FilePresence::Present) {
                        conflicts.push(LegacyConflict {
                            component: "peers".into(),
                            legacy_path: legacy_peers.clone(),
                            compatible_pin: format!(
                                "--peers-file {} (or XMSG_PEERS_FILE / --enroll-state {})",
                                legacy_peers.display(),
                                legacy_enroll_dir.display()
                            ),
                        });
                    }
                }
            }
        }
    }

    Ok(conflicts)
}

fn format_legacy_conflicts(conflicts: &[LegacyConflict]) -> String {
    conflicts
        .iter()
        .map(|c| {
            format!(
                "{} at {} (pin with {})",
                c.component,
                c.legacy_path.display(),
                c.compatible_pin
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn enforce_no_legacy_conflicts(
    resolved: &ResolvedInstall,
    env: &ResolveEnv<'_>,
) -> Result<(), InstallError> {
    let conflicts = check_legacy_components(resolved, env, &LegacyInventory::default())?;
    if !conflicts.is_empty() {
        let summary = format_legacy_conflicts(&conflicts);
        return Err(InstallError::LegacyConflict { summary, conflicts });
    }
    Ok(())
}

enum FilePresence {
    Present,
    Absent,
}

fn inspect_regular_file(path: &Path) -> Result<FilePresence, InstallError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(InstallError::InconclusiveMetadata {
                    path: path.to_path_buf(),
                    detail: "legacy file is a symlink".into(),
                });
            }
            if meta.is_file() {
                Ok(FilePresence::Present)
            } else {
                Ok(FilePresence::Absent)
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(FilePresence::Absent),
        Err(e) => Err(InstallError::InconclusiveMetadata {
            path: path.to_path_buf(),
            detail: e.to_string(),
        }),
    }
}

/// Collects all resolvable legacy default socket endpoints (plus legacy leaf sibling `agent.sock`
/// when leaf mode has no explicit `--agent-sock`), without requiring an account home.
pub fn legacy_socket_probe_targets(
    resolved: &ResolvedInstall,
    env: &ResolveEnv<'_>,
    extra_legacy_sockets: &[PathBuf],
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(Some(xdg_rt)) = validated_xdg("XDG_RUNTIME_DIR", env.xdg_runtime_dir.as_deref()) {
        let legacy_dir = xdg_rt.join("xmsg");
        for name in ["http.sock", "agent.sock", "register.sock"] {
            candidates.push(legacy_dir.join(name));
        }
    } else if env.platform == Platform::MacOs {
        if let Some(darwin_tmp) = &env.darwin_user_temp_dir {
            let legacy_dir = darwin_tmp.join("xmsg");
            for name in ["http.sock", "agent.sock", "register.sock"] {
                candidates.push(legacy_dir.join(name));
            }
        }
    }
    // Q3: in leaf mode without an explicit agent pin, also probe agent.sock beside the resolved
    // leaf registration socket.
    if resolved.leaf {
        let agent_explicit = resolved.agent_sock.as_ref().is_some_and(|ep| ep.explicit);
        if !agent_explicit {
            if let Some(leaf_reg) = &resolved.leaf_register_sock {
                if let Some(parent) = leaf_reg.path.parent() {
                    candidates.push(parent.join("agent.sock"));
                }
            }
        }
    }
    candidates.extend(extra_legacy_sockets.iter().cloned());

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in candidates {
        let key = canonicalize_best_effort(&p).unwrap_or_else(|_| p.clone());
        if seen.insert(key) {
            out.push(p);
        }
    }
    out
}

/// Read-only probe of legacy socket endpoints before binding. Excludes validated systemd-adopted
/// endpoints (`M-S1g`) and refuses if any other legacy endpoint answers a connect.
pub fn probe_legacy_listeners(
    resolved: &ResolvedInstall,
    env: &ResolveEnv<'_>,
    adopted_sockets: &[PathBuf],
    extra_legacy_sockets: &[PathBuf],
) -> Result<(), InstallError> {
    let adopted_canon: HashSet<PathBuf> = adopted_sockets
        .iter()
        .map(|p| canonicalize_best_effort(p).unwrap_or_else(|_| p.clone()))
        .collect();
    for sock in legacy_socket_probe_targets(resolved, env, extra_legacy_sockets) {
        let canon = canonicalize_best_effort(&sock).unwrap_or_else(|_| sock.clone());
        if adopted_canon.contains(&canon) {
            continue;
        }
        if UnixStream::connect(&sock).is_ok() {
            return Err(InstallError::LegacyListenerActive { path: sock });
        }
    }
    Ok(())
}

/// Resolves default socket path for a bare CLI/client entry point using the shared installation
/// contract (read-only: never creates state).
pub fn resolve_client_endpoint(
    name: &'static str,
    explicit: Option<&Path>,
    db_path: Option<&Path>,
    leaf: bool,
) -> Result<PathBuf, InstallError> {
    let lookup = SystemHomeLookup;
    let env = ResolveEnv::from_process(&lookup);
    if let Some(p) = explicit {
        let expanded = expand_explicit_path(p, &env)?;
        validate_socket_path(&expanded)?;
        return Ok(expanded);
    }
    let req = ResolveRequest {
        leaf,
        db_path: db_path.map(Path::to_path_buf),
        writable: false,
        ..Default::default()
    };
    let resolved = resolve_install(&req, &env)?;
    let ep = match name {
        "http" => resolved.http_sock,
        "agent" => resolved.agent_sock,
        "register" => resolved.register_sock,
        "leaf_register" => resolved.leaf_register_sock,
        _ => None,
    };
    ep.map(|e| e.path)
        .ok_or_else(|| InstallError::InvalidEndpointPath {
            path: PathBuf::new(),
            detail: format!("endpoint {name} is disabled in this mode"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn make_env<'a>(
        lookup: &'a FixtureHomeLookup,
        platform: Platform,
        home: Option<&Path>,
    ) -> ResolveEnv<'a> {
        ResolveEnv {
            home: home.map(|p| p.as_os_str().to_os_string()),
            xdg_config_home: None,
            xdg_state_home: None,
            xdg_runtime_dir: None,
            darwin_user_temp_dir: None,
            system_tmp: PathBuf::from("/tmp"),
            platform,
            euid: unsafe { libc::geteuid() },
            home_lookup: lookup,
        }
    }

    #[test]
    fn home_mismatch_refused_and_missing_home_uses_account_home() {
        let tmp = tempdir().unwrap();
        let acct = tmp.path().join("acct");
        let other = tmp.path().join("other");
        fs::create_dir(&acct).unwrap();
        fs::create_dir(&other).unwrap();
        let lookup = FixtureHomeLookup(Some(acct.clone()));

        let env_missing = make_env(&lookup, Platform::MacOs, None);
        assert_eq!(
            resolve_account_home(&env_missing).unwrap(),
            fs::canonicalize(&acct).unwrap()
        );

        let env_mismatch = make_env(&lookup, Platform::MacOs, Some(&other));
        assert!(matches!(
            resolve_account_home(&env_mismatch),
            Err(InstallError::HomeMismatch { .. })
        ));
    }

    #[test]
    fn relative_xdg_root_refused() {
        let tmp = tempdir().unwrap();
        let lookup = FixtureHomeLookup(Some(tmp.path().to_path_buf()));
        let mut env = make_env(&lookup, Platform::Linux, Some(tmp.path()));
        env.xdg_state_home = Some(OsString::from("relative/state"));
        assert!(matches!(
            default_state_root(&env),
            Err(InstallError::RelativeXdgRoot {
                var: "XDG_STATE_HOME",
                ..
            })
        ));
    }

    #[test]
    fn platform_defaults_and_xdg_precedence_on_macos() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join("u");
        fs::create_dir(&home).unwrap();
        let lookup = FixtureHomeLookup(Some(home.clone()));
        let canon = fs::canonicalize(&home).unwrap();

        let env_mac = make_env(&lookup, Platform::MacOs, Some(&home));
        assert_eq!(
            default_state_root(&env_mac).unwrap(),
            canon.join("Library/Application Support/xmsg/state")
        );
        assert_eq!(
            default_config_root(&env_mac).unwrap(),
            canon.join("Library/Application Support/xmsg/config")
        );

        let mut env_mac_xdg = make_env(&lookup, Platform::MacOs, Some(&home));
        env_mac_xdg.xdg_state_home = Some(tmp.path().join("xdg-state").into_os_string());
        assert_eq!(
            default_state_root(&env_mac_xdg).unwrap(),
            tmp.path().join("xdg-state/xmsg")
        );
    }

    #[test]
    fn leaf_v1_precedence_and_all_pinned_skips_runtime_namespace() {
        let tmp = tempdir().unwrap();
        let sock_dir = tmp.path().join("socks");
        fs::create_dir(&sock_dir).unwrap();
        fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let db_dir = tmp.path().join("db");
        fs::create_dir(&db_dir).unwrap();
        fs::set_permissions(&db_dir, fs::Permissions::from_mode(0o700)).unwrap();

        // Passwd-less account (no home), invalid relative XDG_RUNTIME_DIR ignored when all pinned!
        let lookup = FixtureHomeLookup(None);
        let mut env = make_env(&lookup, Platform::Linux, None);
        env.xdg_runtime_dir = Some(OsString::from("relative-ignored"));

        let req = ResolveRequest {
            leaf: true,
            db_path: Some(db_dir.join("xmsg.db")),
            agent_sock: Some(sock_dir.join("agent.sock")),
            register_sock: Some(sock_dir.join("reg-alias.sock")),
            leaf_register_sock: Some(sock_dir.join("leaf-reg.sock")),
            writable: true,
            ..Default::default()
        };
        let resolved = resolve_install(&req, &env).unwrap();
        assert!(resolved.all_enabled_pinned());
        assert!(resolved.runtime_namespace.is_none());
        assert!(resolved.http_sock.is_none());
        assert!(resolved.register_sock.is_none());
        assert_eq!(
            resolved.leaf_register_sock.as_ref().unwrap().path,
            sock_dir.join("leaf-reg.sock")
        );

        // When leaf_register_sock is omitted, register_sock acts as alias.
        let req_alias = ResolveRequest {
            leaf: true,
            db_path: Some(db_dir.join("xmsg.db")),
            agent_sock: Some(sock_dir.join("agent.sock")),
            register_sock: Some(sock_dir.join("reg-alias.sock")),
            leaf_register_sock: None,
            writable: true,
            ..Default::default()
        };
        let resolved_alias = resolve_install(&req_alias, &env).unwrap();
        assert_eq!(
            resolved_alias.leaf_register_sock.as_ref().unwrap().path,
            sock_dir.join("reg-alias.sock")
        );
    }

    #[test]
    fn explicit_private_dir_accepts_inherited_setgid_02700() {
        let tmp = tempdir().unwrap();
        let d = tmp.path().join("setgid-child");
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o2700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(validate_private_dir(&d, uid).is_ok());
        assert!(ensure_explicit_private_dir(&d, uid).is_ok());

        let unsafe_d = tmp.path().join("unsafe-0755");
        fs::create_dir(&unsafe_d).unwrap();
        fs::set_permissions(&unsafe_d, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            validate_private_dir(&unsafe_d, uid),
            Err(InstallError::UnsafeMode { .. })
        ));
    }

    #[test]
    fn multibyte_socket_path_enforces_os_byte_budget() {
        // 52 * U+00E9 = 104 UTF-8 bytes (> 103 on Darwin; add prefix to exceed on Linux too).
        let e_acute: String = std::iter::repeat_n('\u{00e9}', 52).collect();
        let p = PathBuf::from("/private/tmp/h")
            .join(&e_acute)
            .join("agent.sock");
        // Characters: 14 + 1 + 52 + 1 + 10 = 78 chars <= 103, OS bytes: 14 + 1 + 104 + 1 + 10 = 130 >= 104/108!
        assert!(p.to_string_lossy().chars().count() <= 103);
        assert!(p.as_os_str().as_bytes().len() >= sun_path_capacity());
        assert!(matches!(
            validate_socket_path(&p),
            Err(InstallError::SocketPathTooLong { .. })
        ));
    }

    #[test]
    fn legacy_guard_catches_peers_only_and_both_xdg_and_home_arms() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join("home");
        let xdg_other = tmp.path().join("xdg-other");
        let legacy_enroll = home.join(".local/state/xmsg/enroll");
        fs::create_dir_all(&legacy_enroll).unwrap();
        fs::write(legacy_enroll.join("peers.json"), b"{}").unwrap();
        fs::create_dir_all(xdg_other.join("xmsg")).unwrap();
        fs::set_permissions(xdg_other.join("xmsg"), fs::Permissions::from_mode(0o700)).unwrap();

        let lookup = FixtureHomeLookup(Some(home.clone()));
        let mut env = make_env(&lookup, Platform::MacOs, Some(&home));
        env.xdg_state_home = Some(xdg_other.clone().into_os_string());

        let req = ResolveRequest {
            writable: true,
            enforce_legacy_guard: true,
            ..Default::default()
        };
        let err = resolve_install(&req, &env).unwrap_err();
        match err {
            InstallError::LegacyConflict { conflicts, .. } => {
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].component, "peers");
            }
            other => panic!("expected LegacyConflict, got {other:?}"),
        }
        assert!(
            !xdg_other.join("xmsg/xmsg.db").exists(),
            "refusal must occur before any replacement state is created"
        );
    }

    #[test]
    fn legacy_guard_allows_linux_same_path_and_macos_coordinator_only() {
        let tmp = tempdir().unwrap();
        let home = tmp.path().join("home");
        let linux_state = home.join(".local/state/xmsg");
        fs::create_dir_all(&linux_state).unwrap();
        fs::set_permissions(&linux_state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(linux_state.join("xmsg.db"), b"sqlite").unwrap();

        let lookup = FixtureHomeLookup(Some(home.clone()));
        let env_linux = make_env(&lookup, Platform::Linux, Some(&home));
        let req = ResolveRequest {
            writable: true,
            ..Default::default()
        };
        let resolved_linux = resolve_install(&req, &env_linux).unwrap();
        let conflicts_linux =
            check_legacy_components(&resolved_linux, &env_linux, &LegacyInventory::default())
                .unwrap();
        assert!(conflicts_linux.is_empty(), "same-path Linux DB must start");

        // macOS with only claude-coordinator under ~/.local/state/xmsg
        let tmp2 = tempdir().unwrap();
        let home2 = tmp2.path().join("home");
        fs::create_dir_all(home2.join(".local/state/xmsg/claude-coordinator")).unwrap();
        let lookup2 = FixtureHomeLookup(Some(home2.clone()));
        let env_mac = make_env(&lookup2, Platform::MacOs, Some(&home2));
        let resolved_mac = resolve_install(&req, &env_mac).unwrap();
        let conflicts_mac =
            check_legacy_components(&resolved_mac, &env_mac, &LegacyInventory::default()).unwrap();
        assert!(
            conflicts_mac.is_empty(),
            "macOS coordinator-only under old root must start"
        );
    }
}
