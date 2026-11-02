use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

use crate::error::AppError;
use crate::process;

pub trait SessionDirs {
    fn to_dirs(&self) -> Vec<PathBuf>;
}

impl SessionDirs for Path {
    fn to_dirs(&self) -> Vec<PathBuf> {
        vec![self.to_path_buf()]
    }
}

impl SessionDirs for PathBuf {
    fn to_dirs(&self) -> Vec<PathBuf> {
        vec![self.clone()]
    }
}

impl SessionDirs for &Path {
    fn to_dirs(&self) -> Vec<PathBuf> {
        vec![self.to_path_buf()]
    }
}

impl SessionDirs for [PathBuf] {
    fn to_dirs(&self) -> Vec<PathBuf> {
        self.to_vec()
    }
}

impl SessionDirs for Vec<PathBuf> {
    fn to_dirs(&self) -> Vec<PathBuf> {
        self.clone()
    }
}

impl SessionDirs for &[PathBuf] {
    fn to_dirs(&self) -> Vec<PathBuf> {
        self.to_vec()
    }
}

impl SessionDirs for &Vec<PathBuf> {
    fn to_dirs(&self) -> Vec<PathBuf> {
        (*self).clone()
    }
}

impl SessionDirs for [&Path] {
    fn to_dirs(&self) -> Vec<PathBuf> {
        self.iter().map(|p| p.to_path_buf()).collect()
    }
}

impl SessionDirs for &[&Path] {
    fn to_dirs(&self) -> Vec<PathBuf> {
        self.iter().map(|p| p.to_path_buf()).collect()
    }
}

pub fn expand_tilde(p: PathBuf) -> PathBuf {
    if let Ok(stripped) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    p
}

pub fn resolve_sessions_dirs(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut raw_dirs = dirs;
    if raw_dirs.is_empty() {
        if let Ok(val) =
            std::env::var("XMSG_SESSIONS_DIRS").or_else(|_| std::env::var("XMSG_SESSIONS_DIR"))
        {
            for part in val.split(':') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    raw_dirs.push(PathBuf::from(trimmed));
                }
            }
        }
    }

    if raw_dirs.is_empty() {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        return vec![PathBuf::from(home).join(".claude").join("sessions")];
    }

    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for p in raw_dirs {
        let p_str = p.to_string_lossy();
        let parts: Vec<&str> = if p_str.contains(':') {
            p_str.split(':').collect()
        } else {
            vec![&p_str]
        };

        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let expanded = expand_tilde(PathBuf::from(trimmed));
            let canonical_key =
                std::fs::canonicalize(&expanded).unwrap_or_else(|_| expanded.clone());
            if seen.insert(canonical_key) {
                result.push(expanded);
            }
        }
    }

    if result.is_empty() {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        return vec![PathBuf::from(home).join(".claude").join("sessions")];
    }

    result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionFileEntry {
    pub pid: u32,
    pub session_id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub cwd: String,
    pub status: String,
    pub kind: String,
    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    pub started_at: u64,
    pub updated_at: u64,
    pub proc_start: String,
    pub messaging_socket_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub session_id: String,
    pub name: Option<String>,
    pub pid: u32,
    pub cwd: String,
    pub status: String,
    pub kind: String,
    pub entrypoint: Option<String>,
    pub version: Option<String>,
    pub started_at: u64,
    pub updated_at: u64,
    #[serde(default = "default_claude_harness")]
    pub harness: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

fn default_claude_harness() -> String {
    "claude".to_string()
}

impl From<SessionFileEntry> for Session {
    fn from(entry: SessionFileEntry) -> Self {
        Self {
            session_id: entry.session_id,
            // A label containing `@` or `·` is dropped; the session stays listed (AM-8).
            name: entry.name.as_deref().and_then(crate::inbox::clean_label),
            pid: entry.pid,
            cwd: entry.cwd,
            status: entry.status,
            kind: entry.kind,
            entrypoint: entry.entrypoint,
            version: entry.version,
            started_at: entry.started_at,
            updated_at: entry.updated_at,
            harness: "claude".to_string(),
            registered: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SessionsQuery {
    pub cwd: Option<String>,
    pub status: Option<String>,
    pub peer: Option<String>,
}

pub fn is_pid_live(pid: u32, expected_proc_start: &str) -> bool {
    process::claude_proc_start_matches(Path::new(process::LIVE_PROC_ROOT), pid, expected_proc_start)
}

pub fn is_pid_live_in(proc_root: &Path, pid: u32, expected_proc_start: &str) -> bool {
    process::claude_proc_start_matches(proc_root, pid, expected_proc_start)
}

/// Validates a `messaging_socket_path` from a `SessionFileEntry` (XB2 F3):
/// - must be an absolute path (`is_absolute()`),
/// - must contain no `..` (`Component::ParentDir`),
/// - must not name `xmsg`'s own sockets (`agent.sock`, `register.sock`, `http.sock`,
///   `leaf-register.sock`) or reside directly inside `.../xmsg/<file>`,
/// - must have a parent directory that is not `/`, not `/dev`/`/proc`/`/sys`/`/etc`, and
///   when the path exists on disk, `symlink_metadata` must not be a symlink, regular file,
///   directory, FIFO, block, or char device (only a Unix socket or not-yet-bound path).
pub fn validate_messaging_socket_path(sock: &Path) -> Result<(), AppError> {
    use std::path::Component;
    if !sock.is_absolute() {
        return Err(AppError::BadRequest(format!(
            "messaging_socket_path '{}' must be an absolute path",
            sock.display()
        )));
    }
    if sock.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(AppError::BadRequest(format!(
            "messaging_socket_path '{}' must not contain '..'",
            sock.display()
        )));
    }
    let Some(file_name) = sock.file_name().and_then(|s| s.to_str()) else {
        return Err(AppError::BadRequest(format!(
            "messaging_socket_path '{}' has no file name",
            sock.display()
        )));
    };
    if matches!(
        file_name,
        "agent.sock" | "register.sock" | "http.sock" | "leaf-register.sock"
    ) {
        return Err(AppError::BadRequest(format!(
            "messaging_socket_path '{}' must not name an xmsg daemon socket",
            sock.display()
        )));
    }
    let Some(parent) = sock.parent() else {
        return Err(AppError::BadRequest(format!(
            "messaging_socket_path '{}' has no parent directory",
            sock.display()
        )));
    };
    if parent == Path::new("/") {
        return Err(AppError::BadRequest(format!(
            "messaging_socket_path '{}' must not reside directly in '/'",
            sock.display()
        )));
    }
    for blocked in ["/dev", "/proc", "/sys", "/etc"] {
        if sock.starts_with(blocked) {
            return Err(AppError::BadRequest(format!(
                "messaging_socket_path '{}' is not in an allowed socket directory",
                sock.display()
            )));
        }
    }
    if let Ok(meta) = std::fs::symlink_metadata(sock) {
        use std::os::unix::fs::FileTypeExt;
        let ft = meta.file_type();
        if ft.is_symlink() || !ft.is_socket() {
            return Err(AppError::BadRequest(format!(
                "messaging_socket_path '{}' is not a Unix domain socket",
                sock.display()
            )));
        }
    }
    Ok(())
}

/// Validates a `SessionFileEntry` at ingestion and use sites (XB2 F3):
/// requires a UUID-shaped `session_id` and a valid `messaging_socket_path`.
pub fn validate_session_file_entry(entry: &SessionFileEntry) -> bool {
    crate::claim::is_uuid_shaped(&entry.session_id)
        && validate_messaging_socket_path(Path::new(&entry.messaging_socket_path)).is_ok()
}

/// Reads all session files across `sessions_dirs`, ignoring `.key` files and invalid entries.
/// If the same sessionId appears in multiple directories, an error is logged once
/// and the duplicate session is excluded from the returned entries (fail closed).
pub fn read_session_entries(sessions_dirs: &(impl SessionDirs + ?Sized)) -> Vec<SessionFileEntry> {
    let dirs = sessions_dirs.to_dirs();
    let mut entries: Vec<SessionFileEntry> = Vec::new();

    for dir in &dirs {
        let read_dir = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(err) => {
                debug!(
                    "Unable to read sessions directory {}: {}",
                    dir.display(),
                    err
                );
                continue;
            }
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            // Strictly ignore anything that is not a .json file (e.g. .key files, sockets)
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed reading session file {}: {}", path.display(), e);
                    continue;
                }
            };

            match serde_json::from_str::<SessionFileEntry>(&content) {
                Ok(session_entry) => {
                    if !validate_session_file_entry(&session_entry) {
                        warn!(
                            "Ignoring session file {} with invalid session_id or messaging_socket_path",
                            path.display()
                        );
                        continue;
                    }
                    entries.push(session_entry);
                }
                Err(e) => {
                    warn!("Failed parsing session file {}: {}", path.display(), e);
                }
            }
        }
    }

    entries
}

/// Lists all active (live) sessions matching optional query filters across all configured session directories.
pub fn list_sessions(
    sessions_dirs: &(impl SessionDirs + ?Sized),
    query: &SessionsQuery,
) -> Vec<Session> {
    let entries = read_session_entries(sessions_dirs);
    let mut sessions = Vec::new();

    for entry in entries {
        if !is_pid_live(entry.pid, &entry.proc_start) {
            debug!(
                "Skipping dead/reused session pid {} ({})",
                entry.pid, entry.session_id
            );
            continue;
        }

        if let Some(ref q_cwd) = query.cwd {
            if &entry.cwd != q_cwd && !entry.cwd.starts_with(q_cwd) {
                continue;
            }
        }

        if let Some(ref q_status) = query.status {
            if &entry.status != q_status {
                continue;
            }
        }

        sessions.push(entry.into());
    }

    sessions
}

/// Walks ancestor process parent PIDs up to PID 1,
/// searching for the first ancestor that has an active session file in any directory in `sessions_dirs`.
pub fn find_ancestor_session_in_dirs(
    proc_root: &Path,
    sessions_dirs: &[PathBuf],
    start_pid: u32,
) -> Result<Session, AppError> {
    for (pid, start) in process::Ancestry::new(proc_root, start_pid)
        .skip(1)
        .take(32)
    {
        for dir in sessions_dirs {
            let session_file = dir.join(format!("{pid}.json"));
            if session_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&session_file) {
                    if let Ok(entry) = serde_json::from_str::<SessionFileEntry>(&content) {
                        if validate_session_file_entry(&entry)
                            && process::claude_start_token_matches(
                                proc_root,
                                &start,
                                &entry.proc_start,
                            )
                        {
                            return Ok(entry.into());
                        }
                    }
                }
            }
        }
    }

    Err(AppError::NotFound(
        "no live ancestor agent session found".to_string(),
    ))
}

/// Compatibility wrapper for single-directory ancestor walk.
pub fn find_ancestor_session_in(
    proc_root: &Path,
    sessions_dir: &Path,
    start_pid: u32,
) -> Result<Session, AppError> {
    find_ancestor_session_in_dirs(proc_root, &[sessions_dir.to_path_buf()], start_pid)
}

/// Convenience wrapper for live runtime ancestor walk using the running system and current PID.
pub fn find_ancestor_session(
    sessions_dirs: &(impl SessionDirs + ?Sized),
) -> Result<Session, AppError> {
    let dirs = sessions_dirs.to_dirs();
    find_ancestor_session_in_dirs(
        Path::new(process::LIVE_PROC_ROOT),
        &dirs,
        std::process::id(),
    )
}
