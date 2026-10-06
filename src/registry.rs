use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

use crate::error::AppError;

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
}

impl From<SessionFileEntry> for Session {
    fn from(entry: SessionFileEntry) -> Self {
        Self {
            session_id: entry.session_id,
            name: entry.name,
            pid: entry.pid,
            cwd: entry.cwd,
            status: entry.status,
            kind: entry.kind,
            entrypoint: entry.entrypoint,
            version: entry.version,
            started_at: entry.started_at,
            updated_at: entry.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct SessionsQuery {
    pub cwd: Option<String>,
    pub status: Option<String>,
}

/// Checks whether a process with `pid` is currently alive and has the expected `proc_start`.
pub fn is_pid_live(pid: u32, expected_proc_start: &str) -> bool {
    is_pid_live_in(Path::new("/proc"), pid, expected_proc_start)
}

pub fn is_pid_live_in(proc_root: &Path, pid: u32, expected_proc_start: &str) -> bool {
    let stat_path = proc_root.join(pid.to_string()).join("stat");
    let content = match std::fs::read_to_string(&stat_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // In Linux /proc/<pid>/stat, field 2 is the comm in parentheses.
    // Comm can contain spaces or closing parens, so find the LAST ')'
    let Some(rparen) = content.rfind(')') else {
        return false;
    };

    let remainder = &content[rparen + 1..];
    let fields: Vec<&str> = remainder.split_whitespace().collect();
    // After the closing paren:
    // index 0 is field 3 (state)
    // index 19 is field 22 (starttime)
    if fields.len() < 20 {
        return false;
    }

    let actual_starttime = fields[19];
    actual_starttime == expected_proc_start
}

/// Reads all session files in `sessions_dir`, ignoring `.key` files and invalid entries.
pub fn read_session_entries(sessions_dir: &Path) -> Vec<SessionFileEntry> {
    let mut entries = Vec::new();
    let read_dir = match std::fs::read_dir(sessions_dir) {
        Ok(rd) => rd,
        Err(err) => {
            debug!(
                "Unable to read sessions directory {}: {}",
                sessions_dir.display(),
                err
            );
            return entries;
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
            Ok(entry) => entries.push(entry),
            Err(e) => {
                warn!("Failed parsing session file {}: {}", path.display(), e);
            }
        }
    }

    entries
}

/// Lists all active (live) sessions matching optional query filters.
pub fn list_sessions(sessions_dir: &Path, query: &SessionsQuery) -> Vec<Session> {
    let entries = read_session_entries(sessions_dir);
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

/// Resolves a session reference (session_id, pid, or name) to a live Session and messaging socket path.
pub fn resolve_session(sessions_dir: &Path, ref_str: &str) -> Result<(Session, PathBuf), AppError> {
    let entries = read_session_entries(sessions_dir);

    // Candidates matching ref_str by session_id, pid, or name
    let ref_lower = ref_str.to_ascii_lowercase();
    let ref_pid: Option<u32> = ref_str.parse().ok();

    let matching_candidates: Vec<SessionFileEntry> = entries
        .into_iter()
        .filter(|e| {
            if e.session_id.to_ascii_lowercase() == ref_lower {
                return true;
            }
            if let Some(pid) = ref_pid {
                if e.pid == pid {
                    return true;
                }
            }
            if let Some(ref name) = e.name {
                if name == ref_str {
                    return true;
                }
            }
            false
        })
        .collect();

    if matching_candidates.is_empty() {
        return Err(AppError::NotFound(ref_str.to_string()));
    }

    // Check liveness of candidates
    let mut live_candidates = Vec::new();
    let mut last_dead: Option<(String, u32)> = None;

    for candidate in matching_candidates {
        if is_pid_live(candidate.pid, &candidate.proc_start) {
            live_candidates.push(candidate);
        } else {
            last_dead = Some((candidate.session_id, candidate.pid));
        }
    }

    if live_candidates.is_empty() {
        let (session_id, pid) = last_dead.unwrap();
        return Err(AppError::Gone { session_id, pid });
    }

    if live_candidates.len() > 1 {
        let ids: Vec<String> = live_candidates
            .iter()
            .map(|c| c.session_id.clone())
            .collect();
        return Err(AppError::Ambiguous(ids.join(", ")));
    }

    let resolved = live_candidates.into_iter().next().unwrap();
    let socket_path = PathBuf::from(&resolved.messaging_socket_path);
    Ok((resolved.into(), socket_path))
}

/// Walks ancestor process parent PIDs (reading /proc/<pid>/stat field 4) up to PID 1,
/// searching for the first ancestor that has an active session file in `sessions_dir`.
/// Parameterized with `proc_root` to allow unit testing with synthetic proc trees.
pub fn find_ancestor_session_in(
    proc_root: &Path,
    sessions_dir: &Path,
    start_pid: u32,
) -> Result<Session, AppError> {
    let mut curr_pid = start_pid;

    for _ in 0..32 {
        let stat_path = proc_root.join(curr_pid.to_string()).join("stat");
        let content = match std::fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => break,
        };

        let Some(rparen) = content.rfind(')') else {
            break;
        };

        let remainder = &content[rparen + 1..];
        let fields: Vec<&str> = remainder.split_whitespace().collect();
        if fields.len() < 2 {
            break;
        }

        // fields[0] is state (field 3)
        // fields[1] is ppid (field 4)
        let Ok(ppid) = fields[1].parse::<u32>() else {
            break;
        };

        if ppid <= 1 {
            break;
        }

        let session_file = sessions_dir.join(format!("{ppid}.json"));
        if session_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&session_file) {
                if let Ok(entry) = serde_json::from_str::<SessionFileEntry>(&content) {
                    if is_pid_live_in(proc_root, ppid, &entry.proc_start) {
                        return Ok(entry.into());
                    }
                }
            }
        }

        curr_pid = ppid;
    }

    Err(AppError::NotFound(
        "no live ancestor agent session found".to_string(),
    ))
}

/// Convenience wrapper for live runtime ancestor walk using system /proc and current PID.
pub fn find_ancestor_session(sessions_dir: &Path) -> Result<Session, AppError> {
    find_ancestor_session_in(Path::new("/proc"), sessions_dir, std::process::id())
}
