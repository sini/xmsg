use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

pub type AgyStore = Arc<RwLock<HashMap<String, AgyCredentials>>>;

pub fn new_agy_store() -> AgyStore {
    Arc::new(RwLock::new(HashMap::new()))
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
}

impl Default for AgyConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Self {
            presence_dir: PathBuf::from(home).join(".gemini/antigravity-cli/presence"),
            proc_locks_path: PathBuf::from(LIVE_PROC_LOCKS),
            proc_root: PathBuf::from(crate::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
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

/// Lists all active agy sessions from the presence directory and /proc/locks.
pub fn list_agy_sessions(
    config: &AgyConfig,
    store: &AgyStore,
    query: &SessionsQuery,
) -> Vec<Session> {
    let mut sessions = Vec::new();
    if !locks_supported(&config.proc_locks_path) {
        return sessions;
    }

    let entries = match fs::read_dir(&config.presence_dir) {
        Ok(e) => e,
        Err(_) => return sessions,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("lock") {
            continue;
        }

        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let conversation_id = stem.to_string();

        let holder_pid = match get_presence_lock_holder(
            &config.presence_dir,
            &config.proc_locks_path,
            &conversation_id,
        ) {
            Ok(Some(pid)) => pid,
            _ => continue,
        };

        let is_registered = store
            .read()
            .unwrap()
            .get(&conversation_id)
            .map(|c| !c.is_stale)
            .unwrap_or(false);

        let status = if is_registered {
            "idle"
        } else {
            "unregistered"
        };

        let session = Session {
            session_id: conversation_id.clone(),
            name: Some(conversation_id.clone()),
            pid: holder_pid,
            cwd: "/".to_string(),
            status: status.to_string(),
            kind: "interactive".to_string(),
            entrypoint: None,
            version: None,
            started_at: 0,
            updated_at: 0,
            harness: "agy".to_string(),
            registered: Some(is_registered),
        };

        if let Some(ref q_status) = query.status {
            if session.status != *q_status {
                continue;
            }
        }

        sessions.push(session);
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

    let ref_lower = ref_str.to_ascii_lowercase();
    let ref_pid = ref_str.parse::<u32>().ok();

    let matched: Vec<Session> = all
        .into_iter()
        .filter(|s| {
            if s.session_id.to_ascii_lowercase() == ref_lower {
                return true;
            }
            if let Some(pid) = ref_pid {
                if s.pid == pid {
                    return true;
                }
            }
            if let Some(ref name) = s.name {
                if name.to_ascii_lowercase() == ref_lower {
                    return true;
                }
            }
            false
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
pub fn verify_registration(
    proc_root: &Path,
    proc_locks: &Path,
    presence_dir: &Path,
    my_uid: u32,
    peer_uid: u32,
    peer_pid: u32,
    req: &AgyRegisterRequest,
) -> Result<u32, AppError> {
    if !locks_supported(proc_locks) {
        return Err(AppError::BadRequest(format!(
            "agy is Linux only: its presence locks need {LIVE_PROC_LOCKS}"
        )));
    }

    // 1. Peer UID verification
    if peer_uid != my_uid {
        return Err(AppError::NotRecipient(format!(
            "peer UID {peer_uid} does not match server UID {my_uid}"
        )));
    }

    // 2. Presence lock check
    let holder_pid = match get_presence_lock_holder(presence_dir, proc_locks, &req.conversation_id)
    {
        Ok(Some(pid)) => pid,
        Ok(None) => {
            return Err(AppError::Gone {
                session_id: req.conversation_id.clone(),
                pid: 0,
            });
        }
        Err(e) => {
            return Err(AppError::Internal(format!(
                "failed to check presence lock: {e}"
            )))
        }
    };

    // 3. Ancestor walk from peer_pid to holder_pid
    if peer_pid == holder_pid {
        return Ok(holder_pid);
    }

    let mut curr_pid = peer_pid;
    let mut reached_holder = false;

    for _ in 0..32 {
        let Some(ppid) = crate::process::parent_pid(proc_root, curr_pid) else {
            break;
        };
        if ppid <= 1 {
            break;
        }

        if ppid == holder_pid {
            reached_holder = true;
            break;
        }

        curr_pid = ppid;
    }

    if !reached_holder {
        return Err(AppError::NotRecipient(format!(
            "peer PID {peer_pid} is not a descendant of lock holder PID {holder_pid}"
        )));
    }

    Ok(holder_pid)
}

/// Delivers a message to an Antigravity session.
pub async fn deliver_agy(
    config: &AgyConfig,
    store: &AgyStore,
    session: &Session,
    from_name: &str,
    message_id: &str,
    body_text: &str,
) -> Result<DeliveryResponse, AppError> {
    // Format envelope (§9.4)
    let envelope = format!(
        "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
        from_name, message_id, body_text
    );
    deliver_agy_envelope(config, store, session, from_name, &envelope).await?;

    Ok(DeliveryResponse {
        session_id: session.session_id.clone(),
        from_name: from_name.to_string(),
        bytes: body_text.len(),
        message_id: message_id.to_string(),
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
    // 1. Check lock is still held
    let _current_holder = match get_presence_lock_holder(
        &config.presence_dir,
        &config.proc_locks_path,
        &session.session_id,
    ) {
        Ok(Some(pid)) => pid,
        _ => {
            store.write().unwrap().remove(&session.session_id);
            return Err(AppError::Gone {
                session_id: session.session_id.clone(),
                pid: session.pid,
            });
        }
    };

    // 2. Check credentials in store
    let creds = match store.read().unwrap().get(&session.session_id).cloned() {
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

    // 4. Spawn agy agentapi send-message directly as argv vector with NO shell
    let mut cmd = tokio::process::Command::new(&config.agy_bin);
    cmd.arg("agentapi")
        .arg("send-message")
        .arg("--title")
        .arg(title)
        .arg("--")
        .arg(&session.session_id)
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
        if let Some(entry) = store.write().unwrap().get_mut(&session.session_id) {
            entry.is_stale = true;
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

/// Ancestor walk to find an active agy presence lock held by an ancestor process.
pub fn find_ancestor_agy_session_in(
    proc_root: &Path,
    proc_locks: &Path,
    presence_dir: &Path,
    start_pid: u32,
) -> Result<String, AppError> {
    if !locks_supported(proc_locks) {
        return Err(AppError::NotFound(
            "no live ancestor agy session found (agy is Linux only)".to_string(),
        ));
    }
    let mut curr_pid = start_pid;

    for _ in 0..32 {
        let Some(ppid) = crate::process::parent_pid(proc_root, curr_pid) else {
            break;
        };
        if ppid <= 1 {
            break;
        }

        // Check if ppid holds any presence lock in presence_dir
        if let Ok(entries) = fs::read_dir(presence_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("lock") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(Some(holder)) =
                            get_presence_lock_holder(presence_dir, proc_locks, stem)
                        {
                            if holder == ppid {
                                return Ok(stem.to_string());
                            }
                        }
                    }
                }
            }
        }

        curr_pid = ppid;
    }

    Err(AppError::NotFound(
        "no live ancestor agy session found".to_string(),
    ))
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

/// Returns the default registration socket path ($XDG_RUNTIME_DIR/xmsg/register.sock).
pub fn default_register_sock_path() -> Result<PathBuf, AppError> {
    crate::agent::default_register_sock_path()
}

/// Runs the registration Unix domain socket server multiplexing agy and pi harnesses.
#[allow(clippy::too_many_arguments)]
pub async fn run_register_server(
    sock_path: PathBuf,
    config: AgyConfig,
    store: AgyStore,
    pi_store: crate::pi::PiStore,
    db: Arc<Mutex<rusqlite::Connection>>,
    pi_notify_tx: tokio::sync::broadcast::Sender<String>,
    reply_ttl: Duration,
    my_uid: u32,
) -> io::Result<()> {
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

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("register server accept error: {e}");
                continue;
            }
        };

        let ucred = match stream.peer_cred() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("failed to get peer creds: {e}");
                continue;
            }
        };

        let peer_uid = ucred.uid();
        let peer_pid = ucred.pid().map(|p| p as u32).unwrap_or(0);

        let config_clone = config.clone();
        let store_clone = store.clone();
        let pi_store_clone = pi_store.clone();
        let db_clone = db.clone();
        let pi_notify_tx_clone = pi_notify_tx.clone();

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
                    Ok(ref v) if v.get("harness").and_then(|h| h.as_str()) == Some("pi") => {
                        match serde_json::from_value::<crate::pi::PiRegisterRequest>(v.clone()) {
                            Ok(req) => {
                                if let Err(e) = crate::pi::handle_pi_connection(
                                    buf_reader,
                                    writer,
                                    config_clone.proc_root.clone(),
                                    pi_store_clone,
                                    my_uid,
                                    peer_uid,
                                    peer_pid,
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
                    Ok(v) => match serde_json::from_value::<AgyRegisterRequest>(v) {
                        Ok(req) => {
                            match verify_registration(
                                &config_clone.proc_root,
                                &config_clone.proc_locks_path,
                                &config_clone.presence_dir,
                                my_uid,
                                peer_uid,
                                peer_pid,
                                &req,
                            ) {
                                Ok(_) => {
                                    store_clone.write().unwrap().insert(
                                        req.conversation_id.clone(),
                                        AgyCredentials {
                                            ls_address: req.ls_address,
                                            csrf_token: req.csrf_token,
                                            is_stale: false,
                                        },
                                    );
                                    let _ = writer.write_all(b"{\"status\":\"ok\"}\n").await;
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

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn registration_against_live_locks_is_rejected_off_linux() {
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
            uid,
            uid,
            std::process::id(),
            &req,
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(ref d) if d.contains("Linux only")));
        assert!(matches!(
            find_ancestor_agy_session_in(
                Path::new(crate::process::LIVE_PROC_ROOT),
                Path::new(LIVE_PROC_LOCKS),
                Path::new("/nonexistent"),
                std::process::id(),
            ),
            Err(AppError::NotFound(_))
        ));
    }
}
