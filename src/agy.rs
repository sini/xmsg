use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use serde::{Deserialize, Serialize};

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
            proc_locks_path: PathBuf::from("/proc/locks"),
            proc_root: PathBuf::from("/proc"),
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
    if lock_type != "FLOCK" && lock_type != "POSIX" {
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
pub fn find_lock_holder(
    proc_locks_path: &Path,
    dev_major: u32,
    dev_minor: u32,
    target_inode: u64,
) -> io::Result<Option<u32>> {
    let content = fs::read_to_string(proc_locks_path)?;
    for line in content.lines() {
        if let Some((pid, maj, min, ino)) = parse_locks_line(line) {
            if maj == dev_major && min == dev_minor && ino == target_inode {
                return Ok(Some(pid));
            }
        }
    }
    Ok(None)
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

        let status = if is_registered { "idle" } else { "unregistered" };

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
    // 1. Peer UID verification
    if peer_uid != my_uid {
        return Err(AppError::NotRecipient(format!(
            "peer UID {peer_uid} does not match server UID {my_uid}"
        )));
    }

    // 2. Presence lock check
    let holder_pid = match get_presence_lock_holder(presence_dir, proc_locks, &req.conversation_id) {
        Ok(Some(pid)) => pid,
        Ok(None) => {
            return Err(AppError::Gone {
                session_id: req.conversation_id.clone(),
                pid: 0,
            });
        }
        Err(e) => return Err(AppError::Internal(format!("failed to check presence lock: {e}"))),
    };

    // 3. Ancestor walk from peer_pid to holder_pid
    if peer_pid == holder_pid {
        return Ok(holder_pid);
    }

    let mut curr_pid = peer_pid;
    let mut reached_holder = false;

    for _ in 0..32 {
        let stat_path = proc_root.join(curr_pid.to_string()).join("stat");
        let content = match fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => break,
        };

        let Some(rparen) = content.rfind(')') else { break; };
        let remainder = &content[rparen + 1..];
        let fields: Vec<&str> = remainder.split_whitespace().collect();
        if fields.len() < 2 {
            break;
        }

        let Ok(ppid) = fields[1].parse::<u32>() else { break; };
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

    // 3. Format envelope (§9.4)
    let envelope = format!(
        "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
        from_name, message_id, body_text
    );

    // 4. Spawn agy agentapi send-message directly as argv vector with NO shell
    let mut cmd = tokio::process::Command::new(&config.agy_bin);
    cmd.arg("agentapi")
        .arg("send-message")
        .arg("--title")
        .arg(from_name)
        .arg(&session.session_id)
        .arg(&envelope)
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
        return Err(AppError::CredentialsStale(format!(
            "authentication failed: {combined}"
        )));
    }

    if !output.status.success() {
        return Err(AppError::InboxUnavailable(format!(
            "delivery exited with code {:?}: {combined}",
            output.status.code()
        )));
    }

    Ok(DeliveryResponse {
        session_id: session.session_id.clone(),
        from_name: from_name.to_string(),
        bytes: body_text.len(),
        message_id: message_id.to_string(),
    })
}

/// Ancestor walk to find an active agy presence lock held by an ancestor process.
pub fn find_ancestor_agy_session_in(
    proc_root: &Path,
    proc_locks: &Path,
    presence_dir: &Path,
    start_pid: u32,
) -> Result<String, AppError> {
    let mut curr_pid = start_pid;

    for _ in 0..32 {
        let stat_path = proc_root.join(curr_pid.to_string()).join("stat");
        let content = match fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => break,
        };

        let Some(rparen) = content.rfind(')') else { break; };
        let remainder = &content[rparen + 1..];
        let fields: Vec<&str> = remainder.split_whitespace().collect();
        if fields.len() < 2 {
            break;
        }

        let Ok(ppid) = fields[1].parse::<u32>() else { break; };
        if ppid <= 1 {
            break;
        }

        // Check if ppid holds any presence lock in presence_dir
        if let Ok(entries) = fs::read_dir(presence_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("lock") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(Some(holder)) = get_presence_lock_holder(presence_dir, proc_locks, stem) {
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

    Err(AppError::NotFound("no live ancestor agy session found".to_string()))
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

/// Returns the default registration socket path ($XDG_RUNTIME_DIR/xmsg/register.sock or /tmp/xmsg-$UID/register.sock).
pub fn default_register_sock_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("xmsg").join("register.sock")
    } else {
        let uid = current_uid();
        PathBuf::from(format!("/tmp/xmsg-{uid}")).join("register.sock")
    }
}

/// Runs the registration Unix domain socket server.
pub async fn run_register_server(
    sock_path: PathBuf,
    config: AgyConfig,
    store: AgyStore,
    my_uid: u32,
) -> io::Result<()> {
    if let Some(parent) = sock_path.parent() {
        let _ = fs::create_dir_all(parent);
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let _ = fs::remove_file(&sock_path);

    let listener = tokio::net::UnixListener::bind(&sock_path)?;

    loop {
        let (mut stream, _) = match listener.accept().await {
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

        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = stream.split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            let read_ok = buf_reader.read_line(&mut line).await.is_ok();
            if read_ok && !line.trim().is_empty() {
                match serde_json::from_str::<AgyRegisterRequest>(&line) {
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
                                let err_resp = format!("{{\"status\":\"error\",\"detail\":\"{}\"}}\n", e);
                                let _ = writer.write_all(err_resp.as_bytes()).await;
                            }
                        }
                    }
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

