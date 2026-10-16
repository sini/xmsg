use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::agy::AgyConfig;
use crate::error::AppError;
use crate::http::AppState;
use crate::pi::PiStore;
use crate::process;
use crate::registry::{self, Session};
use crate::surface;

/// One `agent.sock` request (AM-4): A13's four operations, mirroring the MCP tools field
/// for field with `idempotency_key` added, and the MCP server's registration. A frame with
/// a field it does not know is refused `bad_request`, naming the field (plan §6 D3).
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentFrame {
    McpStart {
        #[serde(default)]
        schema_version: Option<u32>,
    },
    List {
        #[serde(default)]
        schema_version: Option<u32>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        node: Option<String>,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        within: Option<u64>,
    },
    Send {
        #[serde(default)]
        schema_version: Option<u32>,
        to: String,
        text: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Reply {
        #[serde(default)]
        schema_version: Option<u32>,
        message_id: String,
        text: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Replies {
        #[serde(default)]
        schema_version: Option<u32>,
        message_id: String,
        #[serde(default)]
        wait: Option<u64>,
        #[serde(default)]
        after: Option<i64>,
    },
}

/// Parses one `agent.sock` frame, refusing mismatched `schema_version` or retired v1 fields
/// with an actionable stale-client diagnostic naming the session restart.
pub fn parse_agent_frame(line: &str) -> Result<AgentFrame, AppError> {
    let raw: Option<serde_json::Value> = serde_json::from_str(line).ok();
    if let Some(obj) = raw.as_ref().and_then(serde_json::Value::as_object) {
        if let Some(ver_val) = obj.get("schema_version") {
            match ver_val.as_u64() {
                Some(v) if v == u64::from(surface::MCP_SCHEMA_VERSION) => {}
                Some(v) => {
                    return Err(AppError::BadRequest(format!(
                        "stale xmsg mcp client (schema_version {v}, server expects {}): restart the session to load the current xmsg mcp binary",
                        surface::MCP_SCHEMA_VERSION
                    )));
                }
                None => {
                    return Err(AppError::BadRequest(
                        "schema_version must be an integer".to_string(),
                    ));
                }
            }
        }
    }

    match surface::parse_frame::<AgentFrame>(line) {
        Ok(frame) => Ok(frame),
        Err(AppError::BadRequest(detail)) => {
            if let Some(obj) = raw.as_ref().and_then(serde_json::Value::as_object) {
                let is_stale_v1 = obj
                    .get("schema_version")
                    .and_then(serde_json::Value::as_u64)
                    != Some(u64::from(surface::MCP_SCHEMA_VERSION));
                if is_stale_v1 {
                    let hint = if obj.contains_key("ref") || obj.contains_key("push_replies") {
                        Some("use 'to' instead of 'ref'")
                    } else if obj.contains_key("messageId") {
                        Some("use 'message_id' instead of 'messageId'")
                    } else if obj.contains_key("host") {
                        Some("use 'node' instead of 'host'")
                    } else {
                        None
                    };
                    if let Some(hint) = hint {
                        return Err(AppError::BadRequest(format!(
                            "{detail}; stale xmsg mcp client (schema v1 talking to server v{}): {hint}, and restart the session to load the current xmsg mcp binary",
                            surface::MCP_SCHEMA_VERSION
                        )));
                    }
                }
            }
            Err(AppError::BadRequest(detail))
        }
        Err(other) => Err(other),
    }
}

pub fn current_uid() -> u32 {
    unsafe {
        extern "C" {
            fn getuid() -> u32;
        }
        getuid()
    }
}

/// Creates `dir` and any missing parents at mode 0700 in the `mkdir` call itself, so no
/// concurrent caller can observe it at the umask mode; an existing directory is left as is.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

pub fn ensure_secure_socket_dir(dir: &Path, expected_uid: u32) -> Result<(), AppError> {
    if !dir.exists() {
        create_private_dir(dir).map_err(|e| {
            AppError::InsecureSocketDir(format!(
                "failed to create directory {}: {e}",
                dir.display()
            ))
        })?;
    }

    let meta = fs::symlink_metadata(dir).map_err(|e| {
        AppError::InsecureSocketDir(format!("failed to inspect {}: {e}", dir.display()))
    })?;

    if meta.file_type().is_symlink() {
        return Err(AppError::InsecureSocketDir(format!(
            "path {} is a symlink",
            dir.display()
        )));
    }

    if !meta.is_dir() {
        return Err(AppError::InsecureSocketDir(format!(
            "path {} is not a directory",
            dir.display()
        )));
    }

    let actual_uid = meta.uid();
    if actual_uid != expected_uid {
        return Err(AppError::InsecureSocketDir(format!(
            "directory {} is owned by UID {}, expected UID {}",
            dir.display(),
            actual_uid,
            expected_uid
        )));
    }

    let actual_mode = meta.permissions().mode() & 0o777;
    if actual_mode != 0o700 {
        return Err(AppError::InsecureSocketDir(format!(
            "directory {} has mode {:o}, expected 0700",
            dir.display(),
            actual_mode
        )));
    }

    Ok(())
}

/// Resolves `<runtime dir>/xmsg`: `$XDG_RUNTIME_DIR` when set, otherwise the
/// platform's per-user runtime dir (the Darwin user temp dir on macOS).
pub fn socket_dir_for_env(xdg_var: Option<&str>) -> Result<PathBuf, AppError> {
    match xdg_var {
        Some(val) if !val.trim().is_empty() => Ok(PathBuf::from(val).join("xmsg")),
        _ => crate::process::fallback_runtime_dir()
            .map(|d| d.join("xmsg"))
            .ok_or_else(|| AppError::InsecureSocketDir(
                "XDG_RUNTIME_DIR environment variable is not set. Sockets cannot be safely created without a secure runtime directory."
                    .to_string(),
            )),
    }
}

pub fn default_socket_dir() -> Result<PathBuf, AppError> {
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    socket_dir_for_env(xdg.as_deref())
}

pub fn default_register_sock_path() -> Result<PathBuf, AppError> {
    default_socket_dir().map(|d| d.join("register.sock"))
}

pub fn default_agent_sock_path() -> Result<PathBuf, AppError> {
    default_socket_dir().map(|d| d.join("agent.sock"))
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_caller_session(
    proc_root: &Path,
    sessions_dirs: &(impl crate::registry::SessionDirs + ?Sized),
    agy_config: &AgyConfig,
    agy_store: &crate::agy::AgyStore,
    pi_store: &PiStore,
    svc_store: &crate::svc::SvcStore,
    conn: Option<&rusqlite::Connection>,
    peer_pid: u32,
) -> Result<Session, AppError> {
    let peer = crate::process::PeerCred::unpinned(0, peer_pid);
    resolve_caller_session_peer(
        proc_root,
        sessions_dirs,
        agy_config,
        agy_store,
        pi_store,
        svc_store,
        conn,
        &peer,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_caller_session_peer(
    proc_root: &Path,
    sessions_dirs: &(impl crate::registry::SessionDirs + ?Sized),
    _agy_config: &AgyConfig,
    agy_store: &crate::agy::AgyStore,
    pi_store: &PiStore,
    svc_store: &crate::svc::SvcStore,
    conn: Option<&rusqlite::Connection>,
    peer: &crate::process::PeerCred,
) -> Result<Session, AppError> {
    let peer_pid = peer.pid_or_zero();
    let mut walk = crate::process::Ancestry::from_peer(proc_root, peer);

    for (curr_pid, st) in walk.by_ref().take(32) {
        // Each store is matched against `st`, the start the walk read, never a re-read.
        // 0. A plugin process holds its addresses per session, so it maps to none: a caller
        // reaching it is anonymous (HA2, harness gate v0 C2).
        if let Some(c) = conn {
            if crate::plugin::is_plugin_process(c, curr_pid, &st)
                .map_err(|e| AppError::Internal(e.to_string()))?
            {
                return Err(AppError::NotRecipient(format!(
                    "peer PID {peer_pid} reaches plugin process {curr_pid}, whose addresses are per session"
                )));
            }
        }

        // 1. Check Claude sessions
        let claude_sessions = registry::read_session_entries(sessions_dirs);
        for entry in claude_sessions {
            if entry.pid == curr_pid
                && crate::process::claude_start_token_matches(proc_root, &st, &entry.proc_start)
            {
                let mut session: Session = entry.clone().into();
                if let Some(c) = conn {
                    if let Ok(Some(claim)) =
                        crate::claim::get_active_claim_for_proc(c, entry.pid, &entry.proc_start)
                    {
                        session.session_id = claim.address();
                    }
                }
                return Ok(session);
            }
        }

        // 2. Check Antigravity registered sessions
        {
            let agy_lock = agy_store.read().unwrap();
            for info in agy_lock.values() {
                if info.pid > 0
                    && info.pid == curr_pid
                    && !info.starttime.is_empty()
                    && info.starttime == st
                {
                    return Ok(Session {
                        session_id: info.conversation_id.clone(),
                        name: if !info.conversation_id.is_empty() {
                            Some(info.conversation_id.clone())
                        } else {
                            None
                        },
                        pid: info.pid,
                        cwd: "/".to_string(),
                        status: "idle".to_string(),
                        kind: "interactive".to_string(),
                        entrypoint: None,
                        version: None,
                        started_at: info.registered_at.max(0) as u64,
                        updated_at: info.registered_at.max(0) as u64,
                        harness: "agy".to_string(),
                        registered: Some(info.has_credentials()),
                    });
                }
            }
        }

        // 3. Check Pi sessions
        {
            let pi_lock = pi_store.read().unwrap();
            for info in pi_lock.values() {
                if info.pid == curr_pid && info.starttime == st {
                    return Ok(Session {
                        session_id: info.session_id.clone(),
                        name: info.name.clone().or_else(|| Some(info.session_id.clone())),
                        pid: info.pid,
                        cwd: info.cwd.clone(),
                        status: "idle".to_string(),
                        kind: "interactive".to_string(),
                        entrypoint: None,
                        version: None,
                        started_at: info.registered_at as u64,
                        updated_at: info.registered_at as u64,
                        harness: "pi".to_string(),
                        registered: Some(true),
                    });
                }
            }
        }

        // 4. Check Svc sessions
        {
            let svc_lock = svc_store.read().unwrap();
            for info in svc_lock.values() {
                if info.pid == curr_pid && info.starttime == st {
                    return Ok(Session {
                        session_id: info.session_id.clone(),
                        name: Some(info.name.clone()),
                        pid: info.pid,
                        cwd: info.cwd.clone(),
                        status: "idle".to_string(),
                        kind: "daemon".to_string(),
                        entrypoint: None,
                        version: None,
                        started_at: info.registered_at as u64,
                        updated_at: info.registered_at as u64,
                        harness: "svc".to_string(),
                        registered: Some(true),
                    });
                }
            }
        }
    }

    use crate::process::WalkEnd;
    Err(AppError::NotRecipient(match walk.end() {
        Some(WalkEnd::Younger { parent, child }) => {
            format!("peer PID {peer_pid}: parent {parent} of {child} is not older than it")
        }
        Some(WalkEnd::Unreadable(pid)) => format!(
            "peer PID {peer_pid}: the start time of {pid} cannot be read, so its ancestry is unproven"
        ),
        Some(WalkEnd::Reused(pid)) => {
            format!("peer PID {peer_pid}: PID {pid} was reused while its ancestry was walked")
        }
        Some(WalkEnd::Root) | None => {
            format!("peer PID {peer_pid} does not descend from an active agent session")
        }
    }))
}

pub async fn run_agent_server(
    sock_path: PathBuf,
    state: Arc<AppState>,
    my_uid: u32,
) -> io::Result<()> {
    if let Some(parent) = sock_path.parent() {
        if let Err(e) = ensure_secure_socket_dir(parent, my_uid) {
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

    let listener = UnixListener::bind(&sock_path)?;
    fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("failed to set permissions on {}: {e}", sock_path.display()),
        )
    })?;

    run_agent_server_with_listener(listener, state, my_uid).await
}

pub async fn run_agent_server_with_listener(
    listener: UnixListener,
    state: Arc<AppState>,
    my_uid: u32,
) -> io::Result<()> {
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        let (stream, _) = tokio::select! {
            res = listener.accept() => match res {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("agent server accept error: {e}");
                    continue;
                }
            },
            Some(_) = tasks.join_next() => {
                continue;
            }
        };

        let peer = match process::peer_cred(&stream) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("failed to get peer creds on agent.sock: {e}");
                continue;
            }
        };

        let peer_uid = peer.uid;
        let peer_pid = peer.pid_or_zero();

        if peer_uid != my_uid {
            tracing::warn!("agent.sock rejected connection: UID mismatch {peer_uid} != {my_uid}");
            continue;
        }

        let initial_starttime = match peer.starttime(&state.agy_config.proc_root) {
            Ok(st) => st,
            Err(e) => {
                tracing::warn!("failed to get starttime for peer PID {peer_pid}: {e}");
                continue;
            }
        };

        let state_clone = state.clone();

        tasks.spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut byte_buf = Vec::new();
            let max_frame = state_clone.max_body * 6 + 4096;

            loop {
                byte_buf.clear();
                let n = (&mut buf_reader)
                    .take((max_frame + 1) as u64)
                    .read_until(b'\n', &mut byte_buf)
                    .await
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                if byte_buf.len() > max_frame || (n >= max_frame && !byte_buf.ends_with(b"\n")) {
                    let err_resp = serde_json::json!({
                        "status": "error",
                        "error": "bad_request",
                        "detail": "frame exceeds maximum allowed size"
                    });
                    let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                    break;
                }
                if !byte_buf.ends_with(b"\n") {
                    break;
                }

                // Verify peer PID is still live and starttime has not changed
                if !peer.is_alive(&state_clone.agy_config.proc_root, &initial_starttime) {
                    tracing::warn!("peer PID {peer_pid} died or starttime changed");
                    break;
                }

                let line = match std::str::from_utf8(&byte_buf) {
                    Ok(s) => s,
                    Err(_) => {
                        let err_resp = serde_json::json!({
                            "status": "error",
                            "error": "bad_request",
                            "detail": "invalid utf-8"
                        });
                        let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                        break;
                    }
                };

                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let frame: AgentFrame = match parse_agent_frame(trimmed) {
                    Ok(f) => f,
                    Err(e) => {
                        let err = e.frame();
                        let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
                        continue;
                    }
                };

                let caller_needed = matches!(frame, AgentFrame::Send { .. } | AgentFrame::Reply { .. });
                let caller = if caller_needed {
                    match surface::trace_caller_peer(&state_clone, &peer).await {
                        Ok(c) => Some(c),
                        Err(e) => {
                            let err = e.frame();
                            let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
                            continue;
                        }
                    }
                } else {
                    None
                };

                let resp: Result<serde_json::Value, AppError> = match frame {
                    AgentFrame::McpStart { .. } => {
                    match crate::agy::attest_mcp_caller_peer(
                        &state_clone.agy_config.proc_root,
                        &state_clone.agy_config.proc_locks_path,
                        &state_clone.agy_config.presence_dir,
                        &state_clone.agy_config.trusted_agy_exes,
                        my_uid,
                        &peer,
                    ) {
                        Ok((reg, conv_id)) => {
                            let session_key = conv_id.clone();
                            {
                                let mut store_lock = state_clone.agy_store.write().unwrap();
                                store_lock.entry(session_key.clone())
                                    .and_modify(|current| {
                                        if current.pid != reg.pid || current.starttime != reg.starttime {
                                            *current = crate::agy::AgySessionInfo::new(
                                                conv_id.clone(),
                                                reg.pid,
                                                reg.starttime.clone(),
                                                None,
                                            );
                                        }
                                    })
                                    .or_insert_with(|| {
                                        crate::agy::AgySessionInfo::new(
                                            conv_id,
                                            reg.pid,
                                            reg.starttime,
                                        None,
                                    )
                                });
                            }
                            if let Ok(db) = state_clone.db.lock() {
                                let _ = crate::storage::mark_live(
                                    &db,
                                    &session_key,
                                    "agy",
                                    crate::storage::now_epoch_secs(),
                                );
                            }
                            let _ = crate::claim::sync_claims(
                                &state_clone.db,
                                &state_clone.agy_config.proc_root,
                                &state_clone.sessions_dirs,
                                &state_clone.node_name,
                            ).await;
                            let resp = serde_json::json!({
                                "status": "ok",
                                "sessionId": session_key,
                                "address": session_key,
                            });
                            let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                        }
                        Err(e) => {
                            // Check Claude Code sessions via claim table
                            let claude_res = crate::claim::sync_claims(
                                &state_clone.db,
                                &state_clone.agy_config.proc_root,
                                &state_clone.sessions_dirs,
                                &state_clone.node_name,
                            )
                            .await
                            .ok()
                            .and_then(|active_pairs| {
                                let proc_root = &state_clone.agy_config.proc_root;
                                process::Ancestry::from_peer(proc_root, &peer)
                                    .take(32)
                                    .find_map(|(pid, st)| {
                                        active_pairs.iter().find_map(|(c, _)| {
                                            (c.pid == pid
                                                && process::claude_start_token_matches(
                                                    proc_root,
                                                    &st,
                                                    &c.proc_start,
                                                ))
                                            .then(|| c.address())
                                        })
                                    })
                            });

                            if let Some(address) = claude_res {
                                let resp = serde_json::json!({
                                    "status": "ok",
                                    "sessionId": address,
                                    "address": address,
                                });
                                let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                            } else {
                                let err_resp = serde_json::json!({
                                    "status": "error",
                                    "error": "unattested",
                                    "detail": format!("caller is not an attested agent session: {e}"),
                                });
                                let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
                            }
                        }
                    }
                        continue;
                    }
                    AgentFrame::List {
                        name,
                        node,
                        kind,
                        status,
                        within,
                        ..
                    } => {
                        let query = surface::ListQuery {
                            name,
                            node,
                            kind,
                            status,
                            within,
                            host: None,
                        };
                        surface::list(&state_clone, &query)
                            .await
                            .map(|r| serde_json::json!({ "status": "ok", "recipients": r.recipients, "nodes": r.nodes }))
                    }
                    AgentFrame::Send { to, text, idempotency_key, .. } => {
                        let sender = surface::Sender::Session(caller.expect("caller resolved"));
                        surface::send(&state_clone, &sender, &to, &text, idempotency_key.as_deref())
                            .await
                            .map(|r| {
                                serde_json::json!({
                                    "status": "ok",
                                    "message_id": r.message_id,
                                    "address": r.address,
                                    "outcome": r.outcome,
                                })
                            })
                    }
                    AgentFrame::Reply { message_id, text, idempotency_key, .. } => {
                        let caller = caller.expect("caller resolved");
                        surface::reply(&state_clone, &caller, &message_id, &text, idempotency_key.as_deref())
                            .await
                            .map(|r| serde_json::json!({ "status": "ok", "reply": r }))
                    }
                    AgentFrame::Replies { message_id, wait, after, .. } => {
                        surface::replies(&state_clone, &message_id, after.unwrap_or(0), wait.unwrap_or(0))
                            .await
                            .map(|r| serde_json::json!({ "status": "ok", "replies": r }))
                    }
                };
                let line = match resp {
                    Ok(v) => v,
                    Err(e) => e.frame(),
                };
                let _ = writer.write_all(format!("{line}\n").as_bytes()).await;
            }
        });
    }
}
