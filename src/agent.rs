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
        #[serde(default)]
        ls_address: Option<String>,
        #[serde(default)]
        csrf_token: Option<String>,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        registered_at: Option<i64>,
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
        #[serde(default)]
        #[allow(dead_code)]
        as_agent: Option<String>,
        #[serde(default)]
        codex_session: Option<String>,
        #[serde(default)]
        codex_thread: Option<String>,
        #[serde(default)]
        codex_turn: Option<String>,
    },
    Send {
        #[serde(default)]
        schema_version: Option<u32>,
        to: String,
        text: String,
        #[serde(default)]
        idempotency_key: Option<String>,
        #[serde(default)]
        as_agent: Option<String>,
        #[serde(default)]
        codex_session: Option<String>,
        #[serde(default)]
        codex_thread: Option<String>,
        #[serde(default)]
        codex_turn: Option<String>,
    },
    Reply {
        #[serde(default)]
        schema_version: Option<u32>,
        message_id: String,
        text: String,
        #[serde(default)]
        idempotency_key: Option<String>,
        #[serde(default)]
        as_agent: Option<String>,
        #[serde(default)]
        codex_session: Option<String>,
        #[serde(default)]
        codex_thread: Option<String>,
        #[serde(default)]
        codex_turn: Option<String>,
    },
    Replies {
        #[serde(default)]
        schema_version: Option<u32>,
        message_id: String,
        #[serde(default)]
        wait: Option<u64>,
        #[serde(default)]
        after: Option<i64>,
        #[serde(default)]
        #[allow(dead_code)]
        as_agent: Option<String>,
        #[serde(default)]
        codex_session: Option<String>,
        #[serde(default)]
        codex_thread: Option<String>,
        #[serde(default)]
        codex_turn: Option<String>,
    },
    Inbox {
        #[serde(default)]
        schema_version: Option<u32>,
        #[serde(default)]
        wait: Option<u64>,
        #[serde(default)]
        as_agent: Option<String>,
        #[serde(default)]
        codex_session: Option<String>,
        #[serde(default)]
        codex_thread: Option<String>,
        #[serde(default)]
        codex_turn: Option<String>,
    },
    Subagent {
        #[serde(default)]
        schema_version: Option<u32>,
        event: String,
        agent_id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        agent_type: Option<String>,
        #[serde(default)]
        tool_use_id: Option<String>,
        #[serde(default)]
        transcript_path: Option<String>,
        #[serde(default)]
        to: Option<String>,
        #[serde(default)]
        pin_name: Option<String>,
    },
    CodexHook {
        #[serde(default)]
        schema_version: Option<u32>,
        event: String,
        #[serde(default)]
        label: Option<String>,
        payload: serde_json::Value,
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

#[derive(Debug, Clone)]
pub enum CallerTrace {
    Session(Session),
    CodexOwner {
        owner_pid: u32,
        owner_starttime: String,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_caller_session_peer(
    proc_root: &Path,
    sessions_dirs: &(impl crate::registry::SessionDirs + ?Sized),
    agy_config: &AgyConfig,
    agy_store: &crate::agy::AgyStore,
    pi_store: &PiStore,
    svc_store: &crate::svc::SvcStore,
    conn: Option<&rusqlite::Connection>,
    peer: &crate::process::PeerCred,
) -> Result<Session, AppError> {
    match resolve_caller_session_peer_inner(
        proc_root,
        sessions_dirs,
        agy_config,
        agy_store,
        pi_store,
        svc_store,
        conn,
        None,
        peer,
    )? {
        CallerTrace::Session(s) => Ok(s),
        CallerTrace::CodexOwner { .. } => Err(AppError::NotRecipient(
            "codex MCP call is missing runtime _meta (sessionId/threadId); refresh MCP or restart the codex session"
                .to_string(),
        )),
    }
}

pub fn trace_caller_or_codex_owner(
    state: &AppState,
    peer: &crate::process::PeerCred,
) -> Result<CallerTrace, AppError> {
    #[cfg(target_os = "linux")]
    let codex_cfg = {
        let rt_arc = crate::codex::for_state(state);
        let mut cfg = rt_arc.lock().unwrap().config.clone();
        cfg.proc_root = state.agy_config.proc_root.clone();
        Some(cfg)
    };
    #[cfg(not(target_os = "linux"))]
    let codex_cfg: Option<()> = None;
    let db = state.db.lock().ok();
    resolve_caller_session_peer_inner(
        &state.agy_config.proc_root,
        &state.sessions_dirs,
        &state.agy_config,
        &state.agy_store,
        &state.pi_store,
        &state.svc_store,
        db.as_deref(),
        codex_cfg.as_ref(),
        peer,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_caller_session_peer_inner(
    proc_root: &Path,
    sessions_dirs: &(impl crate::registry::SessionDirs + ?Sized),
    _agy_config: &AgyConfig,
    agy_store: &crate::agy::AgyStore,
    pi_store: &PiStore,
    svc_store: &crate::svc::SvcStore,
    conn: Option<&rusqlite::Connection>,
    #[cfg(target_os = "linux")] codex_config: Option<&crate::codex::CodexConfig>,
    #[cfg(not(target_os = "linux"))] _codex_config: Option<&()>,
    peer: &crate::process::PeerCred,
) -> Result<CallerTrace, AppError> {
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
                if let Some(c) = conn {
                    if crate::claim::is_non_claude_instance(c, &entry.session_id).unwrap_or(false) {
                        continue;
                    }
                }
                let mut session: Session = entry.clone().into();
                if let Some(c) = conn {
                    if let Ok(Some(claim)) =
                        crate::claim::get_active_claim_for_proc(c, entry.pid, &entry.proc_start)
                    {
                        session.session_id = claim.address();
                    }
                }
                return Ok(CallerTrace::Session(session));
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
                    return Ok(CallerTrace::Session(Session {
                        session_id: info.conversation_id.clone(),
                        name: info
                            .label
                            .as_deref()
                            .and_then(crate::inbox::clean_label)
                            .or_else(|| {
                                (!info.conversation_id.is_empty())
                                    .then(|| info.conversation_id.clone())
                            }),
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
                    }));
                }
            }
        }

        // 3. Check Pi sessions
        {
            let pi_lock = pi_store.read().unwrap();
            for info in pi_lock.values() {
                if info.pid == curr_pid && info.starttime == st {
                    return Ok(CallerTrace::Session(Session {
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
                    }));
                }
            }
        }

        // 4. Check Svc sessions (hop 0 only: a service daemon is attested by its own
        //    --svc-exe binary at peer_pid (GI-9); child processes spawned by a service
        //    must not inherit the service's identity on agent.sock).
        if curr_pid == peer_pid {
            let svc_lock = svc_store.read().unwrap();
            for info in svc_lock.values() {
                if info.pid == curr_pid && info.starttime == st {
                    return Ok(CallerTrace::Session(Session {
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
                    }));
                }
            }
        }

        // 5. Check trusted Codex owner (HA9-A.codex §2.2, C4): stop the ancestry walk at
        //    the nearest trusted Codex process `O = (curr_pid, st)` so a Codex caller never
        //    falls through to an outer shell or ancestor harness session.
        #[cfg(target_os = "linux")]
        if let Some(cfg) = codex_config {
            if crate::codex::is_trusted_codex_owner_step(cfg, curr_pid, &st).is_some() {
                return Ok(CallerTrace::CodexOwner {
                    owner_pid: curr_pid,
                    owner_starttime: st,
                });
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

        let initial_starttime = if peer.is_unmapped() && peer.is_pin_alive() {
            "0".to_string()
        } else {
            match peer.starttime(&state.agy_config.proc_root) {
                Ok(st) => st,
                Err(e) => {
                    tracing::warn!("failed to get starttime for peer PID {peer_pid}: {e}");
                    continue;
                }
            }
        };

        let state_clone = state.clone();

        tasks.spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut byte_buf = Vec::new();
            let max_frame = state_clone.max_body * 6 + 4096;
            let mut attested_agy_peer: Option<(String, u32, String)> = None;
            let mut last_pushed_escrow = crate::agy::AgyEscrowState::Empty;
            let mut escrow_rx = crate::agy::subscribe_agy_escrow();

            loop {
                if let Some((ref session_key, reg_pid, ref reg_starttime)) = attested_agy_peer {
                    if !peer.is_alive(&state_clone.agy_config.proc_root, &initial_starttime)
                        || crate::process::starttime(&state_clone.agy_config.proc_root, reg_pid)
                            .ok()
                            .as_deref()
                            != Some(reg_starttime.as_str())
                    {
                        break;
                    }
                    let desired = crate::agy::current_agy_escrow_state(
                        &state_clone.agy_store,
                        session_key,
                        reg_pid,
                        reg_starttime,
                    );
                    if desired != last_pushed_escrow {
                        let ev = match &desired {
                            crate::agy::AgyEscrowState::Active {
                                ls_address,
                                csrf_token,
                                label,
                                registered_at,
                            } => Some(serde_json::json!({
                                "event": "agy_escrow",
                                "ls_address": ls_address,
                                "csrf_token": csrf_token,
                                "label": label,
                                "registered_at": registered_at,
                            })),
                            crate::agy::AgyEscrowState::Stale => Some(serde_json::json!({
                                "event": "agy_escrow_clear",
                            })),
                            crate::agy::AgyEscrowState::Empty => {
                                if last_pushed_escrow != crate::agy::AgyEscrowState::Empty {
                                    Some(serde_json::json!({
                                        "event": "agy_escrow_clear",
                                    }))
                                } else {
                                    None
                                }
                            }
                        };
                        if let Some(ev) = ev {
                            if writer
                                .write_all(format!("{ev}\n").as_bytes())
                                .await
                                .is_err()
                                || writer.flush().await.is_err()
                            {
                                break;
                            }
                        }
                        last_pushed_escrow = desired;
                    }
                }

                let n = if attested_agy_peer.is_some() {
                    let mut limited = (&mut buf_reader).take((max_frame + 1) as u64);
                    tokio::select! {
                        res = limited.read_until(b'\n', &mut byte_buf) => res.unwrap_or(0),
                        _ = escrow_rx.changed() => {
                            continue;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                            continue;
                        }
                    }
                } else {
                    (&mut buf_reader)
                        .take((max_frame + 1) as u64)
                        .read_until(b'\n', &mut byte_buf)
                        .await
                        .unwrap_or(0)
                };
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
                    Ok(s) => s.to_string(),
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
                byte_buf.clear();

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

                #[cfg(target_os = "linux")]
                if let AgentFrame::CodexHook {
                    event,
                    label,
                    payload,
                    ..
                } = frame
                {
                    match handle_codex_hook_frame(
                        &state_clone,
                        &peer,
                        &event,
                        label.as_deref(),
                        &payload,
                    )
                    .await
                    {
                        Ok(outcome) => {
                            let has_handoff = !outcome.handoff_ids.is_empty();
                            let resp_json = serde_json::json!({
                                "status": "ok",
                                "stdout": outcome.stdout,
                                "handoff_ids": outcome.handoff_ids,
                            });
                            let write_res = writer
                                .write_all(format!("{resp_json}\n").as_bytes())
                                .await;
                            let flush_res = writer.flush().await;
                            if has_handoff {
                                if write_res.is_err() || flush_res.is_err() {
                                    if let Ok(db) = state_clone.db.lock() {
                                        let _ = crate::storage::release_codex_handoff_to_pending(
                                            &db,
                                            &outcome.handoff_ids,
                                        );
                                    }
                                    break;
                                }
                                let mut ack_buf = Vec::new();
                                let mut limited = (&mut buf_reader).take(4096);
                                let ack_read = tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    limited.read_until(b'\n', &mut ack_buf),
                                )
                                .await;
                                let ack_action = match ack_read {
                                    Ok(Ok(n)) if n > 0 => std::str::from_utf8(&ack_buf)
                                        .ok()
                                        .and_then(|s| {
                                            serde_json::from_str::<serde_json::Value>(s.trim()).ok()
                                        })
                                        .and_then(|v| {
                                            v.get("ack")
                                                .and_then(serde_json::Value::as_str)
                                                .map(str::to_string)
                                        }),
                                    _ => None,
                                };
                                match ack_action.as_deref() {
                                    Some("accepted") => {
                                        if let Ok(db) = state_clone.db.lock() {
                                            let _ =
                                                crate::storage::complete_codex_handoff_accepted(
                                                    &db,
                                                    &outcome.root_id,
                                                    &outcome.handoff_ids,
                                                );
                                        }
                                        let ok_line = serde_json::json!({ "status": "ok" });
                                        let _ = writer
                                            .write_all(format!("{ok_line}\n").as_bytes())
                                            .await;
                                        let _ = writer.flush().await;
                                    }
                                    Some("abort") => {
                                        if let Ok(db) = state_clone.db.lock() {
                                            let _ =
                                                crate::storage::release_codex_handoff_to_pending(
                                                    &db,
                                                    &outcome.handoff_ids,
                                                );
                                        }
                                        let ok_line = serde_json::json!({ "status": "ok" });
                                        let _ = writer
                                            .write_all(format!("{ok_line}\n").as_bytes())
                                            .await;
                                        let _ = writer.flush().await;
                                    }
                                    _ => {
                                        if let Ok(db) = state_clone.db.lock() {
                                            let _ = crate::storage::mark_codex_handoff_unknown(
                                                &db,
                                                &outcome.handoff_ids,
                                            );
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let err = e.frame();
                            let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
                            let _ = writer.flush().await;
                        }
                    }
                    continue;
                }
                #[cfg(not(target_os = "linux"))]
                if matches!(frame, AgentFrame::CodexHook { .. }) {
                    // INTERIM (HA9-A.codex.darwin): codex support on Darwin is pending.
                    let err = AppError::BadRequest(
                        "codex support on Darwin is pending".to_string(),
                    )
                    .frame();
                    let _ = writer.write_all(format!("{err}\n").as_bytes()).await;
                    let _ = writer.flush().await;
                    continue;
                }

                let _ = crate::claim::sync_claims(
                    &state_clone.db,
                    &state_clone.agy_config.proc_root,
                    &state_clone.sessions_dirs,
                    &state_clone.node_name,
                )
                .await;
                let caller_trace = trace_caller_or_codex_owner(&state_clone, &peer);

                let resp: Result<serde_json::Value, AppError> = match frame {
                    AgentFrame::CodexHook { .. } => unreachable!(),
                    AgentFrame::McpStart {
                        ls_address,
                        csrf_token,
                        label,
                        registered_at,
                        ..
                    } => {
                        let has_escrow_fields = ls_address.is_some()
                            || csrf_token.is_some()
                            || label.is_some()
                            || registered_at.is_some();
                        match crate::agy::attest_mcp_caller_peer(
                            &state_clone.agy_config.proc_root,
                            &state_clone.agy_config.proc_locks_path,
                            &state_clone.agy_config.presence_dir,
                            &state_clone.agy_config.trusted_agy_exes,
                            my_uid,
                            &peer,
                        ) {
                            Ok((reg, conv_id)) => {
                                let escrow_creds = match (ls_address, csrf_token) {
                                    (Some(ls), Some(csrf)) => {
                                        if ls.trim().is_empty()
                                            || csrf.trim().is_empty()
                                            || ls.contains('\0')
                                            || csrf.contains('\0')
                                        {
                                            let err = AppError::BadRequest(
                                                "ls_address and csrf_token in mcp_start must be non-empty"
                                                    .to_string(),
                                            )
                                            .frame();
                                            let _ = writer
                                                .write_all(format!("{err}\n").as_bytes())
                                                .await;
                                            continue;
                                        }
                                        Some(crate::agy::AgyCredentials {
                                            ls_address: ls,
                                            csrf_token: csrf,
                                            is_stale: false,
                                        })
                                    }
                                    (None, None) => None,
                                    _ => {
                                        let err = AppError::BadRequest(
                                            "mcp_start credential escrow requires both ls_address and csrf_token"
                                                .to_string(),
                                        )
                                        .frame();
                                        let _ = writer
                                            .write_all(format!("{err}\n").as_bytes())
                                            .await;
                                        continue;
                                    }
                                };
                                let cleaned_escrow_label = label
                                    .as_deref()
                                    .and_then(crate::inbox::clean_label);
                                let session_key = conv_id.clone();
                                let mut restored_creds = false;
                                {
                                    let mut store_lock = state_clone.agy_store.write().unwrap();
                                    store_lock
                                        .entry(session_key.clone())
                                        .and_modify(|current| {
                                            if current.pid != reg.pid
                                                || current.starttime != reg.starttime
                                            {
                                                let prev_label = current.label.clone();
                                                restored_creds = escrow_creds.is_some();
                                                let mut info = crate::agy::AgySessionInfo::new(
                                                    conv_id.clone(),
                                                    reg.pid,
                                                    reg.starttime.clone(),
                                                    escrow_creds.clone(),
                                                );
                                                if let Some(ref lbl) = cleaned_escrow_label {
                                                    info.label = Some(lbl.clone());
                                                } else if prev_label.is_some() {
                                                    info.label = prev_label;
                                                }
                                                if let Some(reg_at) =
                                                    registered_at.filter(|&t| t > 0)
                                                {
                                                    info.registered_at = reg_at;
                                                }
                                                *current = info;
                                            } else {
                                                if current.credentials.is_none()
                                                    && escrow_creds.is_some()
                                                {
                                                    current.credentials = escrow_creds.clone();
                                                    restored_creds = true;
                                                }
                                                if let Some(ref lbl) = cleaned_escrow_label {
                                                    if lbl != "agy"
                                                        || current.label.is_none()
                                                        || current.label.as_deref() == Some("agy")
                                                    {
                                                        current.label = Some(lbl.clone());
                                                    }
                                                }
                                                if let Some(reg_at) =
                                                    registered_at.filter(|&t| t > 0)
                                                {
                                                    if current.registered_at == 0
                                                        || reg_at < current.registered_at
                                                    {
                                                        current.registered_at = reg_at;
                                                    }
                                                }
                                            }
                                        })
                                        .or_insert_with(|| {
                                            restored_creds = escrow_creds.is_some();
                                            let mut info = crate::agy::AgySessionInfo::new(
                                                conv_id.clone(),
                                                reg.pid,
                                                reg.starttime.clone(),
                                                escrow_creds,
                                            );
                                            if let Some(lbl) = cleaned_escrow_label {
                                                info.label = Some(lbl);
                                            }
                                            if let Some(reg_at) = registered_at.filter(|&t| t > 0) {
                                                info.registered_at = reg_at;
                                            }
                                            info
                                        });
                                }
                                crate::agy::notify_agy_escrow();
                                if let Ok(db) = state_clone.db.lock() {
                                    let now = crate::storage::now_epoch_secs();
                                    let _ = crate::storage::mark_live(
                                        &db,
                                        &session_key,
                                        "agy",
                                        now,
                                    );
                                    let _ = crate::agy::rescan_agy_subagents(
                                        &db,
                                        &state_clone.agy_config.effective_brain_dir(),
                                        &session_key,
                                        now,
                                    );
                                    let _ = crate::agy::sweep_agy_subagent_queues(
                                        &db,
                                        &state_clone.agy_config.proc_root,
                                        &state_clone.agy_store,
                                    );
                                }
                                let _ = crate::claim::sync_claims(
                                    &state_clone.db,
                                    &state_clone.agy_config.proc_root,
                                    &state_clone.sessions_dirs,
                                    &state_clone.node_name,
                                )
                                .await;
                                attested_agy_peer = Some((
                                    session_key.clone(),
                                    reg.pid,
                                    reg.starttime.clone(),
                                ));
                                let resp = serde_json::json!({
                                    "status": "ok",
                                    "sessionId": session_key,
                                    "address": session_key,
                                });
                                let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                                let _ = writer.flush().await;
                                let has_creds = restored_creds
                                    || state_clone
                                        .agy_store
                                        .read()
                                        .unwrap()
                                        .get(&session_key)
                                        .and_then(|info| info.credentials.as_ref())
                                        .is_some_and(|c| !c.is_stale);
                                if has_creds {
                                    crate::agy::flush_agy_queue(
                                        &state_clone.agy_config,
                                        &state_clone.agy_store,
                                        &state_clone.db,
                                        &session_key,
                                        &conv_id,
                                        state_clone.reply_ttl,
                                    )
                                    .await;
                                }
                            }
                            Err(e) => {
                                if has_escrow_fields {
                                    let err_resp = serde_json::json!({
                                        "status": "error",
                                        "error": "unattested",
                                        "detail": format!("agy credential escrow rejected for non-agy caller: {e}"),
                                    });
                                    let _ = writer
                                        .write_all(format!("{err_resp}\n").as_bytes())
                                        .await;
                                    continue;
                                }
                                // Check Claude Code sessions via claim table (stopping if caller is a Codex process)
                                let claude_res = if matches!(caller_trace, Ok(CallerTrace::CodexOwner { .. })) {
                                    None
                                } else {
                                    crate::claim::sync_claims(
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
                                    })
                                };

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
                                    let _ = writer
                                        .write_all(format!("{err_resp}\n").as_bytes())
                                        .await;
                                }
                            }
                        }
                        continue;
                    }
                    other_frame => handle_agent_frame(&state_clone, &peer, other_frame).await,
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

/// Evaluates a non-`McpStart`/`CodexHook` `AgentFrame` on `agent.sock`.
pub async fn handle_agent_frame(
    state: &Arc<AppState>,
    peer: &crate::process::PeerCred,
    frame: AgentFrame,
) -> Result<serde_json::Value, AppError> {
    let _ = crate::claim::sync_claims(
        &state.db,
        &state.agy_config.proc_root,
        &state.sessions_dirs,
        &state.node_name,
    )
    .await;
    let caller_trace = trace_caller_or_codex_owner(state, peer);
    match frame {
        AgentFrame::McpStart { .. } | AgentFrame::CodexHook { .. } => Err(AppError::BadRequest(
            "mcp_start and codex_hook are handled at stream level".to_string(),
        )),
        AgentFrame::List {
            name,
            node,
            kind,
            status,
            within,
            codex_session,
            codex_thread,
            codex_turn,
            ..
        } => {
            let codex_check = match &caller_trace {
                Ok(CallerTrace::CodexOwner {
                    owner_pid,
                    owner_starttime,
                }) => resolve_codex_mcp_caller(
                    state,
                    *owner_pid,
                    owner_starttime,
                    codex_session.as_deref(),
                    codex_thread.as_deref(),
                    codex_turn.as_deref(),
                    false,
                )
                .map(|_| ()),
                _ if codex_session.is_some() || codex_thread.is_some() => {
                    Err(AppError::NotRecipient(
                        "codex runtime metadata rejected: caller does not descend from a trusted --codex-exe process"
                            .to_string(),
                    ))
                }
                _ => Ok(()),
            };
            match codex_check {
                Ok(()) => {
                    let query = surface::ListQuery {
                        name,
                        node,
                        kind,
                        status,
                        within,
                        host: None,
                    };
                    surface::list(state, &query).await.map(|r| {
                        serde_json::json!({ "status": "ok", "recipients": r.recipients, "nodes": r.nodes })
                    })
                }
                Err(e) => Err(e),
            }
        }
        AgentFrame::Send {
            to,
            text,
            idempotency_key,
            as_agent,
            codex_session,
            codex_thread,
            codex_turn,
            ..
        } => {
            let effective_res = match caller_trace {
                Ok(CallerTrace::CodexOwner {
                    owner_pid,
                    ref owner_starttime,
                }) => resolve_codex_mcp_caller(
                    state,
                    owner_pid,
                    owner_starttime,
                    codex_session.as_deref(),
                    codex_thread.as_deref(),
                    codex_turn.as_deref(),
                    false,
                ),
                _ if codex_session.is_some() || codex_thread.is_some() => {
                    Err(AppError::NotRecipient(
                        "codex runtime metadata rejected: caller does not descend from a trusted --codex-exe process"
                            .to_string(),
                    ))
                }
                Ok(CallerTrace::Session(parent)) => {
                    resolve_as_agent(state, parent, as_agent.as_deref(), false)
                }
                Err(e) => Err(e),
            };
            match effective_res {
                Ok(effective_caller) => {
                    let sender = surface::Sender::Session(effective_caller);
                    surface::send(state, &sender, &to, &text, idempotency_key.as_deref())
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
                Err(e) => Err(e),
            }
        }
        AgentFrame::Reply {
            message_id,
            text,
            idempotency_key,
            as_agent,
            codex_session,
            codex_thread,
            codex_turn,
            ..
        } => {
            let effective_res = match caller_trace {
                Ok(CallerTrace::CodexOwner {
                    owner_pid,
                    ref owner_starttime,
                }) => resolve_codex_mcp_caller(
                    state,
                    owner_pid,
                    owner_starttime,
                    codex_session.as_deref(),
                    codex_thread.as_deref(),
                    codex_turn.as_deref(),
                    false,
                ),
                _ if codex_session.is_some() || codex_thread.is_some() => {
                    Err(AppError::NotRecipient(
                        "codex runtime metadata rejected: caller does not descend from a trusted --codex-exe process"
                            .to_string(),
                    ))
                }
                Ok(CallerTrace::Session(parent)) => {
                    resolve_as_agent(state, parent, as_agent.as_deref(), false)
                }
                Err(e) => Err(e),
            };
            match effective_res {
                Ok(effective_caller) => surface::reply(
                    state,
                    &effective_caller,
                    &message_id,
                    &text,
                    idempotency_key.as_deref(),
                )
                .await
                .map(|r| serde_json::json!({ "status": "ok", "reply": r })),
                Err(e) => Err(e),
            }
        }
        AgentFrame::Replies {
            message_id,
            wait,
            after,
            codex_session,
            codex_thread,
            codex_turn,
            ..
        } => {
            let codex_check = match &caller_trace {
                Ok(CallerTrace::CodexOwner {
                    owner_pid,
                    owner_starttime,
                }) => resolve_codex_mcp_caller(
                    state,
                    *owner_pid,
                    owner_starttime,
                    codex_session.as_deref(),
                    codex_thread.as_deref(),
                    codex_turn.as_deref(),
                    false,
                )
                .map(|_| ()),
                _ if codex_session.is_some() || codex_thread.is_some() => {
                    Err(AppError::NotRecipient(
                        "codex runtime metadata rejected: caller does not descend from a trusted --codex-exe process"
                            .to_string(),
                    ))
                }
                _ => Ok(()),
            };
            match codex_check {
                Ok(()) => {
                    surface::replies(state, &message_id, after.unwrap_or(0), wait.unwrap_or(0))
                        .await
                        .map(|r| serde_json::json!({ "status": "ok", "replies": r }))
                }
                Err(e) => Err(e),
            }
        }
        AgentFrame::Inbox {
            wait,
            as_agent,
            codex_session,
            codex_thread,
            codex_turn,
            ..
        } => {
            let effective_res = match caller_trace {
                Ok(CallerTrace::CodexOwner {
                    owner_pid,
                    ref owner_starttime,
                }) => resolve_codex_mcp_caller(
                    state,
                    owner_pid,
                    owner_starttime,
                    codex_session.as_deref(),
                    codex_thread.as_deref(),
                    codex_turn.as_deref(),
                    true,
                ),
                _ if codex_session.is_some() || codex_thread.is_some() => {
                    Err(AppError::NotRecipient(
                        "codex runtime metadata rejected: caller does not descend from a trusted --codex-exe process"
                            .to_string(),
                    ))
                }
                Ok(CallerTrace::Session(parent)) => {
                    resolve_as_agent(state, parent, as_agent.as_deref(), true)
                }
                Err(e) => Err(e),
            };
            match effective_res {
                Ok(effective_caller) => surface::inbox(state, &effective_caller, wait.unwrap_or(0))
                    .await
                    .map(|r| {
                        serde_json::json!({
                            "status": "ok",
                            "address": r.address,
                            "messages": r.messages,
                        })
                    }),
                Err(e) => Err(e),
            }
        }
        AgentFrame::Subagent {
            event,
            agent_id,
            name,
            agent_type,
            tool_use_id,
            transcript_path,
            to,
            pin_name,
            ..
        } => match caller_trace {
            Ok(CallerTrace::Session(parent)) => {
                handle_subagent_frame(
                    state,
                    &parent,
                    &event,
                    &agent_id,
                    name.as_deref(),
                    agent_type.as_deref(),
                    tool_use_id.as_deref(),
                    transcript_path.as_deref(),
                    to.as_deref(),
                    pin_name.as_deref(),
                )
                .await
            }
            Ok(CallerTrace::CodexOwner { .. }) => Err(AppError::BadRequest(
                "subagent frame on agent.sock is only valid for Claude or agy sessions".to_string(),
            )),
            Err(e) => Err(e),
        },
    }
}

/// Resolves `as_agent` against `parent` in `subagents` (HA9-A §2.3 step 3, E1, E2, D1, D5, D6).
/// When `as_agent` is absent, empty, or equal to `parent.session_id` (D6), acts as `parent`
/// unless `require_subagent` is true (`inbox` requires a non-empty bound child `as_agent`).
pub fn resolve_as_agent(
    state: &AppState,
    parent: Session,
    as_agent: Option<&str>,
    require_subagent: bool,
) -> Result<Session, AppError> {
    let agent_id = as_agent.map(str::trim).unwrap_or("");
    if agent_id.is_empty() || agent_id == parent.session_id {
        if require_subagent {
            return Err(AppError::NotRecipient(format!(
                "'{}' is a parent session and receives messages on its channel; 'inbox' is only for subagents",
                parent.session_id
            )));
        }
        return Ok(parent);
    }
    let db = state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let maybe_binding = match crate::storage::get_subagent(&db, &parent.session_id, agent_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
    {
        Some(b) => Some(b),
        None if parent.harness == "agy" => crate::agy::admit_agy(
            &db,
            &state.agy_config.effective_brain_dir(),
            &parent.session_id,
            agent_id,
            crate::storage::now_epoch_secs(),
        )?,
        None => None,
    };
    let binding = maybe_binding.ok_or_else(|| {
        AppError::NotRecipient(format!(
            "subagent '{agent_id}' is not bound under '{}'",
            parent.session_id
        ))
    })?;
    Ok(Session {
        session_id: format!("{}/{}", binding.parent, binding.agent_id),
        name: binding.display_label().map(str::to_string),
        pid: binding.turn_pid.unwrap_or(parent.pid),
        cwd: parent.cwd,
        status: parent.status,
        kind: "subagent".to_string(),
        entrypoint: parent.entrypoint,
        version: parent.version,
        started_at: binding.bound_at as u64,
        updated_at: binding.bound_at as u64,
        harness: parent.harness,
        registered: parent.registered,
    })
}

/// Maximum byte size of a subagent `meta.json` file read from disk (XB2 F2).
const MAX_META_JSON_BYTES: u64 = 65_536;

/// Reads optional `("name", "agentType")` from the subagent `meta.json` beside `transcript_path`
/// (HA9-A §2.5, O12; XB2 F2).
///
/// Confines `transcript_path` and `agent_id` to the expected session directory (absolute path,
/// no `..`, not in `/dev`/`/proc`/`/sys`/`/etc`, valid `agent_id`), and reads only a regular
/// file via `symlink_metadata` with a size cap (`MAX_META_JSON_BYTES`).
pub fn read_meta_json_fields(
    transcript_path: &str,
    agent_id: &str,
) -> (Option<String>, Option<String>) {
    use std::path::Component;
    let Ok(agent_id) = crate::claim::validate_subagent_id(agent_id) else {
        return (None, None);
    };
    if agent_id.contains("..") {
        return (None, None);
    }
    let tp_path = Path::new(transcript_path);
    if !tp_path.is_absolute()
        || tp_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return (None, None);
    }
    let Some(expected_session_dir) = tp_path.parent() else {
        return (None, None);
    };
    if expected_session_dir == Path::new("/") {
        return (None, None);
    }
    for blocked in ["/dev", "/proc", "/sys", "/etc", "/private/etc"] {
        if tp_path.starts_with(blocked) {
            return (None, None);
        }
    }
    let canon_session_dir = fs::canonicalize(expected_session_dir).ok();
    if let Some(ref canon_dir) = canon_session_dir {
        if canon_dir == Path::new("/") {
            return (None, None);
        }
        for blocked in ["/dev", "/proc", "/sys", "/etc", "/private/etc"] {
            if canon_dir.starts_with(blocked) {
                return (None, None);
            }
        }
    }

    let mut candidates = Vec::new();
    let stem = transcript_path
        .strip_suffix(".jsonl")
        .unwrap_or(transcript_path);
    candidates.push(
        PathBuf::from(stem)
            .join("subagents")
            .join(format!("agent-{agent_id}.meta.json")),
    );
    candidates.push(PathBuf::from(format!("{stem}.meta.json")));
    candidates.push(
        expected_session_dir
            .join("subagents")
            .join(format!("agent-{agent_id}.meta.json")),
    );
    candidates.push(expected_session_dir.join(format!("agent-{agent_id}.meta.json")));
    candidates.push(expected_session_dir.join("meta.json"));

    for path in candidates {
        if !path.starts_with(expected_session_dir)
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let ft = meta.file_type();
        if ft.is_symlink() || !ft.is_file() || meta.len() > MAX_META_JSON_BYTES {
            continue;
        }
        if let Some(ref canon_dir) = canon_session_dir {
            let Ok(canon_path) = fs::canonicalize(&path) else {
                continue;
            };
            if !canon_path.starts_with(canon_dir) {
                continue;
            }
        }
        let Ok(file) = fs::File::open(&path) else {
            continue;
        };
        let mut raw = String::new();
        use std::io::Read;
        if file
            .take(MAX_META_JSON_BYTES + 1)
            .read_to_string(&mut raw)
            .is_err()
            || raw.len() as u64 > MAX_META_JSON_BYTES
        {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            let name = val
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let agent_type = val
                .get("agentType")
                .or_else(|| val.get("agent_type"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            return (name, agent_type);
        }
    }
    (None, None)
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_subagent_frame(
    state: &AppState,
    parent: &Session,
    event: &str,
    agent_id: &str,
    name: Option<&str>,
    agent_type: Option<&str>,
    tool_use_id: Option<&str>,
    transcript_path: Option<&str>,
    to: Option<&str>,
    pin_name: Option<&str>,
) -> Result<serde_json::Value, AppError> {
    if parent.harness != "claude" && parent.harness != "agy" {
        return Err(AppError::BadRequest(
            "subagent frame on agent.sock is only valid for Claude or agy sessions".to_string(),
        ));
    }
    let agent_id = crate::claim::validate_subagent_id(agent_id)?;
    let now = crate::storage::now_epoch_secs();
    if parent.harness == "agy" {
        return match event {
            "start" | "SubagentStart" | "subagent_start" => {
                if agent_id == parent.session_id {
                    return Ok(serde_json::json!({
                        "status": "ok",
                        "role": "parent",
                    }));
                }
                let (turn_pid, turn_start) = {
                    let store_lock = state.agy_store.read().unwrap();
                    store_lock
                        .values()
                        .find(|info| {
                            info.session_key == parent.session_id
                                || info.conversation_id == parent.session_id
                        })
                        .map(|info| (info.pid, info.starttime.clone()))
                        .ok_or_else(|| {
                            AppError::NotRecipient(format!(
                                "parent agy session '{}' is not registered",
                                parent.session_id
                            ))
                        })?
                };
                let binding = {
                    let db = state
                        .db
                        .lock()
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    let b = crate::agy::admit_agy(
                        &db,
                        &state.agy_config.effective_brain_dir(),
                        &parent.session_id,
                        agent_id,
                        now,
                    )?
                    .ok_or_else(|| {
                        AppError::NotRecipient(format!(
                            "subagent '{agent_id}' is not bound under '{}'",
                            parent.session_id
                        ))
                    })?;
                    crate::storage::subagent_set_turn(
                        &db,
                        &parent.session_id,
                        agent_id,
                        turn_pid,
                        &turn_start,
                    )
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                    b
                };
                let child_part = binding.name.as_deref().unwrap_or(&binding.agent_id);
                let addr = format!("{}/{child_part}@{}", binding.parent, state.node_name);
                Ok(serde_json::json!({
                    "status": "ok",
                    "role": "subagent",
                    "address": addr,
                }))
            }
            "stop" | "SubagentStop" | "subagent_stop" => {
                if agent_id == parent.session_id {
                    return Ok(serde_json::json!({
                        "status": "ok",
                        "role": "parent",
                    }));
                }
                {
                    let db = state
                        .db
                        .lock()
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    crate::storage::subagent_stop_turn(&db, &parent.session_id, agent_id)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    let _ = crate::agy::sweep_agy_subagent_queues(
                        &db,
                        &state.agy_config.proc_root,
                        &state.agy_store,
                    );
                }
                let has_creds = state.agy_store.read().unwrap().values().any(|info| {
                    (info.session_key == parent.session_id
                        || info.conversation_id == parent.session_id)
                        && info.credentials.as_ref().is_some_and(|c| !c.is_stale)
                });
                if has_creds {
                    crate::agy::flush_agy_queue(
                        &state.agy_config,
                        &state.agy_store,
                        &state.db,
                        &parent.session_id,
                        &parent.session_id,
                        state.reply_ttl,
                    )
                    .await;
                }
                Ok(serde_json::json!({ "status": "ok" }))
            }
            other => Err(AppError::BadRequest(format!(
                "unknown agy subagent event '{other}'"
            ))),
        };
    }
    match event {
        "start" | "SubagentStart" | "subagent_start" => {
            if agent_id == parent.session_id {
                return Ok(serde_json::json!({
                    "status": "ok",
                    "role": "parent",
                }));
            }
            let turn_start =
                process::starttime(&state.agy_config.proc_root, parent.pid).map_err(|e| {
                    AppError::Internal(format!(
                        "failed to read starttime for parent PID {}: {e}",
                        parent.pid
                    ))
                })?;
            let (meta_name, meta_type) = match transcript_path {
                Some(tp) if !tp.is_empty() => read_meta_json_fields(tp, agent_id),
                _ => (None, None),
            };
            let candidate_name = name.or(meta_name.as_deref());
            let valid_name =
                candidate_name.filter(|n| crate::claim::validate_subagent_name(n).is_ok());
            let effective_type = agent_type
                .filter(|s| !s.is_empty())
                .or(meta_type.as_deref().filter(|s| !s.is_empty()));
            let child_part = {
                let db = state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                crate::storage::subagent_start_turn(
                    &db,
                    &parent.session_id,
                    agent_id,
                    parent.pid,
                    &turn_start,
                    valid_name,
                    effective_type,
                    tool_use_id,
                    now,
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;
                crate::storage::get_subagent(&db, &parent.session_id, agent_id)
                    .ok()
                    .flatten()
                    .and_then(|b| b.name)
                    .unwrap_or_else(|| agent_id.to_string())
            };
            let addr = format!("{}/{child_part}@{}", parent.session_id, state.node_name);
            Ok(serde_json::json!({
                "status": "ok",
                "role": "subagent",
                "address": addr,
            }))
        }
        "bind_spawn" | "post_agent" | "spawn" => {
            let valid_name = name.filter(|n| crate::claim::validate_subagent_name(n).is_ok());
            {
                let db = state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                crate::storage::subagent_bind_spawn(
                    &db,
                    &parent.session_id,
                    agent_id,
                    valid_name,
                    tool_use_id,
                    now,
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;
            }
            Ok(serde_json::json!({ "status": "ok" }))
        }
        "reassert_resume" | "post_send_message" | "resume" => {
            let candidate_name = if let Some(t) = to.filter(|t| !t.is_empty()) {
                if !crate::claim::is_subagent_id_shaped(t) {
                    Some(t)
                } else {
                    pin_name.filter(|p| {
                        !p.is_empty() && *p != agent_id && !crate::claim::is_subagent_id_shaped(p)
                    })
                }
            } else if let Some(p) = pin_name.filter(|p| !p.is_empty()) {
                if p != agent_id && !crate::claim::is_subagent_id_shaped(p) {
                    Some(p)
                } else {
                    None
                }
            } else {
                name.filter(|n| {
                    !n.is_empty() && *n != agent_id && !crate::claim::is_subagent_id_shaped(n)
                })
            };
            let valid_name =
                candidate_name.filter(|n| crate::claim::validate_subagent_name(n).is_ok());
            {
                let db = state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                crate::storage::subagent_reassert_resume(
                    &db,
                    &parent.session_id,
                    agent_id,
                    valid_name,
                    now,
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;
            }
            Ok(serde_json::json!({ "status": "ok" }))
        }
        "stop" | "SubagentStop" | "subagent_stop" => {
            {
                let db = state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                crate::storage::subagent_stop_turn(&db, &parent.session_id, agent_id)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
            }
            // Sweep any messages queued during the turn back to P's socket (HA9-A §2.4, O5).
            let _ = crate::claim::sync_claims(
                &state.db,
                &state.agy_config.proc_root,
                &state.sessions_dirs,
                &state.node_name,
            )
            .await;
            Ok(serde_json::json!({ "status": "ok" }))
        }
        other => Err(AppError::BadRequest(format!(
            "unknown subagent event '{other}'"
        ))),
    }
}

/// Runs `xmsg register claude --hook`: processes a Claude Code hook JSON payload from
/// `input` (`PreToolUse`, `SubagentStart`, `PostToolUse`, `SubagentStop`).
/// Returns `Ok(stdout_json)` on success, or `Err(reason)` on any failure (caller exits 2 per E6).
pub fn run_claude_hook(input: &str, agent_sock: Option<&Path>) -> Result<String, String> {
    use serde_json::Value;
    let val: Value =
        serde_json::from_str(input).map_err(|e| format!("malformed hook JSON on stdin: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "hook stdin JSON must be an object".to_string())?;
    let event_name = obj
        .get("hook_event_name")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing string 'hook_event_name' in hook JSON".to_string())?;

    let resolve_sock = || -> Result<PathBuf, String> {
        match agent_sock {
            Some(p) => Ok(p.to_path_buf()),
            None => default_agent_sock_path().map_err(|e| e.to_string()),
        }
    };

    let send_lifecycle_frame = |frame: &Value| {
        if let Err(e) = resolve_sock().and_then(|sock| crate::mcp::call_agent_sock(&sock, frame)) {
            eprintln!("xmsg: {e}");
        }
    };

    match event_name {
        "PreToolUse" => {
            // E6: PreToolUse does no socket I/O; it only reads stdin and writes stdout.
            let tool_input = obj
                .get("tool_input")
                .and_then(Value::as_object)
                .ok_or_else(|| "PreToolUse hook input missing 'tool_input' object".to_string())?;
            let agent_id = match obj.get("agent_id") {
                None | Some(Value::Null) => "",
                Some(Value::String(s)) => s.trim(),
                Some(_) => {
                    return Err("'agent_id' in PreToolUse hook input must be a string".to_string())
                }
            };
            if !agent_id.is_empty() {
                let mut updated_input = tool_input.clone();
                updated_input.insert("as_agent".to_string(), Value::String(agent_id.to_string()));
                let out = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "updatedInput": updated_input,
                    }
                });
                Ok(out.to_string())
            } else if tool_input.contains_key("as_agent") {
                let mut updated_input = tool_input.clone();
                updated_input.remove("as_agent");
                let out = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "updatedInput": updated_input,
                    }
                });
                Ok(out.to_string())
            } else {
                let out = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                    }
                });
                Ok(out.to_string())
            }
        }
        "SubagentStart" => {
            let agent_id = obj
                .get("agent_id")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| {
                    "SubagentStart hook input missing non-empty 'agent_id'".to_string()
                })?;
            let mut frame = serde_json::json!({
                "action": "subagent",
                "schema_version": surface::MCP_SCHEMA_VERSION,
                "event": "start",
                "agent_id": agent_id,
            });
            if let Some(at) = obj.get("agent_type").and_then(Value::as_str) {
                frame["agent_type"] = Value::String(at.to_string());
            }
            if let Some(tp) = obj
                .get("transcript_path")
                .or_else(|| obj.get("agent_transcript_path"))
                .and_then(Value::as_str)
            {
                frame["transcript_path"] = Value::String(tp.to_string());
            }
            send_lifecycle_frame(&frame);
            Ok("{}".to_string())
        }
        "PostToolUse" => {
            let tool_name = obj
                .get("tool_name")
                .and_then(Value::as_str)
                .ok_or_else(|| "PostToolUse hook input missing 'tool_name'".to_string())?;
            match tool_name {
                "Agent" => {
                    let tool_resp = obj
                        .get("tool_response")
                        .and_then(Value::as_object)
                        .ok_or_else(|| {
                            "PostToolUse(Agent) missing 'tool_response' object".to_string()
                        })?;
                    let agent_id = tool_resp
                        .get("agentId")
                        .or_else(|| tool_resp.get("teammate_id"))
                        .or_else(|| tool_resp.get("agent_id"))
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty());
                    if let Some(agent_id) = agent_id {
                        let name = obj
                            .get("tool_input")
                            .and_then(|ti| ti.get("name"))
                            .and_then(Value::as_str)
                            .or_else(|| tool_resp.get("name").and_then(Value::as_str));
                        let tool_use_id = obj.get("tool_use_id").and_then(Value::as_str);
                        let mut frame = serde_json::json!({
                            "action": "subagent",
                            "schema_version": surface::MCP_SCHEMA_VERSION,
                            "event": "bind_spawn",
                            "agent_id": agent_id,
                        });
                        if let Some(n) = name {
                            frame["name"] = Value::String(n.to_string());
                        }
                        if let Some(tu) = tool_use_id {
                            frame["tool_use_id"] = Value::String(tu.to_string());
                        }
                        send_lifecycle_frame(&frame);
                    }
                    Ok("{}".to_string())
                }
                "SendMessage" => {
                    if let Some(tool_resp) = obj.get("tool_response").and_then(Value::as_object) {
                        if let Some(resumed_id) = tool_resp
                            .get("resumedAgentId")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                        {
                            let to = obj
                                .get("tool_input")
                                .and_then(|ti| ti.get("to"))
                                .and_then(Value::as_str);
                            let pin_name = tool_resp
                                .get("pin")
                                .and_then(|p| p.get("name"))
                                .and_then(Value::as_str);
                            let mut frame = serde_json::json!({
                                "action": "subagent",
                                "schema_version": surface::MCP_SCHEMA_VERSION,
                                "event": "reassert_resume",
                                "agent_id": resumed_id,
                            });
                            if let Some(t) = to {
                                frame["to"] = Value::String(t.to_string());
                            }
                            if let Some(pn) = pin_name {
                                frame["pin_name"] = Value::String(pn.to_string());
                            }
                            send_lifecycle_frame(&frame);
                        }
                    }
                    Ok("{}".to_string())
                }
                _ => Ok("{}".to_string()),
            }
        }
        "SubagentStop" => {
            let agent_id = obj
                .get("agent_id")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| {
                    "SubagentStop hook input missing non-empty 'agent_id'".to_string()
                })?;
            let frame = serde_json::json!({
                "action": "subagent",
                "schema_version": surface::MCP_SCHEMA_VERSION,
                "event": "stop",
                "agent_id": agent_id,
            });
            send_lifecycle_frame(&frame);
            Ok("{}".to_string())
        }
        other => Err(format!("unsupported hook_event_name '{other}'")),
    }
}

/// Resolves a Codex MCP caller under trusted owner `(owner_pid, owner_starttime)` using
/// `params._meta` (`codex_session`, `codex_thread`, `codex_turn`) (HA9-A.codex §2.2).
#[cfg(target_os = "linux")]
pub fn resolve_codex_mcp_caller(
    state: &AppState,
    owner_pid: u32,
    owner_starttime: &str,
    codex_session: Option<&str>,
    codex_thread: Option<&str>,
    codex_turn: Option<&str>,
    require_subagent: bool,
) -> Result<Session, AppError> {
    let session_id = codex_session
        .map(str::trim)
        .filter(|s| !s.is_empty() && crate::claim::is_uuid_shaped(s))
        .ok_or_else(|| {
            AppError::NotRecipient(
                "codex MCP call is missing runtime _meta (sessionId/threadId); refresh MCP or restart the codex session"
                    .to_string(),
            )
        })?;
    let thread_id = codex_thread
        .map(str::trim)
        .filter(|s| !s.is_empty() && crate::claim::is_uuid_shaped(s))
        .ok_or_else(|| {
            AppError::NotRecipient(
                "codex MCP call is missing runtime _meta (sessionId/threadId); refresh MCP or restart the codex session"
                    .to_string(),
            )
        })?;

    let rt_arc = crate::codex::for_state(state);
    let (root_res, is_revoked) = {
        let mut rt = rt_arc.lock().unwrap();
        let mut cfg = rt.config.clone();
        cfg.proc_root = state.agy_config.proc_root.clone();
        let res =
            rt.store
                .validate_or_retry_root(&cfg, owner_pid, owner_starttime, session_id, true);
        let rev = rt.store.is_revoked(session_id) || !rt.store.has_root(session_id);
        (res, rev)
    };

    let root_snap = match root_res {
        Ok(snap) => {
            if let Ok(db) = state.db.lock() {
                let _ = crate::storage::upsert_codex_root(&db, &snap);
            }
            snap
        }
        Err(msg) => {
            if is_revoked {
                if let Ok(db) = state.db.lock() {
                    let _ = crate::storage::invalidate_codex_root(&db, session_id);
                }
            }
            return Err(AppError::NotRecipient(msg));
        }
    };

    if thread_id == session_id {
        if require_subagent {
            return Err(AppError::NotRecipient(format!(
                "'{session_id}' is a parent session and receives messages on its channel; 'inbox' is only for subagents"
            )));
        }
        return Ok(crate::codex::codex_root_to_session(&root_snap));
    }

    let (root_snap, _child_state, binding) =
        crate::codex::admit_codex_subagent(&state.db, session_id, thread_id, None)?;

    if let Some(turn_id) = codex_turn.map(str::trim).filter(|s| !s.is_empty()) {
        let repaired = {
            let mut rt = rt_arc.lock().unwrap();
            rt.store.repair_child_turn_from_meta(
                session_id,
                thread_id,
                root_snap.generation,
                turn_id,
            )
        };
        if let Some(repaired_state) = repaired {
            if let Ok(db) = state.db.lock() {
                let now = crate::storage::now_epoch_secs();
                let _ = crate::storage::subagent_start_turn(
                    &db,
                    session_id,
                    thread_id,
                    root_snap.owner_pid,
                    &root_snap.owner_starttime,
                    None,
                    repaired_state.agent_type.as_deref(),
                    None,
                    now,
                );
            }
        }
    }

    Ok(Session {
        session_id: format!("{session_id}/{thread_id}"),
        name: binding.display_label().map(str::to_string),
        pid: root_snap.owner_pid,
        cwd: root_snap.cwd.unwrap_or_else(|| "/".to_string()),
        status: "idle".to_string(),
        kind: "subagent".to_string(),
        entrypoint: None,
        version: None,
        started_at: binding.bound_at as u64,
        updated_at: binding.bound_at as u64,
        harness: "codex".to_string(),
        registered: Some(true),
    })
}

// INTERIM (HA9-A.codex.darwin): codex support on Darwin is pending.
#[cfg(not(target_os = "linux"))]
pub fn resolve_codex_mcp_caller(
    _state: &AppState,
    _owner_pid: u32,
    _owner_starttime: &str,
    _codex_session: Option<&str>,
    _codex_thread: Option<&str>,
    _codex_turn: Option<&str>,
    _require_subagent: bool,
) -> Result<Session, AppError> {
    Err(AppError::NotRecipient(
        "codex support on Darwin is pending".to_string(),
    ))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct CodexHookOutcome {
    pub root_id: String,
    pub stdout: String,
    pub handoff_ids: Vec<String>,
}

#[cfg(target_os = "linux")]
fn find_trusted_codex_owner_for_hook(
    state: &AppState,
    peer: &crate::process::PeerCred,
) -> Result<(u32, String), AppError> {
    let rt_arc = crate::codex::for_state(state);
    let mut cfg = rt_arc.lock().unwrap().config.clone();
    cfg.proc_root = state.agy_config.proc_root.clone();
    let peer_pid = peer.pid_or_zero();
    let mut walk = crate::process::Ancestry::from_peer(&cfg.proc_root, peer);
    for (curr_pid, st) in walk.by_ref().take(32) {
        if crate::codex::is_trusted_codex_owner_step(&cfg, curr_pid, &st).is_some() {
            return Ok((curr_pid, st));
        }
    }
    Err(AppError::NotRecipient(format!(
        "peer PID {peer_pid} does not descend from a trusted --codex-exe process"
    )))
}

/// Handles `AgentFrame::CodexHook` on `agent.sock` (HA9-A.codex §2.1, §2.3, §2.5, §2.7).
#[cfg(target_os = "linux")]
pub async fn handle_codex_hook_frame(
    state: &AppState,
    peer: &crate::process::PeerCred,
    event: &str,
    label: Option<&str>,
    raw_payload: &serde_json::Value,
) -> Result<CodexHookOutcome, AppError> {
    let (owner_pid, owner_starttime) = find_trusted_codex_owner_for_hook(state, peer)?;
    let hook_payload: crate::codex::CodexHookPayload = serde_json::from_value(raw_payload.clone())
        .map_err(|e| AppError::BadRequest(format!("invalid codex hook payload: {e}")))?;

    let session_id = hook_payload
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::BadRequest("codex hook payload missing 'session_id'".to_string())
        })?;
    if !crate::claim::is_uuid_shaped(session_id) {
        return Err(AppError::NotRecipient(format!(
            "codex hook session_id '{session_id}' is not UUID-shaped"
        )));
    }

    let rt_arc = crate::codex::for_state(state);
    let mut cfg = rt_arc.lock().unwrap().config.clone();
    cfg.proc_root = state.agy_config.proc_root.clone();

    match event {
        "SessionStart" | "session-start" => {
            let source = hook_payload.source.as_deref().map(str::trim).unwrap_or("");
            match source {
                "startup" | "clear" | "fork" => {
                    let reg_res = {
                        let mut rt = rt_arc.lock().unwrap();
                        rt.store.register_fresh_root(
                            &cfg,
                            owner_pid,
                            &owner_starttime,
                            session_id,
                            hook_payload.cwd.as_deref(),
                            label,
                            true,
                        )
                    };
                    match reg_res {
                        Ok(Some(root_snap)) => {
                            let reserved = {
                                let db = state
                                    .db
                                    .lock()
                                    .map_err(|e| AppError::Internal(e.to_string()))?;
                                crate::storage::upsert_codex_root(&db, &root_snap)
                                    .map_err(|e| AppError::Internal(e.to_string()))?;
                                crate::storage::reserve_codex_hook_batch(
                                    &db,
                                    session_id,
                                    root_snap.generation,
                                )
                                .map_err(|e| AppError::Internal(e.to_string()))?
                            };
                            match reserved {
                                Some((handoff_ids, context_text)) => {
                                    let out = serde_json::json!({
                                        "hookSpecificOutput": {
                                            "hookEventName": "SessionStart",
                                            "additionalContext": context_text,
                                        }
                                    });
                                    Ok(CodexHookOutcome {
                                        root_id: session_id.to_string(),
                                        stdout: out.to_string(),
                                        handoff_ids,
                                    })
                                }
                                None => Ok(CodexHookOutcome {
                                    root_id: session_id.to_string(),
                                    stdout: String::new(),
                                    handoff_ids: Vec::new(),
                                }),
                            }
                        }
                        Ok(None) => Ok(CodexHookOutcome {
                            root_id: session_id.to_string(),
                            stdout: String::new(),
                            handoff_ids: Vec::new(),
                        }),
                        Err(msg) => {
                            if let Ok(db) = state.db.lock() {
                                let _ = crate::storage::invalidate_codex_root(&db, session_id);
                            }
                            Err(AppError::NotRecipient(msg))
                        }
                    }
                }
                "compact" => {
                    let val_res = {
                        let mut rt = rt_arc.lock().unwrap();
                        rt.store.validate_or_retry_root(
                            &cfg,
                            owner_pid,
                            &owner_starttime,
                            session_id,
                            false,
                        )
                    };
                    match val_res {
                        Ok(root_snap) => {
                            if let Ok(db) = state.db.lock() {
                                let _ = crate::storage::upsert_codex_root(&db, &root_snap);
                            }
                            Ok(CodexHookOutcome {
                                root_id: session_id.to_string(),
                                stdout: String::new(),
                                handoff_ids: Vec::new(),
                            })
                        }
                        Err(msg) => {
                            if let Ok(db) = state.db.lock() {
                                let _ = crate::storage::invalidate_codex_root(&db, session_id);
                            }
                            Err(AppError::NotRecipient(msg))
                        }
                    }
                }
                "resume" => {
                    {
                        let mut rt = rt_arc.lock().unwrap();
                        let _ = rt.store.revoke_root(session_id);
                    }
                    if let Ok(db) = state.db.lock() {
                        let _ = crate::storage::invalidate_codex_root(&db, session_id);
                    }
                    Err(AppError::NotRecipient(format!(
                        "codex resume is unsupported in xmsg v1 for session '{session_id}'; start a fresh codex thread"
                    )))
                }
                other => {
                    {
                        let mut rt = rt_arc.lock().unwrap();
                        let _ = rt.store.revoke_root(session_id);
                    }
                    if let Ok(db) = state.db.lock() {
                        let _ = crate::storage::invalidate_codex_root(&db, session_id);
                    }
                    Err(AppError::NotRecipient(format!(
                        "unsupported or missing SessionStart source '{other}' for session '{session_id}'"
                    )))
                }
            }
        }
        "UserPromptSubmit" | "user-prompt-submit" => {
            let val_res = {
                let mut rt = rt_arc.lock().unwrap();
                rt.store
                    .validate_or_retry_root(&cfg, owner_pid, &owner_starttime, session_id, true)
            };
            match val_res {
                Ok(root_snap) => {
                    if let Some(agent_id) = hook_payload
                        .agent_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && *s != session_id)
                    {
                        let (root_snap, _, _) = crate::codex::admit_codex_subagent(
                            &state.db,
                            session_id,
                            agent_id,
                            hook_payload.agent_type.as_deref(),
                        )?;
                        let updated_child = {
                            let mut rt = rt_arc.lock().unwrap();
                            match hook_payload
                                .turn_id
                                .as_deref()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                            {
                                Some(tid) => rt.store.repair_child_turn_from_meta(
                                    session_id,
                                    agent_id,
                                    root_snap.generation,
                                    tid,
                                ),
                                None => rt.store.mark_child_turn_active(
                                    session_id,
                                    agent_id,
                                    root_snap.generation,
                                    None,
                                ),
                            }
                        };
                        let subagent_addr = format!("{session_id}/{agent_id}");
                        let reserved = {
                            let db = state
                                .db
                                .lock()
                                .map_err(|e| AppError::Internal(e.to_string()))?;
                            crate::storage::upsert_codex_root(&db, &root_snap)
                                .map_err(|e| AppError::Internal(e.to_string()))?;
                            if let Some(child_state) = updated_child {
                                let now = crate::storage::now_epoch_secs();
                                let _ = crate::storage::subagent_start_turn(
                                    &db,
                                    session_id,
                                    agent_id,
                                    root_snap.owner_pid,
                                    &root_snap.owner_starttime,
                                    None,
                                    child_state.agent_type.as_deref(),
                                    None,
                                    now,
                                );
                            }
                            crate::storage::reserve_codex_child_hook_batch(
                                &db,
                                &subagent_addr,
                                root_snap.generation,
                            )
                            .map_err(|e| AppError::Internal(e.to_string()))?
                        };
                        return match reserved {
                            Some((handoff_ids, context_text)) => {
                                let out = serde_json::json!({
                                    "hookSpecificOutput": {
                                        "hookEventName": "UserPromptSubmit",
                                        "additionalContext": context_text,
                                    }
                                });
                                Ok(CodexHookOutcome {
                                    root_id: subagent_addr,
                                    stdout: out.to_string(),
                                    handoff_ids,
                                })
                            }
                            None => Ok(CodexHookOutcome {
                                root_id: subagent_addr,
                                stdout: String::new(),
                                handoff_ids: Vec::new(),
                            }),
                        };
                    }

                    let reserved = {
                        let db = state
                            .db
                            .lock()
                            .map_err(|e| AppError::Internal(e.to_string()))?;
                        crate::storage::upsert_codex_root(&db, &root_snap)
                            .map_err(|e| AppError::Internal(e.to_string()))?;
                        crate::storage::reserve_codex_hook_batch(
                            &db,
                            session_id,
                            root_snap.generation,
                        )
                        .map_err(|e| AppError::Internal(e.to_string()))?
                    };
                    match reserved {
                        Some((handoff_ids, context_text)) => {
                            let out = serde_json::json!({
                                "hookSpecificOutput": {
                                    "hookEventName": "UserPromptSubmit",
                                    "additionalContext": context_text,
                                }
                            });
                            Ok(CodexHookOutcome {
                                root_id: session_id.to_string(),
                                stdout: out.to_string(),
                                handoff_ids,
                            })
                        }
                        None => Ok(CodexHookOutcome {
                            root_id: session_id.to_string(),
                            stdout: String::new(),
                            handoff_ids: Vec::new(),
                        }),
                    }
                }
                Err(msg) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = crate::storage::invalidate_codex_root(&db, session_id);
                    }
                    Err(AppError::NotRecipient(msg))
                }
            }
        }
        "PreModelRequest" | "pre-model-request" => {
            let val_res = {
                let mut rt = rt_arc.lock().unwrap();
                rt.store
                    .validate_or_retry_root(&cfg, owner_pid, &owner_starttime, session_id, true)
            };
            let _root_snap = match val_res {
                Ok(snap) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = crate::storage::upsert_codex_root(&db, &snap);
                    }
                    snap
                }
                Err(msg) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = crate::storage::invalidate_codex_root(&db, session_id);
                    }
                    return Err(AppError::NotRecipient(msg));
                }
            };
            if let Some(agent_id) = hook_payload
                .agent_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != session_id)
            {
                let (root_snap, _, _) = crate::codex::admit_codex_subagent(
                    &state.db,
                    session_id,
                    agent_id,
                    hook_payload.agent_type.as_deref(),
                )?;
                let updated_child = {
                    let mut rt = rt_arc.lock().unwrap();
                    rt.store.mark_child_turn_active(
                        session_id,
                        agent_id,
                        root_snap.generation,
                        hook_payload.turn_id.as_deref(),
                    )
                };
                if let Some(child_state) = updated_child {
                    if let Ok(db) = state.db.lock() {
                        let now = crate::storage::now_epoch_secs();
                        let _ = crate::storage::subagent_start_turn(
                            &db,
                            session_id,
                            agent_id,
                            root_snap.owner_pid,
                            &root_snap.owner_starttime,
                            None,
                            child_state.agent_type.as_deref(),
                            None,
                            now,
                        );
                    }
                }
            }
            Ok(CodexHookOutcome {
                root_id: session_id.to_string(),
                stdout: String::new(),
                handoff_ids: Vec::new(),
            })
        }
        "SubagentStart" | "subagent-start" => {
            let agent_id = hook_payload
                .agent_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "SubagentStart hook payload missing non-empty 'agent_id'".to_string(),
                    )
                })?;
            let val_res = {
                let mut rt = rt_arc.lock().unwrap();
                rt.store
                    .validate_or_retry_root(&cfg, owner_pid, &owner_starttime, session_id, true)
            };
            if let Err(msg) = val_res {
                if let Ok(db) = state.db.lock() {
                    let _ = crate::storage::invalidate_codex_root(&db, session_id);
                }
                return Err(AppError::NotRecipient(msg));
            }
            let (root_snap, _, _) = crate::codex::admit_codex_subagent(
                &state.db,
                session_id,
                agent_id,
                hook_payload.agent_type.as_deref(),
            )?;
            let child_state = {
                let mut rt = rt_arc.lock().unwrap();
                rt.store.mark_child_turn_active(
                    session_id,
                    agent_id,
                    root_snap.generation,
                    hook_payload.turn_id.as_deref(),
                )
            };
            if let Ok(db) = state.db.lock() {
                let now = crate::storage::now_epoch_secs();
                let _ = crate::storage::upsert_codex_root(&db, &root_snap);
                let _ = crate::storage::subagent_start_turn(
                    &db,
                    session_id,
                    agent_id,
                    root_snap.owner_pid,
                    &root_snap.owner_starttime,
                    None,
                    child_state.and_then(|c| c.agent_type).as_deref(),
                    None,
                    now,
                );
            }
            Ok(CodexHookOutcome {
                root_id: session_id.to_string(),
                stdout: String::new(),
                handoff_ids: Vec::new(),
            })
        }
        "SubagentStop" | "subagent-stop" => {
            let agent_id = hook_payload
                .agent_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "SubagentStop hook payload missing non-empty 'agent_id'".to_string(),
                    )
                })?;
            let val_res = {
                let mut rt = rt_arc.lock().unwrap();
                rt.store.validate_or_retry_root(
                    &cfg,
                    owner_pid,
                    &owner_starttime,
                    session_id,
                    false,
                )
            };
            let root_snap = match val_res {
                Ok(snap) => snap,
                Err(msg) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = crate::storage::invalidate_codex_root(&db, session_id);
                    }
                    return Err(AppError::NotRecipient(msg));
                }
            };
            let stop_res = {
                let mut rt = rt_arc.lock().unwrap();
                rt.store.stop_child_turn(
                    session_id,
                    agent_id,
                    root_snap.generation,
                    hook_payload.turn_id.as_deref(),
                )
            };
            let all_stopped = stop_res.map_err(AppError::NotRecipient)?;
            if all_stopped {
                let moved = {
                    let db = state
                        .db
                        .lock()
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    crate::storage::subagent_stop_turn(&db, session_id, agent_id)
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    let now = crate::storage::now_epoch_secs();
                    crate::storage::take_codex_subagent_queue_to_parent(
                        &db,
                        session_id,
                        root_snap.generation,
                        agent_id,
                        now,
                    )
                    .map_err(|e| AppError::Internal(e.to_string()))?
                };
                let local = state.local();
                for msg in moved {
                    let _ = surface::try_push_codex_queued_message(
                        &local,
                        &root_snap,
                        &msg.id,
                        &msg.envelope,
                    )
                    .await;
                }
            }
            Ok(CodexHookOutcome {
                root_id: session_id.to_string(),
                stdout: String::new(),
                handoff_ids: Vec::new(),
            })
        }
        "Stop" | "stop" => {
            if hook_payload
                .agent_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_some()
            {
                return Ok(CodexHookOutcome {
                    root_id: session_id.to_string(),
                    stdout: String::new(),
                    handoff_ids: Vec::new(),
                });
            }
            let val_res = {
                let mut rt = rt_arc.lock().unwrap();
                rt.store
                    .validate_or_retry_root(&cfg, owner_pid, &owner_starttime, session_id, true)
            };
            match val_res {
                Ok(root_snap) => {
                    let reserved = {
                        let db = state
                            .db
                            .lock()
                            .map_err(|e| AppError::Internal(e.to_string()))?;
                        crate::storage::upsert_codex_root(&db, &root_snap)
                            .map_err(|e| AppError::Internal(e.to_string()))?;
                        crate::storage::reserve_codex_hook_batch(
                            &db,
                            session_id,
                            root_snap.generation,
                        )
                        .map_err(|e| AppError::Internal(e.to_string()))?
                    };
                    match reserved {
                        Some((handoff_ids, reason_text)) => {
                            let out = serde_json::json!({
                                "decision": "block",
                                "reason": reason_text,
                            });
                            Ok(CodexHookOutcome {
                                root_id: session_id.to_string(),
                                stdout: out.to_string(),
                                handoff_ids,
                            })
                        }
                        None => Ok(CodexHookOutcome {
                            root_id: session_id.to_string(),
                            stdout: String::new(),
                            handoff_ids: Vec::new(),
                        }),
                    }
                }
                Err(msg) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = crate::storage::invalidate_codex_root(&db, session_id);
                    }
                    Err(AppError::NotRecipient(msg))
                }
            }
        }
        "SessionEnd" | "session-end" => {
            let revoked = {
                let mut rt = rt_arc.lock().unwrap();
                let owned = rt
                    .store
                    .validate_or_retry_root(&cfg, owner_pid, &owner_starttime, session_id, false)
                    .is_ok();
                if owned {
                    let _ = rt.store.end_root(session_id);
                    true
                } else {
                    rt.store.is_revoked(session_id)
                }
            };
            if revoked {
                if let Ok(db) = state.db.lock() {
                    let _ = crate::storage::invalidate_codex_root(&db, session_id);
                }
                Ok(CodexHookOutcome {
                    root_id: session_id.to_string(),
                    stdout: String::new(),
                    handoff_ids: Vec::new(),
                })
            } else {
                Err(AppError::NotRecipient(format!(
                    "codex SessionEnd for '{session_id}' rejected: not owned by caller"
                )))
            }
        }
        other => Err(AppError::BadRequest(format!(
            "unsupported codex hook event '{other}'"
        ))),
    }
}

/// Runs `xmsg register codex --hook --event <event>`: sends `AgentFrame::CodexHook` to
/// `agent.sock`, writes the returned hook JSON (if any) to `stdout_writer` and flushes it,
/// and completes the two-phase `codex_handoff` acknowledgement on the same socket stream (§2.5, §2.7).
// INTERIM (HA9-A.codex.darwin): codex support on Darwin is pending.
#[cfg(target_os = "linux")]
pub fn run_codex_hook<W: std::io::Write>(
    event: &str,
    label: Option<&str>,
    input: &str,
    agent_sock: Option<&Path>,
    mut stdout_writer: W,
) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let payload_val: serde_json::Value =
        serde_json::from_str(input).map_err(|e| format!("malformed hook JSON on stdin: {e}"))?;
    if !payload_val.is_object() {
        return Err("hook stdin JSON must be an object".to_string());
    }

    let sock_path = match agent_sock {
        Some(p) => p.to_path_buf(),
        None => default_agent_sock_path().map_err(|e| e.to_string())?,
    };
    let my_uid = current_uid();
    if let Some(parent) = sock_path.parent() {
        ensure_secure_socket_dir(parent, my_uid)
            .map_err(|e| format!("insecure agent socket directory: {e}"))?;
    }

    let mut stream = UnixStream::connect(&sock_path).map_err(|e| {
        format!(
            "failed to connect to agent socket at {}: {e}",
            sock_path.display()
        )
    })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut frame = serde_json::json!({
        "action": "codex_hook",
        "schema_version": surface::MCP_SCHEMA_VERSION,
        "event": event,
        "payload": payload_val,
    });
    if let Some(lbl) = label.filter(|s| !s.trim().is_empty()) {
        frame["label"] = serde_json::Value::String(lbl.to_string());
    }

    let line = format!("{frame}\n");
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("failed to write to agent socket: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush agent socket: {e}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("failed to clone agent socket stream: {e}"))?,
    );
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .map_err(|e| format!("failed to read response from agent socket: {e}"))?;

    let resp_val: serde_json::Value = serde_json::from_str(&resp_line)
        .map_err(|e| format!("invalid response JSON from agent socket: {e}"))?;

    if resp_val.get("status").and_then(serde_json::Value::as_str) == Some("error") {
        let err_kind = resp_val
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("error");
        let detail = resp_val
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown error");
        return Err(format!("{err_kind}: {detail}"));
    }

    let stdout_str = resp_val
        .get("stdout")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let has_handoff = resp_val
        .get("handoff_ids")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|a| !a.is_empty());

    if !stdout_str.is_empty() {
        let out_bytes = format!("{stdout_str}\n");
        if let Err(e) = stdout_writer
            .write_all(out_bytes.as_bytes())
            .and_then(|()| stdout_writer.flush())
        {
            if has_handoff {
                let _ = stream.write_all(b"{\"ack\":\"abort\"}\n");
                let _ = stream.flush();
            }
            return Err(format!("failed to write hook output to stdout: {e}"));
        }
    }

    if has_handoff {
        stream
            .write_all(b"{\"ack\":\"accepted\"}\n")
            .map_err(|e| format!("failed to write handoff ack to agent socket: {e}"))?;
        stream
            .flush()
            .map_err(|e| format!("failed to flush handoff ack to agent socket: {e}"))?;
        let mut ack_resp = String::new();
        let _ = reader.read_line(&mut ack_resp);
    }

    Ok(())
}
