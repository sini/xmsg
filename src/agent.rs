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
    },
    Inbox {
        #[serde(default)]
        schema_version: Option<u32>,
        #[serde(default)]
        wait: Option<u64>,
        #[serde(default)]
        as_agent: Option<String>,
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

                let caller_needed = matches!(
                    frame,
                    AgentFrame::Send { .. }
                        | AgentFrame::Reply { .. }
                        | AgentFrame::Inbox { .. }
                        | AgentFrame::Subagent { .. }
                );
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
                                if restored_creds {
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
                                    let _ = writer
                                        .write_all(format!("{err_resp}\n").as_bytes())
                                        .await;
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
                    AgentFrame::Send {
                        to,
                        text,
                        idempotency_key,
                        as_agent,
                        ..
                    } => {
                        let parent = caller.expect("caller resolved");
                        match resolve_as_agent(&state_clone, parent, as_agent.as_deref(), false) {
                            Ok(effective_caller) => {
                                let sender = surface::Sender::Session(effective_caller);
                                surface::send(
                                    &state_clone,
                                    &sender,
                                    &to,
                                    &text,
                                    idempotency_key.as_deref(),
                                )
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
                        ..
                    } => {
                        let parent = caller.expect("caller resolved");
                        match resolve_as_agent(&state_clone, parent, as_agent.as_deref(), false) {
                            Ok(effective_caller) => surface::reply(
                                &state_clone,
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
                        ..
                    } => {
                        surface::replies(
                            &state_clone,
                            &message_id,
                            after.unwrap_or(0),
                            wait.unwrap_or(0),
                        )
                        .await
                        .map(|r| serde_json::json!({ "status": "ok", "replies": r }))
                    }
                    AgentFrame::Inbox { wait, as_agent, .. } => {
                        let parent = caller.expect("caller resolved");
                        match resolve_as_agent(&state_clone, parent, as_agent.as_deref(), true) {
                            Ok(effective_caller) => {
                                surface::inbox(&state_clone, &effective_caller, wait.unwrap_or(0))
                                    .await
                                    .map(|r| {
                                        serde_json::json!({
                                            "status": "ok",
                                            "address": r.address,
                                            "messages": r.messages,
                                        })
                                    })
                            }
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
                    } => {
                        let parent = caller.expect("caller resolved");
                        handle_subagent_frame(
                            &state_clone,
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

/// Resolves `as_agent` against `parent` in `subagents` (HA9-A §2.3 step 3, E1, E2, D1, D5).
/// When `as_agent` is absent or empty, acts as `parent` unless `require_subagent` is true
/// (`inbox` requires a non-empty bound `as_agent`).
pub fn resolve_as_agent(
    state: &AppState,
    parent: Session,
    as_agent: Option<&str>,
    require_subagent: bool,
) -> Result<Session, AppError> {
    let agent_id = as_agent.map(str::trim).unwrap_or("");
    if agent_id.is_empty() {
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
    let binding = crate::storage::get_subagent(&db, &parent.session_id, agent_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| {
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

/// Reads optional `("name", "agentType")` from the subagent `meta.json` beside `transcript_path`
/// (HA9-A §2.5, O12).
fn read_meta_json_fields(transcript_path: &str, agent_id: &str) -> (Option<String>, Option<String>) {
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
    if let Some(parent_dir) = Path::new(transcript_path).parent() {
        candidates.push(
            parent_dir
                .join("subagents")
                .join(format!("agent-{agent_id}.meta.json")),
        );
        candidates.push(parent_dir.join(format!("agent-{agent_id}.meta.json")));
        candidates.push(parent_dir.join("meta.json"));
    }
    for path in candidates {
        if let Ok(raw) = fs::read_to_string(&path) {
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
    }
    (None, None)
}

#[allow(clippy::too_many_arguments)]
async fn handle_subagent_frame(
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
    if parent.harness != "claude" {
        return Err(AppError::BadRequest(
            "subagent frame on agent.sock is only valid for Claude sessions".to_string(),
        ));
    }
    let agent_id = agent_id.trim();
    if agent_id.is_empty() || agent_id.contains('/') {
        return Err(AppError::BadRequest(
            "agent_id must be non-empty and must not contain '/'".to_string(),
        ));
    }
    let now = crate::storage::now_epoch_secs();
    match event {
        "start" | "SubagentStart" | "subagent_start" => {
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
            let valid_name = candidate_name.filter(|n| crate::claim::validate_subagent_name(n).is_ok());
            let effective_type = agent_type
                .filter(|s| !s.is_empty())
                .or(meta_type.as_deref().filter(|s| !s.is_empty()));
            {
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
            }
            Ok(serde_json::json!({ "status": "ok" }))
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
                        !p.is_empty()
                            && *p != agent_id
                            && !crate::claim::is_subagent_id_shaped(p)
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
                    !n.is_empty()
                        && *n != agent_id
                        && !crate::claim::is_subagent_id_shaped(n)
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

    match event_name {
        "PreToolUse" => {
            // E6: PreToolUse does no socket I/O; it only reads stdin and writes stdout.
            let tool_input = obj
                .get("tool_input")
                .and_then(Value::as_object)
                .ok_or_else(|| "PreToolUse hook input missing 'tool_input' object".to_string())?;
            let agent_id = match obj.get("agent_id") {
                None | Some(Value::Null) => "",
                Some(Value::String(s)) => s.as_str(),
                Some(_) => return Err("'agent_id' in PreToolUse hook input must be a string".to_string()),
            };
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
        }
        "SubagentStart" => {
            let agent_id = obj
                .get("agent_id")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "SubagentStart hook input missing non-empty 'agent_id'".to_string())?;
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
            let sock = resolve_sock()?;
            crate::mcp::call_agent_sock(&sock, &frame)?;
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
                        .ok_or_else(|| "PostToolUse(Agent) missing 'tool_response' object".to_string())?;
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
                        let sock = resolve_sock()?;
                        crate::mcp::call_agent_sock(&sock, &frame)?;
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
                            let sock = resolve_sock()?;
                            crate::mcp::call_agent_sock(&sock, &frame)?;
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
                .ok_or_else(|| "SubagentStop hook input missing non-empty 'agent_id'".to_string())?;
            let frame = serde_json::json!({
                "action": "subagent",
                "schema_version": surface::MCP_SCHEMA_VERSION,
                "event": "stop",
                "agent_id": agent_id,
            });
            let sock = resolve_sock()?;
            crate::mcp::call_agent_sock(&sock, &frame)?;
            Ok("{}".to_string())
        }
        other => Err(format!("unsupported hook_event_name '{other}'")),
    }
}
