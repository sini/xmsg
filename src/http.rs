use axum::{
    body::Bytes,
    extract::{rejection::QueryRejection, Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

use crate::error::AppError;
use crate::registry;
use crate::storage::{self, ReplyRecord};
use crate::surface::{self, Sender};

pub struct AppState {
    pub sessions_dirs: Vec<PathBuf>,
    pub agy_config: crate::agy::AgyConfig,
    pub agy_store: crate::agy::AgyStore,
    pub pi_store: crate::pi::PiStore,
    pub pi_notify_tx: broadcast::Sender<String>,
    pub svc_store: crate::svc::SvcStore,
    pub svc_notify_tx: broadcast::Sender<String>,
    pub node_name: String,
    pub max_body: usize,
    pub request_counter: AtomicU64,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub notify_tx: broadcast::Sender<String>,
    pub reply_ttl: Duration,
    pub idempotency_ttl: Duration,
    pub long_poll_semaphore: Arc<tokio::sync::Semaphore>,
    pub fed_state: Option<Arc<crate::fed::FedState>>,
}

impl AppState {
    pub fn is_leaf(&self) -> bool {
        self.fed_state.as_ref().map(|f| f.is_leaf).unwrap_or(false)
    }

    pub fn leaf_principal(&self) -> Option<&str> {
        self.fed_state
            .as_ref()
            .and_then(|f| f.leaf_principal.as_deref())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessageDetailResponse {
    pub id: String,
    pub created_at: i64,
    pub session_id: String,
    pub from_name: String,
    pub bytes: usize,
    pub outcome: String,
    pub recipient_harness: String,
    #[serde(default)]
    pub return_harness: Option<String>,
    #[serde(default)]
    pub return_session_id: Option<String>,
    #[serde(default)]
    pub thread_id: String,
    pub replies: Vec<ReplyRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LongPollQuery {
    pub after: Option<i64>,
    pub wait: Option<u64>,
}

/// `POST /v1/messages` (A13). `from` is the anonymous caller's own description (A15).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub to: String,
    pub text: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// `POST /v1/messages/{id}/replies` (A13).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyRequest {
    pub text: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/v1/recipients", get(list_recipients_handler))
        .route("/v1/sessions", get(retired_sessions_handler))
        .route("/v1/messages", post(send_handler))
        .route("/v1/messages/{id}", get(get_message_handler))
        .route(
            "/v1/messages/{id}/replies",
            get(get_replies_handler).post(reply_handler),
        )
        .with_state(state)
}

async fn retired_sessions_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "status": "error",
            "error": "not_found",
            "detail": format!(
                "GET /v1/sessions was replaced by GET /v1/recipients in schema v{}; stale xmsg mcp client: restart the session to load the current xmsg mcp binary",
                surface::MCP_SCHEMA_VERSION
            ),
        })),
    )
}

async fn healthz_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dir_ok = !state.sessions_dirs.is_empty()
        && state.sessions_dirs.iter().any(|d| d.exists() && d.is_dir());
    let status_str = if dir_ok { "ok" } else { "sessions_dir_missing" };
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "sessions_dir": status_str,
        })),
    )
}

pub(crate) enum ResolvedTarget {
    Claude(registry::Session, PathBuf),
    Agy(registry::Session),
    /// A session served from a `register.sock` poll queue: a pi, or a plugin session
    /// (opencode), whose `harness` names which.
    Pi(registry::Session),
    Svc(registry::Session),
    /// A Claude instance observed before and not running now: a send is queued until
    /// `expires_at` (A14).
    Parked {
        session: registry::Session,
        expires_at: i64,
    },
}

impl ResolvedTarget {
    /// Not running now: a parked Claude conversation, or an agy one between turns.
    pub(crate) fn is_parked(&self) -> bool {
        match self {
            ResolvedTarget::Parked { .. } => true,
            ResolvedTarget::Agy(s) => s.status == "parked",
            _ => false,
        }
    }

    pub(crate) fn session(&self) -> &registry::Session {
        match self {
            ResolvedTarget::Claude(s, _)
            | ResolvedTarget::Agy(s)
            | ResolvedTarget::Pi(s)
            | ResolvedTarget::Svc(s)
            | ResolvedTarget::Parked { session: s, .. } => s,
        }
    }

    pub(crate) fn recipient_harness(&self) -> &'static str {
        match self {
            ResolvedTarget::Claude(_, _) | ResolvedTarget::Parked { .. } => "claude",
            ResolvedTarget::Agy(_) => "agy",
            ResolvedTarget::Pi(s) => crate::plugin::harness(&s.harness).unwrap_or("pi"),
            ResolvedTarget::Svc(_) => "svc",
        }
    }
}

/// Local resolution of a send's target (A11, A7, D-4), one order for every surface. Kind
/// prefixes and pids are not refs: a ref is an instance ID (optionally `~n`) or a name.
///
/// 1. An instance ID, which is UUID-shaped (A11): a Claude `X~n` or bare `X`, then an agy
///    or pi ID. Any other ref is a name and skips this step.
///    A bare X with only `X~n` forks live is `ambiguous` (D-4).
/// 2. A name, among services first (A11): a service carrying it wins, whatever any
///    instance is labelled.
/// 3. Only when no service has it, instance labels, and only a unique one (A7): two
///    live instances labelled alike are `ambiguous`, listing each `id@node`.
/// 4. Otherwise (A14, D-1, AM-9, AM-10): an instance this node
///    observed and that is not running now, within its parked lifetime (the reply TTL
///    after it was last live, or as long as its queue), is queued for if it is a Claude
///    or agy conversation and `gone` if it is a pi; past its lifetime it is `not_found`.
///    An `X~n` whose process exited is `gone` (D-4, step 1). An ID never observed is
///    `not_found`.
///    A send arriving from a peer queues the same way (XA6); one marked live-only is
///    refused there instead (`is_parked`, gate v0 C9).
/// 5. An instance this node never observed: `gone` for a fork recorded before and since
///    exited, or `not_found`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_target(
    sessions_dirs: &[PathBuf],
    agy_config: &crate::agy::AgyConfig,
    agy_store: &crate::agy::AgyStore,
    pi_store: &crate::pi::PiStore,
    svc_store: &crate::svc::SvcStore,
    db: &Arc<Mutex<rusqlite::Connection>>,
    node_name: &str,
    ref_str: &str,
    reply_ttl: Duration,
) -> Result<ResolvedTarget, AppError> {
    let proc_root = &agy_config.proc_root;
    let now = storage::now_epoch_secs();
    let query = registry::SessionsQuery::default();
    let is = |id: &str| id == ref_str;
    // A11: only a UUID-shaped reference (optionally `~n`) is an instance ID; any other is a
    // name, even where an instance presents it as its ID.
    let instance = crate::claim::is_instance_ref(ref_str);
    let is_id = |id: &str| instance && is(id);

    // One claim scan answers the Claude half of every step.
    let (claude_by_id, claude_labelled, claude_absence, seen) =
        crate::claim::with_claims(db, proc_root, sessions_dirs, node_name, |conn, pairs| {
            (
                crate::claim::resolve_claude_id_in(conn, pairs, node_name, ref_str),
                crate::claim::claude_label_matches(pairs, ref_str),
                crate::claim::claude_absence_in(conn, sessions_dirs, ref_str),
                storage::seen_instance(conn, ref_str, now, reply_ttl.as_secs() as i64),
            )
        })
        .await?;
    let seen = seen.map_err(|e| AppError::Internal(e.to_string()))?;

    // 1. Instance IDs.
    if let Some(res) = claude_by_id.filter(|_| instance) {
        return res.map(|(session, sock)| ResolvedTarget::Claude(session, sock));
    }
    if let Some(session) = crate::agy::list_agy_sessions(agy_config, agy_store, &query)
        .into_iter()
        .find(|s| is_id(&s.session_id))
    {
        return Ok(ResolvedTarget::Agy(session));
    }
    let mut pi_sessions = crate::pi::list_pi_sessions(proc_root, pi_store, &query);
    pi_sessions.extend(
        crate::plugin::sessions(&*db.lock().map_err(|e| AppError::Internal(e.to_string()))?)
            .map_err(|e| AppError::Internal(e.to_string()))?,
    );
    if let Some(session) = pi_sessions.iter().find(|s| is_id(&s.session_id)) {
        return Ok(ResolvedTarget::Pi(session.clone()));
    }

    // 2. A name: services first (A11). A service's name is unique on its node (A2).
    if let Some(session) = crate::svc::list_svc_sessions(proc_root, svc_store, &query)
        .into_iter()
        .find(|s| is(&s.session_id))
    {
        return Ok(ResolvedTarget::Svc(session));
    }

    // 3. Instance labels, unique only (A7).
    let mut labelled: Vec<ResolvedTarget> = claude_labelled
        .into_iter()
        .map(|(session, sock)| ResolvedTarget::Claude(session, sock))
        .collect();
    labelled.extend(
        pi_sessions
            .into_iter()
            .filter(|s| s.name.as_deref().is_some_and(is))
            .map(ResolvedTarget::Pi),
    );
    match labelled.len() {
        0 => {}
        1 => return Ok(labelled.remove(0)),
        _ => {
            let candidates: Vec<String> = labelled
                .iter()
                .map(|t| format!("{}@{node_name}", t.session().session_id))
                .collect();
            return Err(AppError::Ambiguous(candidates.join(", ")));
        }
    }

    // 4. Nothing live carries it: an instance observed before (A14, D-1, AM-9, AM-10).
    if let Some(seen) = seen {
        let ttl = reply_ttl;
        let parked = seen.queued || now < seen.last_live + ttl.as_secs() as i64;
        let parked_session = |harness: &str| registry::Session {
            session_id: ref_str.to_string(),
            name: Some(ref_str.to_string()),
            pid: 0,
            cwd: "/".to_string(),
            status: "parked".to_string(),
            kind: "interactive".to_string(),
            entrypoint: None,
            version: None,
            started_at: 0,
            updated_at: 0,
            harness: harness.to_string(),
            registered: Some(false),
        };
        return match seen.harness.as_str() {
            _ if !parked => Err(AppError::NotFound(ref_str.to_string())),
            // A pi ID is bound to its process, and a plugin session's address to its
            // registration: never queued (AM-9, AM-10, harness gate v0 C3).
            h if h == "pi" || crate::plugin::harness(h).is_some() => Err(AppError::Gone {
                session_id: ref_str.to_string(),
                pid: 0,
            }),
            // An agy conversation between turns queues where its credentials would.
            "agy" => Ok(ResolvedTarget::Agy(parked_session("agy"))),
            _ => Ok(ResolvedTarget::Parked {
                session: parked_session("claude"),
                expires_at: now + ttl.as_secs() as i64,
            }),
        };
    }

    // 5. No queue here. A recorded instance whose process still runs has moved to another
    // conversation: not this one.
    match claude_absence {
        AppError::Gone { pid, .. } if crate::process::starttime(proc_root, pid).is_ok() => {
            Err(AppError::NotFound(ref_str.to_string()))
        }
        other => Err(other),
    }
}

pub(crate) async fn resolve_target_session(
    state: &AppState,
    ref_str: &str,
) -> Result<ResolvedTarget, AppError> {
    resolve_target(
        &state.sessions_dirs,
        &state.agy_config,
        &state.agy_store,
        &state.pi_store,
        &state.svc_store,
        &state.db,
        &state.node_name,
        ref_str,
        state.reply_ttl,
    )
    .await
}

/// How an HTTP caller reached this server. Only `http.sock` carries peer credentials, so
/// only it yields a peer to trace (A15); a request with no `HttpPeer` (the TCP `--listen`
/// listener) has none (AM-2).
#[derive(Debug, Clone)]
pub struct HttpPeer {
    pub peer: Option<crate::process::PeerCred>,
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, UcredUnixListener>>
    for HttpPeer
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, UcredUnixListener>) -> Self {
        HttpPeer {
            peer: crate::process::peer_cred(stream.io()).ok(),
        }
    }
}

type PeerInfo = Option<axum::Extension<axum::extract::ConnectInfo<HttpPeer>>>;

/// An HTTP caller (A15, AM-2). On `http.sock`, the caller's ancestry is walked to a session
/// or service, and a traced caller acts as that sender; an untraced one is anonymous. With
/// no peer credentials (TCP), the caller is the leaf principal in leaf mode and anonymous
/// otherwise.
async fn http_sender(state: &AppState, peer: &PeerInfo, from: Option<&str>) -> Sender {
    let cred = peer.as_ref().and_then(|p| (p.0).0.peer.as_ref());
    if let Some(cred) = cred {
        if let Ok(session) = surface::trace_caller_peer(state, cred).await {
            return Sender::Session(session);
        }
    } else if let Some(p) = state.leaf_principal().filter(|_| state.is_leaf()) {
        return Sender::service(surface::leaf_service_name(p));
    }
    Sender::Anonymous(from.unwrap_or_default().to_string())
}

fn parse_json<T: serde::de::DeserializeOwned>(
    state: &AppState,
    body: &Bytes,
) -> Result<T, AppError> {
    if body.len() > state.max_body {
        return Err(AppError::PayloadTooLarge {
            size: body.len(),
            limit: state.max_body,
        });
    }
    serde_json::from_slice(body).map_err(|e| AppError::BadRequest(e.to_string()))
}

fn parse_query<T>(query: Result<Query<T>, QueryRejection>) -> Result<T, AppError> {
    query
        .map(|Query(q)| q)
        .map_err(|e| AppError::BadRequest(e.body_text()))
}

async fn list_recipients_handler(
    State(state): State<Arc<AppState>>,
    query: Result<Query<surface::ListQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let query = parse_query(query)?;
    let entries = surface::list(&state, &query).await?;
    Ok((StatusCode::OK, Json(entries)).into_response())
}

async fn send_handler(
    State(state): State<Arc<AppState>>,
    peer: PeerInfo,
    body: Bytes,
) -> Result<Response, AppError> {
    let raw: serde_json::Value = parse_json(&state, &body)?;
    if let Some(obj) = raw.as_object() {
        if obj.contains_key("ref") && !obj.contains_key("to") {
            return Err(AppError::BadRequest(
                "unknown field 'ref'; use 'to' instead".to_string(),
            ));
        }
    }
    let req: SendRequest =
        serde_json::from_value(raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let sender = http_sender(&state, &peer, req.from.as_deref()).await;
    let res = surface::send(
        &state,
        &sender,
        &req.to,
        &req.text,
        req.idempotency_key.as_deref(),
    )
    .await?;
    Ok((StatusCode::ACCEPTED, Json(res)).into_response())
}

async fn reply_handler(
    State(state): State<Arc<AppState>>,
    peer: PeerInfo,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    let req: ReplyRequest = parse_json(&state, &body)?;
    let caller = match http_sender(&state, &peer, None).await {
        Sender::Session(s) => s,
        Sender::Anonymous(_) => {
            return Err(AppError::Denied(
                "an anonymous caller has received no message to reply to".to_string(),
            ))
        }
    };
    let reply = surface::reply(
        &state,
        &caller,
        &id,
        &req.text,
        req.idempotency_key.as_deref(),
    )
    .await?;
    Ok((StatusCode::OK, Json(reply)).into_response())
}

async fn get_replies_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    query: Result<Query<LongPollQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let query = parse_query(query)?;
    let replies = surface::replies(
        &state,
        &id,
        query.after.unwrap_or(0),
        query.wait.unwrap_or(0),
    )
    .await?;
    Ok((StatusCode::OK, Json(replies)).into_response())
}

async fn get_message_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, AppError> {
    let (msg, replies) = {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let msg = storage::get_message(&db, &id)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("message '{id}'")))?;
        let replies =
            storage::get_all_replies(&db, &id).map_err(|e| AppError::Internal(e.to_string()))?;
        (msg, replies)
    };

    Ok((
        StatusCode::OK,
        Json(MessageDetailResponse {
            id: msg.id,
            created_at: msg.created_at,
            session_id: msg.session_id,
            from_name: msg.from_name,
            bytes: msg.bytes,
            outcome: msg.outcome,
            recipient_harness: msg.recipient_harness,
            return_harness: msg.return_harness,
            return_session_id: msg.return_session_id,
            thread_id: msg.thread_id,
            replies,
        }),
    )
        .into_response())
}
pub fn default_http_sock_path() -> Result<PathBuf, AppError> {
    crate::agent::default_socket_dir().map(|d| d.join("http.sock"))
}

pub type PeerUidChecker = Arc<dyn Fn(&tokio::net::UnixStream) -> io::Result<u32> + Send + Sync>;

pub struct UcredUnixListener {
    pub listener: tokio::net::UnixListener,
    pub expected_uid: u32,
    pub peer_uid_checker: Option<PeerUidChecker>,
}

impl axum::serve::Listener for UcredUnixListener {
    type Io = tokio::net::UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    tracing::warn!("http unix socket accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            let peer_uid = if let Some(ref checker) = self.peer_uid_checker {
                match checker(&stream) {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::warn!("http.sock peer cred check failed (seam): {e}");
                        continue;
                    }
                }
            } else {
                match stream.peer_cred() {
                    Ok(c) => c.uid(),
                    Err(e) => {
                        tracing::warn!("failed to get peer creds on http.sock: {e}");
                        continue;
                    }
                }
            };

            if peer_uid != self.expected_uid {
                tracing::warn!(
                    "http.sock rejected connection: UID mismatch {peer_uid} != {}",
                    self.expected_uid
                );
                continue;
            }

            return (stream, addr);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

pub fn bind_ucred_unix_listener(
    sock_path: &Path,
    expected_uid: u32,
    peer_uid_checker: Option<PeerUidChecker>,
) -> io::Result<UcredUnixListener> {
    if let Some(parent) = sock_path.parent() {
        if let Err(e) = crate::agent::ensure_secure_socket_dir(parent, expected_uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                e.to_string(),
            ));
        }
    }
    if sock_path.exists() {
        if std::os::unix::net::UnixStream::connect(sock_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "another server instance is actively listening on {}",
                    sock_path.display()
                ),
            ));
        }
        let _ = fs::remove_file(sock_path);
    }

    let listener = tokio::net::UnixListener::bind(sock_path)?;
    fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("failed to set permissions on {}: {e}", sock_path.display()),
        )
    })?;

    Ok(UcredUnixListener {
        listener,
        expected_uid,
        peer_uid_checker,
    })
}

pub fn http_request_unix(
    sock_path: &Path,
    method: &str,
    path_and_query: &str,
    body: Option<&str>,
) -> io::Result<(StatusCode, String)> {
    http_request_unix_within(
        sock_path,
        method,
        path_and_query,
        body,
        Duration::from_secs(5),
    )
}

/// As [`http_request_unix`], with `timeout` bounding each socket read and write.
/// An expired bound is `ErrorKind::TimedOut` naming the socket and the bound; the
/// request is never retried (a POST is not idempotent).
pub fn http_request_unix_within(
    sock_path: &Path,
    method: &str,
    path_and_query: &str,
    body: Option<&str>,
    timeout: Duration,
) -> io::Result<(StatusCode, String)> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let timed_out = |e: io::Error| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{method} {path_and_query} on {} timed out: no progress within {timeout:?}",
                sock_path.display()
            ),
        ),
        _ => e,
    };

    let mut stream = UnixStream::connect(sock_path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let req = if let Some(b) = body {
        format!(
            "{method} {path_and_query} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        )
    } else {
        format!(
            "{method} {path_and_query} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
    };
    stream.write_all(req.as_bytes()).map_err(timed_out)?;

    let mut resp_bytes = Vec::new();
    let mut buf = [0u8; 4096];
    let mut expected_len: Option<usize> = None;
    let mut header_len = 0;

    loop {
        let n = stream.read(&mut buf).map_err(timed_out)?;
        if n == 0 {
            break;
        }
        resp_bytes.extend_from_slice(&buf[..n]);

        if expected_len.is_none() {
            if let Some(idx) = resp_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                header_len = idx + 4;
                let header_str = String::from_utf8_lossy(&resp_bytes[..header_len]);
                for line in header_str.lines() {
                    let lower = line.to_ascii_lowercase();
                    if lower.starts_with("content-length:") {
                        if let Some(val_str) = line.split(':').nth(1) {
                            if let Ok(cl) = val_str.trim().parse::<usize>() {
                                expected_len = Some(cl);
                            }
                        }
                    }
                }
            }
        }

        if let Some(cl) = expected_len {
            if resp_bytes.len() >= header_len + cl {
                break;
            }
        }
    }

    if resp_bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed by server without response",
        ));
    }

    let resp_str = String::from_utf8_lossy(&resp_bytes);
    let status = if let Some(line) = resp_str.lines().next() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let code = parts[1].parse::<u16>().unwrap_or(500);
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    let body = if let Some(idx) = resp_str.find("\r\n\r\n") {
        resp_str[idx + 4..].to_string()
    } else if let Some(idx) = resp_str.find("\n\n") {
        resp_str[idx + 2..].to_string()
    } else {
        resp_str.to_string()
    };

    Ok((status, body))
}

pub fn http_get_unix(sock_path: &Path, path_and_query: &str) -> io::Result<(StatusCode, String)> {
    http_request_unix(sock_path, "GET", path_and_query, None)
}
