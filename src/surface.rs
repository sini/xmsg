//! The local messaging surface (A13): `list`, `send`, `reply` and `replies`, one
//! implementation behind HTTP, `agent.sock`, `register.sock` and MCP.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

use crate::error::AppError;
use crate::fed::FedListEntry;
use crate::http::{AppState, ResolvedTarget};
use crate::inbox;
use crate::mesh::Dest;
use crate::registry::Session;
use crate::storage::{self, MessageRecord, Origin, ReplyRecord, Reservation};

/// The longest `replies` wait, in seconds (A-12).
pub const MAX_WAIT_SECS: u64 = 60;

/// Wire schema version spoken between `xmsg mcp` and `xmsg serve` on `agent.sock`.
pub const MCP_SCHEMA_VERSION: u32 = 2;

/// What local delivery reads, borrowed from an `AppState` or a `FedState`.
pub struct Local<'a> {
    pub db: &'a Arc<Mutex<rusqlite::Connection>>,
    pub sessions_dirs: &'a [PathBuf],
    pub node_name: &'a str,
    pub agy_config: &'a crate::agy::AgyConfig,
    pub agy_store: &'a crate::agy::AgyStore,
    pub pi_store: &'a crate::pi::PiStore,
    pub pi_notify_tx: &'a broadcast::Sender<String>,
    pub svc_store: &'a crate::svc::SvcStore,
    pub svc_notify_tx: &'a broadcast::Sender<String>,
}

impl AppState {
    pub fn local(&self) -> Local<'_> {
        Local {
            db: &self.db,
            sessions_dirs: &self.sessions_dirs,
            node_name: &self.node_name,
            agy_config: &self.agy_config,
            agy_store: &self.agy_store,
            pi_store: &self.pi_store,
            pi_notify_tx: &self.pi_notify_tx,
            svc_store: &self.svc_store,
            svc_notify_tx: &self.svc_notify_tx,
        }
    }
}

impl crate::fed::FedState {
    pub fn local(&self) -> Local<'_> {
        Local {
            db: &self.db,
            sessions_dirs: &self.sessions_dirs,
            node_name: &self.node_name,
            agy_config: &self.agy_config,
            agy_store: &self.agy_store,
            pi_store: &self.pi_store,
            pi_notify_tx: &self.pi_notify_tx,
            svc_store: &self.svc_store,
            svc_notify_tx: &self.svc_notify_tx,
        }
    }
}

fn db_err(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

type PauseSlot = (
    tokio::sync::oneshot::Sender<String>,
    tokio::sync::oneshot::Receiver<()>,
);

static POST_DELIVER_PAUSE: std::sync::LazyLock<
    Mutex<std::collections::HashMap<String, PauseSlot>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Arms a one-shot pause on `node_name` right after `deliver` or `push_reply` wakes the
/// recipient and before `deliver_send` or `deliver_reply` completes or returns (XF2).
pub fn pause_after_deliver_for_test(
    node_name: &str,
) -> (
    tokio::sync::oneshot::Receiver<String>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    POST_DELIVER_PAUSE
        .lock()
        .unwrap()
        .insert(node_name.to_string(), (entered_tx, release_rx));
    (entered_rx, release_tx)
}

async fn run_post_deliver_pause(node_name: &str, id: &str) {
    let slot = POST_DELIVER_PAUSE
        .lock()
        .ok()
        .and_then(|mut g| g.remove(node_name));
    if let Some((entered_tx, release_rx)) = slot {
        let _ = entered_tx.send(id.to_string());
        let _ = release_rx.await;
    }
}

// -----------------------------------------------------------------------------
// Senders
// -----------------------------------------------------------------------------

/// Who is sending: an attested session or service (its inbox receives pushed replies,
/// A10), or an anonymous HTTP caller, who reads replies with `replies` (A15).
#[derive(Debug, Clone)]
pub enum Sender {
    Session(Session),
    Anonymous(String),
}

impl Sender {
    /// A registered service named `name`, as the leaf principal or a `register.sock` caller.
    pub fn service(name: &str) -> Sender {
        Sender::Session(service_session(name))
    }

    /// A12's label for this sender on `node`.
    pub fn label(&self, node: &str) -> Result<String, AppError> {
        match self {
            Sender::Session(s) => Ok(inbox::sender_label(
                node,
                &s.harness,
                &s.session_id,
                s.name.as_deref(),
            )),
            Sender::Anonymous(from) => inbox::sanitize_from(node, from),
        }
    }

    pub fn origin(&self, node: &str) -> Origin {
        match self {
            Sender::Session(s) if s.harness == "svc" => Origin::service(&s.session_id, node),
            Sender::Session(s) => Origin::instance(
                &s.session_id,
                node,
                s.name
                    .as_deref()
                    .and_then(inbox::clean_label)
                    .filter(|l| l != &s.session_id)
                    .as_deref(),
            ),
            Sender::Anonymous(from) => Origin::anonymous(from, node),
        }
    }

    /// The idempotency principal: the instance ID or service name, `anon:<from>` for an
    /// anonymous caller (A15).
    pub fn idempotency_principal(&self) -> String {
        match self {
            Sender::Session(s) => s.session_id.clone(),
            Sender::Anonymous(from) => format!("anon:{from}"),
        }
    }

    /// Where a reply is pushed: the sender's kind and ID, `None` for a sender with no
    /// inbox (A10 as amended by A-2).
    fn inbox(&self) -> (Option<String>, Option<String>) {
        match self {
            Sender::Session(s) => (Some(s.harness.clone()), Some(s.session_id.clone())),
            Sender::Anonymous(_) => (None, None),
        }
    }
}

/// The session a registered service acts as. Its ID is its name.
pub fn service_session(name: &str) -> Session {
    Session {
        session_id: name.to_string(),
        name: Some(name.to_string()),
        pid: 0,
        cwd: "/".to_string(),
        status: "idle".to_string(),
        kind: "daemon".to_string(),
        entrypoint: None,
        version: None,
        started_at: 0,
        updated_at: 0,
        harness: "svc".to_string(),
        registered: Some(true),
    }
}

/// The leaf principal's service name: the configured principal without a `svc:` prefix.
pub fn leaf_service_name(principal: &str) -> &str {
    principal.strip_prefix("svc:").unwrap_or(principal)
}

/// The session or service a local process acts as (A15, D-5): its ancestry, walked from
/// `pid` through the claim table, to a Claude instance's address, an agy or pi session, or
/// a registered service. Every surface that identifies a caller by pid reads this.
pub async fn trace_caller(state: &AppState, pid: u32) -> Result<Session, AppError> {
    let peer = crate::process::PeerCred::unpinned(0, pid);
    trace_caller_peer(state, &peer).await
}

/// Like [`trace_caller`], starting from a [`crate::process::PeerCred`] whose root pid may
/// be pinned by an `SO_PEERPIDFD` file descriptor.
pub async fn trace_caller_peer(
    state: &AppState,
    peer: &crate::process::PeerCred,
) -> Result<Session, AppError> {
    let _ = crate::claim::sync_claims(
        &state.db,
        &state.agy_config.proc_root,
        &state.sessions_dirs,
        &state.node_name,
    )
    .await;
    let db = state.db.lock().ok();
    crate::agent::resolve_caller_session_peer(
        &state.agy_config.proc_root,
        &state.sessions_dirs,
        &state.agy_config,
        &state.agy_store,
        &state.pi_store,
        &state.svc_store,
        db.as_deref(),
        peer,
    )
}

/// Parses one socket frame. A frame with fields `T` does not know is refused
/// `bad_request` naming every one of them (plan §6 D3), whatever their order.
pub fn parse_frame<T: serde::de::DeserializeOwned>(line: &str) -> Result<T, AppError> {
    let bad = |e: serde_json::Error| AppError::BadRequest(e.to_string());
    let mut value: serde_json::Value = serde_json::from_str(line).map_err(bad)?;
    let mut unknown = Vec::new();
    loop {
        let err = match serde_json::from_value::<T>(value.clone()) {
            Ok(frame) if unknown.is_empty() => return Ok(frame),
            Ok(_) => break,
            Err(e) => e,
        };
        let msg = err.to_string();
        let field = msg
            .strip_prefix("unknown field `")
            .and_then(|r| r.split_once('`'))
            .map(|(f, _)| f.to_string());
        match field {
            Some(f) if value.as_object_mut().and_then(|o| o.remove(&f)).is_some() => {
                unknown.push(format!("`{f}`"))
            }
            _ if unknown.is_empty() => return Err(AppError::BadRequest(msg)),
            _ => break,
        }
    }
    Err(AppError::BadRequest(format!(
        "unknown field{} {}",
        if unknown.len() > 1 { "s" } else { "" },
        unknown.join(", ")
    )))
}

// -----------------------------------------------------------------------------
// The address grammar
// -----------------------------------------------------------------------------

/// Splits a `to` into its local part and its `@node`, if any. An address has at most one
/// `@`; the hop `x@dest@hub` is not in the grammar (A3, A9, B4).
pub fn parse_to(to: &str) -> Result<(&str, Option<&str>), AppError> {
    let to = to.trim();
    if to.is_empty() {
        return Err(AppError::BadRequest("'to' must not be empty".to_string()));
    }
    if to.contains(" · ") || to.contains('·') {
        return Err(AppError::BadRequest(
            "'to' contains ' · '; a label is not an address. Use the header's 'ref=' address instead".to_string(),
        ));
    }
    match to.matches('@').count() {
        0 => Ok((to, None)),
        1 => {
            let (r, node) = to.split_once('@').expect("one '@'");
            if r.is_empty() || node.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "'{to}' is not an address: expected <id or name>[@<node>]"
                )));
            }
            Ok((r, Some(node)))
        }
        _ => Err(AppError::BadRequest(format!(
            "'{to}' has more than one '@': an address is <id or name>[@<node>], and the route is the server's"
        ))),
    }
}

// -----------------------------------------------------------------------------
// list
// -----------------------------------------------------------------------------

/// Default `within` window for `list` with `status: "inactive"` (24 hours).
pub const DEFAULT_INACTIVE_WITHIN_SECS: u64 = 86_400;

/// One entry of `list` (A13, A-12, A16, XL1): its address, kind, label and status (`live`,
/// `parked` or `closed`), the node holding it, the user it belongs to, and its timestamp
/// (`registered_at` when live, `last_seen` when inactive).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub address: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub status: String,
    pub node: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
}

/// What `list` returns: the recipients, and how each node asked answered (A-12).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListResult {
    pub recipients: Vec<Recipient>,
    pub nodes: Vec<crate::fed::NodeStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub node: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub within: Option<u64>,
    #[serde(default)]
    pub host: Option<String>,
}

fn live_entry(
    id: &str,
    service: bool,
    label: Option<String>,
    user: &str,
    registered_at: i64,
) -> FedListEntry {
    FedListEntry {
        id: id.to_string(),
        kind: if service { "service" } else { "instance" }.to_string(),
        label: if service {
            None
        } else {
            label
                .as_deref()
                .and_then(inbox::clean_label)
                .filter(|l| l != id)
        },
        status: "live".to_string(),
        user: user.to_string(),
        registered_at: Some(registered_at),
        last_seen: None,
    }
}

fn inactive_entry(id: &str, status: &str, user: &str, last_seen: i64) -> FedListEntry {
    FedListEntry {
        id: id.to_string(),
        kind: "instance".to_string(),
        label: None,
        status: status.to_string(),
        user: user.to_string(),
        registered_at: None,
        last_seen: Some(last_seen),
    }
}

fn recipient(e: FedListEntry, node: &str) -> Recipient {
    Recipient {
        address: format!("{}@{node}", e.id),
        kind: e.kind,
        label: e.label,
        status: e.status,
        node: node.to_string(),
        user: e.user,
        registered_at: e.registered_at,
        last_seen: e.last_seen,
    }
}

/// The recipients the caller may see (A4, XL1): this node's and every peer's, each peer
/// asked concurrently and bounded by the list timeout (A-1, D14). `node` asks only that
/// node. Default `list` (`status` omitted or `"live"`) returns only live recipients;
/// `status: "inactive"` returns parked and closed instances seen within `within` seconds
/// (default 24h, capped at `reply_ttl`).
pub async fn list(state: &AppState, query: &ListQuery) -> Result<ListResult, AppError> {
    if query.host.is_some() {
        return Err(AppError::BadRequest(
            "unknown parameter 'host'; use 'node' instead (or omit it to list all nodes)".to_string(),
        ));
    }
    if let Some(kind) = query.kind.as_deref() {
        if kind != "service" && kind != "instance" {
            return Err(AppError::BadRequest(format!(
                "kind '{kind}' is not 'service' or 'instance'"
            )));
        }
    }
    let inactive_mode = match query.status.as_deref() {
        None | Some("live") => false,
        Some("inactive") => true,
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "status '{other}' is not 'live' or 'inactive'"
            )));
        }
    };
    if !inactive_mode && query.within.is_some() {
        return Err(AppError::BadRequest(
            "'within' is only valid when status is 'inactive'".to_string(),
        ));
    }
    let max_within = state.reply_ttl.as_secs();
    let within_secs = query
        .within
        .unwrap_or(DEFAULT_INACTIVE_WITHIN_SECS)
        .min(max_within);

    let node = state.node_name.as_str();
    let fed_state = state.fed_state.as_ref();
    let (local, peers): (bool, Vec<String>) = match (query.node.as_deref(), fed_state) {
        (Some(n), _) if n == node => (true, Vec::new()),
        (Some(n), Some(fs)) if fs.current_peers().contains_name(n) => (
            false,
            vec![fs.current_peers().key_for(n).unwrap_or(n).to_string()],
        ),
        (Some(n), _) => return Err(AppError::UnknownPeer(n.to_string())),
        (None, Some(fs)) => (true, fs.current_peers().keys().cloned().collect()),
        (None, None) => (true, Vec::new()),
    };

    let mut recipients = Vec::new();
    let mut nodes = Vec::new();
    if local {
        let user = match fed_state {
            Some(fs) => crate::fed::own_user(fs),
            None => crate::node::own_user(None),
        };
        let local_entries = if inactive_mode {
            listing_inactive(&state.local(), state.reply_ttl, within_secs, &user).await?
        } else {
            listing_live(&state.local(), state.reply_ttl, &user).await?
        };
        for e in local_entries {
            recipients.push(recipient(e, node));
        }
        nodes.push(crate::fed::NodeStatus::ok(node));
    }
    if let Some(fs) = fed_state {
        let mut asked = tokio::task::JoinSet::new();
        for key in peers {
            let fs = fs.clone();
            asked.spawn(async move {
                let (entries, status) = crate::fed::list_peer(&fs, &key).await;
                (key, entries, status)
            });
        }
        let mut answers = Vec::new();
        while let Some(res) = asked.join_next().await {
            answers.push(res.map_err(|e| AppError::Internal(e.to_string()))?);
        }
        answers.sort_by(|a, b| a.0.cmp(&b.0));
        let now = storage::now_epoch_secs();
        let cutoff = now.saturating_sub(within_secs as i64);
        for (key, entries, status) in answers {
            for e in entries {
                if inactive_mode {
                    // Older peers do not stamp `last_seen` on parked entries, so they
                    // cannot be windowed and are excluded from inactive results (XL1).
                    if e.status != "live" && e.last_seen.is_some_and(|ts| ts >= cutoff) {
                        recipients.push(recipient(e, &key));
                    }
                } else if e.status == "live" {
                    recipients.push(recipient(e, &key));
                }
            }
            nodes.push(status);
        }
    }

    recipients.retain(|r| {
        query.kind.as_deref().is_none_or(|k| r.kind == k)
            && query.name.as_deref().is_none_or(|n| {
                let local = r.address.rsplit_once('@').map_or("", |(l, _)| l);
                r.label.as_deref() == Some(n) || (r.kind == "service" && local == n)
            })
    });
    Ok(ListResult { recipients, nodes })
}

/// This node's live recipients (XL1): live Claude, agy and pi instances, plugin sessions
/// (opencode, hermes), and registered services, each carrying its `registered_at`. Also
/// prunes `instance_seen` rows older than `reply_ttl`.
pub(crate) async fn listing_live(
    local: &Local<'_>,
    reply_ttl: Duration,
    user: &str,
) -> Result<Vec<FedListEntry>, AppError> {
    let query = crate::registry::SessionsQuery::default();
    let pairs = crate::claim::sync_claims(
        local.db,
        &local.agy_config.proc_root,
        local.sessions_dirs,
        local.node_name,
    )
    .await?;
    {
        let db = local.db.lock().map_err(db_err)?;
        let _ = storage::purge_instance_seen(&db, storage::now_epoch_secs(), reply_ttl.as_secs() as i64);
    }
    let mut out: Vec<FedListEntry> = pairs
        .into_iter()
        .map(|(claim, e)| live_entry(&claim.address(), false, e.name, user, claim.created_at))
        .collect();
    for s in crate::agy::list_agy_sessions(local.agy_config, local.agy_store, &query) {
        out.push(live_entry(&s.session_id, false, None, user, s.started_at as i64));
    }
    let proc_root = &local.agy_config.proc_root;
    for s in crate::pi::list_pi_sessions(proc_root, local.pi_store, &query) {
        out.push(live_entry(&s.session_id, false, s.name, user, s.started_at as i64));
    }
    let plugin_sessions =
        crate::plugin::sessions(&*local.db.lock().map_err(db_err)?).map_err(db_err)?;
    for s in plugin_sessions {
        out.push(live_entry(&s.session_id, false, s.name, user, s.started_at as i64));
    }
    for s in crate::svc::list_svc_sessions(proc_root, local.svc_store, &query) {
        out.push(live_entry(&s.session_id, true, None, user, s.started_at as i64));
    }
    Ok(out)
}

/// This node's inactive recipients within `within_secs` (capped at `reply_ttl`, XL1):
/// parked Claude/agy instances and closed pi/plugin sessions, each carrying `last_seen`.
pub(crate) async fn listing_inactive(
    local: &Local<'_>,
    reply_ttl: Duration,
    within_secs: u64,
    user: &str,
) -> Result<Vec<FedListEntry>, AppError> {
    let live = listing_live(local, reply_ttl, user).await?;
    let now = storage::now_epoch_secs();
    let ttl_secs = reply_ttl.as_secs() as i64;
    let capped_within = (within_secs as i64).min(ttl_secs);
    let inactive = {
        let db = local.db.lock().map_err(db_err)?;
        storage::inactive_instances(&db, now, ttl_secs, capped_within).map_err(db_err)?
    };
    let mut out = Vec::new();
    for item in inactive {
        if !live.iter().any(|e| e.id == item.id) {
            out.push(inactive_entry(&item.id, &item.status, user, item.last_seen));
        }
    }
    Ok(out)
}

/// This node's full recipient set for federation and mesh/handoff resolution (A4, A-12,
/// A16, A14, XL1): live recipients with `registered_at`, plus parked instances within their
/// parked lifetime with `last_seen`. A pi or plugin session is never parked (AM-9).
pub(crate) async fn listing(
    local: &Local<'_>,
    reply_ttl: Duration,
    user: &str,
) -> Result<Vec<FedListEntry>, AppError> {
    let mut out = listing_live(local, reply_ttl, user).await?;
    let parked = {
        let db = local.db.lock().map_err(db_err)?;
        storage::parked_instances(&db, storage::now_epoch_secs(), reply_ttl.as_secs() as i64)
            .map_err(db_err)?
    };
    for (id, last_live) in parked {
        if !out.iter().any(|e| e.id == id) {
            out.push(inactive_entry(&id, "parked", user, last_live));
        }
    }
    Ok(out)
}

// -----------------------------------------------------------------------------
// Local delivery
// -----------------------------------------------------------------------------

fn agy_has_creds(store: &crate::agy::AgyStore, session: &Session) -> bool {
    let store_lock = store.read().unwrap();
    store_lock
        .get(&session.session_id)
        .or_else(|| {
            store_lock.values().find(|info| {
                info.conversation_id == session.session_id
                    || session.name.as_deref() == Some(&info.conversation_id)
            })
        })
        .map(|info| info.has_credentials())
        .unwrap_or(false)
}

/// Delivers a message to a resolved local target. Returns the target's ID, its harness
/// and the outcome.
pub(crate) async fn deliver(
    local: &Local<'_>,
    target: &ResolvedTarget,
    from_name: &str,
    message_id: &str,
    body: &str,
    origin: Origin,
) -> Result<(String, &'static str, &'static str), AppError> {
    let ref_part = match origin.machine_ref() {
        Some(r) => format!(" ref={r}"),
        None => String::new(),
    };
    let envelope_text = || {
        format!(
            "[xmsg] from={from_name}{ref_part} message_id={message_id} — reply with the xmsg reply tool (tools: send, reply, list, replies)\n\n{body}"
        )
    };
    // A queued message shows when it was sent (A14).
    let sent = storage::utc_rfc3339(storage::now_epoch_secs());
    match target {
        ResolvedTarget::Parked {
            session,
            expires_at,
        } => {
            let queued = storage::QueuedMessage {
                id: message_id.to_string(),
                instance_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                expires_at: *expires_at,
                from_name: from_name.to_string(),
                body: format!(
                    "{body}\n\n[xmsg]{ref_part} message_id={message_id} sent={sent} — reply with the xmsg reply tool (tools: send, reply, list, replies)"
                ),
            };
            let db = local.db.lock().map_err(db_err)?;
            storage::insert_queued(&db, &queued).map_err(db_err)?;
            Ok((session.session_id.clone(), "claude", "queued"))
        }
        ResolvedTarget::Claude(session, socket_path) => {
            let body_with_footer = format!(
                "{body}\n\n[xmsg]{ref_part} message_id={message_id} — reply with the xmsg reply tool (tools: send, reply, list, replies)"
            );
            let line = inbox::encode_transport_line(from_name, &body_with_footer)?;
            inbox::deliver_to_socket(socket_path, &line).await?;
            Ok((session.session_id.clone(), "claude", "delivered"))
        }
        ResolvedTarget::Agy(session) => {
            if agy_has_creds(local.agy_store, session) {
                crate::agy::deliver_agy(
                    local.agy_config,
                    local.agy_store,
                    session,
                    from_name,
                    origin.machine_ref().as_deref(),
                    message_id,
                    body,
                )
                .await?;
                return Ok((session.session_id.clone(), "agy", "delivered"));
            }
            let agy_msg = storage::AgyPendingMessage {
                id: message_id.to_string(),
                session_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                from_name: from_name.to_string(),
                bytes: body.len(),
                text: body.to_string(),
                envelope: format!(
                    "[xmsg] from={from_name}{ref_part} message_id={message_id} sent={sent} — reply with the xmsg reply tool (tools: send, reply, list, replies)\n\n{body}"
                ),
                delivered_at: None,
            };
            let db = local.db.lock().map_err(db_err)?;
            storage::insert_agy_message(&db, &agy_msg).map_err(db_err)?;
            Ok((session.session_id.clone(), "agy", "queued"))
        }
        ResolvedTarget::Pi(session) => {
            let pi_msg = storage::PiPendingMessage {
                id: message_id.to_string(),
                session_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                from_name: from_name.to_string(),
                bytes: body.len(),
                text: body.to_string(),
                envelope: envelope_text(),
                delivered_at: None,
            };
            {
                let db = local.db.lock().map_err(db_err)?;
                if !storage::insert_pi_message(&db, &pi_msg).map_err(db_err)? {
                    return Err(AppError::ServiceUnavailable(
                        "pi session message queue is full".to_string(),
                    ));
                }
            }
            let _ = local.pi_notify_tx.send(session.session_id.clone());
            let harness = crate::plugin::harness(&session.harness).unwrap_or("pi");
            // `delivered` once the harness acks it (HA3): `storage::ack_pi_message`.
            Ok((session.session_id.clone(), harness, "queued"))
        }
        ResolvedTarget::Svc(session) => {
            let svc_msg = storage::SvcPendingMessage {
                id: message_id.to_string(),
                session_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                from_name: from_name.to_string(),
                bytes: body.len(),
                text: body.to_string(),
                envelope: envelope_text(),
                delivered_at: None,
                origin,
                in_reply_to: None,
            };
            {
                let db = local.db.lock().map_err(db_err)?;
                if !storage::insert_svc_message(&db, &svc_msg).map_err(db_err)? {
                    return Err(AppError::ServiceUnavailable(
                        "svc session message queue is full".to_string(),
                    ));
                }
            }
            let _ = local.svc_notify_tx.send(session.session_id.clone());
            // `delivered` once the service acks it: `storage::ack_svc_message`.
            Ok((session.session_id.clone(), "svc", "queued"))
        }
    }
}

/// Pushes a reply into the inbox of a local sender (A10): a Claude, agy or pi session, or
/// a registered service, whose push lands in the inbox it long-polls with `in_reply_to`.
/// Returns `pushed`, `sender_gone` or `push_failed`.
#[allow(clippy::too_many_arguments)]
pub async fn push_reply(
    local: &Local<'_>,
    ret_harness: &str,
    ret_session_id: &str,
    in_reply_to: &str,
    reply_id: &str,
    replier_label: &str,
    replier_origin: Origin,
    text: &str,
) -> &'static str {
    let envelope = format!(
        "[xmsg] reply to message_id={in_reply_to} — message_id={reply_id}; reply with the xmsg reply tool (tools: send, reply, list, replies)\n\n{text}"
    );
    match ret_harness {
        "claude" => {
            match crate::claim::resolve_claude_session_and_deliver(
                local.db,
                &local.agy_config.proc_root,
                local.sessions_dirs,
                local.node_name,
                ret_session_id,
            )
            .await
            {
                Ok((_session, socket_path)) if socket_path.exists() => {
                    let Ok(line) = inbox::encode_transport_line(replier_label, &envelope) else {
                        return "push_failed";
                    };
                    match inbox::deliver_to_socket(&socket_path, &line).await {
                        Ok(()) => "pushed",
                        Err(e) => {
                            let err = e.to_string();
                            if err.contains("Connection refused")
                                || err.contains("No such file or directory")
                            {
                                "sender_gone"
                            } else {
                                "push_failed"
                            }
                        }
                    }
                }
                Ok(_) | Err(AppError::Gone { .. }) | Err(AppError::NotFound(_)) => "sender_gone",
                Err(_) => "push_failed",
            }
        }
        "agy" => {
            match crate::agy::resolve_agy_session(local.agy_config, local.agy_store, ret_session_id)
            {
                Ok(Some(session)) if agy_has_creds(local.agy_store, &session) => {
                    match crate::agy::deliver_agy_envelope(
                        local.agy_config,
                        local.agy_store,
                        &session,
                        replier_label,
                        &envelope,
                    )
                    .await
                    {
                        Ok(()) => "pushed",
                        Err(AppError::Gone { .. }) | Err(AppError::CredentialsStale(_)) => {
                            "sender_gone"
                        }
                        Err(_) => "push_failed",
                    }
                }
                Ok(Some(session)) => {
                    let agy_msg = storage::AgyPendingMessage {
                        id: reply_id.to_string(),
                        session_id: session.session_id.clone(),
                        created_at: storage::now_epoch_secs(),
                        from_name: replier_label.to_string(),
                        bytes: text.len(),
                        text: text.to_string(),
                        envelope,
                        delivered_at: None,
                    };
                    match local.db.lock() {
                        Ok(db) if storage::insert_agy_message(&db, &agy_msg).is_ok() => "pushed",
                        _ => "push_failed",
                    }
                }
                Ok(None) => "sender_gone",
                Err(_) => "push_failed",
            }
        }
        h if h == "pi" || crate::plugin::harness(h).is_some() => {
            let found = if ret_harness == "pi" {
                crate::pi::resolve_pi_session(
                    &local.agy_config.proc_root,
                    local.pi_store,
                    ret_session_id,
                )
            } else {
                local
                    .db
                    .lock()
                    .map_err(db_err)
                    .and_then(|c| crate::plugin::session(&c, ret_session_id).map_err(db_err))
            };
            match found {
                Ok(Some(session)) => {
                    let pi_msg = storage::PiPendingMessage {
                        id: reply_id.to_string(),
                        session_id: session.session_id.clone(),
                        created_at: storage::now_epoch_secs(),
                        from_name: replier_label.to_string(),
                        bytes: text.len(),
                        text: text.to_string(),
                        envelope,
                        delivered_at: None,
                    };
                    let inserted = match local.db.lock() {
                        Ok(db) => storage::insert_pi_message(&db, &pi_msg).unwrap_or(false),
                        Err(_) => false,
                    };
                    if inserted {
                        let _ = local.pi_notify_tx.send(session.session_id);
                        "pushed"
                    } else {
                        "push_failed"
                    }
                }
                Ok(None) => "sender_gone",
                Err(_) => "push_failed",
            }
        }
        "svc" => {
            match crate::svc::resolve_svc_session(
                &local.agy_config.proc_root,
                local.svc_store,
                ret_session_id,
            ) {
                Ok(Some(session)) => {
                    let svc_msg = storage::SvcPendingMessage {
                        id: reply_id.to_string(),
                        session_id: session.session_id.clone(),
                        created_at: storage::now_epoch_secs(),
                        from_name: replier_label.to_string(),
                        bytes: text.len(),
                        text: text.to_string(),
                        envelope,
                        delivered_at: None,
                        origin: replier_origin,
                        in_reply_to: Some(in_reply_to.to_string()),
                    };
                    let inserted = match local.db.lock() {
                        Ok(db) => storage::insert_svc_message(&db, &svc_msg).unwrap_or(false),
                        Err(_) => false,
                    };
                    if inserted {
                        let _ = local.svc_notify_tx.send(session.session_id);
                        "pushed"
                    } else {
                        "push_failed"
                    }
                }
                Ok(None) => "sender_gone",
                Err(_) => "push_failed",
            }
        }
        _ => "sender_gone",
    }
}

// -----------------------------------------------------------------------------
// send
// -----------------------------------------------------------------------------

/// What `send` returns (A13): the message ID, the resolved address (`id@node` for an
/// instance, `name@node` for a service) and the outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SendResult {
    pub message_id: String,
    pub address: String,
    pub outcome: String,
}

fn check_idempotency_key(key: &str) -> Result<(), AppError> {
    if key.is_empty() || key.len() > 128 || key.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest(
            "invalid idempotency_key: must be 1..128 non-control chars".to_string(),
        ));
    }
    Ok(())
}

/// How long a send or reply whose key another one holds waits for that one to settle,
/// before it answers with the holder's ID and the outcome `pending`.
pub const IN_FLIGHT_WAIT: Duration = Duration::from_secs(2);

/// Polls `reserve` until this caller holds the key, the holder settled (`waiting` is
/// false), or `IN_FLIGHT_WAIT` ends.
// ponytail: polls every 50 ms; a per-key notify channel if the wait ever shows up.
async fn reserve_or_wait<T>(
    reserve: impl Fn() -> Result<Reservation<T>, AppError>,
    waiting: impl Fn(&T) -> bool,
) -> Result<Reservation<T>, AppError> {
    let deadline = tokio::time::Instant::now() + IN_FLIGHT_WAIT;
    loop {
        let held = reserve()?;
        match &held {
            Reservation::Held(r) if waiting(r) && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            _ => return Ok(held),
        }
    }
}

/// Sends `text` to `to` from `sender`. An idempotency key, the sender's (A15), is
/// reserved with the message ID before anything is delivered: a send with a key another
/// send holds returns that send's result once it settles, or its message ID with the
/// outcome `pending` while it is still being delivered, and never delivers again. A key
/// whose send failed is delivered again, under the same message ID.
pub async fn send(
    state: &Arc<AppState>,
    sender: &Sender,
    to: &str,
    text: &str,
    idempotency_key: Option<&str>,
) -> Result<SendResult, AppError> {
    if text.is_empty() {
        return Err(AppError::BadRequest("text must not be empty".to_string()));
    }
    if text.len() > state.max_body {
        return Err(AppError::PayloadTooLarge {
            size: text.len(),
            limit: state.max_body,
        });
    }
    parse_to(to)?;
    let from_name = sender.label(&state.node_name)?;
    let principal = sender.idempotency_principal();

    let message_id = match idempotency_key {
        None => ulid::Ulid::new().to_string(),
        Some(key) => {
            check_idempotency_key(key)?;
            let fresh = ulid::Ulid::new().to_string();
            let ttl = state.idempotency_ttl.as_secs();
            let held = reserve_or_wait(
                || {
                    let db = state.db.lock().map_err(db_err)?;
                    storage::reserve_idempotency_key(
                        &db, &principal, key, text, to, &from_name, &fresh, ttl,
                    )
                    .map_err(db_err)
                },
                |r| r.body == text && r.to_ref == to && r.outcome == storage::KEY_PENDING,
            )
            .await?;
            match held {
                Reservation::Mine(id) => id,
                Reservation::Held(r) if r.body != text || r.to_ref != to => {
                    return Err(AppError::Conflict(format!(
                        "idempotency key '{key}' was already used with a different message body or recipient"
                    )))
                }
                Reservation::Held(r) => {
                    // The key follows its message's record, which a later delivery (an ack,
                    // a drained queue) moves from `queued` to `delivered`.
                    let outcome = match r.outcome.as_str() {
                        "queued" => state
                            .db
                            .lock()
                            .map_err(db_err)
                            .and_then(|db| storage::get_message(&db, &r.message_id).map_err(db_err))?
                            .map_or(r.outcome, |m| m.outcome),
                        _ => r.outcome,
                    };
                    return Ok(SendResult {
                        message_id: r.message_id,
                        address: r.session_id,
                        outcome,
                    });
                }
            }
        }
    };

    // Delivered in a task of its own, so a caller that hangs up mid-send cannot leave its
    // key reserved and unsettled: the send runs to its outcome, and the key records it.
    let task = {
        let (state, sender, to, text) = (
            state.clone(),
            sender.clone(),
            to.to_string(),
            text.to_string(),
        );
        let key = idempotency_key.map(str::to_string);
        tokio::spawn(async move {
            let res = deliver_send(&state, &sender, &to, &text, &from_name, message_id).await;
            if let Some(key) = key {
                let (address, outcome) = match &res {
                    Ok(r) => (r.address.as_str(), r.outcome.as_str()),
                    Err(_) => ("", storage::KEY_FAILED),
                };
                let settled = state.db.lock().map_err(db_err).and_then(|db| {
                    storage::settle_idempotency_key(&db, &principal, &key, address, outcome)
                        .map_err(db_err)
                });
                if let Err(e) = settled {
                    tracing::warn!(target: "xmsg", message_id = %res.as_ref().map_or("", |r| r.message_id.as_str()), "idempotency key not settled: {e}");
                }
            }
            res
        })
    };
    task.await.map_err(|e| AppError::Internal(e.to_string()))?
}

/// `send`'s delivery, under its reserved `message_id`.
async fn deliver_send(
    state: &AppState,
    sender: &Sender,
    to: &str,
    text: &str,
    from_name: &str,
    message_id: String,
) -> Result<SendResult, AppError> {
    let (target_ref, node) = parse_to(to)?;
    let from_name = from_name.to_string();
    let (ret_harness, ret_session_id) = sender.inbox();
    let now = storage::now_epoch_secs();

    // `@node` scopes resolution to that node; a bare reference resolves over the view (XA6).
    let mut dest = match (node, state.fed_state.as_ref()) {
        (Some(n), _) if n == state.node_name => Dest::Local,
        (Some(n), Some(fs)) => {
            let peers = fs.current_peers();
            let is_direct = if let Some(p) = peers.get(n) {
                p.leaf || !p.address.is_empty()
            } else {
                peers
                    .admitted_clients
                    .read()
                    .ok()
                    .is_some_and(|adm| adm.contains_key(n))
            };

            if is_direct {
                Dest::Peer {
                    node: peers.key_for(n).unwrap_or(n).to_string(),
                    key: target_ref.to_string(),
                    cached: false,
                    id: false,
                }
            } else if let Some(hub_peer) = peers.default_route_link() {
                let wire_node = peers
                    .key_for(n)
                    .and_then(|k| peers.canonical_name(k))
                    .unwrap_or(n);
                Dest::Peer {
                    node: hub_peer.name.clone(),
                    key: format!("{target_ref}@{wire_node}"),
                    cached: false,
                    id: false,
                }
            } else {
                return Err(AppError::UnknownPeer(n.to_string()));
            }
        }
        (Some(n), _) => return Err(AppError::UnknownPeer(n.to_string())),
        (None, Some(fs)) => crate::mesh::resolve(state, fs, target_ref).await?,
        (None, None) => Dest::Local,
    };

    // The record is written before anything is delivered, so a failure to write it fails
    // the send with nothing delivered; once delivered, its completion is bookkeeping that
    // cannot fail the send (a key settled `failed` would deliver it again).
    let session_id_of = |address: &str| {
        address
            .rsplit_once('@')
            .map_or(address, |(id, _)| id)
            .to_string()
    };
    {
        let db = state.db.lock().map_err(db_err)?;
        storage::upsert_message(
            &db,
            &MessageRecord {
                id: message_id.clone(),
                created_at: now,
                session_id: String::new(),
                from_name: from_name.clone(),
                bytes: text.len(),
                outcome: storage::KEY_PENDING.to_string(),
                recipient_harness: String::new(),
                return_harness: ret_harness.clone(),
                return_session_id: ret_session_id.clone(),
                thread_id: message_id.clone(),
                return_host: None,
            },
        )
        .map_err(db_err)?;
    }
    let delivered: Result<_, AppError> = async {
        Ok(loop {
            let Dest::Peer {
                node: peer_key,
                key,
                cached,
                id,
            } = dest
            else {
                let target = crate::http::resolve_target_session(state, target_ref).await?;
                {
                    let db = state.db.lock().map_err(db_err)?;
                    storage::record_message_recipient(
                        &db,
                        &message_id,
                        &target.session().session_id,
                        target.recipient_harness(),
                    )
                    .map_err(db_err)?;
                }
                let (id, harness, outcome) = deliver(
                    &state.local(),
                    &target,
                    &from_name,
                    &message_id,
                    text,
                    sender.origin(&state.node_name),
                )
                .await?;
                run_post_deliver_pause(&state.node_name, &message_id).await;
                break (
                    format!("{id}@{}", state.node_name),
                    harness.to_string(),
                    outcome.to_string(),
                    None,
                );
            };
            let fed_state = state
                .fed_state
                .as_ref()
                .ok_or_else(|| AppError::UnknownPeer(peer_key.clone()))?
                .clone();
            let peers = fed_state.current_peers();
            let leaf = peers.get(&peer_key).is_some_and(|p| p.leaf);
            if let Ok(db) = state.db.lock() {
                let _ = storage::record_message_recipient(&db, &message_id, &key, "fed");
                if !leaf {
                    let _ = storage::insert_outbound(
                        &db,
                        &message_id,
                        &peer_key,
                        &format!("{key}@{peer_key}"),
                        storage::KEY_PENDING,
                        now,
                    );
                }
            }
            let envelope = crate::fed::FedEnvelope {
                v: crate::fed::WIRE_VERSION,
                id: message_id.clone(),
                // Its node is attested by the receiver (N-2).
                origin: sender.origin(&state.node_name),
                to: crate::fed::FedTarget { r#ref: key.clone() },
                body: text.to_string(),
                thread_id: message_id.clone(),
                created_at: now,
                forwarded: None,
            };
            let resp = match crate::fed::send_federated_message_with(
                &fed_state, &peer_key, &envelope, cached,
            )
            .await
            {
                Ok(resp) => resp,
                Err(e) if node.is_none() => {
                    if let Ok(db) = state.db.lock() {
                        let _ = storage::delete_outbound(&db, &message_id);
                    }
                    // A failed delivery invalidates the location, and a cache-routed send
                    // is resolved again, without the cache (A-12, gate v0 C9).
                    crate::mesh::forget(state, &key);
                    if !cached {
                        return Err(e);
                    }
                    dest = crate::mesh::resolve(state, &fed_state, target_ref).await?;
                    continue;
                }
                Err(e) => {
                    if let Ok(db) = state.db.lock() {
                        let _ = storage::delete_outbound(&db, &message_id);
                    }
                    return Err(e);
                }
            };
            let outcome = resp.outcome.unwrap_or_else(|| "delivered".to_string());
            // A live listing that took the message is cached, whether delivered or held for
            // a live plugin or pi session's ack; a leaf's mailbox is not a live listing. Only
            // a fresh resolution is cached, so a location is at most the TTL old (A-12).
            if id && !cached && !leaf {
                crate::mesh::remember(state, &key, &peer_key);
            }
            let address = match node {
                Some(n) => format!("{}@{n}", resp.session_id),
                None => format!("{}@{peer_key}", resp.session_id),
            };
            if let Ok(db) = state.db.lock() {
                let _ = storage::record_message_recipient(
                    &db,
                    &message_id,
                    &session_id_of(&address),
                    "fed",
                );
                let _ =
                    storage::insert_outbound(&db, &message_id, &peer_key, &address, &outcome, now);
                let _ = storage::update_outbound_outcome(&db, &message_id, &outcome);
                let _ = storage::update_outbound_target(&db, &message_id, &address);
                if node.is_none() {
                    // Resolved here: the record holds the recipient's own key (XA5's reply rule).
                    let _ = storage::mark_outbound_resolved(&db, &message_id);
                }
            }
            // A-2: the outbound reply poller is armed by the sender's kind.
            if ret_harness.is_some()
                && peers
                    .get(&peer_key)
                    .is_some_and(|p| p.is_outbound())
            {
                crate::fed::spawn_outbound_reply_poller(
                    fed_state.clone(),
                    peer_key.clone(),
                    message_id.clone(),
                );
            }
            run_post_deliver_pause(&state.node_name, &message_id).await;
            break (
                address,
                "fed".to_string(),
                outcome,
                Some(state.node_name.clone()),
            );
        })
    }
    .await;
    let (address, _recipient_harness, outcome, return_host) = match delivered {
        Ok(d) => d,
        Err(e) => {
            if let Err(de) = state
                .db
                .lock()
                .map_err(db_err)
                .and_then(|db| {
                    let _ = storage::delete_outbound(&db, &message_id);
                    storage::delete_message(&db, &message_id).map_err(db_err)
                })
            {
                tracing::warn!(target: "xmsg", message_id = %message_id, "undelivered message's record not removed: {de}");
            }
            return Err(e);
        }
    };
    match state.db.lock() {
        Ok(db) => {
            if let Err(e) = storage::complete_message(
                &db,
                &message_id,
                &outcome,
                return_host.as_deref(),
            ) {
                tracing::warn!(target: "xmsg", message_id = %message_id, "delivered message's record not completed: {e}");
            }
            let _ = storage::purge_idempotency_keys(&db, state.idempotency_ttl.as_secs());
            let ttl = state.reply_ttl.as_secs();
            let _ = storage::purge_messages(&db, ttl);
            let _ = storage::purge_replies(&db, ttl);
            let _ = storage::purge_pi_messages(&db, ttl);
            let _ = storage::purge_agy_messages(&db, ttl);
            let _ = storage::purge_svc_messages(&db, ttl);
            let _ = storage::purge_peer_mailbox(&db, ttl);
            let _ = storage::purge_forwarded_messages(&db, ttl);
            let _ = storage::purge_instance_queue(&db, ttl);
            let _ = storage::purge_instance_seen(&db, storage::now_epoch_secs(), ttl as i64);
        }
        Err(e) => {
            tracing::warn!(target: "xmsg", message_id = %message_id, "delivered message's record not completed: {e}");
        }
    }

    // Invariant: message bodies are never logged.
    tracing::info!(
        target: "xmsg",
        message_id = %message_id,
        address = %address,
        from = %from_name,
        bytes = text.len(),
        outcome = %outcome
    );
    Ok(SendResult {
        message_id,
        address,
        outcome,
    })
}

// -----------------------------------------------------------------------------
// reply
// -----------------------------------------------------------------------------

async fn push_federated_reply(
    state: &AppState,
    caller: &Session,
    ret_host: &str,
    in_reply_to: &str,
    reply_id: &str,
    text: &str,
) -> &'static str {
    let Some(fed_state) = &state.fed_state else {
        return "push_failed";
    };
    let replier = Sender::Session(caller.clone()).origin(&state.node_name);
    let envelope = crate::fed::FedReplyEnvelope {
        v: crate::fed::WIRE_VERSION,
        id: reply_id.to_string(),
        in_reply_to: in_reply_to.to_string(),
        replier,
        text: text.to_string(),
        created_at: storage::now_epoch_secs(),
    };
    match crate::fed::send_federated_reply(fed_state, ret_host, &envelope).await {
        Ok(_) => "pushed",
        Err(AppError::Gone { .. }) => "sender_gone",
        Err(_) => "push_failed",
    }
}

/// `caller` replies to `message_id`, a message it received. Every reply is stored; it is
/// also pushed to the original sender when that sender has an inbox (A10, A-2). An
/// idempotency key is the caller's, and names one reply: as for `send`, it is reserved
/// with the reply ID before the reply is pushed, a reply with a key another reply holds
/// returns that reply (or, while it is still being pushed, its ID with `push_outcome`
/// `pending` and `seq` 0), and a key whose reply failed is replied again, same reply ID.
pub async fn reply(
    state: &Arc<AppState>,
    caller: &Session,
    message_id: &str,
    text: &str,
    idempotency_key: Option<&str>,
) -> Result<ReplyRecord, AppError> {
    if message_id.is_empty() || text.is_empty() {
        return Err(AppError::BadRequest(
            "message_id and text are required".to_string(),
        ));
    }
    if text.len() > state.max_body {
        return Err(AppError::PayloadTooLarge {
            size: text.len(),
            limit: state.max_body,
        });
    }
    let (msg, is_forwarded) = {
        let db = state.db.lock().map_err(db_err)?;
        let msg = storage::get_message(&db, message_id)
            .map_err(db_err)?
            .filter(|m| {
                !matches!(
                    m.outcome.as_str(),
                    "not_found" | "ambiguous" | "gone" | "failed" | "delivery_failed"
                )
            })
            .ok_or_else(|| AppError::NotFound(format!("message '{message_id}'")))?;
        let fwd = storage::get_forwarded_message(&db, message_id)
            .map_err(db_err)?
            .is_some();
        (msg, fwd)
    };
    // Reply rights are keyed on the receiving instance ID (A5).
    // Reply rights are symmetric (XU1 Gate 3, Ruled Option b):
    // caller is either the recipient answering the sender, or the sender answering the recipient.
    let caller_is_recipient =
        caller.harness == msg.recipient_harness && caller.session_id == msg.session_id;
    let caller_is_sender = msg.return_session_id.as_deref() == Some(&caller.session_id)
        && (msg.return_harness.as_deref() == Some(&caller.harness)
            || msg.return_harness.as_deref() == Some("fed"));

    if !caller_is_recipient && !caller_is_sender {
        return Err(AppError::NotRecipient(format!(
            "'{}' is not the recipient of message '{message_id}'",
            caller.session_id
        )));
    }

    let principal = Sender::Session(caller.clone()).idempotency_principal();
    let reply_id = match idempotency_key {
        None => ulid::Ulid::new().to_string(),
        Some(key) => {
            check_idempotency_key(key)?;
            let fresh = ulid::Ulid::new().to_string();
            let ttl = state.idempotency_ttl.as_secs();
            let held = reserve_or_wait(
                || {
                    let db = state.db.lock().map_err(db_err)?;
                    storage::reserve_reply_key(&db, &principal, key, message_id, text, &fresh, ttl)
                        .map_err(db_err)
                },
                |r| {
                    r.in_reply_to == message_id && r.body == text && r.state == storage::KEY_PENDING
                },
            )
            .await?;
            match held {
                Reservation::Mine(id) => id,
                Reservation::Held(r) if r.in_reply_to != message_id || r.body != text => {
                    return Err(AppError::Conflict(format!(
                        "idempotency key '{key}' was already used with a different reply"
                    )))
                }
                Reservation::Held(r) => {
                    return match r.seq {
                        Some(seq) => {
                            let db = state.db.lock().map_err(db_err)?;
                            storage::get_reply_by_seq(&db, seq)
                                .map_err(db_err)?
                                .ok_or_else(|| AppError::NotFound(format!("reply {seq} (expired)")))
                        }
                        None => Ok(ReplyRecord {
                            seq: 0,
                            message_id: message_id.to_string(),
                            created_at: r.created_at,
                            replier_session_id: caller.session_id.clone(),
                            text: text.to_string(),
                            push_outcome: Some(storage::KEY_PENDING.to_string()),
                            pushed_message_id: Some(r.reply_id),
                        }),
                    };
                }
            }
        }
    };

    // As in `send`: pushed in a task of its own, so the key always settles.
    let task = {
        let (state, caller, message_id, text) = (
            state.clone(),
            caller.clone(),
            message_id.to_string(),
            text.to_string(),
        );
        let key = idempotency_key.map(str::to_string);
        tokio::spawn(async move {
            let res = deliver_reply(
                &state,
                &caller,
                msg,
                is_forwarded,
                caller_is_sender,
                &message_id,
                &text,
                reply_id,
            )
            .await;
            if let Some(key) = key {
                let (st, seq) = match &res {
                    Ok(r) => (storage::KEY_DONE, Some(r.seq)),
                    Err(_) => (storage::KEY_FAILED, None),
                };
                let settled = state.db.lock().map_err(db_err).and_then(|db| {
                    storage::settle_reply_key(&db, &principal, &key, st, seq).map_err(db_err)
                });
                if let Err(e) = settled {
                    tracing::warn!(target: "xmsg", in_reply_to = %message_id, "idempotency key not settled: {e}");
                }
            }
            res
        })
    };
    task.await.map_err(|e| AppError::Internal(e.to_string()))?
}

/// Records `reply_id`, a reply to `msg` pushed to its sender, as a message that sender
/// may answer in turn: to `replier` (harness, ID), through `return_host` when the replier
/// is on another node, in `msg`'s thread. An anonymous sender has no reply rights, so
/// nothing is recorded; an ID already recorded (a redelivered reply) is kept.
pub(crate) fn record_pushed_reply(
    db: &rusqlite::Connection,
    msg: &MessageRecord,
    reply_id: &str,
    from_name: &str,
    text: &str,
    replier: (&str, &str),
    return_host: Option<&str>,
) {
    let (Some(harness), Some(session_id)) = (&msg.return_harness, &msg.return_session_id) else {
        return;
    };
    let pushed = MessageRecord {
        id: reply_id.to_string(),
        created_at: storage::now_epoch_secs(),
        session_id: session_id.clone(),
        from_name: from_name.to_string(),
        bytes: text.len(),
        outcome: "delivered".to_string(),
        recipient_harness: harness.clone(),
        return_harness: Some(replier.0.to_string()),
        return_session_id: Some(replier.1.to_string()),
        thread_id: if msg.thread_id.is_empty() {
            msg.id.clone()
        } else {
            msg.thread_id.clone()
        },
        return_host: return_host.map(str::to_string),
    };
    let _ = storage::insert_message(db, &pushed);
}

/// `reply`'s push and record, under its reserved `reply_id`.
async fn deliver_reply(
    state: &AppState,
    caller: &Session,
    msg: MessageRecord,
    is_forwarded: bool,
    caller_is_sender: bool,
    message_id: &str,
    text: &str,
    reply_id: String,
) -> Result<ReplyRecord, AppError> {
    let (remote_host, has_inbox, ret_harness, ret_session_id) = if caller_is_sender {
        if msg.recipient_harness == "fed" {
            let db = state.db.lock().map_err(db_err)?;
            let outbound = storage::get_outbound(&db, message_id).map_err(db_err)?;
            let host = outbound.map(|o| o.peer);
            (host, false, String::new(), String::new())
        } else {
            (
                None,
                true,
                msg.recipient_harness.clone(),
                msg.session_id.clone(),
            )
        }
    } else {
        let remote_host = msg
            .return_host
            .as_deref()
            .filter(|h| !h.is_empty() && *h != state.node_name)
            .map(str::to_string);
        let has_inbox = msg.return_harness.is_some() && msg.return_session_id.is_some();
        let ret_harness = msg.return_harness.clone().unwrap_or_default();
        let ret_session_id = msg.return_session_id.clone().unwrap_or_default();
        (remote_host, has_inbox, ret_harness, ret_session_id)
    };
    // A leaf (or other undialable) origin pulls its replies; nothing is pushed to it.
    let to_leaf = remote_host.as_deref().is_some_and(|h| {
        state
            .fed_state
            .as_ref()
            .and_then(|fs| fs.current_peers().get(h).cloned())
            .is_some_and(|p| p.leaf)
    });

    // A reply pushed to or stored for a remote origin is a message sent there, which its
    // receiver may answer: recorded as sent, with its recipient in `outbound` (A7's reply
    // rule; XF1 Defect 2). When `dest_session_id` is `None` (an anonymous sender on a
    // dial-out/leaf node has no inbox and no reply rights), `pushed_id` remains `None` and
    // no `messages`/`outbound` row is recorded; the anonymous sender reads the reply via
    // `GET /v1/messages/{id}/replies`.
    let dest_session_id = if caller_is_sender {
        Some(msg.session_id.clone())
    } else {
        msg.return_session_id.clone()
    };
    let replier_label = inbox::sender_label(
        &state.node_name,
        &caller.harness,
        &caller.session_id,
        caller.name.as_deref(),
    );

    // A reply always travels back to a remote origin node, which decides how it reaches
    // the sender (A-2); a local one is pushed when the sender has an inbox (A10).
    // The pushed reply's `messages` (and `outbound`) row is recorded before the push
    // (XF2), so a recipient that replies the instant it is woken finds the row before
    // `deliver_reply` returns; if the push fails, the row is deleted below.
    let push_outcome = match remote_host.as_deref() {
        Some(host) => {
            if let Some(to) = dest_session_id.as_deref() {
                if let Ok(db) = state.db.lock() {
                    if caller_is_sender {
                        let pushed = MessageRecord {
                            id: reply_id.to_string(),
                            created_at: storage::now_epoch_secs(),
                            session_id: msg.session_id.clone(),
                            from_name: replier_label.clone(),
                            bytes: text.len(),
                            outcome: "delivered".to_string(),
                            recipient_harness: msg.recipient_harness.clone(),
                            return_harness: Some(caller.harness.clone()),
                            return_session_id: Some(caller.session_id.clone()),
                            thread_id: if msg.thread_id.is_empty() {
                                msg.id.clone()
                            } else {
                                msg.thread_id.clone()
                            },
                            return_host: Some(state.node_name.clone()),
                        };
                        let _ = storage::insert_message(&db, &pushed);
                    } else {
                        record_pushed_reply(
                            &db,
                            &msg,
                            &reply_id,
                            &replier_label,
                            text,
                            (&caller.harness, &caller.session_id),
                            None,
                        );
                    }
                    let now = storage::now_epoch_secs();
                    let _ = storage::insert_outbound(
                        &db,
                        &reply_id,
                        host,
                        &format!("{to}@{host}"),
                        "delivered",
                        now,
                    );
                    let _ = storage::mark_outbound_resolved(&db, &reply_id);
                }
            }
            let outcome = if to_leaf {
                "stored"
            } else {
                push_federated_reply(state, caller, host, message_id, &reply_id, text).await
            };
            run_post_deliver_pause(&state.node_name, &reply_id).await;
            if matches!(outcome, "pushed" | "stored") {
                if outcome == "pushed" && dest_session_id.is_some() {
                    if let Some(ref fed_state) = state.fed_state {
                        if fed_state
                            .current_peers()
                            .get(host)
                            .is_some_and(|p| p.is_outbound())
                        {
                            crate::fed::spawn_outbound_reply_poller(
                                fed_state.clone(),
                                host.to_string(),
                                reply_id.clone(),
                            );
                        }
                    }
                }
            } else if let Ok(db) = state.db.lock() {
                let _ = storage::delete_message(&db, &reply_id);
                let _ = storage::delete_outbound(&db, &reply_id);
            }
            Some(outcome)
        }
        None if !has_inbox || is_forwarded => None,
        None => {
            if let Ok(db) = state.db.lock() {
                if caller_is_sender {
                    let pushed = MessageRecord {
                        id: reply_id.to_string(),
                        created_at: storage::now_epoch_secs(),
                        session_id: msg.session_id.clone(),
                        from_name: replier_label.clone(),
                        bytes: text.len(),
                        outcome: "delivered".to_string(),
                        recipient_harness: msg.recipient_harness.clone(),
                        return_harness: Some(caller.harness.clone()),
                        return_session_id: Some(caller.session_id.clone()),
                        thread_id: if msg.thread_id.is_empty() {
                            msg.id.clone()
                        } else {
                            msg.thread_id.clone()
                        },
                        return_host: None,
                    };
                    let _ = storage::insert_message(&db, &pushed);
                } else {
                    record_pushed_reply(
                        &db,
                        &msg,
                        &reply_id,
                        &replier_label,
                        text,
                        (&caller.harness, &caller.session_id),
                        None,
                    );
                }
            }
            let replier_origin = Sender::Session(caller.clone()).origin(&state.node_name);
            let outcome = push_reply(
                &state.local(),
                &ret_harness,
                &ret_session_id,
                message_id,
                &reply_id,
                &replier_label,
                replier_origin,
                text,
            )
            .await;
            run_post_deliver_pause(&state.node_name, &reply_id).await;
            if outcome != "pushed" {
                if let Ok(db) = state.db.lock() {
                    let _ = storage::delete_message(&db, &reply_id);
                }
            }
            Some(outcome)
        }
    };
    // The pushed copy's ID: a local push that landed, or the envelope a remote origin
    // received or will pull (which deduplicates and replies by it).
    let pushed_id = match (remote_host.as_deref(), push_outcome, dest_session_id.as_deref()) {
        (Some(_), Some("stored"), None) | (_, None, _) => None,
        (Some(_), Some(_), _) | (None, Some("pushed"), _) => Some(reply_id.as_str()),
        (None, Some(_), _) => None,
    };

    let record = {
        let db = state.db.lock().map_err(db_err)?;
        let record = storage::insert_reply(
            &db,
            message_id,
            &caller.session_id,
            text,
            push_outcome,
            pushed_id,
        )
        .map_err(db_err)?;
        let _ = storage::purge_replies(&db, state.reply_ttl.as_secs());
        let _ = storage::purge_messages(&db, state.reply_ttl.as_secs());
        record
    };
    let _ = state.notify_tx.send(message_id.to_string());
    Ok(record)
}

// -----------------------------------------------------------------------------
// replies
// -----------------------------------------------------------------------------

/// The stored replies to `message_id` after `after`, waiting up to `wait` seconds (capped
/// at `MAX_WAIT_SECS`) for the first (A10, A-12). Anyone holding the message ID may read
/// them (A15).
pub async fn replies(
    state: &AppState,
    message_id: &str,
    after: i64,
    wait: u64,
) -> Result<Vec<ReplyRecord>, AppError> {
    let wait_secs = wait.min(MAX_WAIT_SECS);
    let outbound = {
        let db = state.db.lock().map_err(db_err)?;
        let msg = storage::get_message(&db, message_id).map_err(db_err)?;
        let out = storage::get_outbound(&db, message_id).map_err(db_err)?;
        if msg.is_none() && out.is_none() {
            return Err(AppError::NotFound(format!("message '{message_id}'")));
        }
        out
    };

    let _permit = if wait_secs > 0 {
        match state.long_poll_semaphore.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                return Err(AppError::ServiceUnavailable(
                    "too many concurrent long-poll requests".to_string(),
                ));
            }
            Err(e) => return Err(AppError::Internal(e.to_string())),
        }
    } else {
        None
    };

    let stored = |state: &AppState| -> Result<Vec<ReplyRecord>, AppError> {
        let db = state.db.lock().map_err(db_err)?;
        storage::get_replies_after(&db, message_id, after).map_err(db_err)
    };

    // A message sent to a dialable peer: its replies may still be there.
    if let (Some(outbound), Some(fed_state)) = (outbound, state.fed_state.as_ref()) {
        let peer_is_leaf = fed_state
            .peers
            .get(&outbound.peer)
            .map(|p| p.leaf)
            .unwrap_or(false);
        if !peer_is_leaf {
            let existing = stored(state)?;
            if !existing.is_empty() {
                return Ok(existing);
            }
            let remote = crate::fed::poll_federated_replies(
                fed_state,
                &outbound.peer,
                message_id,
                after,
                wait_secs,
            )
            .await?;
            let db = state.db.lock().map_err(db_err)?;
            let known = storage::get_replies_after(&db, message_id, 0).map_err(db_err)?;
            for r in &remote {
                if !known
                    .iter()
                    .any(|ex| ex.text == r.text && ex.replier_session_id == r.replier_session_id)
                {
                    let _ = storage::insert_reply(
                        &db,
                        message_id,
                        &r.replier_session_id,
                        &r.text,
                        r.push_outcome.as_deref(),
                        r.pushed_message_id.as_deref(),
                    );
                }
            }
            return Ok(remote);
        }
    }

    let rx = (wait_secs > 0).then(|| state.notify_tx.subscribe());
    let existing = stored(state)?;
    let Some(mut receiver) = rx.filter(|_| existing.is_empty()) else {
        return Ok(existing);
    };
    let _ = tokio::time::timeout(Duration::from_secs(wait_secs), async {
        loop {
            match receiver.recv().await {
                Ok(id) if id == message_id => break,
                Err(_) => break,
                _ => {}
            }
        }
    })
    .await;
    stored(state)
}
