//! A14's queue across one user's nodes (XA7; A16, D-1).
//!
//! A parked node cannot see X go live elsewhere, so the node that gains X asks: when a claim
//! scan newly observes X holding its plain ID, this node asks each of its user's other nodes
//! for X's queue, all of them at once, so a conversation parked on several of them gets
//! every queue in one registration (the user's parked listings are one destination).
//!
//! A holder hands its queue over only when the asker is the only live listing of X in a
//! complete view of the user's nodes and the asker: a node of the user that could not be
//! asked keeps the queue where it is, and so do two live listings. It transfers first, a
//! page at a time, and drops what it handed over only when the asker acknowledges; the
//! acknowledgement's answer counts what it still holds for X, and the asker asks again while
//! that is not zero, so a send that reached the holder during the transfer follows too.
//!
//! The asker stores what it was handed under the message IDs, so a transfer repeated after
//! a lost acknowledgement or a holder's crash delivers nothing twice (X1). It records each
//! ask, and the acknowledgement it owes, in its database before acting on them, and retries
//! an owed acknowledgement until it lands or the messages it names expire, across its own
//! restarts: an acknowledgement that never landed would leave the holder handing the same
//! messages to the next node X goes live on. A node of another user is refused.
//!
//! A handed-over message keeps its reply: the holder records the hand-off as a hub records
//! a forward (X26), so the recipient's reply reaches the holder and goes on to the sender
//! (A8a: replies travel by message ID).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::attachments;
use crate::client::wire::AttachmentRef;
use crate::error::AppError;
use crate::fed::{AuthenticatedPeer, FedState};
use crate::http::AppState;
use crate::storage::{self, MessageRecord, QueuedMessage};

/// How often an asker retries a holder that could not answer for sure (unreachable,
/// crashed, or without a complete view), and how many times before it gives the ask up.
const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const ATTEMPTS: usize = 60;
/// An owed acknowledgement is retried without a count, backing off to this.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// A hand-off request's bound: the holder asks the user's nodes for `list` first.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRequest {
    pub id: String,
    /// The most transfer bytes the asker reads; the holder pages to fit (at least one
    /// message a page).
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub messages: Vec<QueuedMessage>,
    /// The holder's record of each message it has one for, which the reply reads.
    #[serde(default)]
    pub records: Vec<MessageRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<TransferAttachments>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferAttachments {
    pub item_id: String,
    pub attachments: Vec<AttachmentRef>,
    pub expires_at: i64,
}

fn import_attachments(
    conn: &rusqlite::Connection,
    transfer: &Transfer,
    holder: &str,
    max_bytes: usize,
) -> Result<(), AppError> {
    let mut seen = std::collections::HashSet::new();
    for item in &transfer.attachments {
        if !seen.insert(&item.item_id)
            || !transfer.messages.iter().any(|m| m.id == item.item_id)
            || item.attachments.is_empty()
        {
            return Err(AppError::BadRequest("invalid handoff attachments".into()));
        }
        let refs = attachments::normalize_refs(&item.attachments, max_bytes)?;
        let held = attachments::list_rows(conn, &item.item_id)?;
        if held.iter().any(|r| r.expires_at != item.expires_at) {
            return Err(AppError::Conflict(
                "handoff attachment expiry changed".into(),
            ));
        }
        attachments::insert_rows(conn, &item.item_id, &refs, item.expires_at, holder, "")?;
    }
    Ok(())
}

fn transfer_attachments(
    conn: &rusqlite::Connection,
    item_id: &str,
) -> Result<Option<TransferAttachments>, AppError> {
    let rows = attachments::list_rows(conn, item_id)?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let expires_at = first.expires_at;
    if rows.iter().any(|r| r.expires_at != expires_at) {
        return Err(AppError::Internal("inconsistent attachment expiry".into()));
    }
    Ok(Some(TransferAttachments {
        item_id: item_id.to_string(),
        attachments: rows.into_iter().map(|r| r.attachment).collect(),
        expires_at,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub id: String,
    pub messages: Vec<String>,
}

/// The holder's answer to an acknowledgement: how many messages for the ID it still holds.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckAnswer {
    pub remaining: usize,
}

// ponytail: one process-wide channel, set once by `serve`; a library caller that never
// spawns the puller observes without pulling.
static OBSERVED: OnceLock<mpsc::UnboundedSender<String>> = OnceLock::new();

/// A claim scan newly observed `id` holding its plain ID (D-1's event).
pub fn observed(id: &str) {
    if let Some(tx) = OBSERVED.get() {
        let _ = tx.send(id.to_string());
    }
}

/// Starts pulling queues for newly observed conversations, on a node with peers, and
/// resumes the hand-offs this node had not settled when it stopped.
pub fn spawn(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let _ = OBSERVED.set(tx);
    tokio::spawn(async move {
        let owed = storage::owed_handoffs(
            &state
                .db
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        match (owed, state.fed_state.clone()) {
            (Ok(owed), Some(fs)) => {
                for o in owed {
                    tokio::spawn(settle(state.clone(), fs.clone(), o.holder, o.id));
                }
            }
            (Err(e), _) => warn!("hand-off: owed hand-offs unreadable, none resumed: {e}"),
            (Ok(_), None) => {}
        }
        while let Some(id) = rx.recv().await {
            tokio::spawn(pull(state.clone(), id));
        }
    })
}

/// The user's other nodes this node can dial: its own user's peers, less dial-out clients.
fn holders(fs: &FedState) -> Vec<String> {
    let me = crate::fed::own_user(fs);
    fs.current_peers()
        .iter()
        .filter(|(_, c)| !c.leaf && crate::mesh::peer_user(c).as_deref() == Some(me.as_str()))
        .map(|(k, _)| k.clone())
        .collect()
}

/// Pulls X's queue from every holder at once.
async fn pull(state: Arc<AppState>, id: String) {
    let Some(fs) = state.fed_state.clone() else {
        return;
    };
    let mut asked = tokio::task::JoinSet::new();
    for key in holders(&fs) {
        asked.spawn(settle(state.clone(), fs.clone(), key, id.clone()));
    }
    while let Some(res) = asked.join_next().await {
        if let Err(e) = res {
            warn!("hand-off task failed for {id}: {e}");
        }
    }
}

/// What one step of a hand-off left to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Settled: refused, or nothing left at the holder.
    Done,
    /// The holder still holds messages for X: ask again now.
    Again,
    /// Not answered for sure: ask again later.
    Retry,
}

/// Settles X's hand-off with one holder: asks, stores, acknowledges, and asks again while
/// the holder holds more, recording each step so a restart resumes it.
async fn settle(state: Arc<AppState>, fs: Arc<FedState>, key: String, id: String) {
    let db_err = |e: &dyn std::fmt::Display| warn!("hand-off of {id} from {key}: database: {e}");
    match state.db.lock() {
        Ok(db) => {
            if let Err(e) = storage::owe_handoff(&db, &id, &key) {
                return db_err(&e);
            }
        }
        Err(e) => return db_err(&e),
    }
    let (mut attempts, mut backoff) = (0, RETRY_INTERVAL);
    loop {
        match step(&state, &fs, &key, &id).await {
            Ok(Step::Done) => break,
            Ok(Step::Again) => {
                (attempts, backoff) = (0, RETRY_INTERVAL);
                continue;
            }
            Ok(Step::Retry) => {}
            Err(e) => {
                db_err(&e);
                return;
            }
        }
        let owed = match state.db.lock() {
            Ok(db) => storage::get_owed_handoff(&db, &id, &key),
            Err(e) => return db_err(&e),
        };
        let owed = match owed {
            Ok(Some(o)) => o,
            Ok(None) => return,
            Err(e) => return db_err(&e),
        };
        if owed.acks.is_empty() {
            attempts += 1;
            if attempts >= ATTEMPTS {
                warn!("hand-off of {id} from {key} unsettled");
                break;
            }
            tokio::time::sleep(RETRY_INTERVAL).await;
        } else {
            // Past their expiry the holder hands them to nobody, so nothing is owed.
            if storage::now_epoch_secs() >= owed.until {
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
    match state.db.lock() {
        Ok(db) => {
            if let Err(e) = storage::settle_handoff(&db, &id, &key) {
                db_err(&e);
            }
        }
        Err(e) => db_err(&e),
    }
}

/// One step: the owed acknowledgement if there is one, else an ask and its acknowledgement.
pub async fn step(state: &AppState, fs: &FedState, key: &str, id: &str) -> Result<Step, AppError> {
    let db_err = |e: &dyn std::fmt::Display| AppError::Internal(e.to_string());
    let owed = {
        let db = state.db.lock().map_err(|e| db_err(&e))?;
        storage::get_owed_handoff(&db, id, key).map_err(|e| db_err(&e))?
    };
    if let Some(owed) = owed.filter(|o| !o.acks.is_empty()) {
        return acknowledge(state, fs, key, id, owed.acks, owed.until).await;
    }

    let limit = fs.max_body * 64;
    let req = serde_json::json!({ "id": id, "limit": limit });
    let transfer = match post(fs, key, "/fed/v2/handoff", &req, limit + 4096).await {
        Ok((StatusCode::OK, body)) => match serde_json::from_slice::<Transfer>(&body) {
            Ok(t) => t,
            Err(e) => {
                warn!("unreadable hand-off of {id} from {key}: {e}");
                return Ok(Step::Retry);
            }
        },
        // Not parked there, two live listings, or not this node's to take.
        Ok((s, _)) if matches!(s.as_u16(), 403 | 404 | 409) => return Ok(Step::Done),
        Ok((s, _)) => {
            debug!("hand-off of {id} from {key}: {s}");
            return Ok(Step::Retry);
        }
        Err(e) => {
            debug!("hand-off of {id} from {key}: {e}");
            return Ok(Step::Retry);
        }
    };
    crate::fed::validate_handoff_transfer(&transfer, key)?;
    let ids: Vec<String> = transfer.messages.iter().map(|m| m.id.clone()).collect();
    let until = transfer
        .messages
        .iter()
        .map(|m| m.expires_at)
        .max()
        .unwrap_or(0);
    {
        let db = state.db.lock().map_err(|e| db_err(&e))?;
        let tx = crate::observe_effects::transaction(&state.db, &db).map_err(|e| db_err(&e))?;
        for m in &transfer.messages {
            let m = QueuedMessage {
                instance_id: id.to_string(),
                ..m.clone()
            };
            storage::insert_handed_over(&tx, &m).map_err(|e| db_err(&e))?;
        }
        // The reply goes back to the holder, which relays it to the sender (A8a).
        for r in &transfer.records {
            if ids.contains(&r.id)
                && storage::get_message(&tx, &r.id)
                    .map_err(|e| db_err(&e))?
                    .is_none()
            {
                let rec = MessageRecord {
                    session_id: id.to_string(),
                    outcome: "queued".to_string(),
                    recipient_harness: "claude".to_string(),
                    return_harness: None,
                    return_session_id: None,
                    return_host: Some(key.to_string()),
                    ..r.clone()
                };
                storage::insert_message(&tx, &rec).map_err(|e| db_err(&e))?;
            }
        }
        import_attachments(&tx, &transfer, key, state.max_attachment_bytes)?;
        storage::set_owed_acks(&tx, id, key, &ids, until).map_err(|e| db_err(&e))?;
        tx.commit().map_err(|e| db_err(&e))?;
    }
    // Delivered here, by the scan that takes a live holder's queue (A14).
    if !ids.is_empty() {
        let _ = crate::claim::sync_claims(
            &state.db,
            &state.agy_config.proc_root,
            &state.sessions_dirs,
            &state.node_name,
        )
        .await;
    }
    acknowledge(state, fs, key, id, ids, until).await
}

/// Acknowledges `ids` to the holder; once it lands nothing is owed, and the holder's count
/// of what it still holds decides whether to ask again.
async fn acknowledge(
    state: &AppState,
    fs: &FedState,
    key: &str,
    id: &str,
    ids: Vec<String>,
    until: i64,
) -> Result<Step, AppError> {
    let ack = serde_json::to_value(Ack {
        id: id.to_string(),
        messages: ids,
    })
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let remaining = match post(fs, key, "/fed/v2/handoff/ack", &ack, 4096).await {
        Ok((StatusCode::OK, body)) => match serde_json::from_slice::<AckAnswer>(&body) {
            Ok(a) => a.remaining,
            Err(e) => {
                warn!("unreadable acknowledgement of {id} from {key}: {e}");
                return Ok(Step::Retry);
            }
        },
        _ => return Ok(Step::Retry),
    };
    {
        let db = state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::set_owed_acks(&db, id, key, &[], until)
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }
    Ok(if remaining > 0 {
        Step::Again
    } else {
        Step::Done
    })
}

/// Refuses a node of another user (A16): only the user's own nodes take its queues.
fn same_user(fs: &FedState, peer: &AuthenticatedPeer) -> Result<String, AppError> {
    let me = crate::fed::own_user(fs);
    if peer.user != me {
        return Err(AppError::Denied(format!(
            "'{}' is not a node of user '{me}'",
            peer.name
        )));
    }
    Ok(me)
}

/// `POST /fed/v2/handoff`: X's queue, for the asker that is X's only live listing.
pub async fn handoff_handler(
    State(fs): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Json(req): Json<HandoffRequest>,
) -> Result<axum::response::Response, AppError> {
    let me = same_user(&fs, &peer)?;
    let id = req.id.clone();
    let here = crate::surface::listing(&fs.local(), fs.reply_ttl, &me).await?;
    match here
        .iter()
        .find(|e| e.kind == "instance" && e.id == id)
        .map(|e| e.status.as_str())
    {
        Some("parked") => {}
        Some(_) => {
            return Err(AppError::Ambiguous(format!(
                "{id}@{} is live",
                fs.node_name
            )))
        }
        None => return Err(AppError::NotFound(id)),
    }

    // A complete view of the user's nodes, and the asker.
    let peers = fs.current_peers();
    let mut keys: Vec<String> = peers
        .iter()
        .filter(|(_, c)| crate::mesh::peer_user(c).as_deref() == Some(me.as_str()))
        .map(|(k, _)| k.clone())
        .collect();
    if !keys.contains(&peer.name) {
        keys.push(peer.name.clone());
    }
    let mut asked = tokio::task::JoinSet::new();
    for key in keys {
        let fs = fs.clone();
        asked.spawn(async move {
            let (entries, st) = crate::fed::list_peer(&fs, &key).await;
            (key, entries, st)
        });
    }
    let (mut unasked, mut live) = (Vec::new(), Vec::new());
    while let Some(res) = asked.join_next().await {
        let (key, entries, st) = res.map_err(|e| AppError::Internal(e.to_string()))?;
        if st.status != "ok" {
            unasked.push(key);
        } else if entries
            .iter()
            .any(|e| e.kind == "instance" && e.id == id && e.status == "live")
        {
            live.push(key);
        }
    }
    if !unasked.is_empty() {
        unasked.sort();
        return Err(AppError::Unavailable(format!(
            "could not ask {} for {id}; its queue stays on {}",
            unasked.join(", "),
            fs.node_name
        )));
    }
    live.sort();
    match live.as_slice() {
        [one] if *one == peer.name => {}
        [_, _, ..] => {
            return Err(AppError::Ambiguous(
                live.iter()
                    .map(|k| format!("{id}@{k}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            ))
        }
        _ => {
            return Err(AppError::NotLive(format!(
                "'{id}' is not live on {} alone",
                peer.name
            )))
        }
    }

    // A page fits the asker's limit, and holds at least one message; the acknowledgement's
    // count of what is left brings the asker back for the rest.
    let budget = req.limit.unwrap_or(fs.max_body * 64);
    let (mut messages, mut records, mut attachments, mut used) =
        (Vec::new(), Vec::new(), Vec::new(), 0);
    {
        let db = fs
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        for m in storage::queued_for(&db, &id, storage::now_epoch_secs())
            .map_err(|e| AppError::Internal(e.to_string()))?
        {
            let r =
                storage::get_message(&db, &m.id).map_err(|e| AppError::Internal(e.to_string()))?;
            let files = transfer_attachments(&db, &m.id)?;
            let size = serde_json::to_vec(&m).map_or(0, |v| v.len())
                + r.as_ref()
                    .and_then(|r| serde_json::to_vec(r).ok())
                    .map_or(0, |v| v.len())
                + files
                    .as_ref()
                    .and_then(|f| serde_json::to_vec(f).ok())
                    .map_or(0, |v| v.len())
                + 2;
            if !messages.is_empty() && used + size > budget {
                break;
            }
            used += size;
            messages.push(m);
            records.extend(r);
            attachments.extend(files);
        }
    }
    Ok((
        StatusCode::OK,
        Json(Transfer {
            messages,
            records,
            attachments,
        }),
    )
        .into_response())
}

/// `POST /fed/v2/handoff/ack`: the asker holds what it was handed; drop it here.
pub async fn ack_handler(
    State(fs): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Json(ack): Json<Ack>,
) -> Result<axum::response::Response, AppError> {
    same_user(&fs, &peer)?;
    let db = fs
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let remaining = crate::observe_effects::autocommit_registered(&db, |observed_connection| {
        crate::storage::drop_handed_over(
            observed_connection,
            &ack.id,
            &ack.messages,
            &peer.name,
            storage::now_epoch_secs(),
        )
    })
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((StatusCode::OK, Json(AckAnswer { remaining })).into_response())
}

/// POSTs `body` to the direct peer keyed `key`: its status and body.
async fn post(
    fs: &FedState,
    key: &str,
    uri: &str,
    body: &serde_json::Value,
    limit: usize,
) -> Result<(StatusCode, bytes::Bytes), AppError> {
    let peer = fs
        .current_peers()
        .get(key)
        .cloned()
        .ok_or_else(|| AppError::UnknownPeer(key.to_string()))?;
    let unreachable = |what: &str, e: &dyn std::fmt::Display| {
        AppError::PeerUnreachable(format!("{what} '{}': {e}", peer.name))
    };
    let fut = async {
        let connector = crate::fed::make_tls_connector_for_peer(fs, &peer)?;
        let tcp = tokio::net::TcpStream::connect(&peer.address)
            .await
            .map_err(|e| unreachable("connecting to", &e))?;
        let name = ServerName::try_from(peer.name.clone())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| unreachable("TLS with", &e))?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|e| unreachable("HTTP with", &e))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("host", peer.name.as_str())
            .body(http_body_util::Full::new(bytes::Bytes::from(
                body.to_string(),
            )))
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| unreachable("request to", &e))?;
        let status = resp.status();
        use http_body_util::BodyExt;
        let bytes = http_body_util::Limited::new(resp.into_body(), limit)
            .collect()
            .await
            .map_err(|e| unreachable("reading from", &e))?
            .to_bytes();
        Ok((status, bytes))
    };
    tokio::time::timeout(REQUEST_TIMEOUT, fut)
        .await
        .map_err(|_| unreachable("timed out asking", &"no answer"))?
}

#[cfg(test)]
mod attachment_tests {
    use super::*;

    fn db() -> rusqlite::Connection {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        storage::init_db(&db).unwrap();
        db
    }

    fn transfer() -> Transfer {
        Transfer {
            messages: vec![QueuedMessage {
                id: "item".into(),
                instance_id: "recipient".into(),
                created_at: 10,
                expires_at: 70,
                from_name: "sender".into(),
                body: "body".into(),
            }],
            records: vec![],
            attachments: vec![TransferAttachments {
                item_id: "item".into(),
                attachments: vec![AttachmentRef {
                    name: "file.txt".into(),
                    size: 4,
                    media_type: "text/plain".into(),
                    sha256: "0".repeat(64),
                }],
                expires_at: 50,
            }],
        }
    }

    #[test]
    fn attachment_handoff_preserves_expiry_and_holder_without_transferring_hop_secrets() {
        let holder = db();
        let transfer = transfer();
        attachments::insert_rows(
            &holder,
            "item",
            &transfer.attachments[0].attachments,
            50,
            "original-upstream",
            "previous-downstream",
        )
        .unwrap();
        let metadata = transfer_attachments(&holder, "item").unwrap().unwrap();
        let encoded = serde_json::to_string(&metadata).unwrap();
        assert!(!encoded.contains("original-upstream"));
        assert!(!encoded.contains("previous-downstream"));
        let receiver = db();
        import_attachments(
            &receiver,
            &transfer,
            "holder",
            attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        )
        .unwrap();
        import_attachments(
            &receiver,
            &transfer,
            "holder",
            attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        )
        .unwrap();
        let rows = attachments::list_rows(&receiver, "item").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].expires_at, 50);
        assert_eq!(rows[0].upstream, "holder");
        assert!(rows[0].downstream.is_empty());
        assert!(matches!(
            attachments::read_range(&receiver, &rows[0], 0, None, 64, 51),
            Err(AppError::GoneDetail(_))
        ));
    }

    #[test]
    fn attachment_handoff_refuses_unrelated_duplicate_oversized_and_conflicting_metadata() {
        let receiver = db();
        let mut bad = transfer();
        bad.attachments[0].item_id = "unrelated".into();
        assert!(matches!(
            import_attachments(
                &receiver,
                &bad,
                "holder",
                attachments::DEFAULT_MAX_ATTACHMENT_BYTES
            ),
            Err(AppError::BadRequest(_))
        ));
        let mut bad = transfer();
        bad.attachments.push(bad.attachments[0].clone());
        assert!(matches!(
            import_attachments(
                &receiver,
                &bad,
                "holder",
                attachments::DEFAULT_MAX_ATTACHMENT_BYTES
            ),
            Err(AppError::BadRequest(_))
        ));
        let mut bad = transfer();
        bad.attachments[0].attachments[0].size = attachments::DEFAULT_MAX_ATTACHMENT_BYTES + 1;
        assert!(matches!(
            import_attachments(
                &receiver,
                &bad,
                "holder",
                attachments::DEFAULT_MAX_ATTACHMENT_BYTES
            ),
            Err(AppError::PayloadTooLarge { .. })
        ));
        import_attachments(
            &receiver,
            &transfer(),
            "holder",
            attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        )
        .unwrap();
        let mut changed = transfer();
        changed.attachments[0].expires_at = 500;
        assert!(matches!(
            import_attachments(
                &receiver,
                &changed,
                "holder",
                attachments::DEFAULT_MAX_ATTACHMENT_BYTES
            ),
            Err(AppError::Conflict(_))
        ));
        let mut changed = transfer();
        changed.attachments[0].attachments[0].sha256 = "1".repeat(64);
        assert!(matches!(
            import_attachments(
                &receiver,
                &changed,
                "holder",
                attachments::DEFAULT_MAX_ATTACHMENT_BYTES
            ),
            Err(AppError::Conflict(_))
        ));
        assert_eq!(
            attachments::list_rows(&receiver, "item").unwrap()[0].expires_at,
            50
        );
    }

    #[test]
    fn attachment_handoff_failure_rolls_back_prior_rows_and_empty_wire_stays_unchanged() {
        let receiver = db();
        let mut transfer = transfer();
        let mut invalid = transfer.attachments[0].clone();
        invalid.item_id = "not-transferred".into();
        transfer.attachments.push(invalid);
        {
            let tx = receiver.unchecked_transaction().unwrap();
            assert!(import_attachments(
                &tx,
                &transfer,
                "holder",
                attachments::DEFAULT_MAX_ATTACHMENT_BYTES
            )
            .is_err());
        }
        assert!(attachments::list_rows(&receiver, "item")
            .unwrap()
            .is_empty());
        let empty: Transfer = serde_json::from_str(r#"{"messages":[],"records":[]}"#).unwrap();
        assert_eq!(
            serde_json::to_string(&empty).unwrap(),
            r#"{"messages":[],"records":[]}"#
        );
    }
}
