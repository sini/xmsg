//! Mesh resolution (XA6): a bare reference resolves over the send's view, which is every
//! node in the peers file, direct peers and dial-out clients alike, and this node (D-6).
//!
//! - **A bare instance ID** is first looked for on the sender's own user's nodes, and only
//!   those (A17): one live listing is the destination, two are `ambiguous`, and parked-only
//!   listings are one destination, queued at (A14, A16). With none, it resolves over the
//!   full view.
//! - **Over the full view**, a node that could not be asked (unreachable, timed out, a
//!   disconnected dial-out client, or withholding `list` from this node) makes a bare
//!   reference `unavailable` (A-9, D-6, gate v0 C4), except that for an ID, a node of the
//!   match's own user does not block it (P-1). IDs listed under two users are `ambiguous`
//!   (A8a); within one user a live listing beats a parked one (A16).
//! - **A name** never takes A17 or P-1 (D-7): services first everywhere in the view (A11),
//!   then instance labels, and only a unique one (A7).
//!
//! "Who holds this ID" is the `/fed/v2` `list` read for that ID: one fan-out per uncached
//! send (A-12's cost). A remote ID that took a live delivery is cached on this node for
//! `CACHE_TTL_SECS`; a send routed by the cache is live-only (gate v0 C9).

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::error::AppError;
use crate::fed::{FedListEntry, FedState, NodeStatus, PeerConfig};
use crate::http::AppState;
use crate::storage;

/// The location cache's lifetime (A-12): 60 s.
pub const CACHE_TTL_SECS: i64 = 60;

/// Where a bare reference goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Dest {
    /// This node, resolving the reference locally.
    Local,
    /// The peer keyed `node`, and the recipient's own ID or service name there. `cached`
    /// marks a location read from the cache (live-only); `id` marks an instance ID listed
    /// live there, the only kind cached.
    Peer {
        node: String,
        key: String,
        cached: bool,
        id: bool,
    },
}

/// One node's answer: its listing, or that it could not be asked.
struct Answer {
    node: String,
    /// The user the peers file binds the node to (A16, D-8); this node's own for itself.
    user: Option<String>,
    entries: Vec<FedListEntry>,
    asked: bool,
    local: bool,
}

/// One recipient matching the reference.
struct Listing<'a> {
    node: &'a str,
    user: &'a str,
    entry: &'a FedListEntry,
    local: bool,
}

impl Listing<'_> {
    fn address(&self) -> String {
        format!("{}@{}", self.entry.id, self.node)
    }

    fn dest(&self, id: bool) -> Dest {
        if self.local {
            Dest::Local
        } else {
            Dest::Peer {
                node: self.node.to_string(),
                key: self.entry.id.clone(),
                cached: false,
                id,
            }
        }
    }
}

/// The user a peer entry names (A16): its one identity's user, a pinned node's own name,
/// or none when the entry names several identities.
pub(crate) fn peer_user(peer: &PeerConfig) -> Option<String> {
    match (&peer.pin, peer.identities.as_deref()) {
        (Some(pin), _) => crate::node::node_name_from_pin(pin).ok(),
        (None, Some([uri])) => crate::node::user_from_uri(uri).ok(),
        _ => None,
    }
}

fn answer(
    node: String,
    user: Option<String>,
    entries: Vec<FedListEntry>,
    st: NodeStatus,
) -> Answer {
    Answer {
        node,
        user,
        entries,
        asked: st.status == "ok",
        local: false,
    }
}

/// Instance entries whose ID is `r`, from the nodes that answered. Only a UUID-shaped `r`
/// (optionally `~n`) is an ID (A11); any other is a name, whatever a node lists.
fn id_matches<'a>(answers: &'a [Answer], r: &str) -> Vec<Listing<'a>> {
    if !crate::claim::is_instance_ref(r) {
        return Vec::new();
    }
    answers
        .iter()
        .filter(|a| a.asked)
        .flat_map(|a| {
            a.entries
                .iter()
                .filter(move |e| e.kind == "instance" && e.id == r)
                .map(move |e| Listing {
                    node: &a.node,
                    user: &e.user,
                    entry: e,
                    local: a.local,
                })
        })
        .collect()
}

fn addresses(ls: &[Listing]) -> String {
    ls.iter()
        .map(Listing::address)
        .collect::<Vec<_>>()
        .join(", ")
}

/// One user's listings of an ID (A16): a live one beats parked ones, two live ones are
/// `ambiguous`, and parked-only listings are one destination.
fn within_user(ls: &[Listing]) -> Result<Dest, AppError> {
    let live: Vec<&Listing> = ls.iter().filter(|l| l.entry.status == "live").collect();
    match live.as_slice() {
        [one] => Ok(one.dest(true)),
        [] => Ok(ls
            .iter()
            .min_by_key(|l| (!l.local, l.node))
            .expect("at least one listing")
            .dest(false)),
        _ => Err(AppError::Ambiguous(
            live.iter()
                .map(|l| l.address())
                .collect::<Vec<_>>()
                .join(", "),
        )),
    }
}

fn unavailable(nodes: &[&Answer]) -> AppError {
    let names: Vec<&str> = nodes.iter().map(|a| a.node.as_str()).collect();
    AppError::Unavailable(format!(
        "could not ask {} for a bare reference; address it with @node",
        names.join(", ")
    ))
}

/// Resolves the bare reference `r` over the view of `fs`'s peers. A node with no peers
/// resolves locally only.
pub(crate) async fn resolve(
    state: &AppState,
    fs: &Arc<FedState>,
    r: &str,
) -> Result<Dest, AppError> {
    let peers = fs.current_peers();
    if peers.is_empty() {
        return Ok(Dest::Local);
    }
    if let Some(node) = cached(state, r)? {
        if peers
            .get_peer_config(&node)
            .is_some_and(|peer| !peer.is_observe_only())
        {
            return Ok(Dest::Peer {
                node,
                key: r.to_string(),
                cached: true,
                id: true,
            });
        }
    }

    // Every node is asked at once; A17 awaits only the sender's user's nodes first.
    let me = crate::fed::own_user(fs);
    let mut own = Vec::new();
    let mut rest = Vec::new();
    for (key, cfg) in peers.iter().filter(|(_, cfg)| !cfg.is_observe_only()) {
        let (fs, k) = (fs.clone(), key.clone());
        let asked = tokio::spawn(async move { crate::fed::list_peer(&fs, &k).await });
        let user = peer_user(cfg);
        if user.as_deref() == Some(me.as_str()) {
            own.push((key.clone(), user, asked));
        } else {
            rest.push((key.clone(), user, asked));
        }
    }
    let local_entries = crate::surface::listing(&state.local(), state.reply_ttl, &me).await;
    let mut answers = vec![Answer {
        node: state.node_name.clone(),
        user: Some(me.clone()),
        entries: local_entries?,
        asked: true,
        local: true,
    }];
    for (key, user, asked) in own {
        let (entries, st) = asked.await.map_err(|e| AppError::Internal(e.to_string()))?;
        answers.push(answer(key, user, entries, st));
    }

    // A17: the sender's own user first, for an instance ID.
    let own_ids = id_matches(&answers, r);
    if !own_ids.is_empty() {
        let dest = within_user(&own_ids);
        for (_, _, asked) in &rest {
            asked.abort();
        }
        return dest;
    }

    for (key, user, asked) in rest {
        let (entries, st) = asked.await.map_err(|e| AppError::Internal(e.to_string()))?;
        answers.push(answer(key, user, entries, st));
    }
    let unasked: Vec<&Answer> = answers.iter().filter(|a| !a.asked).collect();

    // An instance ID over the full view (A8, A8a, P-1).
    let ids = id_matches(&answers, r);
    if !ids.is_empty() {
        let users: BTreeSet<&str> = ids.iter().map(|l| l.user).collect();
        let blocking: Vec<&Answer> = match users.iter().next() {
            Some(u) if users.len() == 1 => unasked
                .iter()
                .copied()
                .filter(|a| a.user.as_deref() != Some(*u))
                .collect(),
            _ => unasked.clone(),
        };
        if !blocking.is_empty() {
            return Err(unavailable(&blocking));
        }
        if users.len() > 1 {
            return Err(AppError::Ambiguous(addresses(&ids)));
        }
        return within_user(&ids);
    }

    // A name (D-7): the full view, failing closed.
    if !unasked.is_empty() {
        return Err(unavailable(&unasked));
    }
    let named = |pred: &dyn Fn(&FedListEntry) -> bool| -> Vec<Listing> {
        answers
            .iter()
            .flat_map(|a| {
                a.entries.iter().filter(|e| pred(e)).map(move |e| Listing {
                    node: &a.node,
                    user: &e.user,
                    entry: e,
                    local: a.local,
                })
            })
            .collect()
    };
    // A11: services first everywhere in the view, then instance labels.
    let mut found = named(&|e| e.kind == "service" && e.id == r);
    if found.is_empty() {
        found = named(&|e| e.kind == "instance" && e.label.as_deref() == Some(r));
    }
    match found.as_slice() {
        [] => Err(AppError::NotFound(r.to_string())),
        [one] => Ok(one.dest(false)),
        _ => Err(AppError::Ambiguous(addresses(&found))),
    }
}

fn db_err(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(format!("database error: {e}"))
}

fn cached(state: &AppState, id: &str) -> Result<Option<String>, AppError> {
    let db = state.db.lock().map_err(db_err)?;
    storage::cached_location(&db, id, storage::now_epoch_secs(), CACHE_TTL_SECS).map_err(db_err)
}

/// Caches a remote instance's location after a live delivery there (A-12).
pub(crate) fn remember(state: &AppState, id: &str, node: &str) {
    if let Ok(db) = state.db.lock() {
        let _ = storage::cache_location(&db, id, node, storage::now_epoch_secs());
    }
}

/// A failed delivery invalidates the location (A-12).
pub(crate) fn forget(state: &AppState, id: &str) {
    if let Ok(db) = state.db.lock() {
        let _ = storage::forget_location(&db, id);
    }
}
