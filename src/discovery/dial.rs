use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::state::Presence;
use super::Candidate;
use crate::error::AppError;
use crate::fed::{FedState, PeerConfig, PeersMap};

pub struct Dial {
    inner: Route,
    policy: Arc<PeersMap>,
}

enum Route {
    Direct(Box<PreparedDirect>),
    ViaHub(String),
}

pub struct PreparedDirect {
    pub(crate) stream: TlsStream<TcpStream>,
    pub(crate) authority: crate::fed::CurrentLeaf,
}

impl std::ops::Deref for PreparedDirect {
    type Target = TlsStream<TcpStream>;
    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl Dial {
    pub(crate) fn current_policy(&self, fs: &FedState) -> Result<Arc<PeersMap>, AppError> {
        if !Arc::ptr_eq(&fs.current_peers(), &self.policy) {
            return Err(AppError::PeerRejected("discovery policy changed".into()));
        }
        Ok(self.policy.clone())
    }

    pub fn into_direct(self) -> Result<PreparedDirect, AppError> {
        match self.inner {
            Route::Direct(stream) => Ok(*stream),
            Route::ViaHub(hub) => Err(AppError::PeerUnreachable(format!(
                "this operation requires a direct peer; route is via hub '{hub}'"
            ))),
        }
    }

    pub fn via_hub(&self) -> Option<&str> {
        match &self.inner {
            Route::ViaHub(hub) => Some(hub),
            Route::Direct(_) => None,
        }
    }
}

async fn connect(
    fs: &FedState,
    peer: &PeerConfig,
    policy: Arc<PeersMap>,
    address: &str,
) -> Result<PreparedDirect, AppError> {
    let (chain, key, current) = fs.dial_credentials();
    if !Arc::ptr_eq(&current, &policy) {
        return Err(AppError::PeerRejected("discovery policy changed".into()));
    }
    let connector = crate::fed::make_tls_connector_for_policy(chain, key, peer, policy.clone())?;
    let name = if peer.name.starts_with("xmsg-spki1:") {
        ServerName::try_from("xmsg-pair.local".to_string())
            .map_err(|e| AppError::Internal(e.to_string()))?
    } else {
        ServerName::try_from(peer.name.clone()).map_err(|e| AppError::Internal(e.to_string()))?
    };
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|e| AppError::PeerUnreachable(format!("connecting to {}: {e}", peer.name)))?;
    let tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| crate::fed::map_tls_connect_error(&peer.name, e))?;
    let authority = crate::fed::CurrentLeaf::outbound(fs, connector.admission_mode(), &tls)?;
    if !Arc::ptr_eq(&fs.current_peers(), &policy) {
        return Err(AppError::PeerRejected("discovery policy changed".into()));
    }
    Ok(PreparedDirect {
        stream: tls,
        authority,
    })
}

/// The one exact identity a rule can be discovered by, which also keys its presence: the
/// normalized SPKI pin of a pinned entry, or the single concrete URI of a CA entry.
pub(crate) fn exact_identity(peer: &PeerConfig) -> Option<&str> {
    if let Some(pin) = &peer.pin {
        return (peer.ca.is_none() && peer.identities.is_none()).then_some(pin.as_str());
    }
    peer.ca.as_ref()?;
    match peer.identities.as_deref()? {
        [uri] if !uri.contains('*') => Some(uri),
        _ => None,
    }
}

fn candidates(fs: &FedState, peer: &PeerConfig, policy: &PeersMap, now: Instant) -> Vec<Candidate> {
    let table = fs
        .discovery
        .candidates
        .read()
        .unwrap_or_else(|e| e.into_inner());
    if peer.pin.is_some() {
        // A pin names no CA root, so only a candidate without a root hint can be probed.
        return table.unrooted(now);
    }
    eligible_candidates(&table, policy.discovery_roots(&peer.name), now)
}

fn eligible_candidates(
    table: &super::CandidateTable,
    roots: &[[u8; 32]],
    now: Instant,
) -> Vec<Candidate> {
    let mut seen = HashSet::new();
    let mut eligible = roots
        .iter()
        .flat_map(|root| table.eligible(root, now))
        .filter(|candidate| seen.insert((candidate.source, candidate.addr)))
        .collect::<Vec<_>>();
    eligible.sort_by(|a, b| {
        b.hint
            .is_some()
            .cmp(&a.hint.is_some())
            .then(b.seen_at.cmp(&a.seen_at))
    });
    eligible
}

fn witness(tls: &TlsStream<TcpStream>, peer: &PeerConfig) -> Option<(String, i64)> {
    let leaf = tls.get_ref().1.peer_certificates()?.first()?;
    if peer.pin.is_some() {
        // The connector's pin verifier is the one SPKI check: it refuses any other key before
        // the handshake completes. Presence is keyed by the key it proved. Pin mode ignores
        // certificate expiry, so the proof is bounded only by the presence TTL.
        let actual = crate::fed::spki_sha256_from_der(leaf.as_ref()).ok()?;
        let not_after = crate::storage::now_epoch_secs().checked_add(super::MAX_TTL_SECS as i64)?;
        return Some((actual, not_after));
    }
    let uris = crate::fed::extract_uri_sans(leaf.as_ref()).ok()?;
    let [uri] = uris.as_slice() else {
        return None;
    };
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    Some((uri.clone(), cert.validity().not_after.timestamp()))
}

async fn discovered(
    fs: &FedState,
    peer: &PeerConfig,
    policy: &Arc<PeersMap>,
    candidate: Candidate,
) -> Result<PreparedDirect, AppError> {
    let _permit = fs
        .discovery
        .probes
        .acquire()
        .await
        .map_err(|_| AppError::Internal("discovery probes closed".into()))?;
    let tls = tokio::time::timeout(
        Duration::from_secs(2),
        connect(fs, peer, policy.clone(), &candidate.addr.to_string()),
    )
    .await
    .map_err(|_| AppError::PeerUnreachable("discovery handshake timed out".into()))??;
    let (verified_uri, not_after) = witness(&tls, peer)
        .ok_or_else(|| AppError::PeerRejected("discovery identity mismatch".into()))?;
    let now = Instant::now();
    let row = Presence {
        uri: verified_uri,
        rule: peer.name.clone(),
        policy: policy.clone(),
        expires_at: candidate.expires_at,
        candidate,
        verified_at: now,
        not_after,
    };
    tls.authority.check()?;
    let recorded = fs.with_discovery_policy(policy, || {
        fs.discovery
            .record_verified(row, policy, now, crate::storage::now_epoch_secs())
    });
    if recorded != Some(true) {
        return Err(AppError::PeerRejected(
            "discovery proof expired or policy changed".into(),
        ));
    }
    Ok(tls)
}

/// Resolves and authenticates a direct endpoint, or returns the existing operation-level hub route.
pub async fn resolve_dial(fs: &FedState, peer: &PeerConfig) -> Result<Dial, AppError> {
    let policy = fs.current_peers();
    let peer = policy
        .get_peer_config(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;
    resolve_with_policy(fs, peer, policy).await
}

pub(crate) async fn prepare_send(fs: &FedState, name: &str) -> Result<Option<Dial>, AppError> {
    let policy = fs.current_peers();
    let Some(peer) = policy
        .get(name)
        .filter(|peer| !peer.leaf && peer.address.is_empty() && exact_identity(peer).is_some())
    else {
        return Ok(None);
    };
    resolve_with_policy(fs, peer.clone(), policy)
        .await
        .map(Some)
}

async fn resolve_with_policy(
    fs: &FedState,
    peer: PeerConfig,
    policy: Arc<PeersMap>,
) -> Result<Dial, AppError> {
    if !peer.address.is_empty() {
        return connect(fs, &peer, policy.clone(), &peer.address)
            .await
            .map(|tls| Dial {
                inner: Route::Direct(Box::new(tls)),
                policy,
            });
    }
    let work = async {
        if let Some(uri) = exact_identity(&peer) {
            let cached = fs
                .with_discovery_policy(&policy, || {
                    fs.discovery.lookup(
                        uri,
                        &peer.name,
                        &policy,
                        Instant::now(),
                        crate::storage::now_epoch_secs(),
                    )
                })
                .flatten();
            if let Some(row) = cached {
                match discovered(fs, &peer, &policy, row.candidate.clone()).await {
                    Ok(tls) => return Some(tls),
                    Err(_) => {
                        let _ = fs.with_discovery_policy(&policy, || {
                            fs.discovery.evict(uri);
                            fs.discovery.negative(
                                row.candidate.addr,
                                &peer.name,
                                &policy,
                                row.candidate.expires_at,
                                Instant::now(),
                            );
                        });
                    }
                }
            }
            let mut pending = candidates(fs, &peer, &policy, Instant::now());
            fs.discovery
                .order_untried(&policy, &peer.name, &mut pending);
            for candidate in pending {
                let negative = fs.with_discovery_policy(&policy, || {
                    fs.discovery
                        .is_negative(candidate.addr, &peer.name, &policy, Instant::now())
                });
                match negative {
                    Some(false) => {}
                    Some(true) => continue,
                    None => return None,
                }
                fs.with_discovery_policy(&policy, || {
                    fs.discovery
                        .attempted(&policy, &peer.name, candidate.addr, Instant::now())
                })?;
                match discovered(fs, &peer, &policy, candidate.clone()).await {
                    Ok(tls) => return Some(tls),
                    Err(_) => {
                        let _ = fs.with_discovery_policy(&policy, || {
                            fs.discovery.negative(
                                candidate.addr,
                                &peer.name,
                                &policy,
                                candidate.expires_at,
                                Instant::now(),
                            )
                        });
                    }
                }
            }
        }
        None
    };
    let result = tokio::time::timeout(Duration::from_secs(8), work).await;
    if let Ok(Some(tls)) = result {
        return Ok(Dial {
            inner: Route::Direct(Box::new(tls)),
            policy,
        });
    }
    if let Some(hub) = &policy.default_route_peer {
        if hub != &peer.name {
            return Ok(Dial {
                inner: Route::ViaHub(hub.clone()),
                policy,
            });
        }
    }
    if result.is_err() {
        return Err(AppError::PeerUnreachable(
            "discovery budget exhausted".into(),
        ));
    }
    Err(AppError::UnknownPeer(peer.name.clone()))
}

pub fn is_direct(fs: &FedState, peer: &PeerConfig) -> bool {
    if peer.leaf {
        return true;
    }
    if !peer.address.is_empty() {
        return true;
    }
    let Some(uri) = exact_identity(peer) else {
        return false;
    };
    let policy = fs.current_peers();
    fs.with_discovery_policy(&policy, || {
        fs.discovery
            .lookup(
                uri,
                &peer.name,
                &policy,
                Instant::now(),
                crate::storage::now_epoch_secs(),
            )
            .is_some()
            || !candidates(fs, peer, &policy, Instant::now()).is_empty()
    })
    .unwrap_or(false)
}

pub(crate) fn conflicting_identities(
    name: &str,
    presence: Vec<String>,
    admitted: Vec<String>,
) -> Vec<String> {
    let identities = presence
        .into_iter()
        .chain(admitted)
        .filter(|uri| crate::node::node_name_from_uri(uri).is_ok_and(|derived| derived == name))
        .collect::<std::collections::BTreeSet<_>>();
    if identities.len() > 1 {
        identities.into_iter().collect()
    } else {
        Vec::new()
    }
}

pub(crate) fn identity_conflicts(fs: &FedState, name: &str) -> Vec<String> {
    let policy = fs.current_peers();
    if policy.get(name).is_some() {
        return Vec::new();
    }
    fs.with_discovery_policy(&policy, || {
        let presence =
            fs.discovery
                .identity_uris(&policy, Instant::now(), crate::storage::now_epoch_secs());
        conflicting_identities(name, presence, policy.admitted_leaf_uris())
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod ordering_tests {
    use super::*;
    use crate::discovery::{CandidateTable, Source};

    #[test]
    fn eligible_roots_deduplicate_unhinted_roots_and_preserve_global_order() {
        let now = Instant::now();
        let mut table = CandidateTable::new();
        for (address, root, hint) in [
            ("10.1.0.1:7777", None, None),
            ("10.1.0.2:7777", Some([2; 32]), Some("opaque")),
            ("10.1.0.3:7777", Some([3; 32]), Some("foreign")),
        ] {
            assert!(table.upsert(
                Candidate {
                    addr: address.parse().unwrap(),
                    source: Source::Mdns,
                    hint: hint.map(str::to_owned),
                    root_fp: root,
                    seen_at: now,
                    expires_at: now + Duration::from_secs(60),
                },
                now
            ));
        }
        let rows = eligible_candidates(&table, &[[1; 32], [2; 32]], now);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].addr, "10.1.0.2:7777".parse().unwrap());
        assert_eq!(rows[1].addr, "10.1.0.1:7777".parse().unwrap());
    }
}

#[cfg(test)]
#[path = "dial_tests.rs"]
mod tests;

pub fn spawn_sweep(fs: &Arc<FedState>) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(fs);
    let changed = fs.discovery.changed.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut next = 0usize;
        loop {
            tokio::select! {
                _ = tick.tick() => {},
                _ = changed.notified() => {},
            }
            let Some(fs) = weak.upgrade() else {
                break;
            };
            fs.discovery
                .candidates
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .expire(Instant::now());
            let policy = fs.current_peers();
            if !policy.discovery.source_enabled(super::Source::Mdns) {
                continue;
            }
            let mut peers = policy
                .values()
                .filter(|peer| {
                    !peer.leaf && peer.address.is_empty() && exact_identity(peer).is_some()
                })
                .cloned()
                .collect::<Vec<_>>();
            peers.sort_by(|a, b| a.name.cmp(&b.name));
            if peers.is_empty() {
                continue;
            }
            let sweep = async {
                for _ in 0..peers.len() {
                    let index = next % peers.len();
                    next = next.wrapping_add(1);
                    let _ = resolve_dial(&fs, &peers[index]).await;
                }
            };
            let _ = tokio::time::timeout(Duration::from_secs(8), sweep).await;
        }
    })
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn full_identity_union_retains_old_collisions_beyond_presentation_limit() {
        let first = "spiffe://first.test/host/n/user/owner".to_owned();
        let second = "spiffe://second.test/host/n/user/owner".to_owned();
        assert!(
            !conflicting_identities("owner.n", vec![first.clone(), second.clone()], Vec::new())
                .is_empty(),
            "distinct verified presence identities collapsed to one name"
        );
        let mut admitted = (0..501)
            .map(|index| format!("spiffe://test/host/h{index}/user/owner"))
            .collect::<Vec<_>>();
        admitted.push(second);
        assert!(
            !conflicting_identities("owner.n", vec![first.clone()], admitted).is_empty(),
            "complete presence/admitted union lost an older collision"
        );
        assert!(
            conflicting_identities("owner.n", vec![first.clone()], vec![first]).is_empty(),
            "the same full identity counted twice"
        );
    }
}
