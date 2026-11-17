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
}

enum Route {
    Direct(TlsStream<TcpStream>),
    ViaHub(String),
}

impl Dial {
    pub fn into_direct(self) -> Result<TlsStream<TcpStream>, AppError> {
        match self.inner {
            Route::Direct(stream) => Ok(stream),
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
) -> Result<TlsStream<TcpStream>, AppError> {
    let (chain, key, current) = fs.dial_credentials();
    if !Arc::ptr_eq(&current, &policy) {
        return Err(AppError::PeerRejected("discovery policy changed".into()));
    }
    let connector =
        crate::fed::make_tls_connector_with_credentials(chain, key, peer, policy.clone())?;
    let name =
        ServerName::try_from(peer.name.clone()).map_err(|e| AppError::Internal(e.to_string()))?;
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|e| AppError::PeerUnreachable(format!("connecting to {}: {e}", peer.name)))?;
    let tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| crate::fed::map_tls_connect_error(&peer.name, e))?;
    if !Arc::ptr_eq(&fs.current_peers(), &policy) {
        return Err(AppError::PeerRejected("discovery policy changed".into()));
    }
    Ok(tls)
}

fn exact_uri(peer: &PeerConfig) -> Option<&str> {
    if peer.pin.is_some() {
        return None;
    }
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

fn witness(tls: &TlsStream<TcpStream>) -> Option<(String, i64)> {
    let leaf = tls.get_ref().1.peer_certificates()?.first()?;
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
) -> Result<TlsStream<TcpStream>, AppError> {
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
    let (verified_uri, not_after) = witness(&tls)
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
    if !fs.discovery.record_verified(
        row,
        &fs.current_peers(),
        now,
        crate::storage::now_epoch_secs(),
    ) {
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
    if !peer.address.is_empty() {
        return connect(fs, &peer, policy, &peer.address)
            .await
            .map(|tls| Dial {
                inner: Route::Direct(tls),
            });
    }
    let work = async {
        if let Some(uri) = exact_uri(&peer) {
            if let Some(row) = fs.discovery.lookup(
                uri,
                &peer.name,
                &policy,
                Instant::now(),
                crate::storage::now_epoch_secs(),
            ) {
                match discovered(fs, &peer, &policy, row.candidate.clone()).await {
                    Ok(tls) => return Some(tls),
                    Err(_) => {
                        fs.discovery.evict(uri);
                        fs.discovery.negative(
                            row.candidate.addr,
                            &peer.name,
                            &policy,
                            row.candidate.expires_at,
                            Instant::now(),
                        );
                    }
                }
            }
            for candidate in candidates(fs, &peer, &policy, Instant::now()) {
                if fs
                    .discovery
                    .is_negative(candidate.addr, &peer.name, &policy, Instant::now())
                {
                    continue;
                }
                match discovered(fs, &peer, &policy, candidate.clone()).await {
                    Ok(tls) => return Some(tls),
                    Err(_) => fs.discovery.negative(
                        candidate.addr,
                        &peer.name,
                        &policy,
                        candidate.expires_at,
                        Instant::now(),
                    ),
                }
            }
        }
        None
    };
    let result = tokio::time::timeout(Duration::from_secs(8), work).await;
    if let Ok(Some(tls)) = result {
        return Ok(Dial {
            inner: Route::Direct(tls),
        });
    }
    if let Some(hub) = &policy.default_route_peer {
        if hub != &peer.name {
            return Ok(Dial {
                inner: Route::ViaHub(hub.clone()),
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
        return false;
    }
    if !peer.address.is_empty() {
        return true;
    }
    let Some(uri) = exact_uri(peer) else {
        return false;
    };
    let policy = fs.current_peers();
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
