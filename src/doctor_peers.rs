use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::fed::{FedState, PeerConfig};

const MAX_PEERS: usize = 32;
const CONCURRENT_PEERS: usize = 4;
const PEER_TIMEOUT: Duration = Duration::from_secs(2);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(8);
const OFFSET_TOLERANCE: f64 = 120.0;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Certificate {
    subject: String,
    issuer: String,
    not_after: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Peer {
    name: String,
    reachability: &'static str,
    reason: &'static str,
    leaf: Option<Certificate>,
    expiry: &'static str,
    offset_state: &'static str,
    observed_offset_seconds: Option<f64>,
    offset_uncertainty_seconds: Option<f64>,
}

impl Peer {
    fn new(name: &str) -> Self {
        Self {
            name: name.chars().take(512).collect(),
            reachability: "unknown",
            reason: "not_attempted",
            leaf: None,
            expiry: "unknown",
            offset_state: "unknown",
            observed_offset_seconds: None,
            offset_uncertainty_seconds: None,
        }
    }
}

fn outbound_only(peer: &PeerConfig) -> bool {
    peer.leaf && peer.address.is_empty()
}

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    available: bool,
    ambiguous_aliases: bool,
    own_leaf: Option<Certificate>,
    own_expiry: &'static str,
    peers: Vec<Peer>,
    partial: bool,
    truncated: bool,
    budget_exhausted: bool,
}

fn expiry_state(not_before: i64, not_after: i64, now: i64) -> &'static str {
    if not_after <= now {
        return "expired";
    }
    let Some(lifetime) = not_after.checked_sub(not_before).filter(|value| *value > 0) else {
        return "unknown";
    };
    let warning_window = (7 * 86400).min(lifetime / 3);
    let remaining = not_after.saturating_sub(now);
    if remaining <= warning_window {
        "expiring"
    } else {
        "valid"
    }
}

fn certificate(der: &[u8], now: i64) -> Option<(Certificate, &'static str)> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    let not_after = parsed.validity().not_after.timestamp();
    let expiry = expiry_state(parsed.validity().not_before.timestamp(), not_after, now);
    Some((
        Certificate {
            subject: parsed.subject().to_string().chars().take(512).collect(),
            issuer: parsed.issuer().to_string().chars().take(512).collect(),
            not_after,
        },
        expiry,
    ))
}

fn wall_seconds() -> Option<f64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs_f64())
}

fn observed_offset(
    date: &str,
    wall_before: f64,
    wall_after: f64,
    elapsed: Duration,
) -> Option<(f64, f64, &'static str)> {
    let parsed = chrono::DateTime::parse_from_rfc2822(date).ok()?;
    if date.len() != 29 || parsed.format("%a, %d %b %Y %H:%M:%S GMT").to_string() != date {
        return None;
    }
    let elapsed = elapsed.as_secs_f64();
    if (wall_after - wall_before - elapsed).abs() > 0.1 {
        return None;
    }
    let offset = parsed.timestamp() as f64 - (wall_before + elapsed / 2.0);
    let uncertainty = elapsed / 2.0 + 1.0;
    let state = if offset.abs() - uncertainty > OFFSET_TOLERANCE {
        "beyond_tolerance"
    } else if offset.abs() + uncertainty <= OFFSET_TOLERANCE {
        "within_tolerance"
    } else {
        "unknown"
    };
    Some((offset, uncertainty, state))
}

type Probe = Pin<Box<dyn Future<Output = usize> + Send>>;

async fn next_probe(probes: &mut Vec<Probe>) -> usize {
    poll_fn(|context| {
        for index in 0..probes.len() {
            if let Poll::Ready(result) = probes[index].as_mut().poll(context) {
                drop(probes.swap_remove(index));
                return Poll::Ready(result);
            }
        }
        Poll::Pending
    })
    .await
}

async fn probe(fed: Arc<FedState>, peer: PeerConfig, progress: Arc<Mutex<Peer>>) {
    if peer.leaf || peer.address.is_empty() {
        progress.lock().unwrap().reason = "not_dialable";
        return;
    }
    let work = async {
        let connector = match crate::fed::make_tls_connector_for_peer(&fed, &peer) {
            Ok(connector) => connector,
            Err(_) => {
                progress.lock().unwrap().reason = "tls_configuration";
                return;
            }
        };
        let server_name = match rustls::pki_types::ServerName::try_from(peer.name.clone()) {
            Ok(name) => name,
            Err(_) => {
                progress.lock().unwrap().reason = "tls_configuration";
                return;
            }
        };
        let tcp = match tokio::net::TcpStream::connect(&peer.address).await {
            Ok(tcp) => tcp,
            Err(_) => {
                let mut row = progress.lock().unwrap();
                row.reachability = "unreachable";
                row.reason = "connect_failed";
                return;
            }
        };
        let tls = match connector.connect(server_name, tcp).await {
            Ok(tls) => tls,
            Err(_) => {
                let mut row = progress.lock().unwrap();
                row.reachability = "unreachable";
                row.reason = "tls_failed";
                return;
            }
        };
        {
            let mut row = progress.lock().unwrap();
            row.reachability = "reachable";
            row.reason = "authenticated_tls";
            let leaf = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first());
            if let Some((leaf, expiry)) =
                leaf.and_then(|leaf| certificate(leaf.as_ref(), crate::storage::now_epoch_secs()))
            {
                row.leaf = Some(leaf);
                row.expiry = expiry;
            }
        }
        let authority =
            match crate::fed::CurrentLeaf::outbound(&fed, connector.admission_mode(), &tls) {
                Ok(authority) => authority,
                Err(_) => {
                    progress.lock().unwrap().reason = "peer_denied";
                    return;
                }
            };
        let io = hyper_util::rt::TokioIo::new(tls);
        let (mut sender, connection) = match hyper::client::conn::http1::Builder::new()
            .max_buf_size(16 * 1024)
            .handshake(io)
            .await
        {
            Ok(connection) => connection,
            Err(_) => {
                progress.lock().unwrap().reason = "head_failed";
                return;
            }
        };
        let request = match hyper::Request::builder()
            .method("HEAD")
            .uri("/")
            .header("host", &peer.name)
            .header(
                "user-agent",
                concat!("xmsg-doctor/", env!("CARGO_PKG_VERSION")),
            )
            .header("connection", "close")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
        {
            Ok(request) => request,
            Err(_) => {
                progress.lock().unwrap().reason = "head_failed";
                return;
            }
        };
        let wall_before = wall_seconds();
        let started = Instant::now();
        if authority.check().is_err() {
            progress.lock().unwrap().reason = "peer_denied";
            return;
        }
        let response = sender.send_request(request);
        tokio::pin!(connection);
        tokio::pin!(response);
        let response = tokio::select! {
            result = &mut response => result,
            _ = &mut connection => response.await,
        };
        if authority.check().is_err() {
            progress.lock().unwrap().reason = "peer_denied";
            return;
        }
        let elapsed = started.elapsed();
        let wall_after = wall_seconds();
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                progress.lock().unwrap().reason = "head_failed";
                return;
            }
        };
        if response.status() != hyper::StatusCode::NOT_FOUND {
            progress.lock().unwrap().reason = "unexpected_status";
            return;
        }
        let mut dates = response.headers().get_all(hyper::header::DATE).iter();
        let date = dates.next().and_then(|value| value.to_str().ok());
        let offset = match (date, dates.next(), wall_before, wall_after) {
            (Some(date), None, Some(before), Some(after)) => {
                observed_offset(date, before, after, elapsed)
            }
            _ => None,
        };
        let Some((offset, uncertainty, state)) = offset else {
            progress.lock().unwrap().reason = "date_unavailable";
            return;
        };
        let mut row = progress.lock().unwrap();
        row.offset_state = state;
        row.observed_offset_seconds = Some(offset);
        row.offset_uncertainty_seconds = Some(uncertainty);
    };
    if tokio::time::timeout(PEER_TIMEOUT, work).await.is_err() {
        let mut row = progress.lock().unwrap();
        if row.reachability != "reachable" {
            row.reachability = "unreachable";
        }
        row.reason = "peer_timeout";
    }
}

pub(crate) async fn collect(fed: Option<Arc<FedState>>) -> Report {
    let Some(fed) = fed else {
        return Report {
            available: false,
            ambiguous_aliases: false,
            own_leaf: None,
            own_expiry: "unknown",
            peers: Vec::new(),
            partial: true,
            truncated: false,
            budget_exhausted: false,
        };
    };
    let deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;
    let own = fed
        .cert_chain()
        .first()
        .and_then(|leaf| certificate(leaf.as_ref(), crate::storage::now_epoch_secs()));
    let (own_leaf, own_expiry) = match own {
        Some((leaf, expiry)) => (Some(leaf), expiry),
        None => (None, "unknown"),
    };
    let current = fed.current_peers();
    let ambiguous_aliases = !current.ambiguous_alias_classes().is_empty();
    let mut configured = current
        .iter()
        .map(|(_, peer)| peer.clone())
        .collect::<Vec<_>>();
    configured.sort_by(|left, right| left.name.cmp(&right.name));
    let truncated = configured.len() > MAX_PEERS;
    configured.truncate(MAX_PEERS);
    let progress = configured
        .iter()
        .map(|peer| {
            let mut row = Peer::new(&peer.name);
            if outbound_only(peer) {
                row.reason = "outbound_only";
            }
            Arc::new(Mutex::new(row))
        })
        .collect::<Vec<_>>();
    let mut completed = configured.iter().map(outbound_only).collect::<Vec<_>>();
    let mut pending = Vec::<Probe>::new();
    let mut next = 0;
    let mut budget_exhausted = false;
    while next < configured.len() || !pending.is_empty() {
        if tokio::time::Instant::now() >= deadline {
            budget_exhausted = true;
            break;
        }
        while next < configured.len() && pending.len() < CONCURRENT_PEERS {
            if completed[next] {
                next += 1;
                continue;
            }
            let index = next;
            let fed = fed.clone();
            let peer = configured[index].clone();
            let progress = progress[index].clone();
            pending.push(Box::pin(async move {
                probe(fed, peer, progress).await;
                index
            }));
            next += 1;
        }
        if pending.is_empty() {
            continue;
        }
        match tokio::time::timeout_at(deadline, next_probe(&mut pending)).await {
            Ok(index) => completed[index] = true,
            Err(_) => {
                budget_exhausted = true;
                break;
            }
        }
    }
    drop(pending);
    let peers = progress
        .into_iter()
        .enumerate()
        .map(|(index, progress)| {
            let mut row = progress.lock().unwrap().clone();
            if !completed[index] {
                row.reason = "budget_exhausted";
            }
            row
        })
        .collect::<Vec<_>>();
    let partial = truncated
        || budget_exhausted
        || own_expiry == "unknown"
        || peers.iter().any(|peer| {
            peer.reason != "outbound_only"
                && (peer.reachability == "unknown"
                    || peer.expiry == "unknown"
                    || peer.offset_state == "unknown")
        });
    Report {
        available: true,
        ambiguous_aliases,
        own_leaf,
        own_expiry,
        peers,
        partial,
        truncated,
        budget_exhausted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_warning_is_capped_by_one_third_of_lifetime() {
        assert_eq!(expiry_state(0, 900, 599), "valid");
        assert_eq!(expiry_state(0, 900, 600), "expiring");
        assert_eq!(expiry_state(0, 900, 900), "expired");
        assert_eq!(expiry_state(0, 30 * 86400, 24 * 86400), "expiring");
        assert_eq!(expiry_state(0, 30 * 86400, 22 * 86400), "valid");
    }

    #[test]
    fn observed_offset_accounts_for_uncertainty_and_rejects_wall_clock_jumps() {
        let date = "Sun, 15 Nov 2026 12:00:00 GMT";
        let timestamp = chrono::DateTime::parse_from_rfc2822(date)
            .unwrap()
            .timestamp() as f64;
        assert_eq!(
            observed_offset(date, timestamp, timestamp + 0.2, Duration::from_millis(200))
                .unwrap()
                .2,
            "within_tolerance"
        );
        assert_eq!(
            observed_offset(
                date,
                timestamp - 600.0,
                timestamp - 599.8,
                Duration::from_millis(200)
            )
            .unwrap()
            .2,
            "beyond_tolerance"
        );
        assert_eq!(
            observed_offset(
                date,
                timestamp - 120.0,
                timestamp - 119.8,
                Duration::from_millis(200)
            )
            .unwrap()
            .2,
            "unknown"
        );
        assert!(observed_offset(
            date,
            timestamp,
            timestamp + 10.2,
            Duration::from_millis(200)
        )
        .is_none());
        assert!(observed_offset("bad date", timestamp, timestamp, Duration::ZERO).is_none());
    }

    #[tokio::test]
    async fn owned_pool_drops_pending_probe_futures() {
        struct Dropped(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = dropped.clone();
        let guard = Dropped(flag);
        let mut pending: Vec<Probe> = vec![
            Box::pin(async move {
                let _guard = guard;
                std::future::pending::<usize>().await
            }),
            Box::pin(async { 7 }),
        ];
        assert_eq!(next_probe(&mut pending).await, 7);
        drop(pending);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }
}
