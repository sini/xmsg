//! Discovery: candidate addresses learned from local sources.
//!
//! A candidate is only an address. It never admits, names or routes a peer: whoever answers at
//! it must still prove an identity in the federation handshake.

pub mod dial;
#[cfg(feature = "mdns")]
pub mod mdns;
pub mod state;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

/// The longest a candidate lives without a fresh sighting.
pub const MAX_TTL_SECS: u64 = 600;
/// A LAN announcer can flood, so the mDNS source keeps at most this many candidates.
pub const MDNS_CAP: usize = 64;
/// Total candidates retained across all compiled discovery sources.
pub const GLOBAL_CANDIDATE_CAP: usize = 64;
/// Bounded announcement window after a local discoverable activation.
pub const ANNOUNCE_WINDOW_SECS: u64 = 120;
/// Handle, service-instance and target-hostname rotation interval during announcement.
pub const HANDLE_ROTATE_SECS: u64 = 30;
/// Handshake concurrency, per-handshake timeout and resolution budget bounds.
pub const MAX_PAIRING_HANDSHAKES: usize = 4;
pub const PAIRING_HANDSHAKE_TIMEOUT_SECS: u64 = 2;
pub const RESOLVE_BUDGET_SECS: u64 = 8;

/// Controls when an enabled discovery source advertises this node (`discovery.announce`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnounceMode {
    /// Browse-only at rest; announces only during a bounded local-activation window (120 s).
    #[default]
    Timed,
    /// Never announce; browse only.
    BrowseOnly,
    /// Announce continuously (human-only loosening; surfaces a standing doctor warning).
    Always,
}

/// The peers file's top-level `discovery` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub mdns: Option<MdnsConfig>,
    pub announce: AnnounceMode,
    pub ttl_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mdns: None,
            announce: AnnounceMode::Timed,
            ttl_secs: MAX_TTL_SECS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdnsConfig {
    #[serde(default = "yes")]
    pub browse: bool,
    #[serde(default = "yes")]
    pub announce: bool,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    mdns: Option<MdnsConfig>,
    #[serde(default)]
    announce: AnnounceMode,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// An entry may omit `address` only when it names one exact identity (an exact-SPKI pin, or a
/// CA entry with one concrete URI) and an enabled source can find it.
pub(crate) fn permits_address_omission(exact_identity: bool, source_enabled: bool) -> bool {
    exact_identity && source_enabled
}

impl Config {
    /// Parses and validates the `discovery` value; `null` (the key absent) is discovery off.
    pub fn parse(value: serde_json::Value) -> Result<Self, String> {
        if value.is_null() {
            return Ok(Self::default());
        }
        if value.get("tailnet").is_some() {
            return Err("'discovery.tailnet' is not supported by this build".into());
        }
        let raw: RawConfig =
            serde_json::from_value(value).map_err(|e| format!("invalid 'discovery': {e}"))?;
        let ttl_secs = raw.ttl_secs.unwrap_or(MAX_TTL_SECS);
        if !(1..=MAX_TTL_SECS).contains(&ttl_secs) {
            return Err(format!(
                "'discovery.ttl_secs' must be between 1 and {MAX_TTL_SECS}"
            ));
        }
        let config = Self {
            mdns: raw.mdns,
            announce: raw.announce,
            ttl_secs,
        };
        if config.configured(Source::Mdns) && !config.source_enabled(Source::Mdns) {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    "'discovery.mdns' is configured, but mDNS is not compiled into this build"
                )
            });
        }
        Ok(config)
    }

    /// Effective announce posture for mDNS (`mdns.announce: false` maps to `BrowseOnly`).
    pub fn mdns_announce_mode(&self) -> AnnounceMode {
        match self.mdns {
            Some(m) if !m.announce => AnnounceMode::BrowseOnly,
            Some(_) => self.announce,
            None => AnnounceMode::BrowseOnly,
        }
    }

    /// The peers file turns this source on.
    pub fn configured(&self, source: Source) -> bool {
        match source {
            Source::Mdns => self
                .mdns
                .is_some_and(|m| m.browse || self.mdns_announce_mode() != AnnounceMode::BrowseOnly),
        }
    }

    /// The source is configured on and compiled into this build.
    pub fn source_enabled(&self, source: Source) -> bool {
        match source {
            Source::Mdns => self.configured(source) && cfg!(feature = "mdns"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    Mdns,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub addr: SocketAddr,
    pub source: Source,
    /// Opaque announcer id (TXT `id`). Never names or keys a presence.
    pub hint: Option<String>,
    /// Optional untrusted root-selection hint; mDNS supplies None.
    pub root_fp: Option<[u8; 32]>,
    pub seen_at: Instant,
    pub expires_at: Instant,
}

/// Plain data, no clock, no I/O; every method takes `now`.
#[derive(Debug, Default)]
pub struct CandidateTable {
    entries: HashMap<(Source, SocketAddr), Candidate>,
}

impl CandidateTable {
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.entries.keys().map(|(_, addr)| *addr).collect()
    }
}

/// Shared handle to the candidate table.
pub type SharedCandidates = std::sync::Arc<std::sync::RwLock<CandidateTable>>;

fn cap(source: Source) -> usize {
    match source {
        Source::Mdns => MDNS_CAP,
    }
}

/// Loopback, unspecified, multicast and link-local (IPv4 169.254/16, IPv6 fe80::/10) addresses
/// are never candidates. A link-local address needs a scope id to be dialled, and none is kept.
pub fn acceptable_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    let link_local = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || link_local)
}

impl CandidateTable {
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn inject_for_test(&mut self, candidate: Candidate) {
        self.entries
            .insert((candidate.source, candidate.addr), candidate);
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or refresh by (source, addr). A refresh replaces hint/root_fp and extends expires_at.
    /// Refused (returns false): loopback, unspecified, multicast, IPv6 link-local, already-expired.
    /// At the source's cap, evicts that source's entry with the oldest seen_at.
    pub fn upsert(&mut self, c: Candidate, now: Instant) -> bool {
        if !acceptable_ip(c.addr.ip()) || c.addr.port() == 0 || c.expires_at <= now {
            return false;
        }
        let key = (c.source, c.addr);
        if !self.entries.contains_key(&key)
            && self.entries.keys().filter(|k| k.0 == c.source).count() >= cap(c.source)
        {
            let oldest = self
                .entries
                .values()
                .filter(|e| e.source == c.source)
                .min_by_key(|e| e.seen_at)
                .map(|e| (e.source, e.addr));
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, c);
        true
    }

    /// Idempotent; true only when an entry was removed.
    pub fn remove(&mut self, source: Source, addr: SocketAddr) -> bool {
        self.entries.remove(&(source, addr)).is_some()
    }

    /// Interface change / source restart: keep only this source's entries the predicate accepts.
    pub fn retain_source(&mut self, source: Source, mut keep: impl FnMut(&Candidate) -> bool) {
        self.entries.retain(|k, c| k.0 != source || keep(c));
    }

    /// Source stopped (config off): drop all its entries.
    pub fn clear_source(&mut self, source: Source) {
        self.retain_source(source, |_| false);
    }

    /// Drops expired entries; called on the reconcile tick. Readers below also filter by `now`.
    pub fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, c| c.expires_at > now);
    }

    /// Eligibility for a rule: root_fp == Some(rule_root) or root_fp == None, unexpired.
    /// Order: hinted first, then newest seen_at.
    pub fn eligible(&self, rule_root: &[u8; 32], now: Instant) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = self
            .live(now)
            .filter(|c| c.root_fp.is_none_or(|fp| &fp == rule_root))
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.hint
                .is_some()
                .cmp(&a.hint.is_some())
                .then(b.seen_at.cmp(&a.seen_at))
        });
        out
    }

    /// Candidates with no root hint, the only ones an exact-SPKI rule may probe.
    /// Order: hinted first, then newest seen_at.
    pub fn unrooted(&self, now: Instant) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = self
            .live(now)
            .filter(|c| c.root_fp.is_none())
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.hint
                .is_some()
                .cmp(&a.hint.is_some())
                .then(b.seen_at.cmp(&a.seen_at))
        });
        out
    }

    /// Every unexpired candidate, newest first.
    pub fn snapshot(&self, now: Instant) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = self.live(now).cloned().collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.seen_at));
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn live(&self, now: Instant) -> impl Iterator<Item = &Candidate> {
        self.entries.values().filter(move |c| c.expires_at > now)
    }
}

/// The mDNS source's detector/runtime state, as health and doctor report it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    Off,
    Starting,
    /// A genuine reply from one of our own non-loopback LAN addresses answered our multicast query.
    Active,
    /// Outbound multicast sent without error, or no LAN IPv4 interface; permission not proven.
    Unverified,
    /// Debounced outbound multicast failures: Local Network permission suspected, never proven.
    PermissionSuspected,
    Failed,
}

/// Announce posture reported separately from [`State`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnounceState {
    #[default]
    AtRest,
    WindowOpen(u64),
    Always,
}

/// Monotonic announce posture stored inside [`Status`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnnouncePosture {
    #[default]
    AtRest,
    WindowOpen {
        until: Instant,
    },
    Always,
}

impl AnnouncePosture {
    pub fn snapshot(self, now: Instant) -> AnnounceState {
        match self {
            Self::AtRest => AnnounceState::AtRest,
            Self::WindowOpen { until } => match until.checked_duration_since(now) {
                Some(rem) if !rem.is_zero() => {
                    let secs = rem.as_secs() + u64::from(rem.subsec_nanos() > 0);
                    AnnounceState::WindowOpen(secs)
                }
                _ => AnnounceState::AtRest,
            },
            Self::Always => AnnounceState::Always,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub posture: AnnouncePosture,
    pub detail: String,
    /// Unix seconds of the last state change.
    pub since: Option<u64>,
}

impl Status {
    pub fn set(&mut self, state: State, detail: impl Into<String>) {
        if state != self.state || self.since.is_none() {
            self.since = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs());
        }
        self.state = state;
        self.detail = detail.into();
    }

    pub fn set_posture(&mut self, posture: AnnouncePosture) {
        self.posture = posture;
    }
}

pub type SharedStatus = Arc<Mutex<Status>>;

/// The `discovery` health field: `{mdns: {state, announce_state, announce_mode, detail, since, candidates}}`.
pub fn health(fed: Option<&crate::fed::FedState>) -> serde_json::Value {
    let now = Instant::now();
    let (mut status, candidates) = match fed {
        Some(f) => (
            f.discovery
                .mdns_status
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            f.discovery
                .candidates
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .snapshot(now)
                .iter()
                .filter(|c| c.source == Source::Mdns)
                .count(),
        ),
        None => (Status::default(), 0),
    };
    let config = fed.map(|f| f.current_peers().discovery.clone());
    let announce_mode = config
        .as_ref()
        .map_or(AnnounceMode::Timed, Config::mdns_announce_mode);
    if config.is_some_and(|c| c.configured(Source::Mdns) && !c.source_enabled(Source::Mdns)) {
        status.state = State::Off;
        status.posture = AnnouncePosture::AtRest;
        status.detail = "not compiled into this build".into();
    }
    let announce_state = status.posture.snapshot(now);
    serde_json::json!({"mdns": {
        "state": status.state,
        "announce_state": announce_state,
        "announce_mode": announce_mode,
        "detail": status.detail,
        "since": status.since,
        "candidates": candidates,
    }})
}

/// Starts the discovery sources on their own thread, writing directly into `fed.discovery`.
/// It never blocks the caller, and `serve` never waits on it.
pub fn spawn(fed: Option<Arc<crate::fed::FedState>>, fed_listen: Option<SocketAddr>) {
    #[cfg(feature = "mdns")]
    if let Some(fed) = fed {
        mdns::spawn(fed, fed_listen);
    }
    #[cfg(not(feature = "mdns"))]
    {
        let _ = (fed, fed_listen, Ordering::SeqCst);
    }
}

/// Local activation hook: requests a bounded 120 s announcement window when `discovery.announce`
/// is `timed` (used by local pairing activation and operator controls).
pub fn trigger_announce(fed: &crate::fed::FedState) -> bool {
    #[cfg(feature = "mdns")]
    {
        fed.discovery.mdns_trigger.store(true, Ordering::SeqCst);
        true
    }
    #[cfg(not(feature = "mdns"))]
    {
        let _ = fed;
        false
    }
}

/// Closes an active timed LAN announcement window when the last responder intent ends (§5.1).
pub fn close_announce(fed: &crate::fed::FedState) -> bool {
    #[cfg(feature = "mdns")]
    {
        fed.discovery.mdns_close_trigger.store(true, Ordering::SeqCst);
        true
    }
    #[cfg(not(feature = "mdns"))]
    {
        let _ = fed;
        false
    }
}

/// Withdraws the mDNS announcement and stops the source, waiting at most `bound`. Does
/// nothing when no source was started.
pub fn stop(bound: std::time::Duration) {
    #[cfg(feature = "mdns")]
    mdns::stop(bound);
    #[cfg(not(feature = "mdns"))]
    let _ = bound;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cand(addr: &str, root: Option<[u8; 32]>, seen: Instant, ttl: u64) -> Candidate {
        Candidate {
            addr: addr.parse().unwrap(),
            source: Source::Mdns,
            hint: None,
            root_fp: root,
            seen_at: seen,
            expires_at: seen + Duration::from_secs(ttl),
        }
    }

    #[test]
    fn absent_key_is_off_and_defaults_apply() {
        let off = Config::parse(serde_json::Value::Null).unwrap();
        assert_eq!(off, Config::default());
        assert!(!off.configured(Source::Mdns));
        let on = Config::parse(serde_json::json!({"mdns": {}})).unwrap();
        assert_eq!(
            on.mdns,
            Some(MdnsConfig {
                browse: true,
                announce: true
            })
        );
        assert_eq!(on.ttl_secs, MAX_TTL_SECS);
        assert!(on.configured(Source::Mdns));
    }

    #[test]
    fn refuses_tailnet_unknown_keys_and_bad_ttl() {
        let err = Config::parse(serde_json::json!({"tailnet": {"ports": [7788]}})).unwrap_err();
        assert!(err.contains("not supported by this build"), "{err}");
        for bad in [
            serde_json::json!({"mdsn": {}}),
            serde_json::json!({"mdns": {"brwse": true}}),
            serde_json::json!({"ttl_secs": 601}),
            serde_json::json!({"ttl_secs": 0}),
            serde_json::json!("on"),
        ] {
            assert!(Config::parse(bad.clone()).is_err(), "{bad} loaded");
        }
        assert_eq!(
            Config::parse(serde_json::json!({"ttl_secs": 600}))
                .unwrap()
                .ttl_secs,
            600
        );
    }

    #[test]
    fn refuses_unroutable_addresses() {
        let now = Instant::now();
        let mut t = CandidateTable::new();
        for addr in [
            "127.0.0.1:7788",
            "[::1]:7788",
            "0.0.0.0:7788",
            "[::]:7788",
            "224.0.0.251:7788",
            "[ff02::fb]:7788",
            "[fe80::1]:7788",
            "[febf::1]:7788",
            "[::ffff:127.0.0.1]:7788",
            "169.254.10.1:7788",
            "[::ffff:169.254.10.1]:7788",
            "10.0.0.1:0",
        ] {
            assert!(!t.upsert(cand(addr, None, now, 60), now), "{addr} accepted");
        }
        assert!(!t.upsert(cand("10.0.0.1:7788", None, now, 0), now));
        assert!(t.upsert(cand("10.0.0.1:7788", None, now, 60), now));
        assert!(t.upsert(cand("[2001:db8::1]:7788", None, now, 60), now));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn removal_is_idempotent() {
        let now = Instant::now();
        let mut t = CandidateTable::new();
        let c = cand("10.0.0.2:7788", None, now, 60);
        assert!(t.upsert(c.clone(), now));
        assert!(t.remove(Source::Mdns, c.addr));
        assert!(!t.remove(Source::Mdns, c.addr));
        assert!(!t.remove(Source::Mdns, c.addr));
        assert!(t.is_empty());
    }

    #[test]
    fn cap_evicts_the_oldest() {
        let start = Instant::now();
        let mut t = CandidateTable::new();
        for i in 0..1000u32 {
            let seen = start + Duration::from_millis(u64::from(i));
            let addr = format!("10.{}.{}.{}:7788", i >> 16, (i >> 8) & 0xff, i & 0xff);
            assert!(t.upsert(cand(&addr, None, seen, 60), seen));
        }
        assert_eq!(t.len(), MDNS_CAP);
        let now = start + Duration::from_secs(1);
        let snap = t.snapshot(now);
        assert_eq!(snap[0].addr, "10.0.3.231:7788".parse().unwrap());
        assert!(snap
            .iter()
            .all(|c| c.seen_at >= start + Duration::from_millis(1000 - MDNS_CAP as u64)));
    }

    #[test]
    fn eligibility_follows_the_root() {
        let now = Instant::now();
        let ours = [1u8; 32];
        let foreign = [2u8; 32];
        let mut t = CandidateTable::new();
        t.upsert(cand("10.0.0.1:7788", Some(foreign), now, 60), now);
        t.upsert(cand("10.0.0.2:7788", None, now, 60), now);
        let mut hinted = cand("10.0.0.3:7788", Some(ours), now, 60);
        hinted.hint = Some("abc".into());
        t.upsert(hinted, now);
        let got: Vec<String> = t
            .eligible(&ours, now)
            .iter()
            .map(|c| c.addr.to_string())
            .collect();
        assert_eq!(got, ["10.0.0.3:7788", "10.0.0.2:7788"]);
        assert!(t
            .eligible(&foreign, now)
            .iter()
            .all(|c| c.root_fp != Some(ours)));
        let later = now + Duration::from_secs(61);
        assert!(t.eligible(&ours, later).is_empty());
        t.expire(later);
        assert!(t.is_empty());
    }

    #[test]
    fn retain_and_clear_touch_only_their_source() {
        let now = Instant::now();
        let mut t = CandidateTable::new();
        t.upsert(cand("10.0.0.1:7788", None, now, 60), now);
        t.upsert(cand("10.0.0.2:7788", None, now, 60), now);
        t.retain_source(Source::Mdns, |c| c.addr.ip().to_string() == "10.0.0.1");
        assert_eq!(t.len(), 1);
        t.clear_source(Source::Mdns);
        assert!(t.is_empty());
    }

    #[test]
    fn peers_file_carries_the_key() {
        let load = |d: &str| {
            crate::fed::PeersMap::load_from_json(&format!(r#"{{"peers":{{}},"discovery":{d}}}"#))
        };
        let map = load(r#"{"mdns":{"announce":false},"ttl_secs":120}"#).unwrap();
        assert_eq!(map.discovery.ttl_secs, 120);
        assert!(!map.discovery.mdns.unwrap().announce);
        let err = load(r#"{"tailnet":{"ports":[7788]}}"#).unwrap_err();
        assert!(err.contains("not supported by this build"), "{err}");
        assert!(load(r#"{"mdns":{"extra":1}}"#).is_err());
        let none = crate::fed::PeersMap::load_from_json(r#"{"peers":{}}"#).unwrap();
        assert_eq!(none.discovery, Config::default());
    }

    #[test]
    fn address_omission_requires_an_exact_identity_and_an_available_source() {
        assert!(permits_address_omission(true, true));
        assert!(
            !permits_address_omission(false, true),
            "entry without an exact identity accepted source-dependent omission"
        );
        assert!(
            !permits_address_omission(true, false),
            "unavailable source accepted omission"
        );
        assert!(!permits_address_omission(false, false));
    }

    #[test]
    fn mdns_is_enabled_only_when_configured_and_compiled() {
        let off = Config::default();
        assert!(!off.source_enabled(Source::Mdns));
        assert_eq!(off.announce, AnnounceMode::Timed);
        let neither =
            Config::parse(serde_json::json!({"mdns": {"browse": false, "announce": false}}));
        assert!(!neither.unwrap().source_enabled(Source::Mdns));
        let browse_off_mode_off = Config::parse(
            serde_json::json!({"mdns": {"browse": false}, "announce": "browse_only"}),
        )
        .unwrap();
        assert!(!browse_off_mode_off.configured(Source::Mdns));
        let on = Config::parse(serde_json::json!({"mdns": {}})).unwrap();
        assert!(on.configured(Source::Mdns));
        assert_eq!(on.mdns_announce_mode(), AnnounceMode::Timed);
        assert_eq!(on.source_enabled(Source::Mdns), cfg!(feature = "mdns"));
        let compat_off = Config::parse(serde_json::json!({"mdns": {"announce": false}})).unwrap();
        assert_eq!(compat_off.mdns_announce_mode(), AnnounceMode::BrowseOnly);
        let always = Config::parse(serde_json::json!({"mdns": {}, "announce": "always"})).unwrap();
        assert_eq!(always.mdns_announce_mode(), AnnounceMode::Always);
        assert!(Config::parse(serde_json::json!({"mdns": {}, "announce": "bogus"})).is_err());
    }

    #[cfg(not(feature = "mdns"))]
    #[test]
    fn mdns_is_not_enabled_without_a_backend() {
        let on = Config::parse(serde_json::json!({"mdns": {}})).unwrap();
        assert!(on.configured(Source::Mdns));
        assert!(!on.source_enabled(Source::Mdns));
    }
}
