//! Discovery: candidate addresses learned from local sources.
//!
//! A candidate is only an address. It never admits, names or routes a peer: whoever answers at
//! it must still prove an identity in the federation handshake.

pub mod dial;
pub mod state;

use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// The longest a candidate lives without a fresh sighting.
pub const MAX_TTL_SECS: u64 = 600;
/// A LAN announcer can flood, so the mDNS source keeps at most this many candidates.
pub const MDNS_CAP: usize = 64;

/// The peers file's top-level `discovery` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub mdns: Option<MdnsConfig>,
    pub ttl_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mdns: None,
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
    ttl_secs: Option<u64>,
}

pub(crate) fn permits_address_omission(has_ca: bool, source_enabled: bool) -> bool {
    has_ca && source_enabled
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

    /// The peers file turns this source on.
    pub fn configured(&self, source: Source) -> bool {
        match source {
            Source::Mdns => self.mdns.is_some_and(|m| m.browse || m.announce),
        }
    }

    /// The source is configured on and compiled into this build.
    pub fn source_enabled(&self, source: Source) -> bool {
        match source {
            // shortcut: no mDNS backend exists yet, so nothing may claim the source runs.
            Source::Mdns => false,
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
    /// sha256 of the announced trust root (TXT `root`), or None = eligible for every rule.
    pub root_fp: Option<[u8; 32]>,
    pub seen_at: Instant,
    pub expires_at: Instant,
}

/// Plain data, no clock, no I/O; every method takes `now`.
#[derive(Debug, Default)]
pub struct CandidateTable {
    entries: HashMap<(Source, SocketAddr), Candidate>,
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
    fn address_omission_requires_ca_and_an_available_source() {
        assert!(permits_address_omission(true, true));
        assert!(
            !permits_address_omission(false, true),
            "pin-only entry accepted source-dependent omission"
        );
        assert!(
            !permits_address_omission(true, false),
            "unavailable source accepted omission"
        );
        assert!(!permits_address_omission(false, false));
    }

    #[test]
    fn mdns_is_not_enabled_without_a_backend() {
        let on = Config::parse(serde_json::json!({"mdns": {}})).unwrap();
        assert!(on.configured(Source::Mdns));
        assert!(!on.source_enabled(Source::Mdns));
    }
}
