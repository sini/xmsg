use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{DefaultBodyLimit, Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tracing::{debug, info};

use crate::error::AppError;
use crate::inbox::{self, DeliveryResponse};
use crate::storage::{self, MessageRecord};

#[derive(Deserialize)]
struct WireErrorResponse {
    #[serde(default)]
    error: String,
    detail: String,
}

/// The header marking a send routed by a cached location as live-only (gate v0 C9). It
/// belongs to one delivery attempt, not to the message: the same message, re-resolved, is
/// sent again without it.
pub const LIVE_ONLY_HEADER: &str = "xmsg-live-only";

// -----------------------------------------------------------------------------
// Peers Configuration & File Format
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities: Option<Vec<String>>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<String>>,
    #[serde(default)]
    pub leaf: bool,
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial: Option<String>,
}

impl PeerConfig {
    pub fn is_outbound(&self) -> bool {
        self.dial.as_deref() == Some("outbound")
    }
}

/// Filter-entry prefixes from before XA2. An entry starting with one of these and `:` is
/// refused at load, naming the form that replaced it. The list is enumerated, not a
/// `<word>:<rest>` shape, so `anon:<from>` stays admitted.
const RETIRED_FILTER_KINDS: [&str; 6] = ["svc", "session", "claude", "agy", "pi", "http"];

fn check_filter_entry(peer: &str, field: &str, entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err(format!("peer '{peer}': empty '{field}' entry"));
    }
    if let Some((kind, rest)) = entry.split_once(':') {
        if RETIRED_FILTER_KINDS.contains(&kind) {
            return Err(format!(
                "peer '{peer}': '{field}' entry '{entry}' uses the retired '{kind}:' form; \
                 filters match a service name or an instance ID itself (e.g. '{rest}'){}",
                if field == "principals" {
                    ", or 'anon:<from>'"
                } else {
                    ""
                }
            ));
        }
    }
    Ok(())
}

/// The service name or instance ID a filter matches for a resolved target. Instance labels
/// are never matched.
fn target_filter_key(target: &crate::http::ResolvedTarget) -> &str {
    match target {
        crate::http::ResolvedTarget::Svc(s) => s
            .name
            .as_deref()
            .unwrap_or_else(|| s.session_id.strip_prefix("svc:").unwrap_or(&s.session_id)),
        crate::http::ResolvedTarget::Claude(s, _)
        | crate::http::ResolvedTarget::Agy(s)
        | crate::http::ResolvedTarget::Pi(s)
        | crate::http::ResolvedTarget::Parked { session: s, .. } => &s.session_id,
    }
}

pub(crate) fn target_matches_allowlist(
    target: &crate::http::ResolvedTarget,
    targets: &[String],
) -> bool {
    let key = target_filter_key(target);
    targets.iter().any(|t| t == key)
}

/// Before resolution: could `target_ref` name an allowed target? The ref is read in the
/// destination's grammar (`http::resolve_target`): an instance ID or a name, with no kind
/// prefix (A3, B4). A `svc:`, `session:` or harness-prefixed ref is not a ref there, so it
/// matches no entry here (an entry carrying such a prefix is refused at load).
pub(crate) fn target_ref_could_match(target_ref: &str, targets: &[String]) -> bool {
    targets.iter().any(|t| t == target_ref)
}

/// The key a sender is filtered and rate-limited by: its service name, its instance ID, or
/// `anon:<from>`.
pub(crate) fn origin_filter_key(origin: &storage::Origin) -> String {
    match origin.key() {
        Some(key) => key.to_string(),
        None => format!("anon:{}", origin.label.as_deref().unwrap_or_default()),
    }
}

/// Does a `principals` filter admit this sender? It matches the service name, the
/// instance ID, or `anon:<from>`.
pub(crate) fn principal_allowed(origin: &storage::Origin, principals: &[String]) -> bool {
    principals.contains(&origin_filter_key(origin))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpCidr {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl IpCidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|e| format!("invalid IP in CIDR '{s}': {e}"))?;
            let prefix: u32 = prefix_str
                .parse()
                .map_err(|e| format!("invalid prefix in CIDR '{s}': {e}"))?;
            match ip {
                IpAddr::V4(v4) => {
                    if prefix > 32 {
                        return Err(format!("prefix /{prefix} out of bounds for IPv4 in '{s}'"));
                    }
                    let mask = if prefix == 0 {
                        0
                    } else {
                        (!0u32) << (32 - prefix)
                    };
                    let net = u32::from(v4) & mask;
                    Ok(IpCidr::V4 { net, mask })
                }
                IpAddr::V6(v6) => {
                    if prefix > 128 {
                        return Err(format!("prefix /{prefix} out of bounds for IPv6 in '{s}'"));
                    }
                    let mask = if prefix == 0 {
                        0
                    } else {
                        (!0u128) << (128 - prefix)
                    };
                    let net = u128::from(v6) & mask;
                    Ok(IpCidr::V6 { net, mask })
                }
            }
        } else {
            let ip: IpAddr = s
                .parse()
                .map_err(|e| format!("invalid IP address '{s}': {e}"))?;
            match ip {
                IpAddr::V4(v4) => Ok(IpCidr::V4 {
                    net: u32::from(v4),
                    mask: !0u32,
                }),
                IpAddr::V6(v6) => Ok(IpCidr::V6 {
                    net: u128::from(v6),
                    mask: !0u128,
                }),
            }
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let canonical_ip = match ip {
            IpAddr::V4(v4) => IpAddr::V4(*v4),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    IpAddr::V4(v4)
                } else {
                    IpAddr::V6(*v6)
                }
            }
        };
        match (self, canonical_ip) {
            (IpCidr::V4 { net, mask }, IpAddr::V4(v4)) => (u32::from(v4) & mask) == *net,
            (IpCidr::V6 { net, mask }, IpAddr::V6(v6)) => (u128::from(v6) & mask) == *net,
            _ => false,
        }
    }
}

pub fn check_peer_source(peer_cfg: &PeerConfig, remote_ip: &IpAddr) -> Result<(), AppError> {
    if let Some(ref from_list) = peer_cfg.from {
        let mut allowed = false;
        for cidr_str in from_list {
            if let Ok(cidr) = IpCidr::parse(cidr_str) {
                if cidr.contains(remote_ip) {
                    allowed = true;
                    break;
                }
            }
        }
        if !allowed {
            return Err(AppError::PeerRejected(format!(
                "remote IP {remote_ip} not allowed by peer 'from' CIDR rules"
            )));
        }
    }
    Ok(())
}

pub fn uri_matches_identity(uri: &str, pattern: &str) -> bool {
    if let Some(prefix_base) = pattern.strip_suffix("/*") {
        if uri.contains('?') || uri.contains('#') {
            return false;
        }
        let path_part = uri.split_once("://").map(|(_, p)| p).unwrap_or(uri);
        if path_part.contains("//") {
            return false;
        }
        for seg in path_part.split('/') {
            if seg == "." || seg == ".." {
                return false;
            }
        }
        let prefix_with_slash = format!("{prefix_base}/");
        let Some(rem) = uri.strip_prefix(&prefix_with_slash) else {
            return false;
        };
        if rem.is_empty() || rem.ends_with('/') {
            return false;
        }
        true
    } else {
        uri == pattern
    }
}

pub fn uri_matches_any_identity(uri: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| uri_matches_identity(uri, p))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubRule {
    pub pattern: String,
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubConfig {
    pub patterns: Vec<String>,
    pub rules: Vec<HubRule>,
}

#[derive(Debug, Clone)]
pub struct AdmittedClient {
    pub canonical_name: String,
    pub uri: String,
    pub pin: String,
    pub config: PeerConfig,
}

/// Matches a SPIFFE URI against an identity pattern.
/// Pattern matching is on the full SPIFFE URI with '*' matching exactly one path segment (no '/' inside).
/// Names compare exactly.
pub fn spiffe_uri_matches_pattern(uri: &str, pattern: &str) -> bool {
    let (Some(uri_body), Some(pat_body)) = (
        uri.strip_prefix("spiffe://"),
        pattern.strip_prefix("spiffe://"),
    ) else {
        return false;
    };
    if uri.contains('?') || uri.contains('#') {
        return false;
    }
    let u_segs: Vec<&str> = uri_body.split('/').collect();
    let p_segs: Vec<&str> = pat_body.split('/').collect();
    if u_segs.len() != p_segs.len() {
        return false;
    }
    for (u, p) in u_segs.iter().zip(p_segs.iter()) {
        if u.is_empty() || *u == "." || *u == ".." {
            return false;
        }
        if *p == "*" {
            continue;
        }
        if u != p {
            return false;
        }
    }
    true
}

/// Validates a SPIFFE URI pattern at configuration load time.
/// Wildcards are only supported as a single, entire path segment '*'.
pub fn validate_spiffe_pattern(pattern: &str) -> Result<(), String> {
    let Some(body) = pattern.strip_prefix("spiffe://") else {
        return Err(format!(
            "identity pattern '{pattern}' must start with 'spiffe://'"
        ));
    };
    if pattern.contains('?') || pattern.contains('#') {
        return Err(format!(
            "identity pattern '{pattern}' contains forbidden query/fragment"
        ));
    }
    let segs: Vec<&str> = body.split('/').collect();
    if segs.len() < 2 {
        return Err(format!(
            "identity pattern '{pattern}' must contain an authority and a path"
        ));
    }
    for seg in segs {
        if seg.is_empty() {
            return Err(format!(
                "identity pattern '{pattern}' contains an empty path segment"
            ));
        }
        if seg == "." || seg == ".." {
            return Err(format!(
                "identity pattern '{pattern}' contains relative path segments"
            ));
        }
        if seg.contains('*') && seg != "*" {
            return Err(format!("invalid identity pattern '{pattern}': wildcards only supported as a full segment '*'"));
        }
    }
    Ok(())
}

/// Returns true if an admission pattern and a rule pattern could match a common URI.
/// "Orphaned rule": defined as no admission pattern that could match any URI
/// the rule matches (segment-wise, where '*' meets a literal or '*').
pub fn patterns_compatible(admission: &str, rule: &str) -> bool {
    let (Some(adm_body), Some(rule_body)) = (
        admission.strip_prefix("spiffe://"),
        rule.strip_prefix("spiffe://"),
    ) else {
        return false;
    };
    let adm_segs: Vec<&str> = adm_body.split('/').collect();
    let rule_segs: Vec<&str> = rule_body.split('/').collect();
    if adm_segs.len() != rule_segs.len() {
        return false;
    }
    for (a, r) in adm_segs.iter().zip(rule_segs.iter()) {
        if *a != "*" && *r != "*" && a != r {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Default)]
pub struct PeersMap {
    peers_by_name: HashMap<String, PeerConfig>,
    name_by_pin: HashMap<String, String>,
    ca_bundles_by_name: HashMap<String, Vec<rustls::pki_types::TrustAnchor<'static>>>,
    /// Entry key -> canonical node name, and back (B5's nickname translation).
    canonical_by_name: HashMap<String, String>,
    name_by_canonical: HashMap<String, String>,
    pub hub: Option<HubConfig>,
    pub admitted_clients: Arc<std::sync::RwLock<HashMap<String, AdmittedClient>>>,
    pub default_route_peer: Option<String>,
}

/// This node's own identity, for the peers loader's namespace checks.
#[derive(Debug, Clone)]
pub struct OwnNode {
    pub name: String,
    pub pin: Option<String>,
}

/// A peer entry's canonical node name: derived from its single CA identity, or from its
/// pin. A map built in code rather than by the loader may hold entries the rules refuse;
/// those keep their key as their name.
fn derive_canonical(peer: &PeerConfig) -> String {
    let derived = match (&peer.pin, &peer.identities) {
        (Some(pin), _) => crate::node::node_name_from_pin(pin).ok(),
        (None, Some(ids)) if ids.len() == 1 => crate::node::node_name_from_uri(&ids[0]).ok(),
        _ => None,
    };
    derived.unwrap_or_else(|| peer.name.clone())
}

/// Collects a JSON object's members in order, keeping duplicate keys, which
/// `serde_json::Value` would silently collapse to the last one.
struct Members(Vec<(String, serde_json::Value)>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Members;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<Members, A::Error> {
                let mut v = Vec::new();
                while let Some(kv) = m.next_entry()? {
                    v.push(kv);
                }
                Ok(Members(v))
            }
        }
        d.deserialize_map(V)
    }
}

impl PeersMap {
    pub fn new(peers: HashMap<String, PeerConfig>) -> Self {
        let mut map = Self::default();
        for (_, peer) in peers {
            let _ = map.insert(peer);
        }
        map
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, mut peer: PeerConfig) -> Result<(), String> {
        if self.peers_by_name.contains_key(&peer.name) {
            return Err(format!("duplicate peer name '{}'", peer.name));
        }
        if let Some(ref pin) = peer.pin {
            let norm_pin = normalize_pin(pin);
            peer.pin = Some(norm_pin.clone());
            self.name_by_pin.insert(norm_pin, peer.name.clone());
        }
        let canonical = derive_canonical(&peer);
        self.name_by_canonical
            .insert(canonical.clone(), peer.name.clone());
        self.canonical_by_name.insert(peer.name.clone(), canonical);
        self.peers_by_name.insert(peer.name.clone(), peer);
        Ok(())
    }

    pub fn insert_with_anchors(
        &mut self,
        mut peer: PeerConfig,
        anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
    ) -> Result<(), String> {
        if self.peers_by_name.contains_key(&peer.name) {
            return Err(format!("duplicate peer name '{}'", peer.name));
        }
        if let Some(ref pin) = peer.pin {
            let norm_pin = normalize_pin(pin);
            peer.pin = Some(norm_pin.clone());
            self.name_by_pin.insert(norm_pin, peer.name.clone());
        }
        let canonical = derive_canonical(&peer);
        self.name_by_canonical
            .insert(canonical.clone(), peer.name.clone());
        self.canonical_by_name.insert(peer.name.clone(), canonical);
        self.ca_bundles_by_name.insert(peer.name.clone(), anchors);
        self.peers_by_name.insert(peer.name.clone(), peer);
        Ok(())
    }

    pub fn set_default_route(&mut self, peer_name: &str) -> Result<(), String> {
        if !self.peers_by_name.contains_key(peer_name) {
            return Err(format!("unknown peer '{peer_name}'"));
        }
        if self.default_route_peer.is_some()
            && self.default_route_peer.as_deref() != Some(peer_name)
        {
            return Err(format!(
                "at most one peer may be marked 'default_route' (default route): found duplicate on '{peer_name}'"
            ));
        }
        self.default_route_peer = Some(peer_name.to_string());
        Ok(())
    }

    pub fn default_route_peer(&self) -> Option<&str> {
        self.default_route_peer.as_deref()
    }

    pub fn default_route_link(&self) -> Option<&PeerConfig> {
        self.default_route_peer.as_deref().and_then(|p| self.get(p))
    }

    /// A peer by its entry key, or by its canonical node name.
    pub fn get(&self, name: &str) -> Option<&PeerConfig> {
        self.peers_by_name.get(name).or_else(|| {
            self.name_by_canonical
                .get(name)
                .and_then(|k| self.peers_by_name.get(k))
        })
    }

    /// The entry key for a typed `@node`: a local nickname, or a canonical name.
    pub fn key_for(&self, typed: &str) -> Option<&str> {
        self.get(typed).map(|p| p.name.as_str())
    }

    /// The canonical node name of the entry keyed `key`; this is what crosses the wire.
    pub fn canonical_name(&self, key: &str) -> Option<&str> {
        self.canonical_by_name.get(key).map(String::as_str)
    }

    /// How this node shows a canonical node name: its local nickname when it has one, the
    /// canonical name otherwise.
    pub fn display_name<'a>(&'a self, canonical: &'a str) -> &'a str {
        self.name_by_canonical
            .get(canonical)
            .map(String::as_str)
            .unwrap_or(canonical)
    }

    pub fn get_by_pin(&self, pin: &str) -> Option<&PeerConfig> {
        let norm = normalize_pin(pin);
        self.name_by_pin
            .get(&norm)
            .and_then(|name| self.peers_by_name.get(name))
    }

    pub fn ca_peers(&self) -> Vec<&PeerConfig> {
        self.peers_by_name
            .values()
            .filter(|p| p.ca.is_some() || self.ca_bundles_by_name.contains_key(&p.name))
            .collect()
    }

    pub fn get_ca_anchors(&self, name: &str) -> Option<&[rustls::pki_types::TrustAnchor<'static>]> {
        self.ca_bundles_by_name.get(name).map(|v| v.as_slice())
    }

    pub fn update_ca_anchors(
        &mut self,
        name: &str,
        anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
    ) {
        self.ca_bundles_by_name.insert(name.to_string(), anchors);
    }

    pub fn all_ca_anchors(&self) -> Vec<rustls::pki_types::TrustAnchor<'static>> {
        let mut anchors = Vec::new();
        for bundle in self.ca_bundles_by_name.values() {
            anchors.extend(bundle.iter().cloned());
        }
        anchors
    }

    pub fn contains_concrete_name(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn get_peer_config(&self, name: &str) -> Option<PeerConfig> {
        if let Some(p) = self.get(name) {
            return Some(p.clone());
        }
        if let Ok(admitted) = self.admitted_clients.read() {
            if let Some(adm) = admitted.get(name) {
                return Some(adm.config.clone());
            }
        }
        None
    }

    pub fn contains_name(&self, name: &str) -> bool {
        self.get(name).is_some()
            || self
                .admitted_clients
                .read()
                .ok()
                .is_some_and(|adm| adm.contains_key(name))
    }

    pub fn is_empty(&self) -> bool {
        self.peers_by_name.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.peers_by_name.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &PeerConfig)> {
        self.peers_by_name.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &PeerConfig> {
        self.peers_by_name.values()
    }

    /// Every pinned entry's pin -> entry key.
    pub fn pinned_entries(&self) -> HashMap<String, String> {
        self.name_by_pin.clone()
    }

    pub fn allowed_pins(&self) -> HashMap<String, String> {
        self.peers_by_name
            .values()
            .filter(|p| !p.allow.is_empty())
            .filter_map(|p| p.pin.as_ref().map(|pin| (pin.clone(), p.name.clone())))
            .collect()
    }
}

fn parse_hub_config(hub_val: &serde_json::Value) -> Result<HubConfig, String> {
    let hub_obj = hub_val
        .as_object()
        .ok_or_else(|| "'hub' field must be an object".to_string())?;

    for k in hub_obj.keys() {
        match k.as_str() {
            "patterns" | "rules" => {}
            other => return Err(format!("unknown field '{other}' in hub config")),
        }
    }

    let pat_arr = hub_obj
        .get("patterns")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "hub config missing required 'patterns' array".to_string())?;
    if pat_arr.is_empty() {
        return Err("hub 'patterns' array must not be empty".to_string());
    }

    let mut patterns = Vec::new();
    for p_val in pat_arr {
        let p_str = p_val
            .as_str()
            .ok_or_else(|| "hub 'patterns' elements must be strings".to_string())?;
        validate_spiffe_pattern(p_str)?;
        patterns.push(p_str.to_string());
    }

    let mut rules = Vec::new();
    if let Some(r_val) = hub_obj.get("rules") {
        let r_arr = r_val
            .as_array()
            .ok_or_else(|| "hub 'rules' must be an array".to_string())?;
        let mut seen_rule_patterns = std::collections::HashSet::new();
        for item in r_arr {
            let r_obj = item
                .as_object()
                .ok_or_else(|| "hub rule must be an object".to_string())?;
            for k in r_obj.keys() {
                match k.as_str() {
                    "pattern" | "allow" => {}
                    other => return Err(format!("unknown field '{other}' in hub rule")),
                }
            }
            let pat = r_obj
                .get("pattern")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "hub rule missing 'pattern'".to_string())?;
            validate_spiffe_pattern(pat)?;
            if !seen_rule_patterns.insert(pat.to_string()) {
                return Err(format!("duplicate hub rule pattern '{pat}'"));
            }

            let allow_arr = r_obj
                .get("allow")
                .and_then(|v| v.as_array())
                .ok_or_else(|| format!("hub rule for pattern '{pat}' missing 'allow' array"))?;
            if allow_arr.is_empty() {
                return Err(format!(
                    "hub rule for pattern '{pat}' has empty 'allow' list"
                ));
            }
            let mut allow = Vec::new();
            for op_val in allow_arr {
                let op = op_val.as_str().ok_or_else(|| {
                    format!("hub rule for pattern '{pat}': 'allow' items must be strings")
                })?;
                match op {
                    "send" | "reply" | "list" | "forward" => allow.push(op.to_string()),
                    other => {
                        return Err(format!(
                            "unknown operation '{other}' in hub rule for pattern '{pat}'"
                        ))
                    }
                }
            }

            // Orphaned rule check (Amendment 7):
            // "Orphaned rule": define it as no admission pattern that could match any URI
            // the rule matches (segment-wise, where * meets literal or *).
            if !patterns.iter().any(|adm| patterns_compatible(adm, pat)) {
                return Err(format!(
                    "orphaned hub rule for pattern '{pat}': no admission pattern matches it"
                ));
            }

            rules.push(HubRule {
                pattern: pat.to_string(),
                allow,
            });
        }
    }

    Ok(HubConfig { patterns, rules })
}

impl PeersMap {
    pub fn load_from_json(json_str: &str) -> Result<Self, String> {
        Self::load_from_json_for(json_str, None)
    }

    /// Loads a peers file for the node `own` (when known), applying A9's naming rules:
    /// a CA entry is keyed by the name its one identity derives (D10); a pinned entry's
    /// key is a nickname or its key-derived name; every canonical name, this node's own
    /// included, is distinct (A-8); a nickname is not name-shaped (AM-5); no entry pins
    /// this node's own key (AM-6).
    pub fn load_from_json_for(json_str: &str, own: Option<&OwnNode>) -> Result<Self, String> {
        let val: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse peers JSON: {e}"))?;

        type PeerObjects = Vec<(String, serde_json::Map<String, serde_json::Value>)>;
        let member_objects = |members: Members| -> Result<PeerObjects, String> {
            members
                .0
                .into_iter()
                .map(|(k, v)| match v {
                    serde_json::Value::Object(obj) => Ok((k, obj)),
                    _ => Err(format!("peer entry for '{k}' must be an object")),
                })
                .collect()
        };
        let mut hub_config: Option<HubConfig> = None;
        let mut is_wrapped = false;
        let owned_entries: PeerObjects = match &val {
            serde_json::Value::Object(map) => {
                is_wrapped = map.contains_key("peers");

                if is_wrapped {
                    for k in map.keys() {
                        match k.as_str() {
                            "peers" | "hub" => {}
                            other => {
                                return Err(format!("unknown field '{other}' in peers config"));
                            }
                        }
                    }

                    if let Some(hub_val) = map.get("hub") {
                        hub_config = Some(parse_hub_config(hub_val)?);
                    }

                    #[derive(Deserialize)]
                    struct Wrapped {
                        peers: Members,
                    }
                    let w: Wrapped = serde_json::from_str(json_str)
                        .map_err(|_| "'peers' field must be an object".to_string())?;
                    member_objects(w.peers)?
                } else {
                    let m: Members = serde_json::from_str(json_str)
                        .map_err(|e| format!("Failed to parse peers JSON: {e}"))?;
                    member_objects(m)?
                }
            }
            serde_json::Value::Array(list) => list
                .iter()
                .map(|item| {
                    let obj = item
                        .as_object()
                        .ok_or_else(|| "peer list element must be an object".to_string())?;
                    let name = obj
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| "peer list entry missing 'name' field".to_string())?;
                    Ok((name.to_string(), obj.clone()))
                })
                .collect::<Result<Vec<_>, String>>()?,
            _ => return Err("peers JSON must be an object or an array".to_string()),
        };
        let entries = owned_entries.iter().map(|(k, o)| (k.clone(), o));

        // Each parsed entry, with its canonical node name and what derived it.
        let mut parsed: Vec<(
            PeerConfig,
            Option<Vec<rustls::pki_types::TrustAnchor<'static>>>,
            String,
            String,
        )> = Vec::new();
        let mut default_routes: Vec<String> = Vec::new();
        let has_default_route = owned_entries.iter().any(|(_, obj)| {
            obj.get("default_route")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        });
        for (key_name, obj) in entries {
            if !is_wrapped
                && key_name == "hub"
                && (obj.contains_key("patterns") || obj.contains_key("rules"))
            {
                return Err(
                    "hub block is only permitted in wrapped form: expected {\"peers\": {...}, \"hub\": {...}}"
                        .to_string(),
                );
            }

            let name = obj
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or(&key_name)
                .to_string();

            // Oracle 5: A peers file that still carries no_whois is a load error naming the field
            if obj.contains_key("no_whois") {
                return Err(format!(
                    "unknown field 'no_whois' in peer config for '{name}': whois has been removed in favor of 'from' CIDR allowlist"
                ));
            }

            // Check for unknown fields
            for k in obj.keys() {
                match k.as_str() {
                    "name" | "address" | "pin" | "ca" | "identities" | "allow" | "from"
                    | "leaf" | "principals" | "targets" | "dial" | "default_route" => {}
                    other => {
                        return Err(format!(
                            "unknown field '{other}' in peer config for '{name}'"
                        ));
                    }
                }
            }

            let address = obj
                .get("address")
                .and_then(|a| a.as_str())
                .unwrap_or("")
                .to_string();

            let has_pin = obj.contains_key("pin");
            let has_ca = obj.contains_key("ca");
            let has_identities = obj.contains_key("identities");

            if has_pin && has_ca {
                return Err(format!(
                    "peer '{name}' specifies both 'pin' and 'ca': exactly one trust mechanism is allowed"
                ));
            }
            if !has_pin && !has_ca {
                return Err(format!(
                    "peer '{name}' missing trust mechanism: must specify either 'pin' or 'ca'"
                ));
            }
            if has_pin && has_identities {
                return Err(format!(
                    "peer '{name}' specifies 'identities' with 'pin': 'identities' is only valid with 'ca'"
                ));
            }
            if has_ca && !has_identities {
                return Err(format!(
                    "peer '{name}' specifies 'ca' but missing required 'identities'"
                ));
            }

            let pin: Option<String> = if has_pin {
                let p = obj
                    .get("pin")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("peer '{name}': 'pin' must be a string"))?;
                Some(p.to_string())
            } else {
                None
            };

            let (ca, identities, ca_anchors) = if has_ca {
                let ca_str = obj
                    .get("ca")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("peer '{name}': 'ca' must be a file path string"))?;
                let ca_path = PathBuf::from(ca_str);
                let pem_bytes = std::fs::read(&ca_path).map_err(|e| {
                    format!(
                        "peer '{name}': failed to read CA file {}: {e}",
                        ca_path.display()
                    )
                })?;
                let anchors =
                    parse_ca_bundle_pem(&pem_bytes).map_err(|e| format!("peer '{name}': {e}"))?;

                let ids_val = obj
                    .get("identities")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| format!("peer '{name}': 'identities' must be an array"))?;
                if ids_val.is_empty() {
                    return Err(format!(
                        "peer '{name}': 'identities' must contain at least one identity"
                    ));
                }
                if ids_val.len() > 1 {
                    return Err(format!(
                        "peer '{name}': a CA entry names exactly one node, so 'identities' holds exactly one identity (found {})",
                        ids_val.len()
                    ));
                }
                let mut ids = Vec::with_capacity(ids_val.len());
                for item in ids_val {
                    let s = item.as_str().ok_or_else(|| {
                        format!("peer '{name}': 'identities' elements must be strings")
                    })?;
                    if s.is_empty() {
                        return Err(format!(
                            "peer '{name}': empty identity pattern is not allowed"
                        ));
                    }
                    if s.contains('*') && (!s.ends_with("/*") || s[..s.len() - 2].contains('*')) {
                        return Err(format!(
                            "peer '{name}': invalid identity pattern '{s}': wildcards only supported as a single trailing '/*'"
                        ));
                    }
                    if s.contains('*') {
                        return Err(format!(
                            "peer '{name}': identity pattern '{s}' names no single node; a CA entry needs one concrete identity"
                        ));
                    }
                    ids.push(s.to_string());
                }
                (Some(ca_path), Some(ids), Some(anchors))
            } else {
                (None, None, None)
            };

            let allow: Vec<String> = if let Some(al) = obj.get("allow") {
                let arr = al
                    .as_array()
                    .ok_or_else(|| format!("peer '{name}': 'allow' must be an array"))?;
                arr.iter()
                    .map(|v| {
                        v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                            format!("peer '{name}': 'allow' elements must be strings")
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?
            } else {
                Vec::new()
            };

            // Oracle 3: from: [] is a config ERROR at load (refuse to start), naming the peer
            let from: Option<Vec<String>> = if let Some(fr) = obj.get("from") {
                let arr = fr
                    .as_array()
                    .ok_or_else(|| format!("peer '{name}': 'from' must be an array"))?;
                if arr.is_empty() {
                    return Err(format!(
                        "peer '{name}' has empty 'from' list: 'from' must contain at least one CIDR, or be omitted for pin-only"
                    ));
                }
                let mut cidr_strings = Vec::with_capacity(arr.len());
                for item in arr {
                    let s = item
                        .as_str()
                        .ok_or_else(|| format!("peer '{name}': 'from' items must be strings"))?;
                    IpCidr::parse(s)
                        .map_err(|e| format!("peer '{name}' invalid CIDR in 'from': {e}"))?;
                    cidr_strings.push(s.to_string());
                }
                Some(cidr_strings)
            } else {
                None
            };

            let leaf = obj.get("leaf").and_then(|l| l.as_bool()).unwrap_or(false);

            let dial: Option<String> = if let Some(d) = obj.get("dial") {
                let s = d
                    .as_str()
                    .ok_or_else(|| format!("peer '{name}': 'dial' must be a string"))?;
                if s != "outbound" {
                    return Err(format!(
                        "peer '{name}': invalid value '{s}' for 'dial': expected 'outbound'"
                    ));
                }
                Some(s.to_string())
            } else {
                None
            };

            if leaf && dial.is_some() {
                return Err(format!(
                    "peer '{name}': cannot specify both 'leaf' and 'dial'"
                ));
            }

            let is_default_route = obj
                .get("default_route")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_default_route && address.is_empty() {
                return Err(format!(
                    "peer '{name}' marked 'default_route' missing required field 'address'"
                ));
            }
            if !leaf && address.is_empty() && !has_default_route {
                return Err(format!("peer '{name}' missing required field 'address'"));
            }

            let principals: Vec<String> = if let Some(pr) = obj.get("principals") {
                let arr = pr
                    .as_array()
                    .ok_or_else(|| format!("peer '{name}': 'principals' must be an array"))?;
                arr.iter()
                    .map(|v| {
                        let s = v.as_str().ok_or_else(|| {
                            format!("peer '{name}': 'principals' elements must be strings")
                        })?;
                        check_filter_entry(&name, "principals", s)?;
                        Ok(s.to_string())
                    })
                    .collect::<Result<Vec<_>, String>>()?
            } else {
                Vec::new()
            };

            let targets: Option<Vec<String>> = if let Some(trg) = obj.get("targets") {
                let arr = trg
                    .as_array()
                    .ok_or_else(|| format!("peer '{name}': 'targets' must be an array"))?;
                let mut target_list = Vec::with_capacity(arr.len());
                for v in arr {
                    let s = v.as_str().ok_or_else(|| {
                        format!("peer '{name}': 'targets' elements must be strings")
                    })?;
                    check_filter_entry(&name, "targets", s)?;
                    target_list.push(s.to_string());
                }
                Some(target_list)
            } else {
                None
            };

            // A9 / B5: the entry's canonical node name, and the key rules (D10, AM-5).
            let (canonical, source) = if let Some(ref p) = pin {
                let canonical = crate::node::node_name_from_pin(p)
                    .map_err(|e| format!("peer '{name}': {e}"))?;
                if name != canonical {
                    if name.contains('.') {
                        return Err(format!(
                            "peer '{name}': a nickname may not contain '.', which marks a certificate-derived node name"
                        ));
                    }
                    if crate::node::is_key_name_shaped(&name) {
                        return Err(format!(
                            "peer '{name}': a nickname may not be {} characters of [a-z2-7], the shape of a key-derived node name",
                            crate::node::KEY_NAME_LEN
                        ));
                    }
                }
                (canonical, format!("pin {}", normalize_pin(p)))
            } else {
                let uri = identities
                    .as_ref()
                    .and_then(|ids| ids.first())
                    .cloned()
                    .unwrap_or_default();
                let canonical = crate::node::node_name_from_uri(&uri)
                    .map_err(|e| format!("peer '{name}': {e}"))?;
                if name != canonical {
                    return Err(format!(
                        "peer '{name}': a CA entry is keyed by its node name; {uri} is '{canonical}'"
                    ));
                }
                (canonical, uri)
            };

            let is_default_route: bool = if let Some(v) = obj.get("default_route") {
                v.as_bool()
                    .ok_or_else(|| format!("peer '{name}': 'default_route' must be a boolean"))?
            } else {
                false
            };

            let peer_config = PeerConfig {
                name: name.clone(),
                address,
                pin,
                ca,
                identities,
                allow,
                from,
                leaf,
                principals,
                targets,
                dial,
            };
            parsed.push((peer_config, ca_anchors, canonical, source));
            if is_default_route {
                default_routes.push(name.clone());
            }
        }

        check_node_namespace(&parsed, own)?;

        if default_routes.len() > 1 {
            return Err(format!(
                "at most one peer may be marked 'default_route' (default route): found {}",
                default_routes.len()
            ));
        }

        if let Some(ref hub) = hub_config {
            let total_ca_anchors: usize = parsed
                .iter()
                .filter_map(|(_, a, _, _)| a.as_ref())
                .map(|v| v.len())
                .sum();
            if total_ca_anchors == 0 {
                return Err(
                    "hub configuration requires at least one CA trust anchor from peers; no CA peer configured".to_string(),
                );
            }

            for pattern in &hub.patterns {
                if !pattern.contains('*') {
                    if let Ok(canonical) = crate::node::node_name_from_uri(pattern) {
                        if let Some(own) = own {
                            if canonical == own.name {
                                return Err(format!(
                                    "hub pattern '{pattern}' derives this node's own name '{canonical}'"
                                ));
                            }
                        }
                        if parsed.iter().any(|(_, _, c, _)| c == &canonical) {
                            return Err(format!(
                                "hub pattern '{pattern}' derives node name '{canonical}', colliding with concrete peer"
                            ));
                        }
                    }
                }
            }
        }

        let mut map = Self::empty();
        for (peer_config, ca_anchors, _, _) in parsed {
            if let Some(anchors) = ca_anchors {
                map.insert_with_anchors(peer_config, anchors)?;
            } else {
                map.insert(peer_config)?;
            }
        }
        map.default_route_peer = default_routes.into_iter().next();
        if let Some(hub) = hub_config {
            map.hub = Some(hub);
        }
        Ok(map)
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        Self::load_from_file_for(path, None)
    }

    pub fn load_from_file_for(path: &Path, own: Option<&OwnNode>) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read peers file {}: {e}", path.display()))?;
        Self::load_from_json_for(&content, own)
    }

    /// The CA entries a certificate authenticates as: its single URI SAN matches the
    /// entry's identities and it chains to the entry's anchors for `usage`. Inbound
    /// admission and AM-6 on a pinned dial both use this one test.
    pub fn ca_entries_for(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        usage: webpki::KeyUsage,
    ) -> Vec<(&PeerConfig, String)> {
        let uris = extract_uri_sans(leaf.as_ref()).unwrap_or_default();
        let [uri] = uris.as_slice() else {
            return Vec::new();
        };
        self.ca_peers()
            .into_iter()
            .filter(|peer| {
                peer.identities
                    .as_ref()
                    .is_some_and(|ids| uri_matches_any_identity(uri, ids))
                    && self.get_ca_anchors(&peer.name).is_some_and(|anchors| {
                        verify_cert_chain(leaf, intermediates, anchors, now, usage).is_ok()
                    })
            })
            .map(|peer| (peer, uri.clone()))
            .collect()
    }

    pub fn resolve_incoming_peer(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(PeerConfig, Option<String>), AppError> {
        let client_pin = spki_sha256_from_der(leaf.as_ref())
            .map_err(|e| AppError::Internal(format!("Failed to compute SPKI pin: {e}")))?;
        let norm_pin = normalize_pin(&client_pin);
        let any_pin_match = self.get_by_pin(&norm_pin);

        let mut ca_matches: Vec<(&PeerConfig, String)> = self
            .ca_entries_for(
                leaf,
                intermediates,
                UnixTime::now(),
                webpki::KeyUsage::client_auth(),
            )
            .into_iter()
            .filter(|(p, _)| !p.allow.is_empty())
            .collect();

        if let Some(pin_peer) = any_pin_match {
            if !ca_matches.is_empty() {
                let msg = one_node_two_names(
                    &pin_peer.name,
                    ca_matches.iter().map(|(p, _)| p.name.as_str()),
                );
                tracing::warn!("{msg}");
                return Err(AppError::PeerRejected(msg));
            }
            if pin_peer.allow.is_empty() {
                return Err(AppError::PeerRejected(format!(
                    "peer '{}' has empty allow list (outbound-only)",
                    pin_peer.name
                )));
            }
            return Ok((pin_peer.clone(), None));
        }

        if ca_matches.len() > 1 {
            tracing::warn!(
                "Presented certificate matches multiple CA peers; refusing (fail closed)"
            );
            return Err(AppError::PeerRejected(
                "client certificate matches multiple CA peers; refusing (fail closed)".to_string(),
            ));
        }

        if ca_matches.len() == 1 {
            let (peer, uri) = ca_matches.remove(0);
            return Ok((peer.clone(), Some(uri)));
        }

        if let Some(ref hub) = self.hub {
            let uris = extract_uri_sans(leaf.as_ref()).unwrap_or_default();
            if uris.len() == 1 {
                let uri = &uris[0];
                let matches_pattern = hub
                    .patterns
                    .iter()
                    .any(|pat| spiffe_uri_matches_pattern(uri, pat));
                if matches_pattern {
                    let all_anchors = self.all_ca_anchors();
                    if verify_cert_chain(
                        leaf,
                        intermediates,
                        &all_anchors,
                        UnixTime::now(),
                        webpki::KeyUsage::client_auth(),
                    )
                    .is_ok()
                    {
                        let canonical =
                            crate::node::node_name_from_uri(uri).map_err(AppError::PeerRejected)?;

                        // Amendment 3: A pattern-derived name equal to a concrete peer's name is refused
                        if self.contains_concrete_name(&canonical) {
                            let msg = format!(
                                "hub admitted identity '{uri}' derives name '{canonical}', colliding with concrete peer"
                            );
                            tracing::warn!("{msg}");
                            return Err(AppError::PeerRejected(msg));
                        }

                        // Rules table: find matching rule (closed by default if none)
                        let allow = hub
                            .rules
                            .iter()
                            .find(|r| spiffe_uri_matches_pattern(uri, &r.pattern))
                            .map(|r| r.allow.clone())
                            .unwrap_or_default();

                        let peer_config = PeerConfig {
                            name: canonical.clone(),
                            address: String::new(),
                            pin: Some(norm_pin.clone()),
                            ca: None,
                            identities: Some(vec![uri.clone()]),
                            allow,
                            from: None,
                            leaf: false,
                            principals: Vec::new(),
                            targets: None,
                            dial: None,
                        };

                        // Amendment 4 / Oracle 6: collision check and insert under single write lock
                        {
                            let mut admitted = self
                                .admitted_clients
                                .write()
                                .map_err(|e| AppError::Internal(e.to_string()))?;
                            if let Some(existing) = admitted.get(&canonical) {
                                if existing.uri != *uri {
                                    let msg = format!(
                                        "node name '{canonical}' collision: existing client URI '{}' vs incoming '{uri}'",
                                        existing.uri
                                    );
                                    tracing::warn!("{msg}");
                                    return Err(AppError::PeerRejected(msg));
                                }
                            } else {
                                admitted.insert(
                                    canonical.clone(),
                                    AdmittedClient {
                                        canonical_name: canonical.clone(),
                                        uri: uri.clone(),
                                        pin: norm_pin,
                                        config: peer_config.clone(),
                                    },
                                );
                            }
                        }

                        return Ok((peer_config, Some(uri.clone())));
                    }
                }
            }
        }

        Err(AppError::PeerRejected(
            "client certificate did not match any allowed pin or CA peer".to_string(),
        ))
    }
}

pub fn load_peers_file(path: &Path) -> Result<PeersMap, String> {
    PeersMap::load_from_file(path)
}

/// A-8 and AM-6 over a parsed peers file: host, pod and key-derived names share one
/// namespace with this node's own name, and no entry pins this node's own key.
#[allow(clippy::type_complexity)]
fn check_node_namespace(
    parsed: &[(
        PeerConfig,
        Option<Vec<rustls::pki_types::TrustAnchor<'static>>>,
        String,
        String,
    )],
    own: Option<&OwnNode>,
) -> Result<(), String> {
    let mut seen: HashMap<&str, (&str, &str)> = HashMap::new();
    for (peer, _, canonical, source) in parsed {
        if let Some(own) = own {
            if *canonical == own.name {
                return Err(format!(
                    "node name '{canonical}' collides: peer '{}' ({source}) has this node's own name",
                    peer.name
                ));
            }
            if let (Some(pin), Some(own_pin)) = (&peer.pin, &own.pin) {
                if normalize_pin(pin) == normalize_pin(own_pin) {
                    return Err(format!(
                        "peer '{}' pins this node's own key; one node has one canonical name ('{}')",
                        peer.name, own.name
                    ));
                }
            }
        }
        if let Some((other, other_source)) = seen.insert(canonical, (&peer.name, source)) {
            return Err(format!(
                "node name '{canonical}' collides: peer '{other}' ({other_source}) and peer '{}' ({source})",
                peer.name
            ));
        }
    }
    Ok(())
}

/// A ref as it goes on the wire: in `<ref>@<node>` (a hop through a hub), a node this
/// node knows by nickname is written as its canonical name.
pub fn wire_ref(peers: &PeersMap, r: &str) -> String {
    match split_peer_ref(r) {
        Some((target, node)) => match peers.get(node).and_then(|p| peers.canonical_name(&p.name)) {
            Some(canonical) => format!("{target}@{canonical}"),
            None => r.to_string(),
        },
        None => r.to_string(),
    }
}

pub fn split_peer_ref(r: &str) -> Option<(&str, &str)> {
    let r = r.trim();
    if let Some(pos) = r.rfind('@') {
        let target = &r[..pos];
        let host = &r[pos + 1..];
        if !target.is_empty() && !host.is_empty() {
            return Some((target, host));
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Pin Extraction & Normalization
// -----------------------------------------------------------------------------

pub fn normalize_pin(pin: &str) -> String {
    let s = pin.trim();
    let s = s.strip_prefix("sha256:").unwrap_or(s);
    let s = s.strip_prefix("SHA256:").unwrap_or(s);
    s.to_ascii_lowercase()
}

pub fn spki_sha256_from_der(cert_der: &[u8]) -> Result<String, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;
    let spki_bytes = cert.tbs_certificate.subject_pki.raw;
    use sha2::Digest;
    let hash = sha2::Sha256::digest(spki_bytes);
    Ok(hex::encode(hash))
}

pub fn extract_uri_sans(cert_der: &[u8]) -> Result<Vec<String>, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;
    let mut uris = Vec::new();
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    uris.push(uri.to_string());
                }
            }
        }
    }
    Ok(uris)
}

pub fn parse_ca_bundle_pem(
    pem_bytes: &[u8],
) -> Result<Vec<rustls::pki_types::TrustAnchor<'static>>, String> {
    use rustls::pki_types::pem::PemObject;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse CA PEM bundle: {e}"))?;

    if certs.is_empty() {
        return Err("CA PEM bundle contains 0 certificates".to_string());
    }

    let mut anchors = Vec::with_capacity(certs.len());
    for cert in &certs {
        let is_ca = {
            let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
                .map_err(|e| format!("failed to parse certificate in CA bundle: {e}"))?;
            let mut found_ca = false;
            for ext in parsed.extensions() {
                if let x509_parser::extensions::ParsedExtension::BasicConstraints(bc) =
                    ext.parsed_extension()
                {
                    found_ca = bc.ca;
                    break;
                }
            }
            found_ca
        };
        if !is_ca {
            return Err(
                "CA PEM bundle contains a certificate that is not a CA (basicConstraints CA:TRUE required)"
                    .to_string(),
            );
        }

        let ta = webpki::anchor_from_trusted_cert(cert)
            .map_err(|e| format!("failed to parse trust anchor from certificate: {e}"))?;
        anchors.push(ta.to_owned());
    }
    Ok(anchors)
}

pub fn verify_cert_chain(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &[rustls::pki_types::TrustAnchor<'_>],
    now: UnixTime,
    usage: webpki::KeyUsage,
) -> Result<(), rustls::Error> {
    let ee = webpki::EndEntityCert::try_from(end_entity)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        anchors,
        intermediates,
        now,
        usage,
        None,
        None,
    )
    .map_err(|e| match e {
        webpki::Error::CertExpired { .. } => {
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
        }
        webpki::Error::CertNotValidYet { .. } => {
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet)
        }
        webpki::Error::UnknownIssuer => {
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        }
        _ => rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ),
    })?;

    Ok(())
}

// -----------------------------------------------------------------------------
// Custom TLS Verifiers (Pinned SPKI Hash)
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub struct PinnedClientCertVerifier {
    allowed_pins: Arc<HashMap<String, String>>, // pin -> peer_name
}

impl PinnedClientCertVerifier {
    pub fn new(allowed_pins: Arc<HashMap<String, String>>) -> Self {
        Self { allowed_pins }
    }
}

impl rustls::server::danger::ClientCertVerifier for PinnedClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let pin = spki_sha256_from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let norm_pin = normalize_pin(&pin);
        if self.allowed_pins.contains_key(&norm_pin) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    expected_pin: String,
    /// This pinned entry's key, and the peers file, for AM-6.
    peer_name: String,
    peers: Option<Arc<PeersMap>>,
}

impl PinnedServerCertVerifier {
    pub fn new(expected_pin: &str) -> Self {
        Self {
            expected_pin: normalize_pin(expected_pin),
            peer_name: String::new(),
            peers: None,
        }
    }

    /// Refuse a server that also authenticates as a CA entry of the peers file (AM-6).
    pub fn refusing_ca(mut self, peer_name: &str, peers: Arc<PeersMap>) -> Self {
        self.peer_name = peer_name.to_string();
        self.peers = Some(peers);
        self
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let pin = spki_sha256_from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let norm_pin = normalize_pin(&pin);
        if norm_pin != self.expected_pin {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        if let Some(peers) = &self.peers {
            let ca = peers.ca_entries_for(
                end_entity,
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
            );
            if !ca.is_empty() {
                let msg =
                    one_node_two_names(&self.peer_name, ca.iter().map(|(p, _)| p.name.as_str()));
                tracing::warn!("{msg}");
                return Err(rustls::Error::General(msg));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub struct CombinedClientCertVerifier {
    peers: Arc<PeersMap>,
}

impl CombinedClientCertVerifier {
    pub fn new(peers: Arc<PeersMap>) -> Self {
        Self { peers }
    }
}

impl rustls::server::danger::ClientCertVerifier for CombinedClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let pin = spki_sha256_from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let norm_pin = normalize_pin(&pin);
        let any_pin_match = self.peers.get_by_pin(&norm_pin);

        let ca_matches: Vec<&PeerConfig> = self
            .peers
            .ca_entries_for(
                end_entity,
                intermediates,
                now,
                webpki::KeyUsage::client_auth(),
            )
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| !p.allow.is_empty())
            .collect();

        // AM-6: a CA-authenticated connection presenting a pinned entry's key is one node
        // under two names; refuse it (including outbound-only pinned peers).
        if let Some(pin_peer) = any_pin_match {
            if !ca_matches.is_empty() {
                tracing::warn!(
                    "{}",
                    one_node_two_names(&pin_peer.name, ca_matches.iter().map(|p| p.name.as_str()))
                );
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
            if pin_peer.allow.is_empty() {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
            return Ok(rustls::server::danger::ClientCertVerified::assertion());
        }

        if ca_matches.len() > 1 {
            tracing::warn!(
                "Presented certificate matches multiple CA peers; refusing (fail closed)"
            );
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        if ca_matches.len() == 1 {
            return Ok(rustls::server::danger::ClientCertVerified::assertion());
        }

        if let Some(ref hub) = self.peers.hub {
            let uris = extract_uri_sans(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
            if uris.len() == 1 {
                let uri = &uris[0];
                if hub
                    .patterns
                    .iter()
                    .any(|pat| spiffe_uri_matches_pattern(uri, pat))
                {
                    let all_anchors = self.peers.all_ca_anchors();
                    verify_cert_chain(
                        end_entity,
                        intermediates,
                        &all_anchors,
                        now,
                        webpki::KeyUsage::client_auth(),
                    )?;

                    let canonical = crate::node::node_name_from_uri(uri).map_err(|_| {
                        rustls::Error::InvalidCertificate(
                            rustls::CertificateError::ApplicationVerificationFailure,
                        )
                    })?;

                    // Check collision with concrete peer
                    if self.peers.contains_concrete_name(&canonical) {
                        return Err(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::ApplicationVerificationFailure,
                        ));
                    }

                    // Check collision with already admitted client
                    if let Ok(admitted) = self.peers.admitted_clients.read() {
                        if let Some(existing) = admitted.get(&canonical) {
                            if existing.uri != *uri {
                                return Err(rustls::Error::InvalidCertificate(
                                    rustls::CertificateError::ApplicationVerificationFailure,
                                ));
                            }
                        }
                    }

                    return Ok(rustls::server::danger::ClientCertVerified::assertion());
                }
            }
        }

        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The AM-6 refusal: one key reached both as a pinned entry and as CA entries.
fn one_node_two_names<'a>(pinned: &str, ca: impl Iterator<Item = &'a str>) -> String {
    let ca: Vec<String> = ca.map(|n| format!("'{n}'")).collect();
    format!(
        "certificate presents the key pinned for peer '{pinned}' and the CA identity of peer {}; \
         one node has one canonical name, so configure it once; refusing",
        ca.join(", ")
    )
}

#[derive(Debug)]
pub struct CaServerCertVerifier {
    anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
    allowed_identities: Vec<String>,
    /// This CA entry's key, and the peers file's pinned keys (pin -> entry key), for AM-6.
    peer_name: String,
    pinned: HashMap<String, String>,
}

impl CaServerCertVerifier {
    pub fn new(
        anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
        allowed_identities: Vec<String>,
    ) -> Self {
        Self {
            anchors,
            allowed_identities,
            peer_name: String::new(),
            pinned: HashMap::new(),
        }
    }

    /// Refuse a server whose key is pinned by another entry of the peers file (AM-6).
    pub fn refusing_pinned(mut self, peer_name: &str, pinned: HashMap<String, String>) -> Self {
        self.peer_name = peer_name.to_string();
        self.pinned = pinned;
        self
    }
}

impl rustls::client::danger::ServerCertVerifier for CaServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        verify_cert_chain(
            end_entity,
            intermediates,
            &self.anchors,
            now,
            webpki::KeyUsage::server_auth(),
        )?;

        let uris = extract_uri_sans(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if uris.len() != 1 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        if !uri_matches_any_identity(&uris[0], &self.allowed_identities) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        let pin = spki_sha256_from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if let Some(pinned) = self.pinned.get(&normalize_pin(&pin)) {
            let msg = one_node_two_names(pinned, std::iter::once(self.peer_name.as_str()));
            tracing::warn!("{msg}");
            return Err(rustls::Error::General(msg));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// -----------------------------------------------------------------------------
// Token Bucket Rate Limiting
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    fill_rate_per_sec: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, fill_rate_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            fill_rate_per_sec,
            last_update: Instant::now(),
        }
    }

    fn take(&mut self, count: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.tokens = (self.tokens + elapsed * self.fill_rate_per_sec).min(self.capacity);

        if self.tokens >= count {
            self.tokens -= count;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    peer_limit: f64,
    principal_limit: f64,
    peer_buckets: Mutex<HashMap<String, TokenBucket>>,
    principal_buckets: Mutex<HashMap<(String, String), TokenBucket>>,
}

impl RateLimiter {
    pub fn new(peer_per_min: u32, principal_per_min: u32) -> Self {
        Self {
            peer_limit: peer_per_min as f64,
            principal_limit: principal_per_min as f64,
            peer_buckets: Mutex::new(HashMap::new()),
            principal_buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_consume(&self, peer: &str, principal_key: Option<&str>) -> bool {
        let mut p_buckets = self.peer_buckets.lock().unwrap();
        let peer_bucket = p_buckets
            .entry(peer.to_string())
            .or_insert_with(|| TokenBucket::new(self.peer_limit, self.peer_limit / 60.0));

        if !peer_bucket.take(1.0) {
            return false;
        }

        if let Some(pkey) = principal_key {
            let mut pr_buckets = self.principal_buckets.lock().unwrap();
            let pr_bucket = pr_buckets
                .entry((peer.to_string(), pkey.to_string()))
                .or_insert_with(|| {
                    TokenBucket::new(self.principal_limit, self.principal_limit / 60.0)
                });
            if !pr_bucket.take(1.0) {
                return false;
            }
        }

        true
    }
}

// -----------------------------------------------------------------------------
// Wire Protocol Envelopes
// -----------------------------------------------------------------------------

/// The node-to-node protocol version: the `v` of every envelope on `/fed/v2`.
pub const WIRE_VERSION: u32 = 2;

/// The hop mark (A3, X26): set by the node that forwarded an envelope, which attests the
/// origin's node. An envelope carrying it is never forwarded again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FedForwarded {
    pub forwarder: String,
    /// The forwarder's `targets` for the destination (A20), which the destination enforces
    /// on what the reference resolves to there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<String>>,
}

/// A message between nodes. Its `origin` is one shape for every sender (A12): the sending
/// node attests the ID or service name, and the receiving node attests the node name from
/// the identity it authenticated (N-2), so `origin.node` is read only on a forwarded
/// envelope, where the forwarder attests it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedEnvelope {
    pub v: u32,
    pub id: String,
    pub origin: storage::Origin,
    pub to: FedTarget,
    pub body: String,
    pub thread_id: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded: Option<FedForwarded>,
}

/// An envelope's origin with its node attested by this node: the authenticated peer's
/// canonical name, or for a forwarded envelope the node its forwarder attested (N-2). The
/// origin's own parts are checked: a service name, an instance ID, or an anonymous `from`.
fn attested_origin(
    envelope_origin: &storage::Origin,
    sender_node: &str,
    forwarded: Option<&FedForwarded>,
) -> Result<storage::Origin, AppError> {
    let node = match forwarded {
        Some(fwd) if fwd.forwarder != sender_node => {
            return Err(AppError::BadRequest(format!(
                "forwarder '{}' is not the authenticated peer '{sender_node}'",
                fwd.forwarder
            )))
        }
        Some(_) => envelope_origin.node.clone(),
        None => sender_node.to_string(),
    };
    check_origin(envelope_origin)?;
    Ok(storage::Origin {
        node,
        ..envelope_origin.clone()
    })
}

fn check_origin(origin: &storage::Origin) -> Result<(), AppError> {
    let name_re = regex::Regex::new(r"^[A-Za-z0-9._-]{1,32}$").expect("valid regex");
    match (&origin.service, &origin.id) {
        (Some(_), Some(_)) => Err(AppError::BadRequest(
            "origin names both a service and an instance".to_string(),
        )),
        (Some(name), None) if !name_re.is_match(name) => Err(AppError::BadRequest(format!(
            "invalid service name '{name}'"
        ))),
        (None, Some(id))
            if id.is_empty()
                || id.len() > 128
                || id.contains('@')
                || id.contains(char::is_control) =>
        {
            Err(AppError::BadRequest(format!("invalid instance id '{id}'")))
        }
        (None, None) => {
            inbox::sanitize_from("", origin.label.as_deref().unwrap_or_default()).map(|_| ())
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FedInboxMessage {
    pub id: String,
    pub origin: storage::Origin,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// One item of a dial-out client's mailbox: a message, or a `list` query it answers on its
/// next long-poll (A-1, AM-1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FedInboxItem {
    Message(FedInboxMessage),
    List {
        query: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        v: Option<u32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedTarget {
    pub r#ref: String,
}

/// A reply between nodes. The `replier`'s node is attested by the receiving node (N-2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedReplyEnvelope {
    pub v: u32,
    pub id: String,
    pub in_reply_to: String,
    pub replier: storage::Origin,
    pub text: String,
    pub created_at: i64,
}

/// One entry of a node's `list` answer (A4, A-12, A16, XL1, XF3): an instance ID or a
/// service name, its kind, harness, label and status, the user it belongs to, and its
/// timestamp (`registered_at` when live, `last_seen` when inactive). The asking node adds
/// the node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FedListEntry {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub status: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
}

/// A dial-out client's answer to a mailbox `list` query: its entries, or `denied` when its
/// entry for the asking node withholds `list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum FedListAnswer {
    Ok { entries: Vec<FedListEntry> },
    Denied,
}

/// `list` queries waiting in dial-out clients' mailboxes, and the askers awaiting them.
#[derive(Default)]
pub struct ListQueries {
    pending: Mutex<HashMap<String, Vec<String>>>,
    waiting: Mutex<HashMap<String, ListWaiter>>,
}

type ListWaiter = (
    String,
    tokio::sync::oneshot::Sender<(FedListAnswer, String)>,
);

impl ListQueries {
    fn ask(
        &self,
        peer: &str,
    ) -> (
        String,
        tokio::sync::oneshot::Receiver<(FedListAnswer, String)>,
    ) {
        let query = ulid::Ulid::new().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        if let Ok(mut w) = self.waiting.lock() {
            w.insert(query.clone(), (peer.to_string(), tx));
        }
        if let Ok(mut p) = self.pending.lock() {
            p.entry(peer.to_string()).or_default().push(query.clone());
        }
        (query, rx)
    }

    fn forget(&self, query: &str) {
        if let Ok(mut w) = self.waiting.lock() {
            w.remove(query);
        }
        if let Ok(mut p) = self.pending.lock() {
            for qs in p.values_mut() {
                qs.retain(|q| q != query);
            }
        }
    }

    fn next_for(&self, peer: &str) -> Option<String> {
        let mut p = self.pending.lock().ok()?;
        let qs = p.get_mut(peer)?;
        (!qs.is_empty()).then(|| qs.remove(0))
    }

    fn answer(&self, query: &str, peer: &str, answer: FedListAnswer, user: String) -> bool {
        let Ok(mut w) = self.waiting.lock() else {
            return false;
        };
        match w.get(query) {
            Some((asked, _)) if asked == peer => {
                let (_, tx) = w.remove(query).expect("present");
                tx.send((answer, user)).is_ok()
            }
            _ => false,
        }
    }
}

// -----------------------------------------------------------------------------
// Authenticated Peer Context
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub name: String,
    pub pin: String,
    pub uri: Option<String>,
    /// The user of the certificate the peer presented (A16), empty when it names none, so
    /// that no listing entry matches it (P-3).
    pub user: String,
    pub remote_ip: IpAddr,
}

// -----------------------------------------------------------------------------
// Federation State
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct DynamicTls {
    pub cert_der: Vec<u8>,
    pub cert_chain_der: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
    pub ca_anchors: HashMap<String, Vec<rustls::pki_types::TrustAnchor<'static>>>,
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub peers: Arc<PeersMap>,
}

impl DynamicTls {
    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        if !self.cert_chain_der.is_empty() {
            self.cert_chain_der
                .iter()
                .map(|c| CertificateDer::from(c.clone()))
                .collect()
        } else {
            vec![CertificateDer::from(self.cert_der.clone())]
        }
    }
}

pub struct FedState {
    pub node_name: String,
    pub peers: Arc<PeersMap>,
    pub cert_der: Vec<u8>,
    pub cert_chain_der: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
    pub rate_limiter: Arc<RateLimiter>,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    /// Every sessions dir this node scans: a fed-side scan that saw fewer would release
    /// the claims held in the others.
    pub sessions_dirs: Vec<PathBuf>,
    pub agy_config: crate::agy::AgyConfig,
    pub agy_store: crate::agy::AgyStore,
    pub pi_store: crate::pi::PiStore,
    pub pi_notify_tx: broadcast::Sender<String>,
    pub svc_store: crate::svc::SvcStore,
    pub svc_notify_tx: broadcast::Sender<String>,
    pub notify_tx: broadcast::Sender<String>,
    pub max_body: usize,
    pub is_leaf: bool,
    pub leaf_principal: Option<String>,
    pub outbound_replies_pushed: Arc<AtomicU64>,
    pub dynamic_tls: Arc<std::sync::RwLock<Option<DynamicTls>>>,
    /// How long an instance stays parked after it was last live (A14), for `list`.
    pub reply_ttl: Duration,
    pub list_queries: ListQueries,
}

impl FedState {
    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        if let Ok(guard) = self.dynamic_tls.read() {
            if let Some(ref dyn_tls) = *guard {
                return dyn_tls.cert_chain();
            }
        }
        if !self.cert_chain_der.is_empty() {
            self.cert_chain_der
                .iter()
                .map(|c| CertificateDer::from(c.clone()))
                .collect()
        } else {
            vec![CertificateDer::from(self.cert_der.clone())]
        }
    }

    pub fn key_der(&self) -> Vec<u8> {
        if let Ok(guard) = self.dynamic_tls.read() {
            if let Some(ref dyn_tls) = *guard {
                return dyn_tls.key_der.clone();
            }
        }
        self.key_der.clone()
    }

    pub fn current_peers(&self) -> Arc<PeersMap> {
        if let Ok(guard) = self.dynamic_tls.read() {
            if let Some(ref dyn_tls) = *guard {
                return dyn_tls.peers.clone();
            }
        }
        self.peers.clone()
    }

    pub fn get_ca_anchors(
        &self,
        peer_name: &str,
    ) -> Option<Vec<rustls::pki_types::TrustAnchor<'static>>> {
        self.current_peers()
            .get_ca_anchors(peer_name)
            .map(|s| s.to_vec())
    }

    pub fn get_tls_acceptor(&self) -> Option<tokio_rustls::TlsAcceptor> {
        if let Ok(guard) = self.dynamic_tls.read() {
            if let Some(ref dyn_tls) = *guard {
                return Some(dyn_tls.acceptor.clone());
            }
        }
        None
    }
}

// -----------------------------------------------------------------------------
// Federation Router & Handlers
// -----------------------------------------------------------------------------

pub fn build_fed_router(fed_state: Arc<FedState>) -> Router {
    let max_body_limit = fed_state.max_body + 4096;
    Router::new()
        .route("/fed/v2/messages", post(fed_send_message_handler))
        .route("/fed/v2/replies", post(fed_reply_handler))
        .route(
            "/fed/v2/messages/{id}/replies",
            get(fed_get_replies_handler),
        )
        .route("/fed/v2/sessions", get(fed_list_sessions_handler))
        .route("/fed/v2/list/{query}", post(fed_list_answer_handler))
        .route("/fed/v2/inbox", get(fed_get_inbox_handler))
        .route("/fed/v2/inbox/{id}/ack", post(fed_ack_inbox_handler))
        .route("/fed/v2/handoff", post(crate::handoff::handoff_handler))
        .route("/fed/v2/handoff/ack", post(crate::handoff::ack_handler))
        .layer(DefaultBodyLimit::max(max_body_limit))
        .with_state(fed_state)
}

async fn fed_send_message_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    headers: axum::http::HeaderMap,
    Json(envelope): Json<FedEnvelope>,
) -> Result<Response, AppError> {
    let live_only = headers.contains_key(LIVE_ONLY_HEADER);
    if envelope.v != WIRE_VERSION {
        return Err(AppError::BadRequest(format!(
            "unsupported protocol version {}",
            envelope.v
        )));
    }

    // 1. Check peer config and allow list
    let peer_cfg = fed_state
        .peers
        .get_peer_config(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    if !peer_cfg.allow.iter().any(|op| op == "send") {
        return Err(AppError::OpDenied(
            "send operation not allowed for peer".to_string(),
        ));
    }

    if !peer_cfg.principals.is_empty() {
        let authorized = principal_allowed(&envelope.origin, &peer_cfg.principals);
        if !authorized {
            return Err(AppError::OpDenied(
                "principal not authorized for peer".to_string(),
            ));
        }
    }

    // Relayed messages check: if envelope is forwarded, recipient's entry for the peer must allow "relayed"
    if envelope.forwarded.is_some()
        && !peer_cfg
            .allow
            .iter()
            .any(|op| op == "relayed" || op == "relay")
    {
        return Err(AppError::OpDenied(
            "relayed messages not allowed for peer".to_string(),
        ));
    }

    // 2. Validate to.ref and handle forwarding
    let raw_target_ref = &envelope.to.r#ref;
    let (target_ref, dest_host) = match split_peer_ref(raw_target_ref) {
        Some((r, h)) if h != fed_state.node_name => (r, Some(h)),
        Some((r, _)) => (r, None),
        None => (raw_target_ref.as_str(), None),
    };
    // The canonical name this node knows the sender by; it is what crosses the wire.
    let peers = fed_state.current_peers();
    let sender_node = peers
        .canonical_name(&peer.name)
        .unwrap_or(&peer.name)
        .to_string();

    if let Some(dest) = dest_host {
        let dest = peers.key_for(dest).unwrap_or(dest);
        // One-hop rule: cannot forward an already forwarded message
        if envelope.forwarded.is_some() {
            return Err(AppError::NoForward(
                "message has already been forwarded (one hop maximum)".to_string(),
            ));
        }

        // Sender peer must have "forward" in allow
        if !peer_cfg.allow.iter().any(|op| op == "forward") {
            return Err(AppError::NoForward(
                "Forwarding cross-host is not permitted".to_string(),
            ));
        }

        // Dest must be a known peer other than the sender
        let dest_cfg = match peers.get_peer_config(dest) {
            Some(cfg) if dest != peer.name => cfg,
            _ => return Err(AppError::UnknownPeer(dest.to_string())),
        };

        // Dest's targets must allow target_ref
        if let Some(ref allowed_targets) = dest_cfg.targets {
            if !target_ref_could_match(target_ref, allowed_targets) {
                return Err(AppError::OpDenied(
                    "target not allowed for peer".to_string(),
                ));
            }
        }

        // The origin, its node attested here (N-2): the forwarded envelope carries it.
        let origin = attested_origin(&envelope.origin, &sender_node, None)?;

        // Rate limit sender
        let principal_key = origin_filter_key(&origin);
        if !fed_state
            .rate_limiter
            .check_and_consume(&peer.name, Some(&principal_key))
        {
            return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
        }

        // Check if message already delivered / forwarded (idempotency)
        {
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            if let Some(existing) = storage::get_message(&db, &envelope.id)
                .map_err(|e| AppError::Internal(e.to_string()))?
            {
                return match existing.outcome.as_str() {
                    "delivered" | "queued" | "accepted" => Ok((
                        StatusCode::ACCEPTED,
                        Json(DeliveryResponse {
                            session_id: existing.session_id,
                            from_name: existing.from_name,
                            bytes: existing.bytes,
                            message_id: existing.id,
                            outcome: Some(existing.outcome),
                        }),
                    )
                        .into_response()),
                    "not_found" => Err(AppError::NotFound(existing.session_id)),
                    "ambiguous" => Err(AppError::Ambiguous(existing.session_id)),
                    "gone" => Err(AppError::Gone {
                        session_id: existing.session_id,
                        pid: 0,
                    }),
                    other => Err(AppError::BadRequest(format!("outcome: {other}"))),
                };
            }
        }

        let forwarded_envelope = FedEnvelope {
            v: envelope.v,
            id: envelope.id.clone(),
            origin: origin.clone(),
            to: FedTarget {
                r#ref: target_ref.to_string(),
            },
            body: envelope.body.clone(),
            thread_id: envelope.thread_id.clone(),
            created_at: envelope.created_at,
            forwarded: Some(FedForwarded {
                forwarder: fed_state.node_name.clone(),
                targets: dest_cfg.targets.clone(),
            }),
        };

        {
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            storage::insert_forwarded_message(&db, &envelope.id, &peer.name, envelope.created_at)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            storage::insert_outbound(
                &db,
                &envelope.id,
                dest,
                target_ref,
                "pending",
                envelope.created_at,
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        }

        let delivery_resp =
            match send_federated_message(&fed_state, dest, &forwarded_envelope).await {
                Ok(resp) => resp,
                Err(err) => {
                    if let Ok(db) = fed_state.db.lock() {
                        let _ = storage::delete_outbound(&db, &envelope.id);
                        let _ = storage::delete_forwarded_message(&db, &envelope.id);
                    }
                    return Err(err);
                }
            };

        let outcome = delivery_resp.outcome.as_deref().unwrap_or("delivered");

        {
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let _ = storage::update_outbound_outcome(&db, &envelope.id, outcome);
            // The resolved address, as the destination reported it.
            let _ = storage::update_outbound_target(
                &db,
                &envelope.id,
                &format!("{}@{dest}", delivery_resp.session_id),
            );
            let fwd_msg_record = MessageRecord {
                id: envelope.id.clone(),
                created_at: envelope.created_at,
                session_id: target_ref.to_string(),
                from_name: origin.render(&peer.name),
                bytes: envelope.body.len(),
                outcome: outcome.to_string(),
                recipient_harness: "fed".to_string(),
                return_harness: None,
                return_session_id: origin.key().map(str::to_string),
                return_host: Some(peer.name.clone()),
                thread_id: envelope.thread_id.clone(),
            };
            let _ = storage::insert_message(&db, &fwd_msg_record);
        }

        return Ok((StatusCode::ACCEPTED, Json(delivery_resp)).into_response());
    }

    if target_ref.contains('@') {
        return Err(AppError::NoForward(
            "Forwarding cross-host is not permitted".to_string(),
        ));
    }

    // N-2: the origin's node is attested here, from the authenticated peer or, for a
    // forwarded envelope, its forwarder; it is shown by its local nickname, if any.
    let origin = attested_origin(&envelope.origin, &sender_node, envelope.forwarded.as_ref())?;
    let from_name = origin.render(fed_state.current_peers().display_name(&origin.node));
    let principal_key = origin_filter_key(&origin);
    // Replies always return to the origin node, which decides how they reach the sender
    // (A-2); here the sender is only its key, or anonymous.
    let (return_harness, return_session_id) = match origin.key() {
        Some(key) => (Some("fed".to_string()), Some(key.to_string())),
        None => (None, None),
    };

    let target = match resolve_target_session_fed(&fed_state, target_ref).await {
        Ok(t) => {
            if let Some(ref allowed_targets) = peer_cfg.targets {
                if !target_matches_allowlist(&t, allowed_targets) {
                    return Err(AppError::OpDenied(
                        "target not allowed for peer".to_string(),
                    ));
                }
            }
            // A20: the forwarder's restriction for this node, on what the ref resolved to.
            if let Some(allowed) = envelope.forwarded.as_ref().and_then(|f| f.targets.as_ref()) {
                if !target_matches_allowlist(&t, allowed) {
                    return Err(AppError::OpDenied(
                        "target not allowed by the forwarder's targets".to_string(),
                    ));
                }
            }
            // C9: a cache-routed send is never queued here. Nothing is recorded, so the
            // sender's re-resolution may bring the same message back.
            if live_only && t.is_parked() {
                return Err(AppError::NotLive(format!(
                    "'{target_ref}' is not live on {}",
                    fed_state.node_name
                )));
            }
            t
        }
        Err(err) => {
            if let Some(ref allowed_targets) = peer_cfg.targets {
                if !target_ref_could_match(target_ref, allowed_targets) {
                    return Err(AppError::OpDenied(
                        "target not allowed for peer".to_string(),
                    ));
                }
            }
            // Target is allowed but not found / gone / ambiguous:
            // Check rate limiter and record failure outcome
            if !fed_state
                .rate_limiter
                .check_and_consume(&peer.name, Some(&principal_key))
            {
                return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
            }
            let body_len = envelope.body.len();
            let outcome_str = match &err {
                AppError::NotFound(_) | AppError::NotFoundDetail(_) => "not_found",
                AppError::Ambiguous(_) => "ambiguous",
                AppError::Gone { .. } => "gone",
                _ => "failed",
            };
            let pre_record = MessageRecord {
                id: envelope.id.clone(),
                created_at: envelope.created_at,
                session_id: target_ref.to_string(),
                from_name,
                bytes: body_len,
                outcome: outcome_str.to_string(),
                recipient_harness: "claude".to_string(),
                return_harness,
                return_session_id,
                return_host: Some(peer.name.clone()),
                thread_id: envelope.thread_id.clone(),
            };
            if let Ok(db) = fed_state.db.lock() {
                let _ = storage::upsert_message(&db, &pre_record);
            }
            return Err(err);
        }
    };

    // 4. Rate limiting: consume rate limit for authorized, resolved target
    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, Some(&principal_key))
    {
        return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
    }

    let body_len = envelope.body.len();
    let target_session_id = target.session().session_id.clone();
    let recipient_harness = target.recipient_harness().to_string();

    // 6. Idempotent delivery (X1): an ID recorded as delivered, queued or being delivered
    // is answered from its record, never delivered again. An ID recorded as a failure was
    // not delivered, so it is delivered again (a keyed retry keeps its message ID).
    // Checked and recorded `accepted` under one lock, so two concurrent deliveries of one ID
    // deliver it once.
    let pre_record = MessageRecord {
        id: envelope.id.clone(),
        created_at: envelope.created_at,
        session_id: target_session_id.clone(),
        from_name: from_name.clone(),
        bytes: body_len,
        outcome: "accepted".to_string(),
        recipient_harness,
        return_harness: return_harness.clone(),
        return_session_id: return_session_id.clone(),
        return_host: Some(peer.name.clone()),
        thread_id: envelope.thread_id.clone(),
    };
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(existing) = storage::get_message(&db, &envelope.id)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .filter(|m| storage::outcome_reached(&m.outcome))
        {
            return Ok((
                StatusCode::ACCEPTED,
                Json(DeliveryResponse {
                    session_id: existing.session_id,
                    from_name: existing.from_name,
                    bytes: existing.bytes,
                    message_id: existing.id,
                    outcome: Some(existing.outcome),
                }),
            )
                .into_response());
        }
        storage::upsert_message(&db, &pre_record).map_err(|e| AppError::Internal(e.to_string()))?;
        if envelope.forwarded.is_some() {
            storage::insert_forwarded_message(&db, &envelope.id, &peer.name, envelope.created_at)
                .map_err(|e| AppError::Internal(e.to_string()))?;
        }
    }

    // 8. Deliver to local target session
    let deliver_res = crate::surface::deliver(
        &fed_state.local(),
        &target,
        &from_name,
        &envelope.id,
        &envelope.body,
        origin,
    )
    .await;

    match deliver_res {
        Ok((target_session_id, _harness, outcome_str)) => {
            {
                let db = fed_state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                let _ = storage::update_message_outcome(&db, &envelope.id, outcome_str);
            }
            Ok((
                StatusCode::ACCEPTED,
                Json(DeliveryResponse {
                    session_id: target_session_id,
                    from_name,
                    bytes: body_len,
                    message_id: envelope.id,
                    outcome: Some(outcome_str.to_string()),
                }),
            )
                .into_response())
        }
        Err(err) => {
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let _ = storage::update_message_outcome(&db, &envelope.id, "delivery_failed");
            Err(err)
        }
    }
}

/// Stores a reply that came back from `peer_name` and pushes it to the local sender of
/// `in_reply_to` (A10, A-2).
#[allow(clippy::too_many_arguments)]
pub async fn deliver_federated_reply_locally(
    fed_state: &FedState,
    peer_name: &str,
    in_reply_to: &str,
    reply_id: &str,
    replier_badge: &str,
    replier_origin: storage::Origin,
    text: &str,
    ret_harness: &str,
    ret_session_id: &str,
) -> Result<&'static str, AppError> {
    let _ = peer_name;
    // Check if reply already inserted (idempotency)
    let already_inserted = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_reply_by_pushed_id(&db, reply_id)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .is_some()
    };

    if !already_inserted {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::insert_reply(
            &db,
            in_reply_to,
            ret_session_id,
            text,
            Some("accepted"),
            Some(reply_id),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    let push_res = crate::surface::push_reply(
        &fed_state.local(),
        ret_harness,
        ret_session_id,
        in_reply_to,
        reply_id,
        replier_badge,
        replier_origin,
        text,
    )
    .await;

    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let _ = storage::update_reply_push_outcome(&db, reply_id, push_res);
    }
    let _ = fed_state.notify_tx.send(in_reply_to.to_string());
    Ok(push_res)
}

/// Federated reply authorization: is `replier` the recipient `outbound` records (A7)?
/// - A peer that answered the send resolved the reference first, so the record holds the
///   instance ID or service name it reported, and only that key may reply.
/// - A send queued in a dial-out client's mailbox by a typed reference is resolved there,
///   later, so the record holds the reference as typed. The replier must be what that
///   reference resolves to by the resolver's own steps: its ID, its service name, or its
///   label.
/// - A send queued in a dial-out client's mailbox may instead get the client's own
///   `not_found` error reply, which a service sends (the leaf principal, or `system`),
///   never the recipient. Only a reply that is exactly that error object is admitted on
///   that ground.
/// - A send the peer resolved and holds for its recipient's ack also reads `queued`, but
///   the record holds its recipient, so it takes replies by key only.
fn replier_is_recipient(
    o: &storage::OutboundRecord,
    replier: &storage::Origin,
    text: &str,
) -> bool {
    let typed = split_peer_ref(&o.target_ref).map_or(o.target_ref.as_str(), |(r, _)| r);
    if replier.key() == Some(typed) {
        return true;
    }
    o.outcome == "queued"
        && o.via_mailbox
        && ((!o.resolved && replier.id.is_some() && replier.label.as_deref() == Some(typed))
            || (replier.service.is_some() && is_not_found_reply(text)))
}

/// `{"error": "not_found", "detail": …}` and nothing else: a dial-out client's answer
/// that a queued message has no recipient there.
fn is_not_found_reply(text: &str) -> bool {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ErrorReply {
        error: String,
        #[allow(dead_code)]
        detail: String,
    }
    serde_json::from_str::<ErrorReply>(text).is_ok_and(|e| e.error == "not_found")
}

async fn fed_reply_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Json(reply): Json<FedReplyEnvelope>,
) -> Result<Response, AppError> {
    if reply.v != WIRE_VERSION {
        return Err(AppError::BadRequest(format!(
            "unsupported protocol version {}",
            reply.v
        )));
    }

    // 1. Check peer config and allow list
    let peers = fed_state.current_peers();
    let peer_cfg = peers
        .get_peer_config(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    if !peer_cfg.allow.iter().any(|op| op == "reply") {
        return Err(AppError::OpDenied(
            "reply operation not allowed for peer".to_string(),
        ));
    }

    // The replier, its node attested here (N-2).
    let node = peers
        .canonical_name(&peer.name)
        .unwrap_or(&peer.name)
        .to_string();
    let replier = attested_origin(&reply.replier, &node, None)?;
    let replier_key = replier.key().unwrap_or(&peer.name).to_string();

    // Rate limiting: consume peer and principal buckets
    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, Some(&origin_filter_key(&replier)))
    {
        return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
    }

    // Deduplicate reply by id: if already processed, return stored outcome
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(existing) = storage::get_reply_by_pushed_id(&db, &reply.id)
            .map_err(|e| AppError::Internal(e.to_string()))?
        {
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "push_outcome": existing.push_outcome.as_deref().unwrap_or("pushed"),
                    "message_id": reply.id,
                })),
            )
                .into_response());
        }
    }

    // 2. Authorization: in_reply_to MUST exist in outbound table (normal reply)
    // OR in messages table with return_host == peer.name (sender follow-up, XU1 Gate 3).
    let (outbound, orig_msg) = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let out = storage::get_outbound(&db, &reply.in_reply_to)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let msg = storage::get_message(&db, &reply.in_reply_to)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        (out, msg)
    };

    let is_outbound_reply = outbound
        .as_ref()
        .is_some_and(|o| o.peer == peer.name && replier_is_recipient(o, &replier, &reply.text));

    let is_sender_followup = !is_outbound_reply
        && orig_msg.as_ref().is_some_and(|m| {
            m.return_host.as_deref() == Some(&peer.name)
                && m.return_session_id.as_deref() == replier.key()
        });

    if !is_outbound_reply && !is_sender_followup {
        return Err(AppError::NotRecipient(format!(
            "in_reply_to '{}' not authorized for replier '{}' of peer '{}'",
            reply.in_reply_to,
            replier.key().unwrap_or("anon"),
            peer.name
        )));
    }

    // 3. Check if this is a reply to a forwarded message (hub forwarding case)
    let forwarded = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_forwarded_message(&db, &reply.in_reply_to)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    if let Some(fwd) = forwarded {
        let origin_peer_cfg = peers
            .get(&fwd.origin_peer)
            .ok_or_else(|| AppError::UnknownPeer(fwd.origin_peer.clone()))?;

        let orig_msg = {
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            storage::get_message(&db, &reply.in_reply_to)
                .map_err(|e| AppError::Internal(e.to_string()))?
        };

        let origin_target_ref = orig_msg
            .as_ref()
            .and_then(|m| m.return_session_id.clone())
            .unwrap_or_default();

        if !origin_peer_cfg.leaf && !origin_peer_cfg.is_outbound() {
            // Dialable origin: send federated reply to origin peer
            let _ = send_federated_reply(&fed_state, &fwd.origin_peer, &reply).await?;
            {
                let db = fed_state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                let _ =
                    storage::insert_forwarded_message(&db, &reply.id, &peer.name, reply.created_at);
                let _ = storage::insert_outbound(
                    &db,
                    &reply.id,
                    &fwd.origin_peer,
                    &origin_target_ref,
                    "pending",
                    reply.created_at,
                );
                let fwd_reply_record = storage::MessageRecord {
                    id: reply.id.clone(),
                    created_at: reply.created_at,
                    session_id: origin_target_ref,
                    from_name: replier.render(&peer.name),
                    bytes: reply.text.len(),
                    outcome: "relayed".to_string(),
                    recipient_harness: "fed".to_string(),
                    return_harness: None,
                    return_session_id: Some(replier_key.clone()),
                    return_host: Some(peer.name.clone()),
                    thread_id: reply.in_reply_to.clone(),
                };
                let _ = storage::insert_message(&db, &fwd_reply_record);
            }
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "push_outcome": "relayed",
                    "message_id": reply.id,
                })),
            )
                .into_response());
        } else {
            // Undialable origin (leaf / outbound link): store reply for polling
            let replier_session_id = replier_key.clone();

            let push_outcome = "stored";
            {
                let db = fed_state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                storage::insert_reply(
                    &db,
                    &reply.in_reply_to,
                    &replier_session_id,
                    &reply.text,
                    Some(push_outcome),
                    Some(&reply.id),
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;
                let _ =
                    storage::insert_forwarded_message(&db, &reply.id, &peer.name, reply.created_at);
                let _ = storage::insert_outbound(
                    &db,
                    &reply.id,
                    &fwd.origin_peer,
                    &origin_target_ref,
                    "pending",
                    reply.created_at,
                );
                let fwd_reply_record = storage::MessageRecord {
                    id: reply.id.clone(),
                    created_at: reply.created_at,
                    session_id: origin_target_ref,
                    from_name: replier.render(&peer.name),
                    bytes: reply.text.len(),
                    outcome: "stored".to_string(),
                    recipient_harness: "fed".to_string(),
                    return_harness: None,
                    return_session_id: Some(replier_key.clone()),
                    return_host: Some(peer.name.clone()),
                    thread_id: reply.in_reply_to.clone(),
                };
                let _ = storage::insert_message(&db, &fwd_reply_record);
            }
            let _ = fed_state.notify_tx.send(reply.in_reply_to.clone());

            return Ok((
                StatusCode::OK,
                Json(json!({
                    "push_outcome": push_outcome,
                    "message_id": reply.id,
                })),
            )
                .into_response());
        }
    }

    // 4. Every reply is stored; it is pushed when the original sender has an inbox (A10,
    // A-2). A sender with none reads it with `replies`.
    let orig_msg = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_message(&db, &reply.in_reply_to)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    let target = if is_sender_followup {
        orig_msg
            .as_ref()
            .map(|m| (m.recipient_harness.clone(), m.session_id.clone()))
    } else {
        orig_msg
            .as_ref()
            .and_then(|m| Some((m.return_harness.clone()?, m.return_session_id.clone()?)))
    };

    if let Some((ret_harness, ret_session_id)) = target {
        let replier_badge = replier.render(&peer.name);
        let replier_id = replier.key().map(str::to_string);

        // The pushed reply is a message its receiver may answer, back across federation
        // to the replier, as a message received from that peer is (A-2). Recorded before
        // the push wakes the receiver (XF2), and removed if the push does not land.
        if let (Some(orig), Some(id)) = (&orig_msg, &replier_id) {
            if let Ok(db) = fed_state.db.lock() {
                if is_sender_followup {
                    let pushed = storage::MessageRecord {
                        id: reply.id.clone(),
                        created_at: storage::now_epoch_secs(),
                        session_id: orig.session_id.clone(),
                        from_name: replier_badge.clone(),
                        bytes: reply.text.len(),
                        outcome: "delivered".to_string(),
                        recipient_harness: orig.recipient_harness.clone(),
                        return_harness: Some("fed".to_string()),
                        return_session_id: Some(id.clone()),
                        thread_id: if orig.thread_id.is_empty() {
                            orig.id.clone()
                        } else {
                            orig.thread_id.clone()
                        },
                        return_host: Some(peer.name.clone()),
                    };
                    let _ = storage::insert_message(&db, &pushed);
                } else {
                    crate::surface::record_pushed_reply(
                        &db,
                        orig,
                        &reply.id,
                        &replier_badge,
                        &reply.text,
                        ("fed", id),
                        Some(&peer.name),
                    );
                }
            }
        }

        let push_res = match deliver_federated_reply_locally(
            &fed_state,
            &peer.name,
            &reply.in_reply_to,
            &reply.id,
            &replier_badge,
            replier,
            &reply.text,
            &ret_harness,
            &ret_session_id,
        )
        .await
        {
            Ok(res) => {
                if res != "pushed" {
                    if let Ok(db) = fed_state.db.lock() {
                        let _ = storage::delete_message(&db, &reply.id);
                    }
                }
                res
            }
            Err(e) => {
                if let Ok(db) = fed_state.db.lock() {
                    let _ = storage::delete_message(&db, &reply.id);
                }
                return Err(e);
            }
        };

        return Ok((
            StatusCode::OK,
            Json(json!({
                "push_outcome": push_res,
                "message_id": reply.id,
            })),
        )
            .into_response());
    }

    let replier_session_id = replier_key;
    let push_outcome = "stored";
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::insert_reply(
            &db,
            &reply.in_reply_to,
            &replier_session_id,
            &reply.text,
            Some(push_outcome),
            Some(&reply.id),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }
    let _ = fed_state.notify_tx.send(reply.in_reply_to.clone());

    Ok((
        StatusCode::OK,
        Json(json!({
            "push_outcome": push_outcome,
            "message_id": reply.id,
        })),
    )
        .into_response())
}

async fn fed_get_replies_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<crate::http::LongPollQuery>,
) -> Result<Response, AppError> {
    let _peer_cfg = fed_state
        .peers
        .get_peer_config(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    // Check rate limiter
    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, Some(&format!("poll:{}", peer.name)))
    {
        return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
    }

    let (authorized, exists) = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(msg) =
            storage::get_message(&db, &id).map_err(|e| AppError::Internal(e.to_string()))?
        {
            (msg.return_host.as_deref() == Some(&peer.name), true)
        } else if let Some(fwd) = storage::get_forwarded_message(&db, &id)
            .map_err(|e| AppError::Internal(e.to_string()))?
        {
            (fwd.origin_peer == peer.name, true)
        } else {
            (false, false)
        }
    };

    if !exists {
        return Err(AppError::NotFound(format!("message '{id}'")));
    }

    if !authorized {
        return Err(AppError::OpDenied(format!(
            "peer '{}' is not authorized to pull replies for message '{}'",
            peer.name, id
        )));
    }

    let after_seq = query.after.unwrap_or(0);
    let wait_secs = query.wait.unwrap_or(0).min(60);

    let rx = if wait_secs > 0 {
        Some(fed_state.notify_tx.subscribe())
    } else {
        None
    };

    let existing = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_replies_after(&db, &id, after_seq)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    if !existing.is_empty() || wait_secs == 0 {
        return Ok((StatusCode::OK, Json(existing)).into_response());
    }

    let mut receiver = rx.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(wait_secs), async {
        loop {
            match receiver.recv().await {
                Ok(msg_id) if msg_id == id => break,
                Err(broadcast::error::RecvError::Lagged(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    })
    .await;

    let replies = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_replies_after(&db, &id, after_seq)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    Ok((StatusCode::OK, Json(replies)).into_response())
}

#[derive(Debug, Default, Deserialize)]
pub struct FedListQuery {
    #[serde(default)]
    pub v: Option<u32>,
}

async fn fed_list_sessions_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Query(query): Query<FedListQuery>,
) -> Result<Response, AppError> {
    let peer_cfg = fed_state
        .current_peers()
        .get_peer_config(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    // Refused with 403 op_denied unless peer's allow contains "list"
    if !peer_cfg.allow.iter().any(|op| op == "list") {
        return Err(AppError::OpDenied(
            "list operation not allowed for peer".to_string(),
        ));
    }

    // Source address check
    check_peer_source(&peer_cfg, &peer.remote_ip)?;

    // Rate limiting: consume peer bucket
    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, Some(&format!("list:{}", peer.name)))
    {
        return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
    }

    let entries = listing_for_peer(&fed_state, &peer_cfg, query.v.unwrap_or(1) >= 2).await?;
    Ok((StatusCode::OK, Json(entries)).into_response())
}

/// This node's user (A16): the user of the identity it presents to its peers.
pub fn own_user(fed_state: &FedState) -> String {
    let chain = fed_state.cert_chain();
    crate::node::own_user(chain.first().map(|c| c.as_ref()))
}

/// What this node lists to `peer_cfg`'s node: its recipients, narrowed by that entry's
/// `targets`, each carrying this node's user (A16). When `!v2` (a plain request from a
/// pre-XL1 reader whose `FedListEntry` uses `#[serde(deny_unknown_fields)]`), the new
/// fields (`registered_at`, `last_seen`, `harness`) are omitted.
async fn listing_for_peer(
    fed_state: &FedState,
    peer_cfg: &PeerConfig,
    v2: bool,
) -> Result<Vec<FedListEntry>, AppError> {
    let mut entries = crate::surface::listing(
        &fed_state.local(),
        fed_state.reply_ttl,
        &own_user(fed_state),
    )
    .await?;
    if let Some(ref allowed_targets) = peer_cfg.targets {
        entries.retain(|e| allowed_targets.contains(&e.id));
    }
    if !v2 {
        for e in &mut entries {
            e.harness = None;
            e.registered_at = None;
            e.last_seen = None;
        }
    }
    Ok(entries)
}

/// P-3: a listing node may list only its own certificate user's recipients. An entry of
/// any other user is dropped, which is all a receiver can enforce.
pub(crate) fn admit_entries(entries: Vec<FedListEntry>, cert_user: &str) -> Vec<FedListEntry> {
    entries
        .into_iter()
        .filter(|e| e.user == cert_user)
        .collect()
}

/// A dial-out client answers a `list` query from its mailbox (POST, AM-1).
async fn fed_list_answer_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    AxumPath(query): AxumPath<String>,
    Json(answer): Json<FedListAnswer>,
) -> Result<Response, AppError> {
    if !fed_state
        .list_queries
        .answer(&query, &peer.name, answer, peer.user.clone())
    {
        return Err(AppError::NotFound(format!("list query '{query}'")));
    }
    Ok((StatusCode::OK, Json(json!({ "status": "ok" }))).into_response())
}

#[derive(Debug, Deserialize)]
pub struct FedInboxQuery {
    pub wait: Option<u64>,
}

async fn fed_get_inbox_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Query(query): Query<FedInboxQuery>,
) -> Result<Response, AppError> {
    let peer_cfg = fed_state
        .peers
        .get_peer_config(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    if !peer_cfg.leaf {
        return Err(AppError::OpDenied("peer is not a leaf".to_string()));
    }

    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, Some(&format!("inbox:{}", peer.name)))
    {
        return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
    }

    let wait_secs = query.wait.unwrap_or(0).min(60);

    let rx = if wait_secs > 0 {
        Some(fed_state.notify_tx.subscribe())
    } else {
        None
    };

    // A `list` query waiting for this client goes first (AM-1), then its messages.
    let next_item = || -> Result<Option<FedInboxItem>, AppError> {
        if let Some(query) = fed_state.list_queries.next_for(&peer.name) {
            return Ok(Some(FedInboxItem::List { query, v: Some(2) }));
        }
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(storage::get_next_peer_mailbox_message(&db, &peer.name)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .map(|msg| {
                FedInboxItem::Message(FedInboxMessage {
                    id: msg.id,
                    origin: msg.origin,
                    body: msg.body,
                    to: Some(msg.target_ref),
                })
            }))
    };

    if let Some(item) = next_item()? {
        return Ok((StatusCode::OK, Json(Some(item))).into_response());
    }

    if wait_secs == 0 {
        return Ok((StatusCode::OK, Json(None::<FedInboxItem>)).into_response());
    }

    let mut receiver = rx.unwrap();
    let peer_name_clone = peer.name.clone();
    let _ = tokio::time::timeout(Duration::from_secs(wait_secs), async {
        loop {
            match receiver.recv().await {
                Ok(notif_target) if notif_target == peer_name_clone => break,
                Err(broadcast::error::RecvError::Lagged(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    })
    .await;

    Ok((StatusCode::OK, Json(next_item()?)).into_response())
}

async fn fed_ack_inbox_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, AppError> {
    let peer_cfg = fed_state
        .peers
        .get_peer_config(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    if !peer_cfg.leaf {
        return Err(AppError::OpDenied("peer is not a leaf".to_string()));
    }

    let deleted = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::delete_peer_mailbox_message(&db, &peer.name, &id)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    if !deleted {
        return Err(AppError::NotFound(format!(
            "message '{id}' not found in mailbox for peer '{}'",
            peer.name
        )));
    }

    Ok((StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response())
}

pub fn queue_leaf_mailbox_message(
    fed_state: &FedState,
    peer_name: &str,
    target_ref: &str,
    envelope: &FedEnvelope,
    from_name: &str,
) -> Result<DeliveryResponse, AppError> {
    let peer_cfg = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;

    if let Some(ref allowed_targets) = peer_cfg.targets {
        if !target_ref_could_match(target_ref, allowed_targets) {
            return Err(AppError::OpDenied(
                "target not allowed for peer".to_string(),
            ));
        }
    }

    // The sender's node: this one, or the origin a forwarded envelope names (attested by
    // the forwarder, which is this node).
    let origin = match envelope.forwarded {
        Some(_) => envelope.origin.clone(),
        None => storage::Origin {
            node: fed_state.node_name.clone(),
            ..envelope.origin.clone()
        },
    };

    let envelope_json =
        serde_json::to_string(envelope).map_err(|e| AppError::Internal(e.to_string()))?;

    let mailbox_msg = storage::PeerMailboxMessage {
        id: envelope.id.clone(),
        peer: peer_name.to_string(),
        target_ref: target_ref.to_string(),
        created_at: envelope.created_at,
        from_name: from_name.to_string(),
        bytes: envelope.body.len(),
        body: envelope.body.clone(),
        envelope: envelope_json,
        origin,
    };

    let db = fed_state
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    storage::insert_peer_mailbox(&db, &mailbox_msg)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let _ = storage::insert_outbound(
        &db,
        &envelope.id,
        peer_name,
        target_ref,
        "queued",
        envelope.created_at,
    );
    // Marked whether this insert or a forwarder's earlier one wrote the record: only a
    // mailbox send takes the client's own `not_found` reply (`replier_is_recipient`).
    if let Err(e) = storage::mark_outbound_via_mailbox(&db, &envelope.id) {
        tracing::warn!(message_id = %envelope.id, "mailbox send not marked; its client's not_found reply will be refused: {e}");
    }

    // Notify any waiting long-pollers
    let _ = fed_state.notify_tx.send(peer_name.to_string());

    Ok(DeliveryResponse {
        session_id: target_ref.to_string(),
        from_name: from_name.to_string(),
        bytes: envelope.body.len(),
        message_id: envelope.id.clone(),
        outcome: Some("queued".to_string()),
    })
}

async fn resolve_target_session_fed(
    fed_state: &FedState,
    ref_str: &str,
) -> Result<crate::http::ResolvedTarget, AppError> {
    crate::http::resolve_target(
        &fed_state.sessions_dirs,
        &fed_state.agy_config,
        &fed_state.agy_store,
        &fed_state.pi_store,
        &fed_state.svc_store,
        &fed_state.db,
        &fed_state.node_name,
        ref_str,
        fed_state.reply_ttl,
    )
    .await
}

// -----------------------------------------------------------------------------
// Outbound Federated Client
// -----------------------------------------------------------------------------

pub fn make_tls_connector(
    cert_der: &[u8],
    key_der: &[u8],
    expected_pin: &str,
) -> Result<tokio_rustls::TlsConnector, AppError> {
    let verifier = Arc::new(PinnedServerCertVerifier::new(expected_pin));
    let client_cert = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der.to_vec(),
    ));

    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| AppError::Internal(format!("TLS config error: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(client_cert, key)
    .map_err(|e| AppError::Internal(format!("Client cert error: {e}")))?;

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

pub fn make_tls_connector_for_peer(
    fed_state: &FedState,
    peer: &PeerConfig,
) -> Result<tokio_rustls::TlsConnector, AppError> {
    let client_cert = fed_state.cert_chain();
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        fed_state.key_der(),
    ));

    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = if let Some(ref pin) =
        peer.pin
    {
        Arc::new(
            PinnedServerCertVerifier::new(pin).refusing_ca(&peer.name, fed_state.current_peers()),
        )
    } else if let Some(anchors) = fed_state.get_ca_anchors(&peer.name) {
        let identities = peer.identities.clone().unwrap_or_default();
        Arc::new(
            CaServerCertVerifier::new(anchors, identities)
                .refusing_pinned(&peer.name, fed_state.current_peers().pinned_entries()),
        )
    } else {
        return Err(AppError::Internal(format!(
            "peer '{}' has neither pin nor valid CA bundle",
            peer.name
        )));
    };

    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| AppError::Internal(format!("TLS config error: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(client_cert, key)
    .map_err(|e| AppError::Internal(format!("Client cert error: {e}")))?;

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

pub fn make_tls_acceptor(
    cert_chain: &[CertificateDer<'static>],
    key_der: &[u8],
    peers: Arc<PeersMap>,
) -> Result<tokio_rustls::TlsAcceptor, AppError> {
    let verifier = Arc::new(CombinedClientCertVerifier::new(peers));
    let server_cert = cert_chain.to_vec();
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der.to_vec(),
    ));

    let server_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| AppError::Internal(format!("TLS server config error: {e}")))?
    .with_client_cert_verifier(verifier)
    .with_single_cert(server_cert, key)
    .map_err(|e| AppError::Internal(format!("Server cert error: {e}")))?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

fn map_tls_connect_error(peer_name: &str, e: std::io::Error) -> AppError {
    if let Some(rustls_err) = e
        .get_ref()
        .and_then(|err| err.downcast_ref::<rustls::Error>())
    {
        if matches!(
            rustls_err,
            rustls::Error::InvalidCertificate(_) | rustls::Error::General(_)
        ) {
            return AppError::PeerRejected(format!(
                "server TLS certificate verification failed for {peer_name}: {rustls_err}"
            ));
        }
    }
    let s = e.to_string();
    if s.contains("invalid peer certificate")
        || s.contains("UnknownIssuer")
        || s.contains("InvalidCertificate")
        || s.contains("ApplicationVerificationFailure")
    {
        return AppError::PeerRejected(format!(
            "server TLS certificate verification failed for {peer_name}: {s}"
        ));
    }
    AppError::PeerUnreachable(format!("TLS handshake failed with {peer_name}: {e}"))
}

pub async fn send_federated_message(
    fed_state: &FedState,
    peer_name: &str,
    envelope: &FedEnvelope,
) -> Result<DeliveryResponse, AppError> {
    send_federated_message_with(fed_state, peer_name, envelope, false).await
}

/// `send_federated_message`, marked live-only when `live_only` (gate v0 C9).
pub async fn send_federated_message_with(
    fed_state: &FedState,
    peer_name: &str,
    envelope: &FedEnvelope,
    live_only: bool,
) -> Result<DeliveryResponse, AppError> {
    let peer = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;
    let peer_name = peer.name.as_str();

    if peer.leaf {
        let from_name = envelope.origin.render(&fed_state.node_name);
        return queue_leaf_mailbox_message(
            fed_state,
            peer_name,
            &envelope.to.r#ref,
            envelope,
            &from_name,
        );
    }

    let send_fut = async {
        let connector = make_tls_connector_for_peer(fed_state, peer)?;
        let tcp_stream = tokio::net::TcpStream::connect(&peer.address)
            .await
            .map_err(|e| {
                AppError::PeerUnreachable(format!("Failed to connect to {}: {e}", peer.address))
            })?;

        let server_name = ServerName::try_from(peer_name.to_string())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| map_tls_connect_error(peer_name, e))?;

        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("HTTP handshake failed: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP connection closed: {e}");
            }
        });

        let body_bytes =
            serde_json::to_vec(envelope).map_err(|e| AppError::Internal(e.to_string()))?;
        let mut req = hyper::Request::builder()
            .method("POST")
            .uri("/fed/v2/messages")
            .header("content-type", "application/json")
            .header("host", peer_name);
        if live_only {
            req = req.header(LIVE_ONLY_HEADER, "1");
        }
        let req = req
            .body(http_body_util::Full::new(bytes::Bytes::from(body_bytes)))
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("Request failed: {e}")))?;

        let status = resp.status();
        let max_limit = fed_state.max_body + 4096;
        let limited = http_body_util::Limited::new(resp.into_body(), max_limit);
        use http_body_util::BodyExt;
        let body_bytes = limited
            .collect()
            .await
            .map_err(|_| AppError::PayloadTooLarge {
                size: max_limit + 1,
                limit: max_limit,
            })?
            .to_bytes();

        if status.is_success() {
            let delivery_resp: DeliveryResponse = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(delivery_resp)
        } else {
            let err_resp: Result<WireErrorResponse, _> = serde_json::from_slice(&body_bytes);
            if let Ok(err) = err_resp {
                match status {
                    _ if err.error == "not_live" => Err(AppError::NotLive(err.detail)),
                    StatusCode::NOT_FOUND => Err(AppError::NotFoundDetail(err.detail)),
                    StatusCode::CONFLICT => Err(AppError::Ambiguous(err.detail)),
                    StatusCode::GONE => Err(AppError::Gone {
                        session_id: err.detail,
                        pid: 0,
                    }),
                    StatusCode::FORBIDDEN => Err(AppError::OpDenied(err.detail)),
                    StatusCode::BAD_REQUEST => Err(AppError::BadRequest(err.detail)),
                    StatusCode::TOO_MANY_REQUESTS => Err(AppError::RateLimited(err.detail)),
                    StatusCode::PAYLOAD_TOO_LARGE => Err(AppError::PayloadTooLarge {
                        size: 0,
                        limit: max_limit,
                    }),
                    StatusCode::GATEWAY_TIMEOUT => Err(AppError::PeerUnreachable(err.detail)),
                    _ => Err(AppError::ServiceUnavailable(err.detail)),
                }
            } else {
                Err(AppError::ServiceUnavailable(format!(
                    "Remote returned status {status}"
                )))
            }
        }
    };

    match tokio::time::timeout(Duration::from_secs(5), send_fut).await {
        Ok(res) => res,
        Err(_) => Err(AppError::PeerUnreachable(
            "Outbound call timed out after 5s".to_string(),
        )),
    }
}

pub async fn send_federated_reply(
    fed_state: &FedState,
    peer_name: &str,
    reply: &FedReplyEnvelope,
) -> Result<Value, AppError> {
    fed_state
        .outbound_replies_pushed
        .fetch_add(1, Ordering::SeqCst);

    let peer = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;
    let peer_name = peer.name.as_str();

    let reply_fut = async {
        let connector = make_tls_connector_for_peer(fed_state, peer)?;
        let tcp_stream = tokio::net::TcpStream::connect(&peer.address)
            .await
            .map_err(|e| {
                AppError::PeerUnreachable(format!("Failed to connect to {}: {e}", peer.address))
            })?;

        let server_name = ServerName::try_from(peer_name.to_string())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| map_tls_connect_error(peer_name, e))?;

        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("HTTP handshake failed: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP connection closed: {e}");
            }
        });

        let body_bytes =
            serde_json::to_vec(reply).map_err(|e| AppError::Internal(e.to_string()))?;
        let req = hyper::Request::builder()
            .method("POST")
            .uri("/fed/v2/replies")
            .header("content-type", "application/json")
            .header("host", peer_name)
            .body(http_body_util::Full::new(bytes::Bytes::from(body_bytes)))
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("Request failed: {e}")))?;

        let status = resp.status();
        let max_limit = fed_state.max_body + 4096;
        let limited = http_body_util::Limited::new(resp.into_body(), max_limit);
        use http_body_util::BodyExt;
        let body_bytes = limited
            .collect()
            .await
            .map_err(|_| AppError::PayloadTooLarge {
                size: max_limit + 1,
                limit: max_limit,
            })?
            .to_bytes();

        if status.is_success() {
            let val: Value = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(val)
        } else {
            let err_resp: Result<WireErrorResponse, _> = serde_json::from_slice(&body_bytes);
            if let Ok(err) = err_resp {
                match status {
                    StatusCode::NOT_FOUND => Err(AppError::NotFoundDetail(err.detail)),
                    StatusCode::CONFLICT => Err(AppError::Ambiguous(err.detail)),
                    StatusCode::GONE => Err(AppError::Gone {
                        session_id: err.detail,
                        pid: 0,
                    }),
                    StatusCode::FORBIDDEN => Err(AppError::OpDenied(err.detail)),
                    StatusCode::BAD_REQUEST => Err(AppError::BadRequest(err.detail)),
                    StatusCode::TOO_MANY_REQUESTS => Err(AppError::RateLimited(err.detail)),
                    StatusCode::PAYLOAD_TOO_LARGE => Err(AppError::PayloadTooLarge {
                        size: 0,
                        limit: max_limit,
                    }),
                    StatusCode::GATEWAY_TIMEOUT => Err(AppError::PeerUnreachable(err.detail)),
                    _ => Err(AppError::ServiceUnavailable(err.detail)),
                }
            } else {
                Err(AppError::ServiceUnavailable(format!(
                    "Remote returned status {status}"
                )))
            }
        }
    };

    match tokio::time::timeout(Duration::from_secs(5), reply_fut).await {
        Ok(res) => res,
        Err(_) => Err(AppError::PeerUnreachable(
            "Outbound call timed out after 5s".to_string(),
        )),
    }
}

pub async fn poll_federated_replies(
    fed_state: &FedState,
    peer_name: &str,
    message_id: &str,
    after_seq: i64,
    wait_secs: u64,
) -> Result<Vec<storage::ReplyRecord>, AppError> {
    let peer = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;
    let peer_name = peer.name.as_str();

    let poll_fut = async {
        let connector = make_tls_connector_for_peer(fed_state, peer)?;
        let tcp_stream = tokio::net::TcpStream::connect(&peer.address)
            .await
            .map_err(|e| {
                AppError::PeerUnreachable(format!("Failed to connect to {}: {e}", peer.address))
            })?;

        let server_name = ServerName::try_from(peer_name.to_string())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| map_tls_connect_error(peer_name, e))?;

        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("HTTP handshake failed: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP connection closed: {e}");
            }
        });

        let uri =
            format!("/fed/v2/messages/{message_id}/replies?after={after_seq}&wait={wait_secs}");
        let req = hyper::Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", peer_name)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("Request failed: {e}")))?;

        let status = resp.status();
        let max_limit = fed_state.max_body + 4096;
        let limited = http_body_util::Limited::new(resp.into_body(), max_limit);
        use http_body_util::BodyExt;
        let body_bytes = limited
            .collect()
            .await
            .map_err(|_| AppError::PayloadTooLarge {
                size: max_limit + 1,
                limit: max_limit,
            })?
            .to_bytes();

        if status.is_success() {
            let replies: Vec<storage::ReplyRecord> = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(replies)
        } else {
            let err_resp: Result<WireErrorResponse, _> = serde_json::from_slice(&body_bytes);
            if let Ok(err) = err_resp {
                match status {
                    StatusCode::NOT_FOUND => Err(AppError::NotFoundDetail(err.detail)),
                    StatusCode::FORBIDDEN => Err(AppError::OpDenied(err.detail)),
                    _ => Err(AppError::ServiceUnavailable(err.detail)),
                }
            } else {
                Err(AppError::ServiceUnavailable(format!(
                    "Remote returned status {status}"
                )))
            }
        }
    };

    let timeout_duration = Duration::from_secs(wait_secs + 5);
    match tokio::time::timeout(timeout_duration, poll_fut).await {
        Ok(res) => res,
        Err(_) => Err(AppError::PeerUnreachable(
            "Outbound reply poll timed out".to_string(),
        )),
    }
}

pub async fn get_federated_inbox(
    fed_state: &FedState,
    peer_name: &str,
    wait_secs: u64,
) -> Result<Option<FedInboxItem>, AppError> {
    let peer = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;
    let peer_name = peer.name.as_str();

    let poll_fut = async {
        let connector = make_tls_connector_for_peer(fed_state, peer)?;
        let tcp_stream = tokio::net::TcpStream::connect(&peer.address)
            .await
            .map_err(|e| {
                AppError::PeerUnreachable(format!("Failed to connect to {}: {e}", peer.address))
            })?;

        let server_name = ServerName::try_from(peer_name.to_string())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| map_tls_connect_error(peer_name, e))?;

        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("HTTP handshake failed: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP connection closed: {e}");
            }
        });

        let uri = format!("/fed/v2/inbox?wait={wait_secs}");
        let req = hyper::Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", peer_name)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("Request failed: {e}")))?;

        let status = resp.status();
        let max_limit = fed_state.max_body + 4096;
        let limited = http_body_util::Limited::new(resp.into_body(), max_limit);
        use http_body_util::BodyExt;
        let body_bytes = limited
            .collect()
            .await
            .map_err(|_| AppError::PayloadTooLarge {
                size: max_limit + 1,
                limit: max_limit,
            })?
            .to_bytes();

        if status.is_success() {
            let msg: Option<FedInboxItem> = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(format!("failed to parse inbox message: {e}")))?;
            Ok(msg)
        } else {
            let err_resp: Result<WireErrorResponse, _> = serde_json::from_slice(&body_bytes);
            if let Ok(err) = err_resp {
                match status {
                    StatusCode::NOT_FOUND => Err(AppError::NotFoundDetail(err.detail)),
                    StatusCode::FORBIDDEN => Err(AppError::OpDenied(err.detail)),
                    _ => Err(AppError::ServiceUnavailable(err.detail)),
                }
            } else {
                Err(AppError::ServiceUnavailable(format!(
                    "Remote returned status {status}"
                )))
            }
        }
    };

    let timeout_duration = Duration::from_secs(wait_secs + 5);
    match tokio::time::timeout(timeout_duration, poll_fut).await {
        Ok(res) => res,
        Err(_) => Ok(None),
    }
}

pub async fn ack_federated_inbox(
    fed_state: &FedState,
    peer_name: &str,
    message_id: &str,
) -> Result<(), AppError> {
    let peer = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;
    let peer_name = peer.name.as_str();

    let ack_fut = async {
        let connector = make_tls_connector_for_peer(fed_state, peer)?;
        let tcp_stream = tokio::net::TcpStream::connect(&peer.address)
            .await
            .map_err(|e| {
                AppError::PeerUnreachable(format!("Failed to connect to {}: {e}", peer.address))
            })?;

        let server_name = ServerName::try_from(peer_name.to_string())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| map_tls_connect_error(peer_name, e))?;

        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("HTTP handshake failed: {e}")))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP connection closed: {e}");
            }
        });

        let uri = format!("/fed/v2/inbox/{message_id}/ack");
        let req = hyper::Request::builder()
            .method("POST")
            .uri(uri)
            .header("host", peer_name)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| AppError::PeerUnreachable(format!("Request failed: {e}")))?;

        let status = resp.status();
        let max_limit = 4096;
        let limited = http_body_util::Limited::new(resp.into_body(), max_limit);
        use http_body_util::BodyExt;
        let body_bytes = limited
            .collect()
            .await
            .map_err(|_| AppError::PayloadTooLarge {
                size: max_limit + 1,
                limit: max_limit,
            })?
            .to_bytes();

        if status.is_success() {
            Ok(())
        } else {
            let err_resp: Result<WireErrorResponse, _> = serde_json::from_slice(&body_bytes);
            if let Ok(err) = err_resp {
                match status {
                    StatusCode::NOT_FOUND => Err(AppError::NotFoundDetail(err.detail)),
                    StatusCode::FORBIDDEN => Err(AppError::OpDenied(err.detail)),
                    _ => Err(AppError::ServiceUnavailable(err.detail)),
                }
            } else {
                Err(AppError::ServiceUnavailable(format!(
                    "Remote returned status {status}"
                )))
            }
        }
    };

    let timeout_duration = Duration::from_secs(10);
    tokio::time::timeout(timeout_duration, ack_fut)
        .await
        .map_err(|_| AppError::PeerUnreachable("ack request timed out".to_string()))?
}

pub fn spawn_outbound_reply_poller(
    fed_state: Arc<FedState>,
    peer_name: String,
    message_id: String,
) {
    tokio::spawn(async move {
        let mut after_seq = 0i64;
        let mut backoff_millis = 100u64;
        let max_backoff_millis = 2000u64;
        let wait_secs = 5u64;
        let max_iterations = 60;

        for _ in 0..max_iterations {
            match poll_federated_replies(&fed_state, &peer_name, &message_id, after_seq, wait_secs)
                .await
            {
                Ok(replies) => {
                    backoff_millis = 100;
                    let mut should_stop = false;

                    for r in replies {
                        after_seq = after_seq.max(r.seq);

                        let orig_msg = {
                            if let Ok(db) = fed_state.db.lock() {
                                storage::get_message(&db, &message_id).unwrap_or(None)
                            } else {
                                None
                            }
                        };

                        if let Some(orig) = orig_msg {
                            if let (Some(ret_harness), Some(ret_session_id)) =
                                (&orig.return_harness, &orig.return_session_id)
                            {
                                let Some(reply_id) =
                                    r.pushed_message_id.clone().filter(|id| !id.is_empty())
                                else {
                                    tracing::warn!(
                                        message_id = %message_id,
                                        seq = r.seq,
                                        peer = %peer_name,
                                        "refusing pulled reply without authoritative pushed_message_id"
                                    );
                                    continue;
                                };
                                let replier_badge = inbox::sender_label(
                                    &peer_name,
                                    "",
                                    &r.replier_session_id,
                                    None,
                                );

                                let node = fed_state
                                    .current_peers()
                                    .canonical_name(&peer_name)
                                    .unwrap_or(&peer_name)
                                    .to_string();
                                if let Ok(db) = fed_state.db.lock() {
                                    crate::surface::record_pushed_reply(
                                        &db,
                                        &orig,
                                        &reply_id,
                                        &replier_badge,
                                        &r.text,
                                        ("fed", &r.replier_session_id),
                                        Some(&peer_name),
                                    );
                                }
                                match deliver_federated_reply_locally(
                                    &fed_state,
                                    &peer_name,
                                    &message_id,
                                    &reply_id,
                                    &replier_badge,
                                    storage::Origin::instance(&r.replier_session_id, &node, None),
                                    &r.text,
                                    ret_harness,
                                    ret_session_id,
                                )
                                .await
                                {
                                    Ok("pushed") => {}
                                    Ok("sender_gone") => {
                                        if let Ok(db) = fed_state.db.lock() {
                                            let _ = storage::delete_message(&db, &reply_id);
                                        }
                                        should_stop = true;
                                    }
                                    _ => {
                                        if let Ok(db) = fed_state.db.lock() {
                                            let _ = storage::delete_message(&db, &reply_id);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if should_stop {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        "Outbound reply poller error for message {message_id} on {peer_name}: {e}"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_millis)).await;
                    backoff_millis = (backoff_millis * 2).min(max_backoff_millis);
                }
            }
        }
    });
}

pub async fn run_outbound_peer_pull_loop(fed_state: Arc<FedState>, peer_name: String) {
    info!(peer = %peer_name, "starting outbound link pull loop");
    let mut backoff_millis = 100u64;
    let max_backoff_millis = 5000u64;
    let wait_secs = 30u64;

    loop {
        if !fed_state
            .current_peers()
            .get(&peer_name)
            .is_some_and(|p| p.is_outbound())
        {
            info!(peer = %peer_name, "outbound peer removed or no longer outbound, exiting pull loop");
            break;
        }

        match get_federated_inbox(&fed_state, &peer_name, wait_secs).await {
            Ok(Some(FedInboxItem::List { query, v })) => {
                backoff_millis = 100;
                answer_list_query(&fed_state, &peer_name, &query, v.unwrap_or(1) >= 2).await;
            }
            Ok(Some(FedInboxItem::Message(msg))) => {
                backoff_millis = 100;

                // Idempotency (X1): a message already delivered or queued here is acked
                // and skipped; one recorded as a failure is delivered again.
                let already_processed = {
                    if let Ok(db) = fed_state.db.lock() {
                        storage::get_message(&db, &msg.id)
                            .unwrap_or(None)
                            .is_some_and(|m| storage::outcome_reached(&m.outcome))
                    } else {
                        false
                    }
                };

                if already_processed {
                    let mut ack_backoff = 100u64;
                    loop {
                        match ack_federated_inbox(&fed_state, &peer_name, &msg.id).await {
                            Ok(()) => break,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to ack duplicate message {} to hub {}: {e}, retrying",
                                    msg.id,
                                    peer_name
                                );
                                tokio::time::sleep(Duration::from_millis(ack_backoff)).await;
                                ack_backoff = (ack_backoff * 2).min(5000);
                            }
                        }
                    }
                    continue;
                }

                let target_ref = msg.to.as_deref().unwrap_or("");
                // A12: one render, from the origin the hub attests.
                let ret_host = peer_name.clone();
                let from_name = msg
                    .origin
                    .render(fed_state.current_peers().display_name(&msg.origin.node));

                let resolved = resolve_target_session_fed(&fed_state, target_ref).await;

                match resolved {
                    Ok(target) => {
                        // A sender with an inbox gets its reply pushed back through the
                        // hub; an anonymous one reads it with `replies` (A10).
                        let (return_harness, return_session_id) = match msg.origin.key() {
                            Some(key) => (
                                Some(
                                    if msg.origin.service.is_some() {
                                        "svc"
                                    } else {
                                        "fed"
                                    }
                                    .to_string(),
                                ),
                                Some(key.to_string()),
                            ),
                            None => (None, None),
                        };

                        // The record is written before the message is delivered, as the
                        // federation receive path writes it: an ack or reply that lands
                        // before delivery returns finds it, and `queued` never replaces the
                        // `delivered` it records. `pending` is not a reached outcome, so a
                        // message whose delivery was interrupted is delivered again.
                        let pre_record = storage::MessageRecord {
                            id: msg.id.clone(),
                            created_at: storage::now_epoch_secs(),
                            session_id: target.session().session_id.clone(),
                            from_name: from_name.clone(),
                            bytes: msg.body.len(),
                            outcome: storage::KEY_PENDING.to_string(),
                            recipient_harness: target.recipient_harness().to_string(),
                            return_harness,
                            return_session_id,
                            thread_id: msg.id.clone(),
                            return_host: Some(ret_host.clone()),
                        };
                        if let Ok(db) = fed_state.db.lock() {
                            let _ = storage::upsert_message(&db, &pre_record);
                        }

                        let deliver_res = crate::surface::deliver(
                            &fed_state.local(),
                            &target,
                            &from_name,
                            &msg.id,
                            &msg.body,
                            msg.origin.clone(),
                        )
                        .await;

                        let outcome_str = match deliver_res {
                            Ok((_sess_id, _harness, outcome)) => outcome,
                            Err(e) => {
                                if let Ok(db) = fed_state.db.lock() {
                                    let _ = storage::record_message_recipient(
                                        &db, &msg.id, target_ref, "system",
                                    );
                                }
                                match &e {
                                    AppError::Gone { .. } => "gone",
                                    AppError::NotFound(_) | AppError::NotFoundDetail(_) => {
                                        "not_found"
                                    }
                                    AppError::Ambiguous(_) => "ambiguous",
                                    _ => "failed",
                                }
                            }
                        };

                        if let Ok(db) = fed_state.db.lock() {
                            let _ = storage::complete_message(
                                &db,
                                &msg.id,
                                outcome_str,
                                Some(&ret_host),
                            );
                        }

                        let mut ack_backoff = 100u64;
                        loop {
                            match ack_federated_inbox(&fed_state, &peer_name, &msg.id).await {
                                Ok(()) => break,
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to ack message {} to hub {}: {e}, retrying",
                                        msg.id,
                                        peer_name
                                    );
                                    tokio::time::sleep(Duration::from_millis(ack_backoff)).await;
                                    ack_backoff = (ack_backoff * 2).min(5000);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            "message {} target '{target_ref}' unresolvable ({err}); sending error reply and acking at hub",
                            msg.id
                        );

                        let detail = match &err {
                            AppError::NotFound(r) => format!("no live session matches '{r}'"),
                            AppError::Gone { session_id, pid } => {
                                format!("session {session_id} process {pid} exited")
                            }
                            AppError::Ambiguous(d) => d.clone(),
                            _ => format!("no live session matches '{target_ref}'"),
                        };

                        let reply_text = serde_json::json!({
                            "error": "not_found",
                            "detail": detail,
                        })
                        .to_string();

                        let replier = storage::Origin::service("system", &fed_state.node_name);

                        let reply_envelope = FedReplyEnvelope {
                            v: WIRE_VERSION,
                            id: ulid::Ulid::new().to_string(),
                            in_reply_to: msg.id.clone(),
                            replier,
                            text: reply_text,
                            created_at: storage::now_epoch_secs(),
                        };

                        let _ = send_federated_reply(&fed_state, &ret_host, &reply_envelope).await;

                        let msg_record = storage::MessageRecord {
                            id: msg.id.clone(),
                            created_at: storage::now_epoch_secs(),
                            session_id: target_ref.to_string(),
                            from_name: from_name.clone(),
                            bytes: msg.body.len(),
                            outcome: "not_found".to_string(),
                            recipient_harness: "system".to_string(),
                            return_harness: None,
                            return_session_id: None,
                            thread_id: msg.id.clone(),
                            return_host: Some(ret_host.clone()),
                        };

                        if let Ok(db) = fed_state.db.lock() {
                            let _ = storage::upsert_message(&db, &msg_record);
                        }

                        let mut ack_backoff = 100u64;
                        loop {
                            match ack_federated_inbox(&fed_state, &peer_name, &msg.id).await {
                                Ok(()) => break,
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to ack unresolvable message {} to hub {}: {e}, retrying",
                                        msg.id,
                                        peer_name
                                    );
                                    tokio::time::sleep(Duration::from_millis(ack_backoff)).await;
                                    ack_backoff = (ack_backoff * 2).min(5000);
                                }
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                backoff_millis = 100;
            }
            Err(e) => {
                tracing::warn!(
                    "Outbound pull loop error from hub {}: {e}, retrying in {backoff_millis}ms",
                    peer_name
                );
                tokio::time::sleep(Duration::from_millis(backoff_millis)).await;
                backoff_millis = (backoff_millis * 2).min(max_backoff_millis);
            }
        }
    }
}

/// The bound on asking one node for its `list` (D14).
pub const LIST_TIMEOUT: Duration = Duration::from_secs(5);

/// How one node answered a `list` (A-12): `ok`, `unreachable` or `timeout`. A node that
/// withholds `list` counts as one that could not be asked (gate v0 C4): `unreachable`, with
/// the detail `withholds list`. So does a dial-out client that does not answer in time
/// (A-1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeStatus {
    pub node: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl NodeStatus {
    pub fn ok(node: &str) -> Self {
        Self {
            node: node.to_string(),
            status: "ok".to_string(),
            detail: None,
        }
    }

    fn failed(node: &str, status: &str, detail: String) -> Self {
        Self {
            node: node.to_string(),
            status: status.to_string(),
            detail: Some(detail),
        }
    }
}

/// Asks the peer keyed `peer_key` for its `list` (A4, A-1), bounded by `LIST_TIMEOUT`: a
/// direct peer over `/fed/v2/sessions`, a dial-out client through its mailbox. Returns the
/// entries its certificate user may list (P-3) and its status.
pub async fn list_peer(fed_state: &FedState, peer_key: &str) -> (Vec<FedListEntry>, NodeStatus) {
    let Some(peer) = fed_state.current_peers().get(peer_key).cloned() else {
        return (
            Vec::new(),
            NodeStatus::failed(peer_key, "unreachable", "not a peer".to_string()),
        );
    };
    let asked = async {
        if peer.leaf {
            list_dial_out_client(fed_state, &peer.name).await
        } else {
            list_direct_peer(fed_state, &peer).await
        }
    };
    let Ok(res) = tokio::time::timeout(LIST_TIMEOUT, asked).await else {
        let detail = format!("did not answer `list` within {}s", LIST_TIMEOUT.as_secs());
        let status = if peer.leaf { "unreachable" } else { "timeout" };
        return (Vec::new(), NodeStatus::failed(&peer.name, status, detail));
    };
    match res {
        Ok((answer, user)) => match answer {
            FedListAnswer::Ok { entries } => {
                (admit_entries(entries, &user), NodeStatus::ok(&peer.name))
            }
            FedListAnswer::Denied => (Vec::new(), withholds_list(&peer.name)),
        },
        Err(AppError::OpDenied(d)) => (
            Vec::new(),
            NodeStatus::failed(&peer.name, "unreachable", format!("{WITHHOLDS_LIST}: {d}")),
        ),
        Err(e) => (
            Vec::new(),
            NodeStatus::failed(&peer.name, "unreachable", e.to_string()),
        ),
    }
}

fn withholds_list(node: &str) -> NodeStatus {
    NodeStatus::failed(node, "unreachable", WITHHOLDS_LIST.to_string())
}

/// The detail of a node that withholds `list` from the asker.
pub const WITHHOLDS_LIST: &str = "withholds list";

/// A dial-out client is asked through its mailbox: the query wakes its waiting long-poll,
/// and it answers on `/fed/v2/list/{query}` (AM-1). Unbounded here; `list_peer` bounds it.
async fn list_dial_out_client(
    fed_state: &FedState,
    peer_key: &str,
) -> Result<(FedListAnswer, String), AppError> {
    let (query, rx) = fed_state.list_queries.ask(peer_key);
    let _ = fed_state.notify_tx.send(peer_key.to_string());
    struct Forget<'a>(&'a ListQueries, String);
    impl Drop for Forget<'_> {
        fn drop(&mut self) {
            self.0.forget(&self.1);
        }
    }
    let _forget = Forget(&fed_state.list_queries, query);
    rx.await
        .map_err(|_| AppError::PeerUnreachable(format!("'{peer_key}' dropped the list query")))
}

pub async fn list_direct_peer(
    fed_state: &FedState,
    peer: &PeerConfig,
) -> Result<(FedListAnswer, String), AppError> {
    let peer_name = peer.name.as_str();
    let connector = make_tls_connector_for_peer(fed_state, peer)?;
    let tcp_stream = tokio::net::TcpStream::connect(&peer.address)
        .await
        .map_err(|e| {
            AppError::PeerUnreachable(format!(
                "Failed to connect to peer '{peer_name}' at {}: {e}",
                peer.address
            ))
        })?;
    let server_name = ServerName::try_from(peer_name.to_string())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| map_tls_connect_error(peer_name, e))?;
    // The user the peer's certificate names (A16), read from the certificate it presented.
    let user = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(|leaf| crate::node::user_from_cert(leaf.as_ref()).ok())
        .unwrap_or_default();

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            AppError::PeerUnreachable(format!(
                "HTTP handshake failed with peer '{peer_name}': {e}"
            ))
        })?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("HTTP connection closed: {e}");
        }
    });

    let req = hyper::Request::builder()
        .method("GET")
        .uri("/fed/v2/sessions?v=2")
        .header("host", peer_name)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let resp = sender.send_request(req).await.map_err(|e| {
        AppError::PeerUnreachable(format!("Request to peer '{peer_name}' failed: {e}"))
    })?;

    let status = resp.status();
    let max_limit = fed_state.max_body + 4096;
    let limited = http_body_util::Limited::new(resp.into_body(), max_limit);
    use http_body_util::BodyExt;
    let body_bytes = limited
        .collect()
        .await
        .map_err(|_| AppError::PayloadTooLarge {
            size: max_limit + 1,
            limit: max_limit,
        })?
        .to_bytes();

    if status.is_success() {
        let entries: Vec<FedListEntry> = serde_json::from_slice(&body_bytes).map_err(|e| {
            AppError::ServiceUnavailable(format!("unreadable list from peer '{peer_name}': {e}"))
        })?;
        Ok((FedListAnswer::Ok { entries }, user))
    } else if status == StatusCode::FORBIDDEN {
        let detail = serde_json::from_slice::<WireErrorResponse>(&body_bytes)
            .map(|e| e.detail)
            .unwrap_or_else(|_| format!("peer '{peer_name}' returned status {status}"));
        Err(AppError::OpDenied(detail))
    } else {
        Err(AppError::ServiceUnavailable(format!(
            "peer '{peer_name}' returned status {status}"
        )))
    }
}

/// A dial-out client answers a `list` query from `peer_key`'s mailbox, applying its own
/// entry for that node (A-1, AM-1): `denied` unless it allows `list`.
pub async fn answer_list_query(fed_state: &FedState, peer_key: &str, query: &str, v2: bool) {
    let Some(peer) = fed_state.current_peers().get(peer_key).cloned() else {
        return;
    };
    let answer = if peer.allow.iter().any(|op| op == "list") {
        match listing_for_peer(fed_state, &peer, v2).await {
            Ok(entries) => FedListAnswer::Ok { entries },
            Err(e) => {
                tracing::warn!("list for '{peer_key}' failed: {e}");
                return;
            }
        }
    } else {
        FedListAnswer::Denied
    };
    let posted = async {
        let connector = make_tls_connector_for_peer(fed_state, &peer)?;
        let tcp = tokio::net::TcpStream::connect(&peer.address)
            .await
            .map_err(|e| AppError::PeerUnreachable(e.to_string()))?;
        let server_name = ServerName::try_from(peer.name.clone())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| map_tls_connect_error(&peer.name, e))?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|e| AppError::PeerUnreachable(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let body = serde_json::to_vec(&answer).map_err(|e| AppError::Internal(e.to_string()))?;
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("/fed/v2/list/{query}"))
            .header("content-type", "application/json")
            .header("host", peer.name.as_str())
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| AppError::PeerUnreachable(e.to_string()))?;
        match resp.status() {
            s if s.is_success() => Ok(()),
            s => Err(AppError::ServiceUnavailable(format!(
                "'{peer_key}' refused the list answer: {s}"
            ))),
        }
    };
    match tokio::time::timeout(LIST_TIMEOUT, posted).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("list answer to '{peer_key}' failed: {e}"),
        Err(_) => tracing::warn!("list answer to '{peer_key}' timed out"),
    }
}

// -----------------------------------------------------------------------------
// Test Identity Generation Helper
// -----------------------------------------------------------------------------

pub fn generate_self_signed_ed25519(host_name: &str) -> Result<(Vec<u8>, Vec<u8>, String), String> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| format!("Failed to generate keypair: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![host_name.to_string()])
        .map_err(|e| format!("Failed to create cert params: {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host_name);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to sign cert: {e}"))?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();
    let pin = spki_sha256_from_der(&cert_der)?;
    Ok((cert_der, key_der, pin))
}

pub fn generate_self_signed_ed25519_pem(
    host_name: &str,
) -> Result<(String, String, String), String> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| format!("Failed to generate keypair: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![host_name.to_string()])
        .map_err(|e| format!("Failed to create cert params: {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host_name);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to sign cert: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let pin = spki_sha256_from_der(cert.der())?;
    Ok((cert_pem, key_pem, pin))
}

// -----------------------------------------------------------------------------
// Run Federated Listener
// -----------------------------------------------------------------------------

const MAX_UNAUTH_PER_IP: usize = 8;
const MAX_CONNS_PER_PEER: usize = 8;

struct UnauthIpGuard {
    ip: IpAddr,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for UnauthIpGuard {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock() {
            if let Some(count) = counts.get_mut(&self.ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&self.ip);
                }
            }
        }
    }
}

struct PeerConnGuard {
    peer_name: String,
    counts: Arc<Mutex<HashMap<String, usize>>>,
}

impl Drop for PeerConnGuard {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock() {
            if let Some(count) = counts.get_mut(&self.peer_name) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&self.peer_name);
                }
            }
        }
    }
}

pub async fn run_fed_listener(
    listener: tokio::net::TcpListener,
    fed_state: Arc<FedState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acceptor = match fed_state.get_tls_acceptor() {
        Some(a) => a,
        None => make_tls_acceptor(
            &fed_state.cert_chain(),
            &fed_state.key_der(),
            fed_state.current_peers(),
        )?,
    };
    run_fed_listener_with_acceptor(listener, fed_state, acceptor).await
}

pub async fn run_fed_listener_with_acceptor(
    listener: tokio::net::TcpListener,
    fed_state: Arc<FedState>,
    acceptor: tokio_rustls::TlsAcceptor,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let router = build_fed_router(fed_state.clone());
    let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(128));
    let unauth_ip_counts: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let peer_conn_counts: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("federation listener accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        // N3: Cap pre-handshake connections per source IP before taking a permit
        let remote_ip = remote_addr.ip();
        let unauth_guard = {
            let mut counts = unauth_ip_counts.lock().unwrap();
            let count = counts.entry(remote_ip).or_insert(0);
            if *count >= MAX_UNAUTH_PER_IP {
                debug!("pre-handshake connection cap reached for {remote_addr}, dropping");
                drop(tcp_stream);
                continue;
            }
            *count += 1;
            UnauthIpGuard {
                ip: remote_ip,
                counts: unauth_ip_counts.clone(),
            }
        };

        let permit = match conn_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!("federation listener at max connection capacity, dropping {remote_addr}");
                drop(tcp_stream);
                continue;
            }
        };

        let current_acceptor = fed_state
            .get_tls_acceptor()
            .unwrap_or_else(|| acceptor.clone());
        let fed_state = fed_state.clone();
        let router = router.clone();
        let peer_conn_counts = peer_conn_counts.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let unauth_guard = unauth_guard;
            let tls_stream = match tokio::time::timeout(
                Duration::from_secs(3),
                current_acceptor.accept(tcp_stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!("TLS handshake failed from {remote_addr}: {e}");
                    return;
                }
                Err(_) => {
                    debug!("TLS handshake timed out from {remote_addr}");
                    return;
                }
            };

            // TLS handshake complete: release pre-handshake socket slot
            drop(unauth_guard);

            let (_, server_conn) = tls_stream.get_ref();
            let certs = match server_conn.peer_certificates() {
                Some(c) if !c.is_empty() => c,
                _ => {
                    debug!("No peer certificate from {remote_addr}");
                    return;
                }
            };

            let leaf = &certs[0];
            let intermediates = &certs[1..];

            let (peer_config, verified_uri) = match fed_state
                .current_peers()
                .resolve_incoming_peer(leaf, intermediates)
            {
                Ok(p) => p,
                Err(e) => {
                    debug!("Failed to resolve peer from TLS certificate: {e}");
                    return;
                }
            };

            if let Some(ref uri) = verified_uri {
                info!(
                    "Authenticated federated CA peer '{}' with verified URI SAN '{}'",
                    peer_config.name, uri
                );
            }

            let client_pin = spki_sha256_from_der(leaf.as_ref()).unwrap_or_default();

            // N2: Cap connections per authenticated peer
            let peer_guard = {
                let mut counts = peer_conn_counts.lock().unwrap();
                let count = counts.entry(peer_config.name.clone()).or_insert(0);
                if *count >= MAX_CONNS_PER_PEER {
                    debug!(
                        "connection cap reached for peer {}, dropping",
                        peer_config.name
                    );
                    return;
                }
                *count += 1;
                PeerConnGuard {
                    peer_name: peer_config.name.clone(),
                    counts: peer_conn_counts.clone(),
                }
            };

            let peer_info = Arc::new(AuthenticatedPeer {
                name: peer_config.name.clone(),
                pin: client_pin,
                uri: verified_uri,
                user: crate::node::user_from_cert(leaf.as_ref()).unwrap_or_default(),
                remote_ip: remote_addr.ip(),
            });

            // N1: Perform source address check ONCE PER CONNECTION in run_fed_listener
            let reject_msg = check_peer_source(&peer_config, &peer_info.remote_ip)
                .err()
                .map(|e| match e {
                    AppError::PeerRejected(msg) => msg,
                    other => other.to_string(),
                });

            let router = router.clone();
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut router = router.clone();
                    let peer_info = peer_info.clone();
                    let reject_msg = reject_msg.clone();
                    async move {
                        if let Some(msg) = reject_msg {
                            use axum::response::IntoResponse;
                            return Ok::<_, std::convert::Infallible>(
                                AppError::PeerRejected(msg).into_response(),
                            );
                        }
                        let mut req = req.map(axum::body::Body::new);
                        req.extensions_mut().insert(peer_info);
                        use tower::Service;
                        router.call(req).await
                    }
                });

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let mut http1_builder = hyper::server::conn::http1::Builder::new();
            http1_builder
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5));

            let _peer_guard = peer_guard;
            if let Err(e) = http1_builder.serve_connection(io, service).await {
                debug!("Error serving federated connection: {e}");
            }
        });
    }
}

// -----------------------------------------------------------------------------
// Dynamic Credential & CA Bundle Reloader (Unit X17)
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct DummyServerCertVerifier;

impl rustls::client::danger::ServerCertVerifier for DummyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct CredentialReloader {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub peers_path: Option<PathBuf>,
    pub own: Option<OwnNode>,
    pub ca_paths: Mutex<HashMap<String, PathBuf>>,
    pub file_hashes: Mutex<HashMap<PathBuf, Vec<u8>>>,
    pub dynamic_tls: Arc<std::sync::RwLock<Option<DynamicTls>>>,
    pub peers: Mutex<Arc<PeersMap>>,
    pub fed_state: Option<Arc<FedState>>,
    pub active_pull_loops: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl CredentialReloader {
    pub fn new(
        cert_path: PathBuf,
        key_path: PathBuf,
        peers: Arc<PeersMap>,
        dynamic_tls: Arc<std::sync::RwLock<Option<DynamicTls>>>,
    ) -> Result<Self, AppError> {
        Self::new_full(
            cert_path,
            key_path,
            None,
            None,
            peers,
            dynamic_tls,
            None,
            Arc::new(Mutex::new(std::collections::HashSet::new())),
        )
    }

    pub fn new_full(
        cert_path: PathBuf,
        key_path: PathBuf,
        peers_path: Option<PathBuf>,
        own: Option<OwnNode>,
        peers: Arc<PeersMap>,
        dynamic_tls: Arc<std::sync::RwLock<Option<DynamicTls>>>,
        fed_state: Option<Arc<FedState>>,
        active_pull_loops: Arc<Mutex<std::collections::HashSet<String>>>,
    ) -> Result<Self, AppError> {
        let mut ca_paths = HashMap::new();
        for peer in peers.ca_peers() {
            if let Some(ref ca_path) = peer.ca {
                ca_paths.insert(peer.name.clone(), ca_path.clone());
            }
        }

        let reloader = Self {
            cert_path,
            key_path,
            peers_path,
            own,
            ca_paths: Mutex::new(ca_paths),
            file_hashes: Mutex::new(HashMap::new()),
            dynamic_tls,
            peers: Mutex::new(peers),
            fed_state,
            active_pull_loops,
        };

        // Populate initial configuration and hashes
        reloader.check_and_reload()?;
        Ok(reloader)
    }

    pub fn compute_file_hash(path: &Path) -> Result<Vec<u8>, std::io::Error> {
        let bytes = std::fs::read(path)?;
        use sha2::Digest;
        Ok(sha2::Sha256::digest(&bytes).to_vec())
    }

    pub fn check_and_reload(&self) -> Result<bool, AppError> {
        let mut current_hashes = HashMap::new();

        let cert_hash = match Self::compute_file_hash(&self.cert_path) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("failed to read cert file {}: {e}", self.cert_path.display());
                return Err(AppError::Internal(format!("failed to read cert file: {e}")));
            }
        };
        current_hashes.insert(self.cert_path.clone(), cert_hash);

        let key_hash = match Self::compute_file_hash(&self.key_path) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("failed to read key file {}: {e}", self.key_path.display());
                return Err(AppError::Internal(format!("failed to read key file: {e}")));
            }
        };
        current_hashes.insert(self.key_path.clone(), key_hash);

        if let Some(ref peers_path) = self.peers_path {
            let peers_hash = match Self::compute_file_hash(peers_path) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("failed to read peers file {}: {e}", peers_path.display());
                    return Err(AppError::Internal(format!(
                        "failed to read peers file: {e}"
                    )));
                }
            };
            current_hashes.insert(peers_path.clone(), peers_hash);
        }

        let ca_paths = self.ca_paths.lock().unwrap().clone();
        for (peer_name, ca_path) in &ca_paths {
            let ca_hash = match Self::compute_file_hash(ca_path) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!(
                        "failed to read CA file {} for peer {peer_name}: {e}",
                        ca_path.display()
                    );
                    return Err(AppError::Internal(format!("failed to read CA file: {e}")));
                }
            };
            current_hashes.insert(ca_path.clone(), ca_hash);
        }

        let changed = {
            let old_hashes = self.file_hashes.lock().unwrap();
            *old_hashes != current_hashes
        };

        if !changed {
            return Ok(false);
        }

        // If peers file is configured, reload it
        let new_peers_map = if let Some(ref peers_path) = self.peers_path {
            match PeersMap::load_from_file_for(peers_path, self.own.as_ref()) {
                Ok(mut pm) => {
                    // Preserve admitted_clients Arc across reload swap!
                    let current_pm = self.peers.lock().unwrap().clone();
                    pm.admitted_clients = current_pm.admitted_clients.clone();
                    pm
                }
                Err(e) => {
                    tracing::error!(
                        "invalid peers file '{}' during reload; keeping previous configuration: {e}",
                        peers_path.display()
                    );
                    return Err(AppError::Internal(format!(
                        "invalid peers file '{}': {e}",
                        peers_path.display()
                    )));
                }
            }
        } else {
            (*self.peers.lock().unwrap()).as_ref().clone()
        };

        match self.build_tls_config(&new_peers_map) {
            Ok(new_dyn_tls) => {
                let mut new_ca_paths = HashMap::new();
                for peer in new_peers_map.ca_peers() {
                    if let Some(ref ca_path) = peer.ca {
                        new_ca_paths.insert(peer.name.clone(), ca_path.clone());
                    }
                }
                *self.ca_paths.lock().unwrap() = new_ca_paths;

                *self.peers.lock().unwrap() = Arc::new(new_peers_map.clone());
                *self.dynamic_tls.write().unwrap() = Some(new_dyn_tls);
                *self.file_hashes.lock().unwrap() = current_hashes;

                // Reconcile outbound pull loops
                if let Some(ref fs) = self.fed_state {
                    let mut active = self.active_pull_loops.lock().unwrap();
                    for (peer_name, peer_cfg) in new_peers_map.iter() {
                        if peer_cfg.is_outbound() && !active.contains(peer_name) {
                            active.insert(peer_name.clone());
                            let fs_clone = fs.clone();
                            let peer_clone = peer_name.clone();
                            let active_clone = self.active_pull_loops.clone();
                            tokio::spawn(async move {
                                run_outbound_peer_pull_loop(fs_clone, peer_clone.clone()).await;
                                active_clone.lock().unwrap().remove(&peer_clone);
                            });
                        }
                    }
                }

                tracing::info!("successfully reloaded federation TLS credentials and peers");
                Ok(true)
            }
            Err(e) => {
                tracing::error!(
                    "invalid TLS credentials during reload; keeping previous configuration: {e}"
                );
                Err(e)
            }
        }
    }

    fn build_tls_config(&self, peers: &PeersMap) -> Result<DynamicTls, AppError> {
        let cert_pem = std::fs::read(&self.cert_path).map_err(|e| {
            AppError::Internal(format!(
                "failed to read cert file {}: {e}",
                self.cert_path.display()
            ))
        })?;
        let key_pem = std::fs::read(&self.key_path).map_err(|e| {
            AppError::Internal(format!(
                "failed to read key file {}: {e}",
                self.key_path.display()
            ))
        })?;

        use rustls::pki_types::pem::PemObject;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AppError::Internal(format!("failed to parse cert pem: {e}")))?;
        if certs.is_empty() {
            return Err(AppError::Internal(
                "cert file contains 0 certificates".to_string(),
            ));
        }

        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
            .map_err(|e| AppError::Internal(format!("failed to parse key pem: {e}")))?;

        let cert_der = certs[0].to_vec();
        let cert_chain_der: Vec<Vec<u8>> = certs.iter().map(|c| c.to_vec()).collect();
        let key_der = key.secret_der().to_vec();

        let mut ca_anchors = HashMap::new();
        let mut new_peers = peers.clone();

        let ca_peer_configs: Vec<(String, PathBuf)> = peers
            .ca_peers()
            .into_iter()
            .filter_map(|p| p.ca.as_ref().map(|ca| (p.name.clone(), ca.clone())))
            .collect();

        for (peer_name, ca_path) in ca_peer_configs {
            let ca_pem = std::fs::read(&ca_path).map_err(|e| {
                AppError::Internal(format!("failed to read CA file {}: {e}", ca_path.display()))
            })?;
            let anchors = parse_ca_bundle_pem(&ca_pem).map_err(|e| {
                AppError::Internal(format!(
                    "failed to parse CA bundle for peer '{peer_name}': {e}"
                ))
            })?;
            if anchors.is_empty() {
                return Err(AppError::Internal(format!(
                    "CA bundle for peer '{peer_name}' contains 0 certificates"
                )));
            }
            new_peers.update_ca_anchors(&peer_name, anchors.clone());
            ca_anchors.insert(peer_name, anchors);
        }

        let new_peers_arc = Arc::new(new_peers);

        // Validate key matches cert and build acceptor
        let acceptor = make_tls_acceptor(&certs, &key_der, new_peers_arc.clone())?;

        // Also validate client auth config with certs & key (ensures key matches cert)
        let _ = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| AppError::Internal(format!("TLS config error: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DummyServerCertVerifier))
        .with_client_auth_cert(certs, key)
        .map_err(|e| {
            AppError::Internal(format!("Client cert error (key does not match cert): {e}"))
        })?;

        Ok(DynamicTls {
            cert_der,
            cert_chain_der,
            key_der,
            ca_anchors,
            acceptor,
            peers: new_peers_arc,
        })
    }

    pub fn start_watcher(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval_timer.tick().await; // consume first immediate tick
            loop {
                interval_timer.tick().await;
                if let Err(e) = self.check_and_reload() {
                    tracing::error!("federation credential reload check failed: {e}");
                }
            }
        })
    }
}
