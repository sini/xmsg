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
    error: String,
    detail: String,
}

// -----------------------------------------------------------------------------
// Peers Configuration & File Format
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    #[serde(default)]
    pub name: String,
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
}

pub(crate) fn target_matches_allowlist(
    target: &crate::http::ResolvedTarget,
    targets: &[String],
) -> bool {
    if targets.is_empty() {
        return false;
    }
    let badges: Vec<String> = match target {
        crate::http::ResolvedTarget::Svc(s) => {
            let mut b = Vec::new();
            if let Some(ref name) = s.name {
                b.push(format!("svc:{name}"));
            }
            if s.session_id.starts_with("svc:") {
                b.push(s.session_id.clone());
            } else {
                b.push(format!("svc:{}", s.session_id));
            }
            b.push(format!("session:{}", s.session_id));
            b
        }
        crate::http::ResolvedTarget::Claude(s, _)
        | crate::http::ResolvedTarget::Agy(s)
        | crate::http::ResolvedTarget::Pi(s) => {
            let mut b = Vec::new();
            if let Some(ref name) = s.name {
                b.push(format!("{}:{name}", s.harness));
            }
            b.push(format!("session:{}", s.session_id));
            b.push(format!("{}:{}", s.harness, s.session_id));
            b
        }
    };
    targets.iter().any(|t| badges.iter().any(|b| b == t))
}

pub(crate) fn target_ref_could_match(target_ref: &str, targets: &[String]) -> bool {
    if targets.is_empty() {
        return false;
    }
    for t in targets {
        if t == target_ref {
            return true;
        }
        if let Some(name) = t.strip_prefix("svc:") {
            if target_ref == name || target_ref == t {
                return true;
            }
        } else if let Some(id) = t.strip_prefix("session:") {
            if target_ref == id || target_ref == t {
                return true;
            }
        } else if let Some((_harness, name)) = t.split_once(':') {
            if target_ref == name || target_ref == t {
                return true;
            }
        }
    }
    false
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

#[derive(Debug, Clone, Default)]
pub struct PeersMap {
    peers_by_name: HashMap<String, PeerConfig>,
    name_by_pin: HashMap<String, String>,
    ca_bundles_by_name: HashMap<String, Vec<rustls::pki_types::TrustAnchor<'static>>>,
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
        self.ca_bundles_by_name.insert(peer.name.clone(), anchors);
        self.peers_by_name.insert(peer.name.clone(), peer);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&PeerConfig> {
        self.peers_by_name.get(name)
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

    pub fn contains_name(&self, name: &str) -> bool {
        self.peers_by_name.contains_key(name)
    }

    pub fn is_empty(&self) -> bool {
        self.peers_by_name.is_empty()
    }

    pub fn values(&self) -> impl Iterator<Item = &PeerConfig> {
        self.peers_by_name.values()
    }

    pub fn allowed_pins(&self) -> HashMap<String, String> {
        self.peers_by_name
            .values()
            .filter(|p| !p.allow.is_empty())
            .filter_map(|p| p.pin.as_ref().map(|pin| (pin.clone(), p.name.clone())))
            .collect()
    }

    pub fn load_from_json(json_str: &str) -> Result<Self, String> {
        let val: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse peers JSON: {e}"))?;

        let entries: Vec<(String, &serde_json::Map<String, serde_json::Value>)> = match &val {
            serde_json::Value::Object(map) => {
                if let Some(peers_val) = map.get("peers") {
                    let peers_obj = peers_val
                        .as_object()
                        .ok_or_else(|| "'peers' field must be an object".to_string())?;
                    peers_obj
                        .iter()
                        .map(|(k, v)| {
                            let obj = v
                                .as_object()
                                .ok_or_else(|| format!("peer entry for '{k}' must be an object"))?;
                            Ok((k.clone(), obj))
                        })
                        .collect::<Result<Vec<_>, String>>()?
                } else {
                    map.iter()
                        .map(|(k, v)| {
                            let obj = v
                                .as_object()
                                .ok_or_else(|| format!("peer entry for '{k}' must be an object"))?;
                            Ok((k.clone(), obj))
                        })
                        .collect::<Result<Vec<_>, String>>()?
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
                    Ok((name.to_string(), obj))
                })
                .collect::<Result<Vec<_>, String>>()?,
            _ => return Err("peers JSON must be an object or an array".to_string()),
        };

        let mut map = Self::empty();
        for (key_name, obj) in entries {
            let name = obj
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or(&key_name)
                .to_string();

            if map.contains_name(&name) {
                return Err(format!("duplicate peer name '{name}'"));
            }

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
                    | "leaf" | "principals" | "targets" => {}
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
                .ok_or_else(|| format!("peer '{name}' missing required field 'address'"))?
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

            let principals: Vec<String> = if let Some(pr) = obj.get("principals") {
                let arr = pr
                    .as_array()
                    .ok_or_else(|| format!("peer '{name}': 'principals' must be an array"))?;
                arr.iter()
                    .map(|v| {
                        let s = v
                            .as_str()
                            .ok_or_else(|| format!("peer '{name}': 'principals' elements must be strings"))?;
                        let valid = s.starts_with("claude:")
                            || s.starts_with("agy:")
                            || s.starts_with("pi:")
                            || s.starts_with("svc:")
                            || s.starts_with("anon:")
                            || s.starts_with("session:");
                        if !valid {
                            return Err(format!(
                                "principal filter entry '{s}' must be kind-qualified (e.g. claude:<name>, svc:<name>, anon:<from>, session:<id>)"
                            ));
                        }
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
                    let valid = s.starts_with("claude:")
                        || s.starts_with("agy:")
                        || s.starts_with("pi:")
                        || s.starts_with("svc:")
                        || s.starts_with("session:");
                    if !valid {
                        return Err(format!(
                            "target filter entry '{s}' must be kind-qualified (e.g. svc:<name>, claude:<name>, session:<id>)"
                        ));
                    }
                    target_list.push(s.to_string());
                }
                Some(target_list)
            } else {
                None
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
            };
            if let Some(anchors) = ca_anchors {
                map.insert_with_anchors(peer_config, anchors)?;
            } else {
                map.insert(peer_config)?;
            }
        }
        Ok(map)
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read peers file {}: {e}", path.display()))?;
        Self::load_from_json(&content)
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

        let uris = extract_uri_sans(leaf.as_ref()).unwrap_or_default();
        let mut ca_matches: Vec<(&PeerConfig, String)> = Vec::new();

        if uris.len() == 1 {
            let uri = &uris[0];
            let now = UnixTime::now();
            for peer in self.ca_peers().into_iter().filter(|p| !p.allow.is_empty()) {
                if let Some(ref identities) = peer.identities {
                    if uri_matches_any_identity(uri, identities) {
                        if let Some(anchors) = self.get_ca_anchors(&peer.name) {
                            if verify_cert_chain(
                                leaf,
                                intermediates,
                                anchors,
                                now,
                                webpki::KeyUsage::client_auth(),
                            )
                            .is_ok()
                            {
                                ca_matches.push((peer, uri.clone()));
                            }
                        }
                    }
                }
            }
        }

        if let Some(pin_peer) = any_pin_match {
            if !ca_matches.is_empty() {
                tracing::warn!(
                    "Presented certificate matches both pinned peer '{}' and CA peer(s); refusing (fail closed)",
                    pin_peer.name
                );
                return Err(AppError::PeerRejected(format!(
                    "client certificate matches both pinned peer '{}' and CA peer(s); refusing (fail closed)",
                    pin_peer.name
                )));
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

        Err(AppError::PeerRejected(
            "client certificate did not match any allowed pin or CA peer".to_string(),
        ))
    }
}

pub fn load_peers_file(path: &Path) -> Result<PeersMap, String> {
    PeersMap::load_from_file(path)
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
}

impl PinnedServerCertVerifier {
    pub fn new(expected_pin: &str) -> Self {
        Self {
            expected_pin: normalize_pin(expected_pin),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let pin = spki_sha256_from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let norm_pin = normalize_pin(&pin);
        if norm_pin == self.expected_pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
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

        let uris = extract_uri_sans(end_entity.as_ref()).unwrap_or_default();
        let mut ca_matches: Vec<&PeerConfig> = Vec::new();

        if uris.len() == 1 {
            let uri = &uris[0];
            for peer in self
                .peers
                .ca_peers()
                .into_iter()
                .filter(|p| !p.allow.is_empty())
            {
                if let Some(ref identities) = peer.identities {
                    if uri_matches_any_identity(uri, identities) {
                        if let Some(anchors) = self.peers.get_ca_anchors(&peer.name) {
                            if verify_cert_chain(
                                end_entity,
                                intermediates,
                                anchors,
                                now,
                                webpki::KeyUsage::client_auth(),
                            )
                            .is_ok()
                            {
                                ca_matches.push(peer);
                            }
                        }
                    }
                }
            }
        }

        // Silent overlap: refuse if both pin and CA match (including outbound-only pinned peers)
        if let Some(pin_peer) = any_pin_match {
            if !ca_matches.is_empty() {
                tracing::warn!(
                    "Presented certificate matches both pinned peer '{}' and CA peer(s); refusing (fail closed)",
                    pin_peer.name
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

#[derive(Debug)]
pub struct CaServerCertVerifier {
    anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
    allowed_identities: Vec<String>,
}

impl CaServerCertVerifier {
    pub fn new(
        anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
        allowed_identities: Vec<String>,
    ) -> Self {
        Self {
            anchors,
            allowed_identities,
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedEnvelope {
    pub v: u32,
    pub id: String,
    pub principal: FedPrincipal,
    pub to: FedTarget,
    pub body: String,
    pub push_replies: bool,
    pub thread_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum FedPrincipal {
    #[serde(rename = "session")]
    Session {
        harness: String,
        session_id: String,
        name: String,
    },
    #[serde(rename = "service")]
    Service { name: String },
    #[serde(rename = "anonymous")]
    Anonymous { from: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedTarget {
    pub r#ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedReplyEnvelope {
    pub v: u32,
    pub id: String,
    pub in_reply_to: String,
    pub replier: FedReplier,
    pub text: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedReplier {
    pub harness: String,
    pub session_id: String,
    pub name: String,
}

// -----------------------------------------------------------------------------
// Authenticated Peer Context
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub name: String,
    pub pin: String,
    pub uri: Option<String>,
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
    pub host_label: String,
    pub peers: Arc<PeersMap>,
    pub cert_der: Vec<u8>,
    pub cert_chain_der: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
    pub rate_limiter: Arc<RateLimiter>,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub sessions_dir: PathBuf,
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
        .route("/fed/v1/messages", post(fed_send_message_handler))
        .route("/fed/v1/replies", post(fed_reply_handler))
        .route(
            "/fed/v1/messages/{id}/replies",
            get(fed_get_replies_handler),
        )
        .layer(DefaultBodyLimit::max(max_body_limit))
        .with_state(fed_state)
}

async fn fed_send_message_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Json(envelope): Json<FedEnvelope>,
) -> Result<Response, AppError> {
    if envelope.v != 1 {
        return Err(AppError::BadRequest(format!(
            "unsupported protocol version {}",
            envelope.v
        )));
    }

    // 1. Check peer config and allow list
    let peer_cfg = fed_state
        .peers
        .get(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    if !peer_cfg.allow.iter().any(|op| op == "send") {
        return Err(AppError::OpDenied(
            "send operation not allowed for peer".to_string(),
        ));
    }

    if !peer_cfg.principals.is_empty() {
        let authorized = match &envelope.principal {
            FedPrincipal::Session {
                harness,
                name,
                session_id,
            } => {
                let badge = format!("{harness}:{name}");
                let sess_badge = format!("session:{session_id}");
                let harness_sess = format!("{harness}:{session_id}");
                peer_cfg
                    .principals
                    .iter()
                    .any(|p| p == &badge || p == &sess_badge || p == &harness_sess)
            }
            FedPrincipal::Service { name } => {
                let badge = format!("svc:{name}");
                peer_cfg.principals.iter().any(|p| p == &badge)
            }
            FedPrincipal::Anonymous { from } => {
                let badge = format!("anon:{from}");
                peer_cfg.principals.iter().any(|p| p == &badge)
            }
        };
        if !authorized {
            return Err(AppError::OpDenied(
                "principal not authorized for peer".to_string(),
            ));
        }
    }

    // 2. Validate to.ref: forwarding is forbidden
    let target_ref = &envelope.to.r#ref;
    if target_ref.contains('@') {
        return Err(AppError::NoForward(
            "Forwarding cross-host is not permitted".to_string(),
        ));
    }

    let target = match resolve_target_session_fed(&fed_state, target_ref) {
        Ok(t) => {
            if let Some(ref allowed_targets) = peer_cfg.targets {
                if !target_matches_allowlist(&t, allowed_targets) {
                    return Err(AppError::OpDenied(
                        "target not allowed for peer".to_string(),
                    ));
                }
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
            let principal_key = match &envelope.principal {
                FedPrincipal::Session {
                    harness,
                    session_id,
                    ..
                } => Some(format!("{harness}:{session_id}")),
                FedPrincipal::Service { name } => Some(format!("svc:{name}")),
                FedPrincipal::Anonymous { from } => Some(format!("anon:{from}")),
            };
            if !fed_state
                .rate_limiter
                .check_and_consume(&peer.name, principal_key.as_deref())
            {
                return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
            }

            let (from_name, return_harness, return_session_id) = match &envelope.principal {
                FedPrincipal::Session {
                    harness,
                    session_id,
                    name,
                } => {
                    if !matches!(harness.as_str(), "claude" | "agy" | "pi" | "svc") {
                        return Err(AppError::BadRequest(format!("invalid harness '{harness}'")));
                    }
                    let sanitized = inbox::sanitize_attested_from(&peer.name, harness, name);
                    (sanitized, Some(harness.clone()), Some(session_id.clone()))
                }
                FedPrincipal::Service { name } => {
                    let re = regex::Regex::new(r"^[A-Za-z0-9._-]{1,32}$").unwrap();
                    if !re.is_match(name) {
                        return Err(AppError::BadRequest(format!(
                            "invalid service name '{name}'"
                        )));
                    }
                    let badge = format!("xmsg@{} · svc:{}", peer.name, name);
                    (badge, Some("svc".to_string()), Some(name.clone()))
                }
                FedPrincipal::Anonymous { from } => {
                    let sanitized = inbox::sanitize_from(&peer.name, from)?;
                    (sanitized, None, None)
                }
            };
            let push_replies = if peer_cfg.leaf {
                false
            } else {
                envelope.push_replies
            };
            let body_len = envelope.body.len();
            let outcome_str = match &err {
                AppError::NotFound(_) => "not_found",
                AppError::Ambiguous(_) => "ambiguous",
                AppError::Gone { .. } => "gone",
                _ => "failed",
            };
            let pre_record = MessageRecord {
                id: envelope.id.clone(),
                created_at: envelope.created_at,
                session_id: target_ref.clone(),
                from_name,
                bytes: body_len,
                outcome: outcome_str.to_string(),
                recipient_harness: "claude".to_string(),
                return_harness,
                return_session_id,
                return_host: Some(peer.name.clone()),
                push_replies,
                thread_id: envelope.thread_id.clone(),
            };
            if let Ok(db) = fed_state.db.lock() {
                let _ = storage::insert_message(&db, &pre_record);
            }
            return Err(err);
        }
    };

    // 4. Rate limiting: consume rate limit for authorized, resolved target
    let principal_key = match &envelope.principal {
        FedPrincipal::Session {
            harness,
            session_id,
            ..
        } => Some(format!("{harness}:{session_id}")),
        FedPrincipal::Service { name } => Some(format!("svc:{name}")),
        FedPrincipal::Anonymous { from } => Some(format!("anon:{from}")),
    };
    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, principal_key.as_deref())
    {
        return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
    }

    // 5. Validate principal and sanitize badge
    let (from_name, return_harness, return_session_id) = match &envelope.principal {
        FedPrincipal::Session {
            harness,
            session_id,
            name,
        } => {
            if !matches!(harness.as_str(), "claude" | "agy" | "pi" | "svc") {
                return Err(AppError::BadRequest(format!("invalid harness '{harness}'")));
            }
            let sanitized = inbox::sanitize_attested_from(&peer.name, harness, name);
            (sanitized, Some(harness.clone()), Some(session_id.clone()))
        }
        FedPrincipal::Service { name } => {
            let re = regex::Regex::new(r"^[A-Za-z0-9._-]{1,32}$").unwrap();
            if !re.is_match(name) {
                return Err(AppError::BadRequest(format!(
                    "invalid service name '{name}'"
                )));
            }
            let badge = format!("xmsg@{} · svc:{}", peer.name, name);
            (badge, Some("svc".to_string()), Some(name.clone()))
        }
        FedPrincipal::Anonymous { from } => {
            let sanitized = inbox::sanitize_from(&peer.name, from)?;
            (sanitized, None, None)
        }
    };

    // 6. Idempotent delivery: check if id already recorded
    let body_len = envelope.body.len();
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(existing) = storage::get_message(&db, &envelope.id)
            .map_err(|e| AppError::Internal(e.to_string()))?
        {
            // Already delivered or processed! Return stored outcome without writing to inbox again
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

    let push_replies = if peer_cfg.leaf {
        false
    } else {
        envelope.push_replies
    };

    let (target_session_id, recipient_harness) = match &target {
        crate::http::ResolvedTarget::Claude(s, _) => (s.session_id.clone(), "claude".to_string()),
        crate::http::ResolvedTarget::Agy(s) => (s.session_id.clone(), "agy".to_string()),
        crate::http::ResolvedTarget::Pi(s) => (s.session_id.clone(), "pi".to_string()),
        crate::http::ResolvedTarget::Svc(s) => (s.session_id.clone(), "svc".to_string()),
    };

    // Pre-record message as accepted before inbox delivery
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
        push_replies,
        thread_id: envelope.thread_id.clone(),
    };
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::insert_message(&db, &pre_record).map_err(|e| AppError::Internal(e.to_string()))?;
    }

    // 8. Deliver to local target session
    let deliver_res = match target {
        crate::http::ResolvedTarget::Claude(session, socket_path) => {
            let body_with_footer = format!(
                "{}\n\n[xmsg] message_id={} — reply with the xmsg reply tool",
                envelope.body, envelope.id
            );
            match inbox::encode_transport_line(&from_name, &body_with_footer) {
                Ok(line) => inbox::deliver_to_socket(&socket_path, &line)
                    .await
                    .map(|_| (session.session_id, "claude".to_string(), "delivered")),
                Err(e) => Err(e),
            }
        }
        crate::http::ResolvedTarget::Agy(session) => {
            let has_creds = {
                let store_lock = fed_state.agy_store.read().unwrap();
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
            };

            if has_creds {
                crate::agy::deliver_agy(
                    &fed_state.agy_config,
                    &fed_state.agy_store,
                    &session,
                    &from_name,
                    &envelope.id,
                    &envelope.body,
                )
                .await
                .map(|_| (session.session_id, "agy".to_string(), "delivered"))
            } else {
                let envelope_text = format!(
                    "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                    from_name, envelope.id, envelope.body
                );
                let agy_msg = storage::AgyPendingMessage {
                    id: envelope.id.clone(),
                    session_id: session.session_id.clone(),
                    created_at: storage::now_epoch_secs(),
                    from_name: from_name.clone(),
                    bytes: body_len,
                    text: envelope.body.clone(),
                    envelope: envelope_text,
                    delivered_at: None,
                };
                let db = fed_state
                    .db
                    .lock()
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                storage::insert_agy_message(&db, &agy_msg)
                    .map_err(|e| AppError::Internal(e.to_string()))?;
                Ok((session.session_id, "agy".to_string(), "queued"))
            }
        }
        crate::http::ResolvedTarget::Pi(session) => {
            let envelope_text = format!(
                "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                from_name, envelope.id, envelope.body
            );
            let pi_msg = storage::PiPendingMessage {
                id: envelope.id.clone(),
                session_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                from_name: from_name.clone(),
                bytes: body_len,
                text: envelope.body.clone(),
                envelope: envelope_text,
                delivered_at: None,
            };
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let inserted = storage::insert_pi_message(&db, &pi_msg)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            if !inserted {
                return Err(AppError::ServiceUnavailable(
                    "pi session message queue is full".to_string(),
                ));
            }
            let _ = fed_state.pi_notify_tx.send(session.session_id.clone());
            Ok((session.session_id, "pi".to_string(), "delivered"))
        }
        crate::http::ResolvedTarget::Svc(session) => {
            let envelope_text = format!(
                "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                from_name, envelope.id, envelope.body
            );
            let svc_msg = storage::SvcPendingMessage {
                id: envelope.id.clone(),
                session_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                from_name: from_name.clone(),
                bytes: body_len,
                text: envelope.body.clone(),
                envelope: envelope_text,
                delivered_at: None,
                origin: storage::SvcOrigin::Fed {
                    host: peer.name.clone(),
                },
            };
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let inserted = storage::insert_svc_message(&db, &svc_msg)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            if !inserted {
                return Err(AppError::ServiceUnavailable(
                    "svc session message queue is full".to_string(),
                ));
            }
            let _ = fed_state.svc_notify_tx.send(session.session_id.clone());
            Ok((session.session_id, "svc".to_string(), "delivered"))
        }
    };

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

async fn fed_reply_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Json(reply): Json<FedReplyEnvelope>,
) -> Result<Response, AppError> {
    if reply.v != 1 {
        return Err(AppError::BadRequest(format!(
            "unsupported protocol version {}",
            reply.v
        )));
    }

    // 1. Check peer config and allow list
    let peer_cfg = fed_state
        .peers
        .get(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    if !peer_cfg.allow.iter().any(|op| op == "reply") {
        return Err(AppError::OpDenied(
            "reply operation not allowed for peer".to_string(),
        ));
    }

    // Rate limiting: consume peer and principal buckets
    let principal_key = Some(format!(
        "{}:{}",
        reply.replier.harness, reply.replier.session_id
    ));
    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, principal_key.as_deref())
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

    // 2. Authorization: in_reply_to MUST exist in outbound table AND peer must match!
    let outbound = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_outbound(&db, &reply.in_reply_to)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    let _outbound = match outbound {
        Some(o) if o.peer == peer.name => o,
        _ => {
            return Err(AppError::NotRecipient(format!(
                "in_reply_to '{}' not authorized for peer '{}'",
                reply.in_reply_to, peer.name
            )));
        }
    };

    // 4. Look up original message to get caller session
    let orig_msg = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_message(&db, &reply.in_reply_to)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    let orig_msg = match orig_msg {
        Some(m)
            if m.return_harness.is_some() && m.return_session_id.is_some() && m.push_replies =>
        {
            m
        }
        _ => {
            return Err(AppError::NotRecipient(format!(
                "in_reply_to '{}' has no push-capable local recipient",
                reply.in_reply_to
            )));
        }
    };

    let ret_harness = orig_msg.return_harness.unwrap();
    let ret_session_id = orig_msg.return_session_id.unwrap();

    if !matches!(ret_harness.as_str(), "claude" | "agy" | "pi") {
        return Err(AppError::NotRecipient(format!(
            "unknown recipient harness '{ret_harness}'"
        )));
    }

    // Pre-record reply in replies table before delivering to local socket
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::insert_reply(
            &db,
            &reply.in_reply_to,
            &ret_session_id,
            &reply.text,
            Some("accepted"),
            Some(&reply.id),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    // 5. Deliver pushed reply to local session
    let replier_badge =
        inbox::sanitize_attested_from(&peer.name, &reply.replier.harness, &reply.replier.name);
    let push_res = match ret_harness.as_str() {
        "claude" => {
            match crate::registry::resolve_session(&fed_state.sessions_dir, &ret_session_id) {
                Ok((_session, socket_path)) => {
                    if !socket_path.exists() {
                        "sender_gone"
                    } else {
                        let body_with_header = format!(
                            "[xmsg] reply to message_id={} — message_id={}; reply with the xmsg reply tool\n\n{}",
                            reply.in_reply_to, reply.id, reply.text
                        );
                        match inbox::encode_transport_line(&replier_badge, &body_with_header) {
                            Ok(line) => match inbox::deliver_to_socket(&socket_path, &line).await {
                                Ok(()) => "pushed",
                                Err(_) => "push_failed",
                            },
                            Err(_) => "push_failed",
                        }
                    }
                }
                Err(_) => "sender_gone",
            }
        }
        "agy" => {
            let session_opt = crate::agy::resolve_agy_session(
                &fed_state.agy_config,
                &fed_state.agy_store,
                &ret_session_id,
            )
            .ok()
            .flatten();
            if let Some(session) = session_opt {
                let envelope = format!(
                    "[xmsg] reply to message_id={} — message_id={}; reply with the xmsg reply tool\n\n{}",
                    reply.in_reply_to, reply.id, reply.text
                );
                match crate::agy::deliver_agy_envelope(
                    &fed_state.agy_config,
                    &fed_state.agy_store,
                    &session,
                    &replier_badge,
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
            } else {
                "sender_gone"
            }
        }
        "pi" => {
            let session_opt = crate::pi::resolve_pi_session(
                &fed_state.agy_config.proc_root,
                &fed_state.pi_store,
                &ret_session_id,
            )
            .ok()
            .flatten();
            if let Some(session) = session_opt {
                let envelope_text = format!(
                    "[xmsg] reply to message_id={} from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                    reply.in_reply_to, replier_badge, reply.id, reply.text
                );
                let pi_msg = storage::PiPendingMessage {
                    id: reply.id.clone(),
                    session_id: session.session_id.clone(),
                    created_at: storage::now_epoch_secs(),
                    from_name: replier_badge.clone(),
                    bytes: reply.text.len(),
                    text: reply.text.clone(),
                    envelope: envelope_text,
                    delivered_at: None,
                };
                if let Ok(db) = fed_state.db.lock() {
                    let _ = storage::insert_pi_message(&db, &pi_msg);
                    let _ = fed_state.pi_notify_tx.send(session.session_id.clone());
                    "pushed"
                } else {
                    "push_failed"
                }
            } else {
                "sender_gone"
            }
        }
        "svc" => {
            let session_opt = crate::svc::resolve_svc_session(
                &fed_state.agy_config.proc_root,
                &fed_state.svc_store,
                &ret_session_id,
            )
            .ok()
            .flatten();
            if let Some(session) = session_opt {
                let envelope_text = format!(
                    "[xmsg] reply to message_id={} from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                    reply.in_reply_to, replier_badge, reply.id, reply.text
                );
                let svc_msg = storage::SvcPendingMessage {
                    id: reply.id.clone(),
                    session_id: session.session_id.clone(),
                    created_at: storage::now_epoch_secs(),
                    from_name: replier_badge.clone(),
                    bytes: reply.text.len(),
                    text: reply.text.clone(),
                    envelope: envelope_text,
                    delivered_at: None,
                    origin: storage::SvcOrigin::Fed {
                        host: peer.name.clone(),
                    },
                };
                if let Ok(db) = fed_state.db.lock() {
                    let inserted = storage::insert_svc_message(&db, &svc_msg).unwrap_or(false);
                    if inserted {
                        let _ = fed_state.svc_notify_tx.send(session.session_id.clone());
                        "pushed"
                    } else {
                        "push_failed"
                    }
                } else {
                    "push_failed"
                }
            } else {
                "sender_gone"
            }
        }
        _ => {
            return Err(AppError::NotRecipient(format!(
                "unknown recipient harness '{ret_harness}'"
            )))
        }
    };

    // 6. Update reply outcome in replies table and notify subscribers
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let _ = storage::update_reply_push_outcome(&db, &reply.id, push_res);
    }
    let _ = fed_state.notify_tx.send(reply.in_reply_to.clone());

    Ok((
        StatusCode::OK,
        Json(json!({
            "push_outcome": push_res,
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
        .get(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    // Check rate limiter
    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, Some(&format!("poll:{}", peer.name)))
    {
        return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
    }

    let msg = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_message(&db, &id)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("message '{id}'")))?
    };

    if msg.return_host.as_deref() != Some(&peer.name) {
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

fn resolve_target_session_fed(
    fed_state: &FedState,
    ref_str: &str,
) -> Result<crate::http::ResolvedTarget, AppError> {
    let claude_ref = ref_str
        .strip_prefix("claude:")
        .or_else(|| ref_str.strip_prefix("session:"))
        .unwrap_or(ref_str);
    match crate::registry::resolve_session(&fed_state.sessions_dir, claude_ref) {
        Ok((session, socket_path)) => Ok(crate::http::ResolvedTarget::Claude(session, socket_path)),
        Err(AppError::Gone { session_id, pid }) => Err(AppError::Gone { session_id, pid }),
        Err(AppError::Ambiguous(ids)) => Err(AppError::Ambiguous(ids)),
        Err(AppError::NotFound(_)) => {
            let agy_ref = ref_str.strip_prefix("agy:").unwrap_or(ref_str);
            match crate::agy::resolve_agy_session(
                &fed_state.agy_config,
                &fed_state.agy_store,
                agy_ref,
            )? {
                Some(session) => Ok(crate::http::ResolvedTarget::Agy(session)),
                None => {
                    let pi_ref = ref_str.strip_prefix("pi:").unwrap_or(ref_str);
                    match crate::pi::resolve_pi_session(
                        &fed_state.agy_config.proc_root,
                        &fed_state.pi_store,
                        pi_ref,
                    )? {
                        Some(session) => Ok(crate::http::ResolvedTarget::Pi(session)),
                        None => {
                            match crate::svc::resolve_svc_session(
                                &fed_state.agy_config.proc_root,
                                &fed_state.svc_store,
                                ref_str,
                            )? {
                                Some(session) => Ok(crate::http::ResolvedTarget::Svc(session)),
                                None => Err(AppError::NotFound(ref_str.to_string())),
                            }
                        }
                    }
                }
            }
        }
        Err(err) => Err(err),
    }
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

    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        if let Some(ref pin) = peer.pin {
            Arc::new(PinnedServerCertVerifier::new(pin))
        } else if let Some(anchors) = fed_state.get_ca_anchors(&peer.name) {
            let identities = peer.identities.clone().unwrap_or_default();
            Arc::new(CaServerCertVerifier::new(anchors, identities))
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
        if matches!(rustls_err, rustls::Error::InvalidCertificate(_)) {
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
    let peer = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;

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
        let req = hyper::Request::builder()
            .method("POST")
            .uri("/fed/v1/messages")
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
            let delivery_resp: DeliveryResponse = serde_json::from_slice(&body_bytes)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(delivery_resp)
        } else {
            let err_resp: Result<WireErrorResponse, _> = serde_json::from_slice(&body_bytes);
            if let Ok(err) = err_resp {
                match status {
                    StatusCode::NOT_FOUND => Err(AppError::NotFound(err.detail)),
                    StatusCode::CONFLICT => Err(AppError::Ambiguous(err.detail)),
                    StatusCode::GONE => Err(AppError::Gone {
                        session_id: err.detail,
                        pid: 0,
                    }),
                    StatusCode::FORBIDDEN => {
                        if err.error == "op_denied" {
                            Err(AppError::OpDenied(err.detail))
                        } else if err.error == "peer_rejected" {
                            Err(AppError::PeerRejected(err.detail))
                        } else {
                            Err(AppError::NotRecipient(err.detail))
                        }
                    }
                    StatusCode::BAD_REQUEST => {
                        if err.error == "no_forward" {
                            Err(AppError::NoForward(err.detail))
                        } else if err.error == "unknown_peer" {
                            Err(AppError::UnknownPeer(err.detail))
                        } else {
                            Err(AppError::BadRequest(err.detail))
                        }
                    }
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
            .uri("/fed/v1/replies")
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
                    StatusCode::NOT_FOUND => Err(AppError::NotFound(err.detail)),
                    StatusCode::CONFLICT => Err(AppError::Ambiguous(err.detail)),
                    StatusCode::GONE => Err(AppError::Gone {
                        session_id: err.detail,
                        pid: 0,
                    }),
                    StatusCode::FORBIDDEN => {
                        if err.error == "op_denied" {
                            Err(AppError::OpDenied(err.detail))
                        } else if err.error == "peer_rejected" {
                            Err(AppError::PeerRejected(err.detail))
                        } else {
                            Err(AppError::NotRecipient(err.detail))
                        }
                    }
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
            format!("/fed/v1/messages/{message_id}/replies?after={after_seq}&wait={wait_secs}");
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
                    StatusCode::NOT_FOUND => Err(AppError::NotFound(err.detail)),
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

pub fn parse_fed_principal(s: &str) -> Result<FedPrincipal, AppError> {
    let s = s.trim();
    if let Some(name) = s.strip_prefix("svc:") {
        let re = regex::Regex::new(r"^[A-Za-z0-9._-]{1,32}$").unwrap();
        if !re.is_match(name) {
            return Err(AppError::BadRequest(format!(
                "invalid service name '{name}'"
            )));
        }
        Ok(FedPrincipal::Service {
            name: name.to_string(),
        })
    } else if let Some(rest) = s.strip_prefix("claude:") {
        Ok(FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: rest.to_string(),
            name: rest.to_string(),
        })
    } else if let Some(rest) = s.strip_prefix("agy:") {
        Ok(FedPrincipal::Session {
            harness: "agy".to_string(),
            session_id: rest.to_string(),
            name: rest.to_string(),
        })
    } else if let Some(rest) = s.strip_prefix("pi:") {
        Ok(FedPrincipal::Session {
            harness: "pi".to_string(),
            session_id: rest.to_string(),
            name: rest.to_string(),
        })
    } else if let Some(from) = s.strip_prefix("anon:") {
        Ok(FedPrincipal::Anonymous {
            from: from.to_string(),
        })
    } else {
        let re = regex::Regex::new(r"^[A-Za-z0-9._-]{1,32}$").unwrap();
        if !re.is_match(s) {
            return Err(AppError::BadRequest(format!("invalid principal '{s}'")));
        }
        Ok(FedPrincipal::Service {
            name: s.to_string(),
        })
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
    pub ca_paths: HashMap<String, PathBuf>,
    pub file_hashes: Mutex<HashMap<PathBuf, Vec<u8>>>,
    pub dynamic_tls: Arc<std::sync::RwLock<Option<DynamicTls>>>,
    pub peers: Arc<PeersMap>,
}

impl CredentialReloader {
    pub fn new(
        cert_path: PathBuf,
        key_path: PathBuf,
        peers: Arc<PeersMap>,
        dynamic_tls: Arc<std::sync::RwLock<Option<DynamicTls>>>,
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
            ca_paths,
            file_hashes: Mutex::new(HashMap::new()),
            dynamic_tls,
            peers,
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

        for (peer_name, ca_path) in &self.ca_paths {
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

        match self.build_tls_config() {
            Ok(new_dyn_tls) => {
                *self.dynamic_tls.write().unwrap() = Some(new_dyn_tls);
                *self.file_hashes.lock().unwrap() = current_hashes;
                tracing::info!("successfully reloaded federation TLS credentials and CA bundles");
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

    fn build_tls_config(&self) -> Result<DynamicTls, AppError> {
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
        let mut new_peers = (*self.peers).clone();

        for (peer_name, ca_path) in &self.ca_paths {
            let ca_pem = std::fs::read(ca_path).map_err(|e| {
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
            new_peers.update_ca_anchors(peer_name, anchors.clone());
            ca_anchors.insert(peer_name.clone(), anchors);
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
