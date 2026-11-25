//! One-grant authorization: a single grant supplies both an operation's scope and its own
//! valid provenance. Scope and provenance live in one [`Authority`] value, so a grant cannot
//! borrow either from another record, and [`authorize`] never unions grants.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::codec::{ExposurePolicy, PairingProfile};
use crate::fed::{PeerConfig, PeersMap};

/// SHA-256 over a device's DER SPKI: the `xmsg-spki1:` ID and a legacy `pin` name the same bytes.
pub type DeviceId = [u8; 32];
pub type GrantId = [u8; 16];

pub const PROVENANCE_MANUAL: &str = "manual_authenticated_oob";
pub const PROVENANCE_LEGACY: &str = "legacy_unilateral";

/// An operation a remote device asks of this node. A derivative operation (reply poll,
/// attachment range, leaf inbox and ACK) is authorized as the operation it derives from, on the
/// same grant. Local enrollment, administration and policy changes are not operations: no
/// pairing grant can permit them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Send,
    Reply,
    SessionList,
    Forward,
    Relayed,
    Observe,
    Handoff,
}

/// What the operation touches. `target` is the requested `to.ref` (none for a list query);
/// `principal` is the sender's filter key (service name, instance ID or `anon:<from>`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Resource<'a> {
    pub target: Option<&'a str>,
    pub principal: Option<&'a str>,
    pub body_bytes: u64,
    pub attachment_bytes: u64,
}

/// A pinned entry's predicates, preserved exactly as the peers file states them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyPredicates {
    pub rule: String,
    pub allow: Vec<String>,
    pub targets: Option<Vec<String>>,
    pub principals: Vec<String>,
    pub from: Option<Vec<String>>,
    pub leaf: bool,
    pub observe_labels: bool,
}

impl LegacyPredicates {
    pub fn from_peer(peer: &PeerConfig) -> Self {
        Self {
            rule: peer.name.clone(),
            allow: peer.allow.clone(),
            targets: peer.targets.clone(),
            principals: peer.principals.clone(),
            from: peer.from.clone(),
            leaf: peer.leaf,
            observe_labels: peer.observe_labels,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("predicates serialize")
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_json().as_bytes()).into()
    }

    fn has(&self, rights: &[&str]) -> bool {
        self.allow
            .iter()
            .any(|right| rights.contains(&right.as_str()))
    }

    fn principal_admitted(&self, resource: &Resource<'_>) -> bool {
        self.principals.is_empty()
            || resource
                .principal
                .is_some_and(|p| self.principals.iter().any(|allowed| allowed == p))
    }

    fn target_admitted(&self, resource: &Resource<'_>) -> bool {
        match (&self.targets, resource.target) {
            (None, _) | (Some(_), None) => true,
            (Some(targets), Some(target)) => crate::fed::target_ref_could_match(target, targets),
        }
    }

    /// The decision the federation handlers make for this entry today. Source CIDRs (`from`)
    /// are an admission check of their own and stay there.
    pub fn allows(&self, op: Operation, resource: &Resource<'_>) -> bool {
        match op {
            // receive_federated_message: `send`, then `principals`, then this entry's `targets`.
            Operation::Send => {
                self.has(&["send"])
                    && self.principal_admitted(resource)
                    && self.target_admitted(resource)
            }
            // A relayed message is a send that also needs `relayed` (or `relay`).
            Operation::Relayed => {
                self.has(&["send"])
                    && self.has(&["relayed", "relay"])
                    && self.principal_admitted(resource)
                    && self.target_admitted(resource)
            }
            // A hub forwards a send that also needs `forward`; the destination's own `targets`
            // apply, not the sender's.
            Operation::Forward => {
                self.has(&["send"]) && self.has(&["forward"]) && self.principal_admitted(resource)
            }
            Operation::Reply => self.has(&["reply"]),
            Operation::SessionList => self.has(&["list"]),
            Operation::Observe => self.has(&["observe"]),
            // Handoff has no `allow` right: its legacy conditions stay where they are.
            Operation::Handoff => false,
        }
    }
}

/// The durable evidence of a manual ceremony: both original receipt bytes and their binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualEvidence {
    pub transaction_id: [u8; 32],
    pub exporter: [u8; 32],
    pub receipt_local: Vec<u8>,
    pub receipt_remote: Vec<u8>,
    pub ceremony_created: i64,
    pub ceremony_expires: i64,
    pub activated_at: i64,
}

/// A grant's scope together with its provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authority {
    /// An immutable v1 profile, constrained by the exact stored exposure preimage.
    Manual {
        profile: PairingProfile,
        exposure: ExposurePolicy,
        evidence: ManualEvidence,
    },
    /// An imported pin, valid only while the peers file still holds this exact record.
    Legacy { predicates: LegacyPredicates },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub grant_id: GrantId,
    pub issuer: DeviceId,
    pub subject: DeviceId,
    pub not_after: Option<i64>,
    pub active: bool,
    pub authority: Authority,
}

impl Grant {
    pub fn provenance(&self) -> &'static str {
        match self.authority {
            Authority::Manual { .. } => PROVENANCE_MANUAL,
            Authority::Legacy { .. } => PROVENANCE_LEGACY,
        }
    }
}

/// The current state an authorization is evaluated against.
pub struct Context<'a> {
    pub now: i64,
    /// Durable device blocks together with the peers file's `deny.spkis`.
    pub blocked: &'a HashSet<DeviceId>,
    /// Every removed grant ID.
    pub removed: &'a HashSet<GrantId>,
    /// The current peers file, which a legacy grant's provenance must still match.
    pub config: &'a PeersMap,
}

/// Parses a legacy `pin` (hex SHA-256 over the DER SPKI, any accepted prefix) to its device ID.
pub fn device_id_from_pin(pin: &str) -> Option<DeviceId> {
    let bytes = hex::decode(crate::fed::normalize_pin(pin)).ok()?;
    bytes.try_into().ok()
}

/// The device IDs the peers file's `deny.spkis` names.
pub fn config_blocks(config: &PeersMap) -> impl Iterator<Item = DeviceId> + '_ {
    config
        .deny
        .spkis
        .iter()
        .filter_map(|pin| device_id_from_pin(pin))
}

fn provenance_valid(g: &Grant, ctx: &Context<'_>) -> bool {
    match &g.authority {
        Authority::Manual { evidence, .. } => {
            !evidence.receipt_local.is_empty()
                && !evidence.receipt_remote.is_empty()
                && evidence.ceremony_created <= evidence.activated_at
                && evidence.activated_at <= evidence.ceremony_expires
        }
        Authority::Legacy { predicates } => ctx.config.get(&predicates.rule).is_some_and(|peer| {
            peer.name == predicates.rule
                && peer.pin.as_deref().and_then(device_id_from_pin) == Some(g.subject)
                && LegacyPredicates::from_peer(peer) == *predicates
        }),
    }
}

fn scope_allows(g: &Grant, op: Operation, resource: &Resource<'_>) -> bool {
    match &g.authority {
        Authority::Manual {
            profile, exposure, ..
        } => {
            let protocol_right = match op {
                Operation::Send | Operation::Reply => true,
                Operation::SessionList => *profile == PairingProfile::OwnerDevice,
                Operation::Forward
                | Operation::Relayed
                | Operation::Observe
                | Operation::Handoff => false,
            };
            // shortcut: selectors match exactly; spec Q2 (exposure defaults/selector grammar) may widen this.
            protocol_right
                && exposure.profile == *profile
                && !exposure.target_selectors.is_empty()
                && resource
                    .target
                    .is_none_or(|t| exposure.target_selectors.iter().any(|s| s == "*" || s == t))
                && (op == Operation::SessionList
                    && resource.principal.is_none()
                    && exposure.principal_selectors.iter().any(|s| s == "*")
                    || resource.principal.is_some_and(|p| {
                        exposure
                            .principal_selectors
                            .iter()
                            .any(|s| s == "*" || s == p)
                    }))
                && resource.body_bytes <= u64::from(exposure.max_body_bytes)
                && resource.attachment_bytes <= u64::from(exposure.max_attachment_bytes)
        }
        Authority::Legacy { predicates } => predicates.allows(op, resource),
    }
}

/// `eligible(g, issuer, subject, op, resource, now)` of the spec, on one grant.
pub fn eligible(
    g: &Grant,
    issuer: &DeviceId,
    subject: &DeviceId,
    op: Operation,
    resource: &Resource<'_>,
    ctx: &Context<'_>,
) -> bool {
    g.issuer == *issuer
        && g.subject == *subject
        && g.active
        && !ctx.blocked.contains(subject)
        && !ctx.removed.contains(&g.grant_id)
        && g.not_after.is_none_or(|end| ctx.now < end)
        && provenance_valid(g, ctx)
        && scope_allows(g, op, resource)
}

/// The first grant that authorizes the operation on its own; grants are never combined.
pub fn authorize<'g>(
    grants: &'g [Grant],
    issuer: &DeviceId,
    subject: &DeviceId,
    op: Operation,
    resource: &Resource<'_>,
    ctx: &Context<'_>,
) -> Option<&'g Grant> {
    grants
        .iter()
        .find(|g| eligible(g, issuer, subject, op, resource, ctx))
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
