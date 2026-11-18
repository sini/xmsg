#![cfg(feature = "daemon")]

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::CertificateDer;
use serde_json::json;
use xmsg::fed::{AdmissionMode, DenyPolicy, LeafAuthority, PeersMap};

fn leaf(uris: &[&str]) -> CertificateDer<'static> {
    let mut params = CertificateParams::default();
    params.subject_alt_names = uris
        .iter()
        .map(|uri| SanType::URI((*uri).try_into().unwrap()))
        .collect();
    params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap()
        .der()
        .clone()
}

#[test]
fn deny_matches_all_literal_sans_and_exact_spki() {
    let cert = leaf(&[
        "spiffe://example.invalid/first",
        "spiffe://example.invalid/second",
    ]);
    let authority = LeafAuthority::from_certificate(&cert, AdmissionMode::Pin).unwrap();
    let mut peers = PeersMap::default();
    peers.deny.uris = vec![authority.uris[1].clone()];
    assert!(
        authority.check_at(&peers, 0).is_err(),
        "secondary URI SAN must deny pinned leaf"
    );
    peers.deny.uris[0].push('/');
    assert!(authority.check_at(&peers, 0).is_ok(), "URI match is exact");
    peers.deny.spkis = vec![authority.pin.clone()];
    assert!(
        authority.check_at(&peers, 0).is_err(),
        "pin cannot override global deny"
    );
}

#[test]
fn only_ca_mode_expires_at_actual_leaf_deadline() {
    let cert = leaf(&["spiffe://example.invalid/host/device/user/person"]);
    let ca = LeafAuthority::from_certificate(&cert, AdmissionMode::Ca).unwrap();
    let peers = PeersMap::default();
    assert!(ca.check_at(&peers, ca.not_after - 1).is_ok());
    assert!(
        ca.check_at(&peers, ca.not_after).is_err(),
        "CA expires at actual leaf boundary"
    );
    let pin = LeafAuthority::from_certificate(&cert, AdmissionMode::Pin).unwrap();
    assert!(
        pin.check_at(&peers, ca.not_after + 1).is_ok(),
        "explicit pin intentionally ignores expiry"
    );
}

#[test]
fn denied_leaf_never_mutates_admitted_roster() {
    let cert = leaf(&["spiffe://example.invalid/host/device/user/person"]);
    let authority = LeafAuthority::from_certificate(&cert, AdmissionMode::Pin).unwrap();
    let mut peers = PeersMap::default();
    peers.deny.spkis = vec![authority.pin];
    let error = peers.resolve_incoming_peer(&cert, &[]).unwrap_err();
    assert!(
        error.to_string().contains("denied"),
        "deny precedes all admission lookup"
    );
    assert!(peers.admitted_clients.read().unwrap().is_empty());
}

#[test]
fn malformed_deny_is_rejected_and_empty_deny_is_compatible() {
    for deny in [
        json!({"spkis":["A".repeat(64)]}),
        json!({"spkis":["a".repeat(63)]}),
        json!({"uris":[""]}),
        json!({"unexpected":[]}),
        json!({"uris":"wrong"}),
    ] {
        assert!(PeersMap::load_from_json(&json!({"peers":{}, "deny":deny}).to_string()).is_err());
    }
    assert!(PeersMap::load_from_json(r#"{"peers":{},"deny":{}}"#).is_ok());
    assert!(PeersMap::load_from_json(r#"{"peers":{}}"#).is_ok());
}

#[test]
fn uri_deny_covers_a_renewed_key_without_denied_sibling() {
    let uri = "spiffe://example.invalid/host/device/user/person";
    let old = LeafAuthority::from_certificate(&leaf(&[uri]), AdmissionMode::Ca).unwrap();
    let renewed = LeafAuthority::from_certificate(&leaf(&[uri]), AdmissionMode::Ca).unwrap();
    assert_ne!(old.pin, renewed.pin);
    let mut peers = PeersMap::default();
    peers.deny = DenyPolicy {
        uris: vec![uri.into()],
        spkis: vec![],
    };
    assert!(old.check_at(&peers, 0).is_err());
    assert!(renewed.check_at(&peers, 0).is_err());
    let sibling = LeafAuthority::from_certificate(
        &leaf(&["spiffe://example.invalid/host/device/user/other"]),
        AdmissionMode::Ca,
    )
    .unwrap();
    assert!(sibling.check_at(&peers, 0).is_ok());
}
