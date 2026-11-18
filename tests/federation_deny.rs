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

struct CertificateAuthority {
    params: CertificateParams,
    key: KeyPair,
    ca_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}
impl CertificateAuthority {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        std::fs::write(&ca_path, params.self_signed(&key).unwrap().pem()).unwrap();
        Self {
            params,
            key,
            ca_path,
            _dir: dir,
        }
    }
    fn leaf(&self, uris: &[&str]) -> CertificateDer<'static> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI((*uri).try_into().unwrap()))
            .collect();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params
            .signed_by(
                &KeyPair::generate().unwrap(),
                &rcgen::Issuer::from_params(&self.params, &self.key),
            )
            .unwrap()
            .der()
            .clone()
    }
    fn hub(&self, deny: serde_json::Value) -> PeersMap {
        let pattern = "spiffe://deny.invalid/host/*/user/*";
        PeersMap::load_from_json(&json!({"peers":{},"deny":deny,"hub":{"patterns":[{"pattern":pattern,"ca":self.ca_path}],"rules":[{"pattern":pattern,"allow":["send","list"],"leaf":true}]}}).to_string()).unwrap()
    }
}

#[test]
fn hub_pattern_deny_precedes_verifier_and_roster_but_allows_sibling() {
    use rustls::server::danger::ClientCertVerifier;
    let ca = CertificateAuthority::new();
    let denied = ca.leaf(&["spiffe://deny.invalid/host/laptop/user/person"]);
    let sibling = ca.leaf(&["spiffe://deny.invalid/host/desktop/user/person"]);
    let pin = xmsg::fed::spki_sha256_from_der(denied.as_ref()).unwrap();
    let peers = std::sync::Arc::new(ca.hub(json!({"spkis":[pin]})));
    let verifier = xmsg::fed::CombinedClientCertVerifier::new(peers.clone());
    assert!(
        verifier
            .verify_client_cert(&denied, &[], rustls::pki_types::UnixTime::now())
            .is_err(),
        "denied hub-pattern leaf must fail TLS verifier"
    );
    let resolution = peers.resolve_incoming_peer(&denied, &[]);
    assert!(
        resolution.is_err(),
        "denied hub-pattern leaf must fail before roster mutation"
    );
    assert!(resolution.unwrap_err().to_string().contains("denied"));
    assert!(peers.admitted_clients.read().unwrap().is_empty());
    verifier
        .verify_client_cert(&sibling, &[], rustls::pki_types::UnixTime::now())
        .expect("non-denied pattern sibling remains TLS-admitted");
    peers
        .resolve_incoming_peer(&sibling, &[])
        .expect("non-denied pattern sibling remains resolver-admitted");
    assert_eq!(peers.admitted_clients.read().unwrap().len(), 1);
}

#[test]
fn exact_uri_denies_renewed_key_in_pattern_and_concrete_ca_paths() {
    use rustls::server::danger::ClientCertVerifier;
    let ca = CertificateAuthority::new();
    let uri = "spiffe://deny.invalid/host/laptop/user/person";
    let old = ca.leaf(&[uri]);
    let renewed = ca.leaf(&[uri]);
    assert_ne!(
        xmsg::fed::spki_sha256_from_der(old.as_ref()).unwrap(),
        xmsg::fed::spki_sha256_from_der(renewed.as_ref()).unwrap()
    );
    for peers in [ca.hub(json!({"uris":[uri]})),PeersMap::load_from_json(&json!({"peers":{"person.laptop":{"address":"127.0.0.1:1","ca":ca.ca_path,"identities":[uri],"allow":["send"]}},"deny":{"uris":[uri]}}).to_string()).unwrap()] {
        let peers=std::sync::Arc::new(peers);
        let verifier=xmsg::fed::CombinedClientCertVerifier::new(peers.clone());
        for cert in [&old,&renewed] {
            assert!(verifier.verify_client_cert(cert,&[],rustls::pki_types::UnixTime::now()).is_err(),"exact URI deny must survive renewal at the TLS verifier");
            assert!(peers.resolve_incoming_peer(cert,&[]).unwrap_err().to_string().contains("denied"),"exact URI deny must survive renewal before resolving or caching");
        }
        assert!(peers.admitted_clients.read().unwrap().is_empty());
    }
}

#[test]
fn explicit_pin_deny_and_allowed_multiple_sans_apply_to_both_tls_directions() {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::server::danger::ClientCertVerifier;
    let cert = leaf(&[
        "urn:ordinary:pinned",
        "spiffe://deny.invalid/host/laptop/user/person",
    ]);
    let pin = xmsg::fed::spki_sha256_from_der(cert.as_ref()).unwrap();
    let config = |deny| {
        std::sync::Arc::new(
            PeersMap::load_from_json(
                &json!({"peers":{"device":{"address":"127.0.0.1:1","pin":pin,"allow":["send"]}},"deny":deny}).to_string(),
            )
            .unwrap(),
        )
    };
    for deny in [
        json!({}),
        json!({"spkis":[pin]}),
        json!({"uris":["spiffe://deny.invalid/host/laptop/user/person"]}),
    ] {
        let blocked = deny != json!({});
        let peers = config(deny);
        let incoming = xmsg::fed::CombinedClientCertVerifier::new(peers.clone());
        assert_eq!(incoming.verify_client_cert(&cert,&[],rustls::pki_types::UnixTime::now()).is_err(),blocked,"pin-mode inbound TLS must honor all-SAN/SPKI deny and otherwise preserve multi-SAN compatibility");
        let outgoing =
            xmsg::fed::PinnedServerCertVerifier::new(&pin).refusing_ca("device", peers.clone());
        assert_eq!(outgoing.verify_server_cert(&cert,&[],&rustls::pki_types::ServerName::try_from("localhost").unwrap(),&[],rustls::pki_types::UnixTime::now()).is_err(),blocked,"pin-mode outbound TLS must honor all-SAN/SPKI deny and otherwise preserve multi-SAN compatibility");
        assert_eq!(
            peers.resolve_incoming_peer(&cert, &[]).is_err(),
            blocked,
            "explicit pin resolution must honor global deny"
        );
    }
}

#[test]
fn ca_server_verifier_denies_actual_uri_and_spki_before_chain_acceptance() {
    use rustls::client::danger::ServerCertVerifier;
    let ca = CertificateAuthority::new();
    let uri = "spiffe://deny.invalid/host/laptop/user/person";
    let cert = ca.leaf(&[uri]);
    let pin = xmsg::fed::spki_sha256_from_der(cert.as_ref()).unwrap();
    let peers = PeersMap::load_from_json(
        &json!({"person.laptop":{"address":"127.0.0.1:1","ca":ca.ca_path,"identities":[uri],"allow":["send"]}}).to_string(),
    )
    .unwrap();
    for deny in [
        DenyPolicy::default(),
        DenyPolicy {
            uris: vec![uri.into()],
            spkis: vec![],
        },
        DenyPolicy {
            uris: vec![],
            spkis: vec![pin.clone()],
        },
    ] {
        let blocked = !deny.uris.is_empty() || !deny.spkis.is_empty();
        let verifier = xmsg::fed::CaServerCertVerifier::new(
            peers.get_ca_anchors("person.laptop").unwrap().to_vec(),
            vec![uri.into()],
        )
        .with_deny(deny);
        assert_eq!(
            verifier
                .verify_server_cert(
                    &cert,
                    &[],
                    &rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    &[],
                    rustls::pki_types::UnixTime::now()
                )
                .is_err(),
            blocked,
            "CA outbound verifier must apply deny to the actual leaf before accepting it"
        );
    }
}

#[test]
fn malformed_reload_retains_the_entire_previous_policy_and_hashes() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::default().self_signed(&key).unwrap();
    let cert_path = dir.path().join("node.pem");
    let key_path = dir.path().join("key.pem");
    let peers_path = dir.path().join("peers.json");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let original = json!({"peers":{"device":{"address":"127.0.0.1:1","pin":"a".repeat(64),"allow":["send"]}},"deny":{"spkis":["b".repeat(64)]}});
    std::fs::write(&peers_path, original.to_string()).unwrap();
    let peers = std::sync::Arc::new(PeersMap::load_from_file(&peers_path).unwrap());
    let reloader = xmsg::fed::CredentialReloader::new_full(
        cert_path,
        key_path,
        Some(peers_path.clone()),
        None,
        peers,
        None,
        Default::default(),
    )
    .unwrap();
    let retained = reloader.peers.lock().unwrap().clone();
    let hashes = reloader.file_hashes.lock().unwrap().clone();
    for denied in [
        json!({"spkis":["UPPERCASE"]}),
        json!({"unknown":[]}),
        json!({"uris":"wrong-type"}),
    ] {
        let mut invalid = original.clone();
        invalid["peers"]["device"]["allow"] = json!(["reply"]);
        invalid["deny"] = denied;
        std::fs::write(&peers_path, invalid.to_string()).unwrap();
        assert!(
            reloader.force_reload().is_err(),
            "malformed deny must reject whole publication"
        );
        let current = reloader.peers.lock().unwrap().clone();
        assert!(
            std::sync::Arc::ptr_eq(&retained, &current),
            "failed reload must retain the exact previous policy"
        );
        assert_eq!(current.get("device").unwrap().allow, vec!["send"]);
        assert_eq!(current.deny.spkis, vec!["b".repeat(64)]);
        assert_eq!(
            *reloader.file_hashes.lock().unwrap(),
            hashes,
            "failed reload cannot publish new source hashes"
        );
    }
}
