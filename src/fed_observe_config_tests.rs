use super::*;
use rcgen::{CertificateParams, Issuer, KeyPair};

const IDENTITY: &str = "spiffe://xmsg/host/collector/user/owner";
const BROAD: &str = "spiffe://xmsg/host/*/user/*";

struct Fixture {
    _dir: tempfile::TempDir,
    ca: PathBuf,
    cert: CertificateDer<'static>,
}

impl Fixture {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, params.self_signed(&key).unwrap().pem()).unwrap();
        let mut leaf = CertificateParams::default();
        leaf.subject_alt_names = vec![rcgen::SanType::URI(IDENTITY.try_into().unwrap())];
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = leaf
            .signed_by(
                &KeyPair::generate().unwrap(),
                &Issuer::from_params(&params, &key),
            )
            .unwrap()
            .der()
            .clone();
        Self {
            _dir: dir,
            ca,
            cert,
        }
    }

    fn hub(&self, rules: Value) -> Value {
        json!({"peers": {}, "hub": {
            "patterns": [{"pattern": BROAD, "ca": self.ca}], "rules": rules
        }})
    }

    fn concrete(&self, pinned: bool, allow: Value) -> Value {
        if pinned {
            json!({"collector": {"address": "127.0.0.1:1", "pin": spki_sha256_from_der(self.cert.as_ref()).unwrap(), "allow": allow}})
        } else {
            json!({"owner.collector": {"address": "127.0.0.1:1", "ca": self.ca, "identities": [IDENTITY], "allow": allow}})
        }
    }

    fn admit(&self, value: Value) -> PeerConfig {
        PeersMap::load_from_json(&value.to_string())
            .unwrap()
            .resolve_incoming_peer(&self.cert, &[])
            .unwrap()
            .0
    }
}

#[test]
fn literal_observe_hub_rule_loads_and_admits() {
    let fixture = Fixture::new();
    let value = fixture.hub(json!([{"pattern": IDENTITY, "allow": ["observe"]}]));
    let loaded = PeersMap::load_from_json(&value.to_string());
    assert!(
        loaded.is_ok(),
        "literal observe hub rule must load: {loaded:?}"
    );
    let (peer, _) = loaded
        .unwrap()
        .resolve_incoming_peer(&fixture.cert, &[])
        .unwrap();
    assert_eq!(
        peer.allow,
        ["observe"],
        "observe grant must survive hub admission"
    );
}

#[test]
fn explicit_concrete_pin_and_ca_grants_do_not_inherit_other_operations() {
    let fixture = Fixture::new();
    for pinned in [true, false] {
        let peer = fixture.admit(fixture.concrete(pinned, json!(["observe"])));
        assert_eq!(peer.allow, ["observe"]);
        let peer = fixture.admit(fixture.concrete(
            pinned,
            json!(["list", "send", "reply", "forward", "relayed", "*"]),
        ));
        assert!(
            !peer.allow.iter().any(|op| op == "observe"),
            "unrelated concrete rights must not imply observe"
        );
    }
}

#[test]
fn wildcard_observe_rules_are_refused_but_other_wildcard_rules_work() {
    let fixture = Fixture::new();
    for pattern in [
        BROAD,
        "spiffe://xmsg/host/collector/user/*",
        "spiffe://*/host/collector/user/owner",
    ] {
        let value = fixture.hub(json!([{"pattern": pattern, "allow": ["observe"]}]));
        assert!(
            PeersMap::load_from_json(&value.to_string()).is_err(),
            "wildcard observe rule must be refused: {pattern}"
        );
    }
    let peer = fixture.admit(fixture.hub(json!([{"pattern": BROAD, "allow": ["list", "send", "reply", "forward", "relayed"], "leaf": true}])));
    assert!(peer.leaf);
    assert_eq!(peer.allow, ["list", "send", "reply", "forward", "relayed"]);
    let peer = fixture.admit(fixture.hub(json!([])));
    assert!(
        peer.allow.is_empty(),
        "admission alone must not grant observe"
    );
}

#[test]
fn concrete_ca_wildcards_remain_invalid() {
    let fixture = Fixture::new();
    for identity in [
        "spiffe://xmsg/host/collector/user/*",
        "spiffe://xmsg/host/*/user/owner",
    ] {
        let mut value = fixture.concrete(false, json!(["observe"]));
        value["owner.collector"]["identities"] = json!([identity]);
        assert!(
            PeersMap::load_from_json(&value.to_string()).is_err(),
            "concrete wildcard identity must be refused"
        );
    }
    assert_eq!(
        fixture
            .admit(fixture.concrete(false, json!(["observe"])))
            .allow,
        ["observe"]
    );
}

#[test]
fn first_matching_rule_does_not_union_a_later_observe_grant() {
    let fixture = Fixture::new();
    let broad = json!({"pattern": BROAD, "allow": ["list"], "leaf": true});
    let exact = json!({"pattern": IDENTITY, "allow": ["observe"]});
    let peer = fixture.admit(fixture.hub(json!([broad, exact])));
    assert_eq!(
        peer.allow,
        ["list"],
        "first matching rule must not gain later observe authority"
    );
    assert!(peer.leaf);
    let peer = fixture.admit(fixture.hub(json!([exact, broad])));
    assert_eq!(
        peer.allow,
        ["observe"],
        "an earlier exact observer rule must grant observe"
    );
    assert!(!peer.leaf);
}

#[test]
fn labels_require_explicit_observe_even_when_false() {
    let fixture = Fixture::new();
    for labels in [false, true] {
        for pinned in [true, false] {
            let mut value = fixture.concrete(pinned, json!(["list"]));
            let name = if pinned {
                "collector"
            } else {
                "owner.collector"
            };
            value[name]["observe_labels"] = json!(labels);
            assert!(
                PeersMap::load_from_json(&value.to_string()).is_err(),
                "concrete labels field requires observe even when false"
            );
            value[name]["allow"] = json!(["observe"]);
            let peer = fixture.admit(value);
            assert_eq!(
                serde_json::to_value(peer)
                    .unwrap()
                    .get("observe_labels")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                labels
            );
        }
        let mut rule = json!({"pattern": IDENTITY, "allow": ["list"], "observe_labels": labels});
        assert!(
            PeersMap::load_from_json(&fixture.hub(json!([rule])).to_string()).is_err(),
            "hub labels field requires observe even when false"
        );
        rule["allow"] = json!(["observe"]);
        let peer = fixture.admit(fixture.hub(json!([rule])));
        assert_eq!(
            serde_json::to_value(peer)
                .unwrap()
                .get("observe_labels")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            labels,
            "hub label permission must survive admission"
        );
    }
}

#[test]
fn default_labels_omit_field_for_legacy_peer_roundtrip() {
    let fixture = Fixture::new();
    let peer = fixture.admit(fixture.concrete(true, json!(["list"])));
    let encoded = serde_json::to_value(peer).unwrap();
    assert!(
        encoded.get("observe_labels").is_none(),
        "default false labels must not serialize into legacy config"
    );
    assert!(PeersMap::load_from_json(&json!({"collector": encoded}).to_string()).is_ok());
}

#[test]
fn hub_target_omission_empty_and_explicit_scopes_survive_admission() {
    let fixture = Fixture::new();
    for (targets, expected) in [
        (None, None),
        (Some(json!([])), Some(vec![])),
        (
            Some(json!(["worker", "worker@owner.node"])),
            Some(vec!["worker".to_string(), "worker@owner.node".to_string()]),
        ),
    ] {
        let mut rule = json!({"pattern": IDENTITY, "allow": ["observe"]});
        if let Some(targets) = targets {
            rule["targets"] = targets;
        }
        let peer = fixture.admit(fixture.hub(json!([rule])));
        assert_eq!(
            peer.targets, expected,
            "hub target scope must survive admission exactly"
        );
    }
}

#[test]
fn new_fields_keep_unknown_and_type_validation_strict() {
    let fixture = Fixture::new();
    for (field, value) in [
        ("targets", Value::Null),
        ("targets", json!("worker")),
        ("targets", json!([3])),
        ("targets", json!([""])),
        ("targets", json!(["svc:worker"])),
        ("observe_labels", Value::Null),
        ("observe_labels", json!("false")),
        ("observe_labels", json!(0)),
        ("observe_label", json!(true)),
    ] {
        let mut rule = json!({"pattern": IDENTITY, "allow": ["observe"]});
        rule[field] = value.clone();
        assert!(
            PeersMap::load_from_json(&fixture.hub(json!([rule])).to_string()).is_err(),
            "hub field must be rejected: {field}={value}"
        );
        let mut peer = fixture.concrete(true, json!(["observe"]));
        peer["collector"][field] = value.clone();
        assert!(
            PeersMap::load_from_json(&peer.to_string()).is_err(),
            "concrete field must be rejected: {field}={value}"
        );
    }
    let value = fixture.hub(json!([{"pattern": IDENTITY, "allow": ["typo"]}]));
    assert!(
        PeersMap::load_from_json(&value.to_string()).is_err(),
        "unknown hub operation must remain invalid"
    );
}
