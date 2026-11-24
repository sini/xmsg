use xmsg::fed::{OwnNode, PeersMap};

fn own(name: &str) -> OwnNode {
    OwnNode {
        name: name.to_owned(),
        pin: None,
    }
}

fn load_golden(raw: &str, self_name: &str, ca_path: &str) -> Result<PeersMap, String> {
    let before: serde_json::Value = serde_json::from_str(raw).expect("valid golden json");
    let patched = raw
        .replace("/etc/xmsg/ca/root.crt", ca_path)
        .replace("/etc/xmsg/tls/ca.crt", ca_path);
    let after: serde_json::Value = serde_json::from_str(&patched).expect("valid patched json");
    let before_map = before.as_object().expect("top-level object");
    let after_map = after.as_object().expect("patched top-level object");
    assert_eq!(before_map.len(), after_map.len());
    for (peer_name, bv) in before_map {
        let mut bo = bv.as_object().expect("peer object").clone();
        let mut ao = after_map[peer_name].as_object().expect("peer object").clone();
        bo.remove("ca");
        ao.remove("ca");
        assert_eq!(bo, ao, "CA rewrite touched non-ca key on {peer_name}");
    }
    PeersMap::load_from_json_for(&patched, Some(&own(self_name)))
}

fn assert_golden_invariants(label: &str, raw: &str, map: &PeersMap, expect_leaf: Option<&str>, expect_forward: Option<&str>, expect_relayed: Option<&str>) {
    let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
    for peer_name in parsed.as_object().unwrap().keys() {
        let entry = map.get(peer_name).expect("peer present in loaded map");
        assert_eq!(
            entry.leaf,
            expect_leaf == Some(peer_name.as_str()),
            "{label}: unexpected leaf={} on {peer_name}",
            entry.leaf
        );
        assert_eq!(
            entry.allow.iter().any(|op| op == "forward"),
            expect_forward == Some(peer_name.as_str()),
            "{label}: unexpected forward on {peer_name}: {:?}",
            entry.allow
        );
        assert_eq!(
            entry.allow.iter().any(|op| op == "relayed"),
            expect_relayed == Some(peer_name.as_str()),
            "{label}: unexpected relayed on {peer_name}: {:?}",
            entry.allow
        );
    }
}

#[test]
fn fleet_goldens_load_through_production_peer_map_loader() {
    let dir = tempfile::tempdir().unwrap();
    let ca_file = dir.path().join("ca.crt");
    let mut params = rcgen::CertificateParams::new(vec!["fleet-ca.invalid".to_owned()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(&ca_file, cert.pem()).unwrap();
    let ca = ca_file.to_str().unwrap();

    let hub_raw = include_str!("vectors/fleet/alice.hub.json");
    let hub = load_golden(hub_raw, "alice.hub", ca).expect("alice.hub.json must load");
    assert_golden_invariants("alice.hub", hub_raw, &hub, Some("gateway.mcp"), Some("gateway.mcp"), None);
    assert_eq!(hub.default_route_peer(), None);
    let gw = hub.get("gateway.mcp").expect("gateway.mcp entry");
    assert!(gw.leaf);
    assert_eq!(gw.targets, None);
    assert_eq!(gw.allow, vec!["send", "reply", "list", "forward"]);
    assert_eq!(
        hub.get("alice.collector").expect("collector").allow,
        vec!["observe"]
    );
    assert_eq!(
        hub.get("bob.desk").expect("bob.desk").from,
        Some(vec!["192.0.2.0/24".to_owned()])
    );

    let laptop_raw = include_str!("vectors/fleet/alice.laptop.json");
    let laptop = load_golden(laptop_raw, "alice.laptop", ca).expect("alice.laptop.json must load");
    assert_golden_invariants("alice.laptop", laptop_raw, &laptop, None, None, Some("alice.hub"));
    assert_eq!(
        laptop.get("alice.hub").expect("alice.hub").allow,
        vec!["send", "reply", "list", "relayed"]
    );

    let desk_raw = include_str!("vectors/fleet/bob.desk.json");
    let desk = load_golden(desk_raw, "bob.desk", ca).expect("bob.desk.json must load");
    assert_golden_invariants("bob.desk", desk_raw, &desk, None, None, None);
    let desk_laptop = desk.get("alice.laptop").expect("alice.laptop");
    assert_eq!(desk_laptop.allow, vec!["send", "reply"]);
    assert_eq!(desk_laptop.targets, Some(vec!["inbox".to_owned()]));
    assert_eq!(desk_laptop.principals, vec!["ci".to_owned()]);

    let gw_raw = include_str!("vectors/fleet/gateway.mcp.json");
    let gateway = load_golden(gw_raw, "gateway.mcp", ca).expect("gateway.mcp.json must load");
    assert_golden_invariants("gateway.mcp", gw_raw, &gateway, None, None, None);
    assert_eq!(gateway.default_route_peer(), Some("alice.hub"));
    assert_eq!(
        gateway.get("alice.hub").expect("alice.hub").address,
        "10.0.0.2:7788"
    );

    let nothing_raw = include_str!("vectors/fleet/nothing-granted.json");
    let nothing = load_golden(nothing_raw, "alice.hub", ca).expect("nothing-granted.json must load");
    assert_golden_invariants("nothing-granted", nothing_raw, &nothing, None, None, None);
    let carol = nothing.get("carol.x").expect("carol.x");
    assert!(carol.allow.is_empty());
    assert_eq!(carol.targets, Some(vec![]));
    assert!(carol.principals.is_empty());

    // Production loader admission check: key/identity mismatch must be refused.
    let bad_identity = include_str!("vectors/fleet/bob.desk.json").replace(
        "spiffe://example.org/host/hub/user/alice",
        "spiffe://example.org/host/other/user/alice",
    );
    let err = load_golden(&bad_identity, "bob.desk", ca)
        .expect_err("key/identity mismatch must be refused by production loader");
    assert!(err.contains("keyed by its node name"), "unexpected error: {err}");
}
