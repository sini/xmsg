use xmsg::fed::{OwnNode, PeersMap};

fn own(name: &str) -> OwnNode {
    OwnNode {
        name: name.to_owned(),
        pin: None,
    }
}

fn load_golden(raw: &str, self_name: &str, ca_path: &str) -> Result<PeersMap, String> {
    let patched = raw.replace("/etc/xmsg/tls/ca.crt", ca_path);
    PeersMap::load_from_json_for(&patched, Some(&own(self_name)))
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

    let hub = load_golden(
        include_str!("vectors/fleet/alice.hub.json"),
        "alice.hub",
        ca,
    )
    .expect("alice.hub.json must load");
    assert_eq!(hub.default_route_peer(), None);
    let gw = hub.get("gateway.mcp").expect("gateway.mcp entry");
    assert!(gw.leaf);
    assert_eq!(gw.allow, vec!["send", "reply", "list", "forward"]);
    assert_eq!(
        hub.get("alice.collector").expect("collector").allow,
        vec!["observe"]
    );
    assert_eq!(
        hub.get("bob.desk").expect("bob.desk").from,
        Some(vec!["192.0.2.0/24".to_owned()])
    );

    let laptop = load_golden(
        include_str!("vectors/fleet/alice.laptop.json"),
        "alice.laptop",
        ca,
    )
    .expect("alice.laptop.json must load");
    assert_eq!(
        laptop.get("alice.hub").expect("alice.hub").allow,
        vec!["send", "reply", "list", "relayed"]
    );

    let desk = load_golden(
        include_str!("vectors/fleet/bob.desk.json"),
        "bob.desk",
        ca,
    )
    .expect("bob.desk.json must load");
    let desk_laptop = desk.get("alice.laptop").expect("alice.laptop");
    assert_eq!(desk_laptop.allow, vec!["send", "reply"]);
    assert_eq!(desk_laptop.targets, Some(vec!["inbox".to_owned()]));
    assert_eq!(desk_laptop.principals, vec!["ci".to_owned()]);

    let gateway = load_golden(
        include_str!("vectors/fleet/gateway.mcp.json"),
        "gateway.mcp",
        ca,
    )
    .expect("gateway.mcp.json must load");
    assert_eq!(gateway.default_route_peer(), Some("alice.hub"));
    assert_eq!(
        gateway.get("alice.hub").expect("alice.hub").address,
        "10.0.0.2:7788"
    );

    let nothing = load_golden(
        include_str!("vectors/fleet/nothing-granted.json"),
        "alice.hub",
        ca,
    )
    .expect("nothing-granted.json must load");
    let carol = nothing.get("carol.x").expect("carol.x");
    assert!(carol.allow.is_empty());
    assert_eq!(carol.targets, Some(vec![]));

    // Production loader admission check: key/identity mismatch must be refused.
    let bad_identity = include_str!("vectors/fleet/bob.desk.json").replace(
        "spiffe://example.org/host/hub/user/alice",
        "spiffe://example.org/host/other/user/alice",
    );
    let err = load_golden(&bad_identity, "bob.desk", ca)
        .expect_err("key/identity mismatch must be refused by production loader");
    assert!(err.contains("keyed by its node name"), "unexpected error: {err}");
}
