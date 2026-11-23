use super::*;

const ISSUER: DeviceId = [1; 32];
const PEER: DeviceId = [2; 32];
const NOW: i64 = 1_800_000_000;

fn exposure(profile: PairingProfile) -> ExposurePolicy {
    ExposurePolicy {
        profile,
        target_selectors: vec!["inbox".into()],
        principal_selectors: vec!["alice".into()],
        max_body_bytes: 1024,
        max_attachment_bytes: 4096,
        rate_burst: 10,
        rate_per_minute: 60,
    }
}

fn manual(id: u8, profile: PairingProfile, not_after: Option<i64>) -> Grant {
    Grant {
        grant_id: [id; 16],
        issuer: ISSUER,
        subject: PEER,
        not_after,
        active: true,
        authority: Authority::Manual {
            profile,
            exposure: exposure(profile),
            evidence: ManualEvidence {
                transaction_id: [9; 32],
                exporter: [8; 32],
                receipt_local: vec![1],
                receipt_remote: vec![2],
                ceremony_created: NOW - 100,
                ceremony_expires: NOW - 10,
                activated_at: NOW - 50,
            },
        },
    }
}

fn pin_hex(id: &DeviceId) -> String {
    hex::encode(id)
}

fn config(entry: serde_json::Value) -> PeersMap {
    PeersMap::load_from_json(&serde_json::json!({ "laptop": entry }).to_string()).unwrap()
}

fn legacy_entry() -> serde_json::Value {
    serde_json::json!({
        "address": "192.0.2.9:7788",
        "pin": format!("sha256:{}", pin_hex(&PEER)),
        "allow": ["send", "list"],
        "targets": ["inbox"],
        "principals": ["alice"],
    })
}

fn legacy(config: &PeersMap) -> Grant {
    Grant {
        grant_id: [7; 16],
        issuer: ISSUER,
        subject: PEER,
        not_after: None,
        active: true,
        authority: Authority::Legacy {
            predicates: LegacyPredicates::from_peer(config.get("laptop").unwrap()),
        },
    }
}

struct World {
    blocked: HashSet<DeviceId>,
    removed: HashSet<GrantId>,
    config: PeersMap,
}

impl World {
    fn new() -> Self {
        Self {
            blocked: HashSet::new(),
            removed: HashSet::new(),
            config: PeersMap::empty(),
        }
    }

    fn ctx(&self) -> Context<'_> {
        Context {
            now: NOW,
            blocked: &self.blocked,
            removed: &self.removed,
            config: &self.config,
        }
    }
}

fn to(target: &'static str) -> Resource<'static> {
    Resource {
        target: Some(target),
        principal: Some("alice"),
        body_bytes: 10,
        attachment_bytes: 0,
    }
}

fn list() -> Resource<'static> {
    Resource {
        target: None,
        principal: Some("alice"),
        ..Default::default()
    }
}

#[test]
fn p5_expired_owner_scope_with_fresh_contact_provenance_cannot_list() {
    let world = World::new();
    let ctx = world.ctx();
    let expired_owner = manual(1, PairingProfile::OwnerDevice, Some(NOW - 1));
    let fresh_contact = manual(2, PairingProfile::Contact, None);
    let grants = [expired_owner.clone(), fresh_contact.clone()];
    assert!(
        authorize(
            &grants,
            &ISSUER,
            &PEER,
            Operation::SessionList,
            &list(),
            &ctx
        )
        .is_none(),
        "list was authorized by mixing an expired owner scope with a fresh contact grant"
    );
    for g in &grants {
        assert!(!eligible(
            g,
            &ISSUER,
            &PEER,
            Operation::SessionList,
            &list(),
            &ctx
        ));
    }
    let valid_owner = manual(3, PairingProfile::OwnerDevice, Some(NOW + 60));
    let grants = [expired_owner, fresh_contact, valid_owner];
    let chosen = authorize(
        &grants,
        &ISSUER,
        &PEER,
        Operation::SessionList,
        &list(),
        &ctx,
    )
    .expect("an independent valid owner grant must authorize list");
    assert_eq!(chosen.grant_id, [3; 16]);
}

#[test]
fn one_grant_must_supply_both_target_and_principal() {
    // Each grant covers half the request; neither alone covers it.
    let mut targets_only = manual(1, PairingProfile::Contact, None);
    let mut principals_only = manual(2, PairingProfile::Contact, None);
    if let Authority::Manual { exposure, .. } = &mut targets_only.authority {
        exposure.principal_selectors = vec!["bob".into()];
    }
    if let Authority::Manual { exposure, .. } = &mut principals_only.authority {
        exposure.target_selectors = vec!["other".into()];
    }
    let world = World::new();
    let grants = [targets_only, principals_only];
    assert!(
        authorize(
            &grants,
            &ISSUER,
            &PEER,
            Operation::Send,
            &to("inbox"),
            &world.ctx()
        )
        .is_none(),
        "two partial grants combined into one permission"
    );
}

#[test]
fn block_dominates_manual_and_legacy_grants() {
    let mut world = World::new();
    world.config = config(legacy_entry());
    let grants = [
        manual(1, PairingProfile::OwnerDevice, None),
        legacy(&world.config),
    ];
    for op in [Operation::Send, Operation::SessionList] {
        let resource = if op == Operation::Send {
            to("inbox")
        } else {
            list()
        };
        assert!(authorize(&grants, &ISSUER, &PEER, op, &resource, &world.ctx()).is_some());
    }
    world.blocked.insert(PEER);
    for op in [Operation::Send, Operation::Reply, Operation::SessionList] {
        assert!(
            authorize(&grants, &ISSUER, &PEER, op, &to("inbox"), &world.ctx()).is_none(),
            "a blocked device kept {op:?}"
        );
    }
}

#[test]
fn removed_or_inactive_grant_never_authorizes() {
    let mut world = World::new();
    let mut g = manual(1, PairingProfile::Contact, None);
    assert!(eligible(
        &g,
        &ISSUER,
        &PEER,
        Operation::Send,
        &to("inbox"),
        &world.ctx()
    ));
    world.removed.insert(g.grant_id);
    assert!(!eligible(
        &g,
        &ISSUER,
        &PEER,
        Operation::Send,
        &to("inbox"),
        &world.ctx()
    ));
    world.removed.clear();
    g.active = false;
    assert!(!eligible(
        &g,
        &ISSUER,
        &PEER,
        Operation::Send,
        &to("inbox"),
        &world.ctx()
    ));
}

#[test]
fn p8_operation_table_per_profile() {
    let world = World::new();
    let ctx = world.ctx();
    let contact = manual(1, PairingProfile::Contact, None);
    let owner = manual(2, PairingProfile::OwnerDevice, None);
    let cases = [
        (Operation::Send, true, true),
        (Operation::Reply, true, true),
        (Operation::SessionList, false, true),
        (Operation::Forward, false, false),
        (Operation::Relayed, false, false),
        (Operation::Observe, false, false),
        (Operation::Handoff, false, false),
    ];
    for (op, for_contact, for_owner) in cases {
        let resource = if op == Operation::SessionList {
            list()
        } else {
            to("inbox")
        };
        assert_eq!(
            eligible(&contact, &ISSUER, &PEER, op, &resource, &ctx),
            for_contact,
            "contact {op:?}"
        );
        assert_eq!(
            eligible(&owner, &ISSUER, &PEER, op, &resource, &ctx),
            for_owner,
            "owner-device {op:?}"
        );
    }
}

#[test]
fn exposure_constrains_targets_principals_and_sizes() {
    let world = World::new();
    let ctx = world.ctx();
    let g = manual(1, PairingProfile::Contact, None);
    let ok = |r: Resource<'_>| eligible(&g, &ISSUER, &PEER, Operation::Send, &r, &ctx);
    assert!(ok(to("inbox")));
    assert!(!ok(to("elsewhere")), "unlisted target");
    assert!(!ok(Resource {
        principal: Some("mallory"),
        ..to("inbox")
    }));
    assert!(!ok(Resource {
        principal: None,
        ..to("inbox")
    }));
    assert!(!ok(Resource {
        body_bytes: 1025,
        ..to("inbox")
    }));
    assert!(!ok(Resource {
        attachment_bytes: 4097,
        ..to("inbox")
    }));
    let mut empty = g.clone();
    if let Authority::Manual { exposure, .. } = &mut empty.authority {
        exposure.target_selectors.clear();
    }
    assert!(
        !eligible(&empty, &ISSUER, &PEER, Operation::Send, &to("inbox"), &ctx),
        "an empty target set granted data"
    );
}

#[test]
fn issuer_subject_and_manual_evidence_bind_the_grant() {
    let world = World::new();
    let ctx = world.ctx();
    let g = manual(1, PairingProfile::Contact, None);
    assert!(!eligible(
        &g,
        &[3; 32],
        &PEER,
        Operation::Send,
        &to("inbox"),
        &ctx
    ));
    assert!(!eligible(
        &g,
        &ISSUER,
        &[3; 32],
        Operation::Send,
        &to("inbox"),
        &ctx
    ));
    let mut one_receipt = g.clone();
    if let Authority::Manual { evidence, .. } = &mut one_receipt.authority {
        evidence.receipt_remote.clear();
    }
    assert!(
        !eligible(
            &one_receipt,
            &ISSUER,
            &PEER,
            Operation::Send,
            &to("inbox"),
            &ctx
        ),
        "one receipt activated a grant"
    );
    let mut late = g;
    if let Authority::Manual { evidence, .. } = &mut late.authority {
        evidence.activated_at = evidence.ceremony_expires + 1;
    }
    assert!(!eligible(
        &late,
        &ISSUER,
        &PEER,
        Operation::Send,
        &to("inbox"),
        &ctx
    ));
}

#[test]
fn p11_legacy_view_preserves_the_config_predicates_exactly() {
    let mut world = World::new();
    world.config = config(legacy_entry());
    let peer = world.config.get("laptop").unwrap().clone();
    let g = legacy(&world.config);
    let Authority::Legacy { predicates } = &g.authority else {
        unreachable!()
    };
    assert_eq!(predicates.allow, peer.allow);
    assert_eq!(predicates.targets, peer.targets);
    assert_eq!(predicates.principals, peer.principals);
    assert_eq!(predicates.from, peer.from);
    assert_eq!(predicates.leaf, peer.leaf);
    assert_eq!(g.provenance(), PROVENANCE_LEGACY);
    let ctx = world.ctx();
    for (op, right) in [
        (Operation::Send, "send"),
        (Operation::Reply, "reply"),
        (Operation::SessionList, "list"),
        (Operation::Forward, "forward"),
        (Operation::Observe, "observe"),
    ] {
        for target in ["inbox", "other"] {
            for principal in ["alice", "bob"] {
                let resource = Resource {
                    target: Some(target),
                    principal: Some(principal),
                    ..Default::default()
                };
                let fed_rs = peer.allow.iter().any(|r| r == right)
                    && peer.principals.iter().any(|p| p == principal)
                    && crate::fed::target_ref_could_match(target, peer.targets.as_ref().unwrap());
                assert_eq!(
                    eligible(&g, &ISSUER, &PEER, op, &resource, &ctx),
                    fed_rs,
                    "{op:?} to {target} from {principal}"
                );
            }
        }
    }
    assert!(
        !eligible(&g, &ISSUER, &PEER, Operation::Handoff, &to("inbox"), &ctx),
        "a legacy pin gained handoff from a grant"
    );
}

#[test]
fn legacy_provenance_needs_the_current_explicit_record() {
    let mut world = World::new();
    world.config = config(legacy_entry());
    let g = legacy(&world.config);
    assert!(eligible(
        &g,
        &ISSUER,
        &PEER,
        Operation::Send,
        &to("inbox"),
        &world.ctx()
    ));
    let mut widened = legacy_entry();
    widened["allow"] = serde_json::json!(["send", "list", "observe"]);
    world.config = config(widened);
    assert!(
        !eligible(
            &g,
            &ISSUER,
            &PEER,
            Operation::Send,
            &to("inbox"),
            &world.ctx()
        ),
        "a legacy grant outlived a change to its configuration record"
    );
    world.config = PeersMap::empty();
    assert!(!eligible(
        &g,
        &ISSUER,
        &PEER,
        Operation::Send,
        &to("inbox"),
        &world.ctx()
    ));
}

#[test]
fn config_deny_names_the_same_device_id() {
    let map = PeersMap::load_from_json(
        &serde_json::json!({"peers": {}, "deny": {"spkis": [pin_hex(&PEER)]}}).to_string(),
    )
    .unwrap();
    assert_eq!(config_blocks(&map).collect::<Vec<_>>(), [PEER]);
    assert_eq!(
        device_id_from_pin(&format!("SHA256:{}", pin_hex(&PEER).to_uppercase())),
        Some(PEER)
    );
    assert_eq!(device_id_from_pin("sha256:00"), None);
}
