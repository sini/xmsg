use std::sync::{Arc, Barrier};
use std::time::Duration;

use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;
use crate::pairing::auth::PROVENANCE_MANUAL as PROVENANCE_MANUAL_OOB;
use crate::pairing::auth::{authorize, Context, Operation, Resource};
use crate::pairing::codec::{build_signed_receipt, Offer, SignerRole};

const NOW: i64 = 1_800_000_000;
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

struct Device {
    key: Ed25519KeyPair,
    spki: Vec<u8>,
    id: DeviceId,
}

impl Device {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut spki = SPKI_PREFIX.to_vec();
        spki.extend_from_slice(key.public_key().as_ref());
        let id = super::super::codec::SpkiDeviceId::from_spki_der(&spki)
            .unwrap()
            .0;
        Self { key, spki, id }
    }
}

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

fn request(peer: &Device, profile: PairingProfile) -> IntentRequest {
    IntentRequest {
        peer: peer.id,
        exposure: exposure(profile),
        grant_not_after: None,
        revision: 1,
        expires_at: NOW + 120,
        replaces: None,
    }
}

/// A ceremony between `us` (initiator) and `peer` whose local receipt carries `intent`'s bindings.
struct Ceremony<'a> {
    us: &'a Device,
    peer: &'a Device,
    grant_id: GrantId,
    profile: PairingProfile,
    exporter: [u8; 32],
}

impl Ceremony<'_> {
    fn receipts(&self) -> VerifiedReceipts {
        self.receipts_with(|_| {})
    }

    fn receipts_with(&self, edit: impl Fn(&mut Receipt)) -> VerifiedReceipts {
        let digest = exposure(self.profile).sha256().unwrap();
        let remote_digest = exposure(PairingProfile::Contact).sha256().unwrap();
        let offer_i = Offer {
            profile: self.profile,
            grant_not_after: None,
            exposure_policy_sha256: digest,
        };
        let offer_r = Offer {
            profile: PairingProfile::Contact,
            grant_not_after: None,
            exposure_policy_sha256: remote_digest,
        };
        let transaction_id = [5; 32];
        let created = (NOW - 10) as u32;
        let expires = (NOW + 60) as u32;
        let mut local = Receipt {
            transaction_id,
            signer_role: SignerRole::Initiator,
            signer_id: self.us.id,
            subject_id: self.peer.id,
            profile: self.profile,
            grant_not_after: None,
            exposure_policy_sha256: digest,
            grant_id: self.grant_id,
            issued_utc: created + 1,
            ceremony_expires_utc: expires,
            provenance: PROVENANCE_MANUAL_OOB.into(),
            policy_revision: 1,
        };
        edit(&mut local);
        let remote = Receipt {
            signer_role: SignerRole::Responder,
            signer_id: self.peer.id,
            subject_id: self.us.id,
            profile: PairingProfile::Contact,
            exposure_policy_sha256: remote_digest,
            grant_id: [0xee; 16],
            ..local.clone()
        };
        let ctx = ReceiptVerificationContext {
            id_i: self.us.id,
            id_r: self.peer.id,
            spki_i: &self.us.spki,
            spki_r: &self.peer.spki,
            offer_i: Offer {
                profile: local.profile,
                exposure_policy_sha256: local.exposure_policy_sha256,
                ..offer_i
            },
            offer_r,
            created_utc: created,
            ceremony_expires_utc: expires,
            exporter: self.exporter,
            transaction_id: local.transaction_id,
            now_utc: NOW as u32,
            current_policy_i: local.policy_revision,
            current_policy_r: 1,
            blocked: false,
            revoked: false,
            bilateral: true,
        };
        let local_bytes = build_signed_receipt(&local, &self.exporter, &self.us.key).unwrap();
        let remote_bytes = build_signed_receipt(&remote, &self.exporter, &self.peer.key).unwrap();
        VerifiedReceipts::verify(&local_bytes, &remote_bytes, &ctx).unwrap()
    }
}

fn file_db(dir: &tempfile::TempDir) -> Connection {
    let conn = Connection::open(dir.path().join("xmsg.db")).unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    crate::storage::init_db(&conn).unwrap();
    conn
}

fn send_ok(conn: &Connection, us: &Device, peer: &Device) -> bool {
    let grants = grants_for(conn, &us.id, &peer.id).unwrap();
    let blocked = blocked_devices(conn).unwrap();
    let removed = removed_grants(conn).unwrap();
    let config = PeersMap::empty();
    let ctx = Context {
        now: NOW,
        blocked: &blocked,
        removed: &removed,
        config: &config,
    };
    let resource = Resource {
        target: Some("inbox"),
        principal: Some("alice"),
        ..Default::default()
    };
    authorize(&grants, &us.id, &peer.id, Operation::Send, &resource, &ctx).is_some()
}

fn paired<'a>(conn: &Connection, us: &'a Device, peer: &'a Device) -> (Intent, Ceremony<'a>) {
    let intent = reserve_intent(conn, &request(peer, PairingProfile::Contact), NOW).unwrap();
    reserve_capacity(conn, &intent.intent_id, NOW).unwrap();
    let ceremony = Ceremony {
        us,
        peer,
        grant_id: intent.grant_id,
        profile: PairingProfile::Contact,
        exporter: [3; 32],
    };
    (intent, ceremony)
}

#[test]
fn activation_is_idempotent_never_extends_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (us, peer) = (Device::new(), Device::new());
    {
        let conn = file_db(&dir);
        let (intent, ceremony) = paired(&conn, &us, &peer);
        assert!(!send_ok(&conn, &us, &peer), "a reserved grant authorized");
        let receipts = ceremony.receipts();
        let (new, revision) = activate(&conn, &us.id, &intent.intent_id, &receipts, NOW).unwrap();
        assert_eq!(new, Activated::New);
        assert_eq!(
            activate(&conn, &us.id, &intent.intent_id, &receipts, NOW + 1).unwrap(),
            (Activated::AlreadyActive, revision),
            "an identical repeat moved the authority revision"
        );
        let altered = ceremony.receipts_with(|r| r.issued_utc += 1);
        assert!(
            matches!(
                activate(&conn, &us.id, &intent.intent_id, &altered, NOW + 1),
                Err(StoreError::Binding(_))
            ),
            "an altered retry was treated as idempotent"
        );
    }
    let conn = file_db(&dir);
    let grants = grants_for(&conn, &us.id, &peer.id).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].not_after, None);
    let Authority::Manual { evidence, .. } = &grants[0].authority else {
        panic!("not a manual grant")
    };
    assert_eq!(
        evidence.activated_at, NOW,
        "a repeat refreshed the activation"
    );
    assert!(send_ok(&conn, &us, &peer));
}

#[test]
fn p6_removal_wins_over_retry_and_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (us, peer) = (Device::new(), Device::new());
    let (intent, ceremony) = {
        let conn = file_db(&dir);
        let (intent, ceremony) = paired(&conn, &us, &peer);
        activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW).unwrap();
        remove(&conn, &intent.grant_id, NOW).unwrap();
        (intent, ceremony)
    };
    let conn = file_db(&dir);
    assert!(!send_ok(&conn, &us, &peer), "a removed grant authorized");
    assert!(
        matches!(
            activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW),
            Err(StoreError::Removed)
        ),
        "an old receipt revived a removed grant after restart"
    );
    assert!(removed_grants(&conn).unwrap().contains(&intent.grant_id));
}

#[test]
fn removal_before_activation_consumes_the_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer) = (Device::new(), Device::new());
    let (intent, ceremony) = paired(&conn, &us, &peer);
    remove(&conn, &intent.grant_id, NOW).unwrap();
    assert!(matches!(
        activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW),
        Err(StoreError::Removed)
    ));
    assert!(!send_ok(&conn, &us, &peer));
}

#[test]
fn p6_concurrent_remove_and_activate_always_end_removed() {
    let (us, peer) = (Arc::new(Device::new()), Arc::new(Device::new()));
    let mut orders = [0usize; 2];
    for round in 0..24 {
        let dir = tempfile::tempdir().unwrap();
        let conn = file_db(&dir);
        let (intent, ceremony) = paired(&conn, &us, &peer);
        let receipts = Arc::new(ceremony.receipts());
        drop(conn);
        let barrier = Arc::new(Barrier::new(2));
        let path = dir.path().to_path_buf();
        let spawn = |remover: bool| {
            let (barrier, path, receipts, us) =
                (barrier.clone(), path.clone(), receipts.clone(), us.clone());
            std::thread::spawn(move || {
                let conn = Connection::open(path.join("xmsg.db")).unwrap();
                conn.busy_timeout(Duration::from_secs(10)).unwrap();
                barrier.wait();
                if remover {
                    remove(&conn, &intent.grant_id, NOW).map(|_| None)
                } else {
                    activate(&conn, &us.id, &intent.intent_id, &receipts, NOW).map(Some)
                }
            })
        };
        // Alternate which thread starts first so both commit orders occur.
        let (first, second) = if round % 2 == 0 {
            (spawn(true), spawn(false))
        } else {
            (spawn(false), spawn(true))
        };
        let results = [first.join().unwrap(), second.join().unwrap()];
        let activation = results
            .iter()
            .find_map(|r| match r {
                Ok(Some(_)) => Some(true),
                Err(StoreError::Removed) => Some(false),
                _ => None,
            })
            .expect("activation neither committed nor refused as removed");
        orders[usize::from(activation)] += 1;
        assert!(results.iter().any(|r| matches!(r, Ok(None))));
        let conn = file_db(&dir);
        assert!(
            !send_ok(&conn, &us, &peer),
            "round {round}: final state authorized after remove returned"
        );
        assert!(grants_for(&conn, &us.id, &peer.id).unwrap().is_empty());
        assert!(removed_grants(&conn).unwrap().contains(&intent.grant_id));
    }
    eprintln!("remove-first {}, activate-first {}", orders[0], orders[1]);
}

#[test]
fn p6_fresh_intent_after_removal_succeeds_unless_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer) = (Device::new(), Device::new());
    let (old, ceremony) = paired(&conn, &us, &peer);
    activate(&conn, &us.id, &old.intent_id, &ceremony.receipts(), NOW).unwrap();
    remove(&conn, &old.grant_id, NOW).unwrap();
    let (fresh, ceremony) = paired(&conn, &us, &peer);
    assert_ne!(fresh.grant_id, old.grant_id, "a grant ID was reused");
    activate(&conn, &us.id, &fresh.intent_id, &ceremony.receipts(), NOW).unwrap();
    assert!(send_ok(&conn, &us, &peer));

    block_device(&conn, &peer.id, NOW).unwrap();
    assert!(!send_ok(&conn, &us, &peer), "a block left a grant usable");
    assert!(matches!(
        reserve_intent(&conn, &request(&peer, PairingProfile::Contact), NOW),
        Err(StoreError::Blocked)
    ));
    assert!(
        matches!(
            unblock_device(&conn, &peer.id, &PeersMap::empty()),
            Err(StoreError::WouldRestore(_))
        ),
        "unblock lifted a block over an unremoved manual grant"
    );
    remove(&conn, &fresh.grant_id, NOW).unwrap();
    unblock_device(&conn, &peer.id, &PeersMap::empty()).unwrap();
    let (pending, ceremony) = paired(&conn, &us, &peer);
    block_device(&conn, &peer.id, NOW).unwrap();
    assert!(matches!(
        activate(&conn, &us.id, &pending.intent_id, &ceremony.receipts(), NOW),
        Err(StoreError::Blocked)
    ));
}

#[test]
fn activation_rejects_receipts_that_differ_from_the_intent() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer, other) = (Device::new(), Device::new(), Device::new());
    let (intent, mut ceremony) = paired(&conn, &us, &peer);
    let wrong_grant = ceremony.receipts_with(|r| r.grant_id = [0x11; 16]);
    assert!(matches!(
        activate(&conn, &us.id, &intent.intent_id, &wrong_grant, NOW),
        Err(StoreError::Binding("grant_id"))
    ));
    ceremony.profile = PairingProfile::OwnerDevice;
    assert!(
        matches!(
            activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW),
            Err(StoreError::Binding("profile"))
        ),
        "a receipt elevated contact to owner-device"
    );
    ceremony.profile = PairingProfile::Contact;
    ceremony.peer = &other;
    assert!(matches!(
        activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW),
        Err(StoreError::Binding("local subject"))
    ));
    ceremony.peer = &peer;
    assert!(matches!(
        activate(
            &conn,
            &us.id,
            &intent.intent_id,
            &ceremony.receipts(),
            NOW + 61
        ),
        Err(StoreError::Binding("outside the ceremony window"))
    ));
    assert!(matches!(
        activate(&conn, &us.id, &[0; 16], &ceremony.receipts(), NOW),
        Err(StoreError::IntentUnavailable)
    ));
    assert!(!send_ok(&conn, &us, &peer));
}

#[test]
fn intents_are_bounded_one_per_device() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let peer = Device::new();
    reserve_intent(&conn, &request(&peer, PairingProfile::Contact), NOW).unwrap();
    assert!(reserve_intent(&conn, &request(&peer, PairingProfile::Contact), NOW).is_err());
    for _ in 1..MAX_PENDING_INTENTS {
        reserve_intent(
            &conn,
            &request(&Device::new(), PairingProfile::Contact),
            NOW,
        )
        .unwrap();
    }
    assert!(matches!(
        reserve_intent(
            &conn,
            &request(&Device::new(), PairingProfile::Contact),
            NOW
        ),
        Err(StoreError::PendingFull)
    ));
    // Expired intents free their slots without being extended.
    reserve_intent(
        &conn,
        &request(&Device::new(), PairingProfile::Contact),
        NOW + 121,
    )
    .map(|_| ())
    .unwrap_err();
    let mut late = request(&Device::new(), PairingProfile::Contact);
    late.expires_at = NOW + 240;
    reserve_intent(&conn, &late, NOW + 120).unwrap();
    let mut long = request(&Device::new(), PairingProfile::Contact);
    long.expires_at = NOW + 121;
    assert!(matches!(
        reserve_intent(&conn, &long, NOW),
        Err(StoreError::Invalid(_))
    ));
}

fn legacy_config(pin: &DeviceId, allow: &[&str]) -> PeersMap {
    PeersMap::load_from_json(
        &serde_json::json!({"laptop": {
            "address": "192.0.2.9:7788",
            "pin": format!("sha256:{}", hex::encode(pin)),
            "allow": allow,
            "principals": ["alice"],
            "from": ["192.0.2.0/24"],
        }})
        .to_string(),
    )
    .unwrap()
}

#[test]
fn p11_legacy_import_is_exact_unchanged_and_never_revives_a_removal() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer) = (Device::new(), Device::new());
    let config = legacy_config(&peer.id, &["send"]);
    let before = format!("{:?}", config.get("laptop"));
    assert_eq!(import_legacy(&conn, &us.id, &config, NOW).unwrap().0, 1);
    assert_eq!(
        format!("{:?}", config.get("laptop")),
        before,
        "import changed the legacy entry"
    );
    let grants = grants_for(&conn, &us.id, &peer.id).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].provenance(), PROVENANCE_LEGACY);
    assert_eq!(
        grants[0].authority,
        Authority::Legacy {
            predicates: LegacyPredicates::from_peer(config.get("laptop").unwrap())
        },
        "imported predicates differ from the entry"
    );
    assert_eq!(grants[0].not_after, None);
    assert_eq!(import_legacy(&conn, &us.id, &config, NOW).unwrap().0, 0);

    remove(&conn, &grants[0].grant_id, NOW).unwrap();
    drop(conn);
    let conn = file_db(&dir);
    assert_eq!(
        import_legacy(&conn, &us.id, &config, NOW).unwrap().0,
        0,
        "a reload revived a removed legacy grant"
    );
    assert!(grants_for(&conn, &us.id, &peer.id).unwrap().is_empty());

    let restated = legacy_config(&peer.id, &["send", "reply"]);
    assert_eq!(import_legacy(&conn, &us.id, &restated, NOW).unwrap().0, 1);
}

#[test]
fn replace_legacy_is_atomic_and_cancelled_by_removing_the_legacy_grant() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer) = (Device::new(), Device::new());
    import_legacy(&conn, &us.id, &legacy_config(&peer.id, &["send"]), NOW).unwrap();
    let legacy = grants_for(&conn, &us.id, &peer.id).unwrap()[0].grant_id;

    let mut req = request(&peer, PairingProfile::Contact);
    req.replaces = Some(legacy);
    let intent = reserve_intent(&conn, &req, NOW).unwrap();
    remove(&conn, &legacy, NOW).unwrap();
    let ceremony = Ceremony {
        us: &us,
        peer: &peer,
        grant_id: intent.grant_id,
        profile: PairingProfile::Contact,
        exporter: [3; 32],
    };
    assert!(
        matches!(
            activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW),
            Err(StoreError::IntentUnavailable)
        ),
        "removing the legacy grant left its replacement intent live"
    );
    assert!(grants_for(&conn, &us.id, &peer.id).unwrap().is_empty());

    let restated = legacy_config(&peer.id, &["send", "list"]);
    import_legacy(&conn, &us.id, &restated, NOW).unwrap();
    let legacy = grants_for(&conn, &us.id, &peer.id).unwrap()[0].grant_id;
    req.replaces = Some(legacy);
    let intent = reserve_intent(&conn, &req, NOW).unwrap();
    reserve_capacity(&conn, &intent.intent_id, NOW).unwrap();
    let ceremony = Ceremony {
        grant_id: intent.grant_id,
        ..ceremony
    };
    activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW).unwrap();
    let grants = grants_for(&conn, &us.id, &peer.id).unwrap();
    assert_eq!(grants.len(), 1, "replacement kept or lost a record");
    assert_eq!(grants[0].grant_id, intent.grant_id);
    assert!(removed_grants(&conn).unwrap().contains(&legacy));
}

#[test]
fn independent_grants_survive_removing_one() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer) = (Device::new(), Device::new());
    import_legacy(&conn, &us.id, &legacy_config(&peer.id, &["send"]), NOW).unwrap();
    let (intent, ceremony) = paired(&conn, &us, &peer);
    activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW).unwrap();
    assert_eq!(grants_for(&conn, &us.id, &peer.id).unwrap().len(), 2);
    remove(&conn, &intent.grant_id, NOW).unwrap();
    let left = grants_for(&conn, &us.id, &peer.id).unwrap();
    assert_eq!(left.len(), 1, "removing one grant erased another");
    assert_eq!(left[0].provenance(), PROVENANCE_LEGACY);
}

#[test]
fn durable_block_reaches_every_deny_check_of_the_next_policy_generation() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (own_cert, _, _) = crate::fed::generate_self_signed_ed25519("own").unwrap();
    let (peer_cert, _, peer_pin) = crate::fed::generate_self_signed_ed25519("peer").unwrap();
    let peer_id = device_id_from_pin(&peer_pin).unwrap();
    let load = || {
        let mut map = legacy_config(&peer_id, &["send"]);
        map.apply_pairing_authority(&conn, &own_cert).unwrap();
        map
    };
    let leaf = crate::fed::LeafAuthority::from_certificate(
        &rustls::pki_types::CertificateDer::from(peer_cert.clone()),
        crate::fed::AdmissionMode::Pin,
    )
    .unwrap();
    let open = load();
    assert!(leaf.check(&open).is_ok());
    let own = device_id_from_pin(&crate::fed::spki_sha256_from_der(&own_cert).unwrap()).unwrap();
    assert_eq!(
        grants_for(&conn, &own, &peer_id).unwrap().len(),
        1,
        "the policy load did not import the pin"
    );

    block_device(&conn, &peer_id, NOW).unwrap();
    let blocked = load();
    assert!(
        leaf.check(&blocked).is_err(),
        "a durable block did not reach the leaf authority check"
    );
    assert!(blocked
        .check_certificate_deny(&rustls::pki_types::CertificateDer::from(peer_cert))
        .is_err());
    assert_eq!(
        grants_for(&conn, &own, &peer_id).unwrap().len(),
        1,
        "a reload imported the pin twice"
    );
    assert!(open.deny.spkis.is_empty(), "an older generation changed");
}

#[test]
fn a_pre_pairing_schema_3_database_opens_unchanged_with_the_additive_tables() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("xmsg.db");
    {
        let conn = Connection::open(&path).unwrap();
        crate::storage::init_db(&conn).unwrap();
        // The database a schema-3 build without the pairing store leaves behind.
        conn.execute_batch(
            "DROP TABLE pairing_intents; DROP TABLE pairing_grants; DROP TABLE pairing_removed_grants;
             DROP TABLE pairing_device_blocks; DROP TABLE pairing_meta;
             INSERT INTO location_cache (id, node, cached_at) VALUES ('kept', 'node', 7);",
        )
        .unwrap();
    }
    let names = |conn: &Connection| -> std::collections::BTreeSet<String> {
        conn.prepare("SELECT name FROM sqlite_master")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let before = names(&Connection::open(&path).unwrap());
    assert!(!before.contains("pairing_meta"));
    let conn = Connection::open(&path).unwrap();
    crate::storage::init_db(&conn).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, crate::storage::SCHEMA_VERSION);
    assert_eq!(version, 3, "the pairing store changed the schema version");
    let after = names(&conn);
    assert!(
        after.is_superset(&before),
        "an existing table or index was lost"
    );
    let kept: i64 = conn
        .query_row(
            "SELECT cached_at FROM location_cache WHERE id = 'kept'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kept, 7, "an existing row changed");
    assert_eq!(authority_revision(&conn).unwrap(), 0);
    crate::storage::init_db(&conn).unwrap();
    assert_eq!(
        authority_revision(&conn).unwrap(),
        0,
        "reopening reset or moved the revision"
    );
}

#[test]
fn every_authority_transaction_moves_the_revision_and_nothing_else_does() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer, other) = (Device::new(), Device::new(), Device::new());
    let rev = |conn: &Connection| authority_revision(conn).unwrap();
    assert_eq!(rev(&conn), 0);
    let config = legacy_config(&other.id, &["send"]);
    let (_, r1) = import_legacy(&conn, &us.id, &config, NOW).unwrap();
    assert_eq!((r1, rev(&conn)), (1, 1), "import did not commit a revision");
    assert_eq!(
        import_legacy(&conn, &us.id, &config, NOW).unwrap(),
        (0, 1),
        "an idempotent import moved the revision"
    );
    let (intent, ceremony) = paired(&conn, &us, &peer);
    assert_eq!(
        rev(&conn),
        1,
        "reserving an intent or capacity is not an authority change"
    );
    let receipts = ceremony.receipts();
    let (_, r2) = activate(&conn, &us.id, &intent.intent_id, &receipts, NOW).unwrap();
    assert_eq!(
        (r2, rev(&conn)),
        (2, 2),
        "activate did not commit a revision"
    );
    assert_eq!(remove(&conn, &intent.grant_id, NOW).unwrap(), 3, "remove");
    assert_eq!(block_device(&conn, &peer.id, NOW).unwrap(), 4, "block");
    assert_eq!(
        unblock_device(&conn, &peer.id, &PeersMap::empty()).unwrap(),
        5,
        "unblock"
    );
    assert!(cancel_open_intents(&conn).is_ok());
    assert_eq!(rev(&conn), 5);
    drop(conn);
    assert_eq!(
        rev(&file_db(&dir)),
        5,
        "the revision did not survive a restart"
    );
}

#[test]
fn a_refused_unblock_changes_nothing_and_the_file_deny_excuses_file_rights() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let peer = Device::new();
    block_device(&conn, &peer.id, NOW).unwrap();
    let before = authority_revision(&conn).unwrap();
    let pinned = legacy_config(&peer.id, &["send"]);
    let Err(StoreError::WouldRestore(reasons)) = unblock_device(&conn, &peer.id, &pinned) else {
        panic!("unblock lifted a block over a peers-file pin");
    };
    assert!(
        reasons.iter().any(|r| r.contains("'laptop'")),
        "{reasons:?}"
    );
    let mut with_ca = PeersMap::empty();
    with_ca
        .insert(crate::fed::PeerConfig {
            name: "owner.n".into(),
            ca: Some("root.pem".into()),
            identities: Some(vec!["spiffe://example.test/host/n/user/owner".into()]),
            allow: vec!["send".into()],
            ..Default::default()
        })
        .unwrap();
    assert!(
        matches!(
            unblock_device(&conn, &peer.id, &with_ca),
            Err(StoreError::WouldRestore(_))
        ),
        "unblock lifted a block on a node with a CA entry"
    );
    assert_eq!(
        authority_revision(&conn).unwrap(),
        before,
        "a refusal committed"
    );
    assert!(blocked_devices(&conn).unwrap().contains(&peer.id));

    let denied = PeersMap::load_from_json(
        &serde_json::json!({"peers": {"laptop": {
            "address": "192.0.2.9:7788",
            "pin": format!("sha256:{}", hex::encode(peer.id)), "allow": ["send"]
        }}, "deny": {"spkis": [hex::encode(peer.id)]}})
        .to_string(),
    )
    .unwrap();
    unblock_device(&conn, &peer.id, &denied).unwrap();
    assert!(!blocked_devices(&conn).unwrap().contains(&peer.id));
}

/// Fills `n` manual grant slots with minimal rows.
fn fill_manual_slots(conn: &Connection, n: i64) {
    let exposure = exposure(PairingProfile::Contact).encode_cbor().unwrap();
    for i in 0..n {
        let id = (i as u128).to_be_bytes();
        conn.execute(
            "INSERT INTO pairing_grants (grant_id, issuer, subject, provenance, profile, exposure,
                 transaction_id, exporter, receipt_local, receipt_remote, ceremony_created,
                 ceremony_expires, activated_at, active)
             VALUES (?1, ?2, ?2, 'manual_authenticated_oob', 'contact', ?3, ?2, ?2, x'01', x'01',
                 0, 0, 0, 1)",
            params![&id[..], &[9u8; 32][..], exposure],
        )
        .unwrap();
    }
}

#[test]
fn capacity_is_reserved_before_a_receipt_and_never_exceeds_the_cap() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer) = (Device::new(), Device::new());
    let intent = reserve_intent(&conn, &request(&peer, PairingProfile::Contact), NOW).unwrap();
    let ceremony = Ceremony {
        us: &us,
        peer: &peer,
        grant_id: intent.grant_id,
        profile: PairingProfile::Contact,
        exporter: [3; 32],
    };
    assert!(
        matches!(
            activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW),
            Err(StoreError::NoReservation)
        ),
        "activation took a slot it never reserved"
    );
    fill_manual_slots(&conn, MAX_MANUAL_GRANTS - 2);
    reserve_capacity(&conn, &intent.intent_id, NOW).unwrap();
    reserve_capacity(&conn, &intent.intent_id, NOW).unwrap();
    let second = reserve_intent(
        &conn,
        &request(&Device::new(), PairingProfile::Contact),
        NOW,
    )
    .unwrap();
    // A reservation keeps counting while its intent is open, whatever the clock says.
    reserve_capacity(&conn, &second.intent_id, NOW).unwrap();
    let third = reserve_intent(
        &conn,
        &request(&Device::new(), PairingProfile::Contact),
        NOW,
    );
    assert!(matches!(third, Err(StoreError::GrantsFull)), "{third:?}");
    // Past every intent's expiry the slots are still held: no clock term releases them.
    let mut late = request(&Device::new(), PairingProfile::Contact);
    late.expires_at = NOW + 400;
    assert!(matches!(
        reserve_intent(&conn, &late, NOW + 300),
        Err(StoreError::GrantsFull)
    ));
    // The enforcing check: an intent created before the cap filled is refused terminally.
    remove(&conn, &(0u128).to_be_bytes(), NOW).unwrap();
    let fourth = reserve_intent(
        &conn,
        &request(&Device::new(), PairingProfile::Contact),
        NOW,
    )
    .unwrap();
    fill_manual_slots_from(&conn, MAX_MANUAL_GRANTS);
    assert!(matches!(
        reserve_capacity(&conn, &fourth.intent_id, NOW),
        Err(StoreError::GrantsFull)
    ));
    let state: String = conn
        .query_row(
            "SELECT state FROM pairing_intents WHERE intent_id = ?1",
            [&fourth.intent_id[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "refused_cap");
    assert!(matches!(
        reserve_capacity(&conn, &fourth.intent_id, NOW),
        Err(StoreError::IntentUnavailable)
    ));
    let used: i64 = slots_used(&conn, None).unwrap();
    assert!(used <= MAX_MANUAL_GRANTS, "{used} slots used");

    // Startup cancellation ends every reservation.
    assert_eq!(cancel_open_intents(&conn).unwrap(), 2);
    assert_eq!(slots_used(&conn, None).unwrap(), used - 2);
    assert!(matches!(
        activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW),
        Err(StoreError::IntentUnavailable)
    ));
}

/// Adds one more manual grant row with an ID outside `fill_manual_slots`'s range.
fn fill_manual_slots_from(conn: &Connection, start: i64) {
    let exposure = exposure(PairingProfile::Contact).encode_cbor().unwrap();
    let id = (start as u128).to_be_bytes();
    conn.execute(
        "INSERT INTO pairing_grants (grant_id, issuer, subject, provenance, profile, exposure,
             transaction_id, exporter, receipt_local, receipt_remote, ceremony_created,
             ceremony_expires, activated_at, active)
         VALUES (?1, ?2, ?2, 'manual_authenticated_oob', 'contact', ?3, ?2, ?2, x'01', x'01',
             0, 0, 0, 1)",
        params![&id[..], &[9u8; 32][..], exposure],
    )
    .unwrap();
}

#[test]
fn legacy_import_is_idempotent_and_a_changed_pin_reimports_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, old_key, new_key) = (Device::new(), Device::new(), Device::new());
    let config = legacy_config(&old_key.id, &["send"]);
    import_legacy(&conn, &us.id, &config, NOW).unwrap();
    let rows = |conn: &Connection| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM pairing_grants", [], |r| r.get(0))
            .unwrap()
    };
    let (count, revision) = (rows(&conn), authority_revision(&conn).unwrap());
    for _ in 0..3 {
        assert_eq!(import_legacy(&conn, &us.id, &config, NOW + 5).unwrap().0, 0);
    }
    assert_eq!(
        (rows(&conn), authority_revision(&conn).unwrap()),
        (count, revision),
        "a repeated import changed the store"
    );
    // The entry now pins another key: one exact new record, and the old one stops authorizing.
    let changed = legacy_config(&new_key.id, &["send"]);
    assert_eq!(import_legacy(&conn, &us.id, &changed, NOW).unwrap().0, 1);
    let new_grants = grants_for(&conn, &us.id, &new_key.id).unwrap();
    assert_eq!(
        new_grants[0].authority,
        Authority::Legacy {
            predicates: LegacyPredicates::from_peer(changed.get("laptop").unwrap())
        }
    );
    let blocked = HashSet::new();
    let removed = HashSet::new();
    let ctx = Context {
        now: NOW,
        blocked: &blocked,
        removed: &removed,
        config: &changed,
    };
    let send = Resource {
        target: Some("inbox"),
        principal: Some("alice"),
        ..Default::default()
    };
    let old_grants = grants_for(&conn, &us.id, &old_key.id).unwrap();
    assert!(
        authorize(
            &old_grants,
            &us.id,
            &old_key.id,
            Operation::Send,
            &send,
            &ctx
        )
        .is_none(),
        "the replaced pin kept authority"
    );
    assert!(authorize(
        &new_grants,
        &us.id,
        &new_key.id,
        Operation::Send,
        &send,
        &ctx
    )
    .is_some());
    // A narrowed entry never widens: the wider old record no longer matches the file.
    let narrowed = legacy_config(&new_key.id, &[]);
    import_legacy(&conn, &us.id, &narrowed, NOW).unwrap();
    let ctx = Context {
        config: &narrowed,
        ..ctx
    };
    let all = grants_for(&conn, &us.id, &new_key.id).unwrap();
    assert!(
        authorize(&all, &us.id, &new_key.id, Operation::Send, &send, &ctx).is_none(),
        "an older, wider legacy record outlived a narrowed entry"
    );
}

#[test]
fn a_block_cancels_the_devices_open_intents_and_their_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let conn = file_db(&dir);
    let (us, peer, other) = (Device::new(), Device::new(), Device::new());
    let (intent, ceremony) = paired(&conn, &us, &peer);
    let (unrelated, _) = paired(&conn, &us, &other);
    assert_eq!(slots_used(&conn, None).unwrap(), 2);
    block_device(&conn, &peer.id, NOW).unwrap();
    let state = |id: &[u8; 16]| -> String {
        conn.query_row(
            "SELECT state FROM pairing_intents WHERE intent_id = ?1",
            [&id[..]],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        state(&intent.intent_id),
        "cancelled",
        "a block left the device's intent open"
    );
    assert_eq!(
        state(&unrelated.intent_id),
        "open",
        "a block cancelled another device's intent"
    );
    assert_eq!(
        slots_used(&conn, None).unwrap(),
        1,
        "the blocked intent kept its slot"
    );
    // Lifting the block does not revive the cancelled intent.
    unblock_device(&conn, &peer.id, &PeersMap::empty()).unwrap();
    assert!(matches!(
        activate(&conn, &us.id, &intent.intent_id, &ceremony.receipts(), NOW),
        Err(StoreError::IntentUnavailable)
    ));
}
