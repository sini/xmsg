#![cfg(feature = "daemon")]
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use serde_json::{json, Value};
use std::sync::Arc;
use xmsg::fed::{CombinedClientCertVerifier, PeersMap};
use xmsg::storage::{self, PeerMailboxInsert, PeerMailboxLimits, PeerMailboxMessage};

struct Roots {
    _dir: tempfile::TempDir,
    fleet: std::path::PathBuf,
    enroll: std::path::PathBuf,
    f: CertificateParams,
    fk: KeyPair,
    e: CertificateParams,
    ek: KeyPair,
}
impl Roots {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let mut f = CertificateParams::default();
        f.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        f.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let e = f.clone();
        let fk = KeyPair::generate().unwrap();
        let ek = KeyPair::generate().unwrap();
        let fleet = dir.path().join("fleet.pem");
        let enroll = dir.path().join("enroll.pem");
        std::fs::write(&fleet, f.self_signed(&fk).unwrap().pem()).unwrap();
        std::fs::write(&enroll, e.self_signed(&ek).unwrap().pem()).unwrap();
        Self {
            _dir: dir,
            fleet,
            enroll,
            f,
            fk,
            e,
            ek,
        }
    }
    fn cert(&self, enrollment: bool, uri: &str) -> CertificateDer<'static> {
        self.cert_key(enrollment, uri).0
    }
    fn cert_key(&self, enrollment: bool, uri: &str) -> (CertificateDer<'static>, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
        p.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let certificate = p
            .signed_by(
                &key,
                &if enrollment {
                    Issuer::from_params(&self.e, &self.ek)
                } else {
                    Issuer::from_params(&self.f, &self.fk)
                },
            )
            .unwrap()
            .der()
            .clone();
        (certificate, key.serialize_der())
    }
    fn config(&self, patterns: Value, rules: Value) -> Value {
        json!({"peers":{"fleet.hub":{"address":"127.0.0.1:1","ca":self.fleet,"identities":["spiffe://example.org/host/hub/user/fleet"],"allow":["send"]},"enroll.hub":{"address":"127.0.0.1:1","ca":self.enroll,"identities":["spiffe://example.org/host/hub/user/enroll"],"allow":["send"]}},"hub":{"patterns":patterns,"rules":rules}})
    }
}
#[test]
fn pattern_bundle_limits_tls_and_resolver_and_admits_leaf() {
    let roots = Roots::new();
    let pat = "spiffe://example.org/host/*/user/*";
    let value = roots.config(
        json!([{"pattern":pat,"ca":roots.fleet}]),
        json!([{"pattern":pat,"allow":["send","reply"],"leaf":true}]),
    );
    let peers = Arc::new(PeersMap::load_from_json(&value.to_string()).unwrap());
    let verifier = CombinedClientCertVerifier::new(peers.clone());
    let enrollment = roots.cert(true, "spiffe://example.org/host/lap/user/carol");
    assert!(
        peers.resolve_incoming_peer(&enrollment, &[]).is_err(),
        "resolver pooled enrollment anchors into fleet pattern"
    );
    assert!(
        verifier
            .verify_client_cert(&enrollment, &[], UnixTime::now())
            .is_err(),
        "TLS pooled enrollment anchors into fleet pattern"
    );
    let fleet = roots.cert(false, "spiffe://example.org/host/lap/user/dave");
    assert!(verifier
        .verify_client_cert(&fleet, &[], UnixTime::now())
        .is_ok());
    let (peer, _) = peers.resolve_incoming_peer(&fleet, &[]).unwrap();
    assert_eq!(peer.name, "dave.lap");
    assert!(peer.leaf);
    assert!(peer.address.is_empty());
    assert!(peers.get("dave.lap").is_none());
    assert!(peers.get_peer_config("dave.lap").unwrap().leaf);
}
#[test]
fn cross_bundle_names_and_spanning_rules_are_refused() {
    let roots = Roots::new();
    let fleet = "spiffe://example.org/host/x/user/sini";
    for enrollment in [
        "spiffe://other.org/host/x/user/sini",
        "spiffe://example.org/ns/x/sa/sini",
        "spiffe://example.org/*/x/*/sini",
    ] {
        let value = roots.config(
            json!([{"pattern":fleet,"ca":roots.fleet},{"pattern":enrollment,"ca":roots.enroll}]),
            json!([]),
        );
        let error = PeersMap::load_from_json(&value.to_string()).unwrap_err();
        assert!(
            error.contains("sini.x"),
            "cross-bundle name overlap loaded: {error}"
        );
    }
    let value=roots.config(json!([{"pattern":fleet,"ca":roots.fleet},{"pattern":"spiffe://example.org/*/x/*/carol","ca":roots.enroll}]),json!([]));
    assert!(PeersMap::load_from_json(&value.to_string()).is_ok());
    let a = "spiffe://example.org/host/*/user/sini";
    let b = "spiffe://example.org/host/*/user/carol";
    let patterns = json!([{"pattern":a,"ca":roots.fleet},{"pattern":b,"ca":roots.enroll}]);
    let value=roots.config(patterns.clone(),json!([{"pattern":"spiffe://example.org/host/*/user/*","allow":["send","relayed"],"leaf":true}]));
    assert!(PeersMap::load_from_json(&value.to_string())
        .unwrap_err()
        .contains("spans bundles"));
    let value=roots.config(patterns,json!([{"pattern":a,"allow":["send","relayed"],"leaf":true},{"pattern":b,"allow":["reply"]}]));
    let peers = PeersMap::load_from_json(&value.to_string()).unwrap();
    let cert = roots.cert(true, "spiffe://example.org/host/lap/user/carol");
    let (peer, _) = peers.resolve_incoming_peer(&cert, &[]).unwrap();
    assert_eq!(peer.allow, vec!["reply"]);
    assert!(!peer.leaf);
    let value = roots.config(json!(["spiffe://example.org/host/*/user/*"]), json!([]));
    assert!(PeersMap::load_from_json(&value.to_string())
        .unwrap_err()
        .contains("must name its CA bundle"));
}
fn message(id: &str, peer: &str) -> PeerMailboxMessage {
    PeerMailboxMessage {
        id: id.into(),
        peer: peer.into(),
        target_ref: "worker".into(),
        created_at: storage::now_epoch_secs(),
        from_name: "hub".into(),
        bytes: 1,
        body: "x".into(),
        envelope: "{}".into(),
        origin: storage::Origin::service("test", "hub"),
    }
}
#[test]
fn admitted_global_caps_are_durable_and_leave_concrete_mailboxes_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let db = rusqlite::Connection::open(&file).unwrap();
    storage::init_db(&db).unwrap();
    let leaf = PeerMailboxLimits {
        max_rows: 10,
        max_bytes: 4096,
    };
    let global = PeerMailboxLimits {
        max_rows: 1,
        max_bytes: 4096,
    };
    assert_eq!(
        storage::insert_peer_mailbox_with_admission_budget(
            &db,
            &message("a", "alice.lap"),
            leaf,
            true,
            global
        )
        .unwrap(),
        PeerMailboxInsert::Inserted
    );
    drop(db);
    let db = rusqlite::Connection::open(&file).unwrap();
    storage::init_db(&db).unwrap();
    assert_eq!(
        storage::insert_peer_mailbox_with_admission_budget(
            &db,
            &message("b", "bob.lap"),
            leaf,
            true,
            global
        )
        .unwrap(),
        PeerMailboxInsert::Full,
        "global admitted cap lost across reopen"
    );
    assert_eq!(
        storage::insert_peer_mailbox_with_admission_budget(
            &db,
            &message("c", "concrete"),
            leaf,
            false,
            global
        )
        .unwrap(),
        PeerMailboxInsert::Inserted
    );
    assert_eq!(
        storage::count_peer_mailbox_messages(&db, "alice.lap").unwrap(),
        1
    );
    assert_eq!(
        storage::insert_peer_mailbox_with_admission_budget(
            &db,
            &message("d", "bytes.lap"),
            leaf,
            true,
            PeerMailboxLimits {
                max_rows: 100,
                max_bytes: 0
            }
        )
        .unwrap(),
        PeerMailboxInsert::Full
    );
    let bytes_db = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&bytes_db).unwrap();
    let budget = PeerMailboxLimits {
        max_rows: 100,
        max_bytes: 512,
    };
    let mut first = message("byte-a", "alice.lap");
    first.body = "x".repeat(256);
    let mut second = message("byte-b", "bob.lap");
    second.body = "y".repeat(256);
    assert_eq!(
        storage::insert_peer_mailbox_with_admission_budget(&bytes_db, &first, leaf, true, budget)
            .unwrap(),
        PeerMailboxInsert::Inserted
    );
    assert_eq!(
        storage::insert_peer_mailbox_with_admission_budget(&bytes_db, &second, leaf, true, budget)
            .unwrap(),
        PeerMailboxInsert::Full,
        "global admitted byte sum was not bounded"
    );
}
#[test]
fn expired_admitted_entry_is_pruned_only_when_mailbox_empty() {
    let roots = Roots::new();
    let pat = "spiffe://example.org/host/*/user/*";
    let value = roots.config(
        json!([{"pattern":pat,"ca":roots.enroll}]),
        json!([{"pattern":pat,"allow":["send"],"leaf":true}]),
    );
    let peers = PeersMap::load_from_json(&value.to_string()).unwrap();
    let cert = roots.cert(true, "spiffe://example.org/host/lap/user/carol");
    peers.resolve_incoming_peer(&cert, &[]).unwrap();
    peers
        .admitted_clients
        .write()
        .unwrap()
        .get_mut("carol.lap")
        .unwrap()
        .not_after = 0;
    let db = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db).unwrap();
    storage::insert_peer_mailbox(&db, &message("a", "carol.lap")).unwrap();
    assert_eq!(peers.prune_admitted_clients(&db, 1).unwrap(), 0);
    storage::delete_peer_mailbox_message(&db, "carol.lap", "a").unwrap();
    assert_eq!(peers.prune_admitted_clients(&db, 1).unwrap(), 1);
    assert!(peers.get_peer_config("carol.lap").is_none());
}

fn node_state(
    name: &str,
    peers: Arc<PeersMap>,
    cert: CertificateDer<'static>,
    key: Vec<u8>,
    db: Arc<std::sync::Mutex<rusqlite::Connection>>,
    dir: &std::path::Path,
) -> Arc<xmsg::fed::FedState> {
    use xmsg::{agy, pi, svc};
    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);
    Arc::new(xmsg::fed::FedState {
        node_name: name.into(),
        peers: peers.into(),
        cert_der: cert.to_vec(),
        cert_chain_der: vec![cert.to_vec()],
        key_der: key,
        rate_limiter: Arc::new(xmsg::fed::RateLimiter::new(600, 200)),
        db,
        sessions_dirs: vec![dir.join("sessions")],
        agy_config: agy::AgyConfig {
            presence_dir: dir.join("presence"),
            proc_locks_path: dir.join("locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".into(),
            trusted_agy_exes: vec![],
            brain_dir: PathBuf::new(),
        },
        agy_store: agy::new_agy_store(),
        pi_store: pi::new_pi_store(),
        pi_notify_tx,
        svc_store: svc::new_svc_store(),
        svc_notify_tx,
        notify_tx,
        max_body: 65536,
        max_attachment_bytes: xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: std::time::Duration::from_secs(600),
        list_queries: Default::default(),
    })
}
use std::path::PathBuf;
fn leaf_peers(roots: &Roots, address: std::net::SocketAddr) -> Arc<PeersMap> {
    Arc::new(PeersMap::load_from_json(&json!({"fleet.hub":{"address":address.to_string(),"ca":roots.fleet,"identities":["spiffe://example.org/host/hub/user/fleet"],"allow":["send","reply","relayed"]}}).to_string()).unwrap())
}
#[tokio::test]
async fn admitted_leaf_queues_pulls_acks_and_recovers_after_hub_restart() {
    use xmsg::fed::{FedEnvelope, FedInboxItem, FedTarget};
    let roots = Roots::new();
    let dir = tempfile::tempdir().unwrap();
    let db_file = dir.path().join("hub.db");
    let open = || {
        let db = rusqlite::Connection::open(&db_file).unwrap();
        storage::init_db(&db).unwrap();
        Arc::new(std::sync::Mutex::new(db))
    };
    let pat = "spiffe://example.org/host/*/user/carol";
    let config=json!({"peers":{},"hub":{"patterns":[{"pattern":pat,"ca":roots.enroll}],"rules":[{"pattern":pat,"allow":["send","reply"],"leaf":true}]}}).to_string();
    let (hub_cert, hub_key) = roots.cert_key(false, "spiffe://example.org/host/hub/user/fleet");
    let (leaf_cert, leaf_key) = roots.cert_key(true, "spiffe://example.org/host/lap/user/carol");
    let peers = Arc::new(PeersMap::load_from_json(&config).unwrap());
    let hub = node_state(
        "fleet.hub",
        peers,
        hub_cert.clone(),
        hub_key.clone(),
        open(),
        dir.path(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = hub.clone();
    let task =
        tokio::spawn(async move { xmsg::fed::run_fed_listener(listener, state).await.unwrap() });
    let leaf = node_state(
        "carol.lap",
        leaf_peers(&roots, addr),
        leaf_cert.clone(),
        leaf_key.clone(),
        Arc::new(std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        )),
        dir.path(),
    );
    assert!(xmsg::fed::get_federated_inbox(&leaf, "fleet.hub", 0)
        .await
        .unwrap()
        .is_none());
    let attachment_hub = hub.clone();
    let request = tokio::spawn(async move {
        xmsg::fed::fetch_attachment_chunk(&attachment_hub, "carol.lap", "item", 0, 3, 7).await
    });
    let answer = xmsg::fed::get_federated_inbox(&leaf, "fleet.hub", 1)
        .await
        .unwrap();
    assert!(
        matches!(
            answer,
            Some(FedInboxItem::Attachment {
                offset: 3,
                length: 7,
                ..
            })
        ),
        "admitted leaf attachment lookup did not enqueue its query"
    );
    request.abort();
    let _ = request.await;

    let id = ulid::Ulid::new().to_string();
    let envelope = FedEnvelope {
        v: 1,
        id: id.clone(),
        origin: storage::Origin::service("test", "fleet.hub"),
        to: FedTarget {
            r#ref: "worker".into(),
        },
        body: "enrolled mailbox".into(),
        thread_id: "".into(),
        created_at: storage::now_epoch_secs(),
        forwarded: None,
        attachments: vec![],
    };
    storage::set_peer_mailbox_limits(
        &hub.db,
        PeerMailboxLimits {
            max_rows: 1,
            max_bytes: 4096,
        },
    );
    let delivery = xmsg::fed::send_federated_message(&hub, "carol.lap", &envelope)
        .await
        .unwrap();
    assert_eq!(delivery.outcome.as_deref(), Some("queued"));
    assert_eq!(
        storage::count_peer_mailbox_messages(&hub.db.lock().unwrap(), "carol.lap").unwrap(),
        1,
        "admitted mailbox not keyed by canonical name"
    );

    assert!(hub
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT admitted FROM peer_mailbox WHERE id=?1",
            [&id],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    let mut second = envelope.clone();
    second.id = ulid::Ulid::new().to_string();
    assert!(
        xmsg::fed::send_federated_message(&hub, "carol.lap", &second)
            .await
            .is_err()
    );
    task.abort();
    let _ = task.await;
    let peers = Arc::new(PeersMap::load_from_json(&config).unwrap());
    assert!(peers.get_peer_config("carol.lap").is_none());
    let restarted = node_state("fleet.hub", peers, hub_cert, hub_key, open(), dir.path());
    assert!(
        xmsg::fed::send_federated_message(&restarted, "carol.lap", &second)
            .await
            .is_err(),
        "unreconnected client became known across restart"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = restarted.clone();
    let task =
        tokio::spawn(async move { xmsg::fed::run_fed_listener(listener, state).await.unwrap() });
    let leaf = node_state(
        "carol.lap",
        leaf_peers(&roots, addr),
        leaf_cert,
        leaf_key,
        Arc::new(std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        )),
        dir.path(),
    );
    let message = xmsg::fed::get_federated_inbox(&leaf, "fleet.hub", 0)
        .await
        .unwrap()
        .unwrap();
    let FedInboxItem::Message(message) = message else {
        panic!("expected mailbox message")
    };
    assert_eq!(message.id, id);
    assert_eq!(message.body, "enrolled mailbox");
    xmsg::fed::ack_federated_inbox(&leaf, "fleet.hub", &id)
        .await
        .unwrap();
    assert_eq!(
        storage::count_peer_mailbox_messages(&restarted.db.lock().unwrap(), "carol.lap").unwrap(),
        0
    );
    assert!(xmsg::fed::get_federated_inbox(&leaf, "fleet.hub", 0)
        .await
        .unwrap()
        .is_none());
    task.abort();
    let _ = task.await;
    let mut no_leaf: Value = serde_json::from_str(&config).unwrap();
    no_leaf["hub"]["rules"][0]["leaf"] = json!(false);
    let peers = Arc::new(PeersMap::load_from_json(&no_leaf.to_string()).unwrap());
    let (hub_cert, hub_key) = roots.cert_key(false, "spiffe://example.org/host/hub/user/fleet");
    let hub = node_state("fleet.hub", peers, hub_cert, hub_key, open(), dir.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = hub.clone();
    let task =
        tokio::spawn(async move { xmsg::fed::run_fed_listener(listener, state).await.unwrap() });
    let (cert, key) = roots.cert_key(true, "spiffe://example.org/host/lap/user/carol");
    let leaf = node_state(
        "carol.lap",
        leaf_peers(&roots, addr),
        cert,
        key,
        Arc::new(std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        )),
        dir.path(),
    );
    assert!(
        xmsg::fed::get_federated_inbox(&leaf, "fleet.hub", 0)
            .await
            .is_err(),
        "rule without leaf admitted an inbox pull"
    );
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn cross_bundle_restart_takeover_cannot_be_configured() {
    use xmsg::fed::{FedEnvelope, FedInboxItem, FedTarget};
    let roots = Roots::new();
    let config = json!({"peers":{}, "hub": {
        "patterns":[{"pattern":"spiffe://fleet.org/host/*/user/*","ca":roots.fleet},{"pattern":"spiffe://enroll.org/host/*/user/*","ca":roots.enroll}],
        "rules":[{"pattern":"spiffe://fleet.org/host/*/user/*","allow":["send"],"leaf":true},{"pattern":"spiffe://enroll.org/host/*/user/*","allow":["send"],"leaf":true}]
    }}).to_string();
    let own = xmsg::fed::OwnNode {
        name: "fleet.hub".into(),
        pin: None,
    };
    let before = match PeersMap::load_from_json_for(&config, Some(&own)) {
        Err(error) => {
            assert!(error.contains("derive node name"));
            return;
        }
        Ok(peers) => Arc::new(peers),
    };
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(std::sync::Mutex::new(
        rusqlite::Connection::open_in_memory().unwrap(),
    ));
    storage::init_db(&db.lock().unwrap()).unwrap();
    let (hub_cert, hub_key) = roots.cert_key(false, "spiffe://example.org/host/hub/user/fleet");
    let hub = node_state(
        "fleet.hub",
        before,
        hub_cert.clone(),
        hub_key.clone(),
        db.clone(),
        dir.path(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = hub.clone();
    let task =
        tokio::spawn(async move { xmsg::fed::run_fed_listener(listener, state).await.unwrap() });
    let (cert, key) = roots.cert_key(false, "spiffe://fleet.org/host/x/user/sini");
    let fleet = node_state(
        "sini.x",
        leaf_peers(&roots, addr),
        cert,
        key,
        Arc::new(std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        )),
        dir.path(),
    );
    assert!(xmsg::fed::get_federated_inbox(&fleet, "fleet.hub", 0)
        .await
        .unwrap()
        .is_none());
    for body in ["fleet row one", "fleet row two"] {
        let envelope = FedEnvelope {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            origin: storage::Origin::service("test", "fleet.hub"),
            to: FedTarget {
                r#ref: "worker".into(),
            },
            body: body.into(),
            thread_id: "".into(),
            created_at: storage::now_epoch_secs(),
            forwarded: None,
            attachments: vec![],
        };
        xmsg::fed::send_federated_message(&hub, "sini.x", &envelope)
            .await
            .unwrap();
    }
    task.abort();
    let _ = task.await;
    let after = Arc::new(PeersMap::load_from_json_for(&config, Some(&own)).unwrap());
    assert!(after.get_peer_config("sini.x").is_none());
    let hub = node_state("fleet.hub", after, hub_cert, hub_key, db, dir.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = hub.clone();
    let task =
        tokio::spawn(async move { xmsg::fed::run_fed_listener(listener, state).await.unwrap() });
    let (cert, key) = roots.cert_key(true, "spiffe://enroll.org/host/x/user/sini");
    let attacker = node_state(
        "sini.x",
        leaf_peers(&roots, addr),
        cert,
        key,
        Arc::new(std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        )),
        dir.path(),
    );
    let mut stolen = Vec::new();
    for _ in 0..2 {
        let Some(FedInboxItem::Message(row)) =
            xmsg::fed::get_federated_inbox(&attacker, "fleet.hub", 0)
                .await
                .unwrap()
        else {
            panic!("takeover did not reach queued fleet row")
        };
        stolen.push(row.body);
        xmsg::fed::ack_federated_inbox(&attacker, "fleet.hub", &row.id)
            .await
            .unwrap();
    }
    task.abort();
    let _ = task.await;
    stolen.sort();
    assert_eq!(stolen, vec!["fleet row one", "fleet row two"]);
    panic!("cross-bundle restart takeover observed: enrollment client pulled two fleet rows");
}

#[tokio::test]
async fn queue_classifies_admitted_and_concrete_leaves_for_global_budget() {
    use xmsg::fed::{FedEnvelope, FedTarget};
    let roots = Roots::new();
    let dir = tempfile::tempdir().unwrap();
    let pat = "spiffe://example.org/host/*/user/carol";
    let config = json!({"peers":{"bob.lap":{"ca":roots.enroll,"identities":["spiffe://example.org/host/lap/user/bob"],"leaf":true,"allow":["send"]}},"hub":{"patterns":[{"pattern":pat,"ca":roots.enroll}],"rules":[{"pattern":pat,"allow":["send"],"leaf":true}]}});
    let peers = Arc::new(PeersMap::load_from_json(&config.to_string()).unwrap());
    let cert = roots.cert(true, "spiffe://example.org/host/lap/user/carol");
    peers.resolve_incoming_peer(&cert, &[]).unwrap();
    let db = Arc::new(std::sync::Mutex::new(
        rusqlite::Connection::open_in_memory().unwrap(),
    ));
    storage::init_db(&db.lock().unwrap()).unwrap();
    storage::set_admitted_mailbox_limits(
        &db,
        PeerMailboxLimits {
            max_rows: 0,
            max_bytes: 0,
        },
    );
    let (cert, key) = roots.cert_key(false, "spiffe://example.org/host/hub/user/fleet");
    let hub = node_state("fleet.hub", peers, cert, key, db, dir.path());
    let envelope = FedEnvelope {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        origin: storage::Origin::service("test", "fleet.hub"),
        to: FedTarget {
            r#ref: "worker".into(),
        },
        body: "concrete exemption".into(),
        thread_id: "".into(),
        created_at: storage::now_epoch_secs(),
        forwarded: None,
        attachments: vec![],
    };
    assert!(
        xmsg::fed::send_federated_message(&hub, "carol.lap", &envelope)
            .await
            .is_err(),
        "admitted queue bypassed aggregate budget"
    );
    assert!(
        xmsg::fed::send_federated_message(&hub, "bob.lap", &envelope)
            .await
            .is_ok(),
        "concrete leaf counted toward aggregate budget"
    );
    assert_eq!(
        hub.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT admitted FROM peer_mailbox WHERE peer='bob.lap'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}
