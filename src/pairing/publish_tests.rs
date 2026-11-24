//! Policy generations published by `CredentialReloader` from the pairing store.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Barrier, Mutex};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use tempfile::TempDir;

use super::*;
use crate::pairing::auth::{device_id_from_pin, DeviceId};
use crate::pairing::store;

struct Node {
    dir: TempDir,
    peer_cert: Vec<u8>,
    peer_id: DeviceId,
    fs: Arc<FedState>,
    reloader: Arc<CredentialReloader>,
}

fn peers_json(pin: &str, extra: &str) -> String {
    format!(
        r#"{{"laptop": {{"address": "192.0.2.9:7788", "pin": "{pin}", "allow": ["send"]}}}}{extra}"#
    )
}

fn fed_state(dir: &TempDir, peers: Arc<PeersMap>, cert: &[u8], key: &[u8]) -> Arc<FedState> {
    let conn = rusqlite::Connection::open(dir.path().join("xmsg.db")).unwrap();
    crate::storage::init_db(&conn).unwrap();
    Arc::new(FedState {
        discovery: Default::default(),
        node_name: crate::node::node_name_from_cert(cert).unwrap(),
        peers: peers.into(),
        cert_der: cert.to_vec(),
        cert_chain_der: Vec::new(),
        key_der: key.to_vec(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: Arc::new(Mutex::new(conn)),
        sessions_dirs: vec![dir.path().join("sessions")],
        agy_config: crate::agy::AgyConfig::default(),
        agy_store: crate::agy::new_agy_store(),
        pi_store: crate::pi::new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: crate::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        notify_tx: tokio::sync::broadcast::channel(16).0,
        max_body: 65536,
        max_attachment_bytes: 8 * 1024 * 1024,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    })
}

/// Starts a node the way `serve` does: load the peers file, cancel open intents, apply the
/// store, then build the reloader, whose first check installs the first generation.
fn start(dir: TempDir, peer_cert: Vec<u8>, peer_id: DeviceId) -> Node {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_pem = std::fs::read(dir.path().join("cert.pem")).unwrap();
    let cert = CertificateDer::pem_slice_iter(&cert_pem)
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let peers_path = dir.path().join("peers.json");
    let mut peers = PeersMap::load_from_file(&peers_path).unwrap();
    let probe = rusqlite::Connection::open(dir.path().join("xmsg.db")).unwrap();
    crate::storage::init_db(&probe).unwrap();
    cancel_pairing_intents(&probe).unwrap();
    peers.apply_pairing_authority(&probe, &cert).unwrap();
    drop(probe);
    let fs = fed_state(&dir, Arc::new(peers.clone()), &cert, &[]);
    let reloader = Arc::new(
        CredentialReloader::new_full(
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
            Some(peers_path),
            None,
            Arc::new(peers),
            Some(fs.clone()),
            Default::default(),
        )
        .unwrap(),
    );
    Node {
        dir,
        peer_cert,
        peer_id,
        fs,
        reloader,
    }
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem, _) = generate_self_signed_ed25519_pem("own").unwrap();
    std::fs::write(dir.path().join("cert.pem"), cert_pem).unwrap();
    std::fs::write(dir.path().join("key.pem"), key_pem).unwrap();
    let (peer_cert, _, peer_pin) = generate_self_signed_ed25519("laptop").unwrap();
    std::fs::write(dir.path().join("peers.json"), peers_json(&peer_pin, "")).unwrap();
    let peer_id = device_id_from_pin(&peer_pin).unwrap();
    start(dir, peer_cert, peer_id)
}

impl Node {
    fn block(&self) -> u64 {
        let conn = self.fs.db.lock().unwrap();
        store::block_device(&conn, &self.peer_id, 0).unwrap()
    }

    fn committed(&self) -> u64 {
        store::authority_revision(&self.fs.db.lock().unwrap()).unwrap()
    }

    fn denied(&self) -> bool {
        let leaf = LeafAuthority::from_certificate(
            &CertificateDer::from(self.peer_cert.clone()),
            AdmissionMode::Pin,
        )
        .unwrap();
        let current = self.fs.current_peers();
        leaf.check(&current).is_err()
            && current
                .check_certificate_deny(&CertificateDer::from(self.peer_cert.clone()))
                .is_err()
    }

    fn restart(self) -> Node {
        let Node {
            dir,
            peer_cert,
            peer_id,
            fs,
            reloader,
        } = self;
        drop(reloader);
        drop(fs);
        start(dir, peer_cert, peer_id)
    }

    fn rewrite_peers(&self, content: &str) {
        std::fs::write(self.dir.path().join("peers.json"), content).unwrap();
    }
}

#[test]
fn a_block_on_a_pinned_key_wins_at_the_next_generation_and_survives_reload_and_restart() {
    let node = node();
    assert!(
        !node.denied(),
        "the pinned key was refused before any block"
    );
    assert_eq!(node.reloader.installed_revision(), node.committed());
    let revision = node.block();
    assert!(!node.denied(), "an uninstalled block took effect early");
    // A watcher tick with no file change publishes the store change.
    assert!(node.reloader.check_and_reload().unwrap());
    assert!(
        node.denied(),
        "the block did not reach the installed generation"
    );
    assert_eq!(node.reloader.installed_revision(), revision);
    assert_eq!(node.fs.current_peers().authority_revision, revision);

    // A file rebuild keeps it.
    let pin = format!("sha256:{}", hex::encode(node.peer_id));
    node.rewrite_peers(&format!("{}\n", peers_json(&pin, "")));
    assert!(node.reloader.check_and_reload().unwrap());
    assert!(node.denied(), "a file rebuild dropped the block");

    let node = node.restart();
    assert!(node.denied(), "the block did not survive a restart");
    assert_eq!(node.reloader.installed_revision(), node.committed());
}

#[test]
fn a_store_change_publishes_from_last_good_inputs_while_the_peers_file_is_invalid() {
    let node = node();
    node.rewrite_peers("{ not json");
    let before = node.fs.current_peers();
    node.block();
    assert!(
        node.reloader.check_and_reload().is_err(),
        "an invalid peers file was accepted"
    );
    assert!(
        node.denied(),
        "the block waited on a parse of the peers file"
    );
    let after = node.fs.current_peers();
    assert_eq!(
        format!("{:?}", after.get("laptop")),
        format!("{:?}", before.get("laptop")),
        "file rights changed"
    );
    assert_eq!(node.reloader.installed_revision(), node.committed());
}

#[test]
fn an_unreadable_store_keeps_the_previous_generation_installed() {
    let node = node();
    let before = node.fs.current_peers();
    let installed = node.reloader.installed_revision();
    node.fs
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TABLE pairing_device_blocks; DROP TABLE pairing_meta;")
        .unwrap();
    assert!(
        node.reloader.force_reload().is_err(),
        "an unreadable store installed a generation"
    );
    assert!(
        Arc::ptr_eq(&before, &node.fs.current_peers()),
        "the installed generation changed"
    );
    assert_eq!(node.reloader.installed_revision(), installed);
    let health = store::health(Some(&node.fs));
    assert!(health["error"].is_string(), "{health}");
    assert_eq!(health["installed_revision"], installed);
}

#[test]
fn a_generation_older_than_the_installed_one_is_refused_and_records_nothing() {
    let node = node();
    node.block();
    node.reloader.publish_store().unwrap();
    let installed = node.reloader.installed_revision();
    assert!(installed >= 1);
    let inputs = node.reloader.last_good().unwrap();
    let mut stale = inputs.peers.clone();
    stale.authority_revision = installed - 1;
    let dyn_tls = node.reloader.build_from_inputs(&inputs, &stale).unwrap();
    let hashes = node.reloader.file_hashes.lock().unwrap().clone();
    let before = node.fs.current_peers();
    let mut new_hashes = hashes.clone();
    new_hashes.insert(PathBuf::from("/changed"), vec![1]);
    assert!(
        !node
            .reloader
            .install(&stale, dyn_tls, Some(new_hashes), None),
        "an older store snapshot was installed"
    );
    assert!(Arc::ptr_eq(&before, &node.fs.current_peers()));
    assert!(
        node.denied(),
        "the stale generation re-authorized a blocked key"
    );
    assert_eq!(
        *node.reloader.file_hashes.lock().unwrap(),
        hashes,
        "a refused install recorded hashes"
    );
}

#[test]
fn a_store_publication_waits_for_a_file_rebuild_holding_an_older_snapshot() {
    let node = node();
    let snapshot_taken = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let armed = Arc::new(AtomicBool::new(true));
    {
        let (taken, release, armed) = (snapshot_taken.clone(), release.clone(), armed.clone());
        *node.reloader.after_snapshot.lock().unwrap() = Some(Arc::new(move || {
            if armed.swap(false, Ordering::SeqCst) {
                taken.wait();
                release.wait();
            }
        }));
    }
    let file_rebuild = {
        let reloader = node.reloader.clone();
        std::thread::spawn(move || reloader.force_reload())
    };
    snapshot_taken.wait();
    // The rebuild holds a snapshot from before this block.
    let revision = node.block();
    let published = Arc::new(AtomicBool::new(false));
    let store_publication = {
        let (reloader, published) = (node.reloader.clone(), published.clone());
        std::thread::spawn(move || {
            let result = reloader.publish_store();
            published.store(true, Ordering::SeqCst);
            result
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !published.load(Ordering::SeqCst),
        "a store publication ran while a file rebuild held the publication"
    );
    release.wait();
    file_rebuild.join().unwrap().unwrap();
    store_publication.join().unwrap().unwrap();
    assert_eq!(node.reloader.installed_revision(), revision);
    assert!(
        node.denied(),
        "the older snapshot's generation outlived the block"
    );
}

#[test]
fn unblock_proves_against_the_installed_file_policy_under_the_publication() {
    let node = node();
    node.block();
    node.reloader.check_and_reload().unwrap();
    let refused = node.reloader.unblock_device(&node.peer_id);
    assert!(refused.is_err(), "unblock restored a peers-file pin");
    assert!(node.denied());
    // Once the file's own deny dominates the pin, the lift restores nothing.
    let pin = format!("sha256:{}", hex::encode(node.peer_id));
    node.rewrite_peers(&format!(
        r#"{{"peers": {}, "deny": {{"spkis": ["{}"]}}}}"#,
        peers_json(&pin, ""),
        hex::encode(node.peer_id)
    ));
    node.reloader.check_and_reload().unwrap();
    let revision = node.reloader.unblock_device(&node.peer_id).unwrap();
    assert_eq!(node.reloader.installed_revision(), revision);
    assert!(node.denied(), "the file deny stopped applying");
    let conn = node.fs.db.lock().unwrap();
    assert!(!store::blocked_devices(&conn)
        .unwrap()
        .contains(&node.peer_id));
}

#[test]
fn a_file_rebuild_imports_a_new_pin_and_records_the_snapshot_revision() {
    let node = node();
    let own = device_id_from_pin(
        &spki_sha256_from_der(&node.reloader.last_good().unwrap().certs[0]).unwrap(),
    )
    .unwrap();
    let (_, _, second_pin) = generate_self_signed_ed25519("desk").unwrap();
    let second = device_id_from_pin(&second_pin).unwrap();
    let pin = format!("sha256:{}", hex::encode(node.peer_id));
    let mut peers: serde_json::Value = serde_json::from_str(&peers_json(&pin, "")).unwrap();
    peers["desk"] =
        serde_json::json!({"address": "192.0.2.10:7788", "pin": second_pin, "allow": ["reply"]});
    node.rewrite_peers(&peers.to_string());
    assert!(node.reloader.check_and_reload().unwrap());
    let conn = node.fs.db.lock().unwrap();
    let grants = store::grants_for(&conn, &own, &second).unwrap();
    assert_eq!(grants.len(), 1, "the reload did not import the new pin");
    assert_eq!(
        node.fs.current_peers().authority_revision,
        store::authority_revision(&conn).unwrap(),
        "the installed generation does not carry its snapshot revision"
    );
}
