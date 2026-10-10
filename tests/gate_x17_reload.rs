use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UnixListener};

use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::fed::{
    run_fed_listener, send_federated_message, CredentialReloader, FedEnvelope, FedPrincipal,
    FedState, FedTarget, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::pi::new_pi_store;
use xmsg::storage;
use xmsg::svc::new_svc_store;

fn generate_ca(name: &str) -> (rcgen::CertificateParams, rcgen::KeyPair, Vec<u8>, String) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    let pem = cert.pem();
    (params, key, der, pem)
}

fn issue_cert(
    ca_params: &rcgen::CertificateParams,
    ca_key: &rcgen::KeyPair,
    name: &str,
    uri_sans: &[&str],
) -> (Vec<u8>, Vec<u8>, String, String) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.subject_alt_names = uri_sans
        .iter()
        .map(|u| rcgen::SanType::URI(u.to_string().try_into().unwrap()))
        .collect();
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
    let cert = params.signed_by(&key, &issuer).unwrap();
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_der = key.serialize_der();
    let key_pem = key.serialize_pem();
    (cert_der, key_der, cert_pem, key_pem)
}

#[allow(dead_code)]
struct TestReloaderNode {
    name: String,
    fed_addr: SocketAddr,
    fed_state: Arc<FedState>,
    reloader: Arc<CredentialReloader>,
    cert_path: PathBuf,
    key_path: PathBuf,
    ca_paths: HashMap<String, PathBuf>,
    sessions_dir: PathBuf,
    _temp: TempDir,
}

async fn create_reloader_node(
    name: &str,
    mut peers: HashMap<String, PeerConfig>,
    cert_pem: &str,
    key_pem: &str,
    ca_pem_map: HashMap<String, String>,
) -> TestReloaderNode {
    let temp = TempDir::new().unwrap();
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_root = temp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();
    let proc_locks = temp.path().join("locks");
    fs::create_dir_all(&proc_locks).unwrap();

    let cert_path = temp.path().join("fed-cert.pem");
    let key_path = temp.path().join("fed-key.pem");
    fs::write(&cert_path, cert_pem).unwrap();
    fs::write(&key_path, key_pem).unwrap();

    let mut ca_paths = HashMap::new();
    for (peer_name, ca_content) in ca_pem_map {
        let ca_file = temp.path().join(format!("{peer_name}-ca.pem"));
        fs::write(&ca_file, ca_content).unwrap();
        if let Some(peer_config) = peers.get_mut(&peer_name) {
            peer_config.ca = Some(ca_file.clone());
        }
        ca_paths.insert(peer_name, ca_file);
    }

    let peers_map = PeersMap::new(peers);
    let peers_arc = Arc::new(peers_map);

    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root,
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
    };
    let agy_store = new_agy_store();
    let pi_store = new_pi_store();
    let svc_store = new_svc_store();

    let fed_state = Arc::new(FedState {
        host_label: name.to_string(),
        peers: peers_arc.clone(),
        cert_der: Vec::new(),
        cert_chain_der: Vec::new(),
        key_der: Vec::new(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db,
        sessions_dir: sessions_dir.clone(),
        agy_config,
        agy_store,
        pi_store,
        pi_notify_tx,
        svc_store,
        svc_notify_tx,
        notify_tx,
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
    });

    let reloader = Arc::new(
        CredentialReloader::new(
            cert_path.clone(),
            key_path.clone(),
            peers_arc,
            fed_state.dynamic_tls.clone(),
        )
        .unwrap(),
    );

    let fed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fed_addr = fed_listener.local_addr().unwrap();
    let fs_clone = fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(fed_listener, fs_clone).await;
    });

    TestReloaderNode {
        name: name.to_string(),
        fed_addr,
        fed_state,
        reloader,
        cert_path,
        key_path,
        ca_paths,
        sessions_dir,
        _temp: temp,
    }
}

fn create_claude_session_fixture(
    sessions_dir: &Path,
    session_id: &str,
    name: &str,
) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let sock_path = sessions_dir.join(format!("inbox-{session_id}.sock"));
    let listener = UnixListener::bind(&sock_path).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = received.clone();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    let my_pid = std::process::id();
    let live_proc = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&live_proc, my_pid).unwrap_or_else(|_| "1000".to_string());
    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": session_id,
        "name": name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": sock_path.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}-{session_id}.json")),
        session_json.to_string(),
    )
    .unwrap();

    (sock_path, received)
}

fn make_envelope(target: &str, body: &str) -> FedEnvelope {
    FedEnvelope {
        v: 1,
        id: format!("msg-{}", ulid::Ulid::new()),
        principal: FedPrincipal::Session {
            harness: "claude".to_string(),
            session_id: "test-sess".to_string(),
            name: "test-sender".to_string(),
        },
        to: FedTarget {
            r#ref: target.to_string(),
        },
        body: body.to_string(),
        push_replies: false,
        thread_id: format!("thr-{}", ulid::Ulid::new()),
        created_at: 1000,
    }
}

// -----------------------------------------------------------------------------
// Oracle 1: Cert+key rotation on disk from same CA presented on new outbound connection
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_1_outbound_presents_reloaded_cert() {
    let (_ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test Root CA 1");

    let uri_a_v1 = "spiffe://example.org/ns/test/sa/node-a-v1";
    let (_der_a1, _key_a1, cert_a1_pem, key_a1_pem) =
        issue_cert(&_ca_params, &ca_key, "node-a", &[uri_a_v1]);

    let uri_a_v2 = "spiffe://example.org/ns/test/sa/node-a-v2";
    let (_der_a2, _key_a2, cert_a2_pem, key_a2_pem) =
        issue_cert(&_ca_params, &ca_key, "node-a", &[uri_a_v2]);

    let uri_b = "spiffe://example.org/ns/test/sa/node-b";
    let (_der_b, _key_b, cert_b_pem, key_b_pem) =
        issue_cert(&_ca_params, &ca_key, "node-b", &[uri_b]);

    // Node B only accepts node-a with URI SAN v2
    let mut b_peers = HashMap::new();
    b_peers.insert(
        "node-a".to_string(),
        PeerConfig {
            name: "node-a".to_string(),
            address: "127.0.0.1:1".to_string(),
            pin: None,
            ca: None,
            identities: Some(vec![uri_a_v2.to_string()]),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        },
    );
    let mut b_ca_map = HashMap::new();
    b_ca_map.insert("node-a".to_string(), ca_pem.clone());

    let node_b = create_reloader_node("node-b", b_peers, &cert_b_pem, &key_b_pem, b_ca_map).await;
    let (_b_sock, b_received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-b", "recipient-b");

    // Node A connects to Node B
    let mut a_peers = HashMap::new();
    a_peers.insert(
        "node-b".to_string(),
        PeerConfig {
            name: "node-b".to_string(),
            address: node_b.fed_addr.to_string(),
            pin: None,
            ca: None,
            identities: Some(vec![uri_b.to_string()]),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        },
    );
    let mut a_ca_map = HashMap::new();
    a_ca_map.insert("node-b".to_string(), ca_pem.clone());

    let node_a = create_reloader_node("node-a", a_peers, &cert_a1_pem, &key_a1_pem, a_ca_map).await;

    // 1. Initial attempt: Node A presents cert v1, but Node B only allows v2 => rejected!
    let envelope1 = make_envelope("recipient-b", "hello v1");
    let res1 = send_federated_message(&node_a.fed_state, "node-b", &envelope1).await;
    assert!(
        res1.is_err(),
        "Node B must reject Node A presenting cert v1: {:?}",
        res1
    );

    // 2. Rotate Node A's cert and key on disk to v2
    fs::write(&node_a.cert_path, cert_a2_pem).unwrap();
    fs::write(&node_a.key_path, key_a2_pem).unwrap();

    // 3. Trigger reload
    let reloaded = node_a.reloader.check_and_reload().unwrap();
    assert!(reloaded, "check_and_reload must detect file changes");

    // 4. Send again on new outbound connection without restart: Node A presents cert v2 => accepted!
    let envelope2 = make_envelope("recipient-b", "hello v2");
    let res2 = send_federated_message(&node_a.fed_state, "node-b", &envelope2).await;
    assert!(
        res2.is_ok(),
        "Node B must accept Node A presenting reloaded cert v2: {:?}",
        res2
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = b_received.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].contains("hello v2"));
}

// -----------------------------------------------------------------------------
// Oracle 2: Peer CA bundle replacement with different CA refuses old CA certs
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_2_peer_ca_bundle_reload_refuses_old_ca() {
    let (ca1_params, ca1_key, _ca1_der, ca1_pem) = generate_ca("Test Root CA 1");
    let (_ca2_params, _ca2_key, _ca2_der, ca2_pem) = generate_ca("Test Root CA 2");

    let uri_a = "spiffe://example.org/ns/test/sa/node-a";
    let (_der_a, _key_a, cert_a_pem, key_a_pem) =
        issue_cert(&ca1_params, &ca1_key, "node-a", &[uri_a]);

    let uri_b = "spiffe://example.org/ns/test/sa/node-b";
    let (_der_b, _key_b, cert_b_pem, key_b_pem) =
        issue_cert(&ca1_params, &ca1_key, "node-b", &[uri_b]);

    // Node A initially trusts CA 1 for node-b
    let mut a_peers = HashMap::new();
    a_peers.insert(
        "node-b".to_string(),
        PeerConfig {
            name: "node-b".to_string(),
            address: "127.0.0.1:1".to_string(),
            pin: None,
            ca: None,
            identities: Some(vec![uri_b.to_string()]),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        },
    );
    let mut a_ca_map = HashMap::new();
    a_ca_map.insert("node-b".to_string(), ca1_pem.clone());

    let node_a = create_reloader_node("node-a", a_peers, &cert_a_pem, &key_a_pem, a_ca_map).await;
    let (_a_sock, a_received) =
        create_claude_session_fixture(&node_a.sessions_dir, "sess-a", "recipient-a");

    // Node B connects to Node A
    let mut b_peers = HashMap::new();
    b_peers.insert(
        "node-a".to_string(),
        PeerConfig {
            name: "node-a".to_string(),
            address: node_a.fed_addr.to_string(),
            pin: None,
            ca: None,
            identities: Some(vec![uri_a.to_string()]),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        },
    );
    let mut b_ca_map = HashMap::new();
    b_ca_map.insert("node-a".to_string(), ca1_pem.clone());

    let node_b = create_reloader_node("node-b", b_peers, &cert_b_pem, &key_b_pem, b_ca_map).await;

    // 1. Initial inbound connection: Node B presents CA 1 cert => Node A accepts!
    let envelope1 = make_envelope("recipient-a", "first msg under ca1");
    let res1 = send_federated_message(&node_b.fed_state, "node-a", &envelope1).await;
    assert!(
        res1.is_ok(),
        "Initial send under CA 1 must succeed: {:?}",
        res1
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(a_received.lock().unwrap().len(), 1);

    // 2. Replace Node B's CA bundle on Node A's disk with CA 2
    let b_ca_file = node_a.ca_paths.get("node-b").unwrap();
    fs::write(b_ca_file, ca2_pem).unwrap();

    // 3. Trigger reload on Node A
    let reloaded = node_a.reloader.check_and_reload().unwrap();
    assert!(
        reloaded,
        "check_and_reload must detect CA bundle file change"
    );

    // 4. Node B presents old CA 1 cert on new connection => Node A must refuse!
    let envelope2 = make_envelope("recipient-a", "second msg under ca1");
    let res2 = send_federated_message(&node_b.fed_state, "node-a", &envelope2).await;
    assert!(
        res2.is_err(),
        "Node A must refuse connection signed by old CA 1 after CA 2 reload: {:?}",
        res2
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    // Inbox count unchanged
    assert_eq!(a_received.lock().unwrap().len(), 1);
}

// -----------------------------------------------------------------------------
// Oracle 3: Invalid cert (garbage) keeps old configuration working and logs error
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_3_garbage_cert_preserves_old_config() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test Root CA 1");

    let uri_a = "spiffe://example.org/ns/test/sa/node-a";
    let (_der_a, _key_a, cert_a_pem, key_a_pem) =
        issue_cert(&ca_params, &ca_key, "node-a", &[uri_a]);

    let uri_b = "spiffe://example.org/ns/test/sa/node-b";
    let (_der_b, _key_b, cert_b_pem, key_b_pem) =
        issue_cert(&ca_params, &ca_key, "node-b", &[uri_b]);

    let mut b_peers = HashMap::new();
    b_peers.insert(
        "node-a".to_string(),
        PeerConfig {
            name: "node-a".to_string(),
            address: "127.0.0.1:1".to_string(),
            pin: None,
            ca: None,
            identities: Some(vec![uri_a.to_string()]),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        },
    );
    let mut b_ca_map = HashMap::new();
    b_ca_map.insert("node-a".to_string(), ca_pem.clone());

    let node_b = create_reloader_node("node-b", b_peers, &cert_b_pem, &key_b_pem, b_ca_map).await;
    let (_b_sock, b_received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-b", "recipient-b");

    let mut a_peers = HashMap::new();
    a_peers.insert(
        "node-b".to_string(),
        PeerConfig {
            name: "node-b".to_string(),
            address: node_b.fed_addr.to_string(),
            pin: None,
            ca: None,
            identities: Some(vec![uri_b.to_string()]),
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        },
    );
    let mut a_ca_map = HashMap::new();
    a_ca_map.insert("node-b".to_string(), ca_pem.clone());

    let node_a = create_reloader_node("node-a", a_peers, &cert_a_pem, &key_a_pem, a_ca_map).await;

    // 1. Initial delivery succeeds
    let envelope1 = make_envelope("recipient-b", "msg 1");
    let res1 = send_federated_message(&node_a.fed_state, "node-b", &envelope1).await;
    assert!(res1.is_ok(), "Initial send must succeed: {:?}", res1);

    // 2. Overwrite Node A's cert with invalid garbage
    fs::write(
        &node_a.cert_path,
        b"-----BEGIN CERTIFICATE-----\nINVALID GARBAGE NOT DER\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    // 3. Trigger reload: must return Err and NOT swap in broken config
    let reload_res = node_a.reloader.check_and_reload();
    assert!(
        reload_res.is_err(),
        "check_and_reload must fail on garbage cert"
    );

    // 4. Old valid config still active: Node A can still send to Node B!
    let envelope2 = make_envelope("recipient-b", "msg 2 with old valid config");
    let res2 = send_federated_message(&node_a.fed_state, "node-b", &envelope2).await;
    assert!(
        res2.is_ok(),
        "Old configuration must continue working after failed reload: {:?}",
        res2
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = b_received.lock().unwrap();
    assert_eq!(msgs.len(), 2);
    assert!(msgs[1].contains("msg 2 with old valid config"));
}

// -----------------------------------------------------------------------------
// Oracle 4: Kubernetes-style symlink swap (..data -> new dir) is detected
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_4_k8s_symlink_swap_detected() {
    let (ca_params, ca_key, _ca_der, _ca_pem) = generate_ca("Test Root CA 1");

    let uri_v1 = "spiffe://example.org/ns/test/sa/node-v1";
    let (_der_v1, _key_v1, cert_v1_pem, key_v1_pem) =
        issue_cert(&ca_params, &ca_key, "node", &[uri_v1]);

    let uri_v2 = "spiffe://example.org/ns/test/sa/node-v2";
    let (_der_v2, _key_v2, cert_v2_pem, key_v2_pem) =
        issue_cert(&ca_params, &ca_key, "node", &[uri_v2]);

    let temp = TempDir::new().unwrap();
    let data_1 = temp.path().join("..data_1");
    let data_2 = temp.path().join("..data_2");
    fs::create_dir_all(&data_1).unwrap();
    fs::create_dir_all(&data_2).unwrap();

    // Populate data-1 (version 1)
    fs::write(data_1.join("cert.pem"), &cert_v1_pem).unwrap();
    fs::write(data_1.join("key.pem"), &key_v1_pem).unwrap();

    // Populate data-2 (version 2)
    fs::write(data_2.join("cert.pem"), &cert_v2_pem).unwrap();
    fs::write(data_2.join("key.pem"), &key_v2_pem).unwrap();

    // Create ..data symlink pointing to ..data_1
    let data_link = temp.path().join("..data");
    std::os::unix::fs::symlink(&data_1, &data_link).unwrap();

    // Create cert.pem and key.pem symlinks pointing into ..data
    let cert_symlink = temp.path().join("cert.pem");
    let key_symlink = temp.path().join("key.pem");
    std::os::unix::fs::symlink(data_link.join("cert.pem"), &cert_symlink).unwrap();
    std::os::unix::fs::symlink(data_link.join("key.pem"), &key_symlink).unwrap();

    // Record mtime of the symlink cert.pem
    let cert_link_meta_before = fs::symlink_metadata(&cert_symlink).unwrap();
    let mtime_before = cert_link_meta_before.modified().unwrap();

    let peers_map = Arc::new(PeersMap::new(HashMap::new()));
    let dyn_tls = Arc::new(std::sync::RwLock::new(None));

    let reloader = CredentialReloader::new(
        cert_symlink.clone(),
        key_symlink.clone(),
        peers_map,
        dyn_tls.clone(),
    )
    .unwrap();

    // Initial cert chain contains v1
    {
        let guard = dyn_tls.read().unwrap();
        let tls = guard.as_ref().unwrap();
        let sans = xmsg::fed::extract_uri_sans(&tls.cert_der).unwrap();
        assert_eq!(sans, vec![uri_v1]);
    }

    // Now perform Kubernetes atomic secret swap:
    // Create ..data_tmp -> ..data_2, then rename ..data_tmp -> ..data
    let data_tmp = temp.path().join("..data_tmp");
    std::os::unix::fs::symlink(&data_2, &data_tmp).unwrap();
    fs::rename(&data_tmp, &data_link).unwrap();

    // Verify the symlink cert.pem itself was NOT modified (mtime is unchanged)
    let cert_link_meta_after = fs::symlink_metadata(&cert_symlink).unwrap();
    let mtime_after = cert_link_meta_after.modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "Kubernetes symlink swap does not modify the cert.pem symlink metadata"
    );

    // Reloader MUST detect the change by reading file content hash through the symlink!
    let reloaded = reloader.check_and_reload().unwrap();
    assert!(
        reloaded,
        "Reloader must detect content change across Kubernetes symlink swap"
    );

    // Verify cert chain now contains v2
    {
        let guard = dyn_tls.read().unwrap();
        let tls = guard.as_ref().unwrap();
        let sans = xmsg::fed::extract_uri_sans(&tls.cert_der).unwrap();
        assert_eq!(sans, vec![uri_v2]);
    }
}

// -----------------------------------------------------------------------------
// Oracle 5: Background watcher ticks and reloads automatically on interval
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_5_background_watcher_polls_and_reloads() {
    let (ca_params, ca_key, _ca_der, _ca_pem) = generate_ca("Test Root CA 1");

    let uri_v1 = "spiffe://example.org/ns/test/sa/node-v1";
    let (_der_v1, _key_v1, cert_v1_pem, key_v1_pem) =
        issue_cert(&ca_params, &ca_key, "node", &[uri_v1]);

    let uri_v2 = "spiffe://example.org/ns/test/sa/node-v2";
    let (_der_v2, _key_v2, cert_v2_pem, key_v2_pem) =
        issue_cert(&ca_params, &ca_key, "node", &[uri_v2]);

    let temp = TempDir::new().unwrap();
    let cert_path = temp.path().join("cert.pem");
    let key_path = temp.path().join("key.pem");
    fs::write(&cert_path, &cert_v1_pem).unwrap();
    fs::write(&key_path, &key_v1_pem).unwrap();

    let peers_map = Arc::new(PeersMap::new(HashMap::new()));
    let dyn_tls = Arc::new(std::sync::RwLock::new(None));

    let reloader = Arc::new(
        CredentialReloader::new(
            cert_path.clone(),
            key_path.clone(),
            peers_map,
            dyn_tls.clone(),
        )
        .unwrap(),
    );

    // Start background watcher with 30ms interval
    let watcher_handle = reloader.start_watcher(Duration::from_millis(30));

    // Initially cert is v1
    {
        let guard = dyn_tls.read().unwrap();
        let tls = guard.as_ref().unwrap();
        let sans = xmsg::fed::extract_uri_sans(&tls.cert_der).unwrap();
        assert_eq!(sans, vec![uri_v1]);
    }

    // Overwrite files on disk with v2
    fs::write(&cert_path, &cert_v2_pem).unwrap();
    fs::write(&key_path, &key_v2_pem).unwrap();

    // Poll until background watcher has reloaded (up to 1s)
    let start = std::time::Instant::now();
    let mut reloaded = false;
    while start.elapsed() < Duration::from_secs(1) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let guard = dyn_tls.read().unwrap();
        if let Some(ref tls) = *guard {
            let sans = xmsg::fed::extract_uri_sans(&tls.cert_der).unwrap();
            if sans == vec![uri_v2] {
                reloaded = true;
                break;
            }
        }
    }

    assert!(
        reloaded,
        "Background watcher must reload credentials automatically on interval"
    );
    watcher_handle.abort();
}
