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
use xmsg::error::AppError;
use xmsg::fed::{
    parse_ca_bundle_pem, run_fed_listener, send_federated_message, FedEnvelope, FedPrincipal,
    FedState, FedTarget, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::pi::new_pi_store;
use xmsg::storage;
use xmsg::svc::new_svc_store;

fn generate_non_ca(name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::NoCa;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let cert = params.self_signed(&key).unwrap();
    cert.pem()
}

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
    dates: Option<(i32, u8, u8, i32, u8, u8)>,
) -> (Vec<u8>, Vec<u8>) {
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
    if let Some((y1, m1, d1, y2, m2, d2)) = dates {
        params.not_before = rcgen::date_time_ymd(y1, m1, d1);
        params.not_after = rcgen::date_time_ymd(y2, m2, d2);
    }
    let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
    let cert = params.signed_by(&key, &issuer).unwrap();
    (cert.der().to_vec(), key.serialize_der())
}

#[allow(dead_code)]
struct TestFedNode {
    name: String,
    fed_addr: SocketAddr,
    fed_state: Arc<FedState>,
    sessions_dir: PathBuf,
    _temp: TempDir,
}

async fn create_test_node(
    name: &str,
    peers_map: PeersMap,
    cert_der: Vec<u8>,
    cert_chain_der: Vec<Vec<u8>>,
    key_der: Vec<u8>,
) -> TestFedNode {
    let temp = TempDir::new().unwrap();
    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_root = temp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();
    let proc_locks = temp.path().join("locks");
    fs::create_dir_all(&proc_locks).unwrap();

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
        peers: Arc::new(peers_map),
        cert_der,
        cert_chain_der,
        key_der,
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
    });

    let fed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fed_addr = fed_listener.local_addr().unwrap();
    let fs_clone = fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(fed_listener, fs_clone).await;
    });

    TestFedNode {
        name: name.to_string(),
        fed_addr,
        fed_state,
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
// Oracle 1: CA peer, cert chaining to bundle with allowed URI => accepted and delivered
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_1_ca_peer_accepted_and_delivered() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test Root CA 1");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let uri_a = "spiffe://example.org/ns/test/sa/client-a";
    let (cert_a, key_a) = issue_cert(&ca_params, &ca_key, "client-a", &[uri_a], None);
    let (cert_b, key_b) = issue_cert(
        &ca_params,
        &ca_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![uri_a.to_string()]),
                allow: vec!["send".to_string(), "reply".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, cert_b, Vec::new(), key_b).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string(), "reply".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    let node_a = create_test_node("client-a", a_peers, cert_a, Vec::new(), key_a).await;

    let envelope = make_envelope("claude:sess-target", "hello ca federation");
    let res = send_federated_message(&node_a.fed_state, "server-b", &envelope).await;
    assert!(res.is_ok(), "Expected send to succeed, got: {res:?}");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "Expected 1 message delivered to target");
    assert!(msgs[0].contains("hello ca federation"));
}

// -----------------------------------------------------------------------------
// Oracle 2: Cert from different CA, same URI => refused at handshake
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_2_different_ca_refused() {
    let (ca1_params, ca1_key, _ca1_der, ca1_pem) = generate_ca("Test CA 1");
    let (ca2_params, ca2_key, _ca2_der, _ca2_pem) = generate_ca("Test CA 2 (Untrusted)");

    let anchors1 = parse_ca_bundle_pem(ca1_pem.as_bytes()).unwrap();

    let uri = "spiffe://example.org/ns/test/sa/common-uri";
    // Client has cert from CA 2
    let (cert_a, key_a) = issue_cert(&ca2_params, &ca2_key, "client-a", &[uri], None);
    let (cert_b, key_b) = issue_cert(
        &ca1_params,
        &ca1_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    // Server B trusts CA 1
    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca1.pem")),
                identities: Some(vec![uri.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors1.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, cert_b, Vec::new(), key_b).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca1.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors1,
        )
        .unwrap();

    let node_a = create_test_node("client-a", a_peers, cert_a, Vec::new(), key_a).await;

    let envelope = make_envelope("claude:sess-target", "untrusted CA send");
    let res = send_federated_message(&node_a.fed_state, "server-b", &envelope).await;
    assert!(
        res.is_err(),
        "Expected send from untrusted CA to fail handshake"
    );
    match res.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 0, "No messages should be delivered to target");
}

// -----------------------------------------------------------------------------
// Oracle 3: Right CA, URI not in identities => refused at handshake
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_3_uri_not_in_identities_refused() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test CA 3");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let presented_uri = "spiffe://example.org/ns/other/sa/unlisted";
    let allowed_uri = "spiffe://example.org/ns/allowed/sa/listed";

    let (cert_a, key_a) = issue_cert(&ca_params, &ca_key, "client-a", &[presented_uri], None);
    let (cert_b, key_b) = issue_cert(
        &ca_params,
        &ca_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![allowed_uri.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, cert_b, Vec::new(), key_b).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    let node_a = create_test_node("client-a", a_peers, cert_a, Vec::new(), key_a).await;

    let envelope = make_envelope("claude:sess-target", "wrong URI send");
    let res = send_federated_message(&node_a.fed_state, "server-b", &envelope).await;
    assert!(
        res.is_err(),
        "Expected send with non-matching URI to fail handshake"
    );
    match res.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 0, "No messages should be delivered to target");
}

// -----------------------------------------------------------------------------
// Oracle 4: Expired cert, and a not-yet-valid cert => refused
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_4_expired_and_not_yet_valid_refused() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test CA 4");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();
    let uri = "spiffe://example.org/ns/test/sa/time-test";

    // Expired cert: 2020 to 2021
    let (expired_cert, expired_key) = issue_cert(
        &ca_params,
        &ca_key,
        "expired-client",
        &[uri],
        Some((2020, 1, 1, 2021, 1, 1)),
    );

    // Not-yet-valid cert: 2035 to 2036
    let (future_cert, future_key) = issue_cert(
        &ca_params,
        &ca_key,
        "future-client",
        &[uri],
        Some((2035, 1, 1, 2036, 1, 1)),
    );

    let (server_cert, server_key) = issue_cert(
        &ca_params,
        &ca_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![uri.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, server_cert, Vec::new(), server_key).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    // 1. Test expired
    let expired_node = create_test_node(
        "client-a",
        a_peers.clone(),
        expired_cert,
        Vec::new(),
        expired_key,
    )
    .await;
    let envelope = make_envelope("claude:sess-target", "expired cert");
    let res_expired = send_federated_message(&expired_node.fed_state, "server-b", &envelope).await;
    assert!(
        res_expired.is_err(),
        "Expected expired cert to fail handshake"
    );
    match res_expired.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    // 2. Test future
    let future_node = create_test_node(
        "client-a",
        a_peers.clone(),
        future_cert,
        Vec::new(),
        future_key,
    )
    .await;
    let res_future = send_federated_message(&future_node.fed_state, "server-b", &envelope).await;
    assert!(
        res_future.is_err(),
        "Expected not-yet-valid cert to fail handshake"
    );
    match res_future.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        received.lock().unwrap().is_empty(),
        "No messages should be delivered by invalid certs"
    );

    // 3. Positive control: valid cert from ca_params succeeds and delivers
    let (valid_cert, valid_key) = issue_cert(&ca_params, &ca_key, "valid-client", &[uri], None);
    let valid_node = create_test_node("client-a", a_peers, valid_cert, Vec::new(), valid_key).await;
    let res_valid = send_federated_message(&valid_node.fed_state, "server-b", &envelope).await;
    assert!(
        res_valid.is_ok(),
        "Expected valid cert to succeed: {res_valid:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "Expected 1 message delivered by valid cert");
}

// -----------------------------------------------------------------------------
// Oracle 5: Zero URI SANs, and two URI SANs => refused
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_5_zero_and_two_uri_sans_refused() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test CA 5");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let uri1 = "spiffe://example.org/ns/test/sa/san-one";
    let uri2 = "spiffe://example.org/ns/test/sa/san-two";

    // 0 URI SANs
    let (zero_cert, zero_key) = issue_cert(&ca_params, &ca_key, "client-zero", &[], None);
    // 2 URI SANs
    let (two_cert, two_key) = issue_cert(&ca_params, &ca_key, "client-two", &[uri1, uri2], None);

    let (server_cert, server_key) = issue_cert(
        &ca_params,
        &ca_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![uri1.to_string(), uri2.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, server_cert, Vec::new(), server_key).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    // Test zero URI SANs
    let zero_node =
        create_test_node("client-a", a_peers.clone(), zero_cert, Vec::new(), zero_key).await;
    let envelope = make_envelope("claude:sess-target", "zero SANs");
    let res_zero = send_federated_message(&zero_node.fed_state, "server-b", &envelope).await;
    assert!(res_zero.is_err(), "Expected 0 URI SANs to fail handshake");
    match res_zero.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    // Test two URI SANs
    let two_node = create_test_node("client-a", a_peers, two_cert, Vec::new(), two_key).await;
    let res_two = send_federated_message(&two_node.fed_state, "server-b", &envelope).await;
    assert!(res_two.is_err(), "Expected 2 URI SANs to fail handshake");
    match res_two.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        received.lock().unwrap().is_empty(),
        "No messages should be delivered for invalid URI SAN count"
    );
}

// -----------------------------------------------------------------------------
// Oracle 6: Prefix `spiffe://t/ns/a/*` matches `spiffe://t/ns/a/sa/x`,
//           does NOT match `spiffe://t/ns/a` or `spiffe://t/ns/ab/sa/x`
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_6_prefix_wildcard_matching() {
    let pattern = "spiffe://t/ns/a/*";
    assert!(xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a/sa/x",
        pattern
    ));
    assert!(xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a/sub/nested/item",
        pattern
    ));
    assert!(!xmsg::fed::uri_matches_identity("spiffe://t/ns/a", pattern));
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a/",
        pattern
    ));
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/ab/sa/x",
        pattern
    ));
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/ab",
        pattern
    ));

    // P2: URI syntax tightening checks (spiffe)
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a//x",
        pattern
    ));
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a/../b",
        pattern
    ));
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a/./x",
        pattern
    ));
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a//",
        pattern
    ));
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a/?q",
        pattern
    ));
    assert!(!xmsg::fed::uri_matches_identity(
        "spiffe://t/ns/a/#f",
        pattern
    ));

    // P2: Bare path oracle cells from brief
    let bare_pattern = "a/*";
    assert!(xmsg::fed::uri_matches_identity("a/b", bare_pattern));
    assert!(!xmsg::fed::uri_matches_identity("a//x", bare_pattern));
    assert!(!xmsg::fed::uri_matches_identity("a/../b", bare_pattern));
    assert!(!xmsg::fed::uri_matches_identity("a//", bare_pattern));
    assert!(!xmsg::fed::uri_matches_identity("a/?q", bare_pattern));
    assert!(!xmsg::fed::uri_matches_identity("a/#f", bare_pattern));

    // Integration check over TLS
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test CA 6");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let (cert_match, key_match) = issue_cert(
        &ca_params,
        &ca_key,
        "match",
        &["spiffe://t/ns/a/sa/x"],
        None,
    );
    let (cert_nomatch_short, key_nomatch_short) =
        issue_cert(&ca_params, &ca_key, "short", &["spiffe://t/ns/a"], None);
    let (cert_nomatch_prefix, key_nomatch_prefix) =
        issue_cert(&ca_params, &ca_key, "ab", &["spiffe://t/ns/ab/sa/x"], None);
    let (server_cert, server_key) = issue_cert(
        &ca_params,
        &ca_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![pattern.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, server_cert, Vec::new(), server_key).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    // 1. Matching URI -> succeeds
    let node_match = create_test_node(
        "client-a",
        a_peers.clone(),
        cert_match,
        Vec::new(),
        key_match,
    )
    .await;
    let envelope = make_envelope("claude:sess-target", "prefix match");
    let res = send_federated_message(&node_match.fed_state, "server-b", &envelope).await;
    assert!(
        res.is_ok(),
        "Expected valid prefix match to succeed, got: {res:?}"
    );

    // 2. Short URI without segment -> fails
    let node_short = create_test_node(
        "client-a",
        a_peers.clone(),
        cert_nomatch_short,
        Vec::new(),
        key_nomatch_short,
    )
    .await;
    let res_short = send_federated_message(&node_short.fed_state, "server-b", &envelope).await;
    assert!(
        res_short.is_err(),
        "Expected short URI without segment to fail handshake"
    );
    match res_short.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    // 3. Substring without slash (ns/ab) -> fails
    let node_ab = create_test_node(
        "client-a",
        a_peers,
        cert_nomatch_prefix,
        Vec::new(),
        key_nomatch_prefix,
    )
    .await;
    let res_ab = send_federated_message(&node_ab.fed_state, "server-b", &envelope).await;
    assert!(res_ab.is_err(), "Expected ns/ab prefix to fail handshake");
    match res_ab.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "Only matching URI should deliver a message");
}

// -----------------------------------------------------------------------------
// Oracle 7: Two CA peers whose identities both match the presented URI => refused
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_7_overlapping_ca_peers_refused() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test CA 7");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let presented_uri = "spiffe://example.org/ns/dept/sa/worker";
    let (cert_a, key_a) = issue_cert(&ca_params, &ca_key, "client-a", &[presented_uri], None);
    let (server_cert, server_key) = issue_cert(
        &ca_params,
        &ca_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    let mut b_peers = PeersMap::empty();
    // Peer 1 matches via exact URI
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "peer-1".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![presented_uri.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();
    // Peer 2 matches via wildcard prefix
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "peer-2".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/dept/*".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, server_cert, Vec::new(), server_key).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    let node_a = create_test_node("client-a", a_peers, cert_a, Vec::new(), key_a).await;

    let envelope = make_envelope("claude:sess-target", "overlap test");
    let res = send_federated_message(&node_a.fed_state, "server-b", &envelope).await;
    assert!(
        res.is_err(),
        "Expected overlapping CA peer match to fail handshake (fail-closed)"
    );
    match res.unwrap_err() {
        AppError::PeerUnreachable(ref msg) => {
            assert!(
                msg.contains("connection error") || msg.contains("handshake failed"),
                "Unexpected PeerUnreachable: {msg}"
            );
        }
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Unexpected PeerRejected: {msg}"
            );
        }
        other => panic!("Unexpected error variant: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(
        msgs.len(),
        0,
        "No messages should be delivered on overlap refusal"
    );
}

// -----------------------------------------------------------------------------
// Oracle 8: Outbound to a CA peer whose server cert has the wrong URI => send fails
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_8_outbound_wrong_uri_fails() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test CA 8");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let client_uri = "spiffe://example.org/ns/test/sa/client-a";
    let actual_server_uri = "spiffe://example.org/ns/test/sa/actual-server";
    let expected_server_uri = "spiffe://example.org/ns/test/sa/expected-server";

    let (cert_a, key_a) = issue_cert(&ca_params, &ca_key, "client-a", &[client_uri], None);
    let (cert_b, key_b) = issue_cert(&ca_params, &ca_key, "server-b", &[actual_server_uri], None);

    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![client_uri.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, cert_b, Vec::new(), key_b).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    // Client expects expected_server_uri, but server presents actual_server_uri
    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![expected_server_uri.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    let node_a = create_test_node("client-a", a_peers, cert_a, Vec::new(), key_a).await;

    let envelope = make_envelope("claude:sess-target", "outbound wrong URI");
    let res = send_federated_message(&node_a.fed_state, "server-b", &envelope).await;
    assert!(
        res.is_err(),
        "Expected outbound send to fail on server URI mismatch"
    );
    match res.unwrap_err() {
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("server TLS certificate verification failed")
                    || msg.contains("ApplicationVerificationFailure"),
                "Expected verification failure, got: {msg}"
            );
        }
        other => panic!("Expected PeerRejected, got: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 0, "No messages should be delivered");
}

// -----------------------------------------------------------------------------
// Oracle 8b: Outbound to a CA peer whose server cert is from a DIFFERENT CA
//           with the correct URI => send fails, nothing delivered (F2)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_8b_outbound_different_ca_fails() {
    let (ca1_params, ca1_key, _ca1_der, ca1_pem) = generate_ca("Test CA 8b Root 1");
    let (ca2_params, ca2_key, _ca2_der, _ca2_pem) = generate_ca("Test CA 8b Root 2 (Untrusted)");

    let anchors1 = parse_ca_bundle_pem(ca1_pem.as_bytes()).unwrap();

    let client_uri = "spiffe://example.org/ns/test/sa/client-a";
    let server_uri = "spiffe://example.org/ns/test/sa/server-b";

    // Client cert issued by CA 1
    let (cert_a, key_a) = issue_cert(&ca1_params, &ca1_key, "client-a", &[client_uri], None);
    // Server cert issued by DIFFERENT CA (CA 2), but with the EXACT matching URI
    let (cert_b, key_b) = issue_cert(&ca2_params, &ca2_key, "server-b", &[server_uri], None);

    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![client_uri.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors1.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, cert_b, Vec::new(), key_b).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    // Client expects server cert to chain to CA 1 and present server_uri
    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca1.pem")),
                identities: Some(vec![server_uri.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors1,
        )
        .unwrap();

    let node_a = create_test_node("client-a", a_peers, cert_a, Vec::new(), key_a).await;

    let envelope = make_envelope("claude:sess-target", "outbound wrong CA test");
    let res = send_federated_message(&node_a.fed_state, "server-b", &envelope).await;
    assert!(
        res.is_err(),
        "Expected outbound send to fail when server cert is signed by untrusted CA"
    );
    match res.unwrap_err() {
        AppError::PeerRejected(ref msg) => {
            assert!(
                msg.contains("server TLS certificate verification failed")
                    || msg.contains("UnknownIssuer")
                    || msg.contains("InvalidCertificate"),
                "Expected cert verification failure, got: {msg}"
            );
        }
        other => panic!("Expected PeerRejected, got: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 0, "No messages should be delivered to target");
}

// -----------------------------------------------------------------------------
// Oracle 9: Policy is the matched peer's: CA peer with targets = ["svc:x"]
//           cannot reach another target (X14 applies)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_9_ca_peer_policy_targets_enforced() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test CA 9");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let uri_a = "spiffe://example.org/ns/test/sa/client-a";
    let (cert_a, key_a) = issue_cert(&ca_params, &ca_key, "client-a", &[uri_a], None);
    let (cert_b, key_b) = issue_cert(
        &ca_params,
        &ca_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    let mut b_peers = PeersMap::empty();
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![uri_a.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: Some(vec!["claude:allowed-target".to_string()]),
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, cert_b, Vec::new(), key_b).await;
    let (_sock1, rx1) =
        create_claude_session_fixture(&node_b.sessions_dir, "allowed-target", "allowed-target");
    let (_sock2, rx2) =
        create_claude_session_fixture(&node_b.sessions_dir, "denied-target", "denied-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    let node_a = create_test_node("client-a", a_peers, cert_a, Vec::new(), key_a).await;

    // 1. Send to allowed target -> succeeds
    let env_allowed = make_envelope("claude:allowed-target", "msg to allowed");
    let res_allowed = send_federated_message(&node_a.fed_state, "server-b", &env_allowed).await;
    assert!(
        res_allowed.is_ok(),
        "Expected send to allowed target to succeed: {res_allowed:?}"
    );

    // 2. Send to denied target -> rejected by policy
    let env_denied = make_envelope("claude:denied-target", "msg to denied");
    let res_denied = send_federated_message(&node_a.fed_state, "server-b", &env_denied).await;
    assert!(
        res_denied.is_err(),
        "Expected send to unlisted target to fail with policy error"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(rx1.lock().unwrap().len(), 1);
    assert_eq!(rx2.lock().unwrap().len(), 0);
}

// -----------------------------------------------------------------------------
// Oracle 10: Config load errors for mutually exclusive trust mechanisms & validation
// -----------------------------------------------------------------------------
#[test]
fn test_oracle_10_config_validation() {
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Test CA 10");
    fs::write(&ca_file, &ca_pem).unwrap();

    // 1. Both pin and ca -> error
    let json_both = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000",
            "pin": "sha256:abcd",
            "ca": ca_file.display().to_string(),
            "identities": ["spiffe://example.org/ns/test/sa/x"]
        }
    })
    .to_string();
    let res_both = PeersMap::load_from_json(&json_both);
    assert!(res_both.is_err(), "Expected both pin and ca to fail");
    assert!(res_both
        .unwrap_err()
        .contains("specifies both 'pin' and 'ca'"));

    // 2. Ca without identities -> error
    let json_no_ids = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000",
            "ca": ca_file.display().to_string()
        }
    })
    .to_string();
    let res_no_ids = PeersMap::load_from_json(&json_no_ids);
    assert!(
        res_no_ids.is_err(),
        "Expected ca without identities to fail"
    );
    assert!(res_no_ids
        .unwrap_err()
        .contains("missing required 'identities'"));

    // 3. Neither pin nor ca -> error
    let json_neither = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000"
        }
    })
    .to_string();
    let res_neither = PeersMap::load_from_json(&json_neither);
    assert!(res_neither.is_err(), "Expected neither pin nor ca to fail");
    assert!(res_neither.unwrap_err().contains("missing trust mechanism"));

    // 4. Pin with identities -> error
    let json_pin_ids = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000",
            "pin": "sha256:abcd",
            "identities": ["spiffe://example.org/ns/test/sa/x"]
        }
    })
    .to_string();
    let res_pin_ids = PeersMap::load_from_json(&json_pin_ids);
    assert!(res_pin_ids.is_err(), "Expected pin with identities to fail");
    assert!(res_pin_ids
        .unwrap_err()
        .contains("specifies 'identities' with 'pin'"));

    // 5. Valid CA config -> succeeds
    let json_valid_ca = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000",
            "ca": ca_file.display().to_string(),
            "identities": ["spiffe://example.org/ns/test/sa/x"]
        }
    })
    .to_string();
    let res_valid = PeersMap::load_from_json(&json_valid_ca);
    assert!(
        res_valid.is_ok(),
        "Expected valid CA config to succeed: {res_valid:?}"
    );

    // 6. CA bundle with non-CA cert fails (P3)
    let non_ca_pem = generate_non_ca("Test Leaf Not CA");
    let non_ca_file = temp.path().join("non_ca.pem");
    fs::write(&non_ca_file, &non_ca_pem).unwrap();

    let parse_res = parse_ca_bundle_pem(non_ca_pem.as_bytes());
    assert!(parse_res.is_err(), "Expected non-CA bundle to fail parsing");
    assert!(parse_res
        .unwrap_err()
        .contains("basicConstraints CA:TRUE required"));

    let json_non_ca = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000",
            "ca": non_ca_file.display().to_string(),
            "identities": ["spiffe://example.org/ns/test/sa/x"]
        }
    })
    .to_string();
    let res_non_ca = PeersMap::load_from_json(&json_non_ca);
    assert!(
        res_non_ca.is_err(),
        "Expected non-CA bundle config load to fail"
    );
    assert!(res_non_ca
        .unwrap_err()
        .contains("basicConstraints CA:TRUE required"));

    // 7. Empty identity pattern fails (P2)
    let json_empty_id = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000",
            "ca": ca_file.display().to_string(),
            "identities": [""]
        }
    })
    .to_string();
    let res_empty_id = PeersMap::load_from_json(&json_empty_id);
    assert!(res_empty_id.is_err());
    assert!(res_empty_id
        .unwrap_err()
        .contains("empty identity pattern is not allowed"));

    // 8. Invalid wildcard patterns fail (P2)
    let json_mid_star = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000",
            "ca": ca_file.display().to_string(),
            "identities": ["a*b"]
        }
    })
    .to_string();
    let res_mid_star = PeersMap::load_from_json(&json_mid_star);
    assert!(res_mid_star.is_err());
    assert!(res_mid_star
        .unwrap_err()
        .contains("wildcards only supported as a single trailing '/*'"));

    let json_multi_star = serde_json::json!({
        "peer-x": {
            "address": "127.0.0.1:9000",
            "ca": ca_file.display().to_string(),
            "identities": ["spiffe://t/*/x/*"]
        }
    })
    .to_string();
    let res_multi_star = PeersMap::load_from_json(&json_multi_star);
    assert!(res_multi_star.is_err());
    assert!(res_multi_star
        .unwrap_err()
        .contains("wildcards only supported as a single trailing '/*'"));
}

// -----------------------------------------------------------------------------
// Oracle 11: Duplicate peer names refused at load and insert (F1)
// -----------------------------------------------------------------------------
#[test]
fn test_oracle_11_duplicate_peer_name_refused() {
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Test Root CA 11");
    fs::write(&ca_file, &ca_pem).unwrap();

    // 1. Arm C from adversarial review: pin entry and CA entry with same name in map form
    let json_map_dup = serde_json::json!({
        "peers": {
            "k1": {
                "name": "x",
                "address": "127.0.0.1:9000",
                "pin": "sha256:abcd",
                "allow": ["send"]
            },
            "k2": {
                "name": "x",
                "address": "127.0.0.1:9001",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://t/x"],
                "allow": ["send", "reply"]
            }
        }
    })
    .to_string();
    let res_map = PeersMap::load_from_json(&json_map_dup);
    assert!(
        res_map.is_err(),
        "Expected duplicate peer name 'x' in map to fail to load"
    );
    let err = res_map.unwrap_err();
    assert!(
        err.contains("duplicate peer name 'x'"),
        "Expected error mentioning duplicate peer name 'x', got: {err}"
    );

    // 2. Duplicate peer name in array form
    let json_arr_dup = serde_json::json!([
        {
            "name": "dup-peer",
            "address": "127.0.0.1:9000",
            "pin": "sha256:abcd",
            "allow": ["send"]
        },
        {
            "name": "dup-peer",
            "address": "127.0.0.1:9001",
            "pin": "sha256:ef01",
            "allow": ["send"]
        }
    ])
    .to_string();
    let res_arr = PeersMap::load_from_json(&json_arr_dup);
    assert!(
        res_arr.is_err(),
        "Expected duplicate in array form to fail to load"
    );
    assert!(res_arr
        .unwrap_err()
        .contains("duplicate peer name 'dup-peer'"));

    // 3. Programmatic insert duplicate check
    let mut map = PeersMap::empty();
    let p1 = PeerConfig {
        name: "peer-prog".to_string(),
        address: "127.0.0.1:9000".to_string(),
        pin: Some("sha256:abcd".to_string()),
        ca: None,
        identities: None,
        allow: vec!["send".to_string()],
        from: None,
        leaf: false,
        principals: Vec::new(),
        targets: None,
    };
    let p2 = PeerConfig {
        name: "peer-prog".to_string(),
        address: "127.0.0.1:9001".to_string(),
        pin: Some("sha256:ef01".to_string()),
        ca: None,
        identities: None,
        allow: vec!["send".to_string()],
        from: None,
        leaf: false,
        principals: Vec::new(),
        targets: None,
    };
    assert!(map.insert(p1).is_ok());
    let res_insert = map.insert(p2.clone());
    assert!(res_insert.is_err());
    assert!(res_insert
        .unwrap_err()
        .contains("duplicate peer name 'peer-prog'"));

    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();
    let res_insert_anchors = map.insert_with_anchors(p2, anchors);
    assert!(res_insert_anchors.is_err());
    assert!(res_insert_anchors
        .unwrap_err()
        .contains("duplicate peer name 'peer-prog'"));
}

// -----------------------------------------------------------------------------
// Oracle 12: Outbound-only pinned peer + CA double match refused (fail-closed) (P5)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_12_outbound_only_pin_and_ca_double_match_refused() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Test CA 12");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let uri_a = "spiffe://example.org/ns/test/sa/client-a";
    let (cert_a, key_a) = issue_cert(&ca_params, &ca_key, "client-a", &[uri_a], None);
    let (cert_b, key_b) = issue_cert(
        &ca_params,
        &ca_key,
        "server-b",
        &["spiffe://example.org/ns/test/sa/server-b"],
        None,
    );

    // Compute client A's SPKI pin
    let pin_a = xmsg::fed::spki_sha256_from_der(&cert_a).unwrap();

    let mut b_peers = PeersMap::empty();
    // 1. Pinned peer with client A's pin, but empty allow (outbound only)
    b_peers
        .insert(PeerConfig {
            name: "pin-outbound-only".to_string(),
            address: "127.0.0.1:0".to_string(),
            pin: Some(pin_a),
            ca: None,
            identities: None,
            allow: vec![], // outbound only
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
        })
        .unwrap();

    // 2. CA peer trusting CA with matching URI, allow ["send"]
    b_peers
        .insert_with_anchors(
            PeerConfig {
                name: "ca-peer".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![uri_a.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let node_b = create_test_node("server-b", b_peers, cert_b, Vec::new(), key_b).await;
    let (_sock, received) =
        create_claude_session_fixture(&node_b.sessions_dir, "sess-target", "sess-target");

    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "server-b".to_string(),
                address: node_b.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec!["spiffe://example.org/ns/test/sa/server-b".to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
            },
            anchors,
        )
        .unwrap();

    let node_a = create_test_node("client-a", a_peers, cert_a, Vec::new(), key_a).await;

    let envelope = make_envelope("claude:sess-target", "double match test");
    let res = send_federated_message(&node_a.fed_state, "server-b", &envelope).await;
    assert!(
        res.is_err(),
        "Expected dual match with outbound-only pinned peer and CA peer to fail closed"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    let msgs = received.lock().unwrap();
    assert_eq!(
        msgs.len(),
        0,
        "No message should be delivered on double-match refusal"
    );
}
