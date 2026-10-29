//! Gating test suite for Unit H5: Hub admission by CA identity pattern, names from identities,
//! and closed-by-default rules table.

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
    list_direct_peer, parse_ca_bundle_pem, run_fed_listener, send_federated_message,
    send_federated_reply, FedEnvelope, FedListAnswer, FedReplyEnvelope, FedState, FedTarget,
    PeerConfig, PeersMap, RateLimiter, WIRE_VERSION,
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
    let proc_root = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
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
            brain_dir: std::path::PathBuf::new(),
    };
    let agy_store = new_agy_store();
    let pi_store = new_pi_store();
    let svc_store = new_svc_store();

    let fed_state = Arc::new(FedState {
        node_name: name.to_string(),
        peers: Arc::new(peers_map),
        cert_der,
        cert_chain_der,
        key_der,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db,
        sessions_dirs: vec![sessions_dir.clone()],
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
        reply_ttl: Duration::from_secs(7 * 24 * 3600),
        list_queries: Default::default(),
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
        v: WIRE_VERSION,
        id: format!("msg-{}", ulid::Ulid::new()),
        origin: xmsg::storage::Origin {
            id: Some("test-sess".to_string()),
            service: None,
            node: "origin-claim".into(),
            label: Some("test-sender".to_string()),
        },
        to: FedTarget {
            r#ref: target.to_string(),
        },
        body: body.to_string(),
        thread_id: format!("thr-{}", ulid::Ulid::new()),
        created_at: 1000,
        forwarded: None,
    }
}

fn make_reply(in_reply_to: &str, body: &str) -> FedReplyEnvelope {
    FedReplyEnvelope {
        v: WIRE_VERSION,
        id: format!("rep-{}", ulid::Ulid::new()),
        in_reply_to: in_reply_to.to_string(),
        replier: xmsg::storage::Origin {
            id: Some("test-sess".to_string()),
            service: None,
            node: "origin-claim".into(),
            label: Some("test-sender".to_string()),
        },
        text: body.to_string(),
        created_at: 1000,
    }
}

// -----------------------------------------------------------------------------
// Oracle 1: H0 — Hub behavior is off unless configured
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_1_h0_hub_off_by_default() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("H0 CA");
    let anchors = parse_ca_bundle_pem(ca_pem.as_bytes()).unwrap();

    let uri_a = "spiffe://example.org/ns/test/sa/client-a";
    let (cert_a, key_a) = issue_cert(&ca_params, &ca_key, "client-a", &[uri_a]);
    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub-server",
        &["spiffe://example.org/ns/test/sa/hub-server"],
    );
    let (cert_unlisted, key_unlisted) = issue_cert(
        &ca_params,
        &ca_key,
        "unlisted-client",
        &["spiffe://example.org/ns/test/sa/unlisted-client"],
    );

    // Hub node configured with standard peers file only (NO hub block)
    let mut hub_peers = PeersMap::empty();
    hub_peers
        .insert_with_anchors(
            PeerConfig {
                name: "client-a.test".to_string(),
                address: "127.0.0.1:0".to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![uri_a.to_string()]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            },
            anchors.clone(),
        )
        .unwrap();

    let hub_node = create_test_node("hub-server", hub_peers, cert_hub, Vec::new(), key_hub).await;
    let (_sock, received) =
        create_claude_session_fixture(&hub_node.sessions_dir, "sess-target", "sess-target");

    // Client A is listed in static peers: connects and sends successfully
    let mut a_peers = PeersMap::empty();
    a_peers
        .insert_with_anchors(
            PeerConfig {
                name: "hub-server.test".to_string(),
                address: hub_node.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![
                    "spiffe://example.org/ns/test/sa/hub-server".to_string()
                ]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            },
            anchors.clone(),
        )
        .unwrap();
    let node_a = create_test_node("client-a.test", a_peers, cert_a, Vec::new(), key_a).await;

    let env = make_envelope("sess-target", "hello h0 static");
    let res_a = send_federated_message(&node_a.fed_state, "hub-server.test", &env).await;
    assert!(
        res_a.is_ok(),
        "Expected static CA client to succeed: {res_a:?}"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(received.lock().unwrap().len(), 1);

    // Unlisted client signed by same CA tries to connect: rejected (fail closed, H0)
    let mut unlisted_peers = PeersMap::empty();
    unlisted_peers
        .insert_with_anchors(
            PeerConfig {
                name: "hub-server.test".to_string(),
                address: hub_node.fed_addr.to_string(),
                pin: None,
                ca: Some(PathBuf::from("/dummy/ca.pem")),
                identities: Some(vec![
                    "spiffe://example.org/ns/test/sa/hub-server".to_string()
                ]),
                allow: vec!["send".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            },
            anchors,
        )
        .unwrap();
    let node_unlisted = create_test_node(
        "unlisted-client.test",
        unlisted_peers,
        cert_unlisted,
        Vec::new(),
        key_unlisted,
    )
    .await;

    let env_unlisted = make_envelope("sess-target", "hello unlisted");
    let res_unlisted =
        send_federated_message(&node_unlisted.fed_state, "hub-server.test", &env_unlisted).await;
    assert!(
        res_unlisted.is_err(),
        "Expected unlisted CA client to be rejected when hub is not configured: {res_unlisted:?}"
    );
}

// -----------------------------------------------------------------------------
// Oracle 2: Pattern Admission and XA2 Name Derivation (<user>.<host>, <sa>.<ns>)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_2_pattern_admission_and_xa2_naming() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 2");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri_host = "spiffe://json64.dev/host/bitstream/user/sini";
    let (cert_host, key_host) = issue_cert(&ca_params, &ca_key, "sini.bitstream", &[uri_host]);

    let uri_pod = "spiffe://json64.dev/ns/genie/sa/genie-guard";
    let (cert_pod, key_pod) = issue_cert(&ca_params, &ca_key, "genie-guard.genie", &[uri_pod]);

    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub.hub",
        &["spiffe://json64.dev/ns/hub/sa/hub"],
    );

    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/host/*/user/*",
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/host/*/user/*",
                    "allow": ["send", "reply", "list", "forward"]
                },
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                    "allow": ["send", "reply", "list", "forward"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = PeersMap::load_from_json(&hub_json).unwrap();
    let hub_node = create_test_node("hub.hub", hub_peers, cert_hub, Vec::new(), key_hub).await;
    let (_sock, received) =
        create_claude_session_fixture(&hub_node.sessions_dir, "target", "target");

    let client_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        }
    })
    .to_string();

    // Client 1: host pattern -> derived name must be sini.bitstream
    let client1_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let client1_node = create_test_node(
        "sini.bitstream",
        client1_peers,
        cert_host,
        Vec::new(),
        key_host,
    )
    .await;

    let env1 = make_envelope("target", "from sini.bitstream");
    let res1 = send_federated_message(&client1_node.fed_state, "hub.hub", &env1).await;
    assert!(res1.is_ok(), "Client 1 send failed: {res1:?}");

    tokio::time::sleep(Duration::from_millis(50)).await;
    {
        let msgs = received.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(
            msgs[0].contains("sini.bitstream"),
            "Expected message to contain attested origin node 'sini.bitstream', got: {}",
            msgs[0]
        );
        let admitted = hub_node.fed_state.peers.admitted_clients.read().unwrap();
        assert!(admitted.contains_key("sini.bitstream"));
        assert_eq!(
            admitted.get("sini.bitstream").unwrap().uri,
            "spiffe://json64.dev/host/bitstream/user/sini"
        );
    }

    // Client 2: pod pattern -> derived name must be genie-guard.genie
    let client2_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let client2_node = create_test_node(
        "genie-guard.genie",
        client2_peers,
        cert_pod,
        Vec::new(),
        key_pod,
    )
    .await;

    let env2 = make_envelope("target", "from genie-guard.genie");
    let res2 = send_federated_message(&client2_node.fed_state, "hub.hub", &env2).await;
    assert!(res2.is_ok(), "Client 2 send failed: {res2:?}");

    tokio::time::sleep(Duration::from_millis(50)).await;
    {
        let msgs = received.lock().unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(
            msgs[1].contains("genie-guard.genie"),
            "Expected message to contain attested origin node 'genie-guard.genie', got: {}",
            msgs[1]
        );
        let admitted = hub_node.fed_state.peers.admitted_clients.read().unwrap();
        assert!(admitted.contains_key("genie-guard.genie"));
        assert_eq!(
            admitted.get("genie-guard.genie").unwrap().uri,
            "spiffe://json64.dev/ns/genie/sa/genie-guard"
        );
    }
}

// -----------------------------------------------------------------------------
// Oracle 3: Strict Path-Segment Pattern Matching (* does not cross /)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_3_strict_path_segment_matching() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 3");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri_valid = "spiffe://json64.dev/ns/genie/sa/genie-guard";
    let (cert_valid, key_valid) =
        issue_cert(&ca_params, &ca_key, "genie-guard.genie", &[uri_valid]);

    let uri_multi = "spiffe://json64.dev/ns/genie/sa/extra/segment";
    let (cert_multi, key_multi) = issue_cert(&ca_params, &ca_key, "extra.segment", &[uri_multi]);

    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub.hub",
        &["spiffe://json64.dev/ns/hub/sa/hub"],
    );

    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                    "allow": ["send"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = PeersMap::load_from_json(&hub_json).unwrap();
    let hub_node = create_test_node(
        "hub.hub",
        hub_peers,
        cert_hub.clone(),
        Vec::new(),
        key_hub.clone(),
    )
    .await;
    let (_sock, _received) =
        create_claude_session_fixture(&hub_node.sessions_dir, "target", "target");

    let client_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        }
    })
    .to_string();

    // Valid single-segment client: succeeds
    let client1_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let client1_node = create_test_node(
        "genie-guard.genie",
        client1_peers,
        cert_valid.clone(),
        Vec::new(),
        key_valid.clone(),
    )
    .await;
    let env1 = make_envelope("target", "single segment");
    let res1 = send_federated_message(&client1_node.fed_state, "hub.hub", &env1).await;
    assert!(
        res1.is_ok(),
        "Expected single-segment match to succeed: {res1:?}"
    );

    // Multi-segment client: * must not cross / -> rejected at TLS / handshake layer
    let client2_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let client2_node = create_test_node(
        "extra.segment",
        client2_peers,
        cert_multi,
        Vec::new(),
        key_multi,
    )
    .await;
    let env2 = make_envelope("target", "multi segment");
    let res2 = send_federated_message(&client2_node.fed_state, "hub.hub", &env2).await;
    assert!(
        res2.is_err(),
        "Expected multi-segment client to be rejected: {res2:?}"
    );

    // Non-vacuous check: over-long URI that DOES derive a valid node name.
    // Pattern `spiffe://json64.dev/ns/*` must NOT admit `spiffe://json64.dev/ns/genie/sa/genie-guard`
    // (which derives valid name `genie-guard.genie`).
    let hub_star_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/*",
                    "allow": ["send"]
                }
            ]
        }
    })
    .to_string();

    let hub_star_peers = PeersMap::load_from_json(&hub_star_json).unwrap();
    let hub_star_node = create_test_node(
        "hub.hub",
        hub_star_peers,
        cert_hub.clone(),
        Vec::new(),
        key_hub.clone(),
    )
    .await;

    // Direct resolve_incoming_peer check:
    let cert_valid_der = rustls::pki_types::CertificateDer::from(cert_valid.clone());
    let direct_res = hub_star_node
        .fed_state
        .peers
        .resolve_incoming_peer(&cert_valid_der, &[]);
    assert!(
        direct_res.is_err(),
        "Expected resolve_incoming_peer to reject over-long URI against spiffe://json64.dev/ns/*: {direct_res:?}"
    );

    // End-to-end federated send check:
    let client3_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_star_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        }
    })
    .to_string();
    let client3_peers = PeersMap::load_from_json(&client3_peers_json).unwrap();
    let client3_node = create_test_node(
        "genie-guard.genie",
        client3_peers,
        cert_valid,
        Vec::new(),
        key_valid,
    )
    .await;
    let env3 = make_envelope("target", "overlong uri deriving valid name");
    let res3 = send_federated_message(&client3_node.fed_state, "hub.hub", &env3).await;
    assert!(
        res3.is_err(),
        "Expected client with URI spiffe://json64.dev/ns/genie/sa/genie-guard to be rejected by pattern spiffe://json64.dev/ns/*: {res3:?}"
    );
}

// -----------------------------------------------------------------------------
// Oracle 4: Closed by Default — Admitted client with no matching rule may do nothing
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_4_closed_by_default_unruled_may_do_nothing() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 4");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri_unruled = "spiffe://json64.dev/ns/genie/sa/unruled-worker";
    let (cert_unruled, key_unruled) =
        issue_cert(&ca_params, &ca_key, "unruled-worker.genie", &[uri_unruled]);

    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub.hub",
        &["spiffe://json64.dev/ns/hub/sa/hub"],
    );

    // Rule is only for special-worker, so unruled-worker gets allow: []
    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/special-worker",
                    "allow": ["send", "reply", "list", "forward"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = PeersMap::load_from_json(&hub_json).unwrap();
    let hub_node = create_test_node("hub.hub", hub_peers, cert_hub, Vec::new(), key_hub).await;
    let (_sock, _received) =
        create_claude_session_fixture(&hub_node.sessions_dir, "target", "target");

    let client_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send", "reply", "list", "forward"]
            }
        }
    })
    .to_string();

    let client_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let client_node = create_test_node(
        "unruled-worker.genie",
        client_peers,
        cert_unruled,
        Vec::new(),
        key_unruled,
    )
    .await;

    // 1. send -> denied (403 OpDenied)
    let env = make_envelope("target", "unruled send");
    let res_send = send_federated_message(&client_node.fed_state, "hub.hub", &env).await;
    assert!(
        matches!(res_send, Err(AppError::OpDenied(_))),
        "Expected OpDenied for send: {res_send:?}"
    );

    // 2. reply -> denied (403 OpDenied)
    let rep = make_reply("msg-nonexistent", "unruled reply");
    let res_reply = send_federated_reply(&client_node.fed_state, "hub.hub", &rep).await;
    assert!(
        matches!(res_reply, Err(AppError::OpDenied(_))),
        "Expected OpDenied for reply: {res_reply:?}"
    );

    // 3. list -> denied (403 OpDenied)
    let hub_peer_cfg = client_node.fed_state.peers.get("hub.hub").unwrap();
    let res_list = list_direct_peer(&client_node.fed_state, hub_peer_cfg).await;
    assert!(
        matches!(res_list, Err(AppError::OpDenied(_))),
        "Expected OpDenied for list: {res_list:?}"
    );

    // 4. forward -> denied (NoForward)
    let env_fwd = make_envelope("dest@other-peer", "unruled forward");
    let res_fwd = send_federated_message(&client_node.fed_state, "hub.hub", &env_fwd).await;
    assert!(
        matches!(res_fwd, Err(AppError::ServiceUnavailable(ref s)) if s.contains("403"))
            || matches!(res_fwd, Err(AppError::OpDenied(_)))
            || matches!(res_fwd, Err(AppError::NoForward(_))),
        "Expected forwarding denial: {res_fwd:?}"
    );
}

// -----------------------------------------------------------------------------
// Oracle 5: Rule Gating across Operations (send, reply, list, forward)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_5a_send_gate() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 5a");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri_reply_only = "spiffe://json64.dev/ns/genie/sa/reply-only-client";
    let (cert_reply, key_reply) = issue_cert(
        &ca_params,
        &ca_key,
        "reply-only-client.genie",
        &[uri_reply_only],
    );

    let uri_send_allowed = "spiffe://json64.dev/ns/genie/sa/sender-client";
    let (cert_sender, key_sender) = issue_cert(
        &ca_params,
        &ca_key,
        "sender-client.genie",
        &[uri_send_allowed],
    );

    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub.hub",
        &["spiffe://json64.dev/ns/hub/sa/hub"],
    );

    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/reply-only-client",
                    "allow": ["reply"]
                },
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/sender-client",
                    "allow": ["send"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = PeersMap::load_from_json(&hub_json).unwrap();
    let hub_node = create_test_node("hub.hub", hub_peers, cert_hub, Vec::new(), key_hub).await;
    let (_sock, _received) =
        create_claude_session_fixture(&hub_node.sessions_dir, "target", "target");

    let client_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        }
    })
    .to_string();

    // Client without send in allow: fails with OpDenied
    let reply_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let reply_node = create_test_node(
        "reply-only-client.genie",
        reply_peers,
        cert_reply,
        Vec::new(),
        key_reply,
    )
    .await;
    let env = make_envelope("target", "trying to send");
    let res_disallowed = send_federated_message(&reply_node.fed_state, "hub.hub", &env).await;
    assert!(
        matches!(res_disallowed, Err(AppError::OpDenied(ref msg)) if msg.contains("send operation not allowed")),
        "Expected OpDenied on send: {res_disallowed:?}"
    );

    // Client with send in allow: succeeds
    let sender_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let sender_node = create_test_node(
        "sender-client.genie",
        sender_peers,
        cert_sender,
        Vec::new(),
        key_sender,
    )
    .await;
    let res_allowed = send_federated_message(&sender_node.fed_state, "hub.hub", &env).await;
    assert!(
        res_allowed.is_ok(),
        "Expected send to succeed: {res_allowed:?}"
    );
}

#[tokio::test]
async fn test_oracle_5b_reply_gate() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 5b");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri_send_only = "spiffe://json64.dev/ns/genie/sa/send-only-client";
    let (cert_send_only, key_send_only) = issue_cert(
        &ca_params,
        &ca_key,
        "send-only-client.genie",
        &[uri_send_only],
    );

    let uri_reply_ok = "spiffe://json64.dev/ns/genie/sa/reply-ok-client";
    let (cert_reply_ok, key_reply_ok) = issue_cert(
        &ca_params,
        &ca_key,
        "reply-ok-client.genie",
        &[uri_reply_ok],
    );

    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub.hub",
        &["spiffe://json64.dev/ns/hub/sa/hub"],
    );

    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send", "reply"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/send-only-client",
                    "allow": ["send"]
                },
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/reply-ok-client",
                    "allow": ["reply"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = PeersMap::load_from_json(&hub_json).unwrap();
    let hub_node = create_test_node("hub.hub", hub_peers, cert_hub, Vec::new(), key_hub).await;

    let client_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send", "reply"]
            }
        }
    })
    .to_string();

    // Client without reply in allow: fails with OpDenied
    let send_only_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let send_only_node = create_test_node(
        "send-only-client.genie",
        send_only_peers,
        cert_send_only,
        Vec::new(),
        key_send_only,
    )
    .await;
    let rep = make_reply("msg-test", "disallowed reply");
    let res_disallowed = send_federated_reply(&send_only_node.fed_state, "hub.hub", &rep).await;
    assert!(
        matches!(res_disallowed, Err(AppError::OpDenied(ref msg)) if msg.contains("reply operation not allowed")),
        "Expected OpDenied on reply: {res_disallowed:?}"
    );

    // Client with reply in allow: passes the op check (fails with not_found on nonexistent target session, rather than OpDenied)
    let reply_ok_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let reply_ok_node = create_test_node(
        "reply-ok-client.genie",
        reply_ok_peers,
        cert_reply_ok,
        Vec::new(),
        key_reply_ok,
    )
    .await;
    let res_allowed = send_federated_reply(&reply_ok_node.fed_state, "hub.hub", &rep).await;
    assert!(
        !matches!(res_allowed, Err(AppError::OpDenied(ref msg)) if msg.contains("reply operation not allowed")),
        "Expected reply op gate to pass: {res_allowed:?}"
    );
}

#[tokio::test]
async fn test_oracle_5c_list_gate() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 5c");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri_no_list = "spiffe://json64.dev/ns/genie/sa/no-list-client";
    let (cert_no_list, key_no_list) =
        issue_cert(&ca_params, &ca_key, "no-list-client.genie", &[uri_no_list]);

    let uri_list_ok = "spiffe://json64.dev/ns/genie/sa/list-ok-client";
    let (cert_list_ok, key_list_ok) =
        issue_cert(&ca_params, &ca_key, "list-ok-client.genie", &[uri_list_ok]);

    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub.hub",
        &["spiffe://json64.dev/ns/hub/sa/hub"],
    );

    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/no-list-client",
                    "allow": ["send"]
                },
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/list-ok-client",
                    "allow": ["list"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = PeersMap::load_from_json(&hub_json).unwrap();
    let hub_node = create_test_node("hub.hub", hub_peers, cert_hub, Vec::new(), key_hub).await;

    let client_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["list"]
            }
        }
    })
    .to_string();

    // Client without list in allow: fails with OpDenied
    let no_list_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let no_list_node = create_test_node(
        "no-list-client.genie",
        no_list_peers,
        cert_no_list,
        Vec::new(),
        key_no_list,
    )
    .await;
    let peer_cfg = no_list_node.fed_state.peers.get("hub.hub").unwrap();
    let res_disallowed = list_direct_peer(&no_list_node.fed_state, peer_cfg).await;
    assert!(
        matches!(res_disallowed, Err(AppError::OpDenied(ref msg)) if msg.contains("list operation not allowed")),
        "Expected OpDenied on list: {res_disallowed:?}"
    );

    // Client with list in allow: succeeds
    let list_ok_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let list_ok_node = create_test_node(
        "list-ok-client.genie",
        list_ok_peers,
        cert_list_ok,
        Vec::new(),
        key_list_ok,
    )
    .await;
    let peer_cfg_ok = list_ok_node.fed_state.peers.get("hub.hub").unwrap();
    let res_allowed = list_direct_peer(&list_ok_node.fed_state, peer_cfg_ok).await;
    assert!(
        matches!(res_allowed, Ok((FedListAnswer::Ok { .. }, _))),
        "Expected list to succeed: {res_allowed:?}"
    );
}

#[tokio::test]
async fn test_oracle_5d_forward_gate() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 5d");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri_no_fwd = "spiffe://json64.dev/ns/genie/sa/no-fwd-client";
    let (cert_no_fwd, key_no_fwd) =
        issue_cert(&ca_params, &ca_key, "no-fwd-client.genie", &[uri_no_fwd]);

    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub.hub",
        &["spiffe://json64.dev/ns/hub/sa/hub"],
    );

    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            },
            "dest.dest": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/dest/sa/dest"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/no-fwd-client",
                    "allow": ["send"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = PeersMap::load_from_json(&hub_json).unwrap();
    let hub_node = create_test_node("hub.hub", hub_peers, cert_hub, Vec::new(), key_hub).await;

    let client_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        }
    })
    .to_string();

    // Client without forward in allow sends message addressed to dest@dest.node: rejected with NoForward
    let no_fwd_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let no_fwd_node = create_test_node(
        "no-fwd-client.genie",
        no_fwd_peers,
        cert_no_fwd,
        Vec::new(),
        key_no_fwd,
    )
    .await;
    let env = make_envelope("target@dest.dest", "forward attempt");
    let res = send_federated_message(&no_fwd_node.fed_state, "hub.hub", &env).await;
    assert!(
        matches!(res, Err(AppError::OpDenied(ref s)) if s.contains("Forwarding cross-host is not permitted"))
            || matches!(res, Err(AppError::NoForward(_))),
        "Expected forward denial when forward not allowed: {res:?}"
    );
}

// -----------------------------------------------------------------------------
// Oracle 6: Real XA2 collision refusal (host/genie/user/genie-guard vs ns/genie/sa/genie-guard)
// Neither overwrites the other (never last-writer-wins)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_oracle_6_collision_refusal_no_last_writer_wins() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 6");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri1 = "spiffe://json64.dev/host/genie/user/genie-guard";
    let (cert1, key1) = issue_cert(&ca_params, &ca_key, "genie-guard.genie", &[uri1]);

    let uri2 = "spiffe://json64.dev/ns/genie/sa/genie-guard";
    let (cert2, key2) = issue_cert(&ca_params, &ca_key, "genie-guard.genie", &[uri2]);

    let (cert_hub, key_hub) = issue_cert(
        &ca_params,
        &ca_key,
        "hub.hub",
        &["spiffe://json64.dev/ns/hub/sa/hub"],
    );

    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/host/*/user/*",
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/host/*/user/*",
                    "allow": ["send"]
                },
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                    "allow": ["send"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = PeersMap::load_from_json(&hub_json).unwrap();
    let hub_node = create_test_node("hub.hub", hub_peers, cert_hub, Vec::new(), key_hub).await;
    let (_sock, received) =
        create_claude_session_fixture(&hub_node.sessions_dir, "target", "target");

    let client_peers_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": hub_node.fed_addr.to_string(),
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        }
    })
    .to_string();

    // Client 1 connects first -> admitted
    let client1_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let client1_node = create_test_node(
        "genie-guard.genie",
        client1_peers,
        cert1.clone(),
        Vec::new(),
        key1.clone(),
    )
    .await;
    let env1 = make_envelope("target", "first client wins");
    let res1 = send_federated_message(&client1_node.fed_state, "hub.hub", &env1).await;
    assert!(res1.is_ok(), "Client 1 send should succeed: {res1:?}");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(received.lock().unwrap().len(), 1);

    // Verify client 1 is registered
    {
        let admitted = hub_node.fed_state.peers.admitted_clients.read().unwrap();
        assert_eq!(admitted.get("genie-guard.genie").unwrap().uri, uri1);
    }

    // Client 2 connects with colliding derived name genie-guard.genie but different URI -> refused
    let client2_peers = PeersMap::load_from_json(&client_peers_json).unwrap();
    let client2_node = create_test_node(
        "genie-guard.genie",
        client2_peers,
        cert2.clone(),
        Vec::new(),
        key2,
    )
    .await;
    let env2 = make_envelope("target", "second client collides");
    let res2 = send_federated_message(&client2_node.fed_state, "hub.hub", &env2).await;
    assert!(
        res2.is_err(),
        "Client 2 send must be rejected due to collision"
    );

    // Check that the error names BOTH URIs:
    // At TLS layer or fed layer, error names the collision
    // Let's also check direct resolve_incoming_peer on hub_node
    let resolve_res = hub_node.fed_state.peers.resolve_incoming_peer(
        &rustls::pki_types::CertificateDer::from(cert2.as_slice()),
        &[],
    );
    assert!(
        resolve_res.is_err(),
        "resolve_incoming_peer must fail for colliding client"
    );
    let resolve_err = match resolve_res.unwrap_err() {
        AppError::PeerRejected(s) => s,
        other => format!("{other:?}"),
    };
    assert!(
        resolve_err.contains(uri1) && resolve_err.contains(uri2),
        "Expected error to name both URIs ('{uri1}' and '{uri2}'), got: '{resolve_err}'"
    );

    // Client 1's registration is unchanged (no last-writer-wins)
    {
        let admitted = hub_node.fed_state.peers.admitted_clients.read().unwrap();
        assert_eq!(admitted.get("genie-guard.genie").unwrap().uri, uri1);
    }
}

#[tokio::test]
async fn test_oracle_6_concurrent_collision_race() {
    let (ca_params, ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 6 Concurrent");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let uri1 = "spiffe://json64.dev/host/genie/user/genie-guard";
    let (cert1, _) = issue_cert(&ca_params, &ca_key, "genie-guard.genie", &[uri1]);

    let uri2 = "spiffe://json64.dev/ns/genie/sa/genie-guard";
    let (cert2, _) = issue_cert(&ca_params, &ca_key, "genie-guard.genie", &[uri2]);

    let hub_json = serde_json::json!({
        "peers": {
            "hub.hub": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/host/*/user/*",
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/host/*/user/*",
                    "allow": ["send"]
                },
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                    "allow": ["send"]
                }
            ]
        }
    })
    .to_string();

    let hub_peers = Arc::new(PeersMap::load_from_json(&hub_json).unwrap());

    // N parallel resolves across OS threads synchronized at a barrier
    const N: usize = 50;
    let mut handles = Vec::with_capacity(N);
    let barrier = Arc::new(std::sync::Barrier::new(N));

    let cert1_der = rustls::pki_types::CertificateDer::from(cert1);
    let cert2_der = rustls::pki_types::CertificateDer::from(cert2);

    for i in 0..N {
        let peers = Arc::clone(&hub_peers);
        let b = Arc::clone(&barrier);
        let c1 = cert1_der.clone();
        let c2 = cert2_der.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            if i % 2 == 0 {
                (1, peers.resolve_incoming_peer(&c1, &[]))
            } else {
                (2, peers.resolve_incoming_peer(&c2, &[]))
            }
        }));
    }

    let mut c1_success = 0;
    let mut c1_rejected = 0;
    let mut c2_success = 0;
    let mut c2_rejected = 0;

    for handle in handles {
        let (client_id, res) = handle.join().unwrap();
        match (client_id, res) {
            (1, Ok(_)) => c1_success += 1,
            (1, Err(AppError::PeerRejected(s))) => {
                c1_rejected += 1;
                assert!(
                    s.contains(uri1) && s.contains(uri2),
                    "Refusal must name both URIs ('{uri1}' and '{uri2}'), got: '{s}'"
                );
            }
            (1, Err(other)) => panic!("Unexpected error for client 1: {other:?}"),
            (2, Ok(_)) => c2_success += 1,
            (2, Err(AppError::PeerRejected(s))) => {
                c2_rejected += 1;
                assert!(
                    s.contains(uri1) && s.contains(uri2),
                    "Refusal must name both URIs ('{uri1}' and '{uri2}'), got: '{s}'"
                );
            }
            (2, Err(other)) => panic!("Unexpected error for client 2: {other:?}"),
            _ => unreachable!(),
        }
    }

    // Exactly one identity was admitted!
    let admitted = hub_peers.admitted_clients.read().unwrap();
    let winner = admitted
        .get("genie-guard.genie")
        .expect("genie-guard.genie must be admitted");

    if winner.uri == uri1 {
        assert!(
            c1_success > 0,
            "Winner client 1 must have at least 1 success"
        );
        assert_eq!(c2_success, 0, "Losing client 2 must have ZERO successes");
        assert_eq!(
            c2_rejected,
            N / 2,
            "All attempts of client 2 must be refused"
        );
    } else if winner.uri == uri2 {
        assert!(
            c2_success > 0,
            "Winner client 2 must have at least 1 success"
        );
        assert_eq!(c1_success, 0, "Losing client 1 must have ZERO successes");
        assert_eq!(
            c1_rejected,
            N / 2,
            "All attempts of client 1 must be refused"
        );
    } else {
        panic!("Unexpected admitted URI: {}", winner.uri);
    }
}

// -----------------------------------------------------------------------------
// Oracle 7: Load-time refusals (each with an individual test)
// -----------------------------------------------------------------------------
#[test]
fn test_oracle_7a_load_wildcard_segment() {
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 7a");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let json = serde_json::json!({
        "peers": {
            "peer1.test": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/test/sa/peer1"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/host/foo*/user/*"
            ]
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains("wildcards only supported as a full segment '*'"),
        "Unexpected error: {err}"
    );
}

#[test]
fn test_oracle_7b_load_unknown_op() {
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 7b");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let json = serde_json::json!({
        "peers": {
            "peer1.test": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/test/sa/peer1"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                    "allow": ["admin"]
                }
            ]
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains("unknown operation 'admin'"),
        "Unexpected error: {err}"
    );
}

#[test]
fn test_oracle_7c_load_orphan_rule() {
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 7c");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let json = serde_json::json!({
        "peers": {
            "peer1.test": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/test/sa/peer1"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/other/sa/*",
                    "allow": ["send"]
                }
            ]
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("orphaned hub rule"), "Unexpected error: {err}");
}

#[test]
fn test_oracle_7d_load_duplicate_rule_pattern() {
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 7d");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let json = serde_json::json!({
        "peers": {
            "peer1.test": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/test/sa/peer1"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                    "allow": ["send"]
                },
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                    "allow": ["reply"]
                }
            ]
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains("duplicate hub rule pattern"),
        "Unexpected error: {err}"
    );
}

#[test]
fn test_oracle_7e_load_empty_allow() {
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 7e");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let json = serde_json::json!({
        "peers": {
            "peer1.test": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/test/sa/peer1"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "rules": [
                {
                    "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                    "allow": []
                }
            ]
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains("empty 'allow' list"),
        "Unexpected error: {err}"
    );
}

#[test]
fn test_oracle_7f_load_unknown_field() {
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Hub CA 7f");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let json = serde_json::json!({
        "peers": {
            "peer1.test": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/ns/test/sa/peer1"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ],
            "bogus": "field"
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains("unknown field 'bogus' in hub config"),
        "Unexpected error: {err}"
    );
}

#[test]
fn test_oracle_7g_load_missing_ca_anchor() {
    let json = serde_json::json!({
        "peers": {},
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ]
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains("hub configuration requires at least one CA trust anchor from peers; no CA peer configured"),
        "Unexpected error: {err}"
    );
}

#[test]
fn test_oracle_7h_load_wrapped_without_peers() {
    let json = serde_json::json!({
        "hub": {
            "patterns": [
                "spiffe://json64.dev/ns/genie/sa/*"
            ]
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains(r#"expected {"peers": {...}, "hub": {...}}"#),
        "Unexpected error: {err}"
    );
}

#[test]
fn test_oracle_7i_flat_peer_named_hub_stays_peer() {
    let json = serde_json::json!({
        "hub": {
            "address": "127.0.0.1:9001",
            "pin": "1111111111111111111111111111111111111111111111111111111111111111"
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(
        res.is_ok(),
        "Flat peer named 'hub' must be accepted as a peer: {res:?}"
    );
    let map = res.unwrap();
    assert!(map.hub.is_none(), "Hub config must NOT be set");
    assert!(
        map.get("hub").is_some(),
        "Peer named 'hub' must exist in map"
    );
}

#[test]
fn test_oracle_3_load_concrete_peer_collision() {
    let (_ca_params, _ca_key, _ca_der, ca_pem) = generate_ca("Hub CA Coll");
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    fs::write(&ca_file, &ca_pem).unwrap();

    let json = serde_json::json!({
        "peers": {
            "sini.bitstream": {
                "address": "127.0.0.1:0",
                "ca": ca_file.display().to_string(),
                "identities": ["spiffe://json64.dev/host/bitstream/user/sini"],
                "allow": ["send"]
            }
        },
        "hub": {
            "patterns": [
                "spiffe://json64.dev/host/bitstream/user/sini"
            ]
        }
    })
    .to_string();

    let res = PeersMap::load_from_json(&json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains("colliding with concrete peer"),
        "Unexpected error: {err}"
    );
}
