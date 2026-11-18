//! Gating test suite for Unit H5: Hub admission by CA identity pattern, names from identities,
//! and closed-by-default rules table.

mod agy_env;
use agy_env::ScrubAgyEnv;
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
        max_attachment_bytes: xmsg::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        node_name: name.to_string(),
        peers: (Arc::new(peers_map)).into(),
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
    let session_uuid = if xmsg::claim::is_uuid_shaped(session_id) {
        session_id.to_string()
    } else {
        use sha2::{Digest, Sha256};
        let h = hex::encode(Sha256::digest(session_id.as_bytes()));
        format!(
            "{}-{}-4{}-a{}-{}",
            &h[0..8],
            &h[8..12],
            &h[13..16],
            &h[17..20],
            &h[20..32]
        )
    };
    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": session_uuid,
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
        attachments: vec![],
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
        attachments: vec![],
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
                observe_labels: false,
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
                observe_labels: false,
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

    for _ in 0..250 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(received.lock().unwrap().len(), 1);

    // Unlisted client signed by same CA tries to connect: rejected (fail closed, H0)
    let mut unlisted_peers = PeersMap::empty();
    unlisted_peers
        .insert_with_anchors(
            PeerConfig {
                observe_labels: false,
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
            },
            "genie-guard.genie": {
                "ca": ca_file.display().to_string(),
                "identities": [uri_pod],
                "leaf": true,
                "allow": ["send", "reply", "list", "forward"]
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

    for _ in 0..250 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    {
        let msgs = received.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(
            msgs[0].contains("sini.bitstream"),
            "Expected message to contain attested origin node 'sini.bitstream', got: {}",
            msgs[0]
        );
        let current_peers = hub_node.fed_state.current_peers();
        let admitted = current_peers.admitted_clients.read().unwrap();
        assert!(admitted.contains_key(uri_host));
        assert_eq!(
            admitted.get(uri_host).unwrap().uri,
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

    for _ in 0..250 {
        if received.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    {
        let msgs = received.lock().unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(
            msgs[1].contains("genie-guard.genie"),
            "Expected message to contain attested origin node 'genie-guard.genie', got: {}",
            msgs[1]
        );
        let current_peers = hub_node.fed_state.current_peers();
        let admitted = current_peers.admitted_clients.read().unwrap();
        assert!(
            !admitted.contains_key(uri_pod),
            "concrete pod was installed as a dynamic client"
        );
        assert_eq!(
            current_peers
                .get_peer_config("genie-guard.genie")
                .unwrap()
                .identities,
            Some(vec![uri_pod.to_owned()]),
            "concrete pod lost its exact URI reservation"
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
        .current_peers()
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
    let current_peers = client_node.fed_state.current_peers();
    let hub_peer_cfg = current_peers.get("hub.hub").unwrap();
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
    let current_peers = no_list_node.fed_state.current_peers();
    let peer_cfg = current_peers.get("hub.hub").unwrap();
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
    let current_peers_ok = list_ok_node.fed_state.current_peers();
    let peer_cfg_ok = current_peers_ok.get("hub.hub").unwrap();
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

fn grt4_mixed_config(ca_pem: &str) -> (TempDir, String) {
    let temp = TempDir::new().unwrap();
    let ca = temp.path().join("ca.pem");
    fs::write(&ca, ca_pem).unwrap();
    let config = serde_json::json!({
        "peers": {"hub.hub": {
            "ca": ca, "address": "127.0.0.1:1",
            "identities": ["spiffe://example.invalid/ns/hub/sa/hub"],
            "allow": ["send"]
        }},
        "hub": {
            "patterns": ["spiffe://example.invalid/host/*/user/*", "spiffe://example.invalid/ns/pods/sa/*"],
            "rules": [{"pattern": "spiffe://example.invalid/host/*/user/*", "allow": ["send"]},
                      {"pattern": "spiffe://example.invalid/ns/pods/sa/*", "allow": ["send"]}]
        }
    }).to_string();
    (temp, config)
}

#[test]
fn test_oracle_6_no_arrival_order_owns_an_ambiguous_alias() {
    let (params, key, _, pem) = generate_ca("grt4 arrival CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let uris = [
        "spiffe://example.invalid/host/pods/user/guard",
        "spiffe://example.invalid/ns/pods/sa/guard",
    ];
    for first in 0..2 {
        let peers = PeersMap::load_from_json(&config).unwrap();
        for index in [first, 1 - first] {
            let (cert, _) = issue_cert(&params, &key, "guard.pods", &[uris[index]]);
            assert!(
                matches!(
                    peers
                        .resolve_incoming_peer(&rustls::pki_types::CertificateDer::from(cert), &[]),
                    Err(AppError::PeerRejected(_))
                ),
                "grt4 arrival order selected an ambiguous URI"
            );
        }
        assert!(
            peers.admitted_clients.read().unwrap().is_empty(),
            "grt4 arrival refusal left an authoritative row"
        );
        assert!(
            !peers.contains_name("guard.pods"),
            "grt4 refused alias remained routable"
        );
    }
}

#[test]
fn test_oracle_6_concurrent_collision_race() {
    let (params, key, _, pem) = generate_ca("grt4 concurrent CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let peers = Arc::new(PeersMap::load_from_json(&config).unwrap());
    let certs: Vec<_> = [
        "spiffe://example.invalid/host/pods/user/guard",
        "spiffe://example.invalid/ns/pods/sa/guard",
    ]
    .iter()
    .map(|uri| {
        let (cert, _) = issue_cert(&params, &key, "guard.pods", &[uri]);
        rustls::pki_types::CertificateDer::from(cert)
    })
    .collect();
    let barrier = Arc::new(std::sync::Barrier::new(50));
    let handles: Vec<_> = (0..50)
        .map(|index| {
            let peers = peers.clone();
            let barrier = barrier.clone();
            let cert = certs[index % 2].clone();
            std::thread::spawn(move || {
                barrier.wait();
                peers.resolve_incoming_peer(&cert, &[])
            })
        })
        .collect();
    for handle in handles {
        assert!(
            matches!(handle.join().unwrap(), Err(AppError::PeerRejected(_))),
            "grt4 concurrent arrival became an alias winner"
        );
    }
    assert!(
        peers.admitted_clients.read().unwrap().is_empty(),
        "grt4 concurrent refusal published a client"
    );
}

#[test]
fn grt4_tls_refuses_the_first_ambiguous_uri() {
    use rustls::server::danger::ClientCertVerifier;
    let (params, key, _, pem) = generate_ca("grt4 verifier CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let peers = Arc::new(PeersMap::load_from_json(&config).unwrap());
    let verifier = xmsg::fed::CombinedClientCertVerifier::new(peers.clone());
    let (positive, _) = issue_cert(
        &params,
        &key,
        "alice.normal",
        &["spiffe://example.invalid/host/normal/user/alice"],
    );
    assert!(
        verifier
            .verify_client_cert(
                &rustls::pki_types::CertificateDer::from(positive),
                &[],
                rustls::pki_types::UnixTime::now()
            )
            .is_ok(),
        "grt4 TLS fixture rejected a unique ordinary URI"
    );
    for uri in [
        "spiffe://example.invalid/host/pods/user/guard",
        "spiffe://example.invalid/ns/pods/sa/guard",
    ] {
        let (cert, _) = issue_cert(&params, &key, "guard.pods", &[uri]);
        assert!(
            verifier
                .verify_client_cert(
                    &rustls::pki_types::CertificateDer::from(cert),
                    &[],
                    rustls::pki_types::UnixTime::now()
                )
                .is_err(),
            "grt4 TLS accepted the first ambiguous identity"
        );
    }
    assert!(
        peers.admitted_clients.read().unwrap().is_empty(),
        "grt4 TLS verification changed the admitted registry"
    );
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
        err.contains("must name its CA bundle"),
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

#[test]
fn grt4_first_ambiguous_uri_is_refused_before_registration() {
    let (ca_params, ca_key, _, ca_pem) = generate_ca("grt4 prospective CA");
    let (_temp, config) = grt4_mixed_config(&ca_pem);
    for uri in [
        "spiffe://example.invalid/host/pods/user/guard",
        "spiffe://example.invalid/ns/pods/sa/guard",
    ] {
        let peers = PeersMap::load_from_json(&config).unwrap();
        let (cert, _) = issue_cert(&ca_params, &ca_key, "guard.pods", &[uri]);
        let result =
            peers.resolve_incoming_peer(&rustls::pki_types::CertificateDer::from(cert), &[]);
        assert!(
            matches!(result, Err(AppError::PeerRejected(_))),
            "grt4 first ambiguous URI must be refused before any registration"
        );
        assert!(
            peers.admitted_clients.read().unwrap().is_empty(),
            "grt4 refused first URI published an admitted row"
        );
    }
}

fn grt4_pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

type Grt4Sender = hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>;

async fn grt4_keepalive(
    cert: &[u8],
    key: &[u8],
    hub: &TestFedNode,
) -> (Grt4Sender, tokio::task::JoinHandle<()>) {
    let pin = xmsg::fed::spki_sha256_from_der(&hub.fed_state.cert_der).unwrap();
    let connector = xmsg::fed::make_tls_connector(cert, key, &pin).unwrap();
    let tcp = tokio::net::TcpStream::connect(hub.fed_addr).await.unwrap();
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let (sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    (
        sender,
        tokio::spawn(async move {
            let _ = connection.await;
        }),
    )
}

async fn grt4_unknown_list(sender: &mut Grt4Sender) -> (hyper::StatusCode, String) {
    use http_body_util::BodyExt;
    tokio::time::timeout(Duration::from_secs(3), sender.ready())
        .await
        .unwrap()
        .unwrap();
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/fed/v2/list/unknown")
        .header("host", "fixture")
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from_static(
            b"{\"status\":\"ok\",\"entries\":[]}",
        )))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let body = tokio::time::timeout(Duration::from_secs(3), response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn grt4_keepalive_uri_cannot_borrow_a_replacement_alias() {
    let (params, key, _, pem) = generate_ca("grt4 reload CA");
    let temp = TempDir::new().unwrap();
    let ca_path = temp.path().join("ca.pem");
    fs::write(&ca_path, pem).unwrap();
    let uri_a = "spiffe://example.invalid/host/pods/user/guard";
    let uri_b = "spiffe://example.invalid/ns/pods/sa/guard";
    let (cert_a, key_a) = issue_cert(&params, &key, "guard.pods", &[uri_a]);
    let (cert_b, key_b) = issue_cert(&params, &key, "guard.pods", &[uri_b]);
    let (server_cert, server_key) = issue_cert(
        &params,
        &key,
        "hub.hub",
        &["spiffe://example.invalid/ns/hub/sa/hub"],
    );
    let config = |uri: &str| {
        let rights = if uri == uri_a {
            vec!["list"]
        } else {
            vec!["send", "reply", "list"]
        };
        serde_json::json!({"peers": {"guard.pods": {
            "ca": ca_path, "identities": [uri], "leaf": true, "allow": rights
        }}})
        .to_string()
    };
    let peers_path = temp.path().join("peers.json");
    fs::write(&peers_path, config(uri_a)).unwrap();
    let peers = PeersMap::load_from_file(&peers_path).unwrap();
    let hub = create_test_node(
        "hub.hub",
        peers,
        server_cert.clone(),
        Vec::new(),
        server_key.clone(),
    )
    .await;
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    fs::write(&cert_path, grt4_pem("CERTIFICATE", &server_cert)).unwrap();
    fs::write(&key_path, grt4_pem("PRIVATE KEY", &server_key)).unwrap();
    let reloader = xmsg::fed::CredentialReloader::new_full(
        cert_path,
        key_path,
        Some(peers_path.clone()),
        Some(xmsg::fed::OwnNode {
            name: "hub.hub".into(),
            pin: None,
        }),
        hub.fed_state.current_peers(),
        Some(hub.fed_state.clone()),
        Default::default(),
    )
    .unwrap();
    let (mut sender_a, connection_a) = grt4_keepalive(&cert_a, &key_a, &hub).await;
    let initial = grt4_unknown_list(&mut sender_a).await;
    assert_eq!(
        initial.0,
        hyper::StatusCode::NOT_FOUND,
        "grt4 original URI failed its admitted application control"
    );
    assert!(
        initial.1.contains("list query"),
        "grt4 original control did not reach the query handler"
    );
    reloader.force_reload().unwrap();
    let same = grt4_unknown_list(&mut sender_a).await;
    assert_eq!(
        same.0,
        hyper::StatusCode::NOT_FOUND,
        "grt4 same-URI reload broke the existing connection"
    );
    assert!(
        same.1.contains("list query"),
        "grt4 same-URI reload failed before the query handler"
    );
    use tokio::io::AsyncWriteExt;
    let (_inbox, received) = create_claude_session_fixture(&hub.sessions_dir, "target", "target");
    let controls = xmsg::observe_relay::test_hooks::controls(&hub.fed_state);
    let initial_posts = controls
        .delivery_posts
        .load(std::sync::atomic::Ordering::Acquire);
    let server_pin = xmsg::fed::spki_sha256_from_der(&server_cert).unwrap();
    let connector = xmsg::fed::make_tls_connector(&cert_a, &key_a, &server_pin).unwrap();
    let tcp = tokio::net::TcpStream::connect(hub.fed_addr).await.unwrap();
    let mut raw = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let body = serde_json::to_vec(&make_envelope(
        "target",
        "late body must not borrow new grants",
    ))
    .unwrap();
    let headers = format!("POST /fed/v2/messages HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    raw.write_all(headers.as_bytes()).await.unwrap();
    raw.flush().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while controls
            .delivery_posts
            .load(std::sync::atomic::Ordering::Acquire)
            == initial_posts
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("grt4 held body never reached authenticated request admission");
    fs::write(&peers_path, config(uri_b)).unwrap();
    reloader.force_reload().unwrap();
    raw.write_all(&body).await.unwrap();
    raw.flush().await.unwrap();
    let mut late_response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut late_response))
        .await
        .unwrap()
        .unwrap();
    let late_response = String::from_utf8(late_response).unwrap();
    assert!(
        late_response.starts_with("HTTP/1.1 403")
            && late_response.contains("authenticated identity no longer owns"),
        "grt4 body-completion handler borrowed a replacement URI grant: {late_response}"
    );
    assert!(
        received.lock().unwrap().is_empty(),
        "grt4 stale body delivered before current URI refusal"
    );
    let old = grt4_unknown_list(&mut sender_a).await;
    assert_eq!(
        old.0,
        hyper::StatusCode::FORBIDDEN,
        "grt4 old keep-alive URI borrowed replacement ownership"
    );
    let (mut sender_b, connection_b) = grt4_keepalive(&cert_b, &key_b, &hub).await;
    let fresh = grt4_unknown_list(&mut sender_b).await;
    assert_eq!(
        fresh.0,
        hyper::StatusCode::NOT_FOUND,
        "grt4 replacement URI failed its application control"
    );
    assert!(
        fresh.1.contains("list query"),
        "grt4 replacement control failed before the query handler"
    );
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/fed/v2/messages")
        .header("host", "fixture")
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(3), sender_b.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accepted.status(),
        hyper::StatusCode::ACCEPTED,
        "grt4 replacement send control did not retain its current grant"
    );
    use http_body_util::BodyExt;
    accepted.into_body().collect().await.unwrap();
    drop(sender_a);
    drop(sender_b);
    connection_a.abort();
    connection_b.abort();
}

#[derive(Clone)]
struct Grt4Log(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Grt4Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Grt4Log {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn grt4_warning_is_once_per_published_alias_class() {
    let (params, key, _, pem) = generate_ca("grt4 warning CA");
    let (temp, config) = grt4_mixed_config(&pem);
    let mut config: serde_json::Value = serde_json::from_str(&config).unwrap();
    let ca = config["peers"]["hub.hub"]["ca"].clone();
    config["peers"] = serde_json::json!({"seed.seed": {
        "ca": ca, "address": "127.0.0.1:1", "identities": ["spiffe://example.invalid/host/seed/user/seed"], "allow": ["send"]
    }});
    config["hub"]["patterns"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("spiffe://example.invalid/*/pods/*/*"));
    let peers_path = temp.path().join("peers.json");
    fs::write(&peers_path, config.to_string()).unwrap();
    let (cert, key) = issue_cert(
        &params,
        &key,
        "hub.hub",
        &["spiffe://example.invalid/ns/hub/sa/hub"],
    );
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    fs::write(&cert_path, grt4_pem("CERTIFICATE", &cert)).unwrap();
    fs::write(&key_path, grt4_pem("PRIVATE KEY", &key)).unwrap();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(Grt4Log(buffer.clone()))
        .finish();
    // Keep two dispatchers registered so another test's cached callsite interest cannot hide this capture.
    let _interest_guard = tracing::Dispatch::new(tracing_subscriber::registry());
    tracing::subscriber::with_default(subscriber, || {
        let warnings = || {
            String::from_utf8(buffer.lock().unwrap().clone())
                .unwrap()
                .lines()
                .filter(|line| line.contains("pattern admits ambiguous aliases"))
                .count()
        };
        let peers = Arc::new(PeersMap::load_from_file(&peers_path).unwrap());
        assert_eq!(
            warnings(),
            0,
            "grt4 generic config parsing emitted an operator warning"
        );
        let reloader = xmsg::fed::CredentialReloader::new_full(
            cert_path,
            key_path,
            Some(peers_path.clone()),
            None,
            peers,
            None,
            Default::default(),
        )
        .unwrap();
        assert_eq!(
            warnings(),
            1,
            "grt4 startup did not emit exactly one ambiguity class"
        );
        assert!(!reloader.check_and_reload().unwrap());
        assert_eq!(
            warnings(),
            1,
            "grt4 unchanged config repeated an ambiguity warning"
        );
        assert!(reloader.force_reload().unwrap());
        assert_eq!(
            warnings(),
            2,
            "grt4 successful reload did not emit one ambiguity class"
        );
        fs::write(&peers_path, "invalid json").unwrap();
        assert!(reloader.force_reload().is_err());
        assert_eq!(
            warnings(),
            2,
            "grt4 failed reload published an ambiguity warning"
        );
        fs::write(&peers_path, config.to_string()).unwrap();
        fs::write(&reloader.key_path, "invalid private key fixture").unwrap();
        assert!(reloader.force_reload().is_err());
        assert_eq!(
            warnings(),
            2,
            "grt4 failed TLS reload published an ambiguity warning"
        );
        fs::write(&reloader.key_path, grt4_pem("PRIVATE KEY", &key)).unwrap();
        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        let warning_lines: Vec<_> = output
            .lines()
            .filter(|line| line.contains("pattern admits ambiguous aliases"))
            .collect();
        assert!(
            warning_lines.iter().all(|line| line.contains("*.pods")
                && line.contains("host/user")
                && line.contains("ns/sa")),
            "grt4 warning omitted its alias class or colliding forms"
        );
        assert!(
            warning_lines.iter().all(|line| !line.contains("spiffe://")),
            "grt4 ambiguity warning exposed a full URI witness"
        );
        config["hub"]["patterns"] = serde_json::json!([
            "spiffe://example.invalid/host/pods/user/line\nbreak",
            "spiffe://example.invalid/ns/pods/sa/line\nbreak"
        ]);
        config["hub"]["rules"] = serde_json::json!([]);
        fs::write(&peers_path, config.to_string()).unwrap();
        reloader.force_reload().unwrap();
        let escaped = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        let last = escaped
            .lines()
            .rfind(|line| line.contains("pattern admits ambiguous aliases"))
            .unwrap();
        assert!(
            last.contains("line\\nbreak.pods"),
            "grt4 published warning split its alias over log lines"
        );
    });
}

#[test]
fn grt4_check_peers_reports_ambiguity_without_invalidating_config() {
    let (_, _, _, pem) = generate_ca("grt4 offline check CA");
    let (temp, config) = grt4_mixed_config(&pem);
    let file = temp.path().join("peers.json");
    fs::write(&file, config).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .arg("check-peers")
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "grt4 offline ambiguity warning invalidated a permitted config"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.contains("pattern admits ambiguous aliases"))
            .count(),
        1,
        "grt4 offline pre-upgrade check omitted or duplicated its ambiguity warning"
    );
    assert!(
        stderr.contains("*.pods") && stderr.contains("host/user") && stderr.contains("ns/sa"),
        "grt4 offline warning omitted its safe class details"
    );
    assert!(
        !stderr.contains("spiffe://"),
        "grt4 offline warning exposed a full URI witness"
    );
}

struct Grt4Child(std::process::Child);
impl Drop for Grt4Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < until {
            if self.0.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn grt4_serve_startup_reports_its_ambiguity_class_once() {
    use std::io::{Read, Write};
    let (params, ca_key, _, pem) = generate_ca("grt4 startup CA");
    let (temp, config) = grt4_mixed_config(&pem);
    let file = temp.path().join("peers.json");
    fs::write(&file, config).unwrap();
    for name in ["run", "sessions", "codex"] {
        use std::os::unix::fs::PermissionsExt;
        let directory = temp.path().join(name);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let http = temp.path().join("run/http.sock");
    let (cert, key) = issue_cert(
        &params,
        &ca_key,
        "serve.server",
        &["spiffe://example.invalid/ns/server/sa/serve"],
    );
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    fs::write(&cert_path, grt4_pem("CERTIFICATE", &cert)).unwrap();
    fs::write(&key_path, grt4_pem("PRIVATE KEY", &key)).unwrap();
    let log = temp.path().join("stderr.log");
    let log_file = fs::File::create(&log).unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("XMSG_") {
            command.env_remove(key);
        }
    }
    command
        .scrub_agy_env()
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_FDNAMES")
        .env("RUST_LOG", "warn")
        .env("XDG_RUNTIME_DIR", temp.path().join("run"))
        .arg("serve")
        .arg("--http-sock")
        .arg(&http)
        .arg("--agent-sock")
        .arg(temp.path().join("run/agent.sock"))
        .arg("--register-sock")
        .arg(temp.path().join("run/register.sock"))
        .arg("--sessions-dir")
        .arg(temp.path().join("sessions"))
        .arg("--codex-home")
        .arg(temp.path().join("codex"))
        .arg("--db-path")
        .arg(temp.path().join("db.sqlite"))
        .arg("--peers-file")
        .arg(&file)
        .arg("--fed-cert")
        .arg(&cert_path)
        .arg("--fed-key")
        .arg(&key_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log_file.try_clone().unwrap()))
        .stderr(std::process::Stdio::from(log_file));
    let mut child = Grt4Child(command.spawn().unwrap());
    let until = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "grt4 startup fixture exited before health readiness: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&http) {
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            if stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
                .is_ok()
            {
                let mut response = String::new();
                let _ = stream.read_to_string(&mut response);
                if response.starts_with("HTTP/1.1 200") {
                    break;
                }
            }
        }
        assert!(
            std::time::Instant::now() < until,
            "grt4 startup fixture did not reach health readiness: {}",
            fs::read_to_string(&log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = fs::read_to_string(log).unwrap();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.contains("pattern admits ambiguous aliases"))
            .count(),
        1,
        "grt4 serve startup omitted or duplicated its ambiguity class warning"
    );
}

#[test]
fn grt4_offline_warning_escapes_control_characters() {
    let (_, _, _, pem) = generate_ca("grt4 escaped class CA");
    let (temp, config) = grt4_mixed_config(&pem);
    let mut config: serde_json::Value = serde_json::from_str(&config).unwrap();
    config["hub"]["patterns"] = serde_json::json!([
        "spiffe://example.invalid/host/pods/user/line\nbreak",
        "spiffe://example.invalid/ns/pods/sa/line\nbreak"
    ]);
    config["hub"]["rules"] = serde_json::json!([]);
    let file = temp.path().join("peers.json");
    fs::write(&file, config.to_string()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .env("RUST_LOG", "off")
        .arg("check-peers")
        .arg(file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "grt4 escaped class fixture is not a permitted config"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr.lines().count(),
        1,
        "grt4 offline warning split its alias over lines"
    );
    assert!(
        stderr.contains("line\\nbreak.pods"),
        "grt4 offline warning omitted its escaped alias"
    );
}

fn grt4_app_state(fed: Arc<FedState>) -> Arc<xmsg::http::AppState> {
    Arc::new(xmsg::http::AppState {
        sessions_dirs: fed.sessions_dirs.clone(),
        agy_config: fed.agy_config.clone(),
        agy_store: fed.agy_store.clone(),
        pi_store: fed.pi_store.clone(),
        pi_notify_tx: fed.pi_notify_tx.clone(),
        svc_store: fed.svc_store.clone(),
        svc_notify_tx: fed.svc_notify_tx.clone(),
        node_name: fed.node_name.clone(),
        max_body: fed.max_body,
        max_attachment_bytes: fed.max_attachment_bytes,
        request_counter: AtomicU64::new(1),
        db: fed.db.clone(),
        notify_tx: fed.notify_tx.clone(),
        reply_ttl: fed.reply_ttl,
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(fed),
    })
}

#[tokio::test]
async fn grt4_ambiguous_alias_never_uses_default_route() {
    let (params, key, _, pem) = generate_ca("grt4 route CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let mut config: serde_json::Value = serde_json::from_str(&config).unwrap();
    config["peers"]["upstream"] = serde_json::json!({
        "address": "127.0.0.1:1", "pin": "00".repeat(32),
        "allow": ["send", "reply"], "default_route": true
    });
    let peers = PeersMap::load_from_json(&config.to_string()).unwrap();
    assert!(
        peers.default_route_link().is_some(),
        "grt4 default-route fixture has no fallback link"
    );
    let (cert, key) = issue_cert(
        &params,
        &key,
        "hub.hub",
        &["spiffe://example.invalid/ns/hub/sa/hub"],
    );
    let hub = create_test_node("hub.hub", peers, cert, Vec::new(), key).await;
    let app = grt4_app_state(hub.fed_state.clone());
    let result = xmsg::surface::send(
        &app,
        &xmsg::surface::Sender::Anonymous("fixture".into()),
        "worker@guard.pods",
        "must not route",
        None,
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Ambiguous(_))),
        "grt4 ambiguous alias selected a default or direct route"
    );
    let db = app.db.lock().unwrap();
    for table in ["messages", "outbound", "peer_mailbox"] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            count, 0,
            "grt4 refused ambiguous send wrote routing authority state"
        );
    }
}

#[test]
fn grt4_wildcard_identity_cannot_claim_the_hubs_own_alias() {
    use rustls::server::danger::ClientCertVerifier;
    let (params, key, _, pem) = generate_ca("grt4 own reservation CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let mut config: serde_json::Value = serde_json::from_str(&config).unwrap();
    config["hub"]["patterns"] = serde_json::json!(["spiffe://example.invalid/host/*/user/*"]);
    config["hub"]["rules"] = serde_json::json!([{"pattern": "spiffe://example.invalid/host/*/user/*", "allow": ["send"]}]);
    let peers = Arc::new(
        PeersMap::load_from_json_for(
            &config.to_string(),
            Some(&xmsg::fed::OwnNode {
                name: "hub.pods".into(),
                pin: None,
            }),
        )
        .unwrap(),
    );
    let verifier = xmsg::fed::CombinedClientCertVerifier::new(peers.clone());
    let ordinary_uri = "spiffe://example.invalid/host/normal/user/alice";
    let (ordinary, _) = issue_cert(&params, &key, "alice.normal", &[ordinary_uri]);
    let ordinary = rustls::pki_types::CertificateDer::from(ordinary);
    assert!(
        verifier
            .verify_client_cert(&ordinary, &[], rustls::pki_types::UnixTime::now())
            .is_ok(),
        "grt4 own-name fixture rejected an unrelated client certificate"
    );
    assert!(
        peers.resolve_incoming_peer(&ordinary, &[]).is_ok(),
        "grt4 own-name fixture rejected ordinary registration"
    );
    let hostile_uri = "spiffe://example.invalid/host/pods/user/hub";
    let (hostile, _) = issue_cert(&params, &key, "hub.pods", &[hostile_uri]);
    let hostile = rustls::pki_types::CertificateDer::from(hostile);
    assert!(
        verifier
            .verify_client_cert(&hostile, &[], rustls::pki_types::UnixTime::now())
            .is_err(),
        "grt4 TLS wildcard claimant captured this hubs own alias"
    );
    assert!(
        matches!(
            peers.resolve_incoming_peer(&hostile, &[]),
            Err(AppError::PeerRejected(_))
        ),
        "grt4 request wildcard claimant captured this hubs own alias"
    );
    assert!(
        peers.get_peer_config("hub.pods").is_none(),
        "grt4 own alias remained externally routable"
    );
    assert_eq!(
        peers.admitted_names(),
        vec!["alice.normal"],
        "grt4 own alias leaked into admitted listings"
    );
    assert!(
        !peers
            .admitted_clients
            .read()
            .unwrap()
            .contains_key(hostile_uri),
        "grt4 refused own-name claimant left a registered identity"
    );
    config["hub"]["patterns"] = serde_json::json!(["spiffe://example.invalid/*/pods/*/hub"]);
    let reserved = PeersMap::load_from_json_for(
        &config.to_string(),
        Some(&xmsg::fed::OwnNode {
            name: "hub.pods".into(),
            pin: None,
        }),
    )
    .unwrap();
    assert!(
        !reserved.is_ambiguous_alias("hub.pods"),
        "grt4 own reservation became an ambiguous external address"
    );
    assert!(
        reserved.ambiguous_alias_classes().is_empty(),
        "grt4 own reservation produced a dynamic ambiguity warning"
    );
}

#[tokio::test]
async fn grt4_direct_name_lease_reserves_the_running_node() {
    let (params, key, _, pem) = generate_ca("grt4 direct lease CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let peers = PeersMap::load_from_json(&config).unwrap();
    let (cert, key) = issue_cert(
        &params,
        &key,
        "issuer.hub",
        &["spiffe://example.invalid/ns/hub/sa/issuer"],
    );
    let node = create_test_node("issuer.hub", peers, cert, Vec::new(), key).await;
    for renewal in [false, true] {
        assert!(
            node.fed_state
                .lease_enrollment_name("spiffe://example.invalid/host/hub/user/issuer", renewal)
                .is_err(),
            "grt4 FedState issued a name lease for its own running node"
        );
    }
    let lease = node
        .fed_state
        .lease_enrollment_name("spiffe://example.invalid/host/normal/user/alice", false)
        .expect("grt4 unrelated direct name lease positive failed");
    assert!(
        node.fed_state.dynamic_tls.try_write().is_err(),
        "grt4 direct name lease did not retain publication read lock"
    );
    drop(lease);
    assert!(
        node.fed_state.dynamic_tls.try_write().is_ok(),
        "grt4 direct name lease did not release publication read lock"
    );
}

#[tokio::test]
async fn grt4_concrete_name_lease_matches_the_exact_uri_and_mode() {
    let (params, key, _, pem) = generate_ca("grt4 concrete lease CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let original = "spiffe://example.invalid/host/normal/user/alice";
    for configured in [original, "spiffe://other.invalid/ns/normal/sa/alice"] {
        let mut config: serde_json::Value = serde_json::from_str(&config).unwrap();
        config["peers"]["alice.normal"] = serde_json::json!({
            "ca": config["peers"]["hub.hub"]["ca"], "identities": [configured],
            "leaf": true, "allow": ["send", "reply"]
        });
        let peers = PeersMap::load_from_json(&config.to_string()).unwrap();
        let (cert, server_key) = issue_cert(
            &params,
            &key,
            "issuer.hub",
            &["spiffe://example.invalid/ns/hub/sa/issuer"],
        );
        let node = create_test_node("issuer.hub", peers, cert, Vec::new(), server_key).await;
        assert!(
            node.fed_state
                .lease_enrollment_name(original, false)
                .is_err(),
            "grt4 fresh issuance bypassed a concrete name reservation"
        );
        if configured == original {
            assert!(
                node.fed_state.lease_enrollment_name(original, true).is_ok(),
                "grt4 bound same-URI renewal lost its concrete lease"
            );
        } else {
            assert!(
                node.fed_state
                    .lease_enrollment_name(original, true)
                    .is_err(),
                "grt4 foreign concrete URI received a renewal lease"
            );
        }
    }
}

#[test]
fn grt4_loader_enforces_concrete_name_identity_invariants() {
    let (_, _, _, pem) = generate_ca("grt4 loader invariant CA");
    let (temp, _) = grt4_mixed_config(&pem);
    let pin = serde_json::json!({"peers": {"alice.remote": {
        "pin": "00".repeat(32), "address": "127.0.0.1:1", "allow": ["send"]
    }}});
    assert!(
        PeersMap::load_from_json(&pin.to_string()).is_err(),
        "grt4 loader admitted a dotted pin nickname"
    );
    let ca = serde_json::json!({"peers": {"alice.remote": {
        "ca": temp.path().join("ca.pem"), "address": "127.0.0.1:1", "allow": ["send"],
        "identities": ["spiffe://one/host/remote/user/alice", "spiffe://two/host/remote/user/alice"]
    }}});
    assert!(
        PeersMap::load_from_json(&ca.to_string()).is_err(),
        "grt4 loader admitted multiple concrete CA identities"
    );
}

#[test]
fn grt4_dynamic_registry_uses_current_uri_and_rule_grants() {
    let (params, key, _, pem) = generate_ca("grt4 current registry CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let mut config: serde_json::Value = serde_json::from_str(&config).unwrap();
    let pattern_a = "spiffe://example.invalid/host/*/user/*";
    let uri_a = "spiffe://example.invalid/host/normal/user/alice";
    config["hub"]["patterns"] = serde_json::json!([pattern_a]);
    config["hub"]["rules"] = serde_json::json!([{"pattern": uri_a, "allow": ["send", "observe"], "leaf": true, "observe_labels": true, "targets": ["wide"]}]);
    let old = PeersMap::load_from_json(&config.to_string()).unwrap();
    let (cert_a, _) = issue_cert(&params, &key, "alice.normal", &[uri_a]);
    let cert_a = rustls::pki_types::CertificateDer::from(cert_a);
    let (admitted_a, _) = old.resolve_incoming_peer(&cert_a, &[]).unwrap();
    assert!(
        old.get_peer_config("alice.normal").is_some(),
        "grt4 admitted URI lacks name-based routing"
    );
    config["hub"]["rules"] = serde_json::json!([{"pattern": pattern_a, "allow": ["list"], "leaf": false, "targets": ["narrow"]}]);
    let mut current = PeersMap::load_from_json(&config.to_string()).unwrap();
    current.admitted_clients = old.admitted_clients.clone();
    old.resolve_incoming_peer(&cert_a, &[]).unwrap();
    let grant = current
        .get_peer_config("alice.normal")
        .expect("grt4 current grant lookup lost an admitted URI");
    assert_eq!(
        grant.allow,
        vec!["list"],
        "grt4 dynamic lookup restored stale allow grants"
    );
    assert!(
        !grant.leaf,
        "grt4 dynamic lookup restored stale leaf status"
    );
    assert!(
        !grant.observe_labels,
        "grt4 dynamic lookup restored stale label permission"
    );
    assert_eq!(
        grant.targets,
        Some(vec!["narrow".into()]),
        "grt4 dynamic lookup restored stale target grants"
    );
    assert_eq!(
        current.admitted_names(),
        vec!["alice.normal"],
        "grt4 admitted listing exposed a URI key"
    );
    let pattern_b = "spiffe://other.invalid/host/*/user/*";
    config["hub"]["patterns"] = serde_json::json!([pattern_b]);
    config["hub"]["rules"] = serde_json::json!([{"pattern": pattern_b, "allow": ["list"]}]);
    let mut reassigned = PeersMap::load_from_json(&config.to_string()).unwrap();
    reassigned.admitted_clients = old.admitted_clients.clone();
    assert!(
        reassigned.get_peer_config("alice.normal").is_none(),
        "grt4 retired URI remained name-routable"
    );
    assert!(
        reassigned.admitted_names().is_empty(),
        "grt4 retired URI remained in admitted listings"
    );
    let uri_b = "spiffe://other.invalid/host/normal/user/alice";
    let (cert_b, _) = issue_cert(&params, &key, "alice.normal", &[uri_b]);
    reassigned
        .resolve_incoming_peer(&rustls::pki_types::CertificateDer::from(cert_b), &[])
        .unwrap();
    let old_peer = xmsg::fed::AuthenticatedPeer {
        name: "alice.normal".into(),
        pin: admitted_a.pin.unwrap(),
        uri: Some(uri_a.into()),
        certificate_has_uri: true,
        user: "alice".into(),
        remote_ip: "127.0.0.1".parse().unwrap(),
    };
    assert!(
        matches!(
            reassigned.get_authenticated_peer_config(&old_peer),
            Err(AppError::PeerRejected(_))
        ),
        "grt4 current URI lookup lent replacement grants to an old URI"
    );
    assert_eq!(
        reassigned.admitted_names(),
        vec!["alice.normal"],
        "grt4 reassigned registry duplicated or exposed identity keys"
    );
}

#[test]
fn grt4_concrete_pod_reserves_its_name_before_any_connection() {
    use rustls::server::danger::ClientCertVerifier;
    let (params, key, _, pem) = generate_ca("grt4 static pod CA");
    let (_temp, config) = grt4_mixed_config(&pem);
    let mut config: serde_json::Value = serde_json::from_str(&config).unwrap();
    config["hub"]["patterns"] = serde_json::json!(["spiffe://example.invalid/host/*/user/*"]);
    config["hub"]["rules"] = serde_json::json!([{"pattern": "spiffe://example.invalid/host/*/user/*", "allow": ["send"]}]);
    let pod_uri = "spiffe://example.invalid/ns/pods/sa/guard";
    config["peers"]["guard.pods"] = serde_json::json!({
        "ca": config["peers"]["hub.hub"]["ca"], "identities": [pod_uri],
        "leaf": true, "allow": ["send", "reply", "list"]
    });
    for _restart in 0..2 {
        let peers = Arc::new(PeersMap::load_from_json(&config.to_string()).unwrap());
        let verifier = xmsg::fed::CombinedClientCertVerifier::new(peers.clone());
        let (host, _) = issue_cert(
            &params,
            &key,
            "guard.pods",
            &["spiffe://example.invalid/host/pods/user/guard"],
        );
        let host = rustls::pki_types::CertificateDer::from(host);
        assert!(
            verifier
                .verify_client_cert(&host, &[], rustls::pki_types::UnixTime::now())
                .is_err(),
            "grt4 TLS host captured a reserved offline pod name"
        );
        assert!(
            matches!(
                peers.resolve_incoming_peer(&host, &[]),
                Err(AppError::PeerRejected(_))
            ),
            "grt4 host registered against an offline concrete pod reservation"
        );
        let (pod, _) = issue_cert(&params, &key, "guard.pods", &[pod_uri]);
        let pod = rustls::pki_types::CertificateDer::from(pod);
        assert!(
            verifier
                .verify_client_cert(&pod, &[], rustls::pki_types::UnixTime::now())
                .is_ok(),
            "grt4 concrete pod TLS positive was refused"
        );
        let (config, uri) = peers
            .resolve_incoming_peer(&pod, &[])
            .expect("grt4 concrete pod registration positive failed");
        assert_eq!(
            uri.as_deref(),
            Some(pod_uri),
            "grt4 static pod admission lost full identity"
        );
        assert!(
            config.leaf && config.address.is_empty(),
            "grt4 concrete pod no longer has addressless leaf semantics"
        );
        assert!(
            peers.admitted_clients.read().unwrap().is_empty(),
            "grt4 concrete pod created a dynamic identity row"
        );
    }
}
