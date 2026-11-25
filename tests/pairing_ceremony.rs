//! Integration tests for discovery PR 4 (§5.5 oracles & carry-in conditions).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use tempfile::TempDir;
use tower::ServiceExt;

use xmsg::discovery::mdns::{Backend, Engine, Event, Inputs, ProbeOutcome};
use xmsg::discovery::{AnnounceMode, AnnouncePosture, MdnsConfig, SharedCandidates, SharedStatus};
use xmsg::fed::{FedState, PeersMap, RateLimiter};
use xmsg::http::{build_router, build_unix_router_with_enrollment, AppState};
use xmsg::pairing::codec::{PairingProfile, SpkiDeviceId};
use xmsg::pairing::service::{pairing_runtime, IntentRole};

fn gen_ed25519_identity() -> (Vec<u8>, Vec<u8>, String) {
    let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let params = CertificateParams::new(vec!["xmsg-pair.local".to_string()]).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    let cert_der = cert.der().to_vec();
    let key_der = kp.serialize_der();
    let spki = xmsg::pairing::ceremony::spki_der_from_cert(&cert_der).unwrap();
    let id = SpkiDeviceId::from_spki_der(&spki)
        .unwrap()
        .to_device_id_string();
    (cert_der, key_der, id)
}

fn test_fed_state(dir: &TempDir) -> Arc<FedState> {
    let (cert_der, key_der, _) = gen_ed25519_identity();
    let conn = rusqlite::Connection::open(dir.path().join("xmsg.db")).unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    Arc::new(FedState {
        discovery: Default::default(),
        node_name: "test.local".into(),
        peers: Arc::new(PeersMap::empty()).into(),
        cert_der,
        cert_chain_der: Vec::new(),
        key_der,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: Arc::new(Mutex::new(conn)),
        sessions_dirs: vec![dir.path().join("sessions")],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: dir.path().join("presence"),
            brain_dir: dir.path().join("brain"),
            ..Default::default()
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        notify_tx: tokio::sync::broadcast::channel(16).0,
        max_body: 65536,
        max_attachment_bytes: 8 * 1024 * 1024,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Default::default(),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    })
}

fn test_app_state(dir: &TempDir, fed: Arc<FedState>) -> Arc<AppState> {
    let sessions_dir = dir.path().join("sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    Arc::new(AppState {
        sessions_dirs: vec![sessions_dir],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: dir.path().join("presence"),
            brain_dir: dir.path().join("brain"),
            ..Default::default()
        },
        agy_store: fed.agy_store.clone(),
        pi_store: fed.pi_store.clone(),
        pi_notify_tx: fed.pi_notify_tx.clone(),
        svc_store: fed.svc_store.clone(),
        svc_notify_tx: fed.svc_notify_tx.clone(),
        node_name: "test.local".into(),
        max_body: 65536,
        max_attachment_bytes: 8 * 1024 * 1024,
        request_counter: Default::default(),
        db: fed.db.clone(),
        notify_tx: tokio::sync::broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        fed_state: Some(fed),
    })
}

#[tokio::test]
async fn q2_3b_and_q2_5a_5b_intent_role_reconfirm_conflict_and_32_cap() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let rt = pairing_runtime(&fed);
    rt.service.attempt_startup_cancel(&fed).unwrap();

    let (cert_b, key_b, peer_b) = gen_ed25519_identity();
    let (intent, reconf) = rt
        .service
        .create_intent(
            &fed,
            &peer_b,
            IntentRole::Initiator,
            PairingProfile::Contact,
            vec!["svc-a".into()],
            vec![],
            None,
        )
        .await
        .unwrap();
    assert!(!reconf);
    // Q2-3b: initiator intent admits no inbound ceremony (both service gate and TLS verifier).
    let peer_b_id = SpkiDeviceId::parse_device_id_string(&peer_b).unwrap().0;
    assert!(!rt.service.has_live_responder_intent());
    assert!(!rt.service.has_live_responder_intent_for(&peer_b_id));
    let rt_chk = rt.clone();
    let allowed_fn: xmsg::pairing::ceremony::AllowedPeerCheck =
        Arc::new(move |id| rt_chk.service.has_live_responder_intent_for(id));
    let (srv_cfg, _) = xmsg::pairing::ceremony::build_pairing_server_config(
        vec![rustls::pki_types::CertificateDer::from(fed.cert_der.clone())],
        rustls::pki_types::PrivateKeyDer::try_from(fed.key_der.clone()).unwrap(),
        allowed_fn,
        Some(fed.current_peers()),
    )
    .unwrap();
    let (cli_cfg, _) = xmsg::pairing::ceremony::build_pairing_client_config(
        vec![rustls::pki_types::CertificateDer::from(cert_b)],
        rustls::pki_types::PrivateKeyDer::try_from(key_b).unwrap(),
        xmsg::pairing::ceremony::ed25519_device_id_from_cert(&fed.cert_der)
            .unwrap()
            .0,
        None,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tokio_rustls::TlsAcceptor::from(srv_cfg).accept(tcp).await
    });
    let tcp_cli = tokio::net::TcpStream::connect(addr).await.unwrap();
    let dns = rustls::pki_types::ServerName::try_from("xmsg-pair.local").unwrap();
    let cli_res = tokio_rustls::TlsConnector::from(cli_cfg)
        .connect(dns, tcp_cli)
        .await;
    let srv_res = srv_task.await.unwrap();
    assert!(
        cli_res.is_err() || srv_res.is_err(),
        "Q2-3b: initiator intent must not admit inbound pairing TLS"
    );

    // Exact repeat reconfirms same intent_id.
    let (intent2, reconf2) = rt
        .service
        .create_intent(
            &fed,
            &peer_b,
            IntentRole::Initiator,
            PairingProfile::Contact,
            vec!["svc-a".into()],
            vec![],
            None,
        )
        .await
        .unwrap();
    assert!(reconf2);
    assert_eq!(intent.intent_id, intent2.intent_id);

    // Q2-5a: different role/params -> pairing.intent_exists.
    let err = rt
        .service
        .create_intent(
            &fed,
            &peer_b,
            IntentRole::Responder,
            PairingProfile::Contact,
            vec!["svc-a".into()],
            vec![],
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "pairing.intent_exists");

    // Q2-5b: fill to 32, 33rd -> pairing.intents_full.
    for _ in 1..32 {
        let (_, _, pid) = gen_ed25519_identity();
        rt.service
            .create_intent(
                &fed,
                &pid,
                IntentRole::Responder,
                PairingProfile::OwnerDevice,
                vec![],
                vec![],
                None,
            )
            .await
            .unwrap();
    }
    let (_, _, pid33) = gen_ed25519_identity();
    let full_err = rt
        .service
        .create_intent(
            &fed,
            &pid33,
            IntentRole::Responder,
            PairingProfile::OwnerDevice,
            vec![],
            vec![],
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(full_err.code(), "pairing.intents_full");
}

#[tokio::test]
async fn q2_11_tcp_router_returns_404_and_unix_router_mounts_pairing() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let state = test_app_state(&dir, fed);
    let tcp_router = build_router(state.clone());
    let unix_router = build_unix_router_with_enrollment(state, Default::default());

    for path in ["/v1/pairing/id", "/v1/pairing/list", "/v1/diagnostics/pairing"] {
        let resp = tcp_router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "TCP must 404 {path}");
    }
    // Without PeerInfo (non-Unix), Unix-only routes deny instead of 404.
    let unix_resp = unix_router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/pairing/id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unix_resp.status(), StatusCode::FORBIDDEN);

    // Q2-11: Real same-UID PeerInfo with pid: None must refuse pairing.caller_indeterminate
    // on mutations (a same-UID-only mutant would let this proceed past caller auth).
    let indeterminate_peer = axum::extract::ConnectInfo(xmsg::http::HttpPeer {
        peer: Some(xmsg::process::PeerCred::unpinned(
            xmsg::agent::current_uid(),
            999_999_999,
        )),
    });
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/pairing/cancel")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"target":"00000000000000000000000000000000"}"#))
        .unwrap();
    req.extensions_mut().insert(indeterminate_peer);
    let cancel_resp = unix_router.clone().oneshot(req).await.unwrap();
    assert_eq!(cancel_resp.status(), StatusCode::FORBIDDEN);
    let body_bytes = axum::body::to_bytes(cancel_resp.into_body(), 4096)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(
        body_str.contains("pairing.caller_indeterminate"),
        "expected pairing.caller_indeterminate, got: {body_str}"
    );

    // Q2-11: MCP tools/list exposes zero pairing tools.
    let mcp_resp = unix_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let mcp_bytes = axum::body::to_bytes(mcp_resp.into_body(), 65536)
        .await
        .unwrap();
    let mcp_str = String::from_utf8_lossy(&mcp_bytes);
    assert!(
        !mcp_str.contains("pair"),
        "MCP tools/list must expose zero pairing tools: {mcp_str}"
    );
}

#[derive(Default)]
struct NoopMdnsBackend {
    registered: usize,
    unregistered: usize,
}

impl Backend for NoopMdnsBackend {
    fn start(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn register(
        &mut self,
        _id: &str,
        _port: u16,
        _addrs: &[std::net::IpAddr],
        _txt: &[(String, String)],
    ) -> Result<(), String> {
        self.registered += 1;
        Ok(())
    }
    fn unregister(&mut self) {
        self.unregistered += 1;
    }
    fn stop(&mut self) {}
    fn recv(&mut self, _timeout: Duration) -> Option<Event> {
        None
    }
    fn interfaces(&self) -> Vec<(String, std::net::IpAddr)> {
        vec![("eth0".into(), "10.0.0.1".parse().unwrap())]
    }
    fn probe_multicast(&mut self, _qname: &str, _addrs: &[std::net::Ipv4Addr]) -> ProbeOutcome {
        ProbeOutcome::SentOk
    }
}

#[test]
fn q2_12_mdns_timed_window_closes_through_close_announce_window() {
    let status = SharedStatus::default();
    let candidates = SharedCandidates::default();
    let mut engine = Engine::with_trigger(
        NoopMdnsBackend::default(),
        Box::new(|| Ok("abc123".into())),
        status.clone(),
        candidates,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let inputs = Inputs {
        mdns: Some(MdnsConfig {
            browse: true,
            announce: true,
        }),
        announce: AnnounceMode::Timed,
        ttl_secs: 120,
        fed_listen: Some("10.0.0.1:7788".parse().unwrap()),
    };
    let now = Instant::now();
    engine.reconcile(&inputs, now);
    assert!(engine.activate_announce_window(&inputs, now));
    assert!(matches!(
        status.lock().unwrap().posture,
        AnnouncePosture::WindowOpen { .. }
    ));
    assert!(engine.close_announce_window(now + Duration::from_secs(1)));
    assert_eq!(status.lock().unwrap().posture, AnnouncePosture::AtRest);
    assert!(!engine.close_announce_window(now + Duration::from_secs(2)));
}

#[test]
fn q2_14_peers_file_rejects_deferred_preference_keys_in_both_forms() {
    for raw in [
        r#"{"pairing.confirm": true}"#,
        r#"{"discovery.announce_identity": true}"#,
        r#"{"auto_accept": {}}"#,
        r#"{"attestation.offline_grace": 60}"#,
    ] {
        let err = PeersMap::load_from_json_for(raw, None).unwrap_err();
        assert!(
            err.contains("unsupported"),
            "bare deferred key must fail as unsupported, got: {err}"
        );
    }
    for raw in [
        r#"{"peers": {}, "pairing": {}}"#,
        r#"{"peers": {}, "discovery": {"announce_identity": true}}"#,
    ] {
        let err = PeersMap::load_from_json_for(raw, None).unwrap_err();
        assert!(!err.is_empty(), "expected error for {raw}");
    }
}

#[tokio::test]
async fn q2_15c2_startup_cancel_failure_blocks_ceremonies_allows_revocation_and_recovers() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let rt = pairing_runtime(&fed);

    // Seed a pre-restart open intent holding a capacity reservation.
    let (_, _, peer_b) = gen_ed25519_identity();
    let peer_b_id = SpkiDeviceId::parse_device_id_string(&peer_b).unwrap().0;
    {
        let db = fed.db.lock().unwrap();
        let exp = xmsg::pairing::codec::ExposurePolicy {
            profile: PairingProfile::OwnerDevice,
            target_selectors: vec!["*".into()],
            principal_selectors: vec!["*".into()],
            max_body_bytes: 65536,
            max_attachment_bytes: 65536,
            rate_burst: 10,
            rate_per_minute: 60,
        };
        let req = xmsg::pairing::store::IntentRequest {
            peer: peer_b_id,
            exposure: exp,
            grant_not_after: None,
            revision: 1,
            expires_at: 1120,
            replaces: None,
        };
        let intent = xmsg::pairing::store::reserve_intent(&db, &req, 1000).unwrap();
        xmsg::pairing::store::reserve_capacity(&db, &intent.intent_id, 1000).unwrap();
        assert_eq!(xmsg::pairing::store::count_slots_used(&db).unwrap(), 1);
    }

    // Fail the product startup-cancel transaction via a SQLite trigger (not a test-hook flag).
    {
        let db = fed.db.lock().unwrap();
        db.execute_batch(
            "CREATE TRIGGER fail_startup_cancel BEFORE UPDATE ON pairing_intents
             WHEN NEW.state = 'cancelled' AND OLD.expires_at = 1120
             BEGIN SELECT RAISE(ABORT, 'injected db failure'); END;",
        )
        .unwrap();
    }
    let err = rt.service.attempt_startup_cancel(&fed).unwrap_err();
    assert_eq!(err.code(), "pairing.startup_cancel_failed");
    assert!(!rt.service.is_startup_cancel_done());
    assert!(!rt.service.has_live_responder_intent());

    // accept/start refuse pairing.startup_cancel_failed, and reservation stays counted.
    let (_, _, peer_c) = gen_ed25519_identity();
    let acc_err = rt
        .service
        .create_intent(
            &fed,
            &peer_c,
            IntentRole::Responder,
            PairingProfile::OwnerDevice,
            vec![],
            vec![],
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(acc_err.code(), "pairing.startup_cancel_failed");
    {
        let db = fed.db.lock().unwrap();
        assert_eq!(xmsg::pairing::store::count_slots_used(&db).unwrap(), 1);
    }

    // Revocation (block + remove) still succeeds while startup cancel is failing.
    rt.service.block_device(&fed, &peer_c).await.unwrap();
    let (_, _, peer_d) = gen_ed25519_identity();
    let peer_d_id = SpkiDeviceId::parse_device_id_string(&peer_d).unwrap().0;
    let g_d = seed_manual_grant(&fed, peer_d_id, PairingProfile::Contact, vec!["svc-a".into()], None);
    rt.service.remove_grant(&fed, &hex::encode(g_d)).await.unwrap();
    // Doctor diagnostics warn pairing.startup_cancel_failed.
    let diag = rt.service.diagnostics(&fed, true).await.unwrap();
    assert_eq!(diag["pairing.startup"]["code"], "pairing.startup_cancel_failed");

    // Clear the fault and recover via watcher tick (`retry_startup_cancel_if_needed`), NOT create_intent.
    {
        let db = fed.db.lock().unwrap();
        db.execute_batch("DROP TRIGGER fail_startup_cancel;").unwrap();
    }
    rt.service.attempt_startup_cancel(&fed).unwrap();
    assert!(rt.service.is_startup_cancel_done());
    // Artemis: re-read slot count after recovery -> 0 slots used!
    {
        let db = fed.db.lock().unwrap();
        assert_eq!(xmsg::pairing::store::count_slots_used(&db).unwrap(), 0);
    }
    let diag2 = rt.service.diagnostics(&fed, true).await.unwrap();
    assert_eq!(diag2["pairing.startup"]["status"], "pass");
    // Now accept succeeds for unblocked peer_d.
    let _ = rt
        .service
        .create_intent(
            &fed,
            &peer_d,
            IntentRole::Responder,
            PairingProfile::OwnerDevice,
            vec![],
            vec![],
            None,
        )
        .await
        .unwrap();
}

fn seed_manual_grant(
    fed: &FedState,
    peer_id: [u8; 32],
    profile: PairingProfile,
    targets: Vec<String>,
    not_after: Option<i64>,
) -> [u8; 16] {
    let own_id = xmsg::pairing::ceremony::ed25519_device_id_from_cert(&fed.cert_der)
        .unwrap()
        .0;
    let db = fed.db.lock().unwrap();
    let exp = xmsg::pairing::codec::ExposurePolicy {
        profile,
        target_selectors: targets,
        principal_selectors: vec!["*".into()],
        max_body_bytes: 65536,
        max_attachment_bytes: 65536,
        rate_burst: 10,
        rate_per_minute: 60,
    };
    let req = xmsg::pairing::store::IntentRequest {
        peer: peer_id,
        exposure: exp,
        grant_not_after: not_after,
        revision: 1,
        expires_at: xmsg::storage::now_epoch_secs() + 120,
        replaces: None,
    };
    let intent = xmsg::pairing::store::reserve_intent(&db, &req, xmsg::storage::now_epoch_secs()).unwrap();
    xmsg::pairing::store::reserve_capacity(&db, &intent.intent_id, xmsg::storage::now_epoch_secs()).unwrap();
    let grant_id = intent.grant_id;
    let receipt_local = [0xA5u8; 16];
    let receipt_remote = [0x5Au8; 16];
    let tx_id = [0x11u8; 32];
    let exporter = [0x22u8; 32];
    let now = xmsg::storage::now_epoch_secs();
    let exp_cbor = req.exposure.encode_cbor().unwrap();
    db.execute(
        "INSERT INTO pairing_grants (grant_id, issuer, subject, provenance, profile, exposure,
             not_after, origin_intent_id, transaction_id, exporter, receipt_local, receipt_remote,
             ceremony_created, ceremony_expires, activated_at, active)
         VALUES (?1, ?2, ?3, 'manual_authenticated_oob', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 1)",
        rusqlite::params![
            &grant_id[..],
            &own_id[..],
            &peer_id[..],
            profile.as_str(),
            exp_cbor,
            not_after,
            &intent.intent_id[..],
            &tx_id[..],
            &exporter[..],
            &receipt_local[..],
            &receipt_remote[..],
            now - 1,
            now + 119,
            now,
        ],
    )
    .unwrap();
    db.execute(
        "UPDATE pairing_intents SET state = 'consumed' WHERE intent_id = ?1",
        [&intent.intent_id[..]],
    )
    .unwrap();
    grant_id
}

fn manual_auth_peer(cert_der: &[u8], peer_id: [u8; 32], id_str: &str) -> xmsg::fed::AuthenticatedPeer {
    xmsg::fed::AuthenticatedPeer {
        leaf_authority: xmsg::fed::LeafAuthority::from_certificate(
            &rustls::pki_types::CertificateDer::from(cert_der.to_vec()),
            xmsg::fed::AdmissionMode::Pin,
        )
        .unwrap(),
        name: id_str.to_string(),
        pin: hex::encode(peer_id),
        uri: None,
        certificate_has_uri: false,
        user: String::new(),
        remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    }
}

#[test]
fn safety_1_and_q2_9_authorize_peer_op_is_single_decision_point_default_deny() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let (cert_b, _, peer_b) = gen_ed25519_identity();
    let peer_b_id = SpkiDeviceId::parse_device_id_string(&peer_b).unwrap().0;
    let (cert_c, _, peer_c) = gen_ed25519_identity();
    let peer_c_id = SpkiDeviceId::parse_device_id_string(&peer_c).unwrap().0;

    let _gb = seed_manual_grant(&fed, peer_b_id, PairingProfile::Contact, vec!["svc-a".into()], None);
    let _gc = seed_manual_grant(&fed, peer_c_id, PairingProfile::OwnerDevice, vec!["*".into()], None);
    let mut merged = (*fed.current_peers()).clone();
    {
        let db = fed.db.lock().unwrap();
        xmsg::pairing::store::merge_snapshot(&db, &mut merged).unwrap();
    }

    let auth_b = manual_auth_peer(&cert_b, peer_b_id, &peer_b);
    let auth_c = manual_auth_peer(&cert_c, peer_c_id, &peer_c);
    let send_svc_a = xmsg::pairing::auth::Resource {
        target: Some("svc-a"),
        principal: Some("anon"),
        body_bytes: 10,
        attachment_bytes: 0,
    };
    let send_other = xmsg::pairing::auth::Resource {
        target: Some("other"),
        principal: Some("anon"),
        body_bytes: 10,
        attachment_bytes: 0,
    };

    // Contact allows Send to svc-a, denies Send to other, denies SessionList/Observe/Handoff/Forward/Relayed.
    assert!(fed
        .authorize_peer_op(&merged, &auth_b, xmsg::pairing::auth::Operation::Send, &send_svc_a)
        .is_ok());
    assert!(fed
        .authorize_peer_op(&merged, &auth_b, xmsg::pairing::auth::Operation::Send, &send_other)
        .is_err());
    for denied_op in [
        xmsg::pairing::auth::Operation::SessionList,
        xmsg::pairing::auth::Operation::Observe,
        xmsg::pairing::auth::Operation::Handoff,
        xmsg::pairing::auth::Operation::Forward,
        xmsg::pairing::auth::Operation::Relayed,
    ] {
        assert!(
            fed.authorize_peer_op(
                &merged,
                &auth_b,
                denied_op,
                &xmsg::pairing::auth::Resource::default()
            )
            .is_err(),
            "Contact must deny {denied_op:?}"
        );
    }

    // OwnerDevice allows SessionList, denies Observe/Handoff/Forward/Relayed.
    assert!(fed
        .authorize_peer_op(
            &merged,
            &auth_c,
            xmsg::pairing::auth::Operation::SessionList,
            &xmsg::pairing::auth::Resource::default()
        )
        .is_ok());
    for denied_op in [
        xmsg::pairing::auth::Operation::Observe,
        xmsg::pairing::auth::Operation::Handoff,
        xmsg::pairing::auth::Operation::Forward,
        xmsg::pairing::auth::Operation::Relayed,
    ] {
        assert!(
            fed.authorize_peer_op(
                &merged,
                &auth_c,
                denied_op,
                &xmsg::pairing::auth::Resource::default()
            )
            .is_err(),
            "OwnerDevice must deny {denied_op:?}"
        );
    }
}

#[test]
fn safety_2_manual_admission_is_exact_and_refuses_collisions() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let (cert_b, _, peer_b) = gen_ed25519_identity();
    let peer_b_id = SpkiDeviceId::parse_device_id_string(&peer_b).unwrap().0;
    let (cert_other, _, _) = gen_ed25519_identity();

    let _gb = seed_manual_grant(&fed, peer_b_id, PairingProfile::Contact, vec!["svc-a".into()], None);
    let mut merged = (*fed.current_peers()).clone();
    {
        let db = fed.db.lock().unwrap();
        xmsg::pairing::store::merge_snapshot(&db, &mut merged).unwrap();
    }

    // Exact granted Ed25519 SPKI is admitted.
    let cert_b_der = rustls::pki_types::CertificateDer::from(cert_b);
    assert!(merged.resolve_incoming_peer(&cert_b_der, &[]).is_ok());

    // Different SPKI with no grant is refused.
    let cert_other_der = rustls::pki_types::CertificateDer::from(cert_other);
    assert!(merged.resolve_incoming_peer(&cert_other_der, &[]).is_err());

    // Grant issued for another issuer is not honoured.
    let mut wrong_issuer = merged.clone();
    wrong_issuer.own_device_id = Some([0x99u8; 32]);
    assert!(wrong_issuer.resolve_incoming_peer(&cert_b_der, &[]).is_err());

    // Name collision with peers_by_name is refused (fail-closed).
    let mut colliding = merged.clone();
    colliding.peers_by_name.insert(
        peer_b.clone(),
        xmsg::fed::PeerConfig {
            name: peer_b.clone(),
            address: String::new(),
            pin: Some(hex::encode([0x44u8; 32])),
            ca: None,
            identities: None,
            allow: vec!["send".into()],
            observe_labels: false,
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        },
    );
    assert!(colliding.resolve_incoming_peer(&cert_b_der, &[]).is_err());
}

#[test]
fn safety_3_and_4_peers_file_unaffected_and_dial_entries_disappear_on_revoke() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let (_, _, peer_b) = gen_ed25519_identity();
    let peer_b_id = SpkiDeviceId::parse_device_id_string(&peer_b).unwrap().0;
    let grant_b = seed_manual_grant(&fed, peer_b_id, PairingProfile::Contact, vec!["svc-a".into()], None);

    let (cert_alice, _, alice_id) = gen_ed25519_identity();
    let alice_pin = hex::encode(SpkiDeviceId::parse_device_id_string(&alice_id).unwrap().0);
    let mut merged = PeersMap::load_from_json_for(
        &format!(r#"{{"alice":{{"address":"127.0.0.1:7777","pin":"{alice_pin}","allow":["send"]}}}}"#),
        None,
    )
    .unwrap();
    {
        let db = fed.db.lock().unwrap();
        xmsg::pairing::store::merge_snapshot(&db, &mut merged).unwrap();
    }

    // Safety 3: peers-file peer 'alice' keeps exact send-only rights unaffected by manual grant.
    let alice_auth = xmsg::fed::AuthenticatedPeer {
        leaf_authority: xmsg::fed::LeafAuthority::from_certificate(
            &rustls::pki_types::CertificateDer::from(cert_alice),
            xmsg::fed::AdmissionMode::Pin,
        )
        .unwrap(),
        name: "alice".into(),
        pin: alice_pin,
        uri: None,
        certificate_has_uri: false,
        user: String::new(),
        remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    };
    assert!(fed
        .authorize_peer_op(
            &merged,
            &alice_auth,
            xmsg::pairing::auth::Operation::Send,
            &xmsg::pairing::auth::Resource::default()
        )
        .is_ok());
    assert!(fed
        .authorize_peer_op(
            &merged,
            &alice_auth,
            xmsg::pairing::auth::Operation::Reply,
            &xmsg::pairing::auth::Resource::default()
        )
        .is_err());

    // Safety 4: synthesized dial entry exists and is dial-only (allow is empty); disappears after remove.
    let dial_cfg = merged.get_peer_config(&peer_b).unwrap();
    assert!(dial_cfg.allow.is_empty());
    {
        let db = fed.db.lock().unwrap();
        xmsg::pairing::store::remove(&db, &grant_b, xmsg::storage::now_epoch_secs()).unwrap();
        xmsg::pairing::store::merge_snapshot(&db, &mut merged).unwrap();
    }
    assert!(merged.get_peer_config(&peer_b).is_none());
}

#[cfg(feature = "test-hooks")]
#[test]
fn safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let (cert_b, _, peer_b) = gen_ed25519_identity();
    let peer_b_id = SpkiDeviceId::parse_device_id_string(&peer_b).unwrap().0;
    let exp = xmsg::storage::now_epoch_secs() + 60;
    let grant_b = seed_manual_grant(
        &fed,
        peer_b_id,
        PairingProfile::Contact,
        vec!["svc-a".into()],
        Some(exp),
    );
    let mut merged = (*fed.current_peers()).clone();
    {
        let db = fed.db.lock().unwrap();
        xmsg::pairing::store::merge_snapshot(&db, &mut merged).unwrap();
    }
    let auth_b = manual_auth_peer(&cert_b, peer_b_id, &peer_b);
    let res = xmsg::pairing::auth::Resource {
        target: Some("svc-a"),
        principal: Some("anon"),
        body_bytes: 10,
        attachment_bytes: 0,
    };

    // Q2-7i: advance clock past grant_not_after at permit point -> refused.
    xmsg::pairing::service::set_test_now_override(&fed, Some(exp + 1));
    assert!(fed
        .authorize_peer_op(&merged, &auth_b, xmsg::pairing::auth::Operation::Send, &res)
        .is_err());
    xmsg::pairing::service::set_test_now_override(&fed, None);

    // Q2-7f / Q2-7h: plant a remove mark in the hook between admission observation and permit point.
    let db_arc = fed.db.clone();
    xmsg::pairing::service::set_before_permit_hook(
        &fed,
        Some(Arc::new(move || {
            let db = db_arc.lock().unwrap();
            let reg = xmsg::pairing::store::revocations_for_db(&db_arc);
            xmsg::pairing::store::remove_with_marks(
                &db,
                &grant_b,
                xmsg::storage::now_epoch_secs(),
                Some(&reg),
            )
            .unwrap();
        })),
    );
    let err = fed
        .authorize_peer_op(&merged, &auth_b, xmsg::pairing::auth::Operation::Send, &res)
        .unwrap_err();
    assert!(err.to_string().contains("revoked"));
    xmsg::pairing::service::set_before_permit_hook(&fed, None);

    let reg = xmsg::pairing::store::revocations_for_db(&fed.db);
    // Q2-7e: remove mark for g1 covers g1 only, leaving another grant g2 unblocked.
    let g2 = [0x99u8; 16];
    assert!(reg.has_blocking_mark(&peer_b_id, Some(&grant_b), merged.authority_revision));
    assert!(!reg.has_blocking_mark(&peer_b_id, Some(&g2), merged.authority_revision));

    // Q2-7f: GC keeps mark while an older GenerationToken (rev < M) is still alive, and retires once dropped.
    let old_tok = Arc::new(xmsg::pairing::store::GenerationToken::new(0));
    reg.register_token(&old_tok);
    reg.gc(merged.authority_revision + 10);
    assert!(
        reg.mark_count() >= 1,
        "Q2-7f: mark must stay live while older GenerationToken is alive"
    );
    drop(old_tok);
    reg.gc(merged.authority_revision + 10);
    assert_eq!(reg.mark_count(), 0, "Q2-7f: mark must retire after older tokens drop");

    // Q2-7g: ambiguous I/O error at COMMIT after durable write keeps mark and returns Ok(rev).
    reg.inject_commit_io_error
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let blk_rev = {
        let db = fed.db.lock().unwrap();
        xmsg::pairing::store::block_device_with_marks(
            &db,
            &peer_b_id,
            xmsg::storage::now_epoch_secs(),
            Some(&reg),
        )
        .unwrap()
    };
    assert!(reg.has_blocking_mark(&peer_b_id, None, blk_rev - 1));
}

#[tokio::test]
async fn q2_3a_and_q2_4b_no_intent_eof_and_unsupported_alpn_refused() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let rt = pairing_runtime(&fed);
    rt.service.attempt_startup_cancel(&fed).unwrap();
    let (cert_b, key_b, peer_b) = gen_ed25519_identity();

    // Q2-3a & Q2-4: Real run_fed_listener_with_acceptor drops ClientHello when no responder intent exists
    // and records pairing.no_intent (zero ServerHello, zero /fed routing).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = xmsg::fed::make_tls_acceptor(
        &[rustls::pki_types::CertificateDer::from(fed.cert_der.clone())],
        &fed.key_der,
        fed.current_peers(),
    )
    .unwrap();
    let srv_fed = fed.clone();
    let srv = tokio::spawn(async move {
        let _ = xmsg::fed::run_fed_listener_with_acceptor(listener, srv_fed, acceptor).await;
    });
    let (cli_cfg, _) = xmsg::pairing::ceremony::build_pairing_client_config(
        vec![rustls::pki_types::CertificateDer::from(cert_b.clone())],
        rustls::pki_types::PrivateKeyDer::try_from(key_b.clone()).unwrap(),
        xmsg::pairing::ceremony::ed25519_device_id_from_cert(&fed.cert_der)
            .unwrap()
            .0,
        None,
    )
    .unwrap();
    let tcp_cli = tokio::net::TcpStream::connect(addr).await.unwrap();
    let dns = rustls::pki_types::ServerName::try_from("xmsg-pair.local").unwrap();
    assert!(tokio_rustls::TlsConnector::from(cli_cfg).connect(dns, tcp_cli).await.is_err());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        rt.service.budgets.refusal_snapshot().get("pairing.no_intent").copied(),
        Some(1),
        "Q2-3a/Q2-4: no-intent xmsg-pair/1 ClientHello must record pairing.no_intent before ServerHello"
    );
    srv.abort();

    // Q2-4b: Initiator dialing a server that does not negotiate xmsg-pair/1 refuses pairing.peer_unsupported.
    let listener_no_alpn = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_no_alpn = listener_no_alpn.local_addr().unwrap();
    let mut no_alpn_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert_b.clone())],
        rustls::pki_types::PrivateKeyDer::try_from(key_b.clone()).unwrap(),
    )
    .unwrap();
    no_alpn_cfg.alpn_protocols = vec![];
    let srv_no_alpn = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener_no_alpn.accept().await {
            let _ = tokio_rustls::TlsAcceptor::from(Arc::new(no_alpn_cfg))
                .accept(tcp)
                .await;
        }
    });
    let (intent, _) = rt
        .service
        .create_intent(
            &fed,
            &peer_b,
            IntentRole::Initiator,
            PairingProfile::OwnerDevice,
            vec![],
            vec![],
            None,
        )
        .await
        .unwrap();
    let err = rt
        .service
        .run_initiator_and_wait(&fed, intent, vec![addr_no_alpn])
        .await
        .unwrap_err();
    assert_eq!(err.code(), "pairing.peer_unsupported");
    srv_no_alpn.abort();

    // Q2-4b & M22: deny.spkis refuses pairing TLS handshake.
    let deny_pin = hex::encode(
        xmsg::pairing::ceremony::ed25519_device_id_from_cert(&cert_b)
            .unwrap()
            .0,
    );
    let mut deny_peers = PeersMap::default();
    deny_peers.deny.spkis.push(deny_pin);
    let (srv_cfg, _) = xmsg::pairing::ceremony::build_pairing_server_config(
        vec![rustls::pki_types::CertificateDer::from(fed.cert_der.clone())],
        rustls::pki_types::PrivateKeyDer::try_from(fed.key_der.clone()).unwrap(),
        Arc::new(|_| true),
        Some(Arc::new(deny_peers)),
    )
    .unwrap();
    let (cli_cfg2, _) = xmsg::pairing::ceremony::build_pairing_client_config(
        vec![rustls::pki_types::CertificateDer::from(cert_b)],
        rustls::pki_types::PrivateKeyDer::try_from(key_b).unwrap(),
        xmsg::pairing::ceremony::ed25519_device_id_from_cert(&fed.cert_der)
            .unwrap()
            .0,
        None,
    )
    .unwrap();
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let srv2 = tokio::spawn(async move {
        let (tcp, _) = listener2.accept().await.unwrap();
        tokio_rustls::TlsAcceptor::from(srv_cfg).accept(tcp).await
    });
    let tcp_cli2 = tokio::net::TcpStream::connect(addr2).await.unwrap();
    let dns2 = rustls::pki_types::ServerName::try_from("xmsg-pair.local").unwrap();
    assert!(
        tokio_rustls::TlsConnector::from(cli_cfg2).connect(dns2, tcp_cli2).await.is_err()
            || srv2.await.unwrap().is_err(),
        "M22: deny.spkis must refuse pairing TLS"
    );
}

#[tokio::test]
async fn q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let rt = pairing_runtime(&fed);
    rt.service.attempt_startup_cancel(&fed).unwrap();
    let (cert_b, key_b, peer_b) = gen_ed25519_identity();
    let peer_b_id = SpkiDeviceId::parse_device_id_string(&peer_b).unwrap().0;

    // Q2-5e: First live handle_inbound_pairing_stream holds the ceremony slot; second gets pairing.ceremony_busy.
    let (intent, _) = rt
        .service
        .create_intent(
            &fed,
            &peer_b,
            IntentRole::Responder,
            PairingProfile::OwnerDevice,
            vec![],
            vec![],
            None,
        )
        .await
        .unwrap();
    let rt_chk = rt.clone();
    let (srv_cfg, _) = xmsg::pairing::ceremony::build_pairing_server_config(
        vec![rustls::pki_types::CertificateDer::from(fed.cert_der.clone())],
        rustls::pki_types::PrivateKeyDer::try_from(fed.key_der.clone()).unwrap(),
        Arc::new(move |id| rt_chk.service.has_live_responder_intent_for(id)),
        None,
    )
    .unwrap();
    let own_id = xmsg::pairing::ceremony::ed25519_device_id_from_cert(&fed.cert_der)
        .unwrap()
        .0;
    let (cli_cfg, _) = xmsg::pairing::ceremony::build_pairing_client_config(
        vec![rustls::pki_types::CertificateDer::from(cert_b)],
        rustls::pki_types::PrivateKeyDer::try_from(key_b).unwrap(),
        own_id,
        None,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(srv_cfg);
    let connector = tokio_rustls::TlsConnector::from(cli_cfg);
    let dns = rustls::pki_types::ServerName::try_from("xmsg-pair.local").unwrap();

    let (c1_fut, s1_fut) = (
        async {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            connector.connect(dns.clone(), tcp).await.unwrap()
        },
        async {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await.unwrap()
        },
    );
    let (c1_tls, s1_tls) = tokio::join!(c1_fut, s1_fut);
    let svc1 = rt.service.clone();
    let fed1 = fed.clone();
    let h1 = tokio::spawn(async move {
        svc1.handle_inbound_pairing_stream(&fed1, s1_tls).await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let (c2_fut, s2_fut) = (
        async {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            connector.connect(dns, tcp).await.unwrap()
        },
        async {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await.unwrap()
        },
    );
    let (_c2_tls, s2_tls) = tokio::join!(c2_fut, s2_fut);
    rt.service.handle_inbound_pairing_stream(&fed, s2_tls).await;
    assert_eq!(
        rt.service.budgets.refusal_snapshot().get("pairing.ceremony_busy").copied(),
        Some(1),
        "Q2-5e: second authenticated ceremony for same intent must record pairing.ceremony_busy"
    );
    drop(c1_tls);
    h1.abort();
    let _ = rt.service.cancel_intent(&fed, &hex::encode(intent.intent_id)).await;

    // Q2-13c & Q2-13f: expired manual grant holding a slot is named in pairing.grants.expired_grants,
    // and initiator-only (!has_fed_listen) warns pairing.receive_path.
    let exp_grant = seed_manual_grant(
        &fed,
        peer_b_id,
        PairingProfile::Contact,
        vec!["svc-a".into()],
        None,
    );
    {
        let db = fed.db.lock().unwrap();
        db.execute(
            "UPDATE pairing_grants SET not_after = ?1 WHERE grant_id = ?2",
            rusqlite::params![xmsg::storage::now_epoch_secs() - 10, &exp_grant[..]],
        )
        .unwrap();
        // Q2-13b: seed legacy_unilateral grant for same peer_b_id -> coexistence warn.
        let mut leg_gid = [0x88u8; 16];
        leg_gid[0] = 0x77;
        db.execute(
            "INSERT INTO pairing_grants (grant_id, issuer, subject, provenance, legacy_predicates, activated_at, active)
             VALUES (?1, ?2, ?3, 'legacy_unilateral', '{\"rule\":\"b\",\"allow\":[\"send\"],\"targets\":null,\"principals\":[],\"from\":null,\"leaf\":false,\"observe_labels\":false}', 1000, 1)",
            rusqlite::params![&leg_gid[..], &own_id[..], &peer_b_id[..]],
        )
        .unwrap();
        // Q2-13d & Q2-15b: block peer_b_id -> authority_revision advances ahead of installed_rev,
        // and the blocked grant still occupies its slot (count_slots_used == 1).
        xmsg::pairing::store::block_device(&db, &peer_b_id, xmsg::storage::now_epoch_secs()).unwrap();
        assert_eq!(xmsg::pairing::store::count_slots_used(&db).unwrap(), 1);
    }
    let diag = rt.service.diagnostics(&fed, false).await.unwrap();
    assert_eq!(diag["pairing.receive_path"]["code"], "pairing.receive_path");
    assert_eq!(diag["pairing.authority"]["code"], "pairing.reload_failed");
    assert_eq!(diag["pairing.legacy"]["status"], "warn");
    assert!(!diag["pairing.legacy"]["coexistence_peers"].as_array().unwrap().is_empty());
    assert_eq!(diag["pairing.grants"]["expired_grants_holding_slots"], 1);
    let expired_arr = diag["pairing.grants"]["expired_grants"].as_array().unwrap();
    assert_eq!(expired_arr[0]["grant_id"], hex::encode(exp_grant));

    // Q2-16 step 2 (M20): unblock_device refuses when an expired manual grant is unremoved.
    let db = fed.db.lock().unwrap();
    let unblock_err = xmsg::pairing::store::unblock_device(&db, &peer_b_id, &PeersMap::default()).unwrap_err();
    assert!(unblock_err.to_string().contains("unblock would restore"));
}

#[tokio::test(start_paused = true)]
async fn q2_6_monotonic_120s_deadline_expires_intent() {
    let dir = TempDir::new().unwrap();
    let fed = test_fed_state(&dir);
    let rt = pairing_runtime(&fed);
    rt.service.attempt_startup_cancel(&fed).unwrap();
    let (_, _, peer_b) = gen_ed25519_identity();
    let before = tokio::time::Instant::now();
    let (intent, _) = rt
        .service
        .create_intent(
            &fed,
            &peer_b,
            IntentRole::Responder,
            PairingProfile::OwnerDevice,
            vec![],
            vec![],
            None,
        )
        .await
        .unwrap();
    assert!(
        intent.deadline <= before + Duration::from_secs(121),
        "Q2-6: intent monotonic deadline must be bounded by 120s"
    );
    tokio::time::advance(Duration::from_secs(121)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
        if intent.completion.lock().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        intent.completion.lock().unwrap().is_some(),
        "Q2-6: intent must expire at 120s monotonic without waiting 3600s"
    );
    let err = rt.service.wait_for_responder(&intent).await.unwrap_err();
    assert_eq!(err.code(), "pairing.expired");
}

#[tokio::test]
async fn m10_block_device_publishes_update_and_refuses_at_admission_and_permit_fence() {
    let dir = TempDir::new().unwrap();
    let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let params = CertificateParams::new(vec!["test.local".to_string()]).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    let cert_path = dir.path().join("fed.crt");
    let key_path = dir.path().join("fed.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, kp.serialize_pem()).unwrap();

    let conn = rusqlite::Connection::open(dir.path().join("xmsg.db")).unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let fed = Arc::new(FedState {
        discovery: Default::default(),
        node_name: "test.local".into(),
        peers: Arc::new(PeersMap::empty()).into(),
        cert_der: cert.der().to_vec(),
        cert_chain_der: Vec::new(),
        key_der: kp.serialize_der(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: Arc::new(Mutex::new(conn)),
        sessions_dirs: vec![dir.path().join("sessions")],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: dir.path().join("presence"),
            brain_dir: dir.path().join("brain"),
            ..Default::default()
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        notify_tx: tokio::sync::broadcast::channel(16).0,
        max_body: 65536,
        max_attachment_bytes: 8 * 1024 * 1024,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Default::default(),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    });
    let reloader = Arc::new(
        xmsg::fed::CredentialReloader::new_full(
            cert_path,
            key_path,
            None,
            None,
            fed.current_peers(),
            Some(fed.clone()),
            Arc::new(Mutex::new(Default::default())),
        )
        .unwrap(),
    );
    xmsg::fed::attach_pairing_reloader(&fed, &reloader);

    let rt = pairing_runtime(&fed);
    rt.service.attempt_startup_cancel(&fed).unwrap();
    let (cert_b, _, peer_b) = gen_ed25519_identity();
    let peer_b_id = SpkiDeviceId::parse_device_id_string(&peer_b).unwrap().0;
    seed_manual_grant(
        &fed,
        peer_b_id,
        PairingProfile::Contact,
        vec!["svc-a".into()],
        None,
    );
    {
        let db = fed.db.lock().unwrap();
        db.execute("UPDATE pairing_meta SET authority_revision = 1 WHERE singleton = 1", [])
            .unwrap();
    }
    fed.publish_pairing_update(1).await.unwrap();

    let before_peers = fed.current_peers();
    let cert_der_b = rustls::pki_types::CertificateDer::from(cert_b.clone());
    before_peers
        .resolve_incoming_peer(&cert_der_b, &[])
        .expect("pre-block manual SPKI must be admitted");
    let auth_b = manual_auth_peer(&cert_b, peer_b_id, &peer_b);
    let res = xmsg::pairing::auth::Resource {
        target: Some("svc-a"),
        principal: Some("anon"),
        body_bytes: 10,
        attachment_bytes: 0,
    };
    fed.authorize_peer_op(&before_peers, &auth_b, xmsg::pairing::auth::Operation::Send, &res)
        .expect("pre-block send must be permitted");

    let _open_conn_token = Arc::new(xmsg::pairing::store::GenerationToken::new(
        before_peers.authority_revision,
    ));
    xmsg::pairing::store::revocations_for_db(&fed.db).register_token(&_open_conn_token);
    let outcome = rt.service.block_device(&fed, &peer_b).await.unwrap();
    assert!(outcome.committed);
    assert_eq!(
        outcome.installed_revision, outcome.committed_revision,
        "pair block must publish and install the committed revision"
    );
    let after_peers = fed.current_peers();
    assert_eq!(after_peers.authority_revision, outcome.committed_revision);
    assert!(
        after_peers.resolve_incoming_peer(&cert_der_b, &[]).is_err(),
        "blocked SPKI must be refused at TLS admission"
    );
    assert!(
        fed.authorize_peer_op(&before_peers, &auth_b, xmsg::pairing::auth::Operation::Send, &res)
            .is_err(),
        "blocked device must be refused at the permit fence even against pre-block snapshot"
    );
    assert!(
        fed.authorize_peer_op(&after_peers, &auth_b, xmsg::pairing::auth::Operation::Send, &res)
            .is_err(),
        "blocked device must be refused at the permit fence on published snapshot"
    );
}
