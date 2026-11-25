//! Integration tests for discovery PR 4 (§5.5 oracles & carry-in conditions).

use std::collections::HashMap;
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
        agy_config: Default::default(),
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
        agy_config: Default::default(),
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

    let (_, _, peer_b) = gen_ed25519_identity();
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
    // Q2-3b: initiator intent admits no inbound ceremony.
    assert!(!rt.service.has_live_responder_intent());

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
        .oneshot(
            Request::builder()
                .uri("/v1/pairing/id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unix_resp.status(), StatusCode::FORBIDDEN);
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

#[cfg(feature = "test-hooks")]
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

    // Inject failing startup-cancel transaction (carry-in N1/N2/N3/N4).
    rt.service
        .test_inject_startup_cancel_fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
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

    // Revocation (block) still succeeds while startup cancel is failing.
    rt.service.block_device(&fed, &peer_b).await.unwrap();
    // Doctor diagnostics warn pairing.startup_cancel_failed.
    let diag = rt.service.diagnostics(&fed, true).await.unwrap();
    assert_eq!(diag["pairing.startup"]["code"], "pairing.startup_cancel_failed");

    // Clear the fault: retry (accept/start or watcher tick) completes cancel and restores slot count.
    rt.service
        .test_inject_startup_cancel_fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (_, _) = rt
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
        .unwrap();
    assert!(rt.service.is_startup_cancel_done());
    let diag2 = rt.service.diagnostics(&fed, true).await.unwrap();
    assert_eq!(diag2["pairing.startup"]["status"], "pass");
    let _ = HashMap::<String, String>::new();
}
