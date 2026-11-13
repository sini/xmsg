use super::*;
use crate::enroll_oidc::signed_fixture::Fixture;
use crate::{enroll_ca, enroll_client, fed, storage};
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use rcgen::PublicKeyData;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
};
use tower::ServiceExt;

struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Harness {
    _directory: tempfile::TempDir,
    idp: Fixture,
    service: Arc<Service>,
    clock: Arc<TestClock>,
    db: Arc<Mutex<rusqlite::Connection>>,
}
impl Harness {
    async fn new() -> Self {
        let now = WallClock.now();
        let idp = Fixture::new_at(now).await;
        let directory = tempfile::tempdir().unwrap();
        let config = idp.config(true);
        let policy = directory.path().join("policy.json");
        std::fs::write(&policy,serde_json::to_vec(&json!({"trust_domain":"enroll.example","providers":{"idp":config},"users":[{"provider":"idp","sub":"fixture-sub","user":"alice"}],"issue_per_hour":200,"renew_per_hour":200})).unwrap()).unwrap();
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        storage::init_db(&connection).unwrap();
        let db = Arc::new(Mutex::new(connection));
        let ca = Arc::new(
            EnrollCa::open(directory.path().join("ca"), db.clone(), policy, "team.hub").unwrap(),
        );
        let fleet_key = rcgen::KeyPair::generate().unwrap();
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let fleet_root = parameters.self_signed(&fleet_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf = rcgen::CertificateParams::default();
        leaf.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://fleet.example/host/hub/user/team"
                .try_into()
                .unwrap(),
        )];
        leaf.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let leaf = leaf
            .signed_by(
                &leaf_key,
                &rcgen::Issuer::from_params(&parameters, &fleet_key),
            )
            .unwrap();
        let fed = node_state(
            db.clone(),
            directory.path(),
            vec![leaf.der().to_vec(), fleet_root.der().to_vec()],
            leaf_key.serialize_der(),
        );
        let clock = Arc::new(TestClock(AtomicI64::new(now)));
        let (entry, _) = hub_entry(&fed, "127.0.0.1:7788", now).unwrap();
        let identity = ca.reserved_uri();
        let service = Arc::new(Service::with_oidc_http(
            ca,
            fed,
            clock.clone(),
            entry,
            identity,
            idp.http_client(),
        ));
        Self {
            _directory: directory,
            idp,
            service,
            clock,
            db,
        }
    }
    async fn request(
        &self,
        method: &str,
        uri: &str,
        body: Value,
        session: Option<&str>,
        ip: u8,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(handle) = session {
            request = request.header("xmsg-enroll-session", handle);
        }
        let mut request = request
            .body(if method == "GET" {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .unwrap();
        request.extensions_mut().insert(Peer {
            ip: std::net::Ipv4Addr::new(10, 0, 0, ip).into(),
            certificates: vec![],
        });
        let response = router(self.service.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 131072).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn start(&self, host: &str, ip: u8) -> (StatusCode, Value, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let(status,value)=self.request("POST","/enroll/v1/sessions",json!({"csr_pem":csr,"host":host,"provider":"idp","flow":"loopback","redirect_uri":"http://127.0.0.1:18551/cb"}),None,ip).await;
        (status, value, key)
    }
    async fn complete(&self, created: &Value) -> (StatusCode, Value) {
        let (code, state) = self
            .idp
            .authorize(created["authorization_url"].as_str().unwrap());
        let handle = created["session"].as_str().unwrap();
        let (status, _) = self
            .request(
                "POST",
                "/enroll/v1/sessions/code",
                json!({"code":code,"state":state}),
                Some(handle),
                1,
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        self.request(
            "GET",
            "/enroll/v1/sessions?wait=0",
            Value::Null,
            Some(handle),
            1,
        )
        .await
    }
}
fn node_state(
    db: Arc<Mutex<rusqlite::Connection>>,
    dir: &std::path::Path,
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
) -> Arc<fed::FedState> {
    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);
    Arc::new(fed::FedState {
        node_name: "team.hub".into(),
        peers: Arc::new(fed::PeersMap::new(HashMap::new())).into(),
        cert_der: chain[0].clone(),
        cert_chain_der: chain,
        key_der: key,
        rate_limiter: Arc::new(fed::RateLimiter::new(600, 200)),
        db,
        sessions_dirs: vec![dir.join("sessions")],
        agy_config: crate::agy::AgyConfig {
            presence_dir: dir.join("presence"),
            proc_locks_path: dir.join("locks"),
            proc_root: PathBuf::from(crate::process::LIVE_PROC_ROOT),
            agy_bin: "agy".into(),
            trusted_agy_exes: vec![],
            brain_dir: PathBuf::new(),
        },
        agy_store: crate::agy::new_agy_store(),
        pi_store: crate::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: crate::svc::new_svc_store(),
        svc_notify_tx,
        notify_tx,
        max_body: 65536,
        max_attachment_bytes: crate::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(600),
        list_queries: Default::default(),
    })
}

#[tokio::test]
async fn probe_protocol_observations() {
    let h = Harness::new().await;
    let (status, created, key) = h.start("laptop", 1).await;
    println!("creation {}", status);
    assert_eq!(status, StatusCode::CREATED);
    let (status, collected) = h.complete(&created).await;
    println!(
        "collect {} keys={:?}",
        status,
        collected.as_object().unwrap().keys()
    );
    if let Some(pem) = collected["cert_chain_pem"].as_str() {
        use rustls::pki_types::pem::PemObject;
        let cert = rustls::pki_types::CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        println!(
            "spki_equal {}",
            fed::spki_sha256_from_der(cert.as_ref()).unwrap() == {
                use sha2::Digest;
                hex::encode(sha2::Sha256::digest(key.subject_public_key_info()))
            }
        );
    }
    let (second, _) = h
        .request(
            "GET",
            "/enroll/v1/sessions",
            Value::Null,
            created["session"].as_str(),
            1,
        )
        .await;
    println!("second_collect {}", second);
}

#[tokio::test]
async fn probe_protocol_limit_observations() {
    let h = Harness::new().await;
    let mut global = Vec::new();
    for n in 1..=11 {
        global.push(h.start(&format!("host{n}"), n).await.0.as_u16());
    }
    println!("global_statuses {global:?}");
    let h = Harness::new().await;
    let mut per_ip = Vec::new();
    for n in 1..=5 {
        per_ip.push(h.start(&format!("host{n}"), 1).await.0.as_u16());
    }
    println!("per_ip_statuses {per_ip:?}");
    let h = Harness::new().await;
    let mut first = None;
    for n in 1..=64 {
        let (status, value, _) = h.start(&format!("host{n}"), n).await;
        assert_eq!(status, StatusCode::CREATED);
        if n == 1 {
            first = Some(value);
        }
        h.clock.0.fetch_add(2, Ordering::SeqCst);
    }
    let (status, _, _) = h.start("overflow", 65).await;
    println!("pending_overflow {}", status);
    let (status, value) = h.complete(&first.unwrap()).await;
    println!(
        "earlier_complete {} cert={}",
        status,
        value.get("cert_chain_pem").is_some()
    );
}
#[tokio::test]
async fn probe_request_authority_observations() {
    let h = Harness::new().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let(status,_)=h.request("POST","/enroll/v1/sessions",json!({"csr_pem":csr,"host":"laptop","provider":"idp","flow":"loopback","redirect_uri":"http://127.0.0.1:18551/cb","user":"root"}),None,1).await;
    println!("body_user {}", status);
    let(status,value)=h.request("POST","/enroll/v1/sessions",json!({"csr_pem":csr,"host":"laptop","provider":"idp","flow":"device","redirect_uri":"http://127.0.0.1:18551/cb"}),None,1).await;
    println!("device {} reason={}", status, value["error"]["reason"]);
    println!("provider_requests {}", h.idp.request_paths().len());
}
