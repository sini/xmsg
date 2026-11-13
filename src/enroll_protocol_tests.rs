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

pub(crate) struct TestClock(pub(crate) AtomicI64);
impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
pub(crate) struct Harness {
    pub(crate) _directory: tempfile::TempDir,
    pub(crate) idp: Fixture,
    pub(crate) service: Arc<Service>,
    pub(crate) clock: Arc<TestClock>,
    pub(crate) db: Arc<Mutex<rusqlite::Connection>>,
}
impl Harness {
    pub(crate) async fn new() -> Self {
        Self::new_with_address("127.0.0.1:7788").await
    }
    pub(crate) async fn new_with_address(address: &str) -> Self {
        Self::new_with_now(address, WallClock.now()).await
    }
    pub(crate) async fn new_with_now(address: &str, now: i64) -> Self {
        let idp = Fixture::new_at(now).await;
        let directory = tempfile::tempdir().unwrap();
        let config = idp.config(true);
        let policy = directory.path().join("policy.json");
        std::fs::write(&policy,serde_json::to_vec(&json!({"trust_domain":"enroll.example","providers":{"idp":config},"users":[{"provider":"idp","sub":"fixture-sub","user":"alice"}],"issue_per_hour":200,"renew_per_hour":200})).unwrap()).unwrap();
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        storage::init_db(&connection).unwrap();
        let db = Arc::new(Mutex::new(connection));
        let ca = Arc::new(
            EnrollCa::open_at(
                directory.path().join("ca"),
                db.clone(),
                policy,
                "team.hub",
                now,
            )
            .unwrap(),
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
        let admitted = Arc::new(fed::PeersMap::load_from_json(&json!({"peers":{},"hub":{"patterns":[{"pattern":"spiffe://enroll.example/host/*/user/alice","ca":directory.path().join("ca/root.crt")}],"rules":[{"pattern":"spiffe://enroll.example/host/*/user/alice","allow":["send","reply","list","relayed"],"leaf":true}]}}).to_string()).unwrap());
        let fed = node_state(
            db.clone(),
            directory.path(),
            vec![leaf.der().to_vec(), fleet_root.der().to_vec()],
            leaf_key.serialize_der(),
            admitted,
        );
        let clock = Arc::new(TestClock(AtomicI64::new(now)));
        let (entry, _) = hub_entry(&fed, address, now).unwrap();
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
        let (status, response) = self
            .request(
                "POST",
                "/enroll/v1/sessions/code",
                json!({"code":code,"state":state}),
                Some(handle),
                1,
            )
            .await;
        if status != StatusCode::ACCEPTED {
            return (status, response);
        }
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
pub(crate) fn node_state(
    db: Arc<Mutex<rusqlite::Connection>>,
    dir: &std::path::Path,
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
    peers: Arc<fed::PeersMap>,
) -> Arc<fed::FedState> {
    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);
    Arc::new(fed::FedState {
        node_name: "team.hub".into(),
        peers: peers.into(),
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
async fn protocol_user_field_is_not_authority() {
    let h = Harness::new().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let(status,_)=h.request("POST","/enroll/v1/sessions",json!({"csr_pem":csr,"host":"laptop","provider":"idp","flow":"loopback","redirect_uri":"http://127.0.0.1:18551/cb","user":"root"}),None,1).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "session accepted a self-asserted user field"
    );
    assert!(
        h.idp.request_paths().is_empty(),
        "rejected user field reached provider"
    );
    let (status, created, _) = h.start("laptop", 1).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, collected) = h.complete(&created).await;
    assert_eq!(status, StatusCode::OK);
    use rustls::pki_types::pem::PemObject;
    let cert = rustls::pki_types::CertificateDer::from_pem_slice(
        collected["cert_chain_pem"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        crate::node::node_name_from_cert(cert.as_ref()).unwrap(),
        "alice.laptop"
    );
}
#[tokio::test]
async fn protocol_csr_key_and_single_collect_are_bound_to_session() {
    let h = Harness::new().await;
    let (status, created, key) = h.start("laptop", 1).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, collected) = h.complete(&created).await;
    assert_eq!(status, StatusCode::OK);
    use rustls::pki_types::pem::PemObject;
    let cert = rustls::pki_types::CertificateDer::from_pem_slice(
        collected["cert_chain_pem"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    use sha2::Digest;
    assert_eq!(
        fed::spki_sha256_from_der(cert.as_ref()).unwrap(),
        hex::encode(sha2::Sha256::digest(key.subject_public_key_info())),
        "collected certificate changed the session CSR key"
    );
    let (status, _) = h
        .request(
            "GET",
            "/enroll/v1/sessions",
            Value::Null,
            created["session"].as_str(),
            1,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "session certificate was collected more than once"
    );
}
#[tokio::test]
async fn protocol_global_burst_is_charged() {
    let h = Harness::new().await;
    for n in 1..=10 {
        assert_eq!(h.start(&format!("host{n}"), n).await.0, StatusCode::CREATED);
    }
    assert_eq!(
        h.start("overflow", 11).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "eleventh session escaped the global burst bucket"
    );
}
#[tokio::test]
async fn protocol_per_ip_pending_is_bounded() {
    let h = Harness::new().await;
    for n in 1..=4 {
        assert_eq!(h.start(&format!("host{n}"), 1).await.0, StatusCode::CREATED);
    }
    assert_eq!(
        h.start("overflow", 1).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "fifth session escaped the per-IP pending cap"
    );
}
#[tokio::test]
async fn protocol_pending_capacity_keeps_earlier_session() {
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
    assert_eq!(
        h.start("overflow", 65).await.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "full pending table accepted another session"
    );
    let (status, collected) = h.complete(&first.unwrap()).await;
    assert!(
        status == StatusCode::OK && collected.get("cert_chain_pem").is_some(),
        "full pending table evicted an earlier session"
    );
}

pub(crate) async fn network_server(
    h: &Harness,
    wrong_role: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivatePkcs8KeyDer};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let config = if wrong_role {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let csr = enroll_ca::VerifiedCsr::parse_pem(&csr).unwrap();
        let claims = enroll_ca::VerifiedClaims {
            provider: "idp".into(),
            iss: h.idp.issuer(),
            sub: "fixture-sub".into(),
            email: None,
            email_verified: false,
            hd: None,
            groups: vec![],
            preferred_username: None,
        };
        let issued = h
            .service
            .ca
            .issue(&claims, &csr, "attacker", &[], h.clock.now())
            .unwrap();
        let chain = CertificateDer::pem_slice_iter(issued.cert_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, PrivatePkcs8KeyDer::from(key.serialize_der()).into())
                .unwrap(),
        )
    } else {
        tls_config(&h.service).unwrap()
    };
    let service = h.service.clone();
    let task = tokio::spawn(async move {
        let _ = listen_with_config(listener, service, config).await;
    });
    (url, task)
}
pub(crate) fn enrollment_fingerprint(h: &Harness) -> String {
    use rustls::pki_types::pem::PemObject;
    use sha2::Digest;
    let der = rustls::pki_types::CertificateDer::from_pem_slice(h.service.ca.root_pem().as_bytes())
        .unwrap();
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(der.as_ref())))
}
async fn bootstrap_then_create(
    h: &Harness,
    url: &str,
    fp: &str,
    state: &std::path::Path,
) -> Result<(), enroll_client::Error> {
    let trust = enroll_client::bootstrap(url, Some(fp), None).await?;
    let csr = enroll_client::create_key(state)?;
    let http = enroll_client::http_client(&trust, None)?;
    let response=http.post(format!("{url}/enroll/v1/sessions")).json(&json!({"csr_pem":csr,"host":"laptop","provider":"idp","flow":"loopback","redirect_uri":"http://127.0.0.1:18551/cb"})).send().await.map_err(|_|enroll_client::Error::Transport)?;
    if response.status() != reqwest::StatusCode::CREATED {
        return Err(enroll_client::Error::Response);
    }
    let _ = h;
    Ok(())
}

#[derive(Clone)]
struct TraceBytes(Arc<Mutex<Vec<u8>>>);
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TraceBytes {
    type Writer = TraceBytes;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
impl std::io::Write for TraceBytes {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn database_bytes(connection: &rusqlite::Connection) -> Vec<Vec<u8>> {
    let mut tables = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    let names = tables
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut values = Vec::new();
    for name in names {
        let query = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
        let mut statement = connection.prepare(&query).unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for index in 0..columns {
                use rusqlite::types::ValueRef;
                match row.get_ref(index).unwrap() {
                    ValueRef::Text(value) | ValueRef::Blob(value) => values.push(value.to_vec()),
                    ValueRef::Integer(value) => values.push(value.to_string().into_bytes()),
                    ValueRef::Real(value) => values.push(value.to_string().into_bytes()),
                    ValueRef::Null => {}
                }
            }
        }
    }
    values
}
#[tokio::test]
#[ignore = "invoked in a fresh process by protocol_trace_and_database_contain_no_secrets"]
async fn protocol_trace_child() {
    let output = TraceBytes(Arc::new(Mutex::new(Vec::new())));
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .without_time()
            .with_ansi(false)
            .with_writer(output.clone())
            .finish(),
    )
    .unwrap();
    tracing::debug!(public_control = "enrollment-trace-positive-control");
    let h = Harness::new().await;
    let (url, task) = network_server(&h, false).await;
    let fp = enrollment_fingerprint(&h);
    let trust = enroll_client::bootstrap(&url, Some(&fp), None)
        .await
        .unwrap();
    let http = enroll_client::http_client(&trust, None).unwrap();
    let state = h._directory.path().join("client");
    let csr = enroll_client::create_key(&state).unwrap();
    let created=http.post(format!("{url}/enroll/v1/sessions")).json(&json!({"csr_pem":csr,"host":"laptop","provider":"idp","flow":"loopback","redirect_uri":"http://127.0.0.1:18551/cb"})).send().await.unwrap().json::<Value>().await.unwrap();
    let handle = created["session"].as_str().unwrap();
    let (code, state) = h
        .idp
        .authorize(created["authorization_url"].as_str().unwrap());
    let mut header = reqwest::header::HeaderValue::from_str(handle).unwrap();
    header.set_sensitive(true);
    assert_eq!(
        http.post(format!("{url}/enroll/v1/sessions/code"))
            .header("xmsg-enroll-session", header.clone())
            .json(&json!({"code":code,"state":state}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::ACCEPTED
    );
    let collected = http
        .get(format!("{url}/enroll/v1/sessions?wait=0"))
        .header("xmsg-enroll-session", header)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let pem = collected["cert_chain_pem"].as_str().unwrap();
    let key = std::fs::read(h._directory.path().join("client/fed.key")).unwrap();
    let renewing = enroll_client::http_client(&trust, Some((pem.as_bytes(), &key))).unwrap();
    let renewed = renewing
        .post(format!("{url}/enroll/v1/renew"))
        .send()
        .await
        .unwrap();
    assert_eq!(renewed.status(), reqwest::StatusCode::OK);
    let renewed = renewed.json::<Value>().await.unwrap();
    assert_ne!(collected["serial"], renewed["serial"]);
    let mut secrets = h.idp.secret_values();
    secrets.push(handle.to_string());
    let trace = output.0.lock().unwrap().clone();
    assert!(
        trace
            .windows(b"enrollment-trace-positive-control".len())
            .any(|v| v == b"enrollment-trace-positive-control"),
        "trace positive control did not execute"
    );
    let database = database_bytes(&h.db.lock().unwrap());
    assert!(
        !database.is_empty(),
        "database positive control had no rows"
    );
    for secret in secrets {
        assert!(!secret.is_empty());
        assert!(
            !trace.windows(secret.len()).any(|v| v == secret.as_bytes()),
            "enrollment trace leaked a planted secret"
        );
        assert!(
            !database
                .iter()
                .any(|bytes| bytes.windows(secret.len()).any(|v| v == secret.as_bytes())),
            "enrollment database stored a planted secret"
        );
    }
    task.abort();
    println!("enrollment-full-trace-and-database-census:complete");
}
#[test]
fn protocol_trace_and_database_contain_no_secrets() {
    use std::process::{Command, Stdio};
    let name = format!(
        "{}::protocol_trace_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--ignored", "--nocapture"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("trace census child timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&result.stdout).into_owned()
        + &String::from_utf8_lossy(&result.stderr);
    assert!(
        result.status.success(),
        "trace/database census failed: {text}"
    );
    assert!(
        text.contains("enrollment-full-trace-and-database-census:complete"),
        "census child positive completion missing"
    );
}

#[tokio::test]
async fn protocol_fingerprint_mismatch_creates_no_key_or_session() {
    let h = Harness::new().await;
    let (url, task) = network_server(&h, false).await;
    let fp = enrollment_fingerprint(&h);
    let mut wrong = fp.clone();
    wrong.pop();
    wrong.push(if fp.ends_with('0') { '1' } else { '0' });
    let state = h._directory.path().join("wrong-root");
    let result = bootstrap_then_create(&h, &url, &wrong, &state).await;
    assert!(
        result.is_err(),
        "wrong enrollment root fingerprint accepted"
    );
    assert!(
        !state.join("fed.key").exists(),
        "wrong fingerprint caused private key creation"
    );
    assert!(
        h.service.sessions.lock().unwrap().is_empty(),
        "wrong fingerprint sent a CSR"
    );
    bootstrap_then_create(&h, &url, &fp, &h._directory.path().join("correct-root"))
        .await
        .unwrap();
    assert_eq!(
        h.service.sessions.lock().unwrap().len(),
        1,
        "fingerprint positive control created no session"
    );
    task.abort();
}
#[tokio::test]
async fn protocol_bootstrap_requires_reserved_ca_identity() {
    let h = Harness::new().await;
    let (url, task) = network_server(&h, false).await;
    let fp = enrollment_fingerprint(&h);
    let trust = enroll_client::bootstrap(&url, Some(&fp), None)
        .await
        .unwrap();
    assert_eq!(trust.ca_identity, "spiffe://enroll.example/xmsg/enroll");
    let (bad_url, bad_task) = network_server(&h, true).await;
    assert!(
        enroll_client::bootstrap(&bad_url, Some(&fp), None)
            .await
            .is_err(),
        "bootstrap accepted an enrolled host as the CA"
    );
    bad_task.abort();
    task.abort();
}
#[tokio::test]
async fn protocol_later_connections_require_reserved_ca_identity() {
    let h = Harness::new().await;
    let (url, task) = network_server(&h, false).await;
    let fp = enrollment_fingerprint(&h);
    let trust = enroll_client::bootstrap(&url, Some(&fp), None)
        .await
        .unwrap();
    let http = enroll_client::http_client(&trust, None).unwrap();
    assert_eq!(
        http.get(format!("{url}/enroll/v1/sessions"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let (bad_url, bad_task) = network_server(&h, true).await;
    assert!(
        http.get(format!("{bad_url}/enroll/v1/sessions"))
            .send()
            .await
            .is_err(),
        "later connection accepted an enrolled host as the CA"
    );
    let fresh = enroll_client::http_client(&trust, None).unwrap();
    assert!(
        fresh
            .get(format!("{bad_url}/enroll/v1/sessions"))
            .send()
            .await
            .is_err(),
        "later connection accepted an enrolled host as the CA"
    );
    bad_task.abort();
    task.abort();
}
#[test]
fn protocol_private_key_is_never_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("identity");
    enroll_client::create_key(&state).unwrap();
    let original = std::fs::read(state.join("fed.key")).unwrap();
    assert!(
        matches!(
            enroll_client::create_key(&state),
            Err(enroll_client::Error::KeyExists)
        ),
        "enroll overwrote an existing private key"
    );
    assert_eq!(std::fs::read(state.join("fed.key")).unwrap(), original);
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::fs::metadata(state.join("fed.key")).unwrap().mode() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn protocol_device_flow_is_refused_before_provider_work() {
    let h = Harness::new().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let(status,value)=h.request("POST","/enroll/v1/sessions",json!({"csr_pem":csr,"host":"laptop","provider":"idp","flow":"device","redirect_uri":"http://127.0.0.1:18551/cb"}),None,1).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "device request was silently accepted as another flow"
    );
    assert_eq!(value["error"]["reason"], "unsupported_flow");
    assert!(
        h.idp.request_paths().is_empty(),
        "device request invoked provider work"
    );
    assert!(h.service.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn protocol_unverified_email_cannot_issue_under_email_rule() {
    let h = Harness::new().await;
    let file = h._directory.path().join("policy.json");
    let mut policy: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    policy["users"] = json!([{"provider":"idp","email":"alice@example.com","user":"alice"}]);
    std::fs::write(&file, serde_json::to_vec(&policy).unwrap()).unwrap();
    for verified in [json!("true"), json!(false)] {
        let before: i64 =
            h.db.lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM enroll_certs", [], |r| r.get(0))
                .unwrap();
        let (status, created, _) = h
            .start(
                if verified == json!(false) {
                    "email-negative"
                } else {
                    "email-positive"
                },
                1,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let (code, state) = h
            .idp
            .authorize(created["authorization_url"].as_str().unwrap());
        h.idp
            .set_code_claim(&code, "email", json!("alice@example.com"));
        h.idp
            .set_code_claim(&code, "email_verified", verified.clone());
        if verified == json!(false) {
            h.idp
                .set_code_signing(&code, "RS256", "rotated", false, false);
        }
        let handle = created["session"].as_str().unwrap();
        let (status, _) = h
            .request(
                "POST",
                "/enroll/v1/sessions/code",
                json!({"code":code,"state":state}),
                Some(handle),
                1,
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (_, result) = h
            .request(
                "GET",
                "/enroll/v1/sessions?wait=0",
                Value::Null,
                Some(handle),
                1,
            )
            .await;
        let after: i64 =
            h.db.lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM enroll_certs", [], |r| r.get(0))
                .unwrap();
        if verified == json!(false) {
            assert!(
                result.get("cert_chain_pem").is_none(),
                "unverified email issued under an email rule"
            );
            assert_eq!(
                result["error"]["reason"], "denied",
                "unverified-email cell was masked by a different rejection"
            );
            assert_eq!(after, before, "unverified email wrote an authority row");
        } else {
            assert!(
                result.get("cert_chain_pem").is_some(),
                "verified string-boolean email was refused"
            );
            assert_eq!(after, before + 1);
        }
    }
}
