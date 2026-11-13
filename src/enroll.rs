//! Optional enrollment listener, separate from authenticated federation routes.
use crate::{
    enroll_ca::{EnrollCa, Flow, Issued, VerifiedCsr},
    enroll_oidc,
};
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Json, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;

pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}
pub struct WallClock;
impl Clock for WallClock {
    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .min(i64::MAX as u64) as i64
    }
}
#[derive(Clone, Copy)]
struct Failure(StatusCode, &'static str);
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error":{"reason":self.1}}))).into_response()
    }
}
fn core_failure(error: crate::enroll_ca::Error) -> Failure {
    let reason = error.code();
    let status = match reason {
        "unsupported_flow" | "unsupported_key" | "invalid_csr" | "invalid_name" => {
            StatusCode::BAD_REQUEST
        }
        "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
        "reenroll_required" | "reauth_required" => StatusCode::UNAUTHORIZED,
        "denied" | "name_bound" | "reserved_name" | "superseded" | "already_primary" => {
            StatusCode::FORBIDDEN
        }
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    Failure(status, reason)
}
#[derive(Serialize)]
struct SessionFailure {
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<usize>,
}
impl SessionFailure {
    fn reason(reason: &'static str) -> Self {
        Self { reason, rule: None }
    }
}

fn oidc_reason(error: enroll_oidc::Error) -> &'static str {
    use enroll_oidc::Error;
    match error {
        Error::UnsupportedFlow => "unsupported_flow",
        Error::UnsupportedIssuer => "unsupported_issuer",
        Error::Configuration => "provider_configuration",
        Error::Unavailable => "provider_unavailable",
        Error::State => "invalid_state",
        Error::Token => "invalid_id_token",
        Error::Audience => "aud",
        Error::Issuer => "iss",
        Error::Expired => "exp",
        Error::IssuedAt => "iat",
        Error::Nonce => "nonce",
        Error::Signature => "signature",
    }
}
#[derive(Clone)]
pub struct Peer {
    pub ip: IpAddr,
    pub certificates: Vec<Vec<u8>>,
}
struct Authorization {
    provider: Arc<enroll_oidc::Provider>,
    pending: enroll_oidc::PendingAuthorization,
}
enum Phase {
    Preparing,
    Code(Authorization),
    Exchanging,
    Consumed,
    Complete(Result<Issued, SessionFailure>),
}
struct Session {
    ip: IpAddr,
    expires: i64,
    host: String,
    csr: VerifiedCsr,
    phase: Mutex<Phase>,
    notify: Notify,
}
struct Bucket {
    units: u64,
    observed: i64,
}
impl Bucket {
    fn take(&mut self, now: i64) -> bool {
        if now > self.observed {
            self.units = self
                .units
                .saturating_add((now.saturating_sub(self.observed) as u64).saturating_mul(500_000))
                .min(10_000_000);
            self.observed = now;
        }
        if self.units < 1_000_000 {
            false
        } else {
            self.units -= 1_000_000;
            true
        }
    }
}
pub struct Service {
    pub ca: Arc<EnrollCa>,
    pub fed: Arc<crate::fed::FedState>,
    clock: Arc<dyn Clock>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    bucket: Mutex<Bucket>,
    hub_entry: serde_json::Value,
    ca_identity: String,
    oidc_http: reqwest::Client,
}
impl Service {
    pub fn new(
        ca: Arc<EnrollCa>,
        fed: Arc<crate::fed::FedState>,
        clock: Arc<dyn Clock>,
        hub_entry: serde_json::Value,
        ca_identity: String,
    ) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self::with_oidc_http(
            ca,
            fed,
            clock,
            hub_entry,
            ca_identity,
            http,
        ))
    }
    pub(crate) fn with_oidc_http(
        ca: Arc<EnrollCa>,
        fed: Arc<crate::fed::FedState>,
        clock: Arc<dyn Clock>,
        hub_entry: serde_json::Value,
        ca_identity: String,
        http: reqwest::Client,
    ) -> Self {
        let now = clock.now();
        Self {
            ca,
            fed,
            clock,
            sessions: Mutex::new(HashMap::new()),
            bucket: Mutex::new(Bucket {
                units: 10_000_000,
                observed: now,
            }),
            hub_entry,
            ca_identity,
            oidc_http: http,
        }
    }
    fn refresh(&self) {
        let _ = self.ca.reload_policy();
    }
    fn lookup(&self, headers: &HeaderMap) -> Result<Arc<Session>, Failure> {
        let handle = headers
            .get("xmsg-enroll-session")
            .and_then(|h| h.to_str().ok())
            .ok_or(Failure(StatusCode::UNAUTHORIZED, "session_required"))?;
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| session.expires > self.clock.now());
        sessions
            .get(handle)
            .cloned()
            .ok_or(Failure(StatusCode::GONE, "gone"))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    csr_pem: String,
    host: String,
    provider: Option<String>,
    flow: Flow,
    redirect_uri: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    code: String,
    state: String,
}
fn valid_host(host: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    !host.is_empty()
        && host.len() <= 32
        && alnum(host.as_bytes()[0])
        && alnum(*host.as_bytes().last().unwrap())
        && host.bytes().all(|b| alnum(b) || b == b'-')
}
pub fn valid_redirect(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1"))
        && url.port().is_some_and(|p| p != 0)
        && url.path() == "/cb"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}
async fn create(
    State(service): State<Arc<Service>>,
    axum::Extension(peer): axum::Extension<Peer>,
    body: Result<Json<Create>, JsonRejection>,
) -> Result<Response, Failure> {
    let Json(body) = body.map_err(|_| Failure(StatusCode::BAD_REQUEST, "invalid_request"))?;
    if body.flow == Flow::Device {
        return Err(Failure(StatusCode::BAD_REQUEST, "unsupported_flow"));
    }
    if !valid_host(&body.host) {
        return Err(Failure(StatusCode::BAD_REQUEST, "invalid_host"));
    }
    let redirect = body
        .redirect_uri
        .filter(|value| valid_redirect(value))
        .ok_or(Failure(StatusCode::BAD_REQUEST, "invalid_redirect"))?;
    let now = service.clock.now();
    if !service.bucket.lock().unwrap().take(now) {
        return Err(Failure(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }
    let csr = VerifiedCsr::parse_pem(&body.csr_pem).map_err(core_failure)?;
    service.refresh();
    let policy = service.ca.policy();
    let label = match body.provider {
        Some(label) => label,
        None if policy.providers.len() == 1 => policy.providers.keys().next().unwrap().clone(),
        _ => return Err(Failure(StatusCode::BAD_REQUEST, "provider_required")),
    };
    let config = policy
        .providers
        .get(&label)
        .cloned()
        .ok_or(Failure(StatusCode::BAD_REQUEST, "unknown_provider"))?;
    config.client(body.flow).map_err(core_failure)?;
    let handle = {
        use base64::Engine;
        let mut value = [0u8; 32];
        getrandom::fill(&mut value)
            .map_err(|_| Failure(StatusCode::SERVICE_UNAVAILABLE, "random_unavailable"))?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
    };
    let session = Arc::new(Session {
        ip: peer.ip,
        expires: now.saturating_add(600),
        host: body.host,
        csr,
        phase: Mutex::new(Phase::Preparing),
        notify: Notify::new(),
    });
    {
        let mut sessions = service.sessions.lock().unwrap();
        sessions.retain(|_, s| s.expires > now);
        if sessions.values().filter(|s| s.ip == peer.ip).count() >= 4 {
            return Err(Failure(StatusCode::TOO_MANY_REQUESTS, "pending_per_ip"));
        }
        if sessions.len() >= 64 {
            return Err(Failure(StatusCode::SERVICE_UNAVAILABLE, "pending_full"));
        }
        if sessions.contains_key(&handle) {
            return Err(Failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "session_collision",
            ));
        }
        sessions.insert(handle.clone(), session.clone());
    }
    let groups = policy
        .users
        .iter()
        .any(|rule| rule.provider == label && rule.group.is_some());
    let prepared = async {
        let provider = Arc::new(
            enroll_oidc::Provider::discover_with_client(
                &label,
                &config,
                groups,
                service.oidc_http.clone(),
            )
            .await?,
        );
        let pending = provider.begin(body.flow, &redirect)?;
        Ok::<_, enroll_oidc::Error>((provider, pending))
    }
    .await;
    let (provider, pending) = match prepared {
        Ok(value) => value,
        Err(error) => {
            service.sessions.lock().unwrap().remove(&handle);
            return Err(Failure(StatusCode::SERVICE_UNAVAILABLE, oidc_reason(error)));
        }
    };
    if session.expires <= service.clock.now() {
        service.sessions.lock().unwrap().remove(&handle);
        return Err(Failure(StatusCode::GONE, "expired"));
    }
    let authorization_url = pending.authorization_url.clone();
    *session.phase.lock().unwrap() = Phase::Code(Authorization { provider, pending });
    Ok((StatusCode::CREATED,Json(serde_json::json!({"session":handle,"expires_in":600,"authorization_url":authorization_url}))).into_response())
}
async fn code(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    body: Result<Json<Code>, JsonRejection>,
) -> Result<Response, Failure> {
    let Json(body) = body.map_err(|_| Failure(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let session = service.lookup(&headers)?;
    let authorization = {
        let mut phase = session.phase.lock().unwrap();
        match std::mem::replace(&mut *phase, Phase::Exchanging) {
            Phase::Code(auth) => auth,
            other => {
                *phase = other;
                return Err(Failure(StatusCode::CONFLICT, "invalid_session_state"));
            }
        }
    };
    let result = async {
        let claims = authorization
            .provider
            .exchange(authorization.pending, &body.code, &body.state, &|| {
                service.clock.now()
            })
            .await
            .map_err(|error| SessionFailure::reason(oidc_reason(error)))?;
        if session.expires <= service.clock.now() {
            return Err(SessionFailure::reason("expired"));
        }
        service.refresh();
        let peers = service.fed.current_peers();
        let names = peers
            .iter()
            .map(|(_, peer)| {
                peers
                    .canonical_name(&peer.name)
                    .unwrap_or(&peer.name)
                    .to_string()
            })
            .collect::<Vec<_>>();
        service
            .ca
            .issue(
                &claims,
                &session.csr,
                &session.host,
                &names,
                service.clock.now(),
            )
            .map_err(|error| {
                let rule = match &error {
                    crate::enroll_ca::Error::InvalidRuleName(index) => Some(*index),
                    _ => None,
                };
                SessionFailure {
                    reason: error.code(),
                    rule,
                }
            })
    }
    .await;
    *session.phase.lock().unwrap() = Phase::Complete(result);
    session.notify.notify_waiters();
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"status":"complete"})),
    )
        .into_response())
}
#[derive(Deserialize)]
struct Wait {
    wait: Option<u64>,
}
#[derive(Serialize)]
struct Collected {
    cert_chain_pem: String,
    root_pem: String,
    ca_identity: String,
    hub_entry: serde_json::Value,
    serial: String,
    not_after: i64,
    superseded_serials: Vec<String>,
}
async fn collect(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<Wait>,
) -> Result<Response, Failure> {
    let session = service.lookup(&headers)?;
    let notified = session.notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    if !matches!(*session.phase.lock().unwrap(), Phase::Complete(_)) {
        let _ = tokio::time::timeout(
            Duration::from_secs(query.wait.unwrap_or(0).min(30)),
            notified,
        )
        .await;
    }
    let complete = {
        let mut phase = session.phase.lock().unwrap();
        match std::mem::replace(&mut *phase, Phase::Consumed) {
            Phase::Complete(result) => Some(result),
            Phase::Consumed => return Err(Failure(StatusCode::GONE, "gone")),
            other => {
                *phase = other;
                None
            }
        }
    };
    let Some(result) = complete else {
        return Ok(Json(serde_json::json!({"status":"pending"})).into_response());
    };
    let handle = headers
        .get("xmsg-enroll-session")
        .and_then(|h| h.to_str().ok())
        .ok_or(Failure(StatusCode::UNAUTHORIZED, "session_required"))?;
    service.sessions.lock().unwrap().remove(handle);
    session.notify.notify_waiters();
    match result {
        Err(error) => Ok(Json(serde_json::json!({"error":error})).into_response()),
        Ok(issued) => Ok(Json(Collected {
            cert_chain_pem: issued.cert_chain_pem,
            root_pem: issued.root_pem,
            ca_identity: service.ca_identity.clone(),
            hub_entry: service.hub_entry.clone(),
            serial: issued.serial,
            not_after: issued.not_after,
            superseded_serials: issued.superseded_serials,
        })
        .into_response()),
    }
}
async fn renew(
    State(service): State<Arc<Service>>,
    axum::Extension(peer): axum::Extension<Peer>,
    body: axum::body::Bytes,
) -> Result<Response, Failure> {
    if !body.is_empty() {
        return Err(Failure(StatusCode::BAD_REQUEST, "unexpected_body"));
    }
    if peer.certificates.is_empty() {
        return Err(Failure(StatusCode::UNAUTHORIZED, "certificate_required"));
    }
    service.refresh();
    let issued = service
        .ca
        .renew(&peer.certificates, service.clock.now())
        .map_err(core_failure)?;
    Ok(Json(serde_json::json!({"cert_chain_pem":issued.cert_chain_pem,"serial":issued.serial,"not_after":issued.not_after})).into_response())
}
pub fn router(service: Arc<Service>) -> Router {
    Router::new()
        .route("/enroll/v1/sessions", post(create).get(collect))
        .route("/enroll/v1/sessions/code", post(code))
        .route("/enroll/v1/renew", post(renew))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(service)
}

#[derive(Debug)]
struct PresentedCertificate;
impl rustls::server::danger::ClientCertVerifier for PresentedCertificate {
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
struct IpGuard {
    ip: IpAddr,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}
impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap();
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}
pub fn tls_config(
    service: &Service,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let identity = service.ca.server_identity(service.clock.now())?;
    if identity.uri != service.ca_identity {
        return Err("enrollment server identity changed during startup".into());
    }
    let chain = identity
        .cert_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_client_cert_verifier(Arc::new(PresentedCertificate))
    .with_single_cert(
        chain,
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der)),
    )?;
    Ok(Arc::new(config))
}
pub async fn listen(
    listener: tokio::net::TcpListener,
    service: Arc<Service>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = tls_config(&service)?;
    listen_with_config(listener, service, config).await
}
pub async fn listen_with_config(
    listener: tokio::net::TcpListener,
    service: Arc<Service>,
    config: Arc<rustls::ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tower::ServiceExt;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(128));
    let counts = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
    let router = router(service);
    loop {
        let (socket, address) = listener.accept().await?;
        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            continue;
        };
        let guard = {
            let mut counts_guard = counts.lock().unwrap();
            let count = counts_guard.entry(address.ip()).or_default();
            if *count >= 8 {
                continue;
            }
            *count += 1;
            IpGuard {
                ip: address.ip(),
                counts: counts.clone(),
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(3), acceptor.accept(socket)).await
            else {
                return;
            };
            drop(guard);
            let certificates = tls
                .get_ref()
                .1
                .peer_certificates()
                .unwrap_or(&[])
                .iter()
                .map(|c| c.to_vec())
                .collect::<Vec<_>>();
            let peer = Peer {
                ip: address.ip(),
                certificates,
            };
            let handler = hyper::service::service_fn(
                move |mut request: hyper::Request<hyper::body::Incoming>| {
                    request.extensions_mut().insert(peer.clone());
                    let router = router.clone();
                    async move { router.oneshot(request).await }
                },
            );
            let _ =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), handler)
                    .await;
        });
    }
}

/// The returned CA PEM is public and is written locally as hub-ca.pem.
pub fn hub_entry(
    fed: &crate::fed::FedState,
    address: &str,
    now: i64,
) -> Result<(serde_json::Value, Option<String>), &'static str> {
    use rustls::pki_types::UnixTime;
    use x509_parser::extensions::ParsedExtension;
    let endpoint = address.parse::<std::net::SocketAddr>().ok();
    if address.is_empty() || endpoint.is_some_and(|a| a.ip().is_unspecified() || a.port() == 0) {
        return Err("hub_address_required");
    }
    let chain = fed.cert_chain();
    let leaf = chain.first().ok_or("federation_identity_required")?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|_| "invalid_federation_certificate")?;
    let is_ca = |c: &x509_parser::certificate::X509Certificate<'_>| {
        c.extensions().iter().any(|ext|matches!(ext.parsed_extension(),ParsedExtension::BasicConstraints(value) if value.ca))
    };
    let self_signed = |c: &x509_parser::certificate::X509Certificate<'_>| {
        c.subject() == c.issuer() && c.verify_signature(None).is_ok()
    };
    if chain.len() == 1 && !is_ca(&parsed) && self_signed(&parsed) {
        let pin = crate::fed::spki_sha256_from_der(leaf.as_ref())
            .map_err(|_| "invalid_federation_certificate")?;
        let name =
            crate::node::node_name_from_pin(&pin).map_err(|_| "invalid_federation_certificate")?;
        return Ok((
            serde_json::json!({"name":name,"pin":format!("sha256:{pin}"),"address":address}),
            None,
        ));
    }
    if chain.len() < 2 {
        return Err("federation_chain_root_required");
    }
    let root = chain.last().unwrap();
    let (_, parsed_root) = x509_parser::parse_x509_certificate(root.as_ref())
        .map_err(|_| "invalid_federation_certificate")?;
    if !is_ca(&parsed_root) || !self_signed(&parsed_root) {
        return Err("federation_chain_root_required");
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(root.as_ref());
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    let anchors =
        crate::fed::parse_ca_bundle_pem(pem.as_bytes()).map_err(|_| "invalid_federation_root")?;
    crate::fed::verify_cert_chain(
        leaf,
        &chain[1..],
        &anchors,
        UnixTime::since_unix_epoch(Duration::from_secs(now.max(0) as u64)),
        webpki::KeyUsage::server_auth(),
    )
    .map_err(|_| "invalid_federation_chain")?;
    let uris =
        crate::fed::extract_uri_sans(leaf.as_ref()).map_err(|_| "invalid_federation_identity")?;
    let [uri] = uris.as_slice() else {
        return Err("single_federation_uri_required");
    };
    let name = crate::node::node_name_from_uri(uri).map_err(|_| "invalid_federation_identity")?;
    Ok((
        serde_json::json!({"name":name,"ca":pem.clone(),"identities":[uri],"address":address}),
        Some(pem),
    ))
}

#[cfg(test)]
#[path = "enroll_protocol_tests.rs"]
pub(crate) mod protocol_tests;

#[cfg(test)]
mod hub_entry_tests {
    use super::*;
    use crate::enroll::protocol_tests::{node_state, Harness};

    #[tokio::test]
    async fn uri_bearing_self_signed_hub_uses_its_pin() {
        let h = Harness::new().await;
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://fleet.example/host/hub/user/team"
                .try_into()
                .unwrap(),
        )];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.self_signed(&key).unwrap();
        let fed = node_state(
            h.db.clone(),
            h._directory.path(),
            vec![cert.der().to_vec()],
            key.serialize_der(),
            h.service.fed.current_peers(),
        );
        let (entry, bundle) = hub_entry(&fed, "127.0.0.1:7788", WallClock.now())
            .expect("URI-bearing pinned node must use its pin");
        assert!(bundle.is_none());
        assert!(entry.get("ca").is_none());
        let pin = crate::fed::spki_sha256_from_der(cert.der()).unwrap();
        assert_eq!(entry["pin"], format!("sha256:{pin}"));
        assert_eq!(
            entry["name"],
            crate::node::node_name_from_pin(&pin).unwrap()
        );
        let state = h._directory.path().join("pinned-client");
        let csr = crate::enroll_client::create_key(&state).unwrap();
        let issued = h
            .service
            .ca
            .issue(
                &crate::enroll_ca::VerifiedClaims {
                    provider: "idp".into(),
                    iss: h.idp.issuer(),
                    sub: "fixture-sub".into(),
                    email: None,
                    email_verified: false,
                    hd: None,
                    groups: vec![],
                    preferred_username: None,
                },
                &VerifiedCsr::parse_pem(&csr).unwrap(),
                "pinned-client",
                &[],
                WallClock.now(),
            )
            .unwrap();
        use rustls::pki_types::pem::PemObject;
        let chain =
            rustls::pki_types::CertificateDer::pem_slice_iter(issued.cert_chain_pem.as_bytes())
                .map(|c| c.unwrap().to_vec())
                .collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let name = entry["name"].as_str().unwrap();
        let peers = Arc::new(crate::fed::PeersMap::load_from_json(&serde_json::json!({"peers":{name:{"address":address.to_string(),"pin":entry["pin"],"allow":["send"]}}}).to_string()).unwrap());
        let key =
            rcgen::KeyPair::from_pem(&std::fs::read_to_string(state.join("fed.key")).unwrap())
                .unwrap();
        let client = node_state(
            h.db.clone(),
            h._directory.path(),
            chain,
            key.serialize_der(),
            peers.clone(),
        );
        let server = tokio::spawn(crate::fed::run_fed_listener(listener, fed));
        let connector =
            crate::fed::make_tls_connector_for_peer(&client, peers.get(name).unwrap()).unwrap();
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let connected = tokio::time::timeout(
            Duration::from_secs(3),
            connector.connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                socket,
            ),
        )
        .await
        .unwrap();
        assert!(
            connected.is_ok(),
            "URI-bearing pinned hub could not be dialed"
        );
        server.abort();
    }

    #[tokio::test]
    async fn incomplete_ca_chain_is_not_an_enrollment_hub_identity() {
        let h = Harness::new().await;
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut root_params = rcgen::CertificateParams::default();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let intermediate_key = rcgen::KeyPair::generate().unwrap();
        let mut intermediate_params = rcgen::CertificateParams::default();
        intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        intermediate_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let intermediate = intermediate_params
            .signed_by(
                &intermediate_key,
                &rcgen::Issuer::from_params(&root_params, &root_key),
            )
            .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://fleet.example/host/hub/user/team"
                .try_into()
                .unwrap(),
        )];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(
                &key,
                &rcgen::Issuer::from_params(&intermediate_params, &intermediate_key),
            )
            .unwrap();
        let fed = node_state(
            h.db.clone(),
            h._directory.path(),
            vec![leaf.der().to_vec(), intermediate.der().to_vec()],
            key.serialize_der(),
            Arc::new(crate::fed::PeersMap::new(HashMap::new())),
        );
        assert!(
            hub_entry(&fed, "127.0.0.1:7788", WallClock.now()).is_err(),
            "hub entry accepted an intermediate without its root"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redirect_and_host_bounds() {
        assert!(valid_redirect("http://127.0.0.1:18551/cb"));
        assert!(valid_redirect("http://[::1]:18551/cb"));
        for value in [
            "https://127.0.0.1:1/cb",
            "http://localhost:1/cb",
            "http://127.0.0.2:1/cb",
            "http://127.0.0.1:1/cb?x=1",
            "http://127.0.0.1:1/no",
        ] {
            assert!(!valid_redirect(value));
        }
        assert!(valid_host("laptop-1"));
        for host in ["", "Laptop", "a.b", "-x", "x-", "a/b"] {
            assert!(!valid_host(host));
        }
    }
    #[test]
    fn burst_is_bounded_and_refills_without_eviction() {
        let mut bucket = Bucket {
            units: 10_000_000,
            observed: 0,
        };
        for _ in 0..10 {
            assert!(bucket.take(0));
        }
        assert!(!bucket.take(0));
        assert!(bucket.take(2));
        assert!(!bucket.take(2));
    }
}
