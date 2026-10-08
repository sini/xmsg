use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tracing::debug;

use crate::error::AppError;
use crate::inbox::{self, DeliveryResponse};
use crate::storage::{self, MessageRecord};

#[derive(Deserialize)]
struct WireErrorResponse {
    error: String,
    detail: String,
}

// -----------------------------------------------------------------------------
// Peers Configuration & File Format
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    #[serde(default)]
    pub name: String,
    pub address: String,
    pub pin: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub no_whois: bool,
    #[serde(default)]
    pub leaf: bool,
    #[serde(default)]
    pub principals: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum PeersFileRaw {
    MapWrapped {
        peers: HashMap<String, PeerConfigRaw>,
    },
    MapDirect(HashMap<String, PeerConfigRaw>),
    List(Vec<PeerConfigRaw>),
}

#[derive(Debug, Clone, Deserialize)]
struct PeerConfigRaw {
    #[serde(default)]
    pub name: Option<String>,
    pub address: String,
    pub pin: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub no_whois: bool,
    #[serde(default)]
    pub leaf: bool,
    #[serde(default)]
    pub principals: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PeersMap {
    peers_by_name: HashMap<String, PeerConfig>,
    name_by_pin: HashMap<String, String>,
}

impl PeersMap {
    pub fn new(peers: HashMap<String, PeerConfig>) -> Self {
        let mut map = Self::default();
        for (_, peer) in peers {
            map.insert(peer);
        }
        map
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, mut peer: PeerConfig) {
        let norm_pin = normalize_pin(&peer.pin);
        peer.pin = norm_pin.clone();
        self.name_by_pin.insert(norm_pin, peer.name.clone());
        self.peers_by_name.insert(peer.name.clone(), peer);
    }

    pub fn get(&self, name: &str) -> Option<&PeerConfig> {
        self.peers_by_name.get(name)
    }

    pub fn get_by_pin(&self, pin: &str) -> Option<&PeerConfig> {
        let norm = normalize_pin(pin);
        self.name_by_pin
            .get(&norm)
            .and_then(|name| self.peers_by_name.get(name))
    }

    pub fn contains_name(&self, name: &str) -> bool {
        self.peers_by_name.contains_key(name)
    }

    pub fn allowed_pins(&self) -> &HashMap<String, String> {
        &self.name_by_pin
    }

    pub fn load_from_json(json_str: &str) -> Result<Self, String> {
        let raw: PeersFileRaw = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse peers JSON: {e}"))?;

        let mut map = Self::empty();
        match raw {
            PeersFileRaw::MapWrapped { peers } | PeersFileRaw::MapDirect(peers) => {
                for (key_name, entry) in peers {
                    let name = entry.name.unwrap_or(key_name);
                    map.insert(PeerConfig {
                        name,
                        address: entry.address,
                        pin: entry.pin,
                        allow: entry.allow,
                        no_whois: entry.no_whois,
                        leaf: entry.leaf,
                        principals: entry.principals,
                    });
                }
            }
            PeersFileRaw::List(list) => {
                for entry in list {
                    let name = entry
                        .name
                        .ok_or_else(|| "Peer list entry missing 'name' field".to_string())?;
                    map.insert(PeerConfig {
                        name,
                        address: entry.address,
                        pin: entry.pin,
                        allow: entry.allow,
                        no_whois: entry.no_whois,
                        leaf: entry.leaf,
                        principals: entry.principals,
                    });
                }
            }
        }
        Ok(map)
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read peers file {}: {e}", path.display()))?;
        Self::load_from_json(&content)
    }
}

pub fn load_peers_file(path: &Path) -> Result<PeersMap, String> {
    PeersMap::load_from_file(path)
}

pub fn split_peer_ref(r: &str) -> Option<(&str, &str)> {
    let r = r.trim();
    if let Some(pos) = r.rfind('@') {
        let target = &r[..pos];
        let host = &r[pos + 1..];
        if !target.is_empty() && !host.is_empty() {
            return Some((target, host));
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Pin Extraction & Normalization
// -----------------------------------------------------------------------------

pub fn normalize_pin(pin: &str) -> String {
    let s = pin.trim();
    let s = s.strip_prefix("sha256:").unwrap_or(s);
    let s = s.strip_prefix("SHA256:").unwrap_or(s);
    s.to_ascii_lowercase()
}

pub fn spki_sha256_from_der(cert_der: &[u8]) -> Result<String, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;
    let spki_bytes = cert.tbs_certificate.subject_pki.raw;
    use sha2::Digest;
    let hash = sha2::Sha256::digest(spki_bytes);
    Ok(hex::encode(hash))
}

// -----------------------------------------------------------------------------
// Custom TLS Verifiers (Pinned SPKI Hash)
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub struct PinnedClientCertVerifier {
    allowed_pins: Arc<HashMap<String, String>>, // pin -> peer_name
}

impl PinnedClientCertVerifier {
    pub fn new(allowed_pins: Arc<HashMap<String, String>>) -> Self {
        Self { allowed_pins }
    }
}

impl rustls::server::danger::ClientCertVerifier for PinnedClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let pin = spki_sha256_from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let norm_pin = normalize_pin(&pin);
        if self.allowed_pins.contains_key(&norm_pin) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    expected_pin: String,
}

impl PinnedServerCertVerifier {
    pub fn new(expected_pin: &str) -> Self {
        Self {
            expected_pin: normalize_pin(expected_pin),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let pin = spki_sha256_from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let norm_pin = normalize_pin(&pin);
        if norm_pin == self.expected_pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// -----------------------------------------------------------------------------
// WhoIs Verifier Trait & Stand-ins
// -----------------------------------------------------------------------------

pub trait WhoIsVerifier: Send + Sync {
    fn verify_node<'a>(
        &'a self,
        remote_ip: &'a IpAddr,
        expected_node: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + 'a>>;
}

#[derive(Debug, Default, Clone)]
pub struct MockWhoIsVerifier {
    pub rejected_nodes: Arc<Mutex<Vec<String>>>,
    pub rejected_ips: Arc<Mutex<Vec<IpAddr>>>,
}

impl MockWhoIsVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reject_node(&self, node: &str) {
        self.rejected_nodes.lock().unwrap().push(node.to_string());
    }

    pub fn reject_ip(&self, ip: IpAddr) {
        self.rejected_ips.lock().unwrap().push(ip);
    }
}

impl WhoIsVerifier for MockWhoIsVerifier {
    fn verify_node<'a>(
        &'a self,
        remote_ip: &'a IpAddr,
        expected_node: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + 'a>>
    {
        let is_rejected_ip = self.rejected_ips.lock().unwrap().contains(remote_ip);
        let is_rejected_node = self
            .rejected_nodes
            .lock()
            .unwrap()
            .contains(&expected_node.to_string());
        Box::pin(async move {
            if is_rejected_ip || is_rejected_node {
                Ok(false)
            } else {
                Ok(true)
            }
        })
    }
}

// -----------------------------------------------------------------------------
// Token Bucket Rate Limiting
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    fill_rate_per_sec: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, fill_rate_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            fill_rate_per_sec,
            last_update: Instant::now(),
        }
    }

    fn take(&mut self, count: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.tokens = (self.tokens + elapsed * self.fill_rate_per_sec).min(self.capacity);

        if self.tokens >= count {
            self.tokens -= count;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    peer_limit: f64,
    principal_limit: f64,
    peer_buckets: Mutex<HashMap<String, TokenBucket>>,
    principal_buckets: Mutex<HashMap<(String, String), TokenBucket>>,
}

impl RateLimiter {
    pub fn new(peer_per_min: u32, principal_per_min: u32) -> Self {
        Self {
            peer_limit: peer_per_min as f64,
            principal_limit: principal_per_min as f64,
            peer_buckets: Mutex::new(HashMap::new()),
            principal_buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_consume(&self, peer: &str, principal_key: Option<&str>) -> bool {
        let mut p_buckets = self.peer_buckets.lock().unwrap();
        let peer_bucket = p_buckets
            .entry(peer.to_string())
            .or_insert_with(|| TokenBucket::new(self.peer_limit, self.peer_limit / 60.0));

        if !peer_bucket.take(1.0) {
            return false;
        }

        if let Some(pkey) = principal_key {
            let mut pr_buckets = self.principal_buckets.lock().unwrap();
            let pr_bucket = pr_buckets
                .entry((peer.to_string(), pkey.to_string()))
                .or_insert_with(|| {
                    TokenBucket::new(self.principal_limit, self.principal_limit / 60.0)
                });
            if !pr_bucket.take(1.0) {
                return false;
            }
        }

        true
    }
}

// -----------------------------------------------------------------------------
// Wire Protocol Envelopes
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedEnvelope {
    pub v: u32,
    pub id: String,
    pub principal: FedPrincipal,
    pub to: FedTarget,
    pub body: String,
    pub push_replies: bool,
    pub thread_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum FedPrincipal {
    #[serde(rename = "session")]
    Session {
        harness: String,
        session_id: String,
        name: String,
    },
    #[serde(rename = "service")]
    Service { name: String },
    #[serde(rename = "anonymous")]
    Anonymous { from: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedTarget {
    pub r#ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedReplyEnvelope {
    pub v: u32,
    pub id: String,
    pub in_reply_to: String,
    pub replier: FedReplier,
    pub text: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FedReplier {
    pub harness: String,
    pub session_id: String,
    pub name: String,
}

// -----------------------------------------------------------------------------
// Authenticated Peer Context
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub name: String,
    pub pin: String,
    pub remote_ip: IpAddr,
}

// -----------------------------------------------------------------------------
// Federation State
// -----------------------------------------------------------------------------

pub struct FedState {
    pub host_label: String,
    pub peers: Arc<PeersMap>,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub whois_verifier: Arc<dyn WhoIsVerifier>,
    pub rate_limiter: Arc<RateLimiter>,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub sessions_dir: PathBuf,
    pub agy_config: crate::agy::AgyConfig,
    pub agy_store: crate::agy::AgyStore,
    pub pi_store: crate::pi::PiStore,
    pub pi_notify_tx: broadcast::Sender<String>,
    pub notify_tx: broadcast::Sender<String>,
    pub max_body: usize,
}

// -----------------------------------------------------------------------------
// Federation Router & Handlers
// -----------------------------------------------------------------------------

pub fn build_fed_router(fed_state: Arc<FedState>) -> Router {
    let max_body_limit = fed_state.max_body + 4096;
    Router::new()
        .route("/fed/v1/messages", post(fed_send_message_handler))
        .route("/fed/v1/replies", post(fed_reply_handler))
        .layer(DefaultBodyLimit::max(max_body_limit))
        .with_state(fed_state)
}

async fn fed_send_message_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Json(envelope): Json<FedEnvelope>,
) -> Result<Response, AppError> {
    if envelope.v != 1 {
        return Err(AppError::BadRequest(format!(
            "unsupported protocol version {}",
            envelope.v
        )));
    }

    // 1. Check peer config and allow list
    let peer_cfg = fed_state
        .peers
        .get(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    if !peer_cfg.allow.iter().any(|op| op == "send") {
        return Err(AppError::OpDenied(
            "send operation not allowed for peer".to_string(),
        ));
    }

    if !peer_cfg.principals.is_empty() {
        let authorized = match &envelope.principal {
            FedPrincipal::Session {
                harness,
                name,
                session_id,
                ..
            } => {
                let badge = format!("{harness}:{name}");
                peer_cfg
                    .principals
                    .iter()
                    .any(|p| p == name || p == &badge || p == session_id)
            }
            FedPrincipal::Service { name } => {
                let badge = format!("svc:{name}");
                peer_cfg.principals.iter().any(|p| p == name || p == &badge)
            }
            FedPrincipal::Anonymous { from } => {
                let badge = format!("anon:{from}");
                peer_cfg.principals.iter().any(|p| p == from || p == &badge)
            }
        };
        if !authorized {
            return Err(AppError::OpDenied(
                "principal not authorized for peer".to_string(),
            ));
        }
    }

    // 2. WhoIs secondary check (if not no_whois)
    if !peer_cfg.no_whois {
        match fed_state
            .whois_verifier
            .verify_node(&peer.remote_ip, &peer.name)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(AppError::PeerRejected(
                    "WhoIs node identity mismatch".to_string(),
                ));
            }
            Err(e) => {
                return Err(AppError::PeerRejected(format!(
                    "WhoIs verification failed: {e}"
                )));
            }
        }
    }

    // 3. Rate limiting
    let principal_key = match &envelope.principal {
        FedPrincipal::Session {
            harness,
            session_id,
            ..
        } => Some(format!("{harness}:{session_id}")),
        FedPrincipal::Service { name } => Some(format!("svc:{name}")),
        FedPrincipal::Anonymous { from } => Some(format!("anon:{from}")),
    };
    if !fed_state
        .rate_limiter
        .check_and_consume(&peer.name, principal_key.as_deref())
    {
        return Err(AppError::RateLimited("Rate limit exceeded".to_string()));
    }

    // 4. Validate to.ref: forwarding is forbidden
    let target_ref = &envelope.to.r#ref;
    if target_ref.contains('@') {
        return Err(AppError::NoForward(
            "Forwarding cross-host is not permitted".to_string(),
        ));
    }

    // 5. Validate principal and sanitize badge
    let (from_name, return_harness, return_session_id) = match &envelope.principal {
        FedPrincipal::Session {
            harness,
            session_id,
            name,
        } => {
            if !matches!(harness.as_str(), "claude" | "agy" | "pi" | "svc") {
                return Err(AppError::BadRequest(format!("invalid harness '{harness}'")));
            }
            let sanitized = inbox::sanitize_attested_from(&peer.name, harness, name);
            (sanitized, Some(harness.clone()), Some(session_id.clone()))
        }
        FedPrincipal::Service { name } => {
            let re = regex::Regex::new(r"^[A-Za-z0-9._-]{1,32}$").unwrap();
            if !re.is_match(name) {
                return Err(AppError::BadRequest(format!(
                    "invalid service name '{name}'"
                )));
            }
            let badge = format!("xmsg@{} · svc:{}", peer.name, name);
            (badge, Some("svc".to_string()), Some(name.clone()))
        }
        FedPrincipal::Anonymous { from } => {
            let sanitized = inbox::sanitize_from(&peer.name, from)?;
            (sanitized, None, None)
        }
    };

    // 6. Idempotent delivery: check if id already recorded
    let body_len = envelope.body.len();
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(existing) = storage::get_message(&db, &envelope.id)
            .map_err(|e| AppError::Internal(e.to_string()))?
        {
            // Already delivered or processed! Return stored outcome without writing to inbox again
            return Ok((
                StatusCode::ACCEPTED,
                Json(DeliveryResponse {
                    session_id: existing.session_id,
                    from_name: existing.from_name,
                    bytes: existing.bytes,
                    message_id: existing.id,
                }),
            )
                .into_response());
        }
    }

    // 7. Pre-record message as accepted before inbox write
    let pre_record = MessageRecord {
        id: envelope.id.clone(),
        created_at: envelope.created_at,
        session_id: target_ref.clone(),
        from_name: from_name.clone(),
        bytes: body_len,
        outcome: "accepted".to_string(),
        recipient_harness: "claude".to_string(),
        return_harness: return_harness.clone(),
        return_session_id: return_session_id.clone(),
        return_host: Some(peer.name.clone()),
        push_replies: envelope.push_replies,
        thread_id: envelope.thread_id.clone(),
    };
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::insert_message(&db, &pre_record).map_err(|e| AppError::Internal(e.to_string()))?;
    }

    // 8. Deliver to local target session
    let target = match resolve_target_session_fed(&fed_state, target_ref) {
        Ok(t) => t,
        Err(err) => {
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let _ = storage::update_message_outcome(&db, &envelope.id, "not_found");
            return Err(err);
        }
    };

    let deliver_res = match target {
        crate::http::ResolvedTarget::Claude(session, socket_path) => {
            let body_with_footer = format!(
                "{}\n\n[xmsg] message_id={} — reply with the xmsg reply tool",
                envelope.body, envelope.id
            );
            match inbox::encode_transport_line(&from_name, &body_with_footer) {
                Ok(line) => inbox::deliver_to_socket(&socket_path, &line)
                    .await
                    .map(|_| (session.session_id, "claude".to_string())),
                Err(e) => Err(e),
            }
        }
        crate::http::ResolvedTarget::Agy(session) => crate::agy::deliver_agy(
            &fed_state.agy_config,
            &fed_state.agy_store,
            &session,
            &from_name,
            &envelope.id,
            &envelope.body,
        )
        .await
        .map(|_| (session.session_id, "agy".to_string())),
        crate::http::ResolvedTarget::Pi(session) => {
            let envelope_text = format!(
                "[xmsg] from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                from_name, envelope.id, envelope.body
            );
            let pi_msg = storage::PiPendingMessage {
                id: envelope.id.clone(),
                session_id: session.session_id.clone(),
                created_at: storage::now_epoch_secs(),
                from_name: from_name.clone(),
                bytes: body_len,
                text: envelope.body.clone(),
                envelope: envelope_text,
                delivered_at: None,
            };
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            storage::insert_pi_message(&db, &pi_msg)
                .map_err(|e| AppError::Internal(e.to_string()))
                .map(|_| {
                    let _ = fed_state.pi_notify_tx.send(session.session_id.clone());
                    (session.session_id, "pi".to_string())
                })
        }
    };

    match deliver_res {
        Ok((target_session_id, _harness)) => Ok((
            StatusCode::ACCEPTED,
            Json(DeliveryResponse {
                session_id: target_session_id,
                from_name,
                bytes: body_len,
                message_id: envelope.id,
            }),
        )
            .into_response()),
        Err(err) => {
            let db = fed_state
                .db
                .lock()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let _ = storage::update_message_outcome(&db, &envelope.id, "delivery_failed");
            Err(err)
        }
    }
}

async fn fed_reply_handler(
    State(fed_state): State<Arc<FedState>>,
    Extension(peer): Extension<Arc<AuthenticatedPeer>>,
    Json(reply): Json<FedReplyEnvelope>,
) -> Result<Response, AppError> {
    if reply.v != 1 {
        return Err(AppError::BadRequest(format!(
            "unsupported protocol version {}",
            reply.v
        )));
    }

    // 1. Check peer config and allow list
    let peer_cfg = fed_state
        .peers
        .get(&peer.name)
        .ok_or_else(|| AppError::UnknownPeer(peer.name.clone()))?;

    if !peer_cfg.allow.iter().any(|op| op == "reply") {
        return Err(AppError::OpDenied(
            "reply operation not allowed for peer".to_string(),
        ));
    }

    // 2. WhoIs secondary check (if not no_whois)
    if !peer_cfg.no_whois {
        match fed_state
            .whois_verifier
            .verify_node(&peer.remote_ip, &peer.name)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(AppError::PeerRejected(
                    "WhoIs node identity mismatch".to_string(),
                ));
            }
            Err(e) => {
                return Err(AppError::PeerRejected(format!(
                    "WhoIs verification failed: {e}"
                )));
            }
        }
    }

    // 3. Authorization: in_reply_to MUST exist in outbound table AND peer must match!
    let outbound = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_outbound(&db, &reply.in_reply_to)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    let outbound = match outbound {
        Some(o) if o.peer == peer.name => o,
        _ => {
            return Err(AppError::NotRecipient(format!(
                "in_reply_to '{}' not authorized for peer '{}'",
                reply.in_reply_to, peer.name
            )));
        }
    };

    // 4. Look up original message to get caller session
    let orig_msg = {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::get_message(&db, &reply.in_reply_to)
            .map_err(|e| AppError::Internal(e.to_string()))?
    };

    let (ret_harness, ret_session_id) = match orig_msg {
        Some(m) if m.return_harness.is_some() && m.return_session_id.is_some() => {
            (m.return_harness.unwrap(), m.return_session_id.unwrap())
        }
        _ => (reply.replier.harness.clone(), outbound.target_ref.clone()),
    };

    // 5. Deliver pushed reply to local session
    let replier_badge =
        inbox::sanitize_attested_from(&peer.name, &reply.replier.harness, &reply.replier.name);
    let push_res = match ret_harness.as_str() {
        "claude" => {
            match crate::registry::resolve_session(&fed_state.sessions_dir, &ret_session_id) {
                Ok((_session, socket_path)) => {
                    if !socket_path.exists() {
                        "sender_gone"
                    } else {
                        let body_with_header = format!(
                            "[xmsg] reply to message_id={} — message_id={}; reply with the xmsg reply tool\n\n{}",
                            reply.in_reply_to, reply.id, reply.text
                        );
                        match inbox::encode_transport_line(&replier_badge, &body_with_header) {
                            Ok(line) => match inbox::deliver_to_socket(&socket_path, &line).await {
                                Ok(()) => "pushed",
                                Err(_) => "push_failed",
                            },
                            Err(_) => "push_failed",
                        }
                    }
                }
                Err(_) => "sender_gone",
            }
        }
        "agy" => {
            let session_opt = crate::agy::resolve_agy_session(
                &fed_state.agy_config,
                &fed_state.agy_store,
                &ret_session_id,
            )
            .ok()
            .flatten();
            if let Some(session) = session_opt {
                let envelope = format!(
                    "[xmsg] reply to message_id={} — message_id={}; reply with the xmsg reply tool\n\n{}",
                    reply.in_reply_to, reply.id, reply.text
                );
                match crate::agy::deliver_agy_envelope(
                    &fed_state.agy_config,
                    &fed_state.agy_store,
                    &session,
                    &replier_badge,
                    &envelope,
                )
                .await
                {
                    Ok(()) => "pushed",
                    Err(AppError::Gone { .. }) | Err(AppError::CredentialsStale(_)) => {
                        "sender_gone"
                    }
                    Err(_) => "push_failed",
                }
            } else {
                "sender_gone"
            }
        }
        "pi" => {
            let session_opt = crate::pi::resolve_pi_session(
                &fed_state.agy_config.proc_root,
                &fed_state.pi_store,
                &ret_session_id,
            )
            .ok()
            .flatten();
            if let Some(session) = session_opt {
                let envelope_text = format!(
                    "[xmsg] reply to message_id={} from={} message_id={} — reply with the xmsg reply tool\n\n{}",
                    reply.in_reply_to, replier_badge, reply.id, reply.text
                );
                let pi_msg = storage::PiPendingMessage {
                    id: reply.id.clone(),
                    session_id: session.session_id.clone(),
                    created_at: storage::now_epoch_secs(),
                    from_name: replier_badge.clone(),
                    bytes: reply.text.len(),
                    text: reply.text.clone(),
                    envelope: envelope_text,
                    delivered_at: None,
                };
                if let Ok(db) = fed_state.db.lock() {
                    let _ = storage::insert_pi_message(&db, &pi_msg);
                    let _ = fed_state.pi_notify_tx.send(session.session_id.clone());
                    "pushed"
                } else {
                    "push_failed"
                }
            } else {
                "sender_gone"
            }
        }
        _ => "pushed",
    };

    // 6. Record reply in replies table and notify subscribers
    {
        let db = fed_state
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        storage::insert_reply(
            &db,
            &reply.in_reply_to,
            &ret_session_id,
            &reply.text,
            Some(push_res),
            Some(&reply.id),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }
    let _ = fed_state.notify_tx.send(reply.in_reply_to.clone());

    Ok((
        StatusCode::OK,
        Json(json!({
            "push_outcome": push_res,
            "message_id": reply.id,
        })),
    )
        .into_response())
}

fn resolve_target_session_fed(
    fed_state: &FedState,
    ref_str: &str,
) -> Result<crate::http::ResolvedTarget, AppError> {
    match crate::registry::resolve_session(&fed_state.sessions_dir, ref_str) {
        Ok((session, socket_path)) => Ok(crate::http::ResolvedTarget::Claude(session, socket_path)),
        Err(AppError::Gone { session_id, pid }) => Err(AppError::Gone { session_id, pid }),
        Err(AppError::Ambiguous(ids)) => Err(AppError::Ambiguous(ids)),
        Err(AppError::NotFound(_)) => {
            match crate::agy::resolve_agy_session(
                &fed_state.agy_config,
                &fed_state.agy_store,
                ref_str,
            )? {
                Some(session) => Ok(crate::http::ResolvedTarget::Agy(session)),
                None => {
                    match crate::pi::resolve_pi_session(
                        &fed_state.agy_config.proc_root,
                        &fed_state.pi_store,
                        ref_str,
                    )? {
                        Some(session) => Ok(crate::http::ResolvedTarget::Pi(session)),
                        None => Err(AppError::NotFound(ref_str.to_string())),
                    }
                }
            }
        }
        Err(err) => Err(err),
    }
}

// -----------------------------------------------------------------------------
// Outbound Federated Client
// -----------------------------------------------------------------------------

pub fn make_tls_connector(
    cert_der: &[u8],
    key_der: &[u8],
    expected_pin: &str,
) -> Result<tokio_rustls::TlsConnector, AppError> {
    let verifier = Arc::new(PinnedServerCertVerifier::new(expected_pin));
    let client_cert = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der.to_vec(),
    ));

    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| AppError::Internal(format!("TLS config error: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(client_cert, key)
    .map_err(|e| AppError::Internal(format!("Client cert error: {e}")))?;

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

pub fn make_tls_acceptor(
    cert_der: &[u8],
    key_der: &[u8],
    allowed_pins: Arc<HashMap<String, String>>,
) -> Result<tokio_rustls::TlsAcceptor, AppError> {
    let verifier = Arc::new(PinnedClientCertVerifier::new(allowed_pins));
    let server_cert = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der.to_vec(),
    ));

    let server_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| AppError::Internal(format!("TLS server config error: {e}")))?
    .with_client_cert_verifier(verifier)
    .with_single_cert(server_cert, key)
    .map_err(|e| AppError::Internal(format!("Server cert error: {e}")))?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

pub async fn send_federated_message(
    fed_state: &FedState,
    peer_name: &str,
    envelope: &FedEnvelope,
) -> Result<DeliveryResponse, AppError> {
    let peer = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;

    if !peer.allow.iter().any(|op| op == "send") {
        return Err(AppError::OpDenied(
            "send operation not allowed for peer".to_string(),
        ));
    }

    let connector = make_tls_connector(&fed_state.cert_der, &fed_state.key_der, &peer.pin)?;
    let tcp_stream = tokio::net::TcpStream::connect(&peer.address)
        .await
        .map_err(|e| {
            AppError::PeerUnreachable(format!("Failed to connect to {}: {e}", peer.address))
        })?;

    let server_name = ServerName::try_from(peer_name.to_string())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| {
            AppError::PeerUnreachable(format!("TLS handshake failed with {peer_name}: {e}"))
        })?;

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| AppError::PeerUnreachable(format!("HTTP handshake failed: {e}")))?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("HTTP connection closed: {e}");
        }
    });

    let body_bytes = serde_json::to_vec(envelope).map_err(|e| AppError::Internal(e.to_string()))?;
    let req = hyper::Request::builder()
        .method("POST")
        .uri("/fed/v1/messages")
        .header("content-type", "application/json")
        .header("host", peer_name)
        .body(http_body_util::Full::new(bytes::Bytes::from(body_bytes)))
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| AppError::PeerUnreachable(format!("Request failed: {e}")))?;

    let status = resp.status();
    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .to_bytes();

    if status.is_success() {
        let delivery_resp: DeliveryResponse =
            serde_json::from_slice(&body_bytes).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(delivery_resp)
    } else {
        let err_resp: Result<WireErrorResponse, _> = serde_json::from_slice(&body_bytes);
        if let Ok(err) = err_resp {
            match status {
                StatusCode::FORBIDDEN => {
                    if err.error == "op_denied" {
                        Err(AppError::OpDenied(err.detail))
                    } else if err.error == "peer_rejected" {
                        Err(AppError::PeerRejected(err.detail))
                    } else {
                        Err(AppError::NotRecipient(err.detail))
                    }
                }
                StatusCode::BAD_REQUEST => {
                    if err.error == "no_forward" {
                        Err(AppError::NoForward(err.detail))
                    } else {
                        Err(AppError::BadRequest(err.detail))
                    }
                }
                StatusCode::TOO_MANY_REQUESTS => Err(AppError::RateLimited(err.detail)),
                _ => Err(AppError::ServiceUnavailable(err.detail)),
            }
        } else {
            Err(AppError::ServiceUnavailable(format!(
                "Remote returned status {status}"
            )))
        }
    }
}

pub async fn send_federated_reply(
    fed_state: &FedState,
    peer_name: &str,
    reply: &FedReplyEnvelope,
) -> Result<Value, AppError> {
    let peer = fed_state
        .peers
        .get(peer_name)
        .ok_or_else(|| AppError::UnknownPeer(peer_name.to_string()))?;

    if !peer.allow.iter().any(|op| op == "reply") {
        return Err(AppError::OpDenied(
            "reply operation not allowed for peer".to_string(),
        ));
    }

    let connector = make_tls_connector(&fed_state.cert_der, &fed_state.key_der, &peer.pin)?;
    let tcp_stream = tokio::net::TcpStream::connect(&peer.address)
        .await
        .map_err(|e| {
            AppError::PeerUnreachable(format!("Failed to connect to {}: {e}", peer.address))
        })?;

    let server_name = ServerName::try_from(peer_name.to_string())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| {
            AppError::PeerUnreachable(format!("TLS handshake failed with {peer_name}: {e}"))
        })?;

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| AppError::PeerUnreachable(format!("HTTP handshake failed: {e}")))?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("HTTP connection closed: {e}");
        }
    });

    let body_bytes = serde_json::to_vec(reply).map_err(|e| AppError::Internal(e.to_string()))?;
    let req = hyper::Request::builder()
        .method("POST")
        .uri("/fed/v1/replies")
        .header("content-type", "application/json")
        .header("host", peer_name)
        .body(http_body_util::Full::new(bytes::Bytes::from(body_bytes)))
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| AppError::PeerUnreachable(format!("Request failed: {e}")))?;

    let status = resp.status();
    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .to_bytes();

    if status.is_success() {
        let val: Value =
            serde_json::from_slice(&body_bytes).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(val)
    } else {
        let err_resp: Result<WireErrorResponse, _> = serde_json::from_slice(&body_bytes);
        if let Ok(err) = err_resp {
            match status {
                StatusCode::FORBIDDEN => Err(AppError::NotRecipient(err.detail)),
                _ => Err(AppError::ServiceUnavailable(err.detail)),
            }
        } else {
            Err(AppError::ServiceUnavailable(format!(
                "Remote returned status {status}"
            )))
        }
    }
}

// -----------------------------------------------------------------------------
// Test Identity Generation Helper
// -----------------------------------------------------------------------------

pub fn generate_self_signed_ed25519(host_name: &str) -> Result<(Vec<u8>, Vec<u8>, String), String> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| format!("Failed to generate keypair: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![host_name.to_string()])
        .map_err(|e| format!("Failed to create cert params: {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host_name);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to sign cert: {e}"))?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();
    let pin = spki_sha256_from_der(&cert_der)?;
    Ok((cert_der, key_der, pin))
}

// -----------------------------------------------------------------------------
// Run Federated Listener
// -----------------------------------------------------------------------------

pub async fn run_fed_listener(
    listener: tokio::net::TcpListener,
    fed_state: Arc<FedState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let allowed_pins = Arc::new(fed_state.peers.allowed_pins().clone());
    let acceptor = make_tls_acceptor(&fed_state.cert_der, &fed_state.key_der, allowed_pins)?;
    let router = build_fed_router(fed_state.clone());

    loop {
        let (tcp_stream, remote_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let fed_state = fed_state.clone();
        let router = router.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("TLS handshake failed from {remote_addr}: {e}");
                    return;
                }
            };

            let (_, server_conn) = tls_stream.get_ref();
            let certs = match server_conn.peer_certificates() {
                Some(c) if !c.is_empty() => c,
                _ => {
                    debug!("No peer certificate from {remote_addr}");
                    return;
                }
            };

            let client_pin = match spki_sha256_from_der(certs[0].as_ref()) {
                Ok(p) => p,
                Err(e) => {
                    debug!("Failed to calculate SPKI pin from client cert: {e}");
                    return;
                }
            };

            let peer_name = match fed_state.peers.get_by_pin(&client_pin) {
                Some(p) => p.name.clone(),
                None => {
                    debug!("Client pin not in peers list: {client_pin}");
                    return;
                }
            };

            let peer_info = Arc::new(AuthenticatedPeer {
                name: peer_name,
                pin: client_pin,
                remote_ip: remote_addr.ip(),
            });

            let router = router.clone();
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut router = router.clone();
                    let peer_info = peer_info.clone();
                    async move {
                        let mut req = req.map(axum::body::Body::new);
                        req.extensions_mut().insert(peer_info);
                        use tower::Service;
                        router.call(req).await
                    }
                });

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await
            {
                debug!("Error serving federated connection: {e}");
            }
        });
    }
}
