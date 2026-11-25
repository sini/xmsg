//! TLS 1.3 `xmsg-pair/1` ceremony transport, mutual SPKI+Ed25519 verifiers, and framing (§2, §5.1, §5.3).

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::Ed25519KeyPair;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::budgets::PairingError;
use super::codec::{
    build_signed_receipt, decode_frame, encode_frame, extract_ed25519_pubkey,
    parse_and_verify_receipt, validate_ceremony_times, CodecError, HelloI, Offer, Receipt,
    ReceiptVerificationContext, SignerRole, SpkiDeviceId, Transcript, MAX_CEREMONY_WINDOW_SECS,
    MAX_FRAME_BYTES,
};
use crate::fed::PeersMap;

/// ALPN protocol identifier for v1a manual pairing ceremonies.
pub const PAIRING_ALPN: &[u8] = b"xmsg-pair/1";

/// TLS 1.3 exporter label binding Transcript `T` key 12 to the handshake.
pub const PAIRING_EXPORTER_LABEL: &[u8] = b"EXPORTER-xmsg-pair-v1";

/// Extract raw DER SubjectPublicKeyInfo bytes from an X.509 certificate.
pub fn spki_der_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, CodecError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|_| CodecError::InvalidSpki("malformed X.509 certificate"))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// Extract canonical Ed25519 `SpkiDeviceId` from an X.509 certificate.
pub fn ed25519_device_id_from_cert(cert_der: &[u8]) -> Result<SpkiDeviceId, PairingError> {
    let spki = spki_der_from_cert(cert_der).map_err(|e| PairingError::KeyAlgorithm(e.to_string()))?;
    SpkiDeviceId::from_spki_der(&spki).map_err(|e| PairingError::KeyAlgorithm(e.to_string()))
}

fn check_pinned_ed25519_spki(
    end_entity: &CertificateDer<'_>,
    expected_peer: Option<[u8; 32]>,
    deny_peers: Option<&PeersMap>,
    key_alg_mismatch: &AtomicBool,
) -> Result<[u8; 32], rustls::Error> {
    if let Some(peers) = deny_peers {
        peers
            .check_certificate_deny(end_entity)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
    }
    let spki = spki_der_from_cert(end_entity.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let digest: [u8; 32] = Sha256::digest(&spki).into();
    if let Some(expected) = expected_peer {
        if digest != expected {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
    }
    if extract_ed25519_pubkey(&spki).is_err() {
        key_alg_mismatch.store(true, Ordering::SeqCst);
        return Err(rustls::Error::General("pairing.key_algorithm".into()));
    }
    Ok(digest)
}

#[derive(Debug)]
struct PairingServerCertVerifier {
    expected_peer: [u8; 32],
    deny_peers: Option<Arc<PeersMap>>,
    key_alg_mismatch: Arc<AtomicBool>,
}

impl rustls::client::danger::ServerCertVerifier for PairingServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        check_pinned_ed25519_spki(
            end_entity,
            Some(self.expected_peer),
            self.deny_peers.as_deref(),
            &self.key_alg_mismatch,
        )?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
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

/// Callback checked by the pairing server TLS verifier to confirm a live responder intent exists
/// for the presented SPKI digest.
pub type AllowedPeerCheck = Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>;

#[derive(Clone)]
struct PairingClientCertVerifier {
    allowed_peer: AllowedPeerCheck,
    deny_peers: Option<Arc<PeersMap>>,
    key_alg_mismatch: Arc<AtomicBool>,
}

impl std::fmt::Debug for PairingClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingClientCertVerifier").finish()
    }
}

impl rustls::server::danger::ClientCertVerifier for PairingClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let spki = spki_der_from_cert(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let digest: [u8; 32] = Sha256::digest(&spki).into();
        if !(self.allowed_peer)(&digest) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        check_pinned_ed25519_spki(
            end_entity,
            Some(digest),
            self.deny_peers.as_deref(),
            &self.key_alg_mismatch,
        )?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
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

/// Builds a TLS 1.3-only `ClientConfig` with ALPN `xmsg-pair/1`, `enable_sni = false`,
/// and mutual Ed25519 SPKI pinning.
pub fn build_pairing_client_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
    expected_peer: [u8; 32],
    deny_peers: Option<Arc<PeersMap>>,
) -> Result<(Arc<ClientConfig>, Arc<AtomicBool>), PairingError> {
    let key_alg_mismatch = Arc::new(AtomicBool::new(false));
    let verifier = Arc::new(PairingServerCertVerifier {
        expected_peer,
        deny_peers,
        key_alg_mismatch: key_alg_mismatch.clone(),
    });
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| PairingError::Internal(e.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(cert_chain, key_der)
    .map_err(|e| PairingError::Internal(e.to_string()))?;
    cfg.alpn_protocols = vec![PAIRING_ALPN.to_vec()];
    cfg.enable_sni = false;
    Ok((Arc::new(cfg), key_alg_mismatch))
}

/// Builds a TLS 1.3-only `ServerConfig` with ALPN `xmsg-pair/1` and mutual Ed25519 SPKI pinning.
pub fn build_pairing_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
    allowed_peer: AllowedPeerCheck,
    deny_peers: Option<Arc<PeersMap>>,
) -> Result<(Arc<ServerConfig>, Arc<AtomicBool>), PairingError> {
    let key_alg_mismatch = Arc::new(AtomicBool::new(false));
    let verifier = Arc::new(PairingClientCertVerifier {
        allowed_peer,
        deny_peers,
        key_alg_mismatch: key_alg_mismatch.clone(),
    });
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| PairingError::Internal(e.to_string()))?
    .with_client_cert_verifier(verifier)
    .with_single_cert(cert_chain, key_der)
    .map_err(|e| PairingError::Internal(e.to_string()))?;
    cfg.alpn_protocols = vec![PAIRING_ALPN.to_vec()];
    Ok((Arc::new(cfg), key_alg_mismatch))
}

/// Exports the 32-byte TLS 1.3 keying material binding `T` key 12.
pub fn export_pairing_keying_material(
    conn: &rustls::ConnectionCommon<impl rustls::SideData>,
) -> Result<[u8; 32], PairingError> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, PAIRING_EXPORTER_LABEL, None)
        .map_err(|e| PairingError::Internal(format!("export_keying_material: {e}")))?;
    Ok(out)
}

/// Writes a single u32-length-prefixed pairing CBOR frame (<= 8192 bytes).
pub async fn write_pairing_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), PairingError> {
    let frame = encode_frame(payload).map_err(|e| match e {
        CodecError::FrameTooLarge => PairingError::FrameTooLarge(e.to_string()),
        other => PairingError::Internal(other.to_string()),
    })?;
    writer
        .write_all(&frame)
        .await
        .map_err(|e| PairingError::PeerRefused(format!("write frame failed: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| PairingError::PeerRefused(format!("flush frame failed: {e}")))?;
    Ok(())
}

/// Reads a single u32-length-prefixed pairing CBOR frame, closing on > 8192 bytes (`Q2-2`).
pub async fn read_pairing_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, PairingError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| PairingError::PeerRefused(format!("read frame length failed: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(PairingError::FrameTooLarge(format!(
            "frame length {len} exceeds {MAX_FRAME_BYTES} bytes"
        )));
    }
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&len_buf);
    buf.resize(4 + len, 0);
    reader
        .read_exact(&mut buf[4..])
        .await
        .map_err(|e| PairingError::PeerRefused(format!("read frame payload failed: {e}")))?;
    let body = decode_frame(&buf).map_err(|e| match e {
        CodecError::FrameTooLarge => PairingError::FrameTooLarge(e.to_string()),
        other => PairingError::PeerRefused(other.to_string()),
    })?;
    Ok(body.to_vec())
}

/// Tracks active live ceremonies (max 1 per intent ID, acquired only after mutual auth, `Q2-5e`).
#[derive(Clone, Default, Debug)]
pub struct LiveCeremonySlots {
    active: Arc<Mutex<HashSet<[u8; 16]>>>,
}

impl LiveCeremonySlots {
    pub fn try_acquire(&self, intent_id: [u8; 16]) -> Option<LiveCeremonyGuard> {
        let mut guard = self.active.lock().unwrap();
        if guard.insert(intent_id) {
            Some(LiveCeremonyGuard {
                active: self.active.clone(),
                intent_id,
            })
        } else {
            None
        }
    }
}

pub struct LiveCeremonyGuard {
    active: Arc<Mutex<HashSet<[u8; 16]>>>,
    intent_id: [u8; 16],
}

impl Drop for LiveCeremonyGuard {
    fn drop(&mut self) {
        self.active.lock().unwrap().remove(&self.intent_id);
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    SystemRandom::new()
        .fill(&mut buf)
        .expect("system RNG unavailable");
    buf
}

pub fn unix_now_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_secs() as u32
}

/// Inputs for the initiator side of a live `xmsg-pair/1` ceremony.
pub struct InitiatorInputs<'a> {
    pub own_id: [u8; 32],
    pub peer_id: [u8; 32],
    pub own_spki: &'a [u8],
    pub peer_spki: &'a [u8],
    pub offer_i: Offer,
    pub policy_i: u32,
    pub intent_id: [u8; 16],
    pub grant_id: [u8; 16],
    pub signing_key: &'a Ed25519KeyPair,
    pub exporter: [u8; 32],
    pub deadline: tokio::time::Instant,
    pub start_mono_secs: u64,
    pub now_utc: u32,
}

/// Inputs for the responder side of a live `xmsg-pair/1` ceremony.
pub struct ResponderInputs<'a> {
    pub own_id: [u8; 32],
    pub peer_id: [u8; 32],
    pub own_spki: &'a [u8],
    pub peer_spki: &'a [u8],
    pub offer_r: Offer,
    pub policy_r: u32,
    pub intent_id: [u8; 16],
    pub grant_id: [u8; 16],
    pub signing_key: &'a Ed25519KeyPair,
    pub exporter: [u8; 32],
    pub deadline: tokio::time::Instant,
    pub start_mono_secs: u64,
    pub now_utc: u32,
}

/// Outputs produced by a completed ceremony.
pub struct CeremonyArtifacts {
    pub transcript: Transcript,
    pub receipt_i: Vec<u8>,
    pub receipt_r: Vec<u8>,
}

fn remaining_before(deadline: tokio::time::Instant) -> Result<Duration, PairingError> {
    let d = deadline.saturating_duration_since(tokio::time::Instant::now());
    if d.is_zero() {
        Err(PairingError::Expired("ceremony monotonic deadline reached".into()))
    } else {
        Ok(d)
    }
}

fn verify_receipt_pair(
    t: &Transcript,
    exporter: [u8; 32],
    spki_i: &[u8],
    spki_r: &[u8],
    now_utc: u32,
    receipt_i: &[u8],
    receipt_r: &[u8],
) -> Result<(), PairingError> {
    let txn_id = t
        .transaction_id()
        .map_err(|e| PairingError::Internal(e.to_string()))?;
    let ctx = ReceiptVerificationContext {
        id_i: t.id_i,
        id_r: t.id_r,
        spki_i,
        spki_r,
        offer_i: t.offer_i.clone(),
        offer_r: t.offer_r.clone(),
        created_utc: t.created_utc,
        ceremony_expires_utc: t.ceremony_expires_utc,
        exporter,
        transaction_id: txn_id,
        now_utc,
        current_policy_i: t.policy_i,
        current_policy_r: t.policy_r,
        blocked: false,
        revoked: false,
        bilateral: true,
    };
    let parsed_i = parse_and_verify_receipt(receipt_i, &ctx)
        .map_err(|e| PairingError::PeerRefused(format!("invalid ReceiptI: {e}")))?;
    if parsed_i.signer_role != SignerRole::Initiator {
        return Err(PairingError::PeerRefused("ReceiptI has wrong signer role".into()));
    }
    let parsed_r = parse_and_verify_receipt(receipt_r, &ctx)
        .map_err(|e| PairingError::PeerRefused(format!("invalid ReceiptR: {e}")))?;
    if parsed_r.signer_role != SignerRole::Responder {
        return Err(PairingError::PeerRefused("ReceiptR has wrong signer role".into()));
    }
    Ok(())
}

/// Runs the initiator exchange over an already-authenticated TLS 1.3 `xmsg-pair/1` stream.
/// `reserve_capacity_cb` is invoked after `T` validates and before signing `ReceiptI` (§5.3).
pub async fn execute_initiator_exchange<S, F>(
    stream: &mut S,
    inputs: InitiatorInputs<'_>,
    mut reserve_capacity_cb: F,
) -> Result<CeremonyArtifacts, PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut([u8; 16], i64) -> Result<(), PairingError>,
{
    let nonce_i: [u8; 32] = random_bytes();
    let attempt_i: [u8; 16] = random_bytes();
    let created_utc = inputs.now_utc;
    let ceremony_expires_utc = created_utc.saturating_add(MAX_CEREMONY_WINDOW_SECS);
    let hello = HelloI {
        id_i: inputs.own_id,
        id_r: inputs.peer_id,
        nonce_i,
        attempt_i,
        offer_i: inputs.offer_i.clone(),
        created_utc,
        ceremony_expires_utc,
        policy_i: inputs.policy_i,
    };
    let hello_cbor = hello
        .encode_cbor()
        .map_err(|e| PairingError::Internal(e.to_string()))?;

    tokio::time::timeout(
        remaining_before(inputs.deadline)?,
        write_pairing_frame(stream, &hello_cbor),
    )
    .await
    .map_err(|_| PairingError::Expired("ceremony monotonic deadline reached".into()))??;

    let t_bytes = tokio::time::timeout(
        remaining_before(inputs.deadline)?,
        read_pairing_frame(stream),
    )
    .await
    .map_err(|_| PairingError::Expired("ceremony monotonic deadline reached".into()))??;
    let t = Transcript::decode_cbor(&t_bytes)
        .map_err(|e| PairingError::PeerRefused(format!("invalid transcript T: {e}")))?;

    if t.id_i != inputs.own_id
        || t.id_r != inputs.peer_id
        || t.nonce_i != nonce_i
        || t.attempt_i != attempt_i
        || t.offer_i != inputs.offer_i
        || t.policy_i != inputs.policy_i
        || t.created_utc != created_utc
        || t.ceremony_expires_utc != ceremony_expires_utc
    {
        return Err(PairingError::PeerRefused(
            "transcript T did not echo HelloI fields".into(),
        ));
    }
    if t.exporter != inputs.exporter {
        return Err(PairingError::PeerRefused(
            "transcript T key 12 exporter mismatch".into(),
        ));
    }
    let mono_now = inputs.start_mono_secs.saturating_add(
        MAX_CEREMONY_WINDOW_SECS as u64 - remaining_before(inputs.deadline)?.as_secs().min(MAX_CEREMONY_WINDOW_SECS as u64),
    );
    let intent_deadline_mono = inputs.start_mono_secs.saturating_add(MAX_CEREMONY_WINDOW_SECS as u64);
    validate_ceremony_times(
        created_utc,
        ceremony_expires_utc,
        t.created_utc,
        t.ceremony_expires_utc,
        intent_deadline_mono,
        inputs.start_mono_secs,
        created_utc,
        mono_now,
        inputs.now_utc,
    )
    .map_err(|e| PairingError::Clock(format!("ceremony time validation failed: {e}")))?;

    // §5.3: reserve_capacity runs after T validates and BEFORE signing ReceiptI.
    reserve_capacity_cb(inputs.intent_id, i64::from(inputs.now_utc))?;

    let txn_id = t
        .transaction_id()
        .map_err(|e| PairingError::Internal(e.to_string()))?;
    let receipt_i_body = Receipt {
        transaction_id: txn_id,
        signer_role: SignerRole::Initiator,
        signer_id: inputs.own_id,
        subject_id: inputs.peer_id,
        profile: inputs.offer_i.profile,
        grant_not_after: inputs.offer_i.grant_not_after,
        exposure_policy_sha256: inputs.offer_i.exposure_policy_sha256,
        grant_id: inputs.grant_id,
        issued_utc: inputs.now_utc,
        ceremony_expires_utc: t.ceremony_expires_utc,
        provenance: "manual_authenticated_oob".to_owned(),
        policy_revision: inputs.policy_i,
    };
    let receipt_i = build_signed_receipt(&receipt_i_body, &inputs.exporter, inputs.signing_key)
        .map_err(|e| PairingError::Internal(e.to_string()))?;
    tokio::time::timeout(
        remaining_before(inputs.deadline)?,
        write_pairing_frame(stream, &receipt_i),
    )
    .await
    .map_err(|_| PairingError::Expired("ceremony monotonic deadline reached".into()))??;

    let receipt_r = tokio::time::timeout(
        remaining_before(inputs.deadline)?,
        read_pairing_frame(stream),
    )
    .await
    .map_err(|_| PairingError::Expired("ceremony monotonic deadline reached".into()))??;

    verify_receipt_pair(
        &t,
        inputs.exporter,
        inputs.own_spki,
        inputs.peer_spki,
        inputs.now_utc,
        &receipt_i,
        &receipt_r,
    )?;

    Ok(CeremonyArtifacts {
        transcript: t,
        receipt_i,
        receipt_r,
    })
}

/// Runs the responder exchange over an already-authenticated TLS 1.3 `xmsg-pair/1` stream.
/// `reserve_capacity_cb` runs after `ReceiptI` verifies and BEFORE signing `ReceiptR` (§5.3).
/// `activate_cb` commits the responder grant BEFORE `ReceiptR` is written to the wire.
pub async fn execute_responder_exchange<S, FCap, FAct>(
    stream: &mut S,
    inputs: ResponderInputs<'_>,
    mut reserve_capacity_cb: FCap,
    mut activate_cb: FAct,
) -> Result<CeremonyArtifacts, PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    FCap: FnMut([u8; 16], i64) -> Result<(), PairingError>,
    FAct: FnMut(&CeremonyArtifacts) -> Result<(), PairingError>,
{
    let hello_bytes = tokio::time::timeout(
        remaining_before(inputs.deadline)?,
        read_pairing_frame(stream),
    )
    .await
    .map_err(|_| PairingError::Expired("ceremony monotonic deadline reached".into()))??;
    let hello = HelloI::decode_cbor(&hello_bytes)
        .map_err(|e| PairingError::PeerRefused(format!("invalid HelloI: {e}")))?;

    if hello.id_i != inputs.peer_id || hello.id_r != inputs.own_id {
        return Err(PairingError::PeerRefused("HelloI device IDs mismatch".into()));
    }
    let intent_deadline_mono = inputs.start_mono_secs.saturating_add(MAX_CEREMONY_WINDOW_SECS as u64);
    validate_ceremony_times(
        hello.created_utc,
        hello.ceremony_expires_utc,
        hello.created_utc,
        hello.ceremony_expires_utc,
        intent_deadline_mono,
        inputs.start_mono_secs,
        inputs.now_utc,
        inputs.start_mono_secs,
        inputs.now_utc,
    )
    .map_err(|e| PairingError::Clock(format!("ceremony time validation failed: {e}")))?;

    let t = Transcript {
        id_i: hello.id_i,
        id_r: hello.id_r,
        nonce_i: hello.nonce_i,
        nonce_r: random_bytes(),
        offer_i: hello.offer_i,
        offer_r: inputs.offer_r,
        created_utc: hello.created_utc,
        ceremony_expires_utc: hello.ceremony_expires_utc,
        policy_i: hello.policy_i,
        policy_r: inputs.policy_r,
        exporter: inputs.exporter,
        attempt_i: hello.attempt_i,
        attempt_r: random_bytes(),
    };
    let t_cbor = t
        .encode_cbor()
        .map_err(|e| PairingError::Internal(e.to_string()))?;
    tokio::time::timeout(
        remaining_before(inputs.deadline)?,
        write_pairing_frame(stream, &t_cbor),
    )
    .await
    .map_err(|_| PairingError::Expired("ceremony monotonic deadline reached".into()))??;

    let receipt_i = tokio::time::timeout(
        remaining_before(inputs.deadline)?,
        read_pairing_frame(stream),
    )
    .await
    .map_err(|_| PairingError::Expired("ceremony monotonic deadline reached".into()))??;

    let txn_id = t
        .transaction_id()
        .map_err(|e| PairingError::Internal(e.to_string()))?;
    let ctx = ReceiptVerificationContext {
        id_i: t.id_i,
        id_r: t.id_r,
        spki_i: inputs.peer_spki,
        spki_r: inputs.own_spki,
        offer_i: t.offer_i.clone(),
        offer_r: t.offer_r.clone(),
        created_utc: t.created_utc,
        ceremony_expires_utc: t.ceremony_expires_utc,
        exporter: inputs.exporter,
        transaction_id: txn_id,
        now_utc: inputs.now_utc,
        current_policy_i: t.policy_i,
        current_policy_r: t.policy_r,
        blocked: false,
        revoked: false,
        bilateral: true,
    };
    let parsed_i = parse_and_verify_receipt(&receipt_i, &ctx)
        .map_err(|e| PairingError::PeerRefused(format!("invalid ReceiptI: {e}")))?;
    if parsed_i.signer_role != SignerRole::Initiator {
        return Err(PairingError::PeerRefused("ReceiptI has wrong signer role".into()));
    }

    // §5.3: reserve_capacity runs after T/ReceiptI validate and BEFORE signing ReceiptR.
    reserve_capacity_cb(inputs.intent_id, i64::from(inputs.now_utc))?;

    let receipt_r_body = Receipt {
        transaction_id: txn_id,
        signer_role: SignerRole::Responder,
        signer_id: inputs.own_id,
        subject_id: inputs.peer_id,
        profile: inputs.offer_r.profile,
        grant_not_after: inputs.offer_r.grant_not_after,
        exposure_policy_sha256: inputs.offer_r.exposure_policy_sha256,
        grant_id: inputs.grant_id,
        issued_utc: inputs.now_utc,
        ceremony_expires_utc: t.ceremony_expires_utc,
        provenance: "manual_authenticated_oob".to_owned(),
        policy_revision: inputs.policy_r,
    };
    let receipt_r = build_signed_receipt(&receipt_r_body, &inputs.exporter, inputs.signing_key)
        .map_err(|e| PairingError::Internal(e.to_string()))?;
    let artifacts = CeremonyArtifacts {
        transcript: t,
        receipt_i,
        receipt_r: receipt_r.clone(),
    };
    // Commit responder activation before sending ReceiptR (Q2-8: removed/cancelled intent refuses here).
    activate_cb(&artifacts)?;

    tokio::time::timeout(
        remaining_before(inputs.deadline)?,
        write_pairing_frame(stream, &receipt_r),
    )
    .await
    .map_err(|_| PairingError::Expired("ceremony monotonic deadline reached".into()))??;

    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::codec::{ExposurePolicy, PairingProfile};
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ED25519};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn gen_ed25519_cert() -> (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        Ed25519KeyPair,
        [u8; 32],
        Vec<u8>,
    ) {
        let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec!["xmsg-pair.local".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let pkcs8 = kp.serialize_der();
        let ring_kp = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let cert_der = cert.der().clone();
        let spki = spki_der_from_cert(cert_der.as_ref()).unwrap();
        let id = SpkiDeviceId::from_spki_der(&spki).unwrap().0;
        let key_der = PrivateKeyDer::try_from(pkcs8).unwrap();
        (vec![cert_der], key_der, ring_kp, id, spki)
    }

    #[tokio::test]
    async fn frame_over_8192_bytes_is_rejected_as_frame_too_large() {
        let (mut writer, mut reader) = tokio::io::duplex(16384);
        let len_prefix = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
        writer.write_all(&len_prefix).await.unwrap();
        drop(writer);
        let err = read_pairing_frame(&mut reader).await.unwrap_err();
        assert_eq!(err.code(), "pairing.frame_too_large");
    }

    #[tokio::test]
    async fn tls13_pairing_exchange_binds_exporter_and_verifies_both_receipts() {
        let (cert_i, key_i, ring_i, id_i, spki_i) = gen_ed25519_cert();
        let (cert_r, key_r, ring_r, id_r, spki_r) = gen_ed25519_cert();

        let (client_cfg, _) = build_pairing_client_config(cert_i, key_i, id_r, None).unwrap();
        let (server_cfg, _) = build_pairing_server_config(
            cert_r,
            key_r,
            Arc::new(move |id| *id == id_i),
            None,
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(32768);
        let connector = TlsConnector::from(client_cfg);
        let acceptor = TlsAcceptor::from(server_cfg);
        let dns = ServerName::try_from("xmsg-pair.local").unwrap();

        let now_utc = unix_now_u32();
        let exp_i = ExposurePolicy {
            profile: PairingProfile::Contact,
            target_selectors: vec!["svc-a".to_owned()],
            principal_selectors: vec!["*".to_owned()],
            max_body_bytes: 65536,
            max_attachment_bytes: 65536,
            rate_burst: 10,
            rate_per_minute: 60,
        };
        let exp_r = ExposurePolicy {
            profile: PairingProfile::OwnerDevice,
            target_selectors: vec!["*".to_owned()],
            principal_selectors: vec!["*".to_owned()],
            max_body_bytes: 65536,
            max_attachment_bytes: 65536,
            rate_burst: 10,
            rate_per_minute: 60,
        };
        let offer_i = Offer {
            profile: PairingProfile::Contact,
            grant_not_after: None,
            exposure_policy_sha256: exp_i.sha256().unwrap(),
        };
        let offer_r = Offer {
            profile: PairingProfile::OwnerDevice,
            grant_not_after: None,
            exposure_policy_sha256: exp_r.sha256().unwrap(),
        };

        let srv_fut = async {
            let mut tls = acceptor.accept(server_io).await.unwrap();
            let exporter = export_pairing_keying_material(tls.get_ref().1).unwrap();
            let inputs = ResponderInputs {
                own_id: id_r,
                peer_id: id_i,
                own_spki: &spki_r,
                peer_spki: &spki_i,
                offer_r,
                policy_r: 1,
                intent_id: [1u8; 16],
                grant_id: [2u8; 16],
                signing_key: &ring_r,
                exporter,
                deadline: tokio::time::Instant::now() + Duration::from_secs(10),
                start_mono_secs: 100,
                now_utc,
            };
            execute_responder_exchange(&mut tls, inputs, |_, _| Ok(()), |_| Ok(()))
                .await
                .unwrap()
        };

        let cli_fut = async {
            let mut tls = connector.connect(dns, client_io).await.unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(PAIRING_ALPN));
            let exporter = export_pairing_keying_material(tls.get_ref().1).unwrap();
            let inputs = InitiatorInputs {
                own_id: id_i,
                peer_id: id_r,
                own_spki: &spki_i,
                peer_spki: &spki_r,
                offer_i,
                policy_i: 1,
                intent_id: [3u8; 16],
                grant_id: [4u8; 16],
                signing_key: &ring_i,
                exporter,
                deadline: tokio::time::Instant::now() + Duration::from_secs(10),
                start_mono_secs: 100,
                now_utc,
            };
            execute_initiator_exchange(&mut tls, inputs, |_, _| Ok(()))
                .await
                .unwrap()
        };

        let (art_r, art_i) = tokio::join!(srv_fut, cli_fut);
        assert_eq!(art_r.transcript.exporter, art_i.transcript.exporter);
        assert_eq!(art_r.receipt_i, art_i.receipt_i);
        assert_eq!(art_r.receipt_r, art_i.receipt_r);
    }

    #[tokio::test]
    async fn p256_peer_matching_pinned_hash_is_refused_with_key_algorithm() {
        let kp_p256 = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec!["xmsg-pair.local".to_string()]).unwrap();
        let cert_p256 = params.self_signed(&kp_p256).unwrap();
        let spki_p256 = spki_der_from_cert(cert_p256.der().as_ref()).unwrap();
        let p256_hash: [u8; 32] = Sha256::digest(&spki_p256).into();

        let (cert_i, key_i, _, _, _) = gen_ed25519_cert();
        let (client_cfg, key_alg_flag) =
            build_pairing_client_config(cert_i, key_i, p256_hash, None).unwrap();

        let mut server_cfg = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_p256.der().clone()],
            PrivateKeyDer::try_from(kp_p256.serialize_der()).unwrap(),
        )
        .unwrap();
        server_cfg.alpn_protocols = vec![PAIRING_ALPN.to_vec()];

        let (client_io, server_io) = tokio::io::duplex(16384);
        let connector = TlsConnector::from(client_cfg);
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let dns = ServerName::try_from("xmsg-pair.local").unwrap();

        let srv = tokio::spawn(async move {
            let _ = acceptor.accept(server_io).await;
        });
        let res = connector.connect(dns, client_io).await;
        let _ = srv.await;
        assert!(res.is_err());
        assert!(key_alg_flag.load(Ordering::SeqCst));
    }
}
