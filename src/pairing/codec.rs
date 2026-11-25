use std::collections::BTreeSet;
use std::io::Cursor;

use ciborium::value::Value;
use coset::{iana, CoseSign1, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use data_encoding::{Encoding, Specification};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Maximum CBOR frame size permitted by the pairing wire protocol (bytes).
pub const MAX_FRAME_BYTES: usize = 8192;

/// Maximum ceremony lifetime in seconds.
pub const MAX_CEREMONY_WINDOW_SECS: u32 = 120;

/// Prefix for canonical Ed25519 SPKI device identifiers.
pub const SPKI_ID_PREFIX: &str = "xmsg-spki1:";

/// Canonical DER prefix for an Ed25519 SubjectPublicKeyInfo (RFC 8410, absent parameters).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, // SEQUENCE (42 bytes)
    0x30, 0x05, // SEQUENCE (5 bytes)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (id-Ed25519), absent params
    0x03, 0x21, 0x00, // BIT STRING (33 bytes, 0 unused bits)
];

const ED25519_SPKI_LEN: usize = 44;
const COSE_ALG_ED25519: i64 = -19;

const PROFILE_CONTACT: &str = "contact";
const PROFILE_OWNER_DEVICE: &str = "owner-device";

const KIND_EXPOSURE: &str = "xmsg-exposure-v1";
const KIND_OFFER: &str = "xmsg-pair-offer-v1";
const KIND_TRANSCRIPT: &str = "xmsg-pair/1";
const KIND_TXN_LABEL: &str = "xmsg-pair-txn-v1";
const KIND_RECEIPT: &str = "xmsg-pair-receipt-v1";
const PROVENANCE_MANUAL_OOB: &str = "manual_authenticated_oob";
const DIRECTION_INGRESS: &str = "ingress";

/// Errors produced by pairing wire encoding, decoding, and verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("frame exceeds maximum size of {MAX_FRAME_BYTES} bytes")]
    FrameTooLarge,
    #[error("truncated frame")]
    TruncatedFrame,
    #[error("invalid SPKI encoding: {0}")]
    InvalidSpki(&'static str),
    #[error("invalid device ID: {0}")]
    InvalidDeviceId(&'static str),
    #[error("invalid CBOR: {0}")]
    InvalidCbor(&'static str),
    #[error("non-canonical CBOR")]
    NonCanonicalCbor,
    #[error("invalid exposure policy: {0}")]
    InvalidExposure(&'static str),
    #[error("invalid pairing message: {0}")]
    InvalidMessage(&'static str),
    #[error("invalid COSE_Sign1 structure: {0}")]
    InvalidCose(&'static str),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("unknown protected signer")]
    UnknownSigner,
    #[error("receipt verification failed: {0}")]
    VerificationFailed(&'static str),
}

fn base32_lower_nopad() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    spec.encoding().expect("valid lowercase base32 spec")
}

/// A 32-byte SHA-256 digest of a canonical Ed25519 DER SubjectPublicKeyInfo.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpkiDeviceId(pub [u8; 32]);

impl SpkiDeviceId {
    /// Computes the device ID from a canonical Ed25519 DER SPKI.
    pub fn from_spki_der(spki_der: &[u8]) -> Result<Self, CodecError> {
        extract_ed25519_pubkey(spki_der)?;
        let digest: [u8; 32] = Sha256::digest(spki_der).into();
        Ok(Self(digest))
    }

    /// Formats as `xmsg-spki1:<52 lowercase unpadded base32 chars>`.
    pub fn to_device_id_string(self) -> String {
        let encoded = base32_lower_nopad().encode(&self.0);
        format!("{SPKI_ID_PREFIX}{encoded}")
    }

    /// Parses and validates a canonical `xmsg-spki1:...` device ID string.
    pub fn parse_device_id_string(s: &str) -> Result<Self, CodecError> {
        let rest = s
            .strip_prefix(SPKI_ID_PREFIX)
            .ok_or(CodecError::InvalidDeviceId("missing xmsg-spki1: prefix"))?;
        if rest.len() != 52 {
            return Err(CodecError::InvalidDeviceId("expected 52 base32 chars"));
        }
        if !rest.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
            return Err(CodecError::InvalidDeviceId(
                "expected lowercase unpadded RFC4648 base32",
            ));
        }
        let enc = base32_lower_nopad();
        let decoded = enc
            .decode(rest.as_bytes())
            .map_err(|_| CodecError::InvalidDeviceId("invalid base32"))?;
        let arr: [u8; 32] = decoded
            .try_into()
            .map_err(|_| CodecError::InvalidDeviceId("unexpected digest length"))?;
        // Reject non-canonical trailing padding bits in the final base32 symbol.
        if enc.encode(&arr) != rest {
            return Err(CodecError::InvalidDeviceId("non-canonical base32 bits"));
        }
        Ok(Self(arr))
    }

    /// Constant-time 256-bit comparison.
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

/// Validates a canonical 44-byte Ed25519 DER SPKI and returns the 32-byte public key.
pub fn extract_ed25519_pubkey(spki_der: &[u8]) -> Result<[u8; 32], CodecError> {
    if spki_der.len() != ED25519_SPKI_LEN {
        return Err(CodecError::InvalidSpki(
            "expected 44-byte canonical Ed25519 SPKI",
        ));
    }
    if spki_der[..12] != ED25519_SPKI_PREFIX {
        return Err(CodecError::InvalidSpki(
            "expected Ed25519 OID 1.3.101.112 with absent parameters",
        ));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&spki_der[12..]);
    Ok(pubkey)
}

/// Pairing directional profile in protocol v1a.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingProfile {
    Contact,
    OwnerDevice,
}

impl PairingProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contact => PROFILE_CONTACT,
            Self::OwnerDevice => PROFILE_OWNER_DEVICE,
        }
    }

    pub fn parse(s: &str) -> Result<Self, CodecError> {
        match s {
            PROFILE_CONTACT => Ok(Self::Contact),
            PROFILE_OWNER_DEVICE => Ok(Self::OwnerDevice),
            _ => Err(CodecError::InvalidMessage("unknown pairing profile")),
        }
    }
}

/// Encodes a single CBOR payload into a length-prefixed wire frame (`u32` BE + CBOR).
pub fn encode_frame(cbor: &[u8]) -> Result<Vec<u8>, CodecError> {
    if cbor.len() > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge);
    }
    let len = u32::try_from(cbor.len()).map_err(|_| CodecError::FrameTooLarge)?;
    let mut out = Vec::with_capacity(4 + cbor.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(cbor);
    Ok(out)
}

/// Decodes a single length-prefixed wire frame (`u32` BE + CBOR), rejecting trailing bytes
/// and frames exceeding `MAX_FRAME_BYTES`.
pub fn decode_frame(frame: &[u8]) -> Result<&[u8], CodecError> {
    if frame.len() < 4 {
        return Err(CodecError::TruncatedFrame);
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge);
    }
    if frame.len() != 4 + len {
        return Err(CodecError::TruncatedFrame);
    }
    Ok(&frame[4..])
}

/// Encodes a `ciborium::Value` using RFC 8949 §4.2.1 core deterministic encoding.
///
/// Map keys must be integers with no duplicates, and maps are sorted by their
/// encoded key bytes. Floats and tags are rejected.
pub fn encode_deterministic_cbor(value: &Value) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    write_deterministic_value(value, &mut out)?;
    if out.len() > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge);
    }
    Ok(out)
}

/// Decodes a `ciborium::Value` and verifies it is RFC 8949 §4.2.1 deterministic CBOR
/// with no trailing bytes, no floats, no tags, no duplicate keys, and <= `MAX_FRAME_BYTES`.
pub fn decode_deterministic_cbor(bytes: &[u8]) -> Result<Value, CodecError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| CodecError::InvalidCbor("malformed"))?;
    if cursor.position() as usize != bytes.len() {
        return Err(CodecError::InvalidCbor("trailing bytes"));
    }
    // Re-encoding validates no floats/tags/non-integer keys/duplicate keys and
    // enforces shortest integer/length representations and canonical key order.
    let canonical = encode_deterministic_cbor(&value)?;
    if canonical.as_slice() != bytes {
        return Err(CodecError::NonCanonicalCbor);
    }
    Ok(value)
}

fn write_deterministic_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CodecError> {
    match value {
        Value::Null => {
            out.push(0xf6);
            Ok(())
        }
        Value::Bool(false) => {
            out.push(0xf4);
            Ok(())
        }
        Value::Bool(true) => {
            out.push(0xf5);
            Ok(())
        }
        Value::Integer(int) => {
            let n: i128 = (*int).into();
            if n >= 0 {
                let u =
                    u64::try_from(n).map_err(|_| CodecError::InvalidCbor("integer overflow"))?;
                write_cbor_head(0, u, out);
            } else {
                let abs_m1 = u64::try_from(-1 - n)
                    .map_err(|_| CodecError::InvalidCbor("integer underflow"))?;
                write_cbor_head(1, abs_m1, out);
            }
            Ok(())
        }
        Value::Bytes(bytes) => {
            write_cbor_head(2, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
            Ok(())
        }
        Value::Text(text) => {
            let b = text.as_bytes();
            write_cbor_head(3, b.len() as u64, out);
            out.extend_from_slice(b);
            Ok(())
        }
        Value::Array(items) => {
            write_cbor_head(4, items.len() as u64, out);
            for item in items {
                write_deterministic_value(item, out)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            let mut encoded_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            let mut seen_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
            for (k, v) in entries {
                let Value::Integer(_) = k else {
                    return Err(CodecError::InvalidCbor("non-integer map key"));
                };
                let mut k_bytes = Vec::new();
                write_deterministic_value(k, &mut k_bytes)?;
                if !seen_keys.insert(k_bytes.clone()) {
                    return Err(CodecError::InvalidCbor("duplicate map key"));
                }
                let mut v_bytes = Vec::new();
                write_deterministic_value(v, &mut v_bytes)?;
                encoded_entries.push((k_bytes, v_bytes));
            }
            // RFC 8949 §4.2.1: sort map keys by their encoded CBOR byte sequence.
            encoded_entries.sort_by(|(ka, _), (kb, _)| ka.cmp(kb));
            write_cbor_head(5, encoded_entries.len() as u64, out);
            for (k_bytes, v_bytes) in encoded_entries {
                out.extend_from_slice(&k_bytes);
                out.extend_from_slice(&v_bytes);
            }
            Ok(())
        }
        Value::Float(_) => Err(CodecError::InvalidCbor("floats are forbidden")),
        Value::Tag(_, _) => Err(CodecError::InvalidCbor("unexpected CBOR tag")),
        _ => Err(CodecError::InvalidCbor("unsupported CBOR value")),
    }
}

fn write_cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | (n as u8));
    } else if n <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Exposure policy preimage `E`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExposurePolicy {
    pub profile: PairingProfile,
    pub target_selectors: Vec<String>,
    pub principal_selectors: Vec<String>,
    pub max_body_bytes: u32,
    pub max_attachment_bytes: u32,
    pub rate_burst: u32,
    pub rate_per_minute: u32,
}

impl ExposurePolicy {
    /// Validates ASCII-only, strictly sorted, unique selector lists.
    pub fn validate(&self) -> Result<(), CodecError> {
        validate_selectors(&self.target_selectors)?;
        validate_selectors(&self.principal_selectors)?;
        Ok(())
    }

    /// Encodes `E` in deterministic CBOR.
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let map = Value::Map(vec![
            (Value::from(0), Value::from(1u32)),
            (Value::from(1), Value::from(KIND_EXPOSURE)),
            (Value::from(2), Value::from(self.profile.as_str())),
            (
                Value::from(3),
                Value::Array(
                    self.target_selectors
                        .iter()
                        .map(|s| Value::from(s.as_str()))
                        .collect(),
                ),
            ),
            (
                Value::from(4),
                Value::Array(
                    self.principal_selectors
                        .iter()
                        .map(|s| Value::from(s.as_str()))
                        .collect(),
                ),
            ),
            (Value::from(5), Value::from(self.max_body_bytes)),
            (Value::from(6), Value::from(self.max_attachment_bytes)),
            (Value::from(7), Value::from(self.rate_burst)),
            (Value::from(8), Value::from(self.rate_per_minute)),
            (Value::from(9), Value::from(DIRECTION_INGRESS)),
        ]);
        encode_deterministic_cbor(&map)
    }

    /// Decodes `E` from deterministic CBOR.
    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, CodecError> {
        let val = decode_deterministic_cbor(bytes)?;
        let entries = expect_exact_int_map(&val, 10)?;
        expect_u32_eq(entries[0], 1, "exposure version")?;
        expect_text_eq(entries[1], KIND_EXPOSURE, "exposure kind")?;
        let profile = PairingProfile::parse(expect_text(entries[2], "exposure profile")?)?;
        let target_selectors = expect_text_array(entries[3], "target_selectors")?;
        let principal_selectors = expect_text_array(entries[4], "principal_selectors")?;
        let max_body_bytes = expect_u32(entries[5], "max_body_bytes")?;
        let max_attachment_bytes = expect_u32(entries[6], "max_attachment_bytes")?;
        let rate_burst = expect_u32(entries[7], "rate_burst")?;
        let rate_per_minute = expect_u32(entries[8], "rate_per_minute")?;
        expect_text_eq(entries[9], DIRECTION_INGRESS, "exposure direction")?;
        let policy = Self {
            profile,
            target_selectors,
            principal_selectors,
            max_body_bytes,
            max_attachment_bytes,
            rate_burst,
            rate_per_minute,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Computes `exposure_policy_sha256 = SHA256(deterministic_CBOR(E))`.
    pub fn sha256(&self) -> Result<[u8; 32], CodecError> {
        let cbor = self.encode_cbor()?;
        Ok(Sha256::digest(&cbor).into())
    }
}

fn validate_selectors(selectors: &[String]) -> Result<(), CodecError> {
    let mut prev: Option<&[u8]> = None;
    for s in selectors {
        if !s.is_ascii() {
            return Err(CodecError::InvalidExposure("selector must be ASCII in v1"));
        }
        let b = s.as_bytes();
        if let Some(p) = prev {
            if p >= b {
                return Err(CodecError::InvalidExposure(
                    "selectors must be strictly sorted and unique",
                ));
            }
        }
        prev = Some(b);
    }
    Ok(())
}

/// Directional offer `[profile, grant_not_after_or_null, exposure_policy_sha256]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    pub profile: PairingProfile,
    pub grant_not_after: Option<u32>,
    pub exposure_policy_sha256: [u8; 32],
}

impl Offer {
    fn to_value(self) -> Value {
        let not_after = match self.grant_not_after {
            Some(ts) => Value::from(ts),
            None => Value::Null,
        };
        Value::Array(vec![
            Value::from(self.profile.as_str()),
            not_after,
            Value::Bytes(self.exposure_policy_sha256.to_vec()),
        ])
    }

    fn from_value(val: &Value) -> Result<Self, CodecError> {
        let Value::Array(items) = val else {
            return Err(CodecError::InvalidMessage("offer must be array"));
        };
        if items.len() != 3 {
            return Err(CodecError::InvalidMessage("offer must have 3 elements"));
        }
        let profile = PairingProfile::parse(expect_text(&items[0], "offer.profile")?)?;
        let grant_not_after = expect_opt_u32(&items[1], "offer.grant_not_after")?;
        let exposure_policy_sha256 = expect_bstr32(&items[2], "offer.exposure_policy_sha256")?;
        Ok(Self {
            profile,
            grant_not_after,
            exposure_policy_sha256,
        })
    }
}

/// Initiator offer message `HelloI`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloI {
    pub id_i: [u8; 32],
    pub id_r: [u8; 32],
    pub nonce_i: [u8; 32],
    pub attempt_i: [u8; 16],
    pub offer_i: Offer,
    pub created_utc: u32,
    pub ceremony_expires_utc: u32,
    pub policy_i: u32,
}

impl HelloI {
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.id_i == self.id_r {
            return Err(CodecError::InvalidMessage("id_I and id_R must differ"));
        }
        validate_ceremony_window(self.created_utc, self.ceremony_expires_utc)
    }

    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let map = Value::Map(vec![
            (Value::from(0), Value::from(1u32)),
            (Value::from(1), Value::from(KIND_OFFER)),
            (Value::from(2), Value::Bytes(self.id_i.to_vec())),
            (Value::from(3), Value::Bytes(self.id_r.to_vec())),
            (Value::from(4), Value::Bytes(self.nonce_i.to_vec())),
            (Value::from(5), Value::Bytes(self.attempt_i.to_vec())),
            (Value::from(6), self.offer_i.to_value()),
            (Value::from(7), Value::from(self.created_utc)),
            (Value::from(8), Value::from(self.ceremony_expires_utc)),
            (Value::from(9), Value::from(self.policy_i)),
        ]);
        encode_deterministic_cbor(&map)
    }

    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, CodecError> {
        let val = decode_deterministic_cbor(bytes)?;
        let entries = expect_exact_int_map(&val, 10)?;
        expect_u32_eq(entries[0], 1, "HelloI version")?;
        expect_text_eq(entries[1], KIND_OFFER, "HelloI kind")?;
        let msg = Self {
            id_i: expect_bstr32(entries[2], "HelloI.id_I")?,
            id_r: expect_bstr32(entries[3], "HelloI.id_R")?,
            nonce_i: expect_bstr32(entries[4], "HelloI.nonce_I")?,
            attempt_i: expect_bstr16(entries[5], "HelloI.attempt_I")?,
            offer_i: Offer::from_value(entries[6])?,
            created_utc: expect_u32(entries[7], "HelloI.created_utc")?,
            ceremony_expires_utc: expect_u32(entries[8], "HelloI.ceremony_expires_utc")?,
            policy_i: expect_u32(entries[9], "HelloI.policy_I")?,
        };
        msg.validate()?;
        Ok(msg)
    }
}

/// Frozen ceremony transcript `T`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    pub id_i: [u8; 32],
    pub id_r: [u8; 32],
    pub nonce_i: [u8; 32],
    pub nonce_r: [u8; 32],
    pub offer_i: Offer,
    pub offer_r: Offer,
    pub created_utc: u32,
    pub ceremony_expires_utc: u32,
    pub policy_i: u32,
    pub policy_r: u32,
    pub exporter: [u8; 32],
    pub attempt_i: [u8; 16],
    pub attempt_r: [u8; 16],
}

impl Transcript {
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.id_i == self.id_r {
            return Err(CodecError::InvalidMessage("id_I and id_R must differ"));
        }
        validate_ceremony_window(self.created_utc, self.ceremony_expires_utc)
    }

    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let map = Value::Map(vec![
            (Value::from(0), Value::from(1u32)),
            (Value::from(1), Value::from(KIND_TRANSCRIPT)),
            (Value::from(2), Value::Bytes(self.id_i.to_vec())),
            (Value::from(3), Value::Bytes(self.id_r.to_vec())),
            (Value::from(4), Value::Bytes(self.nonce_i.to_vec())),
            (Value::from(5), Value::Bytes(self.nonce_r.to_vec())),
            (Value::from(6), self.offer_i.to_value()),
            (Value::from(7), self.offer_r.to_value()),
            (Value::from(8), Value::from(self.created_utc)),
            (Value::from(9), Value::from(self.ceremony_expires_utc)),
            (Value::from(10), Value::from(self.policy_i)),
            (Value::from(11), Value::from(self.policy_r)),
            (Value::from(12), Value::Bytes(self.exporter.to_vec())),
            (Value::from(13), Value::Bytes(self.attempt_i.to_vec())),
            (Value::from(14), Value::Bytes(self.attempt_r.to_vec())),
        ]);
        encode_deterministic_cbor(&map)
    }

    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, CodecError> {
        let val = decode_deterministic_cbor(bytes)?;
        let entries = expect_exact_int_map(&val, 15)?;
        expect_u32_eq(entries[0], 1, "T version")?;
        expect_text_eq(entries[1], KIND_TRANSCRIPT, "T kind")?;
        let t = Self {
            id_i: expect_bstr32(entries[2], "T.id_I")?,
            id_r: expect_bstr32(entries[3], "T.id_R")?,
            nonce_i: expect_bstr32(entries[4], "T.nonce_I")?,
            nonce_r: expect_bstr32(entries[5], "T.nonce_R")?,
            offer_i: Offer::from_value(entries[6])?,
            offer_r: Offer::from_value(entries[7])?,
            created_utc: expect_u32(entries[8], "T.created_utc")?,
            ceremony_expires_utc: expect_u32(entries[9], "T.ceremony_expires_utc")?,
            policy_i: expect_u32(entries[10], "T.policy_I")?,
            policy_r: expect_u32(entries[11], "T.policy_R")?,
            exporter: expect_bstr32(entries[12], "T.exporter")?,
            attempt_i: expect_bstr16(entries[13], "T.attempt_I")?,
            attempt_r: expect_bstr16(entries[14], "T.attempt_R")?,
        };
        t.validate()?;
        Ok(t)
    }

    /// Computes `transaction_id = SHA256(deterministic_CBOR(["xmsg-pair-txn-v1", T]))`.
    pub fn transaction_id(&self) -> Result<[u8; 32], CodecError> {
        let t_bytes = self.encode_cbor()?;
        let t_val = decode_deterministic_cbor(&t_bytes)?;
        let preimage = Value::Array(vec![Value::from(KIND_TXN_LABEL), t_val]);
        let preimage_bytes = encode_deterministic_cbor(&preimage)?;
        Ok(Sha256::digest(&preimage_bytes).into())
    }
}

/// Computes `external_aad = deterministic_CBOR(["xmsg-pair-receipt-v1", exporter])`.
pub fn external_aad(exporter: &[u8; 32]) -> Result<Vec<u8>, CodecError> {
    let val = Value::Array(vec![
        Value::from(KIND_RECEIPT),
        Value::Bytes(exporter.to_vec()),
    ]);
    encode_deterministic_cbor(&val)
}

/// Role of the receipt signer in the ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRole {
    Initiator = 0,
    Responder = 1,
}

impl SignerRole {
    pub fn from_u32(v: u32) -> Result<Self, CodecError> {
        match v {
            0 => Ok(Self::Initiator),
            1 => Ok(Self::Responder),
            _ => Err(CodecError::InvalidMessage("invalid signer role")),
        }
    }
}

/// Signed receipt payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub transaction_id: [u8; 32],
    pub signer_role: SignerRole,
    pub signer_id: [u8; 32],
    pub subject_id: [u8; 32],
    pub profile: PairingProfile,
    pub grant_not_after: Option<u32>,
    pub exposure_policy_sha256: [u8; 32],
    pub grant_id: [u8; 16],
    pub issued_utc: u32,
    pub ceremony_expires_utc: u32,
    pub provenance: String,
    pub policy_revision: u32,
}

impl Receipt {
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        let not_after = match self.grant_not_after {
            Some(ts) => Value::from(ts),
            None => Value::Null,
        };
        let map = Value::Map(vec![
            (Value::from(0), Value::from(1u32)),
            (Value::from(1), Value::from(KIND_RECEIPT)),
            (Value::from(2), Value::Bytes(self.transaction_id.to_vec())),
            (Value::from(3), Value::from(self.signer_role as u32)),
            (Value::from(4), Value::Bytes(self.signer_id.to_vec())),
            (Value::from(5), Value::Bytes(self.subject_id.to_vec())),
            (Value::from(6), Value::from(self.profile.as_str())),
            (Value::from(7), not_after),
            (
                Value::from(8),
                Value::Bytes(self.exposure_policy_sha256.to_vec()),
            ),
            (Value::from(9), Value::Bytes(self.grant_id.to_vec())),
            (Value::from(10), Value::from(self.issued_utc)),
            (Value::from(11), Value::from(self.ceremony_expires_utc)),
            (Value::from(12), Value::from(self.provenance.as_str())),
            (Value::from(13), Value::from(self.policy_revision)),
        ]);
        encode_deterministic_cbor(&map)
    }

    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, CodecError> {
        let val = decode_deterministic_cbor(bytes)?;
        let entries = expect_exact_int_map(&val, 14)?;
        expect_u32_eq(entries[0], 1, "Receipt version")?;
        expect_text_eq(entries[1], KIND_RECEIPT, "Receipt kind")?;
        Ok(Self {
            transaction_id: expect_bstr32(entries[2], "Receipt.transaction_id")?,
            signer_role: SignerRole::from_u32(expect_u32(entries[3], "Receipt.signer_role")?)?,
            signer_id: expect_bstr32(entries[4], "Receipt.signer_id")?,
            subject_id: expect_bstr32(entries[5], "Receipt.subject_id")?,
            profile: PairingProfile::parse(expect_text(entries[6], "Receipt.profile")?)?,
            grant_not_after: expect_opt_u32(entries[7], "Receipt.grant_not_after")?,
            exposure_policy_sha256: expect_bstr32(entries[8], "Receipt.exposure_policy_sha256")?,
            grant_id: expect_bstr16(entries[9], "Receipt.grant_id")?,
            issued_utc: expect_u32(entries[10], "Receipt.issued_utc")?,
            ceremony_expires_utc: expect_u32(entries[11], "Receipt.ceremony_expires_utc")?,
            provenance: expect_text(entries[12], "Receipt.provenance")?.to_owned(),
            policy_revision: expect_u32(entries[13], "Receipt.policy_revision")?,
        })
    }
}

/// Builds a tagged `COSE_Sign1` (tag 18) receipt with attached payload, empty unprotected map,
/// and protected headers `{1: -19, 3: "application/cbor", 4: signer_id}`.
pub fn build_signed_receipt(
    receipt: &Receipt,
    exporter: &[u8; 32],
    keypair: &Ed25519KeyPair,
) -> Result<Vec<u8>, CodecError> {
    let payload_bytes = receipt.encode_cbor()?;
    let aad = external_aad(exporter)?;
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::Ed25519) // -19 (RFC 9864)
        .content_type("application/cbor".to_owned())
        .key_id(receipt.signer_id.to_vec())
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&aad, |tbs| keypair.sign(tbs).as_ref().to_vec())
        .build();

    let cose_bytes = sign1
        .to_tagged_vec()
        .map_err(|_| CodecError::InvalidCose("failed to serialize COSE_Sign1"))?;
    if cose_bytes.len() > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge);
    }
    Ok(cose_bytes)
}

/// Context required to verify a `COSE_Sign1` pairing receipt.
pub struct ReceiptVerificationContext<'a> {
    pub id_i: [u8; 32],
    pub id_r: [u8; 32],
    pub spki_i: &'a [u8],
    pub spki_r: &'a [u8],
    pub offer_i: Offer,
    pub offer_r: Offer,
    pub created_utc: u32,
    pub ceremony_expires_utc: u32,
    pub exporter: [u8; 32],
    pub transaction_id: [u8; 32],
    pub now_utc: u32,
    pub current_policy_i: u32,
    pub current_policy_r: u32,
    pub blocked: bool,
    pub revoked: bool,
    pub bilateral: bool,
}

/// Parses and verifies a tagged `COSE_Sign1` pairing receipt against `ctx`.
pub fn parse_and_verify_receipt(
    cose_bytes: &[u8],
    ctx: &ReceiptVerificationContext<'_>,
) -> Result<Receipt, CodecError> {
    if cose_bytes.len() > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge);
    }
    if cose_bytes.first().copied() != Some(0xd2) {
        return Err(CodecError::InvalidCose("expected CBOR tag 18 (0xd2)"));
    }
    // Verify the inner 4-element array is canonical deterministic CBOR.
    let inner = decode_deterministic_cbor(&cose_bytes[1..])?;
    let Value::Array(ref top_arr) = inner else {
        return Err(CodecError::InvalidCose("expected 4-element COSE array"));
    };
    if top_arr.len() != 4 {
        return Err(CodecError::InvalidCose("expected 4-element COSE array"));
    }

    let sign1 = CoseSign1::from_tagged_slice(cose_bytes)
        .map_err(|_| CodecError::InvalidCose("malformed COSE_Sign1"))?;
    if !sign1.unprotected.is_empty() {
        return Err(CodecError::InvalidCose("unprotected map must be empty"));
    }
    let payload_bytes = sign1
        .payload
        .as_deref()
        .ok_or(CodecError::InvalidCose("detached payload not allowed"))?;

    // Validate protected headers are canonical CBOR with exact keys {1: -19, 3: "application/cbor", 4: signer_id}.
    let protected_bytes = sign1
        .protected
        .original_data
        .as_deref()
        .ok_or(CodecError::InvalidCose("missing protected bytes"))?;
    let prot_val = decode_deterministic_cbor(protected_bytes)?;
    let Value::Map(ref prot_entries) = prot_val else {
        return Err(CodecError::InvalidCose("protected header must be map"));
    };
    if prot_entries.len() != 3 {
        return Err(CodecError::InvalidCose(
            "protected header must have exact keys {1, 3, 4}",
        ));
    }
    expect_int_key(&prot_entries[0].0, 1)?;
    expect_int_key(&prot_entries[1].0, 3)?;
    expect_int_key(&prot_entries[2].0, 4)?;
    if prot_entries[0].1 != Value::from(COSE_ALG_ED25519) {
        return Err(CodecError::InvalidCose(
            "protected alg must be -19 (Ed25519)",
        ));
    }
    expect_text_eq(
        &prot_entries[1].1,
        "application/cbor",
        "protected content_type",
    )?;
    let prot_signer_id = expect_bstr32(&prot_entries[2].1, "protected kid")?;

    let (
        role,
        expected_signer_id,
        expected_subject_id,
        expected_spki,
        expected_offer,
        expected_policy,
    ) = if prot_signer_id == ctx.id_i {
        (
            SignerRole::Initiator,
            ctx.id_i,
            ctx.id_r,
            ctx.spki_i,
            ctx.offer_i,
            ctx.current_policy_i,
        )
    } else if prot_signer_id == ctx.id_r {
        (
            SignerRole::Responder,
            ctx.id_r,
            ctx.id_i,
            ctx.spki_r,
            ctx.offer_r,
            ctx.current_policy_r,
        )
    } else {
        return Err(CodecError::UnknownSigner);
    };

    // Verify expected SPKI matches expected_signer_id before verifying signature.
    let derived_id = SpkiDeviceId::from_spki_der(expected_spki)?;
    if derived_id.0 != expected_signer_id {
        return Err(CodecError::VerificationFailed(
            "SPKI does not match signer ID",
        ));
    }
    let pubkey = extract_ed25519_pubkey(expected_spki)?;

    let aad = external_aad(&ctx.exporter)?;
    let tbs = sign1.tbs_data(&aad);
    UnparsedPublicKey::new(&ED25519, &pubkey)
        .verify(&tbs, &sign1.signature)
        .map_err(|_| CodecError::SignatureInvalid)?;

    // Decode payload and enforce semantic/role/context checks.
    let receipt = Receipt::decode_cbor(payload_bytes)?;
    if receipt.signer_role != role {
        return Err(CodecError::VerificationFailed(
            "payload role differs from protected signer",
        ));
    }
    if receipt.signer_id != expected_signer_id {
        return Err(CodecError::VerificationFailed(
            "payload signer_id differs from protected signer",
        ));
    }
    if receipt.subject_id != expected_subject_id {
        return Err(CodecError::VerificationFailed("unexpected subject_id"));
    }
    if receipt.transaction_id != ctx.transaction_id {
        return Err(CodecError::VerificationFailed("transaction_id mismatch"));
    }
    if receipt.profile != expected_offer.profile {
        return Err(CodecError::VerificationFailed("profile mismatch"));
    }
    if receipt.grant_not_after != expected_offer.grant_not_after {
        return Err(CodecError::VerificationFailed("grant_not_after mismatch"));
    }
    if receipt.exposure_policy_sha256 != expected_offer.exposure_policy_sha256 {
        return Err(CodecError::VerificationFailed(
            "exposure_policy_sha256 mismatch",
        ));
    }
    if receipt.provenance != PROVENANCE_MANUAL_OOB {
        return Err(CodecError::VerificationFailed("invalid provenance for v1a"));
    }
    if receipt.policy_revision != expected_policy {
        return Err(CodecError::VerificationFailed("policy revision changed"));
    }
    if receipt.ceremony_expires_utc != ctx.ceremony_expires_utc {
        return Err(CodecError::VerificationFailed(
            "ceremony_expires_utc mismatch",
        ));
    }
    if ctx.now_utc < ctx.created_utc {
        return Err(CodecError::VerificationFailed("not yet valid"));
    }
    if ctx.now_utc > receipt.ceremony_expires_utc {
        return Err(CodecError::VerificationFailed("expired"));
    }
    if receipt.issued_utc < ctx.created_utc || receipt.issued_utc > receipt.ceremony_expires_utc {
        return Err(CodecError::VerificationFailed(
            "receipt issued_utc outside ceremony window",
        ));
    }
    if ctx.blocked {
        return Err(CodecError::VerificationFailed("blocked"));
    }
    if ctx.revoked {
        return Err(CodecError::VerificationFailed("revoked"));
    }
    if !ctx.bilateral {
        return Err(CodecError::VerificationFailed("unilateral"));
    }

    Ok(receipt)
}

/// Validates ceremony time reflection, bounded window, monotonic deadline, and UTC validity.
#[allow(clippy::too_many_arguments)]
pub fn validate_ceremony_times(
    hello_created: u32,
    hello_expires: u32,
    transcript_created: u32,
    transcript_expires: u32,
    intent_deadline_mono: u64,
    first_arrival_mono: u64,
    utc_at_arrival: u32,
    mono_now: u64,
    utc_now: u32,
) -> Result<u64, CodecError> {
    if hello_created != transcript_created {
        return Err(CodecError::VerificationFailed(
            "created reflection mismatch",
        ));
    }
    if hello_expires != transcript_expires {
        return Err(CodecError::VerificationFailed("expiry reflection mismatch"));
    }
    validate_ceremony_window(hello_created, hello_expires)?;
    let remaining_from_arrival = hello_expires.saturating_sub(utc_at_arrival) as u64;
    let deadline = intent_deadline_mono
        .min(first_arrival_mono.saturating_add(MAX_CEREMONY_WINDOW_SECS as u64))
        .min(first_arrival_mono.saturating_add(remaining_from_arrival));
    if mono_now > deadline {
        return Err(CodecError::VerificationFailed(
            "responder local deadline expired",
        ));
    }
    if utc_now < hello_created || utc_now > hello_expires {
        return Err(CodecError::VerificationFailed("UTC validity expired"));
    }
    Ok(deadline)
}

/// Summary of a grant record for one-grant operation authorization checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantSummary {
    pub profile: PairingProfile,
    pub expires_utc: u32,
    pub provenance: String,
}

/// Returns `true` iff there exists ONE grant supplying both valid `manual_authenticated_oob`
/// provenance, unexpired lifetime, and permission for `op`.
pub fn authorize_grant_operation(grants: &[GrantSummary], op: &str, now_utc: u32) -> bool {
    grants.iter().any(|g| {
        g.expires_utc > now_utc
            && g.provenance == PROVENANCE_MANUAL_OOB
            && match g.profile {
                PairingProfile::Contact => matches!(op, "send" | "reply"),
                PairingProfile::OwnerDevice => matches!(op, "send" | "reply" | "list"),
            }
    })
}

fn validate_ceremony_window(created_utc: u32, expires_utc: u32) -> Result<(), CodecError> {
    if expires_utc <= created_utc {
        return Err(CodecError::InvalidMessage(
            "ceremony_expires_utc must exceed created_utc",
        ));
    }
    if expires_utc - created_utc > MAX_CEREMONY_WINDOW_SECS {
        return Err(CodecError::InvalidMessage(
            "ceremony window exceeds 120 seconds",
        ));
    }
    Ok(())
}

fn expect_exact_int_map(val: &Value, expected_len: usize) -> Result<Vec<&Value>, CodecError> {
    let Value::Map(entries) = val else {
        return Err(CodecError::InvalidMessage("expected CBOR map"));
    };
    if entries.len() != expected_len {
        return Err(CodecError::InvalidMessage("unexpected CBOR map length"));
    }
    let mut out = Vec::with_capacity(expected_len);
    for (idx, (k, v)) in entries.iter().enumerate() {
        expect_int_key(k, idx as i128)?;
        out.push(v);
    }
    Ok(out)
}

fn expect_int_key(k: &Value, expected: i128) -> Result<(), CodecError> {
    let Value::Integer(int) = k else {
        return Err(CodecError::InvalidMessage("expected integer map key"));
    };
    let n: i128 = (*int).into();
    if n != expected {
        return Err(CodecError::InvalidMessage("unexpected CBOR map key"));
    }
    Ok(())
}

fn expect_u32(val: &Value, _field: &'static str) -> Result<u32, CodecError> {
    let Value::Integer(int) = val else {
        return Err(CodecError::InvalidMessage("expected integer"));
    };
    let n: i128 = (*int).into();
    u32::try_from(n).map_err(|_| CodecError::InvalidMessage("integer out of u32 range"))
}

fn expect_u32_eq(val: &Value, expected: u32, _field: &'static str) -> Result<(), CodecError> {
    let actual = expect_u32(val, _field)?;
    if actual != expected {
        return Err(CodecError::InvalidMessage("unexpected integer value"));
    }
    Ok(())
}

fn expect_opt_u32(val: &Value, field: &'static str) -> Result<Option<u32>, CodecError> {
    if matches!(val, Value::Null) {
        Ok(None)
    } else {
        Ok(Some(expect_u32(val, field)?))
    }
}

fn expect_text<'a>(val: &'a Value, _field: &'static str) -> Result<&'a str, CodecError> {
    let Value::Text(s) = val else {
        return Err(CodecError::InvalidMessage("expected text string"));
    };
    Ok(s.as_str())
}

fn expect_text_eq(val: &Value, expected: &str, field: &'static str) -> Result<(), CodecError> {
    if expect_text(val, field)? != expected {
        return Err(CodecError::InvalidMessage("unexpected text value"));
    }
    Ok(())
}

fn expect_text_array(val: &Value, field: &'static str) -> Result<Vec<String>, CodecError> {
    let Value::Array(items) = val else {
        return Err(CodecError::InvalidMessage("expected array"));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(expect_text(item, field)?.to_owned());
    }
    Ok(out)
}

fn expect_bstr32(val: &Value, _field: &'static str) -> Result<[u8; 32], CodecError> {
    let Value::Bytes(b) = val else {
        return Err(CodecError::InvalidMessage("expected byte string"));
    };
    b.as_slice()
        .try_into()
        .map_err(|_| CodecError::InvalidMessage("expected 32-byte string"))
}

fn expect_bstr16(val: &Value, _field: &'static str) -> Result<[u8; 16], CodecError> {
    let Value::Bytes(b) = val else {
        return Err(CodecError::InvalidMessage("expected byte string"));
    };
    b.as_slice()
        .try_into()
        .map_err(|_| CodecError::InvalidMessage("expected 16-byte string"))
}
