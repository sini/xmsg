use crate::e2e::suite::{kid_for_key, EnvelopeKind, SUITE_IDS};
use crate::e2e::E2eError;
use ciborium::value::Value;
use std::io::Cursor;

pub const TRANSCRIPT_PROTOCOL: u64 = 1;
pub const RECORD_DOMAIN: &str = "xmsg-e2e-record/1";
const MAX_CBOR_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyMode {
    Durable,
    Ephemeral,
}

impl CustodyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Ephemeral => "ephemeral",
        }
    }

    pub fn parse(s: &str) -> Result<Self, E2eError> {
        match s {
            "durable" => Ok(Self::Durable),
            "ephemeral" => Ok(Self::Ephemeral),
            _ => Err(E2eError::Cbor("unknown custody mode")),
        }
    }
}

/// Transcript `T` used as HPKE `aad` and sent in the clear (spec §3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    pub protocol: u64,
    pub kind: EnvelopeKind,
    pub suite: [u16; 3],
    pub sender: String,
    pub recipient: String,
    pub target_ref: String,
    pub message_id: String,
    pub in_reply_to: Option<String>,
    pub sender_sig_kid: [u8; 32],
    pub sender_gen: u64,
    pub recipient_kem_kid: [u8; 32],
    pub created_at: i64,
    pub expires_at: i64,
    pub refs_digest: [u8; 32],
    pub status_attempt_digest: Option<[u8; 32]>,
}

impl Transcript {
    pub fn encode(&self) -> Result<Vec<u8>, E2eError> {
        if self.protocol != TRANSCRIPT_PROTOCOL {
            return Err(E2eError::Cbor("unsupported protocol"));
        }
        if self.suite != SUITE_IDS {
            return Err(E2eError::Cbor("unsupported suite"));
        }
        if self.sender.is_empty()
            || self.recipient.is_empty()
            || self.target_ref.is_empty()
            || self.message_id.is_empty()
        {
            return Err(E2eError::Cbor("empty required string field"));
        }
        if self.status_attempt_digest.is_some() != (self.kind == EnvelopeKind::Status) {
            return Err(E2eError::Cbor(
                "status_attempt_digest must be present iff kind == status",
            ));
        }

        let arr = Value::Array(vec![
            Value::Integer(self.protocol.into()),
            Value::Text(self.kind.as_str().to_owned()),
            Value::Array(
                self.suite
                    .iter()
                    .map(|&v| Value::Integer(u64::from(v).into()))
                    .collect(),
            ),
            Value::Text(self.sender.clone()),
            Value::Text(self.recipient.clone()),
            Value::Text(self.target_ref.clone()),
            Value::Text(self.message_id.clone()),
            opt_text(self.in_reply_to.as_deref()),
            Value::Bytes(self.sender_sig_kid.to_vec()),
            Value::Integer(self.sender_gen.into()),
            Value::Bytes(self.recipient_kem_kid.to_vec()),
            Value::Integer(self.created_at.into()),
            Value::Integer(self.expires_at.into()),
            Value::Bytes(self.refs_digest.to_vec()),
            opt_bytes(self.status_attempt_digest.as_ref()),
        ]);

        let mut out = Vec::new();
        ciborium::ser::into_writer(&arr, &mut out).map_err(|_| E2eError::Cbor("encode failed"))?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, E2eError> {
        if bytes.len() > MAX_CBOR_BYTES {
            return Err(E2eError::Cbor("transcript too large"));
        }
        let val: Value =
            ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| E2eError::Cbor("decode"))?;
        let Value::Array(items) = val else {
            return Err(E2eError::Cbor("expected array"));
        };
        if items.len() != 15 {
            return Err(E2eError::Cbor("unexpected transcript length"));
        }
        let protocol = as_u64(&items[0])?;
        let kind = EnvelopeKind::parse(as_text(&items[1])?)?;
        let suite = as_suite(&items[2])?;
        let sender = as_text(&items[3])?.to_owned();
        let recipient = as_text(&items[4])?.to_owned();
        let target_ref = as_text(&items[5])?.to_owned();
        let message_id = as_text(&items[6])?.to_owned();
        let in_reply_to = as_opt_text(&items[7])?;
        let sender_sig_kid = as_bytes32(&items[8])?;
        let sender_gen = as_u64(&items[9])?;
        let recipient_kem_kid = as_bytes32(&items[10])?;
        let created_at = as_i64(&items[11])?;
        let expires_at = as_i64(&items[12])?;
        let refs_digest = as_bytes32(&items[13])?;
        let status_attempt_digest = as_opt_bytes32(&items[14])?;

        let decoded = Self {
            protocol,
            kind,
            suite,
            sender,
            recipient,
            target_ref,
            message_id,
            in_reply_to,
            sender_sig_kid,
            sender_gen,
            recipient_kem_kid,
            created_at,
            expires_at,
            refs_digest,
            status_attempt_digest,
        };
        if decoded.encode()?.as_slice() != bytes {
            return Err(E2eError::NonCanonicalCbor);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationEntry {
    pub sig_kid: [u8; 32],
    pub sig_pk: [u8; 32],
    pub gen: u64,
    pub sign_from: i64,
    pub sign_until: i64,
}

/// Signed node E2E record payload (spec §3.2) in deterministic CBOR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordPayload {
    pub domain: String,
    pub identity: String,
    pub gen: u64,
    pub kem_pk: [u8; 32],
    pub kem_kid: [u8; 32],
    pub sig_pk: [u8; 32],
    pub sig_kid: [u8; 32],
    pub custody: CustodyMode,
    pub max_residence: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub delegations: Vec<DelegationEntry>,
    pub cert_chain: Vec<Vec<u8>>,
}

impl RecordPayload {
    pub fn encode(&self) -> Result<Vec<u8>, E2eError> {
        if self.domain != RECORD_DOMAIN {
            return Err(E2eError::Cbor("invalid record domain"));
        }
        if self.identity.is_empty() || self.max_residence < 0 || self.expires_at <= self.issued_at {
            return Err(E2eError::Cbor("invalid record metadata"));
        }
        if kid_for_key(&self.kem_pk) != self.kem_kid || kid_for_key(&self.sig_pk) != self.sig_kid {
            return Err(E2eError::Cbor("kid mismatch"));
        }
        let mut delegations_cbor = Vec::with_capacity(self.delegations.len());
        for d in &self.delegations {
            if kid_for_key(&d.sig_pk) != d.sig_kid || d.sign_until < d.sign_from {
                return Err(E2eError::Cbor("invalid delegation entry"));
            }
            delegations_cbor.push(Value::Array(vec![
                Value::Bytes(d.sig_kid.to_vec()),
                Value::Bytes(d.sig_pk.to_vec()),
                Value::Integer(d.gen.into()),
                Value::Integer(d.sign_from.into()),
                Value::Integer(d.sign_until.into()),
            ]));
        }
        let certs_cbor: Vec<Value> = self
            .cert_chain
            .iter()
            .map(|c| Value::Bytes(c.clone()))
            .collect();

        let arr = Value::Array(vec![
            Value::Text(self.domain.clone()),
            Value::Text(self.identity.clone()),
            Value::Integer(self.gen.into()),
            Value::Bytes(self.kem_pk.to_vec()),
            Value::Bytes(self.kem_kid.to_vec()),
            Value::Bytes(self.sig_pk.to_vec()),
            Value::Bytes(self.sig_kid.to_vec()),
            Value::Text(self.custody.as_str().to_owned()),
            Value::Integer(self.max_residence.into()),
            Value::Integer(self.issued_at.into()),
            Value::Integer(self.expires_at.into()),
            Value::Array(delegations_cbor),
            Value::Array(certs_cbor),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&arr, &mut out).map_err(|_| E2eError::Cbor("encode failed"))?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, E2eError> {
        if bytes.len() > MAX_CBOR_BYTES {
            return Err(E2eError::Cbor("record too large"));
        }
        let val: Value =
            ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| E2eError::Cbor("decode"))?;
        let Value::Array(items) = val else {
            return Err(E2eError::Cbor("expected array"));
        };
        if items.len() != 13 {
            return Err(E2eError::Cbor("unexpected record length"));
        }
        let domain = as_text(&items[0])?.to_owned();
        let identity = as_text(&items[1])?.to_owned();
        let gen = as_u64(&items[2])?;
        let kem_pk = as_bytes32(&items[3])?;
        let kem_kid = as_bytes32(&items[4])?;
        let sig_pk = as_bytes32(&items[5])?;
        let sig_kid = as_bytes32(&items[6])?;
        let custody = CustodyMode::parse(as_text(&items[7])?)?;
        let max_residence = as_i64(&items[8])?;
        let issued_at = as_i64(&items[9])?;
        let expires_at = as_i64(&items[10])?;

        let Value::Array(del_items) = &items[11] else {
            return Err(E2eError::Cbor("expected delegations array"));
        };
        let mut delegations = Vec::with_capacity(del_items.len());
        for d in del_items {
            let Value::Array(df) = d else {
                return Err(E2eError::Cbor("expected delegation tuple"));
            };
            if df.len() != 5 {
                return Err(E2eError::Cbor("invalid delegation tuple length"));
            }
            delegations.push(DelegationEntry {
                sig_kid: as_bytes32(&df[0])?,
                sig_pk: as_bytes32(&df[1])?,
                gen: as_u64(&df[2])?,
                sign_from: as_i64(&df[3])?,
                sign_until: as_i64(&df[4])?,
            });
        }

        let Value::Array(cert_items) = &items[12] else {
            return Err(E2eError::Cbor("expected cert_chain array"));
        };
        let mut cert_chain = Vec::with_capacity(cert_items.len());
        for c in cert_items {
            let Value::Bytes(der) = c else {
                return Err(E2eError::Cbor("expected cert bytes"));
            };
            cert_chain.push(der.clone());
        }

        let decoded = Self {
            domain,
            identity,
            gen,
            kem_pk,
            kem_kid,
            sig_pk,
            sig_kid,
            custody,
            max_residence,
            issued_at,
            expires_at,
            delegations,
            cert_chain,
        };
        if decoded.encode()?.as_slice() != bytes {
            return Err(E2eError::NonCanonicalCbor);
        }
        Ok(decoded)
    }
}

fn opt_text(s: Option<&str>) -> Value {
    match s {
        Some(v) => Value::Text(v.to_owned()),
        None => Value::Null,
    }
}

fn opt_bytes(b: Option<&[u8; 32]>) -> Value {
    match b {
        Some(v) => Value::Bytes(v.to_vec()),
        None => Value::Null,
    }
}

fn as_text(v: &Value) -> Result<&str, E2eError> {
    match v {
        Value::Text(s) => Ok(s.as_str()),
        _ => Err(E2eError::Cbor("expected text")),
    }
}

fn as_opt_text(v: &Value) -> Result<Option<String>, E2eError> {
    match v {
        Value::Null => Ok(None),
        Value::Text(s) if !s.is_empty() => Ok(Some(s.clone())),
        _ => Err(E2eError::Cbor("expected null or non-empty text")),
    }
}

fn as_u64(v: &Value) -> Result<u64, E2eError> {
    match v {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| E2eError::Cbor("expected u64")),
        _ => Err(E2eError::Cbor("expected integer")),
    }
}

fn as_i64(v: &Value) -> Result<i64, E2eError> {
    match v {
        Value::Integer(i) => i64::try_from(*i).map_err(|_| E2eError::Cbor("expected i64")),
        _ => Err(E2eError::Cbor("expected integer")),
    }
}

fn as_bytes32(v: &Value) -> Result<[u8; 32], E2eError> {
    match v {
        Value::Bytes(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            Ok(arr)
        }
        _ => Err(E2eError::Cbor("expected 32-byte array")),
    }
}

fn as_opt_bytes32(v: &Value) -> Result<Option<[u8; 32]>, E2eError> {
    match v {
        Value::Null => Ok(None),
        _ => Ok(Some(as_bytes32(v)?)),
    }
}

fn as_suite(v: &Value) -> Result<[u16; 3], E2eError> {
    let Value::Array(arr) = v else {
        return Err(E2eError::Cbor("expected suite array"));
    };
    if arr.len() != 3 {
        return Err(E2eError::Cbor("expected 3-element suite"));
    }
    let mut out = [0u16; 3];
    for (i, item) in arr.iter().enumerate() {
        let n = as_u64(item)?;
        out[i] = u16::try_from(n).map_err(|_| E2eError::Cbor("suite element out of u16"))?;
    }
    Ok(out)
}
