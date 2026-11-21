use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const EPOCH_END: usize = 16;
const SEQ_END: usize = EPOCH_END + 8;
const SCOPE_END: usize = SEQ_END + 32;
const RECORD_END: usize = SCOPE_END + 32;
const BODY_LEN: usize = RECORD_END + 8;
const TAG_LEN: usize = 16;
const CURSOR_LEN: usize = BODY_LEN + TAG_LEN;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum ResumeFailure {
    Invalid,
    EpochChanged,
}

pub(super) struct CursorKey {
    epoch: [u8; EPOCH_END],
    key: hmac::Key,
}

pub(super) struct Partition {
    scope_digest: [u8; 32],
    record_digest: [u8; 32],
    policy_generation: i64,
}

impl Partition {
    pub(super) fn new(scope: &[u8], record_id: &[u8], policy_generation: i64) -> Self {
        Self {
            scope_digest: Sha256::digest(scope).into(),
            record_digest: Sha256::digest(record_id).into(),
            policy_generation,
        }
    }
}

impl CursorKey {
    pub(super) fn new() -> Result<Self, ring::error::Unspecified> {
        let random = SystemRandom::new();
        let mut epoch = [0; EPOCH_END];
        random.fill(&mut epoch)?;
        Ok(Self {
            epoch,
            key: hmac::Key::generate(hmac::HMAC_SHA256, &random)?,
        })
    }

    pub(super) fn epoch(&self) -> String {
        hex::encode(self.epoch)
    }

    #[allow(
        dead_code,
        reason = "Mission Control transport console is wired in a later train commit"
    )]
    pub(super) fn issue(&self, seq: u64, partition: &Partition) -> String {
        let mut bytes = [0; CURSOR_LEN];
        bytes[..EPOCH_END].copy_from_slice(&self.epoch);
        bytes[EPOCH_END..SEQ_END].copy_from_slice(&seq.to_be_bytes());
        bytes[SEQ_END..SCOPE_END].copy_from_slice(&partition.scope_digest);
        bytes[SCOPE_END..RECORD_END].copy_from_slice(&partition.record_digest);
        bytes[RECORD_END..BODY_LEN].copy_from_slice(&partition.policy_generation.to_be_bytes());
        let mac = self.mac(&bytes[..BODY_LEN]);
        bytes[BODY_LEN..].copy_from_slice(&mac.as_ref()[..TAG_LEN]);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub(super) fn verify(&self, cursor: &str, partition: &Partition) -> Result<u64, ResumeFailure> {
        if cursor.len() > 512 {
            return Err(ResumeFailure::Invalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| ResumeFailure::Invalid)?;
        let bytes: [u8; CURSOR_LEN] = bytes.try_into().map_err(|_| ResumeFailure::Invalid)?;
        if bytes[..EPOCH_END] != self.epoch {
            return Err(ResumeFailure::EpochChanged);
        }
        let mac = self.mac(&bytes[..BODY_LEN]);
        if !bool::from(mac.as_ref()[..TAG_LEN].ct_eq(&bytes[BODY_LEN..]))
            || bytes[SEQ_END..SCOPE_END] != partition.scope_digest
            || bytes[SCOPE_END..RECORD_END] != partition.record_digest
            || bytes[RECORD_END..BODY_LEN] != partition.policy_generation.to_be_bytes()
        {
            return Err(ResumeFailure::Invalid);
        }
        Ok(u64::from_be_bytes(
            bytes[EPOCH_END..SEQ_END]
                .try_into()
                .expect("cursor sequence width"),
        ))
    }

    fn mac(&self, body: &[u8]) -> hmac::Tag {
        hmac::sign(&self.key, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_partition_and_rewrite_control() {
        let key = CursorKey::new().unwrap();
        assert_eq!(key.epoch().len(), 32);
        let node = Partition::new(b"node/laptop", b"browser-record", 42);
        let fleet = Partition::new(b"fleet", b"browser-record", 42);
        let native = Partition::new(b"node/laptop", b"native-record", 42);
        let next = Partition::new(b"node/laptop", b"browser-record", 43);
        let cursor = key.issue(42, &node);
        assert_eq!(key.verify(&cursor, &node), Ok(42));
        assert_eq!(key.verify(&cursor, &fleet), Err(ResumeFailure::Invalid));
        assert_eq!(key.verify(&cursor, &native), Err(ResumeFailure::Invalid));
        assert_eq!(key.verify(&cursor, &next), Err(ResumeFailure::Invalid));
        let other_epoch = CursorKey::new().unwrap();
        assert_eq!(
            other_epoch.verify(&cursor, &node),
            Err(ResumeFailure::EpochChanged)
        );
        let bytes = URL_SAFE_NO_PAD.decode(cursor).unwrap();
        let mut corrupt = bytes.clone();
        corrupt[BODY_LEN] ^= 1;
        assert_eq!(
            key.verify(&URL_SAFE_NO_PAD.encode(corrupt), &node),
            Err(ResumeFailure::Invalid)
        );
        let mut rewritten_scope = bytes.clone();
        rewritten_scope[SEQ_END..SCOPE_END].copy_from_slice(&fleet.scope_digest);
        assert_eq!(
            key.verify(&URL_SAFE_NO_PAD.encode(rewritten_scope), &fleet),
            Err(ResumeFailure::Invalid),
            "rewritten scope must invalidate the MAC"
        );
        let mut rewritten_record = bytes;
        rewritten_record[SCOPE_END..RECORD_END].copy_from_slice(&native.record_digest);
        assert_eq!(
            key.verify(&URL_SAFE_NO_PAD.encode(rewritten_record), &native),
            Err(ResumeFailure::Invalid),
            "rewritten record must invalidate the MAC"
        );
    }
}
