use crate::e2e::E2eError;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const SUITE_KEM_ID: u16 = 0x0020;
pub const SUITE_KDF_ID: u16 = 0x0001;
pub const SUITE_AEAD_ID: u16 = 0x0003;
pub const SUITE_IDS: [u16; 3] = [SUITE_KEM_ID, SUITE_KDF_ID, SUITE_AEAD_ID];

pub type Kem = X25519HkdfSha256;
pub type Kdf = HkdfSha256;
pub type Aead = ChaCha20Poly1305;
pub type PrivateKey = <Kem as KemTrait>::PrivateKey;
pub type PublicKey = <Kem as KemTrait>::PublicKey;
pub type EncappedKey = <Kem as KemTrait>::EncappedKey;

const INFO_PREFIX: &[u8] = b"xmsg-e2e/1/";
const SIG_DOMAIN: &[u8] = b"xmsg-e2e-sig/1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeKind {
    Message,
    Reply,
    Status,
    Handoff,
}

impl EnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Reply => "reply",
            Self::Status => "status",
            Self::Handoff => "handoff",
        }
    }

    pub fn parse(s: &str) -> Result<Self, E2eError> {
        match s {
            "message" => Ok(Self::Message),
            "reply" => Ok(Self::Reply),
            "status" => Ok(Self::Status),
            "handoff" => Ok(Self::Handoff),
            _ => Err(E2eError::Cbor("unknown envelope kind")),
        }
    }
}

/// Zeroizing wrapper for 32-byte exported secret key material (`to_bytes()`).
#[derive(Clone)]
pub struct SecretKeyBytes(pub Zeroizing<[u8; 32]>);

impl SecretKeyBytes {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Zeroize the inner array in-place while storage is still live.
    pub fn zeroize_in_place(&mut self) {
        self.0.zeroize();
    }
}

pub fn info_for_kind(kind: EnvelopeKind) -> Vec<u8> {
    let mut out = Vec::with_capacity(INFO_PREFIX.len() + kind.as_str().len());
    out.extend_from_slice(INFO_PREFIX);
    out.extend_from_slice(kind.as_str().as_bytes());
    out
}

pub fn kid_for_key(pk_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(pk_bytes).into()
}

/// Generate a fresh X25519 HPKE keypair using the OS RNG (`SysRng` via `getrandom`).
pub fn generate_keypair() -> Result<(SecretKeyBytes, [u8; 32]), E2eError> {
    let (sk, pk) = Kem::gen_keypair();
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk.to_bytes());
    let sk_wrap = SecretKeyBytes::new(sk_arr);
    sk_arr.zeroize();
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk.to_bytes());
    Ok((sk_wrap, pk_arr))
}

/// Derive an X25519 HPKE keypair deterministically from IKM (used for RFC 9180 vectors).
pub fn derive_keypair(ikm: &[u8]) -> (SecretKeyBytes, [u8; 32]) {
    let (sk, pk) = Kem::derive_keypair(ikm);
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk.to_bytes());
    let sk_wrap = SecretKeyBytes::new(sk_arr);
    sk_arr.zeroize();
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk.to_bytes());
    (sk_wrap, pk_arr)
}

/// Seal `plaintext` to `recipient_pk` in HPKE Base mode using the OS RNG (`SysRng`).
pub fn seal(
    recipient_pk: &[u8; 32],
    kind: EnvelopeKind,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), E2eError> {
    let pk =
        PublicKey::from_bytes(recipient_pk).map_err(|_| E2eError::Hpke("invalid public key"))?;
    let info = info_for_kind(kind);
    let (enc, ct) =
        hpke::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &pk, &info, plaintext, aad)
            .map_err(|_| E2eError::Hpke("seal failed"))?;
    Ok((enc.to_bytes().to_vec(), ct))
}

#[cfg(test)]
pub(crate) fn seal_with_rng<R: hpke::rand_core::CryptoRng>(
    recipient_pk: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), E2eError> {
    let pk =
        PublicKey::from_bytes(recipient_pk).map_err(|_| E2eError::Hpke("invalid public key"))?;
    let (enc, ct) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
        rng,
    )
    .map_err(|_| E2eError::Hpke("seal_with_rng failed"))?;
    Ok((enc.to_bytes().to_vec(), ct))
}

/// Open `ciphertext` with `recipient_sk` and `enc` in HPKE Base mode.
pub fn open(
    recipient_sk: &SecretKeyBytes,
    enc: &[u8],
    kind: EnvelopeKind,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, E2eError> {
    let info = info_for_kind(kind);
    open_with_info(recipient_sk, enc, &info, aad, ciphertext)
}

pub fn open_with_info(
    recipient_sk: &SecretKeyBytes,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, E2eError> {
    let sk = PrivateKey::from_bytes(recipient_sk.as_bytes())
        .map_err(|_| E2eError::Hpke("invalid private key"))?;
    let encapped =
        EncappedKey::from_bytes(enc).map_err(|_| E2eError::Hpke("invalid encapped key"))?;
    let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        info,
        ciphertext,
        aad,
    )
    .map_err(|_| E2eError::Hpke("open failed"))?;
    Ok(Zeroizing::new(pt))
}

/// Build the message-signing input `"xmsg-e2e-sig/1\0" || transcript || enc || SHA-256(ct)`.
pub fn signing_payload(transcript_bytes: &[u8], enc: &[u8], ct: &[u8]) -> Vec<u8> {
    let ct_digest: [u8; 32] = Sha256::digest(ct).into();
    let mut out = Vec::with_capacity(SIG_DOMAIN.len() + transcript_bytes.len() + enc.len() + 32);
    out.extend_from_slice(SIG_DOMAIN);
    out.extend_from_slice(transcript_bytes);
    out.extend_from_slice(enc);
    out.extend_from_slice(&ct_digest);
    out
}

/// Sign a sealed envelope payload with an Ed25519 PKCS#8 v2 keypair (`ring`).
pub fn sign_envelope(
    pkcs8_der: &Zeroizing<Vec<u8>>,
    transcript_bytes: &[u8],
    enc: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, E2eError> {
    let keypair =
        Ed25519KeyPair::from_pkcs8(pkcs8_der).map_err(|_| E2eError::Signature("invalid key"))?;
    let payload = signing_payload(transcript_bytes, enc, ct);
    Ok(keypair.sign(&payload).as_ref().to_vec())
}

/// Verify a sealed envelope signature against an Ed25519 32-byte raw public key.
pub fn verify_envelope(
    sig_pk: &[u8; 32],
    transcript_bytes: &[u8],
    enc: &[u8],
    ct: &[u8],
    signature: &[u8],
) -> Result<(), E2eError> {
    let payload = signing_payload(transcript_bytes, enc, ct);
    UnparsedPublicKey::new(&ED25519, sig_pk)
        .verify(&payload, signature)
        .map_err(|_| E2eError::Signature("signature verification failed"))
}

/// Generate a fresh Ed25519 PKCS#8 v2 keypair (wrapped in `Zeroizing`) and raw 32-byte public key.
pub fn generate_signing_keypair() -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), E2eError> {
    let rng = ring::rand::SystemRandom::new();
    let doc =
        Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| E2eError::Signature("keygen failed"))?;
    let pkcs8 = Zeroizing::new(doc.as_ref().to_vec());
    let kp = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| E2eError::Signature("invalid generated key"))?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.public_key().as_ref());
    Ok((pkcs8, pk))
}
