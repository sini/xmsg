use crate::e2e::E2eError;
use aead_stream::{DecryptorBE32, EncryptorBE32, NewStream, StreamBE32};
use chacha20poly1305::{
    aead::{KeyInit, Payload},
    ChaCha20Poly1305,
};
use getrandom::fill as getrandom_fill;
use zeroize::Zeroizing;

pub const BLOB_MAGIC: &[u8] = b"xmsg-blob/1";
pub const CHUNK_SIZE: usize = 65_536;
pub const TAG_SIZE: usize = 16;
pub const NONCE_PREFIX_LEN: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobHeader {
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub plaintext_len: u64,
    pub chunk_size: u32,
}

impl BlobHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BLOB_MAGIC.len() + NONCE_PREFIX_LEN + 8 + 4);
        out.extend_from_slice(BLOB_MAGIC);
        out.extend_from_slice(&self.nonce_prefix);
        out.extend_from_slice(&self.plaintext_len.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, E2eError> {
        let expected = BLOB_MAGIC.len() + NONCE_PREFIX_LEN + 8 + 4;
        if bytes.len() != expected || &bytes[..BLOB_MAGIC.len()] != BLOB_MAGIC {
            return Err(E2eError::Blob("invalid blob header"));
        }
        let mut off = BLOB_MAGIC.len();
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&bytes[off..off + NONCE_PREFIX_LEN]);
        off += NONCE_PREFIX_LEN;
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bytes[off..off + 8]);
        let plaintext_len = u64::from_be_bytes(len_bytes);
        off += 8;
        let mut cs_bytes = [0u8; 4];
        cs_bytes.copy_from_slice(&bytes[off..off + 4]);
        let chunk_size = u32::from_be_bytes(cs_bytes);
        if chunk_size as usize != CHUNK_SIZE {
            return Err(E2eError::Blob("unsupported chunk size"));
        }
        Ok(Self {
            nonce_prefix,
            plaintext_len,
            chunk_size,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlob {
    pub header: BlobHeader,
    pub chunks: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRange {
    pub offset: u64,
    pub plaintext: Vec<u8>,
    /// Partial range reads never claim whole-file completion.
    pub complete: bool,
}

pub fn chunk_aad(header: &BlobHeader, message_id: &str, index: u32) -> Vec<u8> {
    let hdr = header.to_bytes();
    let mut aad = Vec::with_capacity(BLOB_MAGIC.len() + hdr.len() + message_id.len() + 4);
    aad.extend_from_slice(BLOB_MAGIC);
    aad.extend_from_slice(&hdr);
    aad.extend_from_slice(message_id.as_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

pub fn generate_file_key() -> Result<Zeroizing<[u8; 32]>, E2eError> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom_fill(&mut *key).map_err(|_| E2eError::Rng)?;
    Ok(key)
}

pub fn seal_blob(
    key: &Zeroizing<[u8; 32]>,
    message_id: &str,
    attachment_index: u32,
    plaintext: &[u8],
) -> Result<SealedBlob, E2eError> {
    let mut prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom_fill(&mut prefix).map_err(|_| E2eError::Rng)?;
    seal_blob_with_prefix(key, message_id, attachment_index, plaintext, prefix)
}

pub fn seal_blob_with_prefix(
    key: &Zeroizing<[u8; 32]>,
    message_id: &str,
    attachment_index: u32,
    plaintext: &[u8],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
) -> Result<SealedBlob, E2eError> {
    let header = BlobHeader {
        nonce_prefix,
        plaintext_len: plaintext.len() as u64,
        chunk_size: CHUNK_SIZE as u32,
    };
    let cipher = ChaCha20Poly1305::new((&**key).into());
    let stream = StreamBE32::from_aead(cipher, (&nonce_prefix).into());
    let mut encryptor = EncryptorBE32::from_stream_primitive(stream);
    let aad = chunk_aad(&header, message_id, attachment_index);

    let mut chunks = Vec::new();
    if plaintext.is_empty() {
        let last = encryptor
            .encrypt_last(Payload {
                msg: &[],
                aad: &aad,
            })
            .map_err(|_| E2eError::Blob("encrypt empty final chunk"))?;
        chunks.push(last);
        return Ok(SealedBlob { header, chunks });
    }

    let mut all_chunks: Vec<&[u8]> = plaintext.chunks(CHUNK_SIZE).collect();
    let last_slice = all_chunks.pop().unwrap_or(&[]);
    for slice in all_chunks {
        let ct = encryptor
            .encrypt_next(Payload {
                msg: slice,
                aad: &aad,
            })
            .map_err(|_| E2eError::Blob("encrypt_next failed"))?;
        chunks.push(ct);
    }
    let last_ct = encryptor
        .encrypt_last(Payload {
            msg: last_slice,
            aad: &aad,
        })
        .map_err(|_| E2eError::Blob("encrypt_last failed"))?;
    chunks.push(last_ct);
    Ok(SealedBlob { header, chunks })
}

pub fn expected_chunk_count(plaintext_len: u64) -> usize {
    if plaintext_len == 0 {
        1
    } else {
        (plaintext_len as usize).div_ceil(CHUNK_SIZE)
    }
}

pub fn open_blob(
    key: &Zeroizing<[u8; 32]>,
    message_id: &str,
    attachment_index: u32,
    sealed: &SealedBlob,
) -> Result<Vec<u8>, E2eError> {
    let expected = expected_chunk_count(sealed.header.plaintext_len);
    if sealed.chunks.len() != expected {
        return Err(E2eError::Blob("truncated or extra chunks"));
    }
    let cipher = ChaCha20Poly1305::new((&**key).into());
    let stream = StreamBE32::from_aead(cipher, (&sealed.header.nonce_prefix).into());
    let mut decryptor = DecryptorBE32::from_stream_primitive(stream);
    let aad = chunk_aad(&sealed.header, message_id, attachment_index);

    let mut out = Vec::with_capacity(sealed.header.plaintext_len as usize);
    let (last_ct, mid_cts) = sealed
        .chunks
        .split_last()
        .ok_or(E2eError::Blob("empty chunk list"))?;
    for ct in mid_cts {
        let pt = decryptor
            .decrypt_next(Payload {
                msg: ct.as_slice(),
                aad: &aad,
            })
            .map_err(|_| E2eError::Blob("decrypt_next failed"))?;
        out.extend_from_slice(&pt);
    }
    let last_pt = decryptor
        .decrypt_last(Payload {
            msg: last_ct.as_slice(),
            aad: &aad,
        })
        .map_err(|_| E2eError::Blob("decrypt_last failed"))?;
    out.extend_from_slice(&last_pt);
    if out.len() as u64 != sealed.header.plaintext_len {
        return Err(E2eError::Blob("plaintext length mismatch"));
    }
    Ok(out)
}

/// Authenticate and slice `[offset..offset+len)` across the covered `StreamBE32` chunks.
/// Never claims whole-file completion (`complete: false`).
pub fn verify_range(
    key: &Zeroizing<[u8; 32]>,
    message_id: &str,
    attachment_index: u32,
    header: &BlobHeader,
    chunks: &[(usize, &[u8])],
    offset: u64,
    len: usize,
) -> Result<VerifiedRange, E2eError> {
    let end = offset
        .checked_add(len as u64)
        .ok_or(E2eError::RangeOutOfBounds)?;
    if end > header.plaintext_len {
        return Err(E2eError::RangeOutOfBounds);
    }
    if len == 0 {
        return Ok(VerifiedRange {
            offset,
            plaintext: Vec::new(),
            complete: false,
        });
    }

    let total_chunks = expected_chunk_count(header.plaintext_len);
    let first_chunk = (offset as usize) / CHUNK_SIZE;
    let last_chunk = ((end - 1) as usize) / CHUNK_SIZE;
    let aad = chunk_aad(header, message_id, attachment_index);
    let cipher = ChaCha20Poly1305::new((&**key).into());

    let mut assembled = Vec::new();
    for chunk_idx in first_chunk..=last_chunk {
        let (_, ct) = chunks
            .iter()
            .find(|(idx, _)| *idx == chunk_idx)
            .ok_or(E2eError::Blob("missing chunk for range"))?;
        let is_last = chunk_idx + 1 == total_chunks;
        let pt = decrypt_single_chunk(
            &cipher,
            &header.nonce_prefix,
            &aad,
            chunk_idx as u32,
            is_last,
            ct,
        )?;
        let chunk_start = (chunk_idx * CHUNK_SIZE) as u64;
        let slice_start = offset.saturating_sub(chunk_start) as usize;
        let slice_end = (end - chunk_start).min(pt.len() as u64) as usize;
        assembled.extend_from_slice(&pt[slice_start..slice_end]);
    }

    Ok(VerifiedRange {
        offset,
        plaintext: assembled,
        complete: false,
    })
}

fn decrypt_single_chunk(
    cipher: &ChaCha20Poly1305,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    aad: &[u8],
    chunk_idx: u32,
    is_last: bool,
    ct: &[u8],
) -> Result<Vec<u8>, E2eError> {
    use chacha20poly1305::aead::{Aead, Payload};
    let mut nonce = [0u8; 12];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
    nonce[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&chunk_idx.to_be_bytes());
    nonce[11] = u8::from(is_last);
    cipher
        .decrypt((&nonce).into(), Payload { msg: ct, aad })
        .map_err(|_| E2eError::Blob("range chunk authentication failed"))
}
