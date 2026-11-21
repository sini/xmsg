use std::ptr;

use serde_json::Value as JsonValue;
use zeroize::{Zeroize, Zeroizing};

use super::blob::{
    open_blob, seal_blob_with_prefix, verify_range, CHUNK_SIZE, NONCE_PREFIX_LEN, TAG_SIZE,
};
use super::suite::{
    derive_keypair, generate_keypair, generate_signing_keypair, kid_for_key, open, open_with_info,
    seal, seal_with_rng, sign_envelope, verify_envelope, EnvelopeKind, SecretKeyBytes, SUITE_IDS,
};
use super::transcript::{
    CustodyMode, DelegationEntry, RecordPayload, Transcript, RECORD_DOMAIN, TRANSCRIPT_PROTOCOL,
};

struct FixedBytesRng<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> hpke::rand_core::TryRng for FixedBytesRng<'a> {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.pos + dst.len();
        assert!(end <= self.bytes.len(), "FixedBytesRng exhausted");
        dst.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

impl<'a> hpke::rand_core::TryCryptoRng for FixedBytesRng<'a> {}

fn decode_hex_32(s: &str) -> [u8; 32] {
    let raw = hex::decode(s).expect("valid hex");
    raw.try_into().expect("32 bytes")
}

#[test]
fn rfc9180_hpke_base_mode_vector() {
    let raw = include_str!("../../tests/fixtures/e2e-hpke-vectors.json");
    let doc: JsonValue = serde_json::from_str(raw).expect("valid hpke vector json");
    let vec0 = &doc["vectors"][0];

    let info = hex::decode(vec0["info"].as_str().unwrap()).unwrap();
    let ikm_e = hex::decode(vec0["ikmE"].as_str().unwrap()).unwrap();
    let ikm_r = hex::decode(vec0["ikmR"].as_str().unwrap()).unwrap();
    let expected_sk_rm = decode_hex_32(vec0["skRm"].as_str().unwrap());
    let expected_pk_rm = decode_hex_32(vec0["pkRm"].as_str().unwrap());
    let expected_enc = hex::decode(vec0["enc"].as_str().unwrap()).unwrap();

    let (mut sk_rm, pk_rm) = derive_keypair(&ikm_r);
    assert_eq!(sk_rm.as_bytes(), &expected_sk_rm);
    assert_eq!(pk_rm, expected_pk_rm);

    let enc0 = &vec0["encryptions"][0];
    let aad0 = hex::decode(enc0["aad"].as_str().unwrap()).unwrap();
    let ct0 = hex::decode(enc0["ct"].as_str().unwrap()).unwrap();
    let pt0 = hex::decode(enc0["pt"].as_str().unwrap()).unwrap();

    // Deterministic seal_with_rng matches RFC 9180 enc and ct0 verbatim.
    let mut rng = FixedBytesRng {
        bytes: &ikm_e,
        pos: 0,
    };
    let (sealed_enc, sealed_ct) =
        seal_with_rng(&pk_rm, &info, &aad0, &pt0, &mut rng).expect("seal_with_rng");
    assert_eq!(sealed_enc, expected_enc);
    assert_eq!(sealed_ct, ct0);

    let opened0 =
        open_with_info(&sk_rm, &expected_enc, &info, &aad0, &ct0).expect("open_with_info");
    assert_eq!(opened0.as_slice(), pt0.as_slice());

    // Negative controls: wrong aad, flipped ct byte, wrong recipient sk.
    assert!(open_with_info(&sk_rm, &expected_enc, &info, b"wrong-aad", &ct0).is_err());
    let mut bad_ct = ct0.clone();
    bad_ct[0] ^= 0x01;
    assert!(open_with_info(&sk_rm, &expected_enc, &info, &aad0, &bad_ct).is_err());
    let (other_sk, _) = derive_keypair(&[0x42u8; 32]);
    assert!(open_with_info(&other_sk, &expected_enc, &info, &aad0, &ct0).is_err());

    // Live zeroization of decoded vector secret.
    sk_rm.zeroize_in_place();
    for i in 0..32 {
        let b = unsafe { ptr::read_volatile(sk_rm.as_bytes().as_ptr().add(i)) };
        assert_eq!(b, 0);
    }
}

#[test]
fn hpke_os_rng_seal_and_open_roundtrip() {
    let (sk_r, pk_r) = generate_keypair().expect("generate_keypair");
    let aad = b"transcript-aad";
    let pt = b"hello xmsg e2e";
    let (enc, ct) = seal(&pk_r, EnvelopeKind::Message, aad, pt).expect("seal");
    let opened = open(&sk_r, &enc, EnvelopeKind::Message, aad, &ct).expect("open");
    assert_eq!(opened.as_slice(), pt);
    // Domain separation across EnvelopeKind.
    assert!(open(&sk_r, &enc, EnvelopeKind::Reply, aad, &ct).is_err());
}

#[test]
fn zeroize_live_buffers_in_place() {
    let mut sk = SecretKeyBytes::new([0xA5; 32]);
    let before = unsafe { ptr::read_volatile(sk.as_bytes().as_ptr()) };
    assert_eq!(before, 0xA5);
    sk.zeroize_in_place();
    for i in 0..32 {
        let b = unsafe { ptr::read_volatile(sk.as_bytes().as_ptr().add(i)) };
        assert_eq!(b, 0, "SecretKeyBytes byte {i} not zeroized");
    }

    let (mut pkcs8, sig_pk) = generate_signing_keypair().expect("generate_signing_keypair");
    assert!(!pkcs8.is_empty());
    assert_ne!(sig_pk, [0u8; 32]);
    let len = pkcs8.len();
    pkcs8.zeroize();
    for i in 0..len {
        let b = unsafe { ptr::read_volatile(pkcs8.as_ptr().add(i)) };
        assert_eq!(b, 0, "pkcs8 byte {i} not zeroized");
    }
}

#[test]
fn transcript_vector_roundtrip_and_tamper() {
    let raw = include_str!("../../tests/fixtures/e2e-transcript-vectors.json");
    let doc: JsonValue = serde_json::from_str(raw).expect("valid transcript json");
    let vec0 = &doc["vectors"][0];
    let cbor_bytes = hex::decode(vec0["cbor_hex"].as_str().unwrap()).unwrap();

    let decoded = Transcript::decode(&cbor_bytes).expect("decode transcript");
    assert_eq!(decoded.protocol, TRANSCRIPT_PROTOCOL);
    assert_eq!(decoded.kind, EnvelopeKind::Message);
    assert_eq!(decoded.suite, SUITE_IDS);
    assert_eq!(decoded.sender, vec0["sender"].as_str().unwrap());
    assert_eq!(decoded.recipient, vec0["recipient"].as_str().unwrap());
    assert_eq!(decoded.target_ref, vec0["target_ref"].as_str().unwrap());
    assert_eq!(decoded.message_id, vec0["message_id"].as_str().unwrap());
    assert_eq!(decoded.in_reply_to, None);
    assert_eq!(
        decoded.sender_sig_kid,
        decode_hex_32(vec0["sender_sig_kid_hex"].as_str().unwrap())
    );
    assert_eq!(decoded.sender_gen, vec0["sender_gen"].as_u64().unwrap());
    assert_eq!(
        decoded.recipient_kem_kid,
        decode_hex_32(vec0["recipient_kem_kid_hex"].as_str().unwrap())
    );
    assert_eq!(decoded.created_at, vec0["created_at"].as_i64().unwrap());
    assert_eq!(decoded.expires_at, vec0["expires_at"].as_i64().unwrap());
    assert_eq!(
        decoded.refs_digest,
        decode_hex_32(vec0["refs_digest_hex"].as_str().unwrap())
    );
    assert_eq!(decoded.status_attempt_digest, None);

    // Canonical re-encode matches fixture byte-for-byte.
    let reencoded = decoded.encode().expect("reencode transcript");
    assert_eq!(reencoded, cbor_bytes);

    // Mutating message_id changes transcript bytes (supports M-aad-id).
    let mut changed = decoded.clone();
    changed.message_id = "01M7XTFT021YD9WXAQE3Y7PZPF".to_owned();
    assert_ne!(changed.encode().unwrap(), reencoded);

    // Non-canonical CBOR (e.g. non-shortest integer encoding for protocol 1: 0x18 0x01) is rejected.
    let mut non_canon = cbor_bytes.clone();
    non_canon[1] = 0x18;
    non_canon.insert(2, 0x01);
    assert!(Transcript::decode(&non_canon).is_err());

    // Envelope signing over "xmsg-e2e-sig/1\0" || T || enc || SHA-256(ct) (supports M-skip-sig).
    let (pkcs8, sig_pk) = generate_signing_keypair().expect("signing keypair");
    let (_, kem_pk) = generate_keypair().expect("kem keypair");
    let (enc, ct) = seal(&kem_pk, EnvelopeKind::Message, &reencoded, b"secret").expect("seal");
    let sig = sign_envelope(&pkcs8, &reencoded, &enc, &ct).expect("sign_envelope");
    verify_envelope(&sig_pk, &reencoded, &enc, &ct, &sig).expect("verify_envelope");

    // Tampered ct, enc, transcript, or wrong pk fails verify_envelope.
    let mut bad_ct = ct.clone();
    bad_ct[0] ^= 0x80;
    assert!(verify_envelope(&sig_pk, &reencoded, &enc, &bad_ct, &sig).is_err());
    let bad_t = changed.encode().unwrap();
    assert!(verify_envelope(&sig_pk, &bad_t, &enc, &ct, &sig).is_err());
    let (_, other_sig_pk) = generate_signing_keypair().expect("other signing keypair");
    assert!(verify_envelope(&other_sig_pk, &reencoded, &enc, &ct, &sig).is_err());
}

#[test]
fn record_vector_roundtrip_and_tamper() {
    let raw = include_str!("../../tests/fixtures/e2e-record-vectors.json");
    let doc: JsonValue = serde_json::from_str(raw).expect("valid record json");
    let vec0 = &doc["vectors"][0];
    let cbor_bytes = hex::decode(vec0["cbor_hex"].as_str().unwrap()).unwrap();

    let decoded = RecordPayload::decode(&cbor_bytes).expect("decode record");
    assert_eq!(decoded.domain, RECORD_DOMAIN);
    assert_eq!(decoded.identity, vec0["identity"].as_str().unwrap());
    assert_eq!(decoded.gen, vec0["gen"].as_u64().unwrap());
    assert_eq!(
        decoded.kem_pk,
        decode_hex_32(vec0["kem_pk_hex"].as_str().unwrap())
    );
    assert_eq!(decoded.kem_kid, kid_for_key(&decoded.kem_pk));
    assert_eq!(
        decoded.sig_pk,
        decode_hex_32(vec0["sig_pk_hex"].as_str().unwrap())
    );
    assert_eq!(decoded.sig_kid, kid_for_key(&decoded.sig_pk));
    assert_eq!(decoded.custody, CustodyMode::Durable);
    assert_eq!(decoded.delegations.len(), 1);
    assert_eq!(
        decoded.delegations[0].sig_pk,
        decode_hex_32(vec0["delegation_sig_pk_hex"].as_str().unwrap())
    );
    assert_eq!(
        decoded.delegations[0].sig_kid,
        kid_for_key(&decoded.delegations[0].sig_pk)
    );
    assert_eq!(
        decoded.cert_chain,
        vec![hex::decode(vec0["cert_hex"].as_str().unwrap()).unwrap()]
    );

    assert_eq!(decoded.encode().expect("reencode record"), cbor_bytes);

    // Broken kid is rejected on encode.
    let mut bad_kid = decoded.clone();
    bad_kid.kem_kid[0] ^= 0xff;
    assert!(bad_kid.encode().is_err());

    // Wrong domain is rejected on decode.
    let mut wrong_domain = decoded.clone();
    wrong_domain.domain = "xmsg-e2e-record/2".to_owned();
    assert!(wrong_domain.encode().is_err());

    // Trailing byte is rejected on decode.
    let mut trailing = cbor_bytes.clone();
    trailing.push(0x00);
    assert!(RecordPayload::decode(&trailing).is_err());

    // Non-empty DelegationEntry + CustodyMode::Ephemeral sanity check.
    let _ = DelegationEntry {
        sig_kid: decoded.delegations[0].sig_kid,
        sig_pk: decoded.delegations[0].sig_pk,
        gen: 2,
        sign_from: 10,
        sign_until: 20,
    };
}

#[test]
fn blob_vectors_empty_exact_boundary_and_range() {
    let raw = include_str!("../../tests/fixtures/e2e-blob-vectors.json");
    let doc: JsonValue = serde_json::from_str(raw).expect("valid blob json");
    let file_key = Zeroizing::new(decode_hex_32(doc["file_key_hex"].as_str().unwrap()));
    let prefix_vec = hex::decode(doc["nonce_prefix_hex"].as_str().unwrap()).unwrap();
    let nonce_prefix: [u8; NONCE_PREFIX_LEN] = prefix_vec.try_into().unwrap();

    // 1. Empty 0-byte blob produces 1 final chunk of TAG_SIZE (16 bytes) and opens to b"".
    let empty_msg = doc["empty"]["message_id"].as_str().unwrap();
    let empty_idx = doc["empty"]["attachment_index"].as_u64().unwrap() as u32;
    let empty_blob = seal_blob_with_prefix(&file_key, empty_msg, empty_idx, &[], nonce_prefix)
        .expect("seal empty blob");
    assert_eq!(empty_blob.chunks.len(), 1);
    assert_eq!(empty_blob.chunks[0].len(), TAG_SIZE);
    assert_eq!(
        hex::encode(empty_blob.header.to_bytes()),
        doc["empty"]["header_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&empty_blob.chunks[0]),
        doc["empty"]["chunk0_hex"].as_str().unwrap()
    );
    assert_eq!(
        open_blob(&file_key, empty_msg, empty_idx, &empty_blob).expect("open empty"),
        Vec::<u8>::new()
    );

    // 2. Exact 64 KiB boundary (1 full chunk).
    let exact_one = vec![0x5Au8; CHUNK_SIZE];
    let exact_blob =
        seal_blob_with_prefix(&file_key, "msg-exact", 0, &exact_one, nonce_prefix).unwrap();
    assert_eq!(exact_blob.chunks.len(), 1);
    assert_eq!(exact_blob.chunks[0].len(), CHUNK_SIZE + TAG_SIZE);
    assert_eq!(
        open_blob(&file_key, "msg-exact", 0, &exact_blob).unwrap(),
        exact_one
    );

    // 3. Multi-chunk blob (> 2 * 64 KiB) matching fixture header and final chunk.
    let multi_msg = doc["multi"]["message_id"].as_str().unwrap();
    let multi_idx = doc["multi"]["attachment_index"].as_u64().unwrap() as u32;
    let multi_len = doc["multi"]["plaintext_len"].as_u64().unwrap() as usize;
    let multi_pt: Vec<u8> = (0..multi_len).map(|i| (i % 251) as u8).collect();
    let multi_blob =
        seal_blob_with_prefix(&file_key, multi_msg, multi_idx, &multi_pt, nonce_prefix)
            .expect("seal multi");
    assert_eq!(
        multi_blob.chunks.len(),
        doc["multi"]["chunk_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        hex::encode(multi_blob.header.to_bytes()),
        doc["multi"]["header_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&multi_blob.chunks[2]),
        doc["multi"]["chunk2_hex"].as_str().unwrap()
    );
    assert_eq!(
        open_blob(&file_key, multi_msg, multi_idx, &multi_blob).unwrap(),
        multi_pt
    );

    // Truncated chunk list is refused.
    let mut truncated = multi_blob.clone();
    truncated.chunks.pop();
    assert!(open_blob(&file_key, multi_msg, multi_idx, &truncated).is_err());

    // Wrong attachment index or message_id is refused (AAD binding).
    assert!(open_blob(&file_key, multi_msg, multi_idx + 1, &multi_blob).is_err());
    assert!(open_blob(&file_key, "wrong-msg", multi_idx, &multi_blob).is_err());

    // 4. Range verification: offset 0, cross-chunk boundary, ending at EOF, complete == false.
    let chunk_refs: Vec<(usize, &[u8])> = multi_blob
        .chunks
        .iter()
        .enumerate()
        .map(|(i, c)| (i, c.as_slice()))
        .collect();

    let r0 = verify_range(
        &file_key,
        multi_msg,
        multi_idx,
        &multi_blob.header,
        &chunk_refs,
        0,
        32,
    )
    .expect("range at 0");
    assert!(!r0.complete);
    assert_eq!(r0.offset, 0);
    assert_eq!(r0.plaintext, multi_pt[0..32]);

    let cross_off = CHUNK_SIZE as u64 - 6;
    let r_cross = verify_range(
        &file_key,
        multi_msg,
        multi_idx,
        &multi_blob.header,
        &chunk_refs,
        cross_off,
        12,
    )
    .expect("cross-chunk range");
    assert!(!r_cross.complete);
    assert_eq!(
        r_cross.plaintext,
        multi_pt[(CHUNK_SIZE - 6)..(CHUNK_SIZE + 6)]
    );

    let eof_off = (multi_len - 10) as u64;
    let r_eof = verify_range(
        &file_key,
        multi_msg,
        multi_idx,
        &multi_blob.header,
        &chunk_refs,
        eof_off,
        10,
    )
    .expect("eof range");
    assert!(!r_eof.complete);
    assert_eq!(r_eof.plaintext, multi_pt[(multi_len - 10)..multi_len]);

    // Out-of-bounds range is refused.
    assert!(verify_range(
        &file_key,
        multi_msg,
        multi_idx,
        &multi_blob.header,
        &chunk_refs,
        eof_off,
        11,
    )
    .is_err());
}
