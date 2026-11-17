use ring::signature::Ed25519KeyPair;
use serde::Deserialize;
use xmsg::pairing::codec::{
    authorize_grant_operation, build_signed_receipt, decode_deterministic_cbor, decode_frame,
    encode_deterministic_cbor, encode_frame, external_aad, parse_and_verify_receipt,
    validate_ceremony_times, CodecError, ExposurePolicy, GrantSummary, HelloI, Offer,
    PairingProfile, Receipt, ReceiptVerificationContext, SignerRole, SpkiDeviceId, Transcript,
    MAX_FRAME_BYTES,
};

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "publicKeys")]
    public_keys: Vec<String>,
    spki: Vec<String>,
    #[serde(rename = "deviceIDs")]
    device_ids: Vec<String>,
    exposures: Vec<ExposureVector>,
    exporter: String,
    transcript: String,
    #[serde(rename = "transactionID")]
    transaction_id: String,
    #[serde(rename = "externalAAD")]
    external_aad: String,
    receipts: Vec<ReceiptVector>,
    cases: Vec<CaseVector>,
}

#[derive(Deserialize)]
struct ExposureVector {
    decoded: serde_json::Value,
    #[serde(rename = "canonicalCBOR")]
    canonical_cbor: String,
    sha256: String,
}

#[derive(Deserialize)]
struct ReceiptVector {
    #[serde(rename = "protectedBytes")]
    _protected_bytes: String,
    #[serde(rename = "payloadBytes")]
    payload_bytes: String,
    #[serde(rename = "sigStructure")]
    _sig_structure: String,
    #[serde(rename = "signature")]
    _signature: String,
    cose: String,
}

#[derive(Deserialize)]
struct CaseVector {
    name: String,
    expected: String,
    #[serde(default)]
    error: Option<String>,
    inputs: serde_json::Value,
}

fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in fixture")
}

fn hex_32(s: &str) -> [u8; 32] {
    hex_bytes(s).try_into().expect("32-byte hex")
}

fn seq_32(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

fn seq_16(start: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

fn fixture_seeds() -> [[u8; 32]; 2] {
    [
        hex_32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        hex_32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
    ]
}

fn keypair_from_seed_and_pub(seed: &[u8; 32], pub_bytes: &[u8; 32]) -> Ed25519KeyPair {
    let kp = Ed25519KeyPair::from_seed_and_public_key(seed, pub_bytes)
        .expect("valid ed25519 seed and public key");
    assert_eq!(
        ring::signature::KeyPair::public_key(&kp).as_ref(),
        pub_bytes
    );
    kp
}

#[test]
fn pairing_vectors_byte_for_byte_and_all_cases() {
    let raw = include_str!("fixtures/pairing-vectors.json");
    let vecs: VectorFile = serde_json::from_str(raw).expect("parse pairing-vectors.json");

    assert_eq!(vecs.spki.len(), 2);
    assert_eq!(vecs.device_ids.len(), 2);
    assert_eq!(vecs.exposures.len(), 2);
    assert_eq!(vecs.receipts.len(), 2);
    assert_eq!(vecs.cases.len(), 33);

    let spki_0 = hex_bytes(&vecs.spki[0]);
    let spki_1 = hex_bytes(&vecs.spki[1]);
    let id_0 = SpkiDeviceId::from_spki_der(&spki_0).expect("spki 0");
    let id_1 = SpkiDeviceId::from_spki_der(&spki_1).expect("spki 1");
    assert_eq!(id_0.to_device_id_string(), vecs.device_ids[0]);
    assert_eq!(id_1.to_device_id_string(), vecs.device_ids[1]);
    assert_eq!(
        SpkiDeviceId::parse_device_id_string(&vecs.device_ids[0]).unwrap(),
        id_0
    );
    assert_eq!(
        SpkiDeviceId::parse_device_id_string(&vecs.device_ids[1]).unwrap(),
        id_1
    );

    // Exposures
    let mut exposure_hashes = Vec::new();
    for ev in &vecs.exposures {
        let profile = PairingProfile::parse(ev.decoded["2"].as_str().unwrap()).unwrap();
        let targets: Vec<String> = ev.decoded["3"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let principals: Vec<String> = ev.decoded["4"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let pol = ExposurePolicy {
            profile,
            target_selectors: targets,
            principal_selectors: principals,
            max_body_bytes: ev.decoded["5"].as_u64().unwrap() as u32,
            max_attachment_bytes: ev.decoded["6"].as_u64().unwrap() as u32,
            rate_burst: ev.decoded["7"].as_u64().unwrap() as u32,
            rate_per_minute: ev.decoded["8"].as_u64().unwrap() as u32,
        };
        let encoded = pol.encode_cbor().expect("encode exposure");
        assert_eq!(encoded, hex_bytes(&ev.canonical_cbor));
        let digest = pol.sha256().expect("exposure sha256");
        assert_eq!(digest, hex_32(&ev.sha256));
        assert_eq!(ExposurePolicy::decode_cbor(&encoded).unwrap(), pol);
        exposure_hashes.push(digest);
    }

    let exporter = hex_32(&vecs.exporter);
    let offer_i = Offer {
        profile: PairingProfile::Contact,
        grant_not_after: None,
        exposure_policy_sha256: exposure_hashes[0],
    };
    let offer_r = Offer {
        profile: PairingProfile::OwnerDevice,
        grant_not_after: None,
        exposure_policy_sha256: exposure_hashes[1],
    };

    let transcript = Transcript {
        id_i: id_0.0,
        id_r: id_1.0,
        nonce_i: seq_32(0),
        nonce_r: seq_32(32),
        offer_i,
        offer_r,
        created_utc: 1_700_000_000,
        ceremony_expires_utc: 1_700_000_120,
        policy_i: 7,
        policy_r: 9,
        exporter,
        attempt_i: seq_16(0xa0),
        attempt_r: seq_16(0xb0),
    };
    let t_bytes = transcript.encode_cbor().expect("encode transcript");
    assert_eq!(t_bytes, hex_bytes(&vecs.transcript));
    assert_eq!(Transcript::decode_cbor(&t_bytes).unwrap(), transcript);

    let tx_id = transcript.transaction_id().expect("transaction_id");
    assert_eq!(tx_id, hex_32(&vecs.transaction_id));

    let aad = external_aad(&exporter).expect("external_aad");
    assert_eq!(aad, hex_bytes(&vecs.external_aad));

    // Build and compare both COSE_Sign1 receipts byte-for-byte.
    let seeds = fixture_seeds();
    let kp0 = keypair_from_seed_and_pub(&seeds[0], &hex_32(&vecs.public_keys[0]));
    let kp1 = keypair_from_seed_and_pub(&seeds[1], &hex_32(&vecs.public_keys[1]));
    let kps = [&kp0, &kp1];

    for (role_idx, rv) in vecs.receipts.iter().enumerate() {
        let role = if role_idx == 0 {
            SignerRole::Initiator
        } else {
            SignerRole::Responder
        };
        let offer = if role_idx == 0 { offer_i } else { offer_r };
        let receipt = Receipt {
            transaction_id: tx_id,
            signer_role: role,
            signer_id: if role_idx == 0 { id_0.0 } else { id_1.0 },
            subject_id: if role_idx == 0 { id_1.0 } else { id_0.0 },
            profile: offer.profile,
            grant_not_after: offer.grant_not_after,
            exposure_policy_sha256: offer.exposure_policy_sha256,
            grant_id: [0xc1 + role_idx as u8; 16],
            issued_utc: 1_700_000_001,
            ceremony_expires_utc: 1_700_000_120,
            provenance: "manual_authenticated_oob".to_owned(),
            policy_revision: 7 + (role_idx as u32) * 2,
        };
        assert_eq!(
            receipt.encode_cbor().unwrap(),
            hex_bytes(&rv.payload_bytes),
            "receipt {role_idx} payloadBytes"
        );
        let cose = build_signed_receipt(&receipt, &exporter, kps[role_idx]).unwrap();
        assert_eq!(cose, hex_bytes(&rv.cose), "receipt {role_idx} cose");
    }

    // Execute all 33 cases.
    let mut accept_count = 0usize;
    let mut reject_count = 0usize;

    for case in &vecs.cases {
        let expect_accept = match case.expected.as_str() {
            "accept" => {
                accept_count += 1;
                true
            }
            "reject" => {
                reject_count += 1;
                false
            }
            other => panic!("unexpected expected value: {other}"),
        };

        if case.name == "RFC8032 test 1" {
            let sig = kp0.sign(&[]);
            assert_eq!(
                hex::encode(sig.as_ref()),
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            );
            assert!(expect_accept);
            continue;
        }

        if let Some(cbor_hex) = case.inputs.get("cbor").and_then(|v| v.as_str()) {
            let res = decode_deterministic_cbor(&hex_bytes(cbor_hex));
            assert_eq!(res.is_ok(), expect_accept, "case {}", case.name);
            continue;
        }

        if let (Some(hello_v), Some(t_v), Some(ctx_v)) = (
            case.inputs.get("HelloI"),
            case.inputs.get("T"),
            case.inputs.get("context"),
        ) {
            let res = validate_ceremony_times(
                hello_v["created"].as_u64().unwrap() as u32,
                hello_v["expires"].as_u64().unwrap() as u32,
                t_v["created"].as_u64().unwrap() as u32,
                t_v["expires"].as_u64().unwrap() as u32,
                ctx_v["intentDeadline"].as_u64().unwrap(),
                ctx_v["firstArrival"].as_u64().unwrap(),
                ctx_v["utcAtArrival"].as_u64().unwrap() as u32,
                ctx_v["monoNow"].as_u64().unwrap(),
                ctx_v["utcNow"].as_u64().unwrap() as u32,
            );
            assert_eq!(res.is_ok(), expect_accept, "case {}", case.name);
            continue;
        }

        if let (Some(grants_v), Some(op_v), Some(now_v)) = (
            case.inputs.get("grants"),
            case.inputs.get("operation"),
            case.inputs.get("now"),
        ) {
            let grants: Vec<GrantSummary> = grants_v
                .as_array()
                .unwrap()
                .iter()
                .map(|g| GrantSummary {
                    profile: PairingProfile::parse(g["profile"].as_str().unwrap()).unwrap(),
                    expires_utc: g["expires"].as_u64().unwrap() as u32,
                    provenance: g["provenance"].as_str().unwrap().to_owned(),
                })
                .collect();
            let actual = authorize_grant_operation(
                &grants,
                op_v.as_str().unwrap(),
                now_v.as_u64().unwrap() as u32,
            );
            assert_eq!(actual, expect_accept, "case {}", case.name);
            continue;
        }

        // Receipt verification case
        let cose_hex = case.inputs["cose"].as_str().expect("cose hex");
        let ctx_v = &case.inputs["context"];
        let ctx_exporter = hex_32(ctx_v["exporter"].as_str().unwrap());
        let ctx_tx = hex_32(
            ctx_v
                .get("tx")
                .or_else(|| ctx_v.get("transactionID"))
                .and_then(|v| v.as_str())
                .unwrap(),
        );
        let ctx_now = ctx_v["now"].as_u64().unwrap() as u32;
        let ctx_policy = ctx_v["currentPolicy"].as_u64().unwrap() as u32;
        let ctx_blocked = ctx_v["blocked"].as_bool().unwrap();
        let ctx_revoked = ctx_v["revoked"].as_bool().unwrap();
        let ctx_bilateral = ctx_v["bilateral"].as_bool().unwrap();

        let ctx = ReceiptVerificationContext {
            id_i: id_0.0,
            id_r: id_1.0,
            spki_i: &spki_0,
            spki_r: &spki_1,
            offer_i,
            offer_r,
            created_utc: 1_700_000_000,
            ceremony_expires_utc: 1_700_000_120,
            exporter: ctx_exporter,
            transaction_id: ctx_tx,
            now_utc: ctx_now,
            current_policy_i: ctx_policy,
            current_policy_r: ctx_policy,
            blocked: ctx_blocked,
            revoked: ctx_revoked,
            bilateral: ctx_bilateral,
        };

        let reps = case
            .inputs
            .get("repetitions")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        for _ in 0..reps {
            let res = parse_and_verify_receipt(&hex_bytes(cose_hex), &ctx);
            assert_eq!(
                res.is_ok(),
                expect_accept,
                "case {} (expected {}, error {:?}): got {:?}",
                case.name,
                case.expected,
                case.error,
                res
            );
            if !expect_accept {
                let err_msg = res.unwrap_err().to_string();
                assert!(!err_msg.is_empty(), "case {} missing error", case.name);
            }
        }
    }

    assert_eq!(accept_count, 8);
    assert_eq!(reject_count, 25);
}

#[test]
fn spki_and_cbor_edge_cases() {
    let raw = include_str!("fixtures/pairing-vectors.json");
    let vecs: VectorFile = serde_json::from_str(raw).expect("parse pairing-vectors.json");
    let spki_0 = hex_bytes(&vecs.spki[0]);
    let spki_1 = hex_bytes(&vecs.spki[1]);
    let id_0 = SpkiDeviceId::from_spki_der(&spki_0).unwrap();
    let id_1 = SpkiDeviceId::from_spki_der(&spki_1).unwrap();

    // Non-canonical SPKI (wrong prefix / extra bytes / wrong length)
    let mut bad_spki = spki_0.clone();
    bad_spki[0] = 0x31;
    assert!(matches!(
        SpkiDeviceId::from_spki_der(&bad_spki),
        Err(CodecError::InvalidSpki(_))
    ));
    assert!(matches!(
        SpkiDeviceId::from_spki_der(&spki_0[..43]),
        Err(CodecError::InvalidSpki(_))
    ));

    // Non-canonical device IDs (uppercase, wrong prefix, trailing non-zero bits)
    let valid_id = id_0.to_device_id_string();
    assert!(SpkiDeviceId::parse_device_id_string(&valid_id.to_uppercase()).is_err());
    assert!(SpkiDeviceId::parse_device_id_string("xmsg-spki2:aaa").is_err());
    let mut bad_bits = valid_id.clone();
    let last = bad_bits.pop().unwrap();
    // 'q' (16 = 0b10000) -> 'r' (17 = 0b10001) sets a non-zero trailing padding bit.
    bad_bits.push(if last == 'q' { 'r' } else { 'b' });
    assert!(SpkiDeviceId::parse_device_id_string(&bad_bits).is_err());

    // Frame size cap & trailing bytes
    let big = vec![0x40u8; MAX_FRAME_BYTES + 1];
    assert_eq!(encode_frame(&big), Err(CodecError::FrameTooLarge));
    let small_frame = encode_frame(&[0x01]).unwrap();
    assert_eq!(decode_frame(&small_frame).unwrap(), &[0x01]);
    let mut trailing = small_frame.clone();
    trailing.push(0x00);
    assert_eq!(decode_frame(&trailing), Err(CodecError::TruncatedFrame));

    // Map key sorting during encoding (unsorted input -> canonical sorted output)
    let unsorted = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::from(2),
            ciborium::value::Value::from("b"),
        ),
        (
            ciborium::value::Value::from(0),
            ciborium::value::Value::from("a"),
        ),
    ]);
    let encoded = encode_deterministic_cbor(&unsorted).unwrap();
    assert_eq!(encoded, vec![0xa2, 0x00, 0x61, b'a', 0x02, 0x61, b'b']);

    // HelloI round-trip
    let hello = HelloI {
        id_i: id_0.0,
        id_r: id_1.0,
        nonce_i: seq_32(1),
        attempt_i: seq_16(2),
        offer_i: Offer {
            profile: PairingProfile::Contact,
            grant_not_after: Some(1_800_000_000),
            exposure_policy_sha256: [0x55; 32],
        },
        created_utc: 1_700_000_000,
        ceremony_expires_utc: 1_700_000_060,
        policy_i: 3,
    };
    let hello_bytes = hello.encode_cbor().unwrap();
    assert_eq!(HelloI::decode_cbor(&hello_bytes).unwrap(), hello);

    // Wrong SPKI in verification context must fail
    let cose_0 = hex_bytes(&vecs.receipts[0].cose);
    let exporter = hex_32(&vecs.exporter);
    let tx_id = hex_32(&vecs.transaction_id);
    let offer_i = Offer {
        profile: PairingProfile::Contact,
        grant_not_after: None,
        exposure_policy_sha256: hex_32(&vecs.exposures[0].sha256),
    };
    let offer_r = Offer {
        profile: PairingProfile::OwnerDevice,
        grant_not_after: None,
        exposure_policy_sha256: hex_32(&vecs.exposures[1].sha256),
    };
    let wrong_spki_ctx = ReceiptVerificationContext {
        id_i: id_0.0,
        id_r: id_1.0,
        spki_i: &spki_1, // swapped SPKI!
        spki_r: &spki_1,
        offer_i,
        offer_r,
        created_utc: 1_700_000_000,
        ceremony_expires_utc: 1_700_000_120,
        exporter,
        transaction_id: tx_id,
        now_utc: 1_700_000_002,
        current_policy_i: 7,
        current_policy_r: 9,
        blocked: false,
        revoked: false,
        bilateral: true,
    };
    assert!(parse_and_verify_receipt(&cose_0, &wrong_spki_ctx).is_err());
}
