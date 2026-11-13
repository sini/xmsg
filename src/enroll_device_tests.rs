use super::*;
use rustls::pki_types::pem::PemObject;

async fn enabled() -> Harness {
    let harness = Harness::new().await;
    let mut policy = (*harness.service.ca.policy()).clone();
    policy
        .providers
        .insert("idp".into(), harness.idp.device_config(true));
    std::fs::write(
        harness._directory.path().join("policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    harness.service.ca.reload_policy().unwrap();
    harness.service.register_local_approval().unwrap();
    harness.idp.require_device_authorization();
    harness
}

async fn start(harness: &Harness, host: &str, ip: u8) -> (StatusCode, Value, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let (status, value) = harness
        .request(
            "POST",
            "/enroll/v1/sessions",
            json!({"csr_pem":csr,"host":host,"provider":"idp","flow":"device"}),
            None,
            ip,
        )
        .await;
    (status, value, key)
}

async fn authorized(harness: &Harness, created: &Value) -> Value {
    assert!(harness
        .idp
        .authorize_device(created["user_code"].as_str().unwrap()));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let (status, value) = harness
                .request(
                    "GET",
                    "/enroll/v1/sessions?wait=0",
                    Value::Null,
                    Some(created["session"].as_str().unwrap()),
                    1,
                )
                .await;
            assert_eq!(status, StatusCode::OK);
            if value["status"] != "pending" {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}

fn effects(harness: &Harness) -> Vec<i64> {
    let db = harness.db.lock().unwrap();
    ["enroll_bindings", "enroll_rates", "enroll_certs"]
        .iter()
        .map(|table| {
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
        })
        .collect()
}

fn approval(view: &Value) -> crate::enroll::ApprovalRequest {
    crate::enroll::ApprovalRequest {
        user: view["user"].as_str().unwrap().into(),
        host: view["host"].as_str().unwrap().into(),
        spki_sha256: view["spki_sha256"].as_str().unwrap().into(),
    }
}

#[tokio::test]
async fn signed_device_authorization_waits_for_exact_local_approval_and_collects_once() {
    let harness = enabled().await;
    let (status, created, key) = start(&harness, "remote", 1).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_ne!(created["session"], created["request_id"]);
    let value = authorized(&harness, &created).await;
    assert_eq!(
        value["status"], "awaiting_approval",
        "provider authorization bypassed CA approval"
    );
    assert_eq!(value["user"], "alice");
    assert_eq!(
        effects(&harness),
        [0, 0, 0],
        "provider authorization wrote authority state"
    );
    let views = serde_json::to_value(harness.service.pending_device_requests()).unwrap();
    let view = &views[0];
    assert_eq!(view["request_id"], created["request_id"]);
    assert_eq!(view["host"], "remote");
    let id = created["request_id"].as_str().unwrap();
    for field in ["user", "host", "spki_sha256"] {
        let mut wrong = view.clone();
        wrong[field] = json!("wrong");
        let failure = harness
            .service
            .approve_device(id, approval(&wrong))
            .expect_err("wrong approval accepted");
        assert_eq!(failure.0, StatusCode::FORBIDDEN);
        assert_eq!(effects(&harness), [0, 0, 0]);
    }
    harness
        .service
        .approve_device(id, approval(view))
        .unwrap_or_else(|error| panic!("approval refused: {}", error.1));
    assert_eq!(effects(&harness), [1, 1, 1]);
    assert!(
        harness.service.approve_device(id, approval(view)).is_err(),
        "approval was replayable"
    );
    assert_eq!(effects(&harness), [1, 1, 1]);
    let (status, collected) = harness
        .request(
            "GET",
            "/enroll/v1/sessions?wait=0",
            Value::Null,
            Some(created["session"].as_str().unwrap()),
            1,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let pem = rustls::pki_types::CertificateDer::from_pem_slice(
        collected["cert_chain_pem"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(pem.as_ref()).unwrap();
    assert_eq!(cert.public_key().raw, key.subject_public_key_info());
    let (status, _) = harness
        .request(
            "GET",
            "/enroll/v1/sessions?wait=0",
            Value::Null,
            Some(created["session"].as_str().unwrap()),
            1,
        )
        .await;
    assert_eq!(status, StatusCode::GONE);
}
