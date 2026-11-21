use super::*;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde_json::{json, Value};

pub(crate) const ISSUER: &str = "https://fixture.example/oidc";
const OTHER_ISSUER: &str = "https://other.example/oidc";
const ALIAS: &str = "fixture.example/oidc";
pub(crate) const NOW: i64 = 1800000000;

pub(crate) fn signing_key() -> EcdsaKeyPair {
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &random).unwrap()
}

pub(crate) fn provider(issuer: &str, key: &EcdsaKeyPair) -> Provider {
    let public = key.public_key().as_ref();
    let jwks = serde_json::from_value(json!({"keys": [{
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "fixture",
        "x": URL_SAFE_NO_PAD.encode(&public[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&public[33..65])
    }]}))
    .unwrap();
    let metadata: CoreProviderMetadata = serde_json::from_value(json!({
        "issuer": issuer,
        "authorization_endpoint": "https://fixture.example/authorize",
        "token_endpoint": "https://fixture.example/token",
        "jwks_uri": "https://fixture.example/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid", "email", "offline_access"],
        "id_token_signing_alg_values_supported": ["ES256"],
    }))
    .unwrap();
    let config: Config = serde_json::from_value(json!({
        "issuer": issuer,
        "client_id": "web-client",
        "redirect_uri": "https://collector.example/login/callback",
        "accepted_iss": [ALIAS],
        "provider_auth_params": {"prompt": "consent"}
    }))
    .unwrap();
    Provider {
        redirect: RedirectUrl::new(config.redirect_uri.clone()).unwrap(),
        config,
        secret: None,
        offline: true,
        keys: Arc::new(Keys {
            metadata: RwLock::new(metadata.set_jwks(jwks)),
            attempted: Mutex::new(Attempts {
                periodic: Instant::now(),
                unknown_key: None,
            }),
            http: reqwest::Client::new(),
            interval: Duration::from_secs(3600),
        }),
        refresh_task: tokio::spawn(std::future::pending()),
    }
}

pub(crate) fn claims(issuer: &str) -> Value {
    json!({
        "iss": issuer, "sub": "owner-id", "aud": "web-client",
        "exp": NOW + 1, "iat": NOW, "nonce": "test-nonce",
        "email": "owner@example.test", "email_verified": true
    })
}

pub(crate) fn signed(header: Value, claims: Value, key: &EcdsaKeyPair) -> String {
    let encoded = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = key.sign(&SystemRandom::new(), encoded.as_bytes()).unwrap();
    format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

fn verify(provider: &Provider, token: &str) -> Result<VerifiedClaims, Error> {
    let token = SignedToken::parse(token)?;
    token
        .verify(
            &provider.keys.snapshot()?,
            &provider.config.signing_algorithms,
        )
        .map_err(|_| Error::Signature)?;
    provider.claims(token.payload, "test-nonce", NOW)
}

#[tokio::test]
async fn token_checks_bind_original_signature_issuer_and_nonce() {
    let key = signing_key();
    let flow = provider(ISSUER, &key);
    let header = json!({"alg": "ES256", "kid": "fixture"});

    let sample = signed(header.clone(), claims(ISSUER), &key);
    assert_eq!(verify(&flow, &sample).unwrap().sub, "owner-id");
    let alias = signed(header.clone(), claims(ALIAS), &key);
    assert_eq!(verify(&flow, &alias).unwrap().iss, ALIAS);

    let mut narrowed = provider(ISSUER, &key);
    narrowed.config.signing_algorithms = vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256];
    assert!(matches!(verify(&narrowed, &sample), Err(Error::Signature)));

    let second_flow = provider(OTHER_ISSUER, &key);
    let second_token = signed(header.clone(), claims(OTHER_ISSUER), &key);
    assert!(verify(&second_flow, &second_token).is_ok());
    assert!(matches!(verify(&flow, &second_token), Err(Error::Issuer)));

    let mut different_nonce = claims(ISSUER);
    different_nonce["nonce"] = json!("wrong-nonce");
    let replay = signed(header, different_nonce, &key);
    assert!(matches!(verify(&flow, &replay), Err(Error::Nonce)));
}

#[tokio::test]
async fn token_checks_refuse_unusable_claims_and_signing_profiles() {
    let key = signing_key();
    let flow = provider(ISSUER, &key);
    let header = json!({"alg": "ES256", "kid": "fixture"});
    for (field, value) in [
        ("aud", json!("wrong-client")),
        ("aud", json!(["web-client", "other-client"])),
        ("azp", json!("wrong-client")),
        ("sub", json!("")),
        ("sub", Value::Null),
        ("email_verified", json!(false)),
        ("email", Value::Null),
        ("exp", json!(NOW)),
        ("iat", json!(NOW + 61)),
        ("iat", json!(NOW - 61)),
    ] {
        let mut invalid = claims(ISSUER);
        invalid[field] = value;
        assert!(
            verify(&flow, &signed(header.clone(), invalid, &key)).is_err(),
            "accepted invalid {field}"
        );
    }
    for header in [
        json!({"alg":"none", "kid":"fixture"}),
        json!({"alg":"HS256", "kid":"fixture"}),
        json!({"alg":"ES256", "kid":"unknown"}),
        json!({"alg":"ES256", "kid":"fixture", "crit":["b64"], "b64":false}),
    ] {
        assert!(verify(&flow, &signed(header, claims(ISSUER), &key)).is_err());
    }

    let mismatched = signing_key();
    assert!(matches!(
        verify(&flow, &signed(header.clone(), claims(ISSUER), &mismatched)),
        Err(Error::Signature)
    ));

    let mut multi = claims(ISSUER);
    multi["aud"] = json!(["web-client", "other-client"]);
    multi["azp"] = json!("wrong-client");
    assert!(matches!(
        verify(&flow, &signed(header.clone(), multi.clone(), &key)),
        Err(Error::Audience)
    ));
    multi["azp"] = json!("web-client");
    assert!(verify(&flow, &signed(header, multi, &key)).is_ok());
}

#[tokio::test]
async fn authorization_request_binds_code_flow_and_offline_switch() {
    let key = signing_key();
    let mut flow = provider(ISSUER, &key);
    let pending = flow.begin().unwrap();
    let url = reqwest::Url::parse(&pending.authorization_url).unwrap();
    let query: BTreeMap<_, _> = url.query_pairs().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["response_mode"], "query");
    assert_eq!(query["redirect_uri"], flow.config.redirect_uri);
    assert_eq!(query["state"], pending.state());
    assert_eq!(query["nonce"], pending.nonce.secret().as_str());
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["prompt"], "consent");
    assert!(query["scope"]
        .split_whitespace()
        .any(|s| s == "offline_access"));
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&pending.verifier);
    assert_eq!(query["code_challenge"], challenge.as_str());

    flow.offline = false;
    let pending = flow.begin().unwrap();
    let url = reqwest::Url::parse(&pending.authorization_url).unwrap();
    let query: BTreeMap<_, _> = url.query_pairs().collect();
    assert!(query["scope"]
        .split_whitespace()
        .all(|s| s != "offline_access"));
    assert!(!query.contains_key("prompt"));
}

#[tokio::test]
async fn https_discovery_exchange_and_refresh_use_the_fixture_provider() {
    use crate::enroll_oidc::signed_fixture::Fixture;

    let fixture = Fixture::new_at(NOW).await;
    let config = || {
        serde_json::from_value(json!({
            "issuer": fixture.issuer(),
            "accepted_iss": [ALIAS],
            "client_id": "web-client",
            "redirect_uri": "https://collector.example/login/callback",
        }))
        .unwrap()
    };

    fixture.set_discovery_claim("issuer", json!(OTHER_ISSUER));
    assert!(Provider::discover_with_client(
        config(),
        "https://collector.example",
        true,
        fixture.http_client(),
    )
    .await
    .is_err());
    assert_eq!(
        fixture.request_paths(),
        ["/.well-known/openid-configuration"]
    );

    fixture.set_discovery_claim("issuer", json!(fixture.issuer()));
    fixture.set_discovery_claim(
        "scopes_supported",
        json!(["openid", "email", "offline_access"]),
    );
    let provider = Provider::discover_with_client(
        config(),
        "https://collector.example",
        true,
        fixture.http_client(),
    )
    .await
    .unwrap();
    let pending = provider.begin().unwrap();
    let (code, _) = fixture.authorize(&pending.authorization_url);
    assert!(matches!(
        provider.exchange(pending, &code, "wrong-state", NOW).await,
        Err(Error::State)
    ));
    assert!(!fixture.request_paths().iter().any(|path| path == "/token"));

    let pending = provider.begin().unwrap();
    let (code, state) = fixture.authorize(&pending.authorization_url);
    fixture.set_code_claim(&code, "iss", json!(ALIAS));
    let login = provider
        .exchange(pending, &code, &state, NOW)
        .await
        .unwrap();
    assert_eq!(login.claims.iss, ALIAS);
    assert_eq!(login.claims.sub, "fixture-sub");
    let refresh = login.refresh_token.unwrap();

    fixture.queue_refresh_reply(503, json!({"error":"invalid_grant"}));
    assert!(matches!(
        provider.refresh(&refresh).await,
        Err(RefreshError::Unavailable)
    ));
    let replacement = format!("fixture-rotated-{}", ulid::Ulid::new());
    fixture.queue_refresh_reply(
        200,
        json!({
            "access_token": "fixture-refresh-access",
            "token_type": "Bearer",
            "refresh_token": replacement
        }),
    );
    let rotated = provider.refresh(&refresh).await.unwrap().unwrap();
    assert!(rotated == replacement, "the refresh handle did not rotate");
    fixture.queue_refresh_reply(400, json!({"error":"invalid_grant"}));
    assert!(matches!(
        provider.refresh(&rotated).await,
        Err(RefreshError::InvalidGrant)
    ));
    assert_eq!(fixture.refresh_requests(), 3);
}
