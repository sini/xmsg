use super::*;
use openidconnect::core::{CoreHmacKey, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use ring::signature::KeyPair;
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NOW: i64 = 2_000_000_000;
const SECRET: &str = "fixture-shared-client-secret";
struct Keys {
    rsa: CoreRsaPrivateSigningKey,
    ec: ring::signature::EcdsaKeyPair,
}
fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let rsa = CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new("rsa".into())))
            .unwrap();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        let ec = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        Keys { rsa, ec }
    })
}
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
fn jwks(new_key: bool) -> Value {
    let mut rsa = serde_json::to_value(keys().rsa.as_verification_key()).unwrap();
    if new_key {
        rsa["kid"] = json!("rotated");
    }
    let point = keys().ec.public_key().as_ref();
    json!({"keys":[rsa,{"kty":"EC","crv":"P-256","x":b64(&point[1..33]),"y":b64(&point[33..]),"kid":"ec","use":"sig"}]})
}
#[derive(Clone)]
pub(crate) struct Mode {
    alg: String,
    kid: String,
    overrides: serde_json::Map<String, Value>,
    nonce: String,
    challenge: String,
    bad_signature: bool,
    hmac_modulus: bool,
    client_id: String,
    after_token: Option<Arc<dyn Fn() + Send + Sync>>,
    after_refresh: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl Default for Mode {
    fn default() -> Self {
        Self {
            alg: "RS256".into(),
            kid: "rsa".into(),
            overrides: Default::default(),
            nonce: String::new(),
            challenge: String::new(),
            bad_signature: false,
            hmac_modulus: false,
            client_id: String::new(),
            after_token: None,
            after_refresh: None,
        }
    }
}
struct Shared {
    issuer: String,
    mode: Mode,
    requests: Vec<String>,
    forms: Vec<HashMap<String, String>>,
    jwks_requests: usize,
    now: i64,
    secret: String,
    access: String,
    refresh: String,
    codes: HashMap<String, Mode>,
    values: Vec<String>,
}
pub(crate) struct Fixture {
    shared: Arc<Mutex<Shared>>,
    http: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
    files: tempfile::TempDir,
}
impl Fixture {
    pub(crate) async fn new() -> Self {
        let _ = keys();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let http = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .add_root_certificate(reqwest::Certificate::from_der(generated.cert.der()).unwrap())
            .build()
            .unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![generated.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let shared = Arc::new(Mutex::new(Shared {
            issuer,
            mode: Mode::default(),
            requests: vec![],
            forms: vec![],
            jwks_requests: 0,
            now: NOW,
            secret: SECRET.into(),
            access: format!("fixture-access-{}", ulid::Ulid::new()),
            refresh: format!("fixture-refresh-{}", ulid::Ulid::new()),
            codes: HashMap::new(),
            values: vec![],
        }));
        let state = shared.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(5), async move {
                        let Ok(mut tls) = acceptor.accept(socket).await else { return; };
                        let mut input = Vec::new();
                        let header_end = loop {
                            if let Some(index) = input.windows(4).position(|v| v == b"\r\n\r\n") { break index + 4; }
                            let mut block = [0; 1024];
                            let count = tls.read(&mut block).await.unwrap();
                            if count == 0 || input.len() > 65536 { return; }
                            input.extend_from_slice(&block[..count]);
                        };
                        let header = String::from_utf8(input[..header_end].to_vec()).unwrap();
                        let length = header.lines().find_map(|l|l.split_once(':').filter(|(k,_)|k.eq_ignore_ascii_case("content-length")).map(|(_,v)|v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                        while input.len() - header_end < length {
                            let mut block = [0; 1024];
                            let count = tls.read(&mut block).await.unwrap();
                            if count == 0 { return; }
                            input.extend_from_slice(&block[..count]);
                        }
                        let path = header.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                        let response = reply(&state, path, &header, &input[header_end..]);
                        let body = response.to_string();
                        let bytes = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                        tls.write_all(bytes.as_bytes()).await.unwrap();
                        let _ = tls.shutdown().await;
                    }).await;
                });
            }
        });
        Self {
            shared,
            http,
            task,
            files: tempfile::tempdir().unwrap(),
        }
    }
    pub(crate) async fn new_at(now: i64) -> Self {
        let fixture = Self::new().await;
        {
            let mut shared = fixture.shared.lock().unwrap();
            shared.now = now;
            shared.secret = format!("fixture-client-secret-{}", ulid::Ulid::new());
        }
        fixture
    }
    pub(crate) fn http_client(&self) -> reqwest::Client {
        self.http.clone()
    }
    pub(crate) fn issuer(&self) -> String {
        self.shared.lock().unwrap().issuer.clone()
    }
    pub(crate) fn authorize(&self, authorization_url: &str) -> (String, String) {
        let url = reqwest::Url::parse(authorization_url).unwrap();
        let pairs: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let state = pairs["state"].clone();
        let mode = Mode {
            nonce: pairs["nonce"].clone(),
            challenge: pairs["code_challenge"].clone(),
            client_id: pairs["client_id"].clone(),
            ..Mode::default()
        };
        let code = format!("fixture-code-{}", ulid::Ulid::new());
        let mut shared = self.shared.lock().unwrap();
        shared
            .values
            .extend([code.clone(), state.clone(), mode.nonce.clone()]);
        shared.codes.insert(code.clone(), mode);
        (code, state)
    }
    pub(crate) fn set_code_claim(&self, code: &str, claim: &str, value: Value) {
        self.shared
            .lock()
            .unwrap()
            .codes
            .get_mut(code)
            .unwrap()
            .overrides
            .insert(claim.into(), value);
    }
    pub(crate) fn request_paths(&self) -> Vec<String> {
        self.shared.lock().unwrap().requests.clone()
    }
    pub(crate) fn secret_values(&self) -> Vec<String> {
        let shared = self.shared.lock().unwrap();
        let mut values = shared.values.clone();
        values.extend([
            shared.secret.clone(),
            shared.access.clone(),
            shared.refresh.clone(),
        ]);
        for form in &shared.forms {
            if let Some(value) = form.get("code_verifier") {
                values.push(value.clone());
            }
        }
        values
    }

    pub(crate) fn config(&self, secret: bool) -> ProviderConfig {
        use std::os::unix::fs::PermissionsExt;
        let secret_path = self.files.path().join("client");
        if secret {
            std::fs::write(&secret_path, &self.shared.lock().unwrap().secret).unwrap();
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        ProviderConfig {
            issuer: self.shared.lock().unwrap().issuer.clone(),
            clients: HashMap::from([
                (
                    Flow::Loopback,
                    crate::enroll_ca::ClientConfig {
                        client_id: "loopback-client".into(),
                        client_secret_file: secret.then(|| secret_path.clone()),
                    },
                ),
                (
                    Flow::Paste,
                    crate::enroll_ca::ClientConfig {
                        client_id: "paste-client".into(),
                        client_secret_file: secret.then_some(secret_path),
                    },
                ),
            ]),
        }
    }
    async fn provider(&self, secret: bool) -> Provider {
        Provider::discover_with_client("fixture", &self.config(secret), true, self.http.clone())
            .await
            .unwrap()
    }
    fn prepare(
        &self,
        provider: &Provider,
        flow: Flow,
        change: impl FnOnce(&mut Mode),
    ) -> PendingAuthorization {
        let pending = provider.begin(flow, "http://127.0.0.1:18551/cb").unwrap();
        let mut mode = Mode {
            nonce: pending.nonce.secret().clone(),
            challenge: reqwest::Url::parse(&pending.authorization_url)
                .unwrap()
                .query_pairs()
                .find(|(key, _)| key == "code_challenge")
                .unwrap()
                .1
                .into_owned(),
            ..Mode::default()
        };
        change(&mut mode);
        self.shared.lock().unwrap().mode = mode;
        pending
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn reply(shared: &Mutex<Shared>, path: &str, header: &str, body: &[u8]) -> Value {
    let mut shared = shared.lock().unwrap();
    shared.requests.push(path.into());
    match path {
        "/.well-known/openid-configuration" => {
            json!({"issuer":shared.issuer,"authorization_endpoint":format!("{}/authorize",shared.issuer),"token_endpoint":format!("{}/token",shared.issuer),"jwks_uri":format!("{}/jwks",shared.issuer),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256","ES256","HS256"]})
        }
        "/jwks" => {
            shared.jwks_requests += 1;
            if shared.jwks_requests > 1 {
                if let Some(hook) = shared.mode.after_refresh.clone() {
                    hook();
                }
            }
            jwks(shared.jwks_requests > 1)
        }
        "/token" => {
            let mut form = reqwest::Url::parse("https://form.example/").unwrap();
            form.set_query(Some(std::str::from_utf8(body).unwrap()));
            let fields: HashMap<String, String> = form.query_pairs().into_owned().collect();
            let client = fields.get("client_id").cloned().unwrap_or_else(|| {
                let value = header
                    .lines()
                    .find_map(|l| {
                        l.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                            .map(|(_, v)| v.trim())
                    })
                    .unwrap();
                let value = base64::engine::general_purpose::STANDARD
                    .decode(value.strip_prefix("Basic ").unwrap())
                    .unwrap();
                String::from_utf8(value)
                    .unwrap()
                    .split_once(':')
                    .unwrap()
                    .0
                    .to_owned()
            });
            let mode = match fields.get("code").map(String::as_str) {
                Some("fixture-code") => shared.mode.clone(),
                Some(code) => match shared.codes.remove(code) {
                    Some(mode) => mode,
                    None => return json!({"error":"invalid_grant"}),
                },
                None => return json!({"error":"invalid_grant"}),
            };
            if !mode.client_id.is_empty() && mode.client_id != client {
                return json!({"error":"invalid_grant"});
            }
            if !fields.get("code_verifier").is_some_and(|value| {
                PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(value.clone()))
                    .as_str()
                    == mode.challenge
            }) {
                return json!({"error":"invalid_grant"});
            }
            shared.forms.push(fields);
            let mut claims = json!({"iss":shared.issuer,"sub":"fixture-sub","aud":client,"exp":shared.now+3600,"iat":shared.now,"nonce":mode.nonce,"email":"alice@example.org","email_verified":true,"hd":"example.org","groups":["xmsg-users@example.org","00000000-0000-0000-0000-000000000001"],"preferred_username":"alice"});
            for (key, value) in &mode.overrides {
                claims[key] = value.clone();
            }
            let token = sign(&claims, &mode, &shared.secret);
            shared.values.push(token.clone());
            if let Some(hook) = mode.after_token {
                hook();
            }
            json!({"access_token":shared.access,"refresh_token":shared.refresh,"token_type":"Bearer","id_token":token})
        }
        _ => json!({}),
    }
}
fn sign(claims: &Value, mode: &Mode, secret: &str) -> String {
    let header = json!({"alg":mode.alg,"kid":mode.kid});
    let message = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let mut signature = match mode.alg.as_str() {
        "RS256" => keys()
            .rsa
            .sign(
                &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                message.as_bytes(),
            )
            .unwrap(),
        "ES256" => keys()
            .ec
            .sign(&ring::rand::SystemRandom::new(), message.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec(),
        "HS256" => CoreHmacKey::new(if mode.hmac_modulus {
            let jwk = serde_json::to_value(keys().rsa.as_verification_key()).unwrap();
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk["n"].as_str().unwrap())
                .unwrap()
        } else {
            secret.as_bytes().to_vec()
        })
        .sign(&CoreJwsSigningAlgorithm::HmacSha256, message.as_bytes())
        .unwrap(),
        "none" => vec![],
        _ => unreachable!(),
    };
    if mode.bad_signature {
        signature[0] ^= 1;
    }
    format!("{message}.{}", b64(&signature))
}

#[tokio::test]
async fn signed_https_browser_flows_preserve_verified_projection() {
    let fixture = Fixture::new().await;
    let provider = fixture.provider(true).await;
    for flow in [Flow::Loopback, Flow::Paste] {
        let pending = fixture.prepare(&provider, flow, |_| {});
        let state = pending.state.secret().clone();
        let claims = provider
            .exchange(pending, "fixture-code", &state, &|| NOW)
            .await
            .unwrap();
        assert_eq!(claims.iss, fixture.config(false).issuer);
        assert_eq!(claims.sub, "fixture-sub");
        assert_eq!(claims.preferred_username.as_deref(), Some("alice"));
        assert!(claims.groups.contains(&"xmsg-users@example.org".into()));
    }
}

#[tokio::test]
async fn email_verification_projection_controls() {
    let fixture = Fixture::new().await;
    let provider = fixture.provider(false).await;
    for arm in ["string-bool", "unverified-email"] {
        let pending = fixture.prepare(&provider, Flow::Paste, |mode| match arm {
            "es256" => {
                mode.alg = "ES256".into();
                mode.kid = "ec".into();
            }
            "azp" => {
                mode.overrides
                    .insert("aud".into(), json!(["paste-client", "other"]));
                mode.overrides.insert("azp".into(), json!("paste-client"));
            }
            "string-bool" => {
                mode.overrides
                    .insert("email_verified".into(), json!("true"));
            }
            "unverified-email" => {
                mode.overrides.insert("email_verified".into(), json!(false));
            }
            _ => unreachable!(),
        });
        let state = pending.state.secret().clone();
        let claims = provider
            .exchange(pending, "fixture-code", &state, &|| NOW)
            .await
            .unwrap();
        if arm == "unverified-email" {
            assert!(!claims.email_verified && claims.email.is_none());
        } else {
            assert!(claims.email_verified && claims.email.is_some());
        }
    }
}

#[tokio::test]
async fn state_refusal_makes_no_token_request_and_key_refresh_is_bounded() {
    let fixture = Fixture::new().await;
    let provider = fixture.provider(false).await;
    let pending = fixture.prepare(&provider, Flow::Loopback, |_| {});
    assert!(matches!(
        provider
            .exchange(pending, "fixture-code", "wrong", &|| NOW)
            .await,
        Err(Error::State)
    ));
    assert!(!fixture
        .shared
        .lock()
        .unwrap()
        .requests
        .contains(&"/token".into()));
    let pending = fixture.prepare(&provider, Flow::Loopback, |m| m.kid = "rotated".into());
    let state = pending.state.secret().clone();
    assert!(provider
        .exchange(pending, "fixture-code", &state, &|| NOW)
        .await
        .is_ok());
    assert_eq!(fixture.shared.lock().unwrap().jwks_requests, 2);
    let pending = fixture.prepare(&provider, Flow::Loopback, |m| m.kid = "absent".into());
    let state = pending.state.secret().clone();
    assert!(provider
        .exchange(pending, "fixture-code", &state, &|| NOW)
        .await
        .is_err());
    assert_eq!(fixture.shared.lock().unwrap().jwks_requests, 3);
}

#[tokio::test]
async fn verification_clock_is_sampled_after_token_and_refreshed_jwks_http() {
    for refresh in [false, true] {
        let fixture = Fixture::new().await;
        let provider = fixture.provider(false).await;
        let clock = Arc::new(AtomicI64::new(NOW));
        let changed = clock.clone();
        let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            changed.store(NOW + 20, Ordering::SeqCst);
        });
        let pending = fixture.prepare(&provider, Flow::Loopback, |mode| {
            mode.overrides.insert("exp".into(), json!(NOW + 10));
            if refresh {
                mode.kid = "rotated".into();
                mode.after_refresh = Some(hook);
            } else {
                mode.after_token = Some(hook);
            }
        });
        let state = pending.state.secret().clone();
        assert!(
            matches!(
                provider
                    .exchange(pending, "fixture-code", &state, &|| clock
                        .load(Ordering::SeqCst))
                    .await,
                Err(Error::Expired)
            ),
            "stale verification clock accepted expired token"
        );
    }
}

async fn claim_arm(arm: &str) -> Result<VerifiedClaims, Error> {
    let fixture = Fixture::new().await;
    let provider = fixture.provider(true).await;
    let pending = fixture.prepare(
        &provider,
        if arm == "paste-aud" {
            Flow::Paste
        } else {
            Flow::Loopback
        },
        |mode| match arm {
            "aud" => {
                mode.overrides.insert("aud".into(), json!("paste-client"));
            }
            "paste-aud" => {
                mode.overrides
                    .insert("aud".into(), json!("loopback-client"));
            }
            "azp" => {
                mode.overrides
                    .insert("aud".into(), json!(["loopback-client", "other"]));
                mode.overrides.insert("azp".into(), json!("other"));
            }
            "issuer" => {
                mode.overrides
                    .insert("iss".into(), json!("https://other.example"));
            }
            "expiry" => {
                mode.overrides.insert("exp".into(), json!(NOW));
            }
            "iat" => {
                mode.overrides.insert("iat".into(), json!(NOW + 301));
            }
            "nonce" => {
                mode.overrides.insert("nonce".into(), json!("wrong"));
            }
            "valid" => {}
            "es" => {
                mode.alg = "ES256".into();
                mode.kid = "ec".into();
            }
            "multi" => {
                mode.overrides
                    .insert("aud".into(), json!(["loopback-client", "other"]));
                mode.overrides
                    .insert("azp".into(), json!("loopback-client"));
            }
            "bare" => {
                mode.overrides
                    .insert("iss".into(), json!("accounts.google.com"));
            }
            "signature" => mode.bad_signature = true,
            "hs" => mode.alg = "HS256".into(),
            "hs-modulus" => {
                mode.alg = "HS256".into();
                mode.hmac_modulus = true;
            }
            "none" => mode.alg = "none".into(),
            "unknownkid" => mode.kid = "absent".into(),
            _ => unreachable!(),
        },
    );
    let state = pending.state.secret().clone();
    provider
        .exchange(pending, "fixture-code", &state, &|| NOW)
        .await
}

#[tokio::test]
async fn oidc_aud_refused() {
    assert!(claim_arm("aud").await.is_err(), "OIDC guard omitted: aud");
}

#[tokio::test]
async fn oidc_paste_aud_refused() {
    assert!(
        claim_arm("paste-aud").await.is_err(),
        "OIDC guard omitted: paste-aud"
    );
}

#[tokio::test]
async fn oidc_azp_refused() {
    assert!(claim_arm("azp").await.is_err(), "OIDC guard omitted: azp");
}

#[tokio::test]
async fn oidc_issuer_refused() {
    assert!(
        claim_arm("issuer").await.is_err(),
        "OIDC guard omitted: issuer"
    );
}

#[tokio::test]
async fn oidc_expired_refused() {
    assert!(
        claim_arm("expiry").await.is_err(),
        "OIDC guard omitted: expiry"
    );
}

#[tokio::test]
async fn oidc_future_iat_refused() {
    assert!(claim_arm("iat").await.is_err(), "OIDC guard omitted: iat");
}

#[tokio::test]
async fn oidc_nonce_refused() {
    assert!(
        claim_arm("nonce").await.is_err(),
        "OIDC guard omitted: nonce"
    );
}

#[tokio::test]
async fn oidc_bad_signature_refused() {
    assert!(
        claim_arm("signature").await.is_err(),
        "OIDC guard omitted: signature"
    );
}

#[tokio::test]
async fn oidc_hs_client_secret_refused() {
    assert!(claim_arm("hs").await.is_err(), "OIDC guard omitted: hs");
}

#[tokio::test]
async fn oidc_hs_modulus_refused() {
    assert!(
        claim_arm("hs-modulus").await.is_err(),
        "OIDC guard omitted: hs-modulus"
    );
}

#[tokio::test]
async fn oidc_unsigned_refused() {
    assert!(claim_arm("none").await.is_err(), "OIDC guard omitted: none");
}

#[tokio::test]
async fn oidc_unknown_kid_refused() {
    assert!(
        claim_arm("unknownkid").await.is_err(),
        "OIDC guard omitted: unknownkid"
    );
}

#[tokio::test]
async fn oidc_es256_accepted() {
    assert!(claim_arm("es").await.is_ok(), "valid ES256 token refused");
}

#[tokio::test]
async fn oidc_multiaudience_accepted_with_matching_azp() {
    assert!(
        claim_arm("multi").await.is_ok(),
        "valid multi-audience token refused"
    );
}

#[tokio::test]
async fn oidc_legacy_google_issuer_is_a_clear_refusal() {
    let fixture = Fixture::new().await;
    let mut provider = fixture.provider(false).await;
    provider.issuer = "https://accounts.google.com".into();
    let metadata = provider
        .metadata
        .read()
        .unwrap()
        .clone()
        .set_issuer(IssuerUrl::new(provider.issuer.clone()).unwrap());
    *provider.metadata.write().unwrap() = metadata;
    let pending = fixture.prepare(&provider, Flow::Loopback, |mode| {
        mode.overrides
            .insert("iss".into(), json!("https://accounts.google.com"));
    });
    let state = pending.state.secret().clone();
    let claims = provider
        .exchange(pending, "fixture-code", &state, &|| NOW)
        .await
        .unwrap();
    assert_eq!(claims.iss, "https://accounts.google.com");
    let pending = fixture.prepare(&provider, Flow::Paste, |mode| {
        mode.overrides
            .insert("iss".into(), json!("accounts.google.com"));
    });
    let state = pending.state.secret().clone();
    assert!(
        matches!(
            provider
                .exchange(pending, "fixture-code", &state, &|| NOW)
                .await,
            Err(Error::UnsupportedIssuer)
        ),
        "legacy Google issuer refusal class changed"
    );
}

#[tokio::test]
async fn reusable_fixture_codes_are_one_shot_and_use_the_requested_clock() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let fixture = crate::enroll_oidc::signed_fixture::Fixture::new_at(now).await;
    let config = fixture.config(true);
    assert_eq!(fixture.issuer(), config.issuer);
    let provider = Provider::discover_with_client("fixture", &config, true, fixture.http_client())
        .await
        .unwrap();
    let pending = provider
        .begin(Flow::Loopback, "http://127.0.0.1:18551/cb")
        .unwrap();
    let (code, state) = fixture.authorize(&pending.authorization_url);
    fixture.set_code_claim(&code, "email_verified", json!(false));
    let claims = provider
        .exchange(pending, &code, &state, &|| now)
        .await
        .unwrap();
    assert!(!claims.email_verified && claims.email.is_none());
    assert!(fixture.secret_values().contains(&code));
    assert!(fixture.request_paths().contains(&"/token".into()));
    let pending = provider
        .begin(Flow::Loopback, "http://127.0.0.1:18551/cb")
        .unwrap();
    let state = pending.state.secret().clone();
    assert!(
        provider
            .exchange(pending, &code, &state, &|| now)
            .await
            .is_err(),
        "authorization code replay accepted"
    );
}
