//! Browser callback for the Mission Control issuer.
use super::{
    allowed_algs, https_url, CoreProviderMetadata, Error, OidcClient, SignatureVerificationError,
};
use crate::enroll_ca::VerifiedClaims;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openidconnect::core::{CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, ClientId, ClientSecret, CsrfToken, IssuerUrl, JsonWebKey,
    JsonWebKeyAlgorithm, JsonWebKeyUse, JwsSigningAlgorithm, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{sync::Mutex, time::Instant};

const MAX_TOKEN_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: String,
    #[serde(default)]
    pub accepted_iss: Vec<String>,
    pub client_id: String,
    #[serde(default = "default_signing_algorithms")]
    pub signing_algorithms: Vec<CoreJwsSigningAlgorithm>,
    pub client_secret_file: Option<PathBuf>,
    pub redirect_uri: String,
    #[serde(default = "offline_default")]
    pub request_offline_access: bool,
    #[serde(default)]
    pub provider_auth_params: BTreeMap<String, String>,
    #[serde(default = "clock_skew_default")]
    pub clock_skew_secs: u64,
    #[serde(default = "jwks_refresh_default")]
    pub jwks_refresh_secs: u64,
}

pub(crate) fn default_signing_algorithms() -> Vec<CoreJwsSigningAlgorithm> {
    use CoreJwsSigningAlgorithm::{EcdsaP256Sha256, RsaSsaPkcs1V15Sha256};
    vec![RsaSsaPkcs1V15Sha256, EcdsaP256Sha256]
}

fn offline_default() -> bool {
    true
}
fn clock_skew_default() -> u64 {
    60
}
fn jwks_refresh_default() -> u64 {
    3600
}

pub struct Pending {
    pub authorization_url: String,
    state: CsrfToken,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    provider: Arc<Keys>,
    metadata: CoreProviderMetadata,
}

impl Pending {
    pub fn state(&self) -> &str {
        self.state.secret()
    }
}

pub struct Login {
    pub claims: VerifiedClaims,
    pub refresh_token: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RefreshError {
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("oidc_unavailable")]
    Unavailable,
}

struct Keys {
    metadata: RwLock<CoreProviderMetadata>,
    attempted: Mutex<Attempts>,
    http: reqwest::Client,
    interval: Duration,
}

struct Attempts {
    periodic: Instant,
    unknown_key: Option<Instant>,
}

impl Keys {
    fn snapshot(&self) -> Result<CoreProviderMetadata, Error> {
        Ok(self
            .metadata
            .read()
            .map_err(|_| Error::Unavailable)?
            .clone())
    }

    async fn refresh(&self, unknown_key: bool) -> Result<CoreProviderMetadata, Error> {
        let mut attempted = self.attempted.lock().await;
        let metadata = self.snapshot()?;
        let now = Instant::now();
        if unknown_key {
            if attempted
                .unknown_key
                .is_some_and(|previous| previous.elapsed() < Duration::from_secs(60))
            {
                return Ok(metadata);
            }
            attempted.unknown_key = Some(now);
        } else if attempted.periodic.elapsed() < self.interval {
            return Ok(metadata);
        }
        attempted.periodic = now;
        let keys = CoreJsonWebKeySet::fetch_async(metadata.jwks_uri(), &self.http)
            .await
            .map_err(|_| Error::Unavailable)?;
        let updated = metadata.set_jwks(keys);
        *self.metadata.write().map_err(|_| Error::Unavailable)? = updated.clone();
        Ok(updated)
    }
}

pub struct Provider {
    config: Config,
    redirect: RedirectUrl,
    secret: Option<ClientSecret>,
    offline: bool,
    keys: Arc<Keys>,
    refresh_task: tokio::task::JoinHandle<()>,
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.refresh_task.abort();
    }
}

impl Provider {
    pub async fn discover(
        config: Config,
        public_origin: &str,
        refresh_enabled: bool,
    ) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Configuration)?;
        Self::discover_with_client(config, public_origin, refresh_enabled, http).await
    }

    pub(crate) async fn discover_with_client(
        config: Config,
        public_origin: &str,
        refresh_enabled: bool,
        http: reqwest::Client,
    ) -> Result<Self, Error> {
        let issuer = IssuerUrl::new(config.issuer.clone()).map_err(|_| Error::Configuration)?;
        let redirect =
            RedirectUrl::new(config.redirect_uri.clone()).map_err(|_| Error::Configuration)?;
        let origin = reqwest::Url::parse(public_origin).map_err(|_| Error::Configuration)?;
        let supported = default_signing_algorithms();
        if !https_url(issuer.url())
            || issuer.url().query().is_some()
            || !https_url(&origin)
            || origin.path() != "/"
            || origin.query().is_some()
            || !https_url(redirect.url())
            || redirect.url().origin() != origin.origin()
            || redirect.url().query().is_some()
            || redirect.url().path() != "/login/callback"
            || config.client_id.is_empty()
            || config.signing_algorithms.is_empty()
            || config
                .signing_algorithms
                .iter()
                .any(|alg| !supported.contains(alg))
            || config.jwks_refresh_secs == 0
            || config
                .accepted_iss
                .iter()
                .any(|v| v.is_empty() || v.chars().any(char::is_control))
            || config.provider_auth_params.keys().any(|v| {
                v.is_empty()
                    || matches!(
                        v.as_str(),
                        "client_id"
                            | "redirect_uri"
                            | "response_type"
                            | "response_mode"
                            | "scope"
                            | "state"
                            | "nonce"
                            | "code_challenge"
                            | "code_challenge_method"
                            | "request"
                            | "request_uri"
                    )
            })
        {
            return Err(Error::Configuration);
        }
        let secret = config
            .client_secret_file
            .as_deref()
            .map(super::read_client_secret)
            .transpose()?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|_| Error::Unavailable)?;
        if metadata.issuer().as_str() != config.issuer
            || !https_url(metadata.authorization_endpoint().url())
            || !https_url(metadata.jwks_uri().url())
            || !metadata
                .token_endpoint()
                .is_some_and(|v| https_url(v.url()))
            || !allowed_algs(&metadata)
                .iter()
                .any(|alg| config.signing_algorithms.contains(alg))
        {
            return Err(Error::Configuration);
        }
        let keys = Arc::new(Keys {
            metadata: RwLock::new(metadata),
            attempted: Mutex::new(Attempts {
                periodic: Instant::now(),
                unknown_key: None,
            }),
            http,
            interval: Duration::from_secs(config.jwks_refresh_secs),
        });
        let refresh_task = tokio::spawn({
            let keys = Arc::clone(&keys);
            async move {
                loop {
                    tokio::time::sleep(keys.interval).await;
                    let _ = keys.refresh(false).await;
                }
            }
        });
        let offline = refresh_enabled && config.request_offline_access;
        Ok(Self {
            config,
            redirect,
            secret,
            offline,
            keys,
            refresh_task,
        })
    }

    pub fn begin(&self) -> Result<Pending, Error> {
        let metadata = self.keys.snapshot()?;
        let client = OidcClient::from_provider_metadata(
            metadata.clone(),
            ClientId::new(self.config.client_id.clone()),
            self.secret.clone(),
        )
        .set_redirect_uri(self.redirect.clone());
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge)
            .add_scope(Scope::new("email".into()))
            .add_extra_param("response_mode", "query");
        if self.offline {
            if metadata.scopes_supported().is_some_and(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope.as_str() == "offline_access")
            }) {
                request = request.add_scope(Scope::new("offline_access".into()));
            }
            for (key, value) in &self.config.provider_auth_params {
                request = request.add_extra_param(key, value);
            }
        }
        let (url, state, nonce) = request.url();
        Ok(Pending {
            authorization_url: url.into(),
            state,
            nonce,
            verifier,
            provider: Arc::clone(&self.keys),
            metadata,
        })
    }

    pub async fn exchange(
        &self,
        pending: Pending,
        code: &str,
        state: &str,
        now: i64,
    ) -> Result<Login, Error> {
        if !bool::from(pending.state.secret().as_bytes().ct_eq(state.as_bytes())) {
            return Err(Error::State);
        }
        if !Arc::ptr_eq(&self.keys, &pending.provider) {
            return Err(Error::Configuration);
        }
        let response = self
            .token_request(
                &pending.metadata,
                vec![
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", self.redirect.as_str()),
                    ("code_verifier", pending.verifier.secret()),
                ],
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        let token = response.id_token.as_deref().ok_or(Error::Token)?;
        let signed = SignedToken::parse(token)?;
        let mut verified = signed.verify(&pending.metadata, &self.config.signing_algorithms);
        if matches!(&verified, Err(SignatureVerificationError::NoMatchingKey)) {
            let updated = self.keys.refresh(true).await?;
            verified = signed.verify(&updated, &self.config.signing_algorithms);
        }
        verified.map_err(|_| Error::Signature)?;
        let claims = self.claims(signed.payload, pending.nonce.secret(), now)?;
        Ok(Login {
            claims,
            refresh_token: response
                .refresh_token
                .filter(|value| self.offline && !value.is_empty()),
        })
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<Option<String>, RefreshError> {
        if !self.offline {
            return Err(RefreshError::Unavailable);
        }
        let metadata = self
            .keys
            .snapshot()
            .map_err(|_| RefreshError::Unavailable)?;
        self.token_request(
            &metadata,
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
        )
        .await
        .map(|response| response.refresh_token.filter(|value| !value.is_empty()))
    }

    async fn token_request<'a>(
        &'a self,
        metadata: &CoreProviderMetadata,
        mut fields: Vec<(&'a str, &'a str)>,
    ) -> Result<TokenBody, RefreshError> {
        let endpoint = metadata.token_endpoint().ok_or(RefreshError::Unavailable)?;
        let mut request = self
            .keys
            .http
            .post(endpoint.url().clone())
            .header("accept", "application/json");
        if let Some(secret) = &self.secret {
            request = request.basic_auth(
                form_component(&self.config.client_id),
                Some(form_component(secret.secret())),
            );
        } else {
            fields.push(("client_id", &self.config.client_id));
        }
        let mut response = request
            .form(&fields)
            .send()
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| RefreshError::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_TOKEN_BYTES {
                return Err(RefreshError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        let result: TokenReply =
            serde_json::from_slice(&bytes).map_err(|_| RefreshError::Unavailable)?;
        if status == reqwest::StatusCode::BAD_REQUEST
            && result.error.as_deref() == Some("invalid_grant")
        {
            return Err(RefreshError::InvalidGrant);
        }
        if status != reqwest::StatusCode::OK
            || result.error.is_some()
            || result.access_token.as_deref().is_none_or(str::is_empty)
            || result.token_type.as_deref().is_none_or(str::is_empty)
        {
            return Err(RefreshError::Unavailable);
        }
        Ok(TokenBody {
            id_token: result.id_token,
            refresh_token: result.refresh_token,
        })
    }

    fn claims(&self, payload: &str, nonce: &str, now: i64) -> Result<VerifiedClaims, Error> {
        let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| Error::Token)?;
        let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| Error::Token)?;
        if claims.iss != self.config.issuer && !self.config.accepted_iss.contains(&claims.iss) {
            return Err(Error::Issuer);
        }
        if claims.sub.is_empty() {
            return Err(Error::Token);
        }
        let audiences = claims.aud.as_slice();
        if !audiences.contains(&self.config.client_id)
            || (audiences.len() > 1 && claims.azp.is_none())
            || claims
                .azp
                .as_ref()
                .is_some_and(|azp| azp != &self.config.client_id)
        {
            return Err(Error::Audience);
        }
        if claims.exp <= now {
            return Err(Error::Expired);
        }
        if claims.iat.abs_diff(now) > self.config.clock_skew_secs {
            return Err(Error::IssuedAt);
        }
        if !bool::from(claims.nonce.as_bytes().ct_eq(nonce.as_bytes())) {
            return Err(Error::Nonce);
        }
        let email = claims
            .email
            .filter(|email| claims.email_verified && !email.is_empty())
            .ok_or(Error::Token)?;
        Ok(VerifiedClaims {
            provider: self.config.issuer.clone(),
            iss: claims.iss,
            sub: claims.sub,
            email: Some(email),
            email_verified: true,
            hd: None,
            groups: Vec::new(),
            preferred_username: None,
        })
    }
}

fn form_component(value: &str) -> String {
    openidconnect::url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: Option<String>,
    token_type: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    error: Option<String>,
}

struct TokenBody {
    id_token: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct Header {
    alg: CoreJwsSigningAlgorithm,
    kid: Option<String>,
    crit: Option<serde_json::Value>,
    b64: Option<serde_json::Value>,
}

struct SignedToken<'a> {
    signed: &'a str,
    payload: &'a str,
    signature: Vec<u8>,
    header: Header,
}

impl<'a> SignedToken<'a> {
    fn parse(token: &'a str) -> Result<Self, Error> {
        let (signed, signature) = token.rsplit_once('.').ok_or(Error::Token)?;
        let (header, payload) = signed.split_once('.').ok_or(Error::Token)?;
        if payload.contains('.') {
            return Err(Error::Token);
        }
        let header = URL_SAFE_NO_PAD.decode(header).map_err(|_| Error::Token)?;
        let header: Header = serde_json::from_slice(&header).map_err(|_| Error::Token)?;
        if header.crit.is_some() || header.b64.is_some() {
            return Err(Error::Token);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| Error::Token)?;
        Ok(Self {
            signed,
            payload,
            signature,
            header,
        })
    }

    fn verify(
        &self,
        metadata: &CoreProviderMetadata,
        configured: &[CoreJwsSigningAlgorithm],
    ) -> Result<(), SignatureVerificationError> {
        if !configured.contains(&self.header.alg)
            || !allowed_algs(metadata).contains(&self.header.alg)
        {
            return Err(SignatureVerificationError::DisallowedAlg(
                "unsupported signing algorithm".into(),
            ));
        }
        let mut keys = metadata.jwks().keys().iter().filter(|key| {
            self.header
                .kid
                .as_deref()
                .is_none_or(|kid| key.key_id().is_some_and(|key_id| key_id.as_str() == kid))
                && key.key_use().is_none_or(JsonWebKeyUse::allows_signature)
                && self.header.alg.key_type().as_ref() == Some(key.key_type())
                && match key.signing_alg() {
                    JsonWebKeyAlgorithm::Algorithm(alg) => alg == &self.header.alg,
                    JsonWebKeyAlgorithm::Unspecified => true,
                    JsonWebKeyAlgorithm::Unsupported => false,
                }
        });
        let key = keys
            .next()
            .ok_or(SignatureVerificationError::NoMatchingKey)?;
        if keys.next().is_some() {
            return Err(SignatureVerificationError::NoMatchingKey);
        }
        key.verify_signature(&self.header.alg, self.signed.as_bytes(), &self.signature)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn as_slice(&self) -> &[String] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    azp: Option<String>,
    exp: i64,
    iat: i64,
    nonce: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
}

#[cfg(test)]
pub(crate) mod tests;
