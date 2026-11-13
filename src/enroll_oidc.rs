//! OIDC browser-flow verification for node enrollment.
use crate::enroll_ca::{Flow, Provider as ProviderConfig, VerifiedClaims};
use base64::Engine;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AuthenticationFlow, AuthorizationCode, ClaimsVerificationError, Client,
    ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IdTokenFields, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RequestTokenError, Scope, SignatureVerificationError, StandardErrorResponse,
    StandardTokenResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::RwLock;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported_flow")]
    UnsupportedFlow,
    #[error("unsupported_issuer")]
    UnsupportedIssuer,
    #[error("invalid_provider")]
    Configuration,
    #[error("oidc_unavailable")]
    Unavailable,
    #[error("invalid_state")]
    State,
    #[error("invalid_token")]
    Token,
    #[error("aud")]
    Audience,
    #[error("iss")]
    Issuer,
    #[error("exp")]
    Expired,
    #[error("iat")]
    IssuedAt,
    #[error("nonce")]
    Nonce,
    #[error("signature")]
    Signature,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ExtraClaims {
    hd: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}
impl AdditionalClaims for ExtraClaims {}
type TokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type Response = StandardTokenResponse<TokenFields, CoreTokenType>;
type OidcClient = Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    Response,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

struct FlowClient {
    id: String,
    secret: Option<ClientSecret>,
}

pub struct PendingAuthorization {
    pub authorization_url: String,
    flow: Flow,
    issuer: String,
    client_id: String,
    redirect: RedirectUrl,
    state: CsrfToken,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
}

pub struct Provider {
    label: String,
    issuer: String,
    groups: bool,
    clients: HashMap<Flow, FlowClient>,
    metadata: RwLock<CoreProviderMetadata>,
    http: reqwest::Client,
}

impl Provider {
    pub async fn discover(
        label: &str,
        config: &ProviderConfig,
        groups: bool,
    ) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Configuration)?;
        Self::discover_with_client(label, config, groups, http).await
    }

    pub(crate) async fn discover_with_client(
        label: &str,
        config: &ProviderConfig,
        groups: bool,
        http: reqwest::Client,
    ) -> Result<Self, Error> {
        if label.is_empty()
            || config.clients.is_empty()
            || config.clients.contains_key(&Flow::Device)
        {
            return Err(Error::Configuration);
        }
        let issuer = IssuerUrl::new(config.issuer.clone()).map_err(|_| Error::Configuration)?;
        if !https_url(issuer.url()) {
            return Err(Error::Configuration);
        }
        let mut clients = HashMap::new();
        for (flow, client) in &config.clients {
            if client.client_id.is_empty() {
                return Err(Error::Configuration);
            }
            let secret = client
                .client_secret_file
                .as_ref()
                .map(|file| {
                    let metadata =
                        std::fs::symlink_metadata(file).map_err(|_| Error::Configuration)?;
                    if !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.uid() != unsafe { libc::geteuid() }
                        || metadata.permissions().mode() & 0o077 != 0
                        || metadata.len() > 4096
                    {
                        return Err(Error::Configuration);
                    }
                    let value = std::fs::read_to_string(file).map_err(|_| Error::Configuration)?;
                    let value = value.trim_end_matches('\n');
                    if value.is_empty() {
                        return Err(Error::Configuration);
                    }
                    Ok(ClientSecret::new(value.into()))
                })
                .transpose()?;
            clients.insert(
                *flow,
                FlowClient {
                    id: client.client_id.clone(),
                    secret,
                },
            );
        }
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|_| Error::Unavailable)?;
        if !https_url(metadata.authorization_endpoint().url())
            || !https_url(metadata.jwks_uri().url())
            || !metadata
                .token_endpoint()
                .is_some_and(|v| https_url(v.url()))
            || allowed_algs(&metadata).is_empty()
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            label: label.into(),
            issuer: config.issuer.clone(),
            groups,
            clients,
            metadata: RwLock::new(metadata),
            http,
        })
    }

    fn client(
        &self,
        metadata: CoreProviderMetadata,
        flow: Flow,
        redirect: &RedirectUrl,
    ) -> Result<OidcClient, Error> {
        if flow == Flow::Device {
            return Err(Error::UnsupportedFlow);
        }
        let client = self.clients.get(&flow).ok_or(Error::UnsupportedFlow)?;
        Ok(OidcClient::from_provider_metadata(
            metadata,
            ClientId::new(client.id.clone()),
            client.secret.clone(),
        )
        .set_redirect_uri(redirect.clone()))
    }

    pub fn begin(&self, flow: Flow, redirect_uri: &str) -> Result<PendingAuthorization, Error> {
        if flow == Flow::Device {
            return Err(Error::UnsupportedFlow);
        }
        let redirect = loopback_redirect(redirect_uri)?;
        let metadata = self
            .metadata
            .read()
            .map_err(|_| Error::Unavailable)?
            .clone();
        let client = self.client(metadata, flow, &redirect)?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge)
            .add_scope(Scope::new("email".into()));
        if self.groups {
            request = request.add_scope(Scope::new("groups".into()));
        }
        request = if self.issuer == "https://accounts.google.com" {
            request
                .add_prompt(CoreAuthPrompt::Consent)
                .add_prompt(CoreAuthPrompt::SelectAccount)
        } else {
            request.add_prompt(CoreAuthPrompt::Login)
        };
        let (url, state, nonce) = request.url();
        let client_id = self
            .clients
            .get(&flow)
            .ok_or(Error::UnsupportedFlow)?
            .id
            .clone();
        Ok(PendingAuthorization {
            authorization_url: url.into(),
            flow,
            issuer: self.issuer.clone(),
            client_id,
            redirect,
            state,
            nonce,
            verifier,
        })
    }

    pub async fn exchange(
        &self,
        pending: PendingAuthorization,
        code: &str,
        state: &str,
        now: &(dyn Fn() -> i64 + Send + Sync),
    ) -> Result<VerifiedClaims, Error> {
        use subtle::ConstantTimeEq;
        if !bool::from(pending.state.secret().as_bytes().ct_eq(state.as_bytes())) {
            return Err(Error::State);
        }
        if pending.issuer != self.issuer
            || self.clients.get(&pending.flow).map(|v| v.id.as_str())
                != Some(pending.client_id.as_str())
        {
            return Err(Error::Configuration);
        }
        let metadata = self
            .metadata
            .read()
            .map_err(|_| Error::Unavailable)?
            .clone();
        let client = self.client(metadata.clone(), pending.flow, &pending.redirect)?;
        let response = client
            .exchange_code(AuthorizationCode::new(code.into()))
            .map_err(|_| Error::Configuration)?
            .set_pkce_verifier(pending.verifier)
            .request_async(&self.http)
            .await
            .map_err(|error| {
                if let RequestTokenError::Parse(_, body) = error {
                    if body_has_bare_google_issuer(&body) {
                        return Error::UnsupportedIssuer;
                    }
                }
                Error::Unavailable
            })?;
        let token = response.id_token().ok_or(Error::Token)?;
        let mut verified = self.verify(&client, &metadata, token, &pending.nonce, now());
        if matches!(
            verified,
            Err(ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::NoMatchingKey
            ))
        ) {
            let jwks: CoreJsonWebKeySet =
                CoreJsonWebKeySet::fetch_async(metadata.jwks_uri(), &self.http)
                    .await
                    .map_err(|_| Error::Unavailable)?;
            let updated = metadata.set_jwks(jwks);
            let retry_client = self.client(updated.clone(), pending.flow, &pending.redirect)?;
            *self.metadata.write().map_err(|_| Error::Unavailable)? = updated.clone();
            verified = self.verify(&retry_client, &updated, token, &pending.nonce, now());
        }
        let claims = verified.map_err(claim_error)?;
        if claims.audiences().len() > 1
            && claims.authorized_party().map(|v| v.as_str()) != Some(pending.client_id.as_str())
        {
            return Err(Error::Audience);
        }
        let email_verified = claims.email_verified().unwrap_or(false);
        Ok(VerifiedClaims {
            provider: self.label.clone(),
            iss: self.issuer.clone(),
            sub: claims.subject().to_string(),
            email: if email_verified {
                claims.email().map(|v| v.to_string())
            } else {
                None
            },
            email_verified,
            hd: claims.additional_claims().hd.clone(),
            groups: claims.additional_claims().groups.clone(),
            preferred_username: claims.preferred_username().map(|v| v.to_string()),
        })
    }

    fn verify(
        &self,
        client: &OidcClient,
        metadata: &CoreProviderMetadata,
        token: &openidconnect::IdToken<
            ExtraClaims,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >,
        nonce: &Nonce,
        now: i64,
    ) -> Result<openidconnect::IdTokenClaims<ExtraClaims, CoreGenderClaim>, ClaimsVerificationError>
    {
        let instant = chrono::DateTime::from_timestamp(now, 0)
            .ok_or_else(|| ClaimsVerificationError::Other("invalid verification time".into()))?;
        let latest_issue = instant
            .checked_add_signed(chrono::Duration::seconds(300))
            .ok_or_else(|| ClaimsVerificationError::Other("invalid verification time".into()))?;
        let verifier = client
            .id_token_verifier()
            .set_allowed_algs(allowed_algs(metadata))
            .set_other_audience_verifier_fn(|_| true)
            .set_time_fn(move || instant)
            .set_issue_time_verifier_fn(move |issued| {
                if issued > latest_issue {
                    Err("future issue time".into())
                } else {
                    Ok(())
                }
            });
        token.claims(&verifier, nonce).cloned()
    }
}

fn allowed_algs(metadata: &CoreProviderMetadata) -> Vec<CoreJwsSigningAlgorithm> {
    metadata
        .id_token_signing_alg_values_supported()
        .iter()
        .filter(|alg| {
            matches!(
                alg,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
                    | CoreJwsSigningAlgorithm::EcdsaP256Sha256
            )
        })
        .cloned()
        .collect()
}

fn https_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn loopback_redirect(value: &str) -> Result<RedirectUrl, Error> {
    let authority = value
        .strip_prefix("http://")
        .and_then(|v| v.split_once('/'))
        .map(|(authority, _)| authority)
        .ok_or(Error::Configuration)?;
    let port = authority
        .strip_prefix("127.0.0.1:")
        .or_else(|| authority.strip_prefix("[::1]:"))
        .ok_or(Error::Configuration)?;
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || port.parse::<u16>().ok().is_none_or(|v| v == 0)
    {
        return Err(Error::Configuration);
    }
    let redirect = RedirectUrl::new(value.into()).map_err(|_| Error::Configuration)?;
    let url = redirect.url();
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/cb"
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.host(), Some(openidconnect::url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST)
            && !matches!(url.host(), Some(openidconnect::url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST)
    {
        return Err(Error::Configuration);
    }
    Ok(redirect)
}

fn body_has_bare_google_issuer(body: &[u8]) -> bool {
    let Ok(response) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let Some(token) = response.get("id_token").and_then(|v| v.as_str()) else {
        return false;
    };
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(payload) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&payload)
        .ok()
        .and_then(|v| {
            v.get("iss")
                .and_then(|v| v.as_str())
                .map(|v| v == "accounts.google.com")
        })
        == Some(true)
}

fn claim_error(error: ClaimsVerificationError) -> Error {
    match error {
        ClaimsVerificationError::InvalidAudience(_) => Error::Audience,
        ClaimsVerificationError::InvalidIssuer(_) => Error::Issuer,
        ClaimsVerificationError::InvalidNonce(_) => Error::Nonce,
        ClaimsVerificationError::Expired(value) if value == "future issue time" => Error::IssuedAt,
        ClaimsVerificationError::Expired(_) => Error::Expired,
        ClaimsVerificationError::SignatureVerification(_) => Error::Signature,
        _ => Error::Token,
    }
}
#[cfg(test)]
mod tests {
    fn begin_fixture(issuer: &str) -> Provider {
        let metadata: CoreProviderMetadata = serde_json::from_value(serde_json::json!({
            "issuer": issuer, "authorization_endpoint": "https://fixture.example/authorize",
            "token_endpoint": "https://fixture.example/token", "jwks_uri": "https://fixture.example/jwks",
            "response_types_supported": ["code"], "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"]
        })).unwrap();
        Provider {
            label: "fixture".into(),
            issuer: issuer.into(),
            groups: true,
            clients: HashMap::from([
                (
                    Flow::Loopback,
                    FlowClient {
                        id: "loopback-client".into(),
                        secret: None,
                    },
                ),
                (
                    Flow::Paste,
                    FlowClient {
                        id: "paste-client".into(),
                        secret: None,
                    },
                ),
            ]),
            metadata: RwLock::new(metadata),
            http: reqwest::Client::new(),
        }
    }

    #[test]
    fn browser_flows_bind_clients_and_force_the_prompt_and_pkce() {
        for issuer in ["https://accounts.google.com", "https://fixture.example"] {
            let provider = begin_fixture(issuer);
            for (flow, client) in [
                (Flow::Loopback, "loopback-client"),
                (Flow::Paste, "paste-client"),
            ] {
                let pending = provider.begin(flow, "http://127.0.0.1:18551/cb").unwrap();
                let url = reqwest::Url::parse(&pending.authorization_url).unwrap();
                let pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
                assert_eq!(pairs.get("client_id").unwrap(), client);
                assert_eq!(
                    pairs.get("prompt").unwrap(),
                    if issuer == "https://accounts.google.com" {
                        "consent select_account"
                    } else {
                        "login"
                    }
                );
                assert_eq!(pairs.get("code_challenge_method").unwrap(), "S256");
                assert!(pairs
                    .get("state")
                    .is_some_and(|v| v == pending.state.secret()));
                assert!(pairs
                    .get("nonce")
                    .is_some_and(|v| v == pending.nonce.secret()));
                assert_eq!(pairs.get("scope").unwrap(), "openid email groups");
            }
            assert!(matches!(
                provider.begin(Flow::Device, "http://127.0.0.1:18551/cb"),
                Err(Error::UnsupportedFlow)
            ));
        }
    }

    #[test]
    fn redirects_accept_only_explicit_loopback_literals_and_cb() {
        for value in [
            "http://127.0.0.1:18551/cb",
            "http://[::1]:18551/cb",
            "http://127.0.0.1:80/cb",
        ] {
            assert!(loopback_redirect(value).is_ok(), "valid literal refused");
        }
        for value in [
            "https://127.0.0.1:18551/cb",
            "http://localhost:18551/cb",
            "http://127.1:18551/cb",
            "http://2130706433:18551/cb",
            "http://127.0.0.1:0/cb",
            "http://127.0.0.1:18551/else",
            "http://127.0.0.1:18551/cb?x=1",
            "http://user@127.0.0.1:18551/cb",
        ] {
            assert!(
                loopback_redirect(value).is_err(),
                "nonliteral redirect accepted"
            );
        }
    }

    #[test]
    fn sdk_issuer_url_requires_an_absolute_url() {
        assert!(openidconnect::IssuerUrl::new("https://accounts.google.com".into()).is_ok());
        let result = openidconnect::IssuerUrl::new("accounts.google.com".into());
        assert!(
            result.is_err(),
            "SDK unexpectedly accepts the legacy bare issuer"
        );
        println!("bare-google-issuer-constructor: refused {result:?}");
        let result = serde_json::from_str::<openidconnect::IssuerUrl>("\"accounts.google.com\"");
        assert!(result.is_err());
        println!("bare-google-issuer-deserialization: refused {result:?}");
        use base64::Engine;
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        for issuer in ["https://accounts.google.com", "accounts.google.com"] {
            let claims = serde_json::json!({"iss":issuer,"sub":"fixture-sub","aud":"fixture-client","exp":2000000000,"iat":1700000000});
            let token = format!(
                "{}.{}.{}",
                encode(br#"{"alg":"RS256","kid":"fixture"}"#),
                encode(claims.to_string().as_bytes()),
                encode(&[0; 32])
            );
            let parsed = token.parse::<openidconnect::core::CoreIdToken>();
            if issuer.starts_with("https://") {
                assert!(parsed.is_ok(), "canonical issuer parse control failed");
                println!("canonical-google-id-token-parse: accepted");
            } else {
                let error = parsed.err().expect("bare issuer unexpectedly parsed");
                println!("bare-google-id-token-parse: refused {error}");
            }
        }
    }
}
