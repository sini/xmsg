use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use reqwest::{redirect::Policy, Certificate, Client, Url};
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub issuer: String,
    pub introspection_url: String,
    pub subjects: Vec<String>,
    pub audience: String,
    pub hosted_client: String,
    #[serde(default)]
    pub lookup_client: Option<String>,
    #[serde(default)]
    pub lookup_secret_file: Option<PathBuf>,
    #[serde(default)]
    pub provider_ca: Option<PathBuf>,
}

pub type EpochClock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct VerifiedOwner {
    pub subject: String,
    pub expires_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid bearer credential")]
    Unauthorized,
    #[error("owner access denied")]
    Forbidden,
    #[error("identity provider unavailable")]
    Unavailable,
    #[error("invalid owner authentication configuration")]
    Configuration,
}
impl AuthError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Unavailable | Self::Configuration => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

pub struct Verifier {
    config: AuthConfig,
    endpoint: Url,
    client: Client,
    lookup_secret: Option<String>,
    clock: EpochClock,
}

fn read_bounded(file: &Path, limit: u64) -> Result<Vec<u8>, AuthError> {
    let input = std::fs::File::open(file).map_err(|_| AuthError::Configuration)?;
    if !input
        .metadata()
        .map_err(|_| AuthError::Configuration)?
        .is_file()
    {
        return Err(AuthError::Configuration);
    }
    let mut bytes = Vec::new();
    input
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthError::Configuration)?;
    if bytes.len() as u64 > limit {
        return Err(AuthError::Configuration);
    }
    Ok(bytes)
}

impl Verifier {
    pub fn new(config: AuthConfig, clock: EpochClock) -> Result<Self, AuthError> {
        let endpoint =
            Url::parse(&config.introspection_url).map_err(|_| AuthError::Configuration)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
            || config.issuer.is_empty()
            || config.audience.is_empty()
            || config.hosted_client.is_empty()
            || config.subjects.is_empty()
            || config.subjects.iter().any(String::is_empty)
        {
            return Err(AuthError::Configuration);
        }
        let lookup_secret = match (&config.lookup_client, &config.lookup_secret_file) {
            (None, None) => None,
            (Some(client), Some(file)) if !client.is_empty() => {
                let bytes = read_bounded(file, 8192)?;
                let text = String::from_utf8(bytes).map_err(|_| AuthError::Configuration)?;
                let secret = text.trim_end_matches(['\r', '\n']);
                if secret.is_empty() || secret.chars().any(char::is_control) {
                    return Err(AuthError::Configuration);
                }
                Some(secret.to_owned())
            }
            _ => return Err(AuthError::Configuration),
        };
        let mut client = Client::builder().https_only(true).redirect(Policy::none());
        if let Some(file) = &config.provider_ca {
            let bytes = read_bounded(file, 1024 * 1024)?;
            let certificate =
                Certificate::from_pem(&bytes).map_err(|_| AuthError::Configuration)?;
            client = client.add_root_certificate(certificate);
        }
        let client = client.build().map_err(|_| AuthError::Configuration)?;
        Ok(Self {
            config,
            endpoint,
            client,
            lookup_secret,
            clock,
        })
    }

    pub async fn authorize(&self, headers: &HeaderMap) -> Result<VerifiedOwner, AuthError> {
        let token = bearer(headers)?;
        tokio::time::timeout(Duration::from_secs(2), self.introspect(token))
            .await
            .map_err(|_| AuthError::Unavailable)?
    }

    async fn introspect(&self, token: &str) -> Result<VerifiedOwner, AuthError> {
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .form(&[("token", token)]);
        if let (Some(client), Some(secret)) = (&self.config.lookup_client, &self.lookup_secret) {
            request = request.basic_auth(client, Some(secret));
        }
        let mut response = request.send().await.map_err(|_| AuthError::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(AuthError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| AuthError::Unavailable)? {
            if bytes.len().saturating_add(chunk.len()) > 65_536 {
                return Err(AuthError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        let claims: Value = serde_json::from_slice(&bytes).map_err(|_| AuthError::Unavailable)?;
        self.verify_claims(&claims)
    }

    fn verify_claims(&self, claims: &Value) -> Result<VerifiedOwner, AuthError> {
        if claims.get("active").and_then(Value::as_bool) != Some(true) {
            return Err(AuthError::Unauthorized);
        }
        if claims.get("iss").and_then(Value::as_str) != Some(self.config.issuer.as_str()) {
            return Err(AuthError::Unauthorized);
        }
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .ok_or(AuthError::Unauthorized)?;
        if !self
            .config
            .subjects
            .iter()
            .any(|allowed| allowed == subject)
        {
            return Err(AuthError::Forbidden);
        }
        let audience = match claims.get("aud") {
            Some(Value::String(aud)) => aud == &self.config.audience,
            Some(Value::Array(aud)) => {
                aud.len() == 1 && aud[0].as_str() == Some(self.config.audience.as_str())
            }
            _ => false,
        };
        if !audience {
            return Err(AuthError::Unauthorized);
        }
        let client = match (claims.get("client_id"), claims.get("azp")) {
            (Some(Value::String(client)), None) | (None, Some(Value::String(client))) => client,
            (Some(Value::String(client)), Some(Value::String(azp))) if client == azp => client,
            _ => return Err(AuthError::Unauthorized),
        };
        if client != &self.config.hosted_client {
            return Err(AuthError::Unauthorized);
        }
        let expires_at = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or(AuthError::Unauthorized)?;
        let now = u64::try_from((self.clock)()).map_err(|_| AuthError::Unavailable)?;
        if expires_at <= now {
            return Err(AuthError::Unauthorized);
        }
        let not_before = match claims.get("nbf") {
            None => 0,
            Some(value) => value.as_u64().ok_or(AuthError::Unauthorized)?,
        };
        if not_before > now {
            return Err(AuthError::Unauthorized);
        }
        Ok(VerifiedOwner {
            subject: subject.to_owned(),
            expires_at,
        })
    }
}

fn bearer(headers: &HeaderMap) -> Result<&str, AuthError> {
    let size = headers.iter().fold(2usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4)
    });
    if size > 16_384 {
        return Err(AuthError::Unauthorized);
    }
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(AuthError::Unauthorized)?;
    if values.next().is_some() {
        return Err(AuthError::Unauthorized);
    }
    let value = value.to_str().map_err(|_| AuthError::Unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or(AuthError::Unauthorized)?;
    let token = token.trim_start_matches(' ');
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() || token.len() > 8192 {
        return Err(AuthError::Unauthorized);
    }
    let raw = token.trim_end_matches('=');
    if raw.is_empty()
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
    {
        return Err(AuthError::Unauthorized);
    }
    Ok(token)
}

#[cfg(test)]
#[path = "observe_collector_auth_tests.rs"]
mod tests;
