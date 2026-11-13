//! OIDC browser-flow verification for node enrollment.

use crate::enroll_ca::{Flow, Provider as ProviderConfig, VerifiedClaims};

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
}

pub struct PendingAuthorization {
    pub authorization_url: String,
    _opaque: (),
}

pub struct Provider;
impl Provider {
    pub async fn discover(
        _label: &str,
        _config: &ProviderConfig,
        _groups: bool,
    ) -> Result<Self, Error> {
        Err(Error::Unavailable)
    }
    pub fn begin(&self, _flow: Flow, _redirect_uri: &str) -> Result<PendingAuthorization, Error> {
        Err(Error::Unavailable)
    }
    pub async fn exchange(
        &self,
        _pending: PendingAuthorization,
        _code: &str,
        _state: &str,
        _now: i64,
    ) -> Result<VerifiedClaims, Error> {
        Err(Error::Unavailable)
    }
}

#[cfg(test)]
mod tests {
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
