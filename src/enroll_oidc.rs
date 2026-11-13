//! OIDC browser-flow verification for node enrollment.

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
