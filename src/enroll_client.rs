//! Enrollment transport and private local identity state.
use base64::Engine;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use std::os::unix::{
    fs::PermissionsExt,
    fs::{MetadataExt, OpenOptionsExt},
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid_enrollment_configuration")]
    Configuration,
    #[error("enrollment_transport_failed")]
    Transport,
    #[error("enrollment_state_unavailable")]
    State,
    #[error("private_key_already_exists")]
    KeyExists,
    #[error("invalid_enrollment_response")]
    Response,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedState {
    pub url: String,
    pub fingerprint: String,
    pub ca_identity: String,
    pub serial: String,
    pub not_after: i64,
    pub issued_at: i64,
}
#[derive(Clone, Debug)]
pub struct Trust {
    pub root_pem: String,
    pub fingerprint: String,
    pub ca_identity: String,
}
#[derive(Debug)]
struct Verifier {
    fingerprint: Option<String>,
    configured_roots: Option<Vec<rustls::pki_types::TrustAnchor<'static>>>,
    expected_identity: Option<String>,
    observed: OnceLock<Trust>,
}
fn certificate_pem(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}
fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(der)))
}
fn refused() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let root = chain.last().ok_or_else(refused)?;
        let actual = fingerprint(root.as_ref());
        if self
            .fingerprint
            .as_ref()
            .is_some_and(|expected| expected != &actual)
        {
            return Err(refused());
        }
        let uris = crate::fed::extract_uri_sans(leaf.as_ref()).map_err(|_| refused())?;
        let [identity] = uris.as_slice() else {
            return Err(refused());
        };
        let Some(rest) = identity.strip_prefix("spiffe://") else {
            return Err(refused());
        };
        let Some((domain, path)) = rest.split_once('/') else {
            return Err(refused());
        };
        if crate::fed::validate_spiffe_pattern(identity).is_err()
            || domain.contains('*')
            || domain.is_empty()
            || domain.contains(['?', '#', '@', ':'])
            || path != "xmsg/enroll"
        {
            return Err(refused());
        }
        if self
            .expected_identity
            .as_ref()
            .is_some_and(|expected| expected != identity)
            || self
                .observed
                .get()
                .is_some_and(|old| old.ca_identity != *identity)
        {
            return Err(refused());
        }
        let pem = certificate_pem(root.as_ref());
        let anchors = match &self.configured_roots {
            Some(roots) => roots.clone(),
            None => crate::fed::parse_ca_bundle_pem(pem.as_bytes()).map_err(|_| refused())?,
        };
        let verifier = crate::fed::CaServerCertVerifier::new(anchors, vec![identity.clone()]);
        verifier.verify_server_cert(leaf, chain, name, ocsp, now)?;
        let _ = self.observed.set(Trust {
            root_pem: pem,
            fingerprint: actual,
            ca_identity: identity.clone(),
        });
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
fn endpoint(url: &str) -> Result<reqwest::Url, Error> {
    let url = reqwest::Url::parse(url).map_err(|_| Error::Configuration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(Error::Configuration);
    }
    Ok(url)
}
fn tls(
    verifier: Arc<Verifier>,
    identity: Option<(&[u8], &[u8])>,
) -> Result<rustls::ClientConfig, Error> {
    use rustls::pki_types::pem::PemObject;
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error::Configuration)?
    .dangerous()
    .with_custom_certificate_verifier(verifier);
    match identity {
        None => Ok(builder.with_no_client_auth()),
        Some((cert, key)) => {
            let chain = CertificateDer::pem_slice_iter(cert)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::State)?;
            let key =
                rustls::pki_types::PrivateKeyDer::from_pem_slice(key).map_err(|_| Error::State)?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|_| Error::State)
        }
    }
}
pub async fn bootstrap(
    url: &str,
    expected_fingerprint: Option<&str>,
    root_pem: Option<&[u8]>,
) -> Result<Trust, Error> {
    let url = endpoint(url)?;
    if expected_fingerprint.is_some() == root_pem.is_some() {
        return Err(Error::Configuration);
    }
    if let Some(value) = expected_fingerprint {
        let Some(digest) = value.strip_prefix("sha256:") else {
            return Err(Error::Configuration);
        };
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Configuration);
        }
    }
    let verifier = Arc::new(Verifier {
        fingerprint: expected_fingerprint.map(str::to_ascii_lowercase),
        configured_roots: root_pem
            .map(crate::fed::parse_ca_bundle_pem)
            .transpose()
            .map_err(|_| Error::Configuration)?,
        expected_identity: None,
        observed: OnceLock::new(),
    });
    let config = tls(verifier.clone(), None)?;
    let raw_host = url.host_str().ok_or(Error::Configuration)?;
    let host = raw_host.trim_start_matches('[').trim_end_matches(']');
    let name = ServerName::try_from(host.to_owned()).map_err(|_| Error::Configuration)?;
    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect((host, url.port_or_known_default().unwrap_or(443))),
    )
    .await
    .map_err(|_| Error::Transport)?
    .map_err(|_| Error::Transport)?;
    let _stream = tokio::time::timeout(
        Duration::from_secs(3),
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .map_err(|_| Error::Transport)?
    .map_err(|_| Error::Transport)?;
    verifier.observed.get().cloned().ok_or(Error::Transport)
}
pub fn http_client(
    trust: &Trust,
    identity: Option<(&[u8], &[u8])>,
) -> Result<reqwest::Client, Error> {
    let verifier = Arc::new(Verifier {
        fingerprint: Some(trust.fingerprint.clone()),
        configured_roots: None,
        expected_identity: Some(trust.ca_identity.clone()),
        observed: OnceLock::new(),
    });
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(35))
        .use_preconfigured_tls(tls(verifier, identity)?)
        .build()
        .map_err(|_| Error::Configuration)
}
pub fn private_directory(directory: &Path) -> Result<(), Error> {
    if !directory.exists() {
        std::fs::create_dir_all(directory).map_err(|_| Error::State)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::State)?;
    }
    let metadata = std::fs::symlink_metadata(directory).map_err(|_| Error::State)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(Error::State);
    }
    Ok(())
}
pub fn create_key(directory: &Path) -> Result<String, Error> {
    use std::io::Write;
    private_directory(directory)?;
    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|_| Error::State)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("fed.key"))
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::KeyExists
            } else {
                Error::State
            }
        })?;
    file.write_all(key.serialize_pem().as_bytes())
        .map_err(|_| Error::State)?;
    let mut parameters = rcgen::CertificateParams::default();
    parameters.distinguished_name = rcgen::DistinguishedName::new();
    parameters
        .serialize_request(&key)
        .and_then(|csr| csr.pem())
        .map_err(|_| Error::State)
}
pub fn atomic_write(directory: &Path, filename: &str, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    if !matches!(
        filename,
        "fed.crt" | "root.pem" | "enroll.json" | "peers.json" | "hub-ca.pem"
    ) {
        return Err(Error::State);
    }
    private_directory(directory)?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| Error::State)?;
    let temporary = directory.join(format!(".enroll-{}", hex::encode(random)));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| Error::State)?;
        file.write_all(bytes).map_err(|_| Error::State)?;
        file.sync_all().map_err(|_| Error::State)?;
        std::fs::rename(&temporary, directory.join(filename)).map_err(|_| Error::State)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
pub fn default_state_directory() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local/state")
        })
        .join("xmsg/enroll")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_key_never_overwrites_and_atomic_files_are_private() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("identity");
        let csr = create_key(&state).unwrap();
        assert!(csr.contains("CERTIFICATE REQUEST"));
        let original = std::fs::read(state.join("fed.key")).unwrap();
        assert!(matches!(create_key(&state), Err(Error::KeyExists)));
        assert_eq!(std::fs::read(state.join("fed.key")).unwrap(), original);
        atomic_write(&state, "root.pem", b"public root").unwrap();
        assert_eq!(
            std::fs::metadata(state.join("root.pem")).unwrap().mode() & 0o777,
            0o600
        );
    }
    #[test]
    fn endpoint_requires_https_without_userinfo_or_redirect_components() {
        for value in [
            "http://ca.example",
            "https://user@ca.example",
            "https://ca.example/path",
            "https://ca.example/?q=1",
            "https://ca.example/#fragment",
        ] {
            assert!(endpoint(value).is_err());
        }
        assert!(endpoint("https://ca.example:7790/").is_ok());
    }
}
