//! Enrollment authority core. OIDC verification belongs to the caller's verifier.
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Flow {
    Loopback,
    Paste,
    Device,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret_file: Option<PathBuf>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub issuer: String,
    pub clients: HashMap<Flow, ClientConfig>,
}
impl Provider {
    pub fn client(&self, flow: Flow) -> Result<&ClientConfig, Error> {
        if flow == Flow::Device {
            return Err(Error::UnsupportedFlow);
        }
        self.clients.get(&flow).ok_or(Error::UnsupportedFlow)
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserRule {
    pub provider: String,
    pub email: Option<String>,
    pub hd: Option<String>,
    pub group: Option<String>,
    pub sub: Option<String>,
    pub user: Option<String>,
    pub user_from: Option<String>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deny {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub subs: Vec<String>,
    #[serde(default)]
    pub spkis: Vec<String>,
}
fn lifetime() -> i64 {
    86400
}
fn grace() -> i64 {
    604800
}
fn reauth() -> i64 {
    7776000
}
fn issue_rate() -> usize {
    20
}
fn renew_rate() -> usize {
    6
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub trust_domain: String,
    pub providers: HashMap<String, Provider>,
    pub users: Vec<UserRule>,
    #[serde(default)]
    pub deny: Deny,
    #[serde(default = "lifetime")]
    pub lifetime_secs: i64,
    #[serde(default = "grace")]
    pub renew_grace_secs: i64,
    #[serde(default = "reauth")]
    pub reauth_after_secs: i64,
    #[serde(default = "issue_rate")]
    pub issue_per_hour: usize,
    #[serde(default = "renew_rate")]
    pub renew_per_hour: usize,
    pub hub_address: Option<String>,
}
/// Construct only from the OIDC verifier's accepted projection, never request JSON.
#[derive(Clone)]
pub struct VerifiedClaims {
    pub provider: String,
    pub iss: String,
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub hd: Option<String>,
    pub groups: Vec<String>,
    pub preferred_username: Option<String>,
}
#[derive(Clone)]
pub struct VerifiedCsr {
    key: rcgen::PublicKey,
}
impl VerifiedCsr {
    pub fn parse_pem(pem: &str) -> Result<Self, Error> {
        if pem.len() > 65536 {
            return Err(Error::InvalidCsr);
        }
        let parsed =
            rcgen::CertificateSigningRequestParams::from_pem(pem).map_err(|_| Error::InvalidCsr)?;
        if parsed.public_key.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
            return Err(Error::UnsupportedKey);
        }
        Ok(Self {
            key: parsed.public_key,
        })
    }
    pub fn spki_der(&self) -> Vec<u8> {
        use rcgen::PublicKeyData;
        self.key.subject_public_key_info()
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("enrollment core not initialized")]
    NotReady,
    #[error("unsupported_flow")]
    UnsupportedFlow,
    #[error("invalid_policy")]
    InvalidPolicy,
    #[error("invalid_csr")]
    InvalidCsr,
    #[error("unsupported_key")]
    UnsupportedKey,
    #[error("invalid_ca_key: root.crt/root.key must match; root.key must be owner-private")]
    InvalidCaKey,
    #[error("denied")]
    Denied,
    #[error("invalid_name")]
    InvalidName,
    #[error("already the primary binding of '{0}'; unbind it first")]
    AlreadyPrimary(String),
    #[error("name_bound")]
    NameBound,
    #[error("reserved_name")]
    ReservedName,
    #[error("superseded")]
    Superseded,
    #[error("reenroll_required")]
    ReenrollRequired,
    #[error("reauth_required")]
    ReauthRequired,
    #[error("rate_limited")]
    RateLimited,
    #[error("enrollment storage unavailable")]
    Storage,
}
#[derive(Clone, Serialize)]
pub struct Issued {
    pub cert_chain_pem: String,
    pub root_pem: String,
    pub uri: String,
    pub serial: String,
    pub spki_sha256: String,
    pub not_after: i64,
    pub superseded_serials: Vec<String>,
}
pub struct ServerIdentity {
    pub cert_chain_pem: String,
    pub cert_chain_der: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
    pub uri: String,
}
#[derive(Clone, Serialize)]
pub struct CertificateRecord {
    pub serial: String,
    pub user: String,
    pub host: String,
    pub spki_sha256: String,
    pub iss: String,
    pub sub: String,
    pub oidc_at: i64,
    pub issued_at: i64,
    pub not_after: i64,
    pub superseded_at: Option<i64>,
}
#[derive(Clone, Serialize)]
pub struct ReloadStatus {
    pub degraded: bool,
}
struct LivePolicy {
    policy: Arc<Policy>,
    hash: Vec<u8>,
    degraded: bool,
}
pub struct EnrollCa {
    db: Arc<Mutex<Connection>>,
    policy_file: PathBuf,
    live: Mutex<LivePolicy>,
    own_node_name: String,
    root_pem: String,
    root_der: Vec<u8>,
    signer: rcgen::Issuer<'static, rcgen::KeyPair>,
}
impl Policy {
    pub fn from_json(text: &str) -> Result<Self, Error> {
        let p: Self = serde_json::from_str(text).map_err(|_| Error::InvalidPolicy)?;
        p.validate()?;
        Ok(p)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.trust_domain.is_empty()
            || self.trust_domain.contains(['/', ':', '@', '?', '#'])
            || self.trust_domain.chars().any(char::is_whitespace)
            || self.providers.is_empty()
            || self.lifetime_secs <= 0
            || self.renew_grace_secs < 0
            || self.reauth_after_secs <= 0
            || self.issue_per_hour == 0
            || self.renew_per_hour == 0
        {
            return Err(Error::InvalidPolicy);
        }
        for p in self.providers.values() {
            if !p.issuer.starts_with("https://")
                || p.issuer.contains(['?', '#'])
                || p.clients.contains_key(&Flow::Device)
                || p.clients.is_empty()
                || p.clients.values().any(|c| c.client_id.is_empty())
            {
                return Err(Error::InvalidPolicy);
            }
        }
        for r in &self.users {
            if !self.providers.contains_key(&r.provider)
                || [&r.email, &r.hd, &r.group, &r.sub]
                    .iter()
                    .filter(|v| v.is_some())
                    .count()
                    != 1
                || usize::from(r.user.is_some()) + usize::from(r.user_from.is_some()) != 1
                || r.user.as_ref().is_some_and(|u| !valid_segment(u))
                || r.user_from.as_ref().is_some_and(|f| {
                    !matches!(f.as_str(), "email_local" | "preferred_username" | "sub")
                })
            {
                return Err(Error::InvalidPolicy);
            }
        }
        Ok(())
    }
    pub fn provider(&self, name: &str) -> Result<&Provider, Error> {
        self.providers.get(name).ok_or(Error::Denied)
    }
    pub fn needs_groups(&self, provider: &str) -> bool {
        self.users
            .iter()
            .any(|r| r.provider == provider && r.group.is_some())
    }
    fn user(&self, c: &VerifiedClaims) -> Result<(String, String), Error> {
        let provider = self.provider(&c.provider)?;
        if c.iss != provider.issuer || c.sub.is_empty() {
            return Err(Error::Denied);
        }
        let r = self
            .users
            .iter()
            .find(|r| {
                r.provider == c.provider
                    && (r
                        .email
                        .as_ref()
                        .is_some_and(|v| c.email_verified && c.email.as_ref() == Some(v))
                        || r.hd.as_ref().is_some_and(|v| c.hd.as_ref() == Some(v))
                        || r.group.as_ref().is_some_and(|v| c.groups.contains(v))
                        || r.sub.as_ref().is_some_and(|v| &c.sub == v))
            })
            .ok_or(Error::Denied)?;
        let user = match (&r.user, r.user_from.as_deref()) {
            (Some(u), _) => u.clone(),
            (_, Some("email_local")) if c.email_verified => c
                .email
                .as_deref()
                .and_then(|v| v.split_once('@'))
                .map(|(u, _)| u.to_lowercase())
                .ok_or(Error::InvalidName)?,
            (_, Some("preferred_username")) => {
                c.preferred_username.clone().ok_or(Error::InvalidName)?
            }
            (_, Some("sub")) => c.sub.clone(),
            _ => return Err(Error::InvalidName),
        };
        if !valid_segment(&user) {
            return Err(Error::InvalidName);
        }
        Ok((user, provider.issuer.clone()))
    }
}
pub fn valid_segment(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && v.as_bytes()[0] != b'-'
        && v.as_bytes()[v.len() - 1] != b'-'
}
fn digest(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}
fn spki_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(digest(bytes)))
}
fn unix_now() -> Result<i64, Error> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Storage)?
        .as_secs() as i64)
}
fn read_owned(path: &Path, key: bool) -> Result<Vec<u8>, Error> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::InvalidCaKey)?;
    let m = f.metadata().map_err(|_| Error::InvalidCaKey)?;
    if !m.is_file()
        || m.uid() != crate::client::current_uid()
        || m.len() > 1024 * 1024
        || (key && m.permissions().mode() & 0o077 != 0)
    {
        return Err(Error::InvalidCaKey);
    }
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(|_| Error::InvalidCaKey)?;
    Ok(bytes)
}
fn root_files(
    dir: &Path,
    now: i64,
) -> Result<(String, Vec<u8>, rcgen::Issuer<'static, rcgen::KeyPair>), Error> {
    use rustls::pki_types::pem::PemObject;
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|_| Error::InvalidCaKey)?;
    }
    let m = std::fs::symlink_metadata(dir).map_err(|_| Error::InvalidCaKey)?;
    if !m.is_dir() || m.uid() != crate::client::current_uid() || m.permissions().mode() & 0o022 != 0
    {
        return Err(Error::InvalidCaKey);
    }
    let cert = dir.join("root.crt");
    let key = dir.join("root.key");
    let cert_exists = std::fs::symlink_metadata(&cert).is_ok();
    let key_exists = std::fs::symlink_metadata(&key).is_ok();
    if !cert_exists && !key_exists {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|_| Error::InvalidCaKey)?;
        let mut p = rcgen::CertificateParams::default();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "xmsg enrollment CA");
        p.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        p.not_before = time::OffsetDateTime::from_unix_timestamp(
            now.checked_sub(300).ok_or(Error::InvalidCaKey)?,
        )
        .map_err(|_| Error::InvalidCaKey)?;
        p.not_after = time::OffsetDateTime::from_unix_timestamp(
            now.checked_add(10 * 365 * 86400)
                .ok_or(Error::InvalidCaKey)?,
        )
        .map_err(|_| Error::InvalidCaKey)?;
        let root = p.self_signed(&kp).map_err(|_| Error::InvalidCaKey)?;
        for (path, data, mode) in [
            (&key, kp.serialize_pem(), 0o600),
            (&cert, root.pem(), 0o644),
        ] {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|_| Error::InvalidCaKey)?;
            f.write_all(data.as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|_| Error::InvalidCaKey)?;
        }
    } else if !cert_exists || !key_exists {
        return Err(Error::InvalidCaKey);
    }
    let pem = String::from_utf8(read_owned(&cert, false)?).map_err(|_| Error::InvalidCaKey)?;
    let key_pem = String::from_utf8(read_owned(&key, true)?).map_err(|_| Error::InvalidCaKey)?;
    let kp = rcgen::KeyPair::from_pem(&key_pem).map_err(|_| Error::InvalidCaKey)?;
    if kp.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
        return Err(Error::InvalidCaKey);
    }
    let der = rustls::pki_types::CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|_| Error::InvalidCaKey)?
        .to_vec();
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|_| Error::InvalidCaKey)?;
    if parsed.public_key().raw != rcgen::PublicKeyData::subject_public_key_info(&kp)
        || !parsed.is_ca()
        || parsed.issuer() != parsed.subject()
        || parsed.verify_signature(None).is_err()
    {
        return Err(Error::InvalidCaKey);
    }
    let issuer = rcgen::Issuer::from_ca_cert_pem(&pem, kp).map_err(|_| Error::InvalidCaKey)?;
    Ok((pem, der, issuer))
}
impl EnrollCa {
    pub fn open(
        ca_dir: impl AsRef<Path>,
        db: Arc<Mutex<Connection>>,
        policy_file: impl AsRef<Path>,
        own_node_name: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::open_at(ca_dir, db, policy_file, own_node_name, unix_now()?)
    }
    pub fn open_at(
        ca_dir: impl AsRef<Path>,
        db: Arc<Mutex<Connection>>,
        policy_file: impl AsRef<Path>,
        own_node_name: impl Into<String>,
        now: i64,
    ) -> Result<Self, Error> {
        let policy_file = policy_file.as_ref().to_path_buf();
        let bytes = std::fs::read(&policy_file).map_err(|_| Error::InvalidPolicy)?;
        let policy = Arc::new(Policy::from_json(
            std::str::from_utf8(&bytes).map_err(|_| Error::InvalidPolicy)?,
        )?);
        let (root_pem, root_der, signer) = root_files(ca_dir.as_ref(), now)?;
        db.lock().map_err(|_|Error::Storage)?.execute_batch("CREATE TABLE IF NOT EXISTS enroll_bindings(user TEXT PRIMARY KEY,iss TEXT NOT NULL,sub TEXT NOT NULL,created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS enroll_aliases(iss TEXT NOT NULL,sub TEXT NOT NULL,user TEXT NOT NULL REFERENCES enroll_bindings(user),created_at INTEGER NOT NULL,PRIMARY KEY(iss,sub)); CREATE TABLE IF NOT EXISTS enroll_certs(serial TEXT PRIMARY KEY,user TEXT NOT NULL,host TEXT NOT NULL,spki_sha256 TEXT NOT NULL,iss TEXT NOT NULL,sub TEXT NOT NULL,oidc_at INTEGER NOT NULL,issued_at INTEGER NOT NULL,not_after INTEGER NOT NULL,superseded_at INTEGER); CREATE TABLE IF NOT EXISTS enroll_rates(user TEXT NOT NULL,kind TEXT NOT NULL,at INTEGER NOT NULL);").map_err(|_|Error::Storage)?;
        Ok(Self {
            db,
            policy_file,
            live: Mutex::new(LivePolicy {
                policy,
                hash: digest(&bytes),
                degraded: false,
            }),
            own_node_name: own_node_name.into(),
            root_pem,
            root_der,
            signer,
        })
    }
    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }
    pub fn policy(&self) -> Arc<Policy> {
        self.live.lock().unwrap().policy.clone()
    }
    pub fn reload_status(&self) -> ReloadStatus {
        ReloadStatus {
            degraded: self.live.lock().unwrap().degraded,
        }
    }
    pub fn reload_policy(&self) -> Result<bool, Error> {
        let read = std::fs::read(&self.policy_file).map_err(|_| Error::InvalidPolicy);
        let mut live = self.live.lock().map_err(|_| Error::Storage)?;
        let candidate = read.and_then(|bytes| {
            let hash = digest(&bytes);
            if hash == live.hash {
                return Ok(None);
            };
            let p =
                Policy::from_json(std::str::from_utf8(&bytes).map_err(|_| Error::InvalidPolicy)?)?;
            Ok(Some((Arc::new(p), hash)))
        });
        match candidate {
            Ok(Some((p, hash))) => {
                live.policy = p;
                live.hash = hash;
                live.degraded = false;
                Ok(true)
            }
            Ok(None) => {
                live.degraded = false;
                Ok(false)
            }
            Err(_) => {
                live.degraded = true;
                crate::systemd::notify_reload_failed("invalid enrollment policy");
                tracing::warn!(class="invalid_enrollment_policy",file=%self.policy_file.display(),"enrollment policy reload refused; keeping previous policy");
                Ok(false)
            }
        }
    }
    fn sign(
        &self,
        key: &impl rcgen::PublicKeyData,
        uri: &str,
        now: i64,
        lifetime: i64,
    ) -> Result<(String, String, i64), Error> {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            uri.try_into().map_err(|_| Error::InvalidName)?,
        )];
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let mut serial = [0u8; 16];
        getrandom::fill(&mut serial).map_err(|_| Error::Storage)?;
        serial[0] &= 0x7f;
        if serial[0] == 0 {
            serial[0] = 1;
        }
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        let not_after = now.checked_add(lifetime).ok_or(Error::Storage)?;
        params.not_before =
            time::OffsetDateTime::from_unix_timestamp(now.checked_sub(300).ok_or(Error::Storage)?)
                .map_err(|_| Error::Storage)?;
        params.not_after =
            time::OffsetDateTime::from_unix_timestamp(not_after).map_err(|_| Error::Storage)?;
        let leaf = params
            .signed_by(key, &self.signer)
            .map_err(|_| Error::Storage)?;
        Ok((
            format!("{}{}", leaf.pem(), self.root_pem),
            hex::encode(serial),
            not_after,
        ))
    }
    pub fn reserved_uri(&self) -> String {
        format!("spiffe://{}/xmsg/enroll", self.policy().trust_domain)
    }
    pub fn server_identity(&self, now: i64) -> Result<ServerIdentity, Error> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|_| Error::Storage)?;
        let uri = format!("spiffe://{}/xmsg/enroll", self.policy().trust_domain);
        let (chain, _, _) = self.sign(&key, &uri, now, self.policy().lifetime_secs)?;
        use rustls::pki_types::pem::PemObject;
        let cert_chain_der = rustls::pki_types::CertificateDer::pem_slice_iter(chain.as_bytes())
            .map(|c| c.map(|d| d.to_vec()).map_err(|_| Error::Storage))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ServerIdentity {
            cert_chain_pem: chain,
            cert_chain_der,
            key_der: key.serialize_der(),
            uri,
        })
    }
    fn denied(p: &Policy, user: &str, host: &str, sub: &str, spki: &str) -> bool {
        p.deny.users.iter().any(|v| v == user)
            || p.deny.hosts.iter().any(|v| v == host)
            || p.deny.subs.iter().any(|v| v == sub)
            || p.deny.spkis.iter().any(|v| v == spki)
    }
    fn rate(
        tx: &rusqlite::Transaction<'_>,
        p: &Policy,
        user: &str,
        kind: &str,
        now: i64,
    ) -> Result<(), Error> {
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM enroll_rates WHERE user=?1 AND kind=?2 AND at>?3-3600",
                rusqlite::params![user, kind, now],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)?;
        let cap = if kind == "issue" {
            p.issue_per_hour
        } else {
            p.renew_per_hour
        };
        if count >= cap as i64 {
            return Err(Error::RateLimited);
        }
        tx.execute("DELETE FROM enroll_rates WHERE at<=?1-3600", [now])
            .map_err(|_| Error::Storage)?;
        tx.execute(
            "INSERT INTO enroll_rates VALUES(?1,?2,?3)",
            rusqlite::params![user, kind, now],
        )
        .map_err(|_| Error::Storage)?;
        Ok(())
    }
    pub fn issue(
        &self,
        claims: &VerifiedClaims,
        csr: &VerifiedCsr,
        host: &str,
        reserved_names: &[String],
        now: i64,
    ) -> Result<Issued, Error> {
        self.reload_policy()?;
        let p = self.policy();
        if !valid_segment(host) {
            return Err(Error::InvalidName);
        }
        let (user, iss) = p.user(claims)?;
        let name = format!("{user}.{host}");
        if name == self.own_node_name || reserved_names.contains(&name) {
            return Err(Error::ReservedName);
        }
        let spki = spki_hash(&rcsr_spki(csr));
        if Self::denied(&p, &user, host, &claims.sub, &spki) {
            return Err(Error::Denied);
        }
        let mut db = self.db.lock().map_err(|_| Error::Storage)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        use rusqlite::OptionalExtension;
        let binding: Option<(String, String)> = tx
            .query_row(
                "SELECT iss,sub FROM enroll_bindings WHERE user=?1",
                [&user],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        let alias: Option<String> = tx
            .query_row(
                "SELECT user FROM enroll_aliases WHERE iss=?1 AND sub=?2",
                rusqlite::params![iss, claims.sub],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if alias.as_ref().is_some_and(|u| u != &user) {
            return Err(Error::NameBound);
        }
        if let Some((old_iss, old_sub)) = binding {
            if (old_iss != iss || old_sub != claims.sub) && alias.as_ref() != Some(&user) {
                return Err(Error::NameBound);
            }
        } else {
            let used: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM enroll_bindings WHERE iss=?1 AND sub=?2)",
                    rusqlite::params![iss, claims.sub],
                    |r| r.get(0),
                )
                .map_err(|_| Error::Storage)?;
            if used {
                return Err(Error::NameBound);
            }
            tx.execute(
                "INSERT INTO enroll_bindings VALUES(?1,?2,?3,?4)",
                rusqlite::params![user, iss, claims.sub, now],
            )
            .map_err(|_| Error::Storage)?;
        }
        Self::rate(&tx, &p, &user, "issue", now)?;
        let mut stmt=tx.prepare("SELECT serial FROM enroll_certs WHERE user=?1 AND host=?2 AND spki_sha256!=?3 AND superseded_at IS NULL").map_err(|_|Error::Storage)?;
        let superseded_serials = stmt
            .query_map(rusqlite::params![user, host, spki], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| Error::Storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Storage)?;
        drop(stmt);
        tx.execute("UPDATE enroll_certs SET superseded_at=COALESCE(superseded_at,?4) WHERE user=?1 AND host=?2 AND spki_sha256!=?3",rusqlite::params![user,host,spki,now]).map_err(|_|Error::Storage)?;
        let uri = format!("spiffe://{}/host/{host}/user/{user}", p.trust_domain);
        let (chain, serial, not_after) = self.sign(&csr.key, &uri, now, p.lifetime_secs)?;
        tx.execute(
            "INSERT INTO enroll_certs VALUES(?1,?2,?3,?4,?5,?6,?7,?7,?8,NULL)",
            rusqlite::params![serial, user, host, spki, iss, claims.sub, now, not_after],
        )
        .map_err(|_| Error::Storage)?;
        tx.commit().map_err(|_| Error::Storage)?;
        Ok(Issued {
            cert_chain_pem: chain,
            root_pem: self.root_pem.clone(),
            uri,
            serial,
            spki_sha256: spki,
            not_after,
            superseded_serials,
        })
    }
    pub fn renew(&self, presented_chain: &[Vec<u8>], now: i64) -> Result<Issued, Error> {
        use rusqlite::OptionalExtension;
        use rustls::pki_types::{CertificateDer, UnixTime};
        self.reload_policy()?;
        let p = self.policy();
        let leaf = presented_chain.first().ok_or(Error::ReenrollRequired)?;
        let (_, parsed) =
            x509_parser::parse_x509_certificate(leaf).map_err(|_| Error::ReenrollRequired)?;
        let end = parsed.validity().not_after.timestamp();
        if now > end.saturating_add(p.renew_grace_secs) {
            return Err(Error::ReenrollRequired);
        }
        let at = now.min(end);
        let at = u64::try_from(at).map_err(|_| Error::ReenrollRequired)?;
        let anchors = crate::fed::parse_ca_bundle_pem(self.root_pem.as_bytes())
            .map_err(|_| Error::InvalidCaKey)?;
        let intermediates = presented_chain
            .iter()
            .skip(1)
            .filter(|c| *c != &self.root_der)
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect::<Vec<_>>();
        crate::fed::verify_cert_chain(
            &CertificateDer::from(leaf.as_slice()),
            &intermediates,
            &anchors,
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(at)),
            webpki::KeyUsage::client_auth(),
        )
        .map_err(|_| Error::ReenrollRequired)?;
        let serial = hex::encode(parsed.raw_serial());
        let spki = spki_hash(parsed.public_key().raw);
        let mut db = self.db.lock().map_err(|_| Error::Storage)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let record=tx.query_row("SELECT serial,user,host,spki_sha256,iss,sub,oidc_at,issued_at,not_after,superseded_at FROM enroll_certs WHERE serial=?1",[&serial],record_row).optional().map_err(|_|Error::Storage)?.ok_or(Error::ReenrollRequired)?;
        if record.spki_sha256 != spki {
            return Err(Error::ReenrollRequired);
        }
        let uri = crate::fed::extract_uri_sans(leaf).map_err(|_| Error::ReenrollRequired)?;
        if uri.len() != 1
            || crate::node::node_name_from_uri(&uri[0]).ok()
                != Some(format!("{}.{}", record.user, record.host))
        {
            return Err(Error::ReenrollRequired);
        }
        let superseded:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM enroll_certs WHERE spki_sha256=?1 AND superseded_at IS NOT NULL)",[&spki],|r|r.get(0)).map_err(|_|Error::Storage)?;
        if superseded {
            return Err(Error::Superseded);
        }
        if now.saturating_sub(record.oidc_at) > p.reauth_after_secs {
            return Err(Error::ReauthRequired);
        }
        if Self::denied(&p, &record.user, &record.host, &record.sub, &spki) {
            return Err(Error::Denied);
        }
        let bound:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM enroll_bindings WHERE user=?1 AND iss=?2 AND sub=?3 UNION ALL SELECT 1 FROM enroll_aliases WHERE user=?1 AND iss=?2 AND sub=?3)",rusqlite::params![record.user,record.iss,record.sub],|r|r.get(0)).map_err(|_|Error::Storage)?;
        if !bound {
            return Err(Error::Denied);
        }
        Self::rate(&tx, &p, &record.user, "renew", now)?;
        let key = rcgen::SubjectPublicKeyInfo::from_der(parsed.public_key().raw)
            .map_err(|_| Error::UnsupportedKey)?;
        let (chain, serial, not_after) = self.sign(&key, &uri[0], now, p.lifetime_secs)?;
        tx.execute(
            "INSERT INTO enroll_certs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL)",
            rusqlite::params![
                serial,
                record.user,
                record.host,
                spki,
                record.iss,
                record.sub,
                record.oidc_at,
                now,
                not_after
            ],
        )
        .map_err(|_| Error::Storage)?;
        tx.commit().map_err(|_| Error::Storage)?;
        Ok(Issued {
            cert_chain_pem: chain,
            root_pem: self.root_pem.clone(),
            uri: uri[0].clone(),
            serial,
            spki_sha256: spki,
            not_after,
            superseded_serials: vec![],
        })
    }
    pub fn bind(&self, user: &str, provider: &str, sub: &str, now: i64) -> Result<(), Error> {
        self.reload_policy()?;
        let p = self.policy();
        let issuer = &p.provider(provider)?.issuer;
        if sub.is_empty() {
            return Err(Error::Denied);
        }
        let mut db = self.db.lock().map_err(|_| Error::Storage)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        use rusqlite::OptionalExtension;
        let primary: Option<String> = tx
            .query_row(
                "SELECT user FROM enroll_bindings WHERE iss=?1 AND sub=?2",
                rusqlite::params![issuer, sub],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if let Some(user) = primary {
            return Err(Error::AlreadyPrimary(user));
        }
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM enroll_bindings WHERE user=?1)",
                [user],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)?;
        if !exists {
            return Err(Error::NameBound);
        }
        tx.execute(
            "INSERT INTO enroll_aliases VALUES(?1,?2,?3,?4)",
            rusqlite::params![issuer, sub, user, now],
        )
        .map_err(|_| Error::NameBound)?;
        tx.commit().map_err(|_| Error::Storage)?;
        Ok(())
    }
    pub fn unbind(&self, user: &str) -> Result<(), Error> {
        let mut db = self.db.lock().map_err(|_| Error::Storage)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        tx.execute("DELETE FROM enroll_aliases WHERE user=?1", [user])
            .map_err(|_| Error::Storage)?;
        tx.execute("DELETE FROM enroll_bindings WHERE user=?1", [user])
            .map_err(|_| Error::Storage)?;
        tx.commit().map_err(|_| Error::Storage)?;
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<CertificateRecord>, Error> {
        let db = self.db.lock().map_err(|_| Error::Storage)?;
        let mut s=db.prepare("SELECT serial,user,host,spki_sha256,iss,sub,oidc_at,issued_at,not_after,superseded_at FROM enroll_certs ORDER BY issued_at,serial").map_err(|_|Error::Storage)?;
        let rows = s
            .query_map([], record_row)
            .map_err(|_| Error::Storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Storage)?;
        Ok(rows)
    }
}
fn record_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<CertificateRecord> {
    Ok(CertificateRecord {
        serial: r.get(0)?,
        user: r.get(1)?,
        host: r.get(2)?,
        spki_sha256: r.get(3)?,
        iss: r.get(4)?,
        sub: r.get(5)?,
        oidc_at: r.get(6)?,
        issued_at: r.get(7)?,
        not_after: r.get(8)?,
        superseded_at: r.get(9)?,
    })
}
fn rcsr_spki(csr: &VerifiedCsr) -> Vec<u8> {
    use rcgen::PublicKeyData;
    csr.key.subject_public_key_info()
}

/// Initialize or validate a CA directory without requiring an issuance policy.
pub fn initialize_ca_dir(dir: impl AsRef<Path>, now: i64) -> Result<String, Error> {
    root_files(dir.as_ref(), now).map(|(pem, _, _)| pem)
}

#[cfg(test)]
#[path = "enroll_ca/tests.rs"]
mod tests;
