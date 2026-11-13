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
    _private: (),
}
impl VerifiedCsr {
    pub fn parse_pem(_pem: &str) -> Result<Self, Error> {
        Err(Error::NotReady)
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
    #[error("invalid_ca_key")]
    InvalidCaKey,
    #[error("denied")]
    Denied,
    #[error("invalid_name")]
    InvalidName,
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
pub struct EnrollCa {
    _private: (),
}
impl EnrollCa {
    pub fn open(
        _ca_dir: impl AsRef<Path>,
        _db: Arc<Mutex<Connection>>,
        _policy_file: impl AsRef<Path>,
        _own_node_name: impl Into<String>,
    ) -> Result<Self, Error> {
        Err(Error::NotReady)
    }
    pub fn issue(
        &self,
        _claims: &VerifiedClaims,
        _csr: &VerifiedCsr,
        _host: &str,
        _reserved_names: &[String],
        _now: i64,
    ) -> Result<Issued, Error> {
        Err(Error::NotReady)
    }
    pub fn renew(&self, _presented_chain: &[Vec<u8>], _now: i64) -> Result<Issued, Error> {
        Err(Error::NotReady)
    }
    pub fn root_pem(&self) -> &str {
        ""
    }
    pub fn server_identity(&self, _now: i64) -> Result<ServerIdentity, Error> {
        Err(Error::NotReady)
    }
    pub fn policy(&self) -> Arc<Policy> {
        unreachable!("open refuses until core implementation lands")
    }
    pub fn reload_status(&self) -> ReloadStatus {
        ReloadStatus { degraded: true }
    }
    pub fn reload_policy(&self) -> Result<bool, Error> {
        Err(Error::NotReady)
    }
    pub fn bind(&self, _user: &str, _provider: &str, _sub: &str, _now: i64) -> Result<(), Error> {
        Err(Error::NotReady)
    }
    pub fn unbind(&self, _user: &str) -> Result<(), Error> {
        Err(Error::NotReady)
    }
    pub fn list(&self) -> Result<Vec<CertificateRecord>, Error> {
        Err(Error::NotReady)
    }
}
