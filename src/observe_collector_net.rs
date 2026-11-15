use crate::fed::{PeerConfig, PeersMap};
use crate::observe_collector_auth::AuthConfig;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::io::Read;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub auth: AuthConfig,
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    #[serde(default)]
    pub web_tls: Option<WebTls>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebTls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub node: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub ca: Option<PathBuf>,
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub labels: bool,
    #[serde(default)]
    pub outbound_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid collector configuration")]
    Configuration,
    #[error("observation exporter unavailable")]
    Unavailable,
    #[error("observation exporter timed out")]
    Timeout,
    #[error("observation grant denied")]
    Denied,
    #[error("observation request pending")]
    Pending,
    #[error("outbound-only observation is unsupported")]
    Unsupported,
    #[error("invalid observation response")]
    Malformed,
    #[error("observation exporter rate limited")]
    RateLimited(u64),
}

pub fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let file = std::fs::File::open(path).map_err(|_| Error::Configuration)?;
    if !file.metadata().map_err(|_| Error::Configuration)?.is_file() {
        return Err(Error::Configuration);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Configuration)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Configuration);
    }
    Ok(bytes)
}

fn relative(base: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = read_file(path, 1024 * 1024)?;
        let mut config: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
        if config.sources.len() > 64 {
            return Err(Error::Configuration);
        }
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        relative(base, &mut config.client_cert);
        relative(base, &mut config.client_key);
        for file in [
            &mut config.auth.lookup_secret_file,
            &mut config.auth.provider_ca,
        ]
        .into_iter()
        .flatten()
        {
            relative(base, file);
        }
        if let Some(tls) = &mut config.web_tls {
            relative(base, &mut tls.cert);
            relative(base, &mut tls.key);
        }
        let mut names = BTreeSet::new();
        for source in &mut config.sources {
            crate::observe_export::Scope::new(&source.node, "collector", None, false)
                .map_err(|_| Error::Configuration)?;
            if !names.insert(source.node.clone()) {
                return Err(Error::Configuration);
            }
            if let Some(file) = &mut source.ca {
                relative(base, file);
            }
            if source.outbound_only {
                continue;
            }
            if source.address.as_ref().is_none_or(String::is_empty)
                || source.pin.is_some() == source.ca.is_some()
                || (source.pin.is_some() && source.identity.is_some())
            {
                return Err(Error::Configuration);
            }
            if source.ca.is_some() {
                let identity = source.identity.as_ref().ok_or(Error::Configuration)?;
                if identity.contains('*')
                    || crate::node::node_name_from_uri(identity)
                        .map_err(|_| Error::Configuration)?
                        != source.node
                {
                    return Err(Error::Configuration);
                }
            }
        }
        Ok(config)
    }
}

pub fn credentials(
    cert: &Path,
    key: &Path,
) -> Result<(Vec<CertificateDer<'static>>, Vec<u8>), Error> {
    let pem = read_file(cert, 1024 * 1024)?;
    let chain = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Configuration)?;
    if chain.is_empty() {
        return Err(Error::Configuration);
    }
    let key_pem = read_file(key, 1024 * 1024)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| Error::Configuration)?;
    let PrivateKeyDer::Pkcs8(key) = key else {
        return Err(Error::Configuration);
    };
    Ok((chain, key.secret_pkcs8_der().to_vec()))
}

pub struct Source {
    pub node: String,
    pub labels: bool,
    pub supported: bool,
    peer: Option<PeerConfig>,
    connector: Option<tokio_rustls::TlsConnector>,
    slot: Arc<Semaphore>,
    last_start: Mutex<Option<Instant>>,
}

pub struct Client {
    pub sources: Vec<Source>,
    slots: Arc<Semaphore>,
}

struct Leases {
    _global: OwnedSemaphorePermit,
    _node: OwnedSemaphorePermit,
}

struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn resolve_with_leases(
    leases: Leases,
    lookup: impl FnOnce() -> std::io::Result<Vec<std::net::SocketAddr>> + Send + 'static,
) -> Result<(Vec<std::net::SocketAddr>, Leases), Error> {
    let (resolved, leases) = tokio::task::spawn_blocking(move || (lookup(), leases))
        .await
        .map_err(|_| Error::Unavailable)?;
    Ok((resolved.map_err(|_| Error::Unavailable)?, leases))
}

impl Client {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let (chain, key) = credentials(&config.client_cert, &config.client_key)?;
        let mut entries = serde_json::Map::new();
        for source in config.sources.iter().filter(|source| !source.outbound_only) {
            let mut entry = serde_json::json!({"address":source.address,"allow":[]});
            if let Some(pin) = &source.pin {
                entry["pin"] = serde_json::json!(pin);
            }
            if let Some(ca) = &source.ca {
                entry["ca"] = serde_json::json!(ca);
                entry["identities"] = serde_json::json!([source.identity]);
            }
            entries.insert(source.node.clone(), entry);
        }
        let peers = Arc::new(
            PeersMap::load_from_json(&serde_json::Value::Object(entries).to_string())
                .map_err(|_| Error::Configuration)?,
        );
        let mut sources = Vec::new();
        for config_source in &config.sources {
            let (peer, connector) = if config_source.outbound_only {
                (None, None)
            } else {
                let peer = peers
                    .get_peer_config(&config_source.node)
                    .ok_or(Error::Configuration)?;
                let connector = crate::fed::make_tls_connector_with_credentials(
                    chain.clone(),
                    key.clone(),
                    &peer,
                    peers.clone(),
                )
                .map_err(|_| Error::Configuration)?;
                (Some(peer), Some(connector))
            };
            sources.push(Source {
                node: config_source.node.clone(),
                labels: config_source.labels,
                supported: !config_source.outbound_only,
                peer,
                connector,
                slot: Arc::new(Semaphore::new(1)),
                last_start: Mutex::new(None),
            });
        }
        Ok(Self {
            sources,
            slots: Arc::new(Semaphore::new(8)),
        })
    }

    pub async fn snapshot(
        &self,
        index: usize,
    ) -> Result<crate::observe_export::ExportSnapshot, Error> {
        let source = self.sources.get(index).ok_or(Error::Configuration)?;
        let path = format!("/fed/v2/observe/snapshot?v=1&labels={}", source.labels);
        let bytes = self.get(index, path).await?;
        serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)
    }

    pub async fn events(
        &self,
        index: usize,
        epoch: Option<&str>,
        scope: Option<&str>,
        after: i64,
    ) -> Result<crate::observe_export::ExportPage, Error> {
        Ok(self.events_decoded(index, epoch, scope, after).await?.page)
    }

    pub(crate) async fn events_decoded(
        &self,
        index: usize,
        epoch: Option<&str>,
        scope: Option<&str>,
        after: i64,
    ) -> Result<crate::observe_collector_decode::DecodedPage, Error> {
        let source = self.sources.get(index).ok_or(Error::Configuration)?;
        let mut url = reqwest::Url::parse("https://collector.invalid/fed/v2/observe/events")
            .map_err(|_| Error::Configuration)?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("v", "1")
                .append_pair("after", &after.to_string())
                .append_pair("limit", "200")
                .append_pair("labels", if source.labels { "true" } else { "false" });
            if let Some(epoch) = epoch {
                query.append_pair("epoch", epoch);
            }
            if let Some(scope) = scope {
                query.append_pair("scope", scope);
            }
        }
        let path = format!("{}?{}", url.path(), url.query().unwrap_or_default());
        let bytes = self.get(index, path).await?;
        crate::observe_collector_decode::decode_page(&bytes).map_err(|_| Error::Malformed)
    }

    async fn get(&self, index: usize, path: String) -> Result<Vec<u8>, Error> {
        let source = self.sources.get(index).ok_or(Error::Configuration)?;
        if !source.supported {
            return Err(Error::Unsupported);
        }
        let leases = Leases {
            _node: source
                .slot
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Pending)?,
            _global: self
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Pending)?,
        };
        {
            let mut last = source.last_start.lock().map_err(|_| Error::Unavailable)?;
            let now = Instant::now();
            if last.is_some_and(|last| now.duration_since(last) < Duration::from_secs(2)) {
                return Err(Error::Pending);
            }
            *last = Some(now);
        }
        tokio::time::timeout(Duration::from_secs(5), async move {
            let peer = source.peer.as_ref().ok_or(Error::Configuration)?;
            let address = peer.address.clone();
            // The leases stay with an uncancellable system resolver until it finishes.
            let (addresses, _leases) = resolve_with_leases(leases, move || {
                address
                    .to_socket_addrs()
                    .map(|addresses| addresses.take(16).collect::<Vec<_>>())
            })
            .await?;
            let mut connected = None;
            for address in addresses {
                if let Ok(tcp) = tokio::net::TcpStream::connect(address).await {
                    connected = Some(tcp);
                    break;
                }
            }
            let tcp = connected.ok_or(Error::Unavailable)?;
            let name =
                ServerName::try_from(source.node.clone()).map_err(|_| Error::Configuration)?;
            let tls = source
                .connector
                .as_ref()
                .ok_or(Error::Configuration)?
                .connect(name, tcp)
                .await
                .map_err(|_| Error::Unavailable)?;
            let mut builder = hyper::client::conn::http1::Builder::new();
            builder.max_buf_size(16 * 1024);
            let (mut sender, connection) = builder
                .handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|_| Error::Unavailable)?;
            let _driver = Driver(tokio::spawn(async move {
                let _ = connection.await;
            }));
            let request = hyper::Request::get(path)
                .header("host", &source.node)
                .body(Empty::<Bytes>::new())
                .map_err(|_| Error::Configuration)?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| Error::Unavailable)?;
            if response.status() == hyper::StatusCode::FORBIDDEN {
                return Err(Error::Denied);
            }
            if response.status() == hyper::StatusCode::TOO_MANY_REQUESTS {
                let seconds = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(2)
                    .clamp(2, 60);
                return Err(Error::RateLimited(seconds));
            }
            if response.status() != hyper::StatusCode::OK {
                return Err(Error::Unavailable);
            }
            if response
                .headers()
                .get("content-encoding")
                .is_some_and(|v| v != "identity")
            {
                return Err(Error::Malformed);
            }
            Limited::new(response.into_body(), 256 * 1024)
                .collect()
                .await
                .map(|body| body.to_bytes().to_vec())
                .map_err(|_| Error::Malformed)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

#[cfg(test)]
#[path = "observe_collector_net_tests.rs"]
pub(crate) mod tests;
