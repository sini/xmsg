//! Browser enrollment and certificate renewal commands.
use crate::enroll_client::{self as client, Error, SavedState, Trust};
use rcgen::PublicKeyData;
use rustls::pki_types::{pem::PemObject, CertificateDer, UnixTime};
use serde::Deserialize;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Clone, Copy, clap::ValueEnum, Debug)]
pub enum Flow {
    Loopback,
    Paste,
    Device,
}
#[derive(clap::Parser, Debug)]
pub struct Args {
    #[arg(required_unless_present = "renew")]
    pub url: Option<String>,
    #[arg(long, conflicts_with = "root_file")]
    pub fingerprint: Option<String>,
    #[arg(long, conflicts_with = "fingerprint")]
    pub root_file: Option<PathBuf>,
    #[arg(long)]
    pub provider: Option<String>,
    #[arg(long, value_enum, default_value = "loopback")]
    pub flow: Flow,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub renew: bool,
}
#[derive(Deserialize)]
struct Created {
    session: String,
    expires_in: u64,
    authorization_url: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    request_id: Option<String>,
    provider: Option<String>,
}
#[derive(Deserialize)]
struct Collected {
    cert_chain_pem: String,
    root_pem: String,
    ca_identity: String,
    hub_entry: serde_json::Value,
    serial: String,
    not_after: i64,
}
fn endpoint(url: &str, route: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(url)?;
    let mut parts = route.splitn(2, '?');
    url.set_path(parts.next().unwrap());
    url.set_query(parts.next());
    Ok(url.into())
}
fn header(handle: &str) -> Result<reqwest::header::HeaderValue> {
    let mut value = reqwest::header::HeaderValue::from_str(handle)?;
    value.set_sensitive(true);
    Ok(value)
}
async fn response(mut response: reqwest::Response) -> Result<serde_json::Value> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > 131072 {
            return Err(Error::Response.into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| Error::Response)?;
    if let Some(reason) = value
        .get("error")
        .and_then(|e| e.get("reason"))
        .and_then(|v| v.as_str())
    {
        if reason == "invalid_name" {
            let rule = value
                .get("error")
                .and_then(|e| e.get("rule"))
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "matching".into());
            return Err(
                format!("invalid_name: users rule {rule} needs a literal user mapping").into(),
            );
        }
        return Err(match reason {
            "unsupported_issuer" => "unsupported_issuer",
            "reauth_required" => "reauth_required",
            "reenroll_required" => "reenroll_required",
            "superseded" => "superseded",
            "denied" => "denied",
            "name_bound" => "name_bound",
            "reserved_name" => "reserved_name",
            _ => "enrollment_refused",
        }
        .into());
    }
    Ok(value)
}
fn private_read(directory: &Path, name: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    client::private_directory(directory)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join(name))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 131072
    {
        return Err(Error::State.into());
    }
    let mut value = Vec::new();
    file.by_ref().take(131073).read_to_end(&mut value)?;
    if value.len() > 131072 {
        return Err(Error::State.into());
    }
    Ok(value)
}
fn identity(chain_pem: &[u8], key: &[u8], trust: &Trust) -> Result<(String, i64)> {
    let chain =
        CertificateDer::pem_slice_iter(chain_pem).collect::<std::result::Result<Vec<_>, _>>()?;
    let leaf = chain.first().ok_or(Error::Response)?;
    let anchors =
        crate::fed::parse_ca_bundle_pem(trust.root_pem.as_bytes()).map_err(|_| Error::Response)?;
    crate::fed::verify_cert_chain(
        leaf,
        &chain[1..],
        &anchors,
        UnixTime::now(),
        webpki::KeyUsage::client_auth(),
    )?;
    let key = rcgen::KeyPair::from_pem(std::str::from_utf8(key)?)?;
    use sha2::Digest;
    if crate::fed::spki_sha256_from_der(leaf.as_ref()).map_err(|_| Error::Response)?
        != hex::encode(sha2::Sha256::digest(key.subject_public_key_info()))
    {
        return Err(Error::Response.into());
    }
    let uris = crate::fed::extract_uri_sans(leaf.as_ref()).map_err(|_| Error::Response)?;
    let [uri] = uris.as_slice() else {
        return Err(Error::Response.into());
    };
    crate::node::node_name_from_uri(uri).map_err(|_| Error::Response)?;
    let (_, certificate) =
        x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|_| Error::Response)?;
    Ok((
        uri.clone(),
        certificate
            .validity()
            .not_before
            .timestamp()
            .saturating_add(300),
    ))
}
fn callback_value(value: &str) -> Result<(String, String)> {
    let url = reqwest::Url::parse(value)?;
    if url.scheme() != "http"
        || !matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1"))
        || url.path() != "/cb"
    {
        return Err(Error::Response.into());
    }
    let mut code = None;
    let mut state = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "code" if code.is_none() => code = Some(value.into_owned()),
            "state" if state.is_none() => state = Some(value.into_owned()),
            "code" | "state" => return Err(Error::Response.into()),
            _ => {}
        }
    }
    Ok((code.ok_or(Error::Response)?, state.ok_or(Error::Response)?))
}
async fn callback(listener: tokio::net::TcpListener) -> Result<(String, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut socket, _) = listener.accept().await?;
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 1024];
        let count = socket.read(&mut chunk).await?;
        if count == 0 {
            return Err(Error::Response.into());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > 16384 {
            return Err(Error::Response.into());
        }
        if bytes.windows(4).any(|v| v == b"\r\n\r\n") {
            break;
        }
    }
    let line = std::str::from_utf8(&bytes)?
        .lines()
        .next()
        .ok_or(Error::Response)?;
    let mut parts = line.split_whitespace();
    if parts.next() != Some("GET") {
        return Err(Error::Response.into());
    }
    let route = parts.next().ok_or(Error::Response)?;
    let result = callback_value(&format!("http://127.0.0.1{route}"));
    let reply = if result.is_ok() {
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
    } else {
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
    };
    let _ = socket.write_all(reply).await;
    result
}
type BrowserFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<String>>> + Send + 'a>>;
pub(crate) trait Browser: Send + Sync {
    fn interact<'a>(&'a self, authorization_url: &'a str, flow: Flow) -> BrowserFuture<'a>;
    fn device<'a>(
        &'a self,
        _uri: &'a str,
        _code: &'a str,
        _request: &'a str,
        _spki_sha256: &'a str,
    ) -> BrowserFuture<'a> {
        Box::pin(async { Ok(None) })
    }
}
struct SystemBrowser;
impl Browser for SystemBrowser {
    fn interact<'a>(&'a self, authorization_url: &'a str, flow: Flow) -> BrowserFuture<'a> {
        Box::pin(async move {
            if matches!(flow, Flow::Paste) {
                println!("Paste the final loopback redirect address:");
                let value = tokio::task::spawn_blocking(|| {
                    let mut value = String::new();
                    std::io::stdin().read_line(&mut value).map(|_| value)
                })
                .await??;
                Ok(Some(value))
            } else {
                let command = if cfg!(target_os = "macos") {
                    "open"
                } else {
                    "xdg-open"
                };
                let _ = std::process::Command::new(command)
                    .arg(authorization_url)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                Ok(None)
            }
        })
    }
}

pub async fn run(args: Args) -> Result<()> {
    run_with_browser(args, &SystemBrowser).await
}

pub(crate) async fn run_with_browser(args: Args, browser: &dyn Browser) -> Result<()> {
    let is_device = matches!(args.flow, Flow::Device);
    let directory = args
        .state_dir
        .unwrap_or_else(client::default_state_directory);
    if args.renew {
        renew_once(&directory, None).await?;
        println!("enrollment certificate renewed");
        return Ok(());
    }
    let url = args.url.ok_or(Error::Configuration)?;
    let roots = args.root_file.map(std::fs::read).transpose()?;
    let trust = client::bootstrap(&url, args.fingerprint.as_deref(), roots.as_deref()).await?;
    let csr = client::create_key(&directory)?;
    let listener = if is_device {
        None
    } else {
        Some(tokio::net::TcpListener::bind("127.0.0.1:0").await?)
    };
    let redirect = listener
        .as_ref()
        .map(|listener| {
            listener
                .local_addr()
                .map(|address| format!("http://127.0.0.1:{}/cb", address.port()))
        })
        .transpose()?;
    let host = args.host.unwrap_or_else(|| {
        gethostname::gethostname()
            .to_string_lossy()
            .split('.')
            .next()
            .unwrap_or("localhost")
            .to_owned()
    });
    let flow = match args.flow {
        Flow::Paste => "paste",
        Flow::Loopback => "loopback",
        Flow::Device => "device",
    };
    let http = client::http_client(&trust, None)?;
    let value=response(http.post(endpoint(&url,"/enroll/v1/sessions")?).json(&serde_json::json!({"csr_pem":csr,"host":host,"provider":args.provider,"flow":flow,"redirect_uri":redirect})).send().await?).await?;
    let created: Created = serde_json::from_value(value).map_err(|_| Error::Response)?;
    if created.expires_in == 0 || created.expires_in > if is_device { 300 } else { 600 } {
        return Err(Error::Response.into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(created.expires_in);
    let display = |value: &str| {
        value
            .chars()
            .take(2048)
            .flat_map(char::escape_default)
            .collect::<String>()
    };
    if is_device {
        let code = created.user_code.as_deref().ok_or(Error::Response)?;
        let verification = created.verification_uri.as_deref().ok_or(Error::Response)?;
        let request = created.request_id.as_deref().ok_or(Error::Response)?;
        let projection = crate::enroll_ca::VerifiedCsr::parse_pem(&csr)?;
        use sha2::Digest;
        let key_fingerprint = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(projection.spki_der()))
        );
        println!(
            "CA: {}",
            display(&reqwest::Url::parse(&url)?.origin().ascii_serialization())
        );
        println!(
            "Provider: {}",
            display(
                created
                    .provider
                    .as_deref()
                    .or(args.provider.as_deref())
                    .unwrap_or("configured provider")
            )
        );
        println!("Requested host (not attested): {}", display(&host));
        println!("Policy user: pending verification");
        println!("SPKI SHA-256: {key_fingerprint}");
        println!("Request: {}", display(request));
        println!("Sign in at: {}", display(verification));
        println!("User code: {}", display(code));
        println!(
            "CA acceptance expires in {} seconds; CA operator approval is required.",
            created.expires_in
        );
        println!("Only enter a code from a terminal you intentionally started; never enter a code sent in a message.");
        browser
            .device(verification, code, request, &key_fingerprint)
            .await?;
    } else {
        let authorization = created
            .authorization_url
            .as_deref()
            .ok_or(Error::Response)?;
        println!("Sign in at: {}", display(authorization));
        let pasted = browser.interact(authorization, args.flow).await?;
        let (code, state) = if matches!(args.flow, Flow::Paste) {
            callback_value(pasted.ok_or(Error::Response)?.trim())?
        } else {
            tokio::time::timeout(
                Duration::from_secs(created.expires_in),
                callback(listener.unwrap()),
            )
            .await??
        };
        let _ = response(
            http.post(endpoint(&url, "/enroll/v1/sessions/code")?)
                .header("xmsg-enroll-session", header(&created.session)?)
                .json(&serde_json::json!({"code":code,"state":state}))
                .send()
                .await?,
        )
        .await?;
    }
    let mut shown_user = None;
    let collected = loop {
        let value = response(
            http.get(endpoint(&url, "/enroll/v1/sessions?wait=30")?)
                .header("xmsg-enroll-session", header(&created.session)?)
                .send()
                .await?,
        )
        .await?;
        if value.get("cert_chain_pem").is_some() {
            break serde_json::from_value::<Collected>(value).map_err(|_| Error::Response)?;
        }
        if value.get("status").and_then(|value| value.as_str()) == Some("awaiting_approval") {
            let user = value
                .get("user")
                .and_then(|value| value.as_str())
                .ok_or(Error::Response)?;
            if shown_user.as_deref() != Some(user) {
                println!("Policy user: {}; awaiting CA approval", display(user));
                shown_user = Some(user.to_owned());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Response.into());
        }
        tokio::time::sleep(Duration::from_millis(if is_device { 1000 } else { 200 })).await;
    };
    if collected.ca_identity != trust.ca_identity {
        return Err(Error::Response.into());
    }
    let root = CertificateDer::from_pem_slice(collected.root_pem.as_bytes())?;
    use sha2::Digest;
    if format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(root.as_ref()))
    ) != trust.fingerprint
    {
        return Err(Error::Response.into());
    }
    let key = private_read(&directory, "fed.key")?;
    let (uri, issued_at) = identity(collected.cert_chain_pem.as_bytes(), &key, &trust)?;
    let saved = SavedState {
        url,
        fingerprint: trust.fingerprint.clone(),
        ca_identity: trust.ca_identity.clone(),
        serial: collected.serial,
        not_after: collected.not_after,
        issued_at,
    };
    client::atomic_write(&directory, "fed.crt", collected.cert_chain_pem.as_bytes())?;
    client::atomic_write(&directory, "root.pem", trust.root_pem.as_bytes())?;
    client::atomic_write(
        &directory,
        "enroll.json",
        &serde_json::to_vec_pretty(&saved)?,
    )?;
    let mut entry = collected.hub_entry;
    let name = entry
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(Error::Response)?
        .to_owned();
    let object = entry.as_object_mut().ok_or(Error::Response)?;
    object.remove("name");
    if let Some(pem) = object.get("ca").and_then(|v| v.as_str()) {
        crate::fed::parse_ca_bundle_pem(pem.as_bytes()).map_err(|_| Error::Response)?;
        client::atomic_write(&directory, "hub-ca.pem", pem.as_bytes())?;
        object.insert(
            "ca".into(),
            serde_json::json!(std::fs::canonicalize(&directory)?.join("hub-ca.pem")),
        );
    }
    object.insert("dial".into(), serde_json::json!("outbound"));
    object.insert(
        "allow".into(),
        serde_json::json!(["send", "reply", "relayed"]),
    );
    object.insert("default_route".into(), serde_json::json!(true));
    let peers = serde_json::json!({"peers":{name:entry}});
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("peers.json"))
    {
        Ok(mut file) => file.write_all(&serde_json::to_vec_pretty(&peers)?)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            println!("Existing peers.json kept; add this hub entry: {peers}")
        }
        Err(error) => return Err(error.into()),
    }
    println!(
        "Enrolled {}",
        crate::node::node_name_from_uri(&uri).map_err(|_| Error::Response)?
    );
    println!(
        "Start: xmsg serve --enroll-state {} --peers-file {}/peers.json --fed-listen 127.0.0.1:0",
        directory.display(),
        directory.display()
    );
    Ok(())
}
pub async fn renew_once(
    directory: &Path,
    reloader: Option<&crate::fed::CredentialReloader>,
) -> Result<()> {
    let mut saved: SavedState = serde_json::from_slice(&private_read(directory, "enroll.json")?)
        .map_err(|_| Error::State)?;
    let root = private_read(directory, "root.pem")?;
    let key = private_read(directory, "fed.key")?;
    let cert = private_read(directory, "fed.crt")?;
    let trust = Trust {
        root_pem: String::from_utf8(root).map_err(|_| Error::State)?,
        fingerprint: saved.fingerprint.clone(),
        ca_identity: saved.ca_identity.clone(),
    };
    let old = CertificateDer::from_pem_slice(&cert)?;
    let old_uris = crate::fed::extract_uri_sans(old.as_ref()).map_err(|_| Error::State)?;
    let value = response(
        client::http_client(&trust, Some((&cert, &key)))?
            .post(endpoint(&saved.url, "/enroll/v1/renew")?)
            .send()
            .await?,
    )
    .await?;
    let certificate = value
        .get("cert_chain_pem")
        .and_then(|v| v.as_str())
        .ok_or(Error::Response)?;
    let (uri, issued_at) = identity(certificate.as_bytes(), &key, &trust)?;
    if old_uris.as_slice() != [uri] {
        return Err(Error::Response.into());
    }
    saved.serial = value
        .get("serial")
        .and_then(|v| v.as_str())
        .ok_or(Error::Response)?
        .to_owned();
    saved.not_after = value
        .get("not_after")
        .and_then(|v| v.as_i64())
        .ok_or(Error::Response)?;
    saved.issued_at = issued_at;
    client::atomic_write(directory, "fed.crt", certificate.as_bytes())?;
    client::atomic_write(
        directory,
        "enroll.json",
        &serde_json::to_vec_pretty(&saved)?,
    )?;
    if let Some(reloader) = reloader {
        reloader.force_reload()?;
    }
    Ok(())
}
fn renewal_due(state: &SavedState) -> i64 {
    state.issued_at.saturating_add(
        state
            .not_after
            .saturating_sub(state.issued_at)
            .saturating_mul(2)
            / 3,
    )
}
fn renewal_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(Duration::from_secs(900))
}

pub async fn auto_renew(directory: PathBuf, reloader: Arc<crate::fed::CredentialReloader>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let state = private_read(&directory, "enroll.json")
            .ok()
            .and_then(|v| serde_json::from_slice::<SavedState>(&v).ok());
        let Some(state) = state else {
            tracing::warn!(
                class = "enroll_state_unavailable",
                "enrollment renewal deferred"
            );
            tokio::time::sleep(Duration::from_secs(900)).await;
            continue;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let due = renewal_due(&state);
        tokio::time::sleep(Duration::from_secs(due.saturating_sub(now).max(0) as u64)).await;
        match renew_once(&directory, Some(&reloader)).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(_) => {
                tracing::warn!(
                    class = "enroll_renewal_failed",
                    "enrollment renewal deferred"
                );
                tokio::time::sleep(backoff).await;
                backoff = renewal_backoff(backoff);
            }
        }
    }
}

#[cfg(test)]
mod renewal_policy_tests {
    use super::*;
    #[test]
    fn default_lifetime_renews_at_sixteen_hours_and_retry_stops_at_fifteen_minutes() {
        let state = SavedState {
            url: String::new(),
            fingerprint: String::new(),
            ca_identity: String::new(),
            serial: String::new(),
            issued_at: 1000,
            not_after: 1000 + 86400,
        };
        assert_eq!(
            renewal_due(&state) - state.issued_at,
            16 * 3600,
            "default certificate renewal is not at sixteen hours"
        );
        let mut delay = Duration::from_secs(1);
        for _ in 0..20 {
            delay = renewal_backoff(delay);
            assert!(
                delay <= Duration::from_secs(900),
                "renewal retry exceeded fifteen minutes"
            );
        }
        assert_eq!(delay, Duration::from_secs(900));
    }
}
