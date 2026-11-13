#![cfg(feature = "daemon")]

use base64::Engine;
use openidconnect::{
    core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey},
    JsonWebKeyId, PrivateSigningKey,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rustls::pki_types::{pem::PemObject, CertificateDer};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    task::JoinHandle,
};

const LIMIT: usize = 131072;
const WAIT: Duration = Duration::from_secs(25);

struct DeviceCode {
    device: String,
    approved: bool,
    used: bool,
}
struct IdpState {
    issuer: String,
    signing: CoreRsaPrivateSigningKey,
    codes: HashMap<String, DeviceCode>,
    paths: Vec<String>,
}
impl IdpState {
    fn response(&mut self, route: &str, body: &[u8]) -> (u16, Value) {
        self.paths.push(route.into());
        let fields: HashMap<String, String> = openidconnect::url::form_urlencoded::parse(body)
            .into_owned()
            .collect();
        match route {
            "/.well-known/openid-configuration" => (
                200,
                json!({"issuer":self.issuer,"authorization_endpoint":format!("{}/authorize",self.issuer),"token_endpoint":format!("{}/token",self.issuer),"jwks_uri":format!("{}/jwks",self.issuer),"device_authorization_endpoint":format!("{}/device",self.issuer),"grant_types_supported":["urn:ietf:params:oauth:grant-type:device_code"],"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["none"]}),
            ),
            "/jwks" => (200, json!({"keys":[self.signing.as_verification_key()]})),
            "/device" => {
                assert_eq!(
                    fields.get("client_id").map(String::as_str),
                    Some("device-client")
                );
                assert!(!fields.contains_key("nonce") && !fields.contains_key("code_challenge"));
                assert!(!fields.contains_key("client_secret"));
                let user = format!("TEST-{}", ulid::Ulid::new());
                let device = format!("synthetic-device-{}", ulid::Ulid::new());
                self.codes.insert(
                    user.clone(),
                    DeviceCode {
                        device: device.clone(),
                        approved: false,
                        used: false,
                    },
                );
                (
                    200,
                    json!({"device_code":device,"user_code":user,"verification_uri":format!("{}/verify",self.issuer),"expires_in":300,"interval":5}),
                )
            }
            "/token" => {
                assert_eq!(
                    fields.get("client_id").map(String::as_str),
                    Some("device-client")
                );
                assert_eq!(
                    fields.get("grant_type").map(String::as_str),
                    Some("urn:ietf:params:oauth:grant-type:device_code")
                );
                assert!(
                    !fields.contains_key("code_verifier") && !fields.contains_key("client_secret")
                );
                let code = self
                    .codes
                    .values_mut()
                    .find(|code| Some(&code.device) == fields.get("device_code"));
                let Some(code) = code else {
                    return (400, json!({"error":"invalid_grant"}));
                };
                if code.used {
                    return (400, json!({"error":"invalid_grant"}));
                }
                if !code.approved {
                    return (428, json!({"error":"authorization_pending"}));
                }
                code.used = true;
                let now = xmsg::storage::now_epoch_secs();
                let claims = json!({"iss":self.issuer,"aud":"device-client","sub":"fixture-sub","exp":now+3600,"iat":now,"email":"alice@example.org","email_verified":true});
                let encode =
                    |data: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
                let message = format!(
                    "{}.{}",
                    encode(br#"{"alg":"RS256","kid":"fixture-rsa"}"#),
                    encode(claims.to_string().as_bytes())
                );
                let signature = self
                    .signing
                    .sign(
                        &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                        message.as_bytes(),
                    )
                    .unwrap();
                (
                    200,
                    json!({"access_token":"synthetic-access-only","refresh_token":"synthetic-refresh-only","token_type":"Bearer","id_token":format!("{message}.{}",encode(&signature))}),
                )
            }
            _ => (404, json!({"error":"not_found"})),
        }
    }
}
struct Idp {
    shared: Arc<Mutex<IdpState>>,
    listener: JoinHandle<()>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    root: PathBuf,
}
impl Idp {
    async fn new(directory: &Path) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rsa = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let pem = rsa.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let signing =
            CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new("fixture-rsa".into())))
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("https://{}", listener.local_addr().unwrap());
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut root_params = rcgen::CertificateParams::default();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root = directory.join("idp-public-root.pem");
        std::fs::write(&root, root_cert.pem()).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params
            .signed_by(&key, &rcgen::Issuer::from_params(&root_params, &root_key))
            .unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone(), root_cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let shared = Arc::new(Mutex::new(IdpState {
            issuer,
            signing,
            codes: HashMap::new(),
            paths: vec![],
        }));
        let connections = Arc::new(Mutex::new(vec![]));
        let connection_tasks = connections.clone();
        let state = shared.clone();
        let listener = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let state = state.clone();
                connection_tasks.lock().unwrap().push(tokio::spawn(async move {
                    tokio::time::timeout(Duration::from_secs(10), async move {
                        let mut socket = acceptor.accept(tcp).await.unwrap();
                        let mut bytes = vec![];
                        let header_end = loop {
                            let mut chunk = [0; 1024];
                            let n = socket.read(&mut chunk).await.unwrap();
                            if n == 0 { return; }
                            bytes.extend_from_slice(&chunk[..n]);
                            assert!(bytes.len() <= LIMIT);
                            if let Some(offset) = bytes.windows(4).position(|b| b == b"\r\n\r\n") { break offset+4; }
                        };
                        let header = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                        let length = header.lines().find_map(|line| line.split_once(':').filter(|(name,_)| name.eq_ignore_ascii_case("content-length")).map(|(_,value)| value.trim().parse::<usize>().unwrap())).unwrap_or(0);
                        assert!(header_end + length <= LIMIT);
                        while bytes.len() < header_end + length {
                            let mut chunk = [0;1024]; let n = socket.read(&mut chunk).await.unwrap(); assert!(n > 0); bytes.extend_from_slice(&chunk[..n]);
                        }
                        let route = header.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                        let (status, value) = state.lock().unwrap().response(route, &bytes[header_end..header_end+length]);
                        let body = value.to_string();
                        let reply = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                        socket.write_all(reply.as_bytes()).await.unwrap();
                        socket.shutdown().await.unwrap();
                    }).await.expect("synthetic IdP connection exceeded its bound");
                }));
            }
        });
        Self {
            shared,
            listener,
            connections,
            root,
        }
    }
    async fn stop(self) {
        self.listener.abort();
        let _ = self.listener.await;
        let tasks = std::mem::take(&mut *self.connections.lock().unwrap());
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            if let Err(error) = task.await {
                assert!(error.is_cancelled(), "synthetic IdP task failed: {error}");
            }
        }
    }
}

struct Process {
    child: tokio::sync::Mutex<Child>,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    readers: tokio::sync::Mutex<Vec<JoinHandle<()>>>,
}
fn capture(
    mut input: impl AsyncRead + Unpin + Send + 'static,
    output: Arc<Mutex<Vec<u8>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut bytes = [0; 2048];
        loop {
            let count = input.read(&mut bytes).await.unwrap();
            if count == 0 {
                break;
            }
            let mut output = output.lock().unwrap();
            assert!(output.len() + count <= LIMIT, "child output exceeded bound");
            output.extend_from_slice(&bytes[..count]);
        }
    })
}
impl Process {
    fn text(&self, error: bool) -> String {
        String::from_utf8(
            if error { &self.stderr } else { &self.stdout }
                .lock()
                .unwrap()
                .clone(),
        )
        .unwrap()
    }
    async fn status(&self) -> Option<ExitStatus> {
        self.child.lock().await.try_wait().unwrap()
    }
    async fn finish(&self) -> ExitStatus {
        let status = tokio::time::timeout(WAIT, self.child.lock().await.wait())
            .await
            .expect("child command exceeded bound")
            .unwrap();
        for reader in self.readers.lock().await.drain(..) {
            reader.await.unwrap();
        }
        status
    }
    async fn stop(&self) {
        let mut child = self.child.lock().await;
        if child.try_wait().unwrap().is_none() {
            child.start_kill().unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("captured child did not stop")
            .unwrap();
        let readers = std::mem::take(&mut *self.readers.lock().await);
        for reader in &readers {
            reader.abort();
        }
        for reader in readers {
            let _ = reader.await;
        }
    }
}
struct Context {
    directory: tempfile::TempDir,
    root: PathBuf,
    processes: Mutex<Vec<Arc<Process>>>,
}
impl Context {
    fn command(&self, args: &[String]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        command
            .args(args)
            .env_clear()
            .env("HOME", self.directory.path().join("home"))
            .env("XDG_RUNTIME_DIR", self.directory.path().join("runtime"))
            .env("SSL_CERT_FILE", &self.root)
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .current_dir(self.directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }
    fn spawn(&self, args: &[String]) -> Arc<Process> {
        let mut child = self.command(args).spawn().unwrap();
        let stdout = Arc::new(Mutex::new(vec![]));
        let stderr = Arc::new(Mutex::new(vec![]));
        let readers = vec![
            capture(child.stdout.take().unwrap(), stdout.clone()),
            capture(child.stderr.take().unwrap(), stderr.clone()),
        ];
        let process = Arc::new(Process {
            child: tokio::sync::Mutex::new(child),
            stdout,
            stderr,
            readers: tokio::sync::Mutex::new(readers),
        });
        self.processes.lock().unwrap().push(process.clone());
        process
    }
    async fn run(&self, args: &[String]) -> (ExitStatus, String, String) {
        let process = self.spawn(args);
        let status = process.finish().await;
        (status, process.text(false), process.text(true))
    }
    async fn cleanup(&self) {
        let processes = self.processes.lock().unwrap().clone();
        for process in processes {
            process.stop().await;
        }
    }
}
fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}
fn file(directory: &Path, name: &str) -> String {
    directory.join(name).to_str().unwrap().into()
}
async fn printed(process: &Process, prefix: &str) -> String {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Some(value) = process
                .text(false)
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
            {
                return value.to_owned();
            }
            assert!(
                process.status().await.is_none(),
                "device CLI exited before printing {prefix}: {}",
                process.text(true)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("device CLI output exceeded its wait bound")
}
async fn bound(process: &Process, message: &str) -> String {
    let ansi = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            let output = format!("{}\n{}", process.text(false), process.text(true));
            let output = ansi.replace_all(&output, "");
            for line in output.lines().filter(|line| line.contains(message)) {
                if let Some(value) = line.split("listen=").nth(1) {
                    let value: String = value
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || matches!(c, '.' | ':'))
                        .collect();
                    if value.parse::<std::net::SocketAddr>().is_ok() {
                        return value;
                    }
                }
            }
            assert!(
                process.status().await.is_none(),
                "serve exited before {message}: {}",
                process.text(true)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "serve listener output exceeded its wait bound; stdout: {}; stderr: {}",
            process.text(false),
            process.text(true)
        )
    })
}
fn effects(db: &Path) -> Vec<i64> {
    let connection = rusqlite::Connection::open(db).unwrap();
    ["enroll_bindings", "enroll_rates", "enroll_certs"]
        .iter()
        .map(|table| {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        })
        .collect()
}
fn cert(directory: &Path) -> (String, String, Vec<String>) {
    let der =
        CertificateDer::from_pem_slice(&std::fs::read(directory.join("fed.crt")).unwrap()).unwrap();
    let serial = x509_parser::parse_x509_certificate(der.as_ref())
        .unwrap()
        .1
        .raw_serial_as_string();
    (
        xmsg::fed::spki_sha256_from_der(der.as_ref()).unwrap(),
        serial,
        xmsg::fed::extract_uri_sans(der.as_ref()).unwrap(),
    )
}

async fn exercise(context: Arc<Context>, idp: Arc<Mutex<IdpState>>) {
    let directory = context.directory.path();
    let init = context
        .run(&strings(&[
            "enroll-ca",
            "--enroll-ca-dir",
            &file(directory, "ca"),
            "init",
        ]))
        .await;
    assert!(init.0.success(), "actual CA init failed: {}", init.2);
    let init: Value = serde_json::from_str(&init.1).unwrap();
    let fingerprint = init["fingerprint"].as_str().unwrap();
    let fleet_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        "spiffe://fleet.example/host/hub/user/team"
            .try_into()
            .unwrap(),
    )];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let fleet = params.self_signed(&fleet_key).unwrap();
    std::fs::write(directory.join("fleet.crt"), fleet.pem()).unwrap();
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("fleet.key"))
            .unwrap();
        file.write_all(fleet_key.serialize_pem().as_bytes())
            .unwrap();
    }
    let pin = xmsg::fed::spki_sha256_from_der(fleet.der()).unwrap();
    let policy = json!({"trust_domain":"enroll.example","providers":{"fixture":{"issuer":idp.lock().unwrap().issuer,"device":{"enabled":true},"clients":{"device":{"client_id":"device-client"}}}},"users":[{"provider":"fixture","sub":"fixture-sub","user":"alice"}],"issue_per_hour":200,"renew_per_hour":200});
    std::fs::write(directory.join("policy.json"), policy.to_string()).unwrap();
    let peers = json!({"peers":{},"hub":{"patterns":[{"pattern":"spiffe://enroll.example/host/*/user/alice","ca":directory.join("ca/root.crt")}],"rules":[{"pattern":"spiffe://enroll.example/host/*/user/alice","allow":["send","reply","list","relayed"],"leaf":true}]}});
    std::fs::write(directory.join("peers.json"), peers.to_string()).unwrap();
    let socket = file(directory, "runtime/http.sock");
    let server = context.spawn(&strings(&[
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--fed-listen",
        "127.0.0.1:0",
        "--enroll-listen",
        "127.0.0.1:0",
        "--http-sock",
        &socket,
        "--sessions-dir",
        &file(directory, "sessions"),
        "--codex-home",
        &file(directory, "codex"),
        "--db-path",
        &file(directory, "db.sqlite"),
        "--fed-cert",
        &file(directory, "fleet.crt"),
        "--fed-key",
        &file(directory, "fleet.key"),
        "--peers-file",
        &file(directory, "peers.json"),
        "--enroll-ca-dir",
        &file(directory, "ca"),
        "--enroll-policy",
        &file(directory, "policy.json"),
        "--fed-reload-interval-secs",
        "0",
    ]));
    let address = bound(&server, "bound enrollment https listener").await;
    let tcp_address = bound(&server, "bound tcp http server").await;
    let url = format!("https://{address}");
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert!(http
        .get(format!("http://{tcp_address}/healthz"))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let trust = xmsg::enroll_client::bootstrap(&url, Some(fingerprint), None)
        .await
        .unwrap();
    let enrollment_http = xmsg::enroll_client::http_client(&trust, None).unwrap();
    for (method, route) in [
        ("GET", "/v1/enrollment/pending"),
        ("POST", "/v1/enrollment/request/approve"),
        ("POST", "/v1/enrollment/request/deny"),
    ] {
        for (http, url) in [
            (&http, format!("http://{tcp_address}{route}")),
            (&enrollment_http, format!("{url}{route}")),
        ] {
            let status = http
                .request(method.parse().unwrap(), url)
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(
                status,
                reqwest::StatusCode::NOT_FOUND,
                "actual public listener exposed local approval route"
            );
        }
    }
    let enroll_args = |name: &str| {
        strings(&[
            "enroll",
            &url,
            "--flow",
            "device",
            "--provider",
            "fixture",
            "--host",
            "cli",
            "--fingerprint",
            fingerprint,
            "--state-dir",
            &file(directory, name),
        ])
    };
    let client = context.spawn(&enroll_args("client"));
    let user_code = printed(&client, "User code: ").await;
    let request = printed(&client, "Request: ").await;
    let spki = printed(&client, "SPKI SHA-256: ").await;
    assert!(spki.starts_with("sha256:"));
    assert!(client
        .text(false)
        .contains("Policy user: pending verification"));
    assert!(client
        .text(false)
        .contains("Requested host (not attested): cli"));
    idp.lock()
        .unwrap()
        .codes
        .get_mut(&user_code)
        .expect("CLI printed a code absent from fixture")
        .approved = true;
    let operator_args = |action: &str| strings(&["enroll-ca", "--http-sock", &socket, action]);
    let pending = tokio::time::timeout(WAIT, async {
        loop {
            let result = context.run(&operator_args("pending")).await;
            assert!(
                result.0.success(),
                "actual pending CLI failed: {}",
                result.2
            );
            let rows: Vec<Value> = serde_json::from_str(&result.1).unwrap();
            if let Some(row) = rows.into_iter().find(|row| row["request_id"] == request) {
                break row;
            }
            assert!(
                client.status().await.is_none(),
                "device client exited before approval: {}",
                client.text(true)
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("actual pending CLI never exposed verified device request");
    assert_eq!(pending["spki_sha256"], spki);
    assert_eq!(pending["user"], "alice");
    assert_eq!(pending["host"], "cli");
    assert_eq!(
        effects(&directory.join("db.sqlite")),
        vec![0, 0, 0],
        "device gained authority before operator approval"
    );
    let hyphen_request = format!("-{}", "A".repeat(31));
    for action in ["approve", "deny"] {
        let mut arguments = operator_args(action);
        arguments.push(hyphen_request.clone());
        if action == "approve" {
            arguments.extend(strings(&[
                "--user",
                "alice",
                "--host",
                "cli",
                "--spki-sha256",
                &spki,
            ]));
        }
        let refusal = context.run(&arguments).await;
        assert!(
            !refusal.0.success()
                && refusal
                    .2
                    .contains("enrollment operator request failed (410 Gone)"),
            "actual {action} CLI failed: hyphen-leading {action} request ID failed before reaching CA: {}",
            refusal.2
        );
    }
    let mut approve_args = operator_args("approve");
    approve_args.extend(strings(&[
        &request,
        "--user",
        "alice",
        "--host",
        "cli",
        "--spki-sha256",
        &spki,
    ]));
    let approval = context.run(&approve_args).await;
    assert!(
        approval.0.success(),
        "actual approve CLI failed: {}",
        approval.2
    );
    assert!(
        client.finish().await.success(),
        "actual device CLI failed after approval: {}",
        client.text(true)
    );
    let client_directory = directory.join("client");
    for name in [
        "fed.key",
        "fed.crt",
        "root.pem",
        "enroll.json",
        "peers.json",
    ] {
        assert_eq!(
            std::fs::metadata(client_directory.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let original = cert(&client_directory);
    assert_eq!(
        original.2,
        vec!["spiffe://enroll.example/host/cli/user/alice"]
    );
    assert_eq!(spki, format!("sha256:{}", original.0));
    let key = std::fs::read(client_directory.join("fed.key")).unwrap();
    let private_key = rcgen::KeyPair::from_pem(std::str::from_utf8(&key).unwrap()).unwrap();
    use rcgen::PublicKeyData;
    use sha2::Digest;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(private_key.subject_public_key_info())),
        original.0
    );
    assert_eq!(
        std::fs::read(client_directory.join("root.pem")).unwrap(),
        std::fs::read(directory.join("ca/root.crt")).unwrap()
    );
    assert_ne!(
        std::fs::read(client_directory.join("root.pem")).unwrap(),
        fleet.pem().as_bytes()
    );
    let saved_peers: Value =
        serde_json::from_slice(&std::fs::read(client_directory.join("peers.json")).unwrap())
            .unwrap();
    assert!(
        saved_peers.to_string().contains(&format!("sha256:{pin}")),
        "saved hub identity did not pin fleet F"
    );
    let replay = context.run(&approve_args).await;
    assert!(!replay.0.success(), "operator approval replay succeeded");
    let calls = idp.lock().unwrap().paths.len();
    let renewal = context
        .run(&strings(&[
            "enroll",
            "--renew",
            "--state-dir",
            client_directory.to_str().unwrap(),
        ]))
        .await;
    assert!(
        renewal.0.success(),
        "actual renew CLI failed: {}",
        renewal.2
    );
    let renewed = cert(&client_directory);
    assert_eq!(original.0, renewed.0);
    assert_eq!(original.2, renewed.2);
    assert_ne!(original.1, renewed.1);
    assert_eq!(
        std::fs::read(client_directory.join("fed.key")).unwrap(),
        key
    );
    assert_eq!(
        idp.lock().unwrap().paths.len(),
        calls,
        "actual renew CLI contacted IdP"
    );
    let before_denial = effects(&directory.join("db.sqlite"));
    let denied = context.spawn(&enroll_args("denied"));
    let denied_code = printed(&denied, "User code: ").await;
    let denied_request = printed(&denied, "Request: ").await;
    assert!(!idp.lock().unwrap().codes[&denied_code].approved);
    let mut denial_args = operator_args("deny");
    denial_args.push(denied_request);
    let denial = context.run(&denial_args).await;
    assert!(denial.0.success(), "actual deny CLI failed: {}", denial.2);
    assert!(
        !denied.finish().await.success(),
        "denied actual device CLI succeeded"
    );
    assert!(!directory.join("denied/fed.crt").exists());
    assert_eq!(
        effects(&directory.join("db.sqlite")),
        before_denial,
        "denied device request changed authority"
    );
    let repeat_denial = context.run(&denial_args).await;
    assert!(!repeat_denial.0.success(), "denial replay succeeded");
    assert!(!idp
        .lock()
        .unwrap()
        .paths
        .iter()
        .any(|route| route == "/authorize"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_device_binary_requires_operator_approval_then_renews_and_denies() {
    eprintln!("device-cli-binary={}", env!("CARGO_BIN_EXE_xmsg"));
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["home", "runtime", "sessions", "codex"] {
        xmsg::enroll_client::private_directory(&directory.path().join(name)).unwrap();
    }
    let idp = Idp::new(directory.path()).await;
    let context = Arc::new(Context {
        directory,
        root: idp.root.clone(),
        processes: Mutex::new(vec![]),
    });
    let inner_context = context.clone();
    let shared = idp.shared.clone();
    let mut task = tokio::spawn(async move { exercise(inner_context, shared).await });
    let result = tokio::time::timeout(Duration::from_secs(110), &mut task).await;
    if result.is_err() {
        task.abort();
        let _ = task.await;
    }
    context.cleanup().await;
    idp.stop().await;
    result
        .expect("actual binary test exceeded its total bound")
        .expect("actual binary test assertion failed");
}
