#[path = "support/spawn.rs"]
mod spawn;

use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::header, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");
const DEADLINE: Duration = Duration::from_secs(10);
const REQUEST_ID: &str = "6f1e2d3c4b5a69788796a5b4c3d2e1f0";
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Provider {
    issuer: String,
    _task: AbortTask,
}

struct AbortTask(JoinHandle<()>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Provider {
    async fn start(directory: &Path) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        fs::write(directory.join("fixture.pem"), cert.cert.pem()).unwrap();
        fs::write(
            directory.join("fixture.key"),
            cert.signing_key.serialize_pem(),
        )
        .unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("https://{}", listener.local_addr().unwrap());
        let metadata = json!({
            "issuer":issuer,
            "authorization_endpoint":format!("{issuer}/authorize"),
            "token_endpoint":format!("{issuer}/token"),
            "jwks_uri":format!("{issuer}/jwks"),
            "response_types_supported":["code"],
            "subject_types_supported":["public"],
            "id_token_signing_alg_values_supported":["ES256"]
        });
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (stream, _) = result.unwrap();
                        let tls = tls.clone();
                        let metadata = metadata.clone();
                        connections.spawn(async move {
                            let Ok(stream) = tls.accept(stream).await else { return };
                            let service = service_fn(|request: Request<Incoming>| {
                                let body = match request.uri().path() {
                                    "/.well-known/openid-configuration" => Some(metadata.clone()),
                                    "/jwks" => Some(json!({"keys":[]})),
                                    _ => None,
                                };
                                async move {
                                    let (status, bytes) = body.map_or_else(
                                        || (StatusCode::NOT_FOUND, Bytes::new()),
                                        |body| (StatusCode::OK, Bytes::from(body.to_string())),
                                    );
                                    Ok::<_, Infallible>(Response::builder()
                                        .status(status)
                                        .header(header::CONTENT_TYPE, "application/json")
                                        .body(Full::new(bytes))
                                        .unwrap())
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            issuer,
            _task: AbortTask(task),
        }
    }
}

struct Collector(Child);

impl Drop for Collector {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn seed_native_session(config: &Path, state: &Path, issuer: &str) -> String {
    let output = spawn::command(BIN)
        .args(["observe-collector", "admin", "--config"])
        .arg(config)
        .arg("--state-dir")
        .arg(state)
        .arg("list")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "authority schema setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let db = rusqlite::Connection::open(state.join("authority.sqlite")).unwrap();
    let at = xmsg::storage::now_epoch_secs();
    let handle = URL_SAFE_NO_PAD.encode([19; 32]);
    let digest: [u8; 32] = Sha256::digest(handle.as_bytes()).into();
    db.execute(
        "INSERT INTO owners(principal,email,issuer,subject,entitled) VALUES (?, ?, ?, ?, 1)",
        (
            "fixture-owner",
            "owner@fixture.invalid",
            issuer,
            "fixture-subject",
        ),
    )
    .unwrap();
    let record = json!({
        "record_id":"fixture-native","class":"native","session_id":"fixture-session",
        "principal":"fixture-owner","on_behalf_of":null,"parent_record":null,
        "grants":{"kind":"owner"},"policy_generation":0,"created_at":at,"last_used_at":at,
        "idle_expires_at":at+600,"absolute_expires_at":at+600,"revoked":false
    });
    db.execute(
        "INSERT INTO records(id,digest,record) VALUES (?, ?, ?)",
        ("fixture-native", digest.as_slice(), record.to_string()),
    )
    .unwrap();
    handle
}

async fn start_collector(directory: &Path, config: &Path, state: &Path) -> (Collector, SocketAddr) {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let stderr = directory.join("collector.stderr");
    let mut collector = Collector(
        spawn::command(BIN)
            .args(["observe-collector", "--config"])
            .arg(config)
            .arg("--state-dir")
            .arg(state)
            .arg("--listen")
            .arg(address.to_string())
            .env("SSL_CERT_FILE", directory.join("fixture.pem"))
            .env("NO_PROXY", "*")
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap(),
    );
    timeout(DEADLINE, async {
        loop {
            if let Some(status) = collector.0.try_wait().unwrap() {
                panic!(
                    "shipped collector exited with {status}: {}",
                    fs::read_to_string(&stderr).unwrap()
                );
            }
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("wait for shipped collector");
    (collector, address)
}

async fn handshake(address: SocketAddr, handle: &str, require_commands: bool) -> Socket {
    let mut request = format!("ws://{address}/v1/mission-control/session")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        "xmsg.mission-control.v1".parse().unwrap(),
    );
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {handle}").parse().unwrap(),
    );
    let (mut socket, _) = timeout(DEADLINE, connect_async(request))
        .await
        .unwrap()
        .unwrap();
    let require = if require_commands {
        json!(["commands"])
    } else {
        json!(["observe"])
    };
    let hello = json!({
        "v":1,"type":"hello","id":1,"protocol":1,
        "capabilities":["observe","commands"],"require":require
    });
    socket
        .send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    socket
}

async fn frame(socket: &mut Socket) -> Message {
    timeout(DEADLINE, socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

async fn body(socket: &mut Socket) -> Value {
    serde_json::from_str(frame(socket).await.into_text().unwrap().as_str()).unwrap()
}

#[tokio::test]
async fn shipped_collector_withholds_all_command_carriers() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Provider::start(directory.path()).await;
    let config = directory.path().join("collector.json");
    fs::write(
        &config,
        json!({
            "client_cert":"fixture.pem","client_key":"fixture.key",
            "sources":[{"node":"fixture.node","outbound_only":true}],
            "mission_control":{
                "public_origin":"https://collector.fixture.invalid",
                "issuer":provider.issuer,"client_id":"fixture-web","native_client_id":"fixture-native",
                "redirect_uri":"https://collector.fixture.invalid/login/callback",
                "allowlist":["owner@fixture.invalid"]
            }
        })
        .to_string(),
    )
    .unwrap();
    let state = directory.path().join("state");
    fs::create_dir(&state).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let handle = seed_native_session(&config, &state, &provider.issuer);
    let (_collector, address) = start_collector(directory.path(), &config, &state).await;

    let mut socket = handshake(address, &handle, false).await;
    let hello = body(&mut socket).await;
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["actor"]["class"], "native");
    assert_eq!(
        hello["capabilities"],
        json!(["observe"]),
        "shipped hello advertised commands"
    );
    socket.close(None).await.unwrap();

    let mut required = handshake(address, &handle, true).await;
    let error = body(&mut required).await;
    assert_eq!(error["type"], "error");
    assert_eq!(error["code"], "capability_unavailable");
    let Message::Close(Some(close)) = frame(&mut required).await else {
        panic!("required commands must close with 4409");
    };
    assert_eq!(u16::from(close.code), 4409);

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(DEADLINE)
        .build()
        .unwrap();
    let prepare = json!({
        "v":1,"type":"prepare","request_id":REQUEST_ID,
        "requested_at":xmsg::storage::now_epoch_secs()*1_000,"verb":"send",
        "target":{
            "node":"fixture.node","endpoint":"claude-1@fixture.node",
            "state_epoch":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","incarnation":3,
            "selector":{"kind":"execution","session_id":"exec-alpha","generation":7}
        },
        "params":{"text":"Check the task status."}
    });
    let commit = json!({
        "v":1,"type":"commit","request_id":REQUEST_ID,
        "intent":URL_SAFE_NO_PAD.encode([0;16]),"digest":format!("sha256:{}", "0".repeat(64))
    });
    for (path, request) in [
        (
            "prepare",
            client
                .post(format!(
                    "http://{address}/v1/mission-control/commands/prepare"
                ))
                .json(&prepare),
        ),
        (
            "commit",
            client
                .post(format!(
                    "http://{address}/v1/mission-control/commands/commit"
                ))
                .json(&commit),
        ),
        (
            "lookup",
            client.get(format!("http://{address}/v1/receipts/{REQUEST_ID}")),
        ),
    ] {
        let reply = request.bearer_auth(&handle).send().await.unwrap();
        assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let error: Value = reply.json().await.unwrap();
        assert_eq!(error["type"], "error", "{path}");
        assert_eq!(error["code"], "unavailable", "{path}");
        assert!(
            error.get("intent").is_none() && error.get("receipt_id").is_none(),
            "{path}"
        );
    }
}
