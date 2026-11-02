//! XA5 gate: the node-to-node wire (`/fed/v2`) and the mesh `list` (A3, A4, A-1, A-2, A12,
//! N-2, A16, D-8, P-3, A-12; plan §6 D2, D14).
//!
//! Every oracle runs real `xmsg serve` nodes holding CA-issued SPIFFE leaves: A
//! (`sini.a`), its direct peer B (`eve.b`), its dial-out leaf L (`guard.genie`, a pod) and
//! a forwarder H (`sini.h`). The origin of a relayed message is a wire client presenting a
//! test peer certificate (`sini.o`), since nothing in xmsg originates a hop until H6 (A3,
//! B4). Two oracles add an in-process stub peer: one lists another user's entry (P-3), and
//! one stands for a node still on `/fed/v1` (`ee1b6ca`, the deployed release).
mod short_sock;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use xmsg::fed::{normalize_pin, spki_sha256_from_der, PeerConfig, PeersMap};

mod hop_client;
use hop_client::Origin;

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");

const URI_A: &str = "spiffe://xa5.test/host/a/user/sini";
const URI_B: &str = "spiffe://xa5.test/host/b/user/eve";
const URI_L: &str = "spiffe://xa5.test/ns/genie/sa/guard";
const URI_H: &str = "spiffe://xa5.test/host/h/user/sini";
const URI_O: &str = "spiffe://xa5.test/host/o/user/sini";
const URI_S: &str = "spiffe://xa5.test/host/s/user/eve";

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

struct ChildGuard(Option<tokio::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.start_kill();
        }
    }
}

fn get_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A certificate authority issuing SPIFFE leaves.
struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pem: String,
}

#[derive(Clone)]
struct Creds {
    cert: String,
    key: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    pin: String,
}

impl Ca {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "xa5 test CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }

    fn issue(&self, uri: &str) -> Creds {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "leaf");
        params.subject_alt_names = vec![rcgen::SanType::URI(uri.to_string().try_into().unwrap())];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        Creds {
            pin: spki_sha256_from_der(cert.der()).unwrap(),
            cert: cert.pem(),
            key: key.serialize_pem(),
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }
}

/// A node's files, written before it starts so peers can name its port.
struct Prepared {
    tmp: TempDir,
    fed_port: u16,
    http_port: u16,
}

fn prepare(ca: &Ca) -> Prepared {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(tmp.path().join("ca.pem"), &ca.pem).unwrap();
    Prepared {
        tmp,
        fed_port: get_free_port(),
        http_port: get_free_port(),
    }
}

impl Prepared {
    fn ca_file(&self) -> PathBuf {
        self.tmp.path().join("ca.pem")
    }
}

#[allow(dead_code)]
struct Node {
    tmp: TempDir,
    http_port: u16,
    fed_port: u16,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    sessions_dir: PathBuf,
    child: ChildGuard,
}

/// Starts `xmsg serve` with `creds` and `peers`. `leaf` runs it as a dial-out leaf with that
/// principal; otherwise it listens for federation. `svc` names a service this test
/// executable may register as.
async fn start(
    p: Prepared,
    creds: &Creds,
    peers: Value,
    leaf: Option<&str>,
    svc: Option<&str>,
) -> Node {
    let Prepared {
        tmp,
        fed_port,
        http_port,
    } = p;
    let run_dir = tmp.path().join("run");
    let sessions_dir = tmp.path().join("sessions");
    for d in [&run_dir, &sessions_dir] {
        fs::create_dir_all(d).unwrap();
        fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let cert = tmp.path().join("cert.pem");
    let key = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");
    fs::write(&cert, &creds.cert).unwrap();
    fs::write(&key, &creds.key).unwrap();
    fs::write(&peers_file, peers.to_string()).unwrap();

    let mut args: Vec<String> = vec![
        "serve".into(),
        "--listen".into(),
        format!("127.0.0.1:{http_port}"),
        "--db-path".into(),
        tmp.path().join("node.db").display().to_string(),
        "--sessions-dir".into(),
        sessions_dir.display().to_string(),
        "--register-sock".into(),
        register_sock.display().to_string(),
        "--fed-cert".into(),
        cert.display().to_string(),
        "--fed-key".into(),
        key.display().to_string(),
        "--peers-file".into(),
        peers_file.display().to_string(),
    ];
    match leaf {
        Some(principal) => {
            args.extend(["--leaf".into(), "--leaf-principal".into(), principal.into()])
        }
        None => args.extend([
            "--fed-listen".into(),
            format!("127.0.0.1:{fed_port}"),
            "--agent-sock".into(),
            agent_sock.display().to_string(),
            "--http-sock".into(),
            run_dir.join("http.sock").display().to_string(),
        ]),
    }
    if let Some(name) = svc {
        args.extend([
            "--svc-exe".into(),
            format!("{name}={}", std::env::current_exe().unwrap().display()),
        ]);
    }

    let mut child = tokio::process::Command::new(BIN)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "warn")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn xmsg serve");

    for _ in 0..600 {
        if let Ok(Some(_)) = child.try_wait() {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut err).await;
            }
            panic!("node exited at start (failed to bind?): {err}");
        }
        let http_up = tokio::net::TcpStream::connect(("127.0.0.1", http_port))
            .await
            .is_ok();
        let up = match leaf {
            Some(_) => register_sock.exists() && http_up,
            None => {
                agent_sock.exists()
                    && register_sock.exists()
                    && http_up
                    && tokio::net::TcpStream::connect(("127.0.0.1", fed_port))
                        .await
                        .is_ok()
            }
        };
        if up {
            return Node {
                tmp,
                http_port,
                fed_port,
                agent_sock,
                register_sock,
                sessions_dir,
                child: ChildGuard(Some(child)),
            };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.start_kill();
    panic!("xmsg serve neither served nor exited within 30s: {args:?}");
}

impl Node {
    async fn stop(&mut self) {
        if let Some(mut c) = self.child.0.take() {
            let _ = c.start_kill();
            let _ = c.wait().await;
        }
    }
}

async fn run_with_port_retry<F, Fut>(f: F)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    for attempt in 1..=5 {
        match tokio::task::spawn(f()).await {
            Ok(()) => return,
            Err(e) if e.is_panic() => {
                let p = e.into_panic();
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                let port_race = msg.contains("failed to bind")
                    || msg.contains("AddrInUse")
                    || msg.contains("ddress already in use");
                if port_race && attempt < 5 {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    continue;
                }
                std::panic::resume_unwind(p);
            }
            Err(e) => panic!("join error: {e}"),
        }
    }
}

fn ca_entry(port: u16, ca_file: &Path, uri: &str, allow: &[&str]) -> Value {
    json!({
        "address": format!("127.0.0.1:{port}"),
        "ca": ca_file.display().to_string(),
        "identities": [uri],
        "allow": allow,
    })
}

fn leaf_entry(ca_file: &Path, uri: &str, allow: &[&str]) -> Value {
    let mut e = ca_entry(get_free_port(), ca_file, uri, allow);
    e["leaf"] = json!(true);
    e
}

/// A Claude session fixture owned by this test process; returns its received lines.
fn claude_session(sessions_dir: &Path, session_id: &str, name: &str) -> Arc<Mutex<Vec<String>>> {
    let sock_path = short_sock::sock_path(sessions_dir, "inbox");
    let listener = UnixListener::bind(&sock_path).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
            if let Ok(s) = String::from_utf8(buf) {
                rx.lock().unwrap().push(s);
            }
        }
    });
    let pid = std::process::id();
    let proc_start =
        xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    let sess_uuid = if xmsg::claim::is_uuid_shaped(session_id) {
        session_id.to_string()
    } else {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(session_id.as_bytes());
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-8{:01x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            h[0], h[1], h[2], h[3], h[4], h[5], h[6] & 0x0f, h[7], h[8] & 0x0f, h[9], h[10], h[11], h[12], h[13], h[14], h[15]
        )
    };
    let session = json!({
        "pid": pid, "sessionId": sess_uuid, "name": name, "cwd": "/workspace",
        "status": "idle", "kind": "interactive", "startedAt": 1000, "updatedAt": 2000,
        "procStart": proc_start, "messagingSocketPath": sock_path.display().to_string(),
    });
    fs::write(
        sessions_dir.join(format!("{pid}-{session_id}.json")),
        session.to_string(),
    )
    .unwrap();
    received
}

async fn wait_line(rx: &Arc<Mutex<Vec<String>>>, needle: &str) -> Option<String> {
    for _ in 0..200 {
        if let Some(l) = rx.lock().unwrap().iter().find(|l| l.contains(needle)) {
            return Some(l.clone());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// `list` on `node` over its TCP listener (an anonymous caller, AM-2), bounded by `within`.
async fn list(node: &Node, within: Duration) -> Value {
    let url = format!("http://127.0.0.1:{}/v1/recipients", node.http_port);
    let resp = tokio::time::timeout(within, reqwest::Client::new().get(url).send())
        .await
        .unwrap_or_else(|_| panic!("list did not return within {within:?}"))
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

fn addresses(listed: &Value) -> Vec<String> {
    listed["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["address"].as_str().unwrap().to_string())
        .collect()
}

fn node_status(listed: &Value, node: &str) -> String {
    listed["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node"] == node)
        .unwrap_or_else(|| panic!("no status for {node}: {listed}"))["status"]
        .as_str()
        .unwrap()
        .to_string()
}

fn node_detail(listed: &Value, node: &str) -> String {
    listed["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node"] == node)
        .unwrap_or_else(|| panic!("no status for {node}: {listed}"))["detail"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// An anonymous HTTP send from `ci` over the node's TCP listener: (status, body).
async fn http_send(node: &Node, to: &str, text: &str) -> (u16, Value) {
    let url = format!("http://127.0.0.1:{}/v1/messages", node.http_port);
    let resp = reqwest::Client::new()
        .post(url)
        .json(&json!({ "to": to, "from": "ci", "text": text }))
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .unwrap();
    (
        resp.status().as_u16(),
        resp.json().await.unwrap_or(Value::Null),
    )
}

/// A send over `agent.sock` from this process, which is the Claude fake on that node.
async fn agent_send(node: &Node, to: &str, text: &str) -> Value {
    let stream = UnixStream::connect(&node.agent_sock).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let frame = json!({ "action": "send", "to": to, "text": text });
    w.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

/// A service registered on `register.sock`.
async fn register_svc(sock: &Path, name: &str) -> (BufReader<OwnedReadHalf>, OwnedWriteHalf) {
    let stream = UnixStream::connect(sock).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    w.write_all(format!("{}\n", json!({ "harness": "svc", "name": name })).as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    let v: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["status"], "ok", "svc registration: {v}");
    (r, w)
}

/// One `poll` on a service's connection; a delivered message is acked.
async fn svc_poll(r: &mut BufReader<OwnedReadHalf>, w: &mut OwnedWriteHalf) -> Value {
    w.write_all(format!("{}\n", json!({ "action": "poll", "waitSecs": 5 })).as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    let v: Value = serde_json::from_str(&line).unwrap();
    if v["action"] == "deliver" {
        let ack = json!({ "action": "ack", "messageId": v["messageId"] });
        w.write_all(format!("{ack}\n").as_bytes()).await.unwrap();
        let mut l = String::new();
        r.read_line(&mut l).await.unwrap();
    }
    v
}

async fn svc_reply(
    r: &mut BufReader<OwnedReadHalf>,
    w: &mut OwnedWriteHalf,
    message_id: &str,
    text: &str,
) -> Value {
    let frame = json!({ "action": "reply", "messageId": message_id, "text": text });
    w.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

// -----------------------------------------------------------------------------
// The mesh: A with direct peer B and dial-out leaf L
// -----------------------------------------------------------------------------

struct Mesh {
    a: Node,
    _b: Node,
    l: Node,
    alice: Arc<Mutex<Vec<String>>>,
    bob: Arc<Mutex<Vec<String>>>,
    guard: (BufReader<OwnedReadHalf>, OwnedWriteHalf),
    _ca: Ca,
}

/// A (`sini.a`), B (`eve.b`) and L (`guard.genie`, a leaf of A). `b_allows_list` and
/// `l_allows_list` are B's and L's `list` rights for A.
async fn mesh(b_allows_list: bool, l_allows_list: bool) -> Mesh {
    let ca = Ca::new();
    let (ca_a, ca_b, ca_l) = (ca.issue(URI_A), ca.issue(URI_B), ca.issue(URI_L));
    let (pa, pb, pl) = (prepare(&ca), prepare(&ca), prepare(&ca));

    let peers_a = json!({
        "eve.b": ca_entry(pb.fed_port, &pa.ca_file(), URI_B, &["send", "reply", "list"]),
        "guard.genie": leaf_entry(&pa.ca_file(), URI_L, &["send", "reply", "inbox"]),
    });
    let b_allow: &[&str] = if b_allows_list {
        &["send", "reply", "list"]
    } else {
        &["send", "reply"]
    };
    let peers_b = json!({ "sini.a": ca_entry(pa.fed_port, &pb.ca_file(), URI_A, b_allow) });
    let l_allow: &[&str] = if l_allows_list {
        &["send", "reply", "inbox", "list"]
    } else {
        &["send", "reply", "inbox"]
    };
    let peers_l = json!({ "sini.a": ca_entry(pa.fed_port, &pl.ca_file(), URI_A, l_allow) });

    let b = start(pb, &ca_b, peers_b, None, None).await;
    let a = start(pa, &ca_a, peers_a, None, None).await;
    let l = start(pl, &ca_l, peers_l, Some("guard"), None).await;
    let alice = claude_session(
        &a.sessions_dir,
        "135aa23d-60a6-5595-a42a-c0296722252e",
        "Alice",
    );
    let bob = claude_session(
        &b.sessions_dir,
        "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
        "Bob",
    );
    let guard = register_svc(&l.register_sock, "guard").await;
    Mesh {
        a,
        _b: b,
        l,
        alice,
        bob,
        guard,
        _ca: ca,
    }
}

// -----------------------------------------------------------------------------
// In-process stub peers
// -----------------------------------------------------------------------------

/// An mTLS server presenting `creds`, admitting the client pinned by `client_pin`, that
/// answers every request with `answer(method, path)`: (status, JSON body or empty). Returns
/// its port and every request it saw.
async fn stub_peer(
    creds: &Creds,
    client_pin: &str,
    answer: fn(&str, &str) -> (u16, Option<Value>),
) -> (u16, Arc<Mutex<Vec<String>>>) {
    let mut peers = HashMap::new();
    peers.insert(
        "client".to_string(),
        PeerConfig {
            name: "client".to_string(),
            address: "127.0.0.1:1".to_string(),
            pin: Some(normalize_pin(client_pin)),
            allow: vec!["send".to_string(), "list".to_string()],
            ..Default::default()
        },
    );
    let acceptor = xmsg::fed::make_tls_acceptor(
        &[rustls::pki_types::CertificateDer::from(
            creds.cert_der.clone(),
        )],
        &creds.key_der,
        Arc::new(PeersMap::new(peers)),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let seen = seen_c.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let line = format!("{} {}", req.method(), req.uri().path());
                        seen.lock().unwrap().push(line);
                        let (status, body) = answer(req.method().as_str(), req.uri().path());
                        let bytes = body.map(|b| b.to_string()).unwrap_or_default();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(bytes::Bytes::from(bytes)))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, seen)
}

/// A node on the deployed `ee1b6ca` protocol: it serves `/fed/v1/messages` and nothing on
/// `/fed/v2` (axum's 404, no body).
fn ee1b6ca_node(method: &str, path: &str) -> (u16, Option<Value>) {
    match (method, path) {
        ("POST", "/fed/v1/messages") => (
            202,
            Some(json!({
                "sessionId": "x", "fromName": "old", "bytes": 1, "messageId": "m",
                "outcome": "delivered",
            })),
        ),
        _ => (404, None),
    }
}

/// A node whose certificate user is `eve` and which lists an entry of user `sini` beside
/// one of its own.
fn lying_lister(method: &str, path: &str) -> (u16, Option<Value>) {
    match (method, path) {
        ("GET", "/fed/v2/sessions") => (
            200,
            Some(json!([
                { "id": "11111111-1111-4111-8111-111111111111", "kind": "instance",
                  "status": "live", "user": "sini" },
                { "id": "22222222-2222-4222-8222-222222222222", "kind": "instance",
                  "status": "live", "user": "eve" },
            ])),
        ),
        _ => (404, None),
    }
}

// =============================================================================
// Oracle 1: Mesh list. On A, `list` returns A's, B's and L's recipients with every node
// `ok`, each carrying its user (A16, D-8), and a send to each listed address is delivered
// (A-1: listing and sending take the same path).
// Mutant: skip the mailbox query, so L is missing => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_mesh_list_and_send_to_each() {
    run_with_port_retry(|| async {
        let mut m = mesh(true, true).await;
        let listed = list(&m.a, Duration::from_secs(15)).await;
        let addrs = addresses(&listed);
        for (addr, user) in [
            ("135aa23d-60a6-5595-a42a-c0296722252e@sini.a", "sini"),
            ("baa3a12f-e06d-59f5-90c8-2eda9a54dd91@eve.b", "eve"),
            ("guard@guard.genie", "guard.genie"),
        ] {
            let r = listed["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["address"] == addr)
                .unwrap_or_else(|| panic!("{addr} not listed: {listed}"));
            assert_eq!(r["user"], user, "{listed}");
            assert_eq!(r["status"], "live", "{listed}");
        }
        for n in ["sini.a", "eve.b", "guard.genie"] {
            assert_eq!(node_status(&listed, n), "ok", "{listed}");
        }
        // Exactly the fixtures: each node runs with HOME in its tempdir, so nothing of the
        // host's (an agy conversation on the machine running the test) is listed (§1a).
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            [
                "135aa23d-60a6-5595-a42a-c0296722252e@sini.a",
                "baa3a12f-e06d-59f5-90c8-2eda9a54dd91@eve.b",
                "guard@guard.genie"
            ],
            "{listed}"
        );
        for addr in &addrs {
            let (status, sent) = http_send(&m.a, addr, &format!("to {addr}")).await;
            assert_eq!(status, 202, "send to {addr}: {sent}");
        }
        assert!(
            wait_line(&m.alice, "to 135aa23d-60a6-5595-a42a-c0296722252e@sini.a")
                .await
                .is_some()
        );
        assert!(
            wait_line(&m.bob, "to baa3a12f-e06d-59f5-90c8-2eda9a54dd91@eve.b")
                .await
                .is_some()
        );
        let (r, w) = &mut m.guard;
        let got = svc_poll(r, w).await;
        assert_eq!(got["action"], "deliver", "{got}");
        assert_eq!(got["text"], "to guard@guard.genie", "{got}");
    })
    .await;
}

// =============================================================================
// Oracle 2: Unreachable. With L disconnected, `list` on A reports L `unreachable` within the
// list timeout (D14; A-1: a dial-out node that does not answer is `unreachable`), and the
// rest of the result still comes back.
// Mutant: wait without a bound. Run under a timeout => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_disconnected_dial_out_client_is_bounded() {
    run_with_port_retry(|| async {
        let mut m = mesh(true, true).await;
        m.l.stop().await;
        let t = Instant::now();
        let listed = list(&m.a, Duration::from_secs(15)).await;
        let took = t.elapsed();
        assert!(
            took < xmsg::fed::LIST_TIMEOUT + Duration::from_secs(3),
            "list took {took:?}: {listed}"
        );
        assert_eq!(
            node_status(&listed, "guard.genie"),
            "unreachable",
            "{listed}"
        );
        assert_eq!(node_status(&listed, "eve.b"), "ok", "{listed}");
        let addrs = addresses(&listed);
        assert!(
            addrs.contains(&"135aa23d-60a6-5595-a42a-c0296722252e@sini.a".to_string()),
            "{listed}"
        );
        assert!(
            addrs.contains(&"baa3a12f-e06d-59f5-90c8-2eda9a54dd91@eve.b".to_string()),
            "{listed}"
        );
        assert!(
            !addrs.iter().any(|a| a.ends_with("@guard.genie")),
            "{listed}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 3: Rights. B withholds `list` from A, so B's entries are absent and its status
// says so: `unreachable`, detail `withholds list` (gate v0 C4; A-12's statuses are `ok`,
// `unreachable` and `timeout`).
// Mutant: ignore the right => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_withheld_list_is_reported() {
    run_with_port_retry(|| async {
        let m = mesh(false, true).await;
        let listed = list(&m.a, Duration::from_secs(15)).await;
        assert_eq!(node_status(&listed, "eve.b"), "unreachable", "{listed}");
        assert!(
            node_detail(&listed, "eve.b").starts_with("withholds list"),
            "{listed}"
        );
        let addrs = addresses(&listed);
        assert!(!addrs.iter().any(|a| a.ends_with("@eve.b")), "{listed}");
        assert!(
            addrs.contains(&"135aa23d-60a6-5595-a42a-c0296722252e@sini.a".to_string()),
            "{listed}"
        );
        assert!(addrs.contains(&"guard@guard.genie".to_string()), "{listed}");
    })
    .await;
}

// =============================================================================
// Oracle 4: User refusal (P-3). A node whose certificate user is `eve` lists an entry with
// user `sini`, and A drops it; its own `eve` entry is kept.
// Mutant: accept it => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_entry_of_another_user_is_dropped() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_s) = (ca.issue(URI_A), ca.issue(URI_S));
        let pa = prepare(&ca);
        let (s_port, _) = stub_peer(&ca_s, &ca_a.pin, lying_lister).await;
        let peers_a = json!({
            "eve.s": ca_entry(s_port, &pa.ca_file(), URI_S, &["send", "reply", "list"]),
        });
        let a = start(pa, &ca_a, peers_a, None, None).await;
        let listed = list(&a, Duration::from_secs(15)).await;
        assert_eq!(node_status(&listed, "eve.s"), "ok", "{listed}");
        let addrs = addresses(&listed);
        assert!(
            addrs.contains(&"22222222-2222-4222-8222-222222222222@eve.s".to_string()),
            "eve's own entry is kept: {listed}"
        );
        assert!(
            !addrs.contains(&"11111111-1111-4111-8111-111111111111@eve.s".to_string()),
            "an entry of user sini from eve's node is dropped: {listed}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 5: Push at the origin (A-2). A Claude fake on A sends to a service on B, and B's
// reply is pushed into the session. An anonymous sender on A reads its reply with
// `replies`, from A: the reply returned to the origin even though nothing is pushed.
// Mutant: decide the push at B => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_reply_returns_to_the_origin() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_b) = (ca.issue(URI_A), ca.issue(URI_B));
        let (pa, pb) = (prepare(&ca), prepare(&ca));
        let peers_a =
            json!({ "eve.b": ca_entry(pb.fed_port, &pa.ca_file(), URI_B, &["send", "reply"]) });
        let peers_b =
            json!({ "sini.a": ca_entry(pa.fed_port, &pb.ca_file(), URI_A, &["send", "reply"]) });
        let mut b = start(pb, &ca_b, peers_b, None, Some("answerer")).await;
        let a = start(pa, &ca_a, peers_a, None, None).await;
        let alice = claude_session(
            &a.sessions_dir,
            "135aa23d-60a6-5595-a42a-c0296722252e",
            "Alice",
        );
        let (mut r, mut w) = register_svc(&b.register_sock, "answerer").await;

        // The Claude fake's send: the reply is pushed into its session.
        let sent = agent_send(&a, "answerer@eve.b", "from alice").await;
        assert_eq!(sent["status"], "ok", "{sent}");
        let got = svc_poll(&mut r, &mut w).await;
        assert_eq!(got["text"], "from alice", "{got}");
        let replied = svc_reply(
            &mut r,
            &mut w,
            got["messageId"].as_str().unwrap(),
            "to alice",
        )
        .await;
        assert_eq!(replied["status"], "ok", "{replied}");
        let pushed = wait_line(&alice, "to alice")
            .await
            .expect("B's reply is pushed into the Claude session on A");
        assert!(pushed.contains("answerer@eve.b"), "{pushed}");

        // The anonymous send: the reply is stored at A, and read there with B gone.
        let (status, sent) = http_send(&a, "answerer@eve.b", "from ci").await;
        assert_eq!(status, 202, "{sent}");
        let id = sent["message_id"].as_str().unwrap().to_string();
        let got = svc_poll(&mut r, &mut w).await;
        assert_eq!(got["text"], "from ci", "{got}");
        svc_reply(&mut r, &mut w, got["messageId"].as_str().unwrap(), "to ci").await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        b.stop().await;
        let url = format!(
            "http://127.0.0.1:{}/v1/messages/{id}/replies?wait=2",
            a.http_port
        );
        let resp = reqwest::Client::new().get(url).send().await.unwrap();
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        assert_eq!(status, 200, "replies on A with B stopped: {body}");
        assert!(
            body.as_array()
                .is_some_and(|rs| rs.iter().any(|r| r["text"] == "to ci")),
            "the reply to the anonymous send is held at the origin: {body}"
        );
        assert_eq!(
            alice
                .lock()
                .unwrap()
                .iter()
                .filter(|l| l.contains("to ci"))
                .count(),
            0,
            "nothing for the anonymous sender is pushed to a session"
        );
    })
    .await;
}

// =============================================================================
// Oracle 6: Attested node (N-2). An envelope from O that claims `node: sini.cortex` is
// labelled with O's certificate name.
// Mutant: trust the envelope's field => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_receiver_attests_the_node() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_b, ca_o) = (ca.issue(URI_B), ca.issue(URI_O));
        let pb = prepare(&ca);
        let peers_b =
            json!({ "sini.o": ca_entry(get_free_port(), &pb.ca_file(), URI_O, &["send"]) });
        let b = start(pb, &ca_b, peers_b, None, None).await;
        let bob = claude_session(
            &b.sessions_dir,
            "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
            "Bob",
        );
        let o = Origin {
            cert_der: &ca_o.cert_der,
            key_der: &ca_o.key_der,
        };
        let mut env = hop_client::envelope(
            "alice",
            "Alice",
            "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
            "claims cortex",
        );
        env["origin"]["node"] = json!("sini.cortex");
        let (status, res) = hop_client::send_envelope(&o, &ca_b.pin, b.fed_port, env).await;
        assert_eq!(status, 202, "{res}");
        let line = wait_line(&bob, "claims cortex")
            .await
            .expect("delivered to bob");
        assert!(line.contains("Alice · alice@sini.o"), "{line}");
        assert!(!line.contains("sini.cortex"), "{line}");
    })
    .await;
}

// =============================================================================
// Oracle 7: Skew (§6 D2). `POST /fed/v1/messages` to a v2 node gets 404, and a v2 node's
// send to a node still on `/fed/v1` (ee1b6ca) is refused, never taken as delivered.
// Mutant 7: keep v1 as an alias => RED. Mutant 7b: post to `/fed/v1` => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_7_v1_is_refused_both_ways() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_b, ca_o) = (ca.issue(URI_B), ca.issue(URI_O));
        let pb = prepare(&ca);
        let peers_b =
            json!({ "sini.o": ca_entry(get_free_port(), &pb.ca_file(), URI_O, &["send"]) });
        let b = start(pb, &ca_b, peers_b, None, None).await;
        let bob = claude_session(&b.sessions_dir, "bob", "Bob");
        let o = Origin {
            cert_der: &ca_o.cert_der,
            key_der: &ca_o.key_der,
        };
        let env = hop_client::envelope("alice", "Alice", "bob", "over v1");
        let (status, res) = hop_client::request(
            &o,
            &ca_b.pin,
            b.fed_port,
            "POST",
            "/fed/v1/messages",
            Some(env),
        )
        .await;
        assert_eq!(status, 404, "an old node's route is not served: {res}");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            bob.lock().unwrap().is_empty(),
            "nothing is delivered over v1"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_7b_send_to_a_v1_node_is_refused() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let ca_a = ca.issue(URI_A);
        let (old_cert, old_key, old_pin) = xmsg::fed::generate_self_signed_ed25519("old").unwrap();
        let old = Creds {
            cert: String::new(),
            key: String::new(),
            cert_der: old_cert,
            key_der: old_key,
            pin: old_pin.clone(),
        };
        let (old_port, seen) = stub_peer(&old, &ca_a.pin, ee1b6ca_node).await;
        let pa = prepare(&ca);
        let peers_a = json!({
            "old": { "address": format!("127.0.0.1:{old_port}"), "pin": normalize_pin(&old_pin),
                     "allow": ["send", "reply"] },
        });
        let a = start(pa, &ca_a, peers_a, None, None).await;
        let (status, res) = http_send(&a, "x@old", "to an old node").await;
        assert_ne!(status / 100, 2, "a send to a v1 node is refused: {res}");
        assert_ne!(res["outcome"], "delivered", "{res}");
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter().all(|l| !l.contains("/fed/v1/")),
            "nothing is posted to v1: {seen:?}"
        );
        assert!(
            seen.iter().any(|l| l == "POST /fed/v2/messages"),
            "the send reached the old node on v2: {seen:?}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 8: Relay (X26 carried over). A message relayed through H arrives at B with a
// forwarded origin carrying O's ID and node, and a second forward is refused.
// Mutant: no hop mark => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_8_relay_carries_the_origin_and_one_hop() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_b, ca_h, ca_o) = (
            ca.issue(URI_A),
            ca.issue(URI_B),
            ca.issue(URI_H),
            ca.issue(URI_O),
        );
        let (pa, pb, ph) = (prepare(&ca), prepare(&ca), prepare(&ca));
        let peers_h = json!({
            "sini.o": ca_entry(get_free_port(), &ph.ca_file(), URI_O, &["send", "forward"]),
            "eve.b": ca_entry(pb.fed_port, &ph.ca_file(), URI_B, &["send", "reply"]),
        });
        // B would forward an unmarked envelope from H (it has the right), so only the hop
        // mark stops a second forward.
        let peers_b = json!({
            "sini.h": ca_entry(ph.fed_port, &pb.ca_file(), URI_H,
                               &["send", "reply", "relayed", "forward"]),
            "sini.a": ca_entry(pa.fed_port, &pb.ca_file(), URI_A, &["send", "reply"]),
        });
        let peers_a =
            json!({ "eve.b": ca_entry(pb.fed_port, &pa.ca_file(), URI_B, &["send", "reply"]) });
        let b = start(pb, &ca_b, peers_b, None, None).await;
        let _h = start(ph, &ca_h, peers_h, None, None).await;
        let a = start(pa, &ca_a, peers_a, None, None).await;
        let bob = claude_session(
            &b.sessions_dir,
            "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
            "Bob",
        );
        let bob_on_a = claude_session(
            &a.sessions_dir,
            "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
            "Bob",
        );
        let o = Origin {
            cert_der: &ca_o.cert_der,
            key_der: &ca_o.key_der,
        };

        let (status, res) = hop_client::hop_send(
            &o,
            &ca_h.pin,
            _h.fed_port,
            "baa3a12f-e06d-59f5-90c8-2eda9a54dd91@eve.b",
            "relayed",
        )
        .await;
        assert_eq!(status, 202, "{res}");
        let line = wait_line(&bob, "relayed")
            .await
            .expect("relayed to bob on B");
        assert!(
            line.contains("Alice · alice@sini.o"),
            "the forwarded origin: {line}"
        );

        let (status, res) = hop_client::hop_send(
            &o,
            &ca_h.pin,
            _h.fed_port,
            "baa3a12f-e06d-59f5-90c8-2eda9a54dd91@sini.a@eve.b",
            "twice",
        )
        .await;
        assert_eq!(status, 403, "{res}");
        assert_eq!(
            res["detail"], "message has already been forwarded (one hop maximum)",
            "{res}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            bob_on_a.lock().unwrap().is_empty(),
            "nothing is forwarded a second time"
        );
    })
    .await;
}

// =============================================================================
// Oracle 3b: Rights on a dial-out client (AM-1). L withholds `list` from A: it answers
// `denied` from its mailbox, A reports it `unreachable`, detail `withholds list`, and lists
// none of L's entries.
// Mutants: L ignores its own right => RED; A reports the denied answer `ok` => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3b_dial_out_client_withholding_list_is_reported() {
    run_with_port_retry(|| async {
        let m = mesh(true, false).await;
        let listed = list(&m.a, Duration::from_secs(15)).await;
        assert_eq!(
            node_status(&listed, "guard.genie"),
            "unreachable",
            "{listed}"
        );
        assert_eq!(
            node_detail(&listed, "guard.genie"),
            "withholds list",
            "{listed}"
        );
        let addrs = addresses(&listed);
        assert!(
            !addrs.iter().any(|a| a.ends_with("@guard.genie")),
            "{listed}"
        );
        assert!(
            addrs.contains(&"baa3a12f-e06d-59f5-90c8-2eda9a54dd91@eve.b".to_string()),
            "{listed}"
        );
    })
    .await;
}

const URI_W: &str = "spiffe://xa5.test/host/w/user/sini";
const URI_X: &str = "spiffe://xa5.test/host/x/user/sini";

// =============================================================================
// Oracle 9: A `list` answer is taken only from the dial-out client asked (AM-1). A has two
// dial-out clients, W and X (wire clients). X's answer to W's query is refused 404; W's own
// is taken.
// Mutant: take an answer from any peer => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_9_list_answer_from_another_peer_is_refused() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_w, ca_x) = (ca.issue(URI_A), ca.issue(URI_W), ca.issue(URI_X));
        let pa = prepare(&ca);
        let allow = &["send", "reply", "inbox", "list"];
        let peers_a = json!({
            "sini.w": leaf_entry(&pa.ca_file(), URI_W, allow),
            "sini.x": leaf_entry(&pa.ca_file(), URI_X, allow),
        });
        let a = Arc::new(start(pa, &ca_a, peers_a, None, None).await);
        let asker = {
            let a = a.clone();
            tokio::spawn(async move { list(&a, Duration::from_secs(15)).await })
        };
        let w = Origin {
            cert_der: &ca_w.cert_der,
            key_der: &ca_w.key_der,
        };
        let x = Origin {
            cert_der: &ca_x.cert_der,
            key_der: &ca_x.key_der,
        };
        let (status, item) =
            hop_client::request(&w, &ca_a.pin, a.fed_port, "GET", "/fed/v2/inbox?wait=5", None)
                .await;
        assert_eq!(status, 200, "{item}");
        assert_eq!(item["kind"], "list", "{item}");
        let uri = format!("/fed/v2/list/{}", item["query"].as_str().unwrap());
        let answer = |id: &str| {
            json!({ "status": "ok",
                    "entries": [{ "id": id, "kind": "service", "status": "live", "user": "sini" }] })
        };
        let (status, res) =
            hop_client::request(&x, &ca_a.pin, a.fed_port, "POST", &uri, Some(answer("forged")))
                .await;
        assert_eq!(status, 404, "X answers W's query: {res}");
        let (status, res) =
            hop_client::request(&w, &ca_a.pin, a.fed_port, "POST", &uri, Some(answer("wsvc")))
                .await;
        assert_eq!(status, 200, "W answers its own query: {res}");
        let listed = asker.await.unwrap();
        assert_eq!(node_status(&listed, "sini.w"), "ok", "{listed}");
        let addrs = addresses(&listed);
        assert!(addrs.contains(&"wsvc@sini.w".to_string()), "{listed}");
        assert!(!addrs.iter().any(|a| a.starts_with("forged@")), "{listed}");
    })
    .await;
}

// =============================================================================
// Oracle 10: The forward mark (X26, N-2). B refuses an envelope from O whose mark names a
// forwarder other than O, the peer that authenticated (400). The same envelope marked by O
// is taken.
// Mutant: accept any forwarder => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_10_forward_mark_names_the_authenticated_peer() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_b, ca_o) = (ca.issue(URI_B), ca.issue(URI_O));
        let pb = prepare(&ca);
        let peers_b = json!({
            "sini.o": ca_entry(get_free_port(), &pb.ca_file(), URI_O, &["send", "relayed"]),
        });
        let b = start(pb, &ca_b, peers_b, None, None).await;
        let bob = claude_session(
            &b.sessions_dir,
            "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
            "Bob",
        );
        let o = Origin {
            cert_der: &ca_o.cert_der,
            key_der: &ca_o.key_der,
        };
        let marked = |forwarder: &str, body: &str| {
            let mut env = hop_client::envelope(
                "alice",
                "Alice",
                "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
                body,
            );
            env["forwarded"] = json!({ "forwarder": forwarder });
            env
        };
        let (status, res) =
            hop_client::send_envelope(&o, &ca_b.pin, b.fed_port, marked("sini.h", "marked by h"))
                .await;
        assert_eq!(status, 400, "{res}");
        let (status, res) =
            hop_client::send_envelope(&o, &ca_b.pin, b.fed_port, marked("sini.o", "marked by o"))
                .await;
        assert_eq!(status, 202, "{res}");
        assert!(wait_line(&bob, "marked by o").await.is_some());
        assert!(
            !bob.lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("marked by h")),
            "nothing marked by another forwarder is delivered"
        );
    })
    .await;
}

/// A node that takes every send and reports it delivered to `bob`.
fn delivering_peer(method: &str, path: &str) -> (u16, Option<Value>) {
    match (method, path) {
        ("POST", "/fed/v2/messages") => (
            202,
            Some(json!({
                "sessionId": "bob", "fromName": "ci", "bytes": 1, "messageId": "m",
                "outcome": "delivered",
            })),
        ),
        _ => (404, None),
    }
}

/// A reply on `/fed/v2/replies` from `peer` to the node at `port`: its HTTP status.
async fn fed_reply(
    peer: &Origin<'_>,
    pin: &str,
    port: u16,
    in_reply_to: &str,
    replier: Value,
    text: &str,
) -> u16 {
    let env = json!({
        "v": 2, "id": ulid::Ulid::new().to_string(), "in_reply_to": in_reply_to,
        "replier": replier, "text": text, "created_at": 1000,
    });
    hop_client::request(peer, pin, port, "POST", "/fed/v2/replies", Some(env))
        .await
        .0
}

// =============================================================================
// Oracle 11: Federated reply authorization (A7; `outbound` holds the resolved `id@node`).
// A reply is taken only from the recipient the send recorded.
// - S, a direct peer, answered the send to `bob@eve.s` with `bob`: a reply from S as
//   `mallory` is refused 403, one as `bob` is taken.
// - A send to `Bobby@sini.w` is queued for W, a dial-out client, and resolved there: a reply
//   as `mallory`, or from a service that is not an error reply, is refused; one from the
//   instance labelled `Bobby` is taken.
// - A send to `nobody@sini.w` takes W's `not_found` error reply from a service, and the same
//   error reply from an instance is refused.
// Mutant: accept any replier from the right peer => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_11_reply_only_from_the_recorded_recipient() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_s, ca_w) = (ca.issue(URI_A), ca.issue(URI_S), ca.issue(URI_W));
        let pa = prepare(&ca);
        let (s_port, _) = stub_peer(&ca_s, &ca_a.pin, delivering_peer).await;
        let peers_a = json!({
            "eve.s": ca_entry(s_port, &pa.ca_file(), URI_S, &["send", "reply"]),
            "sini.w": leaf_entry(&pa.ca_file(), URI_W, &["send", "reply", "inbox"]),
        });
        let a = start(pa, &ca_a, peers_a, None, None).await;
        let s = Origin {
            cert_der: &ca_s.cert_der,
            key_der: &ca_s.key_der,
        };
        let w = Origin {
            cert_der: &ca_w.cert_der,
            key_der: &ca_w.key_der,
        };
        let pin = ca_a.pin.as_str();
        let mallory = json!({ "id": "mallory", "node": "x", "label": "Mallory" });
        let system = json!({ "service": "system", "node": "x" });

        // Resolved by the peer that answered.
        let (status, sent) = http_send(&a, "bob@eve.s", "for bob").await;
        assert_eq!(status, 202, "{sent}");
        let id = sent["message_id"].as_str().unwrap();
        let bob = json!({ "id": "bob", "node": "x" });
        assert_eq!(
            fed_reply(&s, pin, a.fed_port, id, mallory.clone(), "forged").await,
            403
        );
        assert_eq!(
            fed_reply(&s, pin, a.fed_port, id, bob, "from bob").await,
            200
        );

        // Queued for a dial-out client, resolved there by label.
        let (status, sent) = http_send(&a, "Bobby@sini.w", "for bobby").await;
        assert_eq!(status, 202, "{sent}");
        assert_eq!(sent["outcome"], "queued", "{sent}");
        let id = sent["message_id"].as_str().unwrap();
        let bobby = json!({ "id": "b0b", "node": "x", "label": "Bobby" });
        assert_eq!(
            fed_reply(&w, pin, a.fed_port, id, mallory.clone(), "forged").await,
            403
        );
        assert_eq!(
            fed_reply(&w, pin, a.fed_port, id, system.clone(), "forged").await,
            403
        );
        assert_eq!(
            fed_reply(&w, pin, a.fed_port, id, bobby, "from bobby").await,
            200
        );

        // The dial-out client's own error reply.
        let (status, sent) = http_send(&a, "nobody@sini.w", "for nobody").await;
        assert_eq!(status, 202, "{sent}");
        let id = sent["message_id"].as_str().unwrap();
        let err = json!({ "error": "not_found", "detail": "no live session matches 'nobody'" })
            .to_string();
        assert_eq!(fed_reply(&w, pin, a.fed_port, id, mallory, &err).await, 403);
        assert_eq!(fed_reply(&w, pin, a.fed_port, id, system, &err).await, 200);
    })
    .await;
}

// =============================================================================
// Idempotency (gate idem-verify-v0 F3): message-ID deduplication means the message was
// delivered once. A recorded failure is not a delivery, so a keyed retry (the same
// message ID) after the peer failed to deliver is delivered.
// Mutant: answer a recorded failure from its record => RED.
// =============================================================================

/// A Claude fake on `sessions_dir` whose inbox socket is bound only when `bind` is called.
fn late_session(sessions_dir: &Path, session_id: &str, name: &str) -> PathBuf {
    let sock_path = short_sock::sock_path(sessions_dir, "late");
    let pid = std::process::id();
    let proc_start =
        xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    let sess_uuid = if xmsg::claim::is_uuid_shaped(session_id) {
        session_id.to_string()
    } else {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(session_id.as_bytes());
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-8{:01x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            h[0], h[1], h[2], h[3], h[4], h[5], h[6] & 0x0f, h[7], h[8] & 0x0f, h[9], h[10], h[11], h[12], h[13], h[14], h[15]
        )
    };
    let session = json!({
        "pid": pid, "sessionId": sess_uuid, "name": name, "cwd": "/workspace",
        "status": "idle", "kind": "interactive", "startedAt": 1000, "updatedAt": 2000,
        "procStart": proc_start, "messagingSocketPath": sock_path.display().to_string(),
    });
    fs::write(
        sessions_dir.join(format!("{pid}-{session_id}.json")),
        session.to_string(),
    )
    .unwrap();
    sock_path
}

fn bind_inbox(sock_path: &Path) -> Arc<Mutex<Vec<String>>> {
    let listener = UnixListener::bind(sock_path).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
            if let Ok(s) = String::from_utf8(buf) {
                rx.lock().unwrap().push(s);
            }
        }
    });
    received
}

async fn keyed_send(node: &Node, to: &str, text: &str, key: Option<&str>) -> (u16, Value) {
    let url = format!("http://127.0.0.1:{}/v1/messages", node.http_port);
    let mut body = json!({ "to": to, "from": "ci", "text": text });
    if let Some(k) = key {
        body["idempotency_key"] = json!(k);
    }
    let resp = reqwest::Client::new()
        .post(url)
        .json(&body)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .unwrap();
    (
        resp.status().as_u16(),
        resp.json().await.unwrap_or(Value::Null),
    )
}

/// A federated send whose peer failed to deliver (the recipient's inbox was down) is
/// retried with its key once the inbox is back. Arm K: keyed (same message ID). Arm U:
/// unkeyed (a fresh ID), the control that the recipient is deliverable again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_idem_keyed_retry_after_peer_delivery_failure_delivers() {
    run_with_port_retry(|| async {
        let m = mesh(true, true).await;
        let kid = "dd0d0d0d-0000-4000-8000-0000000000d1";
        let uid = "dd0d0d0d-0000-4000-8000-0000000000d2";
        let ksock = late_session(&m._b.sessions_dir, kid, "Kay");
        let usock = short_sock::sock_path(&m._b.sessions_dir, "late2");
        {
            let pid = std::process::id();
            let proc_start =
                xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
            let session = json!({
                "pid": pid, "sessionId": uid, "name": "Uma", "cwd": "/workspace",
                "status": "idle", "kind": "interactive", "startedAt": 1000, "updatedAt": 2000,
                "procStart": proc_start, "messagingSocketPath": usock.display().to_string(),
            });
            fs::write(m._b.sessions_dir.join(format!("{pid}-{uid}.json")), session.to_string()).unwrap();
        }
        let kto = format!("{kid}@eve.b");
        let uto = format!("{uid}@eve.b");
        let k1 = keyed_send(&m.a, &kto, "fed-k", Some("k-fed")).await;
        let u1 = keyed_send(&m.a, &uto, "fed-u", None).await;
        let krx = bind_inbox(&ksock);
        let urx = bind_inbox(&usock);
        let k2 = keyed_send(&m.a, &kto, "fed-k", Some("k-fed")).await;
        let u2 = keyed_send(&m.a, &uto, "fed-u", None).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let kn = krx.lock().unwrap().len();
        let un = urx.lock().unwrap().len();
        eprintln!("K first={k1:?} retry={k2:?} delivered={kn} | U first={u1:?} retry={u2:?} delivered={un}");
        assert_ne!(k1.0, 202, "the inbox is down: {k1:?}");
        assert_eq!(k2.0, 202, "{k2:?}");
        assert_eq!(un, 1, "control: the recipient is deliverable again");
        assert_eq!(kn, 1, "a keyed retry after a peer-side failure delivers");
    })
    .await;
}

// =============================================================================
// Oracle 12: A reply that arrived over federation is itself answerable, in both directions
// (A-2, A7). Alice on A sends X to B's `answerer`; its reply R is pushed to Alice; Alice
// answers R, which reaches `answerer` on B attributed to Alice with `inReplyTo` R; and
// `answerer` answers that, which reaches Alice: three hops, one thread.
// A redelivered R (the same `/fed/v2/replies` envelope again) is recorded and pushed once.
// Mutant: no message record for a reply pushed from a peer => RED, `not_found`.
// =============================================================================

struct Pair {
    a: Node,
    _b: Node,
    ca_b: Creds,
    pin_a: String,
    alice: Arc<Mutex<Vec<String>>>,
    r: BufReader<OwnedReadHalf>,
    w: OwnedWriteHalf,
    x: String,
    reply: String,
}

/// The `message_id=` a pushed reply line carries for itself (the second one in it).
fn pushed_id(line: &str) -> String {
    let rest = line
        .split("message_id=")
        .nth(2)
        .expect("a pushed reply's own ID");
    rest.chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Alice on A has sent X to `answerer@eve.b`, and its reply R has been pushed to her.
async fn replied_pair() -> Pair {
    let ca = Ca::new();
    let (ca_a, ca_b) = (ca.issue(URI_A), ca.issue(URI_B));
    let (pa, pb) = (prepare(&ca), prepare(&ca));
    let peers_a =
        json!({ "eve.b": ca_entry(pb.fed_port, &pa.ca_file(), URI_B, &["send", "reply"]) });
    let peers_b =
        json!({ "sini.a": ca_entry(pa.fed_port, &pb.ca_file(), URI_A, &["send", "reply"]) });
    let b = start(pb, &ca_b, peers_b, None, Some("answerer")).await;
    let a = start(pa, &ca_a, peers_a, None, None).await;
    let alice = claude_session(
        &a.sessions_dir,
        "135aa23d-60a6-5595-a42a-c0296722252e",
        "Alice",
    );
    let (mut r, mut w) = register_svc(&b.register_sock, "answerer").await;

    let sent = agent_send(&a, "answerer@eve.b", "x from alice").await;
    assert_eq!(sent["status"], "ok", "{sent}");
    let x = sent["message_id"].as_str().unwrap().to_string();
    let got = svc_poll(&mut r, &mut w).await;
    assert_eq!(got["text"], "x from alice", "{got}");
    let replied = svc_reply(
        &mut r,
        &mut w,
        got["messageId"].as_str().unwrap(),
        "r to alice",
    )
    .await;
    assert_eq!(replied["status"], "ok", "{replied}");
    let line = wait_line(&alice, "r to alice")
        .await
        .expect("B's reply is pushed into the Claude session on A");
    let reply = pushed_id(&line);
    assert_eq!(
        replied["messageId"].as_str(),
        Some(reply.as_str()),
        "{replied} / {line}"
    );
    Pair {
        a,
        _b: b,
        pin_a: ca_a.pin.clone(),
        ca_b,
        alice,
        r,
        w,
        x,
        reply,
    }
}

/// A reply over `agent.sock` from this process, the Claude fake on that node.
async fn agent_reply(node: &Node, message_id: &str, text: &str) -> Value {
    let stream = UnixStream::connect(&node.agent_sock).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let frame = json!({ "action": "reply", "message_id": message_id, "text": text });
    w.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_12_a_federated_reply_is_answerable() {
    run_with_port_retry(|| async {
        let Pair {
            a,
            _b,
            alice,
            mut r,
            mut w,
            reply,
            ..
        } = replied_pair().await;

        // Alice answers R: it reaches `answerer` on B, from Alice, in reply to R.
        let answered = agent_reply(&a, &reply, "a2 to answerer").await;
        assert_eq!(answered["status"], "ok", "Alice answers R: {answered}");
        assert_eq!(answered["reply"]["pushOutcome"], "pushed", "{answered}");
        let got = svc_poll(&mut r, &mut w).await;
        assert_eq!(got["action"], "deliver", "{got}");
        assert_eq!(got["text"], "a2 to answerer", "{got}");
        assert_eq!(got["inReplyTo"], reply.as_str(), "{got}");
        assert_eq!(
            got["origin"]["id"], "135aa23d-60a6-5595-a42a-c0296722252e",
            "attributed to Alice: {got}"
        );
        assert_eq!(got["origin"]["node"], "sini.a", "attested to A: {got}");

        // `answerer` answers Alice's reply: it reaches Alice on A.
        let a2 = got["messageId"].as_str().unwrap().to_string();
        let replied = svc_reply(&mut r, &mut w, &a2, "b3 to alice").await;
        assert_eq!(replied["status"], "ok", "answerer answers A2: {replied}");
        let line = wait_line(&alice, "b3 to alice")
            .await
            .expect("the third hop is pushed into the Claude session on A");
        assert!(line.contains(&format!("message_id={a2}")), "{line}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_12b_a_redelivered_federated_reply_is_recorded_once() {
    run_with_port_retry(|| async {
        let p = replied_pair().await;
        // B delivers R again: the same envelope, as a retry after a lost answer would.
        let b = Origin {
            cert_der: &p.ca_b.cert_der,
            key_der: &p.ca_b.key_der,
        };
        let env = json!({
            "v": 2, "id": p.reply, "in_reply_to": p.x,
            "replier": { "service": "answerer", "node": "x" },
            "text": "r to alice", "created_at": 1000,
        });
        let (status, body) = hop_client::request(
            &b,
            &p.pin_a,
            p.a.fed_port,
            "POST",
            "/fed/v2/replies",
            Some(env),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        tokio::time::sleep(Duration::from_millis(300)).await;

        {
            let db = rusqlite::Connection::open(p.a.tmp.path().join("node.db")).unwrap();
            let count =
                |sql: &str| -> i64 { db.query_row(sql, [&p.reply], |row| row.get(0)).unwrap() };
            assert_eq!(count("SELECT COUNT(*) FROM messages WHERE id = ?1"), 1);
            assert_eq!(
                count("SELECT COUNT(*) FROM replies WHERE pushed_message_id = ?1"),
                1
            );
            let pushes = p
                .alice
                .lock()
                .unwrap()
                .iter()
                .filter(|l| l.contains("r to alice"))
                .count();
            assert_eq!(pushes, 1, "R is pushed to Alice once");
        }

        // And it is still answerable.
        let answered = agent_reply(&p.a, &p.reply, "after redelivery").await;
        assert_eq!(answered["status"], "ok", "{answered}");
    })
    .await;
}
