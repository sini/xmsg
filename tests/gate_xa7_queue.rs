//! XA7 gate: A14's queue across one user's nodes and A16's hand-off (D-1's FAIL-IFs; plan
//! gate v0 C11, C13).
//!
//! Every node is a real `xmsg serve` holding a CA-issued SPIFFE leaf, with HOME in its
//! tempdir (§1a), and every conversation is a Claude fake behind a live process. Where an
//! oracle needs a fault between two nodes (a lost acknowledgement, a crash), the asker
//! reaches the holder through an in-process mTLS proxy that presents the holder's identity
//! and forwards as the asker, and the fault happens there.
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;

use xmsg::fed::{make_tls_connector, normalize_pin, spki_sha256_from_der, PeerConfig, PeersMap};

mod hop_client;
use hop_client::Origin;
mod http_child;
use http_child::{FakeParent, Via};

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");
const CHILD: &str = "http_child_entry";
const X: &str = "0a7a7a7a-0000-4000-8000-00000000000a";
const ALL: &[&str] = &["send", "reply", "list"];

/// The HTTP child of a talking Claude fake (A15's walk finds the fake as its caller).
#[test]
fn http_child_entry() {
    http_child::serve_if_child();
}

fn uri(node: &str) -> String {
    let (user, host) = node.split_once('.').unwrap();
    format!("spiffe://xa7.test/host/{host}/user/{user}")
}

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

fn get_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

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
            .push(rcgen::DnType::CommonName, "xa7 test CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }

    fn issue(&self, node: &str) -> Creds {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "leaf");
        params.subject_alt_names = vec![rcgen::SanType::URI(uri(node).try_into().unwrap())];
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

/// A node's tempdir and ports, fixed before any node starts so peers can name them.
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

struct Node {
    name: String,
    tmp: TempDir,
    http_port: u16,
    sessions_dir: PathBuf,
    args: Vec<String>,
    run_dir: PathBuf,
    child: Option<tokio::process::Child>,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
        }
    }
}

/// Starts `xmsg serve` as `name` with `creds` and `peers`, HOME in its tempdir (§1a).
async fn start(name: &str, p: Prepared, creds: &Creds, peers: Value) -> Node {
    start_with(name, p, creds, peers, &[]).await
}

/// `start`, with `extra` serve arguments.
async fn start_with(
    name: &str,
    p: Prepared,
    creds: &Creds,
    peers: Value,
    extra: &[String],
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
    let (cert, key, peers_file) = (
        tmp.path().join("cert.pem"),
        tmp.path().join("key.pem"),
        tmp.path().join("peers.json"),
    );
    fs::write(&cert, &creds.cert).unwrap();
    fs::write(&key, &creds.key).unwrap();
    fs::write(&peers_file, peers.to_string()).unwrap();
    let s = |p: &Path| p.display().to_string();
    let args: Vec<String> = vec![
        "serve".into(),
        "--listen".into(),
        format!("127.0.0.1:{http_port}"),
        "--db-path".into(),
        s(&tmp.path().join("node.db")),
        "--sessions-dir".into(),
        s(&sessions_dir),
        "--register-sock".into(),
        s(&run_dir.join("register.sock")),
        "--fed-cert".into(),
        s(&cert),
        "--fed-key".into(),
        s(&key),
        "--peers-file".into(),
        s(&peers_file),
        "--fed-listen".into(),
        format!("127.0.0.1:{fed_port}"),
        "--agent-sock".into(),
        s(&run_dir.join("agent.sock")),
        "--http-sock".into(),
        s(&run_dir.join("http.sock")),
    ]
    .into_iter()
    .chain(extra.iter().cloned())
    .collect();
    let mut node = Node {
        name: name.to_string(),
        tmp,
        http_port,
        sessions_dir,
        args,
        run_dir,
        child: None,
    };
    node.spawn(fed_port).await;
    node
}

impl Node {
    async fn spawn(&mut self, fed_port: u16) {
        let agent_sock = self.run_dir.join("agent.sock");
        let http_sock = self.run_dir.join("http.sock");
        let _ = fs::remove_file(&agent_sock);
        let _ = fs::remove_file(&http_sock);
        let mut child = tokio::process::Command::new(BIN)
            .env("XDG_RUNTIME_DIR", &self.run_dir)
            .env("HOME", &self.run_dir)
            .env("RUST_LOG", "warn")
            .args(&self.args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
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
            let up = agent_sock.exists()
                && http_sock.exists()
                && tokio::net::TcpStream::connect(("127.0.0.1", self.http_port))
                    .await
                    .is_ok()
                && tokio::net::TcpStream::connect(("127.0.0.1", fed_port))
                    .await
                    .is_ok();
            if up {
                self.child = Some(child);
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = child.start_kill();
        panic!("xmsg serve neither served nor exited within 30s");
    }

    /// Kills the node outright (SIGKILL): a crash.
    async fn crash(&mut self) {
        if let Some(mut c) = self.child.take() {
            c.kill().await.unwrap();
        }
    }

    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.tmp.path().join("node.db")).unwrap()
    }

    /// The undelivered messages this node holds for `id`: (message ID, expiry).
    fn queued(&self, id: &str) -> Vec<(String, i64)> {
        let db = self.db();
        let mut stmt = db
            .prepare("SELECT id, expires_at FROM instance_queue WHERE instance_id = ?1 AND delivered_at IS NULL ORDER BY id")
            .unwrap();
        stmt.query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// `list` on this node, which observes its Claude fakes (A14): the status of `id` here.
    async fn status_of(&self, id: &str) -> Option<String> {
        for suffix in ["", "&status=inactive"] {
            let url = format!(
                "http://127.0.0.1:{}/v1/recipients?node={}{suffix}",
                self.http_port, self.name
            );
            let v: Value = reqwest::get(url).await.unwrap().json().await.unwrap();
            if let Some(status) = v["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["address"] == format!("{id}@{}", self.name))
                .map(|r| r["status"].as_str().unwrap().to_string())
            {
                return Some(status);
            }
        }
        None
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

fn entry(port: u16, ca_file: &Path, node: &str) -> Value {
    json!({
        "address": format!("127.0.0.1:{port}"),
        "ca": ca_file.display().to_string(),
        "identities": [uri(node)],
        "allow": ALL,
    })
}

/// A set of real nodes, fully peered. `dead` nodes are peers-file entries on a port nothing
/// listens on.
struct Mesh {
    creds: HashMap<String, Creds>,
    nodes: HashMap<String, Node>,
    fed_ports: HashMap<String, u16>,
}

async fn mesh(names: &[&str], dead: &[&str]) -> Mesh {
    mesh_with(names, dead, &[]).await
}

/// `mesh`, with extra serve arguments for some nodes.
async fn mesh_with(names: &[&str], dead: &[&str], extra: &[(&str, Vec<String>)]) -> Mesh {
    let ca = Ca::new();
    let creds: HashMap<String, Creds> =
        names.iter().map(|n| (n.to_string(), ca.issue(n))).collect();
    let preps: Vec<(&str, Prepared)> = names.iter().map(|n| (*n, prepare(&ca))).collect();
    let fed_ports: HashMap<String, u16> = preps
        .iter()
        .map(|(n, p)| (n.to_string(), p.fed_port))
        .chain(dead.iter().map(|n| (n.to_string(), get_free_port())))
        .collect();
    let mut nodes = HashMap::new();
    for (me, p) in preps {
        let ca_file = p.tmp.path().join("ca.pem");
        let mut peers = serde_json::Map::new();
        for other in names.iter().chain(dead).filter(|o| **o != me) {
            peers.insert(other.to_string(), entry(fed_ports[*other], &ca_file, other));
        }
        let args = extra
            .iter()
            .find(|(n, _)| *n == me)
            .map_or(&[][..], |(_, a)| a.as_slice());
        let node = start_with(me, p, &creds[me], Value::Object(peers), args).await;
        nodes.insert(me.to_string(), node);
    }
    Mesh {
        creds,
        nodes,
        fed_ports,
    }
}

impl Mesh {
    fn node(&self, n: &str) -> &Node {
        &self.nodes[n]
    }
}

/// An anonymous HTTP send over the node's TCP listener: (status, body).
async fn http_send(node: &Node, to: &str, text: &str) -> (u16, Value) {
    let url = format!("http://127.0.0.1:{}/v1/messages", node.http_port);
    let resp = reqwest::Client::new()
        .post(url)
        .json(&json!({ "to": to, "from": "ci", "text": text }))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .unwrap();
    (
        resp.status().as_u16(),
        resp.json().await.unwrap_or(Value::Null),
    )
}

// -----------------------------------------------------------------------------
// Claude fakes
// -----------------------------------------------------------------------------

struct Sleeper(Child);

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The process behind a Claude fake: a sleeper, or one whose children make HTTP requests.
enum Proc {
    Sleep(Sleeper),
    Talk(FakeParent),
}

/// A Claude fake presenting `id` on a node, behind a live process, with an inbox.
struct Claude {
    file: PathBuf,
    proc: Proc,
    lines: Arc<Mutex<Vec<String>>>,
    _dir: TempDir,
}

fn claude(node: &Node, id: &str) -> Claude {
    claude_in(&node.sessions_dir, id, false)
}

/// A Claude fake in sessions dir `sessions`; one that `talks` makes HTTP requests.
fn claude_in(sessions: &Path, id: &str, talks: bool) -> Claude {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("inbox.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let rx = lines.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf).await;
            rx.lock().unwrap().push(buf);
        }
    });
    let proc = if talks {
        Proc::Talk(FakeParent::spawn(CHILD))
    } else {
        Proc::Sleep(Sleeper(
            Command::new("sleep")
                .arg("600")
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn sleep"),
        ))
    };
    let pid = match &proc {
        Proc::Sleep(s) => s.0.id(),
        Proc::Talk(f) => f.pid(),
    };
    let start = xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    let session = json!({
        "pid": pid, "sessionId": id, "name": "x", "cwd": "/w", "status": "idle",
        "kind": "interactive", "startedAt": 1, "updatedAt": 2, "procStart": start,
        "messagingSocketPath": sock.display().to_string(),
    });
    let file = sessions.join(format!("{pid}-{id}.json"));
    fs::write(&file, session.to_string()).unwrap();
    Claude {
        file,
        proc,
        lines,
        _dir: dir,
    }
}

impl Claude {
    /// The conversation leaves this node: its file stops naming it (D-2).
    fn exit(self) {
        fs::remove_file(&self.file).unwrap();
    }
    fn count(&self, needle: &str) -> usize {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(needle))
            .count()
    }
    async fn got(&self, needle: &str) -> bool {
        for _ in 0..200 {
            if self.count(needle) > 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    /// A request to `node`'s `http.sock` from this fake's child: (status, body).
    async fn req(&self, node: &Node, method: &str, path: &str, body: Value) -> (u16, Value) {
        let Proc::Talk(fp) = &self.proc else {
            panic!("this Claude fake does not talk");
        };
        let (st, body) = fp
            .request(
                &Via::Unix(node.run_dir.join("http.sock")),
                method,
                path,
                Some(&body),
            )
            .await;
        (
            st,
            serde_json::from_str(&body).unwrap_or(Value::String(body)),
        )
    }
}

/// X goes live on `node` (observed there), then exits, and the node observes it parked.
async fn park(node: &Node, id: &str) {
    let c = claude(node, id);
    assert_eq!(node.status_of(id).await.as_deref(), Some("live"));
    c.exit();
    assert_eq!(node.status_of(id).await.as_deref(), Some("parked"));
}

/// X live on every node of `nodes` at once, then gone from all: parked on each, with no
/// hand-off between them (two live listings).
async fn park_on_all(nodes: &[&Node], id: &str) {
    let fakes: Vec<Claude> = nodes.iter().map(|n| claude(n, id)).collect();
    for n in nodes {
        assert_eq!(n.status_of(id).await.as_deref(), Some("live"));
    }
    for c in fakes {
        c.exit();
    }
    for n in nodes {
        assert_eq!(n.status_of(id).await.as_deref(), Some("parked"));
    }
}

/// Queues `text` for X at `node`, sent there by an anonymous local caller.
async fn queue_at(node: &Node, text: &str) {
    let (status, body) = http_send(node, X, text).await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["outcome"], "queued", "{body}");
    assert_eq!(body["address"], format!("{X}@{}", node.name), "{body}");
}

/// Waits until `node` no longer holds anything queued for X.
async fn drained(node: &Node) -> bool {
    for _ in 0..200 {
        if node.queued(X).is_empty() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// -----------------------------------------------------------------------------
// A fault proxy: presents the holder's identity to the asker, forwards as the asker
// -----------------------------------------------------------------------------

/// What happens to the first request on `path`: dropped before it reaches the holder, or
/// forwarded and its answer lost after the test crashed the holder (`crashed` reports the
/// answer, and the proxy waits for `resume` before failing the request).
struct Fault {
    path: &'static str,
    forward: bool,
    /// While set, every request on `path` is answered 502 and never reaches the holder.
    drop: Option<Arc<AtomicBool>>,
    /// The first request on `path` waits for `crashed`'s resume, then is forwarded and
    /// answered as the holder answers.
    hold_before: bool,
    crashed: Option<(
        tokio::sync::mpsc::UnboundedSender<()>,
        Arc<tokio::sync::Notify>,
    )>,
}

/// Starts the proxy for asker `asker` to holder `holder` (the holder's fed port given),
/// returning its port and how many requests it saw on `fault.path`.
async fn proxy(
    asker: &Creds,
    holder: &Creds,
    holder_port: u16,
    fault: Fault,
) -> (u16, Arc<AtomicUsize>) {
    let peers = HashMap::from([(
        "asker".to_string(),
        PeerConfig {
            name: "asker".to_string(),
            address: "127.0.0.1:1".to_string(),
            pin: Some(normalize_pin(&asker.pin)),
            allow: ALL.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
    )]);
    let acceptor = xmsg::fed::make_tls_acceptor(
        &[rustls::pki_types::CertificateDer::from(
            holder.cert_der.clone(),
        )],
        &holder.key_der,
        Arc::new(PeersMap::new(peers)),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let fault = Arc::new(fault);
    let (asker, holder_pin) = (Arc::new(asker.clone()), holder.pin.clone());
    let seen_c = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, fault, seen) = (acceptor.clone(), fault.clone(), seen_c.clone());
            let (asker, holder_pin) = (asker.clone(), holder_pin.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let (fault, seen) = (fault.clone(), seen.clone());
                        let (asker, holder_pin) = (asker.clone(), holder_pin.clone());
                        async move {
                            use http_body_util::BodyExt;
                            let (method, path) =
                                (req.method().to_string(), req.uri().path().to_string());
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let on_path = path == fault.path;
                            let first = on_path && seen.fetch_add(1, Ordering::SeqCst) == 0;
                            let dropped = on_path
                                && fault
                                    .drop
                                    .as_ref()
                                    .is_some_and(|d| d.load(Ordering::SeqCst));
                            let answer = if dropped {
                                None
                            } else if first && fault.hold_before {
                                if let Some((tx, resume)) = &fault.crashed {
                                    tx.send(()).unwrap();
                                    resume.notified().await;
                                }
                                forward(&asker, &holder_pin, holder_port, &method, &path, &body)
                                    .await
                            } else {
                                let answer = if first && !fault.forward {
                                    None
                                } else {
                                    forward(&asker, &holder_pin, holder_port, &method, &path, &body)
                                        .await
                                };
                                match (first, answer) {
                                    (true, _) => {
                                        if let Some((tx, resume)) = &fault.crashed {
                                            tx.send(()).unwrap();
                                            resume.notified().await;
                                        }
                                        None
                                    }
                                    (false, a) => a,
                                }
                            };
                            let (status, bytes) =
                                answer.unwrap_or((502, bytes::Bytes::from_static(b"{}")));
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(bytes))
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

/// One request to the holder as the asker; `None` when the holder could not be reached.
async fn forward(
    asker: &Creds,
    pin: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &bytes::Bytes,
) -> Option<(u16, bytes::Bytes)> {
    let fut = async {
        let connector = make_tls_connector(&asker.cert_der, &asker.key_der, pin).ok()?;
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        let tls = connector
            .connect(ServerName::try_from("holder".to_string()).unwrap(), tcp)
            .await
            .ok()?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .ok()?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(body.clone()))
            .unwrap();
        let resp = sender.send_request(req).await.ok()?;
        let status = resp.status().as_u16();
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.ok()?.to_bytes();
        Some((status, bytes))
    };
    tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .ok()
        .flatten()
}

// =============================================================================
// Oracle 1 (FAIL-IF 1). Messages are queued for X while it is parked on P. X registers on
// Q (same user) and the messages are delivered on Q within that one registration; they
// keep their expiry, and P no longer lists X.
// Mutant: no pull on registration => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_the_queue_follows_the_conversation() {
    run_with_port_retry(|| async {
        let m = mesh(&["sini.p", "sini.q"], &[]).await;
        let (p, q) = (m.node("sini.p"), m.node("sini.q"));
        park(p, X).await;
        queue_at(p, "first while parked").await;
        queue_at(p, "second while parked").await;
        let held = p.queued(X);
        assert_eq!(held.len(), 2);

        let on_q = claude(q, X);
        assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
        assert!(on_q.got("first while parked").await, "not delivered on Q");
        assert!(on_q.got("second while parked").await, "not delivered on Q");
        assert!(drained(p).await, "P still holds the queue");
        assert_eq!(p.status_of(X).await, None, "P still lists X");
        let db = q.db();
        for (id, expires) in held {
            let e: i64 = db
                .query_row(
                    "SELECT expires_at FROM instance_queue WHERE id = ?1",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(e, expires, "the expiry did not travel with {id}");
        }
    })
    .await;
}

// =============================================================================
// Oracle 2 (FAIL-IF 2). X is parked on P and on Q (one user), and a send from a third
// node returns `queued`, not `ambiguous`.
// Mutant: two listings => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_parked_and_parked_is_one_destination() {
    run_with_port_retry(|| async {
        let m = mesh(&["sini.p", "sini.q", "bob.s"], &[]).await;
        park_on_all(&[m.node("sini.p"), m.node("sini.q")], X).await;
        let (status, body) = http_send(m.node("bob.s"), X, "to x").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["outcome"], "queued", "{body}");
    })
    .await;
}

// =============================================================================
// Oracle 3 (a lost acknowledgement). The asker's first acknowledgement is dropped, the
// transfer repeats, and each message is delivered once.
// Mutant: no deduplication => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_a_lost_acknowledgement_delivers_once() {
    run_with_port_retry(|| async {
        let m = mesh_with_proxy(Fault {
            path: "/fed/v2/handoff/ack",
            forward: false,
            drop: None,
            hold_before: false,
            crashed: None,
        })
        .await;
        let (p, q) = (m.mesh.node("sini.p"), m.mesh.node("sini.q"));
        park(p, X).await;
        queue_at(p, "only once").await;

        let on_q = claude(q, X);
        assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
        assert!(on_q.got("only once").await, "not delivered on Q");
        assert!(
            drained(p).await,
            "the repeated transfer was never acknowledged"
        );
        assert!(
            m.seen.load(Ordering::SeqCst) >= 2,
            "the transfer did not repeat"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(on_q.count("only once"), 1, "delivered twice");
    })
    .await;
}

struct Proxied {
    mesh: Mesh,
    seen: Arc<AtomicUsize>,
}

/// P and Q of user sini, with Q's entry for P routed through a fault proxy.
async fn mesh_with_proxy(fault: Fault) -> Proxied {
    mesh_with_proxy_and(&[], fault).await
}

/// P, Q and `others`, fully peered, with only Q's entry for P routed through a fault proxy.
async fn mesh_with_proxy_and(others: &[&str], fault: Fault) -> Proxied {
    let ca = Ca::new();
    let names: Vec<&str> = ["sini.p", "sini.q"].iter().chain(others).copied().collect();
    let creds: HashMap<String, Creds> =
        names.iter().map(|n| (n.to_string(), ca.issue(n))).collect();
    let preps: Vec<(&str, Prepared)> = names.iter().map(|n| (*n, prepare(&ca))).collect();
    let fed_ports: HashMap<String, u16> = preps
        .iter()
        .map(|(n, p)| (n.to_string(), p.fed_port))
        .collect();
    // Q reaches P through the proxy, whose port is fixed before Q starts.
    let (proxy_port, seen) = proxy(
        &creds["sini.q"],
        &creds["sini.p"],
        fed_ports["sini.p"],
        fault,
    )
    .await;
    let mut nodes = HashMap::new();
    for (me, p) in preps {
        let ca_file = p.tmp.path().join("ca.pem");
        let mut peers = serde_json::Map::new();
        for other in names.iter().filter(|o| **o != me) {
            let port = if (me, *other) == ("sini.q", "sini.p") {
                proxy_port
            } else {
                fed_ports[*other]
            };
            peers.insert(other.to_string(), entry(port, &ca_file, other));
        }
        let node = start(me, p, &creds[me], Value::Object(peers)).await;
        nodes.insert(me.to_string(), node);
    }
    Proxied {
        mesh: Mesh {
            creds,
            nodes,
            fed_ports,
        },
        seen,
    }
}

// =============================================================================
// Oracle 4 (two live listings). X is live on Q and R, so P hands nothing over and a send
// gives `ambiguous`.
// Mutant: hand over to the first asker => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_two_live_listings_take_nothing() {
    run_with_port_retry(|| async {
        let m = mesh(&["sini.p", "sini.q", "sini.r"], &[]).await;
        let (p, q, r) = (m.node("sini.p"), m.node("sini.q"), m.node("sini.r"));
        park(p, X).await;
        queue_at(p, "held at p").await;

        let (on_q, on_r) = (claude(q, X), claude(r, X));
        assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
        assert_eq!(r.status_of(X).await.as_deref(), Some("live"));
        let (status, body) = http_send(p, X, "to x").await;
        assert_eq!(status, 409, "{body}");
        assert_eq!(body["error"], "ambiguous", "{body}");
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            on_q.count("held at p") + on_r.count("held at p"),
            0,
            "handed over"
        );
        assert_eq!(p.queued(X).len(), 1, "P's queue moved");
    })
    .await;
}

// =============================================================================
// Oracle 5 (another user). eve's node E has X live and asks sini's P for X's queue, and P
// refuses. (E's own pull asks only eve's nodes, so the ask is made with E's identity.)
// Mutant: drop the user check => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_another_user_cannot_pull() {
    run_with_port_retry(|| async {
        let m = mesh(&["sini.p", "eve.e"], &[]).await;
        let (p, e) = (m.node("sini.p"), m.node("eve.e"));
        park(p, X).await;
        queue_at(p, "for sini's x").await;
        let on_e = claude(e, X);
        assert_eq!(e.status_of(X).await.as_deref(), Some("live"));

        let ce = &m.creds["eve.e"];
        let asker = Origin {
            cert_der: &ce.cert_der,
            key_der: &ce.key_der,
        };
        let (status, res) = hop_client::request(
            &asker,
            &m.creds["sini.p"].pin,
            m.fed_ports["sini.p"],
            "POST",
            "/fed/v2/handoff",
            Some(json!({ "id": X })),
        )
        .await;
        assert_eq!(status, 403, "{res}");
        assert_eq!(res["error"], "denied", "{res}");
        let (status, _) = hop_client::request(
            &asker,
            &m.creds["sini.p"].pin,
            m.fed_ports["sini.p"],
            "POST",
            "/fed/v2/handoff/ack",
            Some(json!({ "id": X, "messages": [] })),
        )
        .await;
        assert_eq!(status, 403, "eve acknowledged a hand-off");
        assert_eq!(p.queued(X).len(), 1, "P's queue moved");
        assert_eq!(on_e.count("for sini's x"), 0);
    })
    .await;
}

// =============================================================================
// Oracle 6 (a crash; C13). P is killed after it sends the transfer and before the
// acknowledgement, and its transfer is lost with it. Nothing is lost, and nothing is
// delivered twice once P restarts.
// Mutant: drop the listing before the acknowledgement => RED (the message is lost).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_a_crash_loses_nothing() {
    run_with_port_retry(|| async {
        let (crashed_tx, mut crashed) = tokio::sync::mpsc::unbounded_channel();
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut m = mesh_with_proxy(Fault {
            path: "/fed/v2/handoff",
            forward: true,
            drop: None,
            hold_before: false,
            crashed: Some((crashed_tx, resume.clone())),
        })
        .await;
        let p_fed = m.mesh.fed_ports["sini.p"];
        {
            let p = m.mesh.node("sini.p");
            park(p, X).await;
            queue_at(p, "survives the crash").await;
        }
        let on_q = claude(m.mesh.node("sini.q"), X);
        assert_eq!(
            m.mesh.node("sini.q").status_of(X).await.as_deref(),
            Some("live")
        );

        tokio::time::timeout(Duration::from_secs(30), crashed.recv())
            .await
            .expect("no transfer was asked for within 30s")
            .unwrap();
        let p = m.mesh.nodes.get_mut("sini.p").unwrap();
        p.crash().await;
        resume.notify_one();
        p.spawn(p_fed).await;

        assert!(on_q.got("survives the crash").await, "lost in the crash");
        assert!(drained(m.mesh.node("sini.p")).await, "never acknowledged");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(on_q.count("survives the crash"), 1, "delivered twice");
    })
    .await;
}

// =============================================================================
// Oracle 7 (an incomplete view; C11). X is parked on P, and X registers on Q while R (same
// user) is unreachable. P hands nothing over, and its queue stays at P.
// Mutant: hand over when the asker is the only live listing among the nodes that answered
// => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_7_an_incomplete_view_keeps_the_queue() {
    run_with_port_retry(|| async {
        let m = mesh(&["sini.p", "sini.q"], &["sini.r"]).await;
        let (p, q) = (m.node("sini.p"), m.node("sini.q"));
        park(p, X).await;
        queue_at(p, "stays at p").await;

        let on_q = claude(q, X);
        assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(on_q.count("stays at p"), 0, "handed over");
        assert_eq!(p.queued(X).len(), 1, "P's queue moved");
        assert_eq!(p.status_of(X).await.as_deref(), Some("parked"));
    })
    .await;
}

// =============================================================================
// Oracle 8 (pull all; C11). X is parked on P and on Q (one user), with messages queued at
// each. X registers on R, and both queues are delivered on R within that one
// registration.
// Mutant: pull from the first holder that answers only => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_8_pull_all() {
    run_with_port_retry(|| async {
        let m = mesh(&["sini.p", "sini.q", "sini.r"], &[]).await;
        let (p, q, r) = (m.node("sini.p"), m.node("sini.q"), m.node("sini.r"));
        park_on_all(&[p, q], X).await;
        queue_at(p, "queued at p").await;
        queue_at(q, "queued at q").await;

        let on_r = claude(r, X);
        assert_eq!(r.status_of(X).await.as_deref(), Some("live"));
        assert!(
            on_r.got("queued at p").await,
            "P's queue not delivered on R"
        );
        assert!(
            on_r.got("queued at q").await,
            "Q's queue not delivered on R"
        );
        assert!(drained(p).await && drained(q).await);
    })
    .await;
}

// =============================================================================
// Oracle 9 (C1; A8a: "Replies are unaffected: they travel by message ID"). X is parked on
// P, and two senders queue a message for it there: one on O (another node of the user)
// and one on P itself. X registers on Q, receives both, and replies to each: both replies
// are accepted and reach their senders, through P.
// Mutant: P records no forward at the acknowledgement => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_9_a_handed_over_message_keeps_its_reply() {
    run_with_port_retry(|| async {
        const AT_O: &str = "5e5e5e5e-0000-4000-8000-00000000005e";
        const AT_P: &str = "5f5f5f5f-0000-4000-8000-00000000005f";
        let m = mesh(&["sini.o", "sini.p", "sini.q"], &[]).await;
        let (o, p, q) = (m.node("sini.o"), m.node("sini.p"), m.node("sini.q"));
        park(p, X).await;
        let (from_o, from_p) = (
            claude_in(&o.sessions_dir, AT_O, true),
            claude_in(&p.sessions_dir, AT_P, true),
        );
        assert_eq!(o.status_of(AT_O).await.as_deref(), Some("live"));
        assert_eq!(p.status_of(AT_P).await.as_deref(), Some("live"));
        let mut ids = Vec::new();
        for (who, node, text) in [(&from_o, o, "asked-from-o"), (&from_p, p, "asked-from-p")] {
            let (st, body) = who
                .req(
                    node,
                    "POST",
                    "/v1/messages",
                    json!({ "to": X, "text": text }),
                )
                .await;
            assert_eq!(st, 202, "{body}");
            assert_eq!(body["outcome"], "queued", "{body}");
            ids.push(body["message_id"].as_str().unwrap().to_string());
        }

        let x = claude_in(&q.sessions_dir, X, true);
        assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
        assert!(x.got("asked-from-o").await, "not delivered on Q");
        assert!(x.got("asked-from-p").await, "not delivered on Q");
        assert!(drained(p).await, "P still holds the queue");
        for (mid, answer) in ids.iter().zip(["answer-to-o", "answer-to-p"]) {
            let (st, body) = x
                .req(
                    q,
                    "POST",
                    &format!("/v1/messages/{mid}/replies"),
                    json!({ "text": answer }),
                )
                .await;
            assert_eq!(st, 200, "the reply to {mid} was refused on Q: {body}");
        }
        assert!(
            from_o.got("answer-to-o").await,
            "the reply never reached O's sender"
        );
        assert!(
            from_p.got("answer-to-p").await,
            "the reply never reached P's sender"
        );
    })
    .await;
}

// =============================================================================
// Oracle 10 (C2; D-1: "a transfer repeated after a lost acknowledgement delivers nothing
// twice"). Q's acknowledgements to P are lost; X leaves Q, Q restarts, and only then do
// acknowledgements land again. Q acknowledges what it owed from its database, so when X
// moves on to R, P hands R nothing: the message is delivered once overall.
// Mutant: the owed acknowledgement is not resumed at start => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_10_an_owed_acknowledgement_survives_a_restart() {
    run_with_port_retry(|| async {
        let dropping = Arc::new(AtomicBool::new(true));
        let mut m = mesh_with_proxy_and(
            &["sini.r"],
            Fault {
                path: "/fed/v2/handoff/ack",
                forward: true,
                drop: Some(dropping.clone()),
                hold_before: false,
                crashed: None,
            },
        )
        .await;
        let q_fed = m.mesh.fed_ports["sini.q"];
        {
            let (p, q) = (m.mesh.node("sini.p"), m.mesh.node("sini.q"));
            park(p, X).await;
            queue_at(p, "once overall").await;
            let on_q = claude(q, X);
            assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
            assert!(on_q.got("once overall").await, "not delivered on Q");
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(on_q.count("once overall"), 1, "delivered twice on Q");
            for _ in 0..200 {
                if m.seen.load(Ordering::SeqCst) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(m.seen.load(Ordering::SeqCst) > 0, "Q never acknowledged");
            assert_eq!(p.queued(X).len(), 1, "an acknowledgement landed");
            on_q.exit();
            assert_eq!(q.status_of(X).await.as_deref(), Some("parked"));
        }
        let q = m.mesh.nodes.get_mut("sini.q").unwrap();
        q.crash().await;
        dropping.store(false, Ordering::SeqCst);
        q.spawn(q_fed).await;
        assert!(
            drained(m.mesh.node("sini.p")).await,
            "the owed acknowledgement was not resumed after the restart"
        );

        let r = m.mesh.node("sini.r");
        let on_r = claude(r, X);
        assert_eq!(r.status_of(X).await.as_deref(), Some("live"));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(on_r.count("once overall"), 0, "delivered again on R");
    })
    .await;
}

// =============================================================================
// Oracle 11 (C2: the asker's pull resumes after a restart). Q cannot reach P's hand-off
// while X goes live on Q, and Q restarts before it can; X is still live there, so no scan
// newly observes it. Q resumes the ask it recorded, and the queue is delivered on Q.
// Mutant: the recorded ask is not resumed at start => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_11_a_pull_resumes_after_a_restart() {
    run_with_port_retry(|| async {
        let dropping = Arc::new(AtomicBool::new(true));
        let mut m = mesh_with_proxy(Fault {
            path: "/fed/v2/handoff",
            forward: true,
            drop: Some(dropping.clone()),
            hold_before: false,
            crashed: None,
        })
        .await;
        let q_fed = m.mesh.fed_ports["sini.q"];
        {
            let p = m.mesh.node("sini.p");
            park(p, X).await;
            queue_at(p, "after the restart").await;
        }
        let on_q = claude(m.mesh.node("sini.q"), X);
        assert_eq!(
            m.mesh.node("sini.q").status_of(X).await.as_deref(),
            Some("live")
        );
        for _ in 0..200 {
            if m.seen.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(m.seen.load(Ordering::SeqCst) > 0, "Q never asked P");
        let q = m.mesh.nodes.get_mut("sini.q").unwrap();
        q.crash().await;
        dropping.store(false, Ordering::SeqCst);
        q.spawn(q_fed).await;
        assert!(
            on_q.got("after the restart").await,
            "the ask was not resumed after the restart"
        );
        assert!(drained(m.mesh.node("sini.p")).await, "never acknowledged");
    })
    .await;
}

// =============================================================================
// Oracle 12 (C3). A send reaches P between its transfer and Q's acknowledgement. The
// acknowledgement's answer counts it, Q asks again, and it is delivered on Q.
// Mutant: the asker ignores the count => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_12_a_send_in_the_window_follows() {
    run_with_port_retry(|| async {
        let (tx, mut held) = tokio::sync::mpsc::unbounded_channel();
        let resume = Arc::new(tokio::sync::Notify::new());
        let m = mesh_with_proxy(Fault {
            path: "/fed/v2/handoff/ack",
            forward: true,
            drop: None,
            hold_before: true,
            crashed: Some((tx, resume.clone())),
        })
        .await;
        let (p, q) = (m.mesh.node("sini.p"), m.mesh.node("sini.q"));
        park(p, X).await;
        queue_at(p, "before the transfer").await;
        let on_q = claude(q, X);
        assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
        tokio::time::timeout(Duration::from_secs(30), held.recv())
            .await
            .expect("Q never acknowledged within 30s")
            .unwrap();
        let (status, body) = http_send(p, &format!("{X}@sini.p"), "in the window").await;
        assert_eq!(
            (status, body["outcome"].as_str()),
            (202, Some("queued")),
            "{body}"
        );
        resume.notify_one();
        assert!(on_q.got("before the transfer").await, "not delivered on Q");
        assert!(
            on_q.got("in the window").await,
            "the send in the window is stranded at P"
        );
        assert!(drained(p).await, "P still holds a message");
        assert_eq!(p.status_of(X).await, None, "P still lists X");
    })
    .await;
}

// =============================================================================
// Oracle 13 (C4). P holds more for X than one transfer may carry (80 messages of about
// 1 KB, with `--max-body 1024`). P pages the transfer and Q asks again while P holds
// more, so all 80 are delivered on Q and P holds none.
// Mutant: one page holds the whole queue => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_13_a_queue_over_one_transfer_moves_whole() {
    run_with_port_retry(|| async {
        const N: usize = 80;
        let small = vec!["--max-body".to_string(), "1024".to_string()];
        let m = mesh_with(
            &["sini.p", "sini.q"],
            &[],
            &[("sini.p", small.clone()), ("sini.q", small)],
        )
        .await;
        let (p, q) = (m.node("sini.p"), m.node("sini.q"));
        park(p, X).await;
        let pad = "z".repeat(900);
        for i in 0..N {
            queue_at(p, &format!("big-{i:03}-{pad}")).await;
        }
        let on_q = claude(q, X);
        assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
        for _ in 0..400 {
            if on_q.count("big-") == N {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(on_q.count("big-"), N, "the queue did not move whole");
        assert!(drained(p).await, "P still holds part of the queue");
    })
    .await;
}

// =============================================================================
// Oracle 14 (C5). P scans two sessions dirs, and Y is live in the second. A hand-off ask
// at P (for an X it does not hold) leaves Y's claim unreleased, as it leaves Y2's in the
// first dir.
// Mutant: the fed side scans the first sessions dir only => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_14_a_handoff_ask_keeps_every_dirs_claims() {
    run_with_port_retry(|| async {
        const Y: &str = "0b0b0b0b-0000-4000-8000-00000000000b";
        const Y2: &str = "0c0c0c0c-0000-4000-8000-00000000000c";
        let d2 = tempdir().unwrap();
        fs::set_permissions(d2.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let second = vec![
            "--sessions-dir".to_string(),
            d2.path().display().to_string(),
        ];
        let m = mesh_with(&["sini.p", "sini.q"], &[], &[("sini.p", second)]).await;
        let p = m.node("sini.p");
        let (_y, _y2) = (claude_in(d2.path(), Y, false), claude(p, Y2));
        assert_eq!(p.status_of(Y).await.as_deref(), Some("live"));
        assert_eq!(p.status_of(Y2).await.as_deref(), Some("live"));
        let released = |id: &str| -> Vec<i64> {
            let db = p.db();
            let mut s = db
                .prepare("SELECT released FROM instance_claims WHERE id = ?1")
                .unwrap();
            s.query_map([id], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let c = &m.creds["sini.q"];
        let (status, res) = hop_client::request(
            &Origin {
                cert_der: &c.cert_der,
                key_der: &c.key_der,
            },
            &m.creds["sini.p"].pin,
            m.fed_ports["sini.p"],
            "POST",
            "/fed/v2/handoff",
            Some(json!({ "id": X })),
        )
        .await;
        assert_eq!(status, 404, "{res}");
        assert_eq!(released(Y2), vec![0], "the first dir's claim was released");
        assert_eq!(released(Y), vec![0], "the second dir's claim was released");
    })
    .await;
}

// =============================================================================
// Oracle 15 (C5). Q scans two sessions dirs, and X registers in the second. P's view of Q
// lists X live, so P hands its queue over and it is delivered on Q.
// Mutant: the fed side scans the first sessions dir only => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_15_the_queue_follows_into_a_second_sessions_dir() {
    run_with_port_retry(|| async {
        let d2 = tempdir().unwrap();
        fs::set_permissions(d2.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let second = vec![
            "--sessions-dir".to_string(),
            d2.path().display().to_string(),
        ];
        let m = mesh_with(&["sini.p", "sini.q"], &[], &[("sini.q", second)]).await;
        let (p, q) = (m.node("sini.p"), m.node("sini.q"));
        park(p, X).await;
        queue_at(p, "into dir two").await;
        let x = claude_in(d2.path(), X, false);
        assert_eq!(q.status_of(X).await.as_deref(), Some("live"));
        assert!(
            x.got("into dir two").await,
            "not delivered in Q's second dir"
        );
        assert!(drained(p).await, "P still holds the queue");
    })
    .await;
}
