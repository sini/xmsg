//! XA6 gate: mesh resolution (A7, A8, A8a, A11, A16, A17, A20, A-9, A-12, D-6, D-7, P-1;
//! plan gate v0 C4, C6, C7, C9, C11).
//!
//! The sending node is always a real `xmsg serve` holding a CA-issued SPIFFE leaf, and
//! every oracle names it, because A17 makes the outcome depend on the sender's user (C7).
//! Where the oracle is about the sender's resolution, the nodes it asks are in-process
//! mTLS stubs presenting CA leaves of users `sini` and `eve`: each answers `list` with a
//! fixed listing (after an optional delay) and records the sends it takes. Where it is
//! about the receiving node (the cache's live-only mark, A20, the outbound record), the
//! nodes are real. An unreachable node is a peers-file entry naming a port nothing
//! listens on.
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use xmsg::fed::{normalize_pin, spki_sha256_from_der, PeerConfig, PeersMap};

mod hop_client;
use hop_client::Origin;

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");

fn uri(node: &str) -> String {
    // `<user>.<host>`, or a pod `<sa>.<ns>` when `pod` names it.
    let (user, host) = node.split_once('.').unwrap();
    format!("spiffe://xa6.test/host/{host}/user/{user}")
}

const X: &str = "0a6a6a6a-0000-4000-8000-00000000000a";
/// A live session whose node holds a send for its harness's ack: a pi or plugin session (HA3).
const H: &str = "0a6a6a6a-0000-4000-8000-00000000000b";

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
            .push(rcgen::DnType::CommonName, "xa6 test CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }

    fn issue_uri(&self, uri: &str) -> Creds {
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

    fn issue(&self, node: &str) -> Creds {
        self.issue_uri(&uri(node))
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
    register_sock: PathBuf,
    sessions_dir: PathBuf,
    child: ChildGuard,
}

/// Starts `xmsg serve` with `creds` and `peers`, listening for federation, with HOME in its
/// tempdir (§1a). `svc` names a service this test executable may register as.
async fn start(p: Prepared, creds: &Creds, peers: Value, svc: Option<&str>) -> Node {
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
        "--fed-listen".into(),
        format!("127.0.0.1:{fed_port}"),
        "--agent-sock".into(),
        agent_sock.display().to_string(),
        "--http-sock".into(),
        run_dir.join("http.sock").display().to_string(),
    ];
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
        .stdout(Stdio::piped())
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
            && register_sock.exists()
            && tokio::net::TcpStream::connect(("127.0.0.1", http_port))
                .await
                .is_ok()
            && tokio::net::TcpStream::connect(("127.0.0.1", fed_port))
                .await
                .is_ok();
        if up {
            return Node {
                tmp,
                http_port,
                fed_port,
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

const ALL: &[&str] = &["send", "reply", "list"];

fn ca_entry_uri(port: u16, ca_file: &Path, uri: &str, allow: &[&str]) -> Value {
    json!({
        "address": format!("127.0.0.1:{port}"),
        "ca": ca_file.display().to_string(),
        "identities": [uri],
        "allow": allow,
    })
}

fn ca_entry(port: u16, ca_file: &Path, node: &str, allow: &[&str]) -> Value {
    ca_entry_uri(port, ca_file, &uri(node), allow)
}

/// An anonymous HTTP send from `ci` over the node's TCP listener: (status, body).
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
// Stub nodes
// -----------------------------------------------------------------------------

fn inst(id: &str, status: &str, user: &str) -> Value {
    json!({ "id": id, "kind": "instance", "status": status, "user": user })
}

fn labelled(id: &str, label: &str, user: &str) -> Value {
    json!({ "id": id, "kind": "instance", "label": label, "status": "live", "user": user })
}

fn svc(name: &str, user: &str) -> Value {
    json!({ "id": name, "kind": "service", "status": "live", "user": user })
}

/// What a stub node answers `list` with: its entries after `delay`, or `denied` (403).
#[derive(Clone)]
struct Listing {
    entries: Vec<Value>,
    delay: Duration,
    denied: bool,
}

fn listing(entries: Vec<Value>) -> Listing {
    Listing {
        entries,
        delay: Duration::ZERO,
        denied: false,
    }
}

/// An mTLS node presenting `creds`, admitting every pin in `clients`. It answers `list`
/// with `l`, and takes every send: `queued` for an entry it lists parked or for `H`,
/// `delivered` otherwise. Returns its port, the `to.ref` of every send it took, and how many times it
/// was asked for `list`.
async fn stub(
    creds: &Creds,
    clients: &[&str],
    l: Listing,
) -> (u16, Arc<Mutex<Vec<String>>>, Arc<AtomicUsize>) {
    let mut peers = HashMap::new();
    for (i, pin) in clients.iter().enumerate() {
        peers.insert(
            format!("client{i}"),
            PeerConfig {
                name: format!("client{i}"),
                address: "127.0.0.1:1".to_string(),
                pin: Some(normalize_pin(pin)),
                allow: vec!["send".to_string(), "list".to_string()],
                ..Default::default()
            },
        );
    }
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
    let sent = Arc::new(Mutex::new(Vec::new()));
    let lists = Arc::new(AtomicUsize::new(0));
    let (sent_c, lists_c) = (sent.clone(), lists.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let sent = sent_c.clone();
            let lists = lists_c.clone();
            let l = l.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let sent = sent.clone();
                        let lists = lists.clone();
                        let l = l.clone();
                        async move {
                            use http_body_util::BodyExt;
                            let (method, path) =
                                (req.method().clone(), req.uri().path().to_string());
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            if (method.as_str(), path.as_str()) == ("GET", "/fed/v2/sessions") {
                                lists.fetch_add(1, Ordering::SeqCst);
                            }
                            let (status, out) = match (method.as_str(), path.as_str()) {
                                ("GET", "/fed/v2/sessions") if l.denied => (
                                    403,
                                    json!({ "error": "denied", "detail": "list operation not allowed for peer" }),
                                ),
                                ("GET", "/fed/v2/sessions") => {
                                    tokio::time::sleep(l.delay).await;
                                    (200, Value::Array(l.entries.clone()))
                                }
                                ("POST", "/fed/v2/messages") => {
                                    let env: Value = serde_json::from_slice(&body).unwrap();
                                    let r = env["to"]["ref"].as_str().unwrap().to_string();
                                    let parked = r == H
                                        || l.entries
                                            .iter()
                                            .any(|e| e["id"] == r && e["status"] == "parked");
                                    sent.lock().unwrap().push(r.clone());
                                    (
                                        202,
                                        json!({
                                            "sessionId": r, "fromName": "ci", "bytes": 1,
                                            "messageId": env["id"],
                                            "outcome": if parked { "queued" } else { "delivered" },
                                        }),
                                    )
                                }
                                _ => (404, Value::Null),
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(bytes::Bytes::from(
                                        out.to_string(),
                                    )))
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
    (port, sent, lists)
}

/// One sending node and the nodes in its view: stubs, and unreachable entries.
struct View {
    sender: Node,
    sent: HashMap<String, Arc<Mutex<Vec<String>>>>,
    lists: HashMap<String, Arc<AtomicUsize>>,
    _ca: Ca,
}

/// Starts `sender` with a view of `stubs` (node name, listing) and `unreachable` nodes.
async fn view(sender: &str, stubs: Vec<(&str, Listing)>, unreachable: &[&str]) -> View {
    let ca = Ca::new();
    let creds = ca.issue(sender);
    let p = prepare(&ca);
    let mut peers = serde_json::Map::new();
    let mut sent = HashMap::new();
    let mut lists = HashMap::new();
    for (name, l) in stubs {
        let (port, s, n) = stub(&ca.issue(name), &[&creds.pin], l).await;
        peers.insert(name.to_string(), ca_entry(port, &p.ca_file(), name, ALL));
        sent.insert(name.to_string(), s);
        lists.insert(name.to_string(), n);
    }
    for name in unreachable {
        peers.insert(
            name.to_string(),
            ca_entry(get_free_port(), &p.ca_file(), name, ALL),
        );
    }
    let sender = start(p, &creds, Value::Object(peers), None).await;
    View {
        sender,
        sent,
        lists,
        _ca: ca,
    }
}

impl View {
    fn sent_to(&self, node: &str) -> Vec<String> {
        self.sent[node].lock().unwrap().clone()
    }
    fn lists_of(&self, node: &str) -> usize {
        self.lists[node].load(Ordering::SeqCst)
    }
    fn nothing_sent(&self) -> bool {
        self.sent.values().all(|s| s.lock().unwrap().is_empty())
    }
}

fn detail(body: &Value) -> String {
    body["detail"].as_str().unwrap_or_default().to_string()
}

// =============================================================================
// Oracle 1 (A8a). `sini.a` and `eve.b` both list X, and a bare X sent from a third user's
// node (`bob.c`) gives `ambiguous` with both addresses.
// Mutant: the first answer wins => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_two_users_listing_one_id_are_ambiguous() {
    run_with_port_retry(|| async {
        let v = view(
            "bob.c",
            vec![
                ("sini.a", listing(vec![inst(X, "live", "sini")])),
                ("eve.b", listing(vec![inst(X, "live", "eve")])),
            ],
            &[],
        )
        .await;
        let (status, body) = http_send(&v.sender, X, "to x").await;
        assert_eq!(status, 409, "{body}");
        assert_eq!(body["error"], "ambiguous", "{body}");
        let d = detail(&body);
        assert!(d.contains(&format!("{X}@sini.a")), "{body}");
        assert!(d.contains(&format!("{X}@eve.b")), "{body}");
        assert!(v.nothing_sent());
    })
    .await;
}

// =============================================================================
// Oracle 2 (no capture, D-6's input). Sent from `sini.c`: sini's H is unreachable, and
// eve's L lists X. No reachable sini node lists X, so A17 does not apply, and the result
// is `unavailable`, naming H.
// Mutant: resolve over the nodes that answered => RED (L captures the message).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_an_unreachable_own_node_is_not_captured() {
    run_with_port_retry(|| async {
        let v = view(
            "sini.c",
            vec![("eve.l", listing(vec![inst(X, "live", "eve")]))],
            &["sini.h"],
        )
        .await;
        let (status, body) = http_send(&v.sender, X, "to x").await;
        assert_eq!(status, 503, "{body}");
        assert_eq!(body["error"], "unavailable", "{body}");
        assert!(detail(&body).contains("sini.h"), "{body}");
        assert!(v.sent_to("eve.l").is_empty(), "L captured the send");
    })
    .await;
}

// =============================================================================
// Oracle 3 (D-7). Sent from `sini.c`: `foo` is on `sini.cortex` (reachable) and on
// `sini.bitstream` (unreachable), and the result is `unavailable`.
// Mutant: apply the user exception, or A17, to names => RED (delivered at `sini.cortex`).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_names_keep_the_full_view_rule() {
    run_with_port_retry(|| async {
        let v = view(
            "sini.c",
            vec![("sini.cortex", listing(vec![svc("foo", "sini")]))],
            &["sini.bitstream"],
        )
        .await;
        let (status, body) = http_send(&v.sender, "foo", "to foo").await;
        assert_eq!(status, 503, "{body}");
        assert_eq!(body["error"], "unavailable", "{body}");
        assert!(detail(&body).contains("sini.bitstream"), "{body}");
        assert!(v.nothing_sent());
    })
    .await;
}

// =============================================================================
// Oracle 4 (P-1). Sent from `bob.c`: X is live on `sini.a` while `sini.b` is unreachable,
// and the send is delivered to a.
// Mutant: no exception => RED (`unavailable`).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_an_unreachable_node_of_the_match_user_does_not_block() {
    run_with_port_retry(|| async {
        let v = view(
            "bob.c",
            vec![("sini.a", listing(vec![inst(X, "live", "sini")]))],
            &["sini.b"],
        )
        .await;
        let (status, body) = http_send(&v.sender, X, "to x").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["address"], format!("{X}@sini.a"), "{body}");
        assert_eq!(v.sent_to("sini.a"), vec![X.to_string()]);
    })
    .await;
}

// =============================================================================
// Oracle 5 (A11 across the mesh). Sent from `bob.c`: an instance labelled `genie-guard` on
// B and a service `genie-guard` on A. A bare `genie-guard` reaches the service.
// Mutant: consult labels mesh-wide first => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_services_first_across_the_mesh() {
    run_with_port_retry(|| async {
        let v = view(
            "bob.c",
            vec![
                ("sini.a", listing(vec![svc("genie-guard", "sini")])),
                ("eve.b", listing(vec![labelled(X, "genie-guard", "eve")])),
            ],
            &[],
        )
        .await;
        let (status, body) = http_send(&v.sender, "genie-guard", "to the guard").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["address"], "genie-guard@sini.a", "{body}");
        assert_eq!(v.sent_to("sini.a"), vec!["genie-guard".to_string()]);
        assert!(v.sent_to("eve.b").is_empty());
    })
    .await;
}

// =============================================================================
// Oracle 7 (A16). Sent from `bob.e`: X is parked on `sini.a` and live on `sini.b`, and a
// bare X is delivered at b.
// Mutant: treat it as two listings => RED (`ambiguous`).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_7_live_beats_parked() {
    run_with_port_retry(|| async {
        let v = view(
            "bob.e",
            vec![
                ("sini.a", listing(vec![inst(X, "parked", "sini")])),
                ("sini.b", listing(vec![inst(X, "live", "sini")])),
            ],
            &[],
        )
        .await;
        let (status, body) = http_send(&v.sender, X, "to x").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["address"], format!("{X}@sini.b"), "{body}");
        assert_eq!(body["outcome"], "delivered", "{body}");
        assert!(v.sent_to("sini.a").is_empty());
    })
    .await;
}

fn own_user_first_layout() -> Vec<(&'static str, Listing)> {
    vec![
        ("sini.a", listing(vec![inst(X, "live", "sini")])),
        ("eve.b", listing(vec![inst(X, "live", "eve")])),
    ]
}

// =============================================================================
// Oracle 8 (A17). Sent from `sini.c`: X is live on `sini.a`, `eve.b` also lists X, and
// `eve.d` is unreachable. The send is delivered at `sini.a`.
// Control in the same run: the same layout sent from `bob.e` gives `unavailable` naming
// `eve.d`.
// Mutant: no own-user precedence => RED (`unavailable`).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_8_own_user_first() {
    run_with_port_retry(|| async {
        let v = view("sini.c", own_user_first_layout(), &["eve.d"]).await;
        let (status, body) = http_send(&v.sender, X, "to x").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["address"], format!("{X}@sini.a"), "{body}");
        assert!(v.sent_to("eve.b").is_empty());

        let control = view("bob.e", own_user_first_layout(), &["eve.d"]).await;
        let (status, body) = http_send(&control.sender, X, "to x").await;
        assert_eq!(status, 503, "control: {body}");
        assert_eq!(body["error"], "unavailable", "{body}");
        assert!(detail(&body).contains("eve.d"), "{body}");
        assert!(control.nothing_sent());
    })
    .await;
}

// =============================================================================
// Oracle 9 (C6). Sent from `sini.c`: X is live on `sini.a` and on `sini.b`, `sini.b`
// answers after `sini.a` but within the list timeout, and `eve.d` is unreachable. The
// result is `ambiguous`, naming both sini addresses.
// Mutant: fall back to the full view when the own-user listings are not exactly one =>
// RED (`unavailable`).
// Mutant: deliver on the first own-user live answer without awaiting the rest => RED
// (delivered at a).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_9_two_own_user_live_listings_are_ambiguous() {
    run_with_port_retry(|| async {
        let mut late = listing(vec![inst(X, "live", "sini")]);
        late.delay = Duration::from_millis(1500);
        let v = view(
            "sini.c",
            vec![
                ("sini.a", listing(vec![inst(X, "live", "sini")])),
                ("sini.b", late),
            ],
            &["eve.d"],
        )
        .await;
        let (status, body) = http_send(&v.sender, X, "to x").await;
        assert_eq!(status, 409, "{body}");
        assert_eq!(body["error"], "ambiguous", "{body}");
        let d = detail(&body);
        assert!(d.contains(&format!("{X}@sini.a")), "{body}");
        assert!(d.contains(&format!("{X}@sini.b")), "{body}");
        assert!(v.nothing_sent());
    })
    .await;
}

fn parked_own_layout() -> Vec<(&'static str, Listing)> {
    vec![
        ("sini.a", listing(vec![inst(X, "parked", "sini")])),
        ("eve.b", listing(vec![inst(X, "live", "eve")])),
    ]
}

// =============================================================================
// Oracle 10 (A17 as extended). Sent from `sini.c`: X is parked on `sini.a` and live on
// `eve.b`, and every node is reachable. The send returns `queued` at `sini.a`.
// Control in the same run: the same layout sent from `bob.e` gives `ambiguous`.
// Mutant: A17 counts live listings only => RED (`ambiguous` under A8a).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_10_a_parked_own_user_listing_queues() {
    run_with_port_retry(|| async {
        let v = view("sini.c", parked_own_layout(), &[]).await;
        let (status, body) = http_send(&v.sender, X, "to x").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["outcome"], "queued", "{body}");
        assert_eq!(body["address"], format!("{X}@sini.a"), "{body}");
        assert!(v.sent_to("eve.b").is_empty());

        let control = view("bob.e", parked_own_layout(), &[]).await;
        let (status, body) = http_send(&control.sender, X, "to x").await;
        assert_eq!(status, 409, "control: {body}");
        assert_eq!(body["error"], "ambiguous", "{body}");
    })
    .await;
}

// =============================================================================
// Oracle 11 (D-6; C11). Sent from `sini.a`: its dial-out leaf L (`genie-guard.genie`) is
// disconnected, and `foo` is live on `sini.b`. A bare `foo` gives `unavailable`, naming L.
// Mutant: leave disconnected dial-out clients out of the view => RED (delivered at b).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_11_a_disconnected_dial_out_client_is_unreachable() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let creds = ca.issue("sini.a");
        let p = prepare(&ca);
        let (b_port, b_sent, _) = stub(
            &ca.issue("sini.b"),
            &[&creds.pin],
            listing(vec![svc("foo", "sini")]),
        )
        .await;
        let mut leaf = ca_entry_uri(
            get_free_port(),
            &p.ca_file(),
            "spiffe://xa6.test/ns/genie/sa/genie-guard",
            &["send", "reply", "inbox", "list"],
        );
        leaf["leaf"] = json!(true);
        let peers = json!({
            "sini.b": ca_entry(b_port, &p.ca_file(), "sini.b", ALL),
            "genie-guard.genie": leaf,
        });
        let a = start(p, &creds, peers, None).await;
        let (status, body) = http_send(&a, "foo", "to foo").await;
        assert_eq!(status, 503, "{body}");
        assert_eq!(body["error"], "unavailable", "{body}");
        assert!(detail(&body).contains("genie-guard.genie"), "{body}");
        assert!(b_sent.lock().unwrap().is_empty(), "delivered at b");
    })
    .await;
}

// =============================================================================
// Oracle 12 (C4). Sent from `sini.a`: B (`eve.b`) withholds `list` from a, and `foo` is
// live on `sini.c`. A bare `foo` gives `unavailable`, naming B.
// Mutant: resolve over the nodes that answered => RED (delivered at c).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_12_a_withheld_list_fails_closed() {
    run_with_port_retry(|| async {
        let mut withheld = listing(vec![]);
        withheld.denied = true;
        let v = view(
            "sini.a",
            vec![
                ("eve.b", withheld),
                ("sini.c", listing(vec![svc("foo", "sini")])),
            ],
            &[],
        )
        .await;
        let (status, body) = http_send(&v.sender, "foo", "to foo").await;
        assert_eq!(status, 503, "{body}");
        assert_eq!(body["error"], "unavailable", "{body}");
        assert!(detail(&body).contains("eve.b"), "{body}");
        assert!(v.sent_to("sini.c").is_empty(), "delivered at c");
    })
    .await;
}

// -----------------------------------------------------------------------------
// Real nodes: Claude fakes that can exit (A14's parked listing)
// -----------------------------------------------------------------------------

/// A live process to stand behind a Claude fake.
struct Sleeper(Child);

impl Sleeper {
    fn new() -> Sleeper {
        Sleeper(
            Command::new("sleep")
                .arg("600")
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn sleep"),
        )
    }
    fn end(mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A Claude fake presenting `id` on `node`, behind a live process, with an inbox: its file,
/// its process and every line delivered to it.
struct Claude {
    file: PathBuf,
    proc: Sleeper,
    lines: Arc<Mutex<Vec<String>>>,
    _dir: TempDir,
}

fn claude(node: &Node, id: &str, name: &str) -> Claude {
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
    let proc = Sleeper::new();
    let pid = proc.0.id();
    let start = xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    let session = json!({
        "pid": pid, "sessionId": id, "name": name, "cwd": "/w", "status": "idle",
        "kind": "interactive", "startedAt": 1, "updatedAt": 2, "procStart": start,
        "messagingSocketPath": sock.display().to_string(),
    });
    let file = node.sessions_dir.join(format!("{pid}-{id}.json"));
    fs::write(&file, session.to_string()).unwrap();
    Claude {
        file,
        proc,
        lines,
        _dir: dir,
    }
}

impl Claude {
    /// The conversation exits: its file goes, then its process.
    fn exit(self) {
        fs::remove_file(&self.file).unwrap();
        self.proc.end();
    }
    async fn got(&self, needle: &str) -> bool {
        for _ in 0..100 {
            if self
                .lines
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains(needle))
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

/// `list` on `node`, which observes its Claude fakes (A14).
async fn observe(node: &Node) -> Value {
    let url = format!(
        "http://127.0.0.1:{}/v1/recipients?status=inactive",
        node.http_port
    );
    reqwest::get(url).await.unwrap().json().await.unwrap()
}

// =============================================================================
// Oracle 6 (C9). Sent from `bob.c`: a bare X is delivered at `sini.a` and its location
// cached. X then exits on a (parked there) and registers on `sini.b`. The next bare X,
// routed by the cache, gets "not live here" from a, re-resolves, and is delivered at b.
// Second arm: X exits on b too, so every listing is parked, and the next send returns
// `queued`.
// Mutant: the old rule, under which a holds the cache-routed send as `queued` => RED (the
// message strands at a and b never receives it).
// Mutant: no re-resolution after "not live here" => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_the_cache_is_live_only() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (cc, ca_, cb) = (ca.issue("bob.c"), ca.issue("sini.a"), ca.issue("sini.b"));
        let (pc, pa, pb) = (prepare(&ca), prepare(&ca), prepare(&ca));
        let peers_c = json!({
            "sini.a": ca_entry(pa.fed_port, &pc.ca_file(), "sini.a", ALL),
            "sini.b": ca_entry(pb.fed_port, &pc.ca_file(), "sini.b", ALL),
        });
        let peers_a = json!({ "bob.c": ca_entry(pc.fed_port, &pa.ca_file(), "bob.c", ALL) });
        let peers_b = json!({ "bob.c": ca_entry(pc.fed_port, &pb.ca_file(), "bob.c", ALL) });
        let a = start(pa, &ca_, peers_a, None).await;
        let b = start(pb, &cb, peers_b, None).await;
        let c = start(pc, &cc, peers_c, None).await;

        let on_a = claude(&a, X, "x");
        let (status, body) = http_send(&c, X, "first").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["address"], format!("{X}@sini.a"), "{body}");
        assert!(on_a.got("first").await, "delivered at a");

        // X moves: it exits on a, which observes it parked, and registers on b.
        on_a.exit();
        let listed = observe(&a).await;
        assert!(
            listed["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["address"] == format!("{X}@sini.a") && r["status"] == "parked"),
            "X is parked on a: {listed}"
        );
        let on_b = claude(&b, X, "x");
        let (status, body) = http_send(&c, X, "second").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["address"], format!("{X}@sini.b"), "{body}");
        assert_eq!(body["outcome"], "delivered", "{body}");
        assert!(on_b.got("second").await, "delivered at b");

        // Second arm: X exits on b too; every listing is parked, so the send queues.
        on_b.exit();
        observe(&b).await;
        let (status, body) = http_send(&c, X, "third").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["outcome"], "queued", "{body}");
    })
    .await;
}

// =============================================================================
// Oracle 13 (A20). O → hub H → D, with H's entry for D `targets = ["genie-guard"]`. D has
// no service but an instance labelled `genie-guard`: a bare `genie-guard` forwarded
// through H is refused at D. Once D has the service, the same send is delivered to it.
// Mutant: D ignores the carried restriction => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_13_the_destination_enforces_the_forwarders_targets() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ch, cd, co) = (ca.issue("sini.h"), ca.issue("eve.d"), ca.issue("sini.o"));
        let (ph, pd) = (prepare(&ca), prepare(&ca));
        let mut d_entry = ca_entry(pd.fed_port, &ph.ca_file(), "eve.d", &["send", "reply"]);
        d_entry["targets"] = json!(["genie-guard"]);
        let peers_h = json!({
            "sini.o": ca_entry(get_free_port(), &ph.ca_file(), "sini.o", &["send", "forward"]),
            "eve.d": d_entry,
        });
        let peers_d = json!({
            "sini.h": ca_entry(ph.fed_port, &pd.ca_file(), "sini.h", &["send", "reply", "relayed"]),
        });
        let d = start(pd, &cd, peers_d, Some("genie-guard")).await;
        let h = start(ph, &ch, peers_h, None).await;
        let impostor = claude(&d, X, "genie-guard");
        observe(&d).await;
        let o = Origin {
            cert_der: &co.cert_der,
            key_der: &co.key_der,
        };

        let (status, res) =
            hop_client::hop_send(&o, &ch.pin, h.fed_port, "genie-guard@eve.d", "first").await;
        assert_eq!(
            status, 403,
            "a labelled instance is not the hub's target: {res}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !impostor.got("first").await,
            "nothing reached the labelled instance"
        );

        let stream = UnixStream::connect(&d.register_sock).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut r = BufReader::new(r);
        w.write_all(format!("{}\n", json!({ "harness": "svc", "name": "genie-guard" })).as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        r.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ok\""), "{line}");
        let (status, res) =
            hop_client::hop_send(&o, &ch.pin, h.fed_port, "genie-guard@eve.d", "second").await;
        assert_eq!(status, 202, "the service is the target: {res}");
        assert_eq!(res["sessionId"], "genie-guard", "{res}");
    })
    .await;
}

/// W answers the `list` query waiting in its mailbox on the node at `port`, listing X.
async fn answer_list_listing_x(w: &Origin<'_>, pin: &str, port: u16) {
    let (status, item) =
        hop_client::request(w, pin, port, "GET", "/fed/v2/inbox?wait=5", None).await;
    assert_eq!(status, 200, "{item}");
    assert_eq!(item["kind"], "list", "{item}");
    let uri = format!("/fed/v2/list/{}", item["query"].as_str().unwrap());
    let entries = json!({ "status": "ok", "entries": [inst(X, "live", "sini")] });
    let (status, res) = hop_client::request(w, pin, port, "POST", &uri, Some(entries)).await;
    assert_eq!(status, 200, "{res}");
}

/// A reply on `/fed/v2/replies` from `w` to the node at `port`: its HTTP status.
async fn fed_reply(
    w: &Origin<'_>,
    pin: &str,
    port: u16,
    id: &str,
    replier: Value,
    text: &str,
) -> u16 {
    let env = json!({
        "v": 2, "id": ulid::Ulid::new().to_string(), "in_reply_to": id,
        "replier": replier, "text": text, "created_at": 1000,
    });
    hop_client::request(w, pin, port, "POST", "/fed/v2/replies", Some(env))
        .await
        .0
}

// =============================================================================
// Oracle 14 (XA5's reply rule, carried in). A bare X sent from `sini.a` resolves over its
// dial-out client W, which lists X, and is queued for W as `X@sini.w`. The outbound record
// holds the resolved ID, so a reply from an instance merely labelled X is refused and one
// from X is taken; W's own `not_found` error reply from a service is still taken.
// Mutant: admit a replier by label on a resolved record => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_14_a_resolved_dial_out_send_takes_replies_from_the_id_only() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_w) = (ca.issue("sini.a"), ca.issue("sini.w"));
        let pa = prepare(&ca);
        let mut w_entry = ca_entry(
            get_free_port(),
            &pa.ca_file(),
            "sini.w",
            &["send", "reply", "inbox", "list"],
        );
        w_entry["leaf"] = json!(true);
        let a = Arc::new(start(pa, &ca_a, json!({ "sini.w": w_entry }), None).await);
        let w = Origin {
            cert_der: &ca_w.cert_der,
            key_der: &ca_w.key_der,
        };
        let (pin, port) = (ca_a.pin.as_str(), a.fed_port);

        let sender = a.clone();
        let sent = tokio::spawn(async move { http_send(&sender, X, "for x").await });
        answer_list_listing_x(&w, pin, port).await;
        let (status, sent) = sent.await.unwrap();
        assert_eq!(status, 202, "{sent}");
        assert_eq!(sent["outcome"], "queued", "{sent}");
        assert_eq!(sent["address"], format!("{X}@sini.w"), "{sent}");
        let id = sent["message_id"].as_str().unwrap().to_string();
        let impostor = json!({ "id": "other", "node": "x", "label": X });
        assert_eq!(fed_reply(&w, pin, port, &id, impostor, "forged").await, 403);
        let x = json!({ "id": X, "node": "x" });
        assert_eq!(fed_reply(&w, pin, port, &id, x, "from x").await, 200);

        let sender = a.clone();
        let sent = tokio::spawn(async move { http_send(&sender, X, "for x again").await });
        answer_list_listing_x(&w, pin, port).await;
        let (status, sent) = sent.await.unwrap();
        assert_eq!(status, 202, "{sent}");
        let id = sent["message_id"].as_str().unwrap().to_string();
        let err = json!({ "error": "not_found", "detail": "no live session matches" }).to_string();
        let system = json!({ "service": "system", "node": "x" });
        assert_eq!(fed_reply(&w, pin, port, &id, system, &err).await, 200);
    })
    .await;
}

// =============================================================================
// Oracle 15 (A11, A8a, D-7). A node listing an "instance" whose ID is the name-shaped
// `genie-guard` does not capture a bare `genie-guard`, which is a name and reaches the
// service on `sini.a`: over the full view (from `bob.c`), and under A17 when the listing
// node is the sender's own user's (from `eve.c`).
// Mutant: decide ID-vs-name by match, not by UUID shape => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_15_a_name_shaped_listed_id_does_not_capture_a_name() {
    run_with_port_retry(|| async {
        for sender in ["bob.c", "eve.c"] {
            let v = view(
                sender,
                vec![
                    ("sini.a", listing(vec![svc("genie-guard", "sini")])),
                    ("eve.b", listing(vec![inst("genie-guard", "live", "eve")])),
                ],
                &[],
            )
            .await;
            let (status, body) = http_send(&v.sender, "genie-guard", "to the service").await;
            assert_eq!(status, 202, "{sender}: {body}");
            assert_eq!(body["address"], "genie-guard@sini.a", "{sender}: {body}");
            assert!(
                v.sent_to("eve.b").is_empty(),
                "{sender}: eve.b captured a name"
            );
        }
    })
    .await;
}

/// The sender's cached location of `id`: (node, cached_at), read from its database.
fn cache_row(node: &Node, id: &str) -> Option<(String, i64)> {
    let conn = rusqlite::Connection::open(node.tmp.path().join("node.db")).unwrap();
    conn.query_row(
        "SELECT node, cached_at FROM location_cache WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .ok()
}

// =============================================================================
// Oracle 16 (A-12). Sent from `bob.c`: X is live on `sini.a`. The first bare X is resolved
// by a `list` fan-out and delivered; the second, within the TTL, is routed by the cache and
// asks no node.
// Mutant: no cache (`remember` a no-op) => RED (the second send fans out again).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_16_a_cached_location_routes_without_a_fan_out() {
    run_with_port_retry(|| async {
        let v = view(
            "bob.c",
            vec![("sini.a", listing(vec![inst(X, "live", "sini")]))],
            &[],
        )
        .await;
        for text in ["first", "second"] {
            let (status, body) = http_send(&v.sender, X, text).await;
            assert_eq!(status, 202, "{text}: {body}");
            assert_eq!(body["address"], format!("{X}@sini.a"), "{text}: {body}");
        }
        assert_eq!(v.sent_to("sini.a"), vec![X.to_string(), X.to_string()]);
        assert_eq!(v.lists_of("sini.a"), 1, "the second send asked for list");
    })
    .await;
}

// =============================================================================
// Oracle 17 (A-12, orchestrator default P1). A delivery the cache routed does not refresh
// the entry: its time stays that of the fresh resolution, so a location is at most the
// TTL old and a later second live listing surfaces as `ambiguous` within it.
// Mutant: refresh on every cached delivery => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_17_a_cached_delivery_does_not_refresh_the_entry() {
    run_with_port_retry(|| async {
        let v = view(
            "bob.c",
            vec![("sini.a", listing(vec![inst(X, "live", "sini")]))],
            &[],
        )
        .await;
        let (status, body) = http_send(&v.sender, X, "first").await;
        assert_eq!(status, 202, "{body}");
        let fresh = cache_row(&v.sender, X).expect("cached after a live delivery");
        assert_eq!(fresh.0, "sini.a");
        // The cache's clock is in seconds: the next delivery is in a later one.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let (status, body) = http_send(&v.sender, X, "second").await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(
            v.lists_of("sini.a"),
            1,
            "the second send was not cache-routed"
        );
        assert_eq!(
            cache_row(&v.sender, X),
            Some(fresh),
            "a cached delivery refreshed it"
        );
    })
    .await;
}

// =============================================================================
// Oracle 18 (A11, local). A node with the service `genie-guard` and a Claude conversation
// whose session ID is the name-shaped `genie-guard`: a bare `genie-guard` is a name and
// reaches the service, not the conversation.
// Mutant: try exact instance IDs before names whatever their shape => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_18_a_name_shaped_local_id_does_not_capture_a_name() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let creds = ca.issue("sini.a");
        let a = start(prepare(&ca), &creds, json!({}), Some("genie-guard")).await;
        let impostor = claude(&a, "genie-guard", "x");
        observe(&a).await;
        let stream = UnixStream::connect(&a.register_sock).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut r = BufReader::new(r);
        w.write_all(format!("{}\n", json!({ "harness": "svc", "name": "genie-guard" })).as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        r.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ok\""), "{line}");

        let (status, body) = http_send(&a, "genie-guard", "to the service").await;
        assert_eq!(status, 202, "{body}");
        assert!(
            !impostor.got("to the service").await,
            "the conversation captured a name: {body}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 19 (A-12, xh3-verify-v0 C3). H is listed live on `sini.a`, which answers `queued`:
// a pi or plugin session, whose message is `delivered` only once its harness acks it. The
// location is cached on the listing being live, not on the outcome, so the second bare H
// is routed by the cache and asks no node.
// Mutant: cache only on the outcome `delivered` => RED (the second send fans out again).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_19_a_live_session_awaiting_its_ack_is_cached() {
    run_with_port_retry(|| async {
        let v = view(
            "bob.c",
            vec![("sini.a", listing(vec![inst(H, "live", "sini")]))],
            &[],
        )
        .await;
        for text in ["first", "second"] {
            let (status, body) = http_send(&v.sender, H, text).await;
            assert_eq!(status, 202, "{text}: {body}");
            assert_eq!(body["outcome"], "queued", "{text}: {body}");
        }
        assert_eq!(
            cache_row(&v.sender, H).map(|r| r.0).as_deref(),
            Some("sini.a")
        );
        assert_eq!(v.lists_of("sini.a"), 1, "the second send asked for list");
    })
    .await;
}

// =============================================================================
// Oracle 20 (XA5's reply rule, after delivered-on-ack). A bare H sent from `sini.a`
// resolves over `sini.w`, which resolved it and holds it for its harness's ack: `queued`,
// though no dial-out mailbox holds it. Its recipient is known, so another service on
// `sini.w` answering `not_found` is refused, and H's own reply is taken.
// Mutant: admit the `not_found` reply on any `queued` record => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_20_a_peer_resolved_queued_send_takes_no_service_error() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_w) = (ca.issue("sini.a"), ca.issue("sini.w"));
        let pa = prepare(&ca);
        let (port_w, _, _) =
            stub(&ca_w, &[&ca_a.pin], listing(vec![inst(H, "live", "sini")])).await;
        let w_entry = ca_entry(port_w, &pa.ca_file(), "sini.w", ALL);
        let a = start(pa, &ca_a, json!({ "sini.w": w_entry }), None).await;
        let w = Origin {
            cert_der: &ca_w.cert_der,
            key_der: &ca_w.key_der,
        };
        let (pin, port) = (ca_a.pin.as_str(), a.fed_port);

        let (status, sent) = http_send(&a, H, "for h").await;
        assert_eq!(status, 202, "{sent}");
        assert_eq!(sent["outcome"], "queued", "{sent}");
        assert_eq!(sent["address"], format!("{H}@sini.w"), "{sent}");
        let id = sent["message_id"].as_str().unwrap().to_string();
        let err = json!({ "error": "not_found", "detail": "no live session matches" }).to_string();
        let other = json!({ "service": "other", "node": "x" });
        assert_eq!(fed_reply(&w, pin, port, &id, other, &err).await, 403);
        let h = json!({ "id": H, "node": "x" });
        assert_eq!(fed_reply(&w, pin, port, &id, h, "from h").await, 200);
    })
    .await;
}

// =============================================================================
// Oracle 21 (XA5's reply rule, after delivered-on-ack). `H@sini.w` names its node, so
// `sini.a` does not resolve it; `sini.w` resolves it and holds it for its harness's ack
// (`queued`), and the record holds H as `sini.w` reported it. No dial-out client resolves
// it later, so an instance on `sini.w` merely labelled H is refused, and H is taken.
// Mutant: admit by label on any unresolved `queued` record, mailbox or not => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_21_a_peer_resolved_queued_send_takes_no_label() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_w) = (ca.issue("sini.a"), ca.issue("sini.w"));
        let pa = prepare(&ca);
        let (port_w, _, _) =
            stub(&ca_w, &[&ca_a.pin], listing(vec![inst(H, "live", "sini")])).await;
        let w_entry = ca_entry(port_w, &pa.ca_file(), "sini.w", ALL);
        let a = start(pa, &ca_a, json!({ "sini.w": w_entry }), None).await;
        let w = Origin {
            cert_der: &ca_w.cert_der,
            key_der: &ca_w.key_der,
        };
        let (pin, port) = (ca_a.pin.as_str(), a.fed_port);

        let (status, sent) = http_send(&a, &format!("{H}@sini.w"), "for h").await;
        assert_eq!(status, 202, "{sent}");
        assert_eq!(sent["outcome"], "queued", "{sent}");
        assert_eq!(sent["address"], format!("{H}@sini.w"), "{sent}");
        let id = sent["message_id"].as_str().unwrap().to_string();
        let impostor = json!({ "id": "other", "node": "x", "label": H });
        assert_eq!(fed_reply(&w, pin, port, &id, impostor, "forged").await, 403);
        let h = json!({ "id": H, "node": "x" });
        assert_eq!(fed_reply(&w, pin, port, &id, h, "from h").await, 200);
    })
    .await;
}
