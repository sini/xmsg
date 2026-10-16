//! XL1 gate: `list` shows live recipients by default, and `status="inactive"` shows
//! parked and closed instances within a bounded window (`within`, default 24h, capped at
//! `reply_ttl`).
//!
//! Oracles:
//! - 1: Default `list` with one live and one parked instance returns only the live one.
//!   - Mutant: the status filter is dropped => RED.
//! - 2: Over federation, the same holds for a peer's entries (including an older peer that
//!   sends parked entries without `registered_at` or `last_seen`).
//!   - Mutant: the client-side status filter on federated entries is dropped, so an older
//!     peer's parked entry leaks into the default list => RED.
//! - 2b: Older peers in an inactive query: an old peer's parked entries carry no `last_seen`,
//!   so they cannot be windowed and are excluded from `status: "inactive"` results.
//! - 3: `registered_at` is present and correct: it's the registration time, not the list time.
//! - 4: The inactive query returns the parked instance with `last_seen`. An inactive entry
//!   older than the window is excluded by default and included when the window is widened.
//!   - Mutant: no default window => RED.
//! - 4b: `instance_seen` growth: a row older than the cap (`reply_ttl`) is pruned on sync.
//! - 5: `send` to a parked instance by its ID still queues exactly as before.

mod short_sock;

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use xmsg::fed::{normalize_pin, spki_sha256_from_der, PeerConfig, PeersMap};
use xmsg::storage;

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");

const ID_LIVE: &str = "11111111-1111-4111-8111-111111111111";
const ID_PARKED: &str = "22222222-2222-4222-8222-222222222222";
const ID_OLD_PARKED: &str = "33333333-3333-4333-8333-333333333333";
const ID_EXPIRED_SEEN: &str = "44444444-4444-4444-8444-444444444444";

const URI_A: &str = "spiffe://xl1.test/host/a/user/sini";
const URI_B: &str = "spiffe://xl1.test/host/b/user/eve";
const URI_OLD: &str = "spiffe://xl1.test/host/old/user/eve";

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
    fn pid(&self) -> u32 {
        self.0.id()
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

struct Inbox {
    _dir: TempDir,
    sock: PathBuf,
}

fn inbox() -> Inbox {
    let dir = tempdir().unwrap();
    let sock = short_sock::sock_path(dir.path(), "in");
    let listener = UnixListener::bind(&sock).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf).await;
        }
    });
    Inbox {
        _dir: dir,
        sock,
    }
}

fn write_claude_session(sessions_dir: &Path, pid: u32, session_id: &str, name: &str, sock: &Path) {
    let proc_start =
        xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    let entry = json!({
        "pid": pid,
        "sessionId": session_id,
        "name": name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": proc_start,
        "messagingSocketPath": sock.display().to_string(),
    });
    fs::write(
        sessions_dir.join(format!("{pid}-{session_id}.json")),
        entry.to_string(),
    )
    .unwrap();
}

fn remove_claude_session(sessions_dir: &Path, pid: u32, session_id: &str) {
    let _ = fs::remove_file(sessions_dir.join(format!("{pid}-{session_id}.json")));
}

struct ChildGuard(Option<tokio::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.start_kill();
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
            .push(rcgen::DnType::CommonName, "xl1 test CA");
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

struct Node {
    tmp: TempDir,
    http_port: u16,
    #[allow(dead_code)]
    fed_port: u16,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    http_sock: PathBuf,
    sessions_dir: PathBuf,
    db_path: PathBuf,
    _child: ChildGuard,
}

async fn start_node(p: Prepared, creds: &Creds, peers: Value) -> Node {
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
    let http_sock = run_dir.join("http.sock");
    let db_path = tmp.path().join("node.db");
    let cert = tmp.path().join("cert.pem");
    let key = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");
    fs::write(&cert, &creds.cert).unwrap();
    fs::write(&key, &creds.key).unwrap();
    fs::write(&peers_file, peers.to_string()).unwrap();

    let args: Vec<String> = vec![
        "serve".into(),
        "--listen".into(),
        format!("127.0.0.1:{http_port}"),
        "--db-path".into(),
        db_path.display().to_string(),
        "--sessions-dir".into(),
        sessions_dir.display().to_string(),
        "--register-sock".into(),
        register_sock.display().to_string(),
        "--agent-sock".into(),
        agent_sock.display().to_string(),
        "--http-sock".into(),
        http_sock.display().to_string(),
        "--fed-cert".into(),
        cert.display().to_string(),
        "--fed-key".into(),
        key.display().to_string(),
        "--peers-file".into(),
        peers_file.display().to_string(),
        "--fed-listen".into(),
        format!("127.0.0.1:{fed_port}"),
    ];

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
            && http_sock.exists()
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
                agent_sock,
                register_sock,
                http_sock,
                sessions_dir,
                db_path,
                _child: ChildGuard(Some(child)),
            };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.start_kill();
    panic!("xmsg serve did not start within 30s");
}

impl Node {
    async fn http_get(&self, path: &str) -> (u16, Value) {
        let url = format!("http://127.0.0.1:{}{path}", self.http_port);
        let resp = reqwest::get(url).await.unwrap();
        let status = resp.status().as_u16();
        let body = resp.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn http_send(&self, to: &str, text: &str) -> (u16, Value) {
        let url = format!("http://127.0.0.1:{}/v1/messages", self.http_port);
        let resp = reqwest::Client::new()
            .post(url)
            .json(&json!({ "to": to, "from": "ci", "text": text }))
            .send()
            .await
            .unwrap();
        (
            resp.status().as_u16(),
            resp.json().await.unwrap_or(Value::Null),
        )
    }

    async fn agent_call(&self, frame: Value) -> Value {
        let stream = UnixStream::connect(&self.agent_sock).await.unwrap();
        let (r, mut w) = stream.into_split();
        w.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        BufReader::new(r).read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
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

async fn stub_older_peer(creds: &Creds, client_pin: &str, entries: Value) -> u16 {
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
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let entries = entries.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let entries = entries.clone();
                        async move {
                            let (status, body) = match (req.method().as_str(), req.uri().path()) {
                                ("GET", "/fed/v2/sessions") => (200, entries.to_string()),
                                _ => (404, String::new()),
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(bytes::Bytes::from(body)))
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
    port
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

// =============================================================================
// Oracle 1, 3, 5:
// - Oracle 1: Default `list` with one live and one parked instance returns only
//   the live one (across HTTP, agent.sock, register.sock plugin, and MCP).
//   Mutant: the status filter is dropped => RED.
// - Oracle 3: `registered_at` is present and is the registration time, not the
//   list time.
// - Oracle 5: `send` to a parked instance by its ID still queues as before.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_3_5_local_default_list_registered_at_and_parked_send() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let ca_a = ca.issue(URI_A);
        let pa = prepare(&ca);
        let a = start_node(pa, &ca_a, json!({})).await;

        // 1. Start live session ID_LIVE and future-parked session ID_PARKED
        let s_live = Sleeper::new();
        let in_live = inbox();
        let s_parked = Sleeper::new();
        let in_parked = inbox();

        let t_before_reg = storage::now_epoch_secs();
        write_claude_session(&a.sessions_dir, s_live.pid(), ID_LIVE, "live-agent", &in_live.sock);
        write_claude_session(
            &a.sessions_dir,
            s_parked.pid(),
            ID_PARKED,
            "parked-agent",
            &in_parked.sock,
        );

        // Observe both so their claims are recorded at t_reg
        let (st, initial) = a.http_get("/v1/recipients").await;
        let t_after_reg = storage::now_epoch_secs();
        assert_eq!(st, 200, "{initial}");
        assert_eq!(initial["recipients"].as_array().unwrap().len(), 2, "{initial}");

        // Wait 2 seconds so list time is strictly greater than registration time (Oracle 3)
        tokio::time::sleep(Duration::from_millis(2100)).await;

        // Exit ID_PARKED so it transitions to parked
        remove_claude_session(&a.sessions_dir, s_parked.pid(), ID_PARKED);
        s_parked.end();

        let t_list = storage::now_epoch_secs();
        assert!(t_list > t_after_reg, "clock advanced past registration window");

        // Oracle 1: Default `list` over HTTP returns ONLY the live instance
        let (st, listed) = a.http_get("/v1/recipients").await;
        assert_eq!(st, 200, "{listed}");
        let recs = listed["recipients"].as_array().unwrap();
        assert_eq!(
            recs.len(),
            1,
            "Default list must return only the 1 live instance, excluding the parked one: {listed}"
        );
        let live_rec = &recs[0];
        assert_eq!(live_rec["address"], format!("{ID_LIVE}@sini.a"));
        assert_eq!(live_rec["status"], "live");

        // Oracle 3: `registered_at` is registration time, not list time
        let reg_at = live_rec["registered_at"]
            .as_i64()
            .expect("registered_at must be present on live entry");
        assert!(
            reg_at >= t_before_reg && reg_at <= t_after_reg,
            "registered_at ({reg_at}) must fall in [{t_before_reg}, {t_after_reg}]"
        );
        assert!(
            reg_at < t_list,
            "registered_at ({reg_at}) must be registration time, strictly before list time ({t_list})"
        );
        assert!(
            live_rec.get("last_seen").is_none(),
            "live entry must not carry last_seen: {live_rec}"
        );

        // Check `agent.sock` parity
        let agent_listed = a.agent_call(json!({ "action": "list" })).await;
        assert_eq!(agent_listed["status"], "ok", "{agent_listed}");
        assert_eq!(agent_listed["recipients"].as_array().unwrap().len(), 1);
        assert_eq!(
            agent_listed["recipients"][0]["address"],
            format!("{ID_LIVE}@sini.a")
        );

        // Check `register.sock` (opencode/hermes plugin) parity
        let p_stream = UnixStream::connect(&a.register_sock).await.unwrap();
        let (pr, mut pw) = p_stream.into_split();
        let mut pr = BufReader::new(pr);
        pw.write_all(b"{\"harness\":\"opencode\"}\n").await.unwrap();
        let mut pline = String::new();
        pr.read_line(&mut pline).await.unwrap();
        pline.clear();
        pw.write_all(b"{\"action\":\"register\",\"request_id\":\"r1\",\"session\":\"s1\"}\n")
            .await
            .unwrap();
        pr.read_line(&mut pline).await.unwrap();
        let preg: Value = serde_json::from_str(&pline).unwrap();
        assert_eq!(preg["status"], "ok", "{preg}");
        pline.clear();
        pw.write_all(b"{\"action\":\"list\",\"request_id\":\"r2\",\"session\":\"s1\"}\n")
            .await
            .unwrap();
        pr.read_line(&mut pline).await.unwrap();
        let plist: Value = serde_json::from_str(&pline).unwrap();
        assert_eq!(plist["status"], "ok", "{plist}");
        let precs = plist["recipients"].as_array().unwrap();
        assert!(
            precs.iter().all(|r| r["status"] == "live"),
            "plugin list must contain only live entries: {plist}"
        );
        assert!(
            !precs.iter().any(|r| r["address"] == format!("{ID_PARKED}@sini.a")),
            "plugin list must not contain parked instance: {plist}"
        );
        drop(pw);
        drop(pr);

        // Check MCP `execute_tool("list", ...)` parity
        let mcp_cfg = xmsg::mcp::McpConfig {
            sessions_dirs: vec![a.sessions_dir.clone()],
            xmsg_url: format!("http://127.0.0.1:{}", a.http_port),
            http_sock: Some(a.http_sock.clone()),
            agent_sock: a.agent_sock.clone(),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            presence_dir: a.tmp.path().join("presence"),
            proc_locks_path: a.tmp.path().join("locks"),
            reply_only: false,
        };
        let mcp_res = tokio::task::spawn_blocking(move || {
            let client = reqwest::blocking::Client::new();
            xmsg::mcp::execute_tool(&mcp_cfg, &client, "list", &json!({}))
        })
        .await
        .unwrap();
        assert_eq!(mcp_res["isError"], false, "{mcp_res}");
        let mcp_val: Value =
            serde_json::from_str(mcp_res["content"][0]["text"].as_str().unwrap()).unwrap();
        assert!(
            !mcp_val["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["address"] == format!("{ID_PARKED}@sini.a")),
            "MCP default list must not include parked instance: {mcp_val}"
        );

        // Oracle 5: `send` to the parked instance by its ID still queues as before
        let (send_st, send_body) = a.http_send(ID_PARKED, "for parked").await;
        assert_eq!(send_st, 202, "{send_body}");
        assert_eq!(send_body["outcome"], "queued", "{send_body}");
        assert_eq!(send_body["address"], format!("{ID_PARKED}@sini.a"), "{send_body}");
    })
    .await;
}

// =============================================================================
// Oracle 2 & 2b:
// - Oracle 2: Over federation, default `list` returns only live entries from
//   both an XL1 peer and an older peer (which sends a `"parked"` entry on the
//   wire).
//   Mutant: the client-side status filter on federated entries is dropped, so
//   an older peer's parked entry leaks into the default list => RED.
// - Oracle 2b: Older peers in an inactive query: an old peer's parked entries
//   carry no `last_seen`, so they cannot be windowed and are excluded from
//   `status: "inactive"` results, while the XL1 peer's parked entry (with
//   `last_seen`) is included.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_and_2b_federated_live_default_and_older_peer_compat() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let (ca_a, ca_b, ca_old) = (ca.issue(URI_A), ca.issue(URI_B), ca.issue(URI_OLD));
        let (pa, pb) = (prepare(&ca), prepare(&ca));

        // Stub an older pre-XL1 peer (`eve.old`) that returns one live and one parked entry,
        // neither carrying `registered_at` or `last_seen`.
        let old_wire_entries = json!([
            {
                "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "kind": "instance",
                "label": "old-live",
                "status": "live",
                "user": "eve"
            },
            {
                "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "kind": "instance",
                "status": "parked",
                "user": "eve"
            }
        ]);
        let old_port = stub_older_peer(&ca_old, &ca_a.pin, old_wire_entries).await;

        let peers_a = json!({
            "eve.b": ca_entry(pb.fed_port, &pa.ca_file(), URI_B, &["send", "reply", "list"]),
            "eve.old": ca_entry(old_port, &pa.ca_file(), URI_OLD, &["send", "reply", "list"]),
        });
        let peers_b = json!({
            "sini.a": ca_entry(pa.fed_port, &pb.ca_file(), URI_A, &["send", "reply", "list"]),
        });

        let b = start_node(pb, &ca_b, peers_b).await;
        let a = start_node(pa, &ca_a, peers_a).await;

        // On B (an XL1 peer), create one live instance and one parked instance
        let s_b_live = Sleeper::new();
        let in_b_live = inbox();
        let s_b_parked = Sleeper::new();
        let in_b_parked = inbox();
        write_claude_session(&b.sessions_dir, s_b_live.pid(), ID_LIVE, "b-live", &in_b_live.sock);
        write_claude_session(
            &b.sessions_dir,
            s_b_parked.pid(),
            ID_PARKED,
            "b-parked",
            &in_b_parked.sock,
        );
        b.http_get("/v1/recipients").await;
        remove_claude_session(&b.sessions_dir, s_b_parked.pid(), ID_PARKED);
        s_b_parked.end();
        // Trigger sync on B so ID_PARKED is released into instance_seen with last_live
        b.http_get("/v1/recipients").await;

        // Oracle 2: Default `list` on A across the mesh returns ONLY live entries from B and old
        let (st, default_list) = a.http_get("/v1/recipients").await;
        assert_eq!(st, 200, "{default_list}");
        let addrs: Vec<String> = default_list["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["address"].as_str().unwrap().to_string())
            .collect();
        assert!(
            addrs.contains(&format!("{ID_LIVE}@eve.b")),
            "B's live entry must be listed: {default_list}"
        );
        assert!(
            addrs.contains(&"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@eve.old".to_string()),
            "older peer's live entry must be listed: {default_list}"
        );
        assert!(
            !addrs.contains(&format!("{ID_PARKED}@eve.b")),
            "B's parked entry must NOT be in default list: {default_list}"
        );
        assert!(
            !addrs.contains(&"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb@eve.old".to_string()),
            "older peer's parked entry must be filtered out on the client side: {default_list}"
        );

        // Oracle 2b: Inactive query (`status=inactive`) on A includes B's parked entry (with `last_seen`)
        // and excludes `eve.old`'s parked entry (which has no `last_seen`).
        let (st, inactive_list) = a.http_get("/v1/recipients?status=inactive").await;
        assert_eq!(st, 200, "{inactive_list}");
        let inactive_recs = inactive_list["recipients"].as_array().unwrap();
        let inactive_addrs: Vec<String> = inactive_recs
            .iter()
            .map(|r| r["address"].as_str().unwrap().to_string())
            .collect();
        assert!(
            inactive_addrs.contains(&format!("{ID_PARKED}@eve.b")),
            "B's parked entry must be in status=inactive list: {inactive_list}"
        );
        let b_parked_rec = inactive_recs
            .iter()
            .find(|r| r["address"] == format!("{ID_PARKED}@eve.b"))
            .unwrap();
        assert!(
            b_parked_rec["last_seen"].as_i64().is_some(),
            "B's parked entry must carry last_seen: {b_parked_rec}"
        );
        assert!(
            !inactive_addrs.contains(&"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb@eve.old".to_string()),
            "older peer's parked entry without last_seen must be excluded from status=inactive: {inactive_list}"
        );
        assert!(
            !inactive_addrs.contains(&format!("{ID_LIVE}@eve.b")),
            "live entries must not appear in status=inactive: {inactive_list}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 4 & 4b:
// - Oracle 4: The inactive query returns the parked instance with `last_seen`.
//   An inactive entry older than the default 24h window (`within` omitted) is
//   excluded by default and included when `within` is widened.
//   Mutant: no default window => RED.
// - Oracle 4b: `instance_seen` growth: a row whose `last_live` is older than
//   the cap (`reply_ttl`, 7 days) is pruned on sync.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_and_4b_inactive_window_and_instance_seen_pruning() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let ca_a = ca.issue(URI_A);
        let pa = prepare(&ca);
        let a = start_node(pa, &ca_a, json!({})).await;

        let now = storage::now_epoch_secs();
        let seen_1h_ago = now - 3_600; // 1h ago (inside default 24h window)
        let seen_48h_ago = now - 172_800; // 48h ago (outside 24h window, inside 7d reply_ttl)
        let seen_8d_ago = now - 8 * 86_400; // 8d ago (older than 7d reply_ttl cap)

        {
            let conn = rusqlite::Connection::open(&a.db_path).unwrap();
            storage::mark_live(&conn, ID_PARKED, "claude", seen_1h_ago).unwrap();
            storage::mark_live(&conn, ID_OLD_PARKED, "claude", seen_48h_ago).unwrap();
            storage::mark_live(&conn, ID_EXPIRED_SEEN, "claude", seen_8d_ago).unwrap();
        }

        // 1. Default inactive query (`status=inactive`, no `within` -> defaults to 24h = 86400s):
        //    - returns ID_PARKED (1h ago) with `last_seen == seen_1h_ago`
        //    - excludes ID_OLD_PARKED (48h ago)
        //    - prunes ID_EXPIRED_SEEN (8d ago) during sync
        let (st, res_default) = a.http_get("/v1/recipients?status=inactive").await;
        assert_eq!(st, 200, "{res_default}");
        let recs = res_default["recipients"].as_array().unwrap();
        assert_eq!(
            recs.len(),
            1,
            "Default 24h inactive window must include only the 1h-old entry and exclude the 48h-old entry: {res_default}"
        );
        assert_eq!(recs[0]["address"], format!("{ID_PARKED}@sini.a"));
        assert_eq!(recs[0]["status"], "parked");
        assert_eq!(recs[0]["last_seen"].as_i64(), Some(seen_1h_ago));
        assert!(recs[0].get("registered_at").is_none());

        // 2. Widened window (`status=inactive&within=259200` = 72h):
        //    - includes both ID_PARKED (1h ago) and ID_OLD_PARKED (48h ago)
        //    - still excludes ID_EXPIRED_SEEN (8d ago, pruned)
        let (st, res_wide) = a
            .http_get("/v1/recipients?status=inactive&within=259200")
            .await;
        assert_eq!(st, 200, "{res_wide}");
        let wide_recs = res_wide["recipients"].as_array().unwrap();
        let wide_addrs: Vec<String> = wide_recs
            .iter()
            .map(|r| r["address"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            wide_addrs,
            vec![
                format!("{ID_PARKED}@sini.a"),
                format!("{ID_OLD_PARKED}@sini.a"),
            ],
            "Widened 72h window must return both 1h and 48h parked instances: {res_wide}"
        );

        // 3. Oracle 4b: Verify ID_EXPIRED_SEEN row is gone from `instance_seen` in SQLite after sync
        {
            let conn = rusqlite::Connection::open(&a.db_path).unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM instance_seen WHERE id = ?1",
                    [ID_EXPIRED_SEEN],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 0,
                "instance_seen row older than reply_ttl cap must be pruned after sync"
            );
        }
    })
    .await;
}
