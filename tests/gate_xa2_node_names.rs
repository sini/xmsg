//! XA2 gate: node names (A9, B5, A-8, AM-5, AM-6, D4, D9, D10; plan gate v0 C3, C8).
//!
//! Every oracle runs the real `xmsg serve` (or `xmsg check-peers`) binary. Node names are
//! never assigned here: CA nodes hold CA-issued leaves with SPIFFE URI SANs, pinned nodes
//! hold self-signed keys, and each node's name is whatever xmsg derives from those.
mod short_sock;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use xmsg::fed::{
    generate_self_signed_ed25519, generate_self_signed_ed25519_pem, normalize_pin,
    spki_sha256_from_der,
};
use xmsg::node::node_name_from_pin;

mod hop_client;
use hop_client::{hop_send, Origin};

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");

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

impl Ca {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "xa2 test CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }

    /// A leaf for `uri`: (cert PEM, key PEM, pin).
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
        }
    }
}

#[derive(Clone)]
struct Creds {
    cert: String,
    key: String,
    pin: String,
}

fn pinned_creds(cn: &str) -> Creds {
    let (cert, key, pin) = generate_self_signed_ed25519_pem(cn).unwrap();
    Creds { cert, key, pin }
}

#[derive(Default)]
struct NodeSpec {
    creds: Option<Creds>,
    /// The peers file, verbatim (so a test can write duplicate keys).
    peers: Option<String>,
    /// Bind the federation listener.
    fed: bool,
    svc_exe: Option<String>,
    extra_args: Vec<String>,
    extra_env: Vec<(String, String)>,
}

#[allow(dead_code)]
struct Node {
    tmp: TempDir,
    http_port: u16,
    fed_port: u16,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    sessions_dir: PathBuf,
    ca_file: PathBuf,
    child: ChildGuard,
}

/// Writes a node's files. The CA file is written by the caller at `ca_file` when needed.
fn node_dir() -> (TempDir, PathBuf) {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let ca_file = tmp.path().join("ca.pem");
    (tmp, ca_file)
}

/// Spawns `xmsg serve`. `Ok` once it serves; `Err(stderr)` if it exits first.
async fn spawn_node(spec: NodeSpec, prepared: Option<(TempDir, PathBuf)>) -> Result<Node, String> {
    let (tmp, ca_file) = prepared.unwrap_or_else(node_dir);
    let run_dir = tmp.path().join("run");
    let sessions_dir = tmp.path().join("sessions");
    for d in [&run_dir, &sessions_dir] {
        fs::create_dir_all(d).unwrap();
        fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_port = get_free_port();
    let fed_port = get_free_port();

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
        "--agent-sock".into(),
        agent_sock.display().to_string(),
        "--http-sock".into(),
        run_dir.join("http.sock").display().to_string(),
    ];
    if let Some(creds) = &spec.creds {
        let cert = tmp.path().join("cert.pem");
        let key = tmp.path().join("key.pem");
        fs::write(&cert, &creds.cert).unwrap();
        fs::write(&key, &creds.key).unwrap();
        args.extend([
            "--fed-cert".into(),
            cert.display().to_string(),
            "--fed-key".into(),
            key.display().to_string(),
        ]);
    }
    if let Some(peers) = &spec.peers {
        let f = tmp.path().join("peers.json");
        fs::write(&f, peers).unwrap();
        args.extend(["--peers-file".into(), f.display().to_string()]);
    }
    if spec.fed {
        args.extend(["--fed-listen".into(), format!("127.0.0.1:{fed_port}")]);
    }
    if let Some(svc) = &spec.svc_exe {
        args.extend(["--svc-exe".into(), svc.clone()]);
    }
    args.extend(spec.extra_args.iter().cloned());

    let mut cmd = tokio::process::Command::new(BIN);
    cmd.env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "warn")
        .env_remove("XMSG_HOST_LABEL")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in &spec.extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn xmsg serve");

    for _ in 0..600 {
        if let Ok(Some(_)) = child.try_wait() {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut err).await;
            }
            return Err(err);
        }
        let http_up = tokio::net::TcpStream::connect(("127.0.0.1", http_port))
            .await
            .is_ok();
        let fed_up = !spec.fed
            || tokio::net::TcpStream::connect(("127.0.0.1", fed_port))
                .await
                .is_ok();
        if agent_sock.exists() && register_sock.exists() && http_up && fed_up {
            return Ok(Node {
                tmp,
                http_port,
                fed_port,
                agent_sock,
                register_sock,
                sessions_dir,
                ca_file,
                child: ChildGuard(Some(child)),
            });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.start_kill();
    panic!("xmsg serve neither served nor exited within 30s: {args:?}");
}

/// A node that must start; a lost port race panics with a message the retry wrapper reads.
async fn start(spec: NodeSpec, prepared: Option<(TempDir, PathBuf)>) -> Node {
    match spawn_node(spec, prepared).await {
        Ok(n) => n,
        Err(stderr) => panic!("node exited at start (failed to bind?): {stderr}"),
    }
}

/// The stderr of a node that refused to start; empty if it started (and it is stopped).
async fn refused(spec: NodeSpec) -> String {
    spawn_node(spec, None).await.err().unwrap_or_default()
}

impl Node {
    /// Stops the node and returns everything it logged (tracing writes to stdout).
    async fn stop_and_log(mut self) -> String {
        let mut child = self.child.0.take().unwrap();
        let _ = child.start_kill();
        let _ = child.wait().await;
        let mut log = String::new();
        if let Some(mut o) = child.stdout.take() {
            let _ = o.read_to_string(&mut log).await;
        }
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut log).await;
        }
        log
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

fn ca_entry(address: &str, ca_file: &Path, uri: &str, allow: &[&str]) -> Value {
    json!({ "address": address, "ca": ca_file.display().to_string(), "identities": [uri], "allow": allow })
}

fn pin_entry(address: &str, pin: &str, allow: &[&str]) -> Value {
    json!({ "address": address, "pin": normalize_pin(pin), "allow": allow })
}

fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
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

async fn wait_line(rx: &Arc<Mutex<Vec<String>>>) -> Option<String> {
    for _ in 0..100 {
        if let Some(l) = rx.lock().unwrap().first() {
            return Some(l.clone());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// An anonymous HTTP send from `ci`, over the node's TCP listener: (status, body).
async fn http_send(node: &Node, r: &str, text: &str) -> (u16, String) {
    let url = format!("http://127.0.0.1:{}/v1/messages", node.http_port);
    let resp = reqwest::Client::new()
        .post(url)
        .json(&json!({ "to": r, "from": "ci", "text": text }))
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

/// A service registered on `register.sock` (the test executable is its trusted exe).
async fn register_svc(node: &Node, name: &str) -> (BufReader<OwnedReadHalf>, OwnedWriteHalf) {
    let stream = UnixStream::connect(&node.register_sock).await.unwrap();
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

fn svc_exe(name: &str) -> String {
    format!("{name}={}", std::env::current_exe().unwrap().display())
}

/// `xmsg check-peers` (D9): (exit success, stdout + stderr).
fn check_peers(peers: &str, cert: Option<&str>) -> (bool, String) {
    let dir = tempdir().unwrap();
    let f = dir.path().join("peers.json");
    fs::write(&f, peers).unwrap();
    let mut cmd = std::process::Command::new(BIN);
    cmd.arg("check-peers").arg(&f);
    if let Some(cert) = cert {
        let c = dir.path().join("cert.pem");
        fs::write(&c, cert).unwrap();
        cmd.arg("--fed-cert").arg(&c);
    }
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

const SINI_BITSTREAM: &str = "spiffe://json64.dev/host/bitstream/user/sini";
const SINI_CORTEX: &str = "spiffe://json64.dev/host/cortex/user/sini";
const GENIE_GUARD_POD: &str = "spiffe://json64.dev/ns/genie/sa/genie-guard";
const GENIE_HOST_GENIE_GUARD_USER: &str = "spiffe://json64.dev/host/genie/user/genie-guard";

// =============================================================================
// Oracle 1: CA names. Nodes holding certificates for host/bitstream/user/sini and
// ns/genie/sa/genie-guard show up in received origins as sini.bitstream and
// genie-guard.genie.
// Mutant M1: name a host identity by its host part only (H5's old rule) => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_ca_names_in_received_origins() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let r_creds = ca.issue(SINI_CORTEX);
        let s1_creds = ca.issue(SINI_BITSTREAM);
        let s2_creds = ca.issue(GENIE_GUARD_POD);

        let r_dir = node_dir();
        fs::write(&r_dir.1, &ca.pem).unwrap();
        let s1_dir = node_dir();
        fs::write(&s1_dir.1, &ca.pem).unwrap();
        let s2_dir = node_dir();
        fs::write(&s2_dir.1, &ca.pem).unwrap();

        // The receiver's peers file is checked first against its own certificate.
        let s1_fed = get_free_port();
        let s2_fed = get_free_port();
        let r_peers = json!({
            "sini.bitstream": ca_entry(&addr(s1_fed), &r_dir.1, SINI_BITSTREAM, &["send", "reply"]),
            "genie-guard.genie": ca_entry(&addr(s2_fed), &r_dir.1, GENIE_GUARD_POD, &["send", "reply"]),
        })
        .to_string();
        let (ok, out) = check_peers(&r_peers, Some(&r_creds.cert));
        assert!(
            ok && out.contains("loads for node sini.cortex"),
            "the receiver's peers file must load for node sini.cortex: {out}"
        );

        let r = start(
            NodeSpec {
                creds: Some(r_creds),
                peers: Some(r_peers),
                fed: true,
                svc_exe: Some(svc_exe("fed-worker")),
                ..Default::default()
            },
            Some(r_dir),
        )
        .await;
        let to_r = |dir: &Path| {
            json!({ "sini.cortex": ca_entry(&addr(r.fed_port), dir, SINI_CORTEX, &["send", "reply"]) })
                .to_string()
        };
        let s1 = start(
            NodeSpec {
                creds: Some(s1_creds),
                peers: Some(to_r(&s1_dir.1)),
                ..Default::default()
            },
            Some(s1_dir),
        )
        .await;
        let s2 = start(
            NodeSpec {
                creds: Some(s2_creds),
                peers: Some(to_r(&s2_dir.1)),
                ..Default::default()
            },
            Some(s2_dir),
        )
        .await;

        let (mut sr, mut sw) = register_svc(&r, "fed-worker").await;
        for (s, text) in [(&s1, "from bitstream"), (&s2, "from the pod")] {
            let (status, body) = http_send(s, "fed-worker@sini.cortex", text).await;
            assert_eq!(status, 202, "send to sini.cortex: {body}");
        }
        let mut origins = Vec::new();
        for _ in 0..2 {
            let d = svc_poll(&mut sr, &mut sw).await;
            assert_eq!(d["action"], "deliver", "{d}");
            origins.push((
                d["text"].as_str().unwrap().to_string(),
                d["origin"]["node"].as_str().unwrap_or_default().to_string(),
            ));
        }
        origins.sort();
        assert_eq!(
            origins,
            vec![
                ("from bitstream".to_string(), "sini.bitstream".to_string()),
                ("from the pod".to_string(), "genie-guard.genie".to_string()),
            ],
            "received origins carry the certificate-derived node names"
        );
    })
    .await;
}

// =============================================================================
// Oracle 2: Key mismatch. A CA entry keyed `bitstream` for host/bitstream/user/sini fails
// to load, naming sini.bitstream (D10), in `serve` and in `check-peers` alike.
// Mutant M2: accept any key for a CA entry => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_2_ca_entry_keyed_by_other_name_refused() {
    let ca = Ca::new();
    let own = ca.issue(SINI_CORTEX);
    let (tmp, ca_file) = node_dir();
    fs::write(&ca_file, &ca.pem).unwrap();
    let peers = json!({
        "bitstream": ca_entry("127.0.0.1:1", &ca_file, SINI_BITSTREAM, &["send"]),
    })
    .to_string();

    let (ok, out) = check_peers(&peers, Some(&own.cert));
    assert!(
        !ok && out.contains("'sini.bitstream'") && out.contains("'bitstream'"),
        "check-peers must refuse the key, naming the derived name: {out}"
    );
    let stderr = refused(NodeSpec {
        creds: Some(own),
        peers: Some(peers),
        ..Default::default()
    })
    .await;
    assert!(
        stderr.contains("'sini.bitstream'"),
        "serve must refuse the key, naming sini.bitstream: {stderr}"
    );

    // Control: keyed by its derived name, the same entry loads.
    let good = json!({
        "sini.bitstream": ca_entry("127.0.0.1:1", &ca_file, SINI_BITSTREAM, &["send"]),
    })
    .to_string();
    let (ok, out) = check_peers(&good, None);
    assert!(ok, "the correctly keyed entry must load: {out}");
    drop(tmp);
}

// =============================================================================
// Oracle 3: Pinned names. A peer nicknamed `laptop` crosses the wire under its
// 16-character name: a third node with no nickname for it sees the canonical name, and
// `x@laptop` reaches it.
// Topology: L (pinned) and C (pinned) each know only the hub H; H knows L as `laptop` and
// C as `cnode`. L sends through H to C. (H's direct send to `alice@laptop` is oracle 3b.)
// Mutant M3: put the nickname on the wire (the hub's forward mark) => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_pinned_names_cross_the_wire_canonical() {
    run_with_port_retry(|| async {
        let l_creds = pinned_creds("laptop-host");
        let c_creds = pinned_creds("c-host");
        let h_creds = pinned_creds("hub-host");
        let l_name = node_name_from_pin(&l_creds.pin).unwrap();
        let c_name = node_name_from_pin(&c_creds.pin).unwrap();
        assert_eq!(l_name.len(), 16);

        // H is started last: L and C dial it, it dials them. L also knows C, as `cee`.
        let l_dir = node_dir();
        let c_dir = node_dir();
        let h_fed = get_free_port();
        let c = start(
            NodeSpec {
                creds: Some(c_creds.clone()),
                peers: Some(
                    json!({
                        "peers": {
                            "hub": pin_entry(&addr(h_fed), &h_creds.pin, &["send", "reply", "relayed"])
                        }
                    })
                    .to_string(),
                ),
                fed: true,
                ..Default::default()
            },
            Some(c_dir),
        )
        .await;
        let l = start(
            NodeSpec {
                creds: Some(l_creds.clone()),
                peers: Some(
                    json!({
                        "peers": {
                            "hub": json!({
                                "address": addr(h_fed),
                                "pin": normalize_pin(&h_creds.pin),
                                "allow": ["send", "reply"],
                                "default_route": true
                            }),
                            "cee": pin_entry("", &c_creds.pin, &["send", "reply"])
                        }
                    })
                    .to_string(),
                ),
                fed: true,
                ..Default::default()
            },
            Some(l_dir),
        )
        .await;
        let h_peers = json!({
            "peers": {
                "laptop": pin_entry(&addr(l.fed_port), &l_creds.pin, &["send", "reply", "forward"]),
                "cnode": pin_entry(&addr(c.fed_port), &c_creds.pin, &["send", "reply"]),
            }
        })
        .to_string();
        let mut h_spec = NodeSpec {
            creds: Some(h_creds),
            peers: Some(h_peers),
            ..Default::default()
        };
        // H must listen on the port L and C were told.
        h_spec
            .extra_args
            .extend(["--fed-listen".to_string(), addr(h_fed)]);
        let _h = start(h_spec, None).await;

        let bob = claude_session(&c.sessions_dir, "bob", "Bob");

        // L -> H -> C, the destination typed by its canonical name.
        let (status, body) = http_send(&l, &format!("Bob@{c_name}"), "via the hub").await;
        assert_eq!(status, 202, "relay through the hub: {body}");
        let line = wait_line(&bob).await.expect("bob on C receives the relay");
        assert!(
            line.contains(&format!("ci · anon@{l_name}")),
            "C has no nickname for L, so it sees L's canonical name {l_name}: {line}"
        );
        assert!(
            !line.contains("laptop"),
            "H's nickname for L must not cross the wire: {line}"
        );

        // L types its own nickname for C in a hop destination: the hub, which has no
        // `cee`, receives C's canonical name (verifier P1).
        let (status, body) = http_send(&l, "Bob@cee", "by L's nickname").await;
        assert_eq!(status, 202, "L's nickname for C goes on the wire canonical: {body}");
        let mut got = false;
        for _ in 0..100 {
            if bob.lock().unwrap().iter().any(|l| l.contains("by L's nickname")) {
                got = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(got, "bob on C receives the send addressed by L's nickname");
    })
    .await;
}

// =============================================================================
// Oracle 3a (the hub leg of oracle 3): H knows L as `laptop` and C as `cnode`; a hop from
// L reaches C carrying L's canonical name, never H's nickname for it nor H's own name. The
// hop is posted to H by an in-process client holding L's credentials (tests/hop_client);
// L itself is not run. Oracle 3 keeps the origin-side legs (XA5).
// Mutant M3: put the nickname on the wire (the hub's forward mark) => RED.
// Mutant M3b: drop the forward mark (`forwarded: None`) => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3a_hub_forwards_canonical_origin() {
    run_with_port_retry(|| async {
        let (l_cert, l_key, l_pin) = generate_self_signed_ed25519("laptop-host").unwrap();
        let c_creds = pinned_creds("c-host");
        let h_creds = pinned_creds("hub-host");
        let l_name = node_name_from_pin(&l_pin).unwrap();
        let c_name = node_name_from_pin(&c_creds.pin).unwrap();
        let h_name = node_name_from_pin(&h_creds.pin).unwrap();
        let h_fed = get_free_port();
        let c = start(
            NodeSpec {
                creds: Some(c_creds.clone()),
                peers: Some(
                    json!({ "hub": pin_entry(&addr(h_fed), &h_creds.pin, &["send", "reply", "relayed"]) })
                        .to_string(),
                ),
                fed: true,
                ..Default::default()
            },
            None,
        )
        .await;
        let h_peers = json!({
            "laptop": pin_entry(&addr(get_free_port()), &l_pin, &["send", "reply", "forward"]),
            "cnode": pin_entry(&addr(c.fed_port), &c_creds.pin, &["send", "reply"]),
        })
        .to_string();
        let h_pin = h_creds.pin.clone();
        let mut h_spec = NodeSpec {
            creds: Some(h_creds),
            peers: Some(h_peers),
            ..Default::default()
        };
        h_spec
            .extra_args
            .extend(["--fed-listen".to_string(), addr(h_fed)]);
        let _h = start(h_spec, None).await;
        let bob = claude_session(&c.sessions_dir, "baa3a12f-e06d-59f5-90c8-2eda9a54dd91", "Bob");

        let origin = Origin {
            cert_der: &l_cert,
            key_der: &l_key,
        };
        let r = format!("baa3a12f-e06d-59f5-90c8-2eda9a54dd91@{c_name}");
        let (status, body) = hop_send(&origin, &h_pin, h_fed, &r, "via the hub").await;
        assert_eq!(status, 202, "{r} through the hub: {body}");
        let line = wait_line(&bob).await.expect("bob on C receives the relay");
        assert!(
            line.contains(&format!("alice@{l_name}")),
            "C has no nickname for L, so it sees L's canonical name {l_name}: {line}"
        );
        assert!(
            !line.contains("laptop") && !line.contains("@hub") && !line.contains(&h_name),
            "neither H's nickname for L nor H's own name stands for the origin: {line}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 3b (split from oracle 3 by XA3): a direct send by nickname. H knows L as `laptop`;
// `alice@laptop` typed on H resolves through H's peers file and reaches alice on L.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3b_direct_send_by_nickname() {
    run_with_port_retry(|| async {
        let l_creds = pinned_creds("laptop-host");
        let h_creds = pinned_creds("hub-host");
        let h_fed = get_free_port();
        let l = start(
            NodeSpec {
                creds: Some(l_creds.clone()),
                peers: Some(
                    json!({ "hub": pin_entry(&addr(h_fed), &h_creds.pin, &["send", "reply"]) })
                        .to_string(),
                ),
                fed: true,
                ..Default::default()
            },
            None,
        )
        .await;
        let mut h_spec = NodeSpec {
            creds: Some(h_creds),
            peers: Some(
                json!({ "laptop": pin_entry(&addr(l.fed_port), &l_creds.pin, &["send", "reply"]) })
                    .to_string(),
            ),
            ..Default::default()
        };
        h_spec
            .extra_args
            .extend(["--fed-listen".to_string(), addr(h_fed)]);
        let h = start(h_spec, None).await;
        let alice = claude_session(
            &l.sessions_dir,
            "135aa23d-60a6-5595-a42a-c0296722252e",
            "Alice",
        );

        // H types L's nickname.
        let (status, body) = http_send(
            &h,
            "135aa23d-60a6-5595-a42a-c0296722252e@laptop",
            "by nickname",
        )
        .await;
        assert_eq!(
            status, 202,
            "x@laptop resolves through H's peers file: {body}"
        );
        let line = wait_line(&alice).await.expect("alice on L receives it");
        assert!(line.contains("by nickname"), "{line}");
    })
    .await;
}

// =============================================================================
// Oracle 4: Collisions (A-8). Host `genie` with user `genie-guard`, and the pod
// ns/genie/sa/genie-guard, in one peers file, are refused naming both identities; so are
// two nicknames for one pinned key.
// Mutant M4: drop the namespace check => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_4_node_name_collisions_refused() {
    let ca = Ca::new();
    let (_tmp, ca_file) = node_dir();
    fs::write(&ca_file, &ca.pem).unwrap();
    let ca_path = ca_file.display().to_string();
    // Both entries derive genie-guard.genie, so a peers file must key both by it: written
    // by hand, since a JSON object built in code cannot hold the duplicate key.
    let peers = format!(
        r#"{{
  "genie-guard.genie": {{ "address": "127.0.0.1:1", "ca": "{ca_path}", "identities": ["{GENIE_HOST_GENIE_GUARD_USER}"], "allow": ["send"] }},
  "genie-guard.genie": {{ "address": "127.0.0.1:2", "ca": "{ca_path}", "identities": ["{GENIE_GUARD_POD}"], "allow": ["send"] }}
}}"#
    );
    let stderr = refused(NodeSpec {
        creds: Some(ca.issue(SINI_CORTEX)),
        peers: Some(peers),
        ..Default::default()
    })
    .await;
    assert!(
        stderr.contains("collides")
            && stderr.contains(GENIE_HOST_GENIE_GUARD_USER)
            && stderr.contains(GENIE_GUARD_POD),
        "the refusal must name both identities of genie-guard.genie: {stderr}"
    );

    let key = pinned_creds("one-key");
    let two_nicknames = json!({
        "lap": pin_entry("127.0.0.1:1", &key.pin, &["send"]),
        "top": pin_entry("127.0.0.1:2", &key.pin, &["send"]),
    })
    .to_string();
    let (ok, out) = check_peers(&two_nicknames, None);
    assert!(
        !ok && out.contains("collides") && out.contains(&node_name_from_pin(&key.pin).unwrap()),
        "two nicknames for one key are one node name twice: {out}"
    );
}

// =============================================================================
// Oracle 5: Nicknames (AM-5). `lap.top`, and a 16-character base32 nickname, are refused.
// Mutant M5: drop the nickname check => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_5_name_shaped_nicknames_refused() {
    let peer = pinned_creds("peer");
    for nickname in ["lap.top", "abcdefghijklmn23"] {
        let peers = json!({ nickname: pin_entry("127.0.0.1:1", &peer.pin, &["send"]) }).to_string();
        let stderr = refused(NodeSpec {
            creds: Some(pinned_creds("self")),
            peers: Some(peers),
            ..Default::default()
        })
        .await;
        assert!(
            stderr.contains(&format!("peer '{nickname}': a nickname may not")),
            "nickname '{nickname}' must be refused: {stderr}"
        );
    }
    // Control: a plain nickname, and the canonical name itself (no nickname), both load.
    let canonical = node_name_from_pin(&peer.pin).unwrap();
    for key in ["laptop", canonical.as_str()] {
        let peers = json!({ key: pin_entry("127.0.0.1:1", &peer.pin, &["send"]) }).to_string();
        let (ok, out) = check_peers(&peers, None);
        assert!(ok, "'{key}' must load: {out}");
    }
}

// =============================================================================
// Oracle 6: One canonical name (AM-6). One node configured both by pin and by CA identity
// is refused: by the handshake in each direction, naming both entries, and by the loader
// where it can know (an entry pinning this node's own key).
// Mutant M6a: drop the inbound check => RED. M6b: drop the outbound check => RED.
// M6c: drop the loader's own-key check => RED. M6d: a pinned dial checks only the pin => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_one_node_one_canonical_name() {
    run_with_port_retry(|| async {
        let ca = Ca::new();
        let x_creds = ca.issue(SINI_BITSTREAM);
        let n_creds = ca.issue(SINI_CORTEX);
        let x_dir = node_dir();
        fs::write(&x_dir.1, &ca.pem).unwrap();
        let n_dir = node_dir();
        fs::write(&n_dir.1, &ca.pem).unwrap();

        let x_fed = get_free_port();
        // N knows X twice: by CA identity, and pinned as `laptop`.
        let n_peers = json!({
            "sini.bitstream": ca_entry(&addr(x_fed), &n_dir.1, SINI_BITSTREAM, &["send", "reply"]),
            "laptop": pin_entry(&addr(x_fed), &x_creds.pin, &["send", "reply"]),
        })
        .to_string();
        let n = start(
            NodeSpec {
                creds: Some(n_creds),
                peers: Some(n_peers),
                fed: true,
                ..Default::default()
            },
            Some(n_dir),
        )
        .await;
        let mut x_spec = NodeSpec {
            creds: Some(x_creds),
            peers: Some(
                json!({ "sini.cortex": ca_entry(&addr(n.fed_port), &x_dir.1, SINI_CORTEX, &["send", "reply"]) })
                    .to_string(),
            ),
            ..Default::default()
        };
        x_spec
            .extra_args
            .extend(["--fed-listen".to_string(), addr(x_fed)]);
        let x = start(x_spec, Some(x_dir)).await;

        let bob = claude_session(&n.sessions_dir, "bob", "Bob");
        let alice = claude_session(&x.sessions_dir, "alice", "Alice");

        // Inbound to N: X authenticates by CA identity and presents the key N pins.
        let (status, body) = http_send(&x, "bob@sini.cortex", "inbound").await;
        assert_ne!(status, 202, "N must refuse X's connection: {body}");
        // Outbound from N to X's CA entry: X presents the key N pins as `laptop`.
        let (status, body) = http_send(&n, "alice@sini.bitstream", "outbound").await;
        assert_ne!(status, 202, "N must refuse X as a server: {body}");
        assert!(
            body.contains("'laptop'") && body.contains("'sini.bitstream'"),
            "the outbound refusal must name both entries: {body}"
        );
        // Outbound from N through its pinned entry: X's certificate also authenticates as
        // N's CA entry sini.bitstream.
        let (status, body) = http_send(&n, "alice@laptop", "pinned dial").await;
        assert_ne!(status, 202, "N must refuse X through the pin too: {body}");
        assert!(
            body.contains("'laptop'") && body.contains("'sini.bitstream'"),
            "the pinned-dial refusal must name both entries: {body}"
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(bob.lock().unwrap().is_empty(), "nothing reaches bob on N");
        assert!(alice.lock().unwrap().is_empty(), "nothing reaches alice on X");
        drop(x);
        let n_log = n.stop_and_log().await;
        assert!(
            n_log.contains("key pinned for peer 'laptop' and the CA identity of peer 'sini.bitstream'"),
            "N's inbound refusal must name both entries: {n_log}"
        );
    })
    .await;

    // The loader refuses where it can know: an entry pinning this node's own key.
    let ca = Ca::new();
    let own = ca.issue(SINI_CORTEX);
    let peers = json!({ "me": pin_entry("127.0.0.1:1", &own.pin, &["send"]) }).to_string();
    let (ok, out) = check_peers(&peers, Some(&own.cert));
    assert!(
        !ok && out.contains("pins this node's own key"),
        "a pin of this node's own key must be refused: {out}"
    );
    let stderr = refused(NodeSpec {
        creds: Some(own),
        peers: Some(peers),
        ..Default::default()
    })
    .await;
    assert!(stderr.contains("pins this node's own key"), "{stderr}");
}

// =============================================================================
// Oracle 7: Filters. `targets = ["genie-guard"]` admits the service and refuses an
// instance labelled `genie-guard`. `svc:genie-guard` and `claude:foo` fail to load;
// `principals = ["anon:ci"]` loads.
// Mutant M7a: match instance labels => RED. M7b: refuse every `<word>:<rest>` => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_7_filters_match_names_and_ids() {
    let peer = pinned_creds("peer");
    for (field, entry) in [("targets", "svc:genie-guard"), ("targets", "claude:foo")] {
        let mut e = pin_entry("127.0.0.1:1", &peer.pin, &["send"]);
        e[field] = json!([entry]);
        let (ok, out) = check_peers(&json!({ "s": e }).to_string(), None);
        assert!(
            !ok && out.contains(&format!("'{entry}' uses the retired")),
            "'{entry}' must fail to load, naming the new form: {out}"
        );
    }

    run_with_port_retry(|| async {
        let r_creds = pinned_creds("r");
        let s_creds = pinned_creds("s");
        let s_dir = node_dir();
        let r_fed = get_free_port();
        let s = start(
            NodeSpec {
                creds: Some(s_creds.clone()),
                peers: Some(
                    json!({ "r": pin_entry(&addr(r_fed), &r_creds.pin, &["send", "reply"]) })
                        .to_string(),
                ),
                fed: true,
                ..Default::default()
            },
            Some(s_dir),
        )
        .await;
        let mut s_on_r = pin_entry(&addr(s.fed_port), &s_creds.pin, &["send", "reply"]);
        s_on_r["targets"] = json!(["genie-guard"]);
        s_on_r["principals"] = json!(["anon:ci"]);
        let r_peers = json!({ "s": s_on_r }).to_string();
        let (ok, out) = check_peers(&r_peers, Some(&r_creds.cert));
        assert!(ok, "principals = [\"anon:ci\"] must load: {out}");
        let mut r_spec = NodeSpec {
            creds: Some(r_creds),
            peers: Some(r_peers),
            svc_exe: Some(svc_exe("genie-guard")),
            ..Default::default()
        };
        r_spec
            .extra_args
            .extend(["--fed-listen".to_string(), addr(r_fed)]);
        let r = start(r_spec, None).await;

        let (mut sr, mut sw) = register_svc(&r, "genie-guard").await;
        let impostor = claude_session(
            &r.sessions_dir,
            "0199cecf-0007-7000-8000-000000000007",
            "genie-guard",
        );

        let (status, body) = http_send(&s, "genie-guard@r", "to the service").await;
        assert_eq!(status, 202, "the service is admitted: {body}");
        let d = svc_poll(&mut sr, &mut sw).await;
        assert_eq!(d["text"], "to the service", "{d}");

        let (status, body) = http_send(
            &s,
            "0199cecf-0007-7000-8000-000000000007@r",
            "to the labelled instance",
        )
        .await;
        assert_eq!(
            status, 403,
            "an instance labelled genie-guard is not the service genie-guard: {body}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(impostor.lock().unwrap().is_empty());
    })
    .await;
}

// =============================================================================
// Oracle 8: No hand-assigned name (plan gate v0 C3). `xmsg serve --host-label x` is
// refused, naming the flag; a node with no federation identity names itself
// `<user>.<host>` (D4).
// Mutant M8: keep `--host-label` as an override of the derived name => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_8_no_hand_assigned_name() {
    run_with_port_retry(|| async {
        let stderr = refused(NodeSpec {
            extra_args: vec!["--host-label".into(), "x".into()],
            ..Default::default()
        })
        .await;
        assert!(
            stderr.contains("--host-label"),
            "serve must refuse the flag, naming it: {stderr}"
        );

        let stderr = refused(NodeSpec {
            extra_env: vec![("XMSG_HOST_LABEL".into(), "x".into())],
            ..Default::default()
        })
        .await;
        assert!(stderr.contains("XMSG_HOST_LABEL"), "{stderr}");

        let node = start(NodeSpec::default(), None).await;
        let inbox = claude_session(
            &node.sessions_dir,
            "d1529eb1-d8e5-59fd-921c-181abc745c4e",
            "local",
        );
        let (status, body) =
            http_send(&node, "d1529eb1-d8e5-59fd-921c-181abc745c4e", "hello").await;
        assert_eq!(status, 202, "{body}");
        let line = wait_line(&inbox).await.expect("local delivery");
        let expected = xmsg::node::local_node_name();
        assert!(
            line.contains(&format!("ci · anon@{expected}")),
            "a node with no certificate is {expected}: {line}"
        );
        // D4: `<user>.<host>`, the host cut at its first `.`; the user name may contain `.`.
        let host = gethostname::gethostname().to_string_lossy().to_string();
        let host = host.split('.').next().unwrap();
        let user = expected.strip_suffix(&format!(".{host}"));
        assert!(user.is_some_and(|u| !u.is_empty()), "{expected}");
    })
    .await;
}

// =============================================================================
// Oracle 7b: Filters at a hub (xa2-verify-v0 C1). A -> H -> D; on H, D's entry has
// `targets = ["genie-guard", "sess-label"]`, and D has no service, only a Claude instance
// labelled `genie-guard` (id `sess-label`). The hub checks the unresolved ref in the
// destination's grammar (A3, B4): a ref is an ID or a name, so a kind-prefixed ref
// (`session:`, `claude:`) never passes, even naming a listed ID. The bare-label case
// (`genie-guard@D@hub`) is open by design, not asserted.
// The hop is posted to H by an in-process client holding A's credentials (tests/hop_client):
// nothing in xmsg originates one until XA5's routing; A itself is not run.
// Mutant M7c: strip every retired kind prefix from the ref => RED.
// Mutant M7d: map `svc:`/`session:` to the bare name in `target_ref_could_match` => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_7b_hub_targets_refuse_harness_kind_refs() {
    run_with_port_retry(|| async {
        let (a_cert, a_key, a_pin) = generate_self_signed_ed25519("a").unwrap();
        let d_creds = pinned_creds("d");
        let h_creds = pinned_creds("h");
        let h_fed = get_free_port();
        let to_hub = |allow: &[&str]| {
            Some(json!({ "hub": pin_entry(&addr(h_fed), &h_creds.pin, allow) }).to_string())
        };
        let d = start(
            NodeSpec {
                creds: Some(d_creds.clone()),
                peers: to_hub(&["send", "reply", "relayed"]),
                fed: true,
                ..Default::default()
            },
            None,
        )
        .await;
        let mut d_on_h = pin_entry(&addr(d.fed_port), &d_creds.pin, &["send", "reply"]);
        d_on_h["targets"] = json!(["genie-guard", "095f428d-a387-543a-a82b-e21452c783f6"]);
        let h_peers = json!({
            "anode": pin_entry(&addr(get_free_port()), &a_pin, &["send", "reply", "forward"]),
            "dnode": d_on_h,
        })
        .to_string();
        let h_pin = h_creds.pin.clone();
        let mut h_spec = NodeSpec {
            creds: Some(h_creds),
            peers: Some(h_peers),
            ..Default::default()
        };
        h_spec
            .extra_args
            .extend(["--fed-listen".to_string(), addr(h_fed)]);
        let _h = start(h_spec, None).await;
        let d_name = node_name_from_pin(&d_creds.pin).unwrap();
        let inbox = claude_session(
            &d.sessions_dir,
            "095f428d-a387-543a-a82b-e21452c783f6",
            "genie-guard",
        );

        for (r, want) in [
            (
                format!("095f428d-a387-543a-a82b-e21452c783f6@{d_name}"),
                202,
            ),
            (
                format!("session:095f428d-a387-543a-a82b-e21452c783f6@{d_name}"),
                403,
            ),
            (format!("claude:genie-guard@{d_name}"), 403),
            (
                format!("claude:095f428d-a387-543a-a82b-e21452c783f6@{d_name}"),
                403,
            ),
        ] {
            let origin = Origin {
                cert_der: &a_cert,
                key_der: &a_key,
            };
            let (status, body) = hop_send(&origin, &h_pin, h_fed, &r, &format!("to {r}")).await;
            assert_eq!(status, want, "{r} through the hub: {body}");
            if want == 403 {
                assert_eq!(
                    body["detail"], "target not allowed for peer",
                    "{r}: refused by H's targets filter: {body}"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let got = inbox.lock().unwrap().clone();
        assert!(
            got.len() == 1
                && got
                    .iter()
                    .all(|l| !l.contains("to session:") && !l.contains("to claude:")),
            "only the bare-ID send reaches the labelled instance: {got:?}"
        );
    })
    .await;
}
