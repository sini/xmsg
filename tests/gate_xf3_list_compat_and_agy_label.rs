//! XF3 gate:
//! - Part 1: Federated `list` wire compatibility with pre-XL1 (`9096199`) peers (direct
//!   `/fed/v2/sessions` and dial-out `FedInboxItem::List`), plus new-to-new receiving
//!   `harness`, `registered_at`, `last_seen`.
//! - Part 2: `harness` on every recipient kind (`claude`, `agy`, `pi`, `opencode`, `hermes`,
//!   `svc`), including inactive (`parked`, `closed`), and omitted when a pre-XL1 peer answers
//!   without it.
//! - Part 3: Antigravity label registration (`--label`, `XMSG_AGY_LABEL`, default `"agy"`),
//!   step-3 label resolution (`to: "agy"`, `to: "agy@<node>"`, custom label, ambiguity on 2
//!   live `agy` sessions sharing `"agy"`), and sender header `<label> · <id>@<node>`.

mod short_sock;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use xmsg::agy::{dev_major, dev_minor};
use xmsg::fed::spki_sha256_from_der;

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");

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
    received: Arc<Mutex<Vec<String>>>,
}

fn inbox() -> Inbox {
    let dir = tempdir().unwrap();
    let sock = short_sock::sock_path(dir.path(), "in");
    let listener = UnixListener::bind(&sock).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = String::new();
            if stream.read_to_string(&mut buf).await.is_ok() && !buf.is_empty() {
                rx.lock().unwrap().push(buf);
            }
        }
    });
    Inbox {
        _dir: dir,
        sock,
        received,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreXl1FedListEntry {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub status: String,
    pub user: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum PreXl1FedListAnswer {
    Ok { entries: Vec<PreXl1FedListEntry> },
    Denied,
}

async fn fed_raw_request(
    creds: &Creds,
    peer_pin: &str,
    peer_port: u16,
    peer_host: &str,
    method: &str,
    uri: &str,
    body: Option<Vec<u8>>,
) -> (u16, Vec<u8>) {
    let connector =
        xmsg::fed::make_tls_connector(&creds.cert_der, &creds.key_der, peer_pin).unwrap();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", peer_port))
        .await
        .unwrap();
    let server_name = rustls::pki_types::ServerName::try_from(peer_host.to_string()).unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req_body = http_body_util::Full::new(bytes::Bytes::from(body.unwrap_or_default()));
    let req = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", peer_host)
        .header("content-type", "application/json")
        .body(req_body)
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    use http_body_util::BodyExt;
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

impl Ca {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "xf3 test CA");
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
        let cert_der = cert.der().to_vec();
        let key_der = key.serialize_der();
        let pin = spki_sha256_from_der(&cert_der).unwrap();
        Creds {
            cert: cert.pem(),
            key: key.serialize_pem(),
            cert_der,
            key_der,
            pin,
        }
    }
}

struct Node {
    #[allow(dead_code)]
    tmp: TempDir,
    http_port: u16,
    #[allow(dead_code)]
    fed_port: u16,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    #[allow(dead_code)]
    http_sock: PathBuf,
    sessions_dir: PathBuf,
    presence_dir: PathBuf,
    proc_locks: PathBuf,
    #[allow(dead_code)]
    db_path: PathBuf,
    _child: ChildGuard,
}

async fn start_node_with_bin(
    bin_path: &str,
    ca_pem: &str,
    creds: &Creds,
    peers: Value,
    extra_args: &[String],
    listen_fed: bool,
) -> (Node, u16) {
    for attempt in 1..=5 {
        let tmp = tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(tmp.path().join("ca.pem"), ca_pem).unwrap();

        let fed_port = get_free_port();
        let http_port = get_free_port();

        let run_dir = tmp.path().join("run");
        let sessions_dir = tmp.path().join("sessions");
        let presence_dir = run_dir.join(".gemini/antigravity-cli/presence");
        for d in [&run_dir, &sessions_dir, &presence_dir] {
            fs::create_dir_all(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let proc_locks = tmp.path().join("proc_locks");
        fs::write(&proc_locks, "").unwrap();

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

        let mut args: Vec<String> = vec![
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
        ];
        if listen_fed {
            args.push("--fed-listen".into());
            args.push(format!("127.0.0.1:{fed_port}"));
        }
        args.extend_from_slice(extra_args);

        let bin_dir = tmp.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let fake_agy = bin_dir.join("agy");
        fs::write(&fake_agy, "#!/bin/sh\necho 'delivered'\nexit 0\n").unwrap();
        fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();
        let path_env = match std::env::var("PATH") {
            Ok(p) => format!("{}:{p}", bin_dir.display()),
            Err(_) => bin_dir.display().to_string(),
        };

        let mut child = tokio::process::Command::new(bin_path)
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env("HOME", &run_dir)
            .env("PATH", &path_env)
            .env("RUST_LOG", "warn")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn xmsg serve");

        let mut failed_bind = false;
        for _ in 0..600 {
            if let Ok(Some(_)) = child.try_wait() {
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut err).await;
                }
                if (err.contains("AddrInUse") || err.contains("ddress already in use"))
                    && attempt < 5
                {
                    failed_bind = true;
                    break;
                }
                panic!("node exited at start: {err}");
            }
            let fed_up = !listen_fed
                || tokio::net::TcpStream::connect(("127.0.0.1", fed_port))
                    .await
                    .is_ok();
            let up = agent_sock.exists()
                && register_sock.exists()
                && http_sock.exists()
                && tokio::net::TcpStream::connect(("127.0.0.1", http_port))
                    .await
                    .is_ok()
                && fed_up;
            if up {
                return (
                    Node {
                        tmp,
                        http_port,
                        fed_port,
                        agent_sock,
                        register_sock,
                        http_sock,
                        sessions_dir,
                        presence_dir,
                        proc_locks,
                        db_path,
                        _child: ChildGuard(Some(child)),
                    },
                    fed_port,
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = child.start_kill();
        if !failed_bind {
            panic!("xmsg serve did not start within 30s");
        }
    }
    unreachable!()
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

// =============================================================================
// Oracle 1: Pre-XL1 (`9096199`) wire compatibility on both direct (`/fed/v2/sessions`)
// and dial-out (`FedInboxItem::List`), plus new-to-new receiving `harness`,
// `registered_at`, `last_seen`.
// Also verifies against a real `9096199` binary when `XMSG_PRE_XL1_BIN` is set.
// Mutant 1: Omit the version gate (always emit `registered_at` / `harness` on
// `FedListEntry`) -> RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_pre_xl1_wire_compat_direct_and_dialout() {
    let ca = Ca::new();
    let creds_new_a = ca.issue("spiffe://xf3.test/host/newa/user/sini");
    let creds_new_b = ca.issue("spiffe://xf3.test/host/newb/user/sini");
    let creds_old_dir = ca.issue("spiffe://xf3.test/host/olddir/user/sini");
    let creds_old_leaf = ca.issue("spiffe://xf3.test/host/oldleaf/user/sini");

    // 1. Start `new_a` (HEAD binary) which acts as hub for `old_leaf` (9096199 dial-out)
    //    and direct peer for `old_dir` (9096199 direct) and `new_b` (HEAD direct).
    let ca_file_tmp = tempdir().unwrap();
    let ca_path = ca_file_tmp.path().join("ca.pem");
    fs::write(&ca_path, &ca.pem).unwrap();

    let peers_new_a = json!({
        "sini.oldleaf": {
            "address": "127.0.0.1:1",
            "ca": ca_path.display().to_string(),
            "identities": ["spiffe://xf3.test/host/oldleaf/user/sini"],
            "leaf": true,
            "allow": ["send", "reply", "list", "inbox"]
        },
        "sini.olddir": {
            "address": "127.0.0.1:1",
            "ca": ca_path.display().to_string(),
            "identities": ["spiffe://xf3.test/host/olddir/user/sini"],
            "allow": ["send", "reply", "list"]
        },
        "sini.newb": {
            "address": "127.0.0.1:1",
            "ca": ca_path.display().to_string(),
            "identities": ["spiffe://xf3.test/host/newb/user/sini"],
            "allow": ["send", "reply", "list"]
        }
    });

    let (node_new_a, port_new_a) =
        start_node_with_bin(BIN, &ca.pem, &creds_new_a, peers_new_a, &[], true).await;

    // Register a live Claude session on `new_a`
    let sleeper_a = Sleeper::new();
    let inbox_a = inbox();
    let id_a = "11111111-1111-4111-8111-111111111111";
    write_claude_session(
        &node_new_a.sessions_dir,
        sleeper_a.pid(),
        id_a,
        "agent-on-newa",
        &inbox_a.sock,
    );

    let node_status = |body: &Value, name: &str| -> Option<String> {
        if let Some(arr) = body["nodes"].as_array() {
            arr.iter()
                .find(|n| n["node"] == name)
                .and_then(|n| n["status"].as_str())
                .map(str::to_string)
        } else {
            body["nodes"][name]["status"].as_str().map(str::to_string)
        }
    };

    // 1a. In-process pre-XL1 (`9096199`) direct request (`GET /fed/v2/sessions` without `?v=2`):
    //     Must decode cleanly into `PreXl1FedListEntry` (`#[serde(deny_unknown_fields)]`).
    let (st_raw, bytes_raw) = fed_raw_request(
        &creds_old_dir,
        &creds_new_a.pin,
        port_new_a,
        "sini.newa",
        "GET",
        "/fed/v2/sessions",
        None,
    )
    .await;
    assert_eq!(st_raw, 200);
    let pre_xl1_entries: Vec<PreXl1FedListEntry> = serde_json::from_slice(&bytes_raw).expect(
        "pre-XL1 (9096199) FedListEntry (#[serde(deny_unknown_fields)]) must decode /fed/v2/sessions without ?v=2",
    );
    assert_eq!(pre_xl1_entries.len(), 1);
    assert_eq!(pre_xl1_entries[0].id, id_a);

    // 1b. In-process pre-XL1 (`9096199`) dial-out leaf (`sini.oldleaf`) answering `new_a`:
    let id_leaf = "22222222-2222-4222-8222-222222222222";
    let _ = fed_raw_request(
        &creds_old_leaf,
        &creds_new_a.pin,
        port_new_a,
        "sini.newa",
        "GET",
        "/fed/v2/inbox?wait=0",
        None,
    )
    .await;
    let http_port_a = node_new_a.http_port;
    let list_leaf_task = tokio::spawn(async move {
        let url = format!("http://127.0.0.1:{http_port_a}/v1/recipients?node=sini.oldleaf");
        let resp = reqwest::get(url).await.unwrap();
        let st = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap();
        (st, body)
    });

    let mut answered = false;
    for _ in 0..30 {
        let (st_in, bytes_in) = fed_raw_request(
            &creds_old_leaf,
            &creds_new_a.pin,
            port_new_a,
            "sini.newa",
            "GET",
            "/fed/v2/inbox?wait=1",
            None,
        )
        .await;
        if st_in == 200 && !bytes_in.is_empty() {
            let item: Value = serde_json::from_slice(&bytes_in).unwrap_or(Value::Null);
            if item["kind"] == "list" {
                let q = item["query"].as_str().unwrap();
                let ans = PreXl1FedListAnswer::Ok {
                    entries: vec![PreXl1FedListEntry {
                        id: id_leaf.to_string(),
                        kind: "instance".to_string(),
                        label: Some("agent-on-oldleaf".to_string()),
                        status: "live".to_string(),
                        user: "sini".to_string(),
                    }],
                };
                let (st_ans, _) = fed_raw_request(
                    &creds_old_leaf,
                    &creds_new_a.pin,
                    port_new_a,
                    "sini.newa",
                    "POST",
                    &format!("/fed/v2/list/{q}"),
                    Some(serde_json::to_vec(&ans).unwrap()),
                )
                .await;
                assert_eq!(st_ans, 200);
                answered = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(answered, "sini.oldleaf should have received a list query");
    let (st_leaf, body_leaf) = list_leaf_task.await.unwrap();
    assert_eq!(st_leaf, 200, "{body_leaf}");
    assert_eq!(
        node_status(&body_leaf, "sini.oldleaf").as_deref(),
        Some("ok"),
        "{body_leaf}"
    );
    let leaf_recs = body_leaf["recipients"].as_array().unwrap();
    assert_eq!(leaf_recs.len(), 1, "{body_leaf}");
    assert_eq!(leaf_recs[0]["address"], format!("{id_leaf}@sini.oldleaf"));
    assert!(
        leaf_recs[0].get("harness").is_none(),
        "pre-XL1 peer entry must omit harness when not reported: {}",
        leaf_recs[0]
    );

    // 1c. In-process pre-XL1 (`9096199`) hub (`sini.olddir`) sending a `list` query WITHOUT `v`
    //     (`{"kind":"list","query":"q-pre-xl1"}`) to a dial-out new node (`sini.newb`), plus
    //     new-to-new over federation (`new_b` listing `sini.newa` with `?v=2`):
    let peers_mock_hub_file = ca_file_tmp.path().join("peers_mock_hub.json");
    fs::write(
        &peers_mock_hub_file,
        json!({
            "sini.newb": {
                "address": "127.0.0.1:1",
                "ca": ca_path.display().to_string(),
                "identities": ["spiffe://xf3.test/host/newb/user/sini"],
                "leaf": true,
                "allow": ["send", "reply", "list", "inbox"]
            }
        })
        .to_string(),
    )
    .unwrap();
    let mock_hub_peers = Arc::new(xmsg::fed::load_peers_file(&peers_mock_hub_file).unwrap());
    let mock_hub_cert_chain = vec![rustls::pki_types::CertificateDer::from(
        creds_old_dir.cert_der.clone(),
    )];
    let acceptor =
        xmsg::fed::make_tls_acceptor(&mock_hub_cert_chain, &creds_old_dir.key_der, mock_hub_peers)
            .unwrap();
    let mock_hub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_mock_hub = mock_hub_listener.local_addr().unwrap().port();
    let (ans_tx, ans_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let ans_tx = Arc::new(Mutex::new(Some(ans_tx)));
    let ready_to_query = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sent_query = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready_clone = ready_to_query.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = mock_hub_listener.accept().await {
            let acceptor = acceptor.clone();
            let ans_tx = ans_tx.clone();
            let ready_to_query = ready_clone.clone();
            let sent_query = sent_query.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(tls);
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let ans_tx = ans_tx.clone();
                        let ready_to_query = ready_to_query.clone();
                        let sent_query = sent_query.clone();
                        async move {
                            let path = req.uri().path().to_string();
                            if path == "/fed/v2/inbox" {
                                if ready_to_query.load(std::sync::atomic::Ordering::SeqCst)
                                    && !sent_query.swap(true, std::sync::atomic::Ordering::SeqCst)
                                {
                                    let body = serde_json::to_vec(&json!({
                                        "kind": "list",
                                        "query": "q-pre-xl1"
                                    }))
                                    .unwrap();
                                    Ok::<_, std::convert::Infallible>(
                                        hyper::Response::builder()
                                            .status(200)
                                            .header("content-type", "application/json")
                                            .body(http_body_util::Full::new(bytes::Bytes::from(
                                                body,
                                            )))
                                            .unwrap(),
                                    )
                                } else {
                                    Ok(hyper::Response::builder()
                                        .status(204)
                                        .body(http_body_util::Full::new(bytes::Bytes::new()))
                                        .unwrap())
                                }
                            } else if path == "/fed/v2/list/q-pre-xl1" {
                                use http_body_util::BodyExt;
                                let bytes =
                                    req.into_body().collect().await.unwrap().to_bytes().to_vec();
                                if let Some(tx) = ans_tx.lock().unwrap().take() {
                                    let _ = tx.send(bytes);
                                }
                                Ok(hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(bytes::Bytes::from_static(
                                        b"{\"status\":\"ok\"}",
                                    )))
                                    .unwrap())
                            } else {
                                Ok(hyper::Response::builder()
                                    .status(404)
                                    .body(http_body_util::Full::new(bytes::Bytes::new()))
                                    .unwrap())
                            }
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    let peers_new_b_direct = json!({
        "sini.olddir": {
            "address": format!("127.0.0.1:{port_mock_hub}"),
            "ca": ca_path.display().to_string(),
            "identities": ["spiffe://xf3.test/host/olddir/user/sini"],
            "dial": "outbound",
            "allow": ["send", "reply", "list", "inbox"]
        },
        "sini.newa": {
            "address": format!("127.0.0.1:{port_new_a}"),
            "ca": ca_path.display().to_string(),
            "identities": ["spiffe://xf3.test/host/newa/user/sini"],
            "allow": ["send", "reply", "list"]
        }
    });
    let (node_new_b_direct, _) =
        start_node_with_bin(BIN, &ca.pem, &creds_new_b, peers_new_b_direct, &[], false).await;
    let sleeper_b_inproc = Sleeper::new();
    let inbox_b_inproc = inbox();
    let id_b_inproc = "33333333-3333-4333-8333-333333333333";
    write_claude_session(
        &node_new_b_direct.sessions_dir,
        sleeper_b_inproc.pid(),
        id_b_inproc,
        "agent-on-newb",
        &inbox_b_inproc.sock,
    );
    ready_to_query.store(true, std::sync::atomic::Ordering::SeqCst);

    let dialout_ans_bytes = tokio::time::timeout(Duration::from_secs(5), ans_rx)
        .await
        .expect("dial-out node_new_b must answer pre-XL1 list query within 5s")
        .unwrap();
    let dialout_ans: PreXl1FedListAnswer = serde_json::from_slice(&dialout_ans_bytes).expect(
        "pre-XL1 (9096199) FedListAnswer (#[serde(deny_unknown_fields)]) must decode dial-out /fed/v2/list/<q> when v is absent",
    );
    match dialout_ans {
        PreXl1FedListAnswer::Ok { entries } => {
            assert!(
                entries.iter().any(|e| e.id == id_b_inproc),
                "expected {id_b_inproc} in dial-out entries: {entries:?}"
            );
        }
        PreXl1FedListAnswer::Denied => panic!("unexpected denied answer"),
    }

    let (st_n2n, new_to_new) = node_new_b_direct
        .http_get("/v1/recipients?node=sini.newa")
        .await;
    assert_eq!(st_n2n, 200, "{new_to_new}");
    assert_eq!(
        node_status(&new_to_new, "sini.newa").as_deref(),
        Some("ok"),
        "{new_to_new}"
    );
    let new_to_new_rec = &new_to_new["recipients"][0];
    assert_eq!(new_to_new_rec["address"], format!("{id_a}@sini.newa"));
    assert_eq!(new_to_new_rec["harness"], "claude");
    assert!(
        new_to_new_rec["registered_at"].as_i64().is_some(),
        "new-to-new federated list must carry registered_at: {new_to_new_rec}"
    );
    drop(node_new_b_direct);
    drop(sleeper_b_inproc);

    // 2. Optional live two-binary verification when `XMSG_PRE_XL1_BIN` is set:
    match std::env::var("XMSG_PRE_XL1_BIN") {
        Ok(val) if !val.trim().is_empty() => {
            let old_bin = Path::new(val.trim());
            assert!(
                old_bin.exists(),
                "XMSG_PRE_XL1_BIN points to missing binary: {}",
                old_bin.display()
            );
            let old_bin_str = old_bin.to_str().unwrap();

            let peers_old_dir = json!({
                "sini.newa": {
                    "address": format!("127.0.0.1:{port_new_a}"),
                    "ca": ca_path.display().to_string(),
                    "identities": ["spiffe://xf3.test/host/newa/user/sini"],
                    "allow": ["send", "reply", "list"]
                }
            });
            let (node_old_dir, _port_old_dir) = start_node_with_bin(
                old_bin_str,
                &ca.pem,
                &creds_old_dir,
                peers_old_dir,
                &[],
                true,
            )
            .await;

            let (st, old_dir_list) = node_old_dir.http_get("/v1/recipients?node=sini.newa").await;
            assert_eq!(st, 200, "old_dir list failed: {old_dir_list}");
            assert_eq!(
            node_status(&old_dir_list, "sini.newa").as_deref(),
            Some("ok"),
            "real 9096199 node must decode direct /fed/v2/sessions response from new node without unknown-field error: {old_dir_list}"
        );
            let old_dir_recs = old_dir_list["recipients"].as_array().unwrap();
            assert_eq!(old_dir_recs.len(), 1, "{old_dir_list}");
            assert_eq!(
                old_dir_recs[0]["address"],
                format!("{id_a}@sini.newa"),
                "{old_dir_list}"
            );

            let peers_old_leaf = json!({
                "sini.newa": {
                    "address": format!("127.0.0.1:{port_new_a}"),
                    "ca": ca_path.display().to_string(),
                    "identities": ["spiffe://xf3.test/host/newa/user/sini"],
                    "dial": "outbound",
                    "allow": ["send", "reply", "list", "inbox"]
                }
            });
            let (node_old_leaf, _) = start_node_with_bin(
                old_bin_str,
                &ca.pem,
                &creds_old_leaf,
                peers_old_leaf,
                &[],
                false,
            )
            .await;

            let sleeper_leaf = Sleeper::new();
            let inbox_leaf = inbox();
            write_claude_session(
                &node_old_leaf.sessions_dir,
                sleeper_leaf.pid(),
                id_leaf,
                "agent-on-oldleaf",
                &inbox_leaf.sock,
            );

            let mut new_listed_old_leaf = Value::Null;
            for _ in 0..40 {
                let (st, body) = node_new_a
                    .http_get("/v1/recipients?node=sini.oldleaf")
                    .await;
                if st == 200
                    && node_status(&body, "sini.oldleaf").as_deref() == Some("ok")
                    && body["recipients"].as_array().is_some_and(|a| !a.is_empty())
                {
                    new_listed_old_leaf = body;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            assert_eq!(
                node_status(&new_listed_old_leaf, "sini.oldleaf").as_deref(),
                Some("ok"),
                "new node listing dial-out real 9096199 peer must succeed: {new_listed_old_leaf}"
            );

            let peers_old_hub = json!({
                "sini.newb": {
                    "address": "127.0.0.1:1",
                    "ca": ca_path.display().to_string(),
                    "identities": ["spiffe://xf3.test/host/newb/user/sini"],
                    "leaf": true,
                    "allow": ["send", "reply", "list", "inbox"]
                }
            });
            let (node_old_hub, port_old_hub) = start_node_with_bin(
                old_bin_str,
                &ca.pem,
                &creds_old_dir,
                peers_old_hub,
                &[],
                true,
            )
            .await;

            let peers_new_b_dialout = json!({
                "sini.olddir": {
                    "address": format!("127.0.0.1:{port_old_hub}"),
                    "ca": ca_path.display().to_string(),
                    "identities": ["spiffe://xf3.test/host/olddir/user/sini"],
                    "dial": "outbound",
                    "allow": ["send", "reply", "list", "inbox"]
                }
            });
            let (node_new_b, _) =
                start_node_with_bin(BIN, &ca.pem, &creds_new_b, peers_new_b_dialout, &[], false)
                    .await;

            let sleeper_b = Sleeper::new();
            let inbox_b = inbox();
            let id_b = "33333333-3333-4333-8333-333333333333";
            write_claude_session(
                &node_new_b.sessions_dir,
                sleeper_b.pid(),
                id_b,
                "agent-on-newb",
                &inbox_b.sock,
            );

            let mut old_hub_listed_new_b = Value::Null;
            for _ in 0..40 {
                let (st, body) = node_old_hub.http_get("/v1/recipients?node=sini.newb").await;
                if st == 200
                    && node_status(&body, "sini.newb").as_deref() == Some("ok")
                    && body["recipients"].as_array().is_some_and(|a| !a.is_empty())
                {
                    old_hub_listed_new_b = body;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            assert_eq!(
            node_status(&old_hub_listed_new_b, "sini.newb").as_deref(),
            Some("ok"),
            "real 9096199 hub listing dial-out new node must succeed (new node strips v2 fields when v<2): {old_hub_listed_new_b}"
        );
            assert_eq!(
                old_hub_listed_new_b["recipients"][0]["address"],
                format!("{id_b}@sini.newb"),
                "{old_hub_listed_new_b}"
            );
        }
        _ => {
            eprintln!(
                "XMSG_PRE_XL1_BIN unset; skipping live two-binary pre-XL1 (9096199) subprocess check (in-process #[serde(deny_unknown_fields)] direct + dial-out wire checks ran)"
            );
        }
    }
}

// =============================================================================
// Oracle 2: `harness` is present on every recipient kind (`claude`, `agy`, `pi`,
// `opencode`, `hermes`, `svc`), including inactive (`parked`, `closed`).
// Mutant 2: Drop `harness` from `Recipient` -> RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_harness_on_every_kind_live_and_inactive() {
    let ca = Ca::new();
    let creds_a = ca.issue("spiffe://xf3.test/host/nodea/user/sini");
    let my_exe = std::env::current_exe().unwrap();
    let bin_exe = PathBuf::from(BIN);

    let extra_args = vec![
        "--agy-exe".to_string(),
        my_exe.display().to_string(),
        "--agy-exe".to_string(),
        bin_exe.display().to_string(),
        "--svc-exe".to_string(),
        format!("my-svc={}", my_exe.display()),
    ];
    let (node, _) = start_node_with_bin(BIN, &ca.pem, &creds_a, json!({}), &extra_args, true).await;

    // 1. Live `claude` session + a second `claude` session that we'll park
    let s_claude = Sleeper::new();
    let in_claude = inbox();
    let id_claude = "aaaa1111-1111-4111-8111-111111111111";
    write_claude_session(
        &node.sessions_dir,
        s_claude.pid(),
        id_claude,
        "claude-work",
        &in_claude.sock,
    );

    let s_parked = Sleeper::new();
    let in_parked = inbox();
    let id_parked = "bbbb2222-2222-4222-8222-222222222222";
    write_claude_session(
        &node.sessions_dir,
        s_parked.pid(),
        id_parked,
        "claude-parked",
        &in_parked.sock,
    );

    // 2. Live `agy` session via `register.sock`
    let my_pid = std::process::id();
    let conv_agy = "cccc3333-3333-4333-8333-333333333333";
    let lock_file = node.presence_dir.join(format!("{conv_agy}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let _open_lock = fs::File::open(&lock_file).unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let locks_line = format!(
        "1: FLOCK ADVISORY WRITE {my_pid} {:02x}:{:02x}:{} 0 EOF\n",
        dev_major(meta.dev()),
        dev_minor(meta.dev()),
        meta.ino()
    );
    fs::write(&node.proc_locks, &locks_line).unwrap();

    // Note: `xmsg serve` uses `/proc/locks` when started via CLI; for `agy` registration via
    // `xmsg register agy` against `xmsg serve`, hold a real flock on `lock_file`!
    unsafe {
        use std::os::unix::io::AsRawFd;
        libc::flock(_open_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB);
    }

    let reg_out = Command::new(BIN)
        .args([
            "register",
            "agy",
            "--sock",
            node.register_sock.to_str().unwrap(),
        ])
        .env("ANTIGRAVITY_CONVERSATION_ID", conv_agy)
        .env("ANTIGRAVITY_LS_ADDRESS", "127.0.0.1:39999")
        .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-tok")
        .output()
        .unwrap();
    assert_eq!(reg_out.status.code(), Some(0));

    // 3. Live `pi` session via `register.sock`
    let id_pi = "dddd4444-4444-4444-8444-444444444444";
    let pi_stream = UnixStream::connect(&node.register_sock).await.unwrap();
    let (pi_r, mut pi_w) = pi_stream.into_split();
    let mut pi_r = BufReader::new(pi_r);
    pi_w.write_all(
        format!(
            "{}\n",
            json!({
                "harness": "pi",
                "session_id": id_pi,
                "session_name": "pi-work",
                "cwd": "/workspace"
            })
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut pi_line = String::new();
    pi_r.read_line(&mut pi_line).await.unwrap();
    let pi_resp: Value = serde_json::from_str(&pi_line).unwrap();
    assert_eq!(pi_resp["status"], "ok", "{pi_resp}");
    let addr_pi_live = pi_resp["sessionId"].as_str().unwrap().to_string();

    // 4. Live `opencode` session + a second `opencode` session that we'll release (`closed`)
    let oc_stream = UnixStream::connect(&node.register_sock).await.unwrap();
    let (oc_r, mut oc_w) = oc_stream.into_split();
    let mut oc_r = BufReader::new(oc_r);
    oc_w.write_all(b"{\"harness\":\"opencode\"}\n")
        .await
        .unwrap();
    let mut oc_line = String::new();
    oc_r.read_line(&mut oc_line).await.unwrap();
    oc_line.clear();
    oc_w.write_all(b"{\"action\":\"register\",\"request_id\":\"1\",\"session\":\"oc-live\"}\n")
        .await
        .unwrap();
    oc_r.read_line(&mut oc_line).await.unwrap();
    let oc_reg1: Value = serde_json::from_str(&oc_line).unwrap();
    assert_eq!(oc_reg1["status"], "ok", "{oc_reg1}");
    let addr_oc_live = oc_reg1["address"].as_str().unwrap().to_string();

    oc_line.clear();
    oc_w.write_all(b"{\"action\":\"register\",\"request_id\":\"2\",\"session\":\"oc-closed\"}\n")
        .await
        .unwrap();
    oc_r.read_line(&mut oc_line).await.unwrap();
    let oc_reg2: Value = serde_json::from_str(&oc_line).unwrap();
    assert_eq!(oc_reg2["status"], "ok", "{oc_reg2}");
    let addr_oc_closed = oc_reg2["address"].as_str().unwrap().to_string();

    // Release `oc-closed` so it transitions to `closed`
    oc_line.clear();
    oc_w.write_all(b"{\"action\":\"release\",\"request_id\":\"3\",\"session\":\"oc-closed\"}\n")
        .await
        .unwrap();
    oc_r.read_line(&mut oc_line).await.unwrap();

    // 5. Live `hermes` session
    let hm_stream = UnixStream::connect(&node.register_sock).await.unwrap();
    let (hm_r, mut hm_w) = hm_stream.into_split();
    let mut hm_r = BufReader::new(hm_r);
    hm_w.write_all(b"{\"harness\":\"hermes\"}\n").await.unwrap();
    let mut hm_line = String::new();
    hm_r.read_line(&mut hm_line).await.unwrap();
    hm_line.clear();
    hm_w.write_all(b"{\"action\":\"register\",\"request_id\":\"1\",\"session\":\"hm-live\"}\n")
        .await
        .unwrap();
    hm_r.read_line(&mut hm_line).await.unwrap();
    let hm_reg: Value = serde_json::from_str(&hm_line).unwrap();
    assert_eq!(hm_reg["status"], "ok", "{hm_reg}");
    let addr_hm_live = hm_reg["address"].as_str().unwrap().to_string();

    // 6. Live `svc` session
    let svc_stream = UnixStream::connect(&node.register_sock).await.unwrap();
    let (svc_r, mut svc_w) = svc_stream.into_split();
    let mut svc_r = BufReader::new(svc_r);
    svc_w
        .write_all(b"{\"harness\":\"svc\",\"name\":\"my-svc\"}\n")
        .await
        .unwrap();
    let mut svc_line = String::new();
    svc_r.read_line(&mut svc_line).await.unwrap();
    let svc_reg: Value = serde_json::from_str(&svc_line).unwrap();
    assert_eq!(svc_reg["status"], "ok", "{svc_reg}");

    // Observe live list first so `id_parked` is synced into `instance_seen`
    let (st, live_list) = node.http_get("/v1/recipients").await;
    assert_eq!(st, 200, "{live_list}");

    // Now park `id_parked`
    remove_claude_session(&node.sessions_dir, s_parked.pid(), id_parked);
    s_parked.end();

    // Verify live recipients carry their exact `harness`
    let (st, live_list) = node.http_get("/v1/recipients").await;
    assert_eq!(st, 200, "{live_list}");
    let recs = live_list["recipients"].as_array().unwrap();

    let find_by_addr = |list: &[Value], prefix: &str| -> Value {
        list.iter()
            .find(|r| r["address"].as_str().is_some_and(|a| a.starts_with(prefix)))
            .unwrap_or_else(|| panic!("missing recipient starting with {prefix} in {list:?}"))
            .clone()
    };

    assert_eq!(find_by_addr(recs, id_claude)["harness"], "claude");
    assert_eq!(find_by_addr(recs, conv_agy)["harness"], "agy");
    assert_eq!(find_by_addr(recs, &addr_pi_live)["harness"], "pi");
    assert_eq!(find_by_addr(recs, &addr_oc_live)["harness"], "opencode");
    assert_eq!(find_by_addr(recs, &addr_hm_live)["harness"], "hermes");
    assert_eq!(find_by_addr(recs, "my-svc@")["harness"], "svc");

    // Verify inactive (`parked` and `closed`) recipients also carry `harness`
    let (st, inactive_list) = node.http_get("/v1/recipients?status=inactive").await;
    assert_eq!(st, 200, "{inactive_list}");
    let irecs = inactive_list["recipients"].as_array().unwrap();
    let parked_rec = find_by_addr(irecs, id_parked);
    assert_eq!(parked_rec["status"], "parked");
    assert_eq!(parked_rec["harness"], "claude");

    let closed_rec = find_by_addr(irecs, &addr_oc_closed);
    assert_eq!(closed_rec["status"], "closed");
    assert_eq!(closed_rec["harness"], "opencode");
}

// =============================================================================
// Oracle 3a & 3b:
// - Oracle 3a: A single live `agy` session with default label `"agy"` resolves via
//   `to: "agy"` and `to: "agy@<node>"`. And custom label via `--label` / `XMSG_AGY_LABEL`
//   sets its label, resolves via `to: "<custom>"`, and formats sender header as
//   `<label> · <id>@<node>`.
//   Also verifies `--hook` mode passes `--label` in `injectSteps` when non-default.
//   Mutant 3a: Omit `agy_sessions` from step 3 (`labelled`) in `http::resolve_target` -> RED.
// - Oracle 3b: Two live `agy` sessions with default label `"agy"` on the same node:
//   `send(to: "agy")` returns `ambiguous` listing both `id@node` candidates.
//   Mutant 3b: Return `.find(...)` instead of collecting into `labelled` -> RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3a_and_3b_agy_label_resolution_ambiguity_and_sender_header() {
    let ca = Ca::new();
    let creds_a = ca.issue("spiffe://xf3.test/host/nodea/user/sini");
    let my_exe = std::env::current_exe().unwrap();
    let bin_exe = PathBuf::from(BIN);

    let extra_args = vec![
        "--agy-exe".to_string(),
        my_exe.display().to_string(),
        "--agy-exe".to_string(),
        bin_exe.display().to_string(),
    ];
    let (node, _) = start_node_with_bin(BIN, &ca.pem, &creds_a, json!({}), &extra_args, true).await;
    let ls_addr = "127.0.0.1:9999";

    // Register first agy session with default label ("agy")
    let conv_1 = "1111aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let lock_1 = node.presence_dir.join(format!("{conv_1}.lock"));
    fs::write(&lock_1, "lock").unwrap();
    let open_lock_1 = fs::File::open(&lock_1).unwrap();
    unsafe {
        use std::os::unix::io::AsRawFd;
        libc::flock(open_lock_1.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB);
    }

    let out_1 = Command::new(BIN)
        .args([
            "register",
            "agy",
            "--sock",
            node.register_sock.to_str().unwrap(),
        ])
        .env("ANTIGRAVITY_CONVERSATION_ID", conv_1)
        .env("ANTIGRAVITY_LS_ADDRESS", ls_addr.to_string())
        .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-1")
        .env_remove("XMSG_AGY_LABEL")
        .output()
        .unwrap();
    assert_eq!(out_1.status.code(), Some(0));

    // Verify `list` shows `label: "agy"` and `harness: "agy"`
    let (st, listed) = node.http_get("/v1/recipients").await;
    assert_eq!(st, 200, "{listed}");
    let recs = listed["recipients"].as_array().unwrap();
    assert_eq!(recs.len(), 1, "{listed}");
    assert_eq!(recs[0]["address"], format!("{conv_1}@sini.nodea"));
    assert_eq!(recs[0]["label"], "agy");
    assert_eq!(recs[0]["harness"], "agy");

    // Oracle 3a: `send(to: "agy")` and `send(to: "agy@sini.nodea")` resolve to `conv_1@sini.nodea`
    let (st, send_bare) = node.http_send("agy", "hello default agy").await;
    assert_eq!(st, 202, "send(to: \"agy\") must resolve: {send_bare}");
    assert_eq!(send_bare["address"], format!("{conv_1}@sini.nodea"));
    assert_eq!(send_bare["outcome"], "delivered");

    let (st, send_qual) = node
        .http_send("agy@sini.nodea", "hello qualified agy")
        .await;
    assert_eq!(
        st, 202,
        "send(to: \"agy@sini.nodea\") must resolve: {send_qual}"
    );
    assert_eq!(send_qual["address"], format!("{conv_1}@sini.nodea"));

    // Custom label registration on `conv_1`: re-register `conv_1` with `--label agy-ops`
    // and verify sender header when `conv_1` sends to a Claude session shows
    // `agy-ops · 1111aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@sini.nodea` (NOT the raw UUID twice!).
    let out_1_custom = Command::new(BIN)
        .args([
            "register",
            "agy",
            "--sock",
            node.register_sock.to_str().unwrap(),
            "--label",
            "agy-ops",
        ])
        .env("ANTIGRAVITY_CONVERSATION_ID", conv_1)
        .env("ANTIGRAVITY_LS_ADDRESS", ls_addr.to_string())
        .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-1")
        .output()
        .unwrap();
    assert_eq!(out_1_custom.status.code(), Some(0));

    let s_claude = Sleeper::new();
    let in_claude = inbox();
    let id_claude = "9999cccc-cccc-4ccc-8ccc-cccccccccccc";
    write_claude_session(
        &node.sessions_dir,
        s_claude.pid(),
        id_claude,
        "claude-target",
        &in_claude.sock,
    );

    let send_from_agy = node
        .agent_call(json!({
            "action": "send",
            "to": "claude-target",
            "text": "message from agy-ops"
        }))
        .await;
    assert_eq!(send_from_agy["status"], "ok", "{send_from_agy}");

    let mut delivered_env = String::new();
    for _ in 0..40 {
        if let Some(m) = in_claude.received.lock().unwrap().first() {
            delivered_env = m.clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        delivered_env.contains(&format!("agy-ops · {conv_1}@sini.nodea")),
        "expected sender header 'agy-ops · {conv_1}@sini.nodea' in delivered envelope, got: {delivered_env}"
    );

    // Re-register `conv_1` with default label `"agy"`, and register a second live agy session
    // `conv_2` with default label `"agy"`.
    // Oracle 3b: Now `send(to: "agy")` must fail with `ambiguous` (HTTP 409) naming both candidates!
    let out_1_reset = Command::new(BIN)
        .args([
            "register",
            "agy",
            "--sock",
            node.register_sock.to_str().unwrap(),
        ])
        .env("ANTIGRAVITY_CONVERSATION_ID", conv_1)
        .env("ANTIGRAVITY_LS_ADDRESS", ls_addr.to_string())
        .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-1")
        .env_remove("XMSG_AGY_LABEL")
        .output()
        .unwrap();
    assert_eq!(out_1_reset.status.code(), Some(0));

    let conv_2 = "2222bbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let lock_2 = node.presence_dir.join(format!("{conv_2}.lock"));
    fs::write(&lock_2, "lock").unwrap();
    let open_lock_2 = fs::File::open(&lock_2).unwrap();
    unsafe {
        use std::os::unix::io::AsRawFd;
        libc::flock(open_lock_2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB);
    }

    let out_2 = Command::new(BIN)
        .args([
            "register",
            "agy",
            "--sock",
            node.register_sock.to_str().unwrap(),
        ])
        .env("ANTIGRAVITY_CONVERSATION_ID", conv_2)
        .env("ANTIGRAVITY_LS_ADDRESS", ls_addr.to_string())
        .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-2")
        .env_remove("XMSG_AGY_LABEL")
        .output()
        .unwrap();
    assert_eq!(out_2.status.code(), Some(0));

    let (st_amb, amb_body) = node.http_send("agy", "should be ambiguous").await;
    assert_eq!(
        st_amb, 409,
        "two live agy sessions sharing label 'agy' must return 409 Conflict (ambiguous): {amb_body}"
    );
    assert_eq!(amb_body["error"], "ambiguous", "{amb_body}");
    let detail = amb_body["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains(&format!("{conv_1}@sini.nodea"))
            && detail.contains(&format!("{conv_2}@sini.nodea")),
        "ambiguous error detail must list both candidates: {detail}"
    );

    // Also check via `agent.sock`:
    let agent_amb = node
        .agent_call(json!({
            "action": "send",
            "to": "agy",
            "text": "should be ambiguous"
        }))
        .await;
    assert_eq!(agent_amb["status"], "error", "{agent_amb}");
    assert_eq!(agent_amb["error"], "ambiguous", "{agent_amb}");
    let agent_detail = agent_amb["detail"].as_str().unwrap_or("");
    assert!(
        agent_detail.contains(&format!("{conv_1}@sini.nodea"))
            && agent_detail.contains(&format!("{conv_2}@sini.nodea")),
        "agent.sock ambiguous error must list both candidates: {agent_detail}"
    );

    // Disambiguate by re-registering `conv_1` with `--label agy-ops` while `conv_2` keeps `"agy"`
    let out_1_custom_2 = Command::new(BIN)
        .args([
            "register",
            "agy",
            "--sock",
            node.register_sock.to_str().unwrap(),
            "--label",
            "agy-ops",
        ])
        .env("ANTIGRAVITY_CONVERSATION_ID", conv_1)
        .env("ANTIGRAVITY_LS_ADDRESS", ls_addr.to_string())
        .env("ANTIGRAVITY_CSRF_TOKEN", "csrf-1")
        .output()
        .unwrap();
    assert_eq!(out_1_custom_2.status.code(), Some(0));

    // Now `"agy"` is unique again (resolves to `conv_2`), and `"agy-ops"` resolves to `conv_1`!
    let (st_2, body_2) = node.http_send("agy", "now unique again").await;
    assert_eq!(st_2, 202, "{body_2}");
    assert_eq!(body_2["address"], format!("{conv_2}@sini.nodea"));

    let (st_1, body_1) = node.http_send("agy-ops", "hello custom agy-ops").await;
    assert_eq!(st_1, 202, "{body_1}");
    assert_eq!(body_1["address"], format!("{conv_1}@sini.nodea"));

    // Also test `--hook` with `--label work`: when an unregistered conversation invokes the hook,
    // `injectSteps` includes `--label work`.
    let mut hook_child = Command::new(BIN)
        .args([
            "register",
            "agy",
            "--hook",
            "--sock",
            node.register_sock.to_str().unwrap(),
            "--label",
            "work",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let stdin = hook_child.stdin.as_mut().unwrap();
        stdin
            .write_all(b"{\"conversationId\":\"unregistered-conv-999\"}")
            .unwrap();
    }
    let hook_out = hook_child.wait_with_output().unwrap();
    let hook_json: Value = serde_json::from_slice(&hook_out.stdout).unwrap();
    let msg = hook_json["injectSteps"][0]["userMessage"]
        .as_str()
        .unwrap_or("");
    assert!(
        msg.contains("--label work"),
        "hook injectSteps userMessage must include '--label work' when label != 'agy', got: {msg}"
    );
}
