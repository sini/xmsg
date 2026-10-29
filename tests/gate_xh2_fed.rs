//! XH2 gate v0 K1: a federated message to an opencode plugin session can be replied to by
//! that session. Node B is a real `xmsg serve`; node A runs in this process. Adapted from
//! the gate's probe `xh2-verify-v0.probes/review_fed.rs`.

mod short_sock;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, UnixListener, UnixStream};

use serde_json::Value;

use xmsg::agent::{current_uid, run_agent_server};
use xmsg::agy::{new_agy_store, run_register_server, AgyConfig};
use xmsg::fed::{
    generate_self_signed_ed25519, generate_self_signed_ed25519_pem, run_fed_listener, FedState,
    PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::AppState;
use xmsg::pi::new_pi_store;
use xmsg::svc::new_svc_store;

struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn setup_mock_proc(proc_root: &Path, pid: u32, exe_target: &Path, starttime: &str) {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();

    let exe_link = pid_dir.join("exe");
    let _ = fs::remove_file(&exe_link);
    std::os::unix::fs::symlink(exe_target, &exe_link).unwrap();

    let stat_content =
        format!("{pid} (svc_test) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).unwrap();
}

async fn connect_svc(sock_path: &Path) -> (BufReader<OwnedReadHalf>, OwnedWriteHalf) {
    let stream = UnixStream::connect(sock_path).await.unwrap();
    let (reader, writer) = stream.into_split();
    (BufReader::new(reader), writer)
}

async fn read_json_line(reader: &mut BufReader<OwnedReadHalf>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

async fn send_via_agent_sock(agent_sock: &Path, target_ref: &str, text: &str) -> Value {
    let stream = UnixStream::connect(agent_sock).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let send_req = serde_json::json!({
        "action": "send",
        "to": target_ref,
        "text": text,
    });
    writer
        .write_all(format!("{send_req}\n").as_bytes())
        .await
        .unwrap();

    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(&resp_line).expect("valid json response from agent.sock")
}

#[allow(dead_code)]
struct FullTestNode {
    name: String,
    fed_addr: std::net::SocketAddr,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    proc_root: PathBuf,
    fed_state: Arc<FedState>,
    db: Arc<Mutex<rusqlite::Connection>>,
    sessions_dir: PathBuf,
    inbox_rx: Arc<Mutex<Vec<String>>>,
    _temp: TempDir,
}

async fn create_full_test_node(
    name: &str,
    target_session_name: &str,
    peers: Vec<PeerConfig>,
    listener_opt: Option<TcpListener>,
    creds_opt: Option<(Vec<u8>, Vec<u8>, String)>,
    service_name: &str,
) -> FullTestNode {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_sock = short_sock::sock_path(&sock_dir, "agent");
    let register_sock = short_sock::sock_path(&sock_dir, "register");

    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = temp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_locks = temp.path().join("proc_locks");
    fs::write(&proc_locks, "").unwrap();

    let my_uid = current_uid();
    let my_pid = std::process::id();
    let live_proc = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&live_proc, my_pid).unwrap_or_else(|_| "0".to_string());

    // Create trusted exe for service
    let trusted_bin = temp.path().join(format!("trusted_{service_name}"));
    fs::write(&trusted_bin, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&trusted_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let mut trusted_svc_exes: HashMap<String, PathBuf> = HashMap::new();
    trusted_svc_exes.insert(service_name.to_string(), trusted_bin.clone());

    // Setup mock proc for current test process
    setup_mock_proc(&proc_root, my_pid, &trusted_bin, &my_proc_start);

    // Setup Claude inbox listener and session fixture
    let target_inbox_sock = short_sock::sock_path(&sock_dir, "inbox");
    let inbox_listener = UnixListener::bind(&target_inbox_sock).unwrap();
    let inbox_rx = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = inbox_rx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = inbox_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": target_session_name,
        "name": target_session_name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": target_inbox_sock.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}.json")),
        session_json.to_string(),
    )
    .unwrap();

    let (cert_der, key_der, _pin) = match creds_opt {
        Some(creds) => creds,
        None => generate_self_signed_ed25519(name).unwrap(),
    };

    let mut peers_map = HashMap::new();
    for p in peers {
        peers_map.insert(p.name.clone(), p);
    }
    let peers_arc = Arc::new(PeersMap::new(peers_map));

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(16);

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
            brain_dir: std::path::PathBuf::new(),
    };
    let agy_store = new_agy_store();
    let pi_store = new_pi_store();
    let svc_store = new_svc_store();

    let fed_state = Arc::new(FedState {
        node_name: name.to_string(),
        peers: peers_arc,
        cert_der,
        cert_chain_der: Vec::new(),
        key_der,
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db: db.clone(),
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: svc_store.clone(),
        svc_notify_tx: svc_notify_tx.clone(),
        notify_tx: notify_tx.clone(),
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    });

    let fed_listener = match listener_opt {
        Some(l) => l,
        None => TcpListener::bind("127.0.0.1:0").await.unwrap(),
    };
    let fed_addr = fed_listener.local_addr().unwrap();
    let fs_clone = fed_state.clone();
    tokio::spawn(async move {
        let _ = run_fed_listener(fed_listener, fs_clone).await;
    });

    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir.clone()],
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        svc_store: svc_store.clone(),
        svc_notify_tx: svc_notify_tx.clone(),
        node_name: name.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: Some(fed_state.clone()),
    });

    let s_path = agent_sock.clone();
    let s_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    let r_sock = register_sock.clone();

    let r_state_xa3 = app_state.clone();
    tokio::spawn(async move {
        let _ = run_register_server(r_sock, r_state_xa3, my_uid, trusted_svc_exes).await;
    });

    for _ in 0..1500 {
        if agent_sock.exists() && register_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    FullTestNode {
        name: name.to_string(),
        fed_addr,
        agent_sock,
        register_sock,
        proc_root,
        fed_state,
        db,
        sessions_dir,
        inbox_rx,
        _temp: temp,
    }
}

/// Node A in this process and node B a real `xmsg serve`, each a peer of the other: A
/// allows B `send` and `reply`, B allows A `send`, `reply` and `list`.
struct Pair {
    _child: ChildGuard,
    register_sock_b: PathBuf,
    http_sock_b: PathBuf,
    node_a: FullTestNode,
    _tmp_b: TempDir,
}

async fn start_pair() -> Pair {
    let (cert_b_pem, key_b_pem, pin_b) = generate_self_signed_ed25519_pem("node_b").unwrap();
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node_a").unwrap();

    let mut attempt = 0;
    loop {
        attempt += 1;
        let port_b = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let node_a = create_full_test_node(
            "node_a",
            "sess-a",
            vec![PeerConfig {
                name: "node_b".to_string(),
                address: format!("127.0.0.1:{port_b}"),
                pin: Some(pin_b.clone()),
                ca: None,
                identities: None,
                allow: vec!["send".to_string(), "reply".to_string()],
                from: None,
                leaf: false,
                principals: Vec::new(),
                targets: None,
                dial: None,
            }],
            None,
            Some((cert_a.clone(), key_a.clone(), pin_a.clone())),
            "dummy",
        )
        .await;

        // Set up real node B files and directories
        let tmp_b = tempdir().unwrap();
        fs::set_permissions(tmp_b.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let cert_file = tmp_b.path().join("cert.pem");
        let key_file = tmp_b.path().join("key.pem");
        let peers_file = tmp_b.path().join("peers.json");
        fs::write(&cert_file, &cert_b_pem).unwrap();
        fs::write(&key_file, &key_b_pem).unwrap();

        let peers_json = serde_json::json!({
            "node_a": {
                "address": node_a.fed_addr.to_string(),
                "pin": pin_a,
                "allow": ["send", "reply", "list"]
            }
        });
        fs::write(&peers_file, peers_json.to_string()).unwrap();

        let sock_dir_b = tmp_b.path().join("run");
        fs::create_dir_all(&sock_dir_b).unwrap();
        fs::set_permissions(&sock_dir_b, fs::Permissions::from_mode(0o700)).unwrap();

        let sessions_dir_b = tmp_b.path().join("sessions");
        fs::create_dir_all(&sessions_dir_b).unwrap();
        fs::set_permissions(&sessions_dir_b, fs::Permissions::from_mode(0o700)).unwrap();

        let db_path_b = tmp_b.path().join("test.db");
        let register_sock_b = sock_dir_b.join("register.sock");
        let agent_sock_b = sock_dir_b.join("agent.sock");
        let http_sock_b = sock_dir_b.join("http.sock");

        let current_exe = std::env::current_exe().unwrap();

        // Spawn node B as real xmsg serve process
        let bin = env!("CARGO_BIN_EXE_xmsg");
        let child = tokio::process::Command::new(bin)
            .env("XDG_RUNTIME_DIR", &sock_dir_b)
            .env("HOME", tmp_b.path())
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--fed-listen",
                &format!("127.0.0.1:{port_b}"),
                "--peers-file",
                peers_file.to_str().unwrap(),
                "--fed-cert",
                cert_file.to_str().unwrap(),
                "--fed-key",
                key_file.to_str().unwrap(),
                "--db-path",
                db_path_b.to_str().unwrap(),
                "--sessions-dir",
                sessions_dir_b.to_str().unwrap(),
                "--register-sock",
                register_sock_b.to_str().unwrap(),
                "--agent-sock",
                agent_sock_b.to_str().unwrap(),
                "--http-sock",
                http_sock_b.to_str().unwrap(),
                "--svc-exe",
                &format!("guard={}", current_exe.display()),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let mut child_guard = ChildGuard(child);

        // Wait for node B to be ready
        let mut ready = false;
        let mut exited = None;
        for _ in 0..600 {
            if let Ok(Some(status)) = child_guard.0.try_wait() {
                exited = Some(status);
                break;
            }
            if register_sock_b.exists()
                && tokio::net::TcpStream::connect(("127.0.0.1", port_b))
                    .await
                    .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if ready {
            return Pair {
                _child: child_guard,
                register_sock_b,
                http_sock_b,
                node_a,
                _tmp_b: tmp_b,
            };
        }

        let mut stderr = String::new();
        if let Some(mut err) = child_guard.0.stderr.take() {
            let _ = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut stderr).await;
        }
        if exited.is_some()
            && (stderr.contains("AddrInUse")
                || stderr.contains("address already in use")
                || stderr.contains("Address already in use")
                || stderr.contains("failed to bind"))
            && attempt < 5
        {
            eprintln!(
                "child node_b lost port {port_b} before binding, retrying (attempt {attempt}): {stderr}"
            );
            continue;
        }
        panic!(
            "child node_b exited prematurely: {:?}, stderr:\n{}",
            exited, stderr
        );
    }
}

/// An opencode plugin connection on `sock` holding `session`; returns its address.
async fn opencode_session(
    sock: &Path,
    session: &str,
) -> (BufReader<OwnedReadHalf>, OwnedWriteHalf, String) {
    let (mut r, mut w) = connect_svc(sock).await;
    w.write_all(b"{\"harness\":\"opencode\"}\n").await.unwrap();
    let hello = read_json_line(&mut r).await;
    assert_eq!(hello["status"], "ok", "{hello}");
    let reg = serde_json::json!({"action":"register","session":session,"request_id":"r1"});
    w.write_all(format!("{reg}\n").as_bytes()).await.unwrap();
    let reg = read_json_line(&mut r).await;
    assert_eq!(reg["status"], "ok", "{reg}");
    let addr = reg["address"].as_str().unwrap().to_string();
    (r, w, addr)
}

/// K1: node_a (in process) sends to an opencode plugin session on node_b (a real `xmsg
/// serve`) over federation; the recipient's reply on its plugin connection is accepted,
/// because node_b records the recipient's own harness, not `pi`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k1_fed_message_to_opencode_is_replied_to() {
    let pair = start_pair().await;
    let (register_sock_b, node_a) = (&pair.register_sock_b, &pair.node_a);

    // An opencode plugin session on node_b, reached over federation.
    let (mut rb, mut wb, addr) = opencode_session(register_sock_b, "ses_fed").await;
    let id = addr.split_once('@').unwrap().0.to_string();

    let send_resp = send_via_agent_sock(
        &node_a.agent_sock,
        &format!("{id}@node_b"),
        "fed to opencode",
    )
    .await;
    assert_eq!(send_resp["status"], "ok", "{send_resp}");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    wb.write_all(b"{\"action\":\"poll\",\"wait\":5,\"request_id\":\"r2\"}\n")
        .await
        .unwrap();
    let got = read_json_line(&mut rb).await;
    assert_eq!(got["message_id"], msg_id.as_str());

    let reply = serde_json::json!({"action":"reply","session":"ses_fed","message_id":msg_id,"text":"answer","request_id":"r3"});
    wb.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
    let rr = read_json_line(&mut rb).await;
    assert_eq!(
        rr["status"], "ok",
        "the recipient may reply to a federated message: {rr}"
    );
}

/// C3 across nodes: a send to an opencode session on node_b answers `queued`, and node_b's
/// record reads `delivered` only once the plugin acks it. node_a's record keeps the answer
/// it got: no `/fed/v2` exchange reports a later delivery (README, Delivery and the queue).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k4_fed_send_to_plugin_is_queued_until_acked() {
    let pair = start_pair().await;
    let (mut rb, mut wb, addr) = opencode_session(&pair.register_sock_b, "ses_acked").await;
    let id = addr.split_once('@').unwrap().0.to_string();

    let sent = send_via_agent_sock(&pair.node_a.agent_sock, &format!("{id}@node_b"), "held").await;
    assert_eq!(sent["status"], "ok", "{sent}");
    assert_eq!(sent["outcome"], "queued", "answered before the ack: {sent}");
    let msg_id = sent["message_id"].as_str().unwrap().to_string();

    let outcome_b = |msg_id: String| {
        let sock = pair.http_sock_b.clone();
        tokio::task::spawn_blocking(move || {
            let (status, text) = xmsg::http::http_request_unix(
                &sock,
                "GET",
                &format!("/v1/messages/{msg_id}"),
                None,
            )
            .unwrap();
            assert_eq!(status.as_u16(), 200, "{text}");
            let v: Value = serde_json::from_str(&text).unwrap();
            v["outcome"].as_str().unwrap().to_string()
        })
    };
    assert_eq!(outcome_b(msg_id.clone()).await.unwrap(), "queued");

    wb.write_all(b"{\"action\":\"poll\",\"wait\":5,\"request_id\":\"r2\"}\n")
        .await
        .unwrap();
    let got = read_json_line(&mut rb).await;
    assert_eq!(got["message_id"], msg_id.as_str(), "{got}");
    let ack = serde_json::json!({"action":"ack","session":"ses_acked","message_id":msg_id,"request_id":"r3"});
    wb.write_all(format!("{ack}\n").as_bytes()).await.unwrap();
    let acked = read_json_line(&mut rb).await;
    assert_eq!(acked["status"], "ok", "{acked}");
    assert_eq!(
        outcome_b(msg_id.clone()).await.unwrap(),
        "delivered",
        "node_b after the ack"
    );

    let rec = xmsg::storage::get_message(&pair.node_a.db.lock().unwrap(), &msg_id)
        .unwrap()
        .expect("node_a's record");
    assert_eq!(rec.outcome, "queued", "node_a keeps the answer it got");
}

/// K3 (a): an opencode session's send to another node is accepted there: the node-to-node
/// wire carries no harness (XA5), so no `invalid harness` refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k3_opencode_sends_to_another_node() {
    let pair = start_pair().await;
    let (mut rb, mut wb, _addr) = opencode_session(&pair.register_sock_b, "ses_out").await;

    let send = serde_json::json!({"action":"send","session":"ses_out","to":"sess-a@node_a","text":"from opencode","request_id":"r2"});
    wb.write_all(format!("{send}\n").as_bytes()).await.unwrap();
    let sent = read_json_line(&mut rb).await;
    assert_eq!(sent["status"], "ok", "{sent}");
    assert_eq!(sent["outcome"], "delivered", "{sent}");

    let mut got = Vec::new();
    for _ in 0..100 {
        got = pair.node_a.inbox_rx.lock().unwrap().clone();
        if !got.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got.iter().any(|m| m.contains("from opencode")),
        "node_a's session received it: {got:?}"
    );
}

/// K3 (b): the mesh list asked on another node includes this node's opencode session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k3_mesh_list_includes_opencode_session() {
    let pair = start_pair().await;
    let (_rb, _wb, addr) = opencode_session(&pair.register_sock_b, "ses_listed").await;
    let id = addr.split_once('@').unwrap().0.to_string();

    let stream = UnixStream::connect(&pair.node_a.agent_sock).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    writer.write_all(b"{\"action\":\"list\"}\n").await.unwrap();
    let listed = read_json_line(&mut reader).await;
    assert_eq!(listed["status"], "ok", "{listed}");
    let entry = listed["recipients"]
        .as_array()
        .expect("recipients")
        .iter()
        .find(|e| e["address"] == format!("{id}@node_b"))
        .cloned();
    let entry = entry.unwrap_or_else(|| panic!("node_b's opencode session is listed: {listed}"));
    assert_eq!(entry["status"], "live", "{entry}");
    assert_eq!(entry["label"], "ses_listed", "{entry}");
}
