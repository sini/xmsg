mod short_sock;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use serde_json::Value;

use xmsg::fed::{generate_self_signed_ed25519_pem, normalize_pin};

struct ChildGuard(Option<tokio::process::Child>);

impl ChildGuard {
    fn new(child: tokio::process::Child) -> Self {
        Self(Some(child))
    }
    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.0.as_mut().unwrap()
    }
    fn take(&mut self) -> Option<tokio::process::Child> {
        self.0.take()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.start_kill();
        }
    }
}

fn get_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().expect("local addr").port()
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

async fn reply_via_agent_sock(agent_sock: &Path, message_id: &str, text: &str) -> Value {
    let stream = UnixStream::connect(agent_sock).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let reply_req = serde_json::json!({
        "action": "reply",
        "message_id": message_id,
        "text": text,
    });
    writer
        .write_all(format!("{reply_req}\n").as_bytes())
        .await
        .unwrap();

    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(&resp_line).expect("valid json response from agent.sock")
}

fn create_claude_session_fixture(
    sessions_dir: &Path,
    session_id: &str,
    name: &str,
) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let sock_path = short_sock::sock_path(sessions_dir, "inbox");
    let listener = UnixListener::bind(&sock_path).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = received.clone();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    let my_pid = std::process::id();
    let live_proc = PathBuf::from(xmsg::process::LIVE_PROC_ROOT);
    let my_proc_start =
        xmsg::process::starttime(&live_proc, my_pid).unwrap_or_else(|_| "1000".to_string());
    let session_uuid = if xmsg::claim::is_uuid_shaped(session_id) {
        session_id.to_string()
    } else {
        use sha2::{Digest, Sha256};
        let h = hex::encode(Sha256::digest(session_id.as_bytes()));
        format!(
            "{}-{}-4{}-a{}-{}",
            &h[0..8],
            &h[8..12],
            &h[13..16],
            &h[17..20],
            &h[20..32]
        )
    };
    let session_json = serde_json::json!({
        "pid": my_pid,
        "sessionId": session_uuid,
        "name": name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": my_proc_start,
        "messagingSocketPath": sock_path.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{my_pid}-{session_id}.json")),
        session_json.to_string(),
    )
    .unwrap();

    (sock_path, received)
}

struct NodeFixture {
    _tmp: TempDir,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    sessions_dir: PathBuf,
    db_path: PathBuf,
    #[allow(dead_code)]
    child: ChildGuard,
}

async fn spawn_hub_node(
    _name: &str,
    cert_pem: &str,
    key_pem: &str,
    client_name: &str,
    client_pin: &str,
) -> (NodeFixture, u16) {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let fed_port = get_free_port();

        let tmp = tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let cert_file = tmp.path().join("cert.pem");
        let key_file = tmp.path().join("key.pem");
        let peers_file = tmp.path().join("peers.json");
        let db_path = tmp.path().join("hub.db");

        fs::write(&cert_file, cert_pem.as_bytes()).unwrap();
        fs::write(&key_file, key_pem.as_bytes()).unwrap();

        let peers_json = serde_json::json!({
            client_name: {
                "address": "127.0.0.1:0",
                "pin": normalize_pin(client_pin),
                "leaf": true,
                "allow": ["send", "reply", "inbox"]
            }
        });
        fs::write(&peers_file, peers_json.to_string()).unwrap();

        let run_dir = tmp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let sessions_dir = tmp.path().join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();
        fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let agent_sock = run_dir.join("agent.sock");
        let register_sock = run_dir.join("register.sock");
        let http_sock = run_dir.join("http.sock");

        let bin = env!("CARGO_BIN_EXE_xmsg");
        let child = tokio::process::Command::new(bin)
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env("HOME", &run_dir)
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--fed-listen",
                &format!("127.0.0.1:{fed_port}"),
                "--peers-file",
                peers_file.to_str().unwrap(),
                "--fed-cert",
                cert_file.to_str().unwrap(),
                "--fed-key",
                key_file.to_str().unwrap(),
                "--db-path",
                db_path.to_str().unwrap(),
                "--sessions-dir",
                sessions_dir.to_str().unwrap(),
                "--register-sock",
                register_sock.to_str().unwrap(),
                "--agent-sock",
                agent_sock.to_str().unwrap(),
                "--http-sock",
                http_sock.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn hub node");

        let mut guard = ChildGuard::new(child);

        let mut ready = false;
        let mut exited = None;
        for _ in 0..600 {
            if let Ok(Some(status)) = guard.child_mut().try_wait() {
                exited = Some(status);
                break;
            }
            if std::os::unix::net::UnixStream::connect(&agent_sock).is_ok()
                && tokio::net::TcpStream::connect(("127.0.0.1", fed_port))
                    .await
                    .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if ready {
            return (
                NodeFixture {
                    _tmp: tmp,
                    agent_sock,
                    register_sock,
                    sessions_dir,
                    db_path,
                    child: guard,
                },
                fed_port,
            );
        }

        let mut stderr = String::new();
        if let Some(mut err) = guard.child_mut().stderr.take() {
            let _ = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut stderr).await;
        }
        if exited.is_some()
            && (stderr.contains("AddrInUse")
                || stderr.contains("address already in use")
                || stderr.contains("Address already in use")
                || stderr.contains("failed to bind federation listener"))
            && attempt < 5
        {
            eprintln!(
                "hub node lost port {fed_port} before binding, retrying (attempt {attempt}): {stderr}"
            );
            continue;
        }
        panic!(
            "hub node exited prematurely: {:?}, stderr:\n{}",
            exited, stderr
        );
    }
}

async fn spawn_client_node(
    _name: &str,
    cert_pem: &str,
    key_pem: &str,
    hub_name: &str,
    hub_port: u16,
    hub_pin: &str,
    extra_svc_exe: Option<String>,
) -> NodeFixture {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");
    let db_path = tmp.path().join("client.db");

    fs::write(&cert_file, cert_pem.as_bytes()).unwrap();
    fs::write(&key_file, key_pem.as_bytes()).unwrap();

    let peers_json = serde_json::json!({
        hub_name: {
            "address": format!("127.0.0.1:{hub_port}"),
            "pin": normalize_pin(hub_pin),
            "dial": "outbound",
            "allow": ["send", "reply", "inbox"]
        }
    });
    fs::write(&peers_file, peers_json.to_string()).unwrap();

    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let mut cmd = tokio::process::Command::new(bin);
    cmd.env("XDG_RUNTIME_DIR", &run_dir).env("HOME", &run_dir);
    cmd.args([
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--peers-file",
        peers_file.to_str().unwrap(),
        "--fed-cert",
        cert_file.to_str().unwrap(),
        "--fed-key",
        key_file.to_str().unwrap(),
        "--db-path",
        db_path.to_str().unwrap(),
        "--sessions-dir",
        sessions_dir.to_str().unwrap(),
        "--register-sock",
        register_sock.to_str().unwrap(),
        "--agent-sock",
        agent_sock.to_str().unwrap(),
        "--http-sock",
        http_sock.to_str().unwrap(),
    ]);

    if let Some(svc_exe) = extra_svc_exe {
        cmd.args(["--svc-exe", &svc_exe]);
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = cmd.spawn().expect("spawn client node");
    let mut guard = ChildGuard::new(child);

    let mut ready = false;
    for _ in 0..600 {
        if let Ok(Some(status)) = guard.child_mut().try_wait() {
            let mut stderr = String::new();
            if let Some(mut err) = guard.child_mut().stderr.take() {
                let _ = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut stderr).await;
            }
            panic!(
                "client node exited prematurely: {:?}, stderr:\n{}",
                status, stderr
            );
        }
        if std::os::unix::net::UnixStream::connect(&agent_sock).is_ok() && std::os::unix::net::UnixStream::connect(&register_sock).is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "client node failed to become ready");

    NodeFixture {
        _tmp: tmp,
        agent_sock,
        register_sock,
        sessions_dir,
        db_path,
        child: guard,
    }
}

// -----------------------------------------------------------------------------
// Oracle 1: Inbound over outbound link
// Session on H sends to session on C, C delivers locally and replies, H receives reply.
// Mutant in src/main.rs: don't spawn outbound peer pull loop => RED
// -----------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_inbound_over_outbound_link() {
    let (cert_hub, key_hub, pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (cert_client, key_client, pin_client) = generate_self_signed_ed25519_pem("client").unwrap();

    let (hub, hub_port) = spawn_hub_node("hub", &cert_hub, &key_hub, "client", &pin_client).await;
    let client = spawn_client_node(
        "client",
        &cert_client,
        &key_client,
        "hub",
        hub_port,
        &pin_hub,
        None,
    )
    .await;

    // Register c30386d2-5a5b-5831-9948-06e077643f3a on hub and b8110187-e017-573c-a03b-abdc22a07b86 on client
    let (_sock_alice, rx_alice) = create_claude_session_fixture(
        &hub.sessions_dir,
        "c30386d2-5a5b-5831-9948-06e077643f3a",
        "alice",
    );
    let (_sock_bob, rx_bob) = create_claude_session_fixture(
        &client.sessions_dir,
        "b8110187-e017-573c-a03b-abdc22a07b86",
        "bob",
    );

    // 1. Alice on hub sends to b8110187-e017-573c-a03b-abdc22a07b86@client
    let send_resp = send_via_agent_sock(
        &hub.agent_sock,
        "b8110187-e017-573c-a03b-abdc22a07b86@client",
        "hello bob from hub",
    )
    .await;
    assert_eq!(send_resp["status"], "ok");
    assert_eq!(send_resp["outcome"], "queued");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    // 2. Client's pull loop pulls from hub and delivers to Bob
    let mut got_message = false;
    for _ in 0..100 {
        let lines = rx_bob.lock().unwrap().clone();
        if let Some(line) = lines.iter().find(|l| l.contains(&msg_id)) {
            assert!(line.contains("hello bob from hub"));
            got_message = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_message,
        "Bob on client node should receive message from hub"
    );

    // 3. Bob on client replies to msg_id
    let reply_resp =
        reply_via_agent_sock(&client.agent_sock, &msg_id, "hello alice from client").await;
    assert_eq!(reply_resp["status"], "ok");

    // 4. Client posts reply back to hub; Alice receives reply
    let mut got_reply = false;
    for _ in 0..100 {
        let lines = rx_alice.lock().unwrap().clone();
        if let Some(line) = lines
            .iter()
            .find(|l| l.contains(&format!("reply to message_id={msg_id}")))
        {
            assert!(line.contains("hello alice from client"));
            got_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_reply,
        "Alice on hub should receive reply from Bob over outbound link"
    );
}

// -----------------------------------------------------------------------------
// Oracle 2: Outbound send from undialable node
// Session on C sends to H, H replies, C pulls reply and delivers locally.
// Mutant in src/agent.rs: drop spawn_outbound_reply_poller => RED
// -----------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_outbound_send_from_undialable_node() {
    let (cert_hub, key_hub, pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (cert_client, key_client, pin_client) = generate_self_signed_ed25519_pem("client").unwrap();

    let (hub, hub_port) = spawn_hub_node("hub", &cert_hub, &key_hub, "client", &pin_client).await;
    let client = spawn_client_node(
        "client",
        &cert_client,
        &key_client,
        "hub",
        hub_port,
        &pin_hub,
        None,
    )
    .await;

    let (_sock_alice, rx_alice) = create_claude_session_fixture(
        &hub.sessions_dir,
        "c30386d2-5a5b-5831-9948-06e077643f3a",
        "alice",
    );
    let (_sock_bob, rx_bob) = create_claude_session_fixture(
        &client.sessions_dir,
        "b8110187-e017-573c-a03b-abdc22a07b86",
        "bob",
    );

    // 1. Bob on undialable node sends to c30386d2-5a5b-5831-9948-06e077643f3a@hub
    let send_resp = send_via_agent_sock(
        &client.agent_sock,
        "c30386d2-5a5b-5831-9948-06e077643f3a@hub",
        "hello alice from bob",
    )
    .await;
    assert_eq!(send_resp["status"], "ok");
    assert_eq!(send_resp["outcome"], "delivered");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    // 2. Alice on hub receives message
    let mut got_message = false;
    for _ in 0..100 {
        let lines = rx_alice.lock().unwrap().clone();
        if let Some(line) = lines.iter().find(|l| l.contains(&msg_id)) {
            assert!(line.contains("hello alice from bob"));
            got_message = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_message,
        "Alice on hub should receive message from client"
    );

    // 3. Alice on hub replies to msg_id
    let reply_resp = reply_via_agent_sock(&hub.agent_sock, &msg_id, "hello bob from alice").await;
    assert_eq!(reply_resp["status"], "ok");

    // 4. Client's background reply poller polls hub and delivers reply to Bob
    let mut got_reply = false;
    for _ in 0..100 {
        let lines = rx_bob.lock().unwrap().clone();
        if let Some(line) = lines
            .iter()
            .find(|l| l.contains(&format!("reply to message_id={msg_id}")))
        {
            assert!(line.contains("hello bob from alice"));
            got_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_reply,
        "Bob on undialable client should receive polled reply from Alice"
    );
}

// -----------------------------------------------------------------------------
// Oracle 3: svc too
// svc registered on C receives send from H and replies over register.sock
// Mutant in src/fed.rs deliver_to_resolved_target: comment out Svc delivery => RED
// -----------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_svc_over_outbound_link() {
    let (cert_hub, key_hub, pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (cert_client, key_client, pin_client) = generate_self_signed_ed25519_pem("client").unwrap();

    let current_exe = std::env::current_exe().unwrap();
    let svc_exe_arg = format!("guard={}", current_exe.display());

    let (hub, hub_port) = spawn_hub_node("hub", &cert_hub, &key_hub, "client", &pin_client).await;
    let client = spawn_client_node(
        "client",
        &cert_client,
        &key_client,
        "hub",
        hub_port,
        &pin_hub,
        Some(svc_exe_arg),
    )
    .await;

    let (_sock_alice, rx_alice) =
        create_claude_session_fixture(&hub.sessions_dir, "sess-alice", "alice");

    // 1. Connect svc daemon to client's register.sock and register svc:guard
    let (mut reader, mut writer) = connect_svc(&client.register_sock).await;
    let reg_frame = serde_json::json!({
        "harness": "svc",
        "name": "guard",
    });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(reg_resp["status"], "ok");
    assert!(
        reg_resp["address"]
            .as_str()
            .is_some_and(|a| a.starts_with("guard@")),
        "{reg_resp}"
    );

    // 2. Alice on hub sends to svc:guard@client
    let send_resp =
        send_via_agent_sock(&hub.agent_sock, "guard@client", "audit request from hub").await;
    assert_eq!(send_resp["status"], "ok");
    assert_eq!(send_resp["outcome"], "queued");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    // 3. Service guard on client polls and receives message
    let poll_frame = serde_json::json!({
        "action": "poll",
        "waitSecs": 5,
    });
    writer
        .write_all(format!("{poll_frame}\n").as_bytes())
        .await
        .unwrap();
    let poll_resp = read_json_line(&mut reader).await;
    assert_eq!(poll_resp["action"], "deliver");
    assert_eq!(poll_resp["messageId"], msg_id);
    assert_eq!(poll_resp["text"], "audit request from hub");

    // 4. Service acks and replies over register.sock
    let ack_frame = serde_json::json!({
        "action": "ack",
        "messageId": msg_id,
    });
    writer
        .write_all(format!("{ack_frame}\n").as_bytes())
        .await
        .unwrap();
    let ack_resp = read_json_line(&mut reader).await;
    assert_eq!(ack_resp["status"], "ok");

    let reply_frame = serde_json::json!({
        "action": "reply",
        "messageId": msg_id,
        "text": "approved by guard service",
    });
    writer
        .write_all(format!("{reply_frame}\n").as_bytes())
        .await
        .unwrap();
    let reply_resp = read_json_line(&mut reader).await;
    assert_eq!(reply_resp["status"], "ok");

    // 5. Alice on hub receives svc reply
    let mut got_reply = false;
    for _ in 0..100 {
        let lines = rx_alice.lock().unwrap().clone();
        if let Some(line) = lines
            .iter()
            .find(|l| l.contains(&format!("reply to message_id={msg_id}")))
        {
            assert!(line.contains("approved by guard service"));
            got_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_reply,
        "Alice on hub should receive reply from svc:guard"
    );
}

// -----------------------------------------------------------------------------
// Oracle 4: Off by default
// Node without outbound peer starts no pull loop; assert absence of "starting outbound link pull loop" log
// Mutant in src/main.rs: start loop unconditionally => RED
// -----------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_4_off_by_default_no_pull_loop() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");
    let db_path = tmp.path().join("node.db");

    let (cert_pem, key_pem, _own_pin) = generate_self_signed_ed25519_pem("plain-node").unwrap();
    fs::write(&cert_file, cert_pem).unwrap();
    fs::write(&key_file, key_pem).unwrap();
    // XA2 (AM-6): a node may not pin its own key, so the peer has a key of its own.
    let (_, _, pin) = generate_self_signed_ed25519_pem("peer-regular").unwrap();
    let peers_content = serde_json::json!({
        "peer-regular": {
            "address": "127.0.0.1:49999",
            "pin": normalize_pin(&pin)
        }
    });
    fs::write(&peers_file, peers_content.to_string()).unwrap();

    let run_dir = tmp.path().join("run");
    fs::create_dir_all(&run_dir).unwrap();
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock = run_dir.join("agent.sock");
    let register_sock = run_dir.join("register.sock");
    let http_sock = run_dir.join("http.sock");

    let bin = env!("CARGO_BIN_EXE_xmsg");
    let child = tokio::process::Command::new(bin)
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("HOME", &run_dir)
        .env("RUST_LOG", "info")
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--peers-file",
            peers_file.to_str().unwrap(),
            "--fed-cert",
            cert_file.to_str().unwrap(),
            "--fed-key",
            key_file.to_str().unwrap(),
            "--db-path",
            db_path.to_str().unwrap(),
            "--sessions-dir",
            sessions_dir.to_str().unwrap(),
            "--register-sock",
            register_sock.to_str().unwrap(),
            "--agent-sock",
            agent_sock.to_str().unwrap(),
            "--http-sock",
            http_sock.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn plain node");

    let mut guard = ChildGuard::new(child);

    // Wait until ready
    let mut ready = false;
    for _ in 0..600 {
        if let Ok(Some(status)) = guard.child_mut().try_wait() {
            let mut stderr = String::new();
            if let Some(mut err) = guard.child_mut().stderr.take() {
                let _ = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut stderr).await;
            }
            panic!(
                "plain node exited prematurely: {:?}, stderr:\n{}",
                status, stderr
            );
        }
        if std::os::unix::net::UnixStream::connect(&agent_sock).is_ok() && std::os::unix::net::UnixStream::connect(&register_sock).is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "plain node failed to become ready");

    // Let node run briefly
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Kill node and inspect stderr
    let mut child = guard.take().unwrap();
    let _ = child.start_kill();
    let output = child.wait_with_output().await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let all_logs = format!("{stderr}\n{stdout}");

    assert!(
        !all_logs.contains("starting outbound link pull loop"),
        "Oracle 4 violation: node without outbound peer must NOT log 'starting outbound link pull loop'"
    );
}

// -----------------------------------------------------------------------------
// Oracle 5: Unknown ref
// H sends to nosuch@C; H receives not_found error reply and mailbox is acked.
// Mutant in src/fed.rs: unresolvable branch doesn't send error reply => RED
// -----------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_unknown_ref_acked_and_error_reply() {
    let (cert_hub, key_hub, pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (cert_client, key_client, pin_client) = generate_self_signed_ed25519_pem("client").unwrap();

    let (hub, hub_port) = spawn_hub_node("hub", &cert_hub, &key_hub, "client", &pin_client).await;
    let _client = spawn_client_node(
        "client",
        &cert_client,
        &key_client,
        "hub",
        hub_port,
        &pin_hub,
        None,
    )
    .await;

    let (_sock_alice, rx_alice) =
        create_claude_session_fixture(&hub.sessions_dir, "sess-alice", "alice");

    // 1. Alice on hub sends to unresolvable ref nosuch@client
    let send_resp = send_via_agent_sock(&hub.agent_sock, "nosuch@client", "hello nobody").await;
    assert_eq!(send_resp["status"], "ok");
    assert_eq!(send_resp["outcome"], "queued");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    // 2. Client pull loop fetches message, fails resolution, posts not_found error reply to hub, and acks
    let mut got_error_reply = false;
    for _ in 0..100 {
        let lines = rx_alice.lock().unwrap().clone();
        if let Some(line) = lines
            .iter()
            .find(|l| l.contains(&format!("reply to message_id={msg_id}")))
        {
            assert!(
                line.contains("not_found"),
                "Reply should contain error code 'not_found', got: {line}"
            );
            assert!(
                line.contains("no live session matches 'nosuch'"),
                "Reply should contain direct send error format, got: {line}"
            );
            got_error_reply = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        got_error_reply,
        "Alice on hub should receive not_found error reply for unresolvable ref"
    );

    // 3. Verify message is acked and deleted from hub's mailbox
    // Query hub's sqlite db to verify peer_mailbox table has 0 rows for client
    let mut mailbox_empty = false;
    for _ in 0..50 {
        if let Ok(conn) = rusqlite::Connection::open(&hub.db_path) {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM peer_mailbox WHERE peer = 'client'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(1);
            if count == 0 {
                mailbox_empty = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        mailbox_empty,
        "Hub mailbox for client should be acked and empty"
    );
}

// -----------------------------------------------------------------------------
// Oracle 6: an ack that lands while the dial-out client is still delivering
// The client's database acks a service's message the moment it is queued (a trigger on
// `svc_pending_messages` doing what `storage::ack_svc_message` does), so the ack lands
// before `deliver` returns. The client's record still ends `delivered`.
// Mutant in src/fed.rs run_outbound_peer_pull_loop: write the record only after
// delivery => RED (the ack finds no row, and the record reads `queued` forever).
// -----------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_an_ack_during_delivery_is_kept() {
    let (cert_hub, key_hub, pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (cert_client, key_client, pin_client) = generate_self_signed_ed25519_pem("client").unwrap();

    let current_exe = std::env::current_exe().unwrap();
    let (hub, hub_port) = spawn_hub_node("hub", &cert_hub, &key_hub, "client", &pin_client).await;
    let client = spawn_client_node(
        "client",
        &cert_client,
        &key_client,
        "hub",
        hub_port,
        &pin_hub,
        Some(format!("guard={}", current_exe.display())),
    )
    .await;

    let (_sock_alice, _rx_alice) =
        create_claude_session_fixture(&hub.sessions_dir, "sess-alice", "alice");

    let (mut reader, mut writer) = connect_svc(&client.register_sock).await;
    writer
        .write_all(
            format!(
                "{}\n",
                serde_json::json!({"harness": "svc", "name": "guard"})
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(read_json_line(&mut reader).await["status"], "ok");

    rusqlite::Connection::open(&client.db_path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER ack_on_queue AFTER INSERT ON svc_pending_messages BEGIN
               UPDATE svc_pending_messages SET delivered_at = 1 WHERE id = NEW.id;
               UPDATE messages SET outcome = 'delivered' WHERE id = NEW.id;
             END;",
        )
        .unwrap();

    let send_resp = send_via_agent_sock(&hub.agent_sock, "guard@client", "acked at once").await;
    assert_eq!(send_resp["outcome"], "queued", "{send_resp}");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    // The client acks the hub only after recording, so an empty hub mailbox means the
    // client's record is final.
    let mut outcome = None;
    for _ in 0..200 {
        let hub_conn = rusqlite::Connection::open(&hub.db_path).unwrap();
        let left: i64 = hub_conn
            .query_row(
                "SELECT COUNT(*) FROM peer_mailbox WHERE id = ?1",
                [&msg_id],
                |r| r.get(0),
            )
            .unwrap_or(1);
        if left == 0 {
            outcome = rusqlite::Connection::open(&client.db_path)
                .unwrap()
                .query_row(
                    "SELECT outcome FROM messages WHERE id = ?1",
                    [&msg_id],
                    |r| r.get::<_, String>(0),
                )
                .ok();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(outcome.as_deref(), Some("delivered"));
}
