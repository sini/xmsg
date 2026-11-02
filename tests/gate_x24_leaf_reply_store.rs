mod short_sock;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, UnixListener, UnixStream};

use axum::http::StatusCode;
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

struct HubFixture {
    _tmp: TempDir,
    #[allow(dead_code)]
    http_port: u16,
    agent_sock: PathBuf,
    db_path: PathBuf,
    sessions_dir: PathBuf,
    #[allow(dead_code)]
    child: ChildGuard,
}

async fn spawn_hub_node(
    _name: &str,
    cert_pem: &str,
    key_pem: &str,
    leaf_name: &str,
    leaf_pin: &str,
    leaf_address: &str,
) -> (HubFixture, u16) {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let fed_port = get_free_port();
        let http_port = get_free_port();

        let tmp = tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let cert_file = tmp.path().join("cert.pem");
        let key_file = tmp.path().join("key.pem");
        let peers_file = tmp.path().join("peers.json");
        let db_path = tmp.path().join("hub.db");

        fs::write(&cert_file, cert_pem.as_bytes()).unwrap();
        fs::write(&key_file, key_pem.as_bytes()).unwrap();

        let peers_json = serde_json::json!({
            leaf_name: {
                "address": leaf_address,
                "pin": normalize_pin(leaf_pin),
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
                &format!("127.0.0.1:{http_port}"),
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
            if agent_sock.exists()
                && tokio::net::TcpStream::connect(("127.0.0.1", fed_port))
                    .await
                    .is_ok()
                && tokio::net::TcpStream::connect(("127.0.0.1", http_port))
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
                HubFixture {
                    _tmp: tmp,
                    http_port,
                    agent_sock,
                    db_path,
                    sessions_dir,
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
                || stderr.contains("failed to bind"))
            && attempt < 5
        {
            eprintln!("hub node lost port before binding, retrying (attempt {attempt}): {stderr}");
            continue;
        }
        panic!(
            "hub node exited prematurely: {:?}, stderr:\n{}",
            exited, stderr
        );
    }
}

struct LeafFixture {
    _tmp: TempDir,
    reg_sock: PathBuf,
    #[allow(dead_code)]
    child: ChildGuard,
}

async fn spawn_leaf_node(
    _name: &str,
    cert_pem: &str,
    key_pem: &str,
    hub_name: &str,
    hub_fed_port: u16,
    hub_pin: &str,
    leaf_principal: &str,
) -> LeafFixture {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let leaf_http_port = get_free_port();

        let tmp = tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let cert_file = tmp.path().join("cert.pem");
        let key_file = tmp.path().join("key.pem");
        let peers_file = tmp.path().join("peers.json");
        let db_path = tmp.path().join("leaf.db");

        fs::write(&cert_file, cert_pem.as_bytes()).unwrap();
        fs::write(&key_file, key_pem.as_bytes()).unwrap();

        let peers_json = serde_json::json!({
            hub_name: {
                "address": format!("127.0.0.1:{hub_fed_port}"),
                "pin": normalize_pin(hub_pin),
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

        let reg_sock = run_dir.join("register.sock");

        let bin = env!("CARGO_BIN_EXE_xmsg");
        let child = tokio::process::Command::new(bin)
            .env("XDG_RUNTIME_DIR", &run_dir)
            .env("HOME", &run_dir)
            .args([
                "serve",
                "--leaf",
                "--leaf-principal",
                leaf_principal,
                "--listen",
                &format!("127.0.0.1:{leaf_http_port}"),
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
                reg_sock.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn leaf node");

        let mut guard = ChildGuard::new(child);

        let mut ready = false;
        let mut exited = None;
        for _ in 0..600 {
            if let Ok(Some(status)) = guard.child_mut().try_wait() {
                exited = Some(status);
                break;
            }
            if reg_sock.exists() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if ready {
            return LeafFixture {
                _tmp: tmp,
                reg_sock,
                child: guard,
            };
        }

        let mut stderr = String::new();
        if let Some(mut err) = guard.child_mut().stderr.take() {
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
                "leaf node lost port {leaf_http_port} before binding, retrying (attempt {attempt}): {stderr}"
            );
            continue;
        }
        panic!(
            "leaf node exited prematurely: {:?}, stderr:\n{}",
            exited, stderr
        );
    }
}

// =============================================================================
// Oracle 1: HTTP caller on the hub sends to svc:<name>@<leaf>, svc replies,
// and caller's GET /v1/messages/{id}/replies?wait= returns the reply text.
// Mutant: restore the NotRecipient refusal for non-push senders in fed_reply_handler => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_http_caller_leaf_reply_stored_and_polled() {
    let (cert_hub, key_hub, pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (cert_leaf, key_leaf, pin_leaf) = generate_self_signed_ed25519_pem("leaf").unwrap();

    let dummy_leaf_port = get_free_port();

    let (hub, fed_port) = spawn_hub_node(
        "hub",
        &cert_hub,
        &key_hub,
        "leaf",
        &pin_leaf,
        &format!("127.0.0.1:{dummy_leaf_port}"),
    )
    .await;

    let leaf = spawn_leaf_node(
        "leaf",
        &cert_leaf,
        &key_leaf,
        "hub",
        fed_port,
        &pin_hub,
        "svc:guard",
    )
    .await;

    // 1. Service daemon connects to leaf's register.sock and registers as guard
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
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

    // 2. HTTP caller on hub sends to svc:guard@leaf
    let client = reqwest::Client::new();
    let send_url = format!("http://127.0.0.1:{}/v1/messages", hub.http_port);
    let send_resp = client
        .post(&send_url)
        .json(&serde_json::json!({"to": "guard@leaf",
            "from": "http-caller",
            "text": "audit request from http caller"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(send_resp.status(), StatusCode::ACCEPTED);
    let send_json: Value = send_resp.json().await.unwrap();
    assert_eq!(send_json["outcome"], "queued");
    let msg_id = send_json["message_id"]
        .as_str()
        .expect("message_id in response")
        .to_string();

    // 3. Svc daemon on leaf polls message
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
    assert_eq!(poll_resp["text"], "audit request from http caller");

    // 4. Svc daemon acks and replies over register.sock
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
        "text": "audit approved by guard for http",
    });
    writer
        .write_all(format!("{reply_frame}\n").as_bytes())
        .await
        .unwrap();
    let reply_resp = read_json_line(&mut reader).await;
    assert_eq!(reply_resp["status"], "ok");

    // 5. HTTP caller reads replies via GET /v1/messages/{id}/replies?wait=5
    let replies_url = format!(
        "http://127.0.0.1:{}/v1/messages/{msg_id}/replies?wait=5",
        hub.http_port
    );
    let replies_resp = client.get(&replies_url).send().await.unwrap();
    assert_eq!(replies_resp.status(), StatusCode::OK);
    let replies_json: Value = replies_resp.json().await.unwrap();
    let replies_arr = replies_json.as_array().expect("array of replies");
    assert_eq!(replies_arr.len(), 1, "Expected 1 stored reply");
    assert_eq!(
        replies_arr[0]["text"], "audit approved by guard for http",
        "Reply text must match"
    );

    // 6. Verify SQLite storage on hub: the anonymous sender has no inbox, so the reply is
    // stored for `replies` (A10)
    let conn = rusqlite::Connection::open(&hub.db_path).unwrap();
    let replies = xmsg::storage::get_all_replies(&conn, &msg_id).unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(
        replies[0].push_outcome.as_deref(),
        Some("stored"),
        "Stored reply push_outcome must be 'stored'"
    );
    assert_eq!(replies[0].text, "audit approved by guard for http");
}

// =============================================================================
// Oracle 2: Attested sender on hub (bot shape; A10 removed its push opt-out)
// sends to svc:<name>@<leaf>, svc replies, caller reads it via replies endpoint.
// Mutant: restore the NotRecipient refusal for non-push senders => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_attested_sender_reply_stored_and_readable() {
    let (cert_hub, key_hub, pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (cert_leaf, key_leaf, pin_leaf) = generate_self_signed_ed25519_pem("leaf").unwrap();

    let dummy_leaf_port = get_free_port();

    let (hub, fed_port) = spawn_hub_node(
        "hub",
        &cert_hub,
        &key_hub,
        "leaf",
        &pin_leaf,
        &format!("127.0.0.1:{dummy_leaf_port}"),
    )
    .await;

    let leaf = spawn_leaf_node(
        "leaf",
        &cert_leaf,
        &key_leaf,
        "hub",
        fed_port,
        &pin_hub,
        "svc:guard",
    )
    .await;

    // 1. Create attested session fixture for bot
    let (_sock_bot, _rx_bot) = create_claude_session_fixture(&hub.sessions_dir, "sess-bot", "bot");

    // 2. Service daemon registers on leaf
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
    let reg_frame = serde_json::json!({ "harness": "svc", "name": "guard" });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(reg_resp["status"], "ok");

    // 3. Attested sender sends
    let send_resp =
        send_via_agent_sock(&hub.agent_sock, "guard@leaf", "bot query without push").await;
    assert_eq!(send_resp["status"], "ok");
    assert_eq!(send_resp["outcome"], "queued");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    // 3. Svc polls and delivers
    let poll_frame = serde_json::json!({ "action": "poll", "waitSecs": 5 });
    writer
        .write_all(format!("{poll_frame}\n").as_bytes())
        .await
        .unwrap();
    let poll_resp = read_json_line(&mut reader).await;
    assert_eq!(poll_resp["action"], "deliver");
    assert_eq!(poll_resp["messageId"], msg_id);

    // 4. Svc acks and replies
    let ack_frame = serde_json::json!({ "action": "ack", "messageId": msg_id });
    writer
        .write_all(format!("{ack_frame}\n").as_bytes())
        .await
        .unwrap();
    let ack_resp = read_json_line(&mut reader).await;
    assert_eq!(ack_resp["status"], "ok");

    let reply_frame = serde_json::json!({
        "action": "reply",
        "messageId": msg_id,
        "text": "bot answer from guard",
    });
    writer
        .write_all(format!("{reply_frame}\n").as_bytes())
        .await
        .unwrap();
    let reply_resp = read_json_line(&mut reader).await;
    assert_eq!(reply_resp["status"], "ok");

    // 5. Attested sender polls replies via GET /v1/messages/{id}/replies?wait=5
    let client = reqwest::Client::new();
    let replies_url = format!(
        "http://127.0.0.1:{}/v1/messages/{msg_id}/replies?wait=5",
        hub.http_port
    );
    let replies_resp = client.get(&replies_url).send().await.unwrap();
    assert_eq!(replies_resp.status(), StatusCode::OK);
    let replies_json: Value = replies_resp.json().await.unwrap();
    let replies_arr = replies_json.as_array().expect("array of replies");
    assert_eq!(replies_arr.len(), 1);
    assert_eq!(replies_arr[0]["text"], "bot answer from guard");

    // 6. The attested sender has an inbox, so the reply was also pushed to it (A10: no
    // opt-out); it stays stored for `replies` either way.
    let conn = rusqlite::Connection::open(&hub.db_path).unwrap();
    let replies = xmsg::storage::get_all_replies(&conn, &msg_id).unwrap();
    assert_eq!(replies.len(), 1);
    assert_ne!(
        replies[0].push_outcome.as_deref(),
        Some("stored"),
        "{:?}",
        replies[0]
    );
}

// =============================================================================
// Oracle 3: GET /v1/messages/{id}/replies for a leaf message makes 0 outbound connections.
// Assert on observable: tripwire_connections on peer address.
// Mutant: proxy as before (remove is_leaf bypass in get_replies_handler) => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_leaf_replies_get_makes_zero_outbound_connections() {
    let (cert_hub, key_hub, _pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (_cert_leaf, _key_leaf, pin_leaf) = generate_self_signed_ed25519_pem("leaf").unwrap();

    // Bind a TCP tripwire on the address assigned to leaf peer in hub's peers.json
    let tripwire = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tripwire_port = tripwire.local_addr().unwrap().port();
    let tripwire_connections = Arc::new(AtomicU64::new(0));
    let tripwire_clone = tripwire_connections.clone();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tripwire.accept().await {
            tripwire_clone.fetch_add(1, Ordering::SeqCst);
            let _ = stream.shutdown().await;
        }
    });

    let (hub, _fed_port) = spawn_hub_node(
        "hub",
        &cert_hub,
        &key_hub,
        "leaf",
        &pin_leaf,
        &format!("127.0.0.1:{tripwire_port}"),
    )
    .await;

    // Send a message via HTTP to create outbound record pointing to leaf
    let client = reqwest::Client::new();
    let send_url = format!("http://127.0.0.1:{}/v1/messages", hub.http_port);
    let send_resp = client
        .post(&send_url)
        .json(&serde_json::json!({"to": "guard@leaf",
            "from": "http-caller",
            "text": "message for tripwire check"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(send_resp.status(), StatusCode::ACCEPTED);
    let send_json: Value = send_resp.json().await.unwrap();
    let msg_id = send_json["message_id"]
        .as_str()
        .expect("message_id in response")
        .to_string();

    // Now issue GET /v1/messages/{msg_id}/replies?wait=1 on the hub
    let replies_url = format!(
        "http://127.0.0.1:{}/v1/messages/{msg_id}/replies?wait=1",
        hub.http_port
    );
    let replies_resp = client.get(&replies_url).send().await.unwrap();

    // Assert: status is OK (did NOT attempt to proxy and fail with PeerUnreachable/502)
    assert_eq!(
        replies_resp.status(),
        StatusCode::OK,
        "Must return 200 OK without proxy failure"
    );

    // Assert observable: tripwire_connections is exactly 0!
    let conns = tripwire_connections.load(Ordering::SeqCst);
    assert_eq!(
        conns, 0,
        "Observable tripwire_connections must be 0: leaf replies GET must never dial outbound"
    );
}

// =============================================================================
// Oracle 4: Push-capable sender still gets the reply pushed, exactly once.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_push_capable_sender_gets_pushed_exactly_once() {
    let (cert_hub, key_hub, pin_hub) = generate_self_signed_ed25519_pem("hub").unwrap();
    let (cert_leaf, key_leaf, pin_leaf) = generate_self_signed_ed25519_pem("leaf").unwrap();

    let dummy_leaf_port = get_free_port();

    let (hub, fed_port) = spawn_hub_node(
        "hub",
        &cert_hub,
        &key_hub,
        "leaf",
        &pin_leaf,
        &format!("127.0.0.1:{dummy_leaf_port}"),
    )
    .await;

    let leaf = spawn_leaf_node(
        "leaf",
        &cert_leaf,
        &key_leaf,
        "hub",
        fed_port,
        &pin_hub,
        "svc:guard",
    )
    .await;

    // 1. Create push-capable Claude session fixture on hub
    let (_sock_alice, rx_alice) =
        create_claude_session_fixture(&hub.sessions_dir, "sess-alice", "alice");

    // 2. Service daemon registers on leaf
    let (mut reader, mut writer) = connect_svc(&leaf.reg_sock).await;
    let reg_frame = serde_json::json!({ "harness": "svc", "name": "guard" });
    writer
        .write_all(format!("{reg_frame}\n").as_bytes())
        .await
        .unwrap();
    let reg_resp = read_json_line(&mut reader).await;
    assert_eq!(reg_resp["status"], "ok");

    // 3. Alice on hub sends to svc:guard@leaf with push_replies: true
    let send_resp =
        send_via_agent_sock(&hub.agent_sock, "guard@leaf", "audit request with push").await;
    assert_eq!(send_resp["status"], "ok");
    assert_eq!(send_resp["outcome"], "queued");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    // 4. Svc on leaf polls message
    let poll_frame = serde_json::json!({ "action": "poll", "waitSecs": 5 });
    writer
        .write_all(format!("{poll_frame}\n").as_bytes())
        .await
        .unwrap();
    let poll_resp = read_json_line(&mut reader).await;
    assert_eq!(poll_resp["action"], "deliver");
    assert_eq!(poll_resp["messageId"], msg_id);

    // 5. Svc acks and replies
    let ack_frame = serde_json::json!({ "action": "ack", "messageId": msg_id });
    writer
        .write_all(format!("{ack_frame}\n").as_bytes())
        .await
        .unwrap();
    let ack_resp = read_json_line(&mut reader).await;
    assert_eq!(ack_resp["status"], "ok");

    let reply_frame = serde_json::json!({
        "action": "reply",
        "messageId": msg_id,
        "text": "pushed approval for alice",
    });
    writer
        .write_all(format!("{reply_frame}\n").as_bytes())
        .await
        .unwrap();
    let reply_resp = read_json_line(&mut reader).await;
    assert_eq!(reply_resp["status"], "ok");

    // 6. Alice receives pushed reply on inbox socket
    let mut matching_pushes = Vec::new();
    for _ in 0..100 {
        let lines = rx_alice.lock().unwrap().clone();
        matching_pushes = lines
            .into_iter()
            .filter(|l| l.contains(&format!("reply to message_id={msg_id}")))
            .collect();
        if !matching_pushes.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        matching_pushes.len(),
        1,
        "Alice must receive pushed reply exactly once"
    );
    assert!(
        matching_pushes[0].contains("pushed approval for alice"),
        "Pushed reply text must match"
    );

    // 7. Verify SQLite storage on hub: push_outcome == "pushed"
    let conn = rusqlite::Connection::open(&hub.db_path).unwrap();
    let replies = xmsg::storage::get_all_replies(&conn, &msg_id).unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(
        replies[0].push_outcome.as_deref(),
        Some("pushed"),
        "Stored reply push_outcome must be 'pushed'"
    );
    assert_eq!(replies[0].text, "pushed approval for alice");
}
