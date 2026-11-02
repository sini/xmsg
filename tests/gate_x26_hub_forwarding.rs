mod short_sock;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use serde_json::Value;
use xmsg::fed::{generate_self_signed_ed25519, generate_self_signed_ed25519_pem, normalize_pin};

mod hop_client;
use hop_client::{hop_send, Origin};

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

async fn send_via_agent_sock(agent_sock: &Path, target_ref: &str, text: &str) -> Value {
    let stream = UnixStream::connect(agent_sock)
        .await
        .expect("connect to agent.sock");
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
    let stream = UnixStream::connect(agent_sock)
        .await
        .expect("connect to agent.sock");
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

async fn wait_for_inbox_message(
    received: &Arc<Mutex<Vec<String>>>,
    timeout_dur: Duration,
) -> Option<String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout_dur {
        {
            let guard = received.lock().unwrap();
            if let Some(msg) = guard.first() {
                return Some(msg.clone());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[allow(dead_code)]
struct TestNode {
    _tmp: TempDir,
    name: String,
    fed_port: u16,
    http_port: u16,
    agent_sock: PathBuf,
    sessions_dir: PathBuf,
    db_path: PathBuf,
    child: ChildGuard,
}

async fn spawn_test_node(
    name: &str,
    fed_port: u16,
    http_port: u16,
    cert_pem: &str,
    key_pem: &str,
    peers_json: Value,
) -> TestNode {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");
    let db_path = tmp.path().join("node.db");

    fs::write(&cert_file, cert_pem.as_bytes()).unwrap();
    fs::write(&key_file, key_pem.as_bytes()).unwrap();
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
        .expect("spawn test node");

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

    if !ready {
        let mut err = String::new();
        if let Some(mut stderr) = guard.child_mut().stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = stderr.read_to_string(&mut err).await;
        }
        if let Some(status) = exited {
            panic!("node '{name}' exited prematurely with {status}: {err}");
        } else {
            panic!("node '{name}' failed to become ready: {err}");
        }
    }

    TestNode {
        _tmp: tmp,
        name: name.to_string(),
        fed_port,
        http_port,
        agent_sock,
        sessions_dir,
        db_path,
        child: guard,
    }
}

// Extract message_id from delivery footer: "[xmsg] message_id=<id> ..."
fn extract_message_id(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(pos) = line.find("message_id=") {
            let rest = &line[pos + 11..];
            let id = rest.split_whitespace().next().unwrap_or("");
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}

async fn run_test_with_port_retry<F, Fut>(name: &str, f: F)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    for attempt in 1..=5 {
        let task = tokio::task::spawn(f());
        match task.await {
            Ok(()) => return,
            Err(join_err) if join_err.is_panic() => {
                let panic_payload = join_err.into_panic();
                let is_port_conflict = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    s.contains("AddrInUse")
                        || s.contains("Address already in use")
                        || s.contains("address already in use")
                        || s.contains("failed to bind")
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.contains("AddrInUse")
                        || s.contains("Address already in use")
                        || s.contains("address already in use")
                        || s.contains("failed to bind")
                } else {
                    false
                };

                if is_port_conflict && attempt < 5 {
                    eprintln!("{name}: port collision on attempt {attempt}, retrying...");
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    continue;
                }
                std::panic::resume_unwind(panic_payload);
            }
            Err(e) => panic!("{name} join error: {e}"),
        }
    }
}

// =============================================================================
// Oracle 1: Relay and reply
// A session on A sends to <session>@B@H. It is delivered on B with origin
// showing A's principal and A as origin host. B's session replies, and A receives it.
// Mutant: keep refusing '@' (today's no_forward) => RED
// Line: test_oracle_1_relay_and_reply
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_relay_and_reply() {
    run_test_with_port_retry("test_oracle_1_relay_and_reply", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_a = get_free_port();
        let http_a = get_free_port();
        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        // Node A knows Hub
        let peers_a = serde_json::json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "allow": ["send", "reply"],
                    "default_route": true
                }
            }
        });

        // Hub knows A (with "forward") and B (with "send", "reply")
        let peers_h = serde_json::json!({
            "peers": {
                "node-a": {
                    "address": format!("127.0.0.1:{port_a}"),
                    "pin": normalize_pin(&pin_a),
                    "allow": ["send", "reply", "forward"]
                },
                "node-b": {
                    "address": format!("127.0.0.1:{port_b}"),
                    "pin": normalize_pin(&pin_b),
                    "allow": ["send", "reply"]
                }
            }
        });

        // Node B knows Hub (with "relayed" capability)
        let peers_b = serde_json::json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "allow": ["send", "reply", "relayed"]
                }
            }
        });

        let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
        let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
        let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

        // Create session on A (Alice) and session on B (Bob)
        let (_sock_a, rx_a) = create_claude_session_fixture(
            &node_a.sessions_dir,
            "0199cecf-a11c-7000-8000-0000000a11ce",
            "Alice",
        );
        let (_sock_b, rx_b) = create_claude_session_fixture(
            &node_b.sessions_dir,
            "0199cecf-b0b0-7000-8000-00000000b0b0",
            "Bob",
        );

        // Alice on A sends to Bob@node-b
        let send_resp = send_via_agent_sock(
            &node_a.agent_sock,
            "Bob@node-b",
            "Hello Bob from Alice via Hub!",
        )
        .await;

        assert_eq!(
            send_resp["status"], "ok",
            "send must succeed, got: {:?}",
            send_resp
        );

        // Wait for Bob on B to receive the relayed message
        let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
            .await
            .expect("Bob should receive relayed message on B");

        assert!(
            b_msg.contains("Hello Bob from Alice via Hub!"),
            "Bob should see original message body: {b_msg}"
        );
        // XA2: B has no nickname for node-a, so it sees node-a's canonical (key-derived)
        // name, which is what the hub put on the wire.
        let node_a_name = xmsg::node::node_name_from_pin(&pin_a).unwrap();
        assert!(
            b_msg.contains(&format!(
                "Alice · 0199cecf-a11c-7000-8000-0000000a11ce@{node_a_name}"
            )),
            "Bob should see origin showing node-a's canonical name {node_a_name}: {b_msg}"
        );

        let msg_id = extract_message_id(&b_msg).expect("message_id in Bob's delivery footer");

        // Bob on B replies to Alice's message
        let reply_resp = reply_via_agent_sock(
            &node_b.agent_sock,
            &msg_id,
            "Hello Alice! Reply routed through Hub.",
        )
        .await;

        assert_eq!(
            reply_resp["status"], "ok",
            "reply must succeed, got: {:?}",
            reply_resp
        );

        // Alice on A should receive the reply pushed to her inbox socket
        let a_reply = wait_for_inbox_message(&rx_a, Duration::from_secs(5))
            .await
            .expect("Alice should receive reply on A");

        assert!(
            a_reply.contains("Hello Alice! Reply routed through Hub."),
            "Alice should see reply text: {a_reply}"
        );
        assert!(
            a_reply.contains("Bob · 0199cecf-b0b0-7000-8000-00000000b0b0@"),
            "Alice should see origin of reply from Bob: {a_reply}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 2: Polling sender
// Same as Oracle 1, but with push_replies: false: A's sender reads the reply by long-poll.
// Mutant: drop the forward record on H so the reply isn't relayed => RED
// Line: test_oracle_2_polling_sender
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_polling_sender() {
    run_test_with_port_retry("test_oracle_2_polling_sender", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_a = get_free_port();
        let http_a = get_free_port();
        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        let peers_a = serde_json::json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "allow": ["send", "reply"],
                    "default_route": true
                }
            }
        });

        let peers_h = serde_json::json!({
            "peers": {
                "node-a": {
                    "address": format!("127.0.0.1:{port_a}"),
                    "pin": normalize_pin(&pin_a),
                    "allow": ["send", "reply", "forward"]
                },
                "node-b": {
                    "address": format!("127.0.0.1:{port_b}"),
                    "pin": normalize_pin(&pin_b),
                    "allow": ["send", "reply"]
                }
            }
        });

        let peers_b = serde_json::json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "allow": ["send", "reply", "relayed"]
                }
            }
        });

        let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
        let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
        let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

        let (sock_a, rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");
        let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

        // Alice sends with push_replies: false
        let send_resp = send_via_agent_sock(
            &node_a.agent_sock,
            "Bob@node-b",
            "Polling sender test message",
        )
        .await;

        assert_eq!(send_resp["status"], "ok");
        let sent_msg_id = send_resp["message_id"].as_str().unwrap();
        let _ = fs::remove_file(&sock_a);

        let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
            .await
            .expect("Bob should receive relayed message on B");
        let msg_id = extract_message_id(&b_msg).expect("message_id in footer");
        assert_eq!(sent_msg_id, msg_id);

        // Bob replies
        let reply_resp = reply_via_agent_sock(
            &node_b.agent_sock,
            &msg_id,
            "Reply meant for long-polling sender",
        )
        .await;
        assert_eq!(reply_resp["status"], "ok");

        // Alice should NOT receive pushed message on inbox socket (push_replies = false)
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let guard = rx_a.lock().unwrap();
            assert!(
                guard.is_empty(),
                "Alice inbox should not receive push reply"
            );
        }

        // Alice reads reply by long-poll on node A's HTTP endpoint
        let client = reqwest::Client::new();
        let poll_url = format!(
            "http://127.0.0.1:{}/v1/messages/{sent_msg_id}/replies?wait=5",
            node_a.http_port
        );
        let poll_resp = client
            .get(&poll_url)
            .send()
            .await
            .expect("poll replies request");
        assert_eq!(poll_resp.status(), axum::http::StatusCode::OK);

        let replies: Vec<Value> = poll_resp.json().await.expect("json array of replies");
        assert!(!replies.is_empty(), "long-poll should return replies");
        assert_eq!(
            replies[0]["text"], "Reply meant for long-polling sender",
            "reply text should match"
        );
    })
    .await;
}

// =============================================================================
// Oracle 3: A client that can't be dialled
// A is outbound-linked to H (dial: "outbound"); H marks A leaf.
// The A->B send and its reply still complete.
// Mutant: do not store reply for undialable origin in fed_reply_handler => RED
// Line: test_oracle_3_undialable_client
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_undialable_client() {
    run_test_with_port_retry("test_oracle_3_undialable_client", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_a = get_free_port();
        let http_a = get_free_port();
        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        // Node A is outbound-linked to Hub
        let peers_a = serde_json::json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "dial": "outbound",
                    "allow": ["send", "reply", "inbox"],
                    "default_route": true
                }
            }
        });

        // Hub marks A as leaf and allows forward; B is dialable
        let peers_h = serde_json::json!({
            "peers": {
                "node-a": {
                    "address": format!("127.0.0.1:{port_a}"),
                    "pin": normalize_pin(&pin_a),
                    "leaf": true,
                    "allow": ["send", "reply", "inbox", "forward"]
                },
                "node-b": {
                    "address": format!("127.0.0.1:{port_b}"),
                    "pin": normalize_pin(&pin_b),
                    "allow": ["send", "reply"]
                }
            }
        });

        // Node B allows relayed from hub
        let peers_b = serde_json::json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "allow": ["send", "reply", "relayed"]
                }
            }
        });

        let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
        let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
        let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

        let (_sock_a, rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");
        let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

        // Alice on outbound-linked node A sends to Bob on B via Hub
        let send_resp = send_via_agent_sock(
            &node_a.agent_sock,
            "Bob@node-b",
            "Outbound client send to Bob",
        )
        .await;

        assert_eq!(send_resp["status"], "ok");

        let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
            .await
            .expect("Bob should receive message from outbound client");
        assert!(b_msg.contains("Outbound client send to Bob"));
        let msg_id = extract_message_id(&b_msg).expect("message_id");

        // Bob replies
        let reply_resp = reply_via_agent_sock(
            &node_b.agent_sock,
            &msg_id,
            "Reply to outbound linked client Alice",
        )
        .await;
        assert_eq!(reply_resp["status"], "ok");

        // Alice's outbound reply poller pulls reply from Hub and delivers locally
        let a_reply = wait_for_inbox_message(&rx_a, Duration::from_secs(8))
            .await
            .expect("Alice should receive reply via outbound link poller");
        assert!(a_reply.contains("Reply to outbound linked client Alice"));
    })
    .await;
}

// =============================================================================
// Oracles 4-6 are hub-side: the hub's enforcement of a hop envelope. Nothing in xmsg
// originates a hop until XA5's routing, so each is driven by an in-process client that
// presents node-a's credentials and posts `to.ref = <ref>@<dest>` to the hub directly
// (tests/hop_client). Node A itself is not run: the hub never dials it on the send path.
// =============================================================================

/// A hub entry for the origin node; its address is never dialled on the send path.
fn origin_entry(pin_a: &str, allow: &[&str]) -> Value {
    serde_json::json!({
        "address": format!("127.0.0.1:{}", get_free_port()),
        "pin": normalize_pin(pin_a),
        "allow": allow
    })
}

// =============================================================================
// Oracle 4: Gates
// 4a: H refuses when A's entry lacks forward. Mutant: skip that check => RED
// 4b: B refuses when H doesn't allow relaying. Mutant: skip that check => RED
// 4c: dest's targets applies to forwarded ref.
// Line: test_oracle_4_gates
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_gates() {
    run_test_with_port_retry("test_oracle_4_gates", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        // 4a test setup: H does NOT give A "forward" capability
        let peers_h_no_fwd = serde_json::json!({
            "node-a": origin_entry(&pin_a, &["send", "reply"]), // NO "forward"
            "node-b": {
                "address": format!("127.0.0.1:{port_b}"),
                "pin": normalize_pin(&pin_b),
                "allow": ["send", "reply"]
            }
        });

        let peers_b_no_relayed = serde_json::json!({
            "hub": {
                "address": format!("127.0.0.1:{port_h}"),
                "pin": normalize_pin(&pin_h),
                "allow": ["send", "reply"] // NO "relayed"
            }
        });

        let _node_b = spawn_test_node(
            "node-b",
            port_b,
            http_b,
            &cert_b,
            &key_b,
            peers_b_no_relayed,
        )
        .await;
        let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h_no_fwd).await;

        // Gate 4a: a hop from A without "forward" is refused by H itself.
        let origin = Origin {
            cert_der: &cert_a,
            key_der: &key_a,
        };
        let (status, res_4a) = hop_send(
            &origin,
            &pin_h,
            port_h,
            "bob@node-b",
            "Test lacking forward",
        )
        .await;

        assert_eq!(status, 403, "4a: {res_4a}");
        assert_eq!(res_4a["error"], "denied", "4a: {res_4a}");
        assert_eq!(
            res_4a["detail"], "Forwarding cross-host is not permitted",
            "4a: H must refuse a hop lacking 'forward' (no_forward), not pass it on: {res_4a}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4b_recipient_relayed_gate() {
    run_test_with_port_retry("test_oracle_4b_recipient_relayed_gate", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        // Hub allows forward for A
        let peers_h = serde_json::json!({
            "node-a": origin_entry(&pin_a, &["send", "reply", "forward"]),
            "node-b": {
                "address": format!("127.0.0.1:{port_b}"),
                "pin": normalize_pin(&pin_b),
                "allow": ["send", "reply"]
            }
        });

        // B does NOT allow relayed
        let peers_b = serde_json::json!({
            "hub": {
                "address": format!("127.0.0.1:{port_h}"),
                "pin": normalize_pin(&pin_h),
                "allow": ["send", "reply"] // NO "relayed"
            }
        });

        let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
        let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
        let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

        let origin = Origin {
            cert_der: &cert_a,
            key_der: &key_a,
        };
        let (status, res_4b) = hop_send(
            &origin,
            &pin_h,
            port_h,
            "bob@node-b",
            "Test lacking relayed on B",
        )
        .await;

        assert_eq!(status, 403, "4b: {res_4b}");
        assert_eq!(res_4b["error"], "denied", "4b: {res_4b}");
        assert_eq!(
            res_4b["detail"], "relayed messages not allowed for peer",
            "4b: B must refuse a forwarded message lacking 'relayed': {res_4b}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            rx_b.lock().unwrap().is_empty(),
            "4b: nothing reaches bob on B"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4c_dest_targets_gate() {
    run_test_with_port_retry("test_oracle_4c_dest_targets_gate", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        // Hub restricts B's targets to only ["allowed_bob"]
        let peers_h = serde_json::json!({
            "node-a": origin_entry(&pin_a, &["send", "reply", "forward"]),
            "node-b": {
                "address": format!("127.0.0.1:{port_b}"),
                "pin": normalize_pin(&pin_b),
                "allow": ["send", "reply"],
                "targets": ["allowed_bob"]
            }
        });

        let peers_b = serde_json::json!({
            "hub": {
                "address": format!("127.0.0.1:{port_h}"),
                "pin": normalize_pin(&pin_h),
                "allow": ["send", "reply", "relayed"]
            }
        });

        let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
        let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
        let (_sock_b, rx_b) =
            create_claude_session_fixture(&node_b.sessions_dir, "forbidden_bob", "Bob");

        // A hop to a target B's entry on H does not list; it exists on B.
        let origin = Origin {
            cert_der: &cert_a,
            key_der: &key_a,
        };
        let (status, res_4c) = hop_send(
            &origin,
            &pin_h,
            port_h,
            "forbidden_bob@node-b",
            "Test targets check",
        )
        .await;

        assert_eq!(status, 403, "4c: {res_4c}");
        assert_eq!(res_4c["error"], "denied", "4c: {res_4c}");
        assert_eq!(
            res_4c["detail"], "target not allowed for peer",
            "4c: H must check dest targets and reject the forbidden ref: {res_4c}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            rx_b.lock().unwrap().is_empty(),
            "4c: nothing reaches forbidden_bob on B"
        );
    })
    .await;
}

// =============================================================================
// Oracle 5: One hop
// A message forwarded by H to a second forwarding node H2 is refused there.
// Mutant: no hop mark => RED
// Line: test_oracle_5_one_hop
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_one_hop() {
    run_test_with_port_retry("test_oracle_5_one_hop", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node-a").unwrap();
        let (cert_h1, key_h1, pin_h1) = generate_self_signed_ed25519_pem("hub1").unwrap();
        let (cert_h2, key_h2, pin_h2) = generate_self_signed_ed25519_pem("hub2").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_h1 = get_free_port();
        let http_h1 = get_free_port();
        let port_h2 = get_free_port();
        let http_h2 = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        let peers_h1 = serde_json::json!({
            "node-a": origin_entry(&pin_a, &["send", "reply", "forward"]),
            "hub2": {
                "address": format!("127.0.0.1:{port_h2}"),
                "pin": normalize_pin(&pin_h2),
                "allow": ["send", "reply"]
            }
        });

        let peers_h2 = serde_json::json!({
            "hub1": {
                "address": format!("127.0.0.1:{port_h1}"),
                "pin": normalize_pin(&pin_h1),
                "allow": ["send", "reply", "forward", "relayed"]
            },
            "node-b": {
                "address": format!("127.0.0.1:{port_b}"),
                "pin": normalize_pin(&pin_b),
                "allow": ["send", "reply"]
            }
        });

        let peers_b = serde_json::json!({
            "hub2": {
                "address": format!("127.0.0.1:{port_h2}"),
                "pin": normalize_pin(&pin_h2),
                "allow": ["send", "reply", "relayed"]
            }
        });

        let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
        let _hub2 = spawn_test_node("hub2", port_h2, http_h2, &cert_h2, &key_h2, peers_h2).await;
        let _hub1 = spawn_test_node("hub1", port_h1, http_h1, &cert_h1, &key_h1, peers_h1).await;
        let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

        // A's hop to bob@node-b@hub2 through H1: H1 forwards `bob@node-b` to H2, marked
        // forwarded; H2 must refuse to forward it again.
        let origin = Origin {
            cert_der: &cert_a,
            key_der: &key_a,
        };
        let (status, res) = hop_send(
            &origin,
            &pin_h1,
            port_h1,
            "bob@node-b@hub2",
            "Two-hop attempt",
        )
        .await;

        assert_eq!(status, 403, "{res}");
        assert_eq!(res["error"], "denied", "{res}");
        assert_eq!(
            res["detail"], "message has already been forwarded (one hop maximum)",
            "H2 must refuse an already-forwarded envelope with no_forward: {res}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rx_b.lock().unwrap().is_empty(), "nothing reaches bob on B");
    })
    .await;
}

// =============================================================================
// Oracle 6: Off by default
// With no forward anywhere, a hop through H is refused with no_forward.
// Mutant: allow forwarding unconditionally without checking peer config => RED
// Line: test_oracle_6_off_by_default
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_off_by_default() {
    run_test_with_port_retry("test_oracle_6_off_by_default", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        // Default configuration: no "forward" or "relayed" anywhere
        let peers_h = serde_json::json!({
            "node-a": origin_entry(&pin_a, &["send", "reply"]),
            "node-b": {
                "address": format!("127.0.0.1:{port_b}"),
                "pin": normalize_pin(&pin_b),
                "allow": ["send", "reply"]
            }
        });

        let peers_b = serde_json::json!({
            "hub": {
                "address": format!("127.0.0.1:{port_h}"),
                "pin": normalize_pin(&pin_h),
                "allow": ["send", "reply"]
            }
        });

        let _node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
        let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;

        let origin = Origin {
            cert_der: &cert_a,
            key_der: &key_a,
        };
        let (status, res) = hop_send(
            &origin,
            &pin_h,
            port_h,
            "bob@node-b",
            "Send to unconfigured hub",
        )
        .await;

        assert_eq!(status, 403, "{res}");
        assert_eq!(res["error"], "denied", "{res}");
        assert_eq!(
            res["detail"], "Forwarding cross-host is not permitted",
            "Hub without forward capability must refuse with no_forward: {res}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 6b (as amended by XA3, A10/A-2): a direct federated send A->B; B's session
// replies, and the reply is pushed back to the origin, which delivers it to the sender.
// Mutant: unconditional push to return_host without is_forwarded check => RED (push_failed)
// Line: test_oracle_6b_direct_send_reply_pushed_back
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6b_direct_send_reply_pushed_back() {
    run_test_with_port_retry(
        "test_oracle_6b_direct_send_reply_pushed_back",
        || async move {
            let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
            let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

            let port_a = get_free_port();
            let http_a = get_free_port();
            let port_b = get_free_port();
            let http_b = get_free_port();

            // Direct peering A <-> B (no hub involved)
            let peers_a = serde_json::json!({
                "node-b": {
                    "address": format!("127.0.0.1:{port_b}"),
                    "pin": normalize_pin(&pin_b),
                    "allow": ["send", "reply"]
                }
            });

            let peers_b = serde_json::json!({
                "node-a": {
                    "address": format!("127.0.0.1:{port_a}"),
                    "pin": normalize_pin(&pin_a),
                    "allow": ["send", "reply"]
                }
            });

            let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
            let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

            let (_sock_a, rx_a) = create_claude_session_fixture(
                &node_a.sessions_dir,
                "135aa23d-60a6-5595-a42a-c0296722252e",
                "Alice",
            );
            let (_sock_b, rx_b) = create_claude_session_fixture(
                &node_b.sessions_dir,
                "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
                "Bob",
            );

            // Alice sends direct to bob@node-b with push_replies: false
            let send_res = send_via_agent_sock(
                &node_a.agent_sock,
                "baa3a12f-e06d-59f5-90c8-2eda9a54dd91@node-b",
                "Direct send without push replies",
            )
            .await;

            assert_eq!(send_res["status"], "ok");

            // Bob receives the direct message
            let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
                .await
                .expect("Bob should receive direct message on B");
            let msg_id = extract_message_id(&b_msg).expect("message_id in Bob footer");

            // Bob replies
            let reply_res = reply_via_agent_sock(
                &node_b.agent_sock,
                &msg_id,
                "Bob direct reply to non-push sender",
            )
            .await;

            assert_eq!(reply_res["status"], "ok");
            // A-2: the reply travels back to the origin node, which pushes it to Alice
            // (a session has an inbox; the per-message opt-out is gone).
            assert_eq!(
                reply_res["reply"]["pushOutcome"], "pushed",
                "Direct send reply is pushed back to the origin: {:?}",
                reply_res
            );
            let a_msg = wait_for_inbox_message(&rx_a, Duration::from_secs(5))
                .await
                .expect("Alice receives the pushed reply");
            assert!(
                a_msg.contains("Bob direct reply to non-push sender"),
                "{a_msg}"
            );
        },
    )
    .await;
}

// =============================================================================
// Oracles 1a and 3a: the hub half of oracles 1 and 3, the reply to a forwarded message.
// The origin's half (originating the hop, writing its `outbound` row) waits for XA5; the
// hop is posted by tests/hop_client, as for oracles 4-6.
// =============================================================================

/// A hop from node-a through the hub to `bob@node-b`; Bob replies. Returns the forwarded
/// message's ID once Bob's reply has been accepted by the hub.
async fn hop_and_reply(
    origin: &Origin<'_>,
    pin_h: &str,
    port_h: u16,
    node_b: &TestNode,
    rx_b: &Arc<Mutex<Vec<String>>>,
    text: &str,
) -> String {
    let (status, sent) = hop_send(
        origin,
        pin_h,
        port_h,
        "baa3a12f-e06d-59f5-90c8-2eda9a54dd91@node-b",
        "Question for Bob",
    )
    .await;
    assert_eq!(status, 202, "hop: {sent}");
    let b_msg = wait_for_inbox_message(rx_b, Duration::from_secs(5))
        .await
        .expect("Bob receives the forwarded message");
    let msg_id = extract_message_id(&b_msg).expect("message_id");
    let reply = reply_via_agent_sock(&node_b.agent_sock, &msg_id, text).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["reply"]["pushOutcome"], "pushed",
        "the hub takes the reply: {reply}"
    );
    msg_id
}

fn hub_entry(port_h: u16, pin_h: &str, allow: &[&str]) -> Value {
    serde_json::json!({
        "address": format!("127.0.0.1:{port_h}"),
        "pin": normalize_pin(pin_h),
        "allow": allow
    })
}

// Oracle 1a: H relays the reply to a dialable origin, which stores it.
// Mutant: H never relays a forwarded reply (fed_reply_handler's forwarded branch off) => RED
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1a_hub_relays_reply_to_dialable_origin() {
    run_test_with_port_retry(
        "test_oracle_1a_hub_relays_reply_to_dialable_origin",
        || async move {
            use rustls::pki_types::pem::PemObject;
            let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
            let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
            let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();
            let cert_a_der = rustls::pki_types::CertificateDer::from_pem_slice(cert_a.as_bytes())
                .unwrap()
                .to_vec();
            let key_a_der = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_a.as_bytes())
                .unwrap()
                .secret_der()
                .to_vec();

            let (port_a, http_a) = (get_free_port(), get_free_port());
            let (port_h, http_h) = (get_free_port(), get_free_port());
            let (port_b, http_b) = (get_free_port(), get_free_port());

            let peers_a =
                serde_json::json!({ "hub": hub_entry(port_h, &pin_h, &["send", "reply"]) });
            let peers_h = serde_json::json!({
                "node-a": {
                    "address": format!("127.0.0.1:{port_a}"),
                    "pin": normalize_pin(&pin_a),
                    "allow": ["send", "reply", "forward"]
                },
                "node-b": {
                    "address": format!("127.0.0.1:{port_b}"),
                    "pin": normalize_pin(&pin_b),
                    "allow": ["send", "reply"]
                }
            });
            let peers_b = serde_json::json!({
                "hub": hub_entry(port_h, &pin_h, &["send", "reply", "relayed"])
            });

            let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
            let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
            let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;
            let (_sock_b, rx_b) = create_claude_session_fixture(
                &node_b.sessions_dir,
                "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
                "Bob",
            );

            let origin = Origin {
                cert_der: &cert_a_der,
                key_der: &key_a_der,
            };
            let (status, sent) = hop_send(
                &origin,
                &pin_h,
                port_h,
                "baa3a12f-e06d-59f5-90c8-2eda9a54dd91@node-b",
                "Question for Bob",
            )
            .await;
            assert_eq!(status, 202, "hop: {sent}");
            let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
                .await
                .expect("Bob receives the forwarded message");
            let msg_id = extract_message_id(&b_msg).expect("message_id");

            // The rows node-a writes when it originates the hop (XA5), written here: the
            // sent message (a sender with no inbox, so node-a stores the reply) and its
            // `outbound` record naming the hub.
            let a_db = rusqlite::Connection::open(&node_a.db_path).unwrap();
            a_db.busy_timeout(Duration::from_secs(5)).unwrap();
            let sent = xmsg::storage::MessageRecord {
                id: msg_id.clone(),
                created_at: 1000,
                session_id: "baa3a12f-e06d-59f5-90c8-2eda9a54dd91@node-b".to_string(),
                from_name: "alice".to_string(),
                bytes: 16,
                outcome: "delivered".to_string(),
                recipient_harness: "fed".to_string(),
                return_harness: None,
                return_session_id: None,
                return_host: None,
                thread_id: msg_id.clone(),
            };
            xmsg::storage::insert_message(&a_db, &sent).unwrap();
            xmsg::storage::insert_outbound(
                &a_db,
                &msg_id,
                "hub",
                "baa3a12f-e06d-59f5-90c8-2eda9a54dd91@node-b",
                "delivered",
                1000,
            )
            .unwrap();

            let reply = reply_via_agent_sock(&node_b.agent_sock, &msg_id, "Bob answers A").await;
            assert_eq!(reply["status"], "ok", "{reply}");
            assert_eq!(reply["reply"]["pushOutcome"], "pushed", "{reply}");

            let mut at_a = Vec::new();
            for _ in 0..100 {
                at_a = xmsg::storage::get_replies_after(&a_db, &msg_id, 0).unwrap();
                if !at_a.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(
                at_a.iter().map(|r| r.text.as_str()).collect::<Vec<_>>(),
                ["Bob answers A"],
                "H relays the reply to the dialable origin node-a"
            );
        },
    )
    .await;
}

// Oracle 3a: H stores the reply for an undialable (leaf) origin, which reads it from H.
// Mutant: the forwarded branch's leaf arm answers `stored` without storing => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3a_hub_stores_reply_for_undialable_origin() {
    run_test_with_port_retry(
        "test_oracle_3a_hub_stores_reply_for_undialable_origin",
        || async move {
            let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node-a").unwrap();
            let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
            let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();
            let (port_h, http_h) = (get_free_port(), get_free_port());
            let (port_b, http_b) = (get_free_port(), get_free_port());

            let mut entry_a = origin_entry(&pin_a, &["send", "reply", "inbox", "forward"]);
            entry_a["leaf"] = true.into();
            let peers_h = serde_json::json!({
                "node-a": entry_a,
                "node-b": {
                    "address": format!("127.0.0.1:{port_b}"),
                    "pin": normalize_pin(&pin_b),
                    "allow": ["send", "reply"]
                }
            });
            let peers_b = serde_json::json!({
                "hub": hub_entry(port_h, &pin_h, &["send", "reply", "relayed"])
            });

            let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
            let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
            let (_sock_b, rx_b) = create_claude_session_fixture(
                &node_b.sessions_dir,
                "baa3a12f-e06d-59f5-90c8-2eda9a54dd91",
                "Bob",
            );

            let origin = Origin {
                cert_der: &cert_a,
                key_der: &key_a,
            };
            let msg_id = hop_and_reply(
                &origin,
                &pin_h,
                port_h,
                &node_b,
                &rx_b,
                "Bob answers leaf A",
            )
            .await;

            let (status, replies) = hop_client::request(
                &origin,
                &pin_h,
                port_h,
                "GET",
                &format!("/fed/v2/messages/{msg_id}/replies"),
                None,
            )
            .await;
            assert_eq!(status, 200, "{replies}");
            let texts: Vec<&str> = replies
                .as_array()
                .expect("a reply list")
                .iter()
                .filter_map(|r| r["text"].as_str())
                .collect();
            assert_eq!(
                texts,
                ["Bob answers leaf A"],
                "H holds the reply for node-a: {replies}"
            );
        },
    )
    .await;
}
