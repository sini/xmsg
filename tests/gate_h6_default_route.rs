mod hop_client;
mod short_sock;

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use serde_json::{json, Value};
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::fed::{
    generate_self_signed_ed25519, generate_self_signed_ed25519_pem, normalize_pin,
    run_outbound_peer_pull_loop, CredentialReloader, FedState, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::pi::new_pi_store;
use xmsg::storage;
use xmsg::svc::new_svc_store;

use hop_client::{envelope, send_envelope, Origin};

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

    let send_req = json!({
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

    let reply_req = json!({
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
    let session_json = json!({
        "pid": my_pid,
        "sessionId": session_id,
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
    peers_file: PathBuf,
    cert_file: PathBuf,
    key_file: PathBuf,
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
        peers_file,
        cert_file,
        key_file,
        child: guard,
    }
}

const DUMMY_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DUMMY_PIN2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

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

// Extract reply_id from reply footer: "[xmsg] reply to message_id=<orig> — message_id=<reply_id>; ..."
fn extract_reply_id(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(pos) = line.rfind("message_id=") {
            let rest = &line[pos + 11..];
            let id = rest.split([';', ' ', '\n']).next().unwrap_or("");
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
        let fut = f();
        let result = tokio::spawn(fut).await;
        match result {
            Ok(()) => return,
            Err(e) if attempt < 5 && e.is_panic() => {
                eprintln!(
                    "test {name} panicked on attempt {attempt}/5, retrying with new ports: {e:?}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => {
                std::panic::resume_unwind(e.into_panic());
            }
        }
    }
}

// =============================================================================
// Oracle 1: Direct link wins over default route
// Node A has both a direct link to Node B and a default route to Hub.
// Sending to Bob@node-b must route directly to Node B, bypassing Hub entirely.
// Mutant M1: "prefer hub" in deliver_send => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_direct_link_wins_over_default_route() {
    run_test_with_port_retry("test_oracle_1_direct_link_wins_over_default_route", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_a = get_free_port();
        let http_a = get_free_port();
        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        // Node A has both:
        // 1. Hub with default_route: true
        // 2. Direct link to node-b
        let peers_a = json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "allow": ["send", "reply"],
                    "default_route": true
                },
                "node-b": {
                    "address": format!("127.0.0.1:{port_b}"),
                    "pin": normalize_pin(&pin_b),
                    "allow": ["send", "reply"]
                }
            }
        });

        // Hub only knows node-a (hub does NOT know node-b)
        // If Node A erroneously routes via hub, hub will refuse forwarding to node-b
        let peers_h = json!({
            "peers": {
                "node-a": {
                    "address": format!("127.0.0.1:{port_a}"),
                    "pin": normalize_pin(&pin_a),
                    "allow": ["send", "reply", "forward"]
                }
            }
        });

        // Node B knows node-a directly
        let peers_b = json!({
            "peers": {
                "node-a": {
                    "address": format!("127.0.0.1:{port_a}"),
                    "pin": normalize_pin(&pin_a),
                    "allow": ["send", "reply"]
                }
            }
        });

        let _hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
        let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
        let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

        let (_sock_a, _rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");
        let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

        let send_resp = send_via_agent_sock(
            &node_a.agent_sock,
            "Bob@node-b",
            "Direct link wins over default route",
        )
        .await;

        assert_eq!(send_resp["status"], "ok", "direct send must succeed: {send_resp}");

        let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
            .await
            .expect("Bob on B must receive direct message");
        assert!(b_msg.contains("Direct link wins over default route"));
    })
    .await;
}

// =============================================================================
// Oracle 2: Default route via hub
// Node A knows only Hub with default_route: true. Sending to unknown node-b
// routes to Hub, which forwards to Node B.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_default_route_via_hub() {
    run_test_with_port_retry("test_oracle_2_default_route_via_hub", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_a = get_free_port();
        let http_a = get_free_port();
        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        // Node A only knows hub with default_route: true. Does NOT know node-b.
        let peers_a = json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "allow": ["send", "reply"],
                    "default_route": true
                }
            }
        });

        // Hub knows node-a (with forward) and node-b
        let peers_h = json!({
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

        // Node B allows relayed from hub
        let peers_b = json!({
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

        let (_sock_a, _rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");
        let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

        let send_resp = send_via_agent_sock(
            &node_a.agent_sock,
            "Bob@node-b",
            "Routing via default route hub",
        )
        .await;

        assert_eq!(send_resp["status"], "ok", "default route send must succeed: {send_resp}");

        let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
            .await
            .expect("Bob on B must receive relayed message");
        assert!(b_msg.contains("Routing via default route hub"));
        let node_a_name = xmsg::node::node_name_from_pin(&pin_a).unwrap();
        assert!(b_msg.contains(&format!("Alice · alice@{node_a_name}")));
    })
    .await;
}

// =============================================================================
// Oracle 3: Unknown peer refusal when no default route
// Node A has no default route. Sending to an unknown peer must fail immediately.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_unknown_peer_refusal_when_no_default_route() {
    run_test_with_port_retry("test_oracle_3_unknown_peer_refusal_when_no_default_route", || async move {
        let (cert_a, key_a, _pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
        let port_a = get_free_port();
        let http_a = get_free_port();

        // Node A has no default route
        let peers_a = json!({
            "peers": {
                "known-peer": {
                    "address": "127.0.0.1:9999",
                    "pin": DUMMY_PIN,
                    "allow": ["send", "reply"]
                }
            }
        });

        let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;
        let (_sock_a, _rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");

        let send_resp = send_via_agent_sock(
            &node_a.agent_sock,
            "Bob@unreachable-peer",
            "This should fail",
        )
        .await;

        assert_eq!(send_resp["status"], "error", "must fail for unknown peer when no default route");
        let detail = send_resp["detail"].as_str().unwrap_or("");
        assert!(
            detail.contains("unknown peer") || detail.contains("unreachable-peer"),
            "error should indicate unknown peer, got: {send_resp}"
        );
    })
    .await;
}

// =============================================================================
// Oracle 4: Two-hop refusal at hub
// Hub rejects an envelope that already has forwarded: Some(...) (one hop limit).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_two_hop_refusal_at_hub() {
    run_test_with_port_retry("test_oracle_4_two_hop_refusal_at_hub", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        let peers_h = json!({
            "peers": {
                "node-a": {
                    "address": "127.0.0.1:1111",
                    "pin": normalize_pin(&pin_a),
                    "allow": ["send", "reply", "forward", "relayed"]
                },
                "node-b": {
                    "address": format!("127.0.0.1:{port_b}"),
                    "pin": normalize_pin(&pin_b),
                    "allow": ["send", "reply"]
                }
            }
        });

        let peers_b = json!({
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
        let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

        let origin = Origin {
            cert_der: &cert_a,
            key_der: &key_a,
        };

        // Construct envelope that already has forwarded: Some(...)
        let mut fwd_env = envelope("alice", "Alice", "Bob@node-b", "Two hop attempt");
        fwd_env["forwarded"] = json!({
            "forwarder": "node-zero"
        });

        let (status, res) = send_envelope(&origin, &pin_h, port_h, fwd_env).await;

        assert_eq!(status, 403, "Hub must refuse already-forwarded envelope with 403: {res}");
        assert_eq!(res["error"], "denied");
        assert_eq!(
            res["detail"],
            "message has already been forwarded (one hop maximum)"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(rx_b.lock().unwrap().is_empty(), "Bob must receive nothing");
    })
    .await;
}

// =============================================================================
// Oracle 5: Hub-relayed reply answerable
// Multi-turn conversation across hub default route:
// Alice -> Hub -> Bob; Bob replies; Alice answers Bob's reply.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_hub_relayed_reply_answerable() {
    run_test_with_port_retry("test_oracle_5_hub_relayed_reply_answerable", || async move {
        let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
        let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
        let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

        let port_a = get_free_port();
        let http_a = get_free_port();
        let port_h = get_free_port();
        let http_h = get_free_port();
        let port_b = get_free_port();
        let http_b = get_free_port();

        let peers_a = json!({
            "peers": {
                "hub": {
                    "address": format!("127.0.0.1:{port_h}"),
                    "pin": normalize_pin(&pin_h),
                    "allow": ["send", "reply"],
                    "default_route": true
                }
            }
        });

        let peers_h = json!({
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

        let peers_b = json!({
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

        // Turn 1: Alice sends to Bob via Hub
        let send_resp = send_via_agent_sock(&node_a.agent_sock, "Bob@node-b", "Turn 1: Hello Bob").await;
        assert_eq!(send_resp["status"], "ok");

        let b_msg1 = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
            .await
            .expect("Bob receives Turn 1");
        assert!(b_msg1.contains("Turn 1: Hello Bob"));
        let id1 = extract_message_id(&b_msg1).expect("extract id1");

        // Turn 2: Bob replies to Turn 1
        rx_b.lock().unwrap().clear();
        let reply_resp1 = reply_via_agent_sock(&node_b.agent_sock, &id1, "Turn 2: Hello Alice").await;
        assert_eq!(reply_resp1["status"], "ok");

        let a_reply1 = wait_for_inbox_message(&rx_a, Duration::from_secs(5))
            .await
            .expect("Alice receives Turn 2 reply");
        assert!(a_reply1.contains("Turn 2: Hello Alice"));
        let id2 = extract_reply_id(&a_reply1).expect("extract id2");

        // Turn 3: Alice replies to Bob's reply
        rx_a.lock().unwrap().clear();
        let reply_resp2 = reply_via_agent_sock(&node_a.agent_sock, &id2, "Turn 3: Glad you got it").await;
        assert_eq!(reply_resp2["status"], "ok");

        let b_msg2 = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
            .await
            .expect("Bob receives Turn 3 reply");
        assert!(b_msg2.contains("Turn 3: Glad you got it"));
    })
    .await;
}

// =============================================================================
// Oracle 6: Direct dial-out pulled reply answerable without hub
// Dedicated standalone cell (NO HUB):
// Node A is outbound-linked directly to Node B. Alice sends to Bob. Bob replies.
// Reply poller delivers Bob's reply and calls record_pushed_reply.
// Alice answers Bob's reply.
// Mutant M2: skip record_pushed_reply in spawn_outbound_reply_poller => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_direct_dial_out_pulled_reply_answerable_without_hub() {
    run_test_with_port_retry(
        "test_oracle_6_direct_dial_out_pulled_reply_answerable_without_hub",
        || async move {
            let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
            let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

            let port_a = get_free_port();
            let http_a = get_free_port();
            let port_b = get_free_port();
            let http_b = get_free_port();

            // Node A connects directly to Node B as an outbound link
            let peers_a = json!({
                "peers": {
                    "node-b": {
                        "address": format!("127.0.0.1:{port_b}"),
                        "pin": normalize_pin(&pin_b),
                        "dial": "outbound",
                        "allow": ["send", "reply", "inbox"]
                    }
                }
            });

            // Node B knows Node A (inbound connection allowed, leaf: true so replies are stored for polling)
            let peers_b = json!({
                "peers": {
                    "node-a": {
                        "pin": normalize_pin(&pin_a),
                        "leaf": true,
                        "allow": ["send", "reply", "inbox"]
                    }
                }
            });

            let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
            let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

            let (_sock_a, rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");
            let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

            // Alice on Node A sends to Bob on Node B
            let send_resp = send_via_agent_sock(
                &node_a.agent_sock,
                "Bob@node-b",
                "Direct dial-out send to Bob",
            )
            .await;
            assert_eq!(send_resp["status"], "ok");

            let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
                .await
                .expect("Bob should receive message from outbound client A");
            assert!(b_msg.contains("Direct dial-out send to Bob"));
            let msg_id = extract_message_id(&b_msg).expect("message_id in Bob's delivery footer");
            rx_b.lock().unwrap().clear();

            // Bob replies to Alice. Since Node A is outbound, Node B stores the reply.
            let reply_resp = reply_via_agent_sock(
                &node_b.agent_sock,
                &msg_id,
                "Bob replying over stored replies",
            )
            .await;
            assert_eq!(reply_resp["status"], "ok");

            // Node A's reply poller pulls Bob's reply, delivers to Alice, and calls record_pushed_reply!
            let a_reply = wait_for_inbox_message(&rx_a, Duration::from_secs(5))
                .await
                .expect("Alice should receive Bob's reply via pull poller");
            assert!(a_reply.contains("Bob replying over stored replies"));
            let reply_id = extract_reply_id(&a_reply).expect("reply_id in Alice's delivery footer");
            assert_eq!(
                reply_resp["reply"]["pushedMessageId"], reply_id,
                "Node B must stamp pushedMessageId on stored reply so both nodes agree on reply_id"
            );

            // Alice answers Bob's reply!
            // If record_pushed_reply was called and Node B recorded reply_id in messages/outbound,
            // Node A knows reply_id and routes back to Bob, and Node B pushes it into Bob's inbox.
            let answer_resp = reply_via_agent_sock(
                &node_a.agent_sock,
                &reply_id,
                "Alice answering Bob's pulled reply",
            )
            .await;
            assert_eq!(
                answer_resp["status"], "ok",
                "Alice's reply to pulled reply must succeed (proves record_pushed_reply): {answer_resp}"
            );
            assert_eq!(
                answer_resp["reply"]["pushOutcome"], "pushed",
                "Alice's reply to pulled reply must push into Bob's inbox on Node B: {answer_resp}"
            );

            let b_answer = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
                .await
                .expect("Bob on Node B must receive Alice's answer in his inbox");
            assert!(
                b_answer.contains("Alice answering Bob's pulled reply"),
                "Bob's inbox should contain Alice's answer, got: {b_answer}"
            );

            // Verify in Node A's database that the pulled reply was indeed recorded by record_pushed_reply
            let conn = rusqlite::Connection::open(&node_a.db_path).expect("open node_a db");
            let rec = storage::get_message(&conn, &reply_id).expect("query get_message");
            assert!(
                rec.is_some(),
                "record_pushed_reply must have recorded reply_id in messages table"
            );
        },
    )
    .await;
}

// =============================================================================
// Oracle 7: Removed pull loop exits on reload
// An active outbound peer pull loop must exit when that peer is removed on reload.
// Mutant M3: "loop never checks map" in run_outbound_peer_pull_loop => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_7_removed_pull_loop_exits_on_reload() {
    let tmp = tempdir().unwrap();
    let (cert_pem, key_pem, _pin) = generate_self_signed_ed25519_pem("test-node").unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    fs::write(&cert_file, &cert_pem).unwrap();
    fs::write(&key_file, &key_pem).unwrap();

    let dead_port = get_free_port();
    let peers_json = json!({
        "peers": {
            "peer-b": {
                "address": format!("127.0.0.1:{dead_port}"),
                "pin": DUMMY_PIN,
                "dial": "outbound",
                "allow": ["send", "reply", "inbox"]
            }
        }
    });
    fs::write(&peers_file, peers_json.to_string()).unwrap();

    let peers = PeersMap::load_from_file_for(&peers_file, None).unwrap();
    let peers_arc = Arc::new(peers);

    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_locks = tmp.path().join("locks");
    fs::create_dir_all(&proc_locks).unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
    };

    let fs = Arc::new(FedState {
        node_name: "test-node".to_string(),
        peers: peers_arc.clone(),
        cert_der: Vec::new(),
        cert_chain_der: Vec::new(),
        key_der: Vec::new(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db,
        sessions_dirs: vec![tmp.path().join("sessions")],
        agy_config,
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx,
        svc_store: new_svc_store(),
        svc_notify_tx,
        notify_tx,
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    });

    let active_pull_loops = Arc::new(Mutex::new(HashSet::new()));
    active_pull_loops.lock().unwrap().insert("peer-b".to_string());

    let reloader = Arc::new(
        CredentialReloader::new_full(
            cert_file,
            key_file,
            Some(peers_file.clone()),
            None,
            peers_arc.clone(),
            fs.dynamic_tls.clone(),
            Some(fs.clone()),
            active_pull_loops.clone(),
        )
        .unwrap(),
    );

    let fs_clone = fs.clone();
    let handle = tokio::spawn(async move {
        run_outbound_peer_pull_loop(fs_clone, "peer-b".to_string()).await;
    });

    // Small delay to let the pull loop start and enter its loop
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!handle.is_finished(), "pull loop should be running");

    // Rewrite peers.json with peer-b removed
    let new_peers_json = json!({
        "peers": {}
    });
    fs::write(&peers_file, new_peers_json.to_string()).unwrap();

    // Reload federation config
    let reload_ok = reloader.check_and_reload().unwrap();
    assert!(reload_ok);

    // Pull loop should detect peer-b is gone from current_peers() and exit promptly!
    // Mutant M3 (loop never checks map): handle never completes, timeout expires => RED!
    let res = tokio::time::timeout(Duration::from_millis(600), handle).await;
    assert!(res.is_ok(), "pull loop must exit promptly when peer is removed");
}

// =============================================================================
// Oracle 8: Reload adds pull loop
// Adding an outbound peer via peers file reload spawns a pull loop.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_8_reload_adds_pull_loop() {
    let tmp = tempdir().unwrap();
    let (cert_pem, key_pem, _pin) = generate_self_signed_ed25519_pem("test-node").unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    fs::write(&cert_file, &cert_pem).unwrap();
    fs::write(&key_file, &key_pem).unwrap();

    // Initially peer-b is NOT outbound
    let peers_json = json!({
        "peers": {
            "peer-b": {
                "address": "127.0.0.1:9999",
                "pin": DUMMY_PIN,
                "allow": ["send", "reply"]
            }
        }
    });
    fs::write(&peers_file, peers_json.to_string()).unwrap();

    let peers = PeersMap::load_from_file_for(&peers_file, None).unwrap();
    let peers_arc = Arc::new(peers);

    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_locks = tmp.path().join("locks");
    fs::create_dir_all(&proc_locks).unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: proc_locks,
        proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
    };

    let fs = Arc::new(FedState {
        node_name: "test-node".to_string(),
        peers: peers_arc.clone(),
        cert_der: Vec::new(),
        cert_chain_der: Vec::new(),
        key_der: Vec::new(),
        rate_limiter: Arc::new(RateLimiter::new(60, 20)),
        db,
        sessions_dirs: vec![tmp.path().join("sessions")],
        agy_config,
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx,
        svc_store: new_svc_store(),
        svc_notify_tx,
        notify_tx,
        max_body: 65536,
        is_leaf: false,
        leaf_principal: None,
        outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
        dynamic_tls: Default::default(),
        reply_ttl: Duration::from_secs(3600),
        list_queries: Default::default(),
    });

    let active_pull_loops = Arc::new(Mutex::new(HashSet::new()));

    let reloader = Arc::new(
        CredentialReloader::new_full(
            cert_file,
            key_file,
            Some(peers_file.clone()),
            None,
            peers_arc.clone(),
            fs.dynamic_tls.clone(),
            Some(fs.clone()),
            active_pull_loops.clone(),
        )
        .unwrap(),
    );

    assert!(active_pull_loops.lock().unwrap().is_empty());

    // Update peers.json to make peer-b outbound
    let new_peers_json = json!({
        "peers": {
            "peer-b": {
                "address": "127.0.0.1:9999",
                "pin": DUMMY_PIN,
                "dial": "outbound",
                "allow": ["send", "reply", "inbox"]
            }
        }
    });
    fs::write(&peers_file, new_peers_json.to_string()).unwrap();

    let reload_ok = reloader.check_and_reload().unwrap();
    assert!(reload_ok);

    // Verify active_pull_loops now contains peer-b
    assert!(
        active_pull_loops.lock().unwrap().contains("peer-b"),
        "reload must add peer-b to active_pull_loops"
    );
}

// =============================================================================
// Oracle 9: Admitted clients collision preserved across reload
// Preserve admitted_clients Arc across reload swap (Directive 3).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_9_admitted_clients_preserved_across_reload() {
    let tmp = tempdir().unwrap();
    let (cert_pem, key_pem, _pin) = generate_self_signed_ed25519_pem("test-hub").unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    fs::write(&cert_file, &cert_pem).unwrap();
    fs::write(&key_file, &key_pem).unwrap();

    let peers_json = json!({
        "peers": {
            "node-a": {
                "address": "127.0.0.1:1111",
                "pin": DUMMY_PIN,
                "allow": ["send", "reply"]
            }
        }
    });
    fs::write(&peers_file, peers_json.to_string()).unwrap();

    let peers = PeersMap::load_from_file_for(&peers_file, None).unwrap();
    let peers_arc = Arc::new(peers);

    let active_pull_loops = Arc::new(Mutex::new(HashSet::new()));
    let dyn_tls_slot = Arc::new(std::sync::RwLock::new(None));

    let reloader = Arc::new(
        CredentialReloader::new_full(
            cert_file,
            key_file,
            Some(peers_file.clone()),
            None,
            peers_arc.clone(),
            dyn_tls_slot.clone(),
            None,
            active_pull_loops.clone(),
        )
        .unwrap(),
    );

    // Initial load sets dynamic_tls
    reloader.check_and_reload().unwrap();

    let initial_peers = reloader.peers.lock().unwrap().clone();
    let initial_admitted_arc = initial_peers.admitted_clients.clone();

    // Insert an admitted client
    {
        let mut adm = initial_admitted_arc.write().unwrap();
        adm.insert(
            "client-canon".to_string(),
            xmsg::fed::AdmittedClient {
                canonical_name: "client-canon".to_string(),
                uri: "spiffe://example.org/client".to_string(),
                pin: DUMMY_PIN.to_string(),
                config: PeerConfig {
                    name: "client-canon".to_string(),
                    address: "127.0.0.1:2222".to_string(),
                    pin: Some(DUMMY_PIN.to_string()),
                    allow: vec!["send".to_string()],
                    ..Default::default()
                },
            },
        );
    }

    // Now reload peers file with a modification
    let new_peers_json = json!({
        "peers": {
            "node-a": {
                "address": "127.0.0.1:1111",
                "pin": DUMMY_PIN,
                "allow": ["send", "reply", "forward"]
            }
        }
    });
    fs::write(&peers_file, new_peers_json.to_string()).unwrap();

    let reload_ok = reloader.check_and_reload().unwrap();
    assert!(reload_ok);

    let post_reload_peers = reloader.peers.lock().unwrap().clone();
    let post_reload_admitted_arc = post_reload_peers.admitted_clients.clone();

    // Directive 3 invariant: Arc pointer identity preserved across reload swap!
    assert!(
        Arc::ptr_eq(&initial_admitted_arc, &post_reload_admitted_arc),
        "admitted_clients Arc must be identical across reload swap"
    );

    // Client admitted before reload is still present!
    assert!(
        post_reload_admitted_arc
            .read()
            .unwrap()
            .contains_key("client-canon"),
        "admitted client must be preserved after reload"
    );
}

// =============================================================================
// Oracle 10: Invalid peers file keeps old config and logs error naming file
// Invalid peers file on reload keeps old map and returns error naming file (Directive 3).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_10_invalid_peers_file_keeps_old_config_and_logs_error() {
    let tmp = tempdir().unwrap();
    let (cert_pem, key_pem, _pin) = generate_self_signed_ed25519_pem("test-node").unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");

    fs::write(&cert_file, &cert_pem).unwrap();
    fs::write(&key_file, &key_pem).unwrap();

    let peers_json = json!({
        "peers": {
            "initial-peer": {
                "address": "127.0.0.1:1234",
                "pin": DUMMY_PIN,
                "allow": ["send", "reply"]
            }
        }
    });
    fs::write(&peers_file, peers_json.to_string()).unwrap();

    let peers = PeersMap::load_from_file_for(&peers_file, None).unwrap();
    let peers_arc = Arc::new(peers);

    let reloader = Arc::new(
        CredentialReloader::new_full(
            cert_file,
            key_file,
            Some(peers_file.clone()),
            None,
            peers_arc.clone(),
            Arc::new(std::sync::RwLock::new(None)),
            None,
            Arc::new(Mutex::new(HashSet::new())),
        )
        .unwrap(),
    );

    reloader.check_and_reload().unwrap();
    assert!(reloader.peers.lock().unwrap().get("initial-peer").is_some());

    // Write invalid content to peers file
    fs::write(&peers_file, "{ malformed json").unwrap();

    // Reload must fail
    let res = reloader.check_and_reload();
    assert!(res.is_err(), "reload with invalid peers file must fail");
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains(peers_file.to_str().unwrap()),
        "error message must name the peers file path: {err_msg}"
    );

    // Old config preserved!
    assert!(
        reloader.peers.lock().unwrap().get("initial-peer").is_some(),
        "old peers map must be preserved when reload fails"
    );
}

// =============================================================================
// Oracle 11: X1 idempotency key preserved across default-route hop
// Key crosses default-route hop unchanged. Sending same key twice via hub
// delivers once to destination.
// Mutant M4: re-key at hub => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_11_x1_idempotency_key_preserved_across_default_route_hop() {
    run_test_with_port_retry(
        "test_oracle_11_x1_idempotency_key_preserved_across_default_route_hop",
        || async move {
            let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node-a").unwrap();
            let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
            let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

            let port_h = get_free_port();
            let http_h = get_free_port();
            let port_b = get_free_port();
            let http_b = get_free_port();

            // Hub knows A (forward) and B (send, reply)
            let peers_h = json!({
                "peers": {
                    "node-a": {
                        "address": "127.0.0.1:1111",
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

            // Node B allows relayed from hub
            let peers_b = json!({
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
            let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");

            let origin = Origin {
                cert_der: &cert_a,
                key_der: &key_a,
            };

            // Fixed X1 message ID
            let x1_id = format!("x1-idempotent-{}", ulid::Ulid::new());
            let mut env = envelope("alice", "Alice", "Bob@node-b", "X1 idempotency test");
            env["id"] = json!(x1_id);

            // First delivery via hub
            let (status1, res1) = send_envelope(&origin, &pin_h, port_h, env.clone()).await;
            assert_eq!(status1, 202, "first send via hub: {res1}");

            let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
                .await
                .expect("Bob receives first delivery");
            assert!(b_msg.contains("X1 idempotency test"));

            let received_id = extract_message_id(&b_msg).expect("message_id in Bob's delivery footer");
            assert_eq!(
                received_id, x1_id,
                "Bob must receive the exact idempotency key preserved across the default route hop (Mutant M4: re-key at hub => RED)"
            );

            // Second delivery with the SAME message ID via hub
            let (status2, res2) = send_envelope(&origin, &pin_h, port_h, env).await;
            assert_eq!(status2, 202, "second send via hub: {res2}");

            // Wait 500ms to ensure no second delivery occurs at Bob
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Mutant M4: re-key at hub would assign a new id, causing Bob to receive twice!
            let count = rx_b.lock().unwrap().len();
            assert_eq!(
                count, 1,
                "Bob must receive exactly one delivery for same idempotency key (Mutant: re-key at hub => RED)"
            );
        },
    )
    .await;
}

// =============================================================================
// Oracle 12: Default route parsing and invariants
// Default route field parsing, at-most-one validation, and wrapped fixture support.
// =============================================================================
#[test]
fn test_oracle_12_default_route_parsing_and_invariants() {
    // 1. Wrapped fixture with default_route
    let wrapped = json!({
        "peers": {
            "hub": {
                "address": "127.0.0.1:1234",
                "pin": DUMMY_PIN,
                "default_route": true
            },
            "cee": {
                "pin": DUMMY_PIN2,
                "leaf": true
            }
        }
    });
    let pm = PeersMap::load_from_json_for(&wrapped.to_string(), None)
        .expect("wrapped fixture with default_route must parse");
    let dr = pm.default_route_link().expect("default_route_link must be Some");
    assert_eq!(dr.name, "hub");
    assert_eq!(pm.get("cee").unwrap().address, "");
    assert!(pm.get("cee").unwrap().leaf);

    // 2. Unwrapped fixture with default_route
    let unwrapped = json!({
        "hub": {
            "address": "127.0.0.1:1234",
            "pin": DUMMY_PIN,
            "default_route": true
        }
    });
    let pm_unwrapped = PeersMap::load_from_json_for(&unwrapped.to_string(), None)
        .expect("unwrapped fixture must parse");
    assert_eq!(pm_unwrapped.default_route_link().unwrap().name, "hub");

    // 3. Multiple default routes refused mentioning "default route"
    let multi_default = json!({
        "peers": {
            "hub1": {
                "address": "127.0.0.1:1111",
                "pin": DUMMY_PIN,
                "default_route": true
            },
            "hub2": {
                "address": "127.0.0.1:2222",
                "pin": DUMMY_PIN2,
                "default_route": true
            }
        }
    });
    let err = PeersMap::load_from_json_for(&multi_default.to_string(), None)
        .expect_err("multiple default routes must error");
    let err_str = err.to_string();
    assert!(
        err_str.to_lowercase().contains("default route"),
        "error message must mention 'default route', got: {err_str}"
    );

    // 4. No default route
    let no_default = json!({
        "peers": {
            "node-a": {
                "address": "127.0.0.1:1111",
                "pin": DUMMY_PIN
            }
        }
    });
    let pm_none = PeersMap::load_from_json_for(&no_default.to_string(), None).unwrap();
    assert!(pm_none.default_route_link().is_none());

    // 5. Dialable peer without address refused, naming entry
    let no_addr = json!({
        "peers": {
            "dialable-node": {
                "pin": DUMMY_PIN
            }
        }
    });
    let err_no_addr = PeersMap::load_from_json_for(&no_addr.to_string(), None)
        .expect_err("dialable peer without address must be refused");
    assert!(
        err_no_addr.contains("dialable-node") && err_no_addr.contains("address"),
        "error must name entry and address, got: {err_no_addr}"
    );
}

fn make_ca(name: &str) -> (rcgen::CertificateParams, rcgen::KeyPair, Vec<u8>, String) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    let pem = cert.pem();
    (params, key, der, pem)
}

fn issue_cert(
    ca_params: &rcgen::CertificateParams,
    ca_key: &rcgen::KeyPair,
    name: &str,
    uri_sans: &[&str],
) -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.subject_alt_names = uri_sans
        .iter()
        .map(|u| rcgen::SanType::URI(u.to_string().try_into().unwrap()))
        .collect();
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
    let cert = params.signed_by(&key, &issuer).unwrap();
    (cert.der().to_vec(), key.serialize_der())
}

// =============================================================================
// Oracle 13: Leaf with default route queues locally, hub receives zero
// Node A has both a default route to Hub and a leaf peer (with no address).
// Sending to the leaf peer must queue in the leaf's mailbox locally on Node A;
// Hub receives 0 messages.
// Mutant: filtering direct links by !p.address.is_empty() in deliver_send => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_13_leaf_with_default_route_queues_locally_hub_gets_zero() {
    run_test_with_port_retry(
        "test_oracle_13_leaf_with_default_route_queues_locally_hub_gets_zero",
        || async move {
            let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
            let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
            let (_cert_c, _key_c, pin_c) = generate_self_signed_ed25519_pem("cee").unwrap();

            let port_a = get_free_port();
            let http_a = get_free_port();
            let port_h = get_free_port();
            let http_h = get_free_port();

            // Node A has:
            // 1. Hub with default_route: true
            // 2. Leaf peer "cee" with NO address (leaf: true)
            let peers_a = json!({
                "peers": {
                    "hub": {
                        "address": format!("127.0.0.1:{port_h}"),
                        "pin": normalize_pin(&pin_h),
                        "allow": ["send", "reply", "forward"],
                        "default_route": true
                    },
                    "cee": {
                        "pin": normalize_pin(&pin_c),
                        "allow": ["send", "reply"],
                        "leaf": true
                    }
                }
            });

            // Hub knows node-a
            let peers_h = json!({
                "peers": {
                    "node-a": {
                        "address": format!("127.0.0.1:{port_a}"),
                        "pin": normalize_pin(&pin_a),
                        "allow": ["send", "reply", "forward"]
                    }
                }
            });

            let hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
            let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

            let (_sock_a, _rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");
            let (_sock_h, rx_h) = create_claude_session_fixture(&hub.sessions_dir, "hub-sess", "HubSess");

            // Alice on Node A sends to Bob@cee
            let send_resp = send_via_agent_sock(
                &node_a.agent_sock,
                "Bob@cee",
                "hello to leaf mailbox",
            )
            .await;

            assert_eq!(send_resp["status"], "ok", "send to leaf must succeed: {send_resp}");
            assert_eq!(send_resp["outcome"], "queued", "send to leaf must be queued: {send_resp}");

            // Verify message queued in cee's mailbox locally on Node A
            let conn = rusqlite::Connection::open(&node_a.db_path).expect("open node-a db");
            let mailbox_count = storage::count_peer_mailbox_messages(&conn, "cee").expect("count mailbox messages");
            assert_eq!(mailbox_count, 1, "message must be queued in local peer mailbox for cee");

            // Wait 500ms and verify Hub receives 0 messages
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(
                rx_h.lock().unwrap().len(),
                0,
                "Hub must receive 0 messages when sending to leaf peer (Mutant: address filter => RED)"
            );
        },
    )
    .await;
}

// =============================================================================
// Oracle 14: Hub session sends to pattern-admitted client
// Hub has a default route to Upstream and pattern-admission configured.
// A client connects via mTLS, matches a pattern, and is admitted.
// When a hub session sends to this pattern-admitted client, direct link wins:
// it must not route to Upstream. Upstream receives 0 messages.
// Mutant: peers.get(n) instead of admitted-aware lookup in deliver_send => RED
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_14_hub_session_sends_to_pattern_admitted_client() {
    run_test_with_port_retry(
        "test_oracle_14_hub_session_sends_to_pattern_admitted_client",
        || async move {
            let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
            let (_cert_u, _key_u, pin_u) = generate_self_signed_ed25519_pem("upstream").unwrap();

            let port_h = get_free_port();
            let http_h = get_free_port();
            let port_u = get_free_port();

            // Create CA and issue client cert with SPIFFE URI
            let (ca_params, ca_key, _ca_der, ca_pem) = make_ca("test-ca");
            let tmp_ca = tempdir().unwrap();
            let ca_file = tmp_ca.path().join("ca.pem");
            fs::write(&ca_file, &ca_pem).unwrap();

            let client_uri = "spiffe://json64.dev/ns/genie/sa/worker";
            let (client_cert_der, client_key_der) =
                issue_cert(&ca_params, &ca_key, "worker.genie", &[client_uri]);

            // Upstream knows hub
            let listener_u = tokio::net::TcpListener::bind(("127.0.0.1", port_u)).await.unwrap();
            let upstream_conns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let conns_clone = upstream_conns.clone();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener_u.accept().await {
                    conns_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = stream.shutdown().await;
                }
            });

            // Hub has:
            // 1. Default route to upstream
            // 2. CA peer anchor
            // 3. Hub pattern admission block
            let peers_h = json!({
                "peers": {
                    "upstream": {
                        "address": format!("127.0.0.1:{port_u}"),
                        "pin": normalize_pin(&pin_u),
                        "allow": ["send", "reply", "forward"],
                        "default_route": true
                    },
                    "hub.hub": {
                        "address": "127.0.0.1:0",
                        "ca": ca_file.display().to_string(),
                        "identities": ["spiffe://json64.dev/ns/hub/sa/hub"],
                        "allow": ["send", "reply"]
                    }
                },
                "hub": {
                    "patterns": ["spiffe://json64.dev/ns/*/sa/*"],
                    "rules": [
                        {
                            "pattern": "spiffe://json64.dev/ns/genie/sa/*",
                            "allow": ["send", "reply"]
                        }
                    ]
                }
            });

            let hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;

            let (_sock_h_target, _rx_h_target) = create_claude_session_fixture(&hub.sessions_dir, "target", "Target");
            let (_sock_h, _rx_h) = create_claude_session_fixture(&hub.sessions_dir, "alice", "Alice");

            // Client connects to Hub presenting client certificate to get admitted
            let client_origin = Origin {
                cert_der: &client_cert_der,
                key_der: &client_key_der,
            };
            let (status, res) = hop_client::send_envelope(
                &client_origin,
                &pin_h,
                port_h,
                hop_client::envelope("sess-1", "Worker", "Target", "client hello"),
            )
            .await;
            assert_eq!(status, 202, "client must be admitted by hub: {res}");

            // Hub session sends to the admitted client worker.genie
            let _send_resp = send_via_agent_sock(
                &hub.agent_sock,
                "Bob@worker.genie",
                "direct link to admitted client",
            )
            .await;

            // Direct link wins over default route: hub must NOT route to upstream!
            tokio::time::sleep(Duration::from_millis(500)).await;
            let dials_to_upstream = upstream_conns.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                dials_to_upstream, 0,
                "Hub must NOT dial default route upstream for pattern-admitted client (Mutant: get instead of admitted-aware lookup => RED)"
            );
        },
    )
    .await;
}

// =============================================================================
// Oracle 15: Nickname address routes direct
// Node A has a default route to Hub and a direct peer by nickname "laptop".
// Sending to Bob@laptop routes directly to Node B; Hub receives 0 messages.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_15_nickname_address_routes_direct() {
    run_test_with_port_retry(
        "test_oracle_15_nickname_address_routes_direct",
        || async move {
            let (cert_a, key_a, pin_a) = generate_self_signed_ed25519_pem("node-a").unwrap();
            let (cert_h, key_h, pin_h) = generate_self_signed_ed25519_pem("hub").unwrap();
            let (cert_b, key_b, pin_b) = generate_self_signed_ed25519_pem("node-b").unwrap();

            let port_a = get_free_port();
            let http_a = get_free_port();
            let port_h = get_free_port();
            let http_h = get_free_port();
            let port_b = get_free_port();
            let http_b = get_free_port();

            // Node A has:
            // 1. Hub with default_route: true (Hub does NOT know node-b)
            // 2. Peer with nickname "laptop" pointing directly to node-b
            let peers_a = json!({
                "peers": {
                    "hub": {
                        "address": format!("127.0.0.1:{port_h}"),
                        "pin": normalize_pin(&pin_h),
                        "allow": ["send", "reply"],
                        "default_route": true
                    },
                    "laptop": {
                        "address": format!("127.0.0.1:{port_b}"),
                        "pin": normalize_pin(&pin_b),
                        "allow": ["send", "reply"]
                    }
                }
            });

            // Hub only knows node-a
            let peers_h = json!({
                "peers": {
                    "node-a": {
                        "address": format!("127.0.0.1:{port_a}"),
                        "pin": normalize_pin(&pin_a),
                        "allow": ["send", "reply"]
                    }
                }
            });

            // Node B knows node-a
            let peers_b = json!({
                "peers": {
                    "node-a": {
                        "address": format!("127.0.0.1:{port_a}"),
                        "pin": normalize_pin(&pin_a),
                        "allow": ["send", "reply"]
                    }
                }
            });

            let hub = spawn_test_node("hub", port_h, http_h, &cert_h, &key_h, peers_h).await;
            let node_b = spawn_test_node("node-b", port_b, http_b, &cert_b, &key_b, peers_b).await;
            let node_a = spawn_test_node("node-a", port_a, http_a, &cert_a, &key_a, peers_a).await;

            let (_sock_a, _rx_a) = create_claude_session_fixture(&node_a.sessions_dir, "alice", "Alice");
            let (_sock_b, rx_b) = create_claude_session_fixture(&node_b.sessions_dir, "bob", "Bob");
            let (_sock_h, rx_h) = create_claude_session_fixture(&hub.sessions_dir, "hub-sess", "HubSess");

            let send_resp = send_via_agent_sock(
                &node_a.agent_sock,
                "Bob@laptop",
                "hello laptop direct",
            )
            .await;

            assert_eq!(send_resp["status"], "ok", "direct send to nickname must succeed: {send_resp}");

            let b_msg = wait_for_inbox_message(&rx_b, Duration::from_secs(5))
                .await
                .expect("Bob on node-b must receive message via nickname directly");
            assert!(b_msg.contains("hello laptop direct"));

            // Hub must receive 0 messages
            assert_eq!(
                rx_h.lock().unwrap().len(),
                0,
                "Hub must receive 0 messages when nickname address routes direct"
            );
        },
    )
    .await;
}
