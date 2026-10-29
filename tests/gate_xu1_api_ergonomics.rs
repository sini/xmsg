mod short_sock;

use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};

use serde_json::Value;

use xmsg::agent::{current_uid, run_agent_server};
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::error::AppError;
use xmsg::fed::{
    generate_self_signed_ed25519, run_fed_listener, FedState, PeerConfig, PeersMap, RateLimiter,
};
use xmsg::http::{build_router, AppState};
use xmsg::inbox::InboxLine;
use xmsg::mcp::{run_mcp_loop, McpConfig};
use xmsg::pi::new_pi_store;
use xmsg::svc::new_svc_store;

const SESS_ALICE: &str = "a11ce000-0000-0000-0000-000000000001";
const SESS_BOB: &str = "b0b00000-0000-0000-0000-000000000002";
const SESS_CHARLIE: &str = "c0000000-0000-0000-0000-000000000003";

fn write_proc_stat(proc_dir: &Path, pid: u32, ppid: u32, proc_start: &str) {
    let pid_dir = proc_dir.join(pid.to_string());
    fs::create_dir_all(&pid_dir).expect("create pid dir");
    let stat_content =
        format!("{pid} (proc_{pid}) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {proc_start} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).expect("write stat file");
}

fn write_session_file(
    sessions_dir: &Path,
    pid: u32,
    session_id: &str,
    name: &str,
    proc_start: &str,
    sock_path: &Path,
) {
    let session_json = serde_json::json!({
        "pid": pid,
        "sessionId": session_id,
        "name": name,
        "cwd": "/workspace/test",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": proc_start,
        "messagingSocketPath": sock_path.display().to_string()
    });
    fs::write(
        sessions_dir.join(format!("{pid}.json")),
        session_json.to_string(),
    )
    .expect("write session file");
}

async fn call_mcp(config: &McpConfig, req: serde_json::Value) -> serde_json::Value {
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let mut req_bytes = serde_json::to_vec(&req).unwrap();
        req_bytes.push(b'\n');
        let reader = Cursor::new(req_bytes);
        let mut writer = Vec::new();
        run_mcp_loop(&config, reader, &mut writer).unwrap();
        let out_str = String::from_utf8(writer).unwrap();
        serde_json::from_str(out_str.trim()).unwrap()
    })
    .await
    .unwrap()
}

async fn call_agent_sock(sock_path: &Path, action: &Value) -> Value {
    let mut stream = UnixStream::connect(sock_path).await.unwrap();
    let mut payload = serde_json::to_vec(action).unwrap();
    payload.push(b'\n');
    stream.write_all(&payload).await.unwrap();

    let (reader, _) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

#[allow(dead_code)]
struct NodeFixture {
    name: String,
    fed_addr: std::net::SocketAddr,
    agent_sock: PathBuf,
    http_port: u16,
    sessions_dir: PathBuf,
    proc_root: PathBuf,
    mcp_config: McpConfig,
    _temp: TempDir,
}

async fn create_node(
    name: &str,
    peers: Vec<PeerConfig>,
    creds: Option<(Vec<u8>, Vec<u8>, String)>,
    fed_listener_opt: Option<TcpListener>,
) -> NodeFixture {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = temp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_sock = short_sock::sock_path(&sock_dir, "agent");

    let sessions_dir = temp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = temp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let presence_dir = temp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();
    let proc_locks = temp.path().join("proc_locks");
    fs::write(&proc_locks, "").unwrap();

    let (cert_der, key_der, _pin) = match creds {
        Some(c) => c,
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

    let fed_listener = match fed_listener_opt {
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
    let my_uid = current_uid();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let router = build_router(app_state.clone());
    tokio::spawn(async move {
        axum::serve(http_listener, router).await.unwrap();
    });

    for _ in 0..1500 {
        if agent_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mcp_config = McpConfig {
        sessions_dirs: vec![sessions_dir.clone()],
        xmsg_url: format!("http://127.0.0.1:{http_port}"),
        http_sock: None,
        agent_sock: agent_sock.clone(),
        proc_root: proc_root.clone(),
        presence_dir: temp.path().join("presence"),
        proc_locks_path: temp.path().join("proc_locks"),
        reply_only: false,
    };

    NodeFixture {
        name: name.to_string(),
        fed_addr,
        agent_sock,
        http_port,
        sessions_dir,
        proc_root,
        mcp_config,
        _temp: temp,
    }
}

// =============================================================================
// Gate 1: Parameter Validation (Items 1 & 5)
// =============================================================================
#[tokio::test]
async fn test_gate1_parameter_validation() {
    let node = create_node("cortex", Vec::new(), None, None).await;
    let my_pid = std::process::id();
    let caller_pid = 7100;
    write_proc_stat(&node.proc_root, my_pid, caller_pid, "200");
    write_proc_stat(&node.proc_root, caller_pid, 1, "100");
    let caller_sock = node.proc_root.join("caller.sock");
    write_session_file(
        &node.sessions_dir,
        caller_pid,
        SESS_ALICE,
        "caller-agent",
        "100",
        &caller_sock,
    );

    // 1. MCP tool 'send' with 'ref' argument is refused with explicit hint
    let send_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "send",
            "arguments": {
                "ref": "some-target",
                "text": "hello"
            }
        }
    });
    let send_resp = call_mcp(&node.mcp_config, send_req).await;
    let err_msg = send_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        err_msg.contains("error: unknown argument 'ref' for tool 'send'; use 'to' instead"),
        "expected parameter hint for 'send', got: {err_msg}"
    );
    assert_eq!(send_resp["result"]["isError"], true);

    // 2. MCP tool 'list' with 'host' argument is refused with explicit hint
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "list",
            "arguments": {
                "host": "cortex"
            }
        }
    });
    let list_resp = call_mcp(&node.mcp_config, list_req).await;
    let list_err = list_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        list_err.contains("error: unknown argument 'host' for tool 'list'; use 'node' instead (or omit it to list all nodes)"),
        "expected parameter hint for 'list', got: {list_err}"
    );
    assert_eq!(list_resp["result"]["isError"], true);

    // 3. AppError::UnknownPeer detail format
    let unknown_err = AppError::UnknownPeer("fake-host".to_string());
    assert_eq!(
        unknown_err.detail(),
        "unknown node 'fake-host' (omit 'node' to list all nodes)"
    );

    // 4. HTTP Parity: POST /v1/messages with 'ref' field is rejected with 400 Bad Request
    let client = reqwest::Client::new();
    let http_send_resp = client
        .post(format!("http://127.0.0.1:{}/v1/messages", node.http_port))
        .json(&serde_json::json!({
            "ref": "some-target",
            "text": "hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(http_send_resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = http_send_resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap().contains("unknown field 'ref'; use 'to' instead"),
        "expected HTTP send refusal for ref, got: {body:?}"
    );

    // 5. HTTP Parity: GET /v1/recipients?host=cortex is rejected with 400 Bad Request
    let http_list_resp = client
        .get(format!("http://127.0.0.1:{}/v1/recipients?host=cortex", node.http_port))
        .send()
        .await
        .unwrap();
    assert_eq!(http_list_resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let list_body: Value = http_list_resp.json().await.unwrap();
    assert!(
        list_body["detail"].as_str().unwrap().contains("unknown parameter 'host'; use 'node' instead (or omit it to list all nodes)"),
        "expected HTTP list refusal for host, got: {list_body:?}"
    );
}

// =============================================================================
// Gate 2: Addressable Header & Rejecting ' · ' in 'to' (Item 2 / Amendment 1)
// =============================================================================
#[tokio::test]
async fn test_gate2_addressable_header_and_reject_dot() {
    let node = create_node("node-alpha", Vec::new(), None, None).await;
    let my_pid = std::process::id();
    let alice_pid = 7200;
    let bob_pid = 7201;

    write_proc_stat(&node.proc_root, my_pid, alice_pid, "200");
    write_proc_stat(&node.proc_root, alice_pid, 1, "100");
    write_proc_stat(&node.proc_root, bob_pid, 1, "100");

    let alice_sock = node.proc_root.join("alice.sock");
    let alice_listener = UnixListener::bind(&alice_sock).unwrap();
    let alice_rx = Arc::new(Mutex::new(Vec::new()));
    let alice_rx_clone = alice_rx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = alice_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    alice_rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    let bob_sock = node.proc_root.join("bob.sock");
    let bob_listener = UnixListener::bind(&bob_sock).unwrap();
    let bob_rx = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = bob_rx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = bob_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    // Alice's label deliberately contains '@' and ' · '
    write_session_file(
        &node.sessions_dir,
        alice_pid,
        SESS_ALICE,
        "alice@dev-corp · orchestrator",
        "100",
        &alice_sock,
    );
    write_session_file(
        &node.sessions_dir,
        bob_pid,
        SESS_BOB,
        "bob-worker",
        "100",
        &bob_sock,
    );

    // 1. Alice sends to Bob via agent.sock
    let send_res = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "send",
            "to": SESS_BOB,
            "text": "Hello Bob, check the header ref",
        }),
    )
    .await;
    assert_eq!(send_res["status"], "ok");

    // 2. Bob inspects incoming envelope: ref= MUST be attested address "SESS_ALICE@node-alpha"
    tokio::time::sleep(Duration::from_millis(50)).await;
    let received = bob_rx.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    let inbox_line: InboxLine = serde_json::from_str(received[0].trim()).unwrap();
    let content = &inbox_line.message.content;

    // Header MUST contain the machine address ref=
    let expected_ref = format!("ref={SESS_ALICE}@node-alpha");
    assert!(
        content.contains(&expected_ref),
        "header should contain '{expected_ref}', got:\n{content}"
    );
    // Header MUST NOT parse machine ref from the label (which contained @dev-corp)
    assert!(
        !content.contains("ref=alice@dev-corp"),
        "header must not build ref from the label! Got:\n{content}"
    );

    // 3. Sending to the literal ref value succeeds
    let reply_send = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "send",
            "to": format!("{SESS_ALICE}@node-alpha"),
            "text": "Direct address works",
        }),
    )
    .await;
    assert_eq!(reply_send["status"], "ok");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(alice_rx.lock().unwrap().len(), 1);

    // 4. Passing a display label containing ' · ' in 'to' is refused with migration hint
    let bad_to_res = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "send",
            "to": format!("alice@dev-corp · orchestrator · {SESS_ALICE}@node-alpha"),
            "text": "Using label as address should fail",
        }),
    )
    .await;
    assert_eq!(bad_to_res["status"], "error");
    let err_detail = bad_to_res["detail"].as_str().unwrap();
    assert!(
        err_detail.contains("'to' contains ' · '; a label is not an address. Use the header's 'ref=' address instead"),
        "expected dot rejection with hint, got: {err_detail}"
    );

    // 5. HTTP Parity: POST /v1/messages with ' · ' in 'to' returns 400 with hint
    let client = reqwest::Client::new();
    let http_resp = client
        .post(format!("http://127.0.0.1:{}/v1/messages", node.http_port))
        .json(&serde_json::json!({
            "to": format!("alice · {SESS_ALICE}@node-alpha"),
            "text": "HTTP call with dot"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(http_resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let http_body: Value = http_resp.json().await.unwrap();
    assert!(
        http_body["detail"].as_str().unwrap().contains("'to' contains ' · '; a label is not an address. Use the header's 'ref=' address instead"),
        "expected HTTP dot rejection, got: {http_body:?}"
    );
}

// =============================================================================
// Gate 3: Symmetric Reply Rule (Item 3 / Ruled Option b) - Local & Federated
// =============================================================================
#[tokio::test]
async fn test_gate3_symmetric_reply_local_and_third_party() {
    let node = create_node("local-node", Vec::new(), None, None).await;
    let my_pid = std::process::id();
    let alice_pid = 7300;
    let bob_pid = 7301;
    let charlie_pid = 7302;

    write_proc_stat(&node.proc_root, my_pid, alice_pid, "200");
    write_proc_stat(&node.proc_root, alice_pid, 1, "100");
    write_proc_stat(&node.proc_root, bob_pid, 1, "100");
    write_proc_stat(&node.proc_root, charlie_pid, 1, "100");

    let alice_sock = node.proc_root.join("alice.sock");
    let bob_sock = node.proc_root.join("bob.sock");
    let charlie_sock = node.proc_root.join("charlie.sock");

    let bob_listener = UnixListener::bind(&bob_sock).unwrap();
    let bob_rx = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = bob_rx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = bob_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    write_session_file(&node.sessions_dir, alice_pid, SESS_ALICE, "alice", "100", &alice_sock);
    write_session_file(&node.sessions_dir, bob_pid, SESS_BOB, "bob", "100", &bob_sock);
    write_session_file(&node.sessions_dir, charlie_pid, SESS_CHARLIE, "charlie", "100", &charlie_sock);

    // 1. Alice sends message M1 to Bob
    let send_res = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "send",
            "to": SESS_BOB,
            "text": "Hello Bob, this is M1",
        }),
    )
    .await;
    assert_eq!(send_res["status"], "ok");
    let m1_id = send_res["message_id"].as_str().unwrap();

    // 2. Alice calls reply(message_id = M1) answering her OWN message!
    // Symmetric rule (b): routes to Bob (counterpart)!
    let followup_res = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "message_id": m1_id,
            "text": "Alice immediate follow-up on M1",
        }),
    )
    .await;
    assert_eq!(followup_res["status"], "ok");
    assert_eq!(followup_res["reply"]["pushOutcome"], "pushed");
    let pushed_id = followup_res["reply"]["pushedMessageId"].as_str().unwrap();
    assert_ne!(pushed_id, m1_id);

    // Verify Bob receives Alice's follow-up reply in his socket
    tokio::time::sleep(Duration::from_millis(50)).await;
    let received = bob_rx.lock().unwrap().clone();
    assert_eq!(received.len(), 2, "Bob should have received M1 and Alice's reply");
    assert!(received[1].contains("Alice immediate follow-up on M1"));
    assert!(received[1].contains(&format!("reply to message_id={m1_id}")));

    // 3. Third party (Charlie) tries to reply to M1 -> refused with not_recipient
    write_proc_stat(&node.proc_root, my_pid, charlie_pid, "200");
    let charlie_reply_res = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "message_id": m1_id,
            "text": "Charlie unauthorized reply",
        }),
    )
    .await;
    assert_eq!(charlie_reply_res["status"], "error");
    assert_eq!(charlie_reply_res["error"], "denied");
    let err = charlie_reply_res["detail"].as_str().unwrap();
    assert!(
        err.contains("not the recipient of message"),
        "third party must be rejected with not_recipient, got: {err}"
    );
}

#[tokio::test]
async fn test_gate3_symmetric_reply_federated() {
    let (cert_a, key_a, pin_a) = generate_self_signed_ed25519("node_a").unwrap();
    let (cert_b, key_b, pin_b) = generate_self_signed_ed25519("node_b").unwrap();

    let node_b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_b_addr = node_b_listener.local_addr().unwrap();

    let node_a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_a_addr = node_a_listener.local_addr().unwrap();

    let node_a = create_node(
        "node_a",
        vec![PeerConfig {
            name: "node_b".to_string(),
            address: node_b_addr.to_string(),
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
        Some((cert_a.clone(), key_a.clone(), pin_a.clone())),
        Some(node_a_listener),
    )
    .await;

    let node_b = create_node(
        "node_b",
        vec![PeerConfig {
            name: "node_a".to_string(),
            address: node_a_addr.to_string(),
            pin: Some(pin_a.clone()),
            ca: None,
            identities: None,
            allow: vec!["send".to_string(), "reply".to_string()],
            from: None,
            leaf: false,
            principals: Vec::new(),
            targets: None,
            dial: None,
        }],
        Some((cert_b.clone(), key_b.clone(), pin_b.clone())),
        Some(node_b_listener),
    )
    .await;

    let my_pid = std::process::id();
    let alice_pid = 7400;
    let bob_pid = 7401;

    write_proc_stat(&node_a.proc_root, my_pid, alice_pid, "200");
    write_proc_stat(&node_a.proc_root, alice_pid, 1, "100");
    let alice_sock = node_a.proc_root.join("alice.sock");
    write_session_file(&node_a.sessions_dir, alice_pid, SESS_ALICE, "alice", "100", &alice_sock);

    write_proc_stat(&node_b.proc_root, bob_pid, 1, "100");
    let bob_sock = node_b.proc_root.join("bob.sock");
    let bob_listener = UnixListener::bind(&bob_sock).unwrap();
    let bob_rx = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = bob_rx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = bob_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });
    write_session_file(&node_b.sessions_dir, bob_pid, SESS_BOB, "bob", "100", &bob_sock);

    // 1. Alice sends federated message to Bob on node_b
    let fed_send_res = call_agent_sock(
        &node_a.agent_sock,
        &serde_json::json!({
            "action": "send",
            "to": format!("{SESS_BOB}@node_b"),
            "text": "Initial federated send M_fed",
        }),
    )
    .await;
    assert_eq!(fed_send_res["status"], "ok");
    let m_fed_id = fed_send_res["message_id"].as_str().unwrap();

    // 2. Alice on node_a calls reply answering her own federated send
    let fed_reply_res = call_agent_sock(
        &node_a.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "message_id": m_fed_id,
            "text": "Alice federated follow-up to Bob",
        }),
    )
    .await;
    assert_eq!(fed_reply_res["status"], "ok");
    assert_eq!(fed_reply_res["reply"]["pushOutcome"], "pushed");

    // 3. Bob receives Alice's follow-up across federation
    tokio::time::sleep(Duration::from_millis(100)).await;
    let received = bob_rx.lock().unwrap().clone();
    assert_eq!(received.len(), 2, "Bob on node_b should receive M_fed and Alice's federated follow-up");
    assert!(received[1].contains("Alice federated follow-up to Bob"));
    assert!(received[1].contains(&format!("reply to message_id={m_fed_id}")));
}

// =============================================================================
// Gate 4: MCP Reply Reshape & Socket Parity (Item 4 / Amendments 2 & 6)
// =============================================================================
#[tokio::test]
async fn test_gate4_mcp_reply_reshape_and_socket_parity() {
    let node = create_node("mcp-node", Vec::new(), None, None).await;
    let my_pid = std::process::id();
    let caller_pid = 7500;
    let replier_pid = 7501;

    write_proc_stat(&node.proc_root, my_pid, caller_pid, "200");
    write_proc_stat(&node.proc_root, caller_pid, 1, "100");
    write_proc_stat(&node.proc_root, replier_pid, 1, "100");

    let caller_sock = node.proc_root.join("caller.sock");
    let _caller_listener = UnixListener::bind(&caller_sock).unwrap();

    let replier_sock = node.proc_root.join("replier.sock");
    let _replier_listener = UnixListener::bind(&replier_sock).unwrap();

    write_session_file(&node.sessions_dir, caller_pid, SESS_ALICE, "caller", "100", &caller_sock);
    write_session_file(&node.sessions_dir, replier_pid, SESS_BOB, "replier", "100", &replier_sock);

    // 1. Caller sends a message to Replier
    let send_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "send",
            "arguments": {
                "to": SESS_BOB,
                "text": "Question for replier"
            }
        }
    });
    let send_resp = call_mcp(&node.mcp_config, send_req).await;
    assert_eq!(send_resp["result"]["isError"], false);
    let send_delivery: Value = serde_json::from_str(send_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let orig_msg_id = send_delivery["message_id"].as_str().unwrap();

    // 2. Switch caller to replier
    write_proc_stat(&node.proc_root, my_pid, replier_pid, "200");

    let reply_text = "Here is a detailed response that is 50 chars long!";
    let reply_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "reply",
            "arguments": {
                "message_id": orig_msg_id,
                "text": reply_text
            }
        }
    });

    let mcp_reply_resp = call_mcp(&node.mcp_config, reply_req).await;
    assert_eq!(mcp_reply_resp["id"], 11);
    assert_eq!(mcp_reply_resp["result"]["isError"], false);

    let mcp_reply_raw = mcp_reply_resp["result"]["content"][0]["text"].as_str().unwrap();
    let mcp_reply: Value = serde_json::from_str(mcp_reply_raw).unwrap();

    // Reshape Assertions (MCP tool result):
    // 1. messageId is the NEW reply's id (not the replied-to id)
    assert_ne!(
        mcp_reply["messageId"].as_str().unwrap(),
        orig_msg_id,
        "MCP messageId must be the new reply ID, not the answered ID"
    );
    // 2. inReplyTo is the answered message id
    assert_eq!(mcp_reply["inReplyTo"], orig_msg_id);
    // 3. bytes matches text length
    assert_eq!(mcp_reply["bytes"], reply_text.len());
    // 4. outcome is pushed
    assert_eq!(mcp_reply["outcome"], "pushed");
    // 5. Does NOT contain echoed text
    assert!(mcp_reply.get("text").is_none(), "MCP reply must not echo text");
    // 6. Does NOT contain pushedMessageId
    assert!(mcp_reply.get("pushedMessageId").is_none(), "MCP reply must not contain pushedMessageId");

    // Socket Parity Assertion (Amendment 6):
    // Agent-socket frame must retain ReplyRecord with pushedMessageId and text
    let socket_reply_res = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "message_id": orig_msg_id,
            "text": "Second reply via socket",
        }),
    )
    .await;
    assert_eq!(socket_reply_res["status"], "ok");
    let socket_reply = &socket_reply_res["reply"];
    assert!(
        socket_reply["pushedMessageId"].is_string(),
        "socket frame must retain pushedMessageId for matrix-xmsg compatibility"
    );
    assert_eq!(
        socket_reply["text"],
        "Second reply via socket",
        "socket frame must retain text field"
    );

    // 4. Missing pushedMessageId in socket answer yields MCP tool error (no silent fallback to message_id)
    let mock_dir = tempdir().unwrap();
    fs::set_permissions(mock_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mock_sock = short_sock::sock_path(mock_dir.path(), "mock");
    let std_listener = std::os::unix::net::UnixListener::bind(&mock_sock).unwrap();
    let orig_id_clone = orig_msg_id.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tx.send(()).unwrap();
        while let Ok((mut stream, _)) = std_listener.accept() {
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if std::io::BufRead::read_line(&mut reader, &mut line).is_ok() {
                let v: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
                if v.get("action").and_then(Value::as_str) == Some("reply") {
                    let resp = serde_json::json!({
                        "status": "ok",
                        "reply": {
                            "seq": 1,
                            "messageId": orig_id_clone,
                            "createdAt": 1000,
                            "replierSessionId": "bob",
                            "text": "test reply",
                            "pushOutcome": "pushed"
                            // deliberately omitted pushedMessageId
                        }
                    });
                    let mut out = serde_json::to_vec(&resp).unwrap();
                    out.push(b'\n');
                    let _ = std::io::Write::write_all(&mut stream, &out);
                    break;
                } else {
                    let resp = serde_json::json!({ "status": "ok" });
                    let mut out = serde_json::to_vec(&resp).unwrap();
                    out.push(b'\n');
                    let _ = std::io::Write::write_all(&mut stream, &out);
                }
            }
        }
    });
    rx.recv().unwrap();

    let mut mock_mcp_config = node.mcp_config.clone();
    mock_mcp_config.agent_sock = mock_sock;
    let missing_id_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "reply",
            "arguments": {
                "message_id": orig_msg_id,
                "text": "Reply expecting failure on missing pushedMessageId"
            }
        }
    });
    let missing_id_resp = call_mcp(&mock_mcp_config, missing_id_req).await;
    assert_eq!(missing_id_resp["id"], 12);
    assert_eq!(
        missing_id_resp["result"]["isError"], true,
        "socket answer without pushedMessageId must yield a tool error, not fall back silently"
    );
    let err_text = missing_id_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        err_text.contains("missing 'pushedMessageId' in socket response"),
        "tool error must name the missing field, got: {err_text}"
    );
}

// =============================================================================
// Gate 5: Header Names All Four Tools (Item 6 / Amendment 3)
// =============================================================================
#[tokio::test]
async fn test_gate5_header_names_all_four_tools() {
    let node = create_node("tools-node", Vec::new(), None, None).await;
    let my_pid = std::process::id();
    let alice_pid = 7600;
    let bob_pid = 7601;

    write_proc_stat(&node.proc_root, my_pid, alice_pid, "200");
    write_proc_stat(&node.proc_root, alice_pid, 1, "100");
    write_proc_stat(&node.proc_root, bob_pid, 1, "100");

    let alice_sock = node.proc_root.join("alice.sock");
    let bob_sock = node.proc_root.join("bob.sock");
    let bob_listener = UnixListener::bind(&bob_sock).unwrap();
    let bob_rx = Arc::new(Mutex::new(Vec::new()));
    let rx_clone = bob_rx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = bob_listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                if let Ok(s) = String::from_utf8(buf) {
                    rx_clone.lock().unwrap().push(s);
                }
            }
        }
    });

    write_session_file(&node.sessions_dir, alice_pid, SESS_ALICE, "alice", "100", &alice_sock);
    write_session_file(&node.sessions_dir, bob_pid, SESS_BOB, "bob", "100", &bob_sock);

    // Send message to Bob
    let send_res = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "send",
            "to": SESS_BOB,
            "text": "Inspect the tool list in the header",
        }),
    )
    .await;
    assert_eq!(send_res["status"], "ok");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let received = bob_rx.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    let inbox_line: InboxLine = serde_json::from_str(received[0].trim()).unwrap();
    let content = &inbox_line.message.content;

    // Header MUST name all four tools: send, reply, list, replies
    assert!(
        content.contains("(tools: send, reply, list, replies)"),
        "header must name all 4 tools, got:\n{content}"
    );
    // Header MUST preserve the exact anchor phrase
    assert!(
        content.contains("reply with the xmsg reply tool"),
        "header must preserve 'reply with the xmsg reply tool', got:\n{content}"
    );
}

// =============================================================================
// XH1.1 (1b): Stale MCP Client Refusal & Schema Version Check
// =============================================================================
#[tokio::test]
async fn test_xh1_1_stale_mcp_client_refusal() {
    let node = create_node("stale-node", Vec::new(), None, None).await;
    let my_pid = std::process::id();
    let alice_pid = 7700;
    let bob_pid = 7701;

    write_proc_stat(&node.proc_root, my_pid, alice_pid, "200");
    write_proc_stat(&node.proc_root, alice_pid, 1, "100");
    write_proc_stat(&node.proc_root, bob_pid, 1, "100");

    let alice_sock = node.proc_root.join("alice.sock");
    let bob_sock = node.proc_root.join("bob.sock");
    let _bob_listener = UnixListener::bind(&bob_sock).unwrap();

    write_session_file(&node.sessions_dir, alice_pid, SESS_ALICE, "alice", "100", &alice_sock);
    write_session_file(&node.sessions_dir, bob_pid, SESS_BOB, "bob", "100", &bob_sock);

    // 1. Stale v1 send frame over agent.sock (`ref` and `push_replies`, no schema_version)
    let stale_send = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "send",
            "ref": SESS_BOB,
            "text": "from old mcp",
            "push_replies": true,
        }),
    )
    .await;
    assert_eq!(stale_send["status"], "error", "{stale_send}");
    assert_eq!(stale_send["error"], "bad_request", "{stale_send}");
    let send_detail = stale_send["detail"].as_str().unwrap();
    assert!(
        send_detail.contains("`ref`")
            && send_detail.contains("stale xmsg mcp client")
            && send_detail.contains("use 'to' instead of 'ref'")
            && send_detail.contains("restart the session"),
        "expected stale-client diagnostic on v1 send frame, got: {send_detail}"
    );

    // 2. Stale v1 reply frame over agent.sock (`messageId`, no schema_version)
    let stale_reply = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": "01M4YZHHVXXK1PDY6FE0FVJTC6",
            "text": "from old mcp",
        }),
    )
    .await;
    assert_eq!(stale_reply["status"], "error", "{stale_reply}");
    assert_eq!(stale_reply["error"], "bad_request", "{stale_reply}");
    let reply_detail = stale_reply["detail"].as_str().unwrap();
    assert!(
        reply_detail.contains("`messageId`")
            && reply_detail.contains("stale xmsg mcp client")
            && reply_detail.contains("use 'message_id' instead of 'messageId'")
            && reply_detail.contains("restart the session"),
        "expected stale-client diagnostic on v1 reply frame, got: {reply_detail}"
    );

    // 3. Stale v1 list frame over agent.sock (`host`, no schema_version)
    let stale_list = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "list",
            "host": "stale-node",
        }),
    )
    .await;
    assert_eq!(stale_list["status"], "error", "{stale_list}");
    assert_eq!(stale_list["error"], "bad_request", "{stale_list}");
    let list_detail = stale_list["detail"].as_str().unwrap();
    assert!(
        list_detail.contains("`host`")
            && list_detail.contains("stale xmsg mcp client")
            && list_detail.contains("use 'node' instead of 'host'")
            && list_detail.contains("restart the session"),
        "expected stale-client diagnostic on v1 list frame, got: {list_detail}"
    );

    // 4. Mismatched schema_version on mcp_start and send is refused
    for action in [
        serde_json::json!({ "action": "mcp_start", "schema_version": 1 }),
        serde_json::json!({ "action": "send", "schema_version": 1, "to": SESS_BOB, "text": "v1" }),
    ] {
        let resp = call_agent_sock(&node.agent_sock, &action).await;
        assert_eq!(resp["status"], "error", "{resp}");
        assert_eq!(resp["error"], "bad_request", "{resp}");
        let detail = resp["detail"].as_str().unwrap();
        assert!(
            detail.contains("stale xmsg mcp client (schema_version 1, server expects 2)")
                && detail.contains("restart the session"),
            "expected schema_version mismatch refusal, got: {detail}"
        );
    }

    // 5. Current schema_version = 2 succeeds on mcp_start and send
    let ok_start = call_agent_sock(
        &node.agent_sock,
        &serde_json::json!({
            "action": "mcp_start",
            "schema_version": xmsg::surface::MCP_SCHEMA_VERSION,
        }),
    )
    .await;
    assert_eq!(ok_start["status"], "ok", "{ok_start}");

    // 6. Retired GET /v1/sessions (used by v1 xmsg mcp list) returns 404 with stale-client detail
    let client = reqwest::Client::new();
    let sessions_resp = client
        .get(format!("http://127.0.0.1:{}/v1/sessions", node.http_port))
        .send()
        .await
        .unwrap();
    assert_eq!(sessions_resp.status(), reqwest::StatusCode::NOT_FOUND);
    let sessions_body: Value = sessions_resp.json().await.unwrap();
    assert!(
        sessions_body["detail"]
            .as_str()
            .unwrap()
            .contains("GET /v1/sessions was replaced by GET /v1/recipients in schema v2")
            && sessions_body["detail"]
                .as_str()
                .unwrap()
                .contains("stale xmsg mcp client"),
        "expected retired /v1/sessions 404 diagnostic, got: {sessions_body}"
    );
}
