use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use xmsg::http::{build_router, AppState};
use xmsg::inbox::InboxLine;
use xmsg::mcp::{run_mcp_loop, McpConfig};

fn get_self_proc_start() -> String {
    let stat = fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    let rparen = stat.rfind(')').expect("closing paren in stat");
    let fields: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
    fields[19].to_string()
}

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

struct McpHarness {
    _sess_dir: TempDir,
    _proc_dir: TempDir,
    _sock_dir: TempDir,
    base_url: String,
    sessions_dir: PathBuf,
    proc_root: PathBuf,
    agent_sock: PathBuf,
    received_lines: Arc<Mutex<Vec<String>>>,
    stop_signal: Arc<AtomicBool>,
}

impl McpHarness {
    fn mcp_config(&self) -> McpConfig {
        McpConfig {
            sessions_dir: self.sessions_dir.clone(),
            xmsg_url: self.base_url.clone(),
            agent_sock: self.agent_sock.clone(),
            proc_root: self.proc_root.clone(),
            presence_dir: PathBuf::from("/tmp/nonexistent-presence"),
            proc_locks_path: PathBuf::from("/tmp/nonexistent-proc-locks"),
        }
    }
}

impl Drop for McpHarness {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

async fn start_mcp_harness() -> McpHarness {
    let sess_dir = tempdir().expect("tempdir for sessions");
    let proc_dir = tempdir().expect("tempdir for proc");
    let sock_dir = tempdir().expect("tempdir for sockets");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(sock_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_path = sock_dir.path().join("target_inbox.sock");
    let agent_sock_path = sock_dir.path().join("agent.sock");
    let my_uid = xmsg::agent::current_uid();

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    let received_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = received_lines.clone();
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_signal.clone();

    tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((mut stream, _)) = res {
                        let mut buf = Vec::new();
                        let mut temp = [0u8; 1024];
                        while let Ok(n) = stream.read(&mut temp).await {
                            if n == 0 { break; }
                            buf.extend_from_slice(&temp[..n]);
                            if buf.ends_with(b"\n") {
                                break;
                            }
                        }
                        if let Ok(s) = String::from_utf8(buf) {
                            received_clone.lock().await.push(s);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    });

    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();

    // Create target session (PID my_pid so HTTP server can verify liveness against real /proc)
    write_session_file(
        sess_dir.path(),
        my_pid,
        "sess-target-5000",
        "target-agent",
        &my_proc_start,
        &sock_path,
    );

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);

    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let app_state = Arc::new(AppState {
        sessions_dir: sess_dir.path().to_path_buf(),
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: sess_dir.path().join("presence"),
            proc_locks_path: sess_dir.path().join("proc_locks"),
            proc_root: proc_dir.path().to_path_buf(),
            agy_bin: "agy".to_string(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: Arc::new(std::sync::Mutex::new(conn)),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let app = build_router(app_state.clone());
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(tcp_listener, app).await.unwrap();
    });

    let ag_sock = agent_sock_path.clone();
    let ag_state = app_state.clone();
    tokio::spawn(async move {
        let _ = xmsg::agent::run_agent_server(ag_sock, ag_state, my_uid).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    McpHarness {
        sessions_dir: sess_dir.path().to_path_buf(),
        proc_root: proc_dir.path().to_path_buf(),
        agent_sock: agent_sock_path,
        _sess_dir: sess_dir,
        _proc_dir: proc_dir,
        _sock_dir: sock_dir,
        base_url,
        received_lines,
        stop_signal,
    }
}

async fn call_mcp_single(config: &McpConfig, req: serde_json::Value) -> Option<serde_json::Value> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let mut req_bytes = serde_json::to_vec(&req).unwrap();
        req_bytes.push(b'\n');
        let reader = Cursor::new(req_bytes);
        let mut writer = Vec::new();
        run_mcp_loop(&config, reader, &mut writer).unwrap();
        let out_str = String::from_utf8(writer).unwrap();
        let trimmed = out_str.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(serde_json::from_str(trimmed).unwrap())
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn test_mcp_initialize_and_tools_list() {
    let harness = start_mcp_harness().await;
    let config = harness.mcp_config();

    // 1. initialize with default version negotiation
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    let init_resp = call_mcp_single(&config, init_req)
        .await
        .expect("response to initialize");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "xmsg");

    // Negotiate 2024-11-05
    let init_req_2024 = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "initialize",
        "params": { "protocolVersion": "2024-11-05" }
    });
    let init_resp_2024 = call_mcp_single(&config, init_req_2024).await.unwrap();
    assert_eq!(init_resp_2024["result"]["protocolVersion"], "2024-11-05");

    // Negotiate 2025-06-18
    let init_req_2025 = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "initialize",
        "params": { "protocolVersion": "2025-06-18" }
    });
    let init_resp_2025 = call_mcp_single(&config, init_req_2025).await.unwrap();
    assert_eq!(init_resp_2025["result"]["protocolVersion"], "2025-06-18");

    // Fallback for unknown version
    let init_req_unknown = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "initialize",
        "params": { "protocolVersion": "3000-01-01" }
    });
    let init_resp_unknown = call_mcp_single(&config, init_req_unknown).await.unwrap();
    assert_eq!(init_resp_unknown["result"]["protocolVersion"], "2025-06-18");

    // 2. notifications/initialized produces no response
    let notif_req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let notif_resp = call_mcp_single(&config, notif_req).await;
    assert!(notif_resp.is_none(), "notifications produce no response");

    // 3. ping
    let ping_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "ping"
    });
    let ping_resp = call_mcp_single(&config, ping_req)
        .await
        .expect("response to ping");
    assert_eq!(ping_resp["id"], 2);
    assert_eq!(ping_resp["result"], serde_json::json!({}));

    // 4. tools/list (§8.3a)
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list"
    });
    let list_resp = call_mcp_single(&config, list_req)
        .await
        .expect("response to tools/list");
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert_eq!(tools.len(), 3, "Exactly 3 tools listed: list, send, reply");

    let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(tool_names, vec!["list", "send", "reply"]);

    // Invariant: None of the tools may have requiresUserInteraction set
    for t in tools {
        assert!(
            t.get("requiresUserInteraction").is_none(),
            "Tool {} must not have requiresUserInteraction",
            t["name"]
        );
    }

    // Invariant: send tool schema must require ref and text, and forbid from
    let send_tool = tools.iter().find(|t| t["name"] == "send").unwrap();
    let schema = &send_tool["inputSchema"];
    assert!(
        schema["properties"].get("from").is_none(),
        "send schema must not advertise 'from'"
    );
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(required, vec!["ref", "text"]);
}

#[tokio::test]
async fn test_mcp_send_rejects_from_argument() {
    let harness = start_mcp_harness().await;
    let config = harness.mcp_config();

    let call_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "send",
            "arguments": {
                "ref": "target-agent",
                "text": "Hello with spoofed from",
                "from": "spoofed-identity"
            }
        }
    });

    let resp = call_mcp_single(&config, call_req)
        .await
        .expect("response to call");
    assert_eq!(resp["id"], 10);
    let result = &resp["result"];
    assert_eq!(result["isError"], true);
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("'from' argument is forbidden"),
        "Error message must indicate 'from' is forbidden: {}",
        text
    );
}

#[tokio::test]
async fn test_mcp_send_and_reply_with_derived_caller() {
    let harness = start_mcp_harness().await;
    let my_pid = std::process::id();
    let caller_pid = 6000;
    let dummy_sock = harness.proc_root.join("caller.sock");

    // Configure ancestor hierarchy for current process:
    // PID my_pid -> PPID caller_pid (6000) -> PPID 1
    write_proc_stat(&harness.proc_root, my_pid, caller_pid, "start_curr");
    write_proc_stat(&harness.proc_root, caller_pid, 1, "start_6000");
    write_session_file(
        &harness.sessions_dir,
        caller_pid,
        "sess-caller-6000",
        "calling-orchestrator",
        "start_6000",
        &dummy_sock,
    );

    let config = harness.mcp_config();

    // 1. send message via MCP
    let send_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "send",
            "arguments": {
                "ref": "target-agent",
                "text": "Please report status on milestone 2"
            }
        }
    });

    let send_resp = call_mcp_single(&config, send_req)
        .await
        .expect("response to send");
    assert_eq!(send_resp["id"], 20);
    let result = &send_resp["result"];
    assert_eq!(result["isError"], false);
    let resp_text = result["content"][0]["text"].as_str().unwrap();
    let delivery_json: serde_json::Value = serde_json::from_str(resp_text).unwrap();
    let message_id = delivery_json["messageId"].as_str().unwrap();
    assert_eq!(delivery_json["sessionId"], "sess-target-5000");
    assert_eq!(
        delivery_json["fromName"],
        "xmsg@test-host · claude:calling-orchestrator"
    );

    // Check socket delivery to target-agent
    tokio::time::sleep(Duration::from_millis(50)).await;
    let lines = harness.received_lines.lock().await;
    assert_eq!(lines.len(), 1);
    let inbox_line: InboxLine = serde_json::from_str(lines[0].trim()).unwrap();
    assert!(inbox_line
        .message
        .content
        .contains("from-name=\"xmsg@test-host · claude:calling-orchestrator\""));
    assert!(inbox_line
        .message
        .content
        .contains("Please report status on milestone 2"));
    let expected_footer = format!(
        "[xmsg] message_id={} — reply with the xmsg reply tool",
        message_id
    );
    assert!(inbox_line.message.content.contains(&expected_footer));
    drop(lines);

    // 2. reply to the message via MCP
    // Reconfigure ancestor for target-agent (session_id = sess-target-5000)
    let target_sock = harness.proc_root.join("target.sock");
    write_session_file(
        &harness.sessions_dir,
        caller_pid,
        "sess-target-5000",
        "target-agent",
        "start_6000",
        &target_sock,
    );

    let reply_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {
            "name": "reply",
            "arguments": {
                "message_id": message_id,
                "text": "Milestone 2 status: green, all tests passing."
            }
        }
    });

    let reply_resp = call_mcp_single(&config, reply_req)
        .await
        .expect("response to reply");
    assert_eq!(reply_resp["id"], 21);
    let result = &reply_resp["result"];
    assert_eq!(result["isError"], false);
    let reply_text = result["content"][0]["text"].as_str().unwrap();
    let reply_json: serde_json::Value = serde_json::from_str(reply_text).unwrap();
    assert_eq!(reply_json["messageId"], message_id);
    assert_eq!(reply_json["replierSessionId"], "sess-target-5000");
    assert_eq!(
        reply_json["text"],
        "Milestone 2 status: green, all tests passing."
    );
}

#[tokio::test]
async fn test_mcp_list_sessions() {
    let harness = start_mcp_harness().await;
    let config = harness.mcp_config();

    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 30,
        "method": "tools/call",
        "params": {
            "name": "list",
            "arguments": {}
        }
    });

    let list_resp = call_mcp_single(&config, list_req)
        .await
        .expect("response to list");
    assert_eq!(list_resp["id"], 30);
    let result = &list_resp["result"];
    assert_eq!(result["isError"], false);
    let sessions_str = result["content"][0]["text"].as_str().unwrap();
    let sessions: Vec<serde_json::Value> = serde_json::from_str(sessions_str).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["sessionId"], "sess-target-5000");
    assert_eq!(sessions[0]["name"], "target-agent");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_shipped_binary_mcp_initialize_and_tool_call() {
    use std::io::{BufRead, BufReader, Write};

    let harness = start_mcp_harness().await;

    let binary_path = env!("CARGO_BIN_EXE_xmsg");
    let mut child = std::process::Command::new(binary_path)
        .arg("mcp")
        .arg("--sessions-dir")
        .arg(&harness.sessions_dir)
        .arg("--xmsg-url")
        .arg(&harness.base_url)
        .arg("--agent-sock")
        .arg(&harness.agent_sock)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn xmsg mcp");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);

    // 1. Send initialize
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18"
        }
    });
    let mut init_bytes = serde_json::to_vec(&init_req).unwrap();
    init_bytes.push(b'\n');
    stdin.write_all(&init_bytes).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["protocolVersion"], "2025-06-18");

    // 2. Send tools/call list
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "list",
            "arguments": {}
        }
    });
    let mut list_bytes = serde_json::to_vec(&list_req).unwrap();
    list_bytes.push(b'\n');
    stdin.write_all(&list_bytes).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let list_resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(list_resp["id"], 2);
    assert_eq!(list_resp["result"]["isError"], false);

    // Close stdin and assert process exits cleanly
    drop(stdin);
    let status = child.wait().expect("wait on child");
    assert!(
        status.success(),
        "xmsg mcp binary exited cleanly without panic: {:?}",
        status
    );
}
