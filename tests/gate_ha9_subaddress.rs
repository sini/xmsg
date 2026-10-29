//! HA9-A — Delegated Sub-addresses (`<parent>/<child>`), `as_agent` MCP attestation,
//! `inbox` tool, `xmsg register claude --hook`, and harness-neutral sub-addressing (D1–D5).
//!
//! Covers:
//! - O1: `xmsg register claude --hook` PreToolUse stamp (with/without `agent_id`), fail-closed
//!   exit 2 on malformed input, and E2 (`as_agent` in all 5 MCP tool schemas).
//! - O2: Attested child `send` (`<name> · <P>/<id>@<node>`) + parent control (`<P>@<node>`) in
//!   the same run.
//! - O3: Forgery refused (`denied` / `AppError::NotRecipient`) for unbound `as_agent`, cross-session
//!   `as_agent` bound under another parent `Q`, and parent calling `inbox`.
//! - O4: Child in a turn: `send` to `<P>/<name>` returns `queued`; child `inbox` returns the
//!   message and its `<P>/<name>@<node>` address; message outcome becomes `delivered`.
//! - O5: Fallback to parent on `SubagentStop`, new send while idle, dead `turn_pid` sweep on
//!   claim scan, and socket-refused fallback retry on next claim scan.
//! - O6: Restart persistence across `xmsg serve` restart on the same `--db-path`.
//! - O7: Name collision rebind (`n` moves from `id1` to `id2`), E5 (`meta.json` at `SubagentStart`
//!   never displaces `id2`), and E1 (`reply` to `id1`'s message routes to `id1` and refuses `id2`).
//! - O9: `list` returns `kind: "subagent"` entries with parent's status; session labelled `"a/b"`
//!   still resolves via `to: "a/b"` (E3); id-shaped / `atm…` / `/` names are rejected while the
//!   child remains reachable by `<P>/<id>`.
//! - O10: Purging `P`'s `instance_seen` row cascades to `subagents` (`not_found` on send, `denied`
//!   on `as_agent`).
//! - O11 & D4: Recipient's `reply` to a child's message reaches child's `inbox` while in a turn
//!   and falls back to parent with `to=<P>/<child> agent_id=<id>` when idle, for both Claude (`O11`)
//!   and plugin (`opencode`, `D1–D5`) parents.
//! - O12: `SubagentStart` reads `meta.json` beside `transcript_path` to bind `"kid"`;
//!   `PostToolUse(SendMessage)` (`reassert_resume`) with id-shaped `to` and `pin_name == id`
//!   binds no name.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use xmsg::http::{build_router, AppState};
use xmsg::mcp::{run_mcp_loop, tool_definitions, McpConfig};
use xmsg::registry::Session;

fn write_proc_stat(proc_dir: &Path, pid: u32, ppid: u32, proc_start: &str) {
    let pid_dir = proc_dir.join(pid.to_string());
    fs::create_dir_all(&pid_dir).expect("create pid dir");
    let stat_content =
        format!("{pid} (proc_{pid}) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {proc_start} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).expect("write stat file");
}

fn remove_proc_stat(proc_dir: &Path, pid: u32) {
    let _ = fs::remove_dir_all(proc_dir.join(pid.to_string()));
}

fn write_claude_session_file(
    sessions_dir: &Path,
    pid: u32,
    session_id: &str,
    name: &str,
    proc_start: &str,
    sock_path: &Path,
) {
    let uuid_id = if xmsg::claim::is_uuid_shaped(session_id) {
        session_id.to_string()
    } else {
        format!("00000000-0000-4000-8000-{pid:012x}")
    };
    let session_json = json!({
        "pid": pid,
        "sessionId": uuid_id,
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
    .expect("write claude session file");
}

fn remove_claude_session_file(sessions_dir: &Path, pid: u32, _session_id: &str) {
    let _ = fs::remove_file(sessions_dir.join(format!("{pid}.json")));
}

struct SocketListener {
    _sock_dir: TempDir,
    sock_path: PathBuf,
    received_lines: Arc<Mutex<Vec<String>>>,
    stop_signal: Arc<AtomicBool>,
}

impl SocketListener {
    async fn start(name: &str) -> Self {
        let sock_dir = tempdir().expect("tempdir for socket");
        let sock_path = sock_dir.path().join(format!("{name}.sock"));
        Self::bind_at(sock_dir, sock_path).await
    }

    async fn bind_at(sock_dir: TempDir, sock_path: PathBuf) -> Self {
        let _ = fs::remove_file(&sock_path);
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
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
        });

        Self {
            _sock_dir: sock_dir,
            sock_path,
            received_lines,
            stop_signal,
        }
    }

    async fn wait_for_lines(&self, count: usize) -> Vec<String> {
        for _ in 0..300 {
            let lines = self.received_lines.lock().await.clone();
            if lines.len() >= count {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.received_lines.lock().await.clone()
    }

    async fn clear(&self) {
        self.received_lines.lock().await.clear();
    }
}

impl Drop for SocketListener {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

struct Ha9Harness {
    _tmp: TempDir,
    state: Arc<AppState>,
    sessions_dir: PathBuf,
    proc_root: PathBuf,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    http_sock: PathBuf,
    base_url: String,
    node_name: String,
}

impl Ha9Harness {
    async fn start(reply_ttl_secs: u64) -> Self {
        let tmp = tempdir().expect("tempdir for Ha9Harness");
        let sessions_dir = tmp.path().join("sessions");
        let proc_root = tmp.path().join("proc");
        let sock_dir = tmp.path().join("xmsg");
        fs::create_dir_all(&sessions_dir).unwrap();
        fs::create_dir_all(&proc_root).unwrap();
        fs::create_dir_all(&sock_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let db_path = tmp.path().join("xmsg.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        xmsg::storage::init_db(&conn).unwrap();

        let (notify_tx, _) = tokio::sync::broadcast::channel(32);
        let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
        let node_name = "test-node".to_string();

        let state = Arc::new(AppState {
            sessions_dirs: vec![sessions_dir.clone()],
            agy_config: xmsg::agy::AgyConfig {
                presence_dir: tmp.path().join("presence"),
                proc_locks_path: tmp.path().join("proc_locks"),
                proc_root: proc_root.clone(),
                agy_bin: "agy".to_string(),
                trusted_agy_exes: Vec::new(),
            },
            agy_store: xmsg::agy::new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            node_name: node_name.clone(),
            max_body: 65536,
            request_counter: AtomicU64::new(1),
            db: Arc::new(std::sync::Mutex::new(conn)),
            notify_tx,
            reply_ttl: Duration::from_secs(reply_ttl_secs),
            idempotency_ttl: Duration::from_secs(86400),
            long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
            fed_state: None,
        });

        let app = build_router(state.clone());
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp_listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        tokio::spawn(async move {
            let _ = axum::serve(tcp_listener, app).await;
        });

        let http_sock = sock_dir.join("http.sock");
        let http_listener = UnixListener::bind(&http_sock).unwrap();
        let app_unix = build_router(state.clone());
        tokio::spawn(async move {
            let _ = axum::serve(http_listener, app_unix).await;
        });

        let agent_sock = sock_dir.join("agent.sock");
        let ag_sock = agent_sock.clone();
        let ag_state = state.clone();
        let my_uid = xmsg::agent::current_uid();
        tokio::spawn(async move {
            let _ = xmsg::agent::run_agent_server(ag_sock, ag_state, my_uid).await;
        });

        let register_sock = sock_dir.join("register.sock");
        let reg_sock = register_sock.clone();
        let reg_state = state.clone();
        tokio::spawn(async move {
            let _ = xmsg::agy::run_register_server(
                reg_sock,
                reg_state,
                my_uid,
                std::collections::HashMap::new(),
            )
            .await;
        });

        for _ in 0..500 {
            if agent_sock.exists() && register_sock.exists() && http_sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(agent_sock.exists() && register_sock.exists());

        Self {
            _tmp: tmp,
            state,
            sessions_dir,
            proc_root,
            agent_sock,
            register_sock,
            http_sock,
            base_url,
            node_name,
        }
    }

    fn set_caller_parent(&self, parent_pid: u32) {
        let my_pid = std::process::id();
        write_proc_stat(&self.proc_root, my_pid, parent_pid, "2000");
    }

    fn mcp_config(&self) -> McpConfig {
        McpConfig {
            sessions_dirs: vec![self.sessions_dir.clone()],
            xmsg_url: self.base_url.clone(),
            http_sock: Some(self.http_sock.clone()),
            agent_sock: self.agent_sock.clone(),
            proc_root: self.proc_root.clone(),
            presence_dir: self._tmp.path().join("presence"),
            proc_locks_path: self._tmp.path().join("proc_locks"),
            reply_only: false,
        }
    }

    async fn agent_frame(&self, frame: Value) -> Value {
        let mut stream = UnixStream::connect(&self.agent_sock).await.unwrap();
        stream
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let (r, _) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).expect("valid agent.sock json response")
    }

    async fn mcp_tool_call(&self, name: &str, arguments: Value) -> Value {
        let config = self.mcp_config();
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            }
        });
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

    async fn http(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        let mut stream = UnixStream::connect(&self.http_sock).await.unwrap();
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let req = if body.is_some() {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )
        } else {
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        };
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        let (head, body_str) = raw.split_once("\r\n\r\n").unwrap();
        let status: u16 = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let val =
            serde_json::from_str(body_str).unwrap_or_else(|_| Value::String(body_str.to_string()));
        (status, val)
    }

    async fn http_send(&self, to: &str, text: &str) -> (u16, Value) {
        self.http(
            "POST",
            "/v1/messages",
            Some(&json!({ "to": to, "from": "ci-sender", "text": text })),
        )
        .await
    }

    async fn http_list(&self, query: &str) -> Vec<Value> {
        let path = if query.is_empty() {
            "/v1/recipients".to_string()
        } else {
            format!("/v1/recipients?{query}")
        };
        let (status, body) = self.http("GET", &path, None).await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_value(body["recipients"].clone()).unwrap()
    }

    async fn register_claude(
        &self,
        pid: u32,
        _native_id: &str,
        label: &str,
        sock_path: &Path,
    ) -> String {
        let uuid_id = format!("00000000-0000-4000-8000-{pid:012x}");
        write_proc_stat(&self.proc_root, pid, 1, "1000");
        write_claude_session_file(&self.sessions_dir, pid, &uuid_id, label, "1000", sock_path);
        let recs = self.http_list("").await;
        let entry = recs
            .iter()
            .find(|r| r["label"] == label && r["kind"] == "instance")
            .unwrap_or_else(|| panic!("expected claude session '{label}' in {recs:?}"));
        let addr = entry["address"].as_str().unwrap();
        addr.split('@').next().unwrap().to_string()
    }
}

struct PluginConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next: u64,
}

impl PluginConn {
    async fn open(sock: &Path, harness: &str) -> PluginConn {
        let stream = UnixStream::connect(sock).await.unwrap();
        let (r, w) = stream.into_split();
        let mut conn = PluginConn {
            reader: BufReader::new(r),
            writer: w,
            next: 0,
        };
        conn.writer
            .write_all(format!("{}\n", json!({ "harness": harness })).as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        conn.reader.read_line(&mut line).await.unwrap();
        let hello: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(hello["status"], "ok", "{hello}");
        conn
    }

    async fn call(&mut self, mut frame: Value) -> Value {
        self.next += 1;
        let rid = format!("r{}", self.next);
        frame
            .as_object_mut()
            .unwrap()
            .insert("request_id".into(), Value::String(rid.clone()));
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
            .await
            .expect("register.sock plugin answer")
            .unwrap();
        let resp: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["request_id"], rid, "{resp}");
        resp
    }
}

fn run_hook_stdin(stdin_payload: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .arg("register")
        .arg("claude")
        .arg("--hook")
        .env("XDG_RUNTIME_DIR", "/tmp/xmsg-nonexistent-runtime-dir")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xmsg register claude --hook");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(stdin_payload.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// =============================================================================
// O1 & E2: Hook stamp (`xmsg register claude --hook`) + fail-closed exit 2 +
// `as_agent` in all 5 MCP tool schemas.
// =============================================================================
#[tokio::test]
async fn test_ha9_o1_hook_stamp_and_fail_closed() {
    // E2: Every MCP tool (`list`, `send`, `reply`, `replies`, `inbox`) must declare `as_agent`.
    let arr = tool_definitions();
    for expected in ["list", "send", "reply", "replies", "inbox"] {
        let tool = arr
            .iter()
            .find(|t| t["name"] == expected)
            .unwrap_or_else(|| panic!("missing MCP tool '{expected}'"));
        assert!(
            tool["inputSchema"]["properties"]["as_agent"].is_object(),
            "E2: tool '{expected}' must declare inputSchema.properties.as_agent: {tool}"
        );
    }
    let list_tool = arr.iter().find(|t| t["name"] == "list").unwrap();
    let kinds = list_tool["inputSchema"]["properties"]["kind"]["enum"]
        .as_array()
        .unwrap();
    assert!(
        kinds.iter().any(|k| k == "subagent"),
        "list kind enum must include 'subagent': {kinds:?}"
    );

    // 1. PreToolUse WITH `agent_id`, whose `tool_input.as_agent` names a sibling -> overwrites with `agent_id`.
    let (rc1, out1, err1) = run_hook_stdin(
        &json!({
            "hook_event_name": "PreToolUse",
            "agent_id": "0123456789abcdef0",
            "tool_name": "mcp__plugin_hm_xmsg__send",
            "tool_input": {
                "to": "recip",
                "text": "hello",
                "as_agent": "sibling9999999999"
            }
        })
        .to_string(),
    );
    assert_eq!(rc1, 0, "stderr: {err1}");
    let v1: Value = serde_json::from_str(out1.trim()).expect("valid hook JSON output");
    assert_eq!(
        v1["hookSpecificOutput"]["updatedInput"]["as_agent"], "0123456789abcdef0",
        "O1: PreToolUse with agent_id must overwrite tool_input.as_agent: {v1}"
    );
    assert_eq!(v1["hookSpecificOutput"]["updatedInput"]["to"], "recip");

    // 2. PreToolUse WITHOUT `agent_id`, whose `tool_input.as_agent` names a child -> overwrites with `""`.
    let (rc2, out2, err2) = run_hook_stdin(
        &json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__plugin_hm_xmsg__send",
            "tool_input": {
                "to": "recip",
                "text": "hello",
                "as_agent": "0123456789abcdef0"
            }
        })
        .to_string(),
    );
    assert_eq!(rc2, 0, "stderr: {err2}");
    let v2: Value = serde_json::from_str(out2.trim()).expect("valid hook JSON output");
    assert_eq!(
        v2["hookSpecificOutput"]["updatedInput"]["as_agent"],
        "",
        "O1: PreToolUse without agent_id must overwrite tool_input.as_agent with empty string: {v2}"
    );

    // 3. Malformed stdin -> exit 2 and no `updatedInput`.
    let (rc3, out3, _err3) = run_hook_stdin("{malformed json");
    assert_eq!(rc3, 2, "O1: malformed stdin must exit 2 (got {rc3})");
    assert!(
        !out3.contains("updatedInput"),
        "O1: malformed stdin must not emit updatedInput: {out3}"
    );

    // 4. PreToolUse missing object `tool_input` -> exit 2 and no `updatedInput`.
    let (rc4, out4, _err4) = run_hook_stdin(
        &json!({
            "hook_event_name": "PreToolUse",
            "agent_id": "0123456789abcdef0"
        })
        .to_string(),
    );
    assert_eq!(rc4, 2, "O1: missing tool_input must exit 2 (got {rc4})");
    assert!(!out4.contains("updatedInput"));
}

// =============================================================================
// O2: Attested send (`<name> · <P>/<id>@<node>`) + parent control (`<P>@<node>`)
// in the same run.
// =============================================================================
#[tokio::test]
async fn test_ha9_o2_attested_send_and_parent_control() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let r_sock = SocketListener::start("r_inbox").await;

    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    let r_id = h
        .register_claude(5000, "claude-r", "recip-r", &r_sock.sock_path)
        .await;
    h.set_caller_parent(4000);

    let child_id = "0123456789abcdef0";
    let start_resp = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": child_id,
        }))
        .await;
    assert_eq!(start_resp["status"], "ok", "{start_resp}");

    let bind_resp = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "bind_spawn",
            "agent_id": child_id,
            "name": "worker",
        }))
        .await;
    assert_eq!(bind_resp["status"], "ok", "{bind_resp}");

    // Child MCP send with `as_agent = child_id`
    let child_mcp = h
        .mcp_tool_call(
            "send",
            json!({
                "to": r_id,
                "text": "from-child",
                "as_agent": child_id,
            }),
        )
        .await;
    assert_ne!(
        child_mcp["result"]["isError"],
        Value::Bool(true),
        "child mcp send failed: {child_mcp}"
    );

    // Parent MCP send in the same run with `as_agent = ""`
    let parent_mcp = h
        .mcp_tool_call(
            "send",
            json!({
                "to": r_id,
                "text": "from-parent",
                "as_agent": "",
            }),
        )
        .await;
    assert_ne!(
        parent_mcp["result"]["isError"],
        Value::Bool(true),
        "parent mcp send failed: {parent_mcp}"
    );

    let lines = r_sock.wait_for_lines(2).await;
    assert_eq!(lines.len(), 2, "expected 2 lines on R's socket: {lines:?}");

    let c0: Value = serde_json::from_str(&lines[0]).unwrap();
    let content0 = c0["message"]["content"].as_str().unwrap();
    let expected_child_from = format!("from-name=\"worker · {p_id}/{child_id}@{}\"", h.node_name);
    let expected_child_ref = format!("ref={p_id}/{child_id}@{}", h.node_name);
    assert!(
        content0.contains(&expected_child_from) && content0.contains(&expected_child_ref),
        "O2: child send must be labelled '{expected_child_from}' with '{expected_child_ref}', got: {content0}"
    );

    let c1: Value = serde_json::from_str(&lines[1]).unwrap();
    let content1 = c1["message"]["content"].as_str().unwrap();
    let expected_parent_from = format!("from-name=\"parent-p · {p_id}@{}\"", h.node_name);
    let expected_parent_ref = format!("ref={p_id}@{}", h.node_name);
    assert!(
        content1.contains(&expected_parent_from) && content1.contains(&expected_parent_ref),
        "O2: parent send must be labelled '{expected_parent_from}' with '{expected_parent_ref}', got: {content1}"
    );
}

// =============================================================================
// O3: Forgery refused (`denied` / `AppError::NotRecipient`) for unbound `as_agent`,
// cross-session `as_agent` bound under `Q`, and parent calling `inbox`.
// =============================================================================
#[tokio::test]
async fn test_ha9_o3_forgery_refused() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let q_sock = SocketListener::start("q_inbox").await;

    let _p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    let q_id = h
        .register_claude(6000, "claude-q", "parent-q", &q_sock.sock_path)
        .await;

    // Bind `id_q` under Q
    h.set_caller_parent(6000);
    let id_q = "fedcba98765432100";
    let start_q = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": id_q,
        }))
        .await;
    assert_eq!(start_q["status"], "ok", "{start_q}");

    // Switch caller back to P (4000)
    h.set_caller_parent(4000);

    // 1. Unbound `as_agent` under P -> refused with wire `denied` (`AppError::NotRecipient`)
    let forged_unbound = h
        .agent_frame(json!({
            "action": "send",
            "to": q_id,
            "text": "forged",
            "as_agent": "unbound1234567890",
        }))
        .await;
    assert_eq!(forged_unbound["status"], "error", "{forged_unbound}");
    assert_eq!(
        forged_unbound["error"], "denied",
        "O3: unbound as_agent must be refused 'denied' (NotRecipient): {forged_unbound}"
    );

    // 2. Cross-session `as_agent` (`id_q` bound under Q, presented by P) -> refused `denied`
    for frame in [
        json!({
            "action": "send",
            "to": q_id,
            "text": "cross-session-forged",
            "as_agent": id_q,
        }),
        json!({
            "action": "inbox",
            "wait": 0,
            "as_agent": id_q,
        }),
    ] {
        let resp = h.agent_frame(frame).await;
        assert_eq!(resp["status"], "error", "{resp}");
        assert_eq!(
            resp["error"], "denied",
            "O3: cross-session as_agent must be refused 'denied': {resp}"
        );
    }

    // 3. Parent calling `inbox` with `as_agent: ""` -> refused `denied`
    let parent_inbox = h
        .agent_frame(json!({
            "action": "inbox",
            "wait": 0,
            "as_agent": "",
        }))
        .await;
    assert_eq!(parent_inbox["status"], "error", "{parent_inbox}");
    assert_eq!(
        parent_inbox["error"], "denied",
        "O3: parent calling inbox must be refused 'denied': {parent_inbox}"
    );
}

// =============================================================================
// O4: Child in a turn: `send` to `<P>/<name>` returns `queued`; child's `inbox`
// returns the message and its `<P>/<name>@<node>` address; outcome becomes `delivered`.
// =============================================================================
#[tokio::test]
async fn test_ha9_o4_child_in_turn_inbox_delivery() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    h.set_caller_parent(4000);

    let child_id = "0123456789abcdef0";
    h.agent_frame(json!({
        "action": "subagent",
        "event": "start",
        "agent_id": child_id,
        "name": "worker",
    }))
    .await;

    // Send to `<P>/worker` while child is in a turn -> HTTP 202 `queued`, canonical `<P>/<id>@<node>`
    let (status, sent) = h
        .http_send(&format!("{p_id}/worker"), "task-for-worker")
        .await;
    assert_eq!(status, 202, "{sent}");
    assert_eq!(
        sent["outcome"], "queued",
        "O4: send to in-turn child must queue: {sent}"
    );
    assert_eq!(
        sent["address"],
        format!("{p_id}/{child_id}@{}", h.node_name),
        "O4: send response address must be canonical <P>/<id>@<node>: {sent}"
    );
    let msg_id = sent["message_id"].as_str().unwrap().to_string();

    // Parent socket must NOT have received it while child is in turn
    assert!(p_sock.received_lines.lock().await.is_empty());

    // Child calls `inbox` with `as_agent = child_id`
    let inbox_resp = h
        .agent_frame(json!({
            "action": "inbox",
            "wait": 0,
            "as_agent": child_id,
        }))
        .await;
    assert_eq!(inbox_resp["status"], "ok", "{inbox_resp}");
    assert_eq!(
        inbox_resp["address"],
        format!("{p_id}/worker@{}", h.node_name),
        "O4: inbox must report child's named address <P>/<name>@<node>: {inbox_resp}"
    );
    let msgs = inbox_resp["messages"].as_array().unwrap();
    assert_eq!(
        msgs.len(),
        1,
        "O4: inbox must return 1 queued message: {inbox_resp}"
    );
    assert_eq!(msgs[0]["id"], msg_id);
    assert!(
        msgs[0]["body"]
            .as_str()
            .unwrap_or("")
            .contains("task-for-worker"),
        "O4: inbox body must contain 'task-for-worker': {}",
        msgs[0]
    );

    // Verify message outcome in `messages` table is now `"delivered"`
    let db_outcome: String = {
        let db = h.state.db.lock().unwrap();
        db.query_row(
            "SELECT outcome FROM messages WHERE id = ?1",
            rusqlite::params![msg_id],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        db_outcome, "delivered",
        "O4: inbox must mark taken messages as 'delivered' in messages table"
    );

    // Second `inbox` call must be empty
    let inbox_again = h
        .agent_frame(json!({
            "action": "inbox",
            "wait": 0,
            "as_agent": child_id,
        }))
        .await;
    assert_eq!(inbox_again["messages"].as_array().unwrap().len(), 0);
}

// =============================================================================
// O5: Fallback to parent on `SubagentStop`, new send while idle, stranded turn
// (`turn_pid` dead) on next claim scan, and fallback push socket-refusal retry.
// =============================================================================
#[tokio::test]
async fn test_ha9_o5_fallback_on_stop_dead_pid_and_socket_retry() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    h.set_caller_parent(4000);

    let child_id = "0123456789abcdef0";
    h.agent_frame(json!({
        "action": "subagent",
        "event": "start",
        "agent_id": child_id,
        "name": "worker",
    }))
    .await;

    // 1. Queue a message while in a turn, then send `SubagentStop` -> falls back to P's socket
    let (status1, sent1) = h
        .http_send(&format!("{p_id}/worker"), "pending-at-stop")
        .await;
    assert_eq!(status1, 202);
    assert_eq!(sent1["outcome"], "queued");

    let stop_resp = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "stop",
            "agent_id": child_id,
        }))
        .await;
    assert_eq!(stop_resp["status"], "ok", "{stop_resp}");

    let expected_header = format!("to={p_id}/worker agent_id={child_id}");
    let lines1 = p_sock.wait_for_lines(1).await;
    assert_eq!(
        lines1.len(),
        1,
        "O5: pending message must reach P's socket after SubagentStop: {lines1:?}"
    );
    assert!(
        lines1[0].contains(&expected_header) && lines1[0].contains("pending-at-stop"),
        "O5: fallback line must carry '{expected_header}', got: {}",
        lines1[0]
    );
    p_sock.clear().await;

    // 2. New send to `<P>/worker` while child is idle -> reaches P's socket immediately
    let (status2, sent2) = h
        .http_send(&format!("{p_id}/worker"), "sent-while-idle")
        .await;
    assert_eq!(status2, 202, "{sent2}");
    assert_eq!(sent2["outcome"], "delivered", "{sent2}");
    let lines2 = p_sock.wait_for_lines(1).await;
    assert_eq!(lines2.len(), 1);
    assert!(
        lines2[0].contains(&expected_header) && lines2[0].contains("sent-while-idle"),
        "O5: idle send fallback must carry '{expected_header}', got: {}",
        lines2[0]
    );
    p_sock.clear().await;

    // 3. Stranded turn (`turn_pid` dead): falls back on the next claim scan
    h.agent_frame(json!({
        "action": "subagent",
        "event": "start",
        "agent_id": child_id,
    }))
    .await;
    let (status3, sent3) = h
        .http_send(&format!("{p_id}/worker"), "stranded-in-dead-turn")
        .await;
    assert_eq!(status3, 202);
    assert_eq!(sent3["outcome"], "queued");

    // Simulate dead `turn_pid` (process 4500 existed at start, then exited)
    {
        let db = h.state.db.lock().unwrap();
        db.execute(
            "UPDATE subagents SET turn_pid = 4500, turn_start = '1500' WHERE parent = ?1 AND agent_id = ?2",
            rusqlite::params![p_id, child_id],
        )
        .unwrap();
    }
    remove_proc_stat(&h.proc_root, 4500);

    // Trigger claim scan via `list`
    let _ = h.http_list("").await;
    let lines3 = p_sock.wait_for_lines(1).await;
    assert_eq!(
        lines3.len(),
        1,
        "O5: stranded turn with dead turn_pid must fall back on next claim scan"
    );
    assert!(
        lines3[0].contains(&expected_header) && lines3[0].contains("stranded-in-dead-turn"),
        "O5: dead-turn fallback must carry '{expected_header}', got: {}",
        lines3[0]
    );
    p_sock.clear().await;

    // 4. Fallback push that P's socket refuses once is queued and delivered on the next claim scan
    let dead_sock_path = h._tmp.path().join("refused_once.sock");
    write_claude_session_file(
        &h.sessions_dir,
        4000,
        "claude-p",
        "parent-p",
        "1000",
        &dead_sock_path,
    );
    let (status4, sent4) = h
        .http_send(&format!("{p_id}/worker"), "retry-after-refusal")
        .await;
    assert_eq!(
        status4, 202,
        "O5: refused fallback socket push must queue for retry: {sent4}"
    );
    assert_eq!(sent4["outcome"], "queued", "{sent4}");

    // Restore P's working socket and run next claim scan
    write_claude_session_file(
        &h.sessions_dir,
        4000,
        "claude-p",
        "parent-p",
        "1000",
        &p_sock.sock_path,
    );
    let _ = h.http_list("").await;
    let lines4 = p_sock.wait_for_lines(1).await;
    assert_eq!(
        lines4.len(),
        1,
        "O5: queued fallback must deliver on next claim scan once P's socket accepts"
    );
    assert!(
        lines4[0].contains(&expected_header) && lines4[0].contains("retry-after-refusal"),
        "O5: retried fallback must carry '{expected_header}', got: {}",
        lines4[0]
    );
}

// =============================================================================
// O6: Restart persistence: kill and restart `xmsg serve` on the same `--db-path`;
// re-register P with the same session id; `<P>/<name>` and `<P>/<id>` both resolve.
// =============================================================================
struct ServeProcess {
    child: Child,
    http_sock: PathBuf,
    agent_sock: PathBuf,
}

impl ServeProcess {
    fn spawn(run_dir: &Path, db_path: &Path, sessions_dir: &Path) -> Self {
        let http_sock = run_dir.join("http.sock");
        let agent_sock = run_dir.join("agent.sock");
        let register_sock = run_dir.join("register.sock");
        let _ = fs::remove_file(&http_sock);
        let _ = fs::remove_file(&agent_sock);
        let _ = fs::remove_file(&register_sock);

        let mut child = Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .env("XDG_RUNTIME_DIR", run_dir)
            .env("HOME", run_dir)
            .env_remove("XMSG_HOST_LABEL")
            .arg("serve")
            .arg("--db-path")
            .arg(db_path)
            .arg("--sessions-dir")
            .arg(sessions_dir)
            .arg("--http-sock")
            .arg(&http_sock)
            .arg("--agent-sock")
            .arg(&agent_sock)
            .arg("--register-sock")
            .arg(&register_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn xmsg serve");

        for _ in 0..600 {
            if let Ok(Some(_)) = child.try_wait() {
                panic!("xmsg serve exited early");
            }
            if http_sock.exists() && agent_sock.exists() && register_sock.exists() {
                return Self {
                    child,
                    http_sock,
                    agent_sock,
                };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("xmsg serve did not bind sockets in time");
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ServeProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

#[tokio::test]
async fn test_ha9_o6_restart_persistence() {
    let tmp = tempdir().unwrap();
    let run_dir = tmp.path().join("xmsg");
    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let db_path = tmp.path().join("xmsg.db");
    let p_sock = SocketListener::start("p_restart").await;

    // Register the current test process as Claude session P in `/proc`
    let my_pid = std::process::id();
    let my_start = xmsg::process::starttime(Path::new("/proc"), my_pid).unwrap();
    write_claude_session_file(
        &sessions_dir,
        my_pid,
        "claude-persist-p",
        "persist-p",
        &my_start,
        &p_sock.sock_path,
    );

    let mut srv1 = ServeProcess::spawn(&run_dir, &db_path, &sessions_dir);

    // Sync claims via agent.sock `list` and bind subagent `(P, child_id)` with `name = "worker"`
    let mut stream = UnixStream::connect(&srv1.agent_sock).await.unwrap();
    stream
        .write_all(format!("{}\n", json!({ "action": "list" })).as_bytes())
        .await
        .unwrap();
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let list_val: Value = serde_json::from_str(&line).unwrap();
    let p_addr = list_val["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["label"] == "persist-p")
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    let p_id = p_addr.split('@').next().unwrap().to_string();

    let child_id = "0123456789abcdef0";
    for frame in [
        json!({ "action": "subagent", "event": "start", "agent_id": child_id, "name": "worker" }),
        json!({ "action": "subagent", "event": "stop", "agent_id": child_id }),
    ] {
        w.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let resp: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["status"], "ok", "{resp}");
    }
    drop(w);
    drop(reader);

    // Kill first server and spawn a fresh `xmsg serve` on the same `--db-path`
    srv1.stop();
    let srv2 = ServeProcess::spawn(&run_dir, &db_path, &sessions_dir);

    // Send to both `<P>/worker` and `<P>/<id>` against the restarted server
    for (target, body_text) in [
        (format!("{p_id}/worker"), "after-restart-by-name"),
        (format!("{p_id}/{child_id}"), "after-restart-by-id"),
    ] {
        let mut s = UnixStream::connect(&srv2.http_sock).await.unwrap();
        let payload = json!({ "to": target, "from": "ci", "text": body_text }).to_string();
        let req = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).await.unwrap();
        assert!(
            raw.starts_with("HTTP/1.1 202"),
            "O6: {target} must resolve and deliver after restart: {raw}"
        );
    }

    let lines = p_sock.wait_for_lines(2).await;
    assert_eq!(
        lines.len(),
        2,
        "O6: both sends must reach P after restart: {lines:?}"
    );
    assert!(lines[0].contains("after-restart-by-name"));
    assert!(lines[1].contains("after-restart-by-id"));
}

// =============================================================================
// O7, E1 & E5: Name collision (`n` moves from `id1` to `id2`), `meta.json` at
// `SubagentStart` does not steal `n` back (E5), and replies to `id1`'s message
// route to `id1` while `id2`'s reply is refused `denied` (E1).
// =============================================================================
#[tokio::test]
async fn test_ha9_o7_collision_rebind_and_identity_isolation() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let r_sock = SocketListener::start("r_inbox").await;

    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    let r_id = h
        .register_claude(5000, "claude-r", "recip-r", &r_sock.sock_path)
        .await;
    h.set_caller_parent(4000);

    let id1 = "11111111111111111";
    let id2 = "22222222222222222";

    // Bind `n` to `id1`
    h.agent_frame(json!({ "action": "subagent", "event": "start", "agent_id": id1 }))
        .await;
    h.agent_frame(json!({
        "action": "subagent",
        "event": "bind_spawn",
        "agent_id": id1,
        "name": "n"
    }))
    .await;

    // `id1` sends a message `m1` to `R` while holding name `"n"`
    let sent_m1 = h
        .agent_frame(json!({
            "action": "send",
            "to": r_id,
            "text": "from-id1",
            "as_agent": id1,
        }))
        .await;
    assert_eq!(sent_m1["status"], "ok", "{sent_m1}");
    let m1_id = sent_m1["message_id"].as_str().unwrap().to_string();

    // Now bind `n` to `id2` (spawn takeover per OQ1)
    h.agent_frame(json!({ "action": "subagent", "event": "start", "agent_id": id2 }))
        .await;
    h.agent_frame(json!({
        "action": "subagent",
        "event": "bind_spawn",
        "agent_id": id2,
        "name": "n"
    }))
    .await;

    // `<P>/n` must resolve to `id2`, and `<P>/<id1>` must still resolve to `id1`
    let (_, to_n) = h.http_send(&format!("{p_id}/n"), "for-current-n").await;
    assert_eq!(
        to_n["address"],
        format!("{p_id}/{id2}@{}", h.node_name),
        "O7: <P>/n must resolve to id2 after rebind: {to_n}"
    );
    let (_, to_id1) = h
        .http_send(&format!("{p_id}/{id1}"), "for-id1-direct")
        .await;
    assert_eq!(
        to_id1["address"],
        format!("{p_id}/{id1}@{}", h.node_name),
        "O7: <P>/<id1> must still resolve to id1: {to_id1}"
    );
    // Drain the two messages from `id2` and `id1` inboxes
    let _ = h
        .agent_frame(json!({ "action": "inbox", "wait": 0, "as_agent": id2 }))
        .await;
    let _ = h
        .agent_frame(json!({ "action": "inbox", "wait": 0, "as_agent": id1 }))
        .await;

    // E5: A `SubagentStart` for `id1` whose `meta.json` still says `"name": "n"` must NOT take `"n"` back from `id2`!
    let transcript_stem = h._tmp.path().join("sess-e5");
    let subagents_dir = transcript_stem.join("subagents");
    fs::create_dir_all(&subagents_dir).unwrap();
    fs::write(
        subagents_dir.join(format!("agent-{id1}.meta.json")),
        json!({ "name": "n", "agentType": "general-purpose" }).to_string(),
    )
    .unwrap();
    let transcript_path = format!("{}.jsonl", transcript_stem.display());
    h.agent_frame(json!({
        "action": "subagent",
        "event": "start",
        "agent_id": id1,
        "transcript_path": transcript_path,
    }))
    .await;

    let (_, to_n_after_meta) = h.http_send(&format!("{p_id}/n"), "check-n-holder").await;
    assert_eq!(
        to_n_after_meta["address"],
        format!("{p_id}/{id2}@{}", h.node_name),
        "E5/O7: meta.json at SubagentStart for id1 must NOT take 'n' back from id2: {to_n_after_meta}"
    );
    let _ = h
        .agent_frame(json!({ "action": "inbox", "wait": 0, "as_agent": id2 }))
        .await;

    // E1/O7: After `"n"` moved to `id2`, R replies to `m1` (sent by `id1`).
    // The reply must route to `id1` (its inbox), NEVER to `id2`!
    h.set_caller_parent(5000); // caller = R
    let r_reply = h
        .agent_frame(json!({
            "action": "reply",
            "message_id": m1_id,
            "text": "reply-for-id1-only",
        }))
        .await;
    assert_eq!(r_reply["status"], "ok", "{r_reply}");
    let r_reply_pushed_id = r_reply["reply"]["pushedMessageId"]
        .as_str()
        .unwrap()
        .to_string();

    h.set_caller_parent(4000); // caller = P
    let inbox_id2 = h
        .agent_frame(json!({ "action": "inbox", "wait": 0, "as_agent": id2 }))
        .await;
    assert_eq!(
        inbox_id2["messages"].as_array().unwrap().len(),
        0,
        "O7/E1: reply to id1's message must NEVER land in id2's inbox: {inbox_id2}"
    );

    let inbox_id1 = h
        .agent_frame(json!({ "action": "inbox", "wait": 0, "as_agent": id1 }))
        .await;
    let id1_msgs = inbox_id1["messages"].as_array().unwrap();
    assert_eq!(
        id1_msgs.len(),
        1,
        "O7/E1: reply to id1's message must land in id1's inbox: {inbox_id1}"
    );
    assert!(
        id1_msgs[0]["body"]
            .as_str()
            .unwrap_or("")
            .contains("reply-for-id1-only"),
        "O7/E1: inbox body must contain 'reply-for-id1-only': {}",
        id1_msgs[0]
    );

    // E1/O7: `id2` attempting to `reply` to `m1` (or `r_reply_pushed_id`) is refused `denied` (`AppError::NotRecipient`),
    // while `id1` replying succeeds!
    for target_msg in [&m1_id, &r_reply_pushed_id] {
        let id2_attempt = h
            .agent_frame(json!({
                "action": "reply",
                "message_id": target_msg,
                "text": "hijack-by-id2",
                "as_agent": id2,
            }))
            .await;
        assert_eq!(id2_attempt["status"], "error", "{id2_attempt}");
        assert_eq!(
            id2_attempt["error"], "denied",
            "O7/E1: id2 must be refused 'denied' when replying to id1's thread: {id2_attempt}"
        );
    }

    let id1_followup = h
        .agent_frame(json!({
            "action": "reply",
            "message_id": m1_id,
            "text": "followup-from-id1",
            "as_agent": id1,
        }))
        .await;
    assert_eq!(
        id1_followup["status"], "ok",
        "O7/E1: id1 must be allowed to reply on its own thread: {id1_followup}"
    );
}

// =============================================================================
// O9 & E3: `list` with `as_agent: ""` returns `kind: "subagent"` entries with
// parent's status; session labelled `"a/b"` is reached by `to: "a/b"` (E3);
// rejected names (`0123456789abcdef0`, `atm1-0123456789abcdef`, `x/y`) are not
// bound and the child stays reachable by its id.
// =============================================================================
#[tokio::test]
async fn test_ha9_o9_list_subagents_slash_label_and_rejected_names() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let slash_sock = SocketListener::start("slash_inbox").await;

    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    let _slash_id = h
        .register_claude(7000, "claude-slash", "a/b", &slash_sock.sock_path)
        .await;
    h.set_caller_parent(4000);

    // 1. E3: A session labelled `"a/b"` is still reached by `to: "a/b"` because `"a"` is not an instance ref.
    let (status_slash, sent_slash) = h.http_send("a/b", "hello-slash-label").await;
    assert_eq!(
        status_slash, 202,
        "O9/E3: session labelled 'a/b' must resolve: {sent_slash}"
    );
    assert_eq!(sent_slash["outcome"], "delivered");
    let slash_lines = slash_sock.wait_for_lines(1).await;
    assert_eq!(slash_lines.len(), 1);
    assert!(slash_lines[0].contains("hello-slash-label"));

    // 2. Rejected subagent names (`0123456789abcdef0`, `atm1-0123456789abcdef`, `x/y`) are not bound,
    // and that child stays reachable by `<P>/<id>`.
    let child_id = "33333333333333333";
    h.agent_frame(json!({ "action": "subagent", "event": "start", "agent_id": child_id }))
        .await;
    for bad_name in ["0123456789abcdef0", "atm1-0123456789abcdef", "x/y"] {
        h.agent_frame(json!({
            "action": "subagent",
            "event": "bind_spawn",
            "agent_id": child_id,
            "name": bad_name,
        }))
        .await;
        let (st, body) = h
            .http_send(&format!("{p_id}/{bad_name}"), "should-not-resolve")
            .await;
        assert_eq!(
            st, 404,
            "O9: rejected name '{bad_name}' must not be bound: {body}"
        );
    }
    let (st_by_id, body_by_id) = h
        .http_send(&format!("{p_id}/{child_id}"), "reachable-by-id")
        .await;
    assert_eq!(
        st_by_id, 202,
        "O9: child with rejected names must stay reachable by <P>/<id>: {body_by_id}"
    );
    let _ = h
        .agent_frame(json!({ "action": "inbox", "wait": 0, "as_agent": child_id }))
        .await;

    // Bind a valid name on a second subagent and check `list` with `as_agent: ""`
    let child2_id = "44444444444444444";
    h.agent_frame(json!({
        "action": "subagent",
        "event": "start",
        "agent_id": child2_id,
        "name": "reviewer",
    }))
    .await;

    let list_resp = h
        .agent_frame(json!({ "action": "list", "as_agent": "" }))
        .await;
    assert_eq!(list_resp["status"], "ok", "{list_resp}");
    let recs = list_resp["recipients"].as_array().unwrap();
    let sub_entries: Vec<&Value> = recs.iter().filter(|r| r["kind"] == "subagent").collect();
    assert_eq!(
        sub_entries.len(),
        2,
        "O9: list must return one kind='subagent' entry per binding: {recs:?}"
    );
    let e1 = sub_entries
        .iter()
        .find(|r| r["address"] == format!("{p_id}/{child_id}@{}", h.node_name))
        .expect("child 1 in list");
    assert_eq!(e1["status"], "live");
    assert!(e1["label"].is_null());

    let e2 = sub_entries
        .iter()
        .find(|r| r["address"] == format!("{p_id}/reviewer@{}", h.node_name))
        .expect("child 2 in list");
    assert_eq!(e2["status"], "live");
    assert_eq!(e2["label"], "reviewer");
}

// =============================================================================
// O10: After P's `instance_seen` row is purged, `<P>/<name>` and `<P>/<id>` are
// `not_found`, and `as_agent = id` from a re-registered P is refused `denied`.
// =============================================================================
#[tokio::test]
async fn test_ha9_o10_purge_deletes_subagents() {
    let h = Ha9Harness::start(1).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    h.set_caller_parent(4000);

    let child_id = "0123456789abcdef0";
    h.agent_frame(json!({
        "action": "subagent",
        "event": "start",
        "agent_id": child_id,
        "name": "worker",
    }))
    .await;

    // Remove P's session file and run one scan so `instance_claims` marks P released
    remove_claude_session_file(&h.sessions_dir, 4000, "claude-p");
    remove_proc_stat(&h.proc_root, 4000);
    let _ = h.http_list("").await;

    // Now backdate `last_live` past `reply_ttl` so the next `list` purges P from `instance_seen`
    {
        let db = h.state.db.lock().unwrap();
        let old = xmsg::storage::now_epoch_secs() - 7200;
        db.execute(
            "UPDATE instance_seen SET last_live = ?1 WHERE id = ?2",
            rusqlite::params![old, p_id],
        )
        .unwrap();
    }

    // Trigger `purge_instance_seen`
    let _ = h.http_list("").await;

    for target in [format!("{p_id}/worker"), format!("{p_id}/{child_id}")] {
        let (st, body) = h.http_send(&target, "after-purge").await;
        assert_eq!(
            st, 404,
            "O10: {target} must be not_found after purge: {body}"
        );
        assert_eq!(body["error"], "not_found", "{body}");
    }

    // Re-register P with the same session id and attempt `send` with `as_agent = child_id` -> refused `denied`
    write_proc_stat(&h.proc_root, 4000, 1, "1000");
    write_claude_session_file(
        &h.sessions_dir,
        4000,
        "claude-p",
        "parent-p",
        "1000",
        &p_sock.sock_path,
    );
    let _ = h.http_list("").await;
    h.set_caller_parent(4000);

    let forged = h
        .agent_frame(json!({
            "action": "send",
            "to": p_id,
            "text": "after-purge-as-agent",
            "as_agent": child_id,
        }))
        .await;
    assert_eq!(forged["status"], "error", "{forged}");
    assert_eq!(
        forged["error"], "denied",
        "O10: purged subagent id must be refused 'denied' after P re-registers: {forged}"
    );
}

// =============================================================================
// O11 & D1–D5: Recipient's `reply` to a child's message reaches the child's
// `inbox` while in a turn, and falls back to P with `to=<P>/<child> agent_id=<id>`
// after stop — for both a Claude parent (O11) and an `opencode` plugin parent (D1–D5).
// =============================================================================
#[tokio::test]
async fn test_ha9_o11_and_d4_reply_to_child_claude_and_plugin() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let r_sock = SocketListener::start("r_inbox").await;

    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    let r_id = h
        .register_claude(5000, "claude-r", "recip-r", &r_sock.sock_path)
        .await;

    // --- Part A: Claude parent (O11) ---
    h.set_caller_parent(4000);
    let child_id = "0123456789abcdef0";
    h.agent_frame(json!({
        "action": "subagent",
        "event": "start",
        "agent_id": child_id,
        "name": "worker",
    }))
    .await;

    let sent_c = h
        .agent_frame(json!({
            "action": "send",
            "to": r_id,
            "text": "question-from-claude-child",
            "as_agent": child_id,
        }))
        .await;
    assert_eq!(sent_c["status"], "ok", "{sent_c}");
    let msg_c_id = sent_c["message_id"].as_str().unwrap().to_string();

    // R replies while Claude child is in a turn -> reaches child's `inbox`
    h.set_caller_parent(5000);
    let rep1 = h
        .agent_frame(json!({
            "action": "reply",
            "message_id": msg_c_id,
            "text": "answer-in-turn",
        }))
        .await;
    assert_eq!(rep1["status"], "ok", "{rep1}");
    assert_eq!(rep1["reply"]["pushOutcome"], "pushed");
    assert!(
        p_sock.received_lines.lock().await.is_empty(),
        "O11: reply while child is in turn must not hit parent socket"
    );

    h.set_caller_parent(4000);
    let inbox_c = h
        .agent_frame(json!({ "action": "inbox", "wait": 0, "as_agent": child_id }))
        .await;
    let msgs_c = inbox_c["messages"].as_array().unwrap();
    assert_eq!(
        msgs_c.len(),
        1,
        "O11: reply while child in turn must reach child's inbox: {inbox_c}"
    );
    assert!(
        msgs_c[0]["body"]
            .as_str()
            .unwrap_or("")
            .contains("answer-in-turn"),
        "O11: child inbox body must contain 'answer-in-turn': {}",
        msgs_c[0]
    );

    // Stop Claude child's turn; R replies again -> reaches P's socket with `to=<P>/worker agent_id=<id>`
    h.agent_frame(json!({
        "action": "subagent",
        "event": "stop",
        "agent_id": child_id,
    }))
    .await;
    p_sock.clear().await;

    h.set_caller_parent(5000);
    let rep2 = h
        .agent_frame(json!({
            "action": "reply",
            "message_id": msg_c_id,
            "text": "answer-after-stop",
        }))
        .await;
    assert_eq!(rep2["status"], "ok", "{rep2}");
    assert_eq!(rep2["reply"]["pushOutcome"], "pushed");

    let expected_claude_hdr = format!("to={p_id}/worker agent_id={child_id}");
    let lines_p = p_sock.wait_for_lines(1).await;
    assert_eq!(lines_p.len(), 1);
    assert!(
        lines_p[0].contains(&expected_claude_hdr) && lines_p[0].contains("answer-after-stop"),
        "O11: reply after SubagentStop must reach P's socket with '{expected_claude_hdr}', got: {}",
        lines_p[0]
    );

    // --- Part B: Plugin (`opencode`) parent (D1, D2, D3, D4, D5) ---
    let my_pid = std::process::id();
    write_proc_stat(&h.proc_root, my_pid, 1, "2000");
    let mut oc = PluginConn::open(&h.register_sock, "opencode").await;
    let reg_oc = oc
        .call(json!({
            "action": "register",
            "session": "ses_parent_root",
        }))
        .await;
    assert_eq!(reg_oc["status"], "ok", "{reg_oc}");
    let oc_addr = reg_oc["address"].as_str().unwrap().to_string();
    let oc_id = oc_addr.split('@').next().unwrap().to_string();

    // Bind subagent `(oc_id, "ses_child_1")` with `agent_type = "general"` (D5) in an active turn
    let oc_child_id = "ses_child_1";
    {
        let db = h.state.db.lock().unwrap();
        xmsg::storage::subagent_start_turn(
            &db,
            &oc_id,
            oc_child_id,
            my_pid,
            "2000",
            None,
            Some("general"),
            None,
            xmsg::storage::now_epoch_secs(),
        )
        .unwrap();
    }

    // D1 & D5: `list` shows `<oc_id>/ses_child_1@<node>` with `harness: "opencode"` and `name: "general"`
    let recs = h.http_list("").await;
    let oc_sub_entry = recs
        .iter()
        .find(|e| e["address"] == format!("{oc_id}/{oc_child_id}@{}", h.node_name))
        .unwrap_or_else(|| panic!("D1: expected opencode subagent in list: {recs:?}"));
    assert_eq!(oc_sub_entry["kind"], "subagent");
    assert_eq!(
        oc_sub_entry["harness"], "opencode",
        "D1: child must inherit parent harness"
    );
    assert_eq!(
        oc_sub_entry["label"], "general",
        "D5: display label must fall back to agent_type"
    );

    // Send a message from the opencode child (`<oc_id>/ses_child_1`) to R
    let oc_child_session = Session {
        session_id: format!("{oc_id}/{oc_child_id}"),
        name: Some("general".to_string()),
        pid: my_pid,
        cwd: "/".to_string(),
        status: "idle".to_string(),
        kind: "subagent".to_string(),
        entrypoint: None,
        version: None,
        started_at: 1000,
        updated_at: 1000,
        harness: "opencode".to_string(),
        registered: Some(true),
    };
    let sent_oc = xmsg::surface::send(
        &h.state,
        &xmsg::surface::Sender::Session(oc_child_session.clone()),
        &r_id,
        "question-from-oc-child",
        None,
    )
    .await
    .expect("send from opencode child");

    // D4: While `ses_child_1` is in a turn, R's `reply` to `sent_oc.message_id` queues for child's `inbox`
    // (NOT pushed to parent's plugin poll channel!)
    let r_session = Session {
        session_id: r_id.clone(),
        name: Some("recip-r".to_string()),
        pid: 5000,
        cwd: "/".to_string(),
        status: "idle".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: 1000,
        updated_at: 1000,
        harness: "claude".to_string(),
        registered: Some(true),
    };
    let rep_oc_1 = xmsg::surface::reply(
        &h.state,
        &r_session,
        &sent_oc.message_id,
        "reply-to-oc-child-in-turn",
        None,
    )
    .await
    .expect("reply to in-turn opencode child");
    assert_eq!(
        rep_oc_1.push_outcome.as_deref(),
        Some("pushed"),
        "D4: reply to in-turn opencode child must push into child's queue: {rep_oc_1:?}"
    );

    let oc_inbox = xmsg::surface::inbox(&h.state, &oc_child_session, 0)
        .await
        .expect("inbox for opencode child");
    assert_eq!(
        oc_inbox.address,
        format!("{oc_id}/{oc_child_id}@{}", h.node_name)
    );
    assert_eq!(oc_inbox.messages.len(), 1);
    assert!(
        oc_inbox.messages[0]
            .body
            .contains("reply-to-oc-child-in-turn"),
        "D4: opencode child inbox must contain 'reply-to-oc-child-in-turn': {:?}",
        oc_inbox.messages[0]
    );

    // Stop `ses_child_1`'s turn; R sends a second reply -> falls back to `oc` parent via `register.sock` `poll`
    // carrying `to=<oc_id>/ses_child_1 agent_id=ses_child_1` in both `envelope` and `text` (D2 + D4)!
    {
        let db = h.state.db.lock().unwrap();
        xmsg::storage::subagent_stop_turn(&db, &oc_id, oc_child_id).unwrap();
    }
    let rep_oc_2 = xmsg::surface::reply(
        &h.state,
        &r_session,
        &sent_oc.message_id,
        "reply-to-oc-child-after-stop",
        None,
    )
    .await
    .expect("reply to idle opencode child");
    assert_eq!(rep_oc_2.push_outcome.as_deref(), Some("pushed"));

    let deliv = oc.call(json!({ "action": "poll", "wait": 1 })).await;
    assert_eq!(deliv["action"], "deliver", "{deliv}");
    let expected_oc_hdr = format!("to={oc_id}/{oc_child_id} agent_id={oc_child_id}");
    assert!(
        deliv["envelope"]
            .as_str()
            .unwrap_or("")
            .contains(&expected_oc_hdr),
        "D2/D4: plugin fallback envelope must contain '{expected_oc_hdr}', got: {deliv}"
    );
    assert!(
        deliv["text"]
            .as_str()
            .unwrap_or("")
            .contains(&expected_oc_hdr)
            && deliv["text"]
                .as_str()
                .unwrap_or("")
                .contains("reply-to-oc-child-after-stop"),
        "D2/D4: plugin fallback text must contain '{expected_oc_hdr}', got: {deliv}"
    );
}

// =============================================================================
// O12: `SubagentStart` frame for an id with no row binds `"kid"` when `meta.json`
// beside `transcript_path` names `"kid"`. `PostToolUse(SendMessage)` (`reassert_resume`)
// whose `to` is id-shaped and whose `pin_name` equals the id binds no name.
// =============================================================================
#[tokio::test]
async fn test_ha9_o12_meta_json_bind_and_send_message_id_shaped_to() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    h.set_caller_parent(4000);

    // 1. `SubagentStart` reads `<transcript_stem>/subagents/agent-<id>.meta.json` and binds `"kid"`
    let id_meta = "44444444444444444";
    let transcript_stem = h._tmp.path().join("sess-o12");
    let subagents_dir = transcript_stem.join("subagents");
    fs::create_dir_all(&subagents_dir).unwrap();
    fs::write(
        subagents_dir.join(format!("agent-{id_meta}.meta.json")),
        json!({ "agentType": "general-purpose", "name": "kid" }).to_string(),
    )
    .unwrap();
    let transcript_path = format!("{}.jsonl", transcript_stem.display());

    let start_resp = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": id_meta,
            "transcript_path": transcript_path,
        }))
        .await;
    assert_eq!(start_resp["status"], "ok", "{start_resp}");

    let (st_kid, body_kid) = h.http_send(&format!("{p_id}/kid"), "hello-kid").await;
    assert_eq!(
        st_kid, 202,
        "O12: SubagentStart must bind 'kid' from meta.json: {body_kid}"
    );
    assert_eq!(
        body_kid["address"],
        format!("{p_id}/{id_meta}@{}", h.node_name)
    );

    // 2. `PostToolUse(SendMessage)` (`reassert_resume`) whose `to` is id-shaped and whose
    // `pin_name` equals the id binds NO name (`name` stays `None`).
    let id_pin = "55555555555555555";
    h.agent_frame(json!({
        "action": "subagent",
        "event": "start",
        "agent_id": id_pin,
    }))
    .await;
    let resume_resp = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "reassert_resume",
            "agent_id": id_pin,
            "to": id_pin,
            "pin_name": id_pin,
        }))
        .await;
    assert_eq!(resume_resp["status"], "ok", "{resume_resp}");

    let binding = {
        let db = h.state.db.lock().unwrap();
        xmsg::storage::get_subagent(&db, &p_id, id_pin)
            .unwrap()
            .expect("row for id_pin")
    };
    assert_eq!(
        binding.name, None,
        "O12: reassert_resume with id-shaped `to` and `pin_name == id` must bind no name: {binding:?}"
    );
}

// =============================================================================
// D6: A non-empty `as_agent` equal to the caller's own resolved `session_id`
// acts as the parent `P` (just like `""`) for `send` and `reply`, while `inbox`
// refuses it with `denied` (`AppError::NotRecipient`) because `inbox` is child-only.
// =============================================================================
#[tokio::test]
async fn test_ha9_d6_as_agent_equals_parent_session_id() {
    let h = Ha9Harness::start(3600).await;
    let p_sock = SocketListener::start("p_inbox").await;
    let r_sock = SocketListener::start("r_inbox").await;

    let p_id = h
        .register_claude(4000, "claude-p", "parent-p", &p_sock.sock_path)
        .await;
    let r_id = h
        .register_claude(5000, "claude-r", "recip-r", &r_sock.sock_path)
        .await;
    h.set_caller_parent(4000);

    // 1. `send` with `as_agent == p_id` (own resolved session_id) acts as parent `P`
    let sent = h
        .agent_frame(json!({
            "action": "send",
            "to": r_id,
            "text": "from-parent-via-own-id",
            "as_agent": p_id,
        }))
        .await;
    assert_eq!(
        sent["status"], "ok",
        "D6: send with as_agent == own session_id must act as parent: {sent}"
    );
    let lines = r_sock.wait_for_lines(1).await;
    assert_eq!(lines.len(), 1);
    let c0: Value = serde_json::from_str(&lines[0]).unwrap();
    let content0 = c0["message"]["content"].as_str().unwrap();
    let expected_parent_from = format!("from-name=\"parent-p · {p_id}@{}\"", h.node_name);
    assert!(
        content0.contains(&expected_parent_from),
        "D6: send with as_agent == own session_id must carry parent label '{expected_parent_from}', got: {content0}"
    );

    // 2. `inbox` with `as_agent == p_id` is refused `denied` just like `as_agent == ""`
    let inbox_resp = h
        .agent_frame(json!({
            "action": "inbox",
            "wait": 0,
            "as_agent": p_id,
        }))
        .await;
    assert_eq!(inbox_resp["status"], "error", "{inbox_resp}");
    assert_eq!(
        inbox_resp["error"], "denied",
        "D6: inbox with as_agent == own session_id must be refused 'denied': {inbox_resp}"
    );
}
