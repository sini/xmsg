//! HA9-A.agy — Delegated Sub-addresses for Antigravity (`agy`) Subagents (§3a G1, G2, G4, G5, G6, G7, G8).
//!
//! Covers:
//! - G1: `xmsg register agy --hook --event pre-tool-use` stamps `as_agent = conversationId`
//!   on `call_mcp_tool` (`ServerName: "xmsg"`) with `Arguments` as object or JSON string,
//!   returns `{"decision": "ask"}` without `overwrite` or `"allow"` on foreign `ServerName`,
//!   and returns `{"decision": "deny"}` on malformed stdin or unparseable xmsg `Arguments`.
//! - G2: `subagent` frame (`event: "start"`) from a process under fake `agy` with `P` registered:
//!   - `X` with `brain/<P>/.system_generated/subagents/<X>.json` (`role: "kid"`, `typeName: "self"`)
//!     -> `role: "subagent"`, row `(P, X, "kid", "self")`;
//!   - `Y` with no descriptor -> `not_recipient` (`denied`), no row;
//!   - `P` -> `role: "parent"`, no row;
//!   - `X.json` whose `conversationId` is `W` -> `not_recipient` (`denied`), no row;
//!   - `as_agent="../<Q>/x"` -> `not_recipient` (`denied`).
//! - G4: `xmsg mcp` under fake `agy`:
//!   - `send` with `as_agent=X` reaches recipient as `kid · <P>/<X>@<node>` with no prior `start`
//!     frame (lazy admission);
//!   - `send` with `as_agent=P` reaches recipient as `<label> · <P>@<node>` (D6);
//!   - `as_agent=Y` (no descriptor) and `as_agent=Z` (descriptor under another registered `agy` `Q`)
//!     are refused (`denied`);
//!   - `inbox` with `as_agent=P` is refused as for `""` (E3).
//! - G5: After `start`, a send to `<P>/kid` is `queued` and `X`'s `inbox` returns it and marks
//!   it `delivered`; after `stop`, a send to `<P>/kid` lands in `P`'s agy delivery (`agy_pending_messages`
//!   row for `P` without credentials) with `to=<P>/kid agent_id=<X>`.
//! - G6: Reset and crash:
//!   - `start` for `X`, then `P`'s `mcp_start` re-attests -> a send to `<P>/kid` falls back to `P`;
//!   - with a message queued to `X` mid-turn, fake `agy`'s pid exits -> `list` evicts `P` and purges
//!     `subagents` rows only while the message stays in `instance_queue` keyed `<P>/<X>`; a fresh
//!     fake `agy` re-registers `P` -> the message lands in `P`'s agy delivery with `to=<P>/kid agent_id=<X>`.
//! - G7: Re-bind and collisions:
//!   - `P` registers with descriptors `X` (`kid`, step 4), `W` (`kid`, step 9), `V` and `U` (`pair`, step 12 both):
//!     before any child frame, `<P>/kid` resolves to `W`, `<P>/<X>` to `X`, `<P>/pair` is `not_found`,
//!     `<P>/<V>` and `<P>/<U>` resolve; `list` shows four `kind: "subagent"`, `harness: "agy"` entries.
//! - G8: No child in `agy_store`:
//!   - `xmsg register agy` (via `register.sock`) from under fake `agy` with `conversation_id = X`
//!     (descriptor present, no `presence/<X>.lock`) is refused; `agy_store` holds exactly one entry
//!     for the `agy` pid; `P`'s send is still labelled `P`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use xmsg::agy::{dev_major, dev_minor, new_agy_store, AgyConfig};
use xmsg::http::{build_router, AppState};
use xmsg::mcp::McpConfig;
use xmsg::storage;

const P_UUID: &str = "11111111-1111-4111-8111-111111111111";
const Q_UUID: &str = "22222222-2222-4222-8222-222222222222";
const X_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const Y_UUID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const Z_UUID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const W_UUID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const V_UUID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const U_UUID: &str = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const RECIP_UUID: &str = "99999999-9999-4999-8999-999999999999";

fn setup_mock_process(
    proc_root: &Path,
    pid: u32,
    ppid: u32,
    exe: Option<&Path>,
    open_file: Option<&Path>,
    starttime: &str,
) {
    let pid_dir = proc_root.join(pid.to_string());
    let fd_dir = pid_dir.join("fd");
    let fdinfo_dir = pid_dir.join("fdinfo");
    fs::create_dir_all(&fd_dir).unwrap();
    fs::create_dir_all(&fdinfo_dir).unwrap();

    let stat_content = format!(
        "{pid} (proc) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0 0 0 0 0 0 0 0 0\n"
    );
    fs::write(pid_dir.join("stat"), stat_content).unwrap();

    if let Some(e) = exe {
        let exe_link = pid_dir.join("exe");
        let _ = fs::remove_file(&exe_link);
        std::os::unix::fs::symlink(e, &exe_link).unwrap();
    }

    if let Some(target) = open_file {
        let fd_link = fd_dir.join("3");
        let _ = fs::remove_file(&fd_link);
        std::os::unix::fs::symlink(target, &fd_link).unwrap();
        let meta = fs::metadata(target).unwrap();
        let maj = dev_major(meta.dev());
        let min = dev_minor(meta.dev());
        let ino = meta.ino();
        let fdinfo_content = format!(
            "pos:\t0\nflags:\t0100002\nmnt_id:\t25\nino:\t{ino}\nlock:\t1: FLOCK  ADVISORY  WRITE {pid} {maj:02x}:{min:02x}:{ino} 0 EOF\n"
        );
        fs::write(fdinfo_dir.join("3"), fdinfo_content).unwrap();
    }
}

fn remove_mock_process(proc_root: &Path, pid: u32) {
    let _ = fs::remove_dir_all(proc_root.join(pid.to_string()));
}

#[allow(clippy::too_many_arguments)]
fn write_descriptor(
    brain_dir: &Path,
    parent_id: &str,
    file_id: &str,
    conv_id_in_json: &str,
    role: Option<&str>,
    type_name: Option<&str>,
    spawn_step_index: i64,
    flat: bool,
) {
    let sub_dir = brain_dir
        .join(parent_id)
        .join(".system_generated")
        .join("subagents");
    fs::create_dir_all(&sub_dir).unwrap();
    let payload = if flat {
        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), Value::String(conv_id_in_json.into()));
        obj.insert(
            "parentConversationId".into(),
            Value::String(parent_id.into()),
        );
        if let Some(r) = role {
            obj.insert("role".into(), Value::String(r.into()));
        }
        if let Some(t) = type_name {
            obj.insert("typeName".into(), Value::String(t.into()));
        }
        obj.insert("spawnStepIndex".into(), Value::Number(spawn_step_index.into()));
        Value::Object(obj)
    } else {
        let mut desc = serde_json::Map::new();
        if let Some(r) = role {
            desc.insert("role".into(), Value::String(r.into()));
        }
        if let Some(t) = type_name {
            desc.insert("typeName".into(), Value::String(t.into()));
        }
        json!({
            "conversationId": conv_id_in_json,
            "subagentDescriptor": Value::Object(desc),
            "spawnStepIndex": spawn_step_index,
        })
    };
    fs::write(
        sub_dir.join(format!("{file_id}.json")),
        serde_json::to_string(&payload).unwrap(),
    )
    .unwrap();
}

struct AgyTestHarness {
    _tmp: TempDir,
    state: Arc<AppState>,
    sessions_dir: PathBuf,
    proc_root: PathBuf,
    proc_locks: PathBuf,
    presence_dir: PathBuf,
    brain_dir: PathBuf,
    fake_agy: PathBuf,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    http_sock: PathBuf,
    base_url: String,
    node_name: String,
}

impl AgyTestHarness {
    async fn start() -> Self {
        let tmp = tempdir().expect("tempdir for AgyTestHarness");
        let sessions_dir = tmp.path().join("sessions");
        let proc_root = tmp.path().join("proc");
        let proc_locks = tmp.path().join("locks");
        let presence_dir = tmp.path().join("presence");
        let brain_dir = tmp.path().join("brain");
        let sock_dir = tmp.path().join("xmsg");
        fs::create_dir_all(&sessions_dir).unwrap();
        fs::create_dir_all(&proc_root).unwrap();
        fs::create_dir_all(&presence_dir).unwrap();
        fs::create_dir_all(&brain_dir).unwrap();
        fs::create_dir_all(&sock_dir).unwrap();
        fs::write(&proc_locks, "").unwrap();
        fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let fake_agy = tmp.path().join("fake-agy");
        fs::write(&fake_agy, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&fake_agy, fs::Permissions::from_mode(0o755)).unwrap();

        let db_path = tmp.path().join("xmsg.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        storage::init_db(&conn).unwrap();

        let (notify_tx, _) = tokio::sync::broadcast::channel(32);
        let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
        let node_name = "test-node".to_string();

        let state = Arc::new(AppState {
            sessions_dirs: vec![sessions_dir.clone()],
            agy_config: AgyConfig {
                presence_dir: presence_dir.clone(),
                brain_dir: brain_dir.clone(),
                proc_locks_path: proc_locks.clone(),
                proc_root: proc_root.clone(),
                agy_bin: fake_agy.display().to_string(),
                trusted_agy_exes: vec![fake_agy.clone()],
            },
            agy_store: new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            node_name: node_name.clone(),
            max_body: 65536,
            request_counter: AtomicU64::new(1),
            db: Arc::new(Mutex::new(conn)),
            notify_tx,
            reply_ttl: Duration::from_secs(600),
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

        let my_uid = xmsg::agent::current_uid();
        let agent_sock = sock_dir.join("agent.sock");
        let ag_sock = agent_sock.clone();
        let ag_state = state.clone();
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
        assert!(agent_sock.exists() && register_sock.exists() && http_sock.exists());

        Self {
            _tmp: tmp,
            state,
            sessions_dir,
            proc_root,
            proc_locks,
            presence_dir,
            brain_dir,
            fake_agy,
            agent_sock,
            register_sock,
            http_sock,
            base_url,
            node_name,
        }
    }

    fn set_caller_parent(&self, parent_pid: u32) {
        let my_pid = std::process::id();
        setup_mock_process(&self.proc_root, my_pid, parent_pid, None, None, "2000");
    }

    fn setup_agy_lock(&self, conv_id: &str, pid: u32, starttime: &str) -> PathBuf {
        let lock_file = self.presence_dir.join(format!("{conv_id}.lock"));
        fs::write(&lock_file, "lock").unwrap();
        let meta = fs::metadata(&lock_file).unwrap();
        let maj = dev_major(meta.dev());
        let min = dev_minor(meta.dev());
        let ino = meta.ino();

        let mut existing = fs::read_to_string(&self.proc_locks).unwrap_or_default();
        existing.push_str(&format!(
            "1: FLOCK ADVISORY WRITE {pid} {maj:02x}:{min:02x}:{ino} 0 EOF\n"
        ));
        fs::write(&self.proc_locks, existing).unwrap();

        setup_mock_process(
            &self.proc_root,
            pid,
            1,
            Some(&self.fake_agy),
            Some(&lock_file),
            starttime,
        );
        lock_file
    }

    async fn register_frame(&self, frame: Value) -> Value {
        let mut stream = UnixStream::connect(&self.register_sock).await.unwrap();
        stream
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let (r, _) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).expect("valid register.sock json response")
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

    fn mcp_config(&self) -> McpConfig {
        McpConfig {
            sessions_dirs: vec![self.sessions_dir.clone()],
            xmsg_url: self.base_url.clone(),
            http_sock: Some(self.http_sock.clone()),
            agent_sock: self.agent_sock.clone(),
            proc_root: self.proc_root.clone(),
            presence_dir: self.presence_dir.clone(),
            proc_locks_path: self.proc_locks.clone(),
            reply_only: false,
        }
    }

    async fn mcp_tool_call(&self, name: &str, arguments: Value) -> Value {
        let config = self.mcp_config();
        let name_owned = name.to_string();
        tokio::task::spawn_blocking(move || {
            let client = reqwest::blocking::Client::new();
            let res = xmsg::mcp::execute_tool(&config, &client, &name_owned, &arguments);
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": res,
            })
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
}

fn run_hook_bin(event: &str, stdin_str: &str) -> (i32, Value) {
    let bin = env!("CARGO_BIN_EXE_xmsg");
    let mut child = Command::new(bin)
        .args(["register", "agy", "--hook", "--event", event])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xmsg register agy --hook");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_str.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let val: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expected JSON on hook stdout, got {stdout:?}: {e}"));
    (code, val)
}

// ===========================================================================
// G1: Stamp (hook binary, `--event pre-tool-use`)
// ===========================================================================
#[test]
fn g1_pre_tool_use_stamp_and_foreign_and_malformed() {
    // 1. `call_mcp_tool` with `ServerName: "xmsg"` and `Arguments` as object whose `as_agent` is
    //    a sibling id -> `decision: "allow"`, `overwrite.Arguments.as_agent = conversationId`,
    //    other keys byte-equal.
    let (code, out) = run_hook_bin(
        "pre-tool-use",
        &json!({
            "conversationId": X_UUID,
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "xmsg",
                    "ToolName": "send",
                    "Arguments": {
                        "to": "recip",
                        "text": "hello world",
                        "as_agent": Y_UUID,
                    }
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code, 0);
    assert_eq!(out["decision"], "allow", "{out}");
    assert_eq!(out["overwrite"]["Arguments"]["as_agent"], X_UUID, "{out}");
    assert_eq!(out["overwrite"]["Arguments"]["to"], "recip", "{out}");
    assert_eq!(out["overwrite"]["Arguments"]["text"], "hello world", "{out}");

    // 2. Same with `Arguments` as a JSON string -> `overwrite.Arguments` is a JSON string with
    //    `as_agent` replaced and other keys preserved.
    let raw_args_str = serde_json::to_string(&json!({
        "to": "recip",
        "text": "string-encoded",
        "as_agent": Y_UUID,
    }))
    .unwrap();
    let (code, out) = run_hook_bin(
        "pre-tool-use",
        &json!({
            "conversationId": X_UUID,
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "xmsg",
                    "ToolName": "send",
                    "Arguments": raw_args_str,
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code, 0);
    assert_eq!(out["decision"], "allow", "{out}");
    let overwritten_str = out["overwrite"]["Arguments"]
        .as_str()
        .expect("overwrite.Arguments must remain a string when input Arguments was a string");
    let parsed_overwritten: Value = serde_json::from_str(overwritten_str).unwrap();
    assert_eq!(parsed_overwritten["as_agent"], X_UUID);
    assert_eq!(parsed_overwritten["to"], "recip");
    assert_eq!(parsed_overwritten["text"], "string-encoded");

    // 3. Eager form `mcp_xmsg_send` -> `decision: "allow"`, `overwrite.as_agent = conversationId`.
    let (code, out) = run_hook_bin(
        "pre-tool-use",
        &json!({
            "conversationId": X_UUID,
            "toolCall": {
                "name": "mcp_xmsg_send",
                "args": {
                    "to": "recip",
                    "text": "eager",
                    "as_agent": Y_UUID,
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code, 0);
    assert_eq!(out["decision"], "allow", "{out}");
    assert_eq!(out["overwrite"]["as_agent"], X_UUID, "{out}");

    // 4. Non-xmsg `ServerName` -> no `overwrite` and no `"allow"` (`decision: "ask"` per OQ3).
    let (code, out) = run_hook_bin(
        "pre-tool-use",
        &json!({
            "conversationId": X_UUID,
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "hindsight",
                    "ToolName": "recall",
                    "Arguments": { "query": "test" }
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code, 0);
    assert!(out.get("overwrite").is_none(), "foreign server must get no overwrite: {out}");
    assert_ne!(out["decision"], "allow", "foreign server must never get allow: {out}");
    assert_eq!(out["decision"], "ask", "{out}");

    // 5. Malformed stdin -> `decision: "deny"`.
    let (code, out) = run_hook_bin("pre-tool-use", "{not valid json");
    assert_eq!(code, 0);
    assert_eq!(out["decision"], "deny", "{out}");

    // 6. Missing `conversationId` -> `decision: "deny"`.
    let (code, out) = run_hook_bin(
        "pre-tool-use",
        &json!({
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "xmsg",
                    "ToolName": "send",
                    "Arguments": { "to": "recip", "text": "hi" }
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code, 0);
    assert_eq!(out["decision"], "deny", "{out}");

    // 7. Unparseable string `Arguments` on xmsg call -> `decision: "deny"`.
    let (code, out) = run_hook_bin(
        "pre-tool-use",
        &json!({
            "conversationId": X_UUID,
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "xmsg",
                    "ToolName": "send",
                    "Arguments": "{bad-json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code, 0);
    assert_eq!(out["decision"], "deny", "{out}");
}

// ===========================================================================
// G2: Admission (`subagent` frame `start` under registered agy P)
// ===========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn g2_admission_from_descriptor_and_refusals() {
    let h = AgyTestHarness::start().await;
    let agy_pid = 8100;
    h.setup_agy_lock(P_UUID, agy_pid, "1000");
    h.set_caller_parent(agy_pid);

    let reg = h
        .register_frame(json!({
            "conversation_id": P_UUID,
            "ls_address": "127.0.0.1:9",
            "csrf_token": "tok",
            "label": "parent-agy",
        }))
        .await;
    assert_eq!(reg["status"], "ok", "{reg}");

    // Write valid descriptor for X (`role: "kid"`, `typeName: "self"`).
    write_descriptor(
        &h.brain_dir,
        P_UUID,
        X_UUID,
        X_UUID,
        Some("kid"),
        Some("self"),
        4,
        false,
    );

    // 1. `start` for X -> `role: "subagent"`, row `(P, X, "kid", "self")`.
    let resp = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": X_UUID,
        }))
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    assert_eq!(resp["role"], "subagent", "{resp}");
    assert_eq!(
        resp["address"],
        format!("{P_UUID}/kid@{}", h.node_name),
        "{resp}"
    );
    {
        let db = h.state.db.lock().unwrap();
        let row = storage::get_subagent(&db, P_UUID, X_UUID)
            .unwrap()
            .expect("row (P, X) must exist");
        assert_eq!(row.name.as_deref(), Some("kid"));
        assert_eq!(row.agent_type.as_deref(), Some("self"));
        assert_eq!(row.turn_pid, Some(agy_pid));
        assert_eq!(row.turn_start.as_deref(), Some("1000"));
    }

    // 2. `start` for Y with no descriptor -> `not_recipient` (`denied`), no row.
    let resp_y = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": Y_UUID,
        }))
        .await;
    assert_eq!(resp_y["status"], "error", "{resp_y}");
    assert_eq!(resp_y["error"], "denied", "{resp_y}");
    {
        let db = h.state.db.lock().unwrap();
        assert!(storage::get_subagent(&db, P_UUID, Y_UUID).unwrap().is_none());
    }

    // 3. `start` for P -> `role: "parent"`, no row for P under P.
    let resp_p = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": P_UUID,
        }))
        .await;
    assert_eq!(resp_p["status"], "ok", "{resp_p}");
    assert_eq!(resp_p["role"], "parent", "{resp_p}");
    {
        let db = h.state.db.lock().unwrap();
        assert!(storage::get_subagent(&db, P_UUID, P_UUID).unwrap().is_none());
    }

    // 4. Descriptor `Z.json` whose `conversationId` inside the JSON is `W` -> `not_recipient`, no row.
    write_descriptor(
        &h.brain_dir,
        P_UUID,
        Z_UUID,
        W_UUID,
        Some("spoof"),
        Some("self"),
        5,
        false,
    );
    let resp_z = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": Z_UUID,
        }))
        .await;
    assert_eq!(resp_z["status"], "error", "{resp_z}");
    assert_eq!(resp_z["error"], "denied", "{resp_z}");
    {
        let db = h.state.db.lock().unwrap();
        assert!(storage::get_subagent(&db, P_UUID, Z_UUID).unwrap().is_none());
    }

    // 5. G2c (E4 UUID-shape guard): non-UUID `as_agent` / `agent_id` values (`"../aaaa"`,
    // `"kid/../x"`, and `"not-a-uuid"`) with readable, content-matching sentinel files placed
    // at the target paths (`brain/<P>/.system_generated/aaaa.json`,
    // `brain/<P>/.system_generated/subagents/x.json` with `subagents/kid/` present, and
    // `brain/<P>/.system_generated/subagents/not-a-uuid.json`) must be refused before any
    // non-UUID descriptor path is opened.
    let sentinel_outside = h
        .brain_dir
        .join(P_UUID)
        .join(".system_generated")
        .join("aaaa.json");
    fs::write(
        &sentinel_outside,
        serde_json::to_string(&json!({
            "conversationId": "../aaaa",
            "role": "trav-outside",
            "typeName": "self",
            "stepIndex": 6,
        }))
        .unwrap(),
    )
    .unwrap();

    let subagents_dir = h
        .brain_dir
        .join(P_UUID)
        .join(".system_generated")
        .join("subagents");
    fs::create_dir_all(subagents_dir.join("kid")).unwrap();
    fs::write(
        subagents_dir.join("x.json"),
        serde_json::to_string(&json!({
            "conversationId": "kid/../x",
            "role": "trav-sub",
            "typeName": "self",
            "stepIndex": 7,
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        subagents_dir.join("not-a-uuid.json"),
        serde_json::to_string(&json!({
            "conversationId": "not-a-uuid",
            "role": "non-uuid",
            "typeName": "self",
            "stepIndex": 8,
        }))
        .unwrap(),
    )
    .unwrap();

    for bad_id in ["../aaaa", "kid/../x", "not-a-uuid"] {
        let send_trav = h
            .agent_frame(json!({
                "action": "send",
                "to": P_UUID,
                "text": "traversal",
                "as_agent": bad_id,
            }))
            .await;
        assert_eq!(
            send_trav["status"], "error",
            "non-UUID as_agent '{bad_id}' must be refused on send: {send_trav}"
        );
        assert_eq!(send_trav["error"], "denied", "{send_trav}");
        {
            let db = h.state.db.lock().unwrap();
            assert!(
                storage::get_subagent(&db, P_UUID, bad_id).unwrap().is_none(),
                "admit_agy must never admit non-UUID '{bad_id}'"
            );
        }
    }

    let start_non_uuid = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": "not-a-uuid",
        }))
        .await;
    assert_eq!(
        start_non_uuid["status"], "error",
        "non-UUID agent_id must be refused on start: {start_non_uuid}"
    );
    assert_eq!(start_non_uuid["error"], "denied", "{start_non_uuid}");
}

// ===========================================================================
// G4: Attested send (lazy admission, D6 parent send, refusals, E3 inbox refusal)
// ===========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn g4_attested_send_lazy_admission_and_d6_and_inbox_refusal() {
    let h = AgyTestHarness::start().await;
    let p_pid = 8201;
    let q_pid = 8202;
    let recip_pid = 8203;
    h.setup_agy_lock(P_UUID, p_pid, "1001");
    h.setup_agy_lock(Q_UUID, q_pid, "1002");

    // Register P
    h.set_caller_parent(p_pid);
    let reg_p = h
        .register_frame(json!({
            "conversation_id": P_UUID,
            "ls_address": "127.0.0.1:9",
            "csrf_token": "tok-p",
            "label": "agy-parent",
        }))
        .await;
    assert_eq!(reg_p["status"], "ok", "{reg_p}");

    // Register Q
    h.set_caller_parent(q_pid);
    let reg_q = h
        .register_frame(json!({
            "conversation_id": Q_UUID,
            "ls_address": "127.0.0.1:9",
            "csrf_token": "tok-q",
            "label": "other-agy",
        }))
        .await;
    assert_eq!(reg_q["status"], "ok", "{reg_q}");

    // Register a Claude recipient (checked at step 1 of Ancestry walk; its pid is `recip_pid`,
    // distinct from `std::process::id()`, so `set_caller_parent(p_pid)` switches the test
    // process back to P cleanly).
    let recip_sock = h._tmp.path().join("recip-claude.sock");
    let recip_listener = UnixListener::bind(&recip_sock).unwrap();
    setup_mock_process(&h.proc_root, recip_pid, 1, None, None, "1003");
    let claude_json = json!({
        "pid": recip_pid,
        "sessionId": RECIP_UUID,
        "name": "recip-claude",
        "cwd": "/",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 1000,
        "procStart": "1003",
        "messagingSocketPath": recip_sock.display().to_string(),
    });
    fs::write(
        h.sessions_dir.join(format!("{recip_pid}.json")),
        claude_json.to_string(),
    )
    .unwrap();
    let recip_id = RECIP_UUID.to_string();

    async fn accept_one_claude_msg(listener: &UnixListener) -> String {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("claude recipient accept timeout")
            .unwrap();
        let mut s = String::new();
        stream.read_to_string(&mut s).await.unwrap();
        s
    }

    // Write X's descriptor under P AFTER P registered (so only lazy admission on `as_agent` miss
    // can admit X, with NO prior `start` frame). Also write Z's descriptor under Q.
    write_descriptor(
        &h.brain_dir,
        P_UUID,
        X_UUID,
        X_UUID,
        Some("kid"),
        Some("self"),
        16,
        true, // exercise live agy 1.3.6 flat descriptor shape too
    );
    write_descriptor(
        &h.brain_dir,
        Q_UUID,
        Z_UUID,
        Z_UUID,
        Some("qkid"),
        Some("self"),
        3,
        false,
    );

    // Switch caller ancestry back to P.
    h.set_caller_parent(p_pid);

    // 1. `xmsg mcp` `send` with `as_agent = X` (no prior `start` frame) -> lazy admission,
    //    reaches recipient as `kid · <P>/<X>@<node>`.
    let mcp_x = h
        .mcp_tool_call(
            "send",
            json!({
                "to": recip_id,
                "text": "from child X",
                "as_agent": X_UUID,
            }),
        )
        .await;
    assert_eq!(mcp_x["result"]["isError"], false, "{mcp_x}");
    let raw_x = accept_one_claude_msg(&recip_listener).await;
    let expected_from_x = format!("from-name=\\\"kid · {P_UUID}/{X_UUID}@{}", h.node_name);
    let expected_ref_x = format!("ref={P_UUID}/{X_UUID}@{}", h.node_name);
    assert!(
        raw_x.contains(&expected_from_x) && raw_x.contains(&expected_ref_x),
        "expected {expected_from_x:?} and {expected_ref_x:?} in {raw_x:?}"
    );

    // 2. `xmsg mcp` `send` with `as_agent = P` -> reaches recipient as `agy-parent · <P>@<node>` (D6).
    let mcp_p = h
        .mcp_tool_call(
            "send",
            json!({
                "to": recip_id,
                "text": "from parent P",
                "as_agent": P_UUID,
            }),
        )
        .await;
    assert_eq!(mcp_p["result"]["isError"], false, "{mcp_p}");
    let raw_p = accept_one_claude_msg(&recip_listener).await;
    let expected_from_p = format!("from-name=\\\"agy-parent · {P_UUID}@{}", h.node_name);
    let expected_ref_p = format!("ref={P_UUID}@{}", h.node_name);
    assert!(
        raw_p.contains(&expected_from_p) && raw_p.contains(&expected_ref_p),
        "expected {expected_from_p:?} and {expected_ref_p:?} in {raw_p:?}"
    );

    // 3. `as_agent = Y` (no descriptor) -> refused `denied` (`not_recipient`).
    let mcp_y = h
        .mcp_tool_call(
            "send",
            json!({
                "to": recip_id,
                "text": "forged Y",
                "as_agent": Y_UUID,
            }),
        )
        .await;
    assert_eq!(mcp_y["result"]["isError"], true, "{mcp_y}");
    let err_y = mcp_y["result"]["content"][0]["text"].as_str().unwrap();
    assert!(err_y.contains("denied"), "expected denied for Y, got: {err_y}");

    // 4. `as_agent = Z` (descriptor under Q, not P) -> refused `denied` (`not_recipient`).
    let mcp_z = h
        .mcp_tool_call(
            "send",
            json!({
                "to": recip_id,
                "text": "cross-parent Z",
                "as_agent": Z_UUID,
            }),
        )
        .await;
    assert_eq!(mcp_z["result"]["isError"], true, "{mcp_z}");
    let err_z = mcp_z["result"]["content"][0]["text"].as_str().unwrap();
    assert!(err_z.contains("denied"), "expected denied for Z, got: {err_z}");

    // 5. `inbox` with `as_agent = P` -> refused just as for `""` (E3).
    let inbox_p = h
        .mcp_tool_call("inbox", json!({ "as_agent": P_UUID }))
        .await;
    assert_eq!(inbox_p["result"]["isError"], true, "{inbox_p}");
    let err_inbox_p = inbox_p["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        err_inbox_p.contains("denied") && err_inbox_p.contains("parent session"),
        "expected parent-session inbox refusal for as_agent=P, got: {err_inbox_p}"
    );
}

// ===========================================================================
// G5: Turn and fallback
// ===========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn g5_turn_inbox_and_stop_fallback() {
    let h = AgyTestHarness::start().await;
    let p_pid = 8301;
    h.setup_agy_lock(P_UUID, p_pid, "1001");
    h.set_caller_parent(p_pid);

    write_descriptor(
        &h.brain_dir,
        P_UUID,
        X_UUID,
        X_UUID,
        Some("kid"),
        Some("self"),
        4,
        false,
    );

    // Attest P via `mcp_start` WITHOUT credentials so fallback writes a pending row in
    // `agy_pending_messages` for P (as specified by G5).
    let mcp_start = h
        .agent_frame(json!({
            "action": "mcp_start",
        }))
        .await;
    assert_eq!(mcp_start["status"], "ok", "{mcp_start}");

    // 1. Start X's turn.
    let start_x = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": X_UUID,
        }))
        .await;
    assert_eq!(start_x["status"], "ok", "{start_x}");
    assert_eq!(start_x["role"], "subagent", "{start_x}");

    // 2. Send to `<P>/kid` while in turn -> `queued` in X's `inbox`, NOT in P's pending messages.
    let (status, send1) = h.http_send(&format!("{P_UUID}/kid"), "hello in turn").await;
    assert_eq!(status, 202, "{send1}");
    assert_eq!(send1["outcome"], "queued", "{send1}");
    let msg1_id = send1["message_id"].as_str().unwrap().to_string();

    {
        let db = h.state.db.lock().unwrap();
        let pending_p = storage::fetch_undelivered_agy_messages(&db, &[P_UUID]).unwrap();
        assert!(
            pending_p.is_empty(),
            "in-turn send must not fall back to P: {pending_p:?}"
        );
    }

    // 3. X's `inbox` returns the message and marks it `delivered`.
    let inbox_res = h
        .mcp_tool_call("inbox", json!({ "as_agent": X_UUID }))
        .await;
    assert_eq!(inbox_res["result"]["isError"], false, "{inbox_res}");
    let inbox_text = inbox_res["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        inbox_text.contains("hello in turn"),
        "expected message body in inbox output: {inbox_text}"
    );
    {
        let db = h.state.db.lock().unwrap();
        let outcome: String = db
            .query_row(
                "SELECT outcome FROM messages WHERE id = ?1",
                rusqlite::params![msg1_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(outcome, "delivered");
    }

    // 4. Stop X's turn.
    let stop_x = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "stop",
            "agent_id": X_UUID,
        }))
        .await;
    assert_eq!(stop_x["status"], "ok", "{stop_x}");

    // 5. After `stop`, a send to `<P>/kid` lands in P's agy delivery (`agy_pending_messages`)
    //    with `to=<P>/kid agent_id=<X>`.
    let (status2, send2) = h
        .http_send(&format!("{P_UUID}/kid"), "hello after stop")
        .await;
    assert_eq!(status2, 202, "{send2}");
    assert_eq!(send2["outcome"], "queued", "{send2}");

    {
        let db = h.state.db.lock().unwrap();
        let pending_p = storage::fetch_undelivered_agy_messages(&db, &[P_UUID]).unwrap();
        assert_eq!(pending_p.len(), 1, "expected 1 pending message for P");
        let expected_header = format!("to={P_UUID}/kid agent_id={X_UUID}");
        assert!(
            pending_p[0].envelope.contains(&expected_header)
                && pending_p[0].envelope.contains("hello after stop"),
            "unexpected fallback envelope: {}",
            pending_p[0].envelope
        );
    }
}

// ===========================================================================
// G6: Reset and crash
// ===========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn g6_reset_on_mcp_start_and_crash_preserves_queue_until_reregister() {
    let h = AgyTestHarness::start().await;
    let p_pid = 8401;
    h.setup_agy_lock(P_UUID, p_pid, "1001");
    h.set_caller_parent(p_pid);

    write_descriptor(
        &h.brain_dir,
        P_UUID,
        X_UUID,
        X_UUID,
        Some("kid"),
        Some("self"),
        4,
        false,
    );

    // Attest P without credentials.
    let mcp_start1 = h.agent_frame(json!({ "action": "mcp_start" })).await;
    assert_eq!(mcp_start1["status"], "ok", "{mcp_start1}");

    // Part A: `start` for X, then P's `mcp_start` re-attests -> turn columns are cleared, so a
    // subsequent send to `<P>/kid` falls back to P.
    let start1 = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": X_UUID,
        }))
        .await;
    assert_eq!(start1["status"], "ok", "{start1}");

    let mcp_start2 = h.agent_frame(json!({ "action": "mcp_start" })).await;
    assert_eq!(mcp_start2["status"], "ok", "{mcp_start2}");

    let (st_fb, send_fb) = h
        .http_send(&format!("{P_UUID}/kid"), "after mcp_start reset")
        .await;
    assert_eq!(st_fb, 202, "{send_fb}");
    {
        let db = h.state.db.lock().unwrap();
        let pending_p = storage::fetch_undelivered_agy_messages(&db, &[P_UUID]).unwrap();
        assert_eq!(
            pending_p.len(),
            1,
            "send after mcp_start re-attestation must fall back to P"
        );
        let expected_header = format!("to={P_UUID}/kid agent_id={X_UUID}");
        assert!(pending_p[0].envelope.contains(&expected_header));
        // Clear it before Part B.
        storage::mark_agy_message_delivered(&db, &pending_p[0].id, 100).unwrap();
    }

    // Part B: With a message queued to X mid-turn, fake agy's pid exits -> the message is
    // neither delivered nor dropped (one `instance_queue` row keyed `<P>/<X>`); D9's eviction
    // purge deletes `subagents` rows only; a fresh fake agy re-registers P -> the message
    // lands in P's agy delivery with `to=<P>/kid agent_id=<X>`.
    let start2 = h
        .agent_frame(json!({
            "action": "subagent",
            "event": "start",
            "agent_id": X_UUID,
        }))
        .await;
    assert_eq!(start2["status"], "ok", "{start2}");

    let (st_q, send_q) = h
        .http_send(&format!("{P_UUID}/kid"), "queued before agy crash")
        .await;
    assert_eq!(st_q, 202, "{send_q}");
    assert_eq!(send_q["outcome"], "queued", "{send_q}");

    // Fake agy pid exits and releases its lock (remove both proc entry and stale lock file).
    remove_mock_process(&h.proc_root, p_pid);
    let _ = fs::remove_file(h.presence_dir.join(format!("{P_UUID}.lock")));
    fs::write(&h.proc_locks, "").unwrap();

    // Even if `sweep_agy_subagent_queues` runs before `list` evicts P, the dead parent P is
    // no longer live so X's `instance_queue` row must remain in `instance_queue` and not move
    // into `agy_pending_messages` while P is dead (E1).
    {
        let db = h.state.db.lock().unwrap();
        xmsg::agy::sweep_agy_subagent_queues(&db, &h.proc_root, &h.state.agy_store).unwrap();
    }

    // Trigger eviction + purge via `http_list`.
    let recs = h.http_list("").await;
    assert!(
        !recs.iter().any(|r| r["address"]
            .as_str()
            .unwrap_or("")
            .starts_with(P_UUID)),
        "dead P and its subagents must be evicted from live list: {recs:?}"
    );

    {
        let db = h.state.db.lock().unwrap();
        // `subagents` rows under P were purged by D9 eviction...
        let subs = storage::list_subagents_for_parent(&db, P_UUID).unwrap();
        assert!(subs.is_empty(), "expected subagents rows purged on eviction, got {subs:?}");
        // ...while `instance_queue` still holds the 1 undelivered row keyed `<P>/<X>`.
        let sub_queue_key = format!("{P_UUID}/{X_UUID}");
        let q_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM instance_queue WHERE instance_id = ?1 AND delivered_at IS NULL",
                rusqlite::params![sub_queue_key],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            q_count, 1,
            "eviction purge must spare instance_queue rows for <P>/<X>"
        );
        let pending_p = storage::fetch_undelivered_agy_messages(&db, &[P_UUID]).unwrap();
        assert!(
            pending_p.is_empty(),
            "message must not move to agy_pending_messages while P is dead"
        );
    }

    // Fresh fake agy pid starts and re-attests P (`mcp_start` without creds so we can inspect
    // the pending row before/without LS push, or register with creds and check delivery).
    let new_pid = 8402;
    h.setup_agy_lock(P_UUID, new_pid, "1500");
    h.set_caller_parent(new_pid);
    let mcp_start3 = h.agent_frame(json!({ "action": "mcp_start" })).await;
    assert_eq!(mcp_start3["status"], "ok", "{mcp_start3}");

    {
        let db = h.state.db.lock().unwrap();
        let pending_p = storage::fetch_undelivered_agy_messages(&db, &[P_UUID]).unwrap();
        assert_eq!(
            pending_p.len(),
            1,
            "re-registration rescan + sweep must move <P>/<X>'s queued message to P"
        );
        let expected_header = format!("to={P_UUID}/kid agent_id={X_UUID}");
        assert!(
            pending_p[0].envelope.contains(&expected_header)
                && pending_p[0].envelope.contains("queued before agy crash"),
            "unexpected envelope after re-register: {}",
            pending_p[0].envelope
        );
    }
}

// ===========================================================================
// G7: Re-bind and collisions (`spawnStepIndex` greatest wins, tie binds neither, D8 list)
// ===========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn g7_rebind_on_registration_and_role_collisions_and_list() {
    let h = AgyTestHarness::start().await;
    let p_pid = 8501;
    h.setup_agy_lock(P_UUID, p_pid, "1001");
    h.set_caller_parent(p_pid);

    // Write descriptors before P registers:
    // - X (`kid`, step 4)
    // - W (`kid`, step 9) -> W wins `kid`
    // - V (`pair`, step 12) and U (`pair`, step 12) -> tie binds `pair` to neither
    write_descriptor(
        &h.brain_dir,
        P_UUID,
        X_UUID,
        X_UUID,
        Some("kid"),
        Some("self"),
        4,
        false,
    );
    write_descriptor(
        &h.brain_dir,
        P_UUID,
        W_UUID,
        W_UUID,
        Some("kid"),
        Some("self"),
        9,
        false,
    );
    write_descriptor(
        &h.brain_dir,
        P_UUID,
        V_UUID,
        V_UUID,
        Some("pair"),
        Some("research"),
        12,
        false,
    );
    write_descriptor(
        &h.brain_dir,
        P_UUID,
        U_UUID,
        U_UUID,
        Some("pair"),
        Some("research"),
        12,
        false,
    );

    // Register P -> rescan binds all 4 before any child frame.
    let reg = h
        .register_frame(json!({
            "conversation_id": P_UUID,
            "ls_address": "127.0.0.1:9",
            "csrf_token": "tok",
            "label": "agy-p",
        }))
        .await;
    assert_eq!(reg["status"], "ok", "{reg}");

    // 1. `<P>/kid` resolves to W (`agent_id=<W>` in fallback header, or `address` in send response).
    let (st_kid, send_kid) = h.http_send(&format!("{P_UUID}/kid"), "to winner").await;
    assert_eq!(st_kid, 202, "{send_kid}");
    assert_eq!(
        send_kid["address"],
        format!("{P_UUID}/{W_UUID}@{}", h.node_name),
        "{send_kid}"
    );

    // 2. `<P>/<X>` resolves to X.
    let (st_x, send_x) = h.http_send(&format!("{P_UUID}/{X_UUID}"), "to X by id").await;
    assert_eq!(st_x, 202, "{send_x}");
    assert_eq!(
        send_x["address"],
        format!("{P_UUID}/{X_UUID}@{}", h.node_name),
        "{send_x}"
    );

    // 3. `<P>/pair` is `not_found` (404) because of the `spawnStepIndex` tie.
    let (st_pair, send_pair) = h.http_send(&format!("{P_UUID}/pair"), "to tied role").await;
    assert_eq!(st_pair, 404, "{send_pair}");
    assert_eq!(send_pair["error"], "not_found", "{send_pair}");

    // 4. `<P>/<V>` and `<P>/<U>` resolve by UUID.
    let (st_v, send_v) = h.http_send(&format!("{P_UUID}/{V_UUID}"), "to V").await;
    assert_eq!(st_v, 202, "{send_v}");
    assert_eq!(
        send_v["address"],
        format!("{P_UUID}/{V_UUID}@{}", h.node_name),
        "{send_v}"
    );
    let (st_u, send_u) = h.http_send(&format!("{P_UUID}/{U_UUID}"), "to U").await;
    assert_eq!(st_u, 202, "{send_u}");
    assert_eq!(
        send_u["address"],
        format!("{P_UUID}/{U_UUID}@{}", h.node_name),
        "{send_u}"
    );

    // 5. `list` shows four `kind: "subagent"`, `harness: "agy"` entries under P.
    let recs = h.http_list("").await;
    let sub_recs: Vec<&Value> = recs
        .iter()
        .filter(|r| r["kind"] == "subagent" && r["harness"] == "agy")
        .collect();
    assert_eq!(
        sub_recs.len(),
        4,
        "expected 4 agy subagent entries in list, got: {sub_recs:?}"
    );
    let addrs: Vec<&str> = sub_recs
        .iter()
        .map(|r| r["address"].as_str().unwrap())
        .collect();
    assert!(addrs.contains(&format!("{P_UUID}/kid@{}", h.node_name).as_str()));
    assert!(addrs.contains(&format!("{P_UUID}/{X_UUID}@{}", h.node_name).as_str()));
    assert!(addrs.contains(&format!("{P_UUID}/{V_UUID}@{}", h.node_name).as_str()));
    assert!(addrs.contains(&format!("{P_UUID}/{U_UUID}@{}", h.node_name).as_str()));
}

// ===========================================================================
// G8: No child in `agy_store`
// ===========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn g8_child_registration_refused_and_agy_store_keeps_only_parent() {
    let h = AgyTestHarness::start().await;
    let p_pid = 8601;
    h.setup_agy_lock(P_UUID, p_pid, "1001");
    h.set_caller_parent(p_pid);

    write_descriptor(
        &h.brain_dir,
        P_UUID,
        X_UUID,
        X_UUID,
        Some("kid"),
        Some("self"),
        4,
        false,
    );

    // Register P.
    let reg_p = h
        .register_frame(json!({
            "conversation_id": P_UUID,
            "ls_address": "127.0.0.1:9",
            "csrf_token": "tok-p",
            "label": "parent-label",
        }))
        .await;
    assert_eq!(reg_p["status"], "ok", "{reg_p}");

    // Attempt to register child X from under the same fake agy pid (descriptor present, no
    // `presence/<X>.lock`).
    let reg_x = h
        .register_frame(json!({
            "conversation_id": X_UUID,
            "ls_address": "127.0.0.1:9",
            "csrf_token": "tok-x",
            "label": "child-label",
        }))
        .await;
    assert_eq!(
        reg_x["status"], "error",
        "child registration must be refused: {reg_x}"
    );

    // `agy_store` holds exactly one entry for the agy pid.
    {
        let store = h.state.agy_store.read().unwrap();
        let pid_entries: Vec<_> = store.values().filter(|info| info.pid == p_pid).collect();
        assert_eq!(
            pid_entries.len(),
            1,
            "agy_store must hold exactly 1 entry for pid {p_pid}, got: {pid_entries:?}"
        );
        assert_eq!(pid_entries[0].conversation_id, P_UUID);
    }

    // Register a Claude recipient and verify P's send is still labelled P (`parent-label · <P>@<node>`).
    let recip_pid = 8602;
    let recip_sock = h._tmp.path().join("recip-claude-g8.sock");
    let recip_listener = UnixListener::bind(&recip_sock).unwrap();
    setup_mock_process(&h.proc_root, recip_pid, 1, None, None, "1002");
    let claude_json = json!({
        "pid": recip_pid,
        "sessionId": RECIP_UUID,
        "name": "recip-claude-g8",
        "cwd": "/",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 1000,
        "procStart": "1002",
        "messagingSocketPath": recip_sock.display().to_string(),
    });
    fs::write(
        h.sessions_dir.join(format!("{recip_pid}.json")),
        claude_json.to_string(),
    )
    .unwrap();

    h.set_caller_parent(p_pid);
    let mcp_p = h
        .mcp_tool_call(
            "send",
            json!({
                "to": RECIP_UUID,
                "text": "still parent",
            }),
        )
        .await;
    assert_eq!(mcp_p["result"]["isError"], false, "{mcp_p}");
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), recip_listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut raw_p = String::new();
    stream.read_to_string(&mut raw_p).await.unwrap();
    let expected_from_p = format!("from-name=\\\"parent-label · {P_UUID}@{}", h.node_name);
    let expected_ref_p = format!("ref={P_UUID}@{}", h.node_name);
    assert!(
        raw_p.contains(&expected_from_p) && raw_p.contains(&expected_ref_p),
        "expected {expected_from_p:?} and {expected_ref_p:?} in {raw_p:?}"
    );
}
