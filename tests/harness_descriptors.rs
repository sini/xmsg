//! Acceptance oracles for declared plugin harness descriptors (`--harnesses-file`).

mod agy_env;
use agy_env::ScrubAgyEnv;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{atomic::AtomicU64, Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;
use xmsg::harnesses::{validate_file_meta, HarnessRegistry};
use xmsg::http::AppState;
use xmsg::observe_export::Harness;

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Daemon {
    _tmp: TempDir,
    _child: Kill,
    http_sock: PathBuf,
    register_sock: PathBuf,
    db_path: PathBuf,
    harnesses_file: Option<PathBuf>,
}

impl Daemon {
    fn start(harnesses_json: Option<&str>) -> Self {
        let tmp = tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = tmp.path().to_path_buf();
        let run = root.join("run");
        fs::create_dir_all(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();

        let http_sock = run.join("http.sock");
        let agent_sock = run.join("agent.sock");
        let register_sock = run.join("register.sock");
        let db_path = root.join("db.sqlite");

        let harnesses_file = harnesses_json.map(|content| {
            let path = root.join("harnesses.json");
            fs::write(&path, content).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        });

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        cmd.scrub_agy_env()
            .env("XDG_RUNTIME_DIR", &run)
            .env("HOME", &root)
            .env_remove("XMSG_PEERS_FILE")
            .env_remove("XMSG_HARNESSES_FILE")
            .arg("serve")
            .arg("--db-path")
            .arg(&db_path)
            .arg("--sessions-dir")
            .arg(root.join("sessions"))
            .arg("--agent-sock")
            .arg(&agent_sock)
            .arg("--register-sock")
            .arg(&register_sock)
            .arg("--http-sock")
            .arg(&http_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(ref hf) = harnesses_file {
            cmd.arg("--harnesses-file").arg(hf);
        }

        let child = Kill(cmd.spawn().expect("spawn xmsg serve"));
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if http_sock.exists() && register_sock.exists() {
                if let Ok((200, _)) = http_unix(&http_sock, "GET", "/healthz", None) {
                    return Self {
                        _tmp: tmp,
                        _child: child,
                        http_sock,
                        register_sock,
                        db_path,
                        harnesses_file,
                    };
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("xmsg serve failed to become healthy within 10s");
    }

    fn write_harnesses(&self, content: &str) {
        let path = self
            .harnesses_file
            .as_ref()
            .expect("daemon started without harnesses_file");
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, content).unwrap();
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&tmp_path, path).unwrap();
    }
}

fn http_unix(
    sock: &Path,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> std::io::Result<(u16, Value)> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let req = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
    } else {
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    };
    stream.write_all(req.as_bytes())?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    let (head, body_part) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    let json_val = serde_json::from_str(body_part).unwrap_or_else(|_| json!({ "raw": body_part }));
    Ok((status, json_val))
}

struct PluginConn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl PluginConn {
    fn connect(sock: &Path, harness: &str) -> (Self, Value) {
        let stream = UnixStream::connect(sock).expect("connect register.sock");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let hello = format!("{}\n", json!({ "harness": harness }));
        writer.write_all(hello.as_bytes()).unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let resp: Value = serde_json::from_str(line.trim()).expect("valid json hello response");
        (Self { reader, writer }, resp)
    }

    fn send_frame(&mut self, frame: &Value) -> std::io::Result<Option<Value>> {
        let raw = format!("{frame}\n");
        self.writer.write_all(raw.as_bytes())?;
        let mut line = String::new();
        let n = self.reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(
            serde_json::from_str(line.trim()).expect("valid json frame response"),
        ))
    }

    fn wait_eof(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let _ = self
            .reader
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(100)));
        while Instant::now() < deadline {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return true,
                Ok(_) => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(_) => return true,
            }
        }
        false
    }
}

/// H1: V1 poll-only & non-shadowing, plus optionality (pure bus when --harnesses-file omitted).
#[test]
fn h1_v1_poll_only_and_non_shadowing() {
    // 1. Optionality: without --harnesses-file, declared harness hello is refused.
    let bus_only = Daemon::start(None);
    let (_c, hello_err) = PluginConn::connect(&bus_only.register_sock, "cursor");
    assert_eq!(hello_err["status"], "error");
    assert_eq!(hello_err["error"], "bad_request");

    // 2. Config validation: push/pull/reclaim/continues and shadowing built-ins fail config load.
    for bad_mode in ["push", "pull", "reclaim", "continues"] {
        let cfg = json!({ "harnesses": { "cursor": { "delivery_mode": bad_mode } } }).to_string();
        assert!(
            HarnessRegistry::from_json(&cfg).is_err(),
            "delivery_mode '{bad_mode}' must be refused in v1"
        );
    }
    for builtin in [
        "claude", "codex", "agy", "pi", "opencode", "hermes", "svc", "unknown",
    ] {
        let cfg = json!({ "harnesses": { builtin: { "delivery_mode": "poll" } } }).to_string();
        assert!(
            HarnessRegistry::from_json(&cfg).is_err(),
            "shadowing built-in/reserved '{builtin}' must fail config load"
        );
    }

    // 3. Declared poll-only harness registers, receives sends via poll, acks, and records its own harness.
    let cfg = json!({
        "harnesses": {
            "cursor": {
                "delivery_mode": "poll",
                "id_pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                "capabilities": { "attachments": false }
            }
        }
    })
    .to_string();
    let daemon = Daemon::start(Some(&cfg));

    // Undeclared harness is refused.
    let (_u, undeclared) = PluginConn::connect(&daemon.register_sock, "unknown-x");
    assert_eq!(undeclared["status"], "error");
    assert_eq!(undeclared["error"], "bad_request");

    let (mut conn, hello) = PluginConn::connect(&daemon.register_sock, "cursor");
    assert_eq!(hello["status"], "ok", "cursor hello failed: {hello}");

    // V1 poll-only refuses reclaim and continues on declared harnesses.
    let reclaim_err = conn
        .send_frame(&json!({
            "action": "register",
            "request_id": "r-reclaim",
            "session": "ses_1",
            "reclaim": { "id": "11111111-1111-4111-8111-111111111111", "secret": "abc" }
        }))
        .unwrap()
        .unwrap();
    assert_eq!(reclaim_err["error"], "bad_request");

    let reg = conn
        .send_frame(&json!({
            "action": "register",
            "request_id": "r1",
            "session": "ses_42"
        }))
        .unwrap()
        .unwrap();
    assert_eq!(reg["status"], "ok", "register failed: {reg}");
    assert!(
        reg.get("reclaim").is_none(),
        "v1 declared poll-only harness must not mint reclaim tokens"
    );
    let addr = reg["address"].as_str().unwrap().to_string();

    let cont_err = conn
        .send_frame(&json!({
            "action": "continues",
            "request_id": "r-cont",
            "from": "ses_42",
            "to": "ses_43"
        }))
        .unwrap()
        .unwrap();
    assert_eq!(cont_err["error"], "bad_request");

    // Send a message to the declared harness and verify poll + ack + recipientHarness == "cursor".
    let (status, send_resp) = http_unix(
        &daemon.http_sock,
        "POST",
        "/v1/messages",
        Some(&json!({ "to": addr, "text": "hello cursor", "from": "tester" })),
    )
    .unwrap();
    assert_eq!(status, 202, "send failed: {send_resp}");
    let msg_id = send_resp["message_id"].as_str().unwrap().to_string();

    let (status, detail) = http_unix(
        &daemon.http_sock,
        "GET",
        &format!("/v1/messages/{msg_id}"),
        None,
    )
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        detail["recipientHarness"], "cursor",
        "declared harness must not fall back to 'pi': {detail}"
    );

    let delivered = conn
        .send_frame(&json!({ "action": "poll", "request_id": "p1", "wait": 2 }))
        .unwrap()
        .unwrap();
    assert_eq!(delivered["action"], "deliver");
    assert_eq!(delivered["message_id"], msg_id);
    assert_eq!(delivered["text"], "hello cursor");

    let ack = conn
        .send_frame(&json!({
            "action": "ack",
            "request_id": "a1",
            "session": "ses_42",
            "message_id": msg_id
        }))
        .unwrap()
        .unwrap();
    assert_eq!(ack["status"], "ok");

    // Cursor sends a message to itself and replies to verify reply routing for declared harnesses.
    let sent_self = conn
        .send_frame(&json!({
            "action": "send",
            "request_id": "s1",
            "session": "ses_42",
            "to": addr,
            "text": "ping self"
        }))
        .unwrap()
        .unwrap();
    assert_eq!(sent_self["status"], "ok", "cursor send failed: {sent_self}");
    let self_msg_id = sent_self["message_id"].as_str().unwrap().to_string();
    let p2 = conn
        .send_frame(&json!({ "action": "poll", "request_id": "p2", "wait": 2 }))
        .unwrap()
        .unwrap();
    assert_eq!(p2["message_id"], self_msg_id);
    let _ = conn.send_frame(&json!({
        "action": "ack",
        "request_id": "a2",
        "session": "ses_42",
        "message_id": self_msg_id
    }));

    let rep = conn
        .send_frame(&json!({
            "action": "reply",
            "request_id": "rep1",
            "session": "ses_42",
            "message_id": self_msg_id,
            "text": "pong self"
        }))
        .unwrap()
        .unwrap();
    assert_eq!(rep["status"], "ok", "cursor reply failed: {rep}");
    assert_eq!(
        rep["reply"]["pushOutcome"], "pushed",
        "reply to declared harness must push to its poll queue: {rep}"
    );
}

/// H2: Unknown stays `unknown` (no `claude` or `pi` fallback) + observe_export::Harness wire.
#[test]
fn h2_unknown_stays_unknown_and_no_claude_or_pi_fallback() {
    // 1. Bare Session JSON without harness defaults to "unknown", not "claude".
    let bare_session: xmsg::registry::Session = serde_json::from_value(json!({
        "sessionId": "11111111-1111-4111-8111-111111111111",
        "name": "bare",
        "pid": 1,
        "cwd": "/",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1,
        "updatedAt": 1
    }))
    .unwrap();
    assert_eq!(
        bare_session.harness, "unknown",
        "bare Session without harness must not default to 'claude'"
    );

    // 2. observe_export::Harness wire accepts validated declared lowercase names and rejects bad ones.
    let declared_h: Harness = serde_json::from_value(json!("cursor")).unwrap();
    assert_eq!(declared_h, Harness::Declared("cursor".into()));
    assert_eq!(serde_json::to_value(&declared_h).unwrap(), json!("cursor"));
    assert_eq!(
        serde_json::from_value::<Harness>(json!("unknown")).unwrap(),
        Harness::Unknown
    );
    assert!(serde_json::from_value::<Harness>(json!("BadUpper")).is_err());
    assert!(serde_json::from_value::<Harness>(json!("svc")).is_err());

    // 3. Live daemon with declared `cursor` (NO resume_argv) + seeded undeclared `mystery`.
    let cfg = json!({
        "harnesses": {
            "cursor": { "delivery_mode": "poll" }
        }
    })
    .to_string();
    let daemon = Daemon::start(Some(&cfg));

    let (mut conn, hello) = PluginConn::connect(&daemon.register_sock, "cursor");
    assert_eq!(hello["status"], "ok");
    let reg = conn
        .send_frame(&json!({
            "action": "register",
            "request_id": "r1",
            "session": "ses_no_resume"
        }))
        .unwrap()
        .unwrap();
    let cursor_addr = reg["address"].as_str().unwrap().to_string();
    let cursor_id = cursor_addr.split('@').next().unwrap().to_string();

    // Declared harness without resume_argv has native_id but NO resume (never claude --resume).
    let (status, loc_cursor) = http_unix(
        &daemon.http_sock,
        "GET",
        &format!("/v1/locate?address={cursor_id}"),
        None,
    )
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(loc_cursor["locators"][0]["native_id"], "ses_no_resume");
    assert!(
        loc_cursor["locators"][0]["resume"].is_null(),
        "declared harness without resume_argv must yield resume=None: {loc_cursor}"
    );

    // Seed an undeclared "mystery" session directly in DB (as if from an unknown/legacy source).
    let mystery_id = "22222222-2222-4222-8222-222222222222";
    {
        let db = rusqlite::Connection::open(&daemon.db_path).unwrap();
        db.execute(
            "INSERT INTO instance_seen(id, harness, last_live) VALUES (?1, 'mystery', strftime('%s','now'))",
            [mystery_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO locator_metadata(address, harness, native_id, env) VALUES (?1, 'mystery', 'mys_1', NULL)",
            [mystery_id],
        )
        .unwrap();
    }

    let (status, loc_mystery) = http_unix(
        &daemon.http_sock,
        "GET",
        &format!("/v1/locate?address={mystery_id}"),
        None,
    )
    .unwrap();
    assert_eq!(status, 200);
    assert!(
        loc_mystery["locators"][0]["native_id"].is_null(),
        "undeclared 'mystery' must not map native_id: {loc_mystery}"
    );
    assert!(
        loc_mystery["locators"][0]["resume"].is_null(),
        "undeclared 'mystery' must not produce resume: {loc_mystery}"
    );
    assert_ne!(
        loc_mystery["locators"][0]["recipient"]["harness"], "claude",
        "undeclared 'mystery' must never fall back to 'claude'"
    );

    // Sending to a disconnected/seen undeclared 'mystery' or disconnected declared 'cursor'
    // must return 410 gone (NOT parked into Claude's queue!).
    let (status, send_mystery) = http_unix(
        &daemon.http_sock,
        "POST",
        "/v1/messages",
        Some(&json!({ "to": mystery_id, "text": "hi mystery", "from": "tester" })),
    )
    .unwrap();
    assert_eq!(
        status, 410,
        "undeclared 'mystery' must answer gone, not fall back to parked claude: {send_mystery}"
    );

    // Disconnect cursor and verify it answers gone (not parked claude) and lists as closed.
    drop(conn);
    std::thread::sleep(Duration::from_millis(150));
    let (status, send_gone) = http_unix(
        &daemon.http_sock,
        "POST",
        "/v1/messages",
        Some(&json!({ "to": cursor_id, "text": "after disconnect", "from": "tester" })),
    )
    .unwrap();
    assert_eq!(
        status, 410,
        "disconnected declared poll-only harness must answer gone, not parked claude: {send_gone}"
    );
    let (status, inactive) = http_unix(
        &daemon.http_sock,
        "GET",
        "/v1/recipients?status=inactive",
        None,
    )
    .unwrap();
    assert_eq!(status, 200);
    let cursor_row = inactive["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["address"]
                .as_str()
                .is_some_and(|a| a.starts_with(&cursor_id))
        })
        .expect("cursor row in inactive list");
    assert_eq!(
        cursor_row["status"], "closed",
        "disconnected declared harness without reclaim must show 'closed', not 'parked': {cursor_row}"
    );
}

/// H3: Typed `argv` recipe rendering & leading-dash / shell-string refusal.
#[test]
fn h3_typed_argv_and_leading_dash_refusal() {
    // Shell string template is refused at config load.
    let shell_template = json!({
        "harnesses": {
            "cursor": {
                "delivery_mode": "poll",
                "resume_argv": "cursor --resume $id"
            }
        }
    })
    .to_string();
    assert!(
        HarnessRegistry::from_json(&shell_template).is_err(),
        "raw shell string resume_argv must be refused"
    );

    let cfg = json!({
        "harnesses": {
            "cursor": {
                "delivery_mode": "poll",
                "resume_argv": ["cursor", "--resume", { "var": "id" }],
                "id_pattern": "^[A-Za-z0-9._:=-]{1,127}$",
                "env_hint_sources": ["TMUX_PANE"]
            }
        }
    })
    .to_string();
    let daemon = Daemon::start(Some(&cfg));

    let (mut conn, hello) = PluginConn::connect(&daemon.register_sock, "cursor");
    assert_eq!(hello["status"], "ok");

    // Valid session ID renders typed resume_argv.
    let reg_ok = conn
        .send_frame(&json!({
            "action": "register",
            "request_id": "r1",
            "session": "ses_42",
            "env": { "kind": "tmux", "ref": "%7" }
        }))
        .unwrap()
        .unwrap();
    let ok_id = reg_ok["address"]
        .as_str()
        .unwrap()
        .split('@')
        .next()
        .unwrap()
        .to_string();

    // Option-like leading-dash ID must NOT validate or render resume.
    let reg_dash = conn
        .send_frame(&json!({
            "action": "register",
            "request_id": "r2",
            "session": "--exec=sh"
        }))
        .unwrap()
        .unwrap();
    let dash_id = reg_dash["address"]
        .as_str()
        .unwrap()
        .split('@')
        .next()
        .unwrap()
        .to_string();

    let (status, loc_ok) = http_unix(
        &daemon.http_sock,
        "GET",
        &format!("/v1/locate?address={ok_id}"),
        None,
    )
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(loc_ok["locators"][0]["native_id"], "ses_42");
    assert_eq!(
        loc_ok["locators"][0]["resume"],
        json!(["cursor", "--resume", "ses_42"])
    );

    // CLI `xmsg locate` displays inert resume argv without executing anything.
    let cli_out = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .scrub_agy_env()
        .args([
            "locate",
            &ok_id,
            "--http-sock",
            daemon.http_sock.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(cli_out.status.success());
    let stdout = String::from_utf8_lossy(&cli_out.stdout);
    assert!(
        stdout.contains("resume=[cursor, --resume, ses_42]"),
        "expected inert resume argv in locate output: {stdout}"
    );

    let (status, loc_dash) = http_unix(
        &daemon.http_sock,
        "GET",
        &format!("/v1/locate?address={dash_id}"),
        None,
    )
    .unwrap();
    assert_eq!(status, 200);
    assert!(
        loc_dash["locators"][0]["native_id"].is_null(),
        "leading-dash id must be refused: {loc_dash}"
    );
    assert!(
        loc_dash["locators"][0]["resume"].is_null(),
        "leading-dash id must never produce resume: {loc_dash}"
    );
}

/// H4: Default-deny capabilities, drain-by-default on edit/removal, and immediate security revocation.
#[test]
fn h4_default_deny_capabilities_drain_window_and_immediate_security_revocation() {
    let initial = json!({
        "drain_window_secs": 2,
        "harnesses": {
            "cursor": {
                "delivery_mode": "poll"
            }
        }
    })
    .to_string();
    let daemon = Daemon::start(Some(&initial));

    // 1. Default-deny capabilities.attachments == false refuses Attach and ReadAttachment.
    let (mut conn_v1, hello_v1) = PluginConn::connect(&daemon.register_sock, "cursor");
    assert_eq!(hello_v1["status"], "ok");
    let reg_v1 = conn_v1
        .send_frame(&json!({ "action": "register", "request_id": "r1", "session": "s1" }))
        .unwrap()
        .unwrap();
    assert_eq!(reg_v1["status"], "ok");

    let attach_denied = conn_v1
        .send_frame(&json!({
            "action": "attach",
            "request_id": "att1",
            "session": "s1",
            "name": "note.txt",
            "media_type": "text/plain",
            "data": "hello"
        }))
        .unwrap()
        .unwrap();
    assert_eq!(
        attach_denied["error"], "denied",
        "default-deny attachments must refuse Attach: {attach_denied}"
    );
    let read_denied = conn_v1
        .send_frame(&json!({
            "action": "read_attachment",
            "request_id": "ra1",
            "session": "s1",
            "message_id": "01DUMMY",
            "index": 0
        }))
        .unwrap()
        .unwrap();
    assert_eq!(
        read_denied["error"], "denied",
        "default-deny attachments must refuse ReadAttachment: {read_denied}"
    );

    // 2. Ordinary edit enabling attachments: v1 drains for 2s (pinned to attachments=false),
    //    new connection v2 immediately gets attachments=true while still enforcing session ownership.
    let edited = json!({
        "drain_window_secs": 2,
        "harnesses": {
            "cursor": {
                "delivery_mode": "poll",
                "capabilities": { "attachments": true }
            }
        }
    })
    .to_string();
    daemon.write_harnesses(&edited);
    let reload_out = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .scrub_agy_env()
        .args([
            "harness",
            "reload",
            "--http-sock",
            daemon.http_sock.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        reload_out.status.success(),
        "xmsg harness reload failed: {}",
        String::from_utf8_lossy(&reload_out.stderr)
    );

    // v1 is still alive during the 2s drain window and still pinned to attachments=false.
    let list_during_drain = conn_v1
        .send_frame(&json!({ "action": "list", "request_id": "l-drain", "session": "s1" }))
        .unwrap()
        .unwrap();
    assert_eq!(
        list_during_drain["status"], "ok",
        "live session must keep draining during drain_window_secs: {list_during_drain}"
    );
    let attach_still_denied_v1 = conn_v1
        .send_frame(&json!({
            "action": "attach",
            "request_id": "att-v1",
            "session": "s1",
            "name": "note.txt",
            "media_type": "text/plain",
            "data": "hello"
        }))
        .unwrap()
        .unwrap();
    assert_eq!(attach_still_denied_v1["error"], "denied");

    // New connection v2 immediately gets attachments=true.
    let (mut conn_v2, hello_v2) = PluginConn::connect(&daemon.register_sock, "cursor");
    assert_eq!(hello_v2["status"], "ok");
    let reg_v2 = conn_v2
        .send_frame(&json!({ "action": "register", "request_id": "r2", "session": "s2" }))
        .unwrap()
        .unwrap();
    assert_eq!(reg_v2["status"], "ok");

    let attach_ok = conn_v2
        .send_frame(&json!({
            "action": "attach",
            "request_id": "att-v2",
            "session": "s2",
            "name": "note.txt",
            "media_type": "text/plain",
            "data": "aGVsbG8="
        }))
        .unwrap()
        .unwrap();
    assert_eq!(
        attach_ok["status"], "ok",
        "attachments=true must allow Attach for held session: {attach_ok}"
    );
    // Ownership still enforced even with attachments=true (unheld session refused).
    let attach_unheld = conn_v2
        .send_frame(&json!({
            "action": "attach",
            "request_id": "att-unheld",
            "session": "not-mine",
            "name": "note.txt",
            "media_type": "text/plain",
            "data": "aGVsbG8="
        }))
        .unwrap()
        .unwrap();
    assert_eq!(
        attach_unheld["status"], "error",
        "attachments=true must still enforce session ownership: {attach_unheld}"
    );

    // Once the 2s drain window expires, v1 closes automatically while v2 stays alive.
    assert!(
        conn_v1.wait_eof(Duration::from_secs(4)),
        "v1 must close once drain_window_secs expires"
    );
    let list_v2 = conn_v2
        .send_frame(&json!({ "action": "list", "request_id": "l-v2", "session": "s2" }))
        .unwrap()
        .unwrap();
    assert_eq!(list_v2["status"], "ok");

    // 3. Ordinary removal drains v2 during drain_window_secs while blocking new connections at once.
    let removed = json!({
        "drain_window_secs": 2,
        "harnesses": {}
    })
    .to_string();
    daemon.write_harnesses(&removed);
    let reload_rm = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .scrub_agy_env()
        .args([
            "harness",
            "reload",
            "--http-sock",
            daemon.http_sock.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        reload_rm.status.success(),
        "xmsg harness reload (removal) failed: {}",
        String::from_utf8_lossy(&reload_rm.stderr)
    );

    let (_new_c, new_hello) = PluginConn::connect(&daemon.register_sock, "cursor");
    assert_eq!(
        new_hello["error"], "bad_request",
        "removed harness must refuse new connections immediately: {new_hello}"
    );
    let list_v2_drain = conn_v2
        .send_frame(&json!({ "action": "list", "request_id": "l-v2-drain", "session": "s2" }))
        .unwrap()
        .unwrap();
    assert_eq!(
        list_v2_drain["status"], "ok",
        "removed harness must drain existing live session for drain_window_secs"
    );
    assert!(
        conn_v2.wait_eof(Duration::from_secs(4)),
        "v2 must close after removal drain window expires"
    );

    // 4. Explicit security revocation via CLI (`xmsg harness revoke`) immediately blocks active
    //    operations AND new connections with ZERO drain delay (even with a 600s drain window!).
    let readded = json!({
        "drain_window_secs": 600,
        "harnesses": {
            "windsurf": { "delivery_mode": "poll" }
        }
    })
    .to_string();
    daemon.write_harnesses(&readded);
    let reload_re = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .scrub_agy_env()
        .args([
            "harness",
            "reload",
            "--http-sock",
            daemon.http_sock.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        reload_re.status.success(),
        "xmsg harness reload (re-add) failed: {}",
        String::from_utf8_lossy(&reload_re.stderr)
    );

    let (mut conn_ws, hello_ws) = PluginConn::connect(&daemon.register_sock, "windsurf");
    assert_eq!(hello_ws["status"], "ok");
    let reg_ws = conn_ws
        .send_frame(&json!({ "action": "register", "request_id": "rw1", "session": "ws1" }))
        .unwrap()
        .unwrap();
    assert_eq!(reg_ws["status"], "ok");

    let t_revoke = Instant::now();
    let rev_out = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .scrub_agy_env()
        .args([
            "harness",
            "revoke",
            "windsurf",
            "--http-sock",
            daemon.http_sock.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        rev_out.status.success(),
        "xmsg harness revoke failed: {}",
        String::from_utf8_lossy(&rev_out.stderr)
    );

    // Live connection is terminated immediately (well under 600s drain window!).
    assert!(
        conn_ws.wait_eof(Duration::from_secs(2)),
        "security revocation must close live connection immediately without waiting for drain window"
    );
    assert!(
        t_revoke.elapsed() < Duration::from_secs(3),
        "revocation took too long: {:?}",
        t_revoke.elapsed()
    );

    // New connections for revoked harness are immediately refused with `denied`.
    let (_ws2, hello_ws2) = PluginConn::connect(&daemon.register_sock, "windsurf");
    assert_eq!(
        hello_ws2["error"], "denied",
        "security-revoked harness must be refused with denied: {hello_ws2}"
    );

    // 5. Config-marked security revocation ("revoked": true) also blocks immediately with zero drain delay.
    let cfg_add = json!({
        "drain_window_secs": 600,
        "harnesses": {
            "aider": { "delivery_mode": "poll" }
        }
    })
    .to_string();
    daemon.write_harnesses(&cfg_add);
    assert!(Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .scrub_agy_env()
        .args([
            "harness",
            "reload",
            "--http-sock",
            daemon.http_sock.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    let (mut conn_aider, hello_aider) = PluginConn::connect(&daemon.register_sock, "aider");
    assert_eq!(hello_aider["status"], "ok");
    let cfg_revoked = json!({
        "drain_window_secs": 600,
        "harnesses": {
            "aider": { "delivery_mode": "poll", "revoked": true }
        }
    })
    .to_string();
    daemon.write_harnesses(&cfg_revoked);
    assert!(Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .scrub_agy_env()
        .args([
            "harness",
            "reload",
            "--http-sock",
            daemon.http_sock.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert!(
        conn_aider.wait_eof(Duration::from_secs(2)),
        "config-marked security revocation must close live connection immediately"
    );
    let (_aider2, hello_aider2) = PluginConn::connect(&daemon.register_sock, "aider");
    assert_eq!(hello_aider2["error"], "denied");
}

/// Admin routes (`POST /v1/harnesses/reload`, `POST /v1/harnesses/{name}/revoke`) are local-only,
/// owner-UID-only, and never reachable by a plugin connection/process or over TCP / `/fed`.
#[tokio::test]
async fn admin_routes_denied_to_plugins_and_absent_from_fed_and_tcp() {
    let cfg = json!({
        "harnesses": {
            "cursor": { "delivery_mode": "poll" }
        }
    })
    .to_string();
    let daemon = Daemon::start(Some(&cfg));

    // 1. Plugin connection cannot invoke revoke/reload over register.sock.
    let (mut conn, hello) = PluginConn::connect(&daemon.register_sock, "cursor");
    assert_eq!(hello["status"], "ok");
    let bad_revoke = conn
        .send_frame(&json!({ "action": "revoke", "request_id": "x1", "harness": "cursor" }))
        .unwrap()
        .unwrap();
    assert_eq!(bad_revoke["error"], "bad_request");

    // 2. Because this test process holds a live plugin connection in `plugin_procs`, even calling
    //    http.sock admin routes from this plugin process is denied (403)!
    let (status_rev, body_rev) = http_unix(
        &daemon.http_sock,
        "POST",
        "/v1/harnesses/cursor/revoke",
        None,
    )
    .unwrap();
    assert_eq!(
        status_rev, 403,
        "plugin process must be denied /v1/harnesses/{{name}}/revoke: {body_rev}"
    );
    let (status_rel, body_rel) =
        http_unix(&daemon.http_sock, "POST", "/v1/harnesses/reload", None).unwrap();
    assert_eq!(
        status_rel, 403,
        "plugin process must be denied /v1/harnesses/reload: {body_rel}"
    );
    drop(conn);

    // 3. Non-Unix TCP router (`build_router`) does NOT mount harness admin routes (404).
    let dir = tempdir().unwrap();
    let db = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&db).unwrap();
    let state = Arc::new(AppState {
        sessions_dirs: vec![dir.path().join("sessions")],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: dir.path().join("presence"),
            brain_dir: dir.path().join("brain"),
            ..Default::default()
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        node_name: "local.test".into(),
        max_body: 65536,
        max_attachment_bytes: 65536,
        request_counter: AtomicU64::new(0),
        db: Arc::new(Mutex::new(db)),
        notify_tx: tokio::sync::broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        fed_state: None,
    });
    let tcp_router = xmsg::http::build_router(state.clone());
    for uri in ["/v1/harnesses/reload", "/v1/harnesses/cursor/revoke"] {
        let resp = tcp_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "TCP router must not expose {uri}"
        );
    }

    // 4. Unix router without PeerInfo (e.g. forged non-Unix call) denies 403.
    let unix_router = xmsg::http::build_unix_router(state);
    let resp = unix_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/harnesses/cursor/revoke")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Unix router must refuse admin route without same-UID Unix PeerInfo"
    );
}

/// File ownership check accepts NixOS /nix/store style root-owned 0444 files and rejects
/// group/world-writable or other-UID files.
#[test]
fn file_ownership_accepts_root_0444_and_real_0444_file() {
    // Simulated root-owned 0444 file (NixOS /nix/store) accepted for unprivileged UID 1000.
    assert!(validate_file_meta(true, 0, 0o100444, 1000).is_ok());
    assert!(validate_file_meta(true, 0, 0o100664, 1000).is_err());
    assert!(validate_file_meta(true, 2000, 0o100444, 1000).is_err());

    // Real 0444 file on disk owned by current UID loads cleanly; 0666 is refused.
    let dir = tempdir().unwrap();
    let ro_file = dir.path().join("harnesses-ro.json");
    fs::write(
        &ro_file,
        json!({ "harnesses": { "cursor": { "delivery_mode": "poll" } } }).to_string(),
    )
    .unwrap();
    fs::set_permissions(&ro_file, fs::Permissions::from_mode(0o444)).unwrap();
    let reg = HarnessRegistry::load_file(&ro_file).expect("0444 harnesses file must load");
    assert!(reg.is_declared("cursor"));

    let writable = dir.path().join("harnesses-bad.json");
    fs::write(
        &writable,
        json!({ "harnesses": { "cursor": { "delivery_mode": "poll" } } }).to_string(),
    )
    .unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(
        HarnessRegistry::load_file(&writable).is_err(),
        "group-writable harnesses file must be refused"
    );
}
