use std::process::Command;

#[test]
fn list_help_exposes_operator_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .args(["list", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
use std::path::PathBuf;
use std::process::{Child, Output, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn frame(stream: &mut BufReader<UnixStream>, value: Value) -> Value {
    writeln!(stream.get_mut(), "{value}").unwrap();
    let mut line = String::new();
    stream.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn receiver_process() {
    let Ok(dir) = std::env::var("XMSG_OPERATOR_RECEIVER") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let mut stream = BufReader::new(UnixStream::connect(dir.join("run/register.sock")).unwrap());
    stream
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let response = frame(
        &mut stream,
        json!({"harness":"svc", "name":"operator-receiver"}),
    );
    assert_eq!(response["status"], "ok", "{response}");
    fs::write(dir.join("ready"), "ready").unwrap();
    loop {
        let message = frame(&mut stream, json!({"action":"poll", "waitSecs":1}));
        if message["action"] == "deliver" {
            let id = message["messageId"].as_str().unwrap();
            let response = frame(
                &mut stream,
                json!({"action":"reply", "messageId":id, "text":"operator reply"}),
            );
            assert_eq!(response["status"], "ok", "{response}");
            let response = frame(&mut stream, json!({"action":"ack", "messageId":id}));
            assert_eq!(response["status"], "ok", "{response}");
        }
    }
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !predicate() {
        assert!(Instant::now() < deadline, "fixture did not become ready");
        std::thread::sleep(Duration::from_millis(25));
    }
}

struct Fixture {
    _receiver: Process,
    _daemon: Process,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}
impl Fixture {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for name in ["run", "sessions"] {
            fs::create_dir(dir.path().join(name)).unwrap();
            fs::set_permissions(dir.path().join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let socket = dir.path().join("run/http.sock");
        let daemon = Process(
            Command::new(env!("CARGO_BIN_EXE_xmsg"))
                .env("HOME", dir.path())
                .env("CODEX_HOME", dir.path().join("codex"))
                .env_remove("XMSG_CODEX_HOME")
                .env("XDG_RUNTIME_DIR", dir.path().join("run"))
                .env_remove("XMSG_HOST_LABEL")
                .arg("serve")
                .arg("--codex-home")
                .arg(dir.path().join("codex"))
                .arg("--db-path")
                .arg(dir.path().join("xmsg.db"))
                .arg("--sessions-dir")
                .arg(dir.path().join("sessions"))
                .arg("--http-sock")
                .arg(&socket)
                .arg("--agent-sock")
                .arg(dir.path().join("run/agent.sock"))
                .arg("--register-sock")
                .arg(dir.path().join("run/register.sock"))
                .arg("--svc-exe")
                .arg(format!(
                    "operator-receiver={}",
                    std::env::current_exe().unwrap().display()
                ))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for(|| {
            UnixStream::connect(&socket).is_ok()
                && UnixStream::connect(dir.path().join("run/register.sock")).is_ok()
        });
        let receiver = Process(
            Command::new(std::env::current_exe().unwrap())
                .args(["receiver_process", "--exact", "--nocapture"])
                .env("XMSG_OPERATOR_RECEIVER", dir.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for(|| dir.path().join("ready").exists());
        Self {
            _receiver: receiver,
            _daemon: daemon,
            socket,
            _dir: dir,
        }
    }
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .env("XMSG_HTTP_SOCK", &self.socket)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(text) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    }
    fn json(&self, args: &[&str], stdin: Option<&str>) -> Value {
        let output = self.run(args, stdin);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(text.trim_end().lines().count(), 1, "JSON must be compact");
        value
    }
}

#[test]
fn operator_round_trip_over_unix_socket() {
    let fixture = Fixture::start();
    let listed = fixture.json(
        &["list", "--kind", "service", "--status", "live", "--json"],
        None,
    );
    assert_eq!(
        listed["recipients"].as_array().unwrap().len(),
        1,
        "{listed}"
    );
    assert!(listed["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|node| node["status"] == "ok"));
    let address = listed["recipients"][0]["address"].as_str().unwrap();
    let node = listed["recipients"][0]["node"].as_str().unwrap();
    assert_eq!(
        fixture.json(
            &[
                "list",
                "--node",
                node,
                "--json",
                "--http-sock",
                fixture.socket.to_str().unwrap()
            ],
            None
        ),
        listed
    );
    let human = fixture.run(&["list"], None);
    assert!(human.status.success());
    let human = String::from_utf8(human.stdout).unwrap();
    for heading in ["ADDRESS", "KIND", "LABEL", "STATUS", "NODE"] {
        assert!(human.contains(heading), "{human}");
    }
    let sent = fixture.json(
        &[
            "send",
            address,
            "--idempotency-key",
            "operator-one",
            "--json",
        ],
        Some("stdin message\n"),
    );
    let id = sent["message_id"].as_str().unwrap();
    let replay = fixture.json(
        &[
            "send",
            address,
            "-",
            "--idempotency-key",
            "operator-one",
            "--json",
        ],
        Some("stdin message\n"),
    );
    assert_eq!(replay["message_id"], sent["message_id"]);
    let detail = fixture.json(&["show", id, "--json"], None);
    let (status, raw) =
        xmsg::http::http_request_unix(&fixture.socket, "GET", &format!("/v1/messages/{id}"), None)
            .unwrap();
    assert_eq!(status.as_u16(), 200);
    let api: Value = serde_json::from_str(&raw).unwrap();
    for key in [
        "id",
        "createdAt",
        "sessionId",
        "fromName",
        "bytes",
        "recipientHarness",
        "threadId",
    ] {
        assert_eq!(detail[key], api[key], "show must retain API field {key}");
    }
    assert_eq!(detail["id"], id);
    assert_eq!(detail["fromName"], format!("cli · anon@{node}"));
    assert_eq!(detail["bytes"], "stdin message\n".len());
    let mut replies = Value::Null;
    wait_for(|| {
        replies = fixture.json(&["replies", id, "--wait", "1", "--json"], None);
        replies.to_string().contains("operator reply")
    });
    for args in [
        vec!["show", id],
        vec!["replies", id],
        vec!["send", address, "human message"],
    ] {
        let output = fixture.run(&args, None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
    }
    let error = fixture.run(&["send", "unknown-target", "hello", "--json"], None);
    assert!(!error.status.success());
    let error: Value = serde_json::from_slice(&error.stdout).unwrap();
    assert_eq!(error["error"], "not_found", "{error}");
}

#[test]
fn address_shaped_sender_is_rejected_before_socket_access() {
    let dir = tempfile::tempdir().unwrap();
    for sender in ["operator@node", "operator/child"] {
        let output = Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .args(["send", "target", "hello", "--from", sender, "--http-sock"])
            .arg(dir.path().join("missing.sock"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("from"), "{error}");
        assert!(
            !error.contains("No such file"),
            "validation must precede socket access: {error}"
        );
    }
}

#[test]
fn check_peers_help_explains_validation() {
    let output = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .args(["check-peers", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("Validate a peers file (the same rules `serve` applies at startup); exit 0 if valid, otherwise print the failing rule. Use it in CI or before a deploy."), "{help}");
}
