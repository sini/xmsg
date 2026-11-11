use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};

mod http_child;

#[test]
fn http_child_entry() {
    http_child::serve_if_child();
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Node {
    dir: TempDir,
    http: PathBuf,
    register: PathBuf,
    agent: PathBuf,
    _daemon: Process,
}

fn isolated(cmd: &mut Command, dir: &Path) {
    cmd.env("HOME", dir)
        .env("CODEX_HOME", dir.join("codex"))
        .env_remove("XMSG_CODEX_HOME")
        .env_remove("XMSG_HOST_LABEL")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

impl Node {
    fn start() -> Self {
        let dir = tempdir().unwrap();
        for name in ["run", "sessions", "codex"] {
            let p = dir.path().join(name);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let run = dir.path().join("run");
        let http = run.join("http.sock");
        let register = run.join("register.sock");
        let agent = run.join("agent.sock");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        isolated(&mut cmd, dir.path());
        cmd.env("XDG_RUNTIME_DIR", &run)
            .args(["serve", "--db-path"])
            .arg(dir.path().join("messages.db"))
            .arg("--sessions-dir")
            .arg(dir.path().join("sessions"))
            .arg("--codex-home")
            .arg(dir.path().join("codex"))
            .arg("--http-sock")
            .arg(&http)
            .arg("--agent-sock")
            .arg(&agent)
            .arg("--register-sock")
            .arg(&register)
            .arg("--svc-exe")
            .arg(format!("producer={}", env!("CARGO_BIN_EXE_xmsg")));
        let mut daemon = Process(cmd.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(20);
        while std::os::unix::net::UnixStream::connect(&register).is_err()
            || std::os::unix::net::UnixStream::connect(&http).is_err()
        {
            assert!(daemon.0.try_wait().unwrap().is_none(), "daemon exited");
            assert!(Instant::now() < deadline, "daemon readiness timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            dir,
            http,
            register,
            agent,
            _daemon: daemon,
        }
    }

    fn script(&self, body: &str) -> PathBuf {
        let script = self.dir.path().join("producer.sh");
        fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    fn service(&self, program: &Path, args: &[&str], timeout: u64, cap: usize) -> Process {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        isolated(&mut cmd, self.dir.path());
        cmd.current_dir(self.dir.path())
            .env("SYNTHETIC_SECRET", "ENV_CANARY_NOT_FOR_REPLY")
            .args(["service", "exec", "--name", "producer", "--register-sock"])
            .arg(&self.register)
            .arg("--agent-sock")
            .arg(&self.agent)
            .arg("--timeout-ms")
            .arg(timeout.to_string())
            .arg("--max-output-bytes")
            .arg(cap.to_string())
            .arg("--")
            .arg(program)
            .args(args);
        Process(cmd.spawn().unwrap())
    }

    async fn request(&self, method: &str, route: &str, body: Option<&Value>) -> (u16, Value) {
        let (status, text) = http_child::request_detached(
            "http_child_entry",
            &http_child::Via::Unix(self.http.clone()),
            method,
            route,
            body,
        )
        .await;
        (
            status,
            serde_json::from_str(&text).unwrap_or_else(|_| panic!("HTTP {status}: {text}")),
        )
    }

    async fn send(&self, service: &mut Process, text: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(service.0.try_wait().unwrap().is_none(), "service exited");
            let (status, body) = self
                .request(
                    "POST",
                    "/v1/messages",
                    Some(&json!({
                        "to":"producer", "from":"test", "text":text,
                        "idempotency_key":"service-exec-request"
                    })),
                )
                .await;
            if status == 200 || status == 202 {
                return body["message_id"].as_str().unwrap().to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "service registration: {status} {body}"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }

    async fn replies(&self, id: &str) -> Vec<Value> {
        let (status, body) = self
            .request("GET", &format!("/v1/messages/{id}/replies"), None)
            .await;
        assert_eq!(status, 200, "{body}");
        body.as_array()
            .or_else(|| body["replies"].as_array())
            .unwrap()
            .clone()
    }

    async fn settled_reply(&self, id: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let replies = self.replies(id).await;
            let (_, message) = self
                .request("GET", &format!("/v1/messages/{id}"), None)
                .await;
            if !replies.is_empty() && message["outcome"] == "delivered" {
                assert_eq!(replies.len(), 1, "exactly one reply: {replies:?}");
                tokio::time::sleep(Duration::from_millis(150)).await;
                assert_eq!(
                    self.replies(id).await.len(),
                    1,
                    "no duplicate reply after ACK"
                );
                return replies[0]["text"].as_str().unwrap().to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "reply/ACK timed out: {message} {replies:?}"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_stdout_ignores_request_and_keeps_canaries_private() {
    let node = Node::start();
    fs::write(
        node.dir.path().join("fake-token"),
        "FILE_CANARY_NOT_FOR_REPLY",
    )
    .unwrap();
    let output = " {\"status\":\"unknown\",\"age_seconds\":123,\"extra\":true} \n";
    let script = node.script("printf x >> invocations\nprintf '%s\\n' STDERR_CANARY_NOT_FOR_REPLY >&2\n[ \"$#\" -eq 1 ] || exit 9\n[ \"$1\" = 'literal;$(false)' ] || exit 9\nif read -r request; then exit 9; fi\nprintf ' {\"status\":\"unknown\",\"age_seconds\":123,\"extra\":true} \\n'");
    let mut service = node.service(&script, &["literal;$(false)"], 2000, 65536);
    let marker = node.dir.path().join("injected");
    let request = format!(
        "$(touch {}) ; cat fake-token; echo $SYNTHETIC_SECRET",
        marker.display()
    );
    let id = node.send(&mut service, &request).await;
    assert_eq!(node.settled_reply(&id).await, output);
    assert!(
        !marker.exists(),
        "request was interpreted as a shell command"
    );
    assert_eq!(node.send(&mut service, &request).await, id);
    assert_eq!(node.settled_reply(&id).await, output);
    assert_eq!(fs::read(node.dir.path().join("invocations")).unwrap(), b"x");
}

async fn failure(body: &str, error: &str, timeout: u64, cap: usize) {
    let node = Node::start();
    let script = node.script(body);
    let mut service = node.service(&script, &[], timeout, cap);
    let id = node.send(&mut service, "ignored").await;
    let reply = node.settled_reply(&id).await;
    assert_eq!(
        serde_json::from_str::<Value>(&reply).unwrap(),
        json!({"status":"unknown", "error":error})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdout_overflow_is_a_single_typed_failure() {
    let node = Node::start();
    let pidfile = node.dir.path().join("command.pid");
    let script = node.script(
        "printf '%s' \"$$\" > \"$1\"\nwhile :; do printf '01234567890123456789012345678901'; done",
    );
    let mut service = node.service(&script, &[pidfile.to_str().unwrap()], 2000, 64);
    let id = node.send(&mut service, "ignored").await;
    assert_eq!(
        serde_json::from_str::<Value>(&node.settled_reply(&id).await).unwrap(),
        json!({"status":"unknown", "error":"output_limit"})
    );
    let pid: i32 = fs::read_to_string(pidfile).unwrap().parse().unwrap();
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "owned command still exists after overflow reply"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_reaps_the_owned_command() {
    let node = Node::start();
    let pidfile = node.dir.path().join("command.pid");
    let script = node.script("printf '%s' \"$$\" > \"$1\"\nexec sleep 30");
    let mut service = node.service(&script, &[pidfile.to_str().unwrap()], 200, 65536);
    let id = node.send(&mut service, "ignored").await;
    let reply = node.settled_reply(&id).await;
    assert_eq!(
        serde_json::from_str::<Value>(&reply).unwrap(),
        json!({"status":"unknown", "error":"timeout"})
    );
    let pid: i32 = fs::read_to_string(pidfile).unwrap().parse().unwrap();
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "owned command still exists after timeout reply"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_empty_and_failed_commands_have_static_errors() {
    failure("exit 0", "empty_output", 2000, 65536).await;
    failure("printf '\\377'", "invalid_utf8", 2000, 65536).await;
    failure(
        "printf 'SYNTHETIC_PRIVATE_DIAGNOSTIC'; exit 7",
        "command_failed",
        2000,
        65536,
    )
    .await;
    let node = Node::start();
    let mut service = node.service(&node.dir.path().join("missing-program"), &[], 2000, 65536);
    let id = node.send(&mut service, "ignored").await;
    assert_eq!(
        serde_json::from_str::<Value>(&node.settled_reply(&id).await).unwrap(),
        json!({"status":"unknown", "error":"command_failed"})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_is_absent_without_explicit_runner() {
    let node = Node::start();
    let (status, body) = node
        .request(
            "POST",
            "/v1/messages",
            Some(&json!({"to":"producer", "from":"test", "text":"ordinary request"})),
        )
        .await;
    assert!(
        status >= 400,
        "unstarted command service unexpectedly exists: {status} {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_ack_response_reconnects_without_repeating_reply_or_command() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    async fn read(stream: &mut BufReader<UnixStream>) -> Value {
        let mut line = String::new();
        assert!(stream.read_line(&mut line).await.unwrap() > 0);
        serde_json::from_str(&line).unwrap()
    }
    async fn write(stream: &mut BufReader<UnixStream>, frame: Value) {
        stream
            .get_mut()
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
    }

    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let register_path = temp.path().join("register.sock");
    let agent_path = temp.path().join("agent.sock");
    let register = UnixListener::bind(&register_path).unwrap();
    let agent = UnixListener::bind(&agent_path).unwrap();
    let script = temp.path().join("producer.sh");
    fs::write(
        &script,
        "#!/bin/sh\nprintf x >> invocations\nprintf 'retained response\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_xmsg"));
    isolated(&mut command, temp.path());
    command
        .current_dir(temp.path())
        .args(["service", "exec", "--name", "producer", "--register-sock"])
        .arg(&register_path)
        .arg("--agent-sock")
        .arg(&agent_path)
        .arg("--")
        .arg(&script);
    let mut service = Process(command.spawn().unwrap());

    tokio::time::timeout(Duration::from_secs(10), async {
        let registration = json!({"status":"ok", "address":"producer@fixture", "node":"fixture"});
        let mut first = BufReader::new(register.accept().await.unwrap().0);
        assert_eq!(read(&mut first).await["name"], "producer");
        write(&mut first, registration.clone()).await;
        assert_eq!(read(&mut first).await["action"], "poll");
        write(&mut first, json!({"action":"deliver", "messageId":"retained-request", "fromName":"sender@fixture", "text":"ignored", "envelope":"ignored", "origin":{"service":"sender", "node":"fixture"}})).await;

        let mut reply = BufReader::new(agent.accept().await.unwrap().0);
        assert_eq!(read(&mut reply).await, json!({"action":"reply", "schema_version":2, "message_id":"retained-request", "text":"retained response\n", "idempotency_key":"service-exec:producer:retained-request"}));
        write(&mut reply, json!({"status":"ok", "reply":{"seq":1,"messageId":"retained-request","createdAt":1,"replierSessionId":"producer","text":"retained response\n","pushOutcome":"stored"}})).await;
        drop(reply);
        let ack = json!({"action":"ack", "messageId":"retained-request"});
        assert_eq!(read(&mut first).await, ack);
        drop(first);

        let mut second = BufReader::new(register.accept().await.unwrap().0);
        assert_eq!(read(&mut second).await["name"], "producer");
        write(&mut second, registration).await;
        assert_eq!(read(&mut second).await, ack, "retry ACK before polling another request");
        write(&mut second, json!({"status":"ok"})).await;
        assert_eq!(read(&mut second).await["action"], "poll");
        assert!(tokio::time::timeout(Duration::from_millis(150), agent.accept()).await.is_err(), "reply repeated after reconnect");
        assert_eq!(fs::read(temp.path().join("invocations")).unwrap(), b"x", "command repeated after reconnect");
        assert!(service.0.try_wait().unwrap().is_none());
    }).await.expect("reconnect fault cell exceeded 10 seconds");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn termination_reaps_the_running_command() {
    let node = Node::start();
    let pidfile = node.dir.path().join("command.pid");
    let script = node.script("printf '%s' \"$$\" > \"$1\"\nexec sleep 30");
    let mut service = node.service(&script, &[pidfile.to_str().unwrap()], 60000, 65536);
    node.send(&mut service, "ignored").await;
    tokio::time::timeout(Duration::from_secs(10), async {
        let command_pid: i32 = loop {
            if let Ok(text) = fs::read_to_string(&pidfile) {
                if let Ok(pid) = text.parse() {
                    break pid;
                }
            }
            assert!(service.0.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(
            unsafe { libc::kill(service.0.id() as i32, libc::SIGTERM) },
            0
        );
        let status = loop {
            if let Some(status) = service.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert!(status.success(), "service termination: {status}");
        assert_eq!(
            unsafe { libc::kill(command_pid, 0) },
            -1,
            "owned command still exists after service termination"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    })
    .await
    .expect("service termination exceeded 10 seconds");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permanent_reply_refusal_exits_without_retrying() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let register_path = temp.path().join("register.sock");
    let agent_path = temp.path().join("agent.sock");
    let register = UnixListener::bind(&register_path).unwrap();
    let agent = UnixListener::bind(&agent_path).unwrap();
    let script = temp.path().join("producer.sh");
    fs::write(
        &script,
        "#!/bin/sh\nprintf x >> invocations\nprintf 'response'\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_xmsg"));
    isolated(&mut command, temp.path());
    command
        .current_dir(temp.path())
        .args(["service", "exec", "--name", "producer", "--register-sock"])
        .arg(&register_path)
        .arg("--agent-sock")
        .arg(&agent_path)
        .arg("--")
        .arg(&script)
        .stderr(Stdio::piped());
    let mut service = Process(command.spawn().unwrap());
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut connection = BufReader::new(register.accept().await.unwrap().0);
        let mut line = String::new();
        connection.read_line(&mut line).await.unwrap();
        connection.get_mut().write_all(b"{\"status\":\"ok\",\"address\":\"producer@fixture\",\"node\":\"fixture\"}\n").await.unwrap();
        line.clear();
        connection.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["action"], "poll");
        connection.get_mut().write_all(format!("{}\n", json!({"action":"deliver", "messageId":"purged-request", "fromName":"sender@fixture", "text":"ignored", "envelope":"ignored", "origin":{"service":"sender", "node":"fixture"}})).as_bytes()).await.unwrap();
        let mut reply = BufReader::new(agent.accept().await.unwrap().0);
        line.clear();
        reply.read_line(&mut line).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["action"], "reply");
        reply.get_mut().write_all(b"{\"status\":\"error\",\"error\":\"not_found\",\"detail\":\"SYNTHETIC_PRIVATE_SERVER_DETAIL\"}\n").await.unwrap();
        drop(reply);
        let status = loop {
            if let Some(status) = service.0.try_wait().unwrap() {
                break status;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                retry = register.accept() => panic!("permanent reply refusal retried registration: {}", retry.is_ok()),
            }
        };
        assert!(!status.success(), "permanent reply refusal must stop the runner");
        assert_eq!(fs::read(temp.path().join("invocations")).unwrap(), b"x");
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut service.0.stderr.take().unwrap(), &mut stderr).unwrap();
        assert!(!stderr.contains("SYNTHETIC_PRIVATE_SERVER_DETAIL"), "server detail leaked to diagnostic");
        assert!(!stderr.trim().is_empty(), "failure should have a static diagnostic");
    }).await.expect("permanent refusal did not stop the runner within 10 seconds");
}
