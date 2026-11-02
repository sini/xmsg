//! A registered service's message is `delivered` only once the service acks it, as a pi or
//! plugin session's is (HA3, A13); until then it is `queued`.
//!
//! Every cell runs a real `xmsg serve`, registers this test process as a service on its
//! `register.sock`, and sends from a process outside every tree (`http_child`), since this
//! process is the service.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

mod http_child;

use http_child::Via;

const SVC: &str = "acker";

/// The HTTP child's entry point (`http_child`): a no-op in a normal test run.
#[test]
fn http_child_entry() {
    http_child::serve_if_child();
}

struct Node {
    http_sock: PathBuf,
    register_sock: PathBuf,
    child: Child,
}

impl Node {
    fn start(dir: &Path) -> Node {
        let run = dir.join("run");
        let sessions = dir.join("sessions");
        for d in [&run, &sessions] {
            fs::create_dir_all(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let http_sock = run.join("http.sock");
        let register_sock = run.join("register.sock");
        let exe = std::env::current_exe().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .env("XDG_RUNTIME_DIR", &run)
            .env("HOME", dir)
            .env_remove("XMSG_HOST_LABEL")
            .arg("serve")
            .arg("--db-path")
            .arg(dir.join("xmsg.db"))
            .arg("--sessions-dir")
            .arg(&sessions)
            .arg("--http-sock")
            .arg(&http_sock)
            .arg("--agent-sock")
            .arg(run.join("agent.sock"))
            .arg("--register-sock")
            .arg(&register_sock)
            .arg("--svc-exe")
            .arg(format!("{SVC}={}", exe.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn xmsg serve");
        for _ in 0..1200 {
            if std::os::unix::net::UnixStream::connect(&http_sock).is_ok() && std::os::unix::net::UnixStream::connect(&register_sock).is_ok() {
                return Node {
                    http_sock,
                    register_sock,
                    child,
                };
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("xmsg serve exited early: {status}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("xmsg serve never served");
    }

    /// A send to the service from a process outside every tree, keyed when `key` is given.
    async fn send(&self, text: &str, key: Option<&str>) -> Value {
        let mut body = json!({ "to": SVC, "from": "ci", "text": text });
        if let Some(k) = key {
            body["idempotency_key"] = json!(k);
        }
        let (status, text) = http_child::request_detached(
            "http_child_entry",
            &Via::Unix(self.http_sock.clone()),
            "POST",
            "/v1/messages",
            Some(&body),
        )
        .await;
        assert!(status == 200 || status == 202, "send: {status} {text}");
        serde_json::from_str(&text).unwrap()
    }

    /// The outcome `GET /v1/messages/{id}` reads.
    async fn outcome(&self, id: &str) -> String {
        let sock = self.http_sock.clone();
        let path = format!("/v1/messages/{id}");
        let (status, text) = tokio::task::spawn_blocking(move || {
            xmsg::http::http_request_unix(&sock, "GET", &path, None)
        })
        .await
        .unwrap()
        .expect("http.sock request");
        assert_eq!(status.as_u16(), 200, "{text}");
        let v: Value = serde_json::from_str(&text).unwrap();
        v["outcome"].as_str().unwrap().to_string()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// This test process, registered as the service.
struct Service {
    r: BufReader<OwnedReadHalf>,
    w: OwnedWriteHalf,
}

impl Service {
    async fn register(node: &Node) -> Service {
        let (r, w) = UnixStream::connect(&node.register_sock)
            .await
            .unwrap()
            .into_split();
        let mut s = Service {
            r: BufReader::new(r),
            w,
        };
        let reg = s.call(json!({ "harness": "svc", "name": SVC })).await;
        assert_eq!(reg["status"], "ok", "{reg}");
        s
    }

    async fn call(&mut self, frame: Value) -> Value {
        self.w
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(20), self.r.read_line(&mut line))
            .await
            .expect("register.sock answer")
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }

    /// The next message handed to the service; its ID.
    async fn take(&mut self) -> String {
        let d = self.call(json!({ "action": "poll", "waitSecs": 10 })).await;
        assert_eq!(d["action"], "deliver", "{d}");
        d["messageId"].as_str().unwrap().to_string()
    }

    async fn ack(&mut self, id: &str) {
        let a = self.call(json!({ "action": "ack", "messageId": id })).await;
        assert_eq!(a["status"], "ok", "{a}");
    }
}

// Oracle 1. A send to a service answers `queued`; after the service's ack its record reads
// `delivered`. Mutants: `delivered` at enqueue => RED; the ack leaves the record => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_queued_until_acked() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path());
    let mut svc = Service::register(&node).await;

    let sent = node.send("one", None).await;
    assert_eq!(sent["outcome"], "queued", "the send's answer: {sent}");
    let id = sent["message_id"].as_str().unwrap();
    assert_eq!(node.outcome(id).await, "queued", "before the ack");

    assert_eq!(svc.take().await, id);
    svc.ack(id).await;
    assert_eq!(node.outcome(id).await, "delivered", "after the ack");
}

// Oracle 2. A message handed to the service but not acked never reads `delivered`, while
// the one acked before it does. Mutants: `delivered` at hand-out => RED; an ack that
// settles every message of the session => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_unacked_never_delivered() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path());
    let mut svc = Service::register(&node).await;

    let a = node.send("a", None).await;
    let b = node.send("b", None).await;
    let (a, b) = (
        a["message_id"].as_str().unwrap(),
        b["message_id"].as_str().unwrap(),
    );
    assert_eq!(svc.take().await, a);
    svc.ack(a).await;
    assert_eq!(svc.take().await, b, "b is handed out");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(node.outcome(a).await, "delivered", "a was acked");
    assert_eq!(node.outcome(b).await, "queued", "b was never acked");
}

// Oracle 3. A keyed send replayed after the service's ack answers `delivered`, with the
// same message ID. Mutant: the ack leaves the record => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_keyed_replay_after_ack() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path());
    let mut svc = Service::register(&node).await;

    let first = node.send("keyed", Some("svc-k")).await;
    assert_eq!(first["outcome"], "queued", "{first}");
    let id = first["message_id"].as_str().unwrap();
    assert_eq!(svc.take().await, id);
    svc.ack(id).await;

    let again = node.send("keyed", Some("svc-k")).await;
    assert_eq!(again["message_id"], first["message_id"], "{again}");
    assert_eq!(again["outcome"], "delivered", "the replay: {again}");
}
