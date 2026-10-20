//! XF6: Per-connection `in_flight` tracking on `register.sock` for `svc` consumers.
//!
//! Oracles:
//! - (a) A second `poll` on the same `register.sock` connection while `msg_1` is unacked
//!   delivers `msg_2` instead of redelivering `msg_1` (and a waiting `poll` wakes for `msg_3`
//!   while `msg_1` and `msg_2` remain unacked). Mutant: ignore `in_flight` => `msg_1` is
//!   redelivered on the second `poll` => RED.
//! - (b) Dropping the `register.sock` connection without acking `msg_1` releases `in_flight`
//!   and redelivers `msg_1` on reconnect (while any message acked before the drop is not
//!   redelivered).
//! - (c) A serial `poll -> ack -> poll` consumer behaves identically to before XF6.

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

const SVC: &str = "xf6-svc";

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
            if http_sock.exists() && register_sock.exists() {
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

    async fn send(&self, text: &str) -> String {
        let body = json!({ "to": SVC, "from": "ci", "text": text });
        let (status, resp_text) = http_child::request_detached(
            "http_child_entry",
            &Via::Unix(self.http_sock.clone()),
            "POST",
            "/v1/messages",
            Some(&body),
        )
        .await;
        assert!(
            status == 200 || status == 202,
            "send: {status} {resp_text}"
        );
        let val: Value = serde_json::from_str(&resp_text).unwrap();
        val["message_id"].as_str().unwrap().to_string()
    }

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

    async fn poll(&mut self, wait_secs: u64) -> Value {
        self.call(json!({ "action": "poll", "waitSecs": wait_secs }))
            .await
    }

    async fn ack(&mut self, id: &str) {
        let a = self.call(json!({ "action": "ack", "messageId": id })).await;
        assert_eq!(a["status"], "ok", "{a}");
    }
}

// Oracle (a): A second `poll` on the same connection while `msg_1` is unacked delivers `msg_2`
// instead of redelivering `msg_1`, and a subsequent long-poll (`waitSecs > 0`) delivers `msg_3`
// when it arrives while `msg_1` and `msg_2` are still unacked.
// Mutant: ignore `in_flight` => second `poll` redelivers `msg_1` => RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_a_second_poll_while_msg1_unacked_delivers_msg2() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path());
    let mut svc = Service::register(&node).await;

    let msg_1 = node.send("context-request").await;
    let msg_2 = node.send("guard-verdict").await;

    // Poll 1: receives msg_1; do NOT ack msg_1 yet.
    let d1 = svc.poll(5).await;
    assert_eq!(d1["action"], "deliver", "{d1}");
    assert_eq!(d1["messageId"].as_str(), Some(msg_1.as_str()));
    assert_eq!(d1["text"].as_str(), Some("context-request"));

    // Poll 2 (while msg_1 is unacked): MUST deliver msg_2, NOT msg_1!
    let d2 = svc.poll(5).await;
    assert_eq!(d2["action"], "deliver", "{d2}");
    assert_eq!(
        d2["messageId"].as_str(),
        Some(msg_2.as_str()),
        "second poll while msg_1 is unacked must deliver msg_2, not redeliver msg_1"
    );
    assert_eq!(d2["text"].as_str(), Some("guard-verdict"));

    // Poll 3 with waitSecs=0 while both msg_1 and msg_2 are in-flight: must timeout, not spin.
    let d3_empty = svc.poll(0).await;
    assert_eq!(
        d3_empty["action"], "timeout",
        "poll with all pending messages in_flight must timeout: {d3_empty}"
    );

    // Also verify the wait branch in Poll: while msg_1 and msg_2 remain unacked, a new msg_3
    // arriving wakes a waiting poll(5) and delivers msg_3.
    let (msg_3, d3) = tokio::join!(
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            node.send("late-verdict").await
        },
        svc.poll(5)
    );
    assert_eq!(d3["action"], "deliver", "{d3}");
    assert_eq!(d3["messageId"].as_str(), Some(msg_3.as_str()));

    // Outcomes remain `queued` until each is explicitly acked.
    assert_eq!(node.outcome(&msg_1).await, "queued");
    assert_eq!(node.outcome(&msg_2).await, "queued");
    assert_eq!(node.outcome(&msg_3).await, "queued");

    svc.ack(&msg_2).await;
    svc.ack(&msg_1).await;
    svc.ack(&msg_3).await;

    assert_eq!(node.outcome(&msg_1).await, "delivered");
    assert_eq!(node.outcome(&msg_2).await, "delivered");
    assert_eq!(node.outcome(&msg_3).await, "delivered");
}

// Oracle (b): Dropping the connection without acking redelivers unacked messages on reconnect,
// while messages acked before the drop are not redelivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_b_drop_without_ack_redelivers_on_reconnect() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path());
    let mut svc1 = Service::register(&node).await;

    let msg_1 = node.send("in-flight-request").await;
    let msg_2 = node.send("fast-verdict").await;

    let d1 = svc1.poll(5).await;
    assert_eq!(d1["messageId"].as_str(), Some(msg_1.as_str()));

    let d2 = svc1.poll(5).await;
    assert_eq!(d2["messageId"].as_str(), Some(msg_2.as_str()));

    // Ack msg_2 (e.g., verdict routed and acked), but drop connection before msg_1 finishes.
    svc1.ack(&msg_2).await;
    drop(svc1);

    // Wait briefly for server to observe EOF on first connection and clear registration.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut svc2 = Service::register(&node).await;
    let redelivered = svc2.poll(5).await;
    assert_eq!(redelivered["action"], "deliver", "{redelivered}");
    assert_eq!(
        redelivered["messageId"].as_str(),
        Some(msg_1.as_str()),
        "unacked msg_1 must be redelivered after connection drop"
    );

    // Next poll must timeout because msg_2 was already acked before the drop.
    let next = svc2.poll(0).await;
    assert_eq!(
        next["action"], "timeout",
        "already-acked msg_2 must not be redelivered: {next}"
    );

    svc2.ack(&msg_1).await;
    assert_eq!(node.outcome(&msg_1).await, "delivered");
}

// Oracle (c): A serial `poll -> ack -> poll` consumer behaves identically to today.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_c_serial_poll_ack_poll_unchanged() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path());
    let mut svc = Service::register(&node).await;

    let mut sent_ids = Vec::new();
    for i in 1..=3 {
        sent_ids.push(node.send(&format!("serial-{i}")).await);
    }

    for (i, expected_id) in sent_ids.iter().enumerate() {
        let d = svc.poll(5).await;
        assert_eq!(d["action"], "deliver", "{d}");
        assert_eq!(d["messageId"].as_str(), Some(expected_id.as_str()));
        assert_eq!(
            d["text"].as_str(),
            Some(format!("serial-{}", i + 1).as_str())
        );
        assert_eq!(node.outcome(expected_id).await, "queued");
        svc.ack(expected_id).await;
        assert_eq!(node.outcome(expected_id).await, "delivered");
    }

    let empty = svc.poll(0).await;
    assert_eq!(empty["action"], "timeout", "{empty}");
}
