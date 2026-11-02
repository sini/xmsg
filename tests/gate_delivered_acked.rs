//! A plugin or pi session's message is `delivered` only once its harness acks it (HA3, A13);
//! until then it is `queued` (xh3-verify-v0 C3). And one session's undeliverable head does
//! not hold back the other sessions of its connection (the head-of-line residue).
//!
//! Every cell runs a real `xmsg serve` and speaks the plugin or pi frames on its
//! `register.sock` from this test process.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

struct Node {
    _tmp: TempDir,
    http_sock: PathBuf,
    register_sock: PathBuf,
    child: Child,
}

impl Node {
    fn start() -> Node {
        let tmp = tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let run = tmp.path().join("run");
        let sessions = tmp.path().join("sessions");
        for d in [&run, &sessions] {
            fs::create_dir_all(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let http_sock = run.join("http.sock");
        let register_sock = run.join("register.sock");
        let mut child = Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .env("XDG_RUNTIME_DIR", &run)
            .env("HOME", tmp.path())
            .env_remove("XMSG_HOST_LABEL")
            .arg("serve")
            .arg("--db-path")
            .arg(tmp.path().join("xmsg.db"))
            .arg("--sessions-dir")
            .arg(&sessions)
            .arg("--http-sock")
            .arg(&http_sock)
            .arg("--agent-sock")
            .arg(run.join("agent.sock"))
            .arg("--register-sock")
            .arg(&register_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn xmsg serve");
        for _ in 0..1200 {
            if std::os::unix::net::UnixStream::connect(&http_sock).is_ok() && std::os::unix::net::UnixStream::connect(&register_sock).is_ok() {
                return Node {
                    _tmp: tmp,
                    http_sock,
                    register_sock,
                    child,
                };
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("xmsg serve never served");
    }

    async fn http(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let sock = self.http_sock.clone();
        let (method, path) = (method.to_string(), path.to_string());
        let body = body.map(|b| b.to_string());
        let (status, text) = tokio::task::spawn_blocking(move || {
            xmsg::http::http_request_unix(&sock, &method, &path, body.as_deref())
        })
        .await
        .unwrap()
        .expect("http.sock request");
        (
            status.as_u16(),
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    /// A send from this test process, keyed when `key` is given; its answer.
    async fn send(&self, to: &str, text: &str, key: Option<&str>) -> Value {
        let mut body = json!({ "to": to, "from": "ci", "text": text });
        if let Some(k) = key {
            body["idempotency_key"] = json!(k);
        }
        let (status, v) = self.http("POST", "/v1/messages", Some(body)).await;
        assert!(status == 200 || status == 202, "send: {status} {v}");
        v
    }

    /// The outcome `GET /v1/messages/{id}` reads.
    async fn outcome(&self, id: &str) -> String {
        let (status, v) = self.http("GET", &format!("/v1/messages/{id}"), None).await;
        assert_eq!(status, 200, "{v}");
        v["outcome"].as_str().unwrap().to_string()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A plugin connection: every answer is filed under its request id.
struct Plugin {
    writer: OwnedWriteHalf,
    answers: Arc<Mutex<HashMap<String, Value>>>,
    next: u64,
}

impl Plugin {
    async fn connect(node: &Node) -> Plugin {
        let stream = UnixStream::connect(&node.register_sock).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        writer
            .write_all(b"{\"harness\":\"opencode\"}\n")
            .await
            .unwrap();
        let hello: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(hello["status"], "ok", "{hello}");
        let answers = Arc::new(Mutex::new(HashMap::new()));
        let filed = answers.clone();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let v: Value = serde_json::from_str(&line).unwrap();
                let id = v["request_id"].as_str().unwrap_or("").to_string();
                filed.lock().unwrap().insert(id, v);
            }
        });
        Plugin {
            writer,
            answers,
            next: 0,
        }
    }

    async fn put(&mut self, mut frame: Value) -> String {
        self.next += 1;
        let id = format!("r{}", self.next);
        frame["request_id"] = json!(id);
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        id
    }

    async fn take(&self, id: &str, secs: u64) -> Option<Value> {
        for _ in 0..secs * 50 {
            if let Some(v) = self.answers.lock().unwrap().remove(id) {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }

    async fn call(&mut self, frame: Value) -> Value {
        let id = self.put(frame).await;
        self.take(&id, 10).await.expect("an answer within 10 s")
    }

    async fn register(&mut self, session: &str) -> String {
        let a = self
            .call(json!({ "action": "register", "session": session }))
            .await;
        assert_eq!(a["status"], "ok", "register {session}: {a}");
        a["address"].as_str().unwrap().to_string()
    }

    async fn poll(&mut self, secs: u64) -> Value {
        let id = self.put(json!({ "action": "poll", "wait": secs })).await;
        self.take(&id, secs + 5).await.expect("poll answered")
    }

    async fn ack(&mut self, session: &str, message_id: &Value) {
        let a = self
            .call(json!({ "action": "ack", "session": session, "message_id": message_id }))
            .await;
        assert_eq!(a["status"], "ok", "{a}");
    }
}

/// A pi registration on `register.sock`: this test process is the pi process.
struct Pi {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    id: String,
}

impl Pi {
    async fn register(node: &Node) -> Pi {
        let stream = UnixStream::connect(&node.register_sock).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        writer
            .write_all(b"{\"harness\":\"pi\",\"sessionName\":\"pi-acked\",\"cwd\":\"/\"}\n")
            .await
            .unwrap();
        let ok = read_line(&mut reader).await;
        assert_eq!(ok["status"], "ok", "{ok}");
        let id = ok["sessionId"].as_str().unwrap().to_string();
        Pi { reader, writer, id }
    }

    async fn frame(&mut self, v: Value) -> Value {
        self.writer
            .write_all(format!("{v}\n").as_bytes())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), read_line(&mut self.reader))
            .await
            .expect("pi frame answered")
    }
}

async fn read_line(r: &mut BufReader<OwnedReadHalf>) -> Value {
    let mut line = String::new();
    r.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap_or_else(|_| panic!("json line: {line:?}"))
}

// -----------------------------------------------------------------------------
// 1. A plugin session's message is `queued` until the plugin acks it
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_1_plugin_queued_until_acked() {
    let node = Node::start();
    let mut p = Plugin::connect(&node).await;
    let addr = p.register("ses_one").await;

    let sent = node.send(&addr, "hello plugin", None).await;
    assert_eq!(sent["outcome"], "queued", "answered before the ack: {sent}");
    let id = sent["message_id"].as_str().unwrap();
    assert_eq!(node.outcome(id).await, "queued", "recorded before the ack");

    let got = p.poll(5).await;
    assert_eq!(got["action"], "deliver", "{got}");
    assert_eq!(got["message_id"], id);
    assert_eq!(node.outcome(id).await, "queued", "a delivery not yet acked");
    p.ack("ses_one", &got["message_id"]).await;
    assert_eq!(node.outcome(id).await, "delivered", "after the ack");
}

// -----------------------------------------------------------------------------
// 2. The same for a pi session
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_2_pi_queued_until_acked() {
    let node = Node::start();
    let mut pi = Pi::register(&node).await;

    let sent = node.send(&pi.id, "hello pi", None).await;
    assert_eq!(sent["outcome"], "queued", "answered before the ack: {sent}");
    let id = sent["message_id"].as_str().unwrap().to_string();
    assert_eq!(node.outcome(&id).await, "queued", "recorded before the ack");

    let got = pi.frame(json!({ "action": "poll", "waitSecs": 5 })).await;
    assert_eq!(got["action"], "deliver", "{got}");
    assert_eq!(got["messageId"], id.as_str());
    assert_eq!(
        node.outcome(&id).await,
        "queued",
        "a delivery not yet acked"
    );
    let ack = pi.frame(json!({ "action": "ack", "messageId": id })).await;
    assert_eq!(ack["status"], "ok", "{ack}");
    assert_eq!(node.outcome(&id).await, "delivered", "after the ack");
}

// -----------------------------------------------------------------------------
// 3. A message to an address released before its ack never reads `delivered`
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_3_released_address_never_delivered() {
    let node = Node::start();
    let mut p = Plugin::connect(&node).await;
    let addr = p.register("ses_gone").await;

    let sent = node.send(&addr, "never taken", None).await;
    let id = sent["message_id"].as_str().unwrap().to_string();
    let rel = p
        .call(json!({ "action": "release", "session": "ses_gone" }))
        .await;
    assert_eq!(rel["status"], "ok", "{rel}");
    let got = p.poll(1).await;
    assert_eq!(got["action"], "timeout", "nothing is delivered: {got}");
    assert_eq!(sent["outcome"], "queued", "{sent}");
    assert_eq!(node.outcome(&id).await, "queued", "never `delivered`");
}

// -----------------------------------------------------------------------------
// 4. One session's refused head does not hold back another session's message
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_4_refused_head_does_not_block_another_session() {
    let node = Node::start();
    let mut p = Plugin::connect(&node).await;
    let a = p.register("ses_a").await;
    let b = p.register("ses_b").await;

    let to_a = node.send(&a, "for a, refused", None).await;
    let to_b = node.send(&b, "for b", None).await;

    // The plugin refuses A's message every time (never acks it) and polls again.
    let mut b_got = None;
    for _ in 0..4 {
        let got = p.poll(2).await;
        assert_eq!(got["action"], "deliver", "{got}");
        if got["session"] == "ses_b" {
            b_got = Some(got);
            break;
        }
        assert_eq!(got["message_id"], to_a["message_id"], "{got}");
    }
    let got = b_got.expect("session B's message arrives while A's head is refused");
    assert_eq!(got["message_id"], to_b["message_id"], "{got}");
    p.ack("ses_b", &got["message_id"]).await;

    // A's head is still offered, and once acked it is delivered.
    let again = p.poll(2).await;
    assert_eq!(again["message_id"], to_a["message_id"], "{again}");
    p.ack("ses_a", &again["message_id"]).await;
    assert_eq!(
        node.outcome(to_a["message_id"].as_str().unwrap()).await,
        "delivered"
    );
}

// -----------------------------------------------------------------------------
// 5. A keyed send replayed after the ack reads `delivered`
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_5_keyed_replay_after_ack_reads_delivered() {
    let node = Node::start();
    let mut p = Plugin::connect(&node).await;
    let addr = p.register("ses_key").await;

    let first = node.send(&addr, "keyed", Some("k-acked")).await;
    assert_eq!(first["outcome"], "queued", "{first}");
    let replay = node.send(&addr, "keyed", Some("k-acked")).await;
    assert_eq!(replay["message_id"], first["message_id"], "{replay}");
    assert_eq!(replay["outcome"], "queued", "before the ack: {replay}");

    let got = p.poll(5).await;
    assert_eq!(got["message_id"], first["message_id"], "{got}");
    p.ack("ses_key", &got["message_id"]).await;

    let replay = node.send(&addr, "keyed", Some("k-acked")).await;
    assert_eq!(replay["message_id"], first["message_id"], "{replay}");
    assert_eq!(replay["outcome"], "delivered", "after the ack: {replay}");
    let none = p.poll(1).await;
    assert_eq!(
        none["action"], "timeout",
        "the replay delivers nothing: {none}"
    );
}
