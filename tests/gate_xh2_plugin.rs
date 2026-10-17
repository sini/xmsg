//! XH2 gating oracles 1-7: the server half of plugin registration (plan XH2; HA2, HA4,
//! A18, A19; harness gate v0 C1, C2, C3, P6). Every oracle runs a real `xmsg serve` and
//! speaks the plugin frames on `register.sock` from this test process, which therefore is
//! a plugin process: its own HTTP calls, and its children's, are anonymous (C2).

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
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixStream;

mod http_child;
use http_child::{FakeParent, Via};

const CHILD: &str = "http_child_entry";

/// The body of every HTTP child this binary starts.
#[test]
fn http_child_entry() {
    http_child::serve_if_child();
}

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
            if http_sock.exists() && register_sock.exists() {
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

    async fn list(&self) -> Vec<Value> {
        let (status, body) = self.http("GET", "/v1/recipients", None).await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_value(body["recipients"].clone()).unwrap()
    }

    /// An anonymous send from this test process.
    async fn send(&self, to: &str, text: &str) -> (u16, Value) {
        self.http(
            "POST",
            "/v1/messages",
            Some(json!({ "to": to, "from": "ci", "text": text })),
        )
        .await
    }

    async fn plugin(&self) -> Plugin {
        Plugin::connect(&self.register_sock).await
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
    async fn connect(sock: &PathBuf) -> Plugin {
        let stream = UnixStream::connect(sock).await.expect("register.sock");
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

    /// Sends `frame` with a fresh request id; returns the id.
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

    /// The answer to `id`, waiting up to `secs`.
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

    async fn send(&mut self, session: &str, to: &str, text: &str) -> Value {
        self.call(json!({ "action": "send", "session": session, "to": to, "text": text }))
            .await
    }

    /// The next delivery, waiting up to `secs`.
    async fn poll(&mut self, secs: u64) -> Value {
        let id = self.put(json!({ "action": "poll", "wait": secs })).await;
        self.take(&id, secs + 5).await.expect("poll answered")
    }
}

/// The address's local part: the minted ID.
fn id_of(address: &str) -> &str {
    address.split_once('@').map_or(address, |(id, _)| id)
}

// -----------------------------------------------------------------------------
// 1. Two sessions on one connection (C1's FAIL-IF)
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_1_two_sessions_one_connection() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let s2 = a.register("ses_two").await;
    assert_ne!(s1, s2, "two sessions get two addresses");
    let mut r = node.plugin().await;
    let ra = r.register("ses_recv").await;

    let sent = a.send("ses_two", &ra, "from two").await;
    assert_eq!(sent["status"], "ok", "{sent}");
    let got = r.poll(5).await;
    assert_eq!(got["action"], "deliver", "{got}");
    let from = got["from_name"].as_str().unwrap();
    assert!(
        from.ends_with(&s2) && from.starts_with("ses_two"),
        "S2's send is attributed to S2's address {s2}: {from}"
    );

    for (addr, session) in [(&s1, "ses_one"), (&s2, "ses_two")] {
        let sent = r.send("ses_recv", addr, &format!("to {session}")).await;
        assert_eq!(sent["status"], "ok", "{sent}");
        let got = a.poll(5).await;
        assert_eq!(got["action"], "deliver", "{got}");
        assert_eq!(
            got["session"], session,
            "delivered for its own session: {got}"
        );
        assert_eq!(got["text"], format!("to {session}"));
        let ack = a
            .call(json!({ "action": "ack", "session": session, "message_id": got["message_id"] }))
            .await;
        assert_eq!(ack["status"], "ok", "{ack}");
    }
}

// -----------------------------------------------------------------------------
// 2. A tool call while `poll` is pending
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_2_tool_call_while_poll_pending() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let mut r = node.plugin().await;
    let ra = r.register("ses_recv").await;

    let poll = a.put(json!({ "action": "poll", "wait": 8 })).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let send = a
        .put(json!({ "action": "send", "session": "ses_one", "to": ra, "text": "mid-poll" }))
        .await;
    let answer = a.take(&send, 3).await;
    assert!(
        answer.as_ref().is_some_and(|v| v["status"] == "ok"),
        "the send is answered with its request id while the poll is pending: {answer:?}"
    );
    assert!(
        a.answers.lock().unwrap().get(&poll).is_none(),
        "the poll is still pending"
    );

    let sent = r.send("ses_recv", &s1, "after").await;
    assert_eq!(sent["status"], "ok", "{sent}");
    let got = a.take(&poll, 5).await.expect("the poll answers");
    assert_eq!(got["action"], "deliver", "{got}");
    assert_eq!(got["text"], "after");
    assert_eq!(got["session"], "ses_one");
}

// -----------------------------------------------------------------------------
// 3. Only the holder speaks
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_3_only_the_holder_speaks() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let mut b = node.plugin().await;
    let rb = b.register("ses_b").await;

    let refused = b.send("ses_one", &rb, "impostor").await;
    assert_eq!(refused["status"], "error", "{refused}");
    assert_eq!(refused["error"], "denied", "{refused}");
    for action in ["list", "replies"] {
        let mut f = json!({ "action": action, "session": "ses_one" });
        if action == "replies" {
            f["message_id"] = json!("x");
        }
        let refused = b.call(f).await;
        assert_eq!(refused["error"], "denied", "{action}: {refused}");
    }

    let refused = b
        .call(json!({ "action": "continues", "from": "ses_one", "to": "ses_new" }))
        .await;
    assert_eq!(refused["error"], "denied", "{refused}");
    let listed = node.list().await;
    assert!(
        listed
            .iter()
            .any(|e| e["address"] == s1 && e["label"] == "ses_one"),
        "S1 keeps its address and label: {listed:?}"
    );

    let unknown = a
        .call(json!({ "action": "send", "session": "ses_one", "to": rb, "text": "x", "extra": 1 }))
        .await;
    assert_eq!(unknown["error"], "bad_request", "{unknown}");
    assert!(
        unknown["detail"].as_str().unwrap().contains("extra"),
        "{unknown}"
    );
}

/// R2: the plugin `list` answer has agent.sock's list answer shape field for field,
/// `{status, recipients, nodes}` (XA5), never the result nested under `recipients`.
#[tokio::test(flavor = "multi_thread")]
async fn r2_list_answer_shape() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;

    let answer = a
        .call(json!({ "action": "list", "session": "ses_one" }))
        .await;
    let mut keys: Vec<&str> = answer
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["nodes", "recipients", "request_id", "status"],
        "{answer}"
    );
    assert_eq!(answer["status"], "ok", "{answer}");
    let recipients = answer["recipients"].as_array().expect("an array");
    assert!(
        recipients.iter().any(|e| e["address"] == s1),
        "S1 is listed: {answer}"
    );
    let (status, http) = node.http("GET", "/v1/recipients", None).await;
    assert_eq!(status, 200, "{http}");
    assert_eq!(
        answer["recipients"], http["recipients"],
        "{answer} vs {http}"
    );
    assert_eq!(answer["nodes"], http["nodes"], "{answer} vs {http}");
}

// -----------------------------------------------------------------------------
// 4. `to` already registered (C3)
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_4_continues_onto_a_registered_to() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let s2 = a.register("ses_two").await;

    let refused = a
        .call(json!({ "action": "continues", "from": "ses_one", "to": "ses_two" }))
        .await;
    assert_eq!(refused["error"], "conflict", "{refused}");
    let listed = node.list().await;
    for (addr, label) in [(&s1, "ses_one"), (&s2, "ses_two")] {
        assert!(
            listed
                .iter()
                .any(|e| e["address"] == *addr && e["label"] == label),
            "{label} keeps {addr}: {listed:?}"
        );
    }
}

// -----------------------------------------------------------------------------
// 5. A continuation keeps the address (A19)
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_5_continuation_keeps_the_address() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let mut r = node.plugin().await;
    let ra = r.register("ses_recv").await;

    let moved = a
        .call(json!({ "action": "continues", "from": "ses_one", "to": "ses_three" }))
        .await;
    assert_eq!(moved["status"], "ok", "{moved}");
    assert_eq!(moved["address"], s1, "the address carries over");

    let sent = r.send("ses_recv", &s1, "to the old address").await;
    assert_eq!(sent["status"], "ok", "{sent}");
    let got = a.poll(5).await;
    assert_eq!(got["session"], "ses_three", "delivered for S3: {got}");

    let sent = a.send("ses_three", &ra, "from three").await;
    assert_eq!(sent["status"], "ok", "{sent}");
    let got = r.poll(5).await;
    let from = got["from_name"].as_str().unwrap();
    assert!(
        from.ends_with(&s1),
        "S3's send is attributed to {s1}: {from}"
    );

    let stale = a.send("ses_one", &ra, "x").await;
    assert_eq!(stale["error"], "denied", "S1 is no longer held: {stale}");
}

// -----------------------------------------------------------------------------
// 6. Release (C3, P6)
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_6_release_and_close() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let s2 = a.register("ses_two").await;

    let released = a
        .call(json!({ "action": "release", "session": "ses_one" }))
        .await;
    assert_eq!(released["status"], "ok", "{released}");
    let (status, body) = node.send(&s1, "after release").await;
    assert_eq!((status, &body["error"]), (410, &json!("gone")), "{body}");
    // P2: a release names no process.
    assert_eq!(
        body["detail"],
        format!("session {} is gone", id_of(&s1)),
        "the release's gone detail: {body}"
    );
    let got = a.poll(1).await;
    assert_eq!(got["action"], "timeout", "nothing is queued: {got}");
    // R3: not listed at all, so never `parked` while its address answers `gone`.
    let listed = node.list().await;
    assert!(
        !listed.iter().any(|e| e["address"] == s1),
        "S1 is no longer listed: {listed:?}"
    );

    // HA8: when the connection closes without explicit `release`, S2 is detached (not
    // listed live, parked inside reply_ttl, and queues messages for reclaim).
    drop(a);
    for _ in 0..100 {
        if !node.list().await.iter().any(|e| e["address"] == s2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (status, body) = node.send(&s2, "after close").await;
    assert_eq!(
        (status, &body["outcome"]),
        (202, &json!("queued")),
        "S2's address is detached and queues once its connection closes (HA8): {body}"
    );
}

// -----------------------------------------------------------------------------
// 7. Other callers are anonymous (C2)
// -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oracle_7_other_callers_are_anonymous() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let mut r = node.plugin().await;
    let ra = r.register("ses_recv").await;

    // A message S1 received, which the child will try to answer.
    let sent = r.send("ses_recv", &s1, "for S1").await;
    let message_id = sent["message_id"].as_str().unwrap().to_string();
    let got = a.poll(5).await;
    assert_eq!(got["message_id"], message_id.as_str(), "{got}");

    // A child of this process, which holds the plugin connections.
    let child = FakeParent::spawn(CHILD);
    let via = Via::Unix(node.http_sock.clone());
    let (status, body) = child
        .request(
            &via,
            "POST",
            "/v1/messages",
            Some(&json!({ "to": ra, "from": "ci", "text": "from a child" })),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    let got = r.poll(5).await;
    let from = got["from_name"].as_str().unwrap();
    assert!(
        !from.contains(id_of(&s1)) && from.starts_with("ci"),
        "the child's message is anonymous: {from}"
    );

    let (status, body) = child
        .request(
            &via,
            "POST",
            &format!("/v1/messages/{message_id}/replies"),
            Some(&json!({ "text": "not mine" })),
        )
        .await;
    assert_eq!(status, 403, "the child's reply is denied: {body}");
    assert!(body.contains("denied"), "{body}");
}

// -----------------------------------------------------------------------------
// XH2 gate v0 K2, P1-P3: one pending poll, the deliver address, ack by the holder,
// the plugin-process stop in the caller walk
// -----------------------------------------------------------------------------

/// K2: a second `poll` while one is pending is refused `conflict`, so one message is never
/// delivered to two polls; once the first answers, a new poll is accepted.
#[tokio::test(flavor = "multi_thread")]
async fn k2_one_pending_poll_per_connection() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let mut r = node.plugin().await;
    let _ra = r.register("ses_recv").await;

    let p1 = a.put(json!({ "action": "poll", "wait": 5 })).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let p2 = a.put(json!({ "action": "poll", "wait": 5 })).await;
    let second = a.take(&p2, 3).await;
    assert!(
        second
            .as_ref()
            .is_some_and(|v| v["error"] == "conflict" && v["request_id"] == p2.as_str()),
        "the second pending poll is refused conflict with its request id: {second:?}"
    );

    let sent = r.send("ses_recv", &s1, "one message").await;
    assert_eq!(sent["status"], "ok", "{sent}");
    let got = a.take(&p1, 7).await.expect("the first poll answers");
    assert_eq!(got["action"], "deliver", "{got}");
    // P1: the deliver frame names the address as `register` answered it.
    assert_eq!(got["address"], s1.as_str(), "{got}");

    let again = a.poll(1).await;
    assert_eq!(
        again["action"], "deliver",
        "a poll after the first answered is accepted, and the unacked message is offered again: {again}"
    );
}

/// P3 (gate O1): an `ack` acts only on a message pending for the session it names, so a
/// session on another connection cannot settle it.
#[tokio::test(flavor = "multi_thread")]
async fn p3_ack_is_the_holding_sessions() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let s1 = a.register("ses_one").await;
    let mut r = node.plugin().await;
    let _ra = r.register("ses_recv").await;
    let sent = r.send("ses_recv", &s1, "for a").await;
    assert_eq!(sent["status"], "ok", "{sent}");
    let got = a.poll(5).await;
    assert_eq!(got["action"], "deliver", "{got}");
    let mid = got["message_id"].clone();

    let foreign = r
        .call(json!({ "action": "ack", "session": "ses_recv", "message_id": mid }))
        .await;
    assert_eq!(foreign["error"], "not_found", "{foreign}");
    let again = a.poll(2).await;
    assert_eq!(
        (&again["action"], &again["message_id"]),
        (&json!("deliver"), &mid),
        "the message is still pending for its holder: {again}"
    );
}

/// P3 (gate O5): the caller walk stops at a plugin process. This test process holds the
/// plugin connection and is also named by a Claude session file, so without the stop its
/// child's send would be attributed to that Claude session; with it, the child is
/// anonymous (HA2, harness gate v0 C2).
#[tokio::test(flavor = "multi_thread")]
async fn p3_walk_stops_at_the_plugin_process() {
    let node = Node::start();
    let mut a = node.plugin().await;
    let _s1 = a.register("ses_one").await;
    let mut r = node.plugin().await;
    let ra = r.register("ses_recv").await;

    let me = std::process::id();
    let start = xmsg::process::starttime(std::path::Path::new(xmsg::process::LIVE_PROC_ROOT), me)
        .expect("live start time");
    let claude_id = "walk-claude-ancestor";
    let sessions = node
        .http_sock
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("sessions");
    fs::write(
        sessions.join(format!("{me}.json")),
        json!({
            "pid": me,
            "sessionId": claude_id,
            "name": claude_id,
            "cwd": "/w",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1,
            "updatedAt": 2,
            "procStart": start,
            "messagingSocketPath": sessions.join("inbox.sock").display().to_string(),
        })
        .to_string(),
    )
    .unwrap();
    let listed = node.list().await;
    assert!(
        listed
            .iter()
            .any(|e| id_of(e["address"].as_str().unwrap_or("")) == claude_id),
        "the Claude session file is read (live control): {listed:?}"
    );

    let child = FakeParent::spawn(CHILD);
    let via = Via::Unix(node.http_sock.clone());
    let (status, body) = child
        .request(
            &via,
            "POST",
            "/v1/messages",
            Some(&json!({ "to": ra, "from": "ci", "text": "from a child" })),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    let got = r.poll(5).await;
    let from = got["from_name"].as_str().unwrap();
    assert!(
        !from.contains(claude_id) && from.starts_with("ci"),
        "the child of the plugin process is anonymous: {from}"
    );
}
