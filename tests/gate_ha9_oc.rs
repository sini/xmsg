//! HA9-A.oc — Delegated Sub-Addresses for opencode Subagents (Plane i: `register.sock` Oracles).
//!
//! Covers §3a plane (i) gating cells:
//! - C2 (`c2_server_honours_only_bound_id`): `send`, `reply` and `inbox`, each with `as_agent` =
//!   an id with no row under P, are refused `denied` (`AppError::NotRecipient`). So is an id bound
//!   under a session Q held by another connection. A bound id is accepted, and the sender is `<P>/<id>`.
//! - C7 (`c7_turn_state_resets_at_register`): A `start` for `(P, c)`, then the connection closes,
//!   then a new connection reclaims P. A send to `<P>/c` now falls back to P's pending queue.
//! - C10 (`c10_reply_to_child_in_turn_and_fallback`): A recipient's `reply` to a child's message
//!   reaches the child's `inbox` while the child is in a turn. After `stop`, it reaches P's
//!   pending queue with the `to=` header.
//! - C11 (`c11_subagent_frame_is_opencode_only`): On a `{"harness":"hermes"}` connection `subagent`
//!   is refused `bad_request`; on `opencode` it is accepted.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

fn node_name() -> String {
    xmsg::node::local_node_name()
}

struct Node {
    _tmp: TempDir,
    child: Child,
    http_sock: PathBuf,
    register_sock: PathBuf,
}

impl Node {
    fn start() -> Node {
        let tmp = tempdir().unwrap();
        let run = tmp.path().join("xmsg");
        let sessions = tmp.path().join("sessions");
        fs::create_dir_all(&run).unwrap();
        fs::create_dir_all(&sessions).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let db_path = tmp.path().join("xmsg.db");
        let http_sock = run.join("http.sock");
        let register_sock = run.join("register.sock");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        cmd.env("XDG_RUNTIME_DIR", &run)
            .env("HOME", &run)
            .env_remove("XMSG_HOST_LABEL")
            .arg("serve")
            .arg("--db-path")
            .arg(&db_path)
            .arg("--sessions-dir")
            .arg(&sessions)
            .arg("--http-sock")
            .arg(&http_sock)
            .arg("--agent-sock")
            .arg(run.join("agent.sock"))
            .arg("--register-sock")
            .arg(&register_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn xmsg serve");
        for _ in 0..600 {
            if let Ok(Some(_)) = child.try_wait() {
                panic!("xmsg serve exited early");
            }
            if http_sock.exists() && register_sock.exists() {
                return Node {
                    _tmp: tmp,
                    child,
                    http_sock,
                    register_sock,
                };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("xmsg serve did not bind sockets in time");
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

    async fn send(&self, to: &str, text: &str) -> (u16, Value) {
        self.http(
            "POST",
            "/v1/messages",
            Some(&json!({ "to": to, "from": "ci-sender", "text": text })),
        )
        .await
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
        assert_eq!(hello["status"], "ok", "plugin hello: {hello}");
        conn
    }

    async fn call(&mut self, mut frame: Value) -> Value {
        self.next += 1;
        let rid = format!("r{}", self.next);
        frame
            .as_object_mut()
            .unwrap()
            .insert("request_id".to_string(), Value::String(rid.clone()));
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
            .await
            .expect("register.sock plugin answer")
            .unwrap();
        let ans: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ans["request_id"], rid, "mismatched request_id: {ans}");
        ans
    }

    async fn register(&mut self, session: &str) -> (String, String, String) {
        let ans = self
            .call(json!({ "action": "register", "session": session }))
            .await;
        assert_eq!(ans["status"], "ok", "register {session}: {ans}");
        let address = ans["address"].as_str().unwrap().to_string();
        let bare = address.split('@').next().unwrap().to_string();
        let secret = ans["reclaim"].as_str().unwrap().to_string();
        (address, bare, secret)
    }
}

/// C2: The server honours only a bound id (`send`, `reply` and `inbox` with unbound `as_agent`
/// or an id bound under Q held by another connection are refused `denied` / `AppError::NotRecipient`;
/// a bound id is accepted and attributes to `<P>/<id>`; `list` and `replies` accept and ignore `as_agent`).
#[tokio::test]
async fn c2_server_honours_only_bound_id() {
    let node = Node::start();
    let mut conn_p = PluginConn::open(&node.register_sock, "opencode").await;
    let (_p_addr, p_bare, _p_sec) = conn_p.register("ses_root_p").await;

    let mut conn_q = PluginConn::open(&node.register_sock, "opencode").await;
    let (q_addr, _q_bare, _q_sec) = conn_q.register("ses_root_q").await;

    // Seed a message to P so we have a valid message_id to test `reply` against.
    let seed = conn_q
        .call(json!({
            "action": "send",
            "session": "ses_root_q",
            "to": &p_bare,
            "text": "seed to P"
        }))
        .await;
    assert_eq!(seed["status"], "ok", "{seed}");
    let seed_msg_id = seed["message_id"].as_str().unwrap().to_string();

    // 1. Unbound `as_agent` under P is refused `denied` on `send`, `reply` and `inbox`.
    let bad_send = conn_p
        .call(json!({
            "action": "send",
            "session": "ses_root_p",
            "as_agent": "ses_unbound",
            "to": &q_addr,
            "text": "forged send"
        }))
        .await;
    assert_eq!(bad_send["status"], "error", "{bad_send}");
    assert_eq!(bad_send["error"], "denied", "{bad_send}");
    assert!(
        bad_send["detail"]
            .as_str()
            .unwrap_or("")
            .contains("is not bound under"),
        "{bad_send}"
    );

    let bad_reply = conn_p
        .call(json!({
            "action": "reply",
            "session": "ses_root_p",
            "as_agent": "ses_unbound",
            "message_id": &seed_msg_id,
            "text": "forged reply"
        }))
        .await;
    assert_eq!(bad_reply["status"], "error", "{bad_reply}");
    assert_eq!(bad_reply["error"], "denied", "{bad_reply}");
    assert!(
        bad_reply["detail"]
            .as_str()
            .unwrap_or("")
            .contains("is not bound under"),
        "{bad_reply}"
    );

    let bad_inbox = conn_p
        .call(json!({
            "action": "inbox",
            "session": "ses_root_p",
            "as_agent": "ses_unbound",
            "wait": 0
        }))
        .await;
    assert_eq!(bad_inbox["status"], "error", "{bad_inbox}");
    assert_eq!(bad_inbox["error"], "denied", "{bad_inbox}");
    assert!(
        bad_inbox["detail"]
            .as_str()
            .unwrap_or("")
            .contains("is not bound under"),
        "{bad_inbox}"
    );

    // 2. Bind `ses_child_q` under Q on `conn_q`; P on `conn_p` trying to act as `ses_child_q` is refused `denied`.
    let bind_q = conn_q
        .call(json!({
            "action": "subagent",
            "event": "start",
            "session": "ses_root_q",
            "agent_id": "ses_child_q",
            "agent_type": "general"
        }))
        .await;
    assert_eq!(bind_q["status"], "ok", "{bind_q}");

    for frame in [
        json!({
            "action": "send",
            "session": "ses_root_p",
            "as_agent": "ses_child_q",
            "to": &q_addr,
            "text": "cross-parent send"
        }),
        json!({
            "action": "reply",
            "session": "ses_root_p",
            "as_agent": "ses_child_q",
            "message_id": &seed_msg_id,
            "text": "cross-parent reply"
        }),
        json!({
            "action": "inbox",
            "session": "ses_root_p",
            "as_agent": "ses_child_q",
            "wait": 0
        }),
    ] {
        let ans = conn_p.call(frame).await;
        assert_eq!(ans["status"], "error", "{ans}");
        assert_eq!(ans["error"], "denied", "{ans}");
        assert!(
            ans["detail"]
                .as_str()
                .unwrap_or("")
                .contains("is not bound under"),
            "{ans}"
        );
    }

    // 3. Bind `ses_child_p` under P; `send`, `reply` and `inbox` with `as_agent: "ses_child_p"` succeed,
    //    and the sender is `<P>/ses_child_p@<node>` with label `general`.
    let bind_p = conn_p
        .call(json!({
            "action": "subagent",
            "event": "start",
            "session": "ses_root_p",
            "agent_id": "ses_child_p",
            "agent_type": "general"
        }))
        .await;
    assert_eq!(bind_p["status"], "ok", "{bind_p}");

    let ok_send = conn_p
        .call(json!({
            "action": "send",
            "session": "ses_root_p",
            "as_agent": "ses_child_p",
            "to": &q_addr,
            "text": "hello from bound child"
        }))
        .await;
    assert_eq!(ok_send["status"], "ok", "{ok_send}");
    let sent_msg_id = ok_send["message_id"].as_str().unwrap().to_string();

    // Verify Q receives the message attributed to `general · <P>/ses_child_p@<node>`.
    // Drain Q's poll (first message is nothing since Q sent to P; wait for child's message).
    let deliv = conn_q.call(json!({ "action": "poll", "wait": 5 })).await;
    assert_eq!(deliv["action"], "deliver", "{deliv}");
    assert_eq!(
        deliv["from_name"],
        format!("general · {p_bare}/ses_child_p@{}", node_name()),
        "{deliv}"
    );
    conn_q
        .call(json!({
            "action": "ack",
            "session": "ses_root_q",
            "message_id": deliv["message_id"]
        }))
        .await;

    // `reply` from `ses_child_p` on its own message succeeds; `reply` on P's message (`seed_msg_id`) is refused `denied` (§2.5 P3).
    let child_reply_to_p_msg = conn_p
        .call(json!({
            "action": "reply",
            "session": "ses_root_p",
            "as_agent": "ses_child_p",
            "message_id": &seed_msg_id,
            "text": "child trying to reply to parent message"
        }))
        .await;
    assert_eq!(
        child_reply_to_p_msg["status"], "error",
        "{child_reply_to_p_msg}"
    );
    assert_eq!(
        child_reply_to_p_msg["error"], "denied",
        "{child_reply_to_p_msg}"
    );

    let ok_reply = conn_p
        .call(json!({
            "action": "reply",
            "session": "ses_root_p",
            "as_agent": "ses_child_p",
            "message_id": &sent_msg_id,
            "text": "child follow-up reply"
        }))
        .await;
    assert_eq!(ok_reply["status"], "ok", "{ok_reply}");
    assert_eq!(
        ok_reply["reply"]["replierSessionId"],
        format!("{p_bare}/ses_child_p"),
        "{ok_reply}"
    );

    let ok_inbox = conn_p
        .call(json!({
            "action": "inbox",
            "session": "ses_root_p",
            "as_agent": "ses_child_p",
            "wait": 0
        }))
        .await;
    assert_eq!(ok_inbox["status"], "ok", "{ok_inbox}");
    assert_eq!(
        ok_inbox["address"],
        format!("{p_bare}/ses_child_p@{}", node_name())
    );

    // `list` and `replies` accept `as_agent` (even unbound or empty) and ignore it (§2.1).
    let ok_list = conn_p
        .call(json!({
            "action": "list",
            "session": "ses_root_p",
            "as_agent": "ses_unbound"
        }))
        .await;
    assert_eq!(ok_list["status"], "ok", "{ok_list}");

    let ok_replies = conn_p
        .call(json!({
            "action": "replies",
            "session": "ses_root_p",
            "as_agent": "",
            "message_id": &sent_msg_id,
            "wait": 0
        }))
        .await;
    assert_eq!(ok_replies["status"], "ok", "{ok_replies}");
}

/// C7: Turn state resets at `register`. A `start` for `(P, c)`, then the connection closes,
/// then a new connection reclaims P. A send to `<P>/c` now falls back to P's pending queue.
#[tokio::test]
async fn c7_turn_state_resets_at_register() {
    let node = Node::start();
    let (p_bare, p_secret) = {
        let mut conn1 = PluginConn::open(&node.register_sock, "opencode").await;
        let (_p_addr, p_bare, p_sec) = conn1.register("ses_root").await;
        let start = conn1
            .call(json!({
                "action": "subagent",
                "event": "start",
                "session": "ses_root",
                "agent_id": "ses_child_c7",
                "agent_type": "general"
            }))
            .await;
        assert_eq!(start["status"], "ok", "{start}");
        (p_bare, p_sec)
        // `conn1` drops here, detaching `ses_root` without sending `stop` while this test process
        // (`peer_pid`) remains alive!
    };

    // Wait briefly for server's `Closing` drop to detach `ses_root`, then reclaim P on `conn2`.
    let mut conn2 = PluginConn::open(&node.register_sock, "opencode").await;
    let mut reclaimed = false;
    for _ in 0..50 {
        let ans = conn2
            .call(json!({
                "action": "register",
                "session": "ses_root",
                "reclaim": { "id": &p_bare, "secret": &p_secret }
            }))
            .await;
        if ans["status"] == "ok" {
            reclaimed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(reclaimed, "reclaim of {p_bare} should succeed");

    // Now send to `<P>/ses_child_c7`: because `register` cleared the turn columns under P,
    // the message must NOT strand in `instance_queue` — it must fall back to P's pending queue!
    let sub_target = format!("{p_bare}/ses_child_c7");
    let (status, send_body) = node.send(&sub_target, "after-reclaim-fallback").await;
    assert_eq!(status, 202, "{send_body}");

    let deliv = conn2.call(json!({ "action": "poll", "wait": 2 })).await;
    assert_eq!(
        deliv["action"], "deliver",
        "expected fallback delivery to P, got: {deliv}"
    );
    assert_eq!(deliv["session"], "ses_root");
    let env_text = deliv["envelope"].as_str().unwrap_or("");
    let expected_hdr = format!("to={p_bare}/ses_child_c7 agent_id=ses_child_c7");
    assert!(
        env_text.contains(&expected_hdr) && env_text.contains("after-reclaim-fallback"),
        "expected header '{expected_hdr}' in envelope: {env_text}"
    );
}

/// C10: Reply to a child. A recipient's `reply` to a child's message reaches the child's
/// `inbox` while the child is in a turn. After `stop`, it reaches P's pending queue with
/// the `to=` header.
#[tokio::test]
async fn c10_reply_to_child_in_turn_and_fallback() {
    let node = Node::start();
    let mut conn_p = PluginConn::open(&node.register_sock, "opencode").await;
    let (_p_addr, p_bare, _p_sec) = conn_p.register("ses_root").await;

    let mut conn_r = PluginConn::open(&node.register_sock, "opencode").await;
    let (r_addr, _r_bare, _r_sec) = conn_r.register("ses_recip").await;

    // Start turn for `ses_child_c10` under P and send a message to R.
    let start = conn_p
        .call(json!({
            "action": "subagent",
            "event": "start",
            "session": "ses_root",
            "agent_id": "ses_child_c10",
            "agent_type": "general"
        }))
        .await;
    assert_eq!(start["status"], "ok", "{start}");

    let sent = conn_p
        .call(json!({
            "action": "send",
            "session": "ses_root",
            "as_agent": "ses_child_c10",
            "to": &r_addr,
            "text": "question from child"
        }))
        .await;
    assert_eq!(sent["status"], "ok", "{sent}");
    let msg_id = sent["message_id"].as_str().unwrap().to_string();

    // 1. While `ses_child_c10` is in a turn, R's `reply` reaches the child's `inbox`.
    let rep1 = conn_r
        .call(json!({
            "action": "reply",
            "session": "ses_recip",
            "message_id": &msg_id,
            "text": "in-turn reply body"
        }))
        .await;
    assert_eq!(rep1["status"], "ok", "{rep1}");
    assert_eq!(rep1["reply"]["pushOutcome"], "pushed", "{rep1}");

    let inbox = conn_p
        .call(json!({
            "action": "inbox",
            "session": "ses_root",
            "as_agent": "ses_child_c10",
            "wait": 1
        }))
        .await;
    assert_eq!(inbox["status"], "ok", "{inbox}");
    let msgs = inbox["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1, "{inbox}");
    assert!(
        msgs[0]["body"]
            .as_str()
            .unwrap_or("")
            .contains("in-turn reply body"),
        "{inbox}"
    );

    // 2. After `stop`, R's `reply` reaches P's pending queue with the `to=` header.
    let stop = conn_p
        .call(json!({
            "action": "subagent",
            "event": "stop",
            "session": "ses_root",
            "agent_id": "ses_child_c10"
        }))
        .await;
    assert_eq!(stop["status"], "ok", "{stop}");

    let rep2 = conn_r
        .call(json!({
            "action": "reply",
            "session": "ses_recip",
            "message_id": &msg_id,
            "text": "post-stop reply body"
        }))
        .await;
    assert_eq!(rep2["status"], "ok", "{rep2}");
    assert_eq!(rep2["reply"]["pushOutcome"], "pushed", "{rep2}");

    let deliv = conn_p.call(json!({ "action": "poll", "wait": 2 })).await;
    assert_eq!(deliv["action"], "deliver", "{deliv}");
    assert_eq!(deliv["session"], "ses_root");
    let env_text = deliv["envelope"].as_str().unwrap_or("");
    let expected_hdr = format!("to={p_bare}/ses_child_c10 agent_id=ses_child_c10");
    assert!(
        env_text.contains(&expected_hdr) && env_text.contains("post-stop reply body"),
        "expected '{expected_hdr}' and 'post-stop reply body' in envelope: {env_text}"
    );
}

/// C11: The `subagent` frame is opencode-only. On a `{"harness":"hermes"}` connection it is
/// refused `bad_request`; on `opencode` it is accepted.
#[tokio::test]
async fn c11_subagent_frame_is_opencode_only() {
    let node = Node::start();

    let mut hermes = PluginConn::open(&node.register_sock, "hermes").await;
    let _ = hermes.register("hermes_root").await;
    let refused = hermes
        .call(json!({
            "action": "subagent",
            "event": "start",
            "session": "hermes_root",
            "agent_id": "sub_1"
        }))
        .await;
    assert_eq!(refused["status"], "error", "{refused}");
    assert_eq!(refused["error"], "bad_request", "{refused}");

    let mut oc = PluginConn::open(&node.register_sock, "opencode").await;
    let _ = oc.register("oc_root").await;
    let accepted = oc
        .call(json!({
            "action": "subagent",
            "event": "start",
            "session": "oc_root",
            "agent_id": "ses_child_1"
        }))
        .await;
    assert_eq!(accepted["status"], "ok", "{accepted}");
}
