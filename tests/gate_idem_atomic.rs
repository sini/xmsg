//! Atomic idempotency: a key is reserved with its message (or reply) ID before anything is
//! delivered, so concurrent and retried sends and replies with one key deliver once and
//! answer with one ID. Each oracle runs against a real `xmsg serve`.
//!
//! A slow recipient is a Claude fake whose inbox reads nothing for a while: a body larger
//! than the socket buffer keeps the delivery's write blocked until the inbox reads.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

mod http_child;

use http_child::{FakeParent, Via};

const ID_T: &str = "a7a7a7a7-0000-4000-8000-00000000000a";
const ID_R: &str = "b7b7b7b7-0000-4000-8000-00000000000b";
const ID_S: &str = "c7c7c7c7-0000-4000-8000-00000000000c";

/// Twice the unix socket buffers a delivery can fill with no reader, so its write blocks on
/// the reader. Measured, not assumed: their defaults follow the host's kernel tuning (a
/// builder with `net.core.wmem_default` at 1 MiB took a fixed 600 KB body unread).
fn slow_body_len() -> usize {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let opt = |name| {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                a.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                (&mut v as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt: {}", std::io::Error::last_os_error());
        v as usize
    };
    2 * (opt(libc::SO_SNDBUF) + opt(libc::SO_RCVBUF))
}

/// The HTTP child's entry point (`http_child`): a no-op in a normal test run.
#[test]
fn http_child_entry() {
    http_child::serve_if_child();
}

/// A real `xmsg serve`, killed on drop.
struct Node {
    dir: PathBuf,
    sessions: PathBuf,
    http_sock: PathBuf,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    child: Child,
}

impl Node {
    fn start(dir: &Path, services: &[&str]) -> Node {
        let run = dir.join("run");
        let sessions = dir.join("sessions");
        for d in [&run, &sessions] {
            fs::create_dir_all(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (http_sock, agent_sock, register_sock) = (
            run.join("http.sock"),
            run.join("agent.sock"),
            run.join("register.sock"),
        );
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        cmd.env("XDG_RUNTIME_DIR", &run)
            .env("HOME", dir)
            .arg("serve")
            .arg("--db-path")
            .arg(dir.join("xmsg.db"))
            .arg("--sessions-dir")
            .arg(&sessions)
            .arg("--http-sock")
            .arg(&http_sock)
            .arg("--agent-sock")
            .arg(&agent_sock)
            .arg("--register-sock")
            .arg(&register_sock)
            .arg("--max-body")
            .arg((2 * slow_body_len()).to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in services {
            cmd.arg("--svc-exe")
                .arg(format!("{name}={}", exe.display()));
        }
        let mut child = cmd.spawn().expect("spawn xmsg serve");
        for _ in 0..1200 {
            if http_sock.exists() && agent_sock.exists() && register_sock.exists() {
                return Node {
                    dir: dir.to_path_buf(),
                    sessions,
                    http_sock,
                    agent_sock,
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
        panic!("xmsg serve never bound its sockets in 30s");
    }

    async fn http_within(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        within: Duration,
    ) -> std::io::Result<(u16, serde_json::Value)> {
        let sock = self.http_sock.clone();
        let (method, path) = (method.to_string(), path.to_string());
        let body = body.map(|b| b.to_string());
        tokio::task::spawn_blocking(move || {
            xmsg::http::http_request_unix_within(&sock, &method, &path, body.as_deref(), within)
        })
        .await
        .unwrap()
        .map(|(status, text)| {
            (
                status.as_u16(),
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
            )
        })
    }

    /// An anonymous keyed send over `http.sock`, from this test process as `from`.
    async fn send(&self, from: &str, to: &str, text: &str, key: &str) -> serde_json::Value {
        let (status, body) = self
            .http_within(
                "POST",
                "/v1/messages",
                Some(serde_json::json!({"to": to, "from": from, "text": text, "idempotency_key": key})),
                Duration::from_secs(30),
            )
            .await
            .expect("http.sock send");
        assert_eq!(status, 202, "{body}");
        body
    }

    /// One frame over `agent.sock`, from this test process.
    async fn agent(&self, frame: serde_json::Value) -> serde_json::Value {
        let stream = UnixStream::connect(&self.agent_sock).await.unwrap();
        let (r, mut w) = stream.into_split();
        w.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        BufReader::new(r).read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = &self.dir;
    }
}

/// A live process to stand behind a Claude fake.
struct Sleeper(Child);

impl Sleeper {
    fn new() -> Sleeper {
        Sleeper(
            Command::new("sleep")
                .arg("600")
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn sleep"),
        )
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A Claude fake's inbox: every delivered line, each read `delay` after its connection.
struct Inbox {
    _dir: TempDir,
    sock: PathBuf,
    lines: Arc<Mutex<Vec<String>>>,
}

fn inbox(delay: Duration) -> Inbox {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("inbox.sock");
    bind_inbox(dir, sock, delay)
}

/// An inbox at `sock` in `dir`, bound now (a target whose inbox was down comes back).
fn bind_inbox(dir: TempDir, sock: PathBuf, delay: Duration) -> Inbox {
    let listener = UnixListener::bind(&sock).unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let rx = lines.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let rx = rx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let mut buf = String::new();
                let _ = stream.read_to_string(&mut buf).await;
                rx.lock().unwrap().push(buf);
            });
        }
    });
    Inbox {
        _dir: dir,
        sock,
        lines,
    }
}

impl Inbox {
    fn count(&self) -> usize {
        self.lines.lock().unwrap().len()
    }
    /// The number of lines once none has arrived for `quiet`.
    async fn settled_count(&self, quiet: Duration) -> usize {
        let mut last = usize::MAX;
        loop {
            let now = self.count();
            if now == last {
                return now;
            }
            last = now;
            tokio::time::sleep(quiet).await;
        }
    }
}

fn claude_file(node: &Node, tag: &str, pid: u32, id: &str, inbox: &Path) {
    let session = serde_json::json!({
        "pid": pid,
        "sessionId": id,
        "name": tag,
        "cwd": "/w",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1,
        "updatedAt": 2,
        "procStart": xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid)
            .expect("live start time"),
        "messagingSocketPath": inbox.display().to_string(),
    });
    fs::write(
        node.sessions.join(format!("{pid}_{tag}.json")),
        session.to_string(),
    )
    .unwrap();
}

/// A Claude fake `ID_T` behind a `sleep`, with an inbox that reads after `delay`.
fn slow_target(node: &Node, delay: Duration) -> (Sleeper, Inbox) {
    let sleeper = Sleeper::new();
    let inbox = inbox(delay);
    claude_file(node, "target", sleeper.0.id(), ID_T, &inbox.sock);
    (sleeper, inbox)
}

// =============================================================================
// Oracle 1. Two concurrent sends with one key deliver once, and both answers carry the
// same message ID.
// Mutant: reserve nothing while the send is delivered (the key recorded after) => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_1_concurrent_sends_one_key_deliver_once() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (_t, target) = slow_target(&node, Duration::from_millis(1000));
    let text = "x".repeat(slow_body_len());

    let (a, b) = tokio::join!(
        node.send("ci", ID_T, &text, "k-concurrent"),
        node.send("ci", ID_T, &text, "k-concurrent"),
    );
    assert!(a["message_id"].is_string(), "{a}");
    assert_eq!(a["message_id"], b["message_id"], "one key, one message ID");
    assert_eq!(a, b, "both answers are the one send's result");
    assert_eq!(
        target.settled_count(Duration::from_millis(1500)).await,
        1,
        "one key, one delivery"
    );
}

// =============================================================================
// Oracle 2. A send with a key whose first send is still being delivered (a slow
// recipient) delivers nothing; it answers with the first send's message ID and the
// outcome `pending`, and a retry once the first settled answers with its result.
// Mutant: reserve nothing while the send is delivered => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2_retry_during_slow_delivery_is_pending_same_id() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (_t, target) = slow_target(&node, Duration::from_millis(4000));
    let text = "y".repeat(slow_body_len());

    let first = node.send("ci", ID_T, &text, "k-slow");
    let retry = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        node.send("ci", ID_T, &text, "k-slow").await
    };
    let (first, retry) = tokio::join!(first, retry);
    assert_eq!(first["outcome"], "delivered", "{first}");
    assert_eq!(
        retry,
        serde_json::json!({"message_id": first["message_id"], "address": "", "outcome": "pending"}),
        "a retry while the first send is delivered answers with its ID, pending"
    );
    let after = node.send("ci", ID_T, &text, "k-slow").await;
    assert_eq!(
        after, first,
        "a retry once it settled answers with its result"
    );
    assert_eq!(
        target.settled_count(Duration::from_millis(1500)).await,
        1,
        "one key, one delivery"
    );
}

// =============================================================================
// Oracle 2b. A caller that hangs up mid-send (a client timeout) leaves the send running:
// the key settles with the send's outcome, and the retry answers with that result.
// Mutant: abort the send when its caller goes away => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_2b_caller_hangup_still_settles() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (_t, target) = slow_target(&node, Duration::from_millis(2500));
    let text = "z".repeat(slow_body_len());

    let hung_up = node
        .http_within(
            "POST",
            "/v1/messages",
            Some(serde_json::json!({"to": ID_T, "from": "ci", "text": text, "idempotency_key": "k-hangup"})),
            Duration::from_millis(800),
        )
        .await;
    assert!(hung_up.is_err(), "the caller times out: {hung_up:?}");
    assert_eq!(
        target.settled_count(Duration::from_millis(3500)).await,
        1,
        "the send is delivered after its caller hung up"
    );
    let retry = node.send("ci", ID_T, &text, "k-hangup").await;
    assert_eq!(retry["outcome"], "delivered", "{retry}");
    assert_eq!(
        retry["address"],
        format!("{ID_T}@{}", xmsg::node::local_node_name()),
        "{retry}"
    );
    assert_eq!(target.settled_count(Duration::from_millis(1500)).await, 1);
}

// =============================================================================
// Oracle 3. A reply with a key, retried over `agent.sock` and HTTP, is pushed once and
// answers with one reply; the same key with another text is a conflict. A service's
// keyed reply on `register.sock` is stored once.
// Mutant: ignore the reply's key => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_reply_with_key_retried_delivers_once() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    // The replier is this test process; the sender is a Claude fake whose child sends.
    let replier_inbox = inbox(Duration::ZERO);
    claude_file(
        &node,
        "replier",
        std::process::id(),
        ID_R,
        &replier_inbox.sock,
    );
    let sender = FakeParent::spawn("http_child_entry");
    let sender_inbox = inbox(Duration::ZERO);
    claude_file(&node, "sender", sender.pid(), ID_S, &sender_inbox.sock);

    let (status, body) = sender
        .request(
            &Via::Unix(node.http_sock.clone()),
            "POST",
            "/v1/messages",
            Some(&serde_json::json!({"to": ID_R, "text": "question"})),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mid = sent["message_id"].as_str().unwrap().to_string();

    let frame = serde_json::json!({"action": "reply", "message_id": mid, "text": "answer", "idempotency_key": "rk"});
    let first = node.agent(frame.clone()).await;
    assert_eq!(first["status"], "ok", "{first}");
    assert_eq!(first["reply"]["pushOutcome"], "pushed", "{first}");
    let again = node.agent(frame).await;
    assert_eq!(
        again["reply"], first["reply"],
        "the retry answers with the one reply"
    );
    let (status, via_http) = node
        .http_within(
            "POST",
            &format!("/v1/messages/{mid}/replies"),
            Some(serde_json::json!({"text": "answer", "idempotency_key": "rk"})),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(status, 200, "{via_http}");
    assert_eq!(via_http, first["reply"], "HTTP shares the key");
    let other = node
        .agent(serde_json::json!({"action": "reply", "message_id": mid, "text": "other", "idempotency_key": "rk"}))
        .await;
    assert_eq!(other["error"], "conflict", "{other}");
    assert_eq!(
        sender_inbox
            .settled_count(Duration::from_millis(1000))
            .await,
        1,
        "one key, one pushed reply"
    );
    let (_, replies) = node
        .http_within(
            "GET",
            &format!("/v1/messages/{mid}/replies"),
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(
        replies.as_array().unwrap().len(),
        1,
        "one stored reply: {replies}"
    );
    sender.end();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_3_service_reply_with_key_stored_once() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &["idem-svc"]);
    let stream = UnixStream::connect(&node.register_sock).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    let mut call = async |frame: serde_json::Value| -> serde_json::Value {
        w.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), r.read_line(&mut line))
            .await
            .expect("register.sock answer")
            .unwrap();
        serde_json::from_str(&line).unwrap()
    };
    let reg = call(serde_json::json!({"harness": "svc", "name": "idem-svc"})).await;
    assert_eq!(reg["status"], "ok", "{reg}");

    // An anonymous sender, from a process outside every tree (this process is the service).
    let (status, body) = http_child::request_detached(
        "http_child_entry",
        &Via::Unix(node.http_sock.clone()),
        "POST",
        "/v1/messages",
        Some(&serde_json::json!({"to": "idem-svc", "from": "ci", "text": "ask"})),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    let mid = serde_json::from_str::<serde_json::Value>(&body).unwrap()["message_id"]
        .as_str()
        .unwrap()
        .to_string();

    let frame = serde_json::json!({"action": "reply", "messageId": mid, "text": "done", "idempotencyKey": "srk"});
    let a = call(frame.clone()).await;
    let b = call(frame).await;
    assert_eq!(a["status"], "ok", "{a}");
    assert_eq!(a, b, "the retry answers as the first");
    let (_, replies) = node
        .http_within(
            "GET",
            &format!("/v1/messages/{mid}/replies"),
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(
        replies.as_array().unwrap().len(),
        1,
        "one stored reply: {replies}"
    );
}

// =============================================================================
// Oracle 4. One key from two principals is two keys: two deliveries, two message IDs.
// Mutant: scope keys by nothing => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_4_different_principals_same_key_independent() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (_t, target) = slow_target(&node, Duration::ZERO);

    let a = node.send("alice", ID_T, "same", "k-shared").await;
    let b = node.send("bob", ID_T, "same", "k-shared").await;
    assert_eq!(a["outcome"], "delivered", "{a}");
    assert_eq!(b["outcome"], "delivered", "{b}");
    assert_ne!(
        a["message_id"], b["message_id"],
        "two principals, two sends"
    );
    assert_eq!(
        target.settled_count(Duration::from_millis(1000)).await,
        2,
        "two principals, two deliveries"
    );
}

/// One keyed send over `http.sock`, anonymous as `ci`: its status and body.
async fn keyed(node: &Node, to: &str, text: &str, key: &str) -> (u16, serde_json::Value) {
    node.http_within(
        "POST",
        "/v1/messages",
        Some(serde_json::json!({"to": to, "from": "ci", "text": text, "idempotency_key": key})),
        Duration::from_secs(30),
    )
    .await
    .expect("http.sock send")
}

/// A Claude fake `ID_T` whose inbox is down: the directory and path to bind it at later.
fn down_target(node: &Node) -> (Sleeper, TempDir, PathBuf) {
    let sleeper = Sleeper::new();
    let dir = tempdir().unwrap();
    let sock = dir.path().join("inbox.sock");
    claude_file(node, "target", sleeper.0.id(), ID_T, &sock);
    (sleeper, dir, sock)
}

// =============================================================================
// Oracle 5 (gate idem-verify-v0 F1). A failure to record the message never makes a
// delivered message's key `failed`: the record is written before delivery, so a failure
// to write it fails the send with nothing delivered.
// Mutant: write the record after delivery, its error returned => RED (2 deliveries).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_5_record_write_fails_nothing_delivered_twice() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (_t, target) = slow_target(&node, Duration::ZERO);
    let db = rusqlite::Connection::open(tmp.path().join("xmsg.db")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER gate_fail BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'gate'); END;",
    )
    .unwrap();
    let (st1, r1) = keyed(&node, ID_T, "once", "k-if").await;
    let after_first = target.settled_count(Duration::from_millis(800)).await;
    db.execute_batch("DROP TRIGGER gate_fail;").unwrap();
    let (st2, r2) = keyed(&node, ID_T, "once", "k-if").await;
    let after_retry = target.settled_count(Duration::from_millis(800)).await;
    assert_eq!((st1, after_first), (500, 0), "{r1}");
    assert_eq!(st2, 202, "{r2}");
    assert_eq!(after_retry, 1, "one key, one delivery");
}

// =============================================================================
// Oracle 6 (F1). A step after a delivery that fails (completing the record) is logged,
// and the send answers its delivered outcome: a retry returns it, delivering nothing.
// Mutant: return the completion's error => RED (the retry delivers again).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_6_post_delivery_failure_still_delivered() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (_t, target) = slow_target(&node, Duration::ZERO);
    let db = rusqlite::Connection::open(tmp.path().join("xmsg.db")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER gate_fail BEFORE UPDATE OF outcome ON messages WHEN NEW.outcome <> 'pending' BEGIN SELECT RAISE(ABORT, 'gate'); END;",
    )
    .unwrap();
    let (st1, r1) = keyed(&node, ID_T, "once", "k-uf").await;
    db.execute_batch("DROP TRIGGER gate_fail;").unwrap();
    let (st2, r2) = keyed(&node, ID_T, "once", "k-uf").await;
    let n = target.settled_count(Duration::from_millis(800)).await;
    assert_eq!(
        (st1, &r1["outcome"]),
        (202, &serde_json::json!("delivered")),
        "{r1}"
    );
    assert_eq!(r2, r1, "the retry answers the first send's result");
    assert_eq!((st2, n), (202, 1), "one key, one delivery");
}

// =============================================================================
// Oracle 7 (F2). The server dies mid-delivery; at restart the key is settled from the
// message record (here: not delivered, so `failed`), and the retry delivers it once.
// Mutant: no reconciliation at startup => RED (the key stays `pending`).
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_7_restart_mid_delivery_retry_delivers() {
    let tmp = tempdir().unwrap();
    let mut node = Node::start(tmp.path(), &[]);
    let (_t, target) = slow_target(&node, Duration::from_millis(4000));
    let len = slow_body_len();
    let text = "r".repeat(len);
    let sock = node.http_sock.clone();
    let body =
        serde_json::json!({"to": ID_T, "from": "ci", "text": text, "idempotency_key": "k-rs"});
    let b2 = body.to_string();
    let first = tokio::task::spawn_blocking(move || {
        xmsg::http::http_request_unix_within(
            &sock,
            "POST",
            "/v1/messages",
            Some(&b2),
            Duration::from_secs(30),
        )
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    let _ = node.child.kill();
    let _ = node.child.wait();
    let _ = first.await;
    for s in [&node.http_sock, &node.agent_sock, &node.register_sock] {
        let _ = fs::remove_file(s);
    }
    let node2 = Node::start(tmp.path(), &[]);
    // The killed delivery's partial line is read 4 s after its connection.
    let before = target.settled_count(Duration::from_millis(4500)).await;
    let (st, r) = node2
        .http_within("POST", "/v1/messages", Some(body), Duration::from_secs(30))
        .await
        .unwrap();
    let after = target.settled_count(Duration::from_millis(5000)).await;
    assert_eq!(
        (st, &r["outcome"]),
        (202, &serde_json::json!("delivered")),
        "{r}"
    );
    assert_eq!(after, before + 1, "the retry delivers once");
    let last = target.lines.lock().unwrap().last().unwrap().len();
    assert!(last > len, "the whole message: {last} bytes");
}

// =============================================================================
// Oracle 8 (gate P1). A key whose send failed is taken over only by the same body: another
// body is a conflict, and the same body, once the recipient is back, is delivered once.
// Mutants: the takeover ignores the body => RED; a failure leaves the key `pending` => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_8_failed_key_other_body_conflicts() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (_t, dir, sock) = down_target(&node);
    let (st1, r1) = keyed(&node, ID_T, "a", "k-fb").await;
    let (st2, r2) = keyed(&node, ID_T, "b", "k-fb").await;
    let target = bind_inbox(dir, sock, Duration::ZERO);
    let (st3, r3) = keyed(&node, ID_T, "a", "k-fb").await;
    let n = target.settled_count(Duration::from_millis(800)).await;
    assert_ne!(st1, 202, "the inbox is down: {r1}");
    assert_eq!(st2, 409, "{r2}");
    assert_eq!(
        (st3, &r3["outcome"]),
        (202, &serde_json::json!("delivered")),
        "{r3}"
    );
    assert_eq!(n, 1);
}

// =============================================================================
// Oracle 9 (gate P3). A key binds `to` as well as the body: the same key and body to
// another recipient is a conflict, whether the first send settled or failed.
// Mutants: the replay ignores `to` => RED; the takeover ignores `to` => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_oracle_9_key_binds_recipient() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (_t, target) = slow_target(&node, Duration::ZERO);
    let gone = "d7d7d7d7-0000-4000-8000-00000000000d";

    let (st1, r1) = keyed(&node, ID_T, "x", "k-to").await;
    let (st2, r2) = keyed(&node, gone, "x", "k-to").await;
    assert_eq!(
        (st1, &r1["outcome"]),
        (202, &serde_json::json!("delivered")),
        "{r1}"
    );
    assert_eq!(st2, 409, "settled key, another recipient: {r2}");

    let (st3, r3) = keyed(&node, gone, "y", "k-tf").await;
    let (st4, r4) = keyed(&node, ID_T, "y", "k-tf").await;
    assert_eq!(st3, 404, "{r3}");
    assert_eq!(st4, 409, "failed key, another recipient: {r4}");
    assert_eq!(target.settled_count(Duration::from_millis(800)).await, 1);
}
