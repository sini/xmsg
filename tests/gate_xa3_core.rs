//! XA3 gating oracles for local resolution, labels and schema N, each against a real
//! `xmsg serve` (plan §3 XA3, oracles 1, 2, 3, 8 with the XA1 carry-over, and 9).
//!
//! Live recipients are real processes: a Claude fake is a `sleep` child (or this test
//! process) named by a session file whose `procStart` is its real start time, with an
//! inbox socket the test listens on; a service is this test process, trusted through
//! `--svc-exe <name>=<this test binary>` and registered on `register.sock`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

mod http_child;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
const SIGTERM: i32 = 15;

const ID_A: &str = "a3a3a3a3-0000-4000-8000-00000000000a";
const ID_B: &str = "b3b3b3b3-0000-4000-8000-00000000000b";
const ID_X: &str = "c3c3c3c3-0000-4000-8000-00000000000c";
const ID_T: &str = "d3d3d3d3-0000-4000-8000-00000000000d";
const ID_L: &str = "e3e3e3e3-0000-4000-8000-00000000000e";

fn live_starttime(pid: u32) -> String {
    xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid)
        .expect("live start time")
}

fn node_name() -> String {
    xmsg::node::local_node_name()
}

/// A real `xmsg serve`, stopped with SIGTERM on drop.
struct Node {
    dir: PathBuf,
    sessions: PathBuf,
    http_sock: PathBuf,
    agent_sock: PathBuf,
    register_sock: PathBuf,
    db: PathBuf,
    child: Option<Child>,
}

impl Node {
    /// Starts `xmsg serve` in `dir`, trusting this test binary as each of `services`.
    fn start(dir: &Path, services: &[&str]) -> Node {
        let run = dir.join("run");
        let sessions = dir.join("sessions");
        for d in [&run, &sessions] {
            fs::create_dir_all(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut node = Node {
            dir: dir.to_path_buf(),
            http_sock: run.join("http.sock"),
            agent_sock: run.join("agent.sock"),
            register_sock: run.join("register.sock"),
            db: dir.join("xmsg.db"),
            sessions,
            child: None,
        };
        node.spawn(services);
        node
    }

    fn spawn(&mut self, services: &[&str]) {
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        cmd.env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("HOME", &self.dir)
            .arg("serve")
            .arg("--db-path")
            .arg(&self.db)
            .arg("--sessions-dir")
            .arg(&self.sessions)
            .arg("--http-sock")
            .arg(&self.http_sock)
            .arg("--agent-sock")
            .arg(&self.agent_sock)
            .arg("--register-sock")
            .arg(&self.register_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in services {
            cmd.arg("--svc-exe")
                .arg(format!("{name}={}", exe.display()));
        }
        for s in [&self.http_sock, &self.agent_sock, &self.register_sock] {
            let _ = fs::remove_file(s);
        }
        let mut child = cmd.spawn().expect("spawn xmsg serve");
        for _ in 0..1200 {
            if self.http_sock.exists() && self.agent_sock.exists() && self.register_sock.exists() {
                self.child = Some(child);
                return;
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("xmsg serve exited early: {status}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        panic!("xmsg serve never bound its sockets in 30s");
    }

    /// SIGTERM, then wait for a clean exit.
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            unsafe {
                kill(child.id() as i32, SIGTERM);
            }
            for _ in 0..200 {
                if let Ok(Some(status)) = child.try_wait() {
                    assert!(status.success(), "xmsg serve exit: {status}");
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let _ = child.kill();
            let _ = child.wait();
            panic!("xmsg serve did not exit within 5s of SIGTERM");
        }
    }

    async fn http(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, String) {
        let sock = self.http_sock.clone();
        let (method, path) = (method.to_string(), path.to_string());
        let body = body.map(|b| b.to_string());
        let (status, text) = tokio::task::spawn_blocking(move || {
            xmsg::http::http_request_unix_within(
                &sock,
                &method,
                &path,
                body.as_deref(),
                std::time::Duration::from_secs(30),
            )
        })
        .await
        .unwrap()
        .expect("http.sock request");
        (status.as_u16(), text)
    }

    /// An anonymous send over `http.sock`.
    async fn send(&self, to: &str, text: &str) -> (u16, serde_json::Value) {
        let (status, body) = self
            .http(
                "POST",
                "/v1/messages",
                Some(serde_json::json!({"to": to,  "from": "ci", "text": text })),
            )
            .await;
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn list(&self) -> Vec<serde_json::Value> {
        let (status, body) = self.http("GET", "/v1/recipients", None).await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_value(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["recipients"].take(),
        )
        .unwrap()
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
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
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
    fn pid(&self) -> u32 {
        self.0.id()
    }
    fn end(mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A Claude fake's inbox: every line delivered to its messaging socket.
struct Inbox {
    _dir: TempDir,
    sock: PathBuf,
    lines: Arc<Mutex<Vec<String>>>,
}

fn inbox() -> Inbox {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("inbox.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let rx = lines.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf).await;
            rx.lock().unwrap().push(buf);
        }
    });
    Inbox {
        _dir: dir,
        sock,
        lines,
    }
}

impl Inbox {
    async fn wait_line(&self) -> Option<String> {
        for _ in 0..100 {
            if let Some(line) = self.lines.lock().unwrap().first() {
                return Some(line.clone());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }
    async fn wait_for(&self, needle: &str) -> bool {
        for _ in 0..100 {
            if self
                .lines
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains(needle))
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }
    fn is_empty(&self) -> bool {
        self.lines.lock().unwrap().is_empty()
    }
}

/// The `from-name` attribute of a delivered inbox line.
fn from_name(line: &str) -> String {
    let parsed: xmsg::inbox::InboxLine = serde_json::from_str(line).expect("inbox line");
    let content = parsed.message.content;
    let start = content.find("from-name=\"").expect("from-name") + "from-name=\"".len();
    let end = start + content[start..].find('"').expect("closing quote");
    content[start..end].to_string()
}

/// Writes a Claude session file presenting `id` for process `pid`.
fn claude_file(node: &Node, tag: &str, pid: u32, id: &str, name: &str, inbox: &Path) {
    let session = serde_json::json!({
        "pid": pid,
        "sessionId": id,
        "name": name,
        "cwd": "/w",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1,
        "updatedAt": 2,
        "procStart": live_starttime(pid),
        "messagingSocketPath": inbox.display().to_string(),
    });
    fs::write(
        node.sessions.join(format!("{pid}_{tag}.json")),
        session.to_string(),
    )
    .unwrap();
}

/// A service registration on `register.sock`, held open.
struct Service {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Service {
    async fn register(node: &Node, name: &str) -> Service {
        let stream = UnixStream::connect(&node.register_sock).await.unwrap();
        let (r, w) = stream.into_split();
        let mut svc = Service {
            reader: BufReader::new(r),
            writer: w,
        };
        let resp = svc
            .call(serde_json::json!({ "harness": "svc", "name": name }))
            .await;
        assert_eq!(resp["status"], "ok", "register {name}: {resp}");
        // AM-4: the `ok` frame carries the address and the node MA's origin check reads.
        assert_eq!(resp["address"], format!("{name}@{}", node_name()), "{resp}");
        assert_eq!(resp["node"], node_name(), "{resp}");
        svc
    }

    async fn call(&mut self, frame: serde_json::Value) -> serde_json::Value {
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
            .await
            .expect("register.sock answer")
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }

    /// One poll: the delivered message, or `None` on timeout.
    async fn poll(&mut self, wait_secs: u64) -> Option<serde_json::Value> {
        let resp = self
            .call(serde_json::json!({ "action": "poll", "waitSecs": wait_secs }))
            .await;
        (resp["action"] == "deliver").then_some(resp)
    }
}

// =============================================================================
// Oracle 1 (F1 is gone, A11). With a Claude fake labelled `genie-guard` and a service
// `genie-guard`, a bare `genie-guard` reaches the service.
// Mutant: try instance labels before services (the old HTTP resolver order) => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_1_services_resolve_before_instance_labels() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &["genie-guard"]);
    let mut guard = Service::register(&node, "genie-guard").await;

    let impostor = Sleeper::new();
    let impostor_inbox = inbox();
    claude_file(
        &node,
        "imp",
        impostor.pid(),
        ID_A,
        "genie-guard",
        &impostor_inbox.sock,
    );
    let listed = node.list().await;
    assert!(
        listed
            .iter()
            .any(|s| s["address"] == format!("{ID_A}@{}", node_name())
                && s["label"] == "genie-guard"),
        "the impostor is live and labelled genie-guard: {listed:?}"
    );

    let (status, body) = node.send("genie-guard", "for the guard").await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(
        body["address"],
        format!("genie-guard@{}", node_name()),
        "{body}"
    );
    let delivered = guard.poll(3).await.expect("the service receives it");
    assert_eq!(delivered["text"], "for the guard");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        impostor_inbox.is_empty(),
        "an instance label never shadows a service"
    );
}

// =============================================================================
// Oracle 2 (A7). Two live instances labelled `foo` give `ambiguous`, listing both
// addresses as `id@node`.
// Mutant: take the first match => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_2_duplicate_labels_are_ambiguous() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (p1, p2) = (Sleeper::new(), Sleeper::new());
    let (in1, in2) = (inbox(), inbox());
    claude_file(&node, "a", p1.pid(), ID_A, "foo", &in1.sock);
    claude_file(&node, "b", p2.pid(), ID_B, "foo", &in2.sock);

    let (status, body) = node.send("foo", "which foo").await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "ambiguous", "{body}");
    let detail = body["detail"].as_str().unwrap();
    let node = node_name();
    for id in [ID_A, ID_B] {
        assert!(
            detail.contains(&format!("{id}@{node}")),
            "candidates list {id}@{node}: {detail}"
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(in1.is_empty() && in2.is_empty(), "nothing is guessed");
}

// =============================================================================
// Oracle 3 (D-4). While only `X~2` is live, a bare `X` gives `ambiguous` with
// `X~2@node`.
// Mutant: treat a bare X with only forks live as not running => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_3_bare_id_with_only_forks_live_is_ambiguous() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (p1, p2) = (Sleeper::new(), Sleeper::new());
    let (in1, in2) = (inbox(), inbox());

    claude_file(&node, "p1", p1.pid(), ID_X, "x", &in1.sock);
    node.list().await; // P1 observed first: plain X
    claude_file(&node, "p2", p2.pid(), ID_X, "x", &in2.sock);
    let listed = node.list().await;
    let fork = format!("{ID_X}~2");
    assert!(
        listed
            .iter()
            .any(|s| s["address"] == format!("{fork}@{}", node_name())),
        "P2 holds X~2: {listed:?}"
    );

    fs::remove_file(node.sessions.join(format!("{}_p1.json", p1.pid()))).unwrap();
    p1.end();

    let (status, body) = node.send(ID_X, "bare-send-body").await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "ambiguous", "{body}");
    let detail = body["detail"].as_str().unwrap();
    assert!(
        detail.contains(&format!("{fork}@{}", node_name())),
        "the candidates name the live fork: {detail}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    // In2 holds P2's fork notice (XA1); the bare send must not have reached it.
    assert!(
        !in2.lines
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("bare-send-body")),
        "a fork is never taken for the plain ID"
    );

    // Control: the fork's own address still reaches it.
    let (status, body) = node.send(&fork, "to the fork").await;
    assert_eq!(status, 202, "{body}");
    assert!(
        in2.wait_for("to the fork").await,
        "the fork's address reaches it"
    );
}

// =============================================================================
// Oracle 8 (A12, AM-8). An attested sender's label is `label · id@node`. A Claude
// session named `x · y@z` is listed with no label.
// Mutant: render the raw name (drop the AM-8 check) => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_8_label_render() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let target = Sleeper::new();
    let target_inbox = inbox();
    claude_file(&node, "t", target.pid(), ID_T, "target", &target_inbox.sock);
    let me_inbox = inbox();
    claude_file(&node, "me", std::process::id(), ID_L, "lab", &me_inbox.sock);

    let resp = node
        .agent(serde_json::json!({ "action": "send", "to": ID_T, "text": "hi" }))
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    let line = target_inbox.wait_line().await.expect("delivered");
    assert_eq!(from_name(&line), format!("lab · {ID_L}@{}", node_name()));

    let spoof = Sleeper::new();
    let spoof_inbox = inbox();
    claude_file(&node, "s", spoof.pid(), ID_A, "x · y@z", &spoof_inbox.sock);
    let listed = node.list().await;
    let entry = listed
        .iter()
        .find(|s| s["address"] == format!("{ID_A}@{}", node_name()))
        .unwrap_or_else(|| panic!("the session stays listed: {listed:?}"));
    assert!(
        entry["label"].is_null(),
        "a label carrying `@` or `·` is dropped: {entry}"
    );
}

// =============================================================================
// Oracle 8, XA1 carry-over (A12, A6, D-5). The label's attested part is the instance
// ADDRESS: a send from the `X~2` fork shows `X~2` in the receiver's label.
// Mutant: take the label's id from the session name => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_8_fork_sends_as_its_address() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let target = Sleeper::new();
    let target_inbox = inbox();
    claude_file(&node, "t", target.pid(), ID_T, "target", &target_inbox.sock);

    let holder = Sleeper::new();
    let holder_inbox = inbox();
    claude_file(&node, "h", holder.pid(), ID_X, "forked", &holder_inbox.sock);
    node.list().await; // the holder takes plain X
    let me_inbox = inbox();
    claude_file(
        &node,
        "me",
        std::process::id(),
        ID_X,
        "forked",
        &me_inbox.sock,
    );
    node.list().await; // this process takes X~2

    let resp = node
        .agent(serde_json::json!({ "action": "send", "to": ID_T, "text": "from the fork" }))
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    let line = target_inbox.wait_line().await.expect("delivered");
    assert_eq!(
        from_name(&line),
        format!("forked · {ID_X}~2@{}", node_name()),
        "the fork's label carries its own address"
    );
}

// =============================================================================
// Oracle 9 (schema N, plan gate v0 C5). A database created by the deployed ee1b6ca
// binary, with a row in every message table, starts at schema N with those tables
// empty and `user_version` N; a `forwarded_messages` table (199cecf's) is dropped too.
// Mutant: skip the drop => RED.
// =============================================================================
const EE1B6CA_DB: &str = include_str!("fixtures/ee1b6ca-db.sql");

const EE1B6CA_MESSAGE_TABLES: &[&str] = &[
    "messages",
    "outbound",
    "replies",
    "pi_pending_messages",
    "agy_pending_messages",
    "svc_pending_messages",
    "idempotency_keys",
    "peer_mailbox",
];

fn count(conn: &rusqlite::Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn user_version(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_9_migration_from_ee1b6ca_drops_message_state() {
    for with_forwarded in [false, true] {
        let tmp = tempdir().unwrap();
        let db = tmp.path().join("xmsg.db");
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(EE1B6CA_DB).unwrap();
            if with_forwarded {
                conn.execute_batch(
                    "CREATE TABLE forwarded_messages (id TEXT PRIMARY KEY, origin_peer TEXT NOT NULL, created_at INTEGER NOT NULL);
                     INSERT INTO forwarded_messages VALUES ('01OLDFWD', 'hub', 1760000000);",
                )
                .unwrap();
            }
            assert_eq!(user_version(&conn), 0, "the fixture records no version");
            for table in EE1B6CA_MESSAGE_TABLES {
                assert_eq!(count(&conn, table), 1, "fixture row in {table}");
            }
        }

        let mut node = Node::start(tmp.path(), &[]);
        node.stop();

        let conn = rusqlite::Connection::open(&db).unwrap();
        assert_eq!(
            user_version(&conn),
            xmsg::storage::SCHEMA_VERSION,
            "the database is at schema N"
        );
        for table in EE1B6CA_MESSAGE_TABLES {
            assert_eq!(
                count(&conn, table),
                0,
                "{table} is emptied by the migration"
            );
        }
        if with_forwarded {
            assert_eq!(count(&conn, "forwarded_messages"), 0);
        }
    }
}

// =============================================================================
// Oracle 9, second arm (C5's restart). A pending message written at schema N survives
// an xmsg restart.
// Mutant: drop message state on every start => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_9_schema_n_survives_restart() {
    let tmp = tempdir().unwrap();
    let mut node = Node::start(tmp.path(), &["keeper"]);
    let keeper = Service::register(&node, "keeper").await;
    let (status, body) = node.send("keeper", "kept across a restart").await;
    assert_eq!(status, 202, "{body}");
    let message_id = body["message_id"].as_str().unwrap().to_string();
    drop(keeper);
    node.stop();
    {
        let conn = rusqlite::Connection::open(&node.db).unwrap();
        assert_eq!(user_version(&conn), xmsg::storage::SCHEMA_VERSION);
        assert_eq!(
            count(&conn, "svc_pending_messages"),
            1,
            "queued before the restart"
        );
    }

    node.spawn(&["keeper"]);
    let mut keeper = Service::register(&node, "keeper").await;
    let delivered = keeper
        .poll(3)
        .await
        .expect("the message queued at schema N survives the restart");
    assert_eq!(delivered["messageId"], message_id.as_str());
    assert_eq!(delivered["text"], "kept across a restart");
}

/// One `agent.sock` frame from this test process, answered within `secs` seconds.
async fn agent_within(node: &Node, frame: serde_json::Value, secs: u64) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(secs), node.agent(frame))
        .await
        .unwrap_or_else(|_| panic!("agent.sock did not answer within {secs}s"))
}

// =============================================================================
// Oracle 4 (A10 as amended by A-2). Replies are pushed by sender kind: to a Claude
// session that sent to a service, and to a service that sent to a Claude session, whose
// push lands in its inbox with `in_reply_to`.
// Mutant: push only to sessions => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_4_claude_sender_gets_a_service_reply_pushed() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &["helper"]);
    let mut helper = Service::register(&node, "helper").await;
    let me_inbox = inbox();
    claude_file(
        &node,
        "me",
        std::process::id(),
        ID_L,
        "asker",
        &me_inbox.sock,
    );

    let resp = node
        .agent(serde_json::json!({ "action": "send", "to": "helper", "text": "question" }))
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    let message_id = resp["message_id"].as_str().unwrap().to_string();
    let delivered = helper.poll(3).await.expect("the service receives it");
    assert_eq!(delivered["messageId"], message_id.as_str());
    assert_eq!(delivered["origin"]["id"], ID_L, "{delivered}");
    assert_eq!(
        delivered["origin"]["node"],
        node_name().as_str(),
        "{delivered}"
    );

    let ack = helper
        .call(serde_json::json!({ "action": "reply", "messageId": message_id, "text": "answer" }))
        .await;
    assert_eq!(ack["status"], "ok", "{ack}");
    assert!(
        me_inbox
            .wait_for(&format!("[xmsg] reply to message_id={message_id}"))
            .await,
        "the reply is pushed into the Claude session"
    );
    let line = me_inbox.wait_line().await.unwrap();
    assert_eq!(from_name(&line), format!("helper@{}", node_name()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_4_service_sender_gets_a_claude_reply_in_its_inbox() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &["asker"]);
    let mut asker = Service::register(&node, "asker").await;
    let target = Sleeper::new();
    let target_inbox = inbox();
    claude_file(&node, "t", target.pid(), ID_T, "expert", &target_inbox.sock);

    // The service sends over agent.sock, attributed by its pid (plan §6 D15).
    let resp = node
        .agent(serde_json::json!({ "action": "send", "to": ID_T, "text": "please answer" }))
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    let message_id = resp["message_id"].as_str().unwrap().to_string();
    let line = target_inbox.wait_line().await.expect("delivered");
    assert_eq!(from_name(&line), format!("asker@{}", node_name()));

    // The conversation moves to this process: the old holder exits, and this process
    // takes the plain ID and answers as the recipient.
    fs::remove_file(node.sessions.join(format!("{}_t.json", target.pid()))).unwrap();
    target.end();
    node.list().await;
    let me_inbox = inbox();
    claude_file(
        &node,
        "me",
        std::process::id(),
        ID_T,
        "expert",
        &me_inbox.sock,
    );
    let resp = node
        .agent(serde_json::json!({ "action": "reply", "message_id": message_id, "text": "the answer" }))
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    assert_eq!(resp["reply"]["pushOutcome"], "pushed", "{resp}");

    let pushed = asker
        .poll(3)
        .await
        .expect("the reply lands in the service's inbox");
    assert_eq!(pushed["inReplyTo"], message_id.as_str(), "{pushed}");
    assert_eq!(pushed["text"], "the answer");
    assert_eq!(pushed["origin"]["id"], ID_T, "{pushed}");
}

// =============================================================================
// Oracle 5 (A10, A-12). A sender reads the stored reply with `replies`, and
// `wait=600` returns within the 60 s cap.
// Mutant: no cap. The call is bounded by a timeout, so a hang is RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_5_replies_reads_the_stored_reply_and_caps_wait() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &["answerer"]);
    let mut answerer = Service::register(&node, "answerer").await;

    // This test process is now the service `answerer` (A15), so the anonymous sender is a
    // process outside every tree.
    let (status, body) = http_child::request_detached(
        "http_child_entry",
        &http_child::Via::Unix(node.http_sock.clone()),
        "POST",
        "/v1/messages",
        Some(&serde_json::json!({ "to": "answerer", "from": "ci", "text": "anonymous question" })),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let message_id = body["message_id"].as_str().unwrap().to_string();
    let delivered = answerer.poll(3).await.expect("delivered");
    let ack = answerer
        .call(serde_json::json!({ "action": "reply", "messageId": message_id, "text": "stored answer" }))
        .await;
    assert_eq!(ack["status"], "ok", "{ack}");
    assert_eq!(delivered["origin"]["label"], "ci", "{delivered}");

    let (status, body) = node
        .http("GET", &format!("/v1/messages/{message_id}/replies"), None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("stored answer"), "HTTP replies: {body}");
    let resp = agent_within(
        &node,
        serde_json::json!({ "action": "replies", "message_id": message_id }),
        5,
    )
    .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    assert_eq!(resp["replies"][0]["text"], "stored answer", "{resp}");

    // An unanswered message: `wait=600` comes back empty at the 60 s cap.
    let (status, body) = node.send("answerer", "never answered").await;
    assert_eq!(status, 202, "{body}");
    let unanswered = body["message_id"].as_str().unwrap().to_string();
    let started = std::time::Instant::now();
    let resp = agent_within(
        &node,
        serde_json::json!({ "action": "replies", "message_id": unanswered, "wait": 600 }),
        75,
    )
    .await;
    let waited = started.elapsed();
    assert_eq!(resp["status"], "ok", "{resp}");
    assert_eq!(resp["replies"], serde_json::json!([]), "{resp}");
    assert!(
        waited >= Duration::from_secs(55) && waited <= Duration::from_secs(70),
        "wait=600 is capped at 60 s: waited {waited:?}"
    );
}

// =============================================================================
// Oracle 6 (the deploy-skew oracle, plan §6 D3). Old clients are refused: the old
// HTTP routes are gone and an old agent.sock send frame is `bad_request` naming `ref`.
// Mutant: accept unknown fields => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6_old_clients_are_refused() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (status, body) = node.http("GET", "/v1/sessions", None).await;
    assert_eq!(status, 404, "GET /v1/sessions is gone: {body}");
    let (status, body) = node
        .http(
            "POST",
            "/v1/sessions/x/messages",
            Some(serde_json::json!({ "from": "ci", "text": "old" })),
        )
        .await;
    assert_eq!(
        status, 404,
        "POST /v1/sessions/{{ref}}/messages is gone: {body}"
    );
    let (status, body) = node.http("GET", "/v1/recipients?peer=x", None).await;
    assert_eq!(status, 400, "?peer= has no alias: {body}");
    let (status, body) = node
        .http(
            "POST",
            "/v1/messages",
            Some(serde_json::json!({ "to": "x", "text": "old", "push_replies": false })),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("push_replies"),
        "the refusal names the field: {body}"
    );

    let resp = node
        .agent(serde_json::json!({
            "action": "send",
            "ref": "x",
            "text": "old client",
            "push_replies": true,
        }))
        .await;
    assert_eq!(resp["status"], "error", "{resp}");
    assert_eq!(resp["error"], "bad_request", "{resp}");
    assert!(
        resp["detail"].as_str().unwrap().contains("`ref`"),
        "the refusal names `ref`: {resp}"
    );
}

// =============================================================================
// Oracle 7 (A13). A resolved address doesn't drift: `send` by `foo` returns `id@node`,
// and after a second `foo` appears a follow-up to that address still reaches the first.
// Mutant: return the name instead => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_7_send_returns_the_resolved_address() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let (p1, p2) = (Sleeper::new(), Sleeper::new());
    let (in1, in2) = (inbox(), inbox());
    claude_file(&node, "a", p1.pid(), ID_A, "foo", &in1.sock);

    let (status, body) = node.send("foo", "first").await;
    assert_eq!(status, 202, "{body}");
    let address = body["address"].as_str().unwrap().to_string();
    assert_eq!(address, format!("{ID_A}@{}", node_name()), "{body}");
    assert_eq!(body["outcome"], "delivered", "{body}");
    assert!(in1.wait_for("first").await);

    claude_file(&node, "b", p2.pid(), ID_B, "foo", &in2.sock);
    let (status, body) = node.send("foo", "by name").await;
    assert_eq!(status, 409, "two foo are ambiguous now: {body}");

    let (status, body) = node.send(&address, "follow-up").await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["address"], address.as_str(), "{body}");
    assert!(
        in1.wait_for("follow-up").await,
        "the address reaches the first"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(in2.is_empty(), "the second foo never gets the follow-up");
}

// =============================================================================
// Oracle 10 (A13). MCP: `tools/list` shows four tools, or two in reply-only mode, and
// an MCP `send` carries no `idempotency_key`.
// Mutant: keep three tools => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_10_mcp_four_tools_and_no_idempotency_key() {
    let tmp = tempdir().unwrap();
    let run = tmp.path().join("run");
    fs::create_dir_all(&run).unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
    let sock = run.join("agent.sock");

    // A stand-in agent.sock that records the frame MCP sends.
    let listener = UnixListener::bind(&sock).unwrap();
    let frames = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let seen = frames.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            seen.lock()
                .unwrap()
                .push(serde_json::from_str(&line).unwrap());
            let ok = serde_json::json!({ "status": "ok", "message_id": "M", "address": "x@n", "outcome": "delivered" });
            let _ = w.write_all(format!("{ok}\n").as_bytes()).await;
        }
    });

    let config = xmsg::mcp::McpConfig::new(vec![], "http://127.0.0.1:9".to_string())
        .with_agent_sock(sock.clone());
    let res = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::new();
        let list = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        let names = |config: &xmsg::mcp::McpConfig| -> Vec<String> {
            let resp = xmsg::mcp::handle_jsonrpc(config, &client, &list).unwrap();
            resp["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect()
        };
        let mut reply_only = config.clone();
        reply_only.reply_only = true;
        let tools = (names(&config), names(&reply_only));
        let ok = xmsg::mcp::execute_tool(
            &config,
            &client,
            "send",
            &serde_json::json!({ "to": "x", "text": "hi" }),
        );
        let refused = xmsg::mcp::execute_tool(
            &config,
            &client,
            "send",
            &serde_json::json!({ "to": "x", "text": "hi", "idempotency_key": "k" }),
        );
        (ok, refused, tools)
    })
    .await
    .unwrap();
    assert_eq!(res.2 .0, ["list", "send", "reply", "replies", "inbox"]);
    assert_eq!(res.2 .1, ["reply", "replies"], "reply-only mode");

    let send_schema = xmsg::mcp::tool_definitions()
        .into_iter()
        .find(|t| t["name"] == "send")
        .unwrap();
    assert!(
        send_schema["inputSchema"]["properties"]
            .get("idempotency_key")
            .is_none(),
        "MCP send declares no idempotency_key: {send_schema}"
    );
    assert_eq!(res.0["isError"], false, "{}", res.0);
    assert_eq!(res.1["isError"], true, "{}", res.1);
    let frames = frames.lock().unwrap().clone();
    assert_eq!(
        frames.len(),
        1,
        "only the valid send reached agent.sock: {frames:?}"
    );
    assert_eq!(
        frames[0],
        serde_json::json!({
            "action": "send",
            "schema_version": xmsg::surface::MCP_SCHEMA_VERSION,
            "to": "x",
            "text": "hi",
        }),
        "the MCP send frame carries schema_version and no idempotency_key"
    );
}

// =============================================================================
// Oracle 11 (A3, B4). There is no hop in the grammar: `send` with `to = x@dest@hub`
// returns `bad_request`, over HTTP and over agent.sock.
// Mutant: keep X26's hop parse for `to` => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_11_no_hop_in_the_grammar() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &[]);
    let me_inbox = inbox();
    claude_file(&node, "me", std::process::id(), ID_L, "me", &me_inbox.sock);

    let (status, body) = node.send("x@dest@hub", "hop").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "bad_request", "{body}");
    let resp = node
        .agent(serde_json::json!({ "action": "send", "to": "x@dest@hub", "text": "hop" }))
        .await;
    assert_eq!(resp["error"], "bad_request", "{resp}");
}

// =============================================================================
// Oracle 12 (A2, A7: one name equality, exact). Two live services `dup` and `DUP` are
// two names: each send reaches the one it names, and `list?name=` agrees with `send`
// for a Claude label (`LBL-X` lists nothing and sends nowhere while `lbl-x` is live).
// Mutant: case-insensitive service match in `resolve_target`, or in the `list` name
// filter => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_12_names_compare_exactly() {
    let tmp = tempdir().unwrap();
    let node = Node::start(tmp.path(), &["dup", "DUP"]);
    let mut lower = Service::register(&node, "dup").await;
    let mut upper = Service::register(&node, "DUP").await;
    let me = node_name();

    for (to, svc) in [("DUP", &mut upper), ("dup", &mut lower)] {
        let (status, body) = node.send(to, &format!("for {to}")).await;
        assert_eq!(status, 202, "send {to}: {body}");
        assert_eq!(body["address"], format!("{to}@{me}"), "send {to}: {body}");
        let got = svc.poll(3).await.expect("the named service receives it");
        assert_eq!(got["text"], format!("for {to}"), "{got}");
        let ack = svc
            .call(serde_json::json!({ "action": "ack", "messageId": got["messageId"] }))
            .await;
        assert_eq!(ack["status"], "ok", "{ack}");
    }
    assert!(lower.poll(1).await.is_none(), "nothing more for dup");
    assert!(upper.poll(1).await.is_none(), "nothing more for DUP");

    let (status, body) = node.http("GET", "/v1/recipients?name=dup", None).await;
    assert_eq!(status, 200, "{body}");
    let listed: Vec<serde_json::Value> = serde_json::from_value(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["recipients"].take(),
    )
    .unwrap();
    let addrs: Vec<&str> = listed
        .iter()
        .filter_map(|r| r["address"].as_str())
        .collect();
    assert_eq!(addrs, [format!("dup@{me}")], "{body}");

    let sl = Sleeper::new();
    let ib = inbox();
    claude_file(&node, "c", sl.pid(), ID_A, "lbl-x", &ib.sock);
    node.list().await;
    for (name, found) in [("lbl-x", true), ("LBL-X", false)] {
        let (_, body) = node
            .http("GET", &format!("/v1/recipients?name={name}"), None)
            .await;
        let listed: Vec<serde_json::Value> = serde_json::from_value(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["recipients"].take(),
        )
        .unwrap();
        let (status, sent) = node.send(name, "label").await;
        if found {
            assert_eq!(listed.len(), 1, "list {name}: {body}");
            assert_eq!(listed[0]["address"], format!("{ID_A}@{me}"), "{body}");
            assert_eq!(status, 202, "send {name}: {sent}");
        } else {
            assert!(listed.is_empty(), "list {name}: {body}");
            assert_eq!(status, 404, "send {name}: {sent}");
            assert_eq!(sent["error"], "not_found", "send {name}: {sent}");
        }
    }
}

/// The body of every HTTP child this binary starts (`tests/http_child`).
#[test]
fn http_child_entry() {
    http_child::serve_if_child();
}
