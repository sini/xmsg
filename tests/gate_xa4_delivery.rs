//! XA4 gating oracles: local delivery (plan §3 XA4). A14's queue on one node, D-1's
//! parked lifetime, `gone` for a pi and an `X~n` (AM-9, AM-10, D-4), A15's HTTP caller
//! identity, AM-2's TCP callers, and the anonymous principal in a peers-file filter (gate
//! v0 C8). Every oracle runs a real `xmsg serve`.
//!
//! A Claude fake is a real process named by a session file whose `procStart` is its start
//! time, with an inbox socket the test listens on. A fake that makes HTTP requests is a
//! `sh` whose child makes each one (`tests/http_child`), so the caller is traced by its
//! ancestry, not by its own pid. This test process is never a fake or a service in the
//! oracles that use it as the anonymous caller.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

mod http_child;
use http_child::{FakeParent, Via};

const CHILD: &str = "http_child_entry";

const ID_X: &str = "a4a4a4a4-0000-4000-8000-00000000000a";
const ID_Y: &str = "b4b4b4b4-0000-4000-8000-00000000000b";
const ID_R: &str = "c4c4c4c4-0000-4000-8000-00000000000c";
const ID_NEVER: &str = "d4d4d4d4-0000-4000-8000-00000000000d";

/// The body of every HTTP child this binary starts.
#[test]
fn http_child_entry() {
    http_child::serve_if_child();
}

fn node_name() -> String {
    xmsg::node::local_node_name()
}

fn live_starttime(pid: u32) -> String {
    xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid)
        .expect("live start time")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// -----------------------------------------------------------------------------
// A real `xmsg serve`
// -----------------------------------------------------------------------------

#[derive(Default)]
struct Spec {
    services: Vec<String>,
    reply_ttl: Option<u64>,
    /// Bind the TCP `--listen` listener.
    listen: bool,
    /// Leaf mode, with the leaf principal `svc:matrix` (AM-2).
    leaf: bool,
    /// (cert PEM, key PEM, peers file) for a federated node.
    fed: Option<(String, String, String)>,
    fed_listen: Option<u16>,
}

struct Node {
    _tmp: TempDir,
    sessions: PathBuf,
    http_sock: PathBuf,
    register_sock: PathBuf,
    tcp: Option<String>,
    child: Child,
}

impl Node {
    fn start(spec: Spec) -> Node {
        for _ in 0..5 {
            if let Some(node) = Node::try_start(&spec) {
                return node;
            }
        }
        panic!("xmsg serve did not start in 5 attempts");
    }

    /// `None` when the server exits at start (a lost port race); panics if it never serves.
    fn try_start(spec: &Spec) -> Option<Node> {
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
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        cmd.env("XDG_RUNTIME_DIR", &run)
            .env("HOME", &run)
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
            .stderr(Stdio::null());
        for name in &spec.services {
            cmd.arg("--svc-exe")
                .arg(format!("{name}={}", exe.display()));
        }
        if let Some(ttl) = spec.reply_ttl {
            cmd.arg("--reply-ttl").arg(ttl.to_string());
        }
        let tcp = (spec.listen || spec.leaf).then(|| format!("127.0.0.1:{}", free_port()));
        if let Some(addr) = &tcp {
            cmd.arg("--listen").arg(addr);
        }
        if spec.leaf {
            cmd.args(["--leaf", "--leaf-principal", "svc:matrix"]);
        }
        if let Some((cert, key, peers)) = &spec.fed {
            let (c, k, p) = (
                tmp.path().join("cert.pem"),
                tmp.path().join("key.pem"),
                tmp.path().join("peers.json"),
            );
            fs::write(&c, cert).unwrap();
            fs::write(&k, key).unwrap();
            fs::write(&p, peers).unwrap();
            cmd.arg("--fed-cert")
                .arg(c)
                .arg("--fed-key")
                .arg(k)
                .arg("--peers-file")
                .arg(p);
        }
        if let Some(port) = spec.fed_listen {
            cmd.arg("--fed-listen").arg(format!("127.0.0.1:{port}"));
        }
        let mut child = cmd.spawn().expect("spawn xmsg serve");
        for _ in 0..1200 {
            if let Ok(Some(_)) = child.try_wait() {
                return None;
            }
            let up = if spec.leaf {
                std::net::TcpStream::connect(tcp.as_deref().unwrap()).is_ok()
            } else {
                http_sock.exists()
                    && register_sock.exists()
                    && tcp
                        .as_deref()
                        .is_none_or(|a| std::net::TcpStream::connect(a).is_ok())
                    && spec
                        .fed_listen
                        .is_none_or(|p| std::net::TcpStream::connect(("127.0.0.1", p)).is_ok())
            };
            if up {
                return Some(Node {
                    _tmp: tmp,
                    sessions,
                    http_sock,
                    register_sock,
                    tcp,
                    child,
                });
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        panic!("xmsg serve never served");
    }

    fn unix(&self) -> Via {
        Via::Unix(self.http_sock.clone())
    }

    fn tcp(&self) -> Via {
        Via::Tcp(self.tcp.clone().expect("--listen"))
    }

    /// A request from this test process over `http.sock`.
    async fn http(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
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
        (
            status.as_u16(),
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    /// An anonymous send from this test process (outside every tree).
    async fn send(&self, to: &str, text: &str) -> (u16, Value) {
        self.http(
            "POST",
            "/v1/messages",
            Some(json!({ "to": to, "from": "ci", "text": text })),
        )
        .await
    }

    /// Lists recipients, which runs a claim scan: the observation a queue drains on.
    async fn list(&self) -> Vec<Value> {
        let (status, body) = self.http("GET", "/v1/recipients", None).await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_value(body["recipients"].clone()).unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn parse(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::String(body.to_string()))
}

// -----------------------------------------------------------------------------
// Claude fakes and inboxes
// -----------------------------------------------------------------------------

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
            if !buf.is_empty() {
                rx.lock().unwrap().push(buf);
            }
        }
    });
    Inbox {
        _dir: dir,
        sock,
        lines,
    }
}

impl Inbox {
    /// The delivered lines containing `needle`, after waiting up to 2 s for the first.
    async fn wait_for(&self, needle: &str) -> Vec<String> {
        for _ in 0..100 {
            let found = self.matching(needle);
            if !found.is_empty() {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Vec::new()
    }
    fn matching(&self, needle: &str) -> Vec<String> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(needle))
            .cloned()
            .collect()
    }
}

/// The `from-name` attribute and the content of a delivered inbox line.
fn from_name(line: &str) -> String {
    let parsed: xmsg::inbox::InboxLine = serde_json::from_str(line).expect("inbox line");
    let content = parsed.message.content;
    let start = content.find("from-name=\"").expect("from-name") + "from-name=\"".len();
    let end = start + content[start..].find('"').expect("closing quote");
    content[start..end].to_string()
}

/// Writes a Claude session file presenting `id` for process `pid`.
fn claude_file(node: &Node, tag: &str, pid: u32, id: &str, name: &str, inbox: &Path) {
    let session = json!({
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

fn remove_file(node: &Node, tag: &str, pid: u32) {
    fs::remove_file(node.sessions.join(format!("{pid}_{tag}.json"))).unwrap();
}

/// A registration on `register.sock`, held open.
struct Registration {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Registration {
    async fn open(sock: &Path, frame: Value) -> (Registration, Value) {
        let stream = UnixStream::connect(sock).await.unwrap();
        let (r, w) = stream.into_split();
        let mut reg = Registration {
            reader: BufReader::new(r),
            writer: w,
        };
        let resp = reg.call(frame).await;
        assert_eq!(resp["status"], "ok", "registration: {resp}");
        (reg, resp)
    }

    async fn call(&mut self, frame: Value) -> Value {
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

    async fn poll(&mut self, wait_secs: u64) -> Option<Value> {
        let resp = self
            .call(json!({ "action": "poll", "waitSecs": wait_secs }))
            .await;
        (resp["action"] == "deliver").then_some(resp)
    }
}

/// Is `id` listed live?
/// Is `id` listed live? XA5 lists an instance parked here too, with status `parked`.
async fn listed(node: &Node, id: &str) -> bool {
    node.list()
        .await
        .iter()
        .any(|r| r["address"] == format!("{id}@{}", node_name()) && r["status"] == "live")
}

// =============================================================================
// Oracle 1 (A14). Claude fake X exits, and a send returns `queued`. When a new process
// presents X, the message is delivered once, carrying its send time: the second it was
// sent, not the second it was drained.
// Mutant: refuse a non-running instance => RED.
// Mutant: deliver again on the next observation => RED.
// Mutant: stamp the delivery time => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_1_queue_then_deliver_once_with_send_time() {
    let node = Node::start(Spec::default());
    let first = Sleeper::new();
    let in_first = inbox();
    claude_file(&node, "a", first.pid(), ID_X, "x", &in_first.sock);
    assert!(listed(&node, ID_X).await, "X is observed live");
    remove_file(&node, "a", first.pid());
    first.end();
    assert!(!listed(&node, ID_X).await, "X is no longer live");

    let before = xmsg::storage::now_epoch_secs();
    let (status, body) = node.send(ID_X, "queued-body").await;
    let after = xmsg::storage::now_epoch_secs();
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["outcome"], "queued", "{body}");
    assert_eq!(body["address"], format!("{ID_X}@{}", node_name()), "{body}");
    let message_id = body["message_id"].as_str().unwrap().to_string();
    assert!(in_first.matching("queued-body").is_empty());

    // The drain falls at least a second after the send, so a stamp taken at delivery
    // cannot pass for the send time.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // A new process presents X: the next observation drains the queue into it.
    let second = Sleeper::new();
    let in_second = inbox();
    claude_file(&node, "b", second.pid(), ID_X, "x", &in_second.sock);
    node.list().await;
    let got = in_second.wait_for("queued-body").await;
    assert_eq!(got.len(), 1, "delivered once: {got:?}");
    let sent: Vec<String> = (before..=after)
        .map(|t| format!("sent={}", xmsg::storage::utc_rfc3339(t)))
        .collect();
    assert!(
        sent.iter().any(|s| got[0].contains(s)),
        "the delivered message carries its send time ({sent:?}): {}",
        got[0]
    );
    assert!(got[0].contains(&format!("message_id={message_id}")));
    let (status, msg) = node
        .http("GET", &format!("/v1/messages/{message_id}"), None)
        .await;
    assert_eq!(status, 200, "{msg}");
    assert_eq!(msg["outcome"], "delivered", "{msg}");

    // Later observations deliver nothing again.
    node.list().await;
    node.list().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        in_second.matching("queued-body").len(),
        1,
        "a queued message is delivered once"
    );
}

// =============================================================================
// Oracle 2 (A14, D-1). With an injected short TTL, an expired message is not delivered,
// and X past its lifetime gives `not_found`.
// Mutant: no expiry => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_2_ttl_and_lifetime() {
    let node = Node::start(Spec {
        reply_ttl: Some(2),
        ..Default::default()
    });
    let (px, py) = (Sleeper::new(), Sleeper::new());
    let (inx, iny) = (inbox(), inbox());
    claude_file(&node, "x", px.pid(), ID_X, "x", &inx.sock);
    claude_file(&node, "y", py.pid(), ID_Y, "y", &iny.sock);
    node.list().await;
    remove_file(&node, "x", px.pid());
    remove_file(&node, "y", py.pid());
    px.end();
    py.end();
    node.list().await; // both released: their lifetimes start here

    // Within the lifetime, X queues.
    let (status, body) = node.send(ID_X, "expiring-body").await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["outcome"], "queued", "{body}");

    tokio::time::sleep(Duration::from_millis(3500)).await;

    // Past the TTL: Y, with no queue, is `not_found`.
    let (status, body) = node.send(ID_Y, "too-late").await;
    assert_eq!(status, 404, "Y past its lifetime: {body}");
    assert_eq!(body["error"], "not_found", "{body}");

    // X's expired message is not delivered when X is presented again.
    let again = Sleeper::new();
    let in_again = inbox();
    claude_file(&node, "x2", again.pid(), ID_X, "x", &in_again.sock);
    node.list().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        in_again.matching("expiring-body").is_empty(),
        "an expired message is dropped, not delivered"
    );
}

// =============================================================================
// Oracle 3 (AM-9, AM-10, D-4; HA8). An exited pi is parked and reclaimable (HA8: queues
// inside reply_ttl), an explicitly released pi gives `gone`, and an exited `X~2` gives
// `gone`.
// Mutant: queue a released pi or exited fork => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_3_exited_pi_and_fork_are_gone() {
    let node = Node::start(Spec::default());

    // pi: HA8 makes a plain exit detach (parked & reclaimable), while explicit release is gone.
    let (pi, resp) = Registration::open(
        &node.register_sock,
        json!({ "harness": "pi", "sessionName": "pi-a" }),
    )
    .await;
    let pi_id = resp["sessionId"].as_str().unwrap().to_string();
    let secret = resp["reclaim"].as_str().unwrap().to_string();
    let (status, body) = node.send(&pi_id, "to the live pi").await;
    assert_eq!(status, 202, "control, the live pi: {body}");
    drop(pi);
    for _ in 0..100 {
        if !listed(&node, &pi_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // HA8: a detached (exited) pi is parked inside reply_ttl and queues messages.
    let (status, body) = node.send(&pi_id, "to the detached pi").await;
    assert_eq!(status, 202, "a detached pi queues under HA8: {body}");
    assert_eq!(body["outcome"], "queued", "{body}");

    // Reclaim and explicitly release: a permanently released pi answers `gone`.
    let (mut pi2, _) = Registration::open(
        &node.register_sock,
        json!({ "harness": "pi", "sessionName": "pi-a", "reclaim": { "id": pi_id, "secret": secret } }),
    )
    .await;
    let rel = pi2.call(json!({ "action": "release" })).await;
    assert_eq!(rel["status"], "ok", "{rel}");
    drop(pi2);
    let (status, body) = node.send(&pi_id, "to the released pi").await;
    assert_eq!(status, 410, "a released pi: {body}");
    assert_eq!(body["error"], "gone", "{body}");

    // X~2: P1 holds X, P2 holds X~2, and P2 exits.
    let (p1, p2) = (Sleeper::new(), Sleeper::new());
    let (in1, in2) = (inbox(), inbox());
    claude_file(&node, "p1", p1.pid(), ID_X, "x", &in1.sock);
    node.list().await;
    claude_file(&node, "p2", p2.pid(), ID_X, "x", &in2.sock);
    let fork = format!("{ID_X}~2");
    assert!(listed(&node, &fork).await, "P2 holds X~2");
    remove_file(&node, "p2", p2.pid());
    p2.end();
    node.list().await;
    let (status, body) = node.send(&fork, "to the exited fork").await;
    assert_eq!(status, 410, "an exited X~2: {body}");
    assert_eq!(body["error"], "gone", "{body}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(in1.matching("to the exited fork").is_empty());
}

// =============================================================================
// Oracle 4 (A15). A child of Claude fake X posts to `http.sock`: its message is attributed
// to X and the reply to it is pushed into X. A process outside every tree is anonymous,
// and its `reply` is `denied`.
// Mutant: skip the walk => RED.
// Mutant: let anonymous callers reply => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_4_http_identity_by_ancestry() {
    let node = Node::start(Spec::default());
    let (fx, fr) = (FakeParent::spawn(CHILD), FakeParent::spawn(CHILD));
    let (inx, inr) = (inbox(), inbox());
    claude_file(&node, "x", fx.pid(), ID_X, "x-label", &inx.sock);
    claude_file(&node, "r", fr.pid(), ID_R, "r-label", &inr.sock);
    node.list().await;

    // X's child sends: attributed to X.
    let (status, body) = fx
        .request(
            &node.unix(),
            "POST",
            "/v1/messages",
            Some(&json!({ "to": ID_R, "from": "spoofed", "text": "from-x" })),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    let message_id = parse(&body)["message_id"].as_str().unwrap().to_string();
    let got = inr.wait_for("from-x").await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(
        from_name(&got[0]),
        format!("x-label · {ID_X}@{}", node_name()),
        "the sender is X, not its unattested from"
    );

    // R's child replies over http.sock: R may, and the reply is pushed into X.
    let (status, body) = fr
        .request(
            &node.unix(),
            "POST",
            &format!("/v1/messages/{message_id}/replies"),
            Some(&json!({ "text": "answer-to-x" })),
        )
        .await;
    assert_eq!(status, 200, "R replies to what it received: {body}");
    let pushed = inx.wait_for("answer-to-x").await;
    assert_eq!(pushed.len(), 1, "the reply is pushed into X: {pushed:?}");

    // This test process is outside every tree: anonymous.
    let (status, body) = node.send(ID_R, "from-outside").await;
    assert_eq!(status, 202, "{body}");
    let got = inr.wait_for("from-outside").await;
    assert_eq!(
        from_name(&got[0]),
        format!("ci · anon@{}", node_name()),
        "an untraced caller is anonymous"
    );
    let (status, body) = node
        .http(
            "POST",
            &format!("/v1/messages/{message_id}/replies"),
            Some(json!({ "text": "anonymous-reply" })),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "denied", "{body}");
    let (_, replies) = node
        .http("GET", &format!("/v1/messages/{message_id}/replies"), None)
        .await;
    assert!(
        !replies.to_string().contains("anonymous-reply"),
        "an anonymous reply is never stored: {replies}"
    );
}

// =============================================================================
// Oracle 5 (AM-2). A caller on `--listen` is anonymous, even a child of Claude fake X. In
// leaf mode, it is the leaf principal.
// Mutant: attribute TCP callers by walk => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_5_tcp_callers() {
    for leaf in [false, true] {
        let mut spec = Spec {
            listen: true,
            leaf,
            ..Default::default()
        };
        if leaf {
            let (cert, key, _) = xmsg::fed::generate_self_signed_ed25519_pem("xa4-leaf").unwrap();
            spec.fed = Some((cert, key, "{}".to_string()));
        }
        let node = Node::start(spec);
        let fx = FakeParent::spawn(CHILD);
        let inx = inbox();
        let (pr, inr) = (Sleeper::new(), inbox());
        claude_file(&node, "x", fx.pid(), ID_X, "x-label", &inx.sock);
        claude_file(&node, "r", pr.pid(), ID_R, "r-label", &inr.sock);

        let text = format!("over-tcp-leaf-{leaf}");
        let (status, body) = fx
            .request(
                &node.tcp(),
                "POST",
                "/v1/messages",
                Some(&json!({ "to": ID_R, "from": "ci", "text": text })),
            )
            .await;
        assert_eq!(status, 202, "leaf={leaf}: {body}");
        let got = inr.wait_for(&text).await;
        assert_eq!(got.len(), 1, "leaf={leaf}: {got:?}");
        let from = from_name(&got[0]);
        if leaf {
            assert!(
                from.starts_with("matrix@"),
                "in leaf mode a TCP caller is the leaf principal: {from}"
            );
        } else {
            assert_eq!(
                from,
                format!("ci · anon@{}", node_name()),
                "a TCP caller is anonymous, whatever its ancestry"
            );
        }
    }
}

// =============================================================================
// Oracle 6 (A14). A bare ID that no process ever presented gives `not_found`, not
// `queued`.
// Mutant: queue it => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_6_never_listed_is_not_found() {
    let node = Node::start(Spec::default());
    let (status, body) = node.send(ID_NEVER, "to nobody").await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"], "not_found", "{body}");

    // A later process presenting it receives nothing.
    let p = Sleeper::new();
    let inp = inbox();
    claude_file(&node, "n", p.pid(), ID_NEVER, "n", &inp.sock);
    node.list().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(inp.matching("to nobody").is_empty());
}

// =============================================================================
// Oracle 7 (gate v0 C8). With `principals = ["anon:ci"]`, an anonymous sender with
// `from = "ci"` is admitted and one with `from = "x"` is refused.
// Mutant: match the filter against the label instead of the principal => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_7_filter_names_the_anonymous_principal() {
    use xmsg::fed::{generate_self_signed_ed25519_pem, normalize_pin};
    let (s_cert, s_key, s_pin) = generate_self_signed_ed25519_pem("s").unwrap();
    let (r_cert, r_key, r_pin) = generate_self_signed_ed25519_pem("r").unwrap();
    let (s_fed, r_fed) = (free_port(), free_port());
    let s_peers = json!({ "r": {
        "address": format!("127.0.0.1:{r_fed}"), "pin": normalize_pin(&r_pin),
        "allow": ["send", "reply"],
    }});
    let r_peers = json!({ "s": {
        "address": format!("127.0.0.1:{s_fed}"), "pin": normalize_pin(&s_pin),
        "allow": ["send", "reply"], "principals": ["anon:ci"],
    }});
    let r = Node::start(Spec {
        services: vec!["worker".to_string()],
        fed: Some((r_cert, r_key, r_peers.to_string())),
        fed_listen: Some(r_fed),
        ..Default::default()
    });
    let s = Node::start(Spec {
        fed: Some((s_cert, s_key, s_peers.to_string())),
        fed_listen: Some(s_fed),
        ..Default::default()
    });
    // The service registers on R; this process stays untraced on S.
    let (mut worker, _) = Registration::open(
        &r.register_sock,
        json!({ "harness": "svc", "name": "worker" }),
    )
    .await;

    let (status, body) = s
        .http(
            "POST",
            "/v1/messages",
            Some(json!({ "to": "worker@r", "from": "ci", "text": "from-ci" })),
        )
        .await;
    assert_eq!(status, 202, "anon:ci is admitted: {body}");
    let d = worker.poll(5).await.expect("delivered");
    assert_eq!(d["text"], "from-ci", "{d}");

    let (status, body) = s
        .http(
            "POST",
            "/v1/messages",
            Some(json!({ "to": "worker@r", "from": "x", "text": "from-x" })),
        )
        .await;
    assert_eq!(status, 403, "anon:x is refused: {body}");
    assert_eq!(body["error"], "denied", "{body}");
}

// =============================================================================
// Oracle 8 (D-2, A14). Process P presents X, switches to Y, and returns to X. The return is
// a new observation: P holds X again, the message queued while P was on Y is delivered to
// P, and a send to X while P presents it is delivered to P once.
// Mutant: count released rows as observed => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_8_return_to_x_is_observed_again() {
    let node = Node::start(Spec::default());
    let p = Sleeper::new();
    let inp = inbox();
    claude_file(&node, "p", p.pid(), ID_X, "x", &inp.sock);
    assert!(listed(&node, ID_X).await, "P holds X");

    claude_file(&node, "p", p.pid(), ID_Y, "y", &inp.sock);
    assert!(!listed(&node, ID_X).await, "P left X");
    let (status, body) = node.send(ID_X, "while-on-y").await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["outcome"], "queued", "{body}");

    claude_file(&node, "p", p.pid(), ID_X, "x", &inp.sock);
    assert!(listed(&node, ID_X).await, "P back on X holds X");
    let got = inp.wait_for("while-on-y").await;
    assert_eq!(
        got.len(),
        1,
        "the message queued while P was on Y reaches P: {got:?}"
    );

    let (status, body) = node.send(ID_X, "while-back-on-x").await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["outcome"], "delivered", "{body}");
    let got = inp.wait_for("while-back-on-x").await;
    assert_eq!(got.len(), 1, "delivered to P once: {got:?}");
}

// =============================================================================
// Oracle 9 (D-2, D-4, D-5). P presents X and switches to Y; Q then takes plain X; P returns
// to X and is a new observation behind a live holder, so it gets `X~2`. Q keeps plain X,
// and a call on `http.sock` from P's child is attributed to `X~2`, never to plain X.
// Mutant: count released rows as observed => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_9_return_behind_a_new_holder_is_a_fork() {
    let node = Node::start(Spec::default());
    let p = FakeParent::spawn(CHILD);
    let q = Sleeper::new();
    let (r, inr) = (Sleeper::new(), inbox());
    let (inp, inq) = (inbox(), inbox());
    claude_file(&node, "r", r.pid(), ID_R, "r", &inr.sock);
    claude_file(&node, "p", p.pid(), ID_X, "x", &inp.sock);
    assert!(listed(&node, ID_X).await, "P holds X");
    claude_file(&node, "p", p.pid(), ID_Y, "y", &inp.sock);
    node.list().await;
    claude_file(&node, "q", q.pid(), ID_X, "x", &inq.sock);
    assert!(listed(&node, ID_X).await, "Q holds X");
    claude_file(&node, "p", p.pid(), ID_X, "x", &inp.sock);
    let fork = format!("{ID_X}~2");
    assert!(listed(&node, &fork).await, "P back on X holds X~2");

    // Q stays plain X, and P is X~2.
    let (status, body) = node.send(ID_X, "to-plain-x").await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["outcome"], "delivered", "{body}");
    assert_eq!(inq.wait_for("to-plain-x").await.len(), 1, "Q holds plain X");
    assert!(inp.matching("to-plain-x").is_empty(), "P is not plain X");
    let (status, body) = node.send(&fork, "to-the-fork").await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(inp.wait_for("to-the-fork").await.len(), 1, "P holds X~2");

    // P's child calls http.sock: attributed to X~2.
    let (status, body) = p
        .request(
            &node.unix(),
            "POST",
            "/v1/messages",
            Some(&json!({ "to": ID_R, "from": "spoofed", "text": "from-p" })),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    let got = inr.wait_for("from-p").await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(
        from_name(&got[0]),
        format!("x · {fork}@{}", node_name()),
        "P acts as X~2, not as plain X"
    );
}

// =============================================================================
// Oracle 10 (A14). A session file names Y for a process that died before any request
// observed it: Y was never listed, so a send is `not_found`, as for an ID no file names.
// Mutant: answer `gone` from the dead session file => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_10_dead_file_never_observed_is_not_found() {
    let node = Node::start(Spec::default());
    let p = Sleeper::new();
    let inp = inbox();
    claude_file(&node, "d", p.pid(), ID_Y, "y", &inp.sock);
    p.end();
    let (status, body) = node.send(ID_Y, "to-dead-file").await;
    assert_eq!(status, 404, "a dead file never observed: {body}");
    assert_eq!(body["error"], "not_found", "{body}");
    let (status, body) = node.send(ID_NEVER, "control").await;
    assert_eq!(status, 404, "control, an ID no file names: {body}");
    assert_eq!(body["error"], "not_found", "{body}");
}

// =============================================================================
// Oracle 11 (A15). A registered service's own process calls `http.sock`: the caller is
// the service, found at the first step of the walk.
// Mutant: start the walk at the caller's parent => RED.
// =============================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oracle_11_service_process_is_the_service() {
    let node = Node::start(Spec {
        services: vec!["asker".to_string()],
        ..Default::default()
    });
    let (r, inr) = (Sleeper::new(), inbox());
    claude_file(&node, "r", r.pid(), ID_R, "r", &inr.sock);
    // This test process registers as the service, then calls http.sock itself.
    let (_asker, _) = Registration::open(
        &node.register_sock,
        json!({ "harness": "svc", "name": "asker" }),
    )
    .await;
    let (status, body) = node.send(ID_R, "from-the-service").await;
    assert_eq!(status, 202, "{body}");
    let got = inr.wait_for("from-the-service").await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(
        from_name(&got[0]),
        format!("asker@{}", node_name()),
        "the service's own process is the service"
    );
}
