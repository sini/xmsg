//! The sender label's length bound applies only to the self-described part. The attested
//! part, `xmsg@<node>`, is always emitted whole, however long the node's name is (A12:
//! "the `id@node` part is attested by xmsg"). xmsg main CI run 38337329244 found the
//! whole-string cap of 64 cutting a macOS builder's long host name.
//!
//! Mutant: cap the whole string at 64 characters, as before => RED in both cells.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use xmsg::http::{build_router, AppState};
use xmsg::inbox::{InboxLine, LABEL_MAX_CHARS};

/// 71 characters, longer than the old whole-string cap on its own.
const LONG_NODE: &str = "sini.nixbld1-sjc22-bm205-5ce612a9-0000-4000-8000-6eea321d9c20-long-name";

struct Node {
    _dirs: (TempDir, TempDir),
    base_url: String,
    agent_sock: PathBuf,
    received: Arc<Mutex<Vec<String>>>,
}

/// An in-process node named `LONG_NODE`, with this test process as a live Claude session
/// named `caller_name` whose inbox records every delivered line.
async fn start(caller_name: &str) -> Node {
    let sess_dir = tempdir().unwrap();
    let sock_dir = tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(sock_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let inbox_path = sock_dir.path().join("inbox.sock");
    let agent_sock = sock_dir.path().join("agent.sock");

    let listener = UnixListener::bind(&inbox_path).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf).await;
            rx.lock().unwrap().push(buf);
        }
    });

    let pid = std::process::id();
    let proc_start =
        xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    let session = serde_json::json!({
        "pid": pid,
        "sessionId": "e2397278-8044-5bdd-a840-de1665aa1599",
        "name": caller_name,
        "cwd": "/w",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1,
        "updatedAt": 2,
        "procStart": proc_start,
        "messagingSocketPath": inbox_path.display().to_string(),
    });
    fs::write(
        sess_dir.path().join(format!("{pid}.json")),
        session.to_string(),
    )
    .unwrap();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let state = Arc::new(AppState {
        sessions_dirs: vec![sess_dir.path().to_path_buf()],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: sess_dir.path().join("presence"),
            proc_locks_path: sess_dir.path().join("proc_locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
                brain_dir: std::path::PathBuf::new(),
    },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        node_name: LONG_NODE.to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: Arc::new(std::sync::Mutex::new(conn)),
        notify_tx: tokio::sync::broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(600),
        idempotency_ttl: Duration::from_secs(600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(8)),
        fed_state: None,
    });

    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://127.0.0.1:{}", tcp.local_addr().unwrap().port());
    let app = build_router(state.clone());
    tokio::spawn(async move {
        axum::serve(tcp, app).await.unwrap();
    });
    let (st, sock) = (state, agent_sock.clone());
    let uid = xmsg::agent::current_uid();
    tokio::spawn(async move {
        let _ = xmsg::agent::run_agent_server(sock, st, uid).await;
    });
    for _ in 0..3000 {
        if agent_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(agent_sock.exists(), "agent.sock never came up");

    Node {
        _dirs: (sess_dir, sock_dir),
        base_url,
        agent_sock,
        received,
    }
}

/// The `from-name` attribute of the one line the inbox received.
async fn received_from_name(node: &Node) -> String {
    for _ in 0..100 {
        if let Some(line) = node.received.lock().unwrap().first() {
            let parsed: InboxLine = serde_json::from_str(line).expect("inbox line");
            let content = parsed.message.content;
            let start = content.find("from-name=\"").expect("from-name") + "from-name=\"".len();
            let end = start + content[start..].find('"').expect("closing quote");
            return content[start..end].to_string();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing delivered");
}

/// Cell 1: an anonymous HTTP sender's label keeps the whole node name.
#[tokio::test]
async fn test_anonymous_label_keeps_long_node_name_whole() {
    let node = start("cap-caller").await;
    let res = reqwest::Client::new()
        .post(format!("{}/v1/messages", node.base_url))
        .json(&serde_json::json!({"to": "e2397278-8044-5bdd-a840-de1665aa1599",  "from": "a".repeat(200), "text": "hi" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);

    let from_name = received_from_name(&node).await;
    let attested = format!(" · anon@{LONG_NODE}");
    assert!(
        from_name.ends_with(&attested),
        "the attested node name must arrive whole: {from_name}"
    );
    assert_eq!(
        from_name[..from_name.len() - attested.len()],
        "a".repeat(LABEL_MAX_CHARS),
        "only the self-described label is bounded"
    );
}

/// Cell 2: an attested session sender's label keeps the whole node name.
#[tokio::test]
async fn test_attested_label_keeps_long_node_name_whole() {
    let caller_name = "b".repeat(200);
    let node = start(&caller_name).await;
    let stream = UnixStream::connect(&node.agent_sock).await.unwrap();
    let (r, mut w) = stream.into_split();
    let frame = serde_json::json!({ "action": "send", "to": "e2397278-8044-5bdd-a840-de1665aa1599", "text": "hi" });
    w.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await.unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["status"], "ok", "{resp}");

    let from_name = received_from_name(&node).await;
    let attested = format!(" · e2397278-8044-5bdd-a840-de1665aa1599@{LONG_NODE}");
    assert!(
        from_name.ends_with(&attested),
        "the attested node name must arrive whole: {from_name}"
    );
    assert_eq!(
        from_name[..from_name.len() - attested.len()],
        "b".repeat(LABEL_MAX_CHARS),
        "only the self-described label is bounded"
    );
}
