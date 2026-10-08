use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use xmsg::agent::{current_uid, run_agent_server};
use xmsg::agy::{dev_major, dev_minor, new_agy_store, AgyConfig, AgyCredentials};
use xmsg::http::{build_router, AppState};
use xmsg::pi::{new_pi_store, PiSessionInfo};
use xmsg::storage;

fn get_self_proc_start() -> String {
    xmsg::process::starttime(
        std::path::Path::new(xmsg::process::LIVE_PROC_ROOT),
        std::process::id(),
    )
    .expect("live starttime")
}

fn get_proc_start_of(pid: u32) -> String {
    xmsg::process::starttime(std::path::Path::new(xmsg::process::LIVE_PROC_ROOT), pid)
        .expect("live starttime")
}

#[allow(dead_code)]
struct LiveMockSession {
    child: std::process::Child,
    pid: u32,
    proc_start: String,
    session_id: String,
    name: String,
    sock_path: PathBuf,
    rx: tokio::sync::mpsc::Receiver<String>,
}

impl Drop for LiveMockSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_live_session(
    sessions_dir: &Path,
    proc_root: &Path,
    sock_dir: &Path,
    session_id: &str,
    name: &str,
) -> LiveMockSession {
    let child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn sleep process");
    let pid = child.id();
    let proc_start = get_proc_start_of(pid);

    let sock_path = sock_dir.join(format!("inbox_{pid}.sock"));
    let listener = UnixListener::bind(&sock_path).unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(10);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut line = String::new();
            let mut reader = BufReader::new(&mut stream);
            let _ = reader.read_line(&mut line).await;
            let _ = tx.send(line).await;
        }
    });

    let json = serde_json::json!({
        "pid": pid,
        "sessionId": session_id,
        "name": name,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": proc_start,
        "messagingSocketPath": sock_path.display().to_string(),
    });
    fs::write(sessions_dir.join(format!("{pid}.json")), json.to_string()).unwrap();

    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        format!("{pid} (session) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {proc_start} 0 0\n"),
    )
    .unwrap();

    LiveMockSession {
        child,
        pid,
        proc_start,
        session_id: session_id.to_string(),
        name: name.to_string(),
        sock_path,
        rx,
    }
}

fn act_as_session(proc_root: &Path, my_pid: u32, my_proc_start: &str, session_pid: u32) {
    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        format!("{my_pid} (test) S {session_pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {my_proc_start} 0 0\n"),
    )
    .unwrap();
}

struct TestEnv {
    _tmp: tempfile::TempDir,
    agent_sock: PathBuf,
    sessions_dir: PathBuf,
    proc_root: PathBuf,
    presence_dir: PathBuf,
    proc_locks_path: PathBuf,
    http_url: String,
    db: Arc<Mutex<rusqlite::Connection>>,
    state: Arc<AppState>,
    my_pid: u32,
    my_proc_start: String,
}

async fn setup_test_env() -> TestEnv {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let sock_dir = tmp.path().join("xmsg");
    fs::create_dir_all(&sock_dir).unwrap();
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let agent_sock = sock_dir.join("agent.sock");
    let proc_root = tmp.path().join("proc");
    let sessions_dir = tmp.path().join("sessions");
    let presence_dir = tmp.path().join("presence");
    let proc_locks_path = tmp.path().join("locks");

    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::write(&proc_locks_path, "").unwrap();

    let my_pid = std::process::id();
    let my_uid = current_uid();
    let my_proc_start = get_self_proc_start();

    // Default proc stat for my_pid
    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        format!("{my_pid} (test) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {my_proc_start} 0 0\n"),
    )
    .unwrap();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));

    let (notify_tx, _) = broadcast::channel(16);
    let (pi_notify_tx, _) = broadcast::channel(16);

    let fake_agy_bin = tmp.path().join("fake_agy.sh");
    let script_content = r#"#!/bin/sh
exit 0
"#;
    fs::write(&fake_agy_bin, script_content).unwrap();
    fs::set_permissions(&fake_agy_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let agy_config = AgyConfig {
        presence_dir: presence_dir.clone(),
        proc_locks_path: proc_locks_path.clone(),
        proc_root: proc_root.clone(),
        agy_bin: fake_agy_bin.to_string_lossy().to_string(),
        trusted_agy_exes: Vec::new(),
    };

    let state = Arc::new(AppState {
        sessions_dir: sessions_dir.clone(),
        agy_config,
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(3600),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let s_path = agent_sock.clone();
    let s_state = state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(s_path, s_state, my_uid).await;
    });

    // Start HTTP server
    let app = build_router(state.clone());
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let http_url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(tcp_listener, app).await.unwrap();
    });

    // Wait for agent.sock to be bound
    for _ in 0..50 {
        if UnixStream::connect(&agent_sock).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    TestEnv {
        _tmp: tmp,
        agent_sock,
        sessions_dir,
        proc_root,
        presence_dir,
        proc_locks_path,
        http_url,
        db,
        state,
        my_pid,
        my_proc_start,
    }
}

async fn agent_rpc(agent_sock: &Path, payload: &serde_json::Value) -> serde_json::Value {
    let mut stream = UnixStream::connect(agent_sock)
        .await
        .expect("connect to agent.sock");
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    writer
        .write_all(format!("{payload}\n").as_bytes())
        .await
        .expect("write payload");

    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read response");
    serde_json::from_str(&line).expect("parse json response")
}

#[test]
fn test_u8_badge_formatting_invariants() {
    // 1. Pi registration with no name yields a badge with exactly one `pi:`
    let badge_no_name =
        xmsg::inbox::sanitize_attested_from("bitstream", "pi", "pi:3022755:61971591");
    assert_eq!(badge_no_name, "xmsg@bitstream · pi:3022755:61971591");

    // 2. Pi registration with cwd display name
    let badge_with_name = xmsg::inbox::sanitize_attested_from("bitstream", "pi", "nix-config");
    assert_eq!(badge_with_name, "xmsg@bitstream · pi:nix-config");

    // 3. Pi registration where name already had pi:
    let badge_prefixed = xmsg::inbox::sanitize_attested_from("bitstream", "pi", "pi:nix-config");
    assert_eq!(badge_prefixed, "xmsg@bitstream · pi:nix-config");

    // 4. Claude badge
    let badge_claude = xmsg::inbox::sanitize_attested_from("bitstream", "claude", "sess-123");
    assert_eq!(badge_claude, "xmsg@bitstream · claude:sess-123");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_u8_socket_mode_0600() {
    let env = setup_test_env().await;
    let meta = fs::metadata(&env.agent_sock).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o600,
        "agent.sock must be created with mode 0600 (srw-------)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_u8_attested_claude_round_trip_push_and_threading() {
    let env = setup_test_env().await;

    let mut session_a = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-a",
        "alice",
    );
    let mut session_b = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-b",
        "bob",
    );

    // 1. Act as Session A to send to Session B
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_a.pid,
    );

    let send_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "send",
            "ref": "sess-claude-b",
            "text": "Hello Bob from Alice",
        }),
    )
    .await;

    assert_eq!(send_resp["status"], "ok");
    let orig_msg_id = send_resp["delivery"]["messageId"]
        .as_str()
        .unwrap()
        .to_string();

    // Verify Session B received initial message on sock_b
    let line_b = tokio::time::timeout(Duration::from_secs(2), session_b.rx.recv())
        .await
        .unwrap()
        .unwrap();
    let b_msg: serde_json::Value = serde_json::from_str(&line_b).unwrap();
    let content_b = b_msg["message"]["content"].as_str().unwrap();
    assert!(content_b.contains("from-name=\"xmsg@test-host · claude:alice\""));
    assert!(content_b.contains("Hello Bob from Alice"));

    // Verify DB stored derived return address
    {
        let db = env.db.lock().unwrap();
        let rec = storage::get_message(&db, &orig_msg_id).unwrap().unwrap();
        assert_eq!(rec.return_harness.as_deref(), Some("claude"));
        assert_eq!(rec.return_session_id.as_deref(), Some("sess-claude-a"));
        assert!(rec.push_replies);
    }

    // 2. Act as Session B to reply to Session A
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_b.pid,
    );

    let reply_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": orig_msg_id,
            "text": "Hi Alice, loud and clear!",
        }),
    )
    .await;

    assert_eq!(reply_resp["status"], "ok");
    assert_eq!(reply_resp["reply"]["pushOutcome"], "pushed");
    let pushed_msg_id = reply_resp["reply"]["pushedMessageId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!pushed_msg_id.is_empty());
    assert_ne!(pushed_msg_id, orig_msg_id);

    // 3. Verify reply pushed into Session A's inbox socket with Bob's badge and reply header
    let line_a = tokio::time::timeout(Duration::from_secs(2), session_a.rx.recv())
        .await
        .unwrap()
        .unwrap();
    let a_msg: serde_json::Value = serde_json::from_str(&line_a).unwrap();
    let content_a = a_msg["message"]["content"].as_str().unwrap();
    assert!(content_a.contains("from-name=\"xmsg@test-host · claude:bob\""));
    let expected_header = format!(
        "[xmsg] reply to message_id={orig_msg_id} — message_id={pushed_msg_id}; reply with the xmsg reply tool\n\nHi Alice, loud and clear!"
    );
    assert!(content_a.contains(&expected_header));

    // 4. Verify pushed message record is stored in messages table and is repliable
    {
        let db = env.db.lock().unwrap();
        let pushed_rec = storage::get_message(&db, &pushed_msg_id).unwrap().unwrap();
        assert_eq!(pushed_rec.session_id, "sess-claude-a");
        assert_eq!(pushed_rec.recipient_harness, "claude");
        assert_eq!(pushed_rec.return_harness.as_deref(), Some("claude"));
        assert_eq!(
            pushed_rec.return_session_id.as_deref(),
            Some("sess-claude-b")
        );
        assert!(pushed_rec.push_replies);
        assert_eq!(pushed_rec.thread_id, orig_msg_id);
    }

    // 5. Conversational threading: Session A replies to pushed_msg_id!
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_a.pid,
    );

    let followup_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": pushed_msg_id,
            "text": "Great, conversation complete.",
        }),
    )
    .await;

    assert_eq!(followup_resp["status"], "ok");
    assert_eq!(followup_resp["reply"]["pushOutcome"], "pushed");
    let second_pushed_id = followup_resp["reply"]["pushedMessageId"]
        .as_str()
        .unwrap()
        .to_string();

    // Verify Session B receives the followup reply on sock_b
    let line_b2 = tokio::time::timeout(Duration::from_secs(2), session_b.rx.recv())
        .await
        .unwrap()
        .unwrap();
    let b_msg2: serde_json::Value = serde_json::from_str(&line_b2).unwrap();
    let content_b2 = b_msg2["message"]["content"].as_str().unwrap();
    assert!(content_b2.contains("from-name=\"xmsg@test-host · claude:alice\""));
    let expected_b_header = format!(
        "[xmsg] reply to message_id={pushed_msg_id} — message_id={second_pushed_id}; reply with the xmsg reply tool\n\nGreat, conversation complete."
    );
    assert!(content_b2.contains(&expected_b_header));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_u8_anonymous_http_no_push() {
    let env = setup_test_env().await;

    let session_b = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-b",
        "bob",
    );

    // 1. Anonymous HTTP POST /v1/sessions/{ref}/messages
    let client = reqwest::Client::new();
    let post_url = format!("{}/v1/sessions/sess-claude-b/messages", env.http_url);
    let post_resp = client
        .post(&post_url)
        .json(&serde_json::json!({
            "from": "anon-client",
            "text": "Hello from anonymous HTTP client"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(post_resp.status(), reqwest::StatusCode::ACCEPTED);
    let deliv: serde_json::Value = post_resp.json().await.unwrap();
    let anon_msg_id = deliv["messageId"].as_str().unwrap().to_string();

    // Verify DB stored no return address and push_replies = false
    {
        let db = env.db.lock().unwrap();
        let rec = storage::get_message(&db, &anon_msg_id).unwrap().unwrap();
        assert_eq!(rec.return_harness, None);
        assert_eq!(rec.return_session_id, None);
        assert!(!rec.push_replies);
    }

    // 2. Act as Session B to reply over agent.sock
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_b.pid,
    );

    let reply_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": anon_msg_id,
            "text": "Reply to anonymous",
        }),
    )
    .await;

    assert_eq!(reply_resp["status"], "ok");
    assert!(reply_resp["reply"]["pushOutcome"].is_null());
    assert!(reply_resp["reply"]["pushedMessageId"].is_null());

    // 3. HTTP GET /v1/messages/{id} returns the reply
    let get_url = format!("{}/v1/messages/{}", env.http_url, anon_msg_id);
    let get_resp = client.get(&get_url).send().await.unwrap();
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let detail: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(detail["replies"].as_array().unwrap().len(), 1);
    assert_eq!(detail["replies"][0]["text"], "Reply to anonymous");

    // 4. HTTP GET /v1/messages/{id}/replies returns the reply
    let rep_url = format!("{}/v1/messages/{}/replies", env.http_url, anon_msg_id);
    let rep_resp = client.get(&rep_url).send().await.unwrap();
    assert_eq!(rep_resp.status(), reqwest::StatusCode::OK);
    let replies: serde_json::Value = rep_resp.json().await.unwrap();
    assert_eq!(replies.as_array().unwrap().len(), 1);
    assert_eq!(replies[0]["text"], "Reply to anonymous");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_u8_strict_rejection_of_return_address_overrides() {
    let env = setup_test_env().await;

    let mut session_a = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-a",
        "alice",
    );
    let session_b = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-b",
        "bob",
    );
    let mut session_evil = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "evil-session",
        "evil",
    );

    // Act as Session A
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_a.pid,
    );

    // Attacker passes injected return address fields in payload
    let send_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "send",
            "ref": "sess-claude-b",
            "text": "Attempt spoofing return address",
            "return_to": "evil-session",
            "return_harness": "claude",
            "return_session_id": "evil-session",
            "returnAddress": "evil-session"
        }),
    )
    .await;

    assert_eq!(send_resp["status"], "ok");
    let msg_id = send_resp["delivery"]["messageId"]
        .as_str()
        .unwrap()
        .to_string();

    // Verify stored record derives return address ONLY from kernel-attested caller
    {
        let db = env.db.lock().unwrap();
        let rec = storage::get_message(&db, &msg_id).unwrap().unwrap();
        assert_eq!(rec.return_harness.as_deref(), Some("claude"));
        assert_eq!(rec.return_session_id.as_deref(), Some("sess-claude-a"));
        assert_ne!(rec.return_session_id.as_deref(), Some("evil-session"));
    }

    // Switch to Session B and reply
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_b.pid,
    );

    let reply_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": msg_id,
            "text": "Replying to original sender",
        }),
    )
    .await;

    assert_eq!(reply_resp["status"], "ok");
    assert_eq!(reply_resp["reply"]["pushOutcome"], "pushed");

    // Reply must arrive at Session A
    let line_a = tokio::time::timeout(Duration::from_secs(2), session_a.rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(line_a.contains("Replying to original sender"));

    // Evil socket must NEVER receive anything
    let evil_recvd = tokio::time::timeout(Duration::from_millis(100), session_evil.rx.recv()).await;
    assert!(
        evil_recvd.is_err(),
        "evil session must not receive pushed reply"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_u8_push_opt_out_disabled() {
    let env = setup_test_env().await;

    let mut session_a = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-a",
        "alice",
    );
    let session_b = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-b",
        "bob",
    );

    // Act as Session A and opt out of push replies
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_a.pid,
    );

    let send_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "send",
            "ref": "sess-claude-b",
            "text": "Poll-only request, do not push replies",
            "push_replies": false
        }),
    )
    .await;

    assert_eq!(send_resp["status"], "ok");
    let msg_id = send_resp["delivery"]["messageId"]
        .as_str()
        .unwrap()
        .to_string();

    {
        let db = env.db.lock().unwrap();
        let rec = storage::get_message(&db, &msg_id).unwrap().unwrap();
        assert!(!rec.push_replies);
        assert_eq!(rec.return_session_id.as_deref(), Some("sess-claude-a"));
    }

    // Switch to Session B and reply
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_b.pid,
    );

    let reply_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": msg_id,
            "text": "Here is the poll-only answer",
        }),
    )
    .await;

    assert_eq!(reply_resp["status"], "ok");
    assert_eq!(reply_resp["reply"]["pushOutcome"], "disabled");
    assert!(reply_resp["reply"]["pushedMessageId"].is_null());

    // Verify Session A inbox received nothing
    let recvd = tokio::time::timeout(Duration::from_millis(100), session_a.rx.recv()).await;
    assert!(
        recvd.is_err(),
        "no push must be delivered when push_replies is false"
    );

    // Verify stored reply has push_outcome = "disabled"
    {
        let db = env.db.lock().unwrap();
        let replies = storage::get_all_replies(&db, &msg_id).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].push_outcome.as_deref(), Some("disabled"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_u8_sender_gone_handling() {
    let env = setup_test_env().await;

    let mut session_a = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-a",
        "alice",
    );
    let session_b = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-b",
        "bob",
    );

    // Act as Session A to send
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_a.pid,
    );

    let send_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "send",
            "ref": "sess-claude-b",
            "text": "I will disappear before you reply",
        }),
    )
    .await;
    assert_eq!(send_resp["status"], "ok");
    let msg_id = send_resp["delivery"]["messageId"]
        .as_str()
        .unwrap()
        .to_string();

    // Now Session A terminates: kill child and remove session file
    let _ = session_a.child.kill();
    let _ = session_a.child.wait();
    let _ = fs::remove_file(env.sessions_dir.join(format!("{}.json", session_a.pid)));

    // Switch to Session B
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_b.pid,
    );

    // Session B replies
    let reply_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": msg_id,
            "text": "Are you still there?",
        }),
    )
    .await;

    assert_eq!(reply_resp["status"], "ok");
    assert_eq!(reply_resp["reply"]["pushOutcome"], "sender_gone");
    assert!(reply_resp["reply"]["pushedMessageId"].is_null());

    // Verify stored reply has push_outcome = "sender_gone"
    {
        let db = env.db.lock().unwrap();
        let replies = storage::get_all_replies(&db, &msg_id).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].push_outcome.as_deref(), Some("sender_gone"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_u8_cross_harness_push() {
    let env = setup_test_env().await;

    // 1. Setup Pi session
    let mut pi_child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let pi_pid = pi_child.id();
    let pi_proc_start = get_proc_start_of(pi_pid);

    let pi_pid_dir = env.proc_root.join(pi_pid.to_string());
    fs::create_dir_all(&pi_pid_dir).unwrap();
    fs::write(
        pi_pid_dir.join("stat"),
        format!("{pi_pid} (node) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {pi_proc_start} 0 0\n"),
    )
    .unwrap();
    fs::write(pi_pid_dir.join("cmdline"), "node\0pi.js\0").unwrap();

    let pi_session_id = format!("pi:{pi_pid}:{pi_proc_start}");
    env.state.pi_store.write().unwrap().insert(
        pi_session_id.clone(),
        PiSessionInfo {
            pid: pi_pid,
            starttime: pi_proc_start.clone(),
            session_id: pi_session_id.clone(),
            name: Some("pi-worker".to_string()),
            cwd: "/pi/workspace".to_string(),
            registered_at: 1000,
        },
    );

    // 2. Setup Claude session B
    let mut session_b = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-b",
        "bob",
    );

    // Act as Pi session
    act_as_session(&env.proc_root, env.my_pid, &env.my_proc_start, pi_pid);

    // Subscribe to Pi notify channel
    let mut pi_rx = env.state.pi_notify_tx.subscribe();

    // Pi sends to Claude
    let send_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "send",
            "ref": "sess-claude-b",
            "text": "Hello Claude from Pi",
        }),
    )
    .await;
    assert_eq!(send_resp["status"], "ok");
    let pi_msg_id = send_resp["delivery"]["messageId"]
        .as_str()
        .unwrap()
        .to_string();

    // Claude receives on sock_b
    let line_b = tokio::time::timeout(Duration::from_secs(2), session_b.rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(line_b.contains("pi:pi-worker"));

    // Switch our test process to Claude B
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_b.pid,
    );

    // Claude B replies to Pi message
    let reply_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": pi_msg_id,
            "text": "Hello Pi from Claude Bob",
        }),
    )
    .await;

    assert_eq!(reply_resp["status"], "ok");
    assert_eq!(reply_resp["reply"]["pushOutcome"], "pushed");
    let pushed_id = reply_resp["reply"]["pushedMessageId"].as_str().unwrap();

    // Verify Pi notification was triggered
    let notified_id = tokio::time::timeout(Duration::from_secs(2), pi_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(notified_id, pi_session_id);

    // Verify message is queued in pi_pending_messages
    {
        let db = env.db.lock().unwrap();
        let next_msg = storage::get_next_pending_pi_message(&db, &pi_session_id)
            .unwrap()
            .unwrap();
        assert_eq!(next_msg.id, pushed_id);
        assert!(next_msg.envelope.contains("[xmsg] reply to message_id="));
        assert!(next_msg.envelope.contains("Hello Pi from Claude Bob"));
    }

    let _ = pi_child.kill();
    let _ = pi_child.wait();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_u8_cross_harness_claude_to_agy() {
    let env = setup_test_env().await;

    // 1. Setup Claude session A
    let mut session_a = spawn_live_session(
        &env.sessions_dir,
        &env.proc_root,
        env._tmp.path(),
        "sess-claude-a",
        "alice",
    );

    // 2. Setup Agy session: conv-agy-88
    let mut agy_child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let agy_pid = agy_child.id();

    let conv_id = "conv-agy-88";
    let lock_file = env.presence_dir.join(format!("{conv_id}.lock"));
    fs::write(&lock_file, "lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let dev = meta.dev();
    let ino = meta.ino();
    let maj = dev_major(dev);
    let min = dev_minor(dev);

    let locks_content = format!(
        "1: FLOCK ADVISORY WRITE {agy_pid} {:02x}:{:02x}:{} 0 EOF\n",
        maj, min, ino
    );
    fs::write(&env.proc_locks_path, locks_content).unwrap();

    let agy_pid_dir = env.proc_root.join(agy_pid.to_string());
    fs::create_dir_all(&agy_pid_dir).unwrap();
    fs::write(
        agy_pid_dir.join("stat"),
        format!("{agy_pid} (agy) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5000 0 0\n"),
    )
    .unwrap();

    // Register credentials
    env.state.agy_store.write().unwrap().insert(
        conv_id.to_string(),
        xmsg::agy::AgySessionInfo::new(
            conv_id.to_string(),
            agy_pid,
            "5000".to_string(),
            Some(AgyCredentials {
                ls_address: "127.0.0.1:8888".to_string(),
                csrf_token: "csrf-8888".to_string(),
                is_stale: false,
            }),
        ),
    );

    // Act as Claude Session A to send to Agy
    act_as_session(
        &env.proc_root,
        env.my_pid,
        &env.my_proc_start,
        session_a.pid,
    );

    let send_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "send",
            "ref": conv_id,
            "text": "Hello Antigravity from Claude",
        }),
    )
    .await;

    assert_eq!(send_resp["status"], "ok");
    let msg_id = send_resp["delivery"]["messageId"]
        .as_str()
        .unwrap()
        .to_string();

    // Act as Agy holder PID
    act_as_session(&env.proc_root, env.my_pid, &env.my_proc_start, agy_pid);

    // Agy session replies over agent.sock
    let reply_resp = agent_rpc(
        &env.agent_sock,
        &serde_json::json!({
            "action": "reply",
            "messageId": msg_id,
            "text": "Hello Claude from Antigravity",
        }),
    )
    .await;

    assert_eq!(reply_resp["status"], "ok");
    assert_eq!(reply_resp["reply"]["pushOutcome"], "pushed");

    // Verify Claude Session A received the reply push on sock_a
    let line_a = tokio::time::timeout(Duration::from_secs(2), session_a.rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(line_a.contains("agy:conv-agy-88"));
    assert!(line_a.contains("Hello Claude from Antigravity"));

    let _ = agy_child.kill();
    let _ = agy_child.wait();
}
