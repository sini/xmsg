use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use xmsg::http::{build_router, AppState};

fn get_self_proc_start() -> String {
    xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), std::process::id())
        .expect("live starttime")
}

struct X10Harness {
    _sess_dir: Option<TempDir>,
    _sock_dir: Option<TempDir>,
    pub base_url: String,
    pub agent_sock_path: PathBuf,
    pub db: Arc<std::sync::Mutex<rusqlite::Connection>>,
    pub received_lines: Arc<Mutex<Vec<String>>>,
    pub stop_signal: Arc<AtomicBool>,
    pub server_task: tokio::task::JoinHandle<()>,
    pub agent_server_task: tokio::task::JoinHandle<()>,
}

impl Drop for X10Harness {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        self.server_task.abort();
        self.agent_server_task.abort();
    }
}

async fn start_harness(db_path: Option<PathBuf>) -> X10Harness {
    let sess_dir = tempdir().expect("tempdir for sessions");
    let sock_dir = tempdir().expect("tempdir for socket");
    fs::set_permissions(sock_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let received_lines = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));

    let sock_path = sock_dir.path().join("inbox.sock");
    setup_mock_socket(&sock_path, received_lines.clone(), stop_signal.clone());
    setup_session_file(sess_dir.path(), &sock_path);

    let agent_sock_path = sock_dir.path().join("agent.sock");
    let (base_url, db, server_task, agent_server_task) =
        start_server(sess_dir.path(), Some(agent_sock_path.clone()), db_path).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    X10Harness {
        _sess_dir: Some(sess_dir),
        _sock_dir: Some(sock_dir),
        base_url,
        agent_sock_path,
        db,
        received_lines,
        stop_signal,
        server_task,
        agent_server_task,
    }
}

fn setup_session_file(sess_path: &Path, sock_path: &Path) {
    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();
    let live_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "live-session-1234",
            "name": "target-worker",
            "cwd": "/workspace/project-a",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "{}"
        }}"#,
        sock_path.display()
    );
    fs::write(sess_path.join(format!("{my_pid}.json")), live_json).unwrap();
}

fn setup_mock_socket(
    sock_path: &Path,
    received_lines: Arc<Mutex<Vec<String>>>,
    stop_signal: Arc<AtomicBool>,
) {
    if sock_path.exists() {
        let _ = fs::remove_file(sock_path);
    }
    let listener = UnixListener::bind(sock_path).expect("bind unix socket");
    tokio::spawn(async move {
        while !stop_signal.load(Ordering::Relaxed) {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((mut stream, _)) = res {
                        let mut buf = Vec::new();
                        let mut temp = [0u8; 1024];
                        while let Ok(n) = stream.read(&mut temp).await {
                            if n == 0 { break; }
                            buf.extend_from_slice(&temp[..n]);
                            if buf.ends_with(b"\n") {
                                break;
                            }
                        }
                        if let Ok(s) = String::from_utf8(buf) {
                            received_lines.lock().await.push(s);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    });
}

async fn start_server(
    sess_path: &Path,
    agent_sock_path: Option<PathBuf>,
    db_path: Option<PathBuf>,
) -> (
    String,
    Arc<std::sync::Mutex<rusqlite::Connection>>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let conn = if let Some(ref path) = db_path {
        rusqlite::Connection::open(path).unwrap()
    } else {
        rusqlite::Connection::open_in_memory().unwrap()
    };
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(std::sync::Mutex::new(conn));
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);

    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sess_path.to_path_buf()],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: sess_path.join("presence"),
            proc_locks_path: sess_path.join("proc_locks"),
            proc_root: PathBuf::from(xmsg::process::LIVE_PROC_ROOT),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl: Duration::from_secs(604800),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let app = build_router(app_state.clone());
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let server_task = tokio::spawn(async move {
        let _ = axum::serve(tcp_listener, app).await;
    });

    let agent_task = if let Some(p) = agent_sock_path {
        let my_uid = xmsg::agy::current_uid();
        let s_state = app_state.clone();
        tokio::spawn(async move {
            if let Err(e) = xmsg::agent::run_agent_server(p, s_state, my_uid).await {
                eprintln!("run_agent_server error: {e}");
            }
        })
    } else {
        tokio::spawn(async move {})
    };

    (base_url, db, server_task, agent_task)
}

/// Oracle 1: Send twice with one key => one delivery, the same messageId.
/// Mutant 1: Ignore the idempotency key => two deliveries => RED.
#[tokio::test]
async fn test_oracle_1_send_twice_one_key_one_delivery() {
    let harness = start_harness(None).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/sessions/target-worker/messages", harness.base_url);

    let payload = serde_json::json!({
        "from": "sender-alpha",
        "text": "deterministic payload",
        "idempotency_key": "x10-key-oracle-1"
    });

    // Send 1: initial delivery
    let res1 = client.post(&url).json(&payload).send().await.unwrap();
    assert_eq!(res1.status(), reqwest::StatusCode::ACCEPTED);
    let json1: serde_json::Value = res1.json().await.unwrap();
    let msg_id1 = json1["messageId"]
        .as_str()
        .expect("messageId in response")
        .to_string();
    assert!(!msg_id1.is_empty());

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.received_lines.lock().await.len(),
        1,
        "First send must deliver exactly one message"
    );

    // Send 2: duplicate send with exact same key and body
    let res2 = client.post(&url).json(&payload).send().await.unwrap();
    assert_eq!(res2.status(), reqwest::StatusCode::ACCEPTED);
    let json2: serde_json::Value = res2.json().await.unwrap();
    let msg_id2 = json2["messageId"].as_str().expect("messageId in response");

    assert_eq!(
        msg_id1, msg_id2,
        "Duplicate send must return original messageId"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.received_lines.lock().await.len(),
        1,
        "Duplicate send must NOT perform a second delivery"
    );
}

/// Oracle 2: The same key with a different body => 409 Conflict.
/// Mutant 2: Accept it or ignore body mismatch => RED.
#[tokio::test]
async fn test_oracle_2_same_key_different_body_409() {
    let harness = start_harness(None).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/sessions/target-worker/messages", harness.base_url);

    let payload1 = serde_json::json!({
        "from": "sender-alpha",
        "text": "first body",
        "idempotency_key": "x10-key-oracle-2"
    });

    let res1 = client.post(&url).json(&payload1).send().await.unwrap();
    assert_eq!(res1.status(), reqwest::StatusCode::ACCEPTED);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(harness.received_lines.lock().await.len(), 1);

    // Send 2: same key, different body
    let payload2 = serde_json::json!({
        "from": "sender-alpha",
        "text": "second conflicting body",
        "idempotency_key": "x10-key-oracle-2"
    });

    let res2 = client.post(&url).json(&payload2).send().await.unwrap();
    assert_eq!(
        res2.status(),
        reqwest::StatusCode::CONFLICT,
        "Sending same key with different body must return 409 Conflict"
    );

    let json2: serde_json::Value = res2.json().await.unwrap();
    assert_eq!(json2["error"], "conflict");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.received_lines.lock().await.len(),
        1,
        "Conflicting send must NOT deliver any message"
    );
}

/// Oracle 3: Different principals with one key => independent deliveries with distinct messageIds.
/// Mutant 3: A global key space => collision/conflict across principals => RED.
#[tokio::test]
async fn test_oracle_3_different_principals_independent() {
    let harness = start_harness(None).await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/sessions/target-worker/messages", harness.base_url);

    let payload_alice = serde_json::json!({
        "from": "alice",
        "text": "message from alice",
        "idempotency_key": "shared-client-key"
    });

    let res_alice = client.post(&url).json(&payload_alice).send().await.unwrap();
    assert_eq!(res_alice.status(), reqwest::StatusCode::ACCEPTED);
    let json_alice: serde_json::Value = res_alice.json().await.unwrap();
    let msg_id_alice = json_alice["messageId"].as_str().unwrap().to_string();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(harness.received_lines.lock().await.len(), 1);

    // Bob sends with the SAME key but his own identity (and different text)
    let payload_bob = serde_json::json!({
        "from": "bob",
        "text": "message from bob",
        "idempotency_key": "shared-client-key"
    });

    let res_bob = client.post(&url).json(&payload_bob).send().await.unwrap();
    assert_eq!(
        res_bob.status(),
        reqwest::StatusCode::ACCEPTED,
        "Different principal with same key must succeed independently"
    );
    let json_bob: serde_json::Value = res_bob.json().await.unwrap();
    let msg_id_bob = json_bob["messageId"].as_str().unwrap().to_string();

    assert_ne!(
        msg_id_alice, msg_id_bob,
        "Different principals must receive distinct messageIds"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.received_lines.lock().await.len(),
        2,
        "Both principals must have their messages delivered"
    );
}

/// Oracle 4: Survives a server restart within the retention window (persisted in SQLite).
/// Mutant 4: In-memory table => lost after restart => second delivery on replay => RED.
#[tokio::test]
async fn test_oracle_4_survives_server_restart_persisted() {
    let temp_db_dir = tempdir().expect("tempdir for sqlite");
    let db_path = temp_db_dir.path().join("idempotency.sqlite");

    let sess_dir = tempdir().expect("tempdir for sessions");
    let sock_dir = tempdir().expect("tempdir for socket");
    let sock_path = sock_dir.path().join("inbox.sock");

    let received_lines = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));

    setup_mock_socket(&sock_path, received_lines.clone(), stop_signal.clone());
    setup_session_file(sess_dir.path(), &sock_path);

    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "from": "persisted-sender",
        "text": "payload to survive restart",
        "idempotency_key": "x10-persist-key"
    });

    // Server 1
    let original_msg_id = {
        let (base_url1, _, server_task1, agent_task1) =
            start_server(sess_dir.path(), None, Some(db_path.clone())).await;
        let url1 = format!("{}/v1/sessions/target-worker/messages", base_url1);

        let res1 = client.post(&url1).json(&payload).send().await.unwrap();
        assert_eq!(res1.status(), reqwest::StatusCode::ACCEPTED);
        let json1: serde_json::Value = res1.json().await.unwrap();
        let id = json1["messageId"].as_str().unwrap().to_string();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(received_lines.lock().await.len(), 1);

        // Terminate server 1
        server_task1.abort();
        agent_task1.abort();
        id
    };

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Server 2: starts using the same db_path and same sess_dir
    let (base_url2, _, server_task2, agent_task2) =
        start_server(sess_dir.path(), None, Some(db_path.clone())).await;
    let url2 = format!("{}/v1/sessions/target-worker/messages", base_url2);

    // Send duplicate to server 2: must return original messageId and deliver nothing
    let res2 = client.post(&url2).json(&payload).send().await.unwrap();
    assert_eq!(res2.status(), reqwest::StatusCode::ACCEPTED);
    let json2: serde_json::Value = res2.json().await.unwrap();
    let replayed_msg_id = json2["messageId"].as_str().unwrap();

    assert_eq!(
        replayed_msg_id, original_msg_id,
        "Replayed messageId after restart must match original messageId"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        received_lines.lock().await.len(),
        1,
        "Server 2 must NOT deliver duplicate message (total deliveries remains 1)"
    );

    // Also verify conflict check survives restart:
    let payload_conflict = serde_json::json!({
        "from": "persisted-sender",
        "text": "tampered body after restart",
        "idempotency_key": "x10-persist-key"
    });
    let res_conflict = client
        .post(&url2)
        .json(&payload_conflict)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res_conflict.status(),
        reqwest::StatusCode::CONFLICT,
        "Conflicting body after restart must still be rejected with 409 Conflict"
    );

    server_task2.abort();
    agent_task2.abort();
    stop_signal.store(true, Ordering::Relaxed);
}

/// Oracle 5: Attested session (agent.sock) and anonymous HTTP caller with identical idempotency key
/// are isolated by principal (session:<id> vs http:<from>) and do not collide or hijack keys.
#[tokio::test]
async fn test_oracle_5_attested_agent_and_anonymous_http_principal_isolation() {
    let harness = start_harness(None).await;

    // 1. Attested send via agent.sock
    let agent_stream = UnixStream::connect(&harness.agent_sock_path).await.unwrap();
    let (agent_r, mut agent_w) = agent_stream.into_split();
    let mut agent_reader = BufReader::new(agent_r);

    let agent_req = serde_json::json!({
        "action": "send",
        "ref": "target-worker",
        "text": "attested message body from agent",
        "idempotency_key": "cross-protocol-shared-key"
    });
    agent_w
        .write_all(format!("{agent_req}\n").as_bytes())
        .await
        .unwrap();

    let mut agent_line = String::new();
    agent_reader.read_line(&mut agent_line).await.unwrap();
    let agent_resp: serde_json::Value = serde_json::from_str(&agent_line).unwrap();
    assert_eq!(agent_resp["status"], "ok");
    let agent_msg_id = agent_resp["delivery"]["messageId"]
        .as_str()
        .expect("agent messageId")
        .to_string();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.received_lines.lock().await.len(),
        1,
        "Agent send delivered 1 message"
    );

    // 2. Anonymous HTTP send with identical key and declared from matching session
    let client = reqwest::Client::new();
    let http_url = format!("{}/v1/sessions/target-worker/messages", harness.base_url);
    let http_req = serde_json::json!({
        "from": "live-session-1234",
        "text": "anonymous http message body",
        "idempotency_key": "cross-protocol-shared-key"
    });

    let res_http = client.post(&http_url).json(&http_req).send().await.unwrap();
    assert_eq!(res_http.status(), reqwest::StatusCode::ACCEPTED);
    let http_json: serde_json::Value = res_http.json().await.unwrap();
    let http_msg_id = http_json["messageId"]
        .as_str()
        .expect("http messageId")
        .to_string();

    assert_ne!(
        agent_msg_id, http_msg_id,
        "Attested session and anonymous HTTP must receive distinct messageIds despite identical key"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.received_lines.lock().await.len(),
        2,
        "Both messages must be delivered independently"
    );

    // 3. Re-sending via agent.sock returns original agent_msg_id
    let agent_stream2 = UnixStream::connect(&harness.agent_sock_path).await.unwrap();
    let (agent_r2, mut agent_w2) = agent_stream2.into_split();
    let mut agent_reader2 = BufReader::new(agent_r2);
    agent_w2
        .write_all(format!("{agent_req}\n").as_bytes())
        .await
        .unwrap();

    let mut agent_line2 = String::new();
    agent_reader2.read_line(&mut agent_line2).await.unwrap();
    let agent_resp2: serde_json::Value = serde_json::from_str(&agent_line2).unwrap();
    assert_eq!(agent_resp2["status"], "ok");
    assert_eq!(
        agent_resp2["delivery"]["messageId"].as_str().unwrap(),
        agent_msg_id,
        "Agent replay must return original agent messageId"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.received_lines.lock().await.len(),
        2,
        "Agent duplicate must NOT produce additional delivery"
    );

    // 4. Re-sending via HTTP returns original http_msg_id
    let res_http_replay = client.post(&http_url).json(&http_req).send().await.unwrap();
    assert_eq!(res_http_replay.status(), reqwest::StatusCode::ACCEPTED);
    let http_replay_json: serde_json::Value = res_http_replay.json().await.unwrap();
    assert_eq!(
        http_replay_json["messageId"].as_str().unwrap(),
        http_msg_id,
        "HTTP replay must return original http messageId"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.received_lines.lock().await.len(),
        2,
        "HTTP duplicate must NOT produce additional delivery"
    );

    // 5. Conflicting HTTP body returns 409 Conflict without affecting agent record
    let http_conflict_req = serde_json::json!({
        "from": "live-session-1234",
        "text": "tampered conflicting http body",
        "idempotency_key": "cross-protocol-shared-key"
    });
    let res_conflict = client
        .post(&http_url)
        .json(&http_conflict_req)
        .send()
        .await
        .unwrap();
    assert_eq!(res_conflict.status(), reqwest::StatusCode::CONFLICT);

    // 6. Verify SQLite table has two independent records under distinct principals
    {
        let db = harness.db.lock().unwrap();
        let agent_rec = xmsg::storage::get_idempotency_record(
            &db,
            "session:live-session-1234",
            "cross-protocol-shared-key",
            86400,
        )
        .unwrap()
        .expect("agent idempotency record must exist under session:live-session-1234");
        assert_eq!(agent_rec.message_id, agent_msg_id);

        let http_from_name = http_json["fromName"].as_str().unwrap();
        let http_rec = xmsg::storage::get_idempotency_record(
            &db,
            &format!("http:{http_from_name}"),
            "cross-protocol-shared-key",
            86400,
        )
        .unwrap()
        .expect("http idempotency record must exist under http:<from_name>");
        assert_eq!(http_rec.message_id, http_msg_id);
    }
}
