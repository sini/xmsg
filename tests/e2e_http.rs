use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use xmsg::http::{build_router, AppState};
use xmsg::inbox::InboxLine;

fn get_self_proc_start() -> String {
    xmsg::process::starttime(
        std::path::Path::new(xmsg::process::LIVE_PROC_ROOT),
        std::process::id(),
    )
    .expect("live starttime")
}

struct TestHarness {
    _sess_dir: TempDir,
    _sock_dir: TempDir,
    base_url: String,
    received_lines: Arc<Mutex<Vec<String>>>,
    pub app_state: Arc<AppState>,
    stop_signal: Arc<AtomicBool>,
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

async fn start_harness(max_body: usize) -> TestHarness {
    let sess_dir = tempdir().expect("tempdir for sessions");
    let sock_dir = tempdir().expect("tempdir for socket");
    let sock_path = sock_dir.path().join("inbox.sock");

    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    let received_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = received_lines.clone();
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_signal.clone();

    tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
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
                            received_clone.lock().await.push(s);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    });

    // 1. Live session pointing to live socket
    let live_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "live-session-1234",
            "name": "my-worker",
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
    fs::write(sess_dir.path().join(format!("{my_pid}.json")), live_json).unwrap();

    // 2. Dead session (PID not running)
    let dead_json = r#"{
        "pid": 4194302,
        "sessionId": "dead-session-9999",
        "name": "dead-worker",
        "cwd": "/workspace/project-b",
        "status": "busy",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": "11111",
        "messagingSocketPath": "/tmp/dead.sock"
    }"#;
    fs::write(sess_dir.path().join("4194302.json"), dead_json).unwrap();

    // 3. Dead socket session (live PID, dead socket)
    let dead_sock_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "dead-sock-session",
            "name": "dead-sock-worker",
            "cwd": "/workspace/project-c",
            "status": "busy",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "/tmp/non-existent-xmsg-sock-12345.sock"
        }}"#
    );
    fs::write(sess_dir.path().join("dead_sock.json"), dead_sock_json).unwrap();

    // 4. Two live sessions with the same name "twin-worker" for 409 testing
    let twin1_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "twin-1111",
            "name": "twin-worker",
            "cwd": "/workspace/twin1",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "{}"
        }}"#,
        sock_path.display()
    );
    fs::write(sess_dir.path().join("twin1.json"), twin1_json).unwrap();

    let twin2_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "twin-2222",
            "name": "twin-worker",
            "cwd": "/workspace/twin2",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "{}"
        }}"#,
        sock_path.display()
    );
    fs::write(sess_dir.path().join("twin2.json"), twin2_json).unwrap();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);

    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let app_state = Arc::new(AppState {
        sessions_dirs: vec![sess_dir.path().to_path_buf()],
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: sess_dir.path().join("presence"),
            proc_locks_path: sess_dir.path().join("proc_locks"),
            proc_root: PathBuf::from("/proc"),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: Vec::new(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        host_label: "test-host".to_string(),
        max_body,
        request_counter: AtomicU64::new(1),
        db: Arc::new(std::sync::Mutex::new(conn)),
        notify_tx,
        reply_ttl: Duration::from_secs(604800),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let app = build_router(app_state.clone());
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(tcp_listener, app).await.unwrap();
    });

    TestHarness {
        _sess_dir: sess_dir,
        _sock_dir: sock_dir,
        base_url,
        received_lines,
        app_state,
        stop_signal,
    }
}

#[tokio::test]
async fn test_e2e_healthz_200() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/healthz", harness.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let health_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(health_val["status"], "ok");
    assert_eq!(health_val["sessions_dir"], "ok");
}

#[tokio::test]
async fn test_e2e_sessions_list_and_query_200() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    // Unfiltered list returns all live sessions (my-worker, dead-sock-worker, twin1, twin2)
    let res = client
        .get(format!("{}/v1/sessions", harness.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let sessions: Vec<serde_json::Value> = res.json().await.unwrap();
    assert_eq!(
        sessions.len(),
        4,
        "Dead sessions filtered out, 4 live remain"
    );

    // Filter by cwd
    let res = client
        .get(format!(
            "{}/v1/sessions?cwd=/workspace/project-a",
            harness.base_url
        ))
        .send()
        .await
        .unwrap();
    let filtered: Vec<serde_json::Value> = res.json().await.unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["sessionId"], "live-session-1234");

    // Filter by status
    let res = client
        .get(format!("{}/v1/sessions?status=busy", harness.base_url))
        .send()
        .await
        .unwrap();
    let filtered_status: Vec<serde_json::Value> = res.json().await.unwrap();
    assert_eq!(filtered_status.len(), 1);
    assert_eq!(filtered_status[0]["sessionId"], "dead-sock-session");
}

#[tokio::test]
async fn test_e2e_get_session_by_ref_200() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/v1/sessions/my-worker", harness.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let s_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(s_val["sessionId"], "live-session-1234");
    assert!(s_val.get("messagingSocketPath").is_none());
}

#[tokio::test]
async fn test_e2e_post_message_accepted_202() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let post_body = serde_json::json!({
        "from": "claude",
        "text": "hello from test"
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/my-worker/messages",
            harness.base_url
        ))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);
    let deliv: serde_json::Value = res.json().await.unwrap();
    assert_eq!(deliv["sessionId"], "live-session-1234");
    assert_eq!(deliv["fromName"], "xmsg@test-host · claude");

    tokio::time::sleep(Duration::from_millis(100)).await;
    let lines = harness.received_lines.lock().await;
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert!(line.ends_with('\n'));
    let parsed: InboxLine = serde_json::from_str(line).expect("valid wire line JSON");
    assert_eq!(parsed.r#type, "user");
    assert_eq!(parsed.message.role, "user");
    assert!(parsed.message.content.contains("hello from test"));
    assert!(parsed
        .message
        .content
        .contains("from-name=\"xmsg@test-host · claude\""));
}

#[tokio::test]
async fn test_e2e_post_message_dead_session_gone_410() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let post_body = serde_json::json!({
        "from": "claude",
        "text": "ping"
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/dead-worker/messages",
            harness.base_url
        ))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::GONE);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "gone");
}

#[tokio::test]
async fn test_e2e_post_message_unknown_session_not_found_404() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let post_body = serde_json::json!({
        "from": "claude",
        "text": "ping"
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/unknown-ref-xyz/messages",
            harness.base_url
        ))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "not_found");
}

#[tokio::test]
async fn test_e2e_post_message_ambiguous_conflict_409() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let post_body = serde_json::json!({
        "from": "claude",
        "text": "ping"
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/twin-worker/messages",
            harness.base_url
        ))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::CONFLICT);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "ambiguous");
}

#[tokio::test]
async fn test_e2e_post_message_unknown_field_bad_request_400() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let bad_field_body = serde_json::json!({
        "from": "claude",
        "text": "hi",
        "unknown_extra": 123
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/my-worker/messages",
            harness.base_url
        ))
        .json(&bad_field_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "bad_request");
}

#[tokio::test]
async fn test_e2e_post_message_empty_text_bad_request_400() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let empty_text_body = serde_json::json!({
        "from": "claude",
        "text": ""
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/my-worker/messages",
            harness.base_url
        ))
        .json(&empty_text_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "bad_request");
}

#[tokio::test]
async fn test_e2e_post_message_invalid_sender_bad_sender_400() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let bad_sender_body = serde_json::json!({
        "from": "   \"\" <> \t  ",
        "text": "valid text"
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/my-worker/messages",
            harness.base_url
        ))
        .json(&bad_sender_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "bad_sender");
}

#[tokio::test]
async fn test_e2e_post_message_body_too_large_413() {
    let harness = start_harness(256).await;
    let client = reqwest::Client::new();

    let huge_text = "a".repeat(500);
    let huge_body = serde_json::json!({
        "from": "claude",
        "text": huge_text
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/my-worker/messages",
            harness.base_url
        ))
        .json(&huge_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "payload_too_large");
}

#[tokio::test]
async fn test_e2e_post_message_inbox_unavailable_502() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    let post_body = serde_json::json!({
        "from": "claude",
        "text": "hi"
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/dead-sock-worker/messages",
            harness.base_url
        ))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_GATEWAY);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "inbox_unavailable");
}

#[tokio::test]
async fn test_e2e_post_message_reserved_session_prefix_400() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    // Red Demo 2 / C1: HTTP POST with from containing ':' or '/' returns 400 Bad Request (bad_sender)
    let res = client
        .post(format!(
            "{}/v1/sessions/my-worker/messages",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "from": "session:evil",
            "text": "spoofed session prefix"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "bad_sender");
    assert!(err_val["detail"].as_str().unwrap().contains(':'));

    // Also with session/
    let res = client
        .post(format!(
            "{}/v1/sessions/my-worker/messages",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "from": "session/evil",
            "text": "spoofed session slash prefix"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "bad_sender");
    assert!(err_val["detail"].as_str().unwrap().contains('/'));
}

#[tokio::test]
async fn test_e2e_post_message_pi_queue_full_503() {
    let harness = start_harness(65536).await;
    let client = reqwest::Client::new();

    // Register a Pi session in the pi_store using current live process
    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();
    let pi_session_id = format!("pi:{my_pid}:{my_proc_start}");
    {
        let mut store = harness.app_state.pi_store.write().unwrap();
        store.insert(
            pi_session_id.clone(),
            xmsg::pi::PiSessionInfo {
                pid: my_pid,
                session_id: pi_session_id.clone(),
                name: Some("pi-worker".to_string()),
                starttime: my_proc_start,
                registered_at: 1000,
                cwd: "/tmp".to_string(),
            },
        );
    }

    // Fill the Pi queue with 100 pending messages
    {
        let db = harness.app_state.db.lock().unwrap();
        for i in 0..100 {
            let msg = xmsg::storage::PiPendingMessage {
                id: format!("fill-{i}"),
                session_id: pi_session_id.clone(),
                created_at: 1000,
                from_name: "filler".to_string(),
                bytes: 4,
                text: "fill".to_string(),
                envelope: "env".to_string(),
                delivered_at: None,
            };
            xmsg::storage::insert_pi_message(&db, &msg).unwrap();
        }
    }

    // The 101st message over HTTP must return 503 Service Unavailable
    let res = client
        .post(format!(
            "{}/v1/sessions/pi-worker/messages",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "from": "alice",
            "text": "exceeding queue capacity"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "queue full must return 503 Service Unavailable"
    );
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "service_unavailable");
    assert!(err_val["detail"]
        .as_str()
        .unwrap()
        .contains("queue is full"));
}
