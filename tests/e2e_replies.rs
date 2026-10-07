use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use xmsg::http::{build_router, AppState, MessageDetailResponse};
use xmsg::inbox::{self, DeliveryResponse};
use xmsg::storage::ReplyRecord;

fn get_self_proc_start() -> String {
    let stat = fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    let rparen = stat.rfind(')').expect("closing paren in stat");
    let fields: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
    fields[19].to_string()
}

struct RepliesHarness {
    _sess_dir: TempDir,
    _sock_dir: TempDir,
    base_url: String,
    db: Arc<std::sync::Mutex<rusqlite::Connection>>,
    received_lines: Arc<Mutex<Vec<String>>>,
    stop_signal: Arc<AtomicBool>,
}

impl Drop for RepliesHarness {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

async fn start_replies_harness(reply_ttl: Duration) -> RepliesHarness {
    let sess_dir = tempdir().expect("tempdir for sessions");
    let sock_dir = tempdir().expect("tempdir for socket");
    let sock_path = sock_dir.path().join("recipient_inbox.sock");
    let other_sock_path = sock_dir.path().join("other_inbox.sock");

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

    // 1. Recipient session
    let recipient_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "sess-recipient-1111",
            "name": "recipient-worker",
            "cwd": "/workspace/recipient",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "{}"
        }}"#,
        sock_path.display()
    );
    fs::write(
        sess_dir.path().join(format!("{my_pid}.json")),
        recipient_json,
    )
    .unwrap();

    // 2. Another session for testing non-recipient 403
    let other_json = format!(
        r#"{{
            "pid": {my_pid},
            "sessionId": "sess-other-2222",
            "name": "other-worker",
            "cwd": "/workspace/other",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": "{my_proc_start}",
            "messagingSocketPath": "{}"
        }}"#,
        other_sock_path.display()
    );
    fs::write(sess_dir.path().join("other.json"), other_json).unwrap();

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(std::sync::Mutex::new(conn));
    let (notify_tx, _) = tokio::sync::broadcast::channel(16);

    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(16);
    let app_state = Arc::new(AppState {
        sessions_dir: sess_dir.path().to_path_buf(),
        agy_config: xmsg::agy::AgyConfig {
            presence_dir: sess_dir.path().join("presence"),
            proc_locks_path: sess_dir.path().join("proc_locks"),
            proc_root: PathBuf::from("/proc"),
            agy_bin: "agy".to_string(),
        },
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx,
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx,
        reply_ttl,
    });

    let app = build_router(app_state);
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(tcp_listener, app).await.unwrap();
    });

    RepliesHarness {
        _sess_dir: sess_dir,
        _sock_dir: sock_dir,
        base_url,
        db,
        received_lines,
        stop_signal,
    }
}

#[tokio::test]
async fn test_reply_roundtrip_and_envelope_footer() {
    let harness = start_replies_harness(Duration::from_secs(3600)).await;
    let client = reqwest::Client::new();

    // 1. Deliver message to recipient
    let post_msg_payload = serde_json::json!({
        "from": "orchestrator",
        "text": "Review pull request #42"
    });

    let res = client
        .post(format!(
            "{}/v1/sessions/recipient-worker/messages",
            harness.base_url
        ))
        .json(&post_msg_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);
    let delivery: DeliveryResponse = res.json().await.unwrap();
    assert_eq!(delivery.session_id, "sess-recipient-1111");
    assert_eq!(delivery.from_name, "xmsg@test-host · orchestrator");
    assert!(!delivery.message_id.is_empty());
    let message_id = delivery.message_id;

    // 2. Check stand-in socket received message with footer (§8.2)
    tokio::time::sleep(Duration::from_millis(50)).await;
    let lines = harness.received_lines.lock().await;
    assert_eq!(lines.len(), 1, "Stand-in socket received exactly 1 line");
    let raw_line = &lines[0];
    let inbox_line: inbox::InboxLine = serde_json::from_str(raw_line.trim()).unwrap();
    assert_eq!(inbox_line.r#type, "user");
    assert_eq!(inbox_line.message.role, "user");
    assert!(inbox_line
        .message
        .content
        .contains("from-name=\"xmsg@test-host · orchestrator\""));
    assert!(
        inbox_line
            .message
            .content
            .contains("Review pull request #42"),
        "Content contains original text"
    );
    let expected_footer = format!(
        "[xmsg] message_id={} — reply with the xmsg reply tool",
        message_id
    );
    assert!(
        inbox_line.message.content.contains(&expected_footer),
        "Content contains required envelope footer: {}",
        expected_footer
    );
    drop(lines);

    // 3. POST reply as recipient (§8.3)
    let reply_payload = serde_json::json!({
        "sessionRef": "sess-recipient-1111",
        "text": "PR #42 reviewed and accepted."
    });

    let res = client
        .post(format!(
            "{}/v1/messages/{}/replies",
            harness.base_url, message_id
        ))
        .json(&reply_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::CREATED);
    let reply: ReplyRecord = res.json().await.unwrap();
    assert_eq!(reply.seq, 1);
    assert_eq!(reply.message_id, message_id);
    assert_eq!(reply.replier_session_id, "sess-recipient-1111");
    assert_eq!(reply.text, "PR #42 reviewed and accepted.");

    // 4. GET /v1/messages/{id}/replies
    let res = client
        .get(format!(
            "{}/v1/messages/{}/replies",
            harness.base_url, message_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let replies: Vec<ReplyRecord> = res.json().await.unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0], reply);

    // 5. GET /v1/messages/{id}
    let res = client
        .get(format!("{}/v1/messages/{}", harness.base_url, message_id))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let detail: MessageDetailResponse = res.json().await.unwrap();
    assert_eq!(detail.id, message_id);
    assert_eq!(detail.session_id, "sess-recipient-1111");
    assert_eq!(detail.from_name, "xmsg@test-host · orchestrator");
    assert_eq!(detail.outcome, "delivered");
    assert_eq!(detail.replies.len(), 1);
    assert_eq!(detail.replies[0], reply);
}

#[tokio::test]
async fn test_reply_not_recipient_403() {
    let harness = start_replies_harness(Duration::from_secs(3600)).await;
    let client = reqwest::Client::new();

    // Deliver message to recipient
    let post_msg_payload = serde_json::json!({
        "from": "orchestrator",
        "text": "For recipient only"
    });
    let res = client
        .post(format!(
            "{}/v1/sessions/recipient-worker/messages",
            harness.base_url
        ))
        .json(&post_msg_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);
    let delivery: DeliveryResponse = res.json().await.unwrap();

    // Attempt reply from other-worker (different live session)
    let reply_payload = serde_json::json!({
        "sessionRef": "other-worker",
        "text": "Imposter attempting to reply"
    });

    let res = client
        .post(format!(
            "{}/v1/messages/{}/replies",
            harness.base_url, delivery.message_id
        ))
        .json(&reply_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "not_recipient");
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("is not the recipient"));
}

#[tokio::test]
async fn test_reply_error_conditions() {
    let harness = start_replies_harness(Duration::from_secs(3600)).await;
    let client = reqwest::Client::new();

    // 1. Reply to non-existent message ID -> 404
    let res = client
        .post(format!(
            "{}/v1/messages/01HXYZNONEXISTENT00000000/replies",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "sessionRef": "recipient-worker",
            "text": "Hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "not_found");

    // Deliver a valid message for remaining tests
    let res = client
        .post(format!(
            "{}/v1/sessions/recipient-worker/messages",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "from": "tester",
            "text": "Valid message"
        }))
        .send()
        .await
        .unwrap();
    let delivery: DeliveryResponse = res.json().await.unwrap();
    let valid_id = delivery.message_id;

    // 2. Reply with unknown sessionRef -> 404
    let res = client
        .post(format!(
            "{}/v1/messages/{valid_id}/replies",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "sessionRef": "unknown-nonexistent-session",
            "text": "Hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);

    // 3. Reply with empty text -> 400
    let res = client
        .post(format!(
            "{}/v1/messages/{valid_id}/replies",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "sessionRef": "recipient-worker",
            "text": ""
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "bad_request");

    // 4. Reply with extra JSON fields -> 400 (deny_unknown_fields)
    let res = client
        .post(format!(
            "{}/v1/messages/{valid_id}/replies",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "sessionRef": "recipient-worker",
            "text": "Hello",
            "unexpectedField": 123
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_long_poll_replies() {
    let harness = start_replies_harness(Duration::from_secs(3600)).await;
    let client = reqwest::Client::new();

    // 1. Deliver message
    let res = client
        .post(format!(
            "{}/v1/sessions/recipient-worker/messages",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "from": "orchestrator",
            "text": "Ping"
        }))
        .send()
        .await
        .unwrap();
    let delivery: DeliveryResponse = res.json().await.unwrap();
    let message_id = delivery.message_id;

    // 2. Non-existent message returns 404 immediately
    let res = client
        .get(format!(
            "{}/v1/messages/NONEXISTENT_MSG/replies?wait=5",
            harness.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);

    // 3. wait=0 returns immediately with []
    let start = Instant::now();
    let res = client
        .get(format!(
            "{}/v1/messages/{message_id}/replies?after=0&wait=0",
            harness.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let replies: Vec<ReplyRecord> = res.json().await.unwrap();
    assert!(replies.is_empty());
    assert!(start.elapsed() < Duration::from_millis(100));

    // 4. wait=1 times out with [] after ~1s
    let start = Instant::now();
    let res = client
        .get(format!(
            "{}/v1/messages/{message_id}/replies?after=0&wait=1",
            harness.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let replies: Vec<ReplyRecord> = res.json().await.unwrap();
    assert!(replies.is_empty());
    assert!(
        start.elapsed() >= Duration::from_millis(900),
        "Waited approximately 1s on timeout"
    );

    // 5. Long-poll wakes up immediately when reply arrives
    let base_url_clone = harness.base_url.clone();
    let msg_id_clone = message_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let c = reqwest::Client::new();
        let _ = c
            .post(format!(
                "{base_url_clone}/v1/messages/{msg_id_clone}/replies"
            ))
            .json(&serde_json::json!({
                "sessionRef": "recipient-worker",
                "text": "Waking up long poll waiter"
            }))
            .send()
            .await;
    });

    let start = Instant::now();
    let res = client
        .get(format!(
            "{}/v1/messages/{message_id}/replies?after=0&wait=10",
            harness.base_url
        ))
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let replies: Vec<ReplyRecord> = res.json().await.unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].text, "Waking up long poll waiter");
    assert!(
        elapsed < Duration::from_secs(3),
        "Woken promptly on reply broadcast (elapsed: {:?})",
        elapsed
    );
}

#[tokio::test]
async fn test_ttl_purge_on_reply() {
    let harness = start_replies_harness(Duration::from_secs(5)).await;
    let client = reqwest::Client::new();

    // Deliver message
    let res = client
        .post(format!(
            "{}/v1/sessions/recipient-worker/messages",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "from": "orchestrator",
            "text": "Test TTL"
        }))
        .send()
        .await
        .unwrap();
    let delivery: DeliveryResponse = res.json().await.unwrap();
    let message_id = delivery.message_id;

    // Manually insert an expired reply directly into SQLite
    {
        let db = harness.db.lock().unwrap();
        let expired_created_at = xmsg::storage::now_epoch_secs() - 100; // 100s old, TTL is 5s
        db.execute(
            "INSERT INTO replies (message_id, created_at, replier_session_id, text) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![message_id, expired_created_at, "sess-recipient-1111", "old expired reply"],
        )
        .unwrap();
    }

    // Verify expired reply is currently visible
    let res = client
        .get(format!(
            "{}/v1/messages/{message_id}/replies",
            harness.base_url
        ))
        .send()
        .await
        .unwrap();
    let replies: Vec<ReplyRecord> = res.json().await.unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].text, "old expired reply");

    // POST a new reply, which triggers purge (§8.3)
    let res = client
        .post(format!(
            "{}/v1/messages/{message_id}/replies",
            harness.base_url
        ))
        .json(&serde_json::json!({
            "sessionRef": "recipient-worker",
            "text": "brand new reply"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::CREATED);

    // Verify old reply is purged and only new reply remains
    let res = client
        .get(format!(
            "{}/v1/messages/{message_id}/replies",
            harness.base_url
        ))
        .send()
        .await
        .unwrap();
    let replies: Vec<ReplyRecord> = res.json().await.unwrap();
    assert_eq!(replies.len(), 1, "Old reply was purged by TTL");
    assert_eq!(replies[0].text, "brand new reply");
}
