use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use xmsg::http::{build_router, AppState};
use xmsg::inbox::InboxLine;

fn get_self_proc_start() -> String {
    let stat = fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    let rparen = stat.rfind(')').expect("closing paren in stat");
    let fields: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
    fields[19].to_string()
}

#[tokio::test]
async fn test_e2e_http_server() {
    let sess_dir = tempdir().expect("tempdir for sessions");
    let sock_dir = tempdir().expect("tempdir for socket");
    let sock_path = sock_dir.path().join("inbox.sock");

    let my_pid = std::process::id();
    let my_proc_start = get_self_proc_start();

    // Setup mock Unix listener to act as target session inbox
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
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    });

    // Write live session file pointing to our socket
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

    // Write dead session file
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

    // Write dead socket session (live PID, but socket does not exist)
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

    // Start Axum server on random TCP port
    let app_state = Arc::new(AppState {
        sessions_dir: sess_dir.path().to_path_buf(),
        host_label: "test-host".to_string(),
        max_body: 512, // small limit to easily test 413
        request_counter: AtomicU64::new(1),
    });

    let app = build_router(app_state);
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(tcp_listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();

    // 1. GET /healthz
    let res = client.get(format!("{base_url}/healthz")).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let health_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(health_val["status"], "ok");
    assert_eq!(health_val["sessions_dir"], "ok");

    // 2. GET /v1/sessions
    let res = client.get(format!("{base_url}/v1/sessions")).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let sessions: Vec<serde_json::Value> = res.json().await.unwrap();
    assert_eq!(sessions.len(), 2, "Live sessions only");

    // 3. GET /v1/sessions with query filters
    let res = client
        .get(format!("{base_url}/v1/sessions?cwd=/workspace/project-a"))
        .send()
        .await
        .unwrap();
    let filtered: Vec<serde_json::Value> = res.json().await.unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["sessionId"], "live-session-1234");

    let res = client
        .get(format!("{base_url}/v1/sessions?status=busy"))
        .send()
        .await
        .unwrap();
    let filtered_status: Vec<serde_json::Value> = res.json().await.unwrap();
    assert_eq!(filtered_status.len(), 1);
    assert_eq!(filtered_status[0]["sessionId"], "dead-sock-session");

    // 4. GET /v1/sessions/{ref}
    let res = client
        .get(format!("{base_url}/v1/sessions/my-worker"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let s_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(s_val["sessionId"], "live-session-1234");
    assert!(s_val.get("messagingSocketPath").is_none());

    // 5. POST /v1/sessions/{ref}/messages - Happy path (202 Accepted)
    let post_body = serde_json::json!({
        "from": "claude",
        "text": "hello from test"
    });
    let res = client
        .post(format!("{base_url}/v1/sessions/my-worker/messages"))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);
    let deliv: serde_json::Value = res.json().await.unwrap();
    assert_eq!(deliv["sessionId"], "live-session-1234");
    assert_eq!(deliv["fromName"], "xmsg@test-host · claude");

    // Give unix listener a moment to receive
    tokio::time::sleep(Duration::from_millis(100)).await;
    let lines = received_lines.lock().await;
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert!(line.ends_with('\n'));
    let parsed: InboxLine = serde_json::from_str(line).expect("valid wire line JSON");
    assert_eq!(parsed.r#type, "user");
    assert_eq!(parsed.message.role, "user");
    assert!(parsed.message.content.contains("hello from test"));
    assert!(parsed.message.content.contains("from-name=\"xmsg@test-host · claude\""));
    drop(lines);

    // 6. POST to dead session -> 410 Gone
    let res = client
        .post(format!("{base_url}/v1/sessions/dead-worker/messages"))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::GONE);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "gone");

    // 7. POST to non-existent session -> 404 NotFound
    let res = client
        .post(format!("{base_url}/v1/sessions/unknown-ref-xyz/messages"))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "not_found");

    // 8. POST with unknown field -> 400 BadRequest
    let bad_field_body = serde_json::json!({
        "from": "claude",
        "text": "hi",
        "unknown_extra": 123
    });
    let res = client
        .post(format!("{base_url}/v1/sessions/my-worker/messages"))
        .json(&bad_field_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "bad_request");

    // 9. POST with empty text -> 400 BadRequest
    let empty_text_body = serde_json::json!({
        "from": "claude",
        "text": ""
    });
    let res = client
        .post(format!("{base_url}/v1/sessions/my-worker/messages"))
        .json(&empty_text_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "bad_request");

    // 10. POST with invalid sender -> 400 BadSender
    let bad_sender_body = serde_json::json!({
        "from": "   \"\" <> \t  ",
        "text": "valid text"
    });
    let res = client
        .post(format!("{base_url}/v1/sessions/my-worker/messages"))
        .json(&bad_sender_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "bad_sender");

    // 11. POST exceeding max_body (512 bytes limit) -> 413 Payload Too Large
    let huge_text = "a".repeat(1000);
    let huge_body = serde_json::json!({
        "from": "claude",
        "text": huge_text
    });
    let res = client
        .post(format!("{base_url}/v1/sessions/my-worker/messages"))
        .json(&huge_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "payload_too_large");

    // 12. POST to dead socket -> 502 Bad Gateway (inbox_unavailable)
    let res = client
        .post(format!("{base_url}/v1/sessions/dead-sock-worker/messages"))
        .json(&post_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::BAD_GATEWAY);
    let err_val: serde_json::Value = res.json().await.unwrap();
    assert_eq!(err_val["error"], "inbox_unavailable");

    // Clean up
    stop_signal.store(true, Ordering::Relaxed);
}
