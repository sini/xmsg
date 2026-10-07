use axum::http::StatusCode;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use xmsg::agent::run_agent_server;
use xmsg::agy::{current_uid, new_agy_store, run_register_server, AgyConfig};
use xmsg::http::{build_router, AppState};
use xmsg::pi::new_pi_store;

fn setup_mock_proc_pi(proc_root: &Path, pid: u32) -> String {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(pid_dir.join("cmdline"), "node\0/path/to/pi\0").unwrap();

    let starttime = "99887711".to_string();
    let stat_content =
        format!("{pid} (pi) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0\n");
    fs::write(pid_dir.join("stat"), stat_content).unwrap();

    starttime
}

#[tokio::test]
async fn test_e2e_pi_registration_delivery_and_reply_flow() {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let sessions_dir = tmp.path().join("sessions");
    let sock_path = tmp.path().join("register.sock");
    let agent_sock_path = tmp.path().join("agent.sock");

    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();
    fs::write(&proc_locks, "").unwrap();

    let my_pid = std::process::id();
    let my_uid = current_uid();
    let _ = setup_mock_proc_pi(&proc_root, my_pid);

    let agy_config = AgyConfig {
        presence_dir: presence_dir.clone(),
        proc_locks_path: proc_locks.clone(),
        proc_root: proc_root.clone(),
        agy_bin: "agy".to_string(),
        trusted_agy_exes: Vec::new(),
    };

    let agy_store = new_agy_store();
    let pi_store = new_pi_store();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(1024);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(1024);
    let reply_ttl = Duration::from_secs(604800);

    // 1. Start registration server
    let s_path = sock_path.clone();
    let s_cfg = agy_config.clone();
    let s_store = agy_store.clone();
    let s_pi = pi_store.clone();
    let s_db = db.clone();
    let s_tx = pi_notify_tx.clone();
    tokio::spawn(async move {
        let _ = run_register_server(
            s_path,
            s_cfg,
            s_store,
            s_pi,
            vec![],
            s_db,
            s_tx,
            reply_ttl,
            my_uid,
        )
        .await;
    });

    // 2. Start HTTP server
    let app_state = Arc::new(AppState {
        sessions_dir: sessions_dir.clone(),
        agy_config: agy_config.clone(),
        agy_store: agy_store.clone(),
        pi_store: pi_store.clone(),
        pi_notify_tx: pi_notify_tx.clone(),
        host_label: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx: notify_tx.clone(),
        reply_ttl,
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
    });

    let app = build_router(app_state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 2b. Start agent.sock server
    let ag_sock = agent_sock_path.clone();
    let ag_state = app_state.clone();
    tokio::spawn(async move {
        let _ = run_agent_server(ag_sock, ag_state, my_uid).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Mock Pi connects over Unix domain socket and registers
    let stream = UnixStream::connect(&sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let reg_req = serde_json::json!({
        "harness": "pi",
        "sessionId": "pi-worker-1",
        "sessionName": "worker-one",
        "cwd": "/workspace/project"
    });
    writer
        .write_all(format!("{reg_req}\n").as_bytes())
        .await
        .unwrap();

    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    let reg_resp: Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(reg_resp["status"], "ok");
    let derived_session_id = reg_resp["sessionId"].as_str().unwrap().to_string();
    assert!(derived_session_id.starts_with("pi:"));

    // 4. Verify session appears in GET /v1/sessions
    let client = reqwest::Client::new();
    let sessions_resp = client
        .get(format!("http://127.0.0.1:{http_port}/v1/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(sessions_resp.status(), StatusCode::OK);
    let sessions_json: Value = sessions_resp.json().await.unwrap();
    let sessions_arr = sessions_json.as_array().unwrap();
    let pi_sess = sessions_arr
        .iter()
        .find(|s| s["sessionId"] == derived_session_id)
        .expect("pi session should be listed in /v1/sessions");
    assert_eq!(pi_sess["harness"], "pi");
    assert_eq!(pi_sess["name"], "worker-one");
    assert_eq!(pi_sess["registered"], true);

    // 5. Pi starts long-poll on the socket in background task
    let (delivery_tx, mut delivery_rx) = tokio::sync::mpsc::channel::<Value>(1);
    let (keepalive_tx, keepalive_rx) = tokio::sync::oneshot::channel::<()>();
    let mut writer_clone = writer;
    let poll_session_id = derived_session_id.clone();

    tokio::spawn(async move {
        // Send poll
        let poll_cmd = serde_json::json!({
            "action": "poll",
            "sessionId": poll_session_id,
            "waitSecs": 5
        });
        writer_clone
            .write_all(format!("{poll_cmd}\n").as_bytes())
            .await
            .unwrap();

        let mut deliver_line = String::new();
        if reader.read_line(&mut deliver_line).await.unwrap() > 0 {
            let val: Value = serde_json::from_str(&deliver_line).unwrap();
            let _ = delivery_tx.send(val.clone()).await;

            // Send ack
            if let Some(msg_id) = val.get("messageId").and_then(|m| m.as_str()) {
                let ack_cmd = serde_json::json!({
                    "action": "ack",
                    "messageId": msg_id
                });
                writer_clone
                    .write_all(format!("{ack_cmd}\n").as_bytes())
                    .await
                    .unwrap();

                let mut ack_line = String::new();
                let _ = reader.read_line(&mut ack_line).await;
            }
        }

        let _ = keepalive_rx.await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 6. Post message to Pi session via HTTP (using session name worker-one)
    let send_resp = client
        .post(format!(
            "http://127.0.0.1:{http_port}/v1/sessions/worker-one/messages"
        ))
        .json(&serde_json::json!({
            "from": "alice-orch",
            "text": "Hello Pi agent, please run unit tests!"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(send_resp.status(), StatusCode::ACCEPTED);
    let send_data: Value = send_resp.json().await.unwrap();
    let message_id = send_data["messageId"].as_str().unwrap().to_string();
    assert_eq!(send_data["sessionId"], derived_session_id);

    // 7. Verify Pi socket waiter received the delivery with §9.4 envelope
    let delivered_val = tokio::time::timeout(Duration::from_secs(2), delivery_rx.recv())
        .await
        .unwrap()
        .expect("delivery should have been received by Pi socket");

    assert_eq!(delivered_val["action"], "deliver");
    assert_eq!(delivered_val["messageId"], message_id);
    let envelope = delivered_val["envelope"].as_str().unwrap();
    assert!(envelope.contains("[xmsg] from=xmsg@test-host · alice-orch message_id="));
    assert!(envelope.contains("reply with the xmsg reply tool"));
    assert!(envelope.contains("Hello Pi agent, please run unit tests!"));

    // 8a. Red Demo 1: HTTP POST to /v1/messages/{id}/replies returns 405 Method Not Allowed
    let http_reply_resp = client
        .post(format!(
            "http://127.0.0.1:{http_port}/v1/messages/{message_id}/replies"
        ))
        .json(&serde_json::json!({
            "sessionRef": "worker-one",
            "text": "All 42 tests passed cleanly!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(http_reply_resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    // 8b. Test reply from recipient Pi session over agent.sock
    let agent_stream = UnixStream::connect(&agent_sock_path).await.unwrap();
    let (ag_reader, mut ag_writer) = agent_stream.into_split();
    let mut ag_reader = BufReader::new(ag_reader);

    let reply_cmd = serde_json::json!({
        "action": "reply",
        "messageId": message_id,
        "text": "All 42 tests passed cleanly!"
    });
    ag_writer
        .write_all(format!("{reply_cmd}\n").as_bytes())
        .await
        .unwrap();

    let mut reply_line = String::new();
    ag_reader.read_line(&mut reply_line).await.unwrap();
    let reply_resp: Value = serde_json::from_str(&reply_line).unwrap();
    assert_eq!(reply_resp["status"], "ok");
    assert_eq!(reply_resp["reply"]["seq"], 1);
    assert_eq!(reply_resp["reply"]["text"], "All 42 tests passed cleanly!");

    // 9. Test reply to another message (not recipient) returns error on agent.sock
    let other_msg_record = xmsg::storage::MessageRecord {
        id: "other-msg-123".to_string(),
        created_at: xmsg::storage::now_epoch_secs(),
        session_id: "other-agent".to_string(),
        from_name: "test-orch".to_string(),
        bytes: 10,
        outcome: "delivered".to_string(),
        recipient_harness: "pi".to_string(),
        return_harness: None,
        return_session_id: None,
        push_replies: false,
        thread_id: "other-msg-123".to_string(),
    };
    {
        let db_lock = db.lock().unwrap();
        xmsg::storage::insert_message(&db_lock, &other_msg_record).unwrap();
    }

    let hijack_cmd = serde_json::json!({
        "action": "reply",
        "messageId": "other-msg-123",
        "text": "Unauthorized hijack reply"
    });
    ag_writer
        .write_all(format!("{hijack_cmd}\n").as_bytes())
        .await
        .unwrap();

    let mut reject_line = String::new();
    ag_reader.read_line(&mut reject_line).await.unwrap();
    let reject_resp: Value = serde_json::from_str(&reject_line).unwrap();
    assert_eq!(reject_resp["status"], "error");
    assert_eq!(reject_resp["error"], "not_recipient");

    // 10. Check GET /v1/messages/{id} includes the delivered message and recipient's reply
    let msg_detail_resp = client
        .get(format!(
            "http://127.0.0.1:{http_port}/v1/messages/{message_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(msg_detail_resp.status(), StatusCode::OK);
    let msg_detail: Value = msg_detail_resp.json().await.unwrap();
    assert_eq!(msg_detail["sessionId"], derived_session_id);
    let replies = msg_detail["replies"].as_array().unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["seq"], 1);
    assert_eq!(replies[0]["text"], "All 42 tests passed cleanly!");

    let _ = keepalive_tx.send(());
}
