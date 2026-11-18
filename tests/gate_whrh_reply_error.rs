mod write_exe;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use xmsg::agy::{new_agy_store, AgyConfig, AgyCredentials, AgySessionInfo};
use xmsg::client::ReplyRecord;
use xmsg::http::AppState;
use xmsg::mcp::{execute_tool, McpConfig};
use xmsg::storage;

#[test]
fn reply_record_backwards_compat_without_push_error() {
    let old_json = serde_json::json!({
        "seq": 42,
        "messageId": "01M7WHRH000000000000000001",
        "createdAt": 1700000000,
        "replierSessionId": "sess-1",
        "text": "hello",
        "pushOutcome": "pushed",
        "pushedMessageId": "01M7WHRH000000000000000002"
    });
    let parsed: ReplyRecord = serde_json::from_value(old_json)
        .expect("old ReplyRecord JSON without pushError must parse");
    assert_eq!(parsed.push_error, None);
    let reserialized = serde_json::to_value(&parsed).expect("serialize ReplyRecord");
    assert!(
        reserialized.get("pushError").is_none(),
        "pushError must be omitted when None"
    );
}

fn write_fake_agy_failing(dir: &Path) -> PathBuf {
    let bin = dir.join("agy");
    write_exe::write_exe(
        &bin,
        "#!/usr/bin/env sh\necho 'synthetic agy delivery failure' >&2\nexit 1\n",
    );
    bin
}

#[tokio::test]
async fn mcp_reply_to_agy_and_claude_delivery_failures_surface_classified_errors() {
    let dir = tempdir().expect("tempdir");
    let sock_dir = dir.path().join("sock");
    let sess_dir = dir.path().join("sessions");
    let proc_dir = dir.path().join("proc");
    let presence_dir = dir.path().join("presence");
    fs::create_dir_all(&sock_dir).expect("mkdir sock");
    fs::create_dir_all(&sess_dir).expect("mkdir sess");
    fs::create_dir_all(&proc_dir).expect("mkdir proc");
    fs::create_dir_all(&presence_dir).expect("mkdir presence");
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).expect("chmod sock_dir");

    let agy_bin = write_fake_agy_failing(dir.path());
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
    storage::init_db(&conn).expect("init_db");
    let db = Arc::new(Mutex::new(conn));

    // Seed fake proc for agy sender (pid 900001) with open lock fd and proc_locks entry.
    let agy_pid: u32 = 900001;
    let agy_conv_id = "0199cecf-0099-7000-8000-0000000000aa";
    let agy_lock_file = presence_dir.join(format!("{agy_conv_id}.lock"));
    fs::write(&agy_lock_file, "lock").expect("write lock file");
    let lock_meta = fs::metadata(&agy_lock_file).expect("stat lock file");
    let maj = ((lock_meta.dev() >> 8) & 0xfff) | ((lock_meta.dev() >> 32) & !0xfff);
    let min = (lock_meta.dev() & 0xff) | ((lock_meta.dev() >> 12) & !0xff);
    let ino = lock_meta.ino();
    let proc_locks_path = dir.path().join("proc-locks");
    fs::write(
        &proc_locks_path,
        format!("1: FLOCK ADVISORY WRITE {agy_pid} {maj:02x}:{min:02x}:{ino} 0 EOF\n"),
    )
    .expect("write proc_locks");
    let agy_pid_dir = proc_dir.join(agy_pid.to_string());
    let agy_fd_dir = agy_pid_dir.join("fd");
    let agy_task_dir = agy_pid_dir.join("task").join(agy_pid.to_string());
    fs::create_dir_all(&agy_fd_dir).unwrap();
    fs::create_dir_all(&agy_task_dir).unwrap();
    fs::write(
        agy_pid_dir.join("stat"),
        format!("{agy_pid} (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0 0 0 0\n"),
    )
    .unwrap();
    std::os::unix::fs::symlink(&agy_bin, agy_pid_dir.join("exe")).unwrap();
    std::os::unix::fs::symlink(&agy_lock_file, agy_fd_dir.join("3")).unwrap();
    fs::write(agy_task_dir.join("children"), "").unwrap();

    let agy_store = new_agy_store();
    let agy_info = AgySessionInfo::new(
        agy_conv_id.to_string(),
        agy_pid,
        "100".to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:1".to_string(),
            csrf_token: "csrf".to_string(),
            is_stale: false,
        }),
    );
    agy_store
        .write()
        .unwrap()
        .insert(agy_info.session_key.clone(), agy_info);

    let agy_config = AgyConfig {
        presence_dir: presence_dir.clone(),
        proc_locks_path,
        proc_root: proc_dir.clone(),
        agy_bin: agy_bin.to_string_lossy().to_string(),
        trusted_agy_exes: vec![agy_bin.clone()],
        brain_dir: PathBuf::new(),
    };

    // Register a live Claude recipient (pid 5000) and make our process descend from it.
    let my_pid = std::process::id();
    let my_start = xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), my_pid)
        .expect("read own starttime");
    let target_pid: u32 = 5000;
    let target_start = "100";
    let my_proc_dir = proc_dir.join(my_pid.to_string());
    fs::create_dir_all(&my_proc_dir).unwrap();
    fs::write(
        my_proc_dir.join("stat"),
        format!(
            "{my_pid} (test) S {target_pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {my_start} 0 0\n"
        ),
    )
    .unwrap();
    let target_proc_dir = proc_dir.join(target_pid.to_string());
    fs::create_dir_all(&target_proc_dir).unwrap();
    fs::write(
        target_proc_dir.join("stat"),
        format!("{target_pid} (claude) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {target_start} 0 0\n"),
    )
    .unwrap();

    let claude_sock = sock_dir.join("claude.sock");
    let _claude_listener = UnixListener::bind(&claude_sock).expect("bind claude sock");
    let claude_sess_id = "0199cecf-5000-7000-8000-000000005000";
    let sess_json = serde_json::json!({
        "pid": target_pid,
        "sessionId": claude_sess_id,
        "name": "claude-recipient",
        "cwd": "/workspace/test",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": target_start,
        "messagingSocketPath": claude_sock.display().to_string(),
    });
    fs::write(
        sess_dir.join(format!("{target_pid}.json")),
        sess_json.to_string(),
    )
    .expect("write claude session file");

    // Seed two messages addressed to `claude_sess_id`:
    // 1) from `agy_conv_id` (whose `agy` binary will fail with exit 1 -> inbox_unavailable)
    // 2) from a gone `claude` session (whose socket does not exist -> sender_gone)
    let msg_from_agy = "01M7WHRHMSGFROMAGY00000001";
    let msg_from_gone_claude = "01M7WHRHMSGFROMCLAUDE00002";
    {
        let db_lock = db.lock().unwrap();
        let now = storage::now_epoch_secs();
        storage::insert_message(
            &db_lock,
            &storage::MessageRecord {
                id: msg_from_agy.to_string(),
                created_at: now,
                session_id: claude_sess_id.to_string(),
                from_name: "agy-sender".to_string(),
                bytes: 5,
                outcome: "delivered".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: Some("agy".to_string()),
                return_session_id: Some(agy_conv_id.to_string()),
                thread_id: msg_from_agy.to_string(),
                return_host: None,
            },
        )
        .expect("insert agy message");

        storage::insert_message(
            &db_lock,
            &storage::MessageRecord {
                id: msg_from_gone_claude.to_string(),
                created_at: now,
                session_id: claude_sess_id.to_string(),
                from_name: "gone-claude".to_string(),
                bytes: 5,
                outcome: "delivered".to_string(),
                recipient_harness: "claude".to_string(),
                return_harness: Some("claude".to_string()),
                return_session_id: Some("gone-claude-sess".to_string()),
                thread_id: msg_from_gone_claude.to_string(),
                return_host: None,
            },
        )
        .expect("insert gone claude message");
    }

    let state = Arc::new(AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        db: db.clone(),
        sessions_dirs: vec![sess_dir.clone()],
        node_name: "test-node".to_string(),
        notify_tx: broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(600),
        agy_store,
        agy_config,
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: broadcast::channel(16).0,
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });

    let agent_sock = sock_dir.join("agent.sock");
    let my_uid = xmsg::agent::current_uid();
    let listener = xmsg::agent::bind_agent_listener(&agent_sock, my_uid)
        .await
        .expect("bind agent sock");
    let srv_state = state.clone();
    let srv = tokio::spawn(async move {
        let _ = xmsg::agent::run_agent_server_with_listener(listener, srv_state, my_uid).await;
    });

    let mcp_cfg = McpConfig {
        sessions_dirs: vec![sess_dir],
        xmsg_url: "http://127.0.0.1:0".to_string(),
        http_sock: None,
        agent_sock: agent_sock.clone(),
        proc_root: PathBuf::from("/proc"),
        presence_dir,
        proc_locks_path: dir.path().join("proc-locks"),
        reply_only: false,
    };
    // 1. Reply to agy sender whose delivery fails -> classified `inbox_unavailable:` error
    let agy_reply_res = tokio::task::spawn_blocking({
        let cfg = mcp_cfg.clone();
        move || {
            let cli = reqwest::blocking::Client::new();
            execute_tool(
                &cfg,
                &cli,
                "reply",
                &serde_json::json!({
                    "message_id": msg_from_agy,
                    "text": "hello agy"
                }),
            )
        }
    })
    .await
    .expect("spawn_blocking agy reply");

    assert_eq!(agy_reply_res["isError"], true, "{agy_reply_res}");
    let agy_err_text = agy_reply_res["content"][0]["text"].as_str().unwrap();
    assert!(
        agy_err_text.contains("inbox_unavailable:"),
        "expected classified inbox_unavailable error, got: {agy_err_text}"
    );
    assert!(
        !agy_err_text.contains("missing 'pushedMessageId'"),
        "must not return missing pushedMessageId, got: {agy_err_text}"
    );

    // 2. Reply to gone claude sender -> classified `gone:` error
    let claude_reply_res = tokio::task::spawn_blocking({
        let cfg = mcp_cfg.clone();
        move || {
            let cli = reqwest::blocking::Client::new();
            execute_tool(
                &cfg,
                &cli,
                "reply",
                &serde_json::json!({
                    "message_id": msg_from_gone_claude,
                    "text": "hello gone claude"
                }),
            )
        }
    })
    .await
    .expect("spawn_blocking claude reply");

    assert_eq!(claude_reply_res["isError"], true, "{claude_reply_res}");
    let claude_err_text = claude_reply_res["content"][0]["text"].as_str().unwrap();
    assert!(
        claude_err_text.contains("not_found:") || claude_err_text.contains("gone:"),
        "expected classified not_found/gone error, got: {claude_err_text}"
    );
    assert!(
        !claude_err_text.contains("missing 'pushedMessageId'"),
        "must not return missing pushedMessageId, got: {claude_err_text}"
    );

    srv.abort();
}

#[tokio::test]
async fn mcp_reply_stored_outcome_allows_null_message_id() {
    let dir = tempdir().expect("tempdir");
    let sock_dir = dir.path().join("sock");
    fs::create_dir_all(&sock_dir).expect("mkdir sock");
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).expect("chmod sock_dir");

    let agent_sock = sock_dir.join("agent.sock");
    let listener = UnixListener::bind(&agent_sock).expect("bind mock agent sock");
    let srv = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();
            let _ = lines.next_line().await;
            let resp = serde_json::json!({
                "status": "ok",
                "reply": {
                    "seq": 1,
                    "messageId": "01M7WHRHMOCKORIG0000000001",
                    "createdAt": 1700000000,
                    "replierSessionId": "sess-1",
                    "text": "stored reply",
                    "pushOutcome": "stored",
                    "pushedMessageId": null
                }
            });
            let line = format!("{resp}\n");
            let _ = writer.write_all(line.as_bytes()).await;
            let _ = writer.flush().await;
        }
    });

    let mcp_cfg = McpConfig {
        sessions_dirs: vec![],
        xmsg_url: "http://127.0.0.1:0".to_string(),
        http_sock: None,
        agent_sock,
        proc_root: dir.path().join("proc"),
        presence_dir: dir.path().join("presence"),
        proc_locks_path: dir.path().join("proc-locks"),
        reply_only: false,
    };
    let res = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::new();
        execute_tool(
            &mcp_cfg,
            &client,
            "reply",
            &serde_json::json!({
                "message_id": "01M7WHRHMOCKORIG0000000001",
                "text": "stored reply"
            }),
        )
    })
    .await
    .expect("spawn_blocking stored reply");

    assert_ne!(res["isError"], true, "{res}");
    let body: serde_json::Value =
        serde_json::from_str(res["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["outcome"], "stored");
    assert_eq!(body["messageId"], serde_json::Value::Null);
    assert_eq!(body["inReplyTo"], "01M7WHRHMOCKORIG0000000001");

    srv.abort();
}
