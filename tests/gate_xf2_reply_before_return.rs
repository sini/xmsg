//! XF2 gate: a recipient (`svc`, `claude`, or a pushed reply's receiver) that replies the
//! instant it is woken, before `deliver_send` or `deliver_reply` returns, finds its own
//! recipient record in `messages` and gets `ok`; a failed delivery or push leaves no
//! replyable row behind.

mod short_sock;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;

use serde_json::json;
use xmsg::agy::{new_agy_store, AgyConfig};
use xmsg::error::AppError;
use xmsg::http::AppState;
use xmsg::pi::new_pi_store;
use xmsg::registry::Session;
use xmsg::storage::{self, MessageRecord};
use xmsg::surface::{self, Sender};
use xmsg::svc::{new_svc_store, SvcSessionInfo};

fn write_fake_stat(proc_root: &Path, pid: u32, ppid: u32, starttime: &str) {
    let dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&dir).unwrap();
    let stat = format!(
        "{pid} (fake) S {ppid} {pid} {pid} 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 {starttime} 1000000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
    );
    fs::write(dir.join("stat"), stat).unwrap();
}

fn build_test_state(node_name: &str) -> (TempDir, Arc<AppState>) {
    let tmp = tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let proc_root = tmp.path().join("proc");
    fs::create_dir_all(&proc_root).unwrap();

    let sessions_dir = tmp.path().join("sessions");
    fs::create_dir_all(&sessions_dir).unwrap();

    let presence_dir = tmp.path().join("presence");
    fs::create_dir_all(&presence_dir).unwrap();

    let agy_config = AgyConfig {
        presence_dir,
        proc_locks_path: tmp.path().join("locks"),
        proc_root,
        agy_bin: "false".to_string(),
        trusted_agy_exes: Vec::new(),
            brain_dir: std::path::PathBuf::new(),
    };

    let db_conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&db_conn).unwrap();
    let db = Arc::new(Mutex::new(db_conn));

    let (notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(32);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(32);

    let state = Arc::new(AppState {
        sessions_dirs: vec![sessions_dir],
        max_body: 65536,
        request_counter: std::sync::atomic::AtomicU64::new(0),
        fed_state: None,
        db,
        notify_tx,
        pi_notify_tx,
        svc_notify_tx,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        node_name: node_name.to_string(),
        agy_config,
        agy_store: new_agy_store(),
        pi_store: new_pi_store(),
        svc_store: new_svc_store(),
    });

    (tmp, state)
}

fn register_fake_svc(state: &AppState, pid: u32, name: &str) -> Session {
    write_fake_stat(&state.agy_config.proc_root, pid, 1, "1000");
    let now = storage::now_epoch_secs();
    state.svc_store.write().unwrap().insert(
        name.to_string(),
        SvcSessionInfo {
            session_id: name.to_string(),
            name: name.to_string(),
            pid,
            starttime: "1000".to_string(),
            cwd: "/workspace".to_string(),
            registered_at: now,
        },
    );
    Session {
        session_id: name.to_string(),
        name: Some(name.to_string()),
        pid,
        cwd: "/workspace".to_string(),
        status: "idle".to_string(),
        kind: "svc".to_string(),
        entrypoint: None,
        version: None,
        started_at: now as u64,
        updated_at: now as u64,
        harness: "svc".to_string(),
        registered: Some(true),
    }
}

async fn register_fake_claude(
    state: &AppState,
    pid: u32,
    session_id: &str,
    label: &str,
    sock_path: &Path,
) -> Session {
    write_fake_stat(&state.agy_config.proc_root, pid, 1, "2000");
    let now = storage::now_epoch_secs();
    let sessions_dir = &state.sessions_dirs[0];
    let doc = json!({
        "pid": pid,
        "sessionId": session_id,
        "name": label,
        "cwd": "/workspace",
        "status": "idle",
        "kind": "interactive",
        "startedAt": now,
        "updatedAt": now,
        "procStart": "2000",
        "messagingSocketPath": sock_path.display().to_string(),
    });
    fs::write(
        sessions_dir.join(format!("{pid}-{session_id}.json")),
        doc.to_string(),
    )
    .unwrap();
    xmsg::claim::sync_claims(
        &state.db,
        &state.agy_config.proc_root,
        &state.sessions_dirs,
        &state.node_name,
    )
    .await
    .unwrap();
    Session {
        session_id: session_id.to_string(),
        name: Some(label.to_string()),
        pid,
        cwd: "/workspace".to_string(),
        status: "idle".to_string(),
        kind: "interactive".to_string(),
        entrypoint: None,
        version: None,
        started_at: now as u64,
        updated_at: now as u64,
        harness: "claude".to_string(),
        registered: Some(true),
    }
}

// Oracle 1 (service): a service woken by `deliver` replies while `deliver_send` is still
// held between `deliver` and `complete_message`. Mutant: record-after-deliver => RED
// (`NotRecipient`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf2_svc_replies_before_deliver_send_returns() {
    let (_tmp, state) = build_test_state("node-xf2-svc");
    let svc_session = register_fake_svc(&state, 501, "acker");

    let mut svc_rx = state.svc_notify_tx.subscribe();
    let (entered_rx, release_tx) = surface::pause_after_deliver_for_test(&state.node_name);

    let send_state = state.clone();
    let send_task = tokio::spawn(async move {
        surface::send(
            &send_state,
            &Sender::Anonymous("ci".to_string()),
            "acker",
            "ping-svc",
            None,
        )
        .await
    });

    // Wait for `deliver` to notify the service and hit the post-deliver pause before
    // `complete_message` runs.
    let notified = tokio::time::timeout(Duration::from_secs(5), svc_rx.recv())
        .await
        .expect("svc notified")
        .unwrap();
    assert_eq!(notified, "acker");

    let paused_id = tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .expect("deliver_send paused after deliver")
        .unwrap();
    assert!(
        !send_task.is_finished(),
        "deliver_send must still be held before complete_message"
    );

    // Take the pending svc message while the `messages` row is still `pending`.
    let pending_msg = {
        let db = state.db.lock().unwrap();
        let m = storage::get_message(&db, &paused_id)
            .unwrap()
            .expect("messages row present");
        assert_eq!(m.outcome, storage::KEY_PENDING);
        storage::get_next_pending_svc_message(&db, "acker")
            .unwrap()
            .expect("svc queue item")
    };
    assert_eq!(pending_msg.id, paused_id);

    // Reply immediately while `deliver_send` is still held paused.
    let reply_rec = surface::reply(&state, &svc_session, &paused_id, "pong-svc", None)
        .await
        .expect("service reply before deliver_send returns must succeed");
    assert_eq!(reply_rec.message_id, paused_id);
    assert_eq!(reply_rec.text, "pong-svc");
    assert!(
        !send_task.is_finished(),
        "reply completed before deliver_send returned"
    );

    drop(release_tx);
    let sent = send_task.await.unwrap().expect("send succeeds");
    assert_eq!(sent.message_id, paused_id);
    assert_eq!(sent.outcome, "queued");
}

// Oracle 2 (Claude instance): a Claude instance woken on its `messagingSocketPath` by
// `deliver` replies while `deliver_send` is still held between `deliver` and
// `complete_message`. Mutant: record-after-deliver => RED (`NotRecipient`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf2_claude_replies_before_deliver_send_returns() {
    let (tmp, state) = build_test_state("node-xf2-claude");
    let claude_id = "11111111-2222-3333-4444-555555555555";
    let inbox_sock = short_sock::sock_path(tmp.path(), "claude-inbox");
    let listener = UnixListener::bind(&inbox_sock).unwrap();
    let claude_session =
        register_fake_claude(&state, 601, claude_id, "claude-target", &inbox_sock).await;

    let (entered_rx, release_tx) = surface::pause_after_deliver_for_test(&state.node_name);

    let send_state = state.clone();
    let send_task = tokio::spawn(async move {
        surface::send(
            &send_state,
            &Sender::Anonymous("ci".to_string()),
            "claude-target",
            "ping-claude",
            None,
        )
        .await
    });

    // Accept the socket delivery as the Claude instance.
    let (mut conn, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("claude inbox accept")
        .unwrap();
    let mut delivered_bytes = Vec::new();
    conn.read_to_end(&mut delivered_bytes).await.unwrap();
    drop(conn);
    let delivered_line = String::from_utf8(delivered_bytes).unwrap();

    let paused_id = tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .expect("deliver_send paused after deliver")
        .unwrap();
    assert!(delivered_line.contains(&paused_id));
    assert!(
        !send_task.is_finished(),
        "deliver_send must still be held before complete_message"
    );

    {
        let db = state.db.lock().unwrap();
        let m = storage::get_message(&db, &paused_id)
            .unwrap()
            .expect("messages row present");
        assert_eq!(m.outcome, storage::KEY_PENDING);
    }

    // Reply immediately while `deliver_send` is still held paused.
    let reply_rec = surface::reply(&state, &claude_session, &paused_id, "pong-claude", None)
        .await
        .expect("Claude reply before deliver_send returns must succeed");
    assert_eq!(reply_rec.message_id, paused_id);
    assert_eq!(reply_rec.text, "pong-claude");
    assert!(
        !send_task.is_finished(),
        "reply completed before deliver_send returned"
    );

    drop(release_tx);
    let sent = send_task.await.unwrap().expect("send succeeds");
    assert_eq!(sent.message_id, paused_id);
    assert_eq!(sent.outcome, "delivered");
}

// Oracle 3 (reply): a sender woken by `push_reply` inside `deliver_reply` replies to the
// pushed reply ID while `deliver_reply` is still held before returning. Mutant: record
// pushed reply after `push_reply` => RED (`NotFound`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf2_reply_recipient_replies_before_deliver_reply_returns() {
    let (tmp, state) = build_test_state("node-xf2-reply");
    let sender_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let sender_sock = short_sock::sock_path(tmp.path(), "sender-inbox");
    let sender_listener = UnixListener::bind(&sender_sock).unwrap();
    let claude_sender =
        register_fake_claude(&state, 701, sender_id, "claude-sender", &sender_sock).await;
    let svc_replier = register_fake_svc(&state, 702, "replier");

    // 1. `claude-sender` sends `m1` to `replier`.
    let m1 = surface::send(
        &state,
        &Sender::Session(claude_sender.clone()),
        "replier",
        "initial-msg",
        None,
    )
    .await
    .expect("initial send");

    // 2. Arm the post-deliver pause so `deliver_reply` pauses right after `push_reply`
    // wakes `claude-sender` on `sender_listener`.
    let (entered_rx, release_tx) = surface::pause_after_deliver_for_test(&state.node_name);

    let reply_state = state.clone();
    let svc_replier_clone = svc_replier.clone();
    let m1_id = m1.message_id.clone();
    let reply_task = tokio::spawn(async move {
        surface::reply(
            &reply_state,
            &svc_replier_clone,
            &m1_id,
            "first-reply",
            None,
        )
        .await
    });

    // `claude-sender` wakes on its inbox socket as `push_reply` delivers the reply.
    let (mut conn, _) = tokio::time::timeout(Duration::from_secs(5), sender_listener.accept())
        .await
        .expect("sender inbox accept pushed reply")
        .unwrap();
    let mut pushed_bytes = Vec::new();
    conn.read_to_end(&mut pushed_bytes).await.unwrap();
    drop(conn);
    let pushed_line = String::from_utf8(pushed_bytes).unwrap();

    let pushed_reply_id = tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .expect("deliver_reply paused after push_reply")
        .unwrap();
    assert!(pushed_line.contains(&pushed_reply_id));
    assert!(
        !reply_task.is_finished(),
        "deliver_reply must still be held before returning"
    );

    // While `deliver_reply` is still held paused, `claude-sender` replies to `pushed_reply_id`.
    let r2 = surface::reply(
        &state,
        &claude_sender,
        &pushed_reply_id,
        "second-reply",
        None,
    )
    .await
    .expect("reply to pushed reply before deliver_reply returns must succeed");
    assert_eq!(r2.message_id, pushed_reply_id);
    assert_eq!(r2.text, "second-reply");
    assert!(
        !reply_task.is_finished(),
        "second reply completed before first deliver_reply returned"
    );

    drop(release_tx);
    let r1 = reply_task.await.unwrap().expect("first reply succeeds");
    assert_eq!(r1.push_outcome.as_deref(), Some("pushed"));
    assert_eq!(r1.pushed_message_id.as_deref(), Some(pushed_reply_id.as_str()));
}

// Oracle 4 (failure path): if `deliver` or `push_reply` fails after pre-recording the
// recipient, the row is deleted or marked failed, and any later `reply` to it is refused
// with `NotFound`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_xf2_failed_delivery_or_push_refuses_later_reply() {
    let (tmp, state) = build_test_state("node-xf2-fail");

    // 4a. `deliver_send` fails during `deliver` (socket exists on disk with no listener ->
    // ECONNREFUSED after `resolve_target_session` and `record_message_recipient`).
    let dead_id = "22222222-3333-4444-5555-666666666666";
    let dead_sock = short_sock::sock_path(tmp.path(), "dead-inbox");
    {
        let _listener = UnixListener::bind(&dead_sock).unwrap();
    } // socket path exists on disk, but listener is closed -> ECONNREFUSED
    let dead_claude =
        register_fake_claude(&state, 801, dead_id, "dead-claude", &dead_sock).await;

    let err = surface::send(
        &state,
        &Sender::Anonymous("ci".to_string()),
        "dead-claude",
        "will-fail",
        Some("key-dead-send"),
    )
    .await
    .expect_err("send to closed socket must fail");
    assert!(matches!(err, AppError::InboxUnavailable(_)), "got: {err:?}");

    // Read the message ID reserved under `key-dead-send` and verify its `messages` row
    // was deleted and cannot be replied to.
    let failed_msg_id = {
        let db = state.db.lock().unwrap();
        let (msg_id, outcome): (String, String) = db
            .query_row(
                "SELECT message_id, outcome FROM idempotency_keys WHERE key = 'key-dead-send'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("idempotency key record");
        assert_eq!(outcome, storage::KEY_FAILED);
        assert!(
            storage::get_message(&db, &msg_id).unwrap().is_none(),
            "failed send's pre-recorded messages row must be deleted"
        );
        msg_id
    };
    let reply_err = surface::reply(&state, &dead_claude, &failed_msg_id, "nope", None)
        .await
        .expect_err("reply to failed send must be refused");
    assert!(matches!(reply_err, AppError::NotFound(_)), "got: {reply_err:?}");

    // 4b. `deliver_reply` fails during `push_reply` (`sender_gone` after pre-recording the
    // pushed reply row in `messages`).
    let gone_id = "33333333-4444-5555-6666-777777777777";
    let gone_sock = short_sock::sock_path(tmp.path(), "gone-inbox");
    let gone_listener = UnixListener::bind(&gone_sock).unwrap();
    let gone_sender =
        register_fake_claude(&state, 802, gone_id, "gone-sender", &gone_sock).await;
    let svc_replier = register_fake_svc(&state, 803, "svc-target");

    let m = surface::send(
        &state,
        &Sender::Session(gone_sender.clone()),
        "svc-target",
        "hello",
        None,
    )
    .await
    .expect("send succeeds");

    // Remove the sender's socket so `push_reply` returns `sender_gone`.
    drop(gone_listener);
    let _ = fs::remove_file(&gone_sock);

    let r = surface::reply(
        &state,
        &svc_replier,
        &m.message_id,
        "reply-to-gone",
        Some("key-gone-reply"),
    )
    .await
    .expect("reply stored even when push_reply returns sender_gone");
    assert_eq!(r.push_outcome.as_deref(), Some("sender_gone"));
    assert_eq!(r.pushed_message_id, None);

    // Look up the reserved `reply_id` from `reply_idempotency_keys` and verify no row for
    // it remains in `messages`, and `gone_sender` cannot reply to it.
    let unpushed_reply_id: String = {
        let db = state.db.lock().unwrap();
        let id: String = db
            .query_row(
                "SELECT reply_id FROM reply_idempotency_keys WHERE key = 'key-gone-reply'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            storage::get_message(&db, &id).unwrap().is_none(),
            "pre-recorded pushed reply row must be deleted when push_reply != pushed"
        );
        id
    };
    let reply_err = surface::reply(&state, &gone_sender, &unpushed_reply_id, "nope", None)
        .await
        .expect_err("reply to unpushed reply_id must be refused");
    assert!(matches!(reply_err, AppError::NotFound(_)), "got: {reply_err:?}");

    // 4c. A row in `messages` recorded first and then marked with a failure outcome
    // (`delivery_failed`, `failed`, `not_found`, `gone`, `ambiguous`) is also refused by
    // `reply` with `NotFound`.
    for failed_outcome in ["delivery_failed", "failed", "not_found", "gone", "ambiguous"] {
        let id = format!("msg-{failed_outcome}");
        {
            let db = state.db.lock().unwrap();
            storage::upsert_message(
                &db,
                &MessageRecord {
                    id: id.clone(),
                    created_at: storage::now_epoch_secs(),
                    session_id: "svc-target".to_string(),
                    from_name: "peer".to_string(),
                    bytes: 4,
                    outcome: failed_outcome.to_string(),
                    recipient_harness: "svc".to_string(),
                    return_harness: Some("fed".to_string()),
                    return_session_id: Some("sender".to_string()),
                    thread_id: id.clone(),
                    return_host: Some("peer".to_string()),
                },
            )
            .unwrap();
        }
        let err = surface::reply(&state, &svc_replier, &id, "nope", None)
            .await
            .expect_err("reply to failed-outcome row must be refused");
        assert!(
            matches!(err, AppError::NotFound(_)),
            "outcome {failed_outcome}: got {err:?}"
        );
    }
}
