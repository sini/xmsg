use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncBufReadExt;
use xmsg::http::{bind_ucred_unix_listener, build_router, build_unix_router, AppState, HttpPeer};
use xmsg::observe::{Config, Observer};

fn state(root: &Path) -> Arc<AppState> {
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let connection = rusqlite::Connection::open(root.join("primary.sqlite")).unwrap();
    xmsg::storage::init_db(&connection).unwrap();
    Arc::new(AppState {
        sessions_dirs: vec![root.join("sessions")],
        agy_config: xmsg::agy::AgyConfig::default(),
        agy_store: xmsg::agy::new_agy_store(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: tokio::sync::broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: tokio::sync::broadcast::channel(16).0,
        node_name: "observer.example".into(),
        max_body: 65536,
        max_attachment_bytes: 8 * 1024 * 1024,
        request_counter: AtomicU64::new(0),
        db: Arc::new(Mutex::new(connection)),
        notify_tx: tokio::sync::broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observe_is_available_only_through_authenticated_unix_requests() {
    let directory = TempDir::new().unwrap();
    let state = state(directory.path());
    let observer = Observer::start(
        &state.db,
        &directory.path().join("observe.sqlite"),
        &state.node_name,
        Config::default(),
    );
    assert!(observer.flush_for_test(Duration::from_secs(3)));
    let socket = directory.path().join("http.sock");
    let listener = bind_ucred_unix_listener(&socket, xmsg::agent::current_uid(), None).unwrap();
    let router = build_unix_router(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<HttpPeer>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let response = client
        .get("http://localhost/v1/observe/events?after=0&limit=2")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let bytes = response.bytes().await.unwrap();
    assert!(bytes.len() <= 256 * 1024);
    let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(page["node"], "observer.example");
    assert!(!page["events"].as_array().unwrap().is_empty());
    for query in [
        "limit=0",
        "limit=201",
        "after=-1",
        "after=9223372036854775808",
        "extra=1",
    ] {
        assert_eq!(
            client
                .get(format!("http://localhost/v1/observe/events?{query}"))
                .send()
                .await
                .unwrap()
                .status(),
            400,
            "query {query} must be refused"
        );
    }
    for (router, expected) in [
        (build_router(state.clone()), 404),
        (build_unix_router(state.clone()), 403),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tcp = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let response = reqwest::Client::new()
            .get(format!("http://{address}/v1/observe/events"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        tcp.abort();
        let _ = tcp.await;
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observer_rejects_a_different_unix_uid_before_the_handler() {
    let directory = TempDir::new().unwrap();
    let state = state(directory.path());
    let socket = directory.path().join("http.sock");
    let mut listener = bind_ucred_unix_listener(&socket, xmsg::agent::current_uid(), None).unwrap();
    listener.expected_uid = xmsg::agent::current_uid().wrapping_add(1);
    let router = build_unix_router(state);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<HttpPeer>(),
        )
        .await
        .unwrap();
    });
    let result = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .timeout(Duration::from_millis(300))
        .build()
        .unwrap()
        .get("http://localhost/v1/observe/events")
        .send()
        .await;
    assert!(result.is_err(), "foreign UID must be rejected at accept");
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paused_full_observer_does_not_block_committed_message_delivery() {
    exercise_delivery(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unavailable_observer_does_not_break_send_or_reply() {
    exercise_delivery(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_recipient_reply_observes_its_committed_pushed_message() {
    let directory = TempDir::new().unwrap();
    let state = state(directory.path());
    std::fs::create_dir(&state.sessions_dirs[0]).unwrap();
    let socket = directory.path().join("sender.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let pid = std::process::id();
    let start = xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    let sender = "0199cecf-1234-7000-8000-000000001234";
    let recipient = "0199cecf-1234-7000-8000-000000005678";
    std::fs::write(
        state.sessions_dirs[0].join("sender.json"),
        serde_json::to_vec(
            &serde_json::json!({"pid":pid,"sessionId":sender,"name":"reply-sender",
            "cwd":"/synthetic-reply-project","status":"idle","kind":"interactive",
            "startedAt":1000,"updatedAt":2000,"procStart":start,"messagingSocketPath":socket}),
        )
        .unwrap(),
    )
    .unwrap();
    let message = xmsg::storage::MessageRecord {
        id: "01J00000000000000000000001".into(),
        created_at: xmsg::storage::now_epoch_secs(),
        session_id: recipient.into(),
        from_name: "synthetic sender".into(),
        bytes: 3,
        outcome: "delivered".into(),
        recipient_harness: "claude".into(),
        return_harness: Some("claude".into()),
        return_session_id: Some(sender.into()),
        thread_id: String::new(),
        return_host: None,
    };
    xmsg::storage::insert_message(&state.db.lock().unwrap(), &message).unwrap();
    let observer = Observer::start(
        &state.db,
        &directory.path().join("observe.sqlite"),
        &state.node_name,
        Config::default(),
    );
    assert!(observer.flush_for_test(Duration::from_secs(3)));
    let caller = xmsg::registry::Session {
        session_id: recipient.into(),
        name: Some("REPLY_LABEL_CANARY_6bc1".into()),
        pid,
        cwd: "/synthetic-reply-project".into(),
        status: "idle".into(),
        kind: "interactive".into(),
        entrypoint: None,
        version: None,
        started_at: 0,
        updated_at: 0,
        harness: "claude".into(),
        registered: None,
    };
    let received = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut line = String::new();
        tokio::io::BufReader::new(stream)
            .read_line(&mut line)
            .await
            .unwrap();
        line
    });
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        xmsg::surface::reply(
            &state,
            &caller,
            &message.id,
            "REPLY_BODY_CANARY_9f12",
            Some("observed-local-reply"),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let line = tokio::time::timeout(Duration::from_secs(2), received)
        .await
        .unwrap()
        .unwrap();
    assert!(line.contains("REPLY_BODY_CANARY_9f12"));
    let pushed = reply.pushed_message_id.as_deref().unwrap();
    assert!(
        xmsg::storage::get_message(&state.db.lock().unwrap(), pushed)
            .unwrap()
            .is_some()
    );
    assert!(observer.flush_for_test(Duration::from_secs(3)));
    let page = observer
        .page(xmsg::observe::Query {
            after: Some(0),
            ..Default::default()
        })
        .unwrap();
    assert!(
        page.events.iter().any(
            |event| event.observation.message_id.as_deref() == Some(pushed)
                && event.observation.kind == "message_recorded"
        ),
        "committed local pushed-reply creation must be observed"
    );
    let metadata = serde_json::to_string(&page).unwrap();
    assert!(!metadata.contains("REPLY_BODY_CANARY_9f12"));
    assert!(!metadata.contains("REPLY_LABEL_CANARY_6bc1"));
    assert!(!metadata.contains("synthetic-reply-project"));
}

async fn exercise_delivery(unavailable: bool) {
    let directory = TempDir::new().unwrap();
    let state = state(directory.path());
    std::fs::create_dir(&state.sessions_dirs[0]).unwrap();
    let inbox_path = directory.path().join("inbox.sock");
    let inbox = tokio::net::UnixListener::bind(&inbox_path).unwrap();
    let pid = std::process::id();
    let start = xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
    let session = "0199cecf-1234-7000-8000-000000001234";
    std::fs::write(
        state.sessions_dirs[0].join(format!("{pid}.json")),
        serde_json::to_vec(&serde_json::json!({
            "pid": pid, "sessionId": session, "name": "observer-worker",
            "cwd": "/synthetic-observer-project", "status": "idle", "kind": "interactive",
            "startedAt": 1000, "updatedAt": 2000, "procStart": start,
            "messagingSocketPath": inbox_path,
        }))
        .unwrap(),
    )
    .unwrap();
    let sidecar = directory.path().join("observe.sqlite");
    if unavailable {
        std::fs::write(&sidecar, b"unrecognized observer fixture").unwrap();
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let observer = Observer::start(
        &state.db,
        &sidecar,
        &state.node_name,
        Config {
            queue_events: 2,
            ..Config::default()
        },
    );
    if unavailable {
        assert!(!observer.flush_for_test(Duration::from_millis(100)));
        assert!(matches!(
            observer.page(Default::default()),
            Err(xmsg::observe::Error::Unavailable)
        ));
    } else {
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        assert!(observer.set_paused_for_test(true));
        for _ in 0..2 {
            observer.publish(vec![xmsg::observe::Observation {
                kind: "message_recorded".into(),
                message_id: Some("synthetic-queue-filler".into()),
                body_availability: "not_recorded".into(),
                ..Default::default()
            }]);
        }
    }
    let (queued, queued_bytes, dropped) = observer.queue_stats_for_test();
    assert_eq!(queued, if unavailable { 0 } else { 2 });
    assert!(queued_bytes <= 1024 * 1024);
    assert_eq!(dropped, 0);
    let received = tokio::spawn(async move {
        let (stream, _) = inbox.accept().await.unwrap();
        let mut reader = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        line
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = build_router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
        .post(format!("http://{address}/v1/messages"))
        .json(&serde_json::json!({
            "to": "observer-worker", "text": "OBSERVATION_BODY_CANARY_7e4f",
            "from": "OBSERVATION_LABEL_CANARY_1a6c", "idempotency_key": "observer-independent-send",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    let result: serde_json::Value = response.json().await.unwrap();
    assert_eq!(result["outcome"], "delivered");
    let line = tokio::time::timeout(Duration::from_secs(2), received)
        .await
        .unwrap()
        .unwrap();
    assert!(line.contains("OBSERVATION_BODY_CANARY_7e4f"));
    let id = result["message_id"].as_str().unwrap();
    {
        let db = state.db.lock().unwrap();
        assert_eq!(
            xmsg::storage::get_message(&db, id)
                .unwrap()
                .unwrap()
                .outcome,
            "delivered"
        );
    }
    assert!(observer.queue_stats_for_test().0 <= 2);
    if unavailable {
        let caller = xmsg::registry::list_sessions(&state.sessions_dirs, &Default::default())
            .into_iter()
            .find(|caller| caller.session_id == session)
            .unwrap();
        let reply = tokio::time::timeout(
            Duration::from_secs(2),
            xmsg::surface::reply(
                &state,
                &caller,
                id,
                "OBSERVATION_REPLY_CANARY_2c8f",
                Some("observer-unavailable-reply"),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reply.text, "OBSERVATION_REPLY_CANARY_2c8f");
        let rows: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM replies WHERE message_id=?1 AND text=?2",
                rusqlite::params![id, "OBSERVATION_REPLY_CANARY_2c8f"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert!(matches!(
            observer.page(Default::default()),
            Err(xmsg::observe::Error::Unavailable)
        ));
        assert_eq!(
            std::fs::read(&sidecar).unwrap(),
            b"unrecognized observer fixture"
        );
        server.abort();
        let _ = server.await;
        return;
    }
    assert!(observer.set_paused_for_test(false));
    assert!(observer.flush_for_test(Duration::from_secs(3)));
    let page = observer
        .page(xmsg::observe::Query {
            after: Some(0),
            ..Default::default()
        })
        .unwrap();
    assert!(
        page.events
            .iter()
            .any(|event| event.observation.message_id.as_deref() == Some(id)
                && event.observation.outcome.as_deref() == Some("delivered")),
        "the committed delivery must also produce an actual stored-outcome observation"
    );
    assert!(page.losses.queue > dropped);
    let metadata = serde_json::to_string(&page).unwrap();
    assert!(!metadata.contains("OBSERVATION_BODY_CANARY_7e4f"));
    assert!(!metadata.contains("OBSERVATION_LABEL_CANARY_1a6c"));
    assert!(!metadata.contains("synthetic-observer-project"));
    server.abort();
    let _ = server.await;
}
