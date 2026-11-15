use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use xmsg::http::AppState;
use xmsg::observe::{Config, Observer, Query};
use xmsg::{storage, surface};

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

fn caller() -> xmsg::registry::Session {
    xmsg::registry::Session {
        session_id: "parent/child".into(),
        name: None,
        pid: 0,
        cwd: "/".into(),
        status: "idle".into(),
        kind: "interactive".into(),
        entrypoint: None,
        version: None,
        started_at: 0,
        updated_at: 0,
        harness: "claude".into(),
        registered: Some(true),
    }
}
fn seed(state: &AppState, id: &str, recorded: bool) {
    let db = state.db.lock().unwrap();
    let now = storage::now_epoch_secs();
    db.execute("INSERT OR IGNORE INTO subagents(parent,agent_id,name,bound_at,last_active) VALUES ('parent','child','worker',?1,?1)", [now]).unwrap();
    storage::insert_queued(
        &db,
        &storage::QueuedMessage {
            id: id.into(),
            instance_id: caller().session_id,
            created_at: 1,
            expires_at: now + 300,
            from_name: "ARRIVAL_LABEL_CANARY".into(),
            body: "ARRIVAL_BODY_CANARY".into(),
        },
    )
    .unwrap();
    if recorded {
        storage::insert_message(
            &db,
            &storage::MessageRecord {
                id: id.into(),
                created_at: 1,
                session_id: caller().session_id,
                from_name: "ARRIVAL_LABEL_CANARY".into(),
                bytes: 20,
                outcome: "queued".into(),
                recipient_harness: "claude".into(),
                return_harness: Some("claude".into()),
                return_session_id: Some("sender".into()),
                thread_id: "known-thread".into(),
                return_host: None,
            },
        )
        .unwrap();
    }
}
fn events(observer: &Observer) -> xmsg::observe::Page {
    assert!(observer.flush_for_test(Duration::from_secs(3)));
    observer
        .page(Query {
            after: Some(0),
            limit: Some(200),
            epoch: None,
        })
        .unwrap()
}

#[tokio::test]
async fn inbox_arrival_records_only_committed_metadata_once() {
    let root = TempDir::new().unwrap();
    let state = state(root.path());
    seed(&state, "known", true);
    seed(&state, "unrecorded", false);
    let observer = Observer::start(
        &state.db,
        &root.path().join("observe.sqlite"),
        &state.node_name,
        Config::default(),
    );
    let result = surface::inbox(&state, &caller(), 0).await.unwrap();
    assert_eq!(result.messages.len(), 2);
    assert!(result
        .messages
        .iter()
        .all(|m| m.body == "ARRIVAL_BODY_CANARY"));
    let first = events(&observer);
    let arrivals: Vec<_> = first
        .events
        .iter()
        .filter(|e| e.observation.kind == "arrival")
        .collect();
    assert_eq!(arrivals.len(), 2, "one arrival per inbox consumption");
    for event in &arrivals {
        assert_eq!(
            event.observation.to.as_deref(),
            Some("parent/worker@observer.example")
        );
        assert_eq!(event.observation.body_availability, "not_recorded");
        let stamp: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT delivered_at FROM instance_queue WHERE id=?1",
                [event.observation.message_id.as_deref().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(event.observation.source_at, Some(stamp));
    }
    let known = arrivals
        .iter()
        .find(|e| e.observation.message_id.as_deref() == Some("known"))
        .unwrap();
    assert_eq!(
        known.observation.from.as_deref(),
        Some("sender@observer.example")
    );
    assert_eq!(known.observation.thread_id.as_deref(), Some("known-thread"));
    let unknown = arrivals
        .iter()
        .find(|e| e.observation.message_id.as_deref() == Some("unrecorded"))
        .unwrap();
    assert!(unknown.observation.from.is_none());
    assert!(unknown.observation.thread_id.is_none());
    assert!(first
        .events
        .iter()
        .any(|e| e.observation.kind == "outcome_changed"));
    let encoded = serde_json::to_string(&first).unwrap();
    assert!(!encoded.contains("ARRIVAL_BODY_CANARY"));
    assert!(!encoded.contains("ARRIVAL_LABEL_CANARY"));
    assert!(surface::inbox(&state, &caller(), 0)
        .await
        .unwrap()
        .messages
        .is_empty());
    let again = events(&observer);
    assert_eq!(
        again
            .events
            .iter()
            .filter(|e| e.observation.kind == "arrival")
            .count(),
        2
    );
}

#[tokio::test]
async fn failed_inbox_stamp_emits_no_arrival() {
    let root = TempDir::new().unwrap();
    let state = state(root.path());
    seed(&state, "failed", true);
    let observer = Observer::start(
        &state.db,
        &root.path().join("observe.sqlite"),
        &state.node_name,
        Config::default(),
    );
    state.db.lock().unwrap().execute_batch("CREATE TRIGGER refuse_delivery BEFORE UPDATE OF delivered_at ON instance_queue BEGIN SELECT RAISE(ABORT,'fixture-stamp-refusal'); END;").unwrap();
    assert!(surface::inbox(&state, &caller(), 0).await.is_err());
    assert!(!events(&observer)
        .events
        .iter()
        .any(|e| e.observation.kind == "arrival"));
    let stamp: Option<i64> = state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT delivered_at FROM instance_queue WHERE id='failed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(stamp.is_none());
}

#[tokio::test]
async fn unavailable_sidecar_never_changes_inbox_success() {
    let root = TempDir::new().unwrap();
    let state = state(root.path());
    seed(&state, "unavailable", true);
    std::fs::write(root.path().join("blocked"), b"not a directory").unwrap();
    let _observer = Observer::start(
        &state.db,
        &root.path().join("blocked/journal"),
        &state.node_name,
        Config::default(),
    );
    let result = tokio::time::timeout(Duration::from_secs(1), surface::inbox(&state, &caller(), 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.messages[0].body, "ARRIVAL_BODY_CANARY");
    assert_eq!(
        storage::get_message(&state.db.lock().unwrap(), "unavailable")
            .unwrap()
            .unwrap()
            .outcome,
        "delivered"
    );
}

#[tokio::test]
async fn full_observer_queue_never_changes_inbox_success() {
    let root = TempDir::new().unwrap();
    let state = state(root.path());
    seed(&state, "full", true);
    let observer = Observer::start(
        &state.db,
        &root.path().join("observe.sqlite"),
        &state.node_name,
        Config {
            queue_events: 1,
            ..Config::default()
        },
    );
    assert!(observer.flush_for_test(Duration::from_secs(3)));
    assert!(observer.set_paused_for_test(true));
    let result = tokio::time::timeout(Duration::from_secs(1), surface::inbox(&state, &caller(), 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.messages[0].body, "ARRIVAL_BODY_CANARY");
    assert!(observer.queue_stats_for_test().2 > 0);
    assert!(observer.set_paused_for_test(false));
}

#[tokio::test]
async fn ordinary_queue_reservation_does_not_claim_arrival() {
    let root = TempDir::new().unwrap();
    let state = state(root.path());
    seed(&state, "reserved", true);
    let observer = Observer::start(
        &state.db,
        &root.path().join("observe.sqlite"),
        &state.node_name,
        Config::default(),
    );
    {
        let db = state.db.lock().unwrap();
        xmsg::observe_effects::autocommit(&state.db, &db, || {
            storage::take_queued(&db, &caller().session_id, storage::now_epoch_secs())
        })
        .unwrap();
    }
    assert!(!events(&observer)
        .events
        .iter()
        .any(|e| e.observation.kind == "arrival"));
}

#[tokio::test]
async fn committed_inbox_mark_is_observed_even_when_outcome_write_is_refused() {
    let root = TempDir::new().unwrap();
    let state = state(root.path());
    seed(&state, "outcome-refused", true);
    let observer = Observer::start(
        &state.db,
        &root.path().join("observe.sqlite"),
        &state.node_name,
        Config::default(),
    );
    state.db.lock().unwrap().execute_batch("CREATE TRIGGER refuse_outcome BEFORE UPDATE OF outcome ON messages BEGIN SELECT RAISE(ABORT,'fixture-outcome-refusal'); END;").unwrap();
    assert_eq!(
        surface::inbox(&state, &caller(), 0)
            .await
            .unwrap()
            .messages
            .len(),
        1
    );
    let page = events(&observer);
    let arrival = page
        .events
        .iter()
        .find(|event| event.observation.kind == "arrival")
        .unwrap();
    assert_eq!(
        arrival.observation.message_id.as_deref(),
        Some("outcome-refused")
    );
    assert_eq!(
        arrival.observation.outcome.as_deref(),
        Some("queued"),
        "stored outcome must not be invented"
    );
    assert!(!page
        .events
        .iter()
        .any(|event| event.observation.kind == "outcome_changed"));
}
