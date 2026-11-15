use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;
use xmsg::http::{build_router, AppState};

const LIVE: &str = "11111111-1111-4111-8111-111111111111";
const NEW: &str = "22222222-2222-4222-8222-222222222222";
const STALE: &str = "33333333-3333-4333-8333-333333333333";

struct Fixture {
    root: TempDir,
    state: Arc<AppState>,
    inbox: UnixListener,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self::cold();
        xmsg::codex::init_for_state(&fixture.state, xmsg::codex::CodexConfig::default());
        fixture
    }

    fn cold() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(root.path().join("sessions")).unwrap();
        let inbox = UnixListener::bind(root.path().join("inbox.sock")).unwrap();
        inbox.set_nonblocking(true).unwrap();
        let db = rusqlite::Connection::open(root.path().join("primary.sqlite")).unwrap();
        xmsg::storage::init_db(&db).unwrap();
        let state = Arc::new(AppState {
            sessions_dirs: vec![root.path().join("sessions")],
            agy_config: xmsg::agy::AgyConfig {
                presence_dir: root.path().join("presence"),
                ..Default::default()
            },
            agy_store: xmsg::agy::new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            node_name: "snapshot.example".into(),
            max_body: 65536,
            max_attachment_bytes: 8 * 1024 * 1024,
            request_counter: AtomicU64::new(0),
            db: Arc::new(Mutex::new(db)),
            notify_tx: tokio::sync::broadcast::channel(16).0,
            reply_ttl: Duration::from_secs(3600),
            idempotency_ttl: Duration::from_secs(86400),
            long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
            fed_state: None,
        });
        Self { root, state, inbox }
    }

    fn seed(&self) {
        let pid = std::process::id();
        let start = xmsg::process::starttime(Path::new("/proc"), pid).unwrap();
        for (id, label) in [(LIVE, "recorded"), (NEW, "not-yet-observed")] {
            std::fs::write(self.root.path().join("sessions").join(format!("{id}.json")), json!({
                "pid":pid,"sessionId":id,"name":label,"cwd":"/workspace","status":"idle","kind":"interactive", "startedAt":1000,"updatedAt":2000,"procStart":start,
                "messagingSocketPath":self.root.path().join("inbox.sock")
            }).to_string()).unwrap();
        }
        let db = self.state.db.lock().unwrap();
        let now = xmsg::storage::now_epoch_secs();
        db.execute(
            "INSERT INTO instance_claims VALUES (?1,?2,?3,1,0,?4)",
            rusqlite::params![LIVE, pid, start, now],
        )
        .unwrap();
        db.execute(
            "INSERT INTO instance_claims VALUES (?1,4294967295,'gone',1,0,1)",
            [STALE],
        )
        .unwrap();
        db.execute(
            "INSERT INTO instance_seen (id,harness,last_live) VALUES ('expired','claude',1)",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO subagents (parent,agent_id,name,bound_at,last_active) VALUES (?1,'child-id','worker',?2,?2)", rusqlite::params![LIVE,now]).unwrap();
        for (id, instance) in [
            ("queued-parent", LIVE.to_string()),
            ("queued-child", format!("{LIVE}/child-id")),
        ] {
            xmsg::storage::insert_queued(
                &db,
                &xmsg::storage::QueuedMessage {
                    id: id.into(),
                    instance_id: instance,
                    created_at: now,
                    expires_at: now + 3600,
                    from_name: "fixture".into(),
                    body: "queued canary".into(),
                },
            )
            .unwrap();
        }
        db.execute("INSERT INTO codex_roots (root_id,codex_home,owner_pid,owner_starttime,generation,label,registered_at,active) VALUES ('codex-record','/nonexistent',4294967295,'gone',1,'recorded-codex',1,1)",[]).unwrap();
        db.execute("INSERT INTO plugin_sessions VALUES ('plugin-record','conn','hermes','plugin-label',?1,4294967295)",[now]).unwrap();
        self.state.agy_store.write().unwrap().insert(
            "agy-record".into(),
            xmsg::agy::AgySessionInfo::new("agy-record".into(), u32::MAX, "gone".into(), None),
        );
        self.state.pi_store.write().unwrap().insert(
            "pi-record".into(),
            xmsg::pi::PiSessionInfo {
                session_id: "pi-record".into(),
                name: Some("pi label".into()),
                pid: u32::MAX,
                starttime: "gone".into(),
                cwd: "/".into(),
                registered_at: now,
            },
        );
        self.state.svc_store.write().unwrap().insert(
            "status".into(),
            xmsg::svc::SvcSessionInfo {
                session_id: "status".into(),
                name: "status".into(),
                pid: u32::MAX,
                starttime: "gone".into(),
                cwd: "/".into(),
                registered_at: now,
                token: 1,
                liveness: None,
            },
        );
    }

    async fn get(&self, query: &str) -> (StatusCode, Value) {
        let response = build_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/recipients{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn store_snapshot(&self) -> (String, String, String) {
        (
            format!("{:?}", *self.state.agy_store.read().unwrap()),
            format!("{:?}", *self.state.pi_store.read().unwrap()),
            format!("{:?}", *self.state.svc_store.read().unwrap()),
        )
    }
}

#[tokio::test]
async fn snapshot_leaves_claims_queues_database_and_registration_stores_untouched() {
    let fixture = Fixture::new();
    fixture.seed();
    let before = std::fs::read(fixture.root.path().join("primary.sqlite")).unwrap();
    let changes = fixture.state.db.lock().unwrap().total_changes();
    let stores = fixture.store_snapshot();
    for query in [
        "?read_only=true",
        "?read_only=true&node=local",
        "?read_only=true&node=snapshot.example",
    ] {
        let (status, value) = fixture.get(query).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(value["read_only"], true);
        assert_eq!(value["partial"], true);
        let rows = value["recipients"].as_array().unwrap();
        assert!(rows
            .iter()
            .all(|r| matches!(r["status"].as_str(), Some("registered" | "seen"))));
        assert!(rows
            .iter()
            .any(|r| r["address"] == format!("{LIVE}@snapshot.example")));
        assert!(!rows
            .iter()
            .any(|r| r["address"] == format!("{NEW}@snapshot.example")));
        for id in [
            "agy-record",
            "pi-record",
            "status",
            "plugin-record",
            "codex-record",
            "expired",
        ] {
            assert!(
                rows.iter()
                    .any(|r| r["address"] == format!("{id}@snapshot.example")),
                "missing {id}: {value}"
            );
        }
        assert_eq!(
            fixture.state.db.lock().unwrap().total_changes(),
            changes,
            "snapshot wrote to the database"
        );
        assert_eq!(
            std::fs::read(fixture.root.path().join("primary.sqlite")).unwrap(),
            before,
            "snapshot changed database bytes"
        );
        assert_eq!(
            fixture.store_snapshot(),
            stores,
            "snapshot evicted or changed registration stores"
        );
        assert_eq!(
            fixture.inbox.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "snapshot delivered queued work"
        );
    }
}

#[tokio::test]
async fn snapshot_rejects_remote_and_live_filters_without_mutation() {
    let fixture = Fixture::new();
    fixture.seed();
    let changes = fixture.state.db.lock().unwrap().total_changes();
    for query in [
        "?read_only=true&node=remote.example",
        "?read_only=true&node=example",
        "?read_only=true&status=live",
        "?read_only=true&status=inactive",
        "?read_only=true&within=1",
        "?read_only=true&host=example",
        "?read_only=true&kind=unknown",
        "?read_only=1",
        "?read_only=true&unexpected=1",
    ] {
        let (status, value) = fixture.get(query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {value}");
        assert_eq!(fixture.state.db.lock().unwrap().total_changes(), changes);
    }
}

#[tokio::test]
async fn legacy_listing_still_reconciles_and_delivers_parent_and_child_queues() {
    let fixture = Fixture::new();
    fixture.seed();
    let changes = fixture.state.db.lock().unwrap().total_changes();
    let (status, value) = fixture.get("?node=snapshot.example&read_only=false").await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert!(fixture.state.db.lock().unwrap().total_changes() > changes);
    assert!(value["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["address"] == format!("{NEW}@snapshot.example")));
    assert!(fixture.state.agy_store.read().unwrap().is_empty());
    assert!(fixture.state.pi_store.read().unwrap().is_empty());
    assert!(fixture.state.svc_store.read().unwrap().is_empty());
    for _ in 0..2 {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match fixture.inbox.accept() {
                    Ok(value) => break value,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(5)).await
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        })
        .await
        .unwrap();
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut body = String::new();
        socket.read_to_string(&mut body).unwrap();
        assert!(body.contains("queued canary"));
    }
}

#[tokio::test]
async fn snapshot_is_bounded_sorted_and_registered_records_win_duplicates() {
    let fixture = Fixture::new();
    {
        let db = fixture.state.db.lock().unwrap();
        let transaction = db.unchecked_transaction().unwrap();
        for index in 0..1100 {
            transaction
                .execute(
                    "INSERT INTO instance_seen (id,harness,last_live) VALUES (?1,'pi',?2)",
                    rusqlite::params![format!("record-{index:04}"), index],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
    }
    fixture.state.pi_store.write().unwrap().insert(
        "record-0000".into(),
        xmsg::pi::PiSessionInfo {
            session_id: "record-0000".into(),
            name: Some("registered label".into()),
            pid: u32::MAX,
            starttime: "gone".into(),
            cwd: "/".into(),
            registered_at: 2000,
        },
    );
    let (status, value) = fixture.get("?read_only=true").await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["truncated"], true);
    let rows = value["recipients"].as_array().unwrap();
    assert_eq!(rows.len(), 1000);
    assert!(rows
        .windows(2)
        .all(|pair| pair[0]["address"].as_str() < pair[1]["address"].as_str()));
    let row = rows
        .iter()
        .find(|row| row["address"] == "record-0000@snapshot.example")
        .unwrap();
    assert_eq!(row["status"], "registered");
    assert_eq!(row["registered_at"], 2000);
    assert_eq!(row["last_seen"], 0);
    assert_eq!(row["label"], "registered label");
    let (_, again) = fixture.get("?read_only=true").await;
    assert_eq!(again, value);
}

#[tokio::test]
async fn snapshot_filters_known_records_without_discovery_or_admission() {
    let fixture = Fixture::new();
    fixture.seed();
    let (status, value) = fixture
        .get("?read_only=true&kind=service&name=status")
        .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let rows = value["recipients"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["address"], "status@snapshot.example");
    let (_, value) = fixture.get("?read_only=true&kind=subagent").await;
    let rows = value["recipients"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["address"],
        format!("{LIVE}/worker@snapshot.example")
    );
    assert_eq!(rows[0]["status"], "seen");
    fixture
        .state
        .agy_store
        .write()
        .unwrap()
        .get_mut("agy-record")
        .unwrap()
        .label = Some("  displayed  ".into());
    let (_, value) = fixture
        .get("?read_only=true&kind=instance&name=displayed")
        .await;
    let rows = value["recipients"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "name must filter the displayed normalized label"
    );
    assert_eq!(rows[0]["label"], "displayed");
}

#[tokio::test]
async fn snapshot_never_delivers_queued_parent_or_child_messages() {
    let fixture = Fixture::new();
    fixture.seed();
    let (status, value) = fixture.get("?read_only=true").await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(
        fixture.inbox.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "snapshot delivered queued work"
    );
    let db = fixture.state.db.lock().unwrap();
    let queued: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM instance_queue WHERE delivered_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(queued, 2);
}

#[tokio::test]
async fn unix_http_snapshot_keeps_caller_attribution_read_only() {
    let fixture = Fixture::new();
    fixture.seed();
    let socket = fixture.root.path().join("http.sock");
    let listener =
        xmsg::http::bind_ucred_unix_listener(&socket, xmsg::agent::current_uid(), None).unwrap();
    let app = xmsg::http::build_unix_router(fixture.state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<xmsg::http::HttpPeer>(),
        )
        .await
        .unwrap();
    });
    let before = fixture.state.db.lock().unwrap().total_changes();
    let stores = fixture.store_snapshot();
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let response = client
        .get("http://localhost/v1/recipients?read_only=true")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let value: Value = response.json().await.unwrap();
    assert_eq!(value["read_only"], true);
    assert_eq!(fixture.state.db.lock().unwrap().total_changes(), before);
    assert_eq!(fixture.store_snapshot(), stores);
    assert_eq!(
        fixture.inbox.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn cold_unix_http_snapshot_refuses_without_initializing_or_writing() {
    let fixture = Fixture::cold();
    fixture.seed();
    assert!(!xmsg::codex::runtime_initialized(&fixture.state.db));
    let socket = fixture.root.path().join("http.sock");
    let listener =
        xmsg::http::bind_ucred_unix_listener(&socket, xmsg::agent::current_uid(), None).unwrap();
    let app = xmsg::http::build_unix_router(fixture.state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<xmsg::http::HttpPeer>(),
        )
        .await
        .unwrap();
    });
    let before = fixture.state.db.lock().unwrap().total_changes();
    let bytes = std::fs::read(fixture.root.path().join("primary.sqlite")).unwrap();
    let stores = fixture.store_snapshot();
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let response = client
        .get("http://localhost/v1/recipients?read_only=true")
        .send()
        .await
        .unwrap();
    let after = fixture.state.db.lock().unwrap().total_changes();
    assert_eq!(
        response.status(),
        503,
        "cold snapshot must refuse; database changes before={before}, after={after}"
    );
    let value: Value = response.json().await.unwrap();
    assert_eq!(value["error"], "unavailable");
    assert!(value["detail"].as_str().unwrap().contains("initializ"));
    assert_eq!(after, before);
    assert!(!xmsg::codex::runtime_initialized(&fixture.state.db));
    assert_eq!(
        std::fs::read(fixture.root.path().join("primary.sqlite")).unwrap(),
        bytes
    );
    assert_eq!(fixture.store_snapshot(), stores);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn cold_legacy_listing_keeps_its_existing_initialization_and_delivery_behavior() {
    let fixture = Fixture::cold();
    fixture.seed();
    assert!(!xmsg::codex::runtime_initialized(&fixture.state.db));
    let (status, value) = fixture.get("?read_only=false&node=snapshot.example").await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert!(value.get("read_only").is_none());
    assert!(xmsg::codex::runtime_initialized(&fixture.state.db));
    let queued: i64 = fixture
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM instance_queue WHERE delivered_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(queued, 0);
}

#[tokio::test]
async fn snapshot_last_seen_comes_only_from_recorded_seen_evidence() {
    let fixture = Fixture::new();
    {
        let db = fixture.state.db.lock().unwrap();
        db.execute("INSERT INTO instance_claims VALUES ('44444444-4444-4444-8444-444444444444',4294967295,'gone',2,1,123)",[]).unwrap();
        db.execute("INSERT INTO codex_roots (root_id,codex_home,owner_pid,owner_starttime,generation,label,registered_at,active) VALUES ('inactive-codex','/nonexistent',4294967295,'gone',1,'prior label',456,0)",[]).unwrap();
        db.execute("INSERT INTO subagents (parent,agent_id,bound_at,last_active) VALUES ('unseen-parent','child',789,0)",[]).unwrap();
    }
    let (_, value) = fixture.get("?read_only=true").await;
    let rows = value["recipients"].as_array().unwrap();
    for id in ["44444444-4444-4444-8444-444444444444~2", "inactive-codex"] {
        let row = rows
            .iter()
            .find(|r| r["address"] == format!("{id}@snapshot.example"))
            .unwrap();
        assert_eq!(row["status"], "seen");
        assert!(
            row["last_seen"].is_null(),
            "registration time is not last seen: {row}"
        );
    }
    {
        let db = fixture.state.db.lock().unwrap();
        db.execute("INSERT INTO instance_seen (id,harness,last_live) VALUES ('44444444-4444-4444-8444-444444444444~2','claude',789),('inactive-codex','codex',987)",[]).unwrap();
        db.execute("UPDATE subagents SET last_active=555 WHERE parent='unseen-parent' AND agent_id='child'",[]).unwrap();
    }
    let (_, value) = fixture.get("?read_only=true").await;
    let rows = value["recipients"].as_array().unwrap();
    for (id, seen) in [
        ("44444444-4444-4444-8444-444444444444~2", 789),
        ("inactive-codex", 987),
        ("unseen-parent/child", 555),
    ] {
        let row = rows
            .iter()
            .find(|r| r["address"] == format!("{id}@snapshot.example"))
            .unwrap();
        assert_eq!(row["last_seen"], seen);
    }
}
