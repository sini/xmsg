#[path = "support/spawn.rs"]
mod spawn;
use serde_json::{json, Value};
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use xmsg::http::{bind_ucred_unix_listener, build_unix_router, AppState, HttpPeer};

const LIVE: &str = "11111111-1111-4111-8111-111111111111";
const GONE: &str = "33333333-3333-4333-8333-333333333333";
const UNRECONCILED: &str = "22222222-2222-4222-8222-222222222222";
const NODE: &str = "doctor.example";

struct Fixture {
    root: TempDir,
    state: Arc<AppState>,
    inbox: UnixListener,
    _sockets: Vec<UnixListener>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(unavailable_backend: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let run = root.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(root.path().join("sessions")).unwrap();
        let mut sockets = Vec::new();
        for name in ["agent.sock", "register.sock"] {
            let socket = UnixListener::bind(run.join(name)).unwrap();
            std::fs::set_permissions(run.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            sockets.push(socket);
        }
        let inbox = UnixListener::bind(root.path().join("inbox.sock")).unwrap();
        inbox.set_nonblocking(true).unwrap();
        let db_path = root.path().join("primary.sqlite");
        let db = rusqlite::Connection::open(&db_path).unwrap();
        xmsg::storage::init_db(&db).unwrap();
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let observer = root.path().join("primary.sqlite.observe.sqlite");
        std::fs::write(&observer, "doctor observer metadata canary").unwrap();
        std::fs::set_permissions(observer, std::fs::Permissions::from_mode(0o600)).unwrap();
        let state = Arc::new(AppState {
            sessions_dirs: vec![root.path().join("sessions")],
            agy_config: xmsg::agy::AgyConfig {
                proc_root: if unavailable_backend {
                    root.path().join("unavailable-proc")
                } else {
                    Path::new(xmsg::process::LIVE_PROC_ROOT).to_owned()
                },
                presence_dir: root.path().join("presence"),
                brain_dir: root.path().join("brain"),
                ..Default::default()
            },
            agy_store: xmsg::agy::new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            node_name: NODE.into(),
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
        xmsg::codex::init_for_state(&state, xmsg::codex::CodexConfig::default());
        let socket = run.join("http.sock");
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
        let fixture = Self {
            root,
            state,
            inbox,
            _sockets: sockets,
            server,
        };
        fixture.seed();
        fixture
    }

    fn seed(&self) {
        let pid = std::process::id();
        let token =
            xmsg::process::starttime(Path::new(xmsg::process::LIVE_PROC_ROOT), pid).unwrap();
        let mut exited = Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
        let dead_pid = exited.id();
        assert!(exited.wait().unwrap().success());
        for (id, label) in [(LIVE, "recorded"), (UNRECONCILED, "not-yet-observed")] {
            std::fs::write(
                self.root.path().join("sessions").join(format!("{id}.json")),
                json!({
                    "pid":pid,"sessionId":id,"name":label,"cwd":"/workspace","status":"idle",
                    "kind":"interactive","startedAt":1000,"updatedAt":2000,"procStart":token,
                    "messagingSocketPath":self.root.path().join("inbox.sock")
                })
                .to_string(),
            )
            .unwrap();
        }
        let db = self.state.db.lock().unwrap();
        let now = xmsg::storage::now_epoch_secs();
        db.execute(
            "INSERT INTO instance_claims VALUES (?1,?2,?3,1,0,?4)",
            rusqlite::params![LIVE, pid, token, now],
        )
        .unwrap();
        db.execute(
            "INSERT INTO instance_claims VALUES (?1,?2,'exited-process-token',1,0,?3)",
            rusqlite::params![GONE, dead_pid, now],
        )
        .unwrap();
        xmsg::storage::insert_queued(
            &db,
            &xmsg::storage::QueuedMessage {
                id: "doctor-queued-canary".into(),
                instance_id: LIVE.into(),
                created_at: now,
                expires_at: now + 3600,
                from_name: "fixture".into(),
                body: "doctor must not deliver this queued canary".into(),
            },
        )
        .unwrap();
        self.state.pi_store.write().unwrap().insert(
            "stale-pi".into(),
            xmsg::pi::PiSessionInfo {
                session_id: "stale-pi".into(),
                name: Some("stale registration".into()),
                pid: dead_pid,
                starttime: "exited-process-token".into(),
                cwd: "/".into(),
                registered_at: now,
                reg: String::new(),
            },
        );
    }

    fn registration_stores(&self) -> (String, String, String) {
        (
            format!("{:?}", *self.state.agy_store.read().unwrap()),
            format!("{:?}", *self.state.pi_store.read().unwrap()),
            format!("{:?}", *self.state.svc_store.read().unwrap()),
        )
    }

    async fn report(&self) -> (Output, Value) {
        let root = self.root.path().to_owned();
        let output = tokio::task::spawn_blocking(move || {
            spawn::command(env!("CARGO_BIN_EXE_xmsg"))
                .env_remove("XMSG_PEERS_FILE")
                .env_remove("XMSG_FED_CERT")
                .env("HOME", root.join("home"))
                .env("XDG_STATE_HOME", root.join("state"))
                .env("XDG_RUNTIME_DIR", root.join("run"))
                .args(["doctor", "--json", "--http-sock"])
                .arg(root.join("run/http.sock"))
                .arg("--agent-sock")
                .arg(root.join("run/agent.sock"))
                .arg("--register-sock")
                .arg(root.join("run/register.sock"))
                .arg("--db-path")
                .arg(root.join("primary.sqlite"))
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid doctor JSON: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output, report)
    }

    fn assert_untouched(&self, before: &[u8], changes: u64, stores: &(String, String, String)) {
        assert_eq!(
            self.state.db.lock().unwrap().total_changes(),
            changes,
            "doctor reconciled claims or delivered queued work"
        );
        assert_eq!(
            std::fs::read(self.root.path().join("primary.sqlite")).unwrap(),
            before,
            "doctor changed database bytes"
        );
        assert_eq!(
            &self.registration_stores(),
            stores,
            "doctor pruned or changed registration stores"
        );
        let db = self.state.db.lock().unwrap();
        let pending: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM instance_claims WHERE id=?1",
                [UNRECONCILED],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "doctor registered an unreconciled session");
        let queued: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM instance_queue WHERE id='doctor-queued-canary' AND delivered_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(queued, 1, "doctor consumed queued work");
        assert_eq!(
            self.inbox.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "doctor delivered queued work"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap_or_else(|| panic!("missing {id}: {report}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_reports_registered_process_live_and_gone_without_delivery_readiness_claim() {
    let fixture = Fixture::new(false).await;
    let (output, report) = fixture.report().await;
    assert!(output.status.success(), "{report}");
    let aggregate = check(&report, "sessions.process");
    assert!(aggregate["message"].as_str().unwrap().contains("live"));
    assert!(!report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == format!("session.process.{LIVE}@{NODE}")));
    let gone = check(&report, &format!("session.process.{GONE}@{NODE}"));
    assert_eq!(gone["status"], "warn", "{report}");
    assert_eq!(gone["message"], "process gone");
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| { !row["message"].as_str().unwrap().contains("delivery ready") }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_process_liveness_never_reconciles_claims_or_delivers_queue() {
    let fixture = Fixture::new(false).await;
    let before = std::fs::read(fixture.root.path().join("primary.sqlite")).unwrap();
    let changes = fixture.state.db.lock().unwrap().total_changes();
    let stores = fixture.registration_stores();
    let (output, report) = fixture.report().await;
    fixture.assert_untouched(&before, changes, &stores);
    assert!(output.status.success(), "{report}");
    assert!(check(&report, "sessions.process")["message"]
        .as_str()
        .unwrap()
        .contains("live"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_process_backend_is_unknown_with_one_portability_warning() {
    let fixture = Fixture::new(true).await;
    let (output, report) = fixture.report().await;
    assert!(output.status.success(), "{report}");
    assert_eq!(check(&report, "sessions.process")["status"], "warn");
    assert!(check(&report, "sessions.process")["message"]
        .as_str()
        .unwrap()
        .contains("backend_unavailable"));
    assert!(!report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"].as_str().unwrap().starts_with("session.process.")));
    let backend = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["id"] == "sessions.process_backend")
        .collect::<Vec<_>>();
    assert_eq!(backend.len(), 1, "{report}");
    assert_eq!(backend[0]["status"], "warn");
}
