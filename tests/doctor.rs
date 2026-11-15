use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

struct Fixture {
    root: tempfile::TempDir,
    run: PathBuf,
    db: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
    _sockets: Vec<UnixListener>,
}

impl Fixture {
    fn new(health: Value) -> Self {
        Self::with_snapshot(
            health,
            200,
            json!({"read_only":true,"partial":true,"truncated":false,"recipients":[]}),
        )
    }

    fn with_snapshot(health: Value, snapshot_status: u16, snapshot: Value) -> Self {
        let root = tempfile::tempdir().unwrap();
        let run = root.path().join("run");
        fs::create_dir(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let mut sockets = Vec::new();
        for name in ["agent.sock", "register.sock"] {
            let socket = UnixListener::bind(run.join(name)).unwrap();
            fs::set_permissions(run.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            sockets.push(socket);
        }
        let listener = UnixListener::bind(run.join("http.sock")).unwrap();
        fs::set_permissions(run.join("http.sock"), fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let server = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        captured.lock().unwrap().push(line.trim().to_owned());
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                                break;
                            }
                        }
                        let is_health = captured
                            .lock()
                            .unwrap()
                            .last()
                            .is_some_and(|request| request == "GET /healthz HTTP/1.1");
                        let body = if is_health { &health } else { &snapshot }.to_string();
                        let status = if is_health { 200 } else { snapshot_status };
                        let _ = write!(stream, "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                }
            }
        });
        let db = root.path().join("xmsg.db");
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection.execute_batch("PRAGMA user_version=3; CREATE TABLE planted (value TEXT); INSERT INTO planted VALUES ('doctor-must-not-write');").unwrap();
        drop(connection);
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
        let observe = PathBuf::from(format!("{}.observe.sqlite", db.display()));
        fs::write(&observe, b"metadata-only-observer-canary").unwrap();
        fs::set_permissions(observe, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root,
            run,
            db,
            requests,
            stop,
            server: Some(server),
            _sockets: sockets,
        }
    }

    fn healthy() -> Self {
        Self::new(json!({"status":"ok", "sessions_dir":"ok"}))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xmsg"));
        command
            .env_remove("XMSG_PEERS_FILE")
            .env_remove("XMSG_FED_CERT")
            .env("HOME", self.root.path().join("home"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("XDG_RUNTIME_DIR", &self.run)
            .args(["doctor", "--http-sock"])
            .arg(self.run.join("http.sock"))
            .arg("--agent-sock")
            .arg(self.run.join("agent.sock"))
            .arg("--register-sock")
            .arg(self.run.join("register.sock"))
            .arg("--db-path")
            .arg(&self.db);
        command
    }

    fn report(&self) -> (Output, Value) {
        let output = self.command().arg("--json").output().unwrap();
        let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid JSON: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output, report)
    }

    fn assert_read_only_requests(&self) {
        let requests = self.requests.lock().unwrap();
        assert!(!requests.is_empty(), "health detector never ran");
        assert!(
            requests.iter().all(|request| matches!(
                request.as_str(),
                "GET /healthz HTTP/1.1"
                    | "GET /v1/recipients?read_only=true&liveness=true HTTP/1.1"
            )),
            "unexpected requests: {requests:?}"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.server.take().unwrap().join().unwrap();
    }
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap_or_else(|| panic!("missing {id}: {report}"))
}

fn status(report: &Value, id: &str, expected: &str) {
    assert_eq!(check(report, id)["status"], expected, "{id}: {report}");
}

fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>, u32)> {
    fn visit(root: &Path, directory: &Path, entries: &mut Vec<(PathBuf, Vec<u8>, u32)>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            let relative = entry.path().strip_prefix(root).unwrap().to_owned();
            if metadata.is_dir() {
                entries.push((relative, Vec::new(), metadata.permissions().mode()));
                visit(root, &entry.path(), entries);
            } else if metadata.is_file() {
                entries.push((
                    relative,
                    fs::read(entry.path()).unwrap(),
                    metadata.permissions().mode(),
                ));
            }
        }
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries);
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

#[test]
fn healthy_json_is_read_only_and_requests_only_read_only_sources() {
    let fixture = Fixture::healthy();
    let before = snapshot(fixture.root.path());
    let (output, report) = fixture.report();
    assert!(output.status.success(), "{report}");
    for id in [
        "runtime.directory",
        "socket.http",
        "socket.agent",
        "socket.register",
        "daemon.health",
        "daemon.sessions_directory",
        "database.schema_version",
        "database.journal",
        "observe.file",
    ] {
        status(&report, id, "pass");
    }
    assert_eq!(report["failed"], 0);
    assert!(report["client_version"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert!(report["not_checked"]
        .as_array()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(
        snapshot(fixture.root.path()),
        before,
        "doctor created or changed persistent fixture files"
    );
    fixture.assert_read_only_requests();
}

#[test]
fn missing_observer_warns_without_failing_or_creating_it() {
    let fixture = Fixture::healthy();
    let observer = PathBuf::from(format!("{}.observe.sqlite", fixture.db.display()));
    fs::remove_file(&observer).unwrap();
    let (output, report) = fixture.report();
    assert!(output.status.success(), "{report}");
    status(&report, "observe.file", "warn");
    assert!(!observer.exists());
    assert!(report["warnings"].as_u64().unwrap() > 0);
}

#[test]
fn unsafe_runtime_and_socket_modes_are_failures() {
    let fixture = Fixture::healthy();
    fs::set_permissions(&fixture.run, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        fixture.run.join("agent.sock"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let (output, report) = fixture.report();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "runtime.directory", "fail");
    status(&report, "socket.agent", "fail");
    assert_eq!(
        fs::metadata(&fixture.run).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn missing_register_socket_fails_without_recreating_it() {
    let fixture = Fixture::healthy();
    fs::remove_file(fixture.run.join("register.sock")).unwrap();
    let (output, report) = fixture.report();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "socket.register", "fail");
    assert!(!fixture.run.join("register.sock").exists());
}

#[test]
fn missing_optional_sessions_directory_warns_without_failing_node() {
    let fixture = Fixture::new(json!({"status":"ok", "sessions_dir":"sessions_dir_missing"}));
    let (output, report) = fixture.report();
    assert_eq!(output.status.code(), Some(0));
    status(&report, "daemon.sessions_directory", "warn");
    fixture.assert_read_only_requests();
}

#[test]
fn future_schema_fails_without_modifying_database() {
    let fixture = Fixture::healthy();
    rusqlite::Connection::open(&fixture.db)
        .unwrap()
        .execute_batch("PRAGMA user_version=999;")
        .unwrap();
    let before = fs::read(&fixture.db).unwrap();
    let (output, report) = fixture.report();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "database.schema_version", "fail");
    assert_eq!(fs::read(&fixture.db).unwrap(), before);
}

#[test]
fn journal_is_uncertainty_not_a_recovery_or_hot_journal_claim() {
    let fixture = Fixture::healthy();
    let journal = PathBuf::from(format!("{}-journal", fixture.db.display()));
    fs::write(&journal, b"unknown-journal-canary").unwrap();
    let before = snapshot(fixture.root.path());
    let (output, report) = fixture.report();
    assert!(output.status.success(), "{report}");
    status(&report, "database.journal", "warn");
    status(&report, "database.schema_version", "warn");
    assert_eq!(snapshot(fixture.root.path()), before);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("unknown-journal-canary"));
}

#[test]
fn malformed_explicit_peers_file_fails_without_network_or_rewrite() {
    let fixture = Fixture::healthy();
    let peers = fixture.root.path().join("peers.json");
    fs::write(&peers, b"{not valid JSON").unwrap();
    let output = fixture
        .command()
        .arg("--peers-file")
        .arg(&peers)
        .arg("--json")
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "peers.file", "fail");
    assert_eq!(fs::read(peers).unwrap(), b"{not valid JSON");
    fixture.assert_read_only_requests();
}

fn enrollment(fixture: &Fixture, issued_at: i64, not_after: i64) -> PathBuf {
    let directory = fixture.root.path().join("enrollment");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(directory.join("enroll.json"), json!({"url":"https://127.0.0.1:1", "fingerprint":format!("sha256:{}", "0".repeat(64)), "ca_identity":"fixture-ca", "serial":"fixture-serial", "issued_at":issued_at, "not_after":not_after}).to_string()).unwrap();
    fs::set_permissions(
        directory.join("enroll.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    directory
}

#[test]
fn expired_enrollment_fails_from_public_metadata_only() {
    let fixture = Fixture::healthy();
    let directory = enrollment(&fixture, 1, 2);
    let before = snapshot(fixture.root.path());
    let output = fixture
        .command()
        .arg("--enroll-state")
        .arg(directory)
        .arg("--json")
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "enrollment.expiry", "fail");
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn renewal_due_warns_and_unreachable_ca_does_not_invent_expiry() {
    let fixture = Fixture::healthy();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let directory = enrollment(&fixture, now - 2000, now + 500);
    let output = fixture
        .command()
        .arg("--enroll-state")
        .arg(directory)
        .arg("--json")
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{report}");
    status(&report, "enrollment.expiry", "pass");
    status(&report, "enrollment.renewal", "warn");
    status(&report, "enrollment.ca_tls", "warn");
}

#[test]
fn text_output_has_detector_and_actionable_hint() {
    let fixture = Fixture::healthy();
    fs::remove_file(fixture.run.join("register.sock")).unwrap();
    let output = fixture.command().output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("socket.register"), "{text}");
    assert!(text.to_lowercase().contains("fail"), "{text}");
    assert!(
        text.len() > "socket.register fail".len(),
        "missing explanation: {text}"
    );
}

#[test]
fn unhealthy_daemon_payload_is_not_reported_as_pass() {
    let fixture = Fixture::new(json!({"status":"broken", "sessions_dir":"ok"}));
    let (output, report) = fixture.report();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "daemon.health", "fail");
}

#[test]
fn observer_permissions_are_checked_without_opening_its_contents() {
    let fixture = Fixture::healthy();
    let observer = PathBuf::from(format!("{}.observe.sqlite", fixture.db.display()));
    fs::set_permissions(&observer, fs::Permissions::from_mode(0o644)).unwrap();
    let (output, report) = fixture.report();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "observe.file", "fail");
    assert_eq!(
        fs::read(observer).unwrap(),
        b"metadata-only-observer-canary"
    );
}

#[test]
fn malformed_enrollment_metadata_fails_without_creating_identity_files() {
    let fixture = Fixture::healthy();
    let directory = fixture.root.path().join("enrollment");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(directory.join("enroll.json"), b"not-json-canary").unwrap();
    fs::set_permissions(
        directory.join("enroll.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let before = snapshot(fixture.root.path());
    let output = fixture
        .command()
        .arg("--enroll-state")
        .arg(directory)
        .arg("--json")
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "enrollment.metadata", "fail");
    assert_eq!(snapshot(fixture.root.path()), before);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("not-json-canary"));
}

#[test]
fn wal_companion_is_not_opened_or_modified() {
    let fixture = Fixture::healthy();
    let wal = PathBuf::from(format!("{}-wal", fixture.db.display()));
    fs::write(&wal, b"wal-canary").unwrap();
    let before = snapshot(fixture.root.path());
    let (output, report) = fixture.report();
    assert!(output.status.success(), "{report}");
    status(&report, "database.schema_version", "warn");
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn invalid_saved_ca_configuration_fails_without_rewriting_metadata() {
    let fixture = Fixture::healthy();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let directory = enrollment(&fixture, now - 10, now + 1000);
    let file = directory.join("enroll.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    state["url"] = json!("http://invalid.example");
    fs::write(&file, state.to_string()).unwrap();
    let before = snapshot(fixture.root.path());
    let output = fixture
        .command()
        .arg("--enroll-state")
        .arg(directory)
        .arg("--json")
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "enrollment.ca_tls", "fail");
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn unsafe_socket_mode_fails_with_private_runtime() {
    let fixture = Fixture::healthy();
    fs::set_permissions(
        fixture.run.join("agent.sock"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let (output, report) = fixture.report();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "runtime.directory", "pass");
    status(&report, "socket.agent", "fail");
}

#[test]
fn daemon_build_metadata_is_reported_without_guessing() {
    let fixture = Fixture::new(
        json!({"status":"ok", "sessions_dir":"ok", "version":"0.1.7", "build_revision":"fixture-other-revision"}),
    );
    let (output, report) = fixture.report();
    assert!(output.status.success());
    status(&report, "daemon.version", "pass");
    assert!(check(&report, "daemon.version")["message"]
        .as_str()
        .unwrap()
        .contains("0.1.7"));
    status(&report, "daemon.build_revision", "warn");
    assert!(check(&report, "daemon.build_revision")["message"]
        .as_str()
        .unwrap()
        .contains("fixture-other-revision"));
    assert_eq!(
        report["client_build_revision"],
        option_env!("XMSG_BUILD_REVISION").unwrap_or("unknown")
    );
    let text = fixture.command().output().unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("fixture-other-revision") && text.contains("0.1.7"));
    fixture.assert_read_only_requests();
}

#[test]
fn missing_or_invalid_daemon_metadata_warns_without_failing_health() {
    for metadata in [
        json!({}),
        json!({"version":12,"build_revision":false}),
        json!({"version":"","build_revision":"unknown"}),
    ] {
        let mut health = json!({"status":"ok", "sessions_dir":"ok"});
        health
            .as_object_mut()
            .unwrap()
            .extend(metadata.as_object().unwrap().clone());
        let fixture = Fixture::new(health);
        let (output, report) = fixture.report();
        assert!(output.status.success());
        status(&report, "daemon.health", "pass");
        status(&report, "daemon.version", "warn");
        status(&report, "daemon.build_revision", "warn");
        assert!(check(&report, "daemon.build_revision")["message"]
            .as_str()
            .unwrap()
            .contains("unknown"));
    }
}

#[test]
fn matching_build_revision_passes_only_when_known() {
    let revision = option_env!("XMSG_BUILD_REVISION").unwrap_or("unknown");
    let fixture = Fixture::new(
        json!({"status":"ok", "sessions_dir":"ok", "version":env!("CARGO_PKG_VERSION"), "build_revision":revision}),
    );
    let (output, report) = fixture.report();
    assert!(output.status.success());
    status(
        &report,
        "daemon.build_revision",
        if revision == "unknown" {
            "warn"
        } else {
            "pass"
        },
    );
}

#[test]
fn unsupported_or_cold_process_source_warns_without_live_listing_fallback() {
    for code in [400, 404, 503] {
        let fixture = Fixture::with_snapshot(
            json!({"status":"ok","sessions_dir":"ok"}),
            code,
            json!({"error":"unsupported"}),
        );
        let (output, report) = fixture.report();
        assert!(output.status.success());
        status(&report, "sessions.process", "warn");
        assert!(check(&report, "sessions.process")["message"]
            .as_str()
            .unwrap()
            .contains("unknown"));
        fixture.assert_read_only_requests();
        assert_eq!(
            fixture.requests.lock().unwrap().len(),
            2,
            "doctor retried through another route"
        );
    }
}

#[test]
fn unavailable_process_backend_is_explained_once_without_claiming_death() {
    let fixture = Fixture::with_snapshot(
        json!({"status":"ok","sessions_dir":"ok"}),
        200,
        json!({"read_only":true,"partial":true,"truncated":false,"recipients":[
            {"address":"one@fixture","process_liveness":{"state":"unknown","reason":"backend_unavailable"}},
            {"address":"two@fixture","process_liveness":{"state":"unknown","reason":"backend_unavailable"}}
        ]}),
    );
    let (output, report) = fixture.report();
    assert!(output.status.success());
    status(&report, "session.process.one@fixture", "warn");
    status(&report, "session.process.two@fixture", "warn");
    for address in ["one@fixture", "two@fixture"] {
        assert_eq!(
            check(&report, &format!("session.process.{address}"))["message"],
            "process unknown"
        );
    }
    assert_eq!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["id"] == "sessions.process_backend")
            .count(),
        1
    );
}

#[test]
fn process_rows_are_bounded_and_terminal_ids_are_inert() {
    let rows: Vec<_> = (0..1001).map(|i| json!({"address":format!("session-{i}\u{1b}[31m@fixture"),"process_liveness":{"state":"live","reason":"identity_match"}})).collect();
    let fixture = Fixture::with_snapshot(
        json!({"status":"ok","sessions_dir":"ok"}),
        200,
        json!({"read_only":true,"partial":true,"truncated":true,"recipients":rows}),
    );
    let (output, report) = fixture.report();
    assert!(output.status.success());
    assert_eq!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["id"].as_str().unwrap().starts_with("session.process."))
            .count(),
        1000
    );
    status(&report, "sessions.process", "warn");
    let text = fixture.command().output().unwrap();
    assert!(text.status.success());
    assert!(!String::from_utf8_lossy(&text.stdout).contains('\u{1b}'));
}

#[test]
fn registration_status_without_process_evidence_stays_unknown() {
    for snapshot in [
        json!({"read_only":false,"partial":true,"truncated":false,"recipients":[{"address":"one@fixture","status":"live"}]}),
        json!({"read_only":true,"partial":true,"truncated":false,"recipients":[{"address":"one@fixture","status":"registered"}]}),
    ] {
        let fixture =
            Fixture::with_snapshot(json!({"status":"ok","sessions_dir":"ok"}), 200, snapshot);
        let (output, report) = fixture.report();
        assert!(output.status.success());
        status(&report, "sessions.process", "warn");
        assert!(!report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |row| row["id"].as_str().unwrap().starts_with("session.process.")
                    && row["status"] == "pass"
            ));
    }
}
