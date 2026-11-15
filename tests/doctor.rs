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
                        let body = health.to_string();
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
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

    fn assert_health_only(&self) {
        let requests = self.requests.lock().unwrap();
        assert!(!requests.is_empty(), "health detector never ran");
        assert!(
            requests
                .iter()
                .all(|request| request == "GET /healthz HTTP/1.1"),
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
fn healthy_json_is_read_only_and_requests_only_health() {
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
    fixture.assert_health_only();
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
fn health_payload_sessions_directory_failure_is_detected() {
    let fixture = Fixture::new(json!({"status":"ok", "sessions_dir":"sessions_dir_missing"}));
    let (output, report) = fixture.report();
    assert_eq!(output.status.code(), Some(1));
    status(&report, "daemon.sessions_directory", "fail");
    fixture.assert_health_only();
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
    fixture.assert_health_only();
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
