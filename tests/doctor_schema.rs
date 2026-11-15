use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::{
    fs::{MetadataExt, PermissionsExt},
    net::UnixListener,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

const PRIVATE_ROW: &str = "schema-row-must-not-be-printed";
const OLD_CODEX_ROOTS: &str = "CREATE TABLE codex_roots (
    root_id TEXT PRIMARY KEY, codex_home TEXT NOT NULL, owner_pid INTEGER NOT NULL,
    owner_starttime TEXT NOT NULL, generation INTEGER NOT NULL, label TEXT NOT NULL,
    cwd TEXT, registered_at INTEGER NOT NULL, rollout_dev INTEGER NOT NULL DEFAULT 0,
    rollout_ino INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
    revoked INTEGER NOT NULL DEFAULT 0
)";

#[derive(Clone, Copy)]
enum Health {
    Down,
    Unknown,
    Live,
}

#[derive(Clone, Copy)]
enum Shape {
    Current,
    OldAdditive,
    MissingRestart,
}

#[derive(Clone, Copy)]
enum Mode {
    Closed,
    ClosedWal,
    HeldWal,
    HeldWalMigration,
    HeldJournal,
}

struct Fixture {
    root: TempDir,
    db_dir: PathBuf,
    db: PathBuf,
    run: PathBuf,
    writer: Option<rusqlite::Connection>,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
    _sockets: Vec<UnixListener>,
}

impl Fixture {
    fn new(version: i64, shape: Shape, health: Health, mode: Mode) -> Self {
        let root = tempfile::tempdir().unwrap();
        let db_dir = root.path().join("database");
        let run = root.path().join("run");
        for directory in [&db_dir, &run] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let db = db_dir.join("xmsg.db");
        let connection = rusqlite::Connection::open(&db).unwrap();
        for (name, ddl) in current_fixture_ddl() {
            if matches!(shape, Shape::OldAdditive)
                && matches!(name.as_str(), "blob_chunks" | "idx_outbound_created_at")
            {
                continue;
            }
            if name == "codex_roots" && !matches!(shape, Shape::Current) {
                connection.execute_batch(OLD_CODEX_ROOTS).unwrap();
            } else {
                connection.execute_batch(&ddl).unwrap();
            }
        }
        connection
            .execute_batch(&format!("PRAGMA user_version={version};"))
            .unwrap();
        connection.execute("INSERT INTO messages(id,created_at,session_id,from_name,bytes,outcome) VALUES ('committed-schema-fixture',1,'fixture',?1,1,'queued')", [PRIVATE_ROW]).unwrap();
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
        let writer = match mode {
            Mode::Closed => {
                drop(connection);
                None
            }
            Mode::ClosedWal | Mode::HeldWal | Mode::HeldWalMigration => {
                let journal_mode: String = connection
                    .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(journal_mode, "wal");
                if matches!(mode, Mode::HeldWalMigration) {
                    let main_before = fs::read(&db).unwrap();
                    connection.execute_batch("ALTER TABLE codex_roots ADD COLUMN restart_pending INTEGER NOT NULL DEFAULT 0").unwrap();
                    assert_eq!(
                        fs::read(&db).unwrap(),
                        main_before,
                        "fixture DDL must still be present in WAL rather than the main file"
                    );
                } else {
                    connection.execute("INSERT INTO messages(id,created_at,session_id,from_name,bytes,outcome) VALUES ('wal-schema-fixture',2,'fixture',?1,1,'queued')", [PRIVATE_ROW]).unwrap();
                }
                if matches!(mode, Mode::ClosedWal) {
                    drop(connection);
                    assert!(!sidecar(&db, "-wal").exists());
                    assert!(!sidecar(&db, "-shm").exists());
                    None
                } else {
                    assert!(sidecar(&db, "-wal").is_file());
                    assert!(sidecar(&db, "-shm").is_file());
                    Some(connection)
                }
            }
            Mode::HeldJournal => {
                connection.execute_batch("BEGIN; INSERT INTO messages(id,created_at,session_id,from_name,bytes,outcome) VALUES ('uncommitted-schema-fixture',3,'fixture','uncommitted-canary',1,'queued')").unwrap();
                assert!(sidecar(&db, "-journal").is_file());
                assert!(fs::metadata(sidecar(&db, "-journal")).unwrap().len() > 0);
                Some(connection)
            }
        };
        let mut sockets = Vec::new();
        for name in ["agent.sock", "register.sock"] {
            let socket = UnixListener::bind(run.join(name)).unwrap();
            fs::set_permissions(run.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            sockets.push(socket);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let server = if matches!(health, Health::Down) {
            None
        } else {
            let listener = UnixListener::bind(run.join("http.sock")).unwrap();
            fs::set_permissions(run.join("http.sock"), fs::Permissions::from_mode(0o600)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let stopping = stop.clone();
            Some(thread::spawn(move || {
                while !stopping.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let mut reader = BufReader::new(stream.try_clone().unwrap());
                            let mut request = String::new();
                            if reader.read_line(&mut request).unwrap() == 0 {
                                continue;
                            }
                            loop {
                                let mut line = String::new();
                                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                                    break;
                                }
                            }
                            let (status, value) = match request.trim() {
                                "GET /healthz HTTP/1.1" if matches!(health, Health::Live) => (
                                    200,
                                    json!({"status":"ok","sessions_dir":"ok","version":env!("CARGO_PKG_VERSION"),"build_revision":"fixture-other-revision"}),
                                ),
                                "GET /healthz HTTP/1.1" => (503, json!({"status":"starting"})),
                                "GET /v1/recipients?read_only=true&liveness=true HTTP/1.1" => (
                                    200,
                                    json!({"read_only":true,"partial":true,"truncated":false,"recipients":[]}),
                                ),
                                "GET /v1/diagnostics/federation HTTP/1.1" => {
                                    (200, json!({"available":false}))
                                }
                                other => panic!("unexpected doctor request: {other}"),
                            };
                            let body = value.to_string();
                            let _ = write!(stream, "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("fixture accept: {error}"),
                    }
                }
            }))
        };
        Self {
            root,
            db_dir,
            db,
            run,
            writer,
            stop,
            server,
            _sockets: sockets,
        }
    }

    fn report(&self) -> (Output, Value) {
        let output = Command::new(env!("CARGO_BIN_EXE_xmsg"))
            .env_remove("XMSG_PEERS_FILE")
            .env_remove("XMSG_FED_CERT")
            .env("HOME", self.root.path().join("home"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("XDG_RUNTIME_DIR", &self.run)
            .args(["doctor", "--json", "--http-sock"])
            .arg(self.run.join("http.sock"))
            .arg("--agent-sock")
            .arg(self.run.join("agent.sock"))
            .arg("--register-sock")
            .arg(self.run.join("register.sock"))
            .arg("--db-path")
            .arg(&self.db)
            .output()
            .unwrap();
        let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid doctor JSON: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(PRIVATE_ROW),
            "schema status printed row contents"
        );
        (output, report)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().unwrap();
        }
        drop(self.writer.take());
    }
}

fn current_fixture_ddl() -> Vec<(String, String)> {
    let seed = rusqlite::Connection::open_in_memory().unwrap();
    xmsg::storage::init_db(&seed).unwrap();
    let mut statement = seed.prepare("SELECT name,sql FROM sqlite_master WHERE type IN ('table','index') AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END,name").unwrap();
    let records = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    records
}

fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", db.display()))
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    kind: &'static str,
    mode: u32,
    size: u64,
    device: u64,
    inode: u64,
    sha256: Option<String>,
}

fn snapshot(directory: &Path, live_shm_readmarks: bool) -> BTreeMap<PathBuf, Entry> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            let kind = if metadata.is_file() {
                "regular"
            } else if metadata.is_dir() {
                "directory"
            } else {
                "other"
            };
            let excluded =
                live_shm_readmarks && entry.file_name().to_str().unwrap().ends_with("-shm");
            let sha256 = (metadata.is_file() && !excluded)
                .then(|| format!("{:x}", Sha256::digest(fs::read(entry.path()).unwrap())));
            (
                entry.file_name().into(),
                Entry {
                    kind,
                    mode: metadata.permissions().mode(),
                    size: metadata.len(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    sha256,
                },
            )
        })
        .collect()
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

fn message(report: &Value, id: &str) -> String {
    check(report, id)["message"].as_str().unwrap().to_owned()
}

fn assert_mode(report: &Value, mode: &str) {
    let view = message(report, "database.schema_view");
    let needle = format!("mode {mode}");
    let rest = view.split_once(&needle).map(|(_, rest)| rest);
    assert!(
        rest.is_some_and(|rest| rest
            .chars()
            .next()
            .is_none_or(|ch| !ch.is_ascii_alphanumeric() && ch != '_')),
        "{report}"
    );
}

#[test]
fn old_global_version_reports_destructive_message_state_rebuild_without_touching_data() {
    let fixture = Fixture::new(2, Shape::Current, Health::Down, Mode::Closed);
    let before = snapshot(&fixture.db_dir, false);
    let (_, report) = fixture.report();
    status(&report, "database.schema_version", "fail");
    assert!(message(&report, "database.schema_version")
        .contains("schema 3 message-state rebuild (destructive)"));
    let hint = check(&report, "database.schema_version")["hint"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(hint.contains("backup") || hint.contains("back up"));
    assert_mode(&report, "ro_immutable");
    assert_eq!(snapshot(&fixture.db_dir, false), before);
}

#[test]
fn current_closed_databases_are_read_immutably_without_sidecars_or_schema_changes() {
    for mode in [Mode::Closed, Mode::ClosedWal] {
        let fixture = Fixture::new(3, Shape::Current, Health::Down, mode);
        let before = snapshot(&fixture.db_dir, false);
        let (_, report) = fixture.report();
        status(&report, "database.schema_version", "pass");
        status(&report, "database.additive", "pass");
        assert_mode(&report, "ro_immutable");
        assert_eq!(snapshot(&fixture.db_dir, false), before);
        assert_eq!(
            before.len(),
            1,
            "fixture should contain only its main database"
        );
    }
}

#[test]
fn newer_global_version_reports_daemon_refusal_without_touching_data() {
    let fixture = Fixture::new(4, Shape::Current, Health::Down, Mode::Closed);
    let before = snapshot(&fixture.db_dir, false);
    let (_, report) = fixture.report();
    status(&report, "database.schema_version", "fail");
    assert!(message(&report, "database.schema_version")
        .to_lowercase()
        .contains("refus"));
    assert_eq!(snapshot(&fixture.db_dir, false), before);
}

#[test]
fn same_version_old_create_shape_names_pending_table_index_and_column() {
    let fixture = Fixture::new(3, Shape::OldAdditive, Health::Down, Mode::Closed);
    let before = snapshot(&fixture.db_dir, false);
    let (_, report) = fixture.report();
    status(&report, "database.schema_version", "pass");
    status(&report, "database.additive", "warn");
    let pending = message(&report, "database.additive");
    for name in [
        "ensure table blob_chunks",
        "ensure index idx_outbound_created_at",
        "add column codex_roots.restart_pending",
    ] {
        assert!(pending.contains(name), "missing {name}: {report}");
    }
    assert_eq!(
        snapshot(&fixture.db_dir, false),
        before,
        "doctor ran additive initialization on the inspected target"
    );
}

#[test]
fn down_or_unknown_daemon_with_wal_sidecars_is_stat_only_and_changes_no_entry_or_hash() {
    for health in [Health::Down, Health::Unknown] {
        let fixture = Fixture::new(3, Shape::Current, health, Mode::HeldWal);
        let before = snapshot(&fixture.db_dir, false);
        let (_, report) = fixture.report();
        assert_mode(&report, "unopened");
        status(&report, "database.schema_version", "warn");
        status(&report, "database.wal", "warn");
        status(&report, "database.shm", "warn");
        assert_eq!(snapshot(&fixture.db_dir, false), before);
    }
}

#[test]
fn live_wal_reads_the_latest_schema_while_preserving_main_wal_and_directory_entries() {
    let fixture = Fixture::new(
        3,
        Shape::MissingRestart,
        Health::Live,
        Mode::HeldWalMigration,
    );
    let before = snapshot(&fixture.db_dir, true);
    let (_, report) = fixture.report();
    status(&report, "database.schema_version", "pass");
    status(&report, "database.additive", "pass");
    assert_mode(&report, "ro");
    let view = message(&report, "database.schema_view");
    assert!(
        view.contains("next start of THIS binary"),
        "revision mismatch or unknown was not named: {report}"
    );
    assert!(
        view.contains("SHM"),
        "live SHM read-mark exclusion was not named: {report}"
    );
    assert_eq!(snapshot(&fixture.db_dir, true), before, "only SHM read-mark bytes may differ; entry presence/type/size/mode and main+WAL hashes remain fixed");
}

#[test]
fn live_daemon_without_an_existing_wal_shm_pair_stays_unopened() {
    let fixture = Fixture::new(3, Shape::Current, Health::Live, Mode::Closed);
    let before = snapshot(&fixture.db_dir, false);
    let (_, report) = fixture.report();
    assert_mode(&report, "unopened");
    status(&report, "database.schema_version", "warn");
    assert_eq!(snapshot(&fixture.db_dir, false), before);
}

#[test]
fn an_ordinary_held_rollback_journal_reports_presence_and_size_without_recovery() {
    let fixture = Fixture::new(3, Shape::Current, Health::Down, Mode::HeldJournal);
    let before = snapshot(&fixture.db_dir, false);
    let (_, report) = fixture.report();
    assert_mode(&report, "unopened");
    status(&report, "database.schema_version", "warn");
    status(&report, "database.journal", "warn");
    let size = fs::metadata(sidecar(&fixture.db, "-journal"))
        .unwrap()
        .len()
        .to_string();
    let journal = message(&report, "database.journal");
    assert!(
        journal.contains(&size),
        "journal size was not reported: {report}"
    );
    assert!(
        journal.contains("regular"),
        "journal type was not reported: {report}"
    );
    assert_eq!(snapshot(&fixture.db_dir, false), before);
}
