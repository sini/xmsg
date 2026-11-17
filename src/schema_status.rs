use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonState {
    Live,
    Down,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct Sidecar {
    pub suffix: &'static str,
    pub present: bool,
    pub size: Option<u64>,
    pub kind: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub mode: &'static str,
    pub stored_version: Option<i64>,
    pub newest_version: i64,
    pub pending: Vec<String>,
    pub optional_enrollment: Vec<String>,
    pub sidecars: Vec<Sidecar>,
    pub consistent: bool,
    pub error_class: Option<&'static str>,
    pub note: &'static str,
}

impl Report {
    fn new(sidecars: &[ObservedSidecar]) -> Self {
        Self {
            mode: "unopened",
            stored_version: None,
            newest_version: crate::storage::SCHEMA_VERSION,
            pending: Vec::new(),
            optional_enrollment: Vec::new(),
            sidecars: sidecars.iter().map(|value| value.public.clone()).collect(),
            consistent: false,
            error_class: None,
            note: "No metadata view was opened.",
        }
    }

    fn uncertain(mut self, class: &'static str, note: &'static str) -> Self {
        self.stored_version = None;
        self.pending.clear();
        self.optional_enrollment.clear();
        self.consistent = false;
        self.error_class = Some(class);
        self.note = note;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    fn new(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    fn same_file(&self, other: &Self) -> bool {
        (self.device, self.inode) == (other.device, other.inode)
    }
}

struct MainFile {
    file: File,
    stamp: Stamp,
    header: [u8; 100],
}

impl MainFile {
    fn open(path: &Path) -> Result<Self, &'static str> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                "missing"
            } else {
                "unavailable"
            }
        })?;
        if !metadata.is_file() {
            return Err("invalid_target");
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "unavailable")?;
        let opened = file.metadata().map_err(|_| "unavailable")?;
        if !opened.is_file() || Stamp::new(&metadata) != Stamp::new(&opened) {
            return Err("changed_during_probe");
        }
        let mut header = [0; 100];
        file.read_exact(&mut header).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                "not_sqlite"
            } else {
                "unavailable"
            }
        })?;
        if &header[..16] != b"SQLite format 3\0" {
            return Err("not_sqlite");
        }
        Ok(Self {
            file,
            stamp: Stamp::new(&opened),
            header,
        })
    }

    fn unchanged(&mut self, path: &Path, immutable: bool) -> bool {
        let Ok(path_metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        let Ok(open_metadata) = self.file.metadata() else {
            return false;
        };
        if !path_metadata.is_file() || !open_metadata.is_file() {
            return false;
        }
        let path_stamp = Stamp::new(&path_metadata);
        let open_stamp = Stamp::new(&open_metadata);
        if !self.stamp.same_file(&path_stamp) || !self.stamp.same_file(&open_stamp) {
            return false;
        }
        if !immutable {
            return true;
        }
        let mut header = [0; 100];
        self.file.seek(SeekFrom::Start(0)).is_ok()
            && self.file.read_exact(&mut header).is_ok()
            && header == self.header
            && self.stamp == path_stamp
            && self.stamp == open_stamp
    }
}

struct ObservedSidecar {
    public: Sidecar,
    stamp: Option<Stamp>,
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    value.into()
}

fn sidecars(path: &Path) -> Vec<ObservedSidecar> {
    ["-journal", "-wal", "-shm"]
        .into_iter()
        .map(
            |suffix| match fs::symlink_metadata(sidecar_path(path, suffix)) {
                Ok(metadata) => {
                    let kind = if metadata.is_file() {
                        "regular"
                    } else if metadata.file_type().is_symlink() {
                        "symlink"
                    } else if metadata.is_dir() {
                        "directory"
                    } else {
                        "other"
                    };
                    ObservedSidecar {
                        public: Sidecar {
                            suffix,
                            present: true,
                            size: Some(metadata.len()),
                            kind,
                        },
                        stamp: Some(Stamp::new(&metadata)),
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => ObservedSidecar {
                    public: Sidecar {
                        suffix,
                        present: false,
                        size: None,
                        kind: "absent",
                    },
                    stamp: None,
                },
                Err(_) => ObservedSidecar {
                    public: Sidecar {
                        suffix,
                        present: true,
                        size: None,
                        kind: "unavailable",
                    },
                    stamp: None,
                },
            },
        )
        .collect()
}

fn live_wal_files(sidecars: &[ObservedSidecar]) -> bool {
    !sidecars[0].public.present
        && sidecars[1].public.kind == "regular"
        && sidecars[1]
            .public
            .size
            .is_some_and(|size| size == 0 || size >= 32)
        && sidecars[2].public.kind == "regular"
        && sidecars[2]
            .public
            .size
            .is_some_and(|size| size >= 32768 && size % 32768 == 0)
}

fn sidecars_unchanged(
    before: &[ObservedSidecar],
    after: &[ObservedSidecar],
    immutable: bool,
) -> bool {
    if immutable || before.iter().all(|sidecar| !sidecar.public.present) {
        return after.iter().all(|sidecar| !sidecar.public.present);
    }
    live_wal_files(after)
        && before
            .iter()
            .zip(after)
            .all(|(before, after)| match (&before.stamp, &after.stamp) {
                (None, None) => true,
                (Some(before), Some(after)) => before.same_file(after),
                _ => false,
            })
}

fn metadata_uri(path: &Path, immutable: bool) -> String {
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(*byte));
        } else {
            use std::fmt::Write;
            write!(&mut uri, "%{byte:02X}").expect("string formatting");
        }
    }
    uri.push_str(if immutable {
        "?mode=ro&immutable=1"
    } else {
        "?mode=ro"
    });
    uri
}

fn open_metadata(path: &Path, immutable: bool) -> rusqlite::Result<Connection> {
    let uri = metadata_uri(path, immutable);
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(uri, flags)?;
    connection.busy_timeout(Duration::from_millis(150))?;
    connection.execute_batch("BEGIN DEFERRED")?;
    Ok(connection)
}

const ADDITIVE_COLUMNS: [(&str, &str); 12] = [
    ("peer_mailbox", "admitted"),
    ("idempotency_keys", "to_ref"),
    ("idempotency_keys", "refs_digest"),
    ("reply_idempotency_keys", "refs_digest"),
    ("outbound", "via_mailbox"),
    ("instance_seen", "reclaim_hash"),
    ("codex_roots", "rollout_dev"),
    ("codex_roots", "rollout_ino"),
    ("codex_roots", "active"),
    ("codex_roots", "restart_pending"),
    ("subagents", "last_active"),
    ("subagents", "stopped_at"),
];

fn required_objects() -> Vec<(&'static str, String)> {
    let declarations = regex::Regex::new(r"(?i)\bCREATE\s+(?:UNIQUE\s+)?(TABLE|INDEX)\s+IF\s+NOT\s+EXISTS\s+([a-zA-Z_][a-zA-Z_0-9]*)").expect("static schema declaration pattern");
    declarations
        .captures_iter(crate::storage::SCHEMA_N)
        .map(|capture| {
            (
                if capture[1].eq_ignore_ascii_case("table") {
                    "table"
                } else {
                    "index"
                },
                capture[2].to_owned(),
            )
        })
        .collect()
}

struct View {
    version: i64,
    pending: Vec<String>,
    optional_enrollment: Vec<String>,
}

fn read_metadata(connection: &Connection) -> rusqlite::Result<View> {
    let stored_version = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let objects = connection
        .prepare("SELECT type,name FROM sqlite_schema WHERE type IN ('table','index')")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    let mut pending = BTreeSet::new();
    if stored_version == crate::storage::SCHEMA_VERSION {
        for (kind, name) in required_objects() {
            if !objects.contains(&(kind.to_owned(), name.clone())) {
                pending.insert(format!("{kind}:{name}"));
            }
        }
        let mut columns = BTreeMap::<&str, BTreeSet<String>>::new();
        for (table, column) in ADDITIVE_COLUMNS {
            if !objects.contains(&("table".to_owned(), table.to_owned())) {
                continue;
            }
            if !columns.contains_key(table) {
                let names = connection
                    .prepare("SELECT name FROM pragma_table_info(?1)")?
                    .query_map([table], |row| row.get(0))?
                    .collect::<rusqlite::Result<BTreeSet<String>>>()?;
                columns.insert(table, names);
            }
            if !columns[table].contains(column) {
                pending.insert(format!("column:{table}.{column}"));
            }
        }
    }
    let optional_enrollment = [
        "enroll_bindings",
        "enroll_aliases",
        "enroll_certs",
        "enroll_rates",
    ]
    .into_iter()
    .filter(|name| !objects.contains(&("table".to_owned(), (*name).to_owned())))
    .map(|name| format!("table:{name}"))
    .collect();
    Ok(View {
        version: stored_version,
        pending: pending.into_iter().collect(),
        optional_enrollment,
    })
}

fn sqlite_class(error: &rusqlite::Error) -> &'static str {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => "busy",
        Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt) => {
            "not_sqlite"
        }
        _ => "unavailable",
    }
}

pub fn inspect(path: &Path, state: DaemonState) -> Report {
    let before = sidecars(path);
    let mut report = Report::new(&before);
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            return report.uncertain("invalid_target", "The main path is not a regular file.")
        }
        Err(error) => {
            return report.uncertain(
                if error.kind() == io::ErrorKind::NotFound {
                    "missing"
                } else {
                    "unavailable"
                },
                "The main file metadata is unavailable.",
            )
        }
        Ok(_) => {}
    }
    let immutable = state != DaemonState::Live;
    if immutable && before.iter().any(|sidecar| sidecar.public.present) {
        return report.uncertain("sidecars_present", "Sidecar files are present; SQLite recovery status is unknown and no SQLite connection was opened.");
    }
    let no_sidecars = before.iter().all(|sidecar| !sidecar.public.present);
    if !immutable && !no_sidecars && !live_wal_files(&before) {
        return report.uncertain("live_view_unavailable", "A live read-only WAL view requires pre-existing regular WAL and SHM files and no rollback journal; no SQLite connection was opened.");
    }
    let mut main = match MainFile::open(path) {
        Ok(main) => main,
        Err(class) => {
            return report.uncertain(
                class,
                "The main file could not provide SQLite metadata safely.",
            )
        }
    };
    let rollback = !immutable && no_sidecars;
    if rollback && main.header[18..20] != [1, 1] {
        return report.uncertain("live_view_unavailable", "A live WAL database requires pre-existing regular WAL and SHM files; no SQLite connection was opened.");
    }
    report.mode = if immutable { "ro_immutable" } else { "ro" };
    let result = open_metadata(path, immutable).and_then(|connection| read_metadata(&connection));
    let after = sidecars(path);
    report.sidecars = after.iter().map(|value| value.public.clone()).collect();
    if !main.unchanged(path, immutable || rollback)
        || !sidecars_unchanged(&before, &after, immutable)
    {
        return report.uncertain("changed_during_probe", "The main file or sidecar metadata changed during the probe; this observation is uncertain.");
    }
    let view =
        match result {
            Ok(view) => view,
            Err(error) => return report.uncertain(
                sqlite_class(&error),
                "SQLite metadata was unavailable; no integrity or recovery conclusion was made.",
            ),
        };
    report.stored_version = Some(view.version);
    report.pending = view.pending;
    report.optional_enrollment = view.optional_enrollment;
    report.consistent = true;
    report.note = if immutable {
        "Lockless immutable main-file metadata snapshot; no integrity or data-backfill certification. Optional enrollment requirements depend on configuration."
    } else if rollback {
        "Consistent read-only rollback-journal metadata snapshot; main-file fingerprints and absent sidecars rechecked. No integrity or data-backfill certification. Optional enrollment requirements depend on configuration."
    } else {
        "Consistent read-only WAL metadata snapshot; SQLite may update existing SHM read marks. No integrity or data-backfill certification. Optional enrollment requirements depend on configuration."
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &Path, wal: bool) -> Connection {
        let connection = Connection::open(path).unwrap();
        if wal {
            connection
                .pragma_update(None, "journal_mode", "WAL")
                .unwrap();
        }
        connection.execute_batch(crate::storage::SCHEMA_N).unwrap();
        connection
            .pragma_update(None, "user_version", crate::storage::SCHEMA_VERSION)
            .unwrap();
        connection
    }

    fn entries(path: &Path) -> BTreeSet<std::ffi::OsString> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect()
    }

    #[test]
    fn static_schema_objects_match_the_actual_startup_declarations() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(crate::storage::SCHEMA_N).unwrap();
        let actual = connection.prepare("SELECT type,name FROM sqlite_schema WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%'").unwrap()
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).unwrap()
            .collect::<rusqlite::Result<BTreeSet<_>>>().unwrap();
        let parsed = required_objects()
            .into_iter()
            .map(|(kind, name)| (kind.to_owned(), name))
            .collect::<BTreeSet<_>>();
        assert_eq!(parsed, actual);
        assert_eq!(ADDITIVE_COLUMNS.len(), 12);
        connection
            .pragma_update(None, "user_version", crate::storage::SCHEMA_VERSION)
            .unwrap();
        assert!(read_metadata(&connection).unwrap().pending.is_empty());
    }

    #[test]
    fn offline_checkpointed_wal_probe_never_creates_transient_auxiliary_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("main.sqlite");
        drop(fixture(&path, true));
        let before_entries = entries(directory.path());
        let before_main = fs::read(&path).unwrap();
        assert_eq!(before_entries.len(), 1);
        let connection = open_metadata(&path, true).unwrap();
        assert_eq!(
            read_metadata(&connection).unwrap().version,
            crate::storage::SCHEMA_VERSION
        );
        assert_eq!(
            entries(directory.path()),
            before_entries,
            "metadata constructor created transient auxiliary files"
        );
        assert_eq!(fs::read(&path).unwrap(), before_main);
        assert!(connection.is_readonly("main").unwrap());
        drop(connection);
        assert_eq!(entries(directory.path()), before_entries);
        assert_eq!(fs::read(&path).unwrap(), before_main);
        let report = inspect(&path, DaemonState::Down);
        assert!(report.consistent, "{report:?}");
        assert_eq!(report.mode, "ro_immutable");
    }

    #[test]
    fn live_wal_probe_takes_no_writer_reservation_or_main_wal_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("main.sqlite");
        let _writer = fixture(&path, true);
        let second_writer = Connection::open(&path).unwrap();
        let before_entries = entries(directory.path());
        let before_main = fs::read(&path).unwrap();
        let before_wal = fs::read(sidecar_path(&path, "-wal")).unwrap();
        let connection = open_metadata(&path, false).unwrap();
        assert_eq!(
            read_metadata(&connection).unwrap().version,
            crate::storage::SCHEMA_VERSION
        );
        assert!(
            second_writer
                .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
                .is_ok(),
            "metadata probe reserved the writer slot"
        );
        assert_eq!(entries(directory.path()), before_entries);
        assert_eq!(fs::read(&path).unwrap(), before_main);
        assert_eq!(fs::read(sidecar_path(&path, "-wal")).unwrap(), before_wal);
        assert!(connection.is_readonly("main").unwrap());
        drop(connection);
        assert_eq!(entries(directory.path()), before_entries);
        assert_eq!(fs::read(&path).unwrap(), before_main);
        assert_eq!(fs::read(sidecar_path(&path, "-wal")).unwrap(), before_wal);
        let report = inspect(&path, DaemonState::Live);
        assert!(report.consistent, "{report:?}");
        assert_eq!(report.mode, "ro");
    }

    #[test]
    fn sidecars_prevent_offline_open_and_incomplete_live_views_stay_unknown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("main.sqlite");
        let writer = fixture(&path, false);
        writer
            .execute_batch("BEGIN IMMEDIATE; CREATE TABLE pending_metadata(value TEXT);")
            .unwrap();
        assert!(fs::symlink_metadata(sidecar_path(&path, "-journal"))
            .unwrap()
            .is_file());
        for state in [DaemonState::Down, DaemonState::Unknown, DaemonState::Live] {
            let report = inspect(&path, state);
            assert!(!report.consistent);
            assert_eq!(report.mode, "unopened");
            assert!(report.stored_version.is_none());
        }
    }

    #[test]
    fn metadata_uri_keeps_uri_characters_in_the_literal_file_name() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("main?#%.sqlite");
        drop(fixture(&path, false));
        assert!(inspect(&path, DaemonState::Down).consistent);
    }

    #[test]
    fn uncommitted_sqlite_header_does_not_override_sidecar_policy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("main.sqlite");
        let writer = Connection::open(&path).unwrap();
        writer
            .execute_batch("BEGIN IMMEDIATE; CREATE TABLE pending_metadata(value TEXT);")
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            0,
            "new SQLite header already committed"
        );
        assert!(fs::symlink_metadata(sidecar_path(&path, "-journal"))
            .unwrap()
            .is_file());
        for state in [DaemonState::Down, DaemonState::Unknown] {
            let report = inspect(&path, state);
            assert_eq!(report.mode, "unopened");
            assert_eq!(report.error_class, Some("sidecars_present"));
        }
        let live = inspect(&path, DaemonState::Live);
        assert_eq!(live.error_class, Some("live_view_unavailable"));
        writer.execute_batch("ROLLBACK").unwrap();
        writer.execute_batch(crate::storage::SCHEMA_N).unwrap();
        writer
            .pragma_update(None, "user_version", crate::storage::SCHEMA_VERSION)
            .unwrap();
        drop(writer);
        assert!(inspect(&path, DaemonState::Down).consistent);
    }

    #[test]
    fn live_rollback_reader_creates_no_files_or_writer_reservation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("main.sqlite");
        let writer = fixture(&path, false);
        let before_entries = entries(directory.path());
        let before_main = fs::read(&path).unwrap();
        let report = inspect(&path, DaemonState::Live);
        assert!(report.consistent, "{report:?}");
        assert_eq!(report.mode, "ro");
        let connection = open_metadata(&path, false).unwrap();
        read_metadata(&connection).unwrap();
        writer
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
            .expect("read-only metadata probe reserved the writer slot");
        assert!(connection.is_readonly("main").unwrap());
        assert_eq!(entries(directory.path()), before_entries);
        assert_eq!(fs::read(&path).unwrap(), before_main);
        drop(connection);
        assert_eq!(entries(directory.path()), before_entries);
        assert_eq!(fs::read(&path).unwrap(), before_main);
    }

    #[test]
    fn rollback_recheck_rejects_new_journal_or_changed_main() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("main.sqlite");
        let writer = fixture(&path, false);
        let before = sidecars(&path);
        let mut main = MainFile::open(&path).unwrap();
        writer
            .execute_batch("BEGIN IMMEDIATE; CREATE TABLE concurrent_metadata(value TEXT);")
            .unwrap();
        assert!(!sidecars_unchanged(&before, &sidecars(&path), false));
        assert_eq!(
            inspect(&path, DaemonState::Live).error_class,
            Some("live_view_unavailable")
        );
        writer.execute_batch("COMMIT").unwrap();
        assert!(sidecars(&path)
            .iter()
            .all(|sidecar| !sidecar.public.present));
        assert!(!main.unchanged(&path, true));
    }
}
