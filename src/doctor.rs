use clap::Args;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_FILE: u64 = 1_048_576;
const MAX_HEALTH: usize = 65_536;
const MAX_SESSION_BODY: usize = 2 * 1024 * 1024;
const MAX_SESSIONS: usize = 1000;
const MAX_FED_BODY: usize = 512 * 1024;
const MAX_PEERS: usize = 32;

#[derive(Args, Debug)]
pub struct DoctorArgs {
    #[arg(long, env = "XMSG_HTTP_SOCK")]
    http_sock: Option<PathBuf>,
    #[arg(long)]
    agent_sock: Option<PathBuf>,
    #[arg(long)]
    register_sock: Option<PathBuf>,
    #[arg(long, env = "XMSG_DB_PATH")]
    db_path: Option<PathBuf>,
    #[arg(long, env = "XMSG_PEERS_FILE")]
    peers_file: Option<PathBuf>,
    #[arg(long, requires = "peers_file")]
    fed_cert: Option<PathBuf>,
    #[arg(long)]
    enroll_state: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
}
#[derive(Serialize)]
struct Check {
    id: String,
    status: Status,
    message: String,
    hint: Option<&'static str>,
}
#[derive(Serialize)]
struct Report {
    client_version: &'static str,
    client_build_revision: &'static str,
    checks: Vec<Check>,
    passed: usize,
    warnings: usize,
    failed: usize,
    checked_paths: BTreeMap<&'static str, String>,
    not_checked: Vec<&'static str>,
}
impl Report {
    fn new() -> Self {
        Self {
            client_version: env!("CARGO_PKG_VERSION"),
            client_build_revision: option_env!("XMSG_BUILD_REVISION").unwrap_or("unknown"),
            checks: vec![],
            passed: 0,
            warnings: 0,
            failed: 0,
            checked_paths: BTreeMap::new(),
            not_checked: vec![
                "loaded_configuration",
                "additive_migration_readiness",
                "journal_hotness",
                "ca_application_health",
            ],
        }
    }
    fn add(
        &mut self,
        id: impl Into<String>,
        status: Status,
        message: impl Into<String>,
        hint: Option<&'static str>,
    ) {
        match status {
            Status::Pass => self.passed += 1,
            Status::Warn => self.warnings += 1,
            Status::Fail => self.failed += 1,
        }
        self.checks.push(Check {
            id: id.into(),
            status,
            message: message.into(),
            hint,
        });
    }
    fn path(&mut self, name: &'static str, path: &Path) {
        self.checked_paths
            .insert(name, path.to_string_lossy().into_owned());
    }
}
fn suffix(path: &Path, end: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(end);
    value.into()
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn private_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_dir() && m.uid() == uid() && m.mode() & 0o777 == 0o700)
}
fn socket(report: &mut Report, id: &'static str, path: &Path) -> bool {
    let valid = fs::symlink_metadata(path)
        .is_ok_and(|m| m.file_type().is_socket() && m.uid() == uid() && m.mode() & 0o777 == 0o600)
        && path.parent().is_some_and(private_directory);
    report.add(id,if valid {Status::Pass}else{Status::Fail},if valid {"Private node socket is present."}else{"Socket is missing or its type, owner, or permissions are wrong."},if valid {None}else{Some("Run as the node user; start xmsg serve with private runtime paths, or pass the matching socket override.")});
    valid
}
fn state_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != uid() {
        return Err(io::Error::other("not an owned regular state file"));
    }
    Ok(file)
}
fn bounded_file(path: &Path, private: bool) -> io::Result<Vec<u8>> {
    let file = if private {
        state_file(path)?
    } else {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        if !f.metadata()?.is_file() {
            return Err(io::Error::other("not a regular configuration file"));
        }
        f
    };
    if private && file.metadata()?.mode() & 0o777 != 0o600 {
        return Err(io::Error::other("state file is not private"));
    }
    if file.metadata()?.len() > MAX_FILE {
        return Err(io::Error::other("file too large"));
    }
    let mut bytes = vec![];
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(io::Error::other("file too large"));
    }
    Ok(bytes)
}
async fn read_json(
    path: &Path,
    url: &str,
    maximum: usize,
    budget: Duration,
) -> std::result::Result<Value, ()> {
    tokio::time::timeout(budget, async {
        let client = reqwest::Client::builder()
            .unix_socket(path.to_path_buf())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(budget)
            .build()
            .map_err(|_| ())?;
        let mut response = client.get(url).send().await.map_err(|_| ())?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n > maximum as u64)
        {
            return Err(());
        }
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            if bytes.len().saturating_add(chunk.len()) > maximum {
                return Err(());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
        Ok(value)
    })
    .await
    .map_err(|_| ())?
}
async fn health(report: &mut Report, path: &Path) {
    let result = read_json(
        path,
        "http://localhost/healthz",
        MAX_HEALTH,
        Duration::from_secs(5),
    )
    .await;
    match result {
        Ok(value) if value["status"] == "ok" => {
            report.add(
                "daemon.health",
                Status::Pass,
                "Daemon answered the read-only health endpoint.",
                None,
            );
            let version = value["version"].as_str().filter(|v| !v.is_empty());
            report.add(
                "daemon.version",
                if version.is_some() {
                    Status::Pass
                } else {
                    Status::Warn
                },
                format!("Daemon version: {}.", version.unwrap_or("unknown")),
                version
                    .is_none()
                    .then_some("Update the daemon to report its version."),
            );
            let revision = value["build_revision"]
                .as_str()
                .filter(|v| !v.is_empty() && *v != "unknown");
            let client = report.client_build_revision;
            let known = revision.is_some() && client != "unknown";
            let matches = revision == Some(client);
            report.add("daemon.build_revision", if known && matches { Status::Pass } else { Status::Warn },
                format!("Daemon build revision: {}; client build revision: {client}.", revision.unwrap_or("unknown")),
                if !known { Some("Use builds with revision metadata to compare client and daemon.") }
                else if !matches { Some("Client and daemon revisions differ; check the installed pins and restart the intended daemon.") }
                else { None });
            let good = value["sessions_dir"] == "ok";
            report.add("daemon.sessions_directory",if good {Status::Pass}else{Status::Warn},if good {"A configured sessions directory exists."}else{"Sessions directory is missing or this daemon does not report it."},if good {None}else{Some("Check --sessions-dir if using a harness; a service-only node may not need one.")});
        }
        _ => report.add(
            "daemon.health",
            Status::Fail,
            "Daemon health is unavailable, invalid, or timed out.",
            Some("Start the node or pass its actual --http-sock; check the node service logs."),
        ),
    }
}
async fn sessions(report: &mut Report, path: &Path) {
    let snapshot = read_json(
        path,
        "http://localhost/v1/recipients?read_only=true&liveness=true",
        MAX_SESSION_BODY,
        Duration::from_secs(5),
    )
    .await;
    let Ok(snapshot) = snapshot else {
        report.add("sessions.process", Status::Warn, "Registered process liveness: unknown; the read-only source is unavailable or unsupported.", Some("Use a daemon with the Unix process snapshot; no live listing fallback was attempted."));
        return;
    };
    let rows = snapshot["recipients"].as_array();
    if snapshot["read_only"] != true
        || !snapshot["partial"].is_boolean()
        || !snapshot["truncated"].is_boolean()
        || rows.is_none()
    {
        report.add("sessions.process", Status::Warn, "Registered process liveness: unknown; the daemon did not return a read-only process snapshot.", Some("Update the daemon; registration status alone does not prove process liveness."));
        return;
    }
    let rows = rows.unwrap();
    let mut live = 0;
    let mut gone = 0;
    let mut unknown = 0;
    let mut unavailable = false;
    for row in rows.iter().take(MAX_SESSIONS) {
        let Some(address) = row["address"]
            .as_str()
            .filter(|address| !address.is_empty() && address.len() <= 1024)
        else {
            unknown += 1;
            continue;
        };
        let observation = &row["process_liveness"];
        let (state, status) = match observation["state"].as_str() {
            Some("live") => {
                live += 1;
                ("live", Status::Pass)
            }
            Some("gone") => {
                gone += 1;
                ("gone", Status::Warn)
            }
            _ => {
                unknown += 1;
                ("unknown", Status::Warn)
            }
        };
        unavailable |= observation["reason"] == "backend_unavailable";
        report.add(
            format!("session.process.{address}"),
            status,
            format!("process {state}"),
            None,
        );
    }
    let partial =
        snapshot["partial"] == true || snapshot["truncated"] == true || rows.len() > MAX_SESSIONS;
    report.add("sessions.process", if gone > 0 || unknown > 0 || partial { Status::Warn } else { Status::Pass },
        format!("Registered process snapshot: {live} live, {gone} gone, {unknown} unknown; {}. Process liveness is not harness or delivery readiness.", if partial { "partial coverage; absent rows are unknown" } else { "returned catalogue only" }),
        (gone > 0).then_some("Check stale registrations; doctor does not reconcile or deliver queued work."));
    if unavailable {
        report.add("sessions.process_backend", Status::Warn, "Process inspection is unavailable for some rows on this platform; those processes are unknown, not gone.", Some("Native process inspection is optional; /proc is not required. Retain unknown where the backend is unavailable."));
    }
}

fn database(report: &mut Report, path: &Path) {
    let journal = fs::symlink_metadata(suffix(path, "-journal")).is_ok();
    report.add("database.journal",if journal {Status::Warn}else{Status::Pass},if journal {"Rollback journal is present; hotness is not determined."}else{"No rollback journal was found at the checked path."},if journal {Some("Do not delete a journal by hand. Stop the node safely, back up its files, and inspect normal SQLite recovery.")}else{None});
    let mut header = [0u8; 100];
    let read = state_file(path).and_then(|mut f| f.read_exact(&mut header));
    if read.is_err() || &header[..16] != b"SQLite format 3\0" {
        report.add(
            "database.schema_version",
            Status::Fail,
            "Database is missing, unreadable, or has no SQLite header.",
            Some(
                "Check --db-path and node-user access; preserve a backup before attempting repair.",
            ),
        );
        return;
    }
    let wal = header[18] == 2
        || header[19] == 2
        || fs::symlink_metadata(suffix(path, "-wal")).is_ok()
        || fs::symlink_metadata(suffix(path, "-shm")).is_ok();
    if journal || wal {
        report.add("database.schema_version",Status::Warn,"Global schema probe skipped because journal/WAL state requires inspection.",Some("Use a stopped-node backup and the normal daemon upgrade/recovery procedure; doctor does not recover state."));
        return;
    }
    let version = (|| -> rusqlite::Result<i64> {
        let db = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::from_millis(250))?;
        db.pragma_query_value(None, "user_version", |row| row.get(0))
    })();
    match version {
        Ok(v) if v==xmsg::storage::SCHEMA_VERSION=>report.add("database.schema_version",Status::Pass,format!("Read-only global schema version is {v}; additive readiness is not certified."),None),
        Ok(v)=>report.add("database.schema_version",Status::Fail,format!("Global schema version {v} differs from this binary's {}.",xmsg::storage::SCHEMA_VERSION),Some("Use a matching node binary; stop and back up before the normal startup migration procedure.")),
        Err(_)=>report.add("database.schema_version",Status::Fail,"Cannot read the global schema with a read-only SQLite connection.",Some("Check access and a stopped-node backup; doctor never opens the database for writes or recovery.")),
    }
}
fn observe(report: &mut Report, path: &Path) {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind()==io::ErrorKind::NotFound=>report.add("observe.file",Status::Warn,"Observation sidecar is absent; no history health is inferred.",Some("Check node logs if observation is wanted; doctor does not create the sidecar.")),
        Ok(m) if m.is_file() && m.uid()==uid() && m.mode()&0o777==0o600 && path.parent().and_then(|p|fs::symlink_metadata(p).ok()).is_some_and(|p|p.is_dir() && p.uid()==uid() && p.mode()&0o022==0)=>report.add("observe.file",Status::Pass,"Observation sidecar owner and mode are correct; contents were not opened.",None),
        _=>report.add("observe.file",Status::Fail,"Observation sidecar type, owner, or permissions are wrong.",Some("Use the node user and a regular private 0600 sidecar; inspect the node's observation setup.")),
    }
}
fn peers(report: &mut Report, path: &Path, cert: Option<&Path>) -> Vec<String> {
    let result = (|| -> Result<Vec<String>> {
        let own = cert.map(super::own_node_from_cert_file).transpose()?;
        let bytes = bounded_file(path, false)?;
        let text = std::str::from_utf8(&bytes)?;
        let peers = xmsg::fed::PeersMap::load_from_json_for(text, own.as_ref())?;
        let mut names: Vec<_> = peers.iter().map(|(_, peer)| peer.name.clone()).collect();
        names.sort();
        names.dedup();
        Ok(names)
    })();
    report.add("peers.file",if result.is_ok(){Status::Pass}else{Status::Fail},if result.is_ok(){"Peers file passes the existing check-peers parser; connectivity is checked separately by the daemon."}else{"Peers file or supplied node certificate fails check-peers validation."},if result.is_ok(){None}else{Some("Run xmsg check-peers PEERS_JSON with the same optional --fed-cert to see the failing configuration rule.")});
    result.unwrap_or_default()
}

fn certificate_text(value: &Value) -> Option<String> {
    let subject = value["subject"].as_str().filter(|v| v.len() <= 4096)?;
    let issuer = value["issuer"].as_str().filter(|v| v.len() <= 4096)?;
    let not_after = value["not_after"].as_i64()?;
    let not_after = chrono::DateTime::from_timestamp(not_after, 0).map(|date| date.to_rfc3339())?;
    Some(format!(
        "subject {subject}; issuer {issuer}; notAfter {not_after}"
    ))
}

fn unknown_federation(report: &mut Report, names: &[String]) {
    report.add("federation.probe",Status::Warn,"Federation diagnostics: unknown; the daemon is unavailable, older, or has no loaded federation identity. No peers were dialled by doctor.",Some("Check the daemon's Unix socket and federation configuration; doctor does not load private keys or fall back to direct peer probes."));
    report.add(
        "federation.local_certificate",
        Status::Warn,
        "Loaded federation leaf expiry: unknown.",
        None,
    );
    for name in names.iter().take(MAX_PEERS) {
        report.add(
            format!("peer.federation.{name}"),
            Status::Warn,
            "TLS reachability unknown; leaf expiry unknown; observed offset unknown.",
            None,
        );
    }
    if names.len() > MAX_PEERS {
        report.add(
            "federation.coverage",
            Status::Warn,
            "Configured peers exceed the 32-peer diagnostic bound; remaining peers are unknown.",
            None,
        );
    }
}

async fn federation(report: &mut Report, path: Option<&Path>, configured_names: &[String]) {
    let Some(path) = path else {
        unknown_federation(report, configured_names);
        return;
    };
    let result = read_json(
        path,
        "http://localhost/v1/diagnostics/federation",
        MAX_FED_BODY,
        Duration::from_secs(9),
    )
    .await;
    let Ok(value) = result else {
        unknown_federation(report, configured_names);
        return;
    };
    let rows = value["peers"].as_array();
    if value["available"] != true
        || rows.is_none()
        || !value["partial"].is_boolean()
        || !value["truncated"].is_boolean()
        || !value["budget_exhausted"].is_boolean()
    {
        unknown_federation(report, configured_names);
        return;
    }
    let local = certificate_text(&value["own_leaf"]);
    let expiry = if local.is_some() {
        value["own_expiry"].as_str().unwrap_or("unknown")
    } else {
        "unknown"
    };
    let local_status = match expiry {
        "expired" => Status::Fail,
        "valid" => Status::Pass,
        _ => Status::Warn,
    };
    report.add("federation.local_certificate",local_status,format!("Loaded federation leaf {expiry}; {}.",local.unwrap_or_else(||"certificate metadata unknown".into())),
        (expiry!="valid").then_some("Check the normal identity renewal workflow; doctor never renews or writes credentials."));
    let rows = rows.unwrap();
    let mut partial = value["partial"] == true
        || value["truncated"] == true
        || value["budget_exhausted"] == true
        || rows.len() > MAX_PEERS;
    let mut shown = 0;
    for row in rows.iter().take(MAX_PEERS) {
        let Some(name) = row["name"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 4096)
        else {
            partial = true;
            continue;
        };
        let reach = match row["reachability"].as_str() {
            Some("reachable") => "reachable",
            Some("unreachable") => "unreachable",
            _ => "unknown",
        };
        let leaf = certificate_text(&row["leaf"]);
        let expiry = if leaf.is_some() {
            row["expiry"].as_str().unwrap_or("unknown")
        } else {
            "unknown"
        };
        let sample = row["observed_offset_seconds"]
            .as_f64()
            .zip(row["offset_uncertainty_seconds"].as_f64())
            .filter(|(offset, uncertainty)| {
                offset.is_finite() && uncertainty.is_finite() && *uncertainty >= 0.0
            });
        let offset_state = row["offset_state"].as_str().unwrap_or("unknown");
        let offset = match sample {
            Some((offset, uncertainty)) => {
                format!("observed offset {offset:+.3} ± {uncertainty:.3} s ({offset_state})")
            }
            None => "observed offset unknown".into(),
        };
        let good = reach == "reachable"
            && expiry == "valid"
            && offset_state == "within_tolerance"
            && sample.is_some();
        report.add(format!("peer.federation.{name}"),if good {Status::Pass}else{Status::Warn},format!("TLS {reach}; leaf {expiry}; {}; {offset}.",leaf.unwrap_or_else(||"certificate metadata unknown".into())),
            (!good).then_some("Check the peer network, configured identity and normal renewal workflow; compare time synchronization on both nodes using the observed offset and uncertainty."));
        shown += 1;
    }
    report.add("federation.probe",if partial {Status::Warn}else{Status::Pass},format!("Daemon-only federation diagnostics returned {shown} configured peers; {}. Bounds: 32 peers, 4 concurrent, 2 s per peer, 8 s total; doctor IPC 9 s.",if partial {"partial coverage; unobserved peers are unknown"}else{"configured catalogue sampled"}),None);
}

async fn enrollment(report: &mut Report, directory: &Path) {
    let result = (|| -> Result<xmsg::enroll_client::SavedState> {
        if !private_directory(directory) {
            return Err("enrollment directory is not private".into());
        }
        Ok(serde_json::from_slice(&bounded_file(
            &directory.join("enroll.json"),
            true,
        )?)?)
    })();
    let state = match result {
        Ok(s) if s.issued_at >= 0 && s.not_after > s.issued_at => s,
        _ => {
            report.add("enrollment.metadata",Status::Fail,"Existing enrollment metadata is unavailable or invalid.",Some("Check --enroll-state DIR, its 0700 directory and private enroll.json; doctor never creates enrollment files."));
            return;
        }
    };
    report.add("enrollment.metadata",Status::Pass,"Stored public enrollment metadata is readable; loaded daemon credentials are not inferred.",None);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0);
    if state.not_after <= now {
        report.add("enrollment.expiry",Status::Fail,"Stored enrolled identity has expired.",Some("Use the normal owner-controlled enrollment or renewal workflow; doctor never renews."));
        return;
    }
    report.add(
        "enrollment.expiry",
        Status::Pass,
        "Stored enrollment expiry is in the future.",
        None,
    );
    let due = state.issued_at.saturating_add(
        state
            .not_after
            .saturating_sub(state.issued_at)
            .saturating_mul(2)
            / 3,
    );
    report.add("enrollment.renewal",if now>=due {Status::Warn}else{Status::Pass},if now>=due {"Stored enrolled identity is due for renewal under the two-thirds lifetime policy."}else{"Stored enrolled identity is not yet due for renewal."},if now>=due {Some("Check the normal automatic renewal service or run the explicit owner-controlled renew workflow.")}else{None});
    match xmsg::enroll_client::bootstrap(&state.url,Some(&state.fingerprint),None).await {
        Ok(_)=>report.add("enrollment.ca_tls",Status::Pass,"CA TLS endpoint is reachable with the stored trust pin; application/login readiness is not tested.",None),
        Err(xmsg::enroll_client::Error::Configuration)=>report.add("enrollment.ca_tls",Status::Fail,"Stored CA URL or trust pin is invalid.",Some("Correct the saved enrollment configuration through the normal enrollment workflow.")),
        Err(_)=>report.add("enrollment.ca_tls",Status::Warn,"CA TLS endpoint could not be verified; current identity expiry is unchanged.",Some("Check the saved CA URL, trust pin and network; TLS reachability is not enrollment-service readiness.")),
    }
}
async fn inspect(args: &DoctorArgs) -> Report {
    let mut report = Report::new();
    let http = args
        .http_sock
        .clone()
        .or_else(|| xmsg::http::default_http_sock_path().ok());
    let agent = args
        .agent_sock
        .clone()
        .or_else(|| xmsg::agent::default_agent_sock_path().ok());
    let register = args
        .register_sock
        .clone()
        .or_else(|| xmsg::agent::default_register_sock_path().ok());
    let db = super::resolve_db_path(args.db_path.clone());
    report.path("database", &db);
    let mut http_good = false;
    if let Some(path) = &http {
        report.path("http_socket", path);
        let valid = path.parent().is_some_and(private_directory);
        report.add("runtime.directory",if valid{Status::Pass}else{Status::Fail},if valid{"HTTP socket directory is private and owned by this user."}else{"HTTP socket directory is missing or not private for this user."},if valid{None}else{Some("Run as the node user and use its actual private runtime directory; doctor does not create or chmod it.")});
    } else {
        report.add(
            "runtime.directory",
            Status::Fail,
            "Cannot determine the default runtime directory.",
            Some("Set a valid XDG_RUNTIME_DIR or pass the node's socket paths."),
        );
    }
    for (id, path) in [
        ("socket.agent", agent.as_deref()),
        ("socket.register", register.as_deref()),
    ] {
        if let Some(path) = path {
            report.path(id, path);
            socket(&mut report, id, path);
        } else {
            report.add(
                id,
                Status::Fail,
                "Cannot determine socket path.",
                Some("Pass the node's actual socket path."),
            );
        }
    }
    if let Some(path) = &http {
        if socket(&mut report, "socket.http", path) {
            http_good = true;
            health(&mut report, path).await;
            sessions(&mut report, path).await;
        } else {
            report.add(
                "daemon.health",
                Status::Fail,
                "Health was not contacted because the socket metadata is invalid.",
                Some("Correct the socket/user setup and rerun doctor."),
            );
        }
    } else {
        report.add(
            "socket.http",
            Status::Fail,
            "HTTP socket path is unavailable.",
            Some("Pass --http-sock PATH."),
        );
    }
    database(&mut report, &db);
    let sidecar = suffix(&db, ".observe.sqlite");
    report.path("observation_sidecar", &sidecar);
    observe(&mut report, &sidecar);
    let configured_peers = if let Some(path) = &args.peers_file {
        report.path("peers", path);
        peers(&mut report, path, args.fed_cert.as_deref())
    } else {
        report.not_checked.push("peers_configuration");
        Vec::new()
    };
    federation(
        &mut report,
        http.as_deref().filter(|_| http_good),
        &configured_peers,
    )
    .await;
    let default = xmsg::enroll_client::default_state_directory();
    let enrolled = args
        .enroll_state
        .as_ref()
        .or_else(|| fs::symlink_metadata(&default).ok().map(|_| &default));
    if let Some(path) = enrolled {
        report.path("enrollment", path);
        enrollment(&mut report, path).await;
    } else {
        report.not_checked.push("enrollment_metadata");
    }
    report
}
fn inert(text: &str) -> String {
    text.chars().flat_map(char::escape_default).collect()
}
pub fn run(args: DoctorArgs) -> Result<bool> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(inspect(&args));
    runtime.shutdown_timeout(Duration::from_millis(100));
    let mut out = io::stdout().lock();
    if args.json {
        serde_json::to_writer(&mut out, &report)?;
        writeln!(out)?;
    } else {
        writeln!(
            out,
            "xmsg doctor (client {}, revision {})",
            report.client_version, report.client_build_revision
        )?;
        for (name, path) in &report.checked_paths {
            writeln!(out, "checked {name}: {}", inert(path))?;
        }
        for check in &report.checks {
            let status = match check.status {
                Status::Pass => "PASS",
                Status::Warn => "WARN",
                Status::Fail => "FAIL",
            };
            writeln!(
                out,
                "{status} {}: {}",
                inert(&check.id),
                inert(&check.message)
            )?;
            if let Some(hint) = check.hint {
                writeln!(out, "  Fix: {hint}")?;
            }
        }
        writeln!(
            out,
            "{} passed; {} warnings; {} failed. Only the listed checks were performed.",
            report.passed, report.warnings, report.failed
        )?;
    }
    Ok(report.failed != 0)
}
