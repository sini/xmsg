#![cfg(target_os = "macos")]
//! agy presence locks on live macOS: the holder is nominated by the open file's sticky
//! `FWASLOCKED` flag and held only while a kqueue `NOTE_FUNLOCK` watch on the file is unfired.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};
use tokio::sync::broadcast;

use xmsg::agy::{
    attest_mcp_caller, attested_lock_holder, find_lock_holder_fdinfo, list_agy_sessions,
    new_agy_store, run_agy_proc_watcher, verify_registration, AgyConfig, AgyRegisterRequest,
    LIVE_PROC_LOCKS,
};
use xmsg::error::AppError;
use xmsg::process::{open_file_vnodes, LIVE_PROC_ROOT};
use xmsg::registry::SessionsQuery;
use xmsg::storage;

const HOLD: &str = "XMSG_DARWIN_PRESENCE_HOLD";
const MODE: &str = "XMSG_DARWIN_PRESENCE_MODE";

/// A child spawned by any test briefly shows this process's descriptors, close-on-exec ones
/// included, until its exec closes them; while it does, a lock held in this process has two
/// flagged processes and reads as ambiguous. The tests run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn live() -> &'static Path {
    Path::new(LIVE_PROC_ROOT)
}

fn flock(fd: i32, op: i32) {
    assert_eq!(unsafe { libc::flock(fd, op) }, 0, "flock {op}");
}

/// The re-exec'd child. `lock`: hold `$HOLD` locked. `dup`: the same, and share that open file
/// with a `sleep` grandchild. `creds`: the same, and run a `sleep` grandchild carrying agy's
/// credentials, as agy's `run_command` does. `sleep`: wait. All of them wait for stdin to close.
#[test]
fn presence_child() {
    let Some(path) = std::env::var_os(HOLD) else {
        return;
    };
    let mode = std::env::var(MODE).unwrap();
    let mut kids = Vec::new();
    let mut file = None;
    if mode != "sleep" {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        flock(f.as_raw_fd(), libc::LOCK_EX);
        let grandchild = |mode: &str| {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "presence_child", "--nocapture"])
                .env(MODE, mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap()
        };
        if mode == "dup" {
            // Shared across exec: the grandchild's open file is this one, lock flag included.
            unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETFD, 0) };
            kids.push(grandchild("sleep"));
        }
        if mode == "creds" {
            kids.push(grandchild("sleep"));
        }
        file = Some(f);
    }
    let pids: Vec<String> = kids.iter().map(|k| k.id().to_string()).collect();
    println!("ready {}", pids.join(" "));
    std::io::stdout().flush().unwrap();
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
    drop(file);
    for mut k in kids {
        drop(k.stdin.take());
        let _ = k.wait();
    }
}

/// A re-exec'd [`presence_child`], ended (by its own PID) when dropped.
struct Holder {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    grandchildren: Vec<u32>,
}

impl Holder {
    fn spawn(path: &Path, mode: &str, env: &[(&str, &str)]) -> Holder {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "presence_child", "--nocapture"])
            .env(HOLD, path)
            .env(MODE, mode)
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        // Built before the wait for `ready`, so a failed wait still ends the child.
        let mut holder = Holder {
            child,
            stdin,
            stdout,
            grandchildren: Vec::new(),
        };
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                holder.stdout.read_line(&mut line).unwrap(),
                0,
                "child exited early"
            );
            if let Some(rest) = line.strip_prefix("ready") {
                holder.grandchildren = rest
                    .split_whitespace()
                    .map(|p| p.parse().unwrap())
                    .collect();
                return holder;
            }
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Presence {
    _dir: TempDir,
    dir: PathBuf,
}

impl Presence {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        Presence {
            dir: path,
            _dir: dir,
        }
    }

    fn lock(&self, conv: &str) -> PathBuf {
        let p = self.dir.join(format!("{conv}.lock"));
        fs::write(&p, "").unwrap();
        p
    }

    fn config(&self, agy_bin: &str) -> AgyConfig {
        AgyConfig {
            presence_dir: self.dir.clone(),
            brain_dir: PathBuf::new(),
            proc_locks_path: PathBuf::from(LIVE_PROC_LOCKS),
            proc_root: PathBuf::from(LIVE_PROC_ROOT),
            agy_bin: agy_bin.to_string(),
            trusted_agy_exes: vec![std::env::current_exe().unwrap()],
        }
    }

    /// The holder PID List reports for `conv`, if it lists it unregistered.
    fn listed(&self, conv: &str) -> Option<u32> {
        list_agy_sessions(
            &self.config("agy"),
            &new_agy_store(),
            &SessionsQuery::default(),
        )
        .into_iter()
        .find(|s| s.session_id == conv && s.status == "unregistered")
        .map(|s| s.pid)
    }
}

fn has_flock(pid: u32, path: &Path) -> bool {
    let meta = fs::metadata(path).unwrap();
    open_file_vnodes(live(), pid, None)
        .unwrap()
        .iter()
        .any(|v| v.dev == meta.dev() && v.ino == meta.ino() && v.has_flock)
}

// ---------------------------------------------------------------------------
// A real flock in this process: listed while held. LOCK_UN with the fd still open leaves the
// lock flag set (the sticky control), and List omits it. Closing a locked fd omits it too.
// Mutant: trust has_flock without the watch => RED (the LOCK_UN arm).
// ---------------------------------------------------------------------------
#[test]
fn unlock_without_close_is_released_though_the_flag_stays() {
    let _serial = serial();
    let p = Presence::new();
    let conv = "0199cecf-da01-7000-8000-00000000da01";
    let path = p.lock(conv);
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert_eq!(p.listed(conv), None, "unlocked: not listed");
    flock(f.as_raw_fd(), libc::LOCK_EX);
    assert_eq!(p.listed(conv), Some(std::process::id()), "held: listed");
    assert_eq!(p.listed(conv), Some(std::process::id()), "still held");

    flock(f.as_raw_fd(), libc::LOCK_UN);
    assert!(
        has_flock(std::process::id(), &path),
        "control: the lock flag stays set after LOCK_UN while the file is open"
    );
    assert_eq!(p.listed(conv), None, "released by LOCK_UN: not listed");
    drop(f);
}

#[test]
fn close_of_a_locked_fd_is_released() {
    let _serial = serial();
    let p = Presence::new();
    let conv = "0199cecf-da02-7000-8000-00000000da02";
    let path = p.lock(conv);
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    flock(f.as_raw_fd(), libc::LOCK_EX);
    assert_eq!(p.listed(conv), Some(std::process::id()), "held: listed");
    drop(f);
    assert_eq!(p.listed(conv), None, "closed: not listed");

    // A child's lock, and its exit.
    let h = Holder::spawn(&path, "lock", &[]);
    assert_eq!(p.listed(conv), Some(h.pid()), "a child's lock is listed");
    drop(h);
    assert_eq!(p.listed(conv), None, "the child's exit releases it");
}

// ---------------------------------------------------------------------------
// The sibling opener: a child holds the lock while this process has the same file open O_RDWR,
// unlocked. The holder is the child, and neither attestation from the unlocked opener passes.
// Mutant: restore G5's skip of the holder check (`else { true }`) => RED.
// ---------------------------------------------------------------------------
#[test]
fn an_unlocked_sibling_opener_is_not_the_holder() {
    let _serial = serial();
    let p = Presence::new();
    let conv = "0199cecf-da03-7000-8000-00000000da03";
    let path = p.lock(conv);
    let h = Holder::spawn(&path, "lock", &[]);
    let _sibling = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let meta = fs::metadata(&path).unwrap();
    let me = std::process::id();
    let uid = xmsg::agent::current_uid();
    let trusted = vec![std::env::current_exe().unwrap()];
    let locks = Path::new(LIVE_PROC_LOCKS);

    // The order matters to neither: once from a cold cache, once with the child watched.
    for round in ["cold", "watched"] {
        let attest = attest_mcp_caller(live(), locks, &p.dir, &trusted, uid, uid, me);
        assert!(
            matches!(attest, Err(AppError::NotRecipient(_))),
            "{round}: attest from the unlocked opener: {attest:?}"
        );
        let req = AgyRegisterRequest {
            conversation_id: conv.to_string(),
            ls_address: "127.0.0.1:1".to_string(),
            csrf_token: "t".to_string(),
        };
        let reg = verify_registration(live(), locks, &p.dir, &trusted, uid, uid, me, &req);
        assert!(
            matches!(reg, Err(AppError::NotRecipient(_))),
            "{round}: register from the unlocked opener: {reg:?}"
        );
        assert_eq!(
            find_lock_holder_fdinfo(live(), locks, meta.dev(), meta.ino()).unwrap(),
            Some(h.pid()),
            "{round}: the holder is the child"
        );
    }
    // Control: the child itself attests.
    let ok = attest_mcp_caller(live(), locks, &p.dir, &trusted, uid, uid, h.pid());
    assert_eq!(ok.expect("the holder attests").0.pid, h.pid());
}

// ---------------------------------------------------------------------------
// Two processes with the lock flag on the same open file (a dup shared with a grandchild):
// no holder, and List omits it.
// ---------------------------------------------------------------------------
#[test]
fn two_flagged_processes_are_ambiguous() {
    let _serial = serial();
    let p = Presence::new();
    let conv = "0199cecf-da04-7000-8000-00000000da04";
    let path = p.lock(conv);
    let h = Holder::spawn(&path, "dup", &[]);
    assert_eq!(h.grandchildren.len(), 1);
    assert!(has_flock(h.pid(), &path), "control: the child is flagged");
    assert!(
        has_flock(h.grandchildren[0], &path),
        "control: the grandchild is flagged"
    );
    let meta = fs::metadata(&path).unwrap();
    let holder =
        find_lock_holder_fdinfo(live(), Path::new(LIVE_PROC_LOCKS), meta.dev(), meta.ino());
    assert!(
        !matches!(holder, Ok(Some(_))),
        "ambiguous holders fail closed: {holder:?}"
    );
    assert_eq!(p.listed(conv), None);
}

// ---------------------------------------------------------------------------
// The same ambiguity through a call attesting one pid: with two flagged processes, neither is
// the holder, and neither call leaves a watched holder behind for the next List.
// Mutant: scan only the attested pid => RED.
// ---------------------------------------------------------------------------
#[test]
fn attesting_one_of_two_flagged_processes_finds_no_holder() {
    let _serial = serial();
    let p = Presence::new();
    let conv = "0199cecf-da06-7000-8000-00000000da06";
    let path = p.lock(conv);
    let h = Holder::spawn(&path, "dup", &[]);
    let pids = [h.pid(), h.grandchildren[0]];
    assert!(
        pids.iter().all(|&pid| has_flock(pid, &path)),
        "control: both are flagged"
    );
    let meta = fs::metadata(&path).unwrap();
    let locks = Path::new(LIVE_PROC_LOCKS);
    for pid in pids {
        let holder = attested_lock_holder(live(), locks, pid, meta.dev(), meta.ino());
        assert!(
            !matches!(holder, Ok(Some(_))),
            "attesting {pid}: no holder: {holder:?}"
        );
    }
    let holder = find_lock_holder_fdinfo(live(), locks, meta.dev(), meta.ino());
    assert!(
        !matches!(holder, Ok(Some(_))),
        "no watched holder was left behind: {holder:?}"
    );
    let uid = xmsg::agent::current_uid();
    let trusted = vec![std::env::current_exe().unwrap()];
    let attest = attest_mcp_caller(live(), locks, &p.dir, &trusted, uid, uid, h.pid());
    assert!(
        matches!(attest, Err(AppError::NotRecipient(_))),
        "mcp_start from a flagged process is refused: {attest:?}"
    );
    assert_eq!(p.listed(conv), None);
}

fn new_db() -> Arc<Mutex<rusqlite::Connection>> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    Arc::new(Mutex::new(conn))
}

// ---------------------------------------------------------------------------
// The user-visible fix: an agy conversation nothing has registered (no hook turn yet) is listed
// and a send to it is queued; the proc watcher then registers it from the credentials in agy's
// command subtree, and the queued message reaches agy, with no hook request at all.
// ---------------------------------------------------------------------------
// The guard serializes the tests; it guards no data.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread")]
async fn unregistered_conversation_is_listed_queued_and_delivered_before_any_hook() {
    let _serial = serial();
    let tmp = tempdir().unwrap();
    let p = Presence::new();
    let conv = "0199cecf-da05-7000-8000-00000000da05";
    let path = p.lock(conv);
    let delivered = tmp.path().join("delivered.log");
    let agy_bin = tmp.path().join("fake_agy.sh");
    fs::write(
        &agy_bin,
        format!(
            "#!/bin/sh\necho ===DELIVERY=== >> '{0}'\necho \"$@\" >> '{0}'\nexit 0\n",
            delivered.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&agy_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let h = Holder::spawn(
        &path,
        "creds",
        &[
            ("ANTIGRAVITY_LS_ADDRESS", "127.0.0.1:44555"),
            ("ANTIGRAVITY_CSRF_TOKEN", "token-darwin-da05"),
        ],
    );
    let config = p.config(agy_bin.to_str().unwrap());
    let store = new_agy_store();
    let db = new_db();
    let state = Arc::new(xmsg::http::AppState {
        max_attachment_bytes: 8 * 1024 * 1024,
        sessions_dirs: vec![tmp.path().join("sessions")],
        agy_config: config.clone(),
        agy_store: store.clone(),
        pi_store: xmsg::pi::new_pi_store(),
        pi_notify_tx: broadcast::channel(16).0,
        svc_store: xmsg::svc::new_svc_store(),
        svc_notify_tx: broadcast::channel(16).0,
        node_name: "test-host".to_string(),
        max_body: 65536,
        request_counter: AtomicU64::new(1),
        db: db.clone(),
        notify_tx: broadcast::channel(16).0,
        reply_ttl: Duration::from_secs(3600),
        idempotency_ttl: Duration::from_secs(86400),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
        fed_state: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = xmsg::http::build_router(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    assert_eq!(p.listed(conv), Some(h.pid()), "listed before any hook turn");
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/messages"))
        .json(&serde_json::json!({"to": conv, "from": "claude-orch", "text": "darwin first"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["outcome"], "queued", "{body}");
    assert!(!delivered.exists(), "nothing delivered while unregistered");

    // The watcher, as `xmsg serve` runs it; nothing ever sends it a hook `check`.
    let (_arm_tx, arm_rx) = tokio::sync::mpsc::unbounded_channel();
    let watcher = tokio::spawn(run_agy_proc_watcher(
        config,
        store.clone(),
        db,
        xmsg::agent::current_uid(),
        arm_rx,
        Duration::from_secs(3600),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fs::read_to_string(&delivered).is_ok_and(|s| s.contains("darwin first"))
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    watcher.abort();
    let log = fs::read_to_string(&delivered).unwrap_or_default();
    assert_eq!(
        log.matches("===DELIVERY===").count(),
        1,
        "delivered once by the watcher's registration: {log}"
    );
    assert!(log.contains("darwin first"), "{log}");
    let info = store
        .read()
        .unwrap()
        .get(conv)
        .cloned()
        .expect("registered");
    assert_eq!(info.pid, h.pid(), "registered against the lock holder");
    assert_eq!(
        info.credentials.unwrap().csrf_token,
        "token-darwin-da05",
        "from the grandchild's environment"
    );
}
