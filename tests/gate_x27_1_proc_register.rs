use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};
use tokio::sync::broadcast;

use xmsg::agy::{
    dev_major, dev_minor, new_agy_store, run_register_server, scan_and_register_agy_proc,
    AgyConfig, AgyProcWatch, AgyStore,
};
use xmsg::storage;

const ENV_PREFIX: &[u8] = b"ANTIGRAVITY_LS_ADDRESS=127.0.0.1:44555\0ANTIGRAVITY_CSRF_TOKEN=";

fn agy_env(token: &str) -> Vec<u8> {
    [ENV_PREFIX, token.as_bytes(), b"\0OTHER_VAR=secret\0"].concat()
}

fn stat_line(pid: u32, ppid: u32, starttime: &str) -> String {
    format!(
        "{pid} (proc) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0 0 0 0 0 0 0 0 0\n"
    )
}

/// A fake /proc, /proc/locks and agy presence directory.
struct Tree {
    _dirs: [TempDir; 3],
    proc_root: PathBuf,
    proc_locks: PathBuf,
    presence: PathBuf,
    trusted_exe: PathBuf,
}

impl Tree {
    fn new() -> Self {
        let dirs = [tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap()];
        let proc_locks = dirs[1].path().join("locks");
        fs::write(&proc_locks, "").unwrap();
        Tree {
            proc_root: dirs[0].path().to_path_buf(),
            proc_locks,
            presence: dirs[2].path().to_path_buf(),
            trusted_exe: std::env::current_exe().unwrap(),
            _dirs: dirs,
        }
    }

    fn lock_file(&self, conv: &str) -> PathBuf {
        let p = self.presence.join(format!("{conv}.lock"));
        if !p.exists() {
            fs::write(&p, "").unwrap();
        }
        p
    }

    /// Records `holder` as the FLOCK holder of `conv`'s presence lock in /proc/locks.
    fn hold(&self, conv: &str, holder: u32) {
        let meta = fs::metadata(self.lock_file(conv)).unwrap();
        let line = format!(
            "1: FLOCK ADVISORY WRITE {holder} {:02x}:{:02x}:{} 0 EOF\n",
            dev_major(meta.dev()),
            dev_minor(meta.dev()),
            meta.ino()
        );
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&self.proc_locks)
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();
    }

    fn process(&self, pid: u32, ppid: u32, exe: Option<&Path>, open: Option<&Path>, st: &str) {
        let dir = self.proc_root.join(pid.to_string());
        fs::create_dir_all(dir.join("fd")).unwrap();
        fs::write(dir.join("stat"), stat_line(pid, ppid, st)).unwrap();
        if let Some(e) = exe {
            std::os::unix::fs::symlink(e, dir.join("exe")).unwrap();
        }
        if let Some(target) = open {
            std::os::unix::fs::symlink(target, dir.join("fd").join("3")).unwrap();
        }
    }

    /// An agy holding `conv`'s presence lock, running `exe`.
    fn agy(&self, conv: &str, pid: u32, exe: &Path) {
        let lock = self.lock_file(conv);
        self.process(pid, 1, Some(exe), Some(&lock), "100");
    }

    /// Lists `kids` in `/proc/<pid>/task/<tid>/children`, as the kernel does for children forked
    /// by thread `tid`.
    fn children(&self, pid: u32, tid: u32, kids: &[u32]) {
        let dir = self
            .proc_root
            .join(pid.to_string())
            .join("task")
            .join(tid.to_string());
        fs::create_dir_all(&dir).unwrap();
        let s: String = kids.iter().map(|k| format!("{k} ")).collect();
        fs::write(dir.join("children"), s).unwrap();
    }

    fn environ(&self, pid: u32) -> PathBuf {
        self.proc_root.join(pid.to_string()).join("environ")
    }

    fn config(&self) -> AgyConfig {
        AgyConfig {
            presence_dir: self.presence.clone(),
            proc_locks_path: self.proc_locks.clone(),
            proc_root: self.proc_root.clone(),
            agy_bin: "agy".to_string(),
            trusted_agy_exes: vec![self.trusted_exe.clone()],
                brain_dir: std::path::PathBuf::new(),
    }
    }
}

fn new_db() -> Arc<Mutex<rusqlite::Connection>> {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    storage::init_db(&conn).unwrap();
    Arc::new(Mutex::new(conn))
}

async fn scan(tree: &Tree, store: &AgyStore, convs: &[&str]) -> Result<Vec<String>, String> {
    let ids: Vec<String> = convs.iter().map(|c| c.to_string()).collect();
    scan_and_register_agy_proc(
        &tree.config(),
        store,
        &new_db(),
        xmsg::agent::current_uid(),
        &ids,
        &mut AgyProcWatch::default(),
        Duration::from_secs(3600),
    )
    .await
    .map_err(|e| e.to_string())
}

fn csrf_of(store: &AgyStore, conv: &str) -> Option<String> {
    store
        .read()
        .unwrap()
        .values()
        .find(|i| i.conversation_id == conv)
        .and_then(|i| i.credentials.as_ref().map(|c| c.csrf_token.clone()))
}

const O_NONBLOCK: i32 = if cfg!(target_os = "linux") {
    0o4000
} else {
    0x0004
};

/// Makes `path` a FIFO and serves it from a thread: each time a reader opens it, `content(n)` for
/// the n-th open is written and the write end closed. The thread polls a NON-BLOCKING open, so it
/// cannot hang when no reader comes; it stops when `stop` is set or after 10 s, and joins to the
/// number of opens it served.
fn serve_fifo(
    path: PathBuf,
    stop: Arc<AtomicBool>,
    mut content: impl FnMut(usize) -> Vec<u8> + Send + 'static,
) -> JoinHandle<usize> {
    let _ = fs::remove_file(&path);
    assert!(Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap()
        .success());
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut served = 0;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            match fs::OpenOptions::new()
                .write(true)
                .custom_flags(O_NONBLOCK)
                .open(&path)
            {
                Ok(mut f) => {
                    let _ = f.write_all(&content(served));
                    drop(f);
                    served += 1;
                    // Let this reader reach EOF and close before the next open is served.
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
        // Release a reader that is still blocked in open, so the test fails rather than hangs.
        let _ = fs::OpenOptions::new().read(true).write(true).open(&path);
        served
    })
}

fn run_hook(bin: &str, sock_path: &Path, conv_id: &str) -> (i32, Value) {
    let mut child = Command::new(bin)
        .args([
            "register",
            "agy",
            "--hook",
            "--sock",
            sock_path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdin_payload = serde_json::json!({ "conversationId": conv_id });
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let status = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: Value = serde_json::from_str(stdout.trim()).expect("valid json output");
    (status, val)
}

fn assert_hook_injects(out: &Value, what: &str) {
    let steps = out["injectSteps"]
        .as_array()
        .unwrap_or_else(|| panic!("{what}: injectSteps array must exist, got {out}"));
    assert_eq!(steps.len(), 1, "{what}: must inject one ephemeralMessage");
    assert!(
        steps[0].get("userMessage").is_none(),
        "{what}: must not contain userMessage, got {out}"
    );
    let msg = steps[0]["ephemeralMessage"]
        .as_str()
        .unwrap_or_else(|| panic!("{what}: ephemeralMessage string must exist, got {out}"));
    assert!(msg.contains("register agy"), "{what}: {msg}");
}

/// The register server's `check` action, as the hook sends it.
fn check(sock: &Path, conv: &str) -> Value {
    let mut s = UnixStream::connect(sock).unwrap();
    let req = serde_json::json!({ "action": "check", "conversation_id": conv });
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

/// Starts `run_register_server` as `xmsg serve` does, and returns its socket once it exists.
async fn start_server(config: AgyConfig, store: AgyStore) -> (TempDir, PathBuf) {
    let sock_dir = tempdir().unwrap();
    fs::set_permissions(sock_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sock = sock_dir.path().join("register.sock");
    let s_path = sock.clone();
    tokio::spawn(async move {
        let state = Arc::new(xmsg::http::AppState {
            sessions_dirs: vec![],
            agy_config: config,
            agy_store: store,
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx: broadcast::channel(16).0,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: broadcast::channel(16).0,
            node_name: xmsg::node::local_node_name(),
            max_body: 65536,
            request_counter: std::sync::atomic::AtomicU64::new(1),
            db: new_db(),
            notify_tx: broadcast::channel(16).0,
            reply_ttl: Duration::from_secs(604800),
            idempotency_ttl: Duration::from_secs(86400),
            long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
            fed_state: None,
        });
        let _ = run_register_server(
            s_path,
            state,
            xmsg::agent::current_uid(),
            std::collections::HashMap::new(),
        )
        .await;
    });
    for _ in 0..3000 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(sock.exists(), "register server must create its socket");
    (sock_dir, sock)
}

async fn wait_registered(store: &AgyStore, conv: &str, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(c) = csrf_of(store, conv) {
            return Some(c);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    csrf_of(store, conv)
}

// ---------------------------------------------------------------------------
// Oracle 1: an attested agy holding the presence lock, a child whose environ carries both
// variables => the conversation is registered. The child is listed under a NON-main thread's
// children file, as for a command forked by one of agy's worker threads.
// Mutant: scan disabled => RED.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn oracle_1_attested_child_environ_registers() {
    let t = Tree::new();
    t.agy("conv-1", 1000, &t.trusted_exe);
    t.hold("conv-1", 1000);
    t.children(1000, 1000, &[]);
    t.children(1000, 1007, &[1001]);
    t.process(1001, 1000, None, None, "200");
    fs::write(t.environ(1001), agy_env("token-oracle-1")).unwrap();

    let store = new_agy_store();
    let still = scan(&t, &store, &["conv-1"]).await.unwrap();
    assert!(
        still.is_empty(),
        "a registered conversation stops being watched"
    );
    assert_eq!(csrf_of(&store, "conv-1").as_deref(), Some("token-oracle-1"));
    let info = store.read().unwrap().values().next().cloned().unwrap();
    let creds = info.credentials.unwrap();
    assert_eq!(creds.ls_address, "127.0.0.1:44555");
    assert!(!creds.is_stale);
    assert_eq!(info.pid, 1000, "registered against the attested agy");
}

// ---------------------------------------------------------------------------
// Oracle 1c: the scan verifies the process that SUPPLIED the credentials, as `xmsg register agy`
// verifies its peer. Between the attested agy (5900, the FLOCK holder) and the supplying process
// (5902) sits a second trusted agy (5901) with the lock file open but not holding the lock;
// `verify_registration` from 5902 picks 5901 and refuses, so the scan must not register either.
// Mutant: verify with the attested agy as the peer => RED.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn oracle_1c_verification_runs_on_the_supplying_process() {
    let t = Tree::new();
    t.agy("conv-1c", 5900, &t.trusted_exe);
    t.hold("conv-1c", 5900);
    t.children(5900, 5900, &[5901]);
    let lock = t.lock_file("conv-1c");
    t.process(5901, 5900, Some(&t.trusted_exe), Some(&lock), "200");
    t.children(5901, 5901, &[5902]);
    t.process(5902, 5901, None, None, "300");
    fs::write(t.environ(5902), agy_env("token-1c")).unwrap();

    let req = xmsg::agy::AgyRegisterRequest {
        conversation_id: "conv-1c".to_string(),
        ls_address: "127.0.0.1:44555".to_string(),
        csrf_token: "token-1c".to_string(),
    };
    let uid = xmsg::agent::current_uid();
    let c = t.config();
    let direct = xmsg::agy::verify_registration(
        &c.proc_root,
        &c.proc_locks_path,
        &c.presence_dir,
        &c.trusted_agy_exes,
        uid,
        uid,
        5902,
        &req,
    );
    assert!(
        direct.is_err(),
        "fixture: register agy from 5902 is refused"
    );

    let store = new_agy_store();
    assert!(scan(&t, &store, &["conv-1c"]).await.is_ok());
    assert_eq!(
        csrf_of(&store, "conv-1c"),
        None,
        "the scan must refuse what `register agy` from the supplying process refuses"
    );
}

// ---------------------------------------------------------------------------
// Oracle 1b: the PRODUCTION watcher. `run_register_server` (as `xmsg serve` runs it) on the fake
// tree registers, with no hook ever run:
//   (a) a conversation already eligible when the server starts, without any request at all;
//   (b) a conversation that becomes eligible later, once the hook's `check` arms the watcher.
//       Between those, with nothing armed, the watcher does no work: conv-b, eligible but unarmed,
//       stays unregistered.
// Mutants: watcher not spawned => RED (a); no start-up sweep => RED (a); check does not arm => RED (b).
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn oracle_1b_serve_watcher_registers_without_hook() {
    let t = Tree::new();
    t.agy("conv-1b-a", 6000, &t.trusted_exe);
    t.hold("conv-1b-a", 6000);
    t.children(6000, 6000, &[6001]);
    t.process(6001, 6000, None, None, "200");
    fs::write(t.environ(6001), agy_env("token-1b-a")).unwrap();

    t.agy("conv-1b-b", 6100, &t.trusted_exe);
    t.children(6100, 6100, &[6101]);
    t.process(6101, 6100, None, None, "200");
    fs::write(t.environ(6101), agy_env("token-1b-b")).unwrap();

    let store = new_agy_store();
    let (_dir, sock) = start_server(t.config(), store.clone()).await;

    // (a) no request of any kind: the watcher alone registers conv-1b-a.
    assert_eq!(
        wait_registered(&store, "conv-1b-a", Duration::from_secs(5))
            .await
            .as_deref(),
        Some("token-1b-a"),
        "the serve watcher must register an eligible conversation with no hook call"
    );
    assert_eq!(check(&sock, "conv-1b-a")["hasCredentials"], true);

    // conv-1b-b's lock is not held yet: not eligible, not registered.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(csrf_of(&store, "conv-1b-b"), None);

    // Held now, but nothing has armed it: the idle watcher reads nothing.
    t.hold("conv-1b-b", 6100);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        csrf_of(&store, "conv-1b-b"),
        None,
        "with nothing armed the watcher must stay idle"
    );

    // (b) the hook's check arms it; the watcher registers it.
    assert_eq!(check(&sock, "conv-1b-b")["watching"], true);
    let deadline = Instant::now() + Duration::from_secs(5);
    while check(&sock, "conv-1b-b")["hasCredentials"] != true && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        check(&sock, "conv-1b-b")["hasCredentials"],
        true,
        "check must arm the watcher for a conversation that became eligible"
    );
    assert_eq!(csrf_of(&store, "conv-1b-b").as_deref(), Some("token-1b-b"));
}

// ---------------------------------------------------------------------------
// Oracle 2: the variables in a process OUTSIDE the attested agy's subtree => not registered, and
// that process is never even read: FIFOs count the opens of its `environ` and its `stat`.
//   2a: a sibling of the attested agy (ppid 1).
//   2b: the child of a NON-attested agy binary (same file name, other path) holding a lock.
// Each runs with the kernel's children files (descent) and without them. Without them nothing is
// read at all, nothing registers, and `check` reports `watching: false`, so the hook injects on
// turn 1.
// Mutants: subtree replaced by all of /proc => RED (descent); /proc listing restored where the
// children file is absent => RED (no children); attestation skipped => RED (2b).
// ---------------------------------------------------------------------------
async fn oracle_2_outside(non_attested: bool, children: bool) {
    let t = Tree::new();
    t.agy("conv-2a", 2000, &t.trusted_exe);
    t.hold("conv-2a", 2000);
    // An in-subtree child without the variables, so the scan has a subtree to walk.
    t.process(2002, 2000, None, None, "200");
    if children {
        t.children(2000, 2000, &[2002]);
    }

    let other_dir = tempdir().unwrap();
    let outsider = if non_attested {
        let other_exe = other_dir.path().join(t.trusted_exe.file_name().unwrap());
        fs::write(&other_exe, "").unwrap();
        t.agy("conv-2b", 2100, &other_exe);
        t.hold("conv-2b", 2100);
        t.process(2101, 2100, None, None, "200");
        if children {
            t.children(2100, 2100, &[2101]);
        }
        2101
    } else {
        t.process(2001, 1, None, None, "200");
        2001
    };
    let stop = Arc::new(AtomicBool::new(false));
    let opens = serve_fifo(t.environ(outsider), stop.clone(), |_| {
        agy_env("token-oracle-2")
    });
    let outsider_ppid = if non_attested { 2100 } else { 1 };
    let stat_reads = serve_fifo(
        t.proc_root.join(outsider.to_string()).join("stat"),
        stop.clone(),
        move |_| stat_line(outsider, outsider_ppid, "200").into_bytes(),
    );

    let store = new_agy_store();
    let res = scan(&t, &store, &["conv-2a", "conv-2b"]).await;
    let mut checked = None;
    if !children {
        // The production server: its start-up sweep arms conv-2a, and the hook's check runs.
        let (_dir, sock) = start_server(t.config(), store.clone()).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let watching = check(&sock, "conv-2a")["watching"].clone();
        let (code, out) = run_hook(env!("CARGO_BIN_EXE_xmsg"), &sock, "conv-2a");
        checked = Some((watching, code, out));
    }
    stop.store(true, Ordering::SeqCst);
    let opens = opens.join().unwrap();
    let stat_reads = stat_reads.join().unwrap();

    assert_eq!(
        opens, 0,
        "a process outside the attested subtree must never be read"
    );
    assert_eq!(
        stat_reads, 0,
        "a process outside the attested subtree must never be read, not even its stat"
    );
    assert!(res.is_ok(), "{res:?}");
    assert!(store.read().unwrap().is_empty(), "nothing may register");
    if let Some((watching, code, out)) = checked {
        assert_eq!(
            watching, false,
            "without the children file the watcher reads nothing, so check must not stand down"
        );
        assert_eq!(code, 0);
        assert_hook_injects(&out, "turn 1 without the children file");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn oracle_2a_sibling_outside_subtree() {
    oracle_2_outside(false, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oracle_2a_sibling_outside_subtree_no_children() {
    oracle_2_outside(false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oracle_2b_child_of_non_attested_agy() {
    oracle_2_outside(true, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn oracle_2b_child_of_non_attested_agy_no_children() {
    oracle_2_outside(true, false).await;
}

// ---------------------------------------------------------------------------
// Oracle 3: a child whose pid is recycled WHILE its environ is read (start time changes between
// the pin and the re-read) => ignored. The FIFO writer is bounded, so a scan that never opens the
// environ fails the `opens` assertion instead of hanging.
// Mutant: no start-time re-read check => RED.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn oracle_3_recycled_child_pid_starttime_mismatch_ignored() {
    let t = Tree::new();
    t.agy("conv-3", 3000, &t.trusted_exe);
    t.hold("conv-3", 3000);
    t.children(3000, 3000, &[3001]);
    t.process(3001, 3000, None, None, "200");

    let stat = t.proc_root.join("3001").join("stat");
    let stop = Arc::new(AtomicBool::new(false));
    let opens = serve_fifo(t.environ(3001), stop.clone(), move |_| {
        // The pid is recycled while its environ is being read.
        fs::write(&stat, stat_line(3001, 3000, "9999")).unwrap();
        agy_env("token-oracle-3")
    });

    let store = new_agy_store();
    let res = scan(&t, &store, &["conv-3"]).await;
    stop.store(true, Ordering::SeqCst);
    let opens = opens.join().unwrap();

    assert_eq!(
        opens, 1,
        "the scan must read the child's environ exactly once"
    );
    assert!(res.is_ok(), "{res:?}");
    assert!(
        store.read().unwrap().is_empty(),
        "recycled child pid must be ignored"
    );
}

// ---------------------------------------------------------------------------
// Oracle 3b (pid reuse before the ancestry check): the child's stat is a FIFO that serves the
// genuine child on its first read and a recycled outsider (ppid 1, new start time) on every later
// one. Pinning the start time BEFORE the ancestry check makes the ancestry check see the outsider,
// so its environ is never read.
// Mutants: start-time pin moved back after the ancestry check => RED; descent ancestry (ppid) check
// skipped => RED.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn oracle_3b_pid_recycled_before_ancestry_check_never_read() {
    let t = Tree::new();
    t.agy("conv-3b", 3100, &t.trusted_exe);
    t.hold("conv-3b", 3100);
    t.children(3100, 3100, &[3101]);
    t.process(3101, 3100, None, None, "200");

    let stop = Arc::new(AtomicBool::new(false));
    let stat_reads = serve_fifo(t.proc_root.join("3101").join("stat"), stop.clone(), |n| {
        if n == 0 {
            stat_line(3101, 3100, "200").into_bytes()
        } else {
            stat_line(3101, 1, "9999").into_bytes()
        }
    });
    let environ_opens = serve_fifo(t.environ(3101), stop.clone(), |_| {
        agy_env("token-oracle-3b")
    });

    let store = new_agy_store();
    let res = scan(&t, &store, &["conv-3b"]).await;
    stop.store(true, Ordering::SeqCst);
    let stat_reads = stat_reads.join().unwrap();
    let environ_opens = environ_opens.join().unwrap();

    assert_eq!(
        environ_opens, 0,
        "a pid recycled before the ancestry check must never be read"
    );
    assert_eq!(stat_reads, 2, "start-time pin, then ancestry check");
    assert!(res.is_ok(), "{res:?}");
    assert!(store.read().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Oracle 3c (holder pid recycled before its children are listed): the attested agy's stat is a
// FIFO that serves the attested start time on its first read (attestation) and a new one on every
// later read. Its `children` listing then belongs to the recycled process, so no listed child is
// read, not even its stat.
// Mutant: no holder start-time re-check after the listing => RED.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn oracle_3c_holder_recycled_before_listing_children_never_read() {
    let t = Tree::new();
    t.agy("conv-3c", 3200, &t.trusted_exe);
    t.hold("conv-3c", 3200);
    t.children(3200, 3200, &[3201]);
    t.process(3201, 3200, None, None, "200");

    let stop = Arc::new(AtomicBool::new(false));
    let holder_reads = serve_fifo(t.proc_root.join("3200").join("stat"), stop.clone(), |n| {
        stat_line(3200, 1, if n == 0 { "100" } else { "9999" }).into_bytes()
    });
    let child_stat_reads = serve_fifo(t.proc_root.join("3201").join("stat"), stop.clone(), |_| {
        stat_line(3201, 3200, "200").into_bytes()
    });
    let environ_opens = serve_fifo(t.environ(3201), stop.clone(), |_| {
        agy_env("token-oracle-3c")
    });

    let store = new_agy_store();
    let res = scan(&t, &store, &["conv-3c"]).await;
    stop.store(true, Ordering::SeqCst);
    let holder_reads = holder_reads.join().unwrap();
    let child_stat_reads = child_stat_reads.join().unwrap();
    let environ_opens = environ_opens.join().unwrap();

    assert_eq!(
        child_stat_reads, 0,
        "a child listed by a recycled holder pid must never be read"
    );
    assert_eq!(environ_opens, 0);
    assert_eq!(
        holder_reads, 2,
        "attestation, then the re-check after the listing"
    );
    assert!(res.is_ok(), "{res:?}");
    assert!(store.read().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Oracle 4: unreadable environ => no registration, no error surfaced, and B′'s hook output is as
// in X27: the stand-down turn, then the ephemeralMessage injection.
// Mutant: treat unreadable as fatal => RED.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn oracle_4_unreadable_environ_leaves_registration_to_the_hook() {
    let t = Tree::new();
    t.agy("conv-4", 4000, &t.trusted_exe);
    t.hold("conv-4", 4000);
    t.children(4000, 4000, &[4001]);
    t.process(4001, 4000, None, None, "200");
    fs::write(t.environ(4001), b"secret").unwrap();
    fs::set_permissions(t.environ(4001), fs::Permissions::from_mode(0o000)).unwrap();

    let store = new_agy_store();
    let res = scan(&t, &store, &["conv-4"]).await;
    assert_eq!(
        res,
        Ok(vec!["conv-4".to_string()]),
        "unreadable environ: no fatal error, conversation stays watched"
    );
    assert!(store.read().unwrap().is_empty(), "store must remain empty");

    let (_dir, sock) = start_server(t.config(), store.clone()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bin = env!("CARGO_BIN_EXE_xmsg");
    let (code1, out1) = run_hook(bin, &sock, "conv-4");
    assert_eq!(code1, 0);
    assert_eq!(out1, serde_json::json!({}), "turn 1: stand-down");
    let (code2, out2) = run_hook(bin, &sock, "conv-4");
    assert_eq!(code2, 0);
    assert_hook_injects(&out2, "turn 2 with environ unreadable");
    assert!(store.read().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Oracle 5: hook stand-down:
//   A watching + first unregistered turn => hook prints {}
//   still unregistered at a later turn   => hook injects ephemeralMessage
//   A not watching                       => hook injects on first turn
// Mutants: never stand down => RED; stand down forever => RED.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn oracle_5_hook_stand_down_mechanics() {
    let bin = env!("CARGO_BIN_EXE_xmsg");
    let t = Tree::new();
    t.agy("conv-watched-standdown", 5000, &t.trusted_exe);
    t.hold("conv-watched-standdown", 5000);
    t.children(5000, 5000, &[]);

    let (_dir, sock) = start_server(t.config(), new_agy_store()).await;

    let (code1, out1) = run_hook(bin, &sock, "conv-watched-standdown");
    assert_eq!(code1, 0);
    assert_eq!(
        out1,
        serde_json::json!({}),
        "turn 1 while watched must stand down and output {{}}"
    );

    let (code2, out2) = run_hook(bin, &sock, "conv-watched-standdown");
    assert_eq!(code2, 0);
    assert_hook_injects(&out2, "turn 2 still unregistered");

    // No presence lock held => A is not watching => inject on the first turn.
    let (code_unw, out_unw) = run_hook(bin, &sock, "conv-unwatched-immediate");
    assert_eq!(code_unw, 0);
    assert_hook_injects(&out_unw, "turn 1 unwatched");
}
