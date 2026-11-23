//! A stable socket directory as a deployment pin (`programs.xmsg.server.sockets.dir`): the
//! daemon's three endpoints pinned under one owner-private directory.
//!
//! - P3: an early pinned client, or the owner, may create the directory; the daemon accepts it.
//! - P4: rollback to the previous binary is a configuration change plus a runtime-dir reset
//!   (`XMSG_PREV_BIN`; the `mqsh-rollback` Nix check sets it).
//! - P6: a consumer that bind-mounts the directory reconnects across a daemon restart.
//! - P7: doctor in a shell without the pins names the recorded endpoints.
//! - P8: exported pins route an explicit-root client to the pinned daemon.

mod agy_env;
use agy_env::ScrubAgyEnv;

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use xmsg::runtime_lock::OwnerRecord;

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");
const PIN_VARS: [&str; 6] = [
    "XMSG_HTTP_SOCK",
    "XMSG_AGENT_SOCK",
    "XMSG_REGISTER_SOCK",
    "XMSG_LEAF_REGISTER_SOCK",
    "XMSG_DB_PATH",
    "XMSG_PEERS_FILE",
];

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One isolated account: HOME, XDG roots, and a runtime dir, all private.
struct Account {
    tmp: TempDir,
}

impl Account {
    fn new() -> Self {
        // Short base: socket paths stay inside the sun_path budget.
        let tmp = tempfile::Builder::new()
            .prefix("mq")
            .tempdir_in("/tmp")
            .unwrap();
        let a = Self { tmp };
        for d in [a.root(), a.xdg()] {
            fs::create_dir_all(&d).unwrap();
            fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        a
    }
    fn root(&self) -> PathBuf {
        self.tmp.path().to_path_buf()
    }
    fn xdg(&self) -> PathBuf {
        self.root().join("xdg")
    }
    fn state(&self) -> PathBuf {
        self.root().join("state")
    }
    /// A command for `bin` in this account, with no pin from the caller's environment.
    fn cmd(&self, bin: &str) -> Command {
        let mut c = Command::new(bin);
        c.scrub_agy_env()
            .env("HOME", self.root())
            .env("XDG_RUNTIME_DIR", self.xdg())
            .env("XDG_STATE_HOME", self.state())
            .env("XDG_CONFIG_HOME", self.root().join("config"))
            .env("XDG_DATA_HOME", self.root().join("data"));
        for v in PIN_VARS {
            c.env_remove(v);
        }
        c
    }
}

struct Pins {
    dir: PathBuf,
}
impl Pins {
    fn http(&self) -> PathBuf {
        self.dir.join("http.sock")
    }
    fn agent(&self) -> PathBuf {
        self.dir.join("agent.sock")
    }
    fn register(&self) -> PathBuf {
        self.dir.join("register.sock")
    }
    fn serve_args(&self) -> Vec<String> {
        [
            ("--http-sock", self.http()),
            ("--agent-sock", self.agent()),
            ("--register-sock", self.register()),
        ]
        .into_iter()
        .flat_map(|(f, p)| [f.to_string(), p.display().to_string()])
        .collect()
    }
    fn env(&self) -> [(&'static str, PathBuf); 3] {
        [
            ("XMSG_HTTP_SOCK", self.http()),
            ("XMSG_AGENT_SOCK", self.agent()),
            ("XMSG_REGISTER_SOCK", self.register()),
        ]
    }
}

fn spawn(mut c: Command) -> ChildGuard {
    ChildGuard(
        c.stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

fn stderr_of(child: &mut ChildGuard) -> String {
    let mut s = String::new();
    if let Some(mut e) = child.0.stderr.take() {
        use std::io::Read;
        let _ = e.read_to_string(&mut s);
    }
    s
}

/// Waits for `path`; a pinned daemon publishes http.sock last.
fn wait_for_socket(path: &Path, child: &mut ChildGuard) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "daemon exited early ({status}) before binding {}: {}",
                path.display(),
                stderr_of(child)
            );
        }
        if UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {}", path.display());
}

/// SIGTERM, then wait for a clean exit.
fn stop(mut child: ChildGuard) {
    unsafe {
        libc::kill(child.0.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if child.0.try_wait().unwrap().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("daemon did not stop on SIGTERM");
}

fn run(mut c: Command) -> Output {
    c.output().unwrap()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// A minimal MCP client over a child's stdio.
struct Mcp {
    _child: ChildGuard,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    id: u64,
}
impl Mcp {
    /// `c` already names `mcp` and its flags.
    fn start(mut c: Command) -> Self {
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut m = Self {
            _child: ChildGuard(child),
            stdin,
            stdout,
            id: 0,
        };
        let init = m.call(
            "initialize",
            serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
        );
        assert!(init.get("result").is_some(), "MCP initialize: {init}");
        writeln!(
            m.stdin,
            "{}",
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        .unwrap();
        m
    }
    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.id += 1;
        writeln!(
            self.stdin,
            "{}",
            serde_json::json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params})
        )
        .unwrap();
        loop {
            let mut line = String::new();
            assert!(self.stdout.read_line(&mut line).unwrap() > 0, "MCP closed");
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            if v["id"] == self.id {
                return v;
            }
        }
    }
    /// The `list` tool's answer as text.
    fn list(&mut self) -> String {
        let v = self.call(
            "tools/call",
            serde_json::json!({"name": "list", "arguments": {}}),
        );
        v.to_string()
    }
}

/// `xmsg service exec --name <name>` against `register`/`agent`; replies with `--version`.
fn service(acct: &Account, bin: &str, name: &str, register: &Path, agent: &Path) -> ChildGuard {
    let mut c = acct.cmd(bin);
    c.args(["service", "exec", "--name", name, "--register-sock"])
        .arg(register)
        .arg("--agent-sock")
        .arg(agent)
        .args(["--", bin, "--version"]);
    spawn(c)
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out: {what}");
}

/// Every file under `root` with its bytes, mode and inode (atime excluded).
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, u32, u64)> {
    fn walk(cur: &Path, out: &mut BTreeMap<PathBuf, (Vec<u8>, u32, u64)>) {
        let Ok(rd) = fs::read_dir(cur) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let m = fs::symlink_metadata(&p).unwrap();
            let bytes = if m.is_file() {
                fs::read(&p).unwrap()
            } else {
                Vec::new()
            };
            out.insert(p.clone(), (bytes, m.mode(), m.ino()));
            if m.is_dir() {
                walk(&p, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, &mut out);
    out
}

// ===========================================================================
// P3: an early pinned client creates the directory at 0700; the daemon accepts it.
// ===========================================================================
#[test]
fn p3_early_pinned_client_and_owner_created_parent_are_accepted() {
    let acct = Account::new();
    let db = acct.root().join("db").join("xmsg.db");
    let pins = Pins {
        dir: acct.xdg().join("xmsg-sockets"),
    };
    assert!(!pins.dir.exists());

    // The operator CLI only connects: it fails without a daemon and creates nothing.
    let mut send = acct.cmd(BIN);
    send.arg("send")
        .arg("--http-sock")
        .arg(pins.http())
        .args(["nobody", "hi"]);
    let early = run(send);
    assert!(!early.status.success());
    assert!(
        !pins.dir.exists(),
        "xmsg send must not create the directory"
    );

    // A pinned MCP server's registration creates the directory, owner-private.
    let mut c = acct.cmd(BIN);
    c.args(["mcp", "--agent-sock"])
        .arg(pins.agent())
        .arg("--http-sock")
        .arg(pins.http());
    let mut mcp = Mcp::start(c);
    wait_until("the MCP server creates the pinned directory", || {
        pins.dir.exists()
    });
    assert_eq!(mode(&pins.dir), 0o700);

    // The daemon starts pinned, accepts the client-created directory, and binds.
    let mut serve = acct.cmd(BIN);
    serve
        .arg("serve")
        .arg("--db-path")
        .arg(&db)
        .args(pins.serve_args());
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    fs::set_permissions(db.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut daemon = spawn(serve);
    wait_for_socket(&pins.http(), &mut daemon);

    // Both clients connect.
    let listed = mcp.list();
    assert!(
        !listed.contains("\"isError\":true") && listed.contains("\"result\""),
        "MCP list through the pins: {listed}"
    );
    let mut send = acct.cmd(BIN);
    send.arg("send")
        .arg("--http-sock")
        .arg(pins.http())
        .args(["nobody", "hi"]);
    let late = run(send);
    let err = String::from_utf8_lossy(&late.stderr);
    assert!(
        err.contains("not_found"),
        "xmsg send must reach the daemon (an answered 404), got: {err}"
    );
    stop(daemon);

    // The owner's preparation step: a directory made at 0700 before the daemon.
    let owner_made = Pins {
        dir: acct.xdg().join("prepared"),
    };
    fs::create_dir(&owner_made.dir).unwrap();
    fs::set_permissions(&owner_made.dir, fs::Permissions::from_mode(0o700)).unwrap();
    let db2 = acct.root().join("db2").join("xmsg.db");
    fs::create_dir_all(db2.parent().unwrap()).unwrap();
    fs::set_permissions(db2.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut serve = acct.cmd(BIN);
    serve
        .arg("serve")
        .arg("--db-path")
        .arg(&db2)
        .args(owner_made.serve_args());
    let mut daemon = spawn(serve);
    wait_for_socket(&owner_made.http(), &mut daemon);
    stop(daemon);

    // Controls: an existing 0755 parent is refused, unchanged; so is another UID's (S1).
    let open = Pins {
        dir: acct.xdg().join("open"),
    };
    fs::create_dir(&open.dir).unwrap();
    fs::set_permissions(&open.dir, fs::Permissions::from_mode(0o755)).unwrap();
    let db3 = acct.root().join("db3").join("xmsg.db");
    fs::create_dir_all(db3.parent().unwrap()).unwrap();
    fs::set_permissions(db3.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut serve = acct.cmd(BIN);
    serve
        .arg("serve")
        .arg("--db-path")
        .arg(&db3)
        .args(open.serve_args());
    let refused = run(serve);
    assert!(
        !refused.status.success(),
        "a 0755 pinned parent must refuse"
    );
    assert_eq!(
        mode(&open.dir),
        0o755,
        "the refusal must not repair the mode"
    );
    let uid = unsafe { libc::geteuid() };
    assert!(matches!(
        xmsg::install_paths::ensure_explicit_private_dir(&owner_made.dir, uid.wrapping_add(1)),
        Err(xmsg::install_paths::InstallError::UnsafeOwner { .. })
    ));
}

/// The daemon's endpoints for `db` as `xmsg doctor --json` resolves them, unpinned.
fn doctor_json(acct: &Account, db: &Path, env: &[(&str, PathBuf)]) -> serde_json::Value {
    let mut c = acct.cmd(BIN);
    c.args(["doctor", "--json", "--db-path"]).arg(db);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = run(c);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "doctor --json: {e}: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn private_db(acct: &Account, name: &str) -> PathBuf {
    let dir = acct.root().join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir.join("xmsg.db")
}

// ===========================================================================
// P4: rollback to the previous binary by configuration plus a runtime-dir reset.
// ===========================================================================
#[test]
fn p4_rollback_by_configuration_and_reset() {
    let Some(prev) = std::env::var_os("XMSG_PREV_BIN") else {
        eprintln!("XMSG_PREV_BIN unset; skipping P4 (the mqsh-rollback check runs it)");
        return;
    };
    let prev = prev.to_str().unwrap().to_string();
    let acct = Account::new();
    let state_root = acct.state().join("xmsg");
    let pins = Pins {
        dir: acct.xdg().join("xmsg-sockets"),
    };
    let record = || OwnerRecord::load(&state_root).unwrap().expect("owner.json");
    let uid = unsafe { libc::geteuid() };
    // The managed name is the same in both binaries (install_paths is unchanged since 912ca97a).
    let http_of = |bin: &str| {
        let mut c = acct.cmd(bin);
        c.args(["doctor", "--json"]);
        let v: serde_json::Value = serde_json::from_slice(&run(c).stdout).unwrap();
        PathBuf::from(v["http_socket"].as_str().unwrap())
    };

    // (1) The previous binary serves managed on the default root: rows and a fixture.
    let mut serve = acct.cmd(&prev);
    serve.args(["serve", "--svc-exe", &format!("alpha={prev}")]);
    let mut daemon = spawn(serve);
    // Read-only resolution needs the state root the daemon creates.
    wait_until("the previous binary creates its state root", || {
        state_root.join("owner.json").exists()
    });
    let hashed_http = http_of(BIN);
    wait_for_socket(&hashed_http, &mut daemon);
    let hashed_dir = hashed_http.parent().unwrap().to_path_buf();
    let svc = service(
        &acct,
        &prev,
        "alpha",
        &hashed_dir.join("register.sock"),
        &hashed_dir.join("agent.sock"),
    );
    let mut message_id = String::new();
    wait_until("the previous binary's service answers", || {
        let mut c = acct.cmd(&prev);
        c.args(["send", "alpha", "ping"]);
        let out = run(c);
        if !out.status.success() {
            return false;
        }
        message_id = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        true
    });
    let read_reply = |bin: &str| {
        let mut c = acct.cmd(bin);
        c.args(["replies", &message_id, "--wait", "5"]);
        String::from_utf8_lossy(&run(c).stdout).into_owned()
    };
    assert!(
        read_reply(&prev).contains("xmsg"),
        "the reply row is stored"
    );
    drop(svc);
    fs::write(state_root.join("enrollment-fixture"), b"enrolled\n").unwrap();
    stop(daemon);
    let rec = record()
        .runtime_dir
        .expect("managed start records its runtime_dir");
    assert_eq!(
        rec.path,
        fs::canonicalize(&hashed_dir).unwrap(),
        "(1) the record names the hashed directory"
    );
    assert!(hashed_dir
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with(&format!("xmsg-{uid}-")));

    // (2) The new binary serves pinned on the same root: the runtime record is cleared.
    let mut serve = acct.cmd(BIN);
    serve.arg("serve").args(pins.serve_args());
    let mut daemon = spawn(serve);
    wait_for_socket(&pins.http(), &mut daemon);
    stop(daemon);
    assert!(
        record().runtime_dir.is_none(),
        "(2) a pinned start must leave no runtime_dir record"
    );

    // (3) Control: the previous binary refuses its leftover hashed directory, changing nothing.
    let before = (snapshot(&state_root), snapshot(&acct.xdg()));
    let mut serve = acct.cmd(&prev);
    serve.arg("serve");
    let refused = run(serve);
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success(),
        "(3) the previous binary must refuse"
    );
    assert!(
        err.contains("no durable runtime_dir proof in owner.json"),
        "(3) refusal detail: {err}"
    );
    assert_eq!(
        before,
        (snapshot(&state_root), snapshot(&acct.xdg())),
        "(3) the refusal must change nothing"
    );

    // (4) Reset the runtime dir: the previous binary takes the created branch and reads the rows.
    fs::remove_dir_all(acct.xdg()).unwrap();
    fs::create_dir(acct.xdg()).unwrap();
    fs::set_permissions(acct.xdg(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut serve = acct.cmd(&prev);
    serve.arg("serve");
    let mut daemon = spawn(serve);
    wait_for_socket(&hashed_http, &mut daemon);
    assert!(
        read_reply(&prev).contains("xmsg"),
        "(4) the previous binary's client reads the stored reply"
    );
    stop(daemon);
    assert_eq!(
        fs::read(state_root.join("enrollment-fixture")).unwrap(),
        b"enrolled\n"
    );

    // (5) The new binary serves pinned again.
    let mut serve = acct.cmd(BIN);
    serve.arg("serve").args(pins.serve_args());
    let mut daemon = spawn(serve);
    wait_for_socket(&pins.http(), &mut daemon);
    stop(daemon);
    eprintln!("P4: previous binary 912ca97a ran {prev}");
}

// ===========================================================================
// P6: cold start, bind mount and restart.
// ===========================================================================

/// Runs `script` (sh, args after it) in a private mount namespace with `src` bound at `dst`,
/// as this user: arm 1 `sudo -n unshare -m` + `setpriv`, else arm 2 `bwrap`. None: neither works.
fn bound_consumer(src: &Path, dst: &Path, script: &str, args: &[&Path]) -> Option<(u8, Child)> {
    let ok = |c: &mut Command| {
        c.stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if cfg!(target_os = "linux") && ok(Command::new("sudo").args(["-n", "true"])) {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let mut c = Command::new("sudo");
        c.args(["-n", "unshare", "-m", "sh", "-c"])
            .arg(format!(
                "mount --bind \"$1\" \"$2\" && shift 2 && exec setpriv --reuid={uid} --regid={gid} --clear-groups sh -c \"$0\" sh \"$@\""
            ))
            .arg(script)
            .arg(src)
            .arg(dst)
            .args(args);
        return Some((1, c.spawn().unwrap()));
    }
    if cfg!(target_os = "linux") && ok(Command::new("bwrap").args(["--dev-bind", "/", "/", "true"]))
    {
        let mut c = Command::new("bwrap");
        c.args(["--dev-bind", "/", "/", "--bind"])
            .arg(src)
            .arg(dst)
            .args(["sh", "-c", script, "sh"])
            .args(args);
        return Some((2, c.spawn().unwrap()));
    }
    None
}

#[test]
fn p6_bind_mounted_consumer_reconnects_across_restart() {
    let acct = Account::new();
    let db = private_db(&acct, "db");
    // The preparation step, as the owner: the pinned directory in an empty runtime dir.
    let pins = Pins {
        dir: acct.xdg().join("xmsg-sockets"),
    };
    fs::create_dir(&pins.dir).unwrap();
    fs::set_permissions(&pins.dir, fs::Permissions::from_mode(0o700)).unwrap();
    let inode = fs::metadata(&pins.dir).unwrap().ino();

    // The consumer's view: the directory bind-mounted into its own mount namespace.
    let view = acct.root().join("view");
    fs::create_dir(&view).unwrap();
    let restarted = acct.root().join("restarted");
    let log = acct.root().join("consumer.log");
    let script = r#"
        bin="$1"; sock="$2/http.sock"; mark="$3"; log="$4"; export HOME="$5" XDG_RUNTIME_DIR="$5/xdg"
        attempt() { "$bin" list --http-sock "$sock" >/dev/null 2>&1; }
        i=0; until attempt; do i=$((i+1)); [ $i -gt 400 ] && exit 11; sleep 0.05; done
        echo connected >> "$log"
        i=0; until [ -e "$mark" ]; do i=$((i+1)); [ $i -gt 800 ] && exit 12; sleep 0.05; done
        i=0; until attempt; do i=$((i+1)); [ $i -gt 400 ] && exit 13; sleep 0.05; done
        echo reconnected >> "$log"
    "#;
    let consumer = bound_consumer(
        &pins.dir,
        &view,
        script,
        &[Path::new(BIN), &view, &restarted, &log, &acct.root()],
    );

    let start = || {
        let mut serve = acct.cmd(BIN);
        serve
            .arg("serve")
            .arg("--db-path")
            .arg(&db)
            .args(pins.serve_args());
        let mut d = spawn(serve);
        wait_for_socket(&pins.http(), &mut d);
        d
    };
    let daemon = start();
    if consumer.is_some() {
        wait_until("the bound consumer connects", || {
            fs::read_to_string(&log).is_ok_and(|l| l.contains("connected"))
        });
    }
    stop(daemon);
    let daemon = start();
    // The portable cell: the daemon keeps the directory across a restart.
    assert_eq!(
        fs::metadata(&pins.dir).unwrap().ino(),
        inode,
        "the pinned directory's inode must survive a daemon restart"
    );
    fs::write(&restarted, b"").unwrap();
    match consumer {
        Some((arm, mut child)) => {
            let status = child.wait().unwrap();
            assert!(
                status.success(),
                "the bound consumer must reconnect without restarting ({status})"
            );
            assert!(fs::read_to_string(&log).unwrap().contains("reconnected"));
            eprintln!("P6: runner arm {arm} ran the bind-mount cell");
        }
        None => eprintln!("P6: no runner arm (sudo -n, bwrap) available; the inode cell ran alone"),
    }
    stop(daemon);
}

// ===========================================================================
// P7: doctor in a shell without the pins.
// ===========================================================================
#[test]
fn p7_doctor_names_recorded_endpoints_in_an_unpinned_shell() {
    let acct = Account::new();
    let db = private_db(&acct, "db");
    let pins = Pins {
        dir: acct.xdg().join("xmsg-sockets"),
    };
    let mut serve = acct.cmd(BIN);
    serve
        .arg("serve")
        .arg("--db-path")
        .arg(&db)
        .args(pins.serve_args());
    let mut daemon = spawn(serve);
    wait_for_socket(&pins.http(), &mut daemon);

    let check = |v: &serde_json::Value| {
        v["install"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "install.endpoint_pins")
            .cloned()
            .unwrap_or_else(|| panic!("no install.endpoint_pins check: {v}"))
    };
    let old_shell = doctor_json(&acct, &db, &[]);
    let c = check(&old_shell);
    assert_eq!(c["status"], "fail", "{c}");
    let msg = c["message"].as_str().unwrap();
    for (var, p) in pins.env() {
        let p = fs::canonicalize(&p).unwrap();
        assert!(
            msg.contains(&format!("{var}={}", p.display())),
            "the message names {var}: {msg}"
        );
    }
    assert_eq!(old_shell["endpoints_usable"], false);

    let pinned_shell = doctor_json(&acct, &db, &pins.env());
    assert_eq!(check(&pinned_shell)["status"], "pass", "{pinned_shell}");
    stop(daemon);
}

// ===========================================================================
// P8: exported pins route an explicit-root client to the pinned daemon.
// ===========================================================================
#[test]
fn p8_shell_pins_route_explicit_root_clients() {
    let acct = Account::new();
    // A: pinned. B: its own root, unpinned, at that root's hashed managed name.
    let db_a = private_db(&acct, "a");
    let db_b = private_db(&acct, "b");
    let a = Pins {
        dir: acct.xdg().join("xmsg-sockets"),
    };
    let mut serve = acct.cmd(BIN);
    serve
        .arg("serve")
        .arg("--db-path")
        .arg(&db_a)
        .args(a.serve_args())
        .args(["--svc-exe", &format!("alpha={BIN}")]);
    let mut daemon_a = spawn(serve);
    wait_for_socket(&a.http(), &mut daemon_a);

    let b_report = doctor_json(&acct, &db_b, &[]);
    let b = |k: &str| PathBuf::from(b_report[k].as_str().unwrap());
    let (b_http, b_agent, b_register) = (b("http_socket"), b("agent_socket"), b("register_socket"));
    assert_ne!(b_http.parent(), Some(a.dir.as_path()));
    let mut serve = acct.cmd(BIN);
    serve
        .arg("serve")
        .arg("--db-path")
        .arg(&db_b)
        .args(["--svc-exe", &format!("beta={BIN}")]);
    let mut daemon_b = spawn(serve);
    wait_for_socket(&b_http, &mut daemon_b);

    let _alpha = service(&acct, BIN, "alpha", &a.register(), &a.agent());
    let _beta = service(&acct, BIN, "beta", &b_register, &b_agent);

    // The pinned shell: A's three pins exported, and XMSG_DB_PATH naming B's database.
    let mcp = |extra: &[&Path]| {
        let mut c = acct.cmd(BIN);
        for (k, v) in a.env() {
            c.env(k, v);
        }
        c.env("XMSG_DB_PATH", &db_b).arg("mcp");
        if let [agent, http] = extra {
            c.arg("--agent-sock")
                .arg(agent)
                .arg("--http-sock")
                .arg(http);
        }
        Mcp::start(c)
    };
    let mut listed = String::new();
    wait_until("A answers with its service", || {
        listed = mcp(&[]).list();
        listed.contains("alpha")
    });
    assert!(
        !listed.contains("beta"),
        "the pinned shell's explicit-root client must reach A, not B: {listed}"
    );
    wait_until("B answers with its own socket flags", || {
        listed = mcp(&[&b_agent, &b_http]).list();
        listed.contains("beta")
    });
    assert!(!listed.contains("alpha"), "{listed}");
    stop(daemon_b);
    stop(daemon_a);
}
