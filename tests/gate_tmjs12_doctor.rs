//! Gate tests for strictly read-only `xmsg doctor` installation checks (S7),
//! competing dual-manager detection (M-S7), and zero-lock-attempt verification
//! under a continuously held `serve.lock` (M-S7b).

mod agy_env;
#[path = "support/spawn.rs"]
mod spawn;
use agy_env::ScrubAgyEnv;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use xmsg::doctor_install::{inspect_install, ManagerScanRoots, ServiceOwner};
use xmsg::install_paths::{FixtureHomeLookup, Platform, ResolveEnv, ResolveRequest};
use xmsg::runtime_lock::{state_lock_attempts, StateLock};

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnap {
    is_dir: bool,
    is_symlink: bool,
    mode: u32,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
    birthtime_ns: Option<i128>,
    content: Option<Vec<u8>>,
}

/// Captures content, modes, inventory, mtime, ctime and birth time (excluding atime).
fn snapshot_excluding_atime(root: &Path) -> BTreeMap<PathBuf, FileSnap> {
    let mut out = BTreeMap::new();
    fn walk(base: &Path, cur: &Path, out: &mut BTreeMap<PathBuf, FileSnap>) {
        let Ok(meta) = fs::symlink_metadata(cur) else {
            return;
        };
        let rel = cur.strip_prefix(base).unwrap_or(cur).to_path_buf();
        let birthtime_ns = meta.created().ok().and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_nanos() as i128)
        });
        let content = if meta.is_file() {
            fs::read(cur).ok()
        } else {
            None
        };
        out.insert(
            rel,
            FileSnap {
                is_dir: meta.is_dir(),
                is_symlink: meta.file_type().is_symlink(),
                mode: meta.mode(),
                size: meta.len(),
                mtime_sec: meta.mtime(),
                mtime_nsec: meta.mtime_nsec(),
                ctime_sec: meta.ctime(),
                ctime_nsec: meta.ctime_nsec(),
                birthtime_ns,
                content,
            },
        );
        if meta.is_dir() && !meta.file_type().is_symlink() {
            if let Ok(rd) = fs::read_dir(cur) {
                let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                entries.sort();
                for entry in entries {
                    walk(base, &entry, out);
                }
            }
        }
    }
    walk(root, root, &mut out);
    out
}

fn make_private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn wait_for_socket(path: &Path, child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("daemon exited early ({status})");
        }
        if UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {}", path.display());
}

// ===========================================================================
// S7 / M-S7: Competing dual-manager conflict detection (even when one is
//            stopped with KeepAlive/Restart=always) sets service_owner =
//            "ambiguous" and endpoints_usable = false, with unchanged tree.
// ===========================================================================
#[test]
fn s7_competing_dual_manager_conflict_detected() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let home = tmp.path().join("home");
    let state = tmp.path().join("state");
    let run = tmp.path().join("run");
    let launch_agents = home.join("Library/LaunchAgents");
    let systemd_user = home.join(".config/systemd/user");
    for d in [&home, &state, &run, &launch_agents, &systemd_user] {
        make_private_dir(d);
    }

    let db_path = state.join("xmsg.db");
    let http_sock = run.join("http.sock");
    let agent_sock = run.join("agent.sock");
    let reg_sock = run.join("register.sock");

    // Plant two competing service manager definitions targeting the exact same installation:
    // 1. Homebrew LaunchAgent plist with KeepAlive=true
    fs::write(
        launch_agents.join("homebrew.mxcl.xmsg.plist"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>homebrew.mxcl.xmsg</string>
  <key>KeepAlive</key><true/>
  <key>ProgramArguments</key><array>
    <string>/opt/homebrew/bin/xmsg</string>
    <string>serve</string>
    <string>--db-path</string><string>{}</string>
    <string>--http-sock</string><string>{}</string>
  </array>
</dict></plist>"#,
            db_path.display(),
            http_sock.display()
        ),
    )
    .unwrap();

    // 2. Second manager (another LaunchAgent plist or systemd unit with Restart=always)
    //    targeting the same state/endpoints even while stopped.
    fs::write(
        launch_agents.join("com.user.xmsg-custom.plist"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.user.xmsg-custom</string>
  <key>KeepAlive</key><true/>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/xmsg</string>
    <string>serve</string>
    <string>--db-path</string><string>{}</string>
  </array>
</dict></plist>"#,
            db_path.display()
        ),
    )
    .unwrap();

    fs::write(
        systemd_user.join("xmsg.service"),
        format!(
            "[Unit]\nDescription=xmsg\n[Service]\nExecStart=/usr/bin/xmsg serve --db-path {}\nRestart=always\n",
            db_path.display()
        ),
    )
    .unwrap();

    let lookup = FixtureHomeLookup(Some(home.clone()));
    let env = ResolveEnv {
        home: None,
        xdg_config_home: None,
        xdg_state_home: None,
        xdg_runtime_dir: None,
        darwin_user_temp_dir: None,
        system_tmp: PathBuf::from("/tmp"),
        platform: Platform::MacOs,
        euid: uid,
        home_lookup: &lookup,
    };
    let req = ResolveRequest {
        db_path: Some(db_path.clone()),
        http_sock: Some(http_sock.clone()),
        agent_sock: Some(agent_sock.clone()),
        register_sock: Some(reg_sock.clone()),
        writable: false,
        enforce_legacy_guard: false,
        ..Default::default()
    };
    let roots = ManagerScanRoots {
        launch_agents_dir: Some(launch_agents),
        systemd_user_dir: Some(systemd_user),
    };

    let before = snapshot_excluding_atime(tmp.path());
    let report = inspect_install(&req, &env, &roots);
    let after = snapshot_excluding_atime(tmp.path());
    assert_eq!(
        before, after,
        "S7: conflicting-case doctor scan mutated filesystem"
    );

    assert_eq!(
        report.service_owner,
        ServiceOwner::Ambiguous,
        "M-S7: dual competing managers targeting same install must be classified as Ambiguous"
    );
    assert!(
        !report.endpoints_usable,
        "M-S7: endpoints_usable must be false under competing-manager conflict"
    );
    assert!(
        report.competing_managers.len() >= 2,
        "M-S7: expected >= 2 competing managers, got: {:?}",
        report.competing_managers
    );
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.id == "install.service_owner" && c.status == "fail"),
        "M-S7: install.service_owner check must fail on competing managers: {:?}",
        report.checks
    );
}

// ===========================================================================
// S7 / M-S7b: Continuously held `serve.lock` + zero-attempt assertion at the
//             shared lock primitive + bounded completion in text & JSON +
//             snapshots (healthy, stopped, unsafe) + zero secret canaries
// ===========================================================================
#[test]
fn s7_doctor_never_touches_held_serve_lock_and_emits_unredacted_endpoints_without_secrets() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let state = tmp.path().join("state");
    let run = tmp.path().join("run");
    let clean_xdg = tmp.path().join("clean-xdg");
    for d in [&state, &run, &clean_xdg] {
        make_private_dir(d);
    }

    // Plant a synthetic secret canary in an enrollment key file inside the state dir:
    // doctor must inspect metadata only and NEVER read or print secret contents!
    let secret_canary = "CANARY_SECRET_TOKEN_9f3c7e2a1b8d4c6f";
    let enroll_dir = state.join("enroll");
    make_private_dir(&enroll_dir);
    let fed_key = enroll_dir.join("fed.key");
    fs::write(
        &fed_key,
        format!("-----BEGIN PRIVATE KEY-----\n{secret_canary}\n-----END PRIVATE KEY-----\n"),
    )
    .unwrap();
    fs::set_permissions(&fed_key, fs::Permissions::from_mode(0o600)).unwrap();

    let db_path = state.join("xmsg.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        xmsg::storage::init_db(&conn).unwrap();
    }
    let http_sock = run.join("http.sock");
    let agent_sock = run.join("agent.sock");
    let reg_sock = run.join("register.sock");

    // 1. Stopped case + continuously held `serve.lock` in-process:
    //    Assert `runtime_lock::state_lock_attempts()` delta is STRICTLY ZERO (`M-S7b`),
    //    and snapshot (excluding atime) is unchanged!
    let _held_lock = StateLock::try_acquire(&state).expect("fixture owner acquires serve.lock");
    let lookup = FixtureHomeLookup(None);
    let env = ResolveEnv {
        home: None,
        xdg_config_home: None,
        xdg_state_home: None,
        xdg_runtime_dir: Some(clean_xdg.as_os_str().to_os_string()),
        darwin_user_temp_dir: None,
        system_tmp: PathBuf::from("/tmp"),
        platform: Platform::current(),
        euid: uid,
        home_lookup: &lookup,
    };
    let req = ResolveRequest {
        db_path: Some(db_path.clone()),
        http_sock: Some(http_sock.clone()),
        agent_sock: Some(agent_sock.clone()),
        register_sock: Some(reg_sock.clone()),
        writable: false,
        enforce_legacy_guard: false,
        ..Default::default()
    };

    let before_stopped = snapshot_excluding_atime(tmp.path());
    let attempts_before = state_lock_attempts();
    let report = inspect_install(&req, &env, &ManagerScanRoots::default());
    let attempts_after = state_lock_attempts();
    let after_stopped = snapshot_excluding_atime(tmp.path());

    assert_eq!(
        attempts_after - attempts_before,
        0,
        "M-S7b: doctor attempted serve.lock acquisition ({} -> {})",
        attempts_before,
        attempts_after
    );
    assert_eq!(
        before_stopped, after_stopped,
        "S7: stopped-case doctor mutated filesystem"
    );
    assert_eq!(
        report.http_socket.as_deref(),
        Some(http_sock.to_string_lossy().as_ref())
    );
    assert_eq!(
        report.agent_socket.as_deref(),
        Some(agent_sock.to_string_lossy().as_ref())
    );
    assert_eq!(
        report.register_socket.as_deref(),
        Some(reg_sock.to_string_lossy().as_ref())
    );

    // 2. CLI doctor (both text and JSON) while `_held_lock` is STILL held continuously:
    //    must complete bounded (well under 5s), preserve snapshot, expose unredacted endpoints,
    //    and leak ZERO secret canaries!
    for (label, extra_args) in [("json", vec!["--json"]), ("text", vec![])] {
        let before = snapshot_excluding_atime(tmp.path());
        let start = Instant::now();
        let mut args = vec![
            "doctor",
            "--db-path",
            db_path.to_str().unwrap(),
            "--http-sock",
            http_sock.to_str().unwrap(),
            "--agent-sock",
            agent_sock.to_str().unwrap(),
            "--register-sock",
            reg_sock.to_str().unwrap(),
        ];
        args.extend(extra_args);
        let out = spawn::command(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_xdg)
            .args(&args)
            .output()
            .unwrap();
        let elapsed = start.elapsed();
        let after = snapshot_excluding_atime(tmp.path());
        assert!(
            elapsed < Duration::from_secs(5),
            "S7: doctor ({label}) took too long under held serve.lock: {elapsed:?}"
        );
        assert_eq!(
            before, after,
            "S7: doctor ({label}) under held serve.lock mutated filesystem"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(secret_canary) && !stderr.contains(secret_canary),
            "S7: doctor ({label}) leaked synthetic secret canary!"
        );
        if label == "json" {
            let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(v["http_socket"], http_sock.to_string_lossy().as_ref());
            assert_eq!(v["agent_socket"], agent_sock.to_string_lossy().as_ref());
            assert_eq!(v["register_socket"], reg_sock.to_string_lossy().as_ref());
        }
    }
    drop(_held_lock);

    // 3. Healthy live daemon case (daemon itself holds serve.lock continuously):
    let mut serve = ChildGuard(
        spawn::command(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_xdg)
            .args([
                "serve",
                "--db-path",
                db_path.to_str().unwrap(),
                "--http-sock",
                http_sock.to_str().unwrap(),
                "--agent-sock",
                agent_sock.to_str().unwrap(),
                "--register-sock",
                reg_sock.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn live daemon for healthy doctor check"),
    );
    wait_for_socket(&http_sock, &mut serve.0, Duration::from_secs(10));

    let doc_live = spawn::command(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &clean_xdg)
        .args([
            "doctor",
            "--json",
            "--db-path",
            db_path.to_str().unwrap(),
            "--http-sock",
            http_sock.to_str().unwrap(),
            "--agent-sock",
            agent_sock.to_str().unwrap(),
            "--register-sock",
            reg_sock.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let live_stdout = String::from_utf8_lossy(&doc_live.stdout);
    assert!(
        !live_stdout.contains(secret_canary),
        "S7: live doctor leaked synthetic secret canary"
    );
    let live_json: serde_json::Value = serde_json::from_str(&live_stdout).unwrap();
    assert_eq!(live_json["endpoints_usable"], true, "{live_json}");
    assert_eq!(
        live_json["http_socket"],
        http_sock.to_string_lossy().as_ref()
    );
    drop(serve);

    // 4. Unsafe mode case (0755 state root): snapshot unchanged, endpoints_usable = false, install.state_root fails.
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
    let before_unsafe = snapshot_excluding_atime(tmp.path());
    let doc_unsafe = spawn::command(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &clean_xdg)
        .args([
            "doctor",
            "--json",
            "--db-path",
            db_path.to_str().unwrap(),
            "--http-sock",
            http_sock.to_str().unwrap(),
            "--agent-sock",
            agent_sock.to_str().unwrap(),
            "--register-sock",
            reg_sock.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let after_unsafe = snapshot_excluding_atime(tmp.path());
    assert_eq!(
        before_unsafe, after_unsafe,
        "S7: unsafe-case doctor mutated or repaired filesystem"
    );
    let unsafe_json: serde_json::Value = serde_json::from_slice(&doc_unsafe.stdout).unwrap();
    assert_eq!(unsafe_json["endpoints_usable"], false, "{unsafe_json}");
    assert!(
        unsafe_json["install"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "install.state_root" && c["status"] == "fail"),
        "S7: unsafe 0755 state root must fail install.state_root: {unsafe_json}"
    );
}

fn inspect_manager_fixture(
    systemd: &[&str],
    plists: &[&str],
) -> xmsg::doctor_install::InstallDoctorReport {
    use std::os::unix::net::UnixListener;
    use xmsg::install_paths::BindingKind;
    use xmsg::runtime_lock::{BoundEndpointRecord, OwnerRecord};
    let tmp = TempDir::new_in("/tmp").unwrap();
    let home = tmp.path().join("home");
    let state = tmp.path().join("state");
    let run = tmp.path().join("run");
    let units = tmp.path().join("units");
    let agents = tmp.path().join("agents");
    for dir in [&home, &state, &run, &units, &agents] {
        make_private_dir(dir);
    }
    let db = state.join("xmsg.db");
    let http = run.join("http.sock");
    let replace = |s: &str| {
        s.replace("@DB@", &db.to_string_lossy())
            .replace("@STATE@", &state.to_string_lossy())
            .replace("@HTTP@", &http.to_string_lossy())
    };
    for (i, text) in systemd.iter().enumerate() {
        fs::write(units.join(format!("{i}.service")), replace(text)).unwrap();
    }
    for (i, text) in plists.iter().enumerate() {
        fs::write(agents.join(format!("{i}.plist")), replace(text)).unwrap();
    }
    let _listener = UnixListener::bind(&http).unwrap();
    let meta = fs::symlink_metadata(&http).unwrap();
    let uid = unsafe { libc::geteuid() };
    let mut owner = OwnerRecord::new(uid, Some("systemd_user".into()));
    owner.endpoints.insert(
        "http".into(),
        BoundEndpointRecord {
            path: http.clone(),
            dev: meta.dev(),
            ino: meta.ino(),
            uid,
            kind: BindingKind::Manual,
        },
    );
    owner.save(&state).unwrap();
    let lookup = FixtureHomeLookup(Some(home));
    let env = ResolveEnv {
        home: None,
        xdg_config_home: None,
        xdg_state_home: None,
        xdg_runtime_dir: None,
        darwin_user_temp_dir: None,
        system_tmp: PathBuf::from("/tmp"),
        platform: Platform::Linux,
        euid: uid,
        home_lookup: &lookup,
    };
    let req = ResolveRequest {
        db_path: Some(db),
        http_sock: Some(http),
        agent_sock: Some(run.join("agent.sock")),
        register_sock: Some(run.join("register.sock")),
        ..ResolveRequest::default()
    };
    let before = snapshot_excluding_atime(tmp.path());
    let report = inspect_install(
        &req,
        &env,
        &ManagerScanRoots {
            launch_agents_dir: Some(agents),
            systemd_user_dir: Some(units),
        },
    );
    assert_eq!(
        before,
        snapshot_excluding_atime(tmp.path()),
        "manager discovery must stay read-only"
    );
    report
}

#[test]
fn mnau_collector_nested_in_daemon_state_is_not_a_competing_owner() {
    let report = inspect_manager_fixture(&[
        "[Service]\nExecStart=/usr/bin/xmsg serve --db-path @DB@\n",
        "[Service]\nExecStart=/usr/bin/xmsg observe-collector --state-dir @STATE@/observe-collector\n",
    ], &[]);
    assert_eq!(report.competing_managers.len(), 1);
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "install.service_owner" && c.status == "pass"));
}

#[test]
fn mnau_two_real_serve_commands_are_ambiguous() {
    let report = inspect_manager_fixture(
        &[
            "[Service]\nExecStart=\"/usr/bin/xmsg\" serve \\\n --db-path=\"@DB@\"\n",
            "[Service]\nEnvironment=\"XMSG_DB_PATH=@DB@\"\nExecStart=/usr/bin/xmsg serve\n",
        ],
        &[],
    );
    assert_eq!(report.competing_managers.len(), 2);
    assert_eq!(report.service_owner, ServiceOwner::Ambiguous);
}

#[test]
fn mnau_explicit_different_db_and_prefix_paths_are_excluded() {
    let report = inspect_manager_fixture(&[
        "[Service]\nExecStart=/usr/bin/xmsg serve --db-path @DB@\n",
        "[Service]\nExecStart=/usr/bin/xmsg serve --db-path @STATE@/nested/xmsg.db --http-sock @HTTP@\n",
        "[Service]\nEnvironment=XMSG_DB_PATH=@DB@\nExecStart=/usr/bin/xmsg serve --db-path=@DB@.other\n",
        "[Service]\nExecStart=/usr/bin/not-xmsg serve --db-path @DB@\n",
        "[Service]\nExecStart=/usr/bin/xmsg --label serve\n",
        "[Service]\nExecStart=/usr/bin/xmsg serve --db-path @DB@\nExecStart=\nExecStart=/usr/bin/xmsg observe-collector\n",
    ], &[]);
    assert_eq!(report.competing_managers.len(), 1);
    assert_eq!(report.service_owner, ServiceOwner::SystemdUser);
}

#[test]
fn mnau_launchd_argv_distinguishes_collector_and_decodes_paths() {
    let report = inspect_manager_fixture(&[], &[
        "<plist><dict><key>ProgramArguments</key><array><string>/usr/bin/xmsg</string><string>ser&#118;e</string><string>--db-path</string><string>@DB@</string></array></dict></plist>",
        "<plist><dict><key>ProgramArguments</key><array><string>/usr/bin/xmsg</string><string>observe-collector</string><string>--state-dir</string><string>@STATE@/observe-collector</string></array></dict></plist>",
        "<plist><dict><key>ProgramArguments</key><array><string>/usr/bin/xmsg</string><string>serve</string><string>--db-path=@DB@.other</string></array></dict></plist>",
    ]);
    assert_eq!(report.competing_managers.len(), 1);
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "install.service_owner" && c.status == "pass"));
}

#[test]
fn mnau_default_db_serve_counts_despite_different_socket_pins() {
    let collector = "[Service]\nExecStart=/usr/bin/xmsg observe-collector --state-dir @STATE@/observe-collector\n";
    let serve = "[Service]\nExecStart=/usr/bin/xmsg serve --http-sock /other/http.sock\n";
    let report = inspect_manager_fixture(&[serve, collector], &[]);
    assert_eq!(report.competing_managers.len(), 1);
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "install.service_owner" && c.status == "pass"));
    let report = inspect_manager_fixture(
        &[
            serve,
            "[Service]\nExecStart=/usr/bin/xmsg serve --agent-sock /other/agent.sock\n",
            collector,
        ],
        &[],
    );
    assert_eq!(report.competing_managers.len(), 2);
    assert_eq!(report.service_owner, ServiceOwner::Ambiguous);
}

#[test]
fn mnau_missing_or_empty_db_option_never_falls_back_to_default() {
    let report = inspect_manager_fixture(
        &[
            "[Service]\nExecStart=/usr/bin/xmsg serve --db-path @DB@\n",
            "[Service]\nExecStart=/usr/bin/xmsg serve --db-path\n",
            "[Service]\nExecStart=/usr/bin/xmsg serve --db-path=\n",
            "[Service]\nExecStart=/usr/bin/xmsg serve --db-path --http-sock @HTTP@\n",
        ],
        &[],
    );
    assert_eq!(report.competing_managers.len(), 1);
    assert_eq!(report.service_owner, ServiceOwner::SystemdUser);
}
