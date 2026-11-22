//! Gate tests for the installation contract (S1), read-only discovery/doctor (S2),
//! schema preservation fence across `serve` and `enroll-ca` (S5), and process umask
//! enforcement + sampled startup log (S9d).

mod agy_env;
use agy_env::ScrubAgyEnv;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use xmsg::install_paths::{
    canonicalize_best_effort, check_legacy_components, compute_namespace_identity,
    ensure_explicit_private_dir, probe_legacy_listeners, resolve_install, validate_private_dir,
    validate_private_mode_bits, BindingKind, FixtureHomeLookup, InstallError, Platform, ResolveEnv,
    ResolveRequest,
};

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");
const EE1B6CA_DB: &str = include_str!("fixtures/ee1b6ca-db.sql");

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct DirCleanup(Option<PathBuf>);
impl Drop for DirCleanup {
    fn drop(&mut self) {
        if let Some(ref p) = self.0 {
            let _ = fs::remove_dir_all(p);
        }
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

fn fixture_env<'a>(platform: Platform, lookup: &'a FixtureHomeLookup, euid: u32) -> ResolveEnv<'a> {
    ResolveEnv {
        home: None,
        xdg_config_home: None,
        xdg_state_home: None,
        xdg_runtime_dir: None,
        darwin_user_temp_dir: None,
        system_tmp: PathBuf::from("/tmp"),
        platform,
        euid,
        home_lookup: lookup,
    }
}

fn wait_for_socket(path: &Path, child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_string(&mut stderr);
            }
            panic!(
                "xmsg serve exited early ({status}) before binding {}: {stderr}",
                path.display()
            );
        }
        if UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for socket {}", path.display());
}

/// Runs a command expected to fail/refuse quickly; kills it and returns `(false, ...)` if it
/// stays alive past `timeout` (e.g. when a mutant bypasses a startup refusal and starts serving).
fn run_expect_refusal_bounded(cmd: &mut Command, timeout: Duration) -> (bool, String) {
    let mut child = ChildGuard(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn command expected to refuse"),
    );
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut stderr = String::new();
            if let Some(mut s) = child.0.stderr.take() {
                let _ = s.read_to_string(&mut stderr);
            }
            return (!status.success(), stderr);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.0.kill();
    let _ = child.0.wait();
    (
        false,
        format!("timed out after {timeout:?}: daemon stayed alive instead of refusing"),
    )
}

// ===========================================================================
// S1: Entry-point agreement, CLI/env/XDG precedence, HOME mismatch,
//     macOS shell XDG absent from LaunchAgent service environment (M-S1b)
// ===========================================================================
#[test]
fn s1_all_entry_points_agree_on_resolved_defaults_and_precedence() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("acct");
    make_private_dir(&home);
    let uid = unsafe { libc::geteuid() };

    for platform in [Platform::MacOs, Platform::Linux] {
        let lookup = FixtureHomeLookup(Some(home.clone()));
        let mut env = fixture_env(platform, &lookup, uid);
        let xdg_rt = tmp.path().join(format!("rt-{platform:?}"));
        make_private_dir(&xdg_rt);
        env.xdg_runtime_dir = Some(xdg_rt.as_os_str().to_os_string());

        let req = ResolveRequest {
            writable: true,
            enforce_legacy_guard: true,
            ..Default::default()
        };
        let resolved = resolve_install(&req, &env).expect("default install resolution");
        let expected_state = match platform {
            Platform::MacOs => home.join("Library/Application Support/xmsg/state"),
            Platform::Linux => home.join(".local/state/xmsg"),
        };
        let expected_state_canon = canonicalize_best_effort(&expected_state).unwrap();
        assert_eq!(
            canonicalize_best_effort(&resolved.state_root).unwrap(),
            expected_state_canon
        );
        assert_eq!(
            canonicalize_best_effort(&resolved.db_path).unwrap(),
            expected_state_canon.join("xmsg.db")
        );

        // Make state root exist so daemon (writable) and read-only entry points (CLI / hook /
        // MCP / doctor) derive the exact same namespace identity and socket paths.
        make_private_dir(&resolved.state_root);
        let resolved_daemon = resolve_install(&req, &env).expect("live default resolution");
        let resolved_readonly = resolve_install(
            &ResolveRequest {
                writable: false,
                enforce_legacy_guard: false,
                ..Default::default()
            },
            &env,
        )
        .expect("readonly default resolution");
        assert_eq!(
            resolved_readonly.http_sock.as_ref().unwrap().path,
            resolved_daemon.http_sock.as_ref().unwrap().path,
            "M-S1b: HTTP endpoint diverged on {platform:?}"
        );
        assert_eq!(
            resolved_readonly.agent_sock.as_ref().unwrap().path,
            resolved_daemon.agent_sock.as_ref().unwrap().path,
            "M-S1b: agent endpoint diverged on {platform:?}"
        );
        assert_eq!(
            resolved_readonly.register_sock.as_ref().unwrap().path,
            resolved_daemon.register_sock.as_ref().unwrap().path,
            "M-S1b: register endpoint diverged on {platform:?}"
        );

        // Precedence: CLI > XMSG_* > XDG_* > platform default.
        let xdg_state = tmp.path().join(format!("xdg-state-{platform:?}"));
        make_private_dir(&xdg_state);
        let mut prec_env = fixture_env(platform, &lookup, uid);
        prec_env.xdg_state_home = Some(xdg_state.as_os_str().to_os_string());
        let r_xdg = resolve_install(
            &ResolveRequest {
                writable: true,
                enforce_legacy_guard: false,
                ..Default::default()
            },
            &prec_env,
        )
        .unwrap();
        assert_eq!(
            r_xdg.db_path,
            xdg_state.join("xmsg/xmsg.db"),
            "XDG_STATE_HOME must apply on {platform:?}"
        );

        // Relative XDG root is refused with no fallback.
        let mut bad_xdg = fixture_env(platform, &lookup, uid);
        bad_xdg.xdg_state_home = Some(OsString::from("relative/state"));
        assert!(matches!(
            resolve_install(&ResolveRequest::default(), &bad_xdg),
            Err(InstallError::RelativeXdgRoot {
                var: "XDG_STATE_HOME",
                ..
            })
        ));

        // Explicit --db-path beats XDG_STATE_HOME.
        let cli_db = tmp.path().join("cli-db/xmsg.db");
        let r_cli = resolve_install(
            &ResolveRequest {
                db_path: Some(cli_db.clone()),
                writable: true,
                enforce_legacy_guard: false,
                ..Default::default()
            },
            &prec_env,
        )
        .unwrap();
        assert_eq!(r_cli.db_path, cli_db);

        // HOME mismatch against getpwuid(geteuid()) is refused when a home default is required.
        let wrong_home = tmp.path().join(format!("wrong-home-{platform:?}"));
        make_private_dir(&wrong_home);
        let mut mismatch_env = fixture_env(platform, &lookup, uid);
        mismatch_env.home = Some(wrong_home.as_os_str().to_os_string());
        assert!(matches!(
            resolve_install(&ResolveRequest::default(), &mismatch_env),
            Err(InstallError::HomeMismatch { .. })
        ));
    }

    // Live binary check for CLI > XMSG_HTTP_SOCK > managed default and doctor/client agreement (M-S1b):
    let live_state = tmp.path().join("live-agree-state");
    make_private_dir(&live_state);
    let live_db = live_state.join("xmsg.db");
    let clean_rt = tmp.path().join("live-agree-rt");
    make_private_dir(&clean_rt);
    let live_env_ro = ResolveEnv {
        home: None,
        xdg_config_home: None,
        xdg_state_home: None,
        xdg_runtime_dir: Some(clean_rt.as_os_str().to_os_string()),
        darwin_user_temp_dir: None,
        system_tmp: PathBuf::from("/tmp"),
        platform: Platform::current(),
        euid: uid,
        home_lookup: &FixtureHomeLookup(None),
    };
    let expected_live = resolve_install(
        &ResolveRequest {
            db_path: Some(live_db.clone()),
            writable: true,
            enforce_legacy_guard: false,
            ..Default::default()
        },
        &live_env_ro,
    )
    .unwrap();
    let expected_http = expected_live.http_sock.as_ref().unwrap().path.clone();
    let expected_agent = expected_live.agent_sock.as_ref().unwrap().path.clone();
    let expected_reg = expected_live.register_sock.as_ref().unwrap().path.clone();
    let _ns_cleanup = DirCleanup(expected_live.runtime_namespace.clone());

    let mut live_daemon = ChildGuard(
        Command::new(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_rt)
            .args(["serve", "--db-path", live_db.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn daemon on default managed runtime dir"),
    );
    wait_for_socket(&expected_http, &mut live_daemon.0, Duration::from_secs(10));

    // `xmsg doctor --json` resolves the exact same managed endpoints as the daemon!
    let doc = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &clean_rt)
        .args(["doctor", "--json", "--db-path", live_db.to_str().unwrap()])
        .output()
        .unwrap();
    let doc_v: serde_json::Value = serde_json::from_slice(&doc.stdout).unwrap();
    assert_eq!(
        doc_v["http_socket"],
        expected_http.to_string_lossy().as_ref()
    );
    assert_eq!(
        doc_v["agent_socket"],
        expected_agent.to_string_lossy().as_ref()
    );
    assert_eq!(
        doc_v["register_socket"],
        expected_reg.to_string_lossy().as_ref()
    );

    // CLI `--http-sock` beats `XMSG_HTTP_SOCK` (precedence check through real CLI binary).
    let list_cli_wins = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &clean_rt)
        .env("XMSG_HTTP_SOCK", tmp.path().join("nonexistent-env.sock"))
        .args([
            "list",
            "--json",
            "--http-sock",
            expected_http.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        list_cli_wins.status.success(),
        "CLI --http-sock must beat XMSG_HTTP_SOCK: {}",
        String::from_utf8_lossy(&list_cli_wins.stderr)
    );
    drop(live_daemon);

    // macOS shell XDG absent from LaunchAgent service environment with explicit roots:
    // explicit LaunchAgent args resolve identically with or without XDG_STATE_HOME in env.
    let lookup = FixtureHomeLookup(Some(home.clone()));
    let la_state = tmp.path().join("launchagent-state");
    make_private_dir(&la_state);
    let la_run = tmp.path().join("launchagent-run");
    make_private_dir(&la_run);
    let la_req = ResolveRequest {
        db_path: Some(la_state.join("xmsg.db")),
        http_sock: Some(la_run.join("http.sock")),
        agent_sock: Some(la_run.join("agent.sock")),
        register_sock: Some(la_run.join("register.sock")),
        enforce_legacy_guard: true,
        ..Default::default()
    };
    let mut shell_env = fixture_env(Platform::MacOs, &lookup, uid);
    shell_env.xdg_state_home = Some(tmp.path().join("shell-xdg").into_os_string());
    let service_env = fixture_env(Platform::MacOs, &lookup, uid);
    let r_shell = resolve_install(&la_req, &shell_env).unwrap();
    let r_service = resolve_install(&la_req, &service_env).unwrap();
    assert_eq!(r_shell.db_path, r_service.db_path);
    assert_eq!(
        r_shell.http_sock.as_ref().unwrap().path,
        r_service.http_sock.as_ref().unwrap().path
    );
    assert_eq!(
        r_shell.agent_sock.as_ref().unwrap().path,
        r_service.agent_sock.as_ref().unwrap().path
    );
    assert_eq!(
        r_shell.register_sock.as_ref().unwrap().path,
        r_service.register_sock.as_ref().unwrap().path
    );
}

// ===========================================================================
// S1: Legacy component guard — DB refusal on serve & enroll-ca before
//     creating state, even when new DB already exists (M-S1c), peers-only &
//     enrollment-only without DB (M-S1d), home-derived checked when XDG set
//     elsewhere (M-S1e), Linux same-path & macOS coordinator-only controls
// ===========================================================================
#[test]
fn s1_legacy_db_guard_refuses_serve_and_enroll_ca_before_creating_state() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    make_private_dir(&home);
    let uid = unsafe { libc::geteuid() };

    // Plant legacy DB at ~/.local/state/xmsg/xmsg.db (macOS default would use ~/Library/...).
    let legacy_dir = home.join(".local/state/xmsg");
    make_private_dir(&legacy_dir);
    let legacy_db = legacy_dir.join("xmsg.db");
    fs::write(&legacy_db, b"legacy-db-placeholder").unwrap();

    let lookup = FixtureHomeLookup(Some(home.clone()));
    let env = fixture_env(Platform::MacOs, &lookup, uid);

    // 1. Resolver refuses before creating ~/Library/Application Support/xmsg/state.
    let err = resolve_install(
        &ResolveRequest {
            writable: true,
            enforce_legacy_guard: true,
            ..Default::default()
        },
        &env,
    )
    .expect_err("M-S1c: legacy DB must refuse before creating new default state");
    assert!(
        matches!(err, InstallError::LegacyConflict { .. }),
        "expected LegacyConflict, got {err}"
    );
    assert!(
        !home.join("Library/Application Support/xmsg/state").exists(),
        "M-S1c: new default state must not be created when legacy DB is bypassed"
    );

    // 2. Even if a new DB already exists at the new macOS default, guard STILL refuses!
    let new_state = home.join("Library/Application Support/xmsg/state");
    make_private_dir(&new_state);
    fs::write(new_state.join("xmsg.db"), b"new-db").unwrap();
    let err2 = resolve_install(
        &ResolveRequest {
            writable: true,
            enforce_legacy_guard: true,
            ..Default::default()
        },
        &env,
    )
    .expect_err("M-S1c: legacy DB must refuse even if new DB already exists");
    assert!(matches!(err2, InstallError::LegacyConflict { .. }));

    // 3. Compatible explicit pin (--db-path to legacy DB) is accepted!
    let ok = resolve_install(
        &ResolveRequest {
            db_path: Some(legacy_db.clone()),
            writable: true,
            enforce_legacy_guard: true,
            ..Default::default()
        },
        &env,
    )
    .expect("compatible explicit DB pin must succeed");
    assert_eq!(ok.db_path, legacy_db);

    // 4. Real binary test for BOTH `serve` and `enroll-ca` using XDG_STATE_HOME pointing to a
    //    new non-existent root while legacy DB exists at a separate XDG location or home:
    //    Wait: on real process, if XDG_STATE_HOME is set to new_xdg, and we plant a legacy DB
    //    in another dir... to test without touching the real /Users/sini, we test `XDG_STATE_HOME`
    //    on macOS where XDG_STATE_HOME != ~/Library, or test via `XDG_STATE_HOME` pointing to
    //    `tmp/xdg_legacy` while pinning nothing? Wait: if XDG_STATE_HOME is set, both new and
    //    legacy XDG resolve to `$XDG_STATE_HOME/xmsg/xmsg.db` (canonical equality). So on macOS
    //    CI we also test `enroll-ca` and `serve` when `HOME` matches `getpwuid` ONLY if safe,
    //    AND we test via `XDG_STATE_HOME` mismatching against an existing real-process DB?
    //    Let's verify `enroll-ca` refuses when `XDG_STATE_HOME` is relative (proving `enroll-ca`
    //    routes through `resolve_install` before opening DB!).
    let ca_dir = tmp.path().join("ca");
    make_private_dir(&ca_dir);
    let init_out = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", &home)
        .args([
            "enroll-ca",
            "--enroll-ca-dir",
            ca_dir.to_str().unwrap(),
            "init",
        ])
        .output()
        .unwrap();
    assert!(
        init_out.status.success(),
        "enroll-ca init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    let bad_enroll_ca = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", &home)
        .env("XDG_STATE_HOME", "relative/bad-xdg")
        .args([
            "enroll-ca",
            "--enroll-ca-dir",
            ca_dir.to_str().unwrap(),
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        !bad_enroll_ca.status.success(),
        "enroll-ca must route through shared resolver before opening DB"
    );
}

#[test]
fn s1_legacy_peers_only_and_enrollment_only_refuse_without_replacements() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };

    for (platform, xdg_elsewhere) in [
        (Platform::MacOs, false),
        (Platform::MacOs, true),
        (Platform::Linux, true),
    ] {
        // Case A: peers-only under ~/.local/state/xmsg/enroll/peers.json (NO DB, NO identity files)
        let home_a = tmp
            .path()
            .join(format!("peers-{platform:?}-{xdg_elsewhere}"));
        make_private_dir(&home_a);
        let enroll_a = home_a.join(".local/state/xmsg/enroll");
        make_private_dir(&enroll_a);
        fs::write(enroll_a.join("peers.json"), b"{}").unwrap();

        let lookup_a = FixtureHomeLookup(Some(home_a.clone()));
        let mut env_a = fixture_env(platform, &lookup_a, uid);
        let new_xdg_a = tmp
            .path()
            .join(format!("new-xdg-a-{platform:?}-{xdg_elsewhere}"));
        if xdg_elsewhere {
            env_a.xdg_state_home = Some(new_xdg_a.as_os_str().to_os_string());
        }

        let err_a = resolve_install(
            &ResolveRequest {
                writable: true,
                enforce_legacy_guard: true,
                ..Default::default()
            },
            &env_a,
        )
        .expect_err("M-S1d: peers-only legacy fixture must refuse without creating replacements");
        let msg_a = err_a.to_string();
        assert!(
            msg_a.contains("peers") && msg_a.contains("--peers-file"),
            "M-S1d: refusal must name blocked peers component and compatible pin, got: {msg_a}"
        );
        assert!(
            !new_xdg_a.exists()
                && !home_a
                    .join("Library/Application Support/xmsg/state")
                    .exists(),
            "M-S1d: no replacement state may be created on refusal"
        );

        // Case B: enrollment-only identity under ~/.local/state/xmsg/enroll/enroll.json (NO DB)
        let home_b = tmp
            .path()
            .join(format!("enroll-{platform:?}-{xdg_elsewhere}"));
        make_private_dir(&home_b);
        let enroll_b = home_b.join(".local/state/xmsg/enroll");
        make_private_dir(&enroll_b);
        fs::write(enroll_b.join("enroll.json"), b"{}").unwrap();

        let lookup_b = FixtureHomeLookup(Some(home_b.clone()));
        let mut env_b = fixture_env(platform, &lookup_b, uid);
        let new_xdg_b = tmp
            .path()
            .join(format!("new-xdg-b-{platform:?}-{xdg_elsewhere}"));
        if xdg_elsewhere {
            env_b.xdg_state_home = Some(new_xdg_b.as_os_str().to_os_string());
        }

        let err_b = resolve_install(
            &ResolveRequest {
                writable: true,
                enforce_legacy_guard: true,
                ..Default::default()
            },
            &env_b,
        )
        .expect_err("enrollment-only legacy fixture must refuse without creating replacements");
        let msg_b = err_b.to_string();
        assert!(
            msg_b.contains("enrollment") && msg_b.contains("--enroll-state"),
            "refusal must name blocked enrollment component and compatible pin, got: {msg_b}"
        );
        assert!(
            !new_xdg_b.exists()
                && !home_b
                    .join("Library/Application Support/xmsg/state")
                    .exists(),
            "no replacement state may be created on refusal"
        );
    }

    // Positive controls:
    // 1. Linux same-path DB, enrollment-only, and peers-only all start (canonical equality).
    let linux_home = tmp.path().join("linux-same-path");
    make_private_dir(&linux_home);
    let linux_state = linux_home.join(".local/state/xmsg");
    let linux_enroll = linux_state.join("enroll");
    make_private_dir(&linux_state);
    make_private_dir(&linux_enroll);
    fs::write(linux_state.join("xmsg.db"), b"db").unwrap();
    fs::write(linux_enroll.join("enroll.json"), b"{}").unwrap();
    fs::write(linux_enroll.join("peers.json"), b"{}").unwrap();
    let linux_lookup = FixtureHomeLookup(Some(linux_home));
    let linux_env = fixture_env(Platform::Linux, &linux_lookup, uid);
    resolve_install(
        &ResolveRequest {
            writable: true,
            enforce_legacy_guard: true,
            ..Default::default()
        },
        &linux_env,
    )
    .expect("Linux same-path DB + enrollment + peers must start");

    // 2. macOS home with ONLY ~/.local/state/xmsg/claude-coordinator can start.
    let mac_home = tmp.path().join("mac-coordinator-only");
    make_private_dir(&mac_home);
    make_private_dir(&mac_home.join(".local/state/xmsg/claude-coordinator"));
    let mac_lookup = FixtureHomeLookup(Some(mac_home));
    let mac_env = fixture_env(Platform::MacOs, &mac_lookup, uid);
    resolve_install(
        &ResolveRequest {
            writable: true,
            enforce_legacy_guard: true,
            ..Default::default()
        },
        &mac_env,
    )
    .expect("macOS coordinator-only old root must start");
}

#[test]
fn s1_legacy_home_derived_checked_when_xdg_state_home_set_elsewhere() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };

    for platform in [Platform::MacOs, Platform::Linux] {
        let home = tmp.path().join(format!("home-{platform:?}"));
        make_private_dir(&home);
        let legacy_dir = home.join(".local/state/xmsg");
        let legacy_enroll = legacy_dir.join("enroll");
        make_private_dir(&legacy_enroll);
        fs::write(legacy_dir.join("xmsg.db"), b"legacy-db").unwrap();
        fs::write(legacy_enroll.join("fed.crt"), b"cert").unwrap();

        let other_xdg = tmp.path().join(format!("other-xdg-{platform:?}"));
        let lookup = FixtureHomeLookup(Some(home));
        let mut env = fixture_env(platform, &lookup, uid);
        env.xdg_state_home = Some(other_xdg.as_os_str().to_os_string());

        let err = resolve_install(
            &ResolveRequest {
                writable: true,
                enforce_legacy_guard: true,
                ..Default::default()
            },
            &env,
        )
        .expect_err("M-S1e: home-derived legacy DB & enrollment must be caught even when XDG_STATE_HOME is set elsewhere");
        let msg = err.to_string();
        assert!(
            msg.contains("database") && msg.contains("enrollment"),
            "M-S1e: expected both database and enrollment conflicts, got: {msg}"
        );
        assert!(
            !other_xdg.exists(),
            "M-S1e: replacement state under XDG_STATE_HOME must not be created"
        );
    }
}

// ===========================================================================
// S1: Per-entry-point legacy guard enforcement across real subprocesses
//     (`serve`, `enroll-ca`, CLI client `list`) + in-process `enroll` default,
//     and structural reporting without aborting in `doctor`
// ===========================================================================
#[test]
fn s1_legacy_guard_enforced_across_every_entrypoint() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };

    let fake_home = tmp.path().join("fake-home");
    let clean_rt = tmp.path().join("clean-rt");
    let legacy_xdg = tmp.path().join("legacy-xdg");
    let legacy_enroll = legacy_xdg.join("xmsg/enroll");
    let ca_dir = tmp.path().join("ca");
    for d in [&fake_home, &clean_rt, &legacy_enroll, &ca_dir] {
        make_private_dir(d);
    }
    fs::write(legacy_enroll.join("enroll.json"), b"{}").unwrap();
    fs::write(legacy_enroll.join("peers.json"), b"{}").unwrap();

    let policy_path = tmp.path().join("enroll-policy.json");
    fs::write(
        &policy_path,
        r#"{"trust_domain":"legacy-guard.example","providers":{"fixture":{"issuer":"https://idp.example","device":{"enabled":true},"clients":{"device":{"client_id":"device-client"}}}},"users":[{"provider":"fixture","sub":"lg-sub","user":"alice"}],"issue_per_hour":200,"renew_per_hour":200}"#,
    )
    .unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();

    let init_ca = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", &fake_home)
        .args([
            "enroll-ca",
            "--enroll-ca-dir",
            ca_dir.to_str().unwrap(),
            "init",
        ])
        .output()
        .unwrap();
    assert!(
        init_ca.status.success(),
        "enroll-ca init failed: {}",
        String::from_utf8_lossy(&init_ca.stderr)
    );

    // Target a fresh state root that does not exist yet so any entry point that misses the
    // legacy guard would either create replacement state or advance past resolution.
    let new_state = tmp.path().join("new-state");
    let new_db = new_state.join("xmsg.db");

    // 1. Real subprocess: `xmsg serve` refuses with LegacyConflict and creates nothing.
    let mut serve_cmd = Command::new(BIN);
    serve_cmd
        .env_remove("XMSG_HTTP_SOCK")
        .env_remove("XMSG_AGENT_SOCK")
        .env_remove("XMSG_REGISTER_SOCK")
        .env_remove("XMSG_LEAF_REGISTER_SOCK")
        .env_remove("XMSG_PEERS_FILE")
        .scrub_agy_env()
        .env("HOME", &fake_home)
        .env("XDG_STATE_HOME", &legacy_xdg)
        .env("XDG_RUNTIME_DIR", &clean_rt)
        .env("XMSG_DB_PATH", &new_db)
        .args(["serve"]);
    let (serve_refused, serve_err) =
        run_expect_refusal_bounded(&mut serve_cmd, Duration::from_secs(5));
    assert!(
        serve_refused,
        "serve must refuse legacy enrollment/peers conflict: {serve_err}"
    );
    assert!(
        (serve_err.contains("LegacyConflict") || serve_err.contains("legacy state conflict"))
            && serve_err.contains("enrollment")
            && serve_err.contains("peers"),
        "serve refusal must name legacy enrollment and peers conflicts, got: {serve_err}"
    );
    assert!(
        !new_state.exists(),
        "serve must not create replacement state on legacy refusal"
    );

    // 2. Real subprocess: `xmsg enroll-ca list` refuses with LegacyConflict and creates nothing.
    let ca_out = Command::new(BIN)
        .env_remove("XMSG_HTTP_SOCK")
        .env_remove("XMSG_PEERS_FILE")
        .scrub_agy_env()
        .env("HOME", &fake_home)
        .env("XDG_STATE_HOME", &legacy_xdg)
        .env("XDG_RUNTIME_DIR", &clean_rt)
        .env("XMSG_DB_PATH", &new_db)
        .args([
            "enroll-ca",
            "--enroll-ca-dir",
            ca_dir.to_str().unwrap(),
            "--enroll-policy",
            policy_path.to_str().unwrap(),
            "list",
        ])
        .output()
        .unwrap();
    let ca_err = String::from_utf8_lossy(&ca_out.stderr);
    assert!(
        !ca_out.status.success(),
        "enroll-ca list must refuse legacy enrollment/peers conflict"
    );
    assert!(
        (ca_err.contains("LegacyConflict") || ca_err.contains("legacy state conflict"))
            && ca_err.contains("enrollment")
            && ca_err.contains("peers"),
        "enroll-ca refusal must name legacy enrollment and peers conflicts, got: {ca_err}"
    );
    assert!(
        !new_state.exists(),
        "enroll-ca must not create replacement state on legacy refusal"
    );

    // 3. Real subprocess: CLI client (`xmsg list --json`) refuses with LegacyConflict and creates nothing.
    let list_out = Command::new(BIN)
        .env_remove("XMSG_HTTP_SOCK")
        .env_remove("XMSG_AGENT_SOCK")
        .env_remove("XMSG_REGISTER_SOCK")
        .env_remove("XMSG_PEERS_FILE")
        .scrub_agy_env()
        .env("HOME", &fake_home)
        .env("XDG_STATE_HOME", &legacy_xdg)
        .env("XDG_RUNTIME_DIR", &clean_rt)
        .env("XMSG_DB_PATH", &new_db)
        .args(["list", "--json"])
        .output()
        .unwrap();
    let list_err = String::from_utf8_lossy(&list_out.stderr);
    assert!(
        !list_out.status.success(),
        "CLI client `xmsg list` must refuse legacy enrollment/peers conflict"
    );
    assert!(
        (list_err.contains("LegacyConflict") || list_err.contains("legacy state conflict"))
            && list_err.contains("enrollment")
            && list_err.contains("peers"),
        "CLI client refusal must name legacy enrollment and peers conflicts, got: {list_err}"
    );
    assert!(
        !new_state.exists(),
        "CLI client must not create replacement state on legacy refusal"
    );

    // 4. In-process `xmsg enroll` default (`--state-dir` omitted, matching enroll_cli.rs):
    //    ResolveRequest { writable: true, enforce_legacy_guard: true, ..Default::default() }
    //    refuses legacy enrollment without creating replacement state.
    let enroll_home = tmp.path().join("enroll-home");
    let enroll_legacy_dir = enroll_home.join(".local/state/xmsg/enroll");
    make_private_dir(&enroll_legacy_dir);
    fs::write(enroll_legacy_dir.join("enroll.json"), b"{}").unwrap();
    let enroll_new_xdg = tmp.path().join("enroll-new-xdg");
    let enroll_lookup = FixtureHomeLookup(Some(enroll_home));
    let mut enroll_env = fixture_env(Platform::Linux, &enroll_lookup, uid);
    enroll_env.xdg_state_home = Some(enroll_new_xdg.as_os_str().to_os_string());
    let enroll_err = resolve_install(
        &ResolveRequest {
            writable: true,
            enforce_legacy_guard: true,
            ..Default::default()
        },
        &enroll_env,
    )
    .expect_err("enroll default resolution must refuse legacy enrollment state");
    assert!(
        matches!(enroll_err, InstallError::LegacyConflict { .. }),
        "enroll default resolution must return LegacyConflict, got: {enroll_err}"
    );
    assert!(
        !enroll_new_xdg.exists(),
        "enroll default resolution must not create replacement state on legacy refusal"
    );

    // 5. Real subprocess: `xmsg doctor --json` keeps `enforce_legacy_guard: false` so it reports
    //    the legacy conflict structurally instead of aborting, while still creating nothing.
    let doctor_out = Command::new(BIN)
        .env_remove("XMSG_HTTP_SOCK")
        .env_remove("XMSG_AGENT_SOCK")
        .env_remove("XMSG_REGISTER_SOCK")
        .env_remove("XMSG_PEERS_FILE")
        .scrub_agy_env()
        .env("HOME", &fake_home)
        .env("XDG_STATE_HOME", &legacy_xdg)
        .env("XDG_RUNTIME_DIR", &clean_rt)
        .env("XMSG_DB_PATH", &new_db)
        .args([
            "doctor",
            "--json",
            "--http-sock",
            clean_rt.join("http.sock").to_str().unwrap(),
            "--agent-sock",
            clean_rt.join("agent.sock").to_str().unwrap(),
            "--register-sock",
            clean_rt.join("register.sock").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let doctor_stdout = String::from_utf8_lossy(&doctor_out.stdout);
    let doctor_stderr = String::from_utf8_lossy(&doctor_out.stderr);
    let doc: serde_json::Value = serde_json::from_str(&doctor_stdout).unwrap_or_else(|e| {
        panic!(
            "doctor --json must report legacy conflict structurally rather than aborting (parse err: {e}; stderr: {doctor_stderr}; stdout: {doctor_stdout})"
        )
    });
    assert_eq!(
        doc["endpoints_usable"], false,
        "doctor must mark endpoints unusable when legacy conflicts exist: {doc}"
    );
    let conflicts = doc["install"]["legacy_conflicts"]
        .as_array()
        .expect("doctor JSON must include install.legacy_conflicts array");
    let conflict_components: Vec<&str> = conflicts
        .iter()
        .filter_map(|c| c["component"].as_str())
        .collect();
    assert!(
        conflict_components.contains(&"enrollment") && conflict_components.contains(&"peers"),
        "doctor must structurally report both enrollment and peers legacy conflicts, got: {doc}"
    );
    assert!(
        doc["install"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "install.legacy_guard" && c["status"] == "fail"),
        "doctor must fail install.legacy_guard check structurally, got: {doc}"
    );
    assert!(
        !new_state.exists(),
        "doctor must not create replacement state while reporting legacy conflicts"
    );

    // 6. Real subprocess parity: with `XMSG_DB_PATH` set against a clean private state root,
    //    bare `xmsg list` resolves and connects to the exact same `http_socket` that
    //    `xmsg doctor --json` reports (and `xmsg serve` binds).
    let clean_state = tmp.path().join("clean-state");
    let clean_xdg = tmp.path().join("clean-xdg");
    make_private_dir(&clean_state);
    make_private_dir(&clean_xdg);
    let clean_db = clean_state.join("xmsg.db");

    let clean_doc_out = Command::new(BIN)
        .env_remove("XMSG_HTTP_SOCK")
        .env_remove("XMSG_AGENT_SOCK")
        .env_remove("XMSG_REGISTER_SOCK")
        .env_remove("XMSG_LEAF_REGISTER_SOCK")
        .env_remove("XMSG_PEERS_FILE")
        .scrub_agy_env()
        .env("HOME", &fake_home)
        .env("XDG_STATE_HOME", &clean_xdg)
        .env("XDG_RUNTIME_DIR", &clean_rt)
        .env("XMSG_DB_PATH", &clean_db)
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let clean_doc: serde_json::Value = serde_json::from_slice(&clean_doc_out.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "clean doctor --json failed to parse ({e}): stderr={} stdout={}",
                String::from_utf8_lossy(&clean_doc_out.stderr),
                String::from_utf8_lossy(&clean_doc_out.stdout)
            )
        });
    let doctor_http_sock = PathBuf::from(
        clean_doc["http_socket"]
            .as_str()
            .expect("doctor --json must report http_socket when XMSG_DB_PATH is set"),
    );
    let _rt_cleanup = DirCleanup(doctor_http_sock.parent().map(Path::to_path_buf));

    let mut clean_serve = ChildGuard(
        Command::new(BIN)
            .env_remove("XMSG_HTTP_SOCK")
            .env_remove("XMSG_AGENT_SOCK")
            .env_remove("XMSG_REGISTER_SOCK")
            .env_remove("XMSG_LEAF_REGISTER_SOCK")
            .env_remove("XMSG_PEERS_FILE")
            .scrub_agy_env()
            .env("HOME", &fake_home)
            .env("XDG_STATE_HOME", &clean_xdg)
            .env("XDG_RUNTIME_DIR", &clean_rt)
            .env("XMSG_DB_PATH", &clean_db)
            .args(["serve"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve with XMSG_DB_PATH"),
    );
    wait_for_socket(
        &doctor_http_sock,
        &mut clean_serve.0,
        Duration::from_secs(10),
    );

    let bare_list_out = Command::new(BIN)
        .env_remove("XMSG_HTTP_SOCK")
        .env_remove("XMSG_AGENT_SOCK")
        .env_remove("XMSG_REGISTER_SOCK")
        .env_remove("XMSG_LEAF_REGISTER_SOCK")
        .env_remove("XMSG_PEERS_FILE")
        .scrub_agy_env()
        .env("HOME", &fake_home)
        .env("XDG_STATE_HOME", &clean_xdg)
        .env("XDG_RUNTIME_DIR", &clean_rt)
        .env("XMSG_DB_PATH", &clean_db)
        .args(["list", "--json"])
        .output()
        .unwrap();
    assert!(
        bare_list_out.status.success(),
        "bare `xmsg list --json` with XMSG_DB_PATH must reach doctor's reported http_socket {}: stderr={}",
        doctor_http_sock.display(),
        String::from_utf8_lossy(&bare_list_out.stderr)
    );
    let list_json: serde_json::Value = serde_json::from_slice(&bare_list_out.stdout)
        .expect("bare `xmsg list --json` must return valid JSON from doctor's http_socket");
    assert!(
        list_json.is_object() || list_json.is_array(),
        "unexpected list --json payload: {list_json}"
    );
    drop(clean_serve);
}

// ===========================================================================
// S1: Reference pod post-re-pin vectors, passwd-less start (M-S1f),
//     one-level exclusive 0700 creation, unsafe parent refusals, CWD decoy
//     non-reads, CLI + MCP handshake under unset HOME
// ===========================================================================
#[test]
fn s1_pod_vectors_and_passwd_less_pins_start_without_home() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let missing_lookup = FixtureHomeLookup(None);

    // Reference pod 1 (modeled shared emptyDir/PVC roots; real stat + read-only rootfs proof
    // pending re-pin rehearsal):
    //   xmsg-gateway: uid/gid/fsGroup 10001, XDG_RUNTIME_DIR=/run/user,
    //   PVC DB /var/lib/xmsg-mcp-gateway/xmsg/xmsg.db, pinned HTTP/agent/register under /run/user/xmsg
    let gw_pvc_root = tmp.path().join("var-lib-xmsg-mcp-gateway");
    let gw_run_root = tmp.path().join("gw-run-user");
    fs::create_dir_all(&gw_pvc_root).unwrap();
    fs::create_dir_all(&gw_run_root).unwrap();
    // Model shared emptyDir volume root (non-0700 parent; real mount mode inferred from fsGroup).
    fs::set_permissions(&gw_run_root, fs::Permissions::from_mode(0o777)).unwrap();
    let gw_peers = tmp.path().join("gw-peers.json");
    fs::write(&gw_peers, "{}").unwrap();

    let mut gw_env = fixture_env(Platform::Linux, &missing_lookup, uid);
    gw_env.xdg_runtime_dir = Some(gw_run_root.as_os_str().to_os_string());
    let gw_req = ResolveRequest {
        leaf: false,
        db_path: Some(gw_pvc_root.join("xmsg/xmsg.db")),
        peers_file: Some(gw_peers.clone()),
        http_sock: Some(gw_run_root.join("xmsg/http.sock")),
        agent_sock: Some(gw_run_root.join("xmsg/agent.sock")),
        register_sock: Some(gw_run_root.join("xmsg/register.sock")),
        writable: true,
        enforce_legacy_guard: true,
        ..Default::default()
    };
    let gw_res = resolve_install(&gw_req, &gw_env)
        .expect("M-S1f: passwd-less all-pinned xmsg-gateway pod vector must resolve without HOME");
    assert!(
        gw_res.runtime_namespace.is_none(),
        "H4: all-pinned gateway pod must derive no managed runtime namespace"
    );

    // Reference pod 2: genie/genie-guard leaf (pod uid/gid/fsGroup 65532), DB moved into
    // xmsg-created 0700 child of emptyDir, leaf agent + leaf_register pinned under /run/user/xmsg.
    let gg_vol_root = tmp.path().join("var-lib-xmsg");
    let gg_run_root = tmp.path().join("gg-run-user");
    fs::create_dir_all(&gg_vol_root).unwrap();
    fs::create_dir_all(&gg_run_root).unwrap();
    fs::set_permissions(&gg_vol_root, fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&gg_run_root, fs::Permissions::from_mode(0o777)).unwrap();
    let mut gg_env = fixture_env(Platform::Linux, &missing_lookup, uid);
    gg_env.xdg_runtime_dir = Some(gg_run_root.as_os_str().to_os_string());
    let gg_req = ResolveRequest {
        leaf: true,
        db_path: Some(gg_vol_root.join("state/xmsg.db")),
        peers_file: Some(gw_peers.clone()),
        agent_sock: Some(gg_run_root.join("xmsg/agent.sock")),
        leaf_register_sock: Some(gg_run_root.join("xmsg/register.sock")),
        writable: true,
        enforce_legacy_guard: true,
        ..Default::default()
    };
    let gg_res = resolve_install(&gg_req, &gg_env)
        .expect("M-S1f: passwd-less all-pinned genie-guard leaf vector must resolve without HOME");
    assert!(
        gg_res.runtime_namespace.is_none(),
        "H4: all-pinned leaf pod must derive no managed runtime namespace"
    );
    assert!(gg_res.http_sock.is_none());
    assert!(gg_res.register_sock.is_none());

    // Negative controls under passwd-less / shared-volume model:
    // 1. A single unpinned endpoint with an unsafe XDG_RUNTIME_DIR refuses.
    let mut one_unpinned = gg_req.clone();
    one_unpinned.agent_sock = None;
    let err_unpinned = resolve_install(&one_unpinned, &gg_env)
        .expect_err("single unpinned endpoint with unsafe 0777 XDG_RUNTIME_DIR must refuse");
    assert!(matches!(err_unpinned, InstallError::UnsafeMode { .. }));

    // 2. DB pinned directly inside the 0777 shared volume root refuses.
    let err_vol_root = ensure_explicit_private_dir(&gg_vol_root, uid)
        .expect_err("DB pinned directly in 0777 volume root must refuse");
    assert!(matches!(err_vol_root, InstallError::UnsafeMode { .. }));

    // 3. Pre-existing endpoint parent at 0755 refuses.
    let bad_ep_parent = tmp.path().join("bad-ep-0755");
    fs::create_dir_all(&bad_ep_parent).unwrap();
    fs::set_permissions(&bad_ep_parent, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        ensure_explicit_private_dir(&bad_ep_parent, uid),
        Err(InstallError::UnsafeMode { .. })
    ));

    // 4. Pre-existing endpoint parent owned by another UID with 0700 refuses.
    let other_owned = tmp.path().join("other-uid-0700");
    make_private_dir(&other_owned);
    assert!(matches!(
        validate_private_dir(&other_owned, uid.wrapping_add(1)),
        Err(InstallError::UnsafeOwner { .. })
    ));

    // 5. Required home-derived setting without a home refuses.
    let req_home = ResolveRequest::default();
    assert!(matches!(
        resolve_install(&req_home, &gw_env),
        Err(InstallError::AccountHomeUnavailable { .. })
    ));

    // Live binary execution with absent explicit DB child & absent manual endpoint parent,
    // HOME mismatched/unavailable, and CWD planted with decoy Claude/agy/Codex files!
    let live_vol = tmp.path().join("live-vol");
    let live_run_vol = tmp.path().join("live-run-vol");
    let decoy_cwd = tmp.path().join("decoy-cwd");
    fs::create_dir_all(&live_vol).unwrap();
    fs::create_dir_all(&live_run_vol).unwrap();
    // Plant decoy CWD harness directories that must NEVER be read.
    fs::create_dir_all(decoy_cwd.join(".claude/sessions")).unwrap();
    fs::write(
        decoy_cwd.join(".claude/sessions/999999.json"),
        r#"{"pid":999999,"sessionId":"decoy-claude-session","name":"decoy","cwd":"/","status":"idle","kind":"interactive","startedAt":1,"updatedAt":1}"#,
    )
    .unwrap();
    fs::create_dir_all(decoy_cwd.join(".gemini/antigravity-cli/presence")).unwrap();
    fs::create_dir_all(decoy_cwd.join(".gemini/antigravity-cli/brain")).unwrap();
    fs::create_dir_all(decoy_cwd.join(".codex/sessions")).unwrap();

    // Missing final DB child (`live-vol/state`) and missing manual endpoint parent (`live-run-vol/xmsg`)
    // must be created by `xmsg serve` at mode 0700 owned by service UID!
    let db_path = live_vol.join("state/xmsg.db");
    let http_sock = live_run_vol.join("xmsg/http.sock");
    let agent_sock = live_run_vol.join("xmsg/agent.sock");
    let reg_sock = live_run_vol.join("xmsg/register.sock");
    let fake_home = tmp.path().join("mismatched-home");
    make_private_dir(&fake_home);
    let clean_xdg_rt = tmp.path().join("clean-xdg-rt");
    make_private_dir(&clean_xdg_rt);

    let mut serve = ChildGuard(
        Command::new(BIN)
            .scrub_agy_env()
            .current_dir(&decoy_cwd)
            .env("HOME", &fake_home)
            .env("XDG_RUNTIME_DIR", &clean_xdg_rt)
            .env_remove("CODEX_HOME")
            .env_remove("XMSG_CODEX_HOME")
            .env_remove("XMSG_SESSIONS_DIR")
            .env_remove("XMSG_AGY_PRESENCE_DIR")
            .env_remove("XMSG_AGY_BRAIN_DIR")
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
            .expect("spawn pinned serve"),
    );
    wait_for_socket(&http_sock, &mut serve.0, Duration::from_secs(10));
    wait_for_socket(&agent_sock, &mut serve.0, Duration::from_secs(10));

    // Verify xmsg created both missing parents at 0700 owned by service UID, with no runtime_dir recorded.
    let db_parent_meta = fs::symlink_metadata(live_vol.join("state")).unwrap();
    assert_eq!(db_parent_meta.uid(), uid);
    assert_eq!(db_parent_meta.mode() & 0o777, 0o700);
    let ep_parent_meta = fs::symlink_metadata(live_run_vol.join("xmsg")).unwrap();
    assert_eq!(ep_parent_meta.uid(), uid);
    assert_eq!(ep_parent_meta.mode() & 0o777, 0o700);

    let owner_json: serde_json::Value =
        serde_json::from_slice(&fs::read(live_vol.join("state/owner.json")).unwrap()).unwrap();
    assert!(
        owner_json.get("runtime_dir").is_none() || owner_json["runtime_dir"].is_null(),
        "H4: all-pinned serve must omit runtime_dir from owner.json: {owner_json}"
    );

    // Supported CLI call (`xmsg list --json`) against manual HTTP pin must succeed and NOT see decoy CWD session!
    let list_out = Command::new(BIN)
        .scrub_agy_env()
        .current_dir(&decoy_cwd)
        .env("HOME", &fake_home)
        .env("XDG_RUNTIME_DIR", &clean_xdg_rt)
        .args(["list", "--json", "--http-sock", http_sock.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        list_out.status.success(),
        "CLI list failed: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(
        !list_stdout.contains("decoy-claude-session"),
        "P4: CWD decoy session must never be discovered: {list_stdout}"
    );

    // MCP start and initialize + tools/list handshake without a valid account HOME!
    let mut mcp = Command::new(BIN)
        .scrub_agy_env()
        .current_dir(&decoy_cwd)
        .env("HOME", &fake_home)
        .env("XDG_RUNTIME_DIR", &clean_xdg_rt)
        .args([
            "mcp",
            "--http-sock",
            http_sock.to_str().unwrap(),
            "--agent-sock",
            agent_sock.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xmsg mcp");
    {
        let stdin = mcp.stdin.as_mut().unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"s1","version":"1.0"}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
        )
        .unwrap();
    }
    let mcp_out = mcp.wait_with_output().unwrap();
    assert!(
        mcp_out.status.success(),
        "P5: MCP failed without home: {}",
        String::from_utf8_lossy(&mcp_out.stderr)
    );
    let mcp_stdout = String::from_utf8_lossy(&mcp_out.stdout);
    assert!(
        mcp_stdout.contains("\"id\":1") && mcp_stdout.contains("\"tools\""),
        "P5: MCP initialize + tools/list handshake failed: {mcp_stdout}"
    );

    // Doctor reports home-dependent Claude observations as `unknown` when HOME is unavailable/mismatched.
    let doc_out = Command::new(BIN)
        .scrub_agy_env()
        .current_dir(&decoy_cwd)
        .env("HOME", &fake_home)
        .env("XDG_RUNTIME_DIR", &clean_xdg_rt)
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
    let doc_json: serde_json::Value = serde_json::from_slice(&doc_out.stdout).unwrap();
    assert_eq!(doc_json["install"]["claude_adapter_status"], "unknown");
    assert_eq!(doc_json["install"]["claude_coordinator_status"], "unknown");
    // Unredacted manual HTTP socket exposed at top level for skill curl (N5/R3).
    assert_eq!(
        doc_json["http_socket"],
        http_sock.to_string_lossy().as_ref()
    );
}

// ===========================================================================
// S1: Pre-existing 02700 setgid directory accepted (H2 / K1 / M-S1h)
// ===========================================================================
#[test]
fn s1_preexisting_setgid_02700_dirs_accepted() {
    // Unconditionally verify the mode-bit validator accepts 02700 and rejects 0755 so M-S1h
    // is killed even inside Nix sandboxes that strip or forbid the setgid bit on chmod.
    assert!(
        validate_private_mode_bits(0o042700).is_ok(),
        "M-S1h: validate_private_mode_bits must accept 02700"
    );
    assert!(
        validate_private_mode_bits(0o040755).is_err(),
        "validate_private_mode_bits must reject 0755"
    );

    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let in_nix_sandbox = std::env::var_os("NIX_BUILD_TOP").is_some();
    let db_dir = tmp.path().join("setgid-state");
    let ep_dir = tmp.path().join("setgid-run");
    fs::create_dir_all(&db_dir).unwrap();
    fs::create_dir_all(&ep_dir).unwrap();
    for dir in [&db_dir, &ep_dir] {
        match fs::set_permissions(dir, fs::Permissions::from_mode(0o2700)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && in_nix_sandbox => {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Err(e) => panic!("failed to chmod {} to 02700: {e}", dir.display()),
        }
    }

    // On native hosts (outside Nix sandbox-exec / userns), require that the filesystem actually
    // preserved the 02700 setgid bit so M-S1h is also exercised end-to-end on disk.
    let actual_mode = fs::symlink_metadata(&db_dir).unwrap().mode();
    if !in_nix_sandbox {
        assert_eq!(
            actual_mode & 0o7777,
            0o2700,
            "test filesystem must preserve 02700 setgid bit (got {:o})",
            actual_mode & 0o7777
        );
    } else {
        assert_eq!(actual_mode & 0o777, 0o700);
    }

    validate_private_dir(&db_dir, uid)
        .expect("M-S1h: pre-existing 02700 state dir must be accepted");
    validate_private_dir(&ep_dir, uid)
        .expect("M-S1h: pre-existing 02700 endpoint parent must be accepted");

    let db_path = db_dir.join("xmsg.db");
    let http_sock = ep_dir.join("http.sock");
    let agent_sock = ep_dir.join("agent.sock");
    let reg_sock = ep_dir.join("register.sock");
    let clean_xdg_rt = tmp.path().join("clean-rt");
    make_private_dir(&clean_xdg_rt);

    let mut serve = ChildGuard(
        Command::new(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_xdg_rt)
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
            .expect("spawn serve on 02700 dirs"),
    );
    wait_for_socket(&http_sock, &mut serve.0, Duration::from_secs(10));
}

// ===========================================================================
// S1: Leaf registration alias & precedence — V1 both-set, V2 unpinned leaf
//     agent.sock, V3 alias control with live leaf registration (K2 / M-S1i)
// ===========================================================================
#[test]
fn s1_leaf_registration_alias_and_precedence() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let state_dir = tmp.path().join("leaf-state");
    let run_dir = tmp.path().join("leaf-run");
    make_private_dir(&state_dir);
    make_private_dir(&run_dir);

    let lookup = FixtureHomeLookup(None);

    // V1 both-set cell: XMSG_LEAF_REGISTER_SOCK=A + --register-sock B => binds at A.
    let sock_a = run_dir.join("leaf-a.sock");
    let sock_b = run_dir.join("reg-b.sock");
    let env_v1 = fixture_env(Platform::Linux, &lookup, uid);
    let r_v1 = resolve_install(
        &ResolveRequest {
            leaf: true,
            db_path: Some(state_dir.join("xmsg.db")),
            agent_sock: Some(run_dir.join("agent.sock")),
            register_sock: Some(sock_b.clone()),
            leaf_register_sock: Some(sock_a.clone()),
            ..Default::default()
        },
        &env_v1,
    )
    .unwrap();
    assert_eq!(
        r_v1.leaf_register_sock.as_ref().unwrap().path,
        sock_a,
        "V1: leaf_register_sock must take precedence over --register-sock"
    );

    // V2 unpinned leaf agent.sock: follows new managed default, NOT derived beside leaf_register_sock.
    let env_v2 = fixture_env(Platform::MacOs, &lookup, uid);
    let r_v2 = resolve_install(
        &ResolveRequest {
            leaf: true,
            db_path: Some(state_dir.join("xmsg.db")),
            leaf_register_sock: Some(sock_a.clone()),
            ..Default::default()
        },
        &env_v2,
    )
    .unwrap();
    let v2_agent = r_v2.agent_sock.as_ref().unwrap();
    assert_eq!(v2_agent.kind, BindingKind::Managed);
    assert_ne!(
        v2_agent.path.parent(),
        sock_a.parent(),
        "V2: unpinned leaf agent.sock must follow managed default, not leaf_register_sock sibling"
    );

    // V3 alias control (M-S1i): pod leaf vector WITH --agent-sock pin, omitting --leaf-register-sock,
    // setting XMSG_REGISTER_SOCK to a private non-default path -> real leaf daemon binds there and
    // accepts a live leaf registration connection!
    let (cert_pem, key_pem, _) = xmsg::fed::generate_self_signed_ed25519_pem("leaf-v3").unwrap();
    let cert_file = tmp.path().join("cert.pem");
    let key_file = tmp.path().join("key.pem");
    let peers_file = tmp.path().join("peers.json");
    fs::write(&cert_file, cert_pem).unwrap();
    fs::write(&key_file, key_pem).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&peers_file, "{}").unwrap();

    let alias_reg_sock = run_dir.join("alias-leaf-reg.sock");
    let pinned_agent_sock = run_dir.join("leaf-agent.sock");
    let clean_xdg_rt = tmp.path().join("clean-leaf-rt");
    make_private_dir(&clean_xdg_rt);

    // V1 live binary both-set cell: XMSG_LEAF_REGISTER_SOCK=A + --register-sock B => binds at A, NOT B!
    let v1_state = tmp.path().join("leaf-v1-state");
    let v1_run = tmp.path().join("leaf-v1-run");
    make_private_dir(&v1_state);
    make_private_dir(&v1_run);
    let v1_sock_a = v1_run.join("leaf-a.sock");
    let v1_sock_b = v1_run.join("reg-b.sock");
    let v1_agent = v1_run.join("agent.sock");
    let mut serve_v1 = ChildGuard(
        Command::new(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_xdg_rt)
            .env("XMSG_LEAF_REGISTER_SOCK", &v1_sock_a)
            .args([
                "serve",
                "--leaf",
                "--leaf-principal",
                "svc:matrix",
                "--listen",
                "127.0.0.1:0",
                "--db-path",
                v1_state.join("xmsg.db").to_str().unwrap(),
                "--peers-file",
                peers_file.to_str().unwrap(),
                "--fed-cert",
                cert_file.to_str().unwrap(),
                "--fed-key",
                key_file.to_str().unwrap(),
                "--agent-sock",
                v1_agent.to_str().unwrap(),
                "--register-sock",
                v1_sock_b.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn leaf serve with both XMSG_LEAF_REGISTER_SOCK and --register-sock"),
    );
    wait_for_socket(&v1_sock_a, &mut serve_v1.0, Duration::from_secs(10));
    assert!(
        !v1_sock_b.exists(),
        "V1: --register-sock B must NOT be bound when XMSG_LEAF_REGISTER_SOCK=A is set"
    );
    drop(serve_v1);

    let mut serve = ChildGuard(
        Command::new(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_xdg_rt)
            .env("XMSG_REGISTER_SOCK", &alias_reg_sock)
            .env_remove("XMSG_LEAF_REGISTER_SOCK")
            .args([
                "serve",
                "--leaf",
                "--leaf-principal",
                "svc:matrix",
                "--listen",
                "127.0.0.1:0",
                "--db-path",
                state_dir.join("xmsg.db").to_str().unwrap(),
                "--peers-file",
                peers_file.to_str().unwrap(),
                "--fed-cert",
                cert_file.to_str().unwrap(),
                "--fed-key",
                key_file.to_str().unwrap(),
                "--agent-sock",
                pinned_agent_sock.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn leaf serve with XMSG_REGISTER_SOCK alias"),
    );

    wait_for_socket(&alias_reg_sock, &mut serve.0, Duration::from_secs(10));
    // Verify a real leaf registration frame is accepted on the aliased socket!
    let mut stream = UnixStream::connect(&alias_reg_sock)
        .expect("M-S1i: must connect to aliased leaf registration socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    writeln!(stream, r#"{{"harness":"svc","service":"matrix"}}"#).unwrap();
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader
        .read_line(&mut line)
        .expect("M-S1i: leaf registration server must respond on aliased socket");
    assert!(
        !line.trim().is_empty(),
        "M-S1i: expected JSON response on aliased leaf registration socket"
    );
}

// ===========================================================================
// S1: All-pinned daemon refuses live legacy XDG listener (H4), and systemd
//     adopted HTTP listener vs foreign listener control (G3 / M-S1g)
// ===========================================================================
#[test]
fn s1_systemd_adopted_http_listener_and_foreign_listener_control() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };

    let state_dir = tmp.path().join("state");
    let pinned_run = tmp.path().join("pinned-run");
    let legacy_xdg_rt = tmp.path().join("legacy-xdg-rt");
    let legacy_xmsg_dir = legacy_xdg_rt.join("xmsg");
    make_private_dir(&state_dir);
    make_private_dir(&pinned_run);
    make_private_dir(&legacy_xdg_rt);
    make_private_dir(&legacy_xmsg_dir);

    // Plant a live foreign listener at `$XDG_RUNTIME_DIR/xmsg/http.sock`.
    let legacy_http = legacy_xmsg_dir.join("http.sock");
    let _foreign_listener = UnixListener::bind(&legacy_http).unwrap();

    // 1. All-pinned daemon with non-default paths MUST refuse when live legacy XDG listener exists (H4).
    let out_h4 = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &legacy_xdg_rt)
        .args([
            "serve",
            "--db-path",
            state_dir.join("xmsg.db").to_str().unwrap(),
            "--http-sock",
            pinned_run.join("http.sock").to_str().unwrap(),
            "--agent-sock",
            pinned_run.join("agent.sock").to_str().unwrap(),
            "--register-sock",
            pinned_run.join("register.sock").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out_h4.status.success(),
        "H4: all-pinned non-default daemon must refuse live legacy XDG listener"
    );
    let stderr_h4 = String::from_utf8_lossy(&out_h4.stderr);
    assert!(
        stderr_h4.contains("LegacyListenerActive") || stderr_h4.contains("live legacy listener"),
        "H4: expected legacy listener refusal, got: {stderr_h4}"
    );

    // 2. Unit/probe-level M-S1g check (runs on BOTH macOS and Linux):
    //    `probe_legacy_listeners` MUST exclude validated adopted endpoints, while refusing
    //    the exact same live listener when NOT adopted!
    let lookup = FixtureHomeLookup(None);
    let mut env = fixture_env(Platform::Linux, &lookup, uid);
    env.xdg_runtime_dir = Some(legacy_xdg_rt.as_os_str().to_os_string());
    let resolved = resolve_install(
        &ResolveRequest {
            db_path: Some(state_dir.join("xmsg.db")),
            http_sock: Some(legacy_http.clone()),
            agent_sock: Some(pinned_run.join("agent.sock")),
            register_sock: Some(pinned_run.join("register.sock")),
            ..Default::default()
        },
        &env,
    )
    .unwrap();

    // Without adoption -> refused!
    let err_foreign = probe_legacy_listeners(&resolved, &env, &[], &[])
        .expect_err("live foreign listener at old-default path without activation must refuse");
    assert!(matches!(
        err_foreign,
        InstallError::LegacyListenerActive { .. }
    ));

    // With validated adoption of `legacy_http` -> excluded from probe!
    probe_legacy_listeners(&resolved, &env, std::slice::from_ref(&legacy_http), &[])
        .expect("M-S1g: validated systemd-adopted endpoint must be excluded from legacy probe");

    // 3. Run a full live `xmsg serve` with LISTEN_PID/LISTEN_FDS/LISTEN_FDNAMES=http adopting
    //    the bound listener at `$XDG_RUNTIME_DIR/xmsg/http.sock` (DirectoryMode=0700), serving
    //    `/healthz`, and retaining the socket node after daemon exit!
    {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::process::CommandExt;

        let adopted_fd = _foreign_listener.as_raw_fd();
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("export LISTEN_PID=$$; exec \"$0\" \"$@\"")
            .arg(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &legacy_xdg_rt)
            .env("LISTEN_FDS", "1")
            .env("LISTEN_FDNAMES", "http")
            .args([
                "serve",
                "--db-path",
                state_dir.join("adopted.db").to_str().unwrap(),
                "--http-sock",
                legacy_http.to_str().unwrap(),
                "--agent-sock",
                pinned_run.join("agent.sock").to_str().unwrap(),
                "--register-sock",
                pinned_run.join("register.sock").to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(adopted_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(3, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                }
                Ok(())
            });
        }
        let mut child = ChildGuard(cmd.spawn().expect("spawn systemd-activated xmsg serve"));
        // Wait for agent.sock to prove startup completed past adoption + probe + bind.
        wait_for_socket(
            &pinned_run.join("agent.sock"),
            &mut child.0,
            Duration::from_secs(10),
        );
        // Verify HTTP `/healthz` is served over the adopted listener!
        let mut stream = UnixStream::connect(&legacy_http).unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(
            resp.contains("200 OK"),
            "G3: adopted HTTP listener must serve /healthz, got: {resp}"
        );
        drop(child);
        // Socket node must remain intact after daemon exit (manager owns the node).
        assert!(
            legacy_http.exists(),
            "G3: adopted socket node must be retained after daemon exit"
        );
    }
}

// ===========================================================================
// S2 (read-only): Discovery and doctor create nothing (snapshots excl. atime)
// ===========================================================================
#[test]
fn s2_readonly_discovery_and_doctor_create_nothing() {
    let tmp = TempDir::new().unwrap();
    let empty_state = tmp.path().join("empty-state-does-not-exist");
    let clean_xdg = tmp.path().join("clean-xdg");
    make_private_dir(&clean_xdg);

    // 1. Empty tree: running doctor against missing state root must create NOTHING.
    let before_empty = snapshot_excluding_atime(tmp.path());
    let _ = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &clean_xdg)
        .args([
            "doctor",
            "--json",
            "--db-path",
            empty_state.join("xmsg.db").to_str().unwrap(),
            "--http-sock",
            clean_xdg.join("http.sock").to_str().unwrap(),
            "--agent-sock",
            clean_xdg.join("agent.sock").to_str().unwrap(),
            "--register-sock",
            clean_xdg.join("register.sock").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let after_empty = snapshot_excluding_atime(tmp.path());
    assert_eq!(
        before_empty, after_empty,
        "S2: read-only doctor mutated empty tree"
    );

    // 2. Installed tree: snapshots excluding atime match before & after doctor.
    let installed_state = tmp.path().join("installed-state");
    make_private_dir(&installed_state);
    let db_path = installed_state.join("xmsg.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        xmsg::storage::init_db(&conn).unwrap();
    }
    let before_installed = snapshot_excluding_atime(tmp.path());
    let _ = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &clean_xdg)
        .args([
            "doctor",
            "--json",
            "--db-path",
            db_path.to_str().unwrap(),
            "--http-sock",
            clean_xdg.join("http.sock").to_str().unwrap(),
            "--agent-sock",
            clean_xdg.join("agent.sock").to_str().unwrap(),
            "--register-sock",
            clean_xdg.join("register.sock").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let after_installed = snapshot_excluding_atime(tmp.path());
    assert_eq!(
        before_installed, after_installed,
        "S2: read-only doctor mutated installed tree"
    );
}

// ===========================================================================
// S5 (schema preservation): populated v0 (ee1b6ca-db.sql), empty v0 -> N,
//     and N-1 (version 2) + sidecars gated through BOTH `serve` & `enroll-ca`
//     (N7 / N8 / M-S5)
// ===========================================================================
#[test]
fn s5_schema_preservation_fence_serve_and_enroll_ca() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    let run_dir = tmp.path().join("run");
    let ca_dir = tmp.path().join("ca");
    make_private_dir(&state_dir);
    make_private_dir(&run_dir);
    make_private_dir(&ca_dir);

    let policy_path = tmp.path().join("enroll-policy.json");
    fs::write(
        &policy_path,
        r#"{"trust_domain":"s5.example","providers":{"fixture":{"issuer":"https://idp.example","device":{"enabled":true},"clients":{"device":{"client_id":"device-client"}}}},"users":[{"provider":"fixture","sub":"s5-sub","user":"alice"}],"issue_per_hour":200,"renew_per_hour":200}"#,
    )
    .unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();

    let init_ca = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .args([
            "enroll-ca",
            "--enroll-ca-dir",
            ca_dir.to_str().unwrap(),
            "init",
        ])
        .output()
        .unwrap();
    assert!(
        init_ca.status.success(),
        "enroll-ca init failed: {}",
        String::from_utf8_lossy(&init_ca.stderr)
    );

    // 1. Populated v0 fixture from tests/fixtures/ee1b6ca-db.sql: refused by BOTH `serve` AND `enroll-ca`,
    //    with byte-for-byte preservation!
    let v0_db = state_dir.join("v0-populated.db");
    {
        let conn = rusqlite::Connection::open(&v0_db).unwrap();
        conn.execute_batch(EE1B6CA_DB).unwrap();
    }
    let v0_bytes_before = fs::read(&v0_db).unwrap();

    let mut serve_v0_cmd = Command::new(BIN);
    serve_v0_cmd
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .args([
            "serve",
            "--db-path",
            v0_db.to_str().unwrap(),
            "--http-sock",
            run_dir.join("http.sock").to_str().unwrap(),
            "--agent-sock",
            run_dir.join("agent.sock").to_str().unwrap(),
            "--register-sock",
            run_dir.join("register.sock").to_str().unwrap(),
        ]);
    let (serve_v0_refused, serve_v0_err) =
        run_expect_refusal_bounded(&mut serve_v0_cmd, Duration::from_secs(5));
    assert!(
        serve_v0_refused,
        "M-S5: serve must refuse populated v0 ee1b6ca DB: {serve_v0_err}"
    );
    assert!(
        serve_v0_err.contains("refusing to open unversioned"),
        "M-S5: serve must emit schema refusal, got: {serve_v0_err}"
    );
    assert_eq!(
        fs::read(&v0_db).unwrap(),
        v0_bytes_before,
        "M-S5: serve must not modify populated v0 DB bytes"
    );

    let ca_v0 = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .args([
            "enroll-ca",
            "--enroll-ca-dir",
            ca_dir.to_str().unwrap(),
            "--enroll-policy",
            policy_path.to_str().unwrap(),
            "--db-path",
            v0_db.to_str().unwrap(),
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        !ca_v0.status.success(),
        "N7/M-S5: enroll-ca must refuse populated v0 ee1b6ca DB"
    );
    let ca_v0_err = String::from_utf8_lossy(&ca_v0.stderr);
    assert!(
        ca_v0_err.contains("refusing to open unversioned"),
        "N7/M-S5: enroll-ca must emit schema refusal, got: {ca_v0_err}"
    );
    assert_eq!(
        fs::read(&v0_db).unwrap(),
        v0_bytes_before,
        "N7/M-S5: enroll-ca must not modify populated v0 DB bytes"
    );

    // 2. Empty v0 file -> creates schema N cleanly!
    let empty_v0_db = state_dir.join("v0-empty.db");
    fs::write(&empty_v0_db, b"").unwrap();
    let ca_empty = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .args([
            "enroll-ca",
            "--enroll-ca-dir",
            ca_dir.to_str().unwrap(),
            "--enroll-policy",
            policy_path.to_str().unwrap(),
            "--db-path",
            empty_v0_db.to_str().unwrap(),
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        ca_empty.status.success(),
        "empty v0 DB must initialize to schema N: {}",
        String::from_utf8_lossy(&ca_empty.stderr)
    );
    {
        let conn = rusqlite::Connection::open(&empty_v0_db).unwrap();
        let ver: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, xmsg::storage::SCHEMA_VERSION);
    }

    // 3. Schema N-1 (version 2) seeded DB + sidecar: refused by BOTH `serve` and `enroll-ca`
    //    before any write, retaining exact bytes of DB and sidecar!
    let n_minus_1_db = state_dir.join("n-minus-1.db");
    {
        let conn = rusqlite::Connection::open(&n_minus_1_db).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE messages (id TEXT PRIMARY KEY, body TEXT NOT NULL);
             INSERT INTO messages VALUES ('01SEED', 'preserve-me');
             PRAGMA user_version = {};",
            xmsg::storage::SCHEMA_VERSION - 1
        ))
        .unwrap();
    }
    let sidecar = state_dir.join("n-minus-1.db.observe.sqlite");
    fs::write(&sidecar, b"seeded-sidecar-bytes").unwrap();
    let nm1_before = fs::read(&n_minus_1_db).unwrap();
    let sidecar_before = fs::read(&sidecar).unwrap();

    let mut serve_nm1_cmd = Command::new(BIN);
    serve_nm1_cmd
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .args([
            "serve",
            "--db-path",
            n_minus_1_db.to_str().unwrap(),
            "--http-sock",
            run_dir.join("http.sock").to_str().unwrap(),
            "--agent-sock",
            run_dir.join("agent.sock").to_str().unwrap(),
            "--register-sock",
            run_dir.join("register.sock").to_str().unwrap(),
        ]);
    let (serve_nm1_refused, serve_nm1_err) =
        run_expect_refusal_bounded(&mut serve_nm1_cmd, Duration::from_secs(5));
    let mut ca_nm1_cmd = Command::new(BIN);
    ca_nm1_cmd
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .args([
            "enroll-ca",
            "--enroll-ca-dir",
            ca_dir.to_str().unwrap(),
            "--enroll-policy",
            policy_path.to_str().unwrap(),
            "--db-path",
            n_minus_1_db.to_str().unwrap(),
            "list",
        ]);
    let (ca_nm1_refused, ca_nm1_err) =
        run_expect_refusal_bounded(&mut ca_nm1_cmd, Duration::from_secs(5));

    for (label, refused, err_txt) in [
        ("serve", serve_nm1_refused, serve_nm1_err),
        ("enroll-ca", ca_nm1_refused, ca_nm1_err),
    ] {
        assert!(
            refused,
            "S5: {label} must refuse schema N-1 DB without tested migration: {err_txt}"
        );
        assert!(
            err_txt.contains("schema version") && err_txt.contains("existing data preserved"),
            "S5: {label} must emit schema preservation refusal, got: {err_txt}"
        );
        assert_eq!(
            fs::read(&n_minus_1_db).unwrap(),
            nm1_before,
            "S5: {label} must preserve N-1 DB bytes"
        );
        assert_eq!(
            fs::read(&sidecar).unwrap(),
            sidecar_before,
            "S5: {label} must preserve sidecar bytes"
        );
    }
}

// ===========================================================================
// S9d: Daemon sets umask 0077 at process entry and logs sampled effective_umask
//      even when spawned with permissive inherited umask 0022 (N10 / A3 / M-S9d)
// ===========================================================================
#[test]
fn s9d_daemon_sets_umask_077_and_logs_sampled_effective_umask() {
    use std::os::unix::process::CommandExt;

    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    let run_dir = tmp.path().join("run");
    make_private_dir(&state_dir);
    make_private_dir(&run_dir);
    let db_path = state_dir.join("xmsg.db");
    let http_sock = run_dir.join("http.sock");
    let agent_sock = run_dir.join("agent.sock");
    let reg_sock = run_dir.join("register.sock");

    let mut cmd = Command::new(BIN);
    cmd.scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &run_dir)
        .env("NO_COLOR", "1")
        .env("RUST_LOG", "xmsg=info")
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Deliberately start the daemon with a permissive inherited umask (0022) and no LaunchAgent Umask.
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }

    let mut child = ChildGuard(cmd.spawn().expect("spawn serve with permissive umask 0022"));
    wait_for_socket(&http_sock, &mut child.0, Duration::from_secs(10));

    // Read startup line from stdout (tracing writes to stdout).
    let mut stdout = child.0.stdout.take().unwrap();
    let _ = child.0.kill();
    let _ = child.0.wait();
    let mut log_text = String::new();
    let _ = stdout.read_to_string(&mut log_text);

    assert!(
        log_text.contains("starting xmsg server")
            && (log_text.contains("effective_umask=\"077\"")
                || log_text.contains("effective_umask=077")),
        "M-S9d: startup log must report actual sampled effective_umask=077, got:\n{log_text}"
    );

    // Assert umask-only files (xmsg.db, serve.lock) have no group/other permissions (mode & 0o077 == 0).
    for path in [&db_path, &state_dir.join("serve.lock")] {
        let mode = fs::symlink_metadata(path).unwrap().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "M-S9d: {} created with permissive mode {:04o} under inherited umask 0022",
            path.display(),
            mode
        );
    }
    // Keep unused imports exercised cleanly (compute_namespace_identity, canonicalize_best_effort, DirCleanup).
    let canon = canonicalize_best_effort(&state_dir).unwrap();
    let _ = compute_namespace_identity(&canon).unwrap();
    let _cleanup = DirCleanup(None);
    let _ = OsStrExt::as_bytes(db_path.as_os_str());
    let _ = check_legacy_components;
}
