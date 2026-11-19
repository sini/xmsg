use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

use xmsg::agy::{
    attest_mcp_caller, dev_major, dev_minor, is_conversation_proc_watched, new_agy_store,
    verify_registration, AgyConfig, AgyRegisterRequest,
};
use xmsg::codex::{
    find_nearest_codex_owner_from_peer, init_for_state, is_trusted_codex_owner_step, CodexConfig,
};
use xmsg::error::AppError;
use xmsg::http::{bind_ucred_unix_listener, build_unix_router, AppState, HttpPeer};
use xmsg::process::{live_exe_drift, PeerCred};

fn write_mock_proc(
    proc_root: &Path,
    pid: u32,
    ppid: u32,
    exe_target: Option<&Path>,
    open_file: Option<&Path>,
    starttime: &str,
) {
    let pid_dir = proc_root.join(pid.to_string());
    let fd_dir = pid_dir.join("fd");
    fs::create_dir_all(&fd_dir).unwrap();
    let stat_line = format!(
        "{pid} (proc) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime} 0 0 0 0 0 0 0 0 0 0\n"
    );
    fs::write(pid_dir.join("stat"), stat_line).unwrap();
    let exe_link = pid_dir.join("exe");
    let _ = fs::remove_file(&exe_link);
    if let Some(exe) = exe_target {
        std::os::unix::fs::symlink(exe, &exe_link).unwrap();
    }
    let fd_link = fd_dir.join("3");
    let _ = fs::remove_file(&fd_link);
    if let Some(f) = open_file {
        std::os::unix::fs::symlink(f, &fd_link).unwrap();
    }
}

struct DoctorHarness {
    root: TempDir,
    _sockets: Vec<UnixListener>,
    server: tokio::task::JoinHandle<()>,
}

impl DoctorHarness {
    async fn start(agy_config: AgyConfig, codex_config: CodexConfig) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let run = root.path().join("run");
        fs::create_dir(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.path().join("sessions")).unwrap();

        let mut sockets = Vec::new();
        for name in ["agent.sock", "register.sock"] {
            let sock = UnixListener::bind(run.join(name)).unwrap();
            fs::set_permissions(run.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            sockets.push(sock);
        }

        let db_path = root.path().join("primary.sqlite");
        let db = rusqlite::Connection::open(&db_path).unwrap();
        xmsg::storage::init_db(&db).unwrap();
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600)).unwrap();
        let observer = root.path().join("primary.sqlite.observe.sqlite");
        fs::write(&observer, "observer canary").unwrap();
        fs::set_permissions(&observer, fs::Permissions::from_mode(0o600)).unwrap();

        let state = Arc::new(AppState {
            sessions_dirs: vec![root.path().join("sessions")],
            agy_config,
            agy_store: new_agy_store(),
            pi_store: xmsg::pi::new_pi_store(),
            pi_notify_tx: tokio::sync::broadcast::channel(16).0,
            svc_store: xmsg::svc::new_svc_store(),
            svc_notify_tx: tokio::sync::broadcast::channel(16).0,
            node_name: "drift.example".into(),
            max_body: 65536,
            max_attachment_bytes: 8 * 1024 * 1024,
            request_counter: AtomicU64::new(0),
            db: Arc::new(Mutex::new(db)),
            notify_tx: tokio::sync::broadcast::channel(16).0,
            reply_ttl: Duration::from_secs(3600),
            idempotency_ttl: Duration::from_secs(86400),
            long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
            fed_state: None,
        });
        init_for_state(&state, codex_config);

        let http_sock = run.join("http.sock");
        let listener =
            bind_ucred_unix_listener(&http_sock, xmsg::agent::current_uid(), None).unwrap();
        let router = build_unix_router(state);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<HttpPeer>(),
            )
            .await
            .unwrap();
        });

        Self {
            root,
            _sockets: sockets,
            server,
        }
    }

    async fn run_doctor(&self) -> (std::process::Output, Value) {
        let root = self.root.path().to_owned();
        let out = tokio::task::spawn_blocking(move || {
            Command::new(env!("CARGO_BIN_EXE_xmsg"))
                .env_remove("XMSG_PEERS_FILE")
                .env_remove("XMSG_FED_CERT")
                .env("HOME", root.join("home"))
                .env("XDG_STATE_HOME", root.join("state"))
                .env("XDG_RUNTIME_DIR", root.join("run"))
                .args(["doctor", "--json", "--http-sock"])
                .arg(root.join("run/http.sock"))
                .arg("--agent-sock")
                .arg(root.join("run/agent.sock"))
                .arg("--register-sock")
                .arg(root.join("run/register.sock"))
                .arg("--db-path")
                .arg(root.join("primary.sqlite"))
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        let json: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "invalid doctor JSON: {e}; stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out, json)
    }
}

impl Drop for DoctorHarness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn find_check<'a>(report: &'a Value, id: &str) -> Option<&'a Value> {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oracle_1_codex_default_admits_same_name_different_path_and_doctor_reports_info() {
    let tmp = tempfile::tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let store_a = tmp.path().join("store-a/bin");
    let store_b = tmp.path().join("store-b/bin");
    fs::create_dir_all(&store_a).unwrap();
    fs::create_dir_all(&store_b).unwrap();
    let configured_codex = store_a.join("codex");
    let upgraded_codex = store_b.join("codex");
    fs::write(&configured_codex, b"codex-0.169.1").unwrap();
    fs::write(&upgraded_codex, b"codex-0.167.0").unwrap();
    let canon_upgraded = fs::canonicalize(&upgraded_codex).unwrap();

    write_mock_proc(&proc_root, 2000, 1, Some(&upgraded_codex), None, "100");
    write_mock_proc(&proc_root, 2001, 2000, None, None, "200");

    let mut codex_cfg =
        CodexConfig::from_paths(std::slice::from_ref(&configured_codex), &[]).unwrap();
    codex_cfg.proc_root = proc_root.clone();
    assert!(!codex_cfg.codex_exe_strict);

    let uid = xmsg::agent::current_uid();
    let found = find_nearest_codex_owner_from_peer(&codex_cfg, &PeerCred::unpinned(uid, 2001));
    assert_eq!(
        found,
        Some((2000, "100".to_string(), canon_upgraded)),
        "default mode must admit a Codex ancestor whose canonical file_name matches"
    );

    let agy_cfg = AgyConfig {
        proc_root: proc_root.clone(),
        presence_dir: tmp.path().join("presence"),
        brain_dir: tmp.path().join("brain"),
        ..Default::default()
    };
    let doctor = DoctorHarness::start(agy_cfg, codex_cfg.clone()).await;
    let (out, report) = doctor.run_doctor().await;
    assert!(out.status.success(), "{report}");
    assert_eq!(report["failed"], 0, "{report}");

    let row = find_check(&report, "harness.codex_exe").expect("missing harness.codex_exe check");
    assert_eq!(row["status"], "info", "{report}");
    assert_eq!(
        row["message"],
        "codex binary path differs from configured (upgrade?); matched by name"
    );
    assert!(row["hint"].is_null(), "{row}");

    // When the owner restarts onto the configured path, the drift notice clears.
    write_mock_proc(&proc_root, 2000, 1, Some(&configured_codex), None, "300");
    write_mock_proc(&proc_root, 2001, 2000, None, None, "400");
    let exact = find_nearest_codex_owner_from_peer(&codex_cfg, &PeerCred::unpinned(uid, 2001));
    assert!(exact.is_some());
    let (_, report_after) = doctor.run_doctor().await;
    assert!(
        find_check(&report_after, "harness.codex_exe").is_none(),
        "exact-path re-admission must clear drift notice: {report_after}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oracle_2_codex_strict_refuses_different_path_and_doctor_warns() {
    let tmp = tempfile::tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let store_a = tmp.path().join("store-a/bin");
    let store_b = tmp.path().join("store-b/bin");
    fs::create_dir_all(&store_a).unwrap();
    fs::create_dir_all(&store_b).unwrap();
    let configured_codex = store_a.join("codex");
    let drifted_codex = store_b.join("codex");
    fs::write(&configured_codex, b"codex-0.169.1").unwrap();
    fs::write(&drifted_codex, b"codex-0.167.0").unwrap();

    write_mock_proc(&proc_root, 2000, 1, Some(&drifted_codex), None, "100");
    write_mock_proc(&proc_root, 2001, 2000, None, None, "200");

    let mut codex_cfg =
        CodexConfig::from_paths(std::slice::from_ref(&configured_codex), &[]).unwrap();
    codex_cfg.proc_root = proc_root.clone();
    codex_cfg.codex_exe_strict = true;

    let uid = xmsg::agent::current_uid();
    let refused = find_nearest_codex_owner_from_peer(&codex_cfg, &PeerCred::unpinned(uid, 2001));
    assert_eq!(
        refused, None,
        "--codex-exe-strict must refuse a different canonical path even when file_name matches"
    );

    let agy_cfg = AgyConfig {
        proc_root: proc_root.clone(),
        presence_dir: tmp.path().join("presence"),
        brain_dir: tmp.path().join("brain"),
        ..Default::default()
    };
    let doctor = DoctorHarness::start(agy_cfg, codex_cfg.clone()).await;
    let (out, report) = doctor.run_doctor().await;
    assert!(out.status.success(), "warnings exit 0: {report}");
    assert_eq!(report["failed"], 0, "{report}");
    assert!(report["warnings"].as_u64().unwrap() >= 1, "{report}");

    let row = find_check(&report, "harness.codex_exe").expect("missing harness.codex_exe warning");
    assert_eq!(row["status"], "warn", "{report}");
    assert_eq!(
        row["message"],
        "codex binary path differs from configured; strict mode refused admission"
    );
    let hint = row["hint"]
        .as_str()
        .expect("strict warning must carry remedy hint");
    assert!(hint.contains("Restart"), "hint={hint}");
    assert!(hint.contains("--codex-exe-strict"), "hint={hint}");

    // Control: exact canonical path is still admitted under strict mode.
    write_mock_proc(&proc_root, 2002, 1, Some(&configured_codex), None, "150");
    let exact = find_nearest_codex_owner_from_peer(&codex_cfg, &PeerCred::unpinned(uid, 2002));
    assert_eq!(
        exact,
        Some((
            2002,
            "150".to_string(),
            fs::canonicalize(&configured_codex).unwrap()
        ))
    );
}

#[test]
fn oracle_3_different_canonical_filename_refused_in_both_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let store_a = tmp.path().join("store-a/bin");
    let other_dir = tmp.path().join("other/bin");
    let link_dir = tmp.path().join("links");
    fs::create_dir_all(&store_a).unwrap();
    fs::create_dir_all(&other_dir).unwrap();
    fs::create_dir_all(&link_dir).unwrap();

    let configured_codex = store_a.join("codex");
    fs::write(&configured_codex, b"codex").unwrap();

    let bash_bin = other_dir.join("bash");
    let codexx_bin = other_dir.join("codexx");
    let prefix_bin = other_dir.join("my-codex");
    let substr_bin = other_dir.join("cod");
    for p in [&bash_bin, &codexx_bin, &prefix_bin, &substr_bin] {
        fs::write(p, b"other").unwrap();
    }
    let spoof_symlink = link_dir.join("codex");
    std::os::unix::fs::symlink(&bash_bin, &spoof_symlink).unwrap();
    let broken_symlink = link_dir.join("broken-dir");
    fs::create_dir_all(&broken_symlink).unwrap();
    let broken_codex = broken_symlink.join("codex");
    std::os::unix::fs::symlink(tmp.path().join("missing/codex"), &broken_codex).unwrap();

    let candidates: [PathBuf; 6] = [
        bash_bin,
        codexx_bin,
        prefix_bin,
        substr_bin,
        spoof_symlink,
        broken_codex,
    ];

    let uid = xmsg::agent::current_uid();
    for strict in [false, true] {
        let mut codex_cfg =
            CodexConfig::from_paths(std::slice::from_ref(&configured_codex), &[]).unwrap();
        codex_cfg.proc_root = proc_root.clone();
        codex_cfg.codex_exe_strict = strict;

        for (idx, cand) in candidates.iter().enumerate() {
            let pid = 3100 + idx as u32;
            write_mock_proc(&proc_root, pid, 1, Some(cand), None, "100");
            assert_eq!(
                is_trusted_codex_owner_step(&codex_cfg, pid, "100"),
                None,
                "strict={strict} candidate={} must be refused",
                cand.display()
            );
            assert_eq!(
                find_nearest_codex_owner_from_peer(&codex_cfg, &PeerCred::unpinned(uid, pid)),
                None,
                "strict={strict} candidate={} must not be admitted via ancestry",
                cand.display()
            );
            assert_eq!(
                live_exe_drift(&codex_cfg.exe_drift, &proc_root),
                None,
                "non-matching filename {} must never record drift",
                cand.display()
            );
        }
    }
}

#[test]
fn oracle_4_codex_starttime_toctou_guard_holds_in_name_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let store_a = tmp.path().join("store-a/bin");
    let store_b = tmp.path().join("store-b/bin");
    fs::create_dir_all(&store_a).unwrap();
    fs::create_dir_all(&store_b).unwrap();
    let configured_codex = store_a.join("codex");
    let upgraded_codex = store_b.join("codex");
    fs::write(&configured_codex, b"codex-a").unwrap();
    fs::write(&upgraded_codex, b"codex-b").unwrap();

    // PID 3000 has starttime "999" in proc, while the caller pinned "100" before a PID recycle.
    write_mock_proc(&proc_root, 3000, 1, Some(&upgraded_codex), None, "999");

    let mut codex_cfg = CodexConfig::from_paths(&[configured_codex], &[]).unwrap();
    codex_cfg.proc_root = proc_root.clone();
    codex_cfg.codex_exe_strict = false;

    assert_eq!(
        is_trusted_codex_owner_step(&codex_cfg, 3000, "100"),
        None,
        "starttime mismatch must be refused in default name-match mode"
    );
    assert_eq!(
        live_exe_drift(&codex_cfg.exe_drift, &proc_root),
        None,
        "recycled PID with mismatched starttime must not record drift"
    );

    // Positive control: matching starttime "999" succeeds in name-match mode.
    assert_eq!(
        is_trusted_codex_owner_step(&codex_cfg, 3000, "999"),
        Some(fs::canonicalize(&upgraded_codex).unwrap())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oracle_5_agy_default_admits_strict_refuses_and_doctor_reports_drift() {
    // Verify CLI flags are wired on `xmsg serve --help`.
    let help = Command::new(env!("CARGO_BIN_EXE_xmsg"))
        .env_clear()
        .args(["serve", "--help"])
        .env("HOME", "/nonexistent")
        .output()
        .unwrap();
    assert!(help.status.success());
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(help_stdout.contains("--codex-exe-strict"), "{help_stdout}");
    assert!(help_stdout.contains("--agy-exe-strict"), "{help_stdout}");

    let tmp = tempfile::tempdir().unwrap();
    let proc_root = tmp.path().join("proc");
    let proc_locks = tmp.path().join("locks");
    let presence_dir = tmp.path().join("presence");
    let brain_dir = tmp.path().join("brain");
    fs::create_dir_all(&presence_dir).unwrap();
    fs::create_dir_all(&brain_dir).unwrap();

    let store_a = tmp.path().join("store-a/bin");
    let store_b = tmp.path().join("store-b/bin");
    let other_dir = tmp.path().join("other/bin");
    fs::create_dir_all(&store_a).unwrap();
    fs::create_dir_all(&store_b).unwrap();
    fs::create_dir_all(&other_dir).unwrap();

    let configured_agy = store_a.join("agy");
    let upgraded_agy = store_b.join("agy");
    let bash_bin = other_dir.join("bash");
    let agyy_bin = other_dir.join("agyy");
    fs::write(&configured_agy, b"agy-1.5.3").unwrap();
    fs::write(&upgraded_agy, b"agy-1.5.2").unwrap();
    fs::write(&bash_bin, b"bash").unwrap();
    fs::write(&agyy_bin, b"agyy").unwrap();
    let spoof_agy_link = other_dir.join("agy");
    std::os::unix::fs::symlink(&bash_bin, &spoof_agy_link).unwrap();

    let conv = "0199cecf-0005-7000-8000-000000000005";
    let lock_file = presence_dir.join(format!("{conv}.lock"));
    fs::write(&lock_file, b"lock").unwrap();
    let meta = fs::metadata(&lock_file).unwrap();
    let locks_line = format!(
        "1: FLOCK ADVISORY WRITE 4000 {:02x}:{:02x}:{} 0 EOF\n",
        dev_major(meta.dev()),
        dev_minor(meta.dev()),
        meta.ino()
    );
    fs::write(&proc_locks, locks_line).unwrap();

    write_mock_proc(
        &proc_root,
        4000,
        1,
        Some(&upgraded_agy),
        Some(&lock_file),
        "100",
    );
    write_mock_proc(&proc_root, 4001, 4000, None, None, "200");
    let children_dir = proc_root.join("4000/task/4000");
    fs::create_dir_all(&children_dir).unwrap();
    fs::write(children_dir.join("children"), "4001 ").unwrap();

    let req = AgyRegisterRequest {
        conversation_id: conv.to_string(),
        ls_address: "127.0.0.1:41234".to_string(),
        csrf_token: "token-agy".to_string(),
    };

    // 1. Default mode (`agy_exe_strict = false`): admits upgraded store path and reports INFO in doctor.
    let default_cfg = AgyConfig {
        proc_root: proc_root.clone(),
        proc_locks_path: proc_locks.clone(),
        presence_dir: presence_dir.clone(),
        brain_dir: brain_dir.clone(),
        trusted_agy_exes: vec![configured_agy.clone()],
        agy_exe_strict: false,
        ..Default::default()
    };
    let reg = verify_registration(&default_cfg, 1000, 1000, 4001, &req)
        .expect("default mode must admit agy with matching canonical file_name");
    assert_eq!(reg.pid, 4000);
    let (mcp_reg, mcp_conv) = attest_mcp_caller(&default_cfg, 1000, 1000, 4001)
        .expect("default mode must attest agy MCP caller by canonical file_name");
    assert_eq!(mcp_reg.pid, 4000);
    assert_eq!(mcp_conv, conv);
    assert!(is_conversation_proc_watched(&default_cfg, conv));

    let doctor_default = DoctorHarness::start(default_cfg, CodexConfig::default()).await;
    let (out_def, rep_def) = doctor_default.run_doctor().await;
    assert!(out_def.status.success(), "{rep_def}");
    let info_row = find_check(&rep_def, "harness.agy_exe").expect("missing harness.agy_exe info");
    assert_eq!(info_row["status"], "info", "{rep_def}");
    assert_eq!(
        info_row["message"],
        "agy binary path differs from configured (upgrade?); matched by name"
    );
    assert!(info_row["hint"].is_null(), "{info_row}");
    drop(doctor_default);

    // 2. Strict mode (`agy_exe_strict = true`): refuses drifted path and reports WARN in doctor.
    let strict_cfg = AgyConfig {
        proc_root: proc_root.clone(),
        proc_locks_path: proc_locks.clone(),
        presence_dir: presence_dir.clone(),
        brain_dir: brain_dir.clone(),
        trusted_agy_exes: vec![configured_agy.clone()],
        agy_exe_strict: true,
        ..Default::default()
    };
    assert!(matches!(
        verify_registration(&strict_cfg, 1000, 1000, 4001, &req),
        Err(AppError::NotRecipient(_))
    ));
    assert!(matches!(
        attest_mcp_caller(&strict_cfg, 1000, 1000, 4001),
        Err(AppError::NotRecipient(_))
    ));
    assert!(!is_conversation_proc_watched(&strict_cfg, conv));

    let doctor_strict = DoctorHarness::start(strict_cfg, CodexConfig::default()).await;
    let (out_strict, rep_strict) = doctor_strict.run_doctor().await;
    assert!(out_strict.status.success(), "{rep_strict}");
    assert!(
        rep_strict["warnings"].as_u64().unwrap() >= 1,
        "{rep_strict}"
    );
    let warn_row =
        find_check(&rep_strict, "harness.agy_exe").expect("missing harness.agy_exe warn");
    assert_eq!(warn_row["status"], "warn", "{rep_strict}");
    assert_eq!(
        warn_row["message"],
        "agy binary path differs from configured; strict mode refused admission"
    );
    let hint = warn_row["hint"]
        .as_str()
        .expect("strict agy warn must carry hint");
    assert!(hint.contains("Restart Antigravity"), "hint={hint}");
    assert!(hint.contains("--agy-exe-strict"), "hint={hint}");
    drop(doctor_strict);

    // 3. Different canonical file names (including symlink named `agy` -> `bash`) are refused in both modes.
    for strict in [false, true] {
        for bad_exe in [&bash_bin, &agyy_bin, &spoof_agy_link] {
            write_mock_proc(&proc_root, 4000, 1, Some(bad_exe), Some(&lock_file), "100");
            let cfg = AgyConfig {
                proc_root: proc_root.clone(),
                proc_locks_path: proc_locks.clone(),
                presence_dir: presence_dir.clone(),
                brain_dir: brain_dir.clone(),
                trusted_agy_exes: vec![configured_agy.clone()],
                agy_exe_strict: strict,
                ..Default::default()
            };
            assert!(
                matches!(
                    verify_registration(&cfg, 1000, 1000, 4001, &req),
                    Err(AppError::NotRecipient(_))
                ),
                "strict={strict} bad_exe={} must be refused",
                bad_exe.display()
            );
            assert_eq!(
                live_exe_drift(&cfg.exe_drift, &proc_root),
                None,
                "non-matching canonical filename {} must not record drift",
                bad_exe.display()
            );
        }
    }
}
