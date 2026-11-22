//! Gate tests for socket byte budget, multibyte overflow, proof-authorized stale
//! cleanup, live runtime `identity.json` marker recovery, manual endpoint locks,
//! atomic no-replace socket publication (both RenameNoReplace and LinkUnlink arms),
//! incumbent collision barriers, and 1-byte temp-name exhaustion (S8 / M-S8..M-S8g).

mod agy_env;
use agy_env::ScrubAgyEnv;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use xmsg::agent::socket_publish_hook;
use xmsg::install_paths::{
    canonicalize_best_effort, compute_namespace_identity, resolve_install, select_runtime_parent,
    sun_path_capacity, validate_socket_path, BindingKind, FixtureHomeLookup, InstallError,
    Platform, ResolveEnv, ResolveRequest,
};
use xmsg::runtime_lock::{
    bind_and_publish_socket, ensure_managed_runtime_dir, publish_control,
    verify_runtime_dir_readonly, EndpointLock, OwnerRecord, PublishPrimitive, RuntimeLockError,
    StateLock,
};

const BIN: &str = env!("CARGO_BIN_EXE_xmsg");

/// Serialize tests that touch global test hooks (`socket_publish_hook`, `publish_control`).
static HOOK_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

struct ResetPublishControl;
impl Drop for ResetPublishControl {
    fn drop(&mut self) {
        publish_control::force_primitive(None);
    }
}

fn make_private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn wait_for_socket(path: &Path, child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "daemon exited early ({status}) before binding {}",
                path.display()
            );
        }
        if StdUnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {}", path.display());
}

// ===========================================================================
// S8 / M-S8: Exact OS-byte boundary (103 accept / 104 refuse on Darwin;
//            107 / 108 on Linux), C6 multibyte `52 * U+00E9` under
//            `/private/tmp/h`, and long Linux XDG_RUNTIME_DIR fallback to /tmp
// ===========================================================================
#[test]
fn s8_socket_byte_budget_and_multibyte_darwin_bounds() {
    let cap = sun_path_capacity();
    let max_bytes = cap - 1; // 103 on Darwin, 107 on Linux

    // Exact boundary: `max_bytes` accepted, `max_bytes + 1` refused.
    let prefix = "/tmp/";
    let exact_ok = PathBuf::from(format!("{prefix}{}", "a".repeat(max_bytes - prefix.len())));
    assert_eq!(exact_ok.as_os_str().as_bytes().len(), max_bytes);
    validate_socket_path(&exact_ok).expect("exact max_bytes socket path must be accepted");

    let over_one = PathBuf::from(format!(
        "{prefix}{}",
        "a".repeat(max_bytes - prefix.len() + 1)
    ));
    assert_eq!(over_one.as_os_str().as_bytes().len(), max_bytes + 1);
    assert!(
        matches!(
            validate_socket_path(&over_one),
            Err(InstallError::SocketPathTooLong { .. })
        ),
        "max_bytes + 1 socket path must be refused"
    );

    // Exact C6 / M-S8 multibyte fixture:
    // Under `/private/tmp/h`, component of 52 U+00E9 ('é', 2 UTF-8 bytes each) + `/agent.sock`.
    // 15 + 52 + 11 = 78 chars (<= 103) and 15 + 104 + 11 = 130 OS bytes (>= 104 and >= 108).
    let multibyte_comp = "\u{00E9}".repeat(52);
    let multibyte_str = format!("/private/tmp/h/{multibyte_comp}/agent.sock");
    let char_count = multibyte_str.chars().count();
    let os_bytes = multibyte_str.len();
    assert!(
        char_count <= 103,
        "C6 precondition: expected <= 103 chars, got {char_count}"
    );
    assert!(
        os_bytes >= 104,
        "C6 precondition: expected >= 104 OS bytes, got {os_bytes}"
    );
    assert!(
        matches!(
            validate_socket_path(Path::new(&multibyte_str)),
            Err(InstallError::SocketPathTooLong { .. })
        ),
        "M-S8: validator must count OS bytes, not Unicode characters (chars={char_count}, bytes={os_bytes})"
    );

    // Long ASCII & multibyte home state roots still produce a short managed socket path under
    // `/tmp/xmsg-<uid>-<12hex>/agent.sock`, and a valid-but-too-long Linux XDG_RUNTIME_DIR
    // falls back to canonical system `/tmp`.
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let long_home = tmp
        .path()
        .join(format!("long-{}-{}", "x".repeat(40), "\u{00E9}".repeat(12)));
    make_private_dir(&long_home);
    let long_state = long_home.join("state");
    make_private_dir(&long_state);
    let lookup = FixtureHomeLookup(Some(long_home.clone()));

    let long_xdg_rt = tmp.path().join("r".repeat(90));
    make_private_dir(&long_xdg_rt);
    let linux_env = ResolveEnv {
        home: None,
        xdg_config_home: None,
        xdg_state_home: None,
        xdg_runtime_dir: Some(long_xdg_rt.as_os_str().to_os_string()),
        darwin_user_temp_dir: None,
        system_tmp: PathBuf::from("/tmp"),
        platform: Platform::Linux,
        euid: uid,
        home_lookup: &lookup,
    };
    let ns_id =
        compute_namespace_identity(&canonicalize_best_effort(&long_state).unwrap()).unwrap();
    let selected = select_runtime_parent(&linux_env, &ns_id.dir_name, "register.sock")
        .expect("valid-but-too-long Linux XDG_RUNTIME_DIR must fall back to /tmp");
    let canon_tmp = canonicalize_best_effort(Path::new("/tmp")).unwrap();
    assert_eq!(
        selected.path, canon_tmp,
        "long Linux XDG_RUNTIME_DIR must fall back to canonical /tmp"
    );
    let resolved = resolve_install(
        &ResolveRequest {
            db_path: Some(long_state.join("xmsg.db")),
            writable: true,
            enforce_legacy_guard: false,
            ..Default::default()
        },
        &linux_env,
    )
    .unwrap();
    validate_socket_path(&resolved.agent_sock.as_ref().unwrap().path)
        .expect("managed socket path from long multibyte home must fit sun_path");
}

// ===========================================================================
// S8 / M-S8b: Proof-authorized stale cleanup (kill + restart manual daemon
//             succeeds), unrecorded stale node refused WITHOUT unlink,
//             two states naming one endpoint refused, unproven empty runtime
//             dir & mismatched identity.json refused
// ===========================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s8_proof_authorized_stale_cleanup_and_unproven_refusal() {
    let _guard = HOOK_SERIAL.lock().await;
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let state1 = tmp.path().join("state1");
    let state2 = tmp.path().join("state2");
    let run = tmp.path().join("run");
    let clean_xdg = tmp.path().join("clean-xdg");
    for d in [&state1, &state2, &run, &clean_xdg] {
        make_private_dir(d);
    }

    let db1 = state1.join("xmsg.db");
    let http_sock = run.join("http.sock");
    let agent_sock = run.join("agent.sock");
    let reg_sock = run.join("register.sock");

    // 1. Start a real daemon with manual bindings, SIGKILL it (leaving stale sockets behind
    //    with matching owner.json proof), and restart on the same state root -> SUCCEEDS!
    let mut first = ChildGuard(
        Command::new(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_xdg)
            .args([
                "serve",
                "--db-path",
                db1.to_str().unwrap(),
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
            .expect("spawn first daemon"),
    );
    wait_for_socket(&http_sock, &mut first.0, Duration::from_secs(10));
    let _ = first.0.kill();
    let _ = first.0.wait();
    assert!(http_sock.exists(), "SIGKILL leaves recorded stale socket");

    let mut restarted = ChildGuard(
        Command::new(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_xdg)
            .args([
                "serve",
                "--db-path",
                db1.to_str().unwrap(),
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
            .expect("restart daemon after SIGKILL"),
    );
    wait_for_socket(&http_sock, &mut restarted.0, Duration::from_secs(10));

    // 2. While state1 owns those endpoints, a second state root naming the same endpoint REFUSES!
    let conflict = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &clean_xdg)
        .args([
            "serve",
            "--db-path",
            state2.join("xmsg.db").to_str().unwrap(),
            "--http-sock",
            http_sock.to_str().unwrap(),
            "--agent-sock",
            agent_sock.to_str().unwrap(),
            "--register-sock",
            reg_sock.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !conflict.status.success(),
        "two state roots naming the same endpoint must refuse"
    );
    drop(restarted);

    // 3. Unrecorded stale socket (bound, never listening -> connect fails) MUST BE REFUSED
    //    AND NEVER UNLINKED (`M-S8b`)!
    let unrecorded_run = tmp.path().join("unrecorded-run");
    make_private_dir(&unrecorded_run);
    let stale_sock = unrecorded_run.join("agent.sock");
    let stale_holder = tokio::net::UnixSocket::new_stream().unwrap();
    stale_holder.bind(&stale_sock).unwrap();
    drop(stale_holder);
    assert!(
        StdUnixStream::connect(&stale_sock).is_err(),
        "precondition: stale socket connect must fail"
    );
    let stale_ino_before = fs::symlink_metadata(&stale_sock).unwrap().ino();

    let st_lock = StateLock::try_acquire(&state2).unwrap();
    let ep_lock = EndpointLock::try_acquire(&stale_sock, uid).unwrap();
    let mut owner2 = OwnerRecord::new(uid, None);
    let err = bind_and_publish_socket(
        &st_lock,
        Some(&ep_lock),
        &state2,
        "agent",
        &stale_sock,
        BindingKind::Manual,
        &mut owner2,
        uid,
    )
    .expect_err("M-S8b: unrecorded stale socket must be refused");
    assert!(
        matches!(err, RuntimeLockError::UnprovenExistingSocket { .. }),
        "M-S8b: expected UnprovenExistingSocket, got {err}"
    );
    assert!(
        stale_sock.exists() && fs::symlink_metadata(&stale_sock).unwrap().ino() == stale_ino_before,
        "M-S8b: unrecorded stale socket must NOT be unlinked on failed connect!"
    );

    // 4. Unproven existing runtime directory (even when completely empty!) & marker mismatch refuse!
    let rt_parent = tmp.path().join("rt-parent");
    make_private_dir(&rt_parent);
    let canon_state2 = canonicalize_best_effort(&state2).unwrap();
    let ns_id = compute_namespace_identity(&canon_state2).unwrap();
    let unproven_dir = rt_parent.join(&ns_id.dir_name);
    make_private_dir(&unproven_dir); // empty, private, 0700, owned by uid — STILL UNPROVEN!
    let err_empty =
        ensure_managed_runtime_dir(&st_lock, &state2, &unproven_dir, &ns_id, &mut owner2, uid)
            .expect_err("Q3: existing empty runtime dir without durable proof must refuse");
    assert!(matches!(
        err_empty,
        RuntimeLockError::UnprovenRuntimeDir { .. }
    ));

    // Plant a mismatched identity.json -> also refuses!
    fs::write(unproven_dir.join("identity.json"), b"{\"wrong\":true}").unwrap();
    fs::set_permissions(
        unproven_dir.join("identity.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let err_mismatch =
        ensure_managed_runtime_dir(&st_lock, &state2, &unproven_dir, &ns_id, &mut owner2, uid)
            .expect_err("mismatched identity.json must refuse");
    assert!(matches!(
        err_mismatch,
        RuntimeLockError::UnprovenRuntimeDir { .. }
    ));
}

// ===========================================================================
// S8 / M-S8c: Live daemon (`--reply-ttl 1`), remove runtime `identity.json`,
//             verify recovery within 1s + 1s scheduling margin WITHOUT
//             restart and with seeded durable rows intact!
// ===========================================================================
#[test]
fn s8_live_runtime_marker_removal_recovers_within_one_period() {
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let state_dir = tmp.path().join("state");
    let clean_xdg = tmp.path().join("clean-xdg");
    make_private_dir(&state_dir);
    make_private_dir(&clean_xdg);

    let db_path = state_dir.join("xmsg.db");
    // Seed durable state OUTSIDE the mailbox & session-context TTL prune set (`messages` + `instance_queue`).
    let witness_id = "01B5DURABLEWITNESS00000001";
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        xmsg::storage::init_db(&conn).unwrap();
        let now = xmsg::storage::now_epoch_secs();
        xmsg::storage::insert_message(
            &conn,
            &xmsg::storage::MessageRecord {
                id: witness_id.into(),
                created_at: now + 3600,
                session_id: "0199cecf-b5b5-7000-8000-00000000b5b5".into(),
                from_name: "witness".into(),
                bytes: 7,
                outcome: "queued".into(),
                recipient_harness: "claude".into(),
                return_harness: None,
                return_session_id: None,
                thread_id: witness_id.into(),
                return_host: None,
            },
        )
        .unwrap();
    }

    // Resolve the managed runtime namespace that `xmsg serve` will create (unpinned endpoints!).
    let lookup = FixtureHomeLookup(None);
    let mut env = ResolveEnv {
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
    let resolved = resolve_install(
        &ResolveRequest {
            db_path: Some(db_path.clone()),
            writable: true,
            enforce_legacy_guard: false,
            ..Default::default()
        },
        &env,
    )
    .unwrap();
    let ns_dir = resolved.runtime_namespace.clone().unwrap();
    let ns_id = resolved.namespace_identity.clone().unwrap();
    let http_sock = resolved.http_sock.as_ref().unwrap().path.clone();
    let _cleanup = DirCleanup(Some(ns_dir.clone()));

    let mut serve = ChildGuard(
        Command::new(BIN)
            .scrub_agy_env()
            .env("HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", &clean_xdg)
            .args([
                "serve",
                "--db-path",
                db_path.to_str().unwrap(),
                "--reply-ttl",
                "1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn live daemon with --reply-ttl 1"),
    );
    wait_for_socket(&http_sock, &mut serve.0, Duration::from_secs(10));

    let marker = ns_dir.join("identity.json");
    assert!(
        marker.exists(),
        "runtime identity.json must exist at startup"
    );

    // Simulate a tmp cleaner removing ONLY `identity.json` while daemon stays live.
    fs::remove_file(&marker).unwrap();
    assert!(!marker.exists());

    // Must recover within one maintenance period (1s) + 1s scheduling margin WITHOUT restart!
    let deadline = Instant::now() + Duration::from_millis(2000);
    let mut recovered = false;
    while Instant::now() < deadline {
        assert!(
            serve.0.try_wait().unwrap().is_none(),
            "daemon must stay alive without restarting"
        );
        if verify_runtime_dir_readonly(&ns_dir, &ns_id, uid).is_ok() {
            recovered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        recovered,
        "M-S8c: missing runtime identity.json was not re-stamped live within 1s + 1s margin"
    );

    // New client resolves & connects cleanly after live recovery.
    let list_out = Command::new(BIN)
        .scrub_agy_env()
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", &clean_xdg)
        .args(["list", "--json", "--http-sock", http_sock.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        list_out.status.success(),
        "new client must connect after live marker recovery: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );

    // Seeded durable witness outside the TTL prune set remains untouched (B5).
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE id = ?1",
            [witness_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "B5: durable witness row must remain unchanged");
    env.xdg_runtime_dir = None;
}

// ===========================================================================
// S8 / M-S8d: Two manual owners competing for the same endpoint while owner 1
//             is paused at `socket_publish_hook`: owner 2 CANNOT reach
//             publication while owner 1 holds the endpoint lock!
// ===========================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s8_competing_manual_owners_serialized_by_endpoint_lock() {
    let _guard = HOOK_SERIAL.lock().await;
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let state1 = tmp.path().join("state1");
    let state2 = tmp.path().join("state2");
    let run = tmp.path().join("run");
    for d in [&state1, &state2, &run] {
        make_private_dir(d);
    }
    let sock = run.join("shared-manual.sock");
    let canon_sock = canonicalize_best_effort(&run)
        .unwrap()
        .join("shared-manual.sock");

    let barrier = Arc::new(Barrier::new(2));
    socket_publish_hook::pause_once(canon_sock.clone(), barrier.clone());

    let sock_for_t1 = sock.clone();
    let state1_clone = state1.clone();
    let mut t1 = tokio::spawn(async move {
        let st1 = StateLock::try_acquire(&state1_clone).unwrap();
        let ep1 = EndpointLock::try_acquire(&sock_for_t1, uid).unwrap();
        let mut owner1 = OwnerRecord::new(uid, None);
        let res = bind_and_publish_socket(
            &st1,
            Some(&ep1),
            &state1_clone,
            "agent",
            &sock_for_t1,
            BindingKind::Manual,
            &mut owner1,
            uid,
        );
        (res, st1, ep1)
    });

    // Wait for owner 1 to reach the publish barrier while holding its endpoint lock.
    let reached = barrier.clone();
    let mut reach_task = tokio::task::spawn_blocking(move || reached.wait());
    tokio::select! {
        res = &mut reach_task => {
            res.unwrap();
        }
        early = &mut t1 => {
            // Release the blocking thread parked on `reached.wait()` so Tokio's
            // BlockingPool shutdown never hangs and swallows the panic.
            barrier.wait();
            let _ = reach_task.await;
            panic!("owner 1 exited before reaching publish barrier: {early:?}");
        }
    }

    // Owner 2 (distinct state root) tries to acquire the manual endpoint lock while owner 1
    // is paused at the publish barrier. Capture the result and release the barrier BEFORE
    // asserting so a mutant failure never leaves owner 1 parked at the barrier.
    let ep2_res = EndpointLock::try_acquire(&sock, uid);

    // Release owner 1 before asserting so tokio shutdown never hangs on a failed assertion.
    let release = barrier.clone();
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .unwrap();
    let (res1, _st1, _ep1) = t1.await.unwrap();

    let ep2_err =
        ep2_res.expect_err("M-S8d: competing manual owner must be blocked by held endpoint lock");
    assert!(
        matches!(ep2_err, RuntimeLockError::EndpointLockHeld { .. }),
        "M-S8d: expected EndpointLockHeld, got {ep2_err}"
    );
    let (listener, _prim) = res1.expect("owner 1 must publish cleanly after release");
    let _client = StdUnixStream::connect(&sock).expect("connect to owner 1 socket");
    let _ = listener.accept().await.unwrap();
}

// ===========================================================================
// S8 / M-S8e & M-S8g & P2: Incumbent collision barrier immediately before
//     atomic publication, exercised for BOTH `BindingKind::Managed` and
//     `BindingKind::Manual`, AND for BOTH `RenameNoReplace` and forced
//     `LinkUnlink` publication arms! Also checks client connectivity after
//     clean publish per arm and records the exercised primitive.
// ===========================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s8_incumbent_collision_barrier_per_primitive_arm() {
    let _guard = HOOK_SERIAL.lock().await;
    let _reset = ResetPublishControl;
    let uid = unsafe { libc::geteuid() };

    let arms = [
        ("rename_no_replace", PublishPrimitive::RenameNoReplace),
        ("link_unlink", PublishPrimitive::LinkUnlink),
    ];

    for (arm_name, forced_prim) in arms {
        publish_control::force_primitive(Some(forced_prim));
        for kind in [BindingKind::Managed, BindingKind::Manual] {
            let tmp = TempDir::new().unwrap();
            let state = tmp.path().join("state");
            let run = tmp.path().join("run");
            make_private_dir(&state);
            make_private_dir(&run);

            // Part A: Clean publish on this arm -> record primitive + verify real client connect!
            // Scoped in its own block so Part A's StateLock and EndpointLock are guaranteed to be
            // dropped strictly BEFORE Part B spawns `candidate`.
            {
                let clean_sock = run.join("clean.sock");
                let st_lock = StateLock::try_acquire(&state).unwrap();
                let ep_lock = (kind == BindingKind::Manual)
                    .then(|| EndpointLock::try_acquire(&clean_sock, uid).unwrap());
                let mut owner = OwnerRecord::new(uid, None);
                let (listener, used_prim) = bind_and_publish_socket(
                    &st_lock,
                    ep_lock.as_ref(),
                    &state,
                    "agent",
                    &clean_sock,
                    kind,
                    &mut owner,
                    uid,
                )
                .unwrap_or_else(|e| panic!("clean publish failed for {arm_name}/{kind:?}: {e}"));
                assert_eq!(
                    used_prim, forced_prim,
                    "P2: recorded primitive must match exercised arm {arm_name}"
                );
                println!(
                    "s8-publish-arm: {arm_name} kind={kind:?} primitive={used_prim:?} clean=ok"
                );
                let _client = StdUnixStream::connect(&clean_sock).unwrap_or_else(|e| {
                    panic!("client connect failed on {arm_name}/{kind:?}: {e}")
                });
                let _ = listener.accept().await.unwrap();
            }

            // Part B: Incumbent barrier immediately before atomic publication call (H5 / M-S8e / M-S8g):
            // Pause candidate AFTER pending record is durable and ALL userspace checks completed,
            // plant an independent incumbent at `collide_sock` WITHOUT taking xmsg locks, resume,
            // and assert typed PublishCollision refusal + unchanged incumbent inode + candidate cleanup!
            let collide_sock = run.join("collide.sock");
            let canon_collide = canonicalize_best_effort(&run).unwrap().join("collide.sock");
            let barrier = Arc::new(Barrier::new(2));
            socket_publish_hook::pause_once(canon_collide.clone(), barrier.clone());

            let state_c = state.clone();
            let sock_c = collide_sock.clone();
            let mut candidate = tokio::spawn(async move {
                let st2 = StateLock::try_acquire(&state_c).unwrap();
                let ep2 = (kind == BindingKind::Manual)
                    .then(|| EndpointLock::try_acquire(&sock_c, uid).unwrap());
                let mut owner2 = OwnerRecord::new(uid, None);
                bind_and_publish_socket(
                    &st2,
                    ep2.as_ref(),
                    &state_c,
                    "http",
                    &sock_c,
                    kind,
                    &mut owner2,
                    uid,
                )
            });

            // Wait until candidate reaches the barrier immediately before atomic publication.
            // Select against `candidate` so an unexpected early exit fails fast instead of hanging.
            let b_reach = barrier.clone();
            let mut reach_task = tokio::task::spawn_blocking(move || b_reach.wait());
            tokio::select! {
                res = &mut reach_task => {
                    res.unwrap();
                }
                early = &mut candidate => {
                    // Release the blocking thread parked on `b_reach.wait()` so Tokio's
                    // BlockingPool shutdown never hangs and swallows the panic.
                    barrier.wait();
                    let _ = reach_task.await;
                    panic!("candidate exited before reaching publish barrier ({arm_name}/{kind:?}): {early:?}");
                }
            }

            // Confirm pending record is already durable on disk BEFORE planting incumbent.
            let pending_disk = OwnerRecord::load(&state).unwrap().unwrap();
            assert!(
                pending_disk.pending.contains_key("http"),
                "pending record must be durable before publication barrier"
            );
            let candidate_tmp = pending_disk.pending["http"].tmp_path.clone();

            // Independently plant an incumbent socket WITHOUT taking xmsg locks!
            let _incumbent = StdUnixListener::bind(&collide_sock).unwrap();
            let inc_meta_before = fs::symlink_metadata(&collide_sock).unwrap();

            // Release candidate -> MUST collide cleanly without replacing incumbent!
            let b_rel = barrier.clone();
            tokio::task::spawn_blocking(move || b_rel.wait())
                .await
                .unwrap();

            let err = candidate
                .await
                .unwrap()
                .expect_err("M-S8e/M-S8g: independent incumbent at publish barrier must win");
            assert!(
                matches!(err, RuntimeLockError::PublishCollision { .. }),
                "M-S8e/M-S8g ({arm_name}/{kind:?}): expected PublishCollision, got {err}"
            );

            // Incumbent identity (dev, ino) MUST be unchanged!
            let inc_meta_after = fs::symlink_metadata(&collide_sock).unwrap();
            assert_eq!(
                (inc_meta_after.dev(), inc_meta_after.ino()),
                (inc_meta_before.dev(), inc_meta_before.ino()),
                "M-S8e/M-S8g ({arm_name}/{kind:?}): incumbent was replaced!"
            );
            // Candidate cleaned ONLY its own temporary node & pending record!
            assert!(
                !candidate_tmp.exists(),
                "candidate temp socket {} must be cleaned on collision",
                candidate_tmp.display()
            );
            let after_disk = OwnerRecord::load(&state).unwrap().unwrap();
            assert!(
                !after_disk.pending.contains_key("http"),
                "candidate pending record must be removed on collision"
            );
            assert!(
                !after_disk.endpoints.contains_key("http"),
                "collided candidate must not promote bound endpoint"
            );
            println!("s8-publish-arm: {arm_name} kind={kind:?} barrier-collision=refused");
        }
    }
}

// ===========================================================================
// S8 / Q1 / M-S8f: 1-byte final basename with EVERY other admissible 1-byte
//     basename occupied -> typed TempNameExhausted refusal, final name
//     remains ABSENT (no direct-bind fallback!)
// ===========================================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s8_one_byte_temp_name_exhaustion_refuses_without_binding_final() {
    let _guard = HOOK_SERIAL.lock().await;
    let tmp = TempDir::new().unwrap();
    let uid = unsafe { libc::geteuid() };
    let state = tmp.path().join("state");
    let run = tmp.path().join("r");
    make_private_dir(&state);
    make_private_dir(&run);

    // Final basename is 1 byte (`"z"`), absent and well within sun_path budget.
    let final_sock = run.join("z");
    validate_socket_path(&final_sock).expect("final 1-byte socket path must fit within budget");

    // Occupy EVERY other admissible 1-byte POSIX basename (1..=127 excluding '/', '.', 'z',
    // and on macOS APFS case-insensitive filesystems also excluding 'Z').
    for byte in 1u8..=127u8 {
        if byte == b'/' || byte == b'.' || byte == b'z' {
            continue;
        }
        if cfg!(target_os = "macos") && byte.eq_ignore_ascii_case(&b'z') {
            continue;
        }
        let slice = [byte];
        let p = run.join(OsStr::from_bytes(&slice));
        if fs::symlink_metadata(&p).is_ok() {
            continue;
        }
        let _ = fs::write(&p, b"");
    }
    assert!(
        !final_sock.exists(),
        "Q1 precondition: final name 'z' must remain absent"
    );

    let st_lock = StateLock::try_acquire(&state).unwrap();
    let mut owner = OwnerRecord::new(uid, None);
    let err = bind_and_publish_socket(
        &st_lock,
        None,
        &state,
        "agent",
        &final_sock,
        BindingKind::Managed,
        &mut owner,
        uid,
    )
    .expect_err("M-S8f: exhausted 1-byte temp names must refuse without direct-bind fallback");
    assert!(
        matches!(err, RuntimeLockError::TempNameExhausted { .. }),
        "M-S8f: expected TempNameExhausted, got {err}"
    );
    assert!(
        !final_sock.exists(),
        "M-S8f: direct-bind fallback bound the final name 'z'!"
    );
}
