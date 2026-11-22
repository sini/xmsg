use super::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const FIRST: &str = "11111111-1111-4111-8111-111111111111";
const SECOND: &str = "22222222-2222-4222-8222-222222222222";
struct Fixture {
    _dir: tempfile::TempDir,
    state: AppState,
    proc_root: PathBuf,
}
fn stat(root: &Path, pid: u32, parent: u32, start: u64) {
    std::fs::create_dir_all(root.join(pid.to_string())).unwrap();
    let mut fields = vec!["0".to_owned(); 20];
    fields[0] = "S".into();
    fields[1] = parent.to_string();
    fields[19] = start.to_string();
    std::fs::write(
        root.join(pid.to_string()).join("stat"),
        format!("{pid} (reader-fixture) {}\n", fields.join(" ")),
    )
    .unwrap();
}
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let proc_root = dir.path().join("proc");
    let sessions = dir.path().join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    for (pid, parent, start) in [
        (1, 0, 1),
        (100, 200, 30),
        (200, 300, 20),
        (300, 1, 10),
        (900, 1, 40),
    ] {
        stat(&proc_root, pid, parent, start);
    }
    let db = rusqlite::Connection::open_in_memory().unwrap();
    crate::storage::init_db(&db).unwrap();
    let db = Arc::new(Mutex::new(db));
    let (notify_tx, _) = tokio::sync::broadcast::channel(4);
    let (pi_notify_tx, _) = tokio::sync::broadcast::channel(4);
    let (svc_notify_tx, _) = tokio::sync::broadcast::channel(4);
    let state = AppState {
        sessions_dirs: vec![sessions],
        agy_config: crate::agy::AgyConfig {
            proc_root: proc_root.clone(),
            presence_dir: dir.path().join("presence"),
            brain_dir: dir.path().join("brain"),
            proc_locks_path: proc_root.join("locks"),
            ..Default::default()
        },
        agy_store: crate::agy::new_agy_store(),
        pi_store: crate::pi::new_pi_store(),
        pi_notify_tx,
        svc_store: crate::svc::new_svc_store(),
        svc_notify_tx,
        node_name: "reader.node".into(),
        max_body: 65536,
        max_attachment_bytes: 65536,
        request_counter: std::sync::atomic::AtomicU64::new(0),
        db,
        notify_tx,
        reply_ttl: Duration::from_secs(60),
        idempotency_ttl: Duration::from_secs(60),
        long_poll_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
        fed_state: None,
    };
    crate::codex::init_for_state(
        &state,
        crate::codex::CodexConfig {
            proc_root: proc_root.clone(),
            ..Default::default()
        },
    );
    Fixture {
        _dir: dir,
        state,
        proc_root,
    }
}
fn file(f: &Fixture, pid: u32, start: &str, id: &str) {
    let entry = crate::registry::SessionFileEntry {
        env: None,
        pid,
        session_id: id.into(),
        name: None,
        cwd: "/".into(),
        status: "idle".into(),
        kind: "interactive".into(),
        entrypoint: None,
        version: None,
        started_at: 1,
        updated_at: 1,
        proc_start: start.into(),
        messaging_socket_path: f
            ._dir
            .path()
            .join(format!("caller-{pid}.sock"))
            .to_str()
            .unwrap()
            .into(),
    };
    std::fs::write(
        f.state.sessions_dirs[0].join(format!("{pid}.json")),
        serde_json::to_vec(&entry).unwrap(),
    )
    .unwrap();
}
fn query(f: &Fixture, original: u32, executor: u32) -> Result<ResolvedCaller, FailureReason> {
    resolve(
        &f.state,
        &PeerCred::unpinned(unsafe { libc::geteuid() }, original),
        &PeerCred::unpinned(unsafe { libc::geteuid() }, executor),
        None,
        Instant::now() + Duration::from_secs(2),
    )
}
fn agy(f: &Fixture, id: &str, pid: u32, start: &str) {
    let mut info = crate::agy::AgySessionInfo::new(id.into(), pid, start.into(), None);
    info.registered_at = 10;
    f.state.agy_store.write().unwrap().insert(id.into(), info);
}
#[test]
fn strict_reader_file_identity_is_positive_and_readonly() {
    let f = fixture();
    file(&f, 100, "30", FIRST);
    let before = f.state.db.lock().unwrap().total_changes();
    let answer = query(&f, 100, 900).unwrap();
    assert_eq!(answer.principal, format!("{FIRST}@reader.node"));
    assert_eq!(answer.stamp.source, "claude");
    assert_eq!(answer.stamp.matched_pid, 100);
    assert_eq!(
        f.state.db.lock().unwrap().total_changes(),
        before,
        "attribution wrote authority or queue records"
    );
}
#[test]
fn strict_reader_active_suffix_is_bound_to_the_selected_claim() {
    let f = fixture();
    file(&f, 100, "30", FIRST);
    f.state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO instance_claims VALUES(?1,100,'30',2,0,42)",
            [FIRST],
        )
        .unwrap();
    let answer = query(&f, 100, 900).unwrap();
    assert_eq!(answer.principal, format!("{FIRST}~2@reader.node"));
}
#[test]
fn strict_reader_executor_incarnation_stops_before_session_match() {
    let f = fixture();
    file(&f, 300, "10", FIRST);
    file(&f, 200, "20", SECOND);
    let answer = query(&f, 100, 200);
    assert_eq!(
        answer.err(),
        Some(FailureReason::ExecutorLineage),
        "executor lineage constructed an ancestor principal"
    );
}
#[test]
fn strict_reader_registered_child_below_executor_keeps_own_identity() {
    let f = fixture();
    file(&f, 100, "30", FIRST);
    file(&f, 200, "20", SECOND);
    let answer = query(&f, 100, 200).unwrap();
    assert_eq!(answer.principal, format!("{FIRST}@reader.node"));
}
#[test]
fn strict_reader_unregistered_reaper_does_not_become_a_new_stop() {
    let f = fixture();
    file(&f, 300, "10", FIRST);
    let answer = query(&f, 100, 900).unwrap();
    assert_eq!(answer.principal, format!("{FIRST}@reader.node"));
}
#[test]
fn strict_reader_pid_one_is_a_matchable_reaper_not_runtime_excluded() {
    let f = fixture();
    file(&f, 1, "1", FIRST);
    let answer = query(&f, 100, 900).unwrap();
    assert_eq!(answer.principal, format!("{FIRST}@reader.node"));
}
#[test]
fn strict_reader_agy_without_credentials_remains_in_matched_set() {
    let f = fixture();
    agy(&f, FIRST, 100, "30");
    let answer = query(&f, 100, 900).unwrap();
    assert_eq!(answer.principal, format!("{FIRST}@reader.node"));
    assert_eq!(answer.stamp.source, "agy");
}
#[test]
fn strict_reader_refuses_a_parent_incarnation_change_between_steps() {
    let f = fixture();
    agy(&f, FIRST, 200, "21");
    let proc_root = f.proc_root.clone();
    NEXT_LINEAGE_STEP.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(move || stat(&proc_root, 200, 300, 21)));
    });
    assert_eq!(
        query(&f, 100, 900).err(),
        Some(FailureReason::Changed),
        "a recycled parent published authority during the lineage walk"
    );
    let updated = query(&f, 100, 900).unwrap();
    assert_eq!(updated.principal, format!("{FIRST}@reader.node"));
    assert_eq!(updated.stamp.matched_start, "21");
}

#[test]
fn strict_reader_competing_identities_never_select_the_first() {
    let f = fixture();
    agy(&f, FIRST, 100, "30");
    agy(&f, SECOND, 100, "30");
    let step = strict_process_link(&f.proc_root, 100).unwrap();
    assert_eq!(
        capture_step(
            &f.state,
            &step,
            100,
            None,
            Instant::now() + Duration::from_secs(2)
        )
        .err(),
        Some(FailureReason::Ambiguous),
        "the capture must reject competing registrations before the walk uses them"
    );
    let answer = query(&f, 100, 900);
    assert_eq!(
        answer.err(),
        Some(FailureReason::Ambiguous),
        "competing registrations constructed a principal"
    );
}
#[test]
fn strict_reader_codex_executable_competes_with_uncredentialed_agy() {
    use std::os::unix::fs::symlink;
    let f = fixture();
    agy(&f, FIRST, 100, "30");
    let exe = f._dir.path().join("codex-fixture");
    std::fs::write(&exe, b"not executable, metadata fixture only").unwrap();
    symlink(&exe, f.proc_root.join("100/exe")).unwrap();
    crate::codex::init_for_state(
        &f.state,
        crate::codex::CodexConfig {
            proc_root: f.proc_root.clone(),
            trusted_codex_exes: vec![exe.canonicalize().unwrap()],
            ..Default::default()
        },
    );
    assert_eq!(
        query(&f, 100, 900).err(),
        Some(FailureReason::Ambiguous),
        "Codex owner was omitted from full matched set"
    );
}
#[test]
fn strict_reader_authority_query_error_is_not_parent_fallback() {
    let f = fixture();
    file(&f, 100, "30", FIRST);
    file(&f, 300, "10", SECOND);
    f.state
        .db
        .lock()
        .unwrap()
        .execute("DROP TABLE instance_seen", [])
        .unwrap();
    assert_eq!(
        query(&f, 100, 900).err(),
        Some(FailureReason::AuthorityUnavailable),
        "failed authority read constructed a parent principal"
    );
}
#[test]
fn strict_reader_unreadable_registry_is_not_parent_fallback() {
    let f = fixture();
    agy(&f, FIRST, 300, "10");
    let parent = query(&f, 100, 900).unwrap();
    assert_eq!(parent.principal, format!("{FIRST}@reader.node"));
    assert_eq!(parent.stamp.source, "agy");
    std::fs::write(
        f.state.sessions_dirs[0].join("broken.json"),
        b"invalid fixture JSON",
    )
    .unwrap();
    assert_eq!(
        query(&f, 100, 900).err(),
        Some(FailureReason::AuthorityUnavailable),
        "registry error fell through to parent authority"
    );
}
#[test]
fn strict_reader_poisoned_store_is_not_false_absence() {
    let f = fixture();
    file(&f, 300, "10", FIRST);
    let store = f.state.agy_store.clone();
    let _ = std::thread::spawn(move || {
        let _guard = store.write().unwrap();
        panic!("fixture poison");
    })
    .join();
    assert_eq!(
        query(&f, 100, 900).err(),
        Some(FailureReason::AuthorityUnavailable),
        "poisoned authority store became absence"
    );
}
#[test]
fn strict_reader_busy_timeout_restored_on_success_and_failure() {
    let f = fixture();
    file(&f, 100, "30", FIRST);
    f.state
        .db
        .lock()
        .unwrap()
        .busy_timeout(Duration::from_millis(1234))
        .unwrap();
    let before = f.state.db.lock().unwrap().total_changes();
    query(&f, 100, 900).unwrap();
    let timeout: i64 = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .unwrap();
    assert_eq!(timeout, 1234);
    assert_eq!(f.state.db.lock().unwrap().total_changes(), before);
    agy(&f, SECOND, 100, "30");
    assert_eq!(query(&f, 100, 900).err(), Some(FailureReason::Ambiguous));
    let timeout: i64 = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        timeout, 1234,
        "error path changed ordinary bus busy timeout"
    );
    assert_eq!(f.state.db.lock().unwrap().total_changes(), before);
}
#[test]
fn strict_reader_locked_store_honors_absolute_deadline() {
    let f = fixture();
    let _held = f.state.agy_store.write().unwrap();
    let answer = resolve(
        &f.state,
        &PeerCred::unpinned(unsafe { libc::geteuid() }, 100),
        &PeerCred::unpinned(unsafe { libc::geteuid() }, 900),
        None,
        Instant::now() + Duration::from_millis(5),
    );
    assert_eq!(answer.err(), Some(FailureReason::Deadline));
}

#[test]
fn strict_reader_late_store_release_cannot_publish_stale_authority() {
    let f = fixture();
    file(&f, 100, "30", FIRST);
    let held = f.state.agy_store.write().unwrap();
    let deadline = Instant::now() + Duration::from_millis(30);
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
    let answer = std::thread::scope(|scope| {
        let state = &f.state;
        let worker = scope.spawn(move || {
            started_tx.send(()).unwrap();
            resolve(
                state,
                &PeerCred::unpinned(unsafe { libc::geteuid() }, 100),
                &PeerCred::unpinned(unsafe { libc::geteuid() }, 900),
                None,
                deadline,
            )
        });
        started_rx.recv().unwrap();
        while Instant::now() <= deadline {
            std::thread::yield_now();
        }
        drop(held);
        worker.join().unwrap()
    });
    assert!(
        answer.is_err(),
        "late authority-store completion published a stale principal"
    );
    assert_eq!(answer.err(), Some(FailureReason::Deadline));
}

#[test]
fn strict_reader_claim_suffix_change_invalidates_selected_binding() {
    let f = fixture();
    file(&f, 100, "30", FIRST);
    f.state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO instance_claims VALUES(?1,100,'30',1,0,42)",
            [FIRST],
        )
        .unwrap();
    let db = f.state.db.clone();
    REVALIDATION_BARRIER.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(move || {
            db.lock()
                .unwrap()
                .execute("UPDATE instance_claims SET suffix=2 WHERE id=?1", [FIRST])
                .unwrap();
        }))
    });
    let reply = query(&f, 100, 900);
    assert!(
        reply.is_err(),
        "changed claim suffix constructed the old principal"
    );
    assert_eq!(reply.err(), Some(FailureReason::Changed));
}
#[test]
fn strict_reader_registry_duplicate_binding_is_ambiguous_not_first_match() {
    let f = fixture();
    file(&f, 100, "30", FIRST);
    let entry = std::fs::read(f.state.sessions_dirs[0].join("100.json")).unwrap();
    std::fs::write(f.state.sessions_dirs[0].join("duplicate.json"), entry).unwrap();
    assert_eq!(
        query(&f, 100, 900).err(),
        Some(FailureReason::Ambiguous),
        "duplicate session binding selected first source"
    );
}
#[test]
fn strict_reader_missing_session_directory_is_not_empty_authority() {
    let f = fixture();
    std::fs::remove_dir(&f.state.sessions_dirs[0]).unwrap();
    assert_eq!(
        query(&f, 100, 900).err(),
        Some(FailureReason::AuthorityUnavailable)
    );
}
#[test]
fn strict_reader_session_symlink_is_not_read_as_authority() {
    use std::os::unix::fs::symlink;
    let f = fixture();
    file(&f, 100, "30", FIRST);
    let entry = f.state.sessions_dirs[0].join("100.json");
    let external = f._dir.path().join("outside.json");
    std::fs::rename(&entry, &external).unwrap();
    symlink(external, entry).unwrap();
    assert_eq!(
        query(&f, 100, 900).err(),
        Some(FailureReason::AuthorityUnavailable)
    );
}
