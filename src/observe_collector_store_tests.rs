use super::*;
use crate::observe_export::{Availability, EventKind};
use std::sync::atomic::{AtomicI64, Ordering};
fn private_temp() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
const NOW: i64 = 1_800_000_000;
fn fixture() -> (tempfile::TempDir, Store, Arc<AtomicI64>) {
    let dir = private_temp();
    let now = Arc::new(AtomicI64::new(NOW));
    let c = now.clone();
    let store = Store::open(
        dir.path(),
        vec![NodePolicy {
            node: "node".into(),
            labels: false,
            supported: true,
        }],
        Arc::new(move || c.load(Ordering::SeqCst)),
    )
    .unwrap();
    (dir, store, now)
}
fn page(sequence: i64) -> ExportPage {
    ExportPage {
        v: 1,
        node: "node".into(),
        epoch: "epoch".into(),
        scope: "a".repeat(64),
        events: vec![ExportEvent {
            sequence,
            source_at: Some(NOW),
            observed_at: NOW,
            persisted_at: NOW,
            kind: EventKind::MessageRecorded,
            from: Some("bot@node".into()),
            to: None,
            message_id: None,
            reply_id: None,
            thread_id: None,
            outcome: None,
            reason: None,
            available: Availability::NotRecorded,
        }],
        next: sequence,
        has_more: false,
        gaps: vec![],
        available: true,
    }
}
#[test]
fn startup_hidden_and_denial_hide_before_failed_purge() {
    let (dir, store, _) = fixture();
    store
        .ingest_page("node", &Cursor::default(), page(1))
        .unwrap();
    drop(store);
    let store = Store::open(
        dir.path(),
        vec![NodePolicy {
            node: "node".into(),
            labels: false,
            supported: true,
        }],
        Arc::new(|| NOW),
    )
    .unwrap();
    let v = store.view(None, 100).unwrap().remove(0);
    assert_eq!(
        v.status,
        NodeStatus::HiddenPendingRevalidation,
        "startup history exposed"
    );
    assert!(
        v.events.is_empty() && v.cursor.is_none(),
        "hidden history contents exposed"
    );
    let cursor = store.cursor("node").unwrap();
    let mut p = page(2);
    p.events.clear();
    store.ingest_page("node", &cursor, p).unwrap();
    store.inner.lock().unwrap().connection.as_ref().unwrap().execute_batch("CREATE TRIGGER refuse_purge BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(store.deny("node").is_err());
    assert_eq!(
        store.view(None, 100).unwrap()[0].status,
        NodeStatus::Denied,
        "failed purge unmasked history"
    );
    assert!(store.view(None, 100).unwrap()[0].events.is_empty());
}
#[test]
fn validation_is_atomic_and_filtered_progress_is_valid() {
    let (_dir, store, _) = fixture();
    let mut bad = page(1);
    bad.node = "foreign".into();
    assert!(
        store.ingest_page("node", &Cursor::default(), bad).is_err(),
        "wrong node accepted"
    );
    assert_eq!(store.cursor("node").unwrap(), Cursor::default());
    let mut filtered = page(1);
    filtered.events.clear();
    filtered.next = 20;
    store
        .ingest_page("node", &Cursor::default(), filtered)
        .unwrap();
    assert_eq!(store.cursor("node").unwrap().next, 20);
    let current = store.cursor("node").unwrap();
    assert!(
        store.ingest_page("node", &current, page(19)).is_err(),
        "backward cursor accepted"
    );
    assert_eq!(store.cursor("node").unwrap(), current);
}
#[test]
fn row_and_ttl_retention_are_honest() {
    let (_dir, store, now) = fixture();
    store
        .ingest_page("node", &Cursor::default(), page(1))
        .unwrap();
    now.store(NOW + TTL + 1, Ordering::SeqCst);
    store.maintain().unwrap();
    let v = store.view(None, 100).unwrap().remove(0);
    assert!(v.events.is_empty(), "idle TTL did not expire history");
    assert!(v.truncated, "eviction fabricated continuity");
    let count: i64 = store
        .inner
        .lock()
        .unwrap()
        .connection
        .as_ref()
        .unwrap()
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0, "idle maintenance retained expired rows");
}
fn snapshot() -> ExportSnapshot {
    use crate::observe_export::*;
    ExportSnapshot {
        v: 1,
        node: "node".into(),
        scope: "a".repeat(64),
        observed_at: NOW,
        endpoints: vec![EndpointDescriptor {
            id: "bot@node".into(),
            node: "node".into(),
            kind: EndpointKind::Service,
            harness: Harness::Unknown,
            state: RegistrationState::Unknown,
            source_at: None,
            label: None,
        }],
        truncated: false,
        available: SnapshotAvailability::Partial,
    }
}
#[test]
fn wire_fields_refuse_independently_without_cursor_changes() {
    let (_dir, store, _) = fixture();
    let mut base = serde_json::to_value(page(1)).unwrap();
    for field in ["to", "message_id", "thread_id", "reply_id"] {
        base["events"][0][field] = serde_json::Value::Null;
    }
    for (pointer, value) in [
        ("/v", serde_json::json!(2)),
        ("/node", serde_json::json!("foreign")),
        ("/epoch", serde_json::json!("")),
        ("/scope", serde_json::json!("A".repeat(64))),
        ("/next", serde_json::json!(-1)),
        ("/available", serde_json::json!(false)),
        ("/events/0/sequence", serde_json::json!(0)),
        ("/events/0/source_at", serde_json::json!(-1)),
        ("/events/0/observed_at", serde_json::json!(-1)),
        ("/events/0/persisted_at", serde_json::json!(-1)),
        ("/events/0/from", serde_json::json!("bot")),
        ("/events/0/to", serde_json::json!("svc:bot@node")),
        ("/events/0/message_id", serde_json::json!("/private")),
        ("/events/0/thread_id", serde_json::json!("a ")),
        ("/events/0/reply_id", serde_json::json!(0)),
    ] {
        let mut wire = base.clone();
        *wire
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("missing fixture field {pointer}")) = value;
        let p: ExportPage = serde_json::from_value(wire).unwrap();
        assert!(
            store.ingest_page("node", &Cursor::default(), p).is_err(),
            "invalid field accepted: {pointer}"
        );
        assert_eq!(
            store.cursor("node").unwrap(),
            Cursor::default(),
            "rejected cursor advanced"
        );
    }
}
#[test]
fn snapshot_validation_labels_and_latest_only() {
    let (_dir, store, _) = fixture();
    let mut s = snapshot();
    s.endpoints[0].label = Some("label".into());
    assert!(
        store.ingest_snapshot("node", s).is_err(),
        "labels accepted without opt-in"
    );
    store.ingest_snapshot("node", snapshot()).unwrap();
    let mut s = snapshot();
    s.endpoints.clear();
    s.truncated = true;
    store.ingest_snapshot("node", s).unwrap();
    let v = store.view(None, 100).unwrap().remove(0);
    assert!(
        v.latest_snapshot.unwrap().snapshot.endpoints.is_empty(),
        "snapshot archive retained"
    );
}
#[test]
fn scope_purge_and_epoch_preservation_and_stale() {
    let (_dir, store, _) = fixture();
    store
        .ingest_page("node", &Cursor::default(), page(1))
        .unwrap();
    let old = store.cursor("node").unwrap();
    let mut p = page(1);
    p.epoch = "new_epoch".into();
    store.ingest_page("node", &old, p).unwrap();
    let v = store.view(None, 100).unwrap().remove(0);
    assert_eq!(v.events.len(), 2, "epoch boundary destroyed history");
    assert!(
        v.gaps.iter().any(|g| g.reason == Reason::EpochChanged),
        "epoch boundary concealed"
    );
    let old = store.cursor("node").unwrap();
    let mut p = page(1);
    p.scope = "b".repeat(64);
    store.ingest_page("node", &old, p).unwrap();
    assert_eq!(
        store.view(None, 100).unwrap()[0].events.len(),
        1,
        "scope cache not purged"
    );
    store.unavailable("node", UnavailableKind::Timeout).unwrap();
    let v = store.view(None, 100).unwrap().remove(0);
    assert_eq!(v.status, NodeStatus::Stale, "timeout substituted success");
    assert!(
        !v.history_hidden && v.events.len() == 1,
        "validated stale history hidden"
    );
}
#[test]
fn transaction_failure_and_replay_never_refresh_or_split() {
    let (_dir, store, now) = fixture();
    store
        .ingest_page("node", &Cursor::default(), page(1))
        .unwrap();
    now.store(NOW + 30, Ordering::SeqCst);
    assert!(
        store
            .ingest_page("node", &Cursor::default(), page(1))
            .is_err(),
        "stale request accepted"
    );
    assert_eq!(
        store.view(None, 100).unwrap()[0].events[0].received_at,
        NOW,
        "replay refreshed age"
    );
    let current = store.cursor("node").unwrap();
    store.inner.lock().unwrap().connection.as_ref().unwrap().execute_batch("CREATE TRIGGER refuse_cursor BEFORE UPDATE OF next ON nodes BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(store.ingest_page("node", &current, page(2)).is_err());
    assert_eq!(
        store.cursor("node").unwrap(),
        current,
        "failed transaction advanced cursor"
    );
    assert_eq!(
        store.view(None, 100).unwrap()[0].events.len(),
        1,
        "failed transaction kept page"
    );
    assert!(
        store
            .inner
            .lock()
            .unwrap()
            .connection
            .as_ref()
            .unwrap()
            .is_autocommit(),
        "errored transaction resumed"
    );
}
#[test]
fn future_and_late_observation_ttl() {
    let (_dir, store, now) = fixture();
    let mut p = page(1);
    p.events[0].observed_at = NOW - TTL - 1;
    store.ingest_page("node", &Cursor::default(), p).unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].events.is_empty(),
        "late observation renewed TTL"
    );
    let old = store.cursor("node").unwrap();
    let mut p = page(2);
    p.events[0].observed_at = NOW + TTL + 100;
    store.ingest_page("node", &old, p).unwrap();
    now.store(NOW + TTL + 1, Ordering::SeqCst);
    store.maintain().unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].events.is_empty(),
        "future observation extended TTL"
    );
}
#[test]
fn independent_row_and_byte_limits_include_snapshot() {
    for (rows, bytes, expected) in [(1, BYTES, 1), (ROWS, 500, 0)] {
        let dir = private_temp();
        let store = Store::open_limits(
            dir.path(),
            vec![NodePolicy {
                node: "node".into(),
                labels: false,
                supported: true,
            }],
            Arc::new(|| NOW),
            Limits {
                rows,
                bytes,
                pages: 128,
            },
        )
        .unwrap();
        let result = store.ingest_page("node", &Cursor::default(), page(1));
        assert!(result.is_ok(), "logical eviction refused safe ingest");
        let cursor = store.cursor("node").unwrap();
        store.ingest_page("node", &cursor, page(2)).unwrap();
        if bytes == 500 {
            store.ingest_snapshot("node", snapshot()).unwrap();
        }
        let v = store.view(None, 100).unwrap().remove(0);
        assert_eq!(
            v.events.len(),
            expected,
            "retention cap ignored rows={rows} bytes={bytes}"
        );
        assert!(v.truncated, "retention omitted boundary");
    }
}
#[test]
fn private_paths_and_preexisting_physical_limits() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn open(dir: &Path) -> Result<Store, StoreError> {
        Store::open_limits(
            dir,
            vec![NodePolicy {
                node: "node".into(),
                labels: false,
                supported: true,
            }],
            Arc::new(|| NOW),
            Limits {
                rows: ROWS,
                bytes: BYTES,
                pages: 128,
            },
        )
    }
    let dir = private_temp();
    assert!(open(dir.path()).is_ok());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(open(dir.path()).is_err(), "unsafe directory mode accepted");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let db = dir.path().join("collector.sqlite");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(open(dir.path()).is_err(), "unsafe database mode accepted");
    fs::remove_file(&db).unwrap();
    symlink("other", &db).unwrap();
    assert!(open(dir.path()).is_err(), "database symlink accepted");
    fs::remove_file(&db).unwrap();
    fs::create_dir(&db).unwrap();
    assert!(open(dir.path()).is_err(), "database substitution accepted");
    fs::remove_dir(&db).unwrap();
    assert!(open(dir.path()).is_ok());
    OpenOptions::new()
        .write(true)
        .open(&db)
        .unwrap()
        .set_len(128 * 4096 + 1)
        .unwrap();
    assert!(open(dir.path()).is_err(), "oversized database accepted");
    fs::remove_file(&db).unwrap();
    let journal = dir.path().join("collector.sqlite-journal");
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&journal)
        .unwrap()
        .set_len(128 * 4104 + 131073)
        .unwrap();
    assert!(open(dir.path()).is_err(), "oversized journal accepted");
}
#[test]
fn engine_settings_journal_peak_full_abort_and_compaction() {
    let dir = private_temp();
    let store = Store::open_limits(
        dir.path(),
        vec![NodePolicy {
            node: "node".into(),
            labels: false,
            supported: true,
        }],
        Arc::new(|| NOW),
        Limits {
            rows: ROWS,
            bytes: BYTES,
            pages: 128,
        },
    )
    .unwrap();
    let mut full = false;
    for batch in 0..30 {
        let cursor = store.cursor("node").unwrap();
        let mut p = page(1);
        p.events.clear();
        for n in 1..=200 {
            let sequence = batch * 200 + n;
            let mut e = page(sequence).events.remove(0);
            e.message_id = Some("m".repeat(512));
            e.thread_id = Some("t".repeat(512));
            p.events.push(e);
        }
        p.next = (batch + 1) * 200;
        match store.ingest_page("node", &cursor, p) {
            Ok(_) => (),
            Err(StoreError::Full) => {
                assert_eq!(
                    store.cursor("node").unwrap(),
                    cursor,
                    "physical full committed cursor alone"
                );
                full = true;
                break;
            }
            Err(e) => panic!("unexpected physical-cap error: {e:?}"),
        }
    }
    assert!(full, "physical page cap not enforced");
    let db = dir.path().join("collector.sqlite");
    assert!(
        fs::metadata(&db).unwrap().len() <= 128 * 4096,
        "database file exceeded physical cap"
    );
    let before = fs::metadata(&db).unwrap().len();
    {
        let mut inner = store.inner.lock().unwrap();
        let peak = transaction(&mut inner, |c| {
            c.execute("DELETE FROM events WHERE node='node'", [])?;
            let journal = dir.path().join("collector.sqlite-journal");
            let length = fs::metadata(journal).unwrap().len();
            assert!(length > 4096, "journal positive control empty");
            assert!(
                length <= 128 * 4104 + 131072,
                "journal exceeded construction bound"
            );
            eprintln!(
                "sqlite-engine={} max_pages=128 db_before={} journal_peak={} journal_bound={}",
                rusqlite::version(),
                before,
                length,
                128 * 4104 + 131072
            );
            Ok(length)
        })
        .unwrap();
        assert!(peak > 0);
    }
    store.maintain().unwrap();
    let after = fs::metadata(&db).unwrap().len();
    assert!(after < before, "bounded compaction did not reduce file");
}
#[test]
fn secure_delete_removes_metadata_canary() {
    let (_dir, store, _) = fixture();
    let canary = "freshsyntheticmetadatacanaryuniqueforremoval";
    let mut p = page(1);
    p.events[0].message_id = Some(canary.into());
    store.ingest_page("node", &Cursor::default(), p).unwrap();
    let db = _dir.path().join("collector.sqlite");
    let contains = |bytes: Vec<u8>| bytes.windows(canary.len()).any(|b| b == canary.as_bytes());
    assert!(
        contains(fs::read(&db).unwrap()),
        "canary positive control missing"
    );
    store.deny("node").unwrap();
    assert!(
        !contains(fs::read(&db).unwrap()),
        "deleted metadata persisted in managed database"
    );
}
#[test]
fn wire_count_and_byte_caps_have_positive_controls() {
    let (_dir, store, _) = fixture();
    let policy = NodePolicy {
        node: "node".into(),
        labels: false,
        supported: true,
    };
    let mut p = page(1);
    p.events.clear();
    for i in 1..=200 {
        let mut e = page(i).events.remove(0);
        e.message_id = Some("a".repeat(512));
        e.thread_id = Some("b".repeat(512));
        p.events.push(e);
    }
    p.next = 200;
    assert!(
        validate_page(&policy, &Cursor::default(), &p).is_ok(),
        "bounded page control rejected"
    );
    p.events.push(page(201).events.remove(0));
    p.next = 201;
    assert!(
        validate_page(&policy, &Cursor::default(), &p).is_err(),
        "event count cap ignored"
    );
    p.events.pop();
    p.next = 200;
    for e in &mut p.events {
        e.from = Some(format!("{}@{}", "x".repeat(32), "n".repeat(128)));
        e.to = Some(format!("{}@{}", "y".repeat(32), "n".repeat(128)));
    }
    // Correlations and endpoints independently remain in grammar while aggregate bytes exceed the page cap.
    assert!(
        serde_json::to_vec(&p).unwrap().len() > PAGE_BYTES,
        "aggregate byte positive control too small"
    );
    assert!(
        store.ingest_page("node", &Cursor::default(), p).is_err(),
        "page byte cap ignored"
    );
}
#[test]
fn independent_string_ranges_sequence_and_snapshot_guards() {
    let (_dir, store, _) = fixture();
    let policy = NodePolicy {
        node: "node".into(),
        labels: false,
        supported: true,
    };
    for epoch in ["".into(), "x".repeat(129), "é".into(), "has space".into()] {
        let mut p = page(1);
        p.epoch = epoch;
        assert!(
            validate_page(&policy, &Cursor::default(), &p).is_err(),
            "invalid epoch accepted"
        );
    }
    for scope in [
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
    ] {
        let mut p = page(1);
        p.scope = scope;
        assert!(
            validate_page(&policy, &Cursor::default(), &p).is_err(),
            "invalid scope accepted"
        );
    }
    for id in ["".into(), "a".repeat(513), "/private".into()] {
        let mut p = page(1);
        p.events[0].message_id = Some(id);
        assert!(
            validate_page(&policy, &Cursor::default(), &p).is_err(),
            "invalid correlation accepted"
        );
    }
    for value in [-1, MAX_TIME + 1] {
        for field in ["source_at", "observed_at", "persisted_at"] {
            let mut p = page(1);
            match field {
                "source_at" => p.events[0].source_at = Some(value),
                "observed_at" => p.events[0].observed_at = value,
                _ => p.events[0].persisted_at = value,
            }
            assert!(
                validate_page(&policy, &Cursor::default(), &p).is_err(),
                "invalid timestamp accepted: {field}"
            );
        }
    }
    let mut p = page(2);
    p.next = 1;
    assert!(
        validate_page(&policy, &Cursor::default(), &p).is_err(),
        "next before visible sequence accepted"
    );
    let mut p = page(1);
    p.events.clear();
    p.next = 0;
    p.has_more = true;
    assert!(
        validate_page(&policy, &Cursor::default(), &p).is_err(),
        "nonprogress has_more accepted"
    );
    let mut p = page(1);
    p.events.push(p.events[0].clone());
    assert!(
        validate_page(&policy, &Cursor::default(), &p).is_err(),
        "unordered sequence accepted"
    );
    for field in [
        "v",
        "node",
        "scope",
        "time",
        "count",
        "id",
        "endpoint_node",
        "endpoint_time",
        "label_length",
        "label_opt_in",
        "duplicate",
    ] {
        let mut s = snapshot();
        match field {
            "v" => s.v = 2,
            "node" => s.node = "foreign".into(),
            "scope" => s.scope = "bad".into(),
            "time" => s.observed_at = -1,
            "count" => {
                let e = s.endpoints[0].clone();
                s.endpoints = (0..201)
                    .map(|i| {
                        let mut e = e.clone();
                        e.id = format!("svc{i}@node");
                        e
                    })
                    .collect();
            }
            "id" => s.endpoints[0].id = "bot".into(),
            "endpoint_node" => s.endpoints[0].node = "foreign".into(),
            "endpoint_time" => s.endpoints[0].source_at = Some(NOW + 1),
            "label_length" => s.endpoints[0].label = Some("a".repeat(257)),
            "label_opt_in" => s.endpoints[0].label = Some("label".into()),
            _ => s.endpoints.push(s.endpoints[0].clone()),
        }
        let mut labels = policy.clone();
        labels.labels = field == "label_length";
        assert!(
            validate_snapshot(&labels, &s).is_err(),
            "invalid snapshot accepted: {field}"
        );
    }
    assert_eq!(store.cursor("node").unwrap(), Cursor::default());
}
#[test]
fn repeated_epoch_records_deduplicate_without_refresh() {
    let (_dir, store, now) = fixture();
    store
        .ingest_page("node", &Cursor::default(), page(1))
        .unwrap();
    let current = store.cursor("node").unwrap();
    let mut p = page(1);
    p.epoch = "other".into();
    store.ingest_page("node", &current, p).unwrap();
    now.store(NOW + 30, Ordering::SeqCst);
    let current = store.cursor("node").unwrap();
    let _out = store.ingest_page("node", &current, page(1)).unwrap();
    let v = store.view(None, 100).unwrap().remove(0);
    assert_eq!(v.events.len(), 2, "replayed record duplicated");
    assert!(
        v.events.iter().all(|e| e.received_at == NOW),
        "replayed record refreshed retention age"
    );
}
#[test]
fn rollback_failure_closes_connection_and_restart_revalidates() {
    use std::ffi::{c_char, c_int, c_void, CStr};
    unsafe extern "C" fn authorizer(
        _: *mut c_void,
        action: c_int,
        arg: *const c_char,
        _: *const c_char,
        _: *const c_char,
        _: *const c_char,
    ) -> c_int {
        if action == rusqlite::ffi::SQLITE_TRANSACTION
            && !arg.is_null()
            && unsafe { CStr::from_ptr(arg) }.to_bytes() == b"ROLLBACK"
        {
            rusqlite::ffi::SQLITE_DENY
        } else {
            rusqlite::ffi::SQLITE_OK
        }
    }
    let (dir, store, _) = fixture();
    store
        .ingest_page("node", &Cursor::default(), page(1))
        .unwrap();
    let cursor = store.cursor("node").unwrap();
    {
        let inner = store.inner.lock().unwrap();
        let c = inner.connection.as_ref().unwrap();
        c.execute_batch("CREATE TRIGGER refuse_cursor BEFORE UPDATE OF next ON nodes BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert_eq!(
            unsafe {
                rusqlite::ffi::sqlite3_set_authorizer(
                    c.handle(),
                    Some(authorizer),
                    std::ptr::null_mut(),
                )
            },
            rusqlite::ffi::SQLITE_OK
        );
    }
    assert!(store.ingest_page("node", &cursor, page(2)).is_err());
    assert!(
        store.inner.lock().unwrap().connection.is_none(),
        "failed rollback connection remained writable"
    );
    drop(store);
    let store = Store::open(
        dir.path(),
        vec![NodePolicy {
            node: "node".into(),
            labels: false,
            supported: true,
        }],
        Arc::new(|| NOW),
    )
    .unwrap();
    assert_eq!(
        store.cursor("node").unwrap(),
        cursor,
        "restart retained uncommitted cursor"
    );
    assert!(
        store.view(None, 100).unwrap()[0].history_hidden,
        "restart bypassed revalidation"
    );
}
#[test]
fn scope_purge_failure_masks_before_sql_and_restarts_hidden() {
    let (dir, store, _) = fixture();
    store
        .ingest_page("node", &Cursor::default(), page(1))
        .unwrap();
    let cursor = store.cursor("node").unwrap();
    store.inner.lock().unwrap().connection.as_ref().unwrap().execute_batch("CREATE TRIGGER refuse_purge BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    let mut p = page(1);
    p.scope = "b".repeat(64);
    assert!(store.ingest_page("node", &cursor, p).is_err());
    let v = store.view(None, 100).unwrap().remove(0);
    assert!(
        v.history_hidden
            && v.events.is_empty()
            && v.latest_snapshot.is_none()
            && v.cursor.is_none()
            && v.gaps.is_empty(),
        "scope purge failure exposed retained history"
    );
    drop(store);
    let store = Store::open(
        dir.path(),
        vec![NodePolicy {
            node: "node".into(),
            labels: false,
            supported: true,
        }],
        Arc::new(|| NOW),
    )
    .unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].history_hidden,
        "failed purge restart exposed history"
    );
}
#[test]
fn authenticated_cursor_ahead_resets_and_conflicting_replay_refuses() {
    let (_dir, store, now) = fixture();
    let mut p = page(1);
    p.next = 10;
    store.ingest_page("node", &Cursor::default(), p).unwrap();
    now.store(NOW + 30, Ordering::SeqCst);
    let mut p = page(1);
    p.gaps.push(ExportGap {
        reason: Reason::CursorAhead,
        unknown_loss: false,
    });
    let cursor = store.cursor("node").unwrap();
    let result = store.ingest_page("node", &cursor, p.clone());
    assert!(result.is_ok(), "cursor ahead reset rejected");
    assert_eq!(store.cursor("node").unwrap().next, 1);
    assert_eq!(
        store.view(None, 100).unwrap()[0].events[0].received_at,
        NOW,
        "cursor reset refreshed receipt"
    );
    p.events[0].message_id = Some("changed".into());
    let cursor = store.cursor("node").unwrap();
    assert!(
        store.ingest_page("node", &cursor, p).is_err(),
        "conflicting replay accepted"
    );
    assert_eq!(
        store.cursor("node").unwrap(),
        cursor,
        "conflicting replay advanced cursor"
    );
}
#[test]
fn snapshot_budget_and_replay_receipt_are_independent() {
    let dir = private_temp();
    let now = Arc::new(AtomicI64::new(NOW));
    let clock = now.clone();
    let store = Store::open_limits(
        dir.path(),
        vec![NodePolicy {
            node: "node".into(),
            labels: true,
            supported: true,
        }],
        Arc::new(move || clock.load(Ordering::SeqCst)),
        Limits {
            rows: ROWS,
            bytes: 1000,
            pages: 128,
        },
    )
    .unwrap();
    store
        .ingest_page("node", &Cursor::default(), page(1))
        .unwrap();
    assert_eq!(
        store.view(None, 100).unwrap()[0].events.len(),
        1,
        "snapshot budget positive control missing"
    );
    let mut s = snapshot();
    s.endpoints[0].label = Some("a".repeat(256));
    store.ingest_snapshot("node", s.clone()).unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].events.is_empty(),
        "snapshot bytes omitted from budget"
    );
    now.store(NOW + 30, Ordering::SeqCst);
    store.ingest_snapshot("node", s).unwrap();
    assert_eq!(
        store.view(None, 100).unwrap()[0]
            .latest_snapshot
            .as_ref()
            .unwrap()
            .received_at,
        NOW,
        "snapshot replay refreshed receipt"
    );
}
#[test]
fn identical_future_snapshot_cannot_renew_after_idle_expiry() {
    let (_dir, store, now) = fixture();
    let mut s = snapshot();
    s.observed_at = NOW + 100 * 86400;
    store.ingest_snapshot("node", s.clone()).unwrap();
    now.store(NOW + TTL + 1, Ordering::SeqCst);
    store.maintain().unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].latest_snapshot.is_none(),
        "snapshot expiry control failed"
    );
    store.ingest_snapshot("node", s.clone()).unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].latest_snapshot.is_none(),
        "expired future snapshot replay resurrected cache"
    );
    s.observed_at += 1;
    store.ingest_snapshot("node", s).unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].latest_snapshot.is_some(),
        "new observation reused expired watermark"
    );
    assert_eq!(
        store.view(None, 100).unwrap()[0]
            .latest_snapshot
            .as_ref()
            .unwrap()
            .received_at,
        NOW + TTL + 1,
        "new observation reused old snapshot receipt"
    );
}
#[test]
fn removed_inventory_is_purged_on_restart_and_retained_nodes_expire() {
    for keep_old in [true, false] {
        let dir = private_temp();
        let policies = vec![
            NodePolicy {
                node: "node".into(),
                labels: false,
                supported: true,
            },
            NodePolicy {
                node: "other".into(),
                labels: false,
                supported: true,
            },
        ];
        let store = Store::open(dir.path(), policies.clone(), Arc::new(|| NOW)).unwrap();
        store
            .ingest_page("node", &Cursor::default(), page(1))
            .unwrap();
        store.ingest_snapshot("node", snapshot()).unwrap();
        drop(store);
        let configured = if keep_old {
            policies
        } else {
            vec![policies[1].clone()]
        };
        let store = Store::open(dir.path(), configured, Arc::new(|| NOW + TTL + 1)).unwrap();
        store.maintain().unwrap();
        let inner = store.inner.lock().unwrap();
        let c = inner.connection.as_ref().unwrap();
        let events: i64 = c
            .query_row("SELECT count(*) FROM events WHERE node='node'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let snapshots: i64 = c
            .query_row(
                "SELECT count(*) FROM nodes WHERE node='node' AND snapshot IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            events, 0,
            "removed inventory events persisted keep_old={keep_old}"
        );
        assert_eq!(
            snapshots, 0,
            "removed inventory snapshot persisted keep_old={keep_old}"
        );
    }
}
#[test]
fn startup_replaces_full_inventory_and_refuses_oversized_legacy_inventory() {
    let dir = private_temp();
    let policies = |offset| {
        (offset..offset + 64)
            .map(|i| NodePolicy {
                node: format!("node{i}"),
                labels: false,
                supported: true,
            })
            .collect()
    };
    let store = Store::open(dir.path(), policies(0), Arc::new(|| NOW)).unwrap();
    let mut p = page(1);
    p.node = "node0".into();
    store.ingest_page("node0", &Cursor::default(), p).unwrap();
    let mut s = snapshot();
    s.node = "node0".into();
    store.ingest_snapshot("node0", s).unwrap();
    drop(store);
    let store = Store::open(dir.path(), policies(64), Arc::new(|| NOW)).unwrap();
    {
        let inner = store.inner.lock().unwrap();
        let c = inner.connection.as_ref().unwrap();
        let nodes: i64 = c
            .query_row("SELECT count(*) FROM nodes", [], |r| r.get(0))
            .unwrap();
        let events: i64 = c
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(nodes, 64, "replaced inventory retained old control rows");
        assert_eq!(events, 0, "replaced inventory retained old events");
        c.execute("INSERT INTO nodes(node) VALUES('extra')", [])
            .unwrap();
    }
    drop(store);
    assert!(
        matches!(
            Store::open(dir.path(), policies(64), Arc::new(|| NOW)),
            Err(StoreError::Storage)
        ),
        "oversized stored inventory accepted"
    );
}
#[test]
fn snapshot_watermark_survives_restart_and_authority_changes_reset_it() {
    let (dir, store, now) = fixture();
    let mut s = snapshot();
    s.observed_at = NOW + 100 * 86400;
    store.ingest_snapshot("node", s.clone()).unwrap();
    now.store(NOW + TTL + 1, Ordering::SeqCst);
    store.maintain().unwrap();
    drop(store);
    let clock = now.clone();
    let store = Store::open(
        dir.path(),
        vec![NodePolicy {
            node: "node".into(),
            labels: false,
            supported: true,
        }],
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].history_hidden,
        "watermark restart unmasked history"
    );
    store.ingest_snapshot("node", s.clone()).unwrap();
    assert!(
        store.view(None, 100).unwrap()[0].latest_snapshot.is_none(),
        "restart forgot expired snapshot watermark"
    );
    now.fetch_add(30, Ordering::SeqCst);
    s.scope = "b".repeat(64);
    store.ingest_snapshot("node", s.clone()).unwrap();
    assert_eq!(
        store.view(None, 100).unwrap()[0]
            .latest_snapshot
            .as_ref()
            .unwrap()
            .received_at,
        NOW + TTL + 31,
        "scope change retained old snapshot receipt"
    );
    store.deny("node").unwrap();
    let count: i64 = store
        .inner
        .lock()
        .unwrap()
        .connection
        .as_ref()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM nodes WHERE snapshot_fingerprint IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "denial retained snapshot watermark");
    now.fetch_add(30, Ordering::SeqCst);
    store.ingest_snapshot("node", s).unwrap();
    assert_eq!(
        store.view(None, 100).unwrap()[0]
            .latest_snapshot
            .as_ref()
            .unwrap()
            .received_at,
        NOW + TTL + 61,
        "denial retained old snapshot receipt"
    );
}
#[test]
fn snapshot_control_counts_toward_bytes_and_survives_blob_byte_eviction() {
    for cap in [270, 500] {
        let dir = private_temp();
        let now = Arc::new(AtomicI64::new(NOW));
        let clock = now.clone();
        let store = Store::open_limits(
            dir.path(),
            vec![NodePolicy {
                node: "node".into(),
                labels: true,
                supported: true,
            }],
            Arc::new(move || clock.load(Ordering::SeqCst)),
            Limits {
                rows: ROWS,
                bytes: cap,
                pages: 128,
            },
        )
        .unwrap();
        let mut s = snapshot();
        s.observed_at = NOW + 100 * 86400;
        s.endpoints[0].label = Some("a".repeat(256));
        let result = store.ingest_snapshot("node", s.clone());
        if cap == 270 {
            assert!(
                matches!(result, Err(StoreError::Full)),
                "snapshot control bytes omitted from budget"
            );
            assert_eq!(
                store.cursor("node").unwrap(),
                Cursor::default(),
                "control full advanced cursor"
            );
        } else {
            result.unwrap();
            assert!(
                store.view(None, 100).unwrap()[0].latest_snapshot.is_none(),
                "snapshot byte eviction control failed"
            );
            now.store(NOW + 30, Ordering::SeqCst);
            store.ingest_snapshot("node", s).unwrap();
            let receipt: i64 = store
                .inner
                .lock()
                .unwrap()
                .connection
                .as_ref()
                .unwrap()
                .query_row(
                    "SELECT snapshot_receipt FROM nodes WHERE node='node'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(receipt, NOW, "byte eviction forgot snapshot first receipt");
        }
    }
}
#[test]
fn collector_directory_special_mode_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = private_temp();
    let store = journal_store(dir.path());
    drop(store);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o1700)).unwrap();
    assert!(
        crate::agent::ensure_secure_socket_dir(dir.path(), unsafe { libc::geteuid() }).is_ok(),
        "inherited ordinary-mode control rejected sticky directory"
    );
    let result = Store::open(
        dir.path(),
        vec![NodePolicy {
            node: "node".into(),
            labels: false,
            supported: true,
        }],
        Arc::new(|| NOW),
    );
    assert!(
        matches!(result, Err(StoreError::UnsafePath)),
        "state directory special mode accepted"
    );
}
#[test]
fn inherited_directory_predicates_use_real_metadata() {
    use std::os::unix::fs::PermissionsExt;
    let dir = private_temp();
    let uid = unsafe { libc::geteuid() };
    assert!(
        crate::agent::ensure_secure_socket_dir(dir.path(), uid).is_ok(),
        "secure directory control refused"
    );
    assert!(
        crate::agent::ensure_secure_socket_dir(dir.path(), uid.wrapping_add(1)).is_err(),
        "inherited directory owner mismatch accepted"
    );
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        crate::agent::ensure_secure_socket_dir(dir.path(), uid).is_err(),
        "inherited directory mode accepted"
    );
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.path().join("regular");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&file)
        .unwrap();
    assert!(
        crate::agent::ensure_secure_socket_dir(&file, uid).is_err(),
        "inherited directory type accepted"
    );
}
#[test]
fn private_file_metadata_predicates_use_real_metadata() {
    use std::os::unix::fs::PermissionsExt;
    let dir = private_temp();
    let uid = unsafe { libc::geteuid() };
    let file = dir.path().join("file");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .unwrap()
        .set_len(100)
        .unwrap();
    let metadata = fs::symlink_metadata(&file).unwrap();
    assert!(
        private_file_metadata(&metadata, uid, 100).is_ok(),
        "private file exact-boundary control refused"
    );
    assert!(
        private_file_metadata(&metadata, uid.wrapping_add(1), 100).is_err(),
        "private file owner mismatch accepted"
    );
    assert!(
        private_file_metadata(&metadata, uid, 99).is_err(),
        "private file length accepted"
    );
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        private_file_metadata(&fs::symlink_metadata(&file).unwrap(), uid, 100).is_err(),
        "private file mode accepted"
    );
    let substitute = dir.path().join("directory");
    fs::create_dir(&substitute).unwrap();
    fs::set_permissions(&substitute, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        private_file_metadata(&fs::symlink_metadata(substitute).unwrap(), uid, u64::MAX).is_err(),
        "private file type accepted"
    );
}
fn journal_store(dir: &Path) -> Store {
    Store::open_limits(
        dir,
        vec![NodePolicy {
            node: "node".into(),
            labels: false,
            supported: true,
        }],
        Arc::new(|| NOW),
        Limits {
            rows: ROWS,
            bytes: BYTES,
            pages: 128,
        },
    )
    .unwrap()
}
fn journal_seed(store: &Store) -> Cursor {
    let mut p = page(1);
    p.events = (1..=200)
        .map(|i| {
            let mut event = page(i).events.remove(0);
            event.message_id = Some("m".repeat(512));
            event.thread_id = Some("t".repeat(512));
            event
        })
        .collect();
    p.next = 200;
    store.ingest_page("node", &Cursor::default(), p).unwrap();
    store.ingest_snapshot("node", snapshot()).unwrap();
    store.cursor("node").unwrap()
}
#[test]
fn journal_failure_barrier_bounds_abort_and_reopen() {
    use std::ffi::{c_char, c_int, c_void, CStr};
    struct Barrier {
        journal: std::path::PathBuf,
        samples: Mutex<Vec<u64>>,
        deny_rollback: bool,
    }
    unsafe extern "C" fn authorize(
        ctx: *mut c_void,
        action: c_int,
        arg: *const c_char,
        column: *const c_char,
        _: *const c_char,
        _: *const c_char,
    ) -> c_int {
        let barrier = unsafe { &*(ctx as *const Barrier) };
        let value = if arg.is_null() {
            b"".as_slice()
        } else {
            unsafe { CStr::from_ptr(arg) }.to_bytes()
        };
        let column = if column.is_null() {
            b"".as_slice()
        } else {
            unsafe { CStr::from_ptr(column) }.to_bytes()
        };
        let update =
            action == rusqlite::ffi::SQLITE_UPDATE && value == b"nodes" && column == b"next";
        let rollback = action == rusqlite::ffi::SQLITE_TRANSACTION && value == b"ROLLBACK";
        if update || rollback {
            let length = fs::metadata(&barrier.journal).map_or(0, |m| m.len());
            if let Ok(mut samples) = barrier.samples.lock() {
                samples.push(length);
            }
        }
        if update || (rollback && barrier.deny_rollback) {
            rusqlite::ffi::SQLITE_DENY
        } else {
            rusqlite::ffi::SQLITE_OK
        }
    }
    for deny_rollback in [false, true] {
        let dir = private_temp();
        let mut barrier = Box::new(Barrier {
            journal: dir.path().join("collector.sqlite-journal"),
            samples: Mutex::new(Vec::new()),
            deny_rollback,
        });
        let store = journal_store(dir.path());
        let cursor = journal_seed(&store);
        {
            let inner = store.inner.lock().unwrap();
            let c = inner.connection.as_ref().unwrap();
            assert_eq!(
                unsafe {
                    rusqlite::ffi::sqlite3_set_authorizer(
                        c.handle(),
                        Some(authorize),
                        (&mut *barrier as *mut Barrier).cast(),
                    )
                },
                rusqlite::ffi::SQLITE_OK
            );
        }
        for _ in 0..if deny_rollback { 1 } else { 3 } {
            assert!(
                store.ingest_page("node", &cursor, page(201)).is_err(),
                "failure barrier did not reject cursor statement"
            );
            let inner = store.inner.lock().unwrap();
            if deny_rollback {
                assert!(
                    inner.connection.is_none(),
                    "failed rollback retained writable connection"
                );
            } else {
                assert!(
                    inner.connection.as_ref().unwrap().is_autocommit(),
                    "error resumed live transaction"
                );
            }
        }
        let samples = barrier.samples.lock().unwrap().clone();
        assert!(samples.len() >= 2, "journal failure barrier not reached");
        assert!(
            samples.iter().all(|&n| n > 0 && n <= 128 * 4104 + 131072),
            "journal failure barrier exceeded bound"
        );
        assert!(
            samples.iter().all(|&n| n == samples[0]),
            "journal accumulated across aborted transactions"
        );
        eprintln!("journal-error engine={} deny_rollback={} before_failure_lengths={:?} bound={} observation=authorizer_barrier",rusqlite::version(),deny_rollback,samples,128*4104+131072);
        {
            let inner = store.inner.lock().unwrap();
            if let Some(c) = inner.connection.as_ref() {
                assert_eq!(
                    unsafe {
                        rusqlite::ffi::sqlite3_set_authorizer(
                            c.handle(),
                            None,
                            std::ptr::null_mut(),
                        )
                    },
                    rusqlite::ffi::SQLITE_OK
                );
            }
        }
        drop(store);
        drop(barrier);
        let reopened = journal_store(dir.path());
        assert_eq!(
            reopened.cursor("node").unwrap(),
            cursor,
            "error reopen changed cursor"
        );
        let inner = reopened.inner.lock().unwrap();
        let c = inner.connection.as_ref().unwrap();
        let count: i64 = c
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 200, "error reopen changed page");
        drop(inner);
        assert!(
            reopened.view(None, 200).unwrap()[0].history_hidden,
            "error reopen exposed cached history"
        );
    }
}
#[test]
fn journal_crash_child_fixture() {
    let Some(dir) = std::env::var_os("XMSG_TEST_COLLECTOR_JOURNAL_CRASH_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let store = journal_store(&dir);
    let inner = store.inner.lock().unwrap();
    let c = inner.connection.as_ref().unwrap();
    c.execute_batch("BEGIN IMMEDIATE; DELETE FROM events WHERE node='node'; UPDATE nodes SET next=999,snapshot=NULL WHERE node='node';").unwrap();
    let length = fs::metadata(dir.join("collector.sqlite-journal"))
        .unwrap()
        .len();
    assert!(length > 0 && length <= 128 * 4104 + 131072);
    fs::write(dir.join("child-ready"), length.to_string()).unwrap();
    unsafe { libc::_exit(73) };
}
#[test]
fn uncommitted_child_crash_journal_is_bounded_and_recovers_hidden() {
    let dir = private_temp();
    let store = journal_store(dir.path());
    let cursor = journal_seed(&store);
    drop(store);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "observe_collector_store::tests::journal_crash_child_fixture",
            "--exact",
            "--nocapture",
        ])
        .env("XMSG_TEST_COLLECTOR_JOURNAL_CRASH_DIR", dir.path())
        .spawn()
        .unwrap();
    let child_pid = child.id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while child.try_wait().unwrap().is_none()
                && std::time::Instant::now() < cleanup_deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("journal fixture child exceeded bounded wait pid={child_pid}");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert_eq!(
        status.code(),
        Some(73),
        "child did not stop inside uncommitted transaction"
    );
    let journal = dir.path().join("collector.sqlite-journal");
    let observed = fs::metadata(&journal).unwrap().len();
    let recorded: u64 = fs::read_to_string(dir.path().join("child-ready"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(observed, recorded, "producer journal marker disagrees");
    assert!(
        recorded > 0 && recorded <= 128 * 4104 + 131072,
        "crash journal exceeded bound"
    );
    use std::io::Read;
    let mut magic = [0u8; 8];
    fs::File::open(&journal)
        .unwrap()
        .read_exact(&mut magic)
        .unwrap();
    let magic_valid = magic == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
    eprintln!("journal-crash engine={} child_pid={} exit=73 journal_length={} bound={} synced_hot_header={} observation=post_child_exit_preopen",rusqlite::version(),child_pid,recorded,128*4104+131072,magic_valid);
    let reopened = journal_store(dir.path());
    assert_eq!(
        reopened.cursor("node").unwrap(),
        cursor,
        "crash recovery changed cursor"
    );
    let inner = reopened.inner.lock().unwrap();
    let c = inner.connection.as_ref().unwrap();
    let (events,snapshots):(i64,i64)=c.query_row("SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM nodes WHERE snapshot IS NOT NULL)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!(events, 200, "crash recovery changed page");
    assert_eq!(snapshots, 1, "crash recovery changed snapshot");
    drop(inner);
    assert!(
        reopened.view(None, 200).unwrap()[0].history_hidden,
        "crash recovery exposed history before revalidation"
    );
    assert!(
        fs::metadata(&journal).map_or(true, |m| m.len() <= 128 * 4104 + 131072),
        "recovery grew journal beyond bound"
    );
}
