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
        store
            .ingest_page("node", &Cursor::default(), page(1))
            .unwrap();
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
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
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
