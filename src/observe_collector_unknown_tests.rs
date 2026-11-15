use crate::observe_collector_decode::decode_page;
use crate::observe_collector_store::{NodePolicy, Store, StoreError};
use crate::observe_collector_web::{render, Filter};
use crate::observe_export::EventKind;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

const NODE: &str = "fixture.node";
fn packet(kind: &str) -> Value {
    json!({"v":1,"node":NODE,"epoch":"future-epoch","scope":"a".repeat(64),
        "events":[
            {"sequence":1,"observed_at":1000,"persisted_at":1000,"kind":"message_recorded","available":"not_recorded"},
            {"sequence":2,"observed_at":1000,"persisted_at":1000,"kind":kind,"available":"not_recorded"},
            {"sequence":3,"observed_at":1000,"persisted_at":1000,"kind":"arrival","available":"not_recorded"}],
        "next":3,"has_more":false,"gaps":[],"available":true})
}
fn fixture() -> (tempfile::TempDir, Store, Arc<AtomicI64>) {
    let directory = tempfile::tempdir().unwrap();
    let now = Arc::new(AtomicI64::new(1000));
    let clock = now.clone();
    let store = Store::open(
        &directory.path().join("state"),
        vec![NodePolicy {
            node: NODE.into(),
            labels: false,
            supported: true,
        }],
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .unwrap();
    (directory, store, now)
}
fn ingest(
    store: &Store,
    value: Value,
) -> Result<crate::observe_collector_store::CommitOutcome, StoreError> {
    let decoded = decode_page(&serde_json::to_vec(&value).unwrap()).unwrap();
    store.ingest_decoded_page(NODE, &store.cursor(NODE).unwrap(), decoded)
}
fn stored(directory: &tempfile::TempDir) -> (Vec<u8>, i64, i64, i64) {
    let connection = rusqlite::Connection::open_with_flags(
        directory.path().join("state/collector.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    connection
        .query_row(
            "SELECT json,receipt,base,bytes FROM events WHERE sequence=2",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

#[test]
fn unknown_kind_storage_rendering_and_exact_replay() {
    let (directory, store, now) = fixture();
    let input = packet("future_delivery");
    assert_eq!(ingest(&store, input.clone()).unwrap().inserted, 3);
    let views = store.view(Some(NODE), 200).unwrap();
    assert_eq!(views[0].events.len(), 3);
    let unknown = views[0]
        .events
        .iter()
        .find(|row| row.event.sequence == 2)
        .unwrap();
    assert_eq!(unknown.event.kind, EventKind::Unknown);
    assert!(views[0]
        .events
        .iter()
        .any(|row| row.event.kind == EventKind::Arrival));
    let html = render(
        &views,
        views.first(),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    assert!(
        html.contains("unknown event kind (newer node)"),
        "unknown caption missing"
    );
    assert!(
        !html.contains("future_delivery"),
        "private kind name reached view"
    );
    let before = stored(&directory);
    assert_eq!(
        serde_json::from_slice::<Value>(&before.0).unwrap()["kind"],
        "future_delivery"
    );
    now.store(1010, Ordering::SeqCst);
    let mut replay = input;
    replay["gaps"] = json!([{"reason":"cursor_ahead","unknown_loss":true}]);
    assert_eq!(
        ingest(&store, replay.clone()).unwrap().inserted,
        0,
        "future replay was not duplicate"
    );
    assert_eq!(
        stored(&directory),
        before,
        "replay changed stored envelope or receipt/base/accounting"
    );
    replay["events"][1]["kind"] = json!("different_future");
    assert!(
        matches!(ingest(&store, replay), Err(StoreError::Invalid)),
        "changed unknown kind was accepted as duplicate"
    );
    assert_eq!(stored(&directory), before);
}

#[test]
fn unknown_kind_does_not_bypass_semantic_envelope_validation() {
    for (field, bad) in [
        ("observed_at", json!(-1)),
        ("from", json!("/private")),
        ("message_id", json!("bad/path")),
    ] {
        let (_directory, store, _) = fixture();
        let mut input = packet("future_delivery");
        input["events"][1][field] = bad;
        assert!(
            matches!(ingest(&store, input), Err(StoreError::Invalid)),
            "unknown kind bypassed {field}"
        );
        assert_eq!(store.cursor(NODE).unwrap().next, 0);
        assert!(store.view(Some(NODE), 200).unwrap()[0].history_hidden);
    }
}
