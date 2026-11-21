use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use xmsg::observe_collector_store::{NodePolicy, Store};
use xmsg::observe_collector_web::{render, Filter};
use xmsg::observe_export::{EventKind, ExportPage};

const NODE: &str = "fixture.node";
const FUTURE: &str = "future_writer_fixture";

fn page(kinds: &[&str], next: i64) -> ExportPage {
    serde_json::from_value(json!({
        "v": 2, "node": NODE, "epoch": "compat-fixture", "scope": "a".repeat(64),
        "events": kinds.iter().enumerate().map(|(index, kind)| json!({
            "sequence": index + 1, "observed_at": 1000, "persisted_at": 1000,
            "kind": kind, "available": "not_recorded"
        })).collect::<Vec<_>>(),
        "next": next, "has_more": false, "gaps": [], "available": true
    }))
    .expect("fixture build does not know the writer kind")
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    assert_eq!(args.len(), 3, "usage: store-compat MODE PRIVATE_CHILD_DIR");
    let mode = args[1].as_str();
    let directory = Path::new(&args[2]);
    let input = match mode {
        "write-newer" => Some(page(&["message_recorded", FUTURE, "message_recorded"], 3)),
        "write-known" => Some(page(&["message_recorded"; 3], 3)),
        "read-unknown" | "read-newer" | "read-known" => None,
        _ => panic!("unknown fixture mode"),
    };
    let store = Store::open(
        directory,
        vec![NodePolicy {
            relay: None,
            node: NODE.into(),
            labels: false,
            supported: true,
        }],
        Arc::new(|| 1000),
    )
    .expect("fixture private store refused");
    if let Some(input) = input {
        assert_eq!(
            store.cursor(NODE).unwrap().next,
            0,
            "writer store is not fresh"
        );
        store
            .ingest_page(NODE, &store.cursor(NODE).unwrap(), input)
            .unwrap();
        assert_eq!(store.cursor(NODE).unwrap().next, 3);
        println!("writer persisted three production rows");
        return;
    }

    let hidden = store.view(Some(NODE), 200).unwrap();
    assert!(hidden[0].history_hidden && hidden[0].events.is_empty());
    store
        .ingest_page(NODE, &store.cursor(NODE).unwrap(), page(&[], 3))
        .unwrap();
    let result = store.view(Some(NODE), 200);
    assert!(
        result.is_ok(),
        "older collector rejected a newer stored kind: {result:?}"
    );
    let views = result.unwrap();
    let view = &views[0];
    assert!(!view.history_hidden);
    assert_eq!(
        view.events.len(),
        3,
        "unknown kind discarded neighboring rows"
    );
    assert_eq!(view.cursor.as_ref().unwrap().next, 3);
    for cached in &view.events {
        assert_eq!(cached.received_at, 1000, "readback refreshed receipt age");
        if cached.event.sequence != 2 || mode == "read-known" {
            assert_eq!(cached.event.kind, EventKind::MessageRecorded);
        } else if mode == "read-unknown" {
            assert_eq!(cached.event.kind, EventKind::Unknown);
        } else {
            assert_eq!(
                serde_json::to_value(cached.event.kind).unwrap(),
                json!(FUTURE)
            );
        }
    }
    if mode == "read-unknown" {
        let html = render(
            &views,
            Some(view),
            Filter {
                node: Some(0),
                page: 0,
            },
        );
        assert!(html.contains("unknown event kind (newer node)"));
        assert!(
            !html.contains(FUTURE),
            "view exposed private future-kind identifier"
        );
    }
    println!("reader validated scope and preserved three rows and their cursor");
}
