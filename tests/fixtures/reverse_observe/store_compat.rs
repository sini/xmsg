use serde_json::json;
use std::path::Path;
use std::sync::Arc;
#[cfg(candidate)]
use xmsg::observe_collector_store::RelayOrigin;
use xmsg::observe_collector_store::{NodePolicy, Store};
use xmsg::observe_collector_web::{render, Filter};
use xmsg::observe_export::{ExportPage, ExportSnapshot};

const DIRECT: &str = "direct.node";
const LEAF: &str = "leaf.node";
const HUB: &str = "spiffe://fleet.example/host/hub/user/owner";

fn policy(node: &str, relay: bool, supported: bool) -> NodePolicy {
    #[cfg(not(candidate))]
    assert!(!relay);
    NodePolicy {
        node: node.into(),
        labels: false,
        supported,
        #[cfg(candidate)]
        relay: relay.then(|| RelayOrigin {
            hub: HUB.into(),
            leaf: "spiffe://fleet.example/host/node/user/leaf".into(),
        }),
    }
}
fn page(node: &str, write: bool) -> ExportPage {
    #[cfg(candidate)]
    let v = 2;
    #[cfg(not(candidate))]
    let v = 1;
    serde_json::from_value(json!({"v":v,"node":node,"epoch":"downgrade-fixture",
        "scope":"a".repeat(64),"events":if write {vec![json!({"sequence":1,
        "observed_at":1000,"persisted_at":1000,"kind":"message_recorded",
        "available":"not_recorded"})]} else {vec![]},"next":1,"has_more":false,
        "gaps":[],"available":true}))
    .unwrap()
}
fn snapshot(node: &str) -> ExportSnapshot {
    #[cfg(candidate)]
    return serde_json::from_value(json!({"v":2,"node":node,"scope":"a".repeat(64),
        "observed_at":1000,"endpoints":[],"truncated":false,"available":"partial",
        "activity":{"status":"disabled","complete":true}}))
    .unwrap();
    #[cfg(not(candidate))]
    serde_json::from_value(json!({"v":1,"node":node,"scope":"a".repeat(64),
        "observed_at":1000,"endpoints":[],"truncated":false,"available":"partial"}))
    .unwrap()
}
fn validate(store: &Store, node: &str) {
    store
        .ingest_page(node, &store.cursor(node).unwrap(), page(node, false))
        .unwrap();
}
fn write(store: &Store, node: &str) {
    store
        .ingest_page(node, &store.cursor(node).unwrap(), page(node, true))
        .unwrap();
    store.ingest_snapshot(node, snapshot(node)).unwrap();
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "nonce" {
        println!("{}", env!("REVERSE_BUILD_NONCE"));
        return;
    }
    assert_eq!(args.len(), 3);
    let mode = args[1].as_str();
    let relay = matches!(mode, "write" | "upgrade");
    let supported = mode != "saved";
    let store = Store::open(
        Path::new(&args[2]),
        vec![policy(DIRECT, false, true), policy(LEAF, relay, supported)],
        Arc::new(|| 1000),
    )
    .unwrap();
    match mode {
        "write" => {
            write(&store, DIRECT);
            write(&store, LEAF);
        }
        "saved" | "direct" => {
            validate(&store, DIRECT);
            let direct = store.view(Some(DIRECT), 200).unwrap();
            assert_eq!(direct[0].events.len(), 1, "neighboring direct event lost");
            assert!(
                direct[0].latest_snapshot.is_some(),
                "neighboring direct snapshot lost"
            );
            if mode == "direct" {
                validate(&store, LEAF);
            }
            let views = store.view(None, 200).unwrap();
            let leaf = views.iter().find(|v| v.node == LEAF).unwrap();
            assert!(
                leaf.events.is_empty() && leaf.latest_snapshot.is_none(),
                "OLD READER LEAK: relayed history rendered as direct after fresh validation"
            );
            let html = render(
                &views,
                Some(leaf),
                Filter {
                    node: Some(1),
                    page: 0,
                },
            );
            assert!(!html.contains(HUB), "old view retained relay origin");
            println!("OLD READER SAFE: relay event/snapshot absent; direct control survived");
        }
        "upgrade" => {
            assert_eq!(
                store.cursor(LEAF).unwrap().next,
                0,
                "downgrade retained relay cursor"
            );
            write(&store, LEAF);
            validate(&store, DIRECT);
            let views = store.view(None, 200).unwrap();
            let leaf = views.iter().find(|v| v.node == LEAF).unwrap();
            assert_eq!(leaf.events.len(), 1);
            #[cfg(candidate)]
            {
                assert_eq!(leaf.events[0].origin_hub.as_deref(), Some(HUB));
                assert_eq!(
                    leaf.latest_snapshot.as_ref().unwrap().origin_hub.as_deref(),
                    Some(HUB)
                );
            }
            let html = render(
                &views,
                Some(leaf),
                Filter {
                    node: Some(1),
                    page: 0,
                },
            );
            assert!(
                html.contains(HUB) && html.contains("via"),
                "fresh upgrade lost via-hub view"
            );
            println!("FRESH UPGRADE SAFE: new relay event/snapshot carry via-hub provenance");
        }
        _ => panic!("unknown mode"),
    }
}
