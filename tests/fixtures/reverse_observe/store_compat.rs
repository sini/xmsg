use serde_json::json;
use std::path::Path;
use std::sync::Arc;
#[cfg(candidate)]
use xmsg::observe_collector_store::RelayOrigin;
use xmsg::observe_collector_store::{NodePolicy, Store};
use xmsg::observe_collector_web::{render, Filter};
use xmsg::observe_export::{ExportPage, ExportSnapshot};

const DIRECT: &str = "direct.node";
const DIRECT_VALID: &str = "direct-valid.node";
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
        if matches!(mode, "refresh_write" | "refresh_old" | "refresh_read") {
            vec![policy(DIRECT, false, true), policy(DIRECT_VALID, false, true)]
        } else {
            vec![policy(DIRECT, false, true), policy(LEAF, relay, supported)]
        },
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
        #[cfg(candidate)]
        "refresh_write" => {
            for (node, ep_id, state_json) in [
                (
                    DIRECT,
                    "claude-1@direct.node",
                    json!({
                        "state": "working",
                        "state_epoch": "1".repeat(32),
                        "changed_at": 950,
                        "fresh_at": 990,
                        "incarnation": 1,
                        "revision": 1
                    }),
                ),
                (
                    DIRECT_VALID,
                    "claude-2@direct-valid.node",
                    json!({
                        "state": "blocked",
                        "block": "permission",
                        "state_epoch": "2".repeat(32),
                        "changed_at": 960,
                        "fresh_at": 995,
                        "incarnation": 1,
                        "revision": 1
                    }),
                ),
            ] {
                validate(&store, node);
                let snap: ExportSnapshot = serde_json::from_value(json!({
                    "v": 2,
                    "node": node,
                    "scope": "a".repeat(64),
                    "observed_at": 1000,
                    "endpoints": [{
                        "id": ep_id,
                        "node": node,
                        "kind": "instance",
                        "harness": "claude",
                        "state": "registered",
                        "activity": state_json
                    }],
                    "truncated": false,
                    "available": "available",
                    "activity": {"status": "enabled", "complete": true}
                }))
                .unwrap();
                store.ingest_snapshot(node, snap).unwrap();
            }
            let views = store.view(None, 200).unwrap();
            assert_eq!(
                views.iter().find(|v| v.node == DIRECT).unwrap().latest_snapshot.as_ref().unwrap().snapshot.endpoints[0].activity.as_ref().unwrap().state,
                xmsg::activity::ActivityState::Working
            );
            assert_eq!(
                views.iter().find(|v| v.node == DIRECT_VALID).unwrap().latest_snapshot.as_ref().unwrap().snapshot.endpoints[0].activity.as_ref().unwrap().state,
                xmsg::activity::ActivityState::Blocked
            );
            println!("REFRESH WRITE: new collector persisted and read two active snapshots");
        }
        #[cfg(not(candidate))]
        "refresh_old" => {
            validate(&store, DIRECT);
            validate(&store, DIRECT_VALID);
            let refreshed: ExportSnapshot = serde_json::from_value(json!({
                "v": 1,
                "node": DIRECT,
                "scope": "a".repeat(64),
                "observed_at": 2000,
                "endpoints": [{
                    "id": "claude-9@direct.node",
                    "node": DIRECT,
                    "kind": "instance",
                    "harness": "claude",
                    "state": "registered"
                }],
                "truncated": false,
                "available": "available"
            }))
            .unwrap();
            store.ingest_snapshot(DIRECT, refreshed).unwrap();
            println!("REFRESH OLD: pinned old collector refreshed direct.node");
        }
        #[cfg(candidate)]
        "refresh_read" => {
            validate(&store, DIRECT);
            validate(&store, DIRECT_VALID);
            let views = store.view(None, 200).unwrap();
            let refreshed = views.iter().find(|v| v.node == DIRECT).unwrap();
            let refreshed_snap = &refreshed.latest_snapshot.as_ref().unwrap().snapshot;
            assert_eq!(refreshed_snap.observed_at, 2000, "legacy observed_at lost");
            assert_eq!(refreshed_snap.endpoints[0].id, "claude-9@direct.node");
            assert!(
                refreshed_snap.endpoints[0].activity.is_none(),
                "stale prior-capture activity leaked onto old-refreshed row"
            );
            assert_eq!(
                refreshed_snap.activity,
                xmsg::activity::SnapshotActivity {
                    status: xmsg::activity::ActivityStatus::Disabled,
                    complete: false,
                },
                "unmatched sidecar must show incomplete/disabled, never stale"
            );
            let refreshed_html = render(
                &views,
                Some(refreshed),
                Filter {
                    node: Some(0),
                    page: 0,
                },
            );
            assert!(
                !refreshed_html.contains("activity: working"),
                "rendered HTML leaked stale working activity"
            );
            let valid = views.iter().find(|v| v.node == DIRECT_VALID).unwrap();
            let valid_snap = &valid.latest_snapshot.as_ref().unwrap().snapshot;
            assert_eq!(valid_snap.observed_at, 1000);
            assert_eq!(
                valid_snap.endpoints[0].activity.as_ref().unwrap().state,
                xmsg::activity::ActivityState::Blocked,
                "valid same-capture activity lost"
            );
            assert_eq!(
                valid_snap.activity,
                xmsg::activity::SnapshotActivity {
                    status: xmsg::activity::ActivityStatus::Enabled,
                    complete: true,
                }
            );
            let valid_html = render(
                &views,
                Some(valid),
                Filter {
                    node: Some(1),
                    page: 0,
                },
            );
            assert!(
                valid_html.contains("activity: blocked/permission"),
                "valid same-capture activity missing from rendered HTML"
            );
            println!("REFRESH READ SAFE: stale sidecar suppressed; valid same-capture activity survived");
        }
        _ => panic!("unknown mode"),
    }
}
