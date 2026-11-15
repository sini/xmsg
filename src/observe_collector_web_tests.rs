use super::*;
use crate::observe_collector_store::{CachedEvent, CachedSnapshot};
use crate::observe_export::*;

fn view() -> NodeView {
    NodeView {
        history_hidden: false,
        node: "fixture.node".into(),
        status: NodeStatus::Stale,
        events: vec![],
        latest_snapshot: None,
        cursor: None,
        gaps: vec![
            ExportGap {
                reason: Reason::PolicyFiltered,
                unknown_loss: false,
            },
            ExportGap {
                reason: Reason::QueueLoss,
                unknown_loss: true,
            },
        ],
        truncated: true,
        backfill: true,
    }
}
fn hostile_view() -> NodeView {
    let mut node = view();
    let hostile =
        "</text><image href=\"https://attacker.invalid/collect\"/><script>alert('x')</script>&";
    node.latest_snapshot = Some(CachedSnapshot {
        snapshot: ExportSnapshot {
            v: 1,
            node: node.node.clone(),
            scope: "s".repeat(64),
            observed_at: 100,
            endpoints: vec![EndpointDescriptor {
                id: "svc:one@fixture.node".into(),
                node: node.node.clone(),
                kind: EndpointKind::Service,
                harness: Harness::Unknown,
                state: RegistrationState::Unknown,
                source_at: None,
                label: Some(hostile.into()),
            }],
            truncated: true,
            available: SnapshotAvailability::Partial,
        },
        received_at: 110,
        source_age_seconds: 20,
        receipt_age_seconds: 10,
    });
    node.events = vec![CachedEvent {
        epoch: "epoch".into(),
        event: ExportEvent {
            sequence: 1,
            source_at: None,
            observed_at: 100,
            persisted_at: 101,
            kind: EventKind::MessageRecorded,
            from: Some("svc:one@fixture.node".into()),
            to: None,
            message_id: Some("message".into()),
            reply_id: None,
            thread_id: None,
            outcome: None,
            reason: None,
            available: Availability::NotRecorded,
        },
        received_at: 110,
        source_age_seconds: 20,
        receipt_age_seconds: 10,
    }];
    node
}
#[test]
fn numeric_filters_never_become_network_destinations() {
    assert_eq!(
        Filter::parse(Some("node=0&page=49"), 1)
            .unwrap()
            .read_limit(),
        10_000
    );
    for query in [
        "node=https://attacker.invalid",
        "node=1",
        "node=0&node=0",
        "page=50",
        "page=1",
        "node=-1",
        "node=0&address=1",
        "node=%30",
        "node=0&page=18446744073709551616",
    ] {
        assert!(
            Filter::parse(Some(query), 1).is_err(),
            "browser authority or invalid paging accepted: {query}"
        );
    }
}
#[test]
fn hostile_html_label_is_text() {
    let node = hostile_view();
    let html = render(
        &[node.clone()],
        Some(&node),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    assert!(html.contains("&lt;/text&gt;&lt;image"));
    assert!(
        !html.contains("<script>"),
        "HTML label created executable markup"
    );
    let html_label = html
        .split("class=\"endpoint-label\">")
        .nth(1)
        .unwrap()
        .split("<small>")
        .next()
        .unwrap();
    assert!(
        !html_label.contains("<image"),
        "HTML label created a resource node"
    );
}
#[test]
fn hostile_svg_label_and_lane_are_text() {
    let node = hostile_view();
    let html = render(
        &[node.clone()],
        Some(&node),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    for fragment in html.split("<svg").skip(1) {
        let svg = fragment.split("</svg>").next().unwrap();
        assert!(
            !svg.contains("<image"),
            "SVG label or lane created a resource node"
        );
        assert!(svg.contains("&lt;/text&gt;"));
    }
}
#[test]
fn presentation_preserves_boundaries_and_separate_clocks() {
    let node = hostile_view();
    let html = render(
        &[node.clone()],
        Some(&node),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    for phrase in [
        "stale: exporter unavailable",
        "Backfill pending",
        "policy_filtered; unknown loss: false",
        "queue_loss; unknown loss: true",
        "Availability: partial; truncated: true",
        "Source event time: unknown",
        "source observation: 100 (age 20 s)",
        "Collector receipt: 110 (age 10 s)",
        "outcome: unknown",
        "Epoch epoch · sequence 1",
        "content=\"5\"",
    ] {
        assert!(html.contains(phrase), "missing presentation fact: {phrase}");
    }
    let mut hidden = node;
    hidden.history_hidden = true;
    let html = render(
        &[hidden.clone()],
        Some(&hidden),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    assert!(html.contains("history hidden until this node answers"));
    assert!(!html.contains("message</code>"), "hidden history rendered");
}
#[test]
fn rows_objects_and_response_bytes_are_bounded() {
    let mut node = hostile_view();
    node.events = vec![node.events[0].clone(); 201];
    let endpoint = node.latest_snapshot.as_ref().unwrap().snapshot.endpoints[0].clone();
    node.latest_snapshot.as_mut().unwrap().snapshot.endpoints = vec![endpoint; 201];
    let html = render(
        &[node.clone()],
        Some(&node),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    assert_eq!(
        html.matches("class=\"event\"").count(),
        200,
        "event row cap bypassed"
    );
    assert_eq!(
        html.matches("class=\"endpoint\"").count(),
        200,
        "endpoint cap bypassed"
    );
    assert!(html.contains("Endpoint objects truncated to 200"));
    assert!(html.contains("Next page"));
    let html = render_with_cap(
        &[node.clone()],
        Some(&node),
        Filter {
            node: Some(0),
            page: 0,
        },
        5000,
    );
    assert!(html.len() <= 5000, "HTML byte cap bypassed");
    assert!(html.contains("Output truncated by the response byte limit"));
    assert!(html.ends_with("</main></body></html>"));
}
#[test]
fn endpoint_lookup_never_crosses_node_projection() {
    let mut other = hostile_view();
    other.node = "other.node".into();
    other.latest_snapshot.as_mut().unwrap().snapshot.endpoints[0].label =
        Some("OTHER_NODE_SECRET_LABEL".into());
    let mut node = hostile_view();
    node.latest_snapshot = None;
    let html = render(
        &[node.clone(), other],
        Some(&node),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    assert!(
        !html.contains("OTHER_NODE_SECRET_LABEL"),
        "cross-node endpoint hydrated"
    );
    assert!(html.contains("svc:one@fixture.node"));
}
#[test]
fn csp_hash_covers_only_the_static_stylesheet() {
    let csp = content_security_policy();
    assert!(csp.contains("script-src 'none'"));
    assert!(csp.contains("style-src 'sha256-"));
    assert!(!csp.contains("unsafe-inline"));
    for policy in [
        "default-src 'self'",
        "frame-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    ] {
        assert!(csp.contains(policy), "missing policy: {policy}");
    }
}
