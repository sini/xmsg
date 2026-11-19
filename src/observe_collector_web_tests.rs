use super::*;
use crate::observe_collector_store::{CachedEvent, CachedSnapshot};
use crate::observe_export::*;

fn view() -> NodeView {
    NodeView {
        failure: None,
        origin_hub: None,
        history_hidden: false,
        has_stored_history: false,
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
        origin_hub: None,
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
        origin_hub: None,
        epoch: "epoch".into(),
        event: ExportEvent {
            sequence: 1,
            source_at: None,
            observed_at: 100,
            persisted_at: 101,
            kind: EventKind::MessageRecorded,
            from: Some("svc:one@fixture.node".into()),
            to: Some("svc:one@fixture.node".into()),
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
        "node=0&page=50",
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
        std::slice::from_ref(&node),
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
        std::slice::from_ref(&node),
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
        std::slice::from_ref(&node),
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
        std::slice::from_ref(&hidden),
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
        std::slice::from_ref(&node),
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
        std::slice::from_ref(&node),
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

#[test]
fn records_without_reported_endpoints_do_not_invent_lanes() {
    let mut node = hostile_view();
    node.events[0].event.from = None;
    node.events[0].event.to = None;
    let html = render(
        std::slice::from_ref(&node),
        Some(&node),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    assert!(
        !html.contains("class=\"lane\""),
        "record without endpoints gained a decorative exchange"
    );
    assert!(html.contains("No exchange endpoints reported"));
}

#[test]
fn relay_origin_is_escaped_in_event_snapshot_and_stale_view() {
    let mut node = hostile_view();
    let hub = "spiffe://fleet/host/<hub>&\"/user/owner";
    node.origin_hub = Some(hub.into());
    node.latest_snapshot.as_mut().unwrap().origin_hub = Some(hub.into());
    node.events[0].origin_hub = Some(hub.into());
    node.failure = Some(UnavailableKind::Timeout);
    let html = render(
        &[node.clone()],
        Some(&node),
        Filter {
            node: Some(0),
            page: 0,
        },
    );
    assert!(
        html.contains("stale: exporter unavailable"),
        "relay stale provenance view omitted truthful unavailable status"
    );
    assert!(
        html.contains("Observation request timed out."),
        "relay stale provenance view omitted fixed timeout caption"
    );
    assert!(
        !html.contains(hub),
        "relay via-hub provenance rendered raw HTML instead of escaped text"
    );
    let via = "via spiffe://fleet/host/&lt;hub&gt;&amp;&quot;/user/owner (hub-attested)";
    let tile = html
        .split_once("<article class=\"tile\">")
        .expect("relay provenance tile section missing")
        .1
        .split_once("</article>")
        .unwrap()
        .0;
    assert!(
        tile.contains(via),
        "relay tile omitted escaped configured via-hub provenance"
    );
    let detail = html
        .split_once("<section><h2>")
        .expect("relay provenance detail section missing")
        .1
        .split_once("<h3>Latest source inventory</h3>")
        .unwrap()
        .0;
    assert!(
        detail.contains(via),
        "relay detail omitted escaped configured via-hub provenance"
    );
    let snapshot = html
        .split_once("<h3>Latest source inventory</h3>")
        .expect("relay provenance snapshot section missing")
        .1
        .split_once("<h3>Reported exchanges</h3>")
        .unwrap()
        .0;
    assert!(
        snapshot.contains(via),
        "relay snapshot omitted escaped persisted via-hub provenance"
    );
    let event = html
        .split_once("<article class=\"event\">")
        .expect("relay provenance event section missing")
        .1
        .split_once("</article>")
        .unwrap()
        .0;
    assert!(
        event.contains(via),
        "relay event omitted escaped persisted via-hub provenance"
    );

    assert_eq!(
        html.matches("via spiffe://fleet/host/&lt;hub&gt;&amp;&quot;/user/owner (hub-attested)")
            .count(),
        4,
        "relay escaped via-hub provenance count changed across tile detail snapshot and event"
    );
}

#[test]
fn dynamic_relay_unsupported_retains_hidden_history_warning_in_tiles() {
    let mut node = view();
    node.events.clear();
    node.latest_snapshot = None;
    node.history_hidden = true;
    node.status = NodeStatus::Unsupported;
    node.failure = Some(UnavailableKind::Unsupported);
    node.origin_hub = Some("spiffe://fleet/host/hub/user/owner".into());
    let html = render(std::slice::from_ref(&node), None, Filter::default());
    assert!(
        html.contains("history hidden until this node answers"),
        "dynamic relay unsupported tile omitted startup hidden-history explanation"
    );
    assert!(
        html.contains("unsupported: observation transport"),
        "dynamic relay unsupported tile omitted relay transport caption"
    );
    assert!(
        !html.contains("unsupported: outbound-only source"),
        "dynamic relay unsupported tile claimed static outbound-only transport"
    );
    node.origin_hub = None;
    node.failure = None;
    let html = render(&[node], None, Filter::default());
    assert!(
        html.contains("unsupported: outbound-only source"),
        "static direct unsupported tile lost inherited outbound-only caption"
    );
    assert!(
        !html.contains("history hidden until this node answers"),
        "static direct unsupported presentation changed"
    );
}

#[test]
fn r2_coverage_banner_seven_configured_nodes() {
    let mut healthy = view();
    healthy.node = "node-healthy".into();
    healthy.status = NodeStatus::Healthy;
    healthy.failure = None;

    let mut stale = view();
    stale.node = "node-stale".into();
    stale.status = NodeStatus::Stale;
    stale.failure = None;

    let mut unreachable = view();
    unreachable.node = "node-unreachable".into();
    unreachable.status = NodeStatus::Stale;
    unreachable.failure = Some(UnavailableKind::Unreachable);

    let mut not_found = view();
    not_found.node = "node-not-found".into();
    not_found.status = NodeStatus::Stale;
    not_found.failure = Some(UnavailableKind::EndpointNotFound);

    let mut denied = view();
    denied.node = "node-denied".into();
    denied.status = NodeStatus::Denied;
    denied.failure = None;
    denied.history_hidden = true;

    let mut loading = view();
    loading.node = "node-loading".into();
    loading.status = NodeStatus::Loading;
    loading.failure = None;
    loading.history_hidden = true;

    let mut relayed_fail = view();
    relayed_fail.node = "node-relayed-fail".into();
    relayed_fail.status = NodeStatus::Stale;
    relayed_fail.failure = Some(UnavailableKind::Unreachable);
    relayed_fail.origin_hub = Some("hub-a".into());

    let html = render(
        &[
            healthy,
            stale,
            unreachable,
            not_found,
            denied,
            loading,
            relayed_fail,
        ],
        None,
        Filter::default(),
    );
    assert!(
        html.contains(
            "1/7 configured nodes reporting · 3 unreachable · 1 endpoint not found/unsupported or misconfigured · 1 loading · 1 denied"
        ),
        "unexpected coverage banner:\n{html}"
    );
    assert!(
        !html.contains("· 0 "),
        "zero-count bucket must not be rendered:\n{html}"
    );
}

#[test]
fn r3_loading_vs_scope_changed_pending_revalidation() {
    let mut loading = view();
    loading.node = "node-loading".into();
    loading.status = NodeStatus::Loading;
    loading.history_hidden = true;
    loading.has_stored_history = false;
    loading.failure = None;

    let mut revalidating = view();
    revalidating.node = "node-revalidating".into();
    revalidating.status = NodeStatus::HiddenPendingRevalidation;
    revalidating.history_hidden = true;
    revalidating.has_stored_history = true;
    revalidating.failure = None;

    let mut healthy = view();
    healthy.node = "node-healthy".into();
    healthy.status = NodeStatus::Healthy;
    healthy.history_hidden = false;
    healthy.has_stored_history = true;
    healthy.failure = None;

    let html = render(&[loading, revalidating, healthy], None, Filter::default());
    assert!(
        html.contains("loading: first observation pending"),
        "missing loading status:\n{html}"
    );
    assert!(
        html.contains("pending revalidation")
            && html.contains("stored history hidden until this node answers"),
        "missing restart/scope-changed stored-history caption:\n{html}"
    );
}

#[test]
fn r4_gap_last_success_and_unknown_loss_respect_masks() {
    let mut healthy = view();
    healthy.node = "node-healthy".into();
    healthy.status = NodeStatus::Healthy;
    healthy.history_hidden = false;
    healthy.failure = None;
    healthy.gaps = vec![];

    let mut denied = view();
    denied.node = "node-denied".into();
    denied.status = NodeStatus::Denied;
    denied.history_hidden = true;
    denied.failure = None;
    denied.gaps = vec![crate::observe_export::ExportGap {
        reason: crate::observe_export::Reason::SequenceGap,
        unknown_loss: true,
    }];

    let mut loading = view();
    loading.node = "node-loading".into();
    loading.status = NodeStatus::Loading;
    loading.history_hidden = true;
    loading.failure = None;

    let mut health = CollectorHealth::default();
    health.nodes.insert(
        "node-healthy".into(),
        NodeFreshness {
            stale_for_secs: None,
            stale_since_start: false,
            last_success: Some((1000, 5)),
        },
    );

    let html_healthy = render_with_health(&[healthy], None, Filter::default(), &health);
    assert!(
        html_healthy.contains("gaps: 0 · loss counters: not exported/unknown"),
        "missing gap/loss line on healthy node:\n{html_healthy}"
    );
    assert!(
        html_healthy.contains("last successful poll 1970-01-01T00:16:40Z (5 s ago)"),
        "missing last-success line on healthy node:\n{html_healthy}"
    );

    let html_masked = render_with_health(&[denied, loading], None, Filter::default(), &health);
    assert!(
        !html_masked.contains("gaps:")
            && !html_masked.contains("loss counters:")
            && !html_masked.contains("last successful poll"),
        "masked or loading node leaked gap/loss/last-success:\n{html_masked}"
    );
}

#[test]
fn r5_relayed_node_retains_escaped_provenance() {
    for status in [NodeStatus::Loading, NodeStatus::Stale, NodeStatus::Denied] {
        let mut node = view();
        node.node = "node-relayed".into();
        node.status = status;
        node.history_hidden = matches!(status, NodeStatus::Loading | NodeStatus::Denied);
        node.failure = None;
        node.origin_hub = Some("<script>hub-a</script>".into());

        let summary_html = render(std::slice::from_ref(&node), None, Filter::default());
        assert!(
            summary_html.contains("via &lt;script&gt;hub-a&lt;/script&gt; (hub-attested)"),
            "missing escaped provenance in summary for {status:?}:\n{summary_html}"
        );
        assert!(
            !summary_html.contains("<script>hub-a</script>"),
            "unescaped origin_hub in summary:\n{summary_html}"
        );

        let detail_html = render(std::slice::from_ref(&node), Some(&node), Filter::default());
        assert!(
            detail_html.contains("via &lt;script&gt;hub-a&lt;/script&gt; (hub-attested)"),
            "missing escaped provenance in detail for {status:?}:\n{detail_html}"
        );
        assert!(
            !detail_html.contains("<script>hub-a</script>"),
            "unescaped origin_hub in detail:\n{detail_html}"
        );
    }
}
