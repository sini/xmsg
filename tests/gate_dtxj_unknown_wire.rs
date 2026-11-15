#[path = "support/dtxj2_wire.rs"]
mod wire;
use serde_json::{json, Value};
use wire::{event, page, receive, receive_raw};
use xmsg::observe_collector_net::Error;
use xmsg::observe_export::EventKind;

#[tokio::test]
async fn known_neighbors_and_cursor_control() {
    let result = receive(page(vec![
        event(1, json!("message_recorded")),
        event(2, json!("unknown")),
        event(3, json!("reply_recorded")),
    ]))
    .await
    .unwrap();
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![
            EventKind::MessageRecorded,
            EventKind::Unknown,
            EventKind::ReplyRecorded
        ]
    );
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(result.next, 3);
    assert!(!result.has_more);
}

#[tokio::test]
async fn future_kind_preserves_known_neighbors_and_cursor() {
    let result = receive(page(vec![
        event(1, json!("message_recorded")),
        event(2, json!("future_delivery")),
        event(3, json!("reply_recorded")),
    ]))
    .await;
    assert!(result.is_ok(), "valid future kind rejected: {result:?}");
    let result = result.unwrap();
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![
            EventKind::MessageRecorded,
            EventKind::Unknown,
            EventKind::ReplyRecorded
        ]
    );
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(result.next, 3);
}

#[tokio::test]
async fn future_kind_accepts_exact_64_byte_identifier() {
    let kind = format!("f{}", "a".repeat(63));
    assert_eq!(kind.len(), 64);
    let result = receive(page(vec![event(1, json!(kind))])).await;
    assert!(result.is_ok(), "64-byte future kind rejected: {result:?}");
    assert_eq!(result.unwrap().events[0].kind, EventKind::Unknown);
}

#[tokio::test]
async fn future_kind_refuses_65_byte_identifier() {
    assert!(matches!(
        receive(page(vec![event(1, json!("f".repeat(65)))])).await,
        Err(Error::Malformed)
    ));
}

#[tokio::test]
async fn malformed_kind_representations_and_grammar_refuse() {
    for kind in [
        json!(""),
        json!("Future"),
        json!("future-kind"),
        json!("0future"),
        json!("_future"),
        json!("future kind"),
        json!("futuré"),
        json!(null),
        json!(12),
        json!({"future":true}),
        json!(["future"]),
    ] {
        assert!(
            matches!(
                receive(page(vec![event(1, kind.clone())])).await,
                Err(Error::Malformed)
            ),
            "accepted malformed kind {kind}"
        );
    }
}

#[tokio::test]
async fn future_kind_does_not_hide_invalid_envelope() {
    for (field, value) in [
        ("body", json!("must not persist")),
        ("sequence", json!("invalid")),
        ("outcome", json!("future_outcome")),
        ("available", json!("future_availability")),
    ] {
        let mut row = event(1, json!("future_delivery"));
        row[field] = value;
        assert!(
            matches!(receive(page(vec![row])).await, Err(Error::Malformed)),
            "future kind hid invalid {field}"
        );
    }
}

#[tokio::test]
async fn known_invalid_envelope_controls_refuse() {
    for (field, value) in [
        ("body", json!("must not persist")),
        ("sequence", json!("invalid")),
        ("outcome", json!("future_outcome")),
        ("available", json!("future_availability")),
    ] {
        let mut row = event(1, json!("message_recorded"));
        row[field] = value;
        assert!(
            matches!(receive(page(vec![row])).await, Err(Error::Malformed)),
            "known control accepted invalid {field}"
        );
    }
}

#[tokio::test]
async fn duplicate_kind_and_other_fields_refuse() {
    for kind in ["message_recorded", "future_delivery"] {
        for duplicate in [format!("\"kind\":\"{kind}\""), "\"sequence\":1".into()] {
            let result = receive_raw(|node| {
                let mut value = page(vec![event(1, json!(kind))]);
                value["node"] = json!(node);
                let encoded = value.to_string();
                encoded.replacen("\"events\":[{", &format!("\"events\":[{{{duplicate},"), 1)
            })
            .await;
            assert!(
                matches!(result, Err(Error::Malformed)),
                "accepted duplicate {duplicate}"
            );
        }
    }
}

#[test]
fn public_event_kind_remains_closed_control() {
    assert!(serde_json::from_value::<EventKind>(json!("future_delivery")).is_err());
    assert_eq!(
        serde_json::from_value::<EventKind>(Value::String("unknown".into())).unwrap(),
        EventKind::Unknown
    );
}

#[tokio::test]
async fn page_byte_budget_control() {
    for bytes in [256 * 1024, 256 * 1024 + 1] {
        let result = receive_raw(|node| {
            let mut value = page(vec![event(1, json!("message_recorded"))]);
            value["node"] = json!(node);
            let mut encoded = value.to_string();
            encoded.extend(std::iter::repeat_n(' ', bytes - encoded.len()));
            assert_eq!(encoded.len(), bytes);
            encoded
        })
        .await;
        if bytes == 256 * 1024 {
            assert!(result.is_ok(), "exact page byte budget refused: {result:?}");
        } else {
            assert!(
                matches!(result, Err(Error::Malformed)),
                "oversized page accepted"
            );
        }
    }
}
