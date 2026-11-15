use super::*;
use serde_json::json;
fn event(kind: &str) -> Value {
    json!({"sequence":1,"observed_at":1,"persisted_at":1,"kind":kind,"available":"not_recorded"})
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn page(events: Vec<Value>) -> Value {
    json!({"v":1,"node":"local","epoch":"e","scope":"s","events":events,"next":1,"has_more":false,"gaps":[],"available":true})
}
#[test]
fn known_canonical_matches_export_and_omits_nulls() {
    for kind in ["arrival", "message_recorded", "unknown"] {
        let mut value = event(kind);
        value["source_at"] = Value::Null;
        let decoded = decode_event(&bytes(&value)).unwrap();
        assert_eq!(
            decoded.canonical,
            serde_json::to_vec(&decoded.event).unwrap()
        );
        assert!(!String::from_utf8(decoded.canonical)
            .unwrap()
            .contains("source_at"));
    }
}
#[test]
fn populated_known_envelope_matches_export_bytes() {
    let value = json!({"sequence":1,"source_at":2,"observed_at":3,"persisted_at":4,
        "kind":"arrival","from":"a\"b","to":"target","message_id":"message",
        "reply_id":5,"thread_id":"thread","outcome":"delivered","reason":"outbound",
        "available":"retained_at_capture"});
    let decoded = decode_event(&bytes(&value)).unwrap();
    assert_eq!(
        decoded.canonical,
        serde_json::to_vec(&decoded.event).unwrap()
    );
}
#[test]
fn unknown_preserves_identifier_and_replay_bytes() {
    for kind in ["future_delivery", "future_writer_fixture", &"a".repeat(64)] {
        let decoded = decode_event(&bytes(&event(kind))).unwrap();
        assert_eq!(decoded.event.kind, EventKind::Unknown);
        assert_eq!(
            serde_json::from_slice::<Value>(&decoded.canonical).unwrap()["kind"],
            kind
        );
        assert_eq!(
            decode_event(&decoded.canonical).unwrap().canonical,
            decoded.canonical
        );
    }
    assert_ne!(
        decode_event(&bytes(&event("future_a"))).unwrap().canonical,
        decode_event(&bytes(&event("future_b"))).unwrap().canonical
    );
}
#[test]
fn unknown_identifier_grammar_and_length_are_closed() {
    for kind in [
        "".into(),
        "a".repeat(65),
        "A".into(),
        "1x".into(),
        "_x".into(),
        "a-b".into(),
        "a/b".into(),
        "a b".into(),
        "é".into(),
    ] {
        assert!(
            decode_event(&bytes(&event(&kind))).is_err(),
            "accepted invalid identifier"
        );
    }
    for kind in [
        json!(1),
        Value::Null,
        json!({"future_delivery":null}),
        json!([]),
    ] {
        let mut value = event("arrival");
        value["kind"] = kind;
        assert!(decode_event(&bytes(&value)).is_err());
    }
    let mut value = event("arrival");
    value.as_object_mut().unwrap().remove("kind");
    assert!(decode_event(&bytes(&value)).is_err());
}
#[test]
fn duplicate_fields_and_unknown_fields_remain_errors() {
    let encoded = String::from_utf8(bytes(&event("future_delivery"))).unwrap();
    let duplicate = encoded.replacen("\"kind\":", "\"kind\":\"arrival\",\"kind\":", 1);
    assert!(decode_event(duplicate.as_bytes()).is_err());
    let duplicate = encoded.replacen("\"kind\":", "\"k\\u0069nd\":\"arrival\",\"kind\":", 1);
    assert!(decode_event(duplicate.as_bytes()).is_err());
    for field in ["body", "payload", "path"] {
        let mut value = event("future_delivery");
        value[field] = json!("canary");
        assert!(decode_event(&bytes(&value)).is_err());
    }
    for field in ["outcome", "reason", "available"] {
        let mut value = event("future_delivery");
        value[field] = json!("future_value");
        assert!(decode_event(&bytes(&value)).is_err());
    }
    let mut value = page(vec![event("future_delivery")]);
    value["extra"] = json!(true);
    assert!(decode_page(&bytes(&value)).is_err());
    let mut value = page(vec![]);
    value["gaps"] = json!([{"reason":"unknown","unknown_loss":false,"extra":true}]);
    assert!(decode_page(&bytes(&value)).is_err());
    let duplicate = bytes(&page(vec![]));
    let duplicate =
        String::from_utf8(duplicate)
            .unwrap()
            .replacen("\"gaps\":", "\"gaps\":[],\"gaps\":", 1);
    assert!(decode_page(duplicate.as_bytes()).is_err());
    assert!(decode_event(b"null").is_err());
    assert!(decode_page(b"[]").is_err());
}
#[test]
fn mixed_page_length_accounts_for_original_names() {
    let value = page(vec![
        event("arrival"),
        event(&"a".repeat(64)),
        event("message_recorded"),
    ]);
    let decoded = decode_page(&bytes(&value)).unwrap();
    assert_eq!(decoded.page.events[0].kind, EventKind::Arrival);
    assert_eq!(decoded.page.events[1].kind, EventKind::Unknown);
    assert_eq!(decoded.events.len(), 3);
    assert_eq!(
        decoded.canonical_len,
        serde_json::to_vec(&decoded.page).unwrap().len() + 64 - 7
    );
    let typed = from_typed_page(decoded.page).unwrap();
    assert_eq!(typed.events[1].event.kind, EventKind::Unknown);
}
#[test]
fn canonical_event_and_page_bounds_remain_enforced() {
    let mut value = event("future_delivery");
    value["message_id"] = json!("x".repeat(4096));
    assert!(decode_event(&bytes(&value)).is_err());
    assert!(decode_page(&bytes(&page(vec![event("arrival"); 200]))).is_ok());
    assert!(decode_page(&bytes(&page(vec![event("arrival"); 201]))).is_err());
    let mut value = page(vec![event("future_delivery")]);
    value["node"] = json!("x".repeat(MAX_BYTES));
    assert!(decode_page(&bytes(&value)).is_err());
    let mut value = page(vec![]);
    let base = bytes(&value).len();
    value["node"] = json!("x".repeat(MAX_BYTES - base + "local".len()));
    assert_eq!(
        decode_page(&bytes(&value)).unwrap().canonical_len,
        MAX_BYTES
    );
    let name = value["node"].as_str().unwrap().to_owned() + "x";
    value["node"] = json!(name);
    assert!(decode_page(&bytes(&value)).is_err());
}

#[test]
fn measure_shared_known_kind_representation() {
    for (kind, accepted) in [
        (json!({"message_recorded":null}), true),
        (json!({"arrival":null}), true),
        (json!({"future_delivery":null}), false),
        (json!({"arrival":1}), false),
        (json!({"arrival":null,"gap":null}), false),
        (json!(1), false),
        (json!(true), false),
    ] {
        let mut value = event("arrival");
        value["kind"] = kind.clone();
        let result = serde_json::from_value::<crate::observe_export::ExportEvent>(value);
        println!("shared kind {kind}: accepted={}", result.is_ok());
        assert_eq!(result.is_ok(), accepted);
    }
}

#[test]
fn collector_preserves_shared_known_kind_map_representation() {
    for kind in ["message_recorded", "arrival", "unknown"] {
        let mut value = event(kind);
        value["kind"] = json!({kind:null});
        let expected: ExportEvent = serde_json::from_value(value.clone()).unwrap();
        let decoded = decode_event(&bytes(&value)).unwrap();
        assert_eq!(decoded.event.kind, expected.kind);
        assert_eq!(decoded.canonical, serde_json::to_vec(&expected).unwrap());
    }
    for kind in [
        json!({"future_delivery":null}),
        json!({"arrival":1}),
        json!({"arrival":null,"gap":null}),
        json!({}),
        json!(1),
        json!(true),
    ] {
        let mut value = event("arrival");
        value["kind"] = kind;
        assert!(decode_event(&bytes(&value)).is_err());
    }
}
