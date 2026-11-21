use serde_json::Value;

use super::codec;

const ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/mission-control/v1"
);

fn vector(name: &str) -> Vec<u8> {
    std::fs::read(format!("{ROOT}/{name}.json")).unwrap()
}

fn web_binding(mut value: Value, websocket: bool) -> Value {
    let obj = value.as_object_mut().unwrap();
    if !websocket {
        for name in ["sub", "id", "re"] {
            obj.remove(name);
        }
    } else if obj["type"] == "snapshot" || obj["type"] == "event" {
        obj.entry("sub")
            .or_insert_with(|| Value::String("fixture".into()));
    }
    value
}

fn sse_binding(value: &Value) -> String {
    let mut output = String::new();
    if let Some(cursor) = value.get("cursor").and_then(Value::as_str) {
        output.push_str("id: ");
        output.push_str(cursor);
        output.push('\n');
    }
    output.push_str("event: ");
    output.push_str(value["type"].as_str().unwrap());
    output.push_str("\ndata: ");
    output.push_str(&value.to_string());
    output.push_str("\n\n");
    output
}

fn decode_sse(frame: &str) -> Option<Value> {
    let fields = frame.strip_suffix("\n\n")?;
    let mut id = None;
    let mut event = None;
    let mut data = None;
    for line in fields.split('\n') {
        let (key, body) = line.split_once(": ")?;
        let slot = match key {
            "id" => &mut id,
            "event" => &mut event,
            "data" => &mut data,
            _ => return None,
        };
        if slot.replace(body).is_some() {
            return None;
        }
    }
    let message: Value = serde_json::from_str(data?).ok()?;
    if message["type"].as_str() != event || message.get("cursor").and_then(Value::as_str) != id {
        return None;
    }
    Some(message)
}

#[test]
fn server_vectors_round_trip_in_native_codec_on_listed_bindings() {
    for (name, ws, http, sse) in [
        ("V-H2", true, false, false),
        ("V-S3", true, false, false),
        ("V-P1", true, true, true),
        ("V-P2", true, true, true),
        ("V-E1", true, false, true),
        ("V-E2", true, false, true),
        ("V-E3", true, false, true),
        ("V-E4", true, false, true),
        ("V-G1", true, false, true),
        ("V-T1", true, false, true),
        ("V-X1", true, false, false),
        ("V-X2", false, true, true),
    ] {
        let value: Value = serde_json::from_slice(&vector(name)).unwrap();
        for (enabled, websocket, stream) in
            [(ws, true, false), (http, false, false), (sse, false, true)]
        {
            if !enabled {
                continue;
            }
            let projected = web_binding(value.clone(), websocket);
            let wire = if stream {
                let framed = sse_binding(&projected);
                assert_eq!(decode_sse(&framed).unwrap(), projected);
                decode_sse(&framed).unwrap()
            } else {
                serde_json::from_str(&projected.to_string()).unwrap()
            };
            let decoded = codec::decode(&serde_json::to_vec(&wire).unwrap(), 262_144)
                .unwrap_or_else(|error| panic!("{name} failed: {error}"));
            assert_eq!(serde_json::to_value(decoded).unwrap(), projected, "{name}");
        }
    }
    for name in ["V-I13", "V-I14", "V-I24"] {
        assert!(codec::decode(&vector(name), 262_144).is_err(), "{name}");
    }
    let invalid: Value = serde_json::from_slice(&vector("V-I24")).unwrap();
    let descriptor = invalid["nodes"][0]["endpoints"][0]["descriptor"].clone();
    let export = serde_json::json!({
        "v":2,"node":"laptop","scope":"a".repeat(64),"observed_at":1795000000,
        "endpoints":[descriptor],"truncated":false,"available":"available",
        "activity":{"status":"disabled","complete":true}
    });
    assert!(serde_json::from_value::<crate::observe_export::ExportSnapshot>(export).is_err());
}
