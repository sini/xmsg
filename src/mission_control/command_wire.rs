use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::authority;
use super::request::{bounded_json, Code, RequestError};

const MAX_EXECUTOR_TEXT_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Carrier {
    WebSocket,
    Http,
}

#[derive(Debug)]
pub(super) enum CommandRequest {
    Prepare {
        id: Option<u32>,
        request: PreparedRequest,
    },
    Commit {
        id: Option<u32>,
        request_id: String,
        intent: String,
        digest: String,
    },
    Lookup {
        id: Option<u32>,
        request_id: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Verb {
    Send,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SelectorKind {
    Execution,
}

// These closed structs declare their ASCII keys in RFC 8785 order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selector {
    pub generation: u64,
    pub kind: SelectorKind,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub endpoint: String,
    pub incarnation: u64,
    pub node: String,
    pub selector: Selector,
    pub state_epoch: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Params {
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedRequest {
    pub params: Params,
    pub request_id: String,
    pub requested_at: u64,
    pub target: Target,
    pub verb: Verb,
}

impl PreparedRequest {
    pub(super) fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("command request contains only strings and safe integers")
    }

    pub(super) fn digest(&self) -> String {
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.canonical_bytes()))
        )
    }

    fn valid(&self) -> bool {
        valid_request_id(&self.request_id)
            && authority::valid_endpoint(&self.target.node, &self.target.endpoint)
            && valid_request_id(&self.target.state_epoch)
            && self.target.selector.generation != 0
            && !self.target.selector.session_id.is_empty()
            && self.target.selector.session_id.len() <= 128
            && !self
                .target
                .selector
                .session_id
                .chars()
                .any(char::is_control)
            && !self.params.text.is_empty()
            && self.params.text.len() <= MAX_EXECUTOR_TEXT_BYTES
    }
}

pub(super) fn valid_request_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitFields {
    request_id: String,
    intent: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupFields {
    request_id: String,
}

pub(super) fn decode(
    bytes: &[u8],
    depth: usize,
    strings: usize,
    carrier: Carrier,
) -> Result<CommandRequest, RequestError> {
    let bad = |reply| RequestError {
        code: Code::BadMessage,
        reply,
    };
    // serde_json rejects malformed UTF-8 and lone surrogates. The bounded
    // visitor also rejects signed or floating-point numeric token spellings.
    let Value::Object(mut fields) = bounded_json(bytes, depth, strings).map_err(|_| bad(None))?
    else {
        return Err(bad(None));
    };
    let id = match (carrier, fields.remove("id")) {
        (Carrier::Http, None) => None,
        (Carrier::WebSocket, Some(id)) => Some(
            id.as_u64()
                .filter(|id| (1..=i32::MAX as u64).contains(id))
                .ok_or_else(|| bad(None))? as u32,
        ),
        _ => return Err(bad(None)),
    };
    if fields.remove("v").and_then(|v| v.as_u64()) != Some(1) {
        return Err(bad(id));
    }
    let kind = fields.remove("type").ok_or_else(|| bad(id))?;
    let value = Value::Object(fields);
    match kind.as_str() {
        Some("prepare") => {
            let request: PreparedRequest = serde_json::from_value(value).map_err(|_| bad(id))?;
            if !request.valid() {
                return Err(bad(id));
            }
            Ok(CommandRequest::Prepare { id, request })
        }
        Some("commit") => {
            let fields: CommitFields = serde_json::from_value(value).map_err(|_| bad(id))?;
            if !valid_request_id(&fields.request_id) {
                return Err(bad(id));
            }
            Ok(CommandRequest::Commit {
                id,
                request_id: fields.request_id,
                intent: fields.intent,
                digest: fields.digest,
            })
        }
        Some("lookup") if carrier == Carrier::WebSocket => {
            let fields: LookupFields = serde_json::from_value(value).map_err(|_| bad(id))?;
            if !valid_request_id(&fields.request_id) {
                return Err(bad(id));
            }
            Ok(CommandRequest::Lookup {
                id,
                request_id: fields.request_id,
            })
        }
        _ => Err(bad(id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREPARE: &str = r#"{"v":1,"type":"prepare","id":6,"request_id":"6f1e2d3c4b5a69788796a5b4c3d2e1f0","requested_at":1795000000500,"verb":"send","target":{"node":"laptop","endpoint":"claude-1@laptop","state_epoch":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","incarnation":3,"selector":{"kind":"execution","session_id":"exec-alpha","generation":7}},"params":{"text":"Check the task status."}}"#;

    fn parse(bytes: &[u8]) -> Result<CommandRequest, RequestError> {
        decode(bytes, 16, 4096, Carrier::WebSocket)
    }

    fn prep(bytes: &[u8]) -> PreparedRequest {
        let CommandRequest::Prepare {
            id: Some(6),
            request,
        } = parse(bytes).unwrap()
        else {
            panic!("expected correlated prepare")
        };
        request
    }

    #[test]
    fn oq13_generation_spellings_and_range() {
        for invalid in [
            "7.0",
            "7e0",
            "-0",
            "0",
            "-1",
            "1.5",
            "\"7\"",
            "9007199254740992",
        ] {
            let raw = PREPARE.replace("\"generation\":7", &format!("\"generation\":{invalid}"));
            assert_eq!(
                parse(raw.as_bytes()).err().map(|error| error.code),
                Some(Code::BadMessage),
                "accepted invalid generation {invalid}"
            );
        }
        for generation in [1_u64, (1 << 53) - 1] {
            let raw = PREPARE.replace("\"generation\":7", &format!("\"generation\":{generation}"));
            let request = prep(raw.as_bytes());
            assert_eq!(request.target.selector.generation, generation);
            assert!(String::from_utf8(request.canonical_bytes())
                .unwrap()
                .contains(&format!("\"generation\":{generation}")));
        }
    }

    #[test]
    fn oq13_unsigned_fields_reject_noncanonical_zero() {
        for original in [r#""incarnation":3"#, r#""requested_at":1795000000500"#] {
            let field = original.split(':').next().unwrap();
            let zero = PREPARE.replace(original, &format!("{field}:0"));
            assert!(parse(zero.as_bytes()).is_ok(), "canonical zero {field}");
            for invalid in ["-0", "0.0"] {
                let raw = PREPARE.replace(original, &format!("{field}:{invalid}"));
                assert_eq!(
                    parse(raw.as_bytes()).err().map(|error| error.code),
                    Some(Code::BadMessage),
                    "accepted noncanonical zero spelling {field}:{invalid}"
                );
            }
        }
    }

    #[test]
    fn oq13_executor_text_limit_applies_with_raised_string_limit() {
        let at_limit = "é".repeat(MAX_EXECUTOR_TEXT_BYTES / 2);
        let raw = PREPARE.replace("Check the task status.", &at_limit);
        let raised_limit = MAX_EXECUTOR_TEXT_BYTES + 1;
        let CommandRequest::Prepare { request, .. } =
            decode(raw.as_bytes(), 16, raised_limit, Carrier::WebSocket).unwrap()
        else {
            panic!("expected prepare at the executor text limit");
        };
        assert_eq!(request.params.text.len(), MAX_EXECUTOR_TEXT_BYTES);

        let over_limit = PREPARE.replace("Check the task status.", &(at_limit + "x"));
        assert_eq!(
            decode(over_limit.as_bytes(), 16, raised_limit, Carrier::WebSocket)
                .err()
                .map(|error| error.code),
            Some(Code::BadMessage),
            "accepted text one byte over the executor limit"
        );
    }

    #[test]
    fn oq13_session_id_limits_utf8_bytes() {
        let at_limit = "é".repeat(64);
        let raw = PREPARE.replace("exec-alpha", &at_limit);
        assert_eq!(prep(raw.as_bytes()).target.selector.session_id, at_limit);
        let over_limit = PREPARE.replace("exec-alpha", &(at_limit + "x"));
        assert_eq!(
            parse(over_limit.as_bytes()).err().map(|error| error.code),
            Some(Code::BadMessage),
            "accepted a 129-byte executor session ID"
        );
    }

    #[test]
    fn oq13_decoder_rejects_lone_surrogates() {
        for invalid in [r#"\uD800"#, r#"\uDC00"#] {
            let raw = PREPARE.replace("Check the task status.", invalid);
            assert_eq!(parse(raw.as_bytes()).unwrap_err().code, Code::BadMessage);
        }
        let marker = "Check the task status.";
        let start = PREPARE.find(marker).unwrap();
        let mut raw = PREPARE.as_bytes().to_vec();
        raw.splice(start..start + marker.len(), [0xed, 0xa0, 0x80]);
        assert_eq!(parse(&raw).unwrap_err().code, Code::BadMessage);
        let pair = PREPARE.replace(marker, r#"\uD83D\uDE00"#);
        assert_eq!(prep(pair.as_bytes()).params.text, "😀");
    }

    #[test]
    fn oq13_closed_send_schema() {
        for verb in [
            "dispatch",
            "steer",
            "interrupt",
            "resume",
            "stop",
            "status",
            "result",
            "approve",
            "invalid",
        ] {
            let raw = PREPARE.replace("\"verb\":\"send\"", &format!("\"verb\":\"{verb}\""));
            assert_eq!(parse(raw.as_bytes()).unwrap_err().code, Code::BadMessage);
        }
        for raw in [
            PREPARE.replace("\"text\":\"Check the task status.\"", "\"text\":\"\""),
            PREPARE.replace(
                "\"text\":\"Check the task status.\"",
                "\"prefer_live\":true",
            ),
            PREPARE.replace("\"text\":", "\"prefer_live\":false,\"text\":"),
            PREPARE.replace("\"params\":", "\"deadline\":1,\"params\":"),
            PREPARE.replace("\"kind\":\"execution\"", "\"kind\":\"session\""),
            PREPARE.replace("\"generation\":7", "\"generation\":7,\"extra\":true"),
            PREPARE.replace("\"generation\":7", "\"generation\":7,\"generation\":8"),
        ] {
            assert_eq!(parse(raw.as_bytes()).unwrap_err().code, Code::BadMessage);
        }
    }

    #[test]
    fn command_carriers_bind_their_own_correlations() {
        let commit = br#"{"v":1,"type":"commit","request_id":"6f1e2d3c4b5a69788796a5b4c3d2e1f0","intent":"bound","digest":"digest"}"#;
        assert!(matches!(
            decode(commit, 16, 4096, Carrier::Http).unwrap(),
            CommandRequest::Commit { id: None, intent, digest, .. }
                if intent == "bound" && digest == "digest"
        ));
        let lookup =
            r#"{"v":1,"type":"lookup","id":1,"request_id":"6f1e2d3c4b5a69788796a5b4c3d2e1f0"}"#;
        assert!(matches!(
            parse(lookup.as_bytes()).unwrap(),
            CommandRequest::Lookup { id: Some(1), request_id }
                if valid_request_id(&request_id)
        ));
        let lookup = lookup.replace(r#""id":1,"#, "");
        assert_eq!(
            decode(lookup.as_bytes(), 16, 4096, Carrier::Http)
                .unwrap_err()
                .code,
            Code::BadMessage
        );
    }

    #[test]
    fn oq13_digest_matches_frozen_selector_and_http_prepare() {
        let ws = prep(PREPARE.as_bytes());
        let http = PREPARE.replace("\"id\":6,", "");
        let CommandRequest::Prepare { id: None, request } =
            decode(http.as_bytes(), 16, 4096, Carrier::Http).unwrap()
        else {
            panic!("expected uncorrelated prepare")
        };
        assert_eq!(ws, request);
        let expected = "sha256:b7143a78da92c0e677f539819c4faf4342bd612b0448e18b5d3c5ebe1585e5a5";
        assert_eq!(
            request.digest(),
            expected,
            "canonical digest lost its selector"
        );
        let rebound = PREPARE.replace("\"generation\":7", "\"generation\":8");
        assert_ne!(prep(rebound.as_bytes()).digest(), expected);
        assert_eq!(
            decode(PREPARE.as_bytes(), 16, 4096, Carrier::Http)
                .unwrap_err()
                .code,
            Code::BadMessage
        );
        assert_eq!(parse(http.as_bytes()).unwrap_err().code, Code::BadMessage);

        let vectors: Value = serde_json::from_slice(include_bytes!(
            "../../tests/vectors/mission-control/v1/OQ13.json"
        ))
        .unwrap();
        for (input, output, carrier) in [
            ("c1_prepare", "c2_prepared", Carrier::WebSocket),
            (
                "c6_prepare_alternate",
                "c6_prepared_alternate",
                Carrier::WebSocket,
            ),
            ("c7_prepare", "c7_prepared", Carrier::Http),
        ] {
            let raw = serde_json::to_vec(&vectors[input]).unwrap();
            let CommandRequest::Prepare { request, .. } = decode(&raw, 16, 4096, carrier).unwrap()
            else {
                panic!("vector must be a prepare");
            };
            assert_eq!(
                request.digest(),
                vectors[output]["digest"],
                "canonical digest lost its selector"
            );
            assert_eq!(
                serde_json::to_value(&request.target.selector).unwrap(),
                vectors[output]["presentation"]["selector"]
            );
        }
        for (input, prepared, carrier) in [
            ("c6_commit", "c6_prepared_alternate", Carrier::WebSocket),
            ("c8_commit", "c7_prepared", Carrier::Http),
        ] {
            let raw = serde_json::to_vec(&vectors[input]).unwrap();
            let CommandRequest::Commit {
                intent,
                digest,
                request_id,
                ..
            } = decode(&raw, 16, 4096, carrier).unwrap()
            else {
                panic!("vector must be a commit");
            };
            assert_eq!(intent, vectors[prepared]["intent"]);
            assert_eq!(digest, vectors[prepared]["digest"]);
            assert_eq!(request_id, vectors[prepared]["request_id"]);
        }
        for (key, code) in [("c6_conflict", "conflict"), ("c9_conflict", "conflict")] {
            assert_eq!(vectors[key]["code"], code);
            assert!(vectors[key].get("target").is_none());
        }
        assert_eq!(vectors["c8_held"]["outcome"], "held");
    }
}
