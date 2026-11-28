use std::{fmt, marker::PhantomData};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::authority::Scope;

const SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Code {
    BadMessage,
    UnsupportedType,
    Unsupported,
    VersionMismatch,
    CapabilityUnavailable,
    NotFoundOrDenied,
    DuplicateSub,
    TooManySubscriptions,
    RateLimited,
    LeaseExpired,
    Revoked,
    PolicyChanged,
    Unauthenticated,
    Forbidden,
    Unavailable,
    Internal,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Hello {
        v: u8,
        id: u32,
        protocol: u64,
        capabilities: Vec<String>,
        #[serde(default)]
        require: Vec<String>,
        client: Option<Client>,
    },
    Subscribe {
        v: u8,
        id: u32,
        sub: String,
        scope: Scope,
        cursor: Option<String>,
    },
    Unsubscribe {
        v: u8,
        id: u32,
        sub: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Client {
    name: String,
    version: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RequestError {
    pub code: Code,
    pub reply: Option<u32>,
}

pub(super) fn decode(bytes: &[u8], depth: usize, strings: usize) -> Result<Request, RequestError> {
    let bad = |reply| RequestError {
        code: Code::BadMessage,
        reply,
    };
    let value = bounded_json(bytes, depth, strings).map_err(|_| bad(None))?;
    let object = value.as_object().ok_or_else(|| bad(None))?;
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| (1..=i32::MAX as u64).contains(id))
        .map(|id| id as u32)
        .ok_or_else(|| bad(None))?;
    let reply = Some(id);
    if object.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(bad(reply));
    }
    match object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| bad(reply))?
    {
        "hello" | "subscribe" | "unsubscribe" => {}
        "prepare" | "commit" | "lookup" => {
            return Err(RequestError {
                code: Code::Unsupported,
                reply,
            })
        }
        _ => {
            return Err(RequestError {
                code: Code::UnsupportedType,
                reply,
            })
        }
    }
    let request: Request = serde_json::from_value(value).map_err(|_| bad(reply))?;
    match &request {
        Request::Hello {
            capabilities,
            require,
            client,
            ..
        } => {
            if capabilities.len() > 8
                || require.len() > 8
                || !require.iter().all(|name| capabilities.contains(name))
                || client.as_ref().is_some_and(|client| {
                    client.name.len() > 64
                        || client.version.len() > 32
                        || !client.name.is_ascii()
                        || !client.version.is_ascii()
                })
            {
                return Err(bad(reply));
            }
        }
        Request::Subscribe {
            sub, scope, cursor, ..
        } => {
            if !valid_sub(sub)
                || !valid_scope(scope)
                || cursor.as_ref().is_some_and(|cursor| {
                    cursor.is_empty()
                        || cursor.len() > 512
                        || !cursor
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
            {
                return Err(bad(reply));
            }
        }
        Request::Unsubscribe { sub, .. } if !valid_sub(sub) => return Err(bad(reply)),
        _ => {}
    }
    Ok(request)
}

fn valid_sub(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

pub(super) fn valid_scope(scope: &Scope) -> bool {
    match scope {
        Scope::Fleet | Scope::Attention => true,
        Scope::Node { node } => super::authority::valid_node(node),
        Scope::Session { node, endpoint } => super::authority::valid_endpoint(node, endpoint),
    }
}

pub(super) fn bounded_json(
    bytes: &[u8],
    depth: usize,
    strings: usize,
) -> serde_json::Result<Value> {
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let value = JsonBound { depth, strings }.deserialize(&mut parser)?;
    parser.end()?;
    Ok(value)
}

#[derive(Clone, Copy)]
struct JsonBound {
    depth: usize,
    strings: usize,
}

impl<'de> DeserializeSeed<'de> for JsonBound {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        decoder.deserialize_any(BoundedVisitor(self, PhantomData))
    }
}

struct BoundedVisitor<'de>(JsonBound, PhantomData<&'de ()>);

impl<'de> Visitor<'de> for BoundedVisitor<'de> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON with unique keys and safe unsigned integers")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        if value > SAFE_INTEGER {
            return Err(E::custom("integer outside protocol range"));
        }
        Ok(value.into())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > self.0.strings {
            return Err(E::custom("string exceeds protocol bound"));
        }
        Ok(value.into())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let child = self.0.child()?;
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if key.len() > self.0.strings || map.contains_key(&key) {
                return Err(de::Error::custom("duplicate or oversized key"));
            }
            map.insert(key, access.next_value_seed(child)?);
        }
        Ok(Value::Object(map))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let child = self.0.child()?;
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(child)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
}

impl JsonBound {
    fn child<E: de::Error>(self) -> Result<Self, E> {
        let depth = self
            .depth
            .checked_sub(1)
            .ok_or_else(|| E::custom("JSON depth exceeds protocol bound"))?;
        Ok(Self { depth, ..self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_nested_fields_and_requires_explicit_version() {
        for invalid in [
            br#"{"v":1,"type":"subscribe","id":1,"sub":"a","scope":{"kind":"node","node":"a","node":"b"}}"#.as_slice(),
            br#"{"v":1,"type":"subscribe","id":1,"sub":"a","scope":{"kind":"fleet"},"token":"x"}"#,
            br#"{"type":"hello","id":1,"protocol":1,"capabilities":[]}"#,
        ] {
            assert_eq!(decode(invalid, 16, 4096).unwrap_err().code, Code::BadMessage);
        }
        assert!(matches!(
            decode(
                br#"{"v":1,"type":"subscribe","id":1,"sub":"a","scope":{"kind":"fleet"}}"#,
                16,
                4096
            ),
            Ok(Request::Subscribe { id: 1, .. })
        ));
    }
}

#[cfg(test)]
#[test]
fn client_vectors_hit_the_production_decoder() {
    use std::{fs, path::Path};
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/mission-control/v1");
    for name in ["V-H1", "V-S1", "V-S2", "V-S4", "V-U1"] {
        let file = fs::read(root.join(format!("{name}.json"))).unwrap();
        let file = String::from_utf8(file).unwrap().replace("<C>", "Y3Vyc29y");
        assert!(decode(file.as_bytes(), 16, 4096).is_ok(), "{name}");
    }
    for name in [
        "V-I1", "V-I3", "V-I4", "V-I5", "V-I7", "V-I8", "V-I10", "V-I25", "V-I26",
    ] {
        let file = fs::read(root.join(format!("{name}.json"))).unwrap();
        let code = if name == "V-I10" {
            Code::UnsupportedType
        } else {
            Code::BadMessage
        };
        assert_eq!(decode(&file, 16, 4096).unwrap_err().code, code, "{name}");
    }
    let command = fs::read(root.join("V-I11.json")).unwrap();
    assert_eq!(
        decode(&command, 16, 4096).unwrap_err().code,
        Code::Unsupported
    );
    let version = fs::read(root.join("V-I2.json")).unwrap();
    assert!(matches!(
        decode(&version, 16, 4096),
        Ok(Request::Hello { protocol: 2, .. })
    ));
}
