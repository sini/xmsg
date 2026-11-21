use crate::observe_export::{
    EventKind, ExportEvent, ExportPage, MAX_BYTES, MAX_EVENTS, MAX_EVENT_BYTES,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fmt;

#[derive(Clone)]
pub(crate) struct DecodedEvent {
    pub(crate) event: ExportEvent,
    pub(crate) canonical: Vec<u8>,
}
#[derive(Clone)]
pub(crate) struct DecodedPage {
    pub(crate) page: ExportPage,
    pub(crate) events: Vec<DecodedEvent>,
    pub(crate) canonical_len: usize,
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("invalid observation envelope")]
pub(crate) struct DecodeError;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON value")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Unique, M::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate field"));
                    }
                    values.insert(key, map.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(values)))
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Unique, S::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<Unique>()? {
                    values.push(value.0);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(
                    serde_json::Number::from_f64(v).ok_or_else(|| E::custom("invalid number"))?,
                )))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn decode_value(mut value: Value) -> Result<DecodedEvent, DecodeError> {
    let original = value.get("kind").ok_or(DecodeError)?;
    let kind = match serde_json::from_value::<EventKind>(original.clone()) {
        Ok(known) => serde_json::to_value(known)
            .map_err(|_| DecodeError)?
            .as_str()
            .ok_or(DecodeError)?
            .to_owned(),
        Err(_) => {
            let kind = original.as_str().ok_or(DecodeError)?;
            if kind.len() > 64
                || !kind.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                || !kind
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(DecodeError);
            }
            let kind = kind.to_owned();
            value["kind"] = Value::String("unknown".into());
            kind
        }
    };
    let event: ExportEvent = serde_json::from_value(value).map_err(|_| DecodeError)?;
    let canonical = canonical_event(&event, &kind)?;
    if canonical.len() > MAX_EVENT_BYTES {
        return Err(DecodeError);
    }
    Ok(DecodedEvent { event, canonical })
}

fn canonical_event(event: &ExportEvent, kind: &str) -> Result<Vec<u8>, DecodeError> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        sequence: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_at: Option<i64>,
        observed_at: i64,
        persisted_at: i64,
        kind: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        from: &'a Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        to: &'a Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_id: &'a Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reply_id: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        thread_id: &'a Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        outcome: Option<crate::observe_export::Outcome>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<crate::observe_export::Reason>,
        available: crate::observe_export::Availability,
        #[serde(skip_serializing_if = "Option::is_none")]
        activity: &'a Option<crate::activity::ActivityDescriptor>,
    }
    serde_json::to_vec(&Envelope {
        sequence: event.sequence,
        source_at: event.source_at,
        observed_at: event.observed_at,
        persisted_at: event.persisted_at,
        kind,
        from: &event.from,
        to: &event.to,
        message_id: &event.message_id,
        reply_id: event.reply_id,
        thread_id: &event.thread_id,
        outcome: event.outcome,
        reason: event.reason,
        available: event.available,
        activity: &event.activity,
    })
    .map_err(|_| DecodeError)
}

pub(crate) fn decode_event(bytes: &[u8]) -> Result<DecodedEvent, DecodeError> {
    decode_value(
        serde_json::from_slice::<Unique>(bytes)
            .map_err(|_| DecodeError)?
            .0,
    )
}
pub(crate) fn decode_page(bytes: &[u8]) -> Result<DecodedPage, DecodeError> {
    let mut value = serde_json::from_slice::<Unique>(bytes)
        .map_err(|_| DecodeError)?
        .0;
    let raw = value
        .get_mut("events")
        .and_then(Value::as_array_mut)
        .ok_or(DecodeError)?;
    if raw.len() > MAX_EVENTS {
        return Err(DecodeError);
    }
    let events = raw
        .iter_mut()
        .map(|value| decode_value(value.take()))
        .collect::<Result<Vec<_>, _>>()?;
    *raw = events
        .iter()
        .map(|value| serde_json::to_value(&value.event).map_err(|_| DecodeError))
        .collect::<Result<_, _>>()?;
    let page: ExportPage = serde_json::from_value(value).map_err(|_| DecodeError)?;
    finish_page(page, events)
}
fn finish_page(page: ExportPage, events: Vec<DecodedEvent>) -> Result<DecodedPage, DecodeError> {
    let normalized_len = serde_json::to_vec(&page).map_err(|_| DecodeError)?.len();
    let mut canonical_len = normalized_len;
    for event in &events {
        let typed_len = serde_json::to_vec(&event.event)
            .map_err(|_| DecodeError)?
            .len();
        canonical_len = canonical_len
            .checked_sub(typed_len)
            .and_then(|n| n.checked_add(event.canonical.len()))
            .ok_or(DecodeError)?;
    }
    if canonical_len > MAX_BYTES {
        return Err(DecodeError);
    }
    Ok(DecodedPage {
        page,
        events,
        canonical_len,
    })
}
pub(crate) fn from_typed_page(page: ExportPage) -> Result<DecodedPage, DecodeError> {
    decode_page(&serde_json::to_vec(&page).map_err(|_| DecodeError)?)
}

#[cfg(test)]
#[path = "observe_collector_decode_tests.rs"]
mod tests;
