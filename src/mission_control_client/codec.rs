use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::activity::{ActivityDescriptor, ActivityReason};
use crate::observe_export::{EndpointDescriptor, ExportEvent, ExportGap};

#[derive(Debug, thiserror::Error)]
#[error("collector sent an invalid Mission Control message")]
pub struct InvalidMessage;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    Hello {
        v: u8,
        re: u32,
        protocol: u8,
        capabilities: Vec<String>,
        connection: String,
        actor: Actor,
        lease_expires_at: u64,
        server_at: u64,
        limits: Limits,
    },
    Subscribed {
        v: u8,
        re: u32,
        sub: String,
        mode: Mode,
        stream_epoch: String,
    },
    Unsubscribed {
        v: u8,
        re: u32,
        sub: String,
    },
    Snapshot {
        v: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<String>,
        part: u32,
        #[serde(rename = "final")]
        final_part: bool,
        stream_epoch: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
        server_at: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        truncated: Option<bool>,
        nodes: Vec<Node>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attention: Option<Vec<Attention>>,
    },
    Event {
        v: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<String>,
        seq: u64,
        cursor: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        replayed: Option<bool>,
        at: u64,
        delta: Box<Delta>,
    },
    Gap {
        v: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<String>,
        reason: GapReason,
        unknown_loss: bool,
        reset: bool,
    },
    Tick {
        v: u8,
        server_at: u64,
    },
    Error {
        v: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        re: Option<u32>,
        code: ErrorCode,
        fatal: bool,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub principal: String,
    pub display: String,
    pub class: Class,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Browser,
    Native,
    Machine,
    Delegated,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_client_message_bytes: usize,
    pub max_server_message_bytes: usize,
    pub max_json_depth: usize,
    pub subscriptions_per_connection: usize,
    pub tick_interval_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Resume,
    Snapshot,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    Live,
    Delayed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Loading,
    PendingRevalidation,
    Healthy,
    Stale,
    Denied,
    UnsupportedOutboundOnly,
    UnsupportedTransport,
    StorageFull,
    RemovedRetained,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    Disabled,
    Complete,
    Incomplete,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub node: String,
    pub status: Status,
    pub delivery: Delivery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_source_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_hub: Option<String>,
    pub history_hidden: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_authority: Option<Authority>,
    pub endpoints: Vec<Endpoint>,
    pub endpoints_truncated: bool,
    pub exchanges: Vec<Exchange>,
    pub source_gaps: Vec<ExportGap>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub descriptor: EndpointDescriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity: Option<ActivityDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_stale: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    pub event: ExportEvent,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attention {
    pub id: String,
    pub kind: AttentionKind,
    pub node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub since: u64,
    pub detail: AttentionDetail,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<ActivityReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_loss: Option<bool>,
    pub delivery: Delivery,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionKind {
    BlockedInput,
    BlockedPermission,
    NodeStale,
    NodeUnreachable,
    NodeDenied,
    CoverageGap,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Delta {
    NodeStatus {
        node: String,
        status: Status,
        delivery: Delivery,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_success_at: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_source_at: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        via_hub: Option<String>,
        history_hidden: bool,
    },
    EndpointUpserted {
        node: String,
        descriptor: EndpointDescriptor,
        #[serde(skip_serializing_if = "Option::is_none")]
        activity: Option<ActivityDescriptor>,
        #[serde(skip_serializing_if = "Option::is_none")]
        activity_stale: Option<bool>,
    },
    EndpointRemoved {
        node: String,
        id: String,
    },
    Exchange {
        node: String,
        event: ExportEvent,
    },
    ActivityChanged {
        node: String,
        event: ExportEvent,
    },
    SourceGap {
        node: String,
        gap: ExportGap,
    },
    AttentionUpserted {
        item: Attention,
    },
    AttentionCleared {
        id: String,
        cleared_at: u64,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    CursorInvalid,
    CursorExpired,
    EpochChanged,
    ScopeChanged,
    SlowConsumer,
    Coalesced,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
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

pub fn decode(bytes: &[u8], maximum: usize) -> Result<Message, InvalidMessage> {
    if bytes.len() > maximum || !crate::activity::hook::check_json_depth(bytes, 16) {
        return Err(InvalidMessage);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| InvalidMessage)?;
    if value.get("v").and_then(Value::as_u64) != Some(1) || !within_bounds(&value) {
        return Err(InvalidMessage);
    }
    let message = serde_json::from_slice(bytes).map_err(|_| InvalidMessage)?;
    if matches!(&message, Message::Snapshot { final_part, cursor, truncated, .. }
        if *final_part != cursor.is_some() || *final_part != truncated.is_some())
    {
        return Err(InvalidMessage);
    }
    if matches!(
        &message,
        Message::Event {
            replayed: Some(false),
            ..
        }
    ) {
        return Err(InvalidMessage);
    }
    Ok(message)
}

fn within_bounds(value: &Value) -> bool {
    match value {
        Value::String(text) => text.len() <= 4096,
        Value::Number(number) => number.as_u64().is_some_and(|n| n < (1 << 53)),
        Value::Array(list) => list.iter().all(within_bounds),
        Value::Object(fields) => fields
            .iter()
            .all(|(name, value)| name.len() <= 4096 && within_bounds(value)),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_types_refuse_unknown_and_duplicate_members() {
        let valid = br#"{"v":1,"type":"tick","server_at":123}"#;
        assert!(matches!(
            decode(valid, 100),
            Ok(Message::Tick { server_at: 123, .. })
        ));
        for invalid in [
            br#"{"v":1,"type":"tick","server_at":123,"token":"no"}"#.as_slice(),
            br#"{"v":1,"type":"tick","server_at":123,"server_at":124}"#,
            br#"{"v":2,"type":"tick","server_at":123}"#,
        ] {
            assert!(decode(invalid, 100).is_err());
        }
    }
}
