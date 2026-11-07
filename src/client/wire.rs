use super::Origin;
use serde::{Deserialize, Serialize};

/// A service's registration frame on `register.sock`. Unknown fields are refused (plan
/// §6 D3); `harness` is the multiplexer's tag.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SvcRegisterRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    pub name: String,
    #[serde(default)]
    pub cwd: Option<String>,
}

/// A registered service's frames on `register.sock`: `poll`, `ack` and `reply`. It runs
/// `list`, `send` and `replies` over `agent.sock` (AM-4; plan §6 D15).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SvcFrame {
    Poll {
        #[serde(default, rename = "waitSecs")]
        wait_secs: Option<u64>,
    },
    Ack {
        #[serde(rename = "messageId")]
        message_id: String,
    },
    Reply {
        #[serde(rename = "messageId")]
        message_id: String,
        text: String,
        #[serde(default, rename = "idempotencyKey")]
        idempotency_key: Option<String>,
    },
}

/// One `agent.sock` request (AM-4): A13's four operations, mirroring the MCP tools field
/// for field with `idempotency_key` added, and the MCP server's registration. A frame with
/// a field it does not know is refused `bad_request`, naming the field (plan §6 D3).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentFrame {
    McpStart {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ls_address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        csrf_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        registered_at: Option<i64>,
    },
    List {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[allow(dead_code)]
        as_agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_thread: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_turn: Option<String>,
    },
    Send {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        to: String,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        as_agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_thread: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_turn: Option<String>,
    },
    Reply {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        message_id: String,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idempotency_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        as_agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_thread: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_turn: Option<String>,
    },
    Replies {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        message_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wait: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[allow(dead_code)]
        as_agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_thread: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_turn: Option<String>,
    },
    Inbox {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wait: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        as_agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_thread: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codex_turn: Option<String>,
    },
    Subagent {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        event: String,
        agent_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_use_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transcript_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pin_name: Option<String>,
    },
    CodexHook {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        event: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        payload: serde_json::Value,
    },
    #[serde(alias = "codex-revoke")]
    CodexRevoke {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema_version: Option<u32>,
        session_id: String,
        #[serde(default = "default_true")]
        revoked: bool,
    },
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub status: String,
    pub address: String,
    pub node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svc_queue_cap: Option<usize>,
    /// Effective maximum message body length in BYTES (`--max-body` / `XMSG_MAX_BODY`),
    /// sourced from `state.max_body` enforced by `surface::send` and `surface::reply`.
    /// `None` when registering against an older daemon that omits `max_body_bytes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryFrame {
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "fromName")]
    pub from_name: String,
    pub text: String,
    pub envelope: String,
    pub origin: Origin,
    #[serde(rename = "inReplyTo")]
    pub in_reply_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ServiceResponse {
    Deliver(Box<DeliveryFrame>),
    Timeout,
}

#[cfg(feature = "daemon")]
impl DeliveryFrame {
    pub fn envelope(self) -> ServiceResponse {
        ServiceResponse::Deliver(Box::new(self))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReplyRecord {
    pub seq: i64,
    pub message_id: String,
    pub created_at: i64,
    pub replier_session_id: String,
    pub text: String,
    #[serde(default)]
    pub push_outcome: Option<String>,
    #[serde(default)]
    pub pushed_message_id: Option<String>,
}

/// One entry of `list` (A13, A-12, A16, XL1, XF3): its address, kind, harness, label and
/// status (`live`, `parked` or `closed`), the node holding it, the user it belongs to, and
/// its timestamp (`registered_at` when live, `last_seen` when inactive).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub address: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub status: String,
    pub node: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
}

/// What `list` returns: the recipients, and how each node asked answered (A-12).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListResult {
    pub recipients: Vec<Recipient>,
    pub nodes: Vec<NodeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SendResult {
    pub message_id: String,
    pub address: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeStatus {
    pub node: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl NodeStatus {
    pub fn ok(node: &str) -> Self {
        Self {
            node: node.to_string(),
            status: "ok".to_string(),
            detail: None,
        }
    }

    #[cfg(feature = "daemon")]
    pub(crate) fn failed(node: &str, status: &str, detail: String) -> Self {
        Self {
            node: node.to_string(),
            status: status.to_string(),
            detail: Some(detail),
        }
    }
}
