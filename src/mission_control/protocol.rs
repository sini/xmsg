use serde::{Deserialize, Serialize};

use super::authority::Scope;
use crate::activity::{ActivityDescriptor, ActivityReason};
use crate::observe_export::{EndpointDescriptor, ExportEvent, ExportGap};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Delivery {
    Live,
    Delayed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ActivityAuthority {
    Disabled,
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Endpoint {
    pub descriptor: EndpointDescriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity: Option<ActivityDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_stale: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Exchange {
    pub event: ExportEvent,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeStatus {
    pub node: String,
    pub status: Status,
    pub delivery: Delivery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_source_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_hub: Option<String>,
    pub history_hidden: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Node {
    pub node: String,
    pub status: Status,
    pub delivery: Delivery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_source_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_hub: Option<String>,
    pub history_hidden: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_authority: Option<ActivityAuthority>,
    pub endpoints: Vec<Endpoint>,
    pub endpoints_truncated: bool,
    pub exchanges: Vec<Exchange>,
    pub source_gaps: Vec<ExportGap>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AttentionKind {
    BlockedInput,
    BlockedPermission,
    NodeStale,
    NodeUnreachable,
    NodeDenied,
    CoverageGap,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attention {
    pub id: String,
    pub kind: AttentionKind,
    pub node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub since: i64,
    pub detail: AttentionDetail,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttentionDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<ActivityReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_loss: Option<bool>,
    pub delivery: Delivery,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Delta {
    NodeStatus(NodeStatus),
    EndpointUpserted {
        node: String,
        #[serde(flatten)]
        endpoint: Endpoint,
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
        cleared_at: i64,
        #[serde(skip)]
        removed: Attention,
    },
}

impl Delta {
    pub(super) fn node(&self) -> &str {
        match self {
            Self::NodeStatus(status) => &status.node,
            Self::EndpointUpserted { node, .. }
            | Self::EndpointRemoved { node, .. }
            | Self::Exchange { node, .. }
            | Self::ActivityChanged { node, .. }
            | Self::SourceGap { node, .. } => node,
            Self::AttentionUpserted { item } | Self::AttentionCleared { removed: item, .. } => {
                &item.node
            }
        }
    }

    pub(super) fn contains_history(&self) -> bool {
        !matches!(self, Self::NodeStatus(_) | Self::AttentionCleared { .. })
    }
}

impl Node {
    pub(super) fn wire_status(&self) -> NodeStatus {
        NodeStatus {
            node: self.node.clone(),
            status: self.status,
            delivery: self.delivery,
            last_success_at: self.last_success_at,
            last_source_at: self.last_source_at,
            via_hub: self.via_hub.clone(),
            history_hidden: self.history_hidden,
        }
    }
}

pub(super) fn scope_node(scope: &Scope) -> Option<&str> {
    match scope {
        Scope::Fleet | Scope::Attention => None,
        Scope::Node { node } | Scope::Session { node, .. } => Some(node),
    }
}

fn allows_endpoint(scope: &Scope, node: &str, id: &str) -> bool {
    scope_node(scope).is_none_or(|name| name == node)
        && match scope {
            Scope::Session { endpoint, .. } => endpoint == id,
            _ => true,
        }
}

pub(super) struct Projection<'a> {
    pub scope: &'a Scope,
    pub grants: &'a [Scope],
    pub masked: &'a dyn Fn(&str) -> bool,
    pub activity: bool,
}

impl Projection<'_> {
    pub(super) fn node_allowed(&self, node: &str) -> bool {
        scope_node(self.scope).is_none_or(|name| name == node)
            && self.grants.iter().any(|scope| {
                self.grant_matches(scope) && scope_node(scope).is_none_or(|name| name == node)
            })
    }

    fn grant_matches(&self, grant: &Scope) -> bool {
        grant != &Scope::Attention || self.scope == &Scope::Attention
    }

    fn endpoint_granted(&self, node: &str, id: &str) -> bool {
        id.rsplit_once('@')
            .is_some_and(|(_, origin)| origin == node)
            && self
                .grants
                .iter()
                .any(|scope| self.grant_matches(scope) && allows_endpoint(scope, node, id))
    }

    pub(super) fn endpoint_allowed(&self, node: &str, id: &str) -> bool {
        !(self.masked)(node)
            && allows_endpoint(self.scope, node, id)
            && self.endpoint_granted(node, id)
    }

    pub(super) fn event_allowed(&self, node: &str, event: &ExportEvent) -> bool {
        let endpoints = [event.from.as_deref(), event.to.as_deref()];
        self.node_allowed(node)
            && !(self.masked)(node)
            && endpoints
                .into_iter()
                .flatten()
                .all(|id| self.endpoint_granted(node, id))
            && match self.scope {
                Scope::Session { endpoint, .. } => endpoints.contains(&Some(endpoint.as_str())),
                Scope::Attention => false,
                _ => true,
            }
    }

    pub(super) fn project_delta(&self, delta: &Delta) -> Option<Delta> {
        if self.scope == &Scope::Attention {
            return match delta {
                Delta::AttentionUpserted { item }
                | Delta::AttentionCleared { removed: item, .. }
                    if self.attention_allowed(&item.node, item.endpoint.as_deref()) =>
                {
                    Some(delta.clone())
                }
                _ => None,
            };
        }
        match delta {
            Delta::NodeStatus(status) if self.node_allowed(&status.node) => {
                let mut status = status.clone();
                status.history_hidden |= (self.masked)(&status.node);
                Some(Delta::NodeStatus(status))
            }
            Delta::EndpointUpserted { node, endpoint }
                if self.endpoint_allowed(node, &endpoint.descriptor.id) =>
            {
                let mut endpoint = endpoint.clone();
                self.project_activity(&mut endpoint);
                Some(Delta::EndpointUpserted {
                    node: node.clone(),
                    endpoint,
                })
            }
            Delta::EndpointRemoved { node, id } if self.endpoint_allowed(node, id) => {
                Some(delta.clone())
            }
            Delta::Exchange { node, event } if self.event_allowed(node, event) => {
                Some(delta.clone())
            }
            Delta::ActivityChanged { node, event }
                if self.activity && self.event_allowed(node, event) =>
            {
                Some(delta.clone())
            }
            Delta::SourceGap { node, .. } if self.node_allowed(node) && !(self.masked)(node) => {
                Some(delta.clone())
            }
            _ => None,
        }
    }

    fn project_activity(&self, endpoint: &mut Endpoint) {
        if !self.activity {
            endpoint.activity = None;
            endpoint.activity_stale = None;
            endpoint.descriptor.activity = None;
        }
    }

    pub(super) fn attention_allowed(&self, node: &str, endpoint: Option<&str>) -> bool {
        self.scope == &Scope::Attention
            && self.node_allowed(node)
            && endpoint.is_none_or(|id| self.activity && self.endpoint_allowed(node, id))
    }

    pub(super) fn project_node(&self, node: &Node) -> Option<Node> {
        let name = &node.node;
        if self.scope == &Scope::Attention || !self.node_allowed(name) {
            return None;
        }
        let mut projected = node.clone();
        projected.history_hidden |= (self.masked)(name);
        if projected.history_hidden || projected.status == Status::RemovedRetained {
            projected.endpoints.clear();
            projected.exchanges.clear();
            projected.source_gaps.clear();
            projected.endpoints_truncated = false;
            projected.activity_authority = None;
            return Some(projected);
        }
        projected
            .endpoints
            .retain(|ep| self.endpoint_allowed(name, &ep.descriptor.id));
        if matches!(self.scope, Scope::Fleet) {
            projected.exchanges.clear();
        } else {
            projected
                .exchanges
                .retain(|exchange| self.event_allowed(name, &exchange.event));
        }
        if !self.activity {
            projected.activity_authority = None;
            for endpoint in &mut projected.endpoints {
                self.project_activity(endpoint);
            }
        }
        Some(projected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe_export::{Availability, EventKind};

    #[test]
    fn all_event_paths_mask_nested_counterpart() {
        let session = Scope::Session {
            node: "laptop".into(),
            endpoint: "reader@laptop".into(),
        };
        let event = ExportEvent {
            sequence: 1,
            source_at: None,
            observed_at: 1,
            persisted_at: 1,
            kind: EventKind::MessageRecorded,
            from: Some("reader@laptop".into()),
            to: Some("private@laptop".into()),
            message_id: None,
            reply_id: None,
            thread_id: None,
            outcome: None,
            reason: None,
            available: Availability::NotRecorded,
            activity: None,
        };
        let delta = Delta::Exchange {
            node: "laptop".into(),
            event,
        };
        for (grants, masked, allowed) in [
            (&[Scope::Fleet][..], false, true),
            (std::slice::from_ref(&session), false, false),
            (&[Scope::Fleet][..], true, false),
        ] {
            let projection = Projection {
                scope: &session,
                grants,
                masked: &|_| masked,
                activity: true,
            };
            assert_eq!(projection.project_delta(&delta).is_some(), allowed);
        }
    }
}
