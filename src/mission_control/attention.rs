use sha2::{Digest, Sha256};

use super::protocol::{ActivityAuthority, Attention, AttentionDetail, AttentionKind, Node, Status};
use crate::activity::{ActivityDescriptor, ActivityState, BlockKind};

pub(super) struct ObservedCondition {
    pub status_since: i64,
    pub coverage_since: i64,
    pub unreachable: bool,
}

fn item(
    node: &Node,
    kind: AttentionKind,
    endpoint: Option<&str>,
    activity: Option<&ActivityDescriptor>,
    since: i64,
    unknown_loss: Option<bool>,
) -> Attention {
    let identity = serde_json::to_vec(&(
        kind,
        &node.node,
        endpoint,
        activity.map(|a| &a.state_epoch),
        activity.map(|a| a.incarnation),
        activity.and_then(|a| a.block),
    ))
    .expect("attention identity is JSON serializable");
    let digest = Sha256::digest(identity);
    Attention {
        id: format!("att_{}", hex::encode(&digest[..16])),
        kind,
        node: node.node.clone(),
        endpoint: endpoint.map(str::to_owned),
        since,
        detail: AttentionDetail {
            reason: activity.and_then(|a| a.reason),
            unknown_loss,
            delivery: node.delivery,
        },
    }
}

pub(super) fn derive(node: &Node, condition: &ObservedCondition) -> Vec<Attention> {
    if node.status == Status::RemovedRetained {
        return Vec::new();
    }
    let mut items = Vec::new();
    let node_condition = if node.status == Status::Denied {
        Some(AttentionKind::NodeDenied)
    } else if condition.unreachable {
        Some(AttentionKind::NodeUnreachable)
    } else if node.status == Status::Stale {
        Some(AttentionKind::NodeStale)
    } else {
        None
    };
    if let Some(kind) = node_condition {
        items.push(item(node, kind, None, None, condition.status_since, None));
    }
    if node.history_hidden || node.status == Status::Denied {
        return items;
    }
    let unknown_loss = node.source_gaps.iter().any(|gap| gap.unknown_loss);
    if unknown_loss
        || node.endpoints_truncated
        || node.activity_authority == Some(ActivityAuthority::Incomplete)
    {
        items.push(item(
            node,
            AttentionKind::CoverageGap,
            None,
            None,
            condition.coverage_since,
            Some(unknown_loss),
        ));
    }
    if matches!(node.status, Status::Stale) || condition.unreachable {
        return items;
    }
    for endpoint in &node.endpoints {
        let Some(activity) = endpoint.activity.as_ref().filter(|activity| {
            activity.state == ActivityState::Blocked
                && endpoint.activity_stale != Some(true)
                && activity.is_valid()
        }) else {
            continue;
        };
        let kind = match activity.block.expect("valid blocked activity has a block") {
            BlockKind::Input => AttentionKind::BlockedInput,
            BlockKind::Permission => AttentionKind::BlockedPermission,
        };
        items.push(item(
            node,
            kind,
            Some(&endpoint.descriptor.id),
            Some(activity),
            activity.changed_at.saturating_mul(1000),
            None,
        ));
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mission_control::protocol::Delivery;

    #[test]
    fn unreachable_takes_precedence_and_ids_survive_new_clock_observations() {
        let node = Node {
            node: "laptop".into(),
            status: Status::Stale,
            delivery: Delivery::Delayed,
            last_success_at: None,
            last_source_at: None,
            via_hub: None,
            history_hidden: false,
            last_activity_at: None,
            activity_authority: None,
            endpoints: vec![],
            endpoints_truncated: false,
            exchanges: vec![],
            source_gaps: vec![],
        };
        let mut condition = ObservedCondition {
            status_since: 10,
            coverage_since: 10,
            unreachable: true,
        };
        let first = derive(&node, &condition);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind, AttentionKind::NodeUnreachable);
        condition.status_since = 200;
        let second = derive(&node, &condition);
        assert_eq!(first[0].id, second[0].id);
        assert_eq!(
            derive(
                &Node {
                    status: Status::RemovedRetained,
                    ..node
                },
                &condition
            ),
            []
        );
    }
}
