use std::collections::HashMap;

use super::model::{ActivityDescriptor, ActivityState, ActivityStatus};
use crate::observe_export::{EventKind, ExportEvent, ExportSnapshot};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciledEndpoint {
    pub descriptor: ActivityDescriptor,
    pub stale: bool,
    pub received_at: i64,
}

#[derive(Clone, Debug, Default)]
pub struct NodeActivityState {
    pub scope: String,
    pub journal_epoch: String,
    pub disabled: bool,
    /// Authoritative fence `(state_epoch, revision)` from disabled or complete-absent snapshot.
    pub disable_fence: Option<(String, u64)>,
    pub current_state_epoch: Option<String>,
    pub endpoints: HashMap<String, ReconciledEndpoint>,
    pub endpoint_fences: HashMap<String, (String, u64)>,
}

/// Collector-side activity reconciler implementing §2.7, AE12, AE24, and AO8.
#[derive(Clone, Debug, Default)]
pub struct CollectorActivityReconciler {
    pub nodes: HashMap<String, NodeActivityState>,
}

impl CollectorActivityReconciler {
    pub fn apply_snapshot(&mut self, snapshot: &ExportSnapshot, received_at: i64) {
        let entry = self.nodes.entry(snapshot.node.clone()).or_default();
        if entry.scope != snapshot.scope {
            *entry = NodeActivityState {
                scope: snapshot.scope.clone(),
                ..Default::default()
            };
        }

        if snapshot.activity.status == ActivityStatus::Disabled {
            let max_rev = entry
                .endpoints
                .values()
                .map(|e| e.descriptor.revision)
                .max()
                .unwrap_or(0);
            let epoch = entry.current_state_epoch.clone().unwrap_or_default();
            entry.disabled = true;
            entry.disable_fence = Some((epoch, max_rev));
            entry.endpoints.clear();
            return;
        }

        // Verified re-enable via snapshot clears the disable fence.
        entry.disabled = false;
        entry.disable_fence = None;

        // Detect state_epoch change across snapshot.
        let snapshot_epoch = snapshot
            .endpoints
            .iter()
            .filter_map(|e| e.activity.as_ref().map(|a| a.state_epoch.clone()))
            .next();
        if let Some(ref ep) = snapshot_epoch {
            if entry.current_state_epoch.as_deref() != Some(ep.as_str()) {
                entry.current_state_epoch = Some(ep.clone());
                entry.endpoints.clear();
                entry.endpoint_fences.clear();
            }
        }

        let max_snap_rev = snapshot
            .endpoints
            .iter()
            .filter_map(|e| e.activity.as_ref().map(|a| a.revision))
            .max()
            .unwrap_or(0);

        if snapshot.activity.complete && !snapshot.truncated {
            let present: std::collections::HashSet<&str> = snapshot
                .endpoints
                .iter()
                .filter(|e| e.activity.is_some())
                .map(|e| e.id.as_str())
                .collect();
            let epoch = entry.current_state_epoch.clone().unwrap_or_default();
            entry.endpoints.retain(|k, _| {
                if present.contains(k.as_str()) {
                    true
                } else {
                    entry
                        .endpoint_fences
                        .insert(k.clone(), (epoch.clone(), max_snap_rev));
                    false
                }
            });
        } else {
            // Incomplete or truncated snapshot: missing endpoints stay and are marked stale.
            let present: std::collections::HashSet<&str> =
                snapshot.endpoints.iter().map(|e| e.id.as_str()).collect();
            for (k, v) in &mut entry.endpoints {
                if !present.contains(k.as_str()) {
                    v.stale = true;
                }
            }
        }

        for ep in &snapshot.endpoints {
            let Some(ref desc) = ep.activity else {
                continue;
            };
            if !desc.is_valid() {
                continue;
            }
            if let Some((fe, fr)) = entry.endpoint_fences.get(&ep.id) {
                if fe == &desc.state_epoch && desc.revision <= *fr {
                    continue;
                }
            }
            let replace = match entry.endpoints.get(&ep.id) {
                None => true,
                Some(cur) => {
                    cur.descriptor.state_epoch != desc.state_epoch
                        || (desc.incarnation, desc.revision)
                            > (cur.descriptor.incarnation, cur.descriptor.revision)
                }
            };
            if replace {
                entry.endpoints.insert(
                    ep.id.clone(),
                    ReconciledEndpoint {
                        descriptor: desc.clone(),
                        stale: false,
                        received_at,
                    },
                );
            }
        }
    }

    /// Apply an `activity_changed` event. Returns `Some(true)` if this event is a newly
    /// witnessed eligible completion (`working|blocked -> idle` with no reason) for browser Done.
    pub fn apply_event(
        &mut self,
        node: &str,
        scope: &str,
        journal_epoch: &str,
        event: &ExportEvent,
        received_at: i64,
    ) -> bool {
        if event.kind != EventKind::ActivityChanged {
            return false;
        }
        let Some(ref from) = event.from else {
            return false;
        };
        let Some(ref desc) = event.activity else {
            return false;
        };
        if !desc.is_valid() {
            return false;
        }

        let entry = self.nodes.entry(node.to_owned()).or_default();
        if entry.scope != scope {
            *entry = NodeActivityState {
                scope: scope.to_owned(),
                journal_epoch: journal_epoch.to_owned(),
                ..Default::default()
            };
        } else if entry.journal_epoch.is_empty() {
            entry.journal_epoch = journal_epoch.to_owned();
        }

        // AE24: preserve authoritative disable fence until a verified re-enable snapshot.
        if entry.disabled {
            return false;
        }

        // A state_epoch change replaces state by snapshot only (AE12).
        match entry.current_state_epoch.as_deref() {
            Some(ep) if ep != desc.state_epoch => return false,
            None => entry.current_state_epoch = Some(desc.state_epoch.clone()),
            _ => {}
        }

        if let Some((fe, fr)) = entry.endpoint_fences.get(from) {
            if fe == &desc.state_epoch && desc.revision <= *fr {
                return false;
            }
        }

        let prior_state = entry.endpoints.get(from).map(|r| {
            (
                r.descriptor.incarnation,
                r.descriptor.revision,
                r.descriptor.state,
            )
        });

        if let Some((inc, rev, _)) = prior_state {
            if (desc.incarnation, desc.revision) <= (inc, rev) {
                return false;
            }
        }

        let witnessed_done = prior_state.is_some_and(|(_, _, prev)| {
            matches!(prev, ActivityState::Working | ActivityState::Blocked)
                && desc.state == ActivityState::Idle
                && desc.reason.is_none()
        });

        entry.endpoints.insert(
            from.clone(),
            ReconciledEndpoint {
                descriptor: desc.clone(),
                stale: false,
                received_at,
            },
        );
        witnessed_done
    }

    pub fn revoke_node(&mut self, node: &str) {
        self.nodes.remove(node);
    }
}
