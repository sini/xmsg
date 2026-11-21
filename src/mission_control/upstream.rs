use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::attention::{self, ObservedCondition};
use super::cursor::Partition;
use super::hub::{Hub, ReplayLimits, Reset, Sequenced, Snapshot};
use super::protocol::{
    ActivityAuthority, Delivery, Delta, Endpoint, Exchange, Node, Projection, Status,
};
use crate::activity::{reconcile::CollectorActivityReconciler, ActivityStatus};
use crate::observe_collector_store::{NodeStatus, NodeView, UnavailableKind};
use crate::observe_export::{EventKind, ExportGap};

pub(crate) struct ReadHub {
    state: Mutex<ReadState>,
    changed: tokio::sync::watch::Sender<u64>,
    pub(super) budgets: std::sync::Arc<super::budgets::Budgets>,
}

struct ReadState {
    hub: Hub,
    poll: BTreeMap<String, PollSource>,
}

impl ReadHub {
    pub(crate) fn new() -> Result<Self, ring::error::Unspecified> {
        Ok(Self {
            changed: tokio::sync::watch::channel(0).0,
            budgets: std::sync::Arc::default(),
            state: Mutex::new(ReadState {
                hub: Hub::new(ReplayLimits {
                    events: 4096,
                    bytes: 8 * 1024 * 1024,
                    window: Duration::from_secs(120),
                })?,
                poll: BTreeMap::new(),
            }),
        })
    }

    pub(crate) fn accept_poll(
        &self,
        view: NodeView,
        success_at: Option<i64>,
        stale: bool,
        now: i64,
    ) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        let update = state
            .poll
            .entry(view.node.clone())
            .or_default()
            .update(view, success_at, stale);
        update
            .apply(&mut state.hub, milliseconds(now), Instant::now())
            .map_err(|_| ())?;
        self.changed.send_if_modified(|seq| {
            if *seq == state.hub.watermark() {
                false
            } else {
                *seq = state.hub.watermark();
                true
            }
        });
        Ok(())
    }

    pub(crate) fn mask_poll(&self, node: &str, denied: bool, now: i64) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        state.poll.remove(node);
        state
            .hub
            .hide(node, denied, milliseconds(now), Instant::now())
            .map_err(|_| ())?;
        self.changed.send_replace(state.hub.watermark());
        Ok(())
    }

    pub(super) fn snapshot(
        &self,
        projection: &Projection<'_>,
    ) -> Result<Option<(Snapshot, String)>, ()> {
        let state = self.state.lock().map_err(|_| ())?;
        Ok(state
            .hub
            .scope_available(projection)
            .then(|| (state.hub.snapshot(projection), state.hub.epoch())))
    }

    pub(super) fn subscribed_snapshot(
        &self,
        projection: &Projection<'_>,
    ) -> Result<(Snapshot, String), ()> {
        let state = self.state.lock().map_err(|_| ())?;
        Ok((state.hub.snapshot(projection), state.hub.epoch()))
    }

    pub(super) fn cursor(&self, seq: u64, partition: &Partition) -> Result<String, ()> {
        let state = self.state.lock().map_err(|_| ())?;
        Ok(state.hub.cursor(seq, partition))
    }

    pub(super) fn resume(&self, cursor: &str, partition: &Partition) -> Result<u64, Reset> {
        let mut state = self.state.lock().map_err(|_| Reset::EpochChanged)?;
        state.hub.resume(cursor, partition, Instant::now())
    }

    pub(super) fn after(
        &self,
        seq: u64,
        projection: &Projection<'_>,
        cap: usize,
    ) -> Result<(Vec<Sequenced>, u64), Reset> {
        let mut state = self.state.lock().map_err(|_| Reset::EpochChanged)?;
        let mut delivered_through = seq;
        let mut output = Vec::new();
        for event in state.hub.after(seq, Instant::now())? {
            if let Some(delta) = projection.project_delta(&event.delta) {
                if output.len() == cap {
                    return Ok((output, delivered_through));
                }
                output.push(Sequenced {
                    delta,
                    ..event.clone()
                });
            }
            delivered_through = event.seq;
        }
        Ok((output, delivered_through.max(state.hub.watermark())))
    }

    pub(super) fn current(&self, event: &Sequenced) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.hub.current(event))
    }

    pub(crate) fn wake(&self) {
        self.changed.send_modify(|_| {});
    }

    pub(super) fn watch(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }
}

pub(super) struct Update {
    pub node: Node,
    pub unreachable: bool,
    pub events: Vec<Delta>,
}

impl Update {
    pub(super) fn apply(
        self,
        hub: &mut Hub,
        at: i64,
        now: Instant,
    ) -> Result<(), serde_json::Error> {
        let (status_since, coverage_since) = hub.condition_since(&self.node, self.unreachable, at);
        let condition = ObservedCondition {
            status_since,
            coverage_since,
            unreachable: self.unreachable,
        };
        let items = attention::derive(&self.node, &condition);
        hub.apply(self.node, items, self.events, at, now)
    }
}

#[derive(Default)]
pub(super) struct PollSource {
    seen_scope: Option<String>,
    snapshot_at: Option<i64>,
    journal_epoch: Option<String>,
    sequence: i64,
    gaps: Vec<ExportGap>,
    reconciler: CollectorActivityReconciler,
}

impl PollSource {
    pub(super) fn update(
        &mut self,
        view: NodeView,
        success_at: Option<i64>,
        stale: bool,
    ) -> Update {
        let status = match view.status {
            NodeStatus::Loading => Status::Loading,
            NodeStatus::HiddenPendingRevalidation => Status::PendingRevalidation,
            NodeStatus::Healthy if stale => Status::Stale,
            NodeStatus::Healthy => Status::Healthy,
            NodeStatus::Stale => Status::Stale,
            NodeStatus::Denied => Status::Denied,
            NodeStatus::Unsupported if view.origin_hub.is_none() => Status::UnsupportedOutboundOnly,
            NodeStatus::Unsupported => Status::UnsupportedTransport,
            NodeStatus::StorageFull => Status::StorageFull,
            NodeStatus::RemovedRetained => Status::RemovedRetained,
        };
        let unreachable = view.failure == Some(UnavailableKind::Unreachable);
        let mut node = Node {
            node: view.node,
            status,
            delivery: Delivery::Delayed,
            last_success_at: success_at.map(milliseconds),
            last_source_at: None,
            via_hub: view.origin_hub,
            history_hidden: view.history_hidden,
            last_activity_at: view.last_activity.map(|(at, _)| milliseconds(at)),
            activity_authority: None,
            endpoints: Vec::new(),
            endpoints_truncated: false,
            exchanges: Vec::new(),
            source_gaps: Vec::new(),
        };
        if node.history_hidden || matches!(status, Status::Denied | Status::RemovedRetained) {
            self.reconciler.revoke_node(&node.node);
            self.seen_scope = None;
            self.snapshot_at = None;
            self.gaps.clear();
            return Update {
                node,
                unreachable,
                events: Vec::new(),
            };
        }
        let scope = view
            .cursor
            .as_ref()
            .and_then(|cursor| cursor.scope.as_deref());
        if self.seen_scope.as_deref() != scope {
            self.seen_scope = scope.map(str::to_owned);
            self.reconciler.revoke_node(&node.node);
            self.snapshot_at = None;
            self.journal_epoch = None;
            self.sequence = 0;
            self.gaps.clear();
        }
        let epoch = view
            .cursor
            .as_ref()
            .and_then(|cursor| cursor.epoch.as_deref());
        if self.journal_epoch.as_deref() != epoch {
            self.journal_epoch = epoch.map(str::to_owned);
            self.sequence = 0;
        }
        if let Some(cached) = view.latest_snapshot {
            let snapshot = cached.snapshot;
            node.last_source_at = Some(milliseconds(snapshot.observed_at));
            node.activity_authority = Some(match snapshot.activity.status {
                ActivityStatus::Disabled => ActivityAuthority::Disabled,
                ActivityStatus::Enabled if snapshot.activity.complete && !snapshot.truncated => {
                    ActivityAuthority::Complete
                }
                ActivityStatus::Enabled => ActivityAuthority::Incomplete,
            });
            if self.snapshot_at != Some(cached.received_at) {
                self.reconciler
                    .apply_snapshot(&snapshot, cached.received_at);
                self.snapshot_at = Some(cached.received_at);
            }
            node.endpoints_truncated = snapshot.truncated;
            node.endpoints = snapshot
                .endpoints
                .into_iter()
                .map(|descriptor| Endpoint {
                    descriptor,
                    activity: None,
                    activity_stale: None,
                })
                .collect();
        }
        let mut deltas = Vec::new();
        for cached in view.events.into_iter().rev() {
            let event = cached.event;
            let observed_at = milliseconds(event.observed_at);
            node.last_source_at = Some(
                node.last_source_at
                    .map_or(observed_at, |at| at.max(observed_at)),
            );
            let new = epoch == Some(cached.epoch.as_str()) && event.sequence > self.sequence;
            if new {
                self.sequence = event.sequence;
            }
            if event.kind == EventKind::ActivityChanged {
                if new {
                    if let Some(scope) = scope {
                        self.reconciler.apply_event(
                            &node.node,
                            scope,
                            &cached.epoch,
                            &event,
                            cached.received_at,
                        );
                    }
                    if node.activity_authority != Some(ActivityAuthority::Disabled) {
                        deltas.push(Delta::ActivityChanged {
                            node: node.node.clone(),
                            event,
                        });
                    }
                }
            } else {
                if new {
                    deltas.push(Delta::Exchange {
                        node: node.node.clone(),
                        event: event.clone(),
                    });
                }
                node.exchanges.push(Exchange { event });
            }
        }
        if let Some(activity) = self.reconciler.nodes.get(&node.node) {
            for endpoint in &mut node.endpoints {
                if let Some(value) = activity.endpoints.get(&endpoint.descriptor.id) {
                    endpoint.activity = Some(value.descriptor.clone());
                    endpoint.activity_stale = Some(value.stale);
                }
            }
        }
        for gap in &view.gaps {
            if !self.gaps.contains(gap) {
                deltas.push(Delta::SourceGap {
                    node: node.node.clone(),
                    gap: gap.clone(),
                });
            }
        }
        self.gaps.clone_from(&view.gaps);
        node.source_gaps = view.gaps;
        Update {
            node,
            unreachable,
            events: deltas,
        }
    }
}

fn milliseconds(seconds: i64) -> i64 {
    seconds.saturating_mul(1000)
}
