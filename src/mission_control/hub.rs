use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::authority::Scope;
use super::cursor::{CursorKey, Partition, ResumeFailure};
use super::protocol::{Attention, Delta, Node, Projection, Status};

const MAX_SEQUENCE: u64 = (1 << 53) - 1;

pub(super) struct ReplayLimits {
    pub events: usize,
    pub bytes: usize,
    pub window: Duration,
}

pub(super) struct Snapshot {
    pub nodes: Vec<Node>,
    pub attention: Option<Vec<Attention>>,
    pub watermark: u64,
}

pub(super) struct Frozen {
    pub nodes: Vec<Arc<Node>>,
    pub attention: Option<Vec<Attention>>,
    pub watermark: u64,
}

#[derive(Clone)]
pub(super) struct Sequenced {
    pub seq: u64,
    pub at: i64,
    pub delta: Delta,
}

struct Entry {
    update: Arc<Sequenced>,
    inserted: Instant,
    bytes: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Reset {
    CursorInvalid,
    CursorExpired,
    EpochChanged,
    ScopeChanged,
    SlowConsumer,
}

pub(super) struct Batch {
    pub events: Vec<Sequenced>,
    pub through: u64,
    pub coalesced: bool,
}

const QUEUE_BYTES: usize = 1024 * 1024;
const QUEUE_MESSAGES: usize = 1024;

pub(super) struct Hub {
    key: CursorKey,
    limits: ReplayLimits,
    seq: u64,
    bytes: usize,
    replay: VecDeque<Entry>,
    nodes: BTreeMap<String, Arc<Node>>,
    history_barriers: BTreeMap<String, u64>,
    attention: BTreeMap<String, Attention>,
}

impl Hub {
    pub(super) fn new(limits: ReplayLimits) -> Result<Self, ring::error::Unspecified> {
        Ok(Self {
            key: CursorKey::new()?,
            limits,
            seq: 0,
            bytes: 0,
            replay: VecDeque::new(),
            nodes: BTreeMap::new(),
            history_barriers: BTreeMap::new(),
            attention: BTreeMap::new(),
        })
    }

    pub(super) fn watermark(&self) -> u64 {
        self.seq
    }

    pub(super) fn epoch(&self) -> String {
        self.key.epoch()
    }

    pub(super) fn cursor(&self, seq: u64, partition: &Partition) -> String {
        self.key.issue(seq, partition)
    }

    pub(super) fn hide(
        &mut self,
        name: &str,
        denied: bool,
        at: i64,
        now: Instant,
    ) -> Result<(), serde_json::Error> {
        let Some(mut node) = self.nodes.get(name).map(|node| (**node).clone()) else {
            return Ok(());
        };
        node.history_hidden = true;
        node.status = if denied {
            Status::Denied
        } else {
            Status::PendingRevalidation
        };
        node.endpoints.clear();
        node.exchanges.clear();
        node.source_gaps.clear();
        node.endpoints_truncated = false;
        node.activity_authority = None;
        let (status_since, coverage_since) = self.condition_since(&node, false, at);
        let items = super::attention::derive(
            &node,
            &super::attention::ObservedCondition {
                status_since,
                coverage_since,
                unreachable: false,
            },
        );
        self.apply(node, items, Vec::new(), at, now)
    }

    pub(super) fn apply(
        &mut self,
        node: Node,
        items: Vec<Attention>,
        mut deltas: Vec<Delta>,
        at: i64,
        now: Instant,
    ) -> Result<(), serde_json::Error> {
        let next_status = node.wire_status();
        let previous = self.nodes.get(&node.node);
        if previous.is_none_or(|old| old.wire_status() != next_status) {
            deltas.insert(0, Delta::NodeStatus(next_status));
        }
        if !node.history_hidden && node.status != Status::RemovedRetained {
            let previous = previous
                .map(|old| {
                    old.endpoints
                        .iter()
                        .map(|ep| (ep.descriptor.id.as_str(), ep))
                        .collect::<BTreeMap<_, _>>()
                })
                .unwrap_or_default();
            for ep in &node.endpoints {
                let unchanged = match previous.get(ep.descriptor.id.as_str()) {
                    Some(old) => serde_json::to_vec(old)? == serde_json::to_vec(ep)?,
                    None => false,
                };
                if !unchanged {
                    deltas.push(Delta::EndpointUpserted {
                        node: node.node.clone(),
                        endpoint: ep.clone(),
                    });
                }
            }
            for id in previous.keys() {
                if !node.endpoints.iter().any(|ep| ep.descriptor.id == *id) {
                    deltas.push(Delta::EndpointRemoved {
                        node: node.node.clone(),
                        id: (*id).to_owned(),
                    });
                }
            }
        }
        let next_items: BTreeMap<_, _> = items
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect();
        for (id, old) in &self.attention {
            if old.node == node.node && !next_items.contains_key(id) {
                deltas.push(Delta::AttentionCleared {
                    id: id.clone(),
                    cleared_at: at,
                    removed: old.clone(),
                });
            }
        }
        for (id, item) in &next_items {
            if self.attention.get(id) != Some(item) {
                deltas.push(Delta::AttentionUpserted { item: item.clone() });
            }
        }
        let entries = deltas
            .into_iter()
            .map(|delta| {
                let bytes = serde_json::to_vec(&delta)?.len();
                Ok((delta, bytes))
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()?;
        if self.seq.saturating_add(entries.len() as u64) > MAX_SEQUENCE {
            return Err(<serde_json::Error as serde::ser::Error>::custom(
                "sequence exhausted",
            ));
        }
        if previous.is_some_and(|old| old.history_hidden != node.history_hidden)
            || node.status == Status::RemovedRetained
        {
            self.history_barriers.insert(node.node.clone(), self.seq);
        }
        self.attention.retain(|_, item| item.node != node.node);
        self.attention.extend(next_items);
        self.nodes.insert(node.node.clone(), Arc::new(node));
        for (delta, bytes) in entries {
            self.append_encoded(delta, bytes, at, now);
        }
        Ok(())
    }

    pub(super) fn condition_since(&self, node: &Node, unreachable: bool, now: i64) -> (i64, i64) {
        use super::protocol::AttentionKind;
        let wanted_status = if node.status == Status::Denied {
            AttentionKind::NodeDenied
        } else if unreachable {
            AttentionKind::NodeUnreachable
        } else {
            AttentionKind::NodeStale
        };
        let since = |kind| {
            self.attention
                .values()
                .find(|item| item.node == node.node && item.kind == kind)
                .map_or(now, |item| item.since)
        };
        (since(wanted_status), since(AttentionKind::CoverageGap))
    }

    pub(super) fn scope_available(&self, projection: &Projection<'_>) -> bool {
        match projection.scope {
            Scope::Fleet | Scope::Attention => !projection.grants.is_empty(),
            Scope::Node { node } => self.nodes.get(node).is_some_and(|view| {
                view.status != Status::RemovedRetained
                    && !view.history_hidden
                    && !(projection.masked)(node)
                    && projection.node_allowed(node)
            }),
            Scope::Session { node, endpoint } => self.nodes.get(node).is_some_and(|view| {
                view.status != Status::RemovedRetained
                    && !view.history_hidden
                    && projection.endpoint_allowed(node, endpoint)
                    && view
                        .endpoints
                        .iter()
                        .any(|entry| entry.descriptor.id == *endpoint)
            }),
        }
    }

    pub(super) fn frozen(&self, projection: &Projection<'_>) -> Frozen {
        let attention = (projection.scope == &Scope::Attention).then(|| {
            let mut items: Vec<_> = self
                .attention
                .values()
                .filter(|item| projection.attention_allowed(&item.node, item.endpoint.as_deref()))
                .cloned()
                .collect();
            items.sort_by(|a, b| (a.since, &a.id).cmp(&(b.since, &b.id)));
            items
        });
        Frozen {
            nodes: self
                .nodes
                .values()
                .filter(|node| projection.node_allowed(&node.node))
                .cloned()
                .collect(),
            attention,
            watermark: self.seq,
        }
    }

    pub(super) fn snapshot(&self, projection: &Projection<'_>) -> Snapshot {
        let frozen = self.frozen(projection);
        Snapshot {
            nodes: frozen
                .nodes
                .iter()
                .filter_map(|node| projection.project_node(node))
                .collect(),
            attention: frozen.attention,
            watermark: frozen.watermark,
        }
    }

    pub(super) fn append(
        &mut self,
        delta: Delta,
        at: i64,
        now: Instant,
    ) -> Result<(), serde_json::Error> {
        let seq = self
            .seq
            .checked_add(1)
            .filter(|&seq| seq <= MAX_SEQUENCE)
            .ok_or_else(|| {
                <serde_json::Error as serde::ser::Error>::custom("sequence exhausted")
            })?;
        let bytes = serde_json::to_vec(&delta)?.len();
        debug_assert_eq!(seq, self.seq + 1);
        self.append_encoded(delta, bytes, at, now);
        Ok(())
    }

    fn append_encoded(&mut self, delta: Delta, bytes: usize, at: i64, now: Instant) {
        self.seq += 1;
        if bytes <= self.limits.bytes {
            self.bytes += bytes;
            self.replay.push_back(Entry {
                update: Arc::new(Sequenced {
                    seq: self.seq,
                    at,
                    delta,
                }),
                inserted: now,
                bytes,
            });
            self.expire(now);
        } else {
            self.bytes = 0;
            self.replay.clear();
        }
    }

    pub(super) fn resume(
        &mut self,
        cursor: &str,
        partition: &Partition,
        now: Instant,
    ) -> Result<u64, Reset> {
        let seq = self
            .key
            .verify(cursor, partition)
            .map_err(|error| match error {
                ResumeFailure::Invalid => Reset::CursorInvalid,
                ResumeFailure::EpochChanged => Reset::EpochChanged,
            })?;
        self.check_sequence(seq, now)?;
        Ok(seq)
    }

    pub(super) fn after(
        &mut self,
        seq: u64,
        now: Instant,
    ) -> Result<impl Iterator<Item = &Sequenced>, Reset> {
        self.check_sequence(seq, now)?;
        let view: &Self = self;
        Ok(view
            .replay
            .iter()
            .filter(move |entry| entry.update.seq > seq && view.current(&entry.update))
            .map(|entry| entry.update.as_ref()))
    }

    pub(super) fn project_after(
        &mut self,
        seq: u64,
        projection: &Projection<'_>,
        cap: usize,
        replaying: bool,
        now: Instant,
    ) -> Result<Batch, Reset> {
        self.check_sequence(seq, now)?;
        let mut history = Vec::new();
        let mut bytes: usize = 0;
        for entry in self
            .replay
            .iter()
            .filter(|entry| entry.update.seq > seq && self.current(&entry.update))
        {
            if projection.project_delta(&entry.update.delta).is_none() {
                continue;
            }
            bytes = bytes.saturating_add(entry.bytes);
            history.push(entry);
        }
        let original = history.len();
        if !replaying && (bytes > QUEUE_BYTES / 2 || history.len() > QUEUE_MESSAGES / 2) {
            let mut keys = std::collections::HashSet::new();
            history.reverse();
            history.retain(|&entry| {
                let keep = entry
                    .update
                    .delta
                    .coalesce_key()
                    .is_none_or(|key| keys.insert(key));
                if !keep {
                    bytes -= entry.bytes;
                }
                keep
            });
            history.reverse();
        }
        if !replaying && (bytes > QUEUE_BYTES || history.len() > QUEUE_MESSAGES) {
            return Err(Reset::SlowConsumer);
        }
        let retained = history.len();
        let mut events = Vec::new();
        let mut through = seq;
        let mut queued_bytes = 0usize;
        for entry in history {
            if events.len() == cap
                || (!events.is_empty() && queued_bytes.saturating_add(entry.bytes) > QUEUE_BYTES)
            {
                break;
            }
            queued_bytes = queued_bytes.saturating_add(entry.bytes);
            through = entry.update.seq;
            let Some(delta) = projection.project_delta(&entry.update.delta) else {
                continue;
            };
            events.push(Sequenced {
                delta,
                seq: entry.update.seq,
                at: entry.update.at,
            });
        }
        if events.len() == retained {
            through = self.seq;
        }
        Ok(Batch {
            events,
            through,
            coalesced: original != retained,
        })
    }

    pub(super) fn current(&self, event: &Sequenced) -> bool {
        !event.delta.contains_history()
            || self
                .history_barriers
                .get(event.delta.node())
                .is_none_or(|&barrier| event.seq > barrier)
    }

    fn check_sequence(&mut self, seq: u64, now: Instant) -> Result<(), Reset> {
        self.expire(now);
        let floor = self
            .replay
            .front()
            .map_or(self.seq, |entry| entry.update.seq - 1);
        if seq < floor {
            return Err(Reset::CursorExpired);
        }
        if seq > self.seq {
            return Err(Reset::CursorInvalid);
        }
        Ok(())
    }

    fn expire(&mut self, now: Instant) {
        while self.replay.front().is_some_and(|entry| {
            self.replay.len() > self.limits.events
                || self.bytes > self.limits.bytes
                || now.saturating_duration_since(entry.inserted) > self.limits.window
        }) {
            self.bytes -= self.replay.pop_front().expect("nonempty replay").bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_watermark_is_followed_by_ordered_replay_or_reset() {
        let mut hub = Hub::new(ReplayLimits {
            events: 2,
            bytes: 1024,
            window: Duration::from_secs(2),
        })
        .unwrap();
        let partition = Partition::new(b"fleet", b"local-record", 1);
        let now = Instant::now();
        let event = || Delta::EndpointRemoved {
            node: "laptop".to_owned(),
            id: "endpoint@laptop".to_owned(),
        };
        hub.append(event(), 12, now).unwrap();
        let snapshot = hub.snapshot(&Projection {
            scope: &Scope::Fleet,
            grants: &[Scope::Fleet],
            masked: &|_| false,
            activity: true,
        });
        let cursor = hub.cursor(snapshot.watermark, &partition);
        hub.append(event(), 13, now).unwrap();
        hub.append(event(), 14, now).unwrap();
        let after = hub.resume(&cursor, &partition, now).unwrap();
        assert_eq!(
            hub.after(after, now)
                .unwrap()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        hub.append(event(), 15, now).unwrap();
        assert_eq!(
            hub.resume(&cursor, &partition, now),
            Err(Reset::CursorExpired)
        );
    }
    #[test]
    fn sustained_backlog_coalesces_state_and_resets_history_without_silent_loss() {
        use crate::observe_export::{Availability, EventKind, ExportEvent};
        let mut hub = Hub::new(ReplayLimits {
            events: 4096,
            bytes: 8 * 1024 * 1024,
            window: Duration::from_secs(120),
        })
        .unwrap();
        let now = Instant::now();
        let projection = Projection {
            scope: &Scope::Fleet,
            grants: &[Scope::Fleet],
            masked: &|_| false,
            activity: true,
        };
        let state = || Delta::EndpointRemoved {
            node: "laptop".into(),
            id: "agent@laptop".into(),
        };
        let exchange = |seq| Delta::Exchange {
            node: "laptop".into(),
            event: ExportEvent {
                sequence: seq,
                kind: EventKind::MessageRecorded,
                source_at: None,
                observed_at: 100,
                persisted_at: 100,
                from: Some("agent@laptop".into()),
                to: Some("worker@laptop".into()),
                message_id: None,
                reply_id: None,
                thread_id: None,
                outcome: None,
                reason: None,
                available: Availability::NotRecorded,
                activity: None,
            },
        };
        for _ in 0..550 {
            hub.append(state(), 100, now).unwrap();
        }
        hub.append(exchange(1), 100, now).unwrap();
        hub.append(exchange(2), 100, now).unwrap();
        let batch = hub.project_after(0, &projection, 8, false, now).unwrap();
        assert!(batch.coalesced);
        assert_eq!(
            batch
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            [550, 551, 552],
            "history events cannot coalesce"
        );
        for seq in 0..1024 {
            hub.append(exchange(seq), 100, now).unwrap();
        }
        assert!(
            matches!(
                hub.project_after(0, &projection, 8, false, now),
                Err(Reset::SlowConsumer)
            ),
            "overflow must reset instead of silently dropping history"
        );
    }
}
