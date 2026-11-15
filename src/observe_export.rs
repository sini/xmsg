use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_EVENTS: usize = 200;
pub const MAX_EVENT_BYTES: usize = 4096;
pub const MAX_BYTES: usize = 256 * 1024;
pub const MAX_CANDIDATES: usize = 8 * (MAX_EVENTS + 1);
const TTL: i64 = 7 * 86400;
const MAX_TIME: i64 = 253_402_300_799;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid observation export query")]
    BadQuery,
    #[error("invalid observation export source")]
    InvalidSource,
}

#[derive(Clone, Debug)]
pub struct Scope {
    node: String,
    targets: Option<BTreeSet<String>>,
    effective_labels: bool,
    fingerprint: String,
}
impl Scope {
    pub fn new(
        node: &str,
        peer: &str,
        targets: Option<&[String]>,
        effective_labels: bool,
    ) -> Result<Self, Error> {
        if !valid_node(node) || peer.is_empty() || peer.len() > 512 {
            return Err(Error::InvalidSource);
        }
        let targets = targets
            .map(|values| {
                values
                    .iter()
                    .map(|value| canonical_endpoint(value, node).ok_or(Error::InvalidSource))
                    .collect::<Result<BTreeSet<_>, _>>()
            })
            .transpose()?;
        let encoded = serde_json::to_vec(&(1, node, peer, &targets, effective_labels))
            .map_err(|_| Error::InvalidSource)?;
        let fingerprint = hex::encode(Sha256::digest(encoded));
        Ok(Self {
            node: node.into(),
            targets,
            effective_labels,
            fingerprint,
        })
    }
    pub fn node(&self) -> &str {
        &self.node
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn effective_labels(&self) -> bool {
        self.effective_labels
    }
    pub fn canonical_endpoint(&self, value: &str) -> Option<String> {
        canonical_endpoint(value, &self.node)
    }
    pub fn allows(&self, value: &str) -> bool {
        self.canonical_endpoint(value).is_some_and(|id| {
            self.targets
                .as_ref()
                .is_none_or(|targets| targets.contains(&id))
        })
    }
}
fn version() -> u8 {
    1
}
fn default_limit() -> usize {
    100
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportQuery {
    #[serde(default = "version")]
    pub v: u8,
    pub epoch: Option<String>,
    #[serde(default)]
    pub after: i64,
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub scope: Option<String>,
    #[serde(default)]
    pub labels: bool,
}
impl ExportQuery {
    pub fn validate(&self) -> Result<(), Error> {
        if self.v != 1
            || self.after < 0
            || !(1..=MAX_EVENTS).contains(&self.limit)
            || self
                .epoch
                .as_ref()
                .is_some_and(|epoch| epoch.is_empty() || epoch.len() > 128)
            || self.scope.as_ref().is_some_and(|scope| {
                scope.len() != 64
                    || !scope
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || (self.after > 0 && (self.epoch.is_none() || self.scope.is_none()))
        {
            return Err(Error::BadQuery);
        }
        Ok(())
    }
    pub fn journal_query(&self, scope: &Scope) -> Result<crate::observe::Query, Error> {
        self.validate()?;
        Ok(crate::observe::Query {
            epoch: self.epoch.clone(),
            after: Some(if self.scope_changed(scope) {
                0
            } else {
                self.after
            }),
            limit: Some(self.limit),
        })
    }
    fn scope_changed(&self, scope: &Scope) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|value| value != scope.fingerprint())
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotQuery {
    #[serde(default = "version")]
    pub v: u8,
    #[serde(default)]
    pub labels: bool,
}
impl SnapshotQuery {
    pub fn validate(&self) -> Result<(), Error> {
        if self.v != 1 {
            return Err(Error::BadQuery);
        }
        Ok(())
    }
}
macro_rules! closed_enum {
    ($name:ident {$($variant:ident),+ $(,)?}) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all="snake_case")]
        pub enum $name {$($variant),+}
    };
}
closed_enum!(EventKind {
    MessageRecorded,
    RecipientResolved,
    OutcomeChanged,
    ReplyRecorded,
    ReplyPushOutcomeChanged,
    RecordRemoved,
    RecordTransferred,
    Gap,
    Unknown
});
closed_enum!(Outcome {
    Delivered,
    Queued,
    Pending,
    Failed,
    Done,
    Accepted,
    Relayed,
    Stored,
    Pushed,
    PushFailed,
    SenderGone,
    Expired,
    Unknown
});
closed_enum!(Reason {
    EpochChanged,
    CursorAhead,
    CursorEvicted,
    QueueLoss,
    SequenceGap,
    WriterRestart,
    WriterUnavailable,
    ScopeChanged,
    PolicyFiltered,
    SourceFiltered,
    Expired,
    CaptureUnavailable,
    CaptureOverflow,
    Outbound,
    QueueTransfer,
    Unknown
});
closed_enum!(Availability {
    NotRecorded,
    RetainedAtCapture
});
closed_enum!(EndpointKind {
    Instance,
    Subagent,
    Service,
    Unknown
});
closed_enum!(Harness {
    Claude,
    Codex,
    Agy,
    Pi,
    Opencode,
    Hermes,
    Unknown
});
closed_enum!(RegistrationState {
    Registered,
    Released,
    Seen,
    Unknown
});
closed_enum!(SnapshotAvailability {
    Available,
    Partial,
    Unavailable
});
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEvent {
    pub sequence: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_at: Option<i64>,
    pub observed_at: i64,
    pub persisted_at: i64,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    pub available: Availability,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportGap {
    pub reason: Reason,
    pub unknown_loss: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportPage {
    pub v: u8,
    pub node: String,
    pub epoch: String,
    pub scope: String,
    pub events: Vec<ExportEvent>,
    pub next: i64,
    pub has_more: bool,
    pub gaps: Vec<ExportGap>,
    pub available: bool,
}
#[derive(Clone, Debug)]
pub struct SnapshotRecord {
    pub id: String,
    pub kind: EndpointKind,
    pub harness: Harness,
    pub state: RegistrationState,
    pub source_at: Option<i64>,
    pub label: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointDescriptor {
    pub id: String,
    pub node: String,
    pub kind: EndpointKind,
    pub harness: Harness,
    pub state: RegistrationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSnapshot {
    pub v: u8,
    pub node: String,
    pub scope: String,
    pub observed_at: i64,
    pub endpoints: Vec<EndpointDescriptor>,
    pub truncated: bool,
    pub available: SnapshotAvailability,
}
fn valid_node(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
fn canonical_endpoint(value: &str, local_node: &str) -> Option<String> {
    if value.len() > 512 {
        return None;
    }
    let (key, node) = value.split_once('@').unwrap_or((value, local_node));
    if !valid_node(node) {
        return None;
    }
    let key = key.strip_prefix("svc:").unwrap_or(key);
    let valid = if let Some((_, child)) = crate::client::split_subaddress(key) {
        crate::claim::validate_subagent_id(child).is_ok_and(|checked| checked == child)
    } else {
        crate::client::is_instance_ref(key) || crate::client::validate_service_name(key).is_ok()
    };
    valid.then(|| format!("{key}@{node}"))
}
fn valid_time(value: i64) -> bool {
    (0..=MAX_TIME).contains(&value)
}
fn correlation(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 512
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
        .cloned()
}
fn kind(value: &str) -> EventKind {
    match value {
        "message_recorded" => EventKind::MessageRecorded,
        "recipient_resolved" => EventKind::RecipientResolved,
        "outcome_changed" => EventKind::OutcomeChanged,
        "reply_recorded" => EventKind::ReplyRecorded,
        "reply_push_outcome_changed" => EventKind::ReplyPushOutcomeChanged,
        "record_removed" => EventKind::RecordRemoved,
        "record_transferred" => EventKind::RecordTransferred,
        "gap" => EventKind::Gap,
        _ => EventKind::Unknown,
    }
}
fn outcome(value: &str) -> Outcome {
    match value {
        "delivered" => Outcome::Delivered,
        "queued" => Outcome::Queued,
        "pending" => Outcome::Pending,
        "failed" => Outcome::Failed,
        "done" => Outcome::Done,
        "accepted" => Outcome::Accepted,
        "relayed" => Outcome::Relayed,
        "stored" => Outcome::Stored,
        "pushed" => Outcome::Pushed,
        "push_failed" => Outcome::PushFailed,
        "sender_gone" => Outcome::SenderGone,
        "expired" => Outcome::Expired,
        _ => Outcome::Unknown,
    }
}
fn reason(value: &str) -> Reason {
    match value {
        "epoch_changed" => Reason::EpochChanged,
        "cursor_ahead" => Reason::CursorAhead,
        "cursor_evicted" => Reason::CursorEvicted,
        "queue_loss" => Reason::QueueLoss,
        "sequence_gap" => Reason::SequenceGap,
        "writer_restart" => Reason::WriterRestart,
        "writer_unavailable" => Reason::WriterUnavailable,
        "capture_unavailable" => Reason::CaptureUnavailable,
        "capture_overflow" => Reason::CaptureOverflow,
        "outbound" => Reason::Outbound,
        "queue_transfer" => Reason::QueueTransfer,
        _ => Reason::Unknown,
    }
}
fn encoded_size(value: &impl Serialize, limit: usize) -> Result<usize, Error> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes = self.bytes.saturating_add(buf.len());
            if self.bytes > self.limit {
                return Err(std::io::Error::other("observation export size limit"));
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| Error::InvalidSource)?;
    Ok(counter.bytes)
}
fn add_gap(gaps: &mut Vec<ExportGap>, reason: Reason, unknown_loss: bool) {
    let gap = ExportGap {
        reason,
        unknown_loss,
    };
    if !gaps.contains(&gap) {
        gaps.push(gap);
    }
}
pub fn project_page(
    source: crate::observe::Page,
    query: &ExportQuery,
    scope: &Scope,
    now: i64,
) -> Result<ExportPage, Error> {
    let journal_query = query.journal_query(scope)?;
    if !valid_time(now)
        || source.node != scope.node
        || source.epoch.is_empty()
        || source.epoch.len() > 128
        || !source
            .epoch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || (source.has_more && source.next >= source.head)
        || source.events.len() > query.limit
        || source.initial_omitted != 0
        || !source.available
        || source.floor < 1
        || source.floor > source.head.saturating_add(1)
    {
        return Err(Error::InvalidSource);
    }
    encoded_size(&source, MAX_BYTES)?;
    let requested_after = journal_query.after.unwrap_or(0);
    let reset = query
        .epoch
        .as_ref()
        .is_some_and(|epoch| epoch != &source.epoch)
        || requested_after > source.head;
    let after = if reset { 0 } else { requested_after };
    let mut previous = after;
    for event in &source.events {
        if event.node != source.node
            || event.epoch != source.epoch
            || event.sequence <= previous
            || event.sequence < source.floor
            || event.sequence > source.head
        {
            return Err(Error::InvalidSource);
        }
        encoded_size(event, MAX_EVENT_BYTES)?;
        previous = event.sequence;
    }
    if source.next != previous {
        return Err(Error::InvalidSource);
    }
    let mut output = ExportPage {
        v: 1,
        node: source.node,
        epoch: source.epoch,
        scope: scope.fingerprint.clone(),
        events: Vec::new(),
        next: after,
        has_more: source.has_more,
        gaps: Vec::new(),
        available: true,
    };
    for gap in &source.gaps {
        add_gap(&mut output.gaps, reason(&gap.reason), gap.unknown_loss);
    }
    if query.scope_changed(scope) {
        add_gap(&mut output.gaps, Reason::ScopeChanged, false);
    }
    let cutoff = now.saturating_sub(TTL);
    // Reserve every possible fixed marker before choosing the byte-bounded prefix.
    let mut reserved = output.clone();
    for marker in [
        Reason::PolicyFiltered,
        Reason::SourceFiltered,
        Reason::Expired,
    ] {
        add_gap(&mut reserved.gaps, marker, false);
    }
    let reserve_bytes =
        encoded_size(&reserved, MAX_BYTES)?.saturating_sub(encoded_size(&output, MAX_BYTES)?);
    for event in source.events {
        let observation = event.observation;
        if !valid_time(event.observed_at)
            || !valid_time(event.persisted_at)
            || event.observed_at > now
            || event.persisted_at > now
        {
            output.next = event.sequence;
            add_gap(&mut output.gaps, Reason::SourceFiltered, false);
            continue;
        }
        if event.observed_at < cutoff {
            output.next = event.sequence;
            add_gap(&mut output.gaps, Reason::Expired, false);
            continue;
        }
        let from = observation
            .from
            .as_deref()
            .and_then(|value| scope.canonical_endpoint(value));
        let to = observation
            .to
            .as_deref()
            .and_then(|value| scope.canonical_endpoint(value));
        if scope.targets.as_ref().is_some_and(|targets| {
            !from.as_ref().is_some_and(|id| targets.contains(id))
                || !to.as_ref().is_some_and(|id| targets.contains(id))
        }) {
            output.next = event.sequence;
            add_gap(&mut output.gaps, Reason::PolicyFiltered, false);
            continue;
        }
        let projected = ExportEvent {
            sequence: event.sequence,
            source_at: observation.source_at.filter(|value| valid_time(*value)),
            observed_at: event.observed_at,
            persisted_at: event.persisted_at,
            kind: kind(&observation.kind),
            from,
            to,
            message_id: correlation(&observation.message_id),
            reply_id: observation.reply_id.filter(|id| *id > 0),
            thread_id: correlation(&observation.thread_id),
            outcome: observation.outcome.as_deref().map(outcome),
            reason: observation.reason.as_deref().map(reason),
            available: if observation.body_availability == "retained_at_capture" {
                Availability::RetainedAtCapture
            } else {
                Availability::NotRecorded
            },
        };
        if encoded_size(&projected, MAX_EVENT_BYTES).is_err() {
            output.has_more = true;
            break;
        }
        let previous_next = output.next;
        output.next = projected.sequence;
        output.events.push(projected);
        if encoded_size(&output, MAX_BYTES - reserve_bytes).is_err() {
            output.events.pop();
            output.next = previous_next;
            output.has_more = true;
            break;
        }
    }
    encoded_size(&output, MAX_BYTES)?;
    Ok(output)
}
fn bounded_label(value: &str) -> String {
    let mut end = value.len().min(256);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
pub fn project_snapshot(
    scope: &Scope,
    candidates: Vec<SnapshotRecord>,
    observed_at: i64,
    partial: bool,
) -> Result<ExportSnapshot, Error> {
    if candidates.len() > MAX_CANDIDATES || !valid_time(observed_at) {
        return Err(Error::InvalidSource);
    }
    let mut endpoints: BTreeMap<String, EndpointDescriptor> = BTreeMap::new();
    let mut partial = partial;
    for candidate in candidates {
        let Some(id) = scope.canonical_endpoint(&candidate.id) else {
            partial = true;
            continue;
        };
        if !scope.allows(&id) {
            continue;
        }
        let node = id.split_once('@').ok_or(Error::InvalidSource)?.1.to_owned();
        let label = if scope.effective_labels {
            candidate.label.as_deref().map(bounded_label)
        } else {
            None
        };
        let source_at = candidate
            .source_at
            .filter(|value| valid_time(*value) && *value <= observed_at);
        let descriptor = EndpointDescriptor {
            id: id.clone(),
            node,
            kind: candidate.kind,
            harness: candidate.harness,
            state: candidate.state,
            source_at,
            label,
        };
        if let Some(previous) = endpoints.get_mut(&id) {
            let conflict = previous.kind != descriptor.kind
                || previous.harness != descriptor.harness
                || previous.state != descriptor.state;
            if conflict {
                previous.kind = EndpointKind::Unknown;
                previous.harness = Harness::Unknown;
                previous.state = RegistrationState::Unknown;
                previous.label = None;
                partial = true;
            } else if previous.label != descriptor.label {
                previous.label = None;
            }
            previous.source_at = match (previous.source_at, descriptor.source_at) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            };
        } else {
            endpoints.insert(id, descriptor);
        }
    }
    let mut output = ExportSnapshot {
        v: 1,
        node: scope.node.clone(),
        scope: scope.fingerprint.clone(),
        observed_at,
        endpoints: Vec::new(),
        truncated: false,
        available: if partial {
            SnapshotAvailability::Partial
        } else {
            SnapshotAvailability::Available
        },
    };
    for descriptor in endpoints.into_values() {
        if output.endpoints.len() >= MAX_EVENTS {
            output.truncated = true;
            break;
        }
        output.endpoints.push(descriptor);
        if encoded_size(&output, MAX_BYTES).is_err() {
            output.endpoints.pop();
            output.truncated = true;
            break;
        }
    }
    if output.truncated {
        output.available = SnapshotAvailability::Partial;
    }
    encoded_size(&output, MAX_BYTES)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{Event, Gap, LossCounters, Observation, Page};
    use serde_json::{json, Value};
    const ID: &str = "11111111-1111-4111-8111-111111111111";
    const NOW: i64 = 2_000_000;
    fn scope(targets: Option<&[String]>, labels: bool) -> Scope {
        Scope::new("local.node", "collector", targets, labels).unwrap()
    }
    fn query() -> ExportQuery {
        serde_json::from_value(json!({})).unwrap()
    }
    fn event(sequence: i64) -> Event {
        Event {
            node: "local.node".into(),
            epoch: "epoch".into(),
            sequence,
            observed_at: NOW,
            persisted_at: NOW,
            observation: Observation {
                source_at: Some(NOW),
                kind: "message_recorded".into(),
                from: Some(ID.into()),
                to: Some("svc:bot".into()),
                message_id: Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()),
                reply_id: Some(42),
                thread_id: Some("01ARZ3NDEKTSV4RRFFQ69G5FAX".into()),
                outcome: Some("delivered".into()),
                reason: None,
                body_availability: "retained_at_capture".into(),
            },
        }
    }
    fn page(events: Vec<Event>) -> Page {
        let next = events.last().map_or(0, |e| e.sequence);
        Page {
            node: "local.node".into(),
            epoch: "epoch".into(),
            events,
            next,
            floor: 1,
            head: next,
            has_more: false,
            gaps: vec![],
            losses: LossCounters::default(),
            available: true,
            initial_omitted: 0,
        }
    }
    fn wire(events: Vec<Event>, scope: &Scope) -> Value {
        serde_json::to_value(project_page(page(events), &query(), scope, NOW).unwrap()).unwrap()
    }
    fn candidate(id: &str) -> SnapshotRecord {
        SnapshotRecord {
            id: id.into(),
            kind: EndpointKind::Instance,
            harness: Harness::Claude,
            state: RegistrationState::Registered,
            source_at: Some(NOW),
            label: Some("private label".into()),
        }
    }
    #[test]
    fn query_is_strict_bounded_and_explicit() {
        let s = scope(None, false);
        let q = query();
        assert_eq!(q.journal_query(&s).unwrap().after, Some(0));
        for bad in [
            json!({"v":2}),
            json!({"epoch":""}),
            json!({"epoch":"x".repeat(129)}),
            json!({"after":-1}),
            json!({"after":1}),
            json!({"after":1,"epoch":"e"}),
            json!({"after":1,"scope":"a".repeat(64)}),
            json!({"limit":0}),
            json!({"limit":201}),
            json!({"scope":"A".repeat(64)}),
            json!({"scope":"a".repeat(63)}),
        ] {
            let q: ExportQuery = serde_json::from_value(bad.clone()).unwrap();
            assert!(q.validate().is_err(), "accepted invalid query: {bad}");
        }
        assert!(
            serde_json::from_value::<ExportQuery>(json!({"body":"canary"})).is_err(),
            "event query accepted unknown field"
        );
        assert!(serde_json::from_value::<ExportQuery>(json!({"after":u64::MAX})).is_err());
        assert!(
            serde_json::from_value::<SnapshotQuery>(json!({"after":0})).is_err(),
            "snapshot query accepted unknown field"
        );
        assert!(SnapshotQuery {
            v: 2,
            labels: false
        }
        .validate()
        .is_err());
        let q: ExportQuery =
            serde_json::from_value(json!({"after":i64::MAX,"epoch":"e","scope":s.fingerprint()}))
                .unwrap();
        assert!(q.validate().is_ok());
        assert_eq!(q.journal_query(&s).unwrap().after, Some(i64::MAX));
    }
    #[test]
    fn scope_is_stable_and_policy_sensitive() {
        let a = vec!["bot".into(), ID.into(), "bot".into()];
        let b = vec![format!("{ID}@local.node"), "bot@local.node".into()];
        let x = scope(Some(&a), false);
        let y = scope(Some(&b), false);
        assert_eq!(x.fingerprint(), y.fingerprint());
        assert_ne!(x.fingerprint(), scope(Some(&b), true).fingerprint());
        assert_ne!(
            x.fingerprint(),
            Scope::new("local.node", "other", Some(&b), false)
                .unwrap()
                .fingerprint()
        );
        assert_ne!(
            scope(None, false).fingerprint(),
            scope(Some(&[]), false).fingerprint()
        );
        assert_ne!(
            x.fingerprint(),
            scope(Some(&["other".into()]), false).fingerprint(),
            "target scope hash did not change"
        );
        assert_ne!(
            scope(None, false).fingerprint(),
            Scope::new("remote.node", "collector", None, false)
                .unwrap()
                .fingerprint(),
            "exporter scope hash did not change"
        );
        assert_eq!(x.fingerprint().len(), 64);
        assert!(Scope::new("bad/node", "peer", None, false).is_err());
        assert!(
            Scope::new(&"n".repeat(129), "peer", None, false).is_err(),
            "oversized node accepted"
        );
        assert!(Scope::new("local.node", "peer", Some(&["../private".into()]), false).is_err());
    }
    #[test]
    fn scoped_events_require_both_valid_allowed_endpoints() {
        let allowed = vec![ID.into(), "bot".into()];
        let s = scope(Some(&allowed), false);
        let positive = wire(vec![event(1)], &s);
        assert_eq!(positive["events"].as_array().unwrap().len(), 1);
        assert_eq!(positive["events"][0]["to"], "bot@local.node");
        for (from, to) in [
            (Some(ID), Some("bot@remote.node")),
            (Some("hidden"), Some("bot")),
            (None, Some("bot")),
            (Some(ID), None),
            (Some("/secret/token"), Some("bot")),
        ] {
            let mut e = event(1);
            e.observation.from = from.map(str::to_owned);
            e.observation.to = to.map(str::to_owned);
            let w = wire(vec![e], &s);
            assert_eq!(
                w["events"].as_array().unwrap().len(),
                0,
                "excluded endpoint leaked"
            );
            assert_eq!(w["next"], 1);
            assert_eq!(w["gaps"][0]["reason"], "policy_filtered");
            assert_eq!(w["gaps"][0]["unknown_loss"], false);
        }
        assert_eq!(
            wire(vec![event(1)], &scope(Some(&[]), false))["events"],
            json!([]),
            "empty targets leaked"
        );
        let remote = vec![format!("{ID}@remote.node"), "bot".into()];
        let mut e = event(1);
        e.observation.from = Some(format!("{ID}@remote.node"));
        assert_eq!(
            wire(vec![e], &scope(Some(&remote), false))["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        for suffix in ["~2", "/a1234567890123456", "~3/worker"] {
            let key = format!("{ID}{suffix}");
            let mut e = event(1);
            e.observation.from = Some(key.clone());
            assert_eq!(
                wire(vec![e], &scope(Some(&[key, "bot".into()]), false))["events"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }
    #[test]
    fn wire_is_closed_and_excludes_internal_details() {
        let mut e = event(1);
        e.observation.outcome = Some("secret-outcome-canary".into());
        e.observation.reason = Some("secret-reason-canary".into());
        e.observation.kind = "secret-kind-canary".into();
        e.observation.message_id = Some("/private/body-canary".into());
        e.observation.thread_id = Some("token=private".into());
        e.observation.reply_id = Some(-1);
        e.observation.from = Some("/private/path".into());
        e.observation.to = Some("bad@node/path".into());
        e.observation.body_availability = "secret-availability-canary".into();
        let mut p = page(vec![e]);
        p.gaps.push(Gap {
            reason: "secret-gap-canary".into(),
            unknown_loss: true,
            count: Some(123456789),
        });
        let w = serde_json::to_value(project_page(p, &query(), &scope(None, false), NOW).unwrap())
            .unwrap();
        let v = &w["events"][0];
        assert_eq!(
            w["gaps"][0],
            json!({"reason":"unknown","unknown_loss":true})
        );
        assert_eq!(v["kind"], "unknown", "unknown kind leaked");
        assert_eq!(v["outcome"], "unknown", "unknown outcome leaked");
        assert_eq!(v["reason"], "unknown", "unknown reason leaked");
        assert_eq!(
            v["available"], "not_recorded",
            "availability schema changed"
        );
        for key in [
            "from",
            "to",
            "message_id",
            "reply_id",
            "thread_id",
            "node",
            "epoch",
            "body_availability",
        ] {
            assert!(v.get(key).is_none(), "forbidden event field: {key}");
        }
        let encoded = serde_json::to_string(&w).unwrap();
        assert!(
            !encoded.contains("canary") && !encoded.contains("private"),
            "private metadata leaked"
        );
        let keys = w
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                "available",
                "epoch",
                "events",
                "gaps",
                "has_more",
                "next",
                "node",
                "scope",
                "v"
            ]
        );
        assert!(serde_json::from_value::<ExportPage>(json!({"v":1,"node":"n","epoch":"e","scope":"s","events":[],"next":0,"has_more":false,"gaps":[],"available":true,"body":"canary"})).is_err());
    }
    #[test]
    fn ttl_and_extreme_times_never_extend_retention() {
        let mut expired = event(1);
        expired.observed_at = NOW - 7 * 86400 - 1;
        let mut edge = event(2);
        edge.observed_at = NOW - 7 * 86400;
        let mut invalid = event(3);
        invalid.persisted_at = i64::MAX;
        let mut invalid2 = event(4);
        invalid2.observed_at = i64::MIN;
        let mut source = event(5);
        source.observation.source_at = Some(i64::MAX);
        let mut future_observed = event(6);
        future_observed.observed_at = NOW + 1;
        let mut future_persisted = event(7);
        future_persisted.persisted_at = NOW + 1;
        let w = wire(
            vec![
                expired,
                edge,
                invalid,
                invalid2,
                source,
                future_observed,
                future_persisted,
            ],
            &scope(None, false),
        );
        assert_eq!(
            w["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["sequence"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![2, 5],
            "expired metadata leaked"
        );
        assert!(
            w["events"][1].get("source_at").is_none(),
            "extreme source timestamp leaked"
        );
        assert_eq!(w["next"], 7);
        assert!(project_page(
            page(vec![event(1)]),
            &query(),
            &scope(None, false),
            i64::MIN
        )
        .is_err());
        assert!(project_page(
            page(vec![event(1)]),
            &query(),
            &scope(None, false),
            i64::MAX
        )
        .is_err());
    }
    #[test]
    fn reset_and_zero_visible_pages_have_truthful_cursors() {
        let s = scope(None, false);
        let mut q = query();
        q.after = 99;
        q.epoch = Some("epoch".into());
        q.scope = Some("a".repeat(64));
        assert_eq!(
            q.journal_query(&s).unwrap().after,
            Some(0),
            "scope mismatch did not reset"
        );
        let w =
            serde_json::to_value(project_page(page(vec![event(1)]), &q, &s, NOW).unwrap()).unwrap();
        assert_eq!(w["next"], 1);
        assert!(w["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["reason"] == "scope_changed"));
        q.scope = Some(s.fingerprint().into());
        for reason in ["epoch_changed", "cursor_ahead"] {
            let mut p = page(vec![event(1)]);
            p.gaps.push(Gap {
                reason: reason.into(),
                unknown_loss: true,
                count: None,
            });
            assert_eq!(project_page(p, &q, &s, NOW).unwrap().next, 1);
        }
        let mut p = page(vec![]);
        p.head = 99;
        p.next = 99;
        assert_eq!(project_page(p, &q, &s, NOW).unwrap().next, 99);
        let mut e = event(8);
        e.observed_at = 0;
        assert_eq!(wire(vec![e], &s)["next"], 8);
    }
    #[test]
    fn source_identity_order_rows_and_bytes_are_validated() {
        let s = scope(None, false);
        let mut cases = vec![
            page(vec![event(2), event(1)]),
            page(vec![event(1), event(1)]),
            page((1..=201).map(event).collect()),
        ];
        let mut p = page(vec![]);
        p.node = "remote.node".into();
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.events[0].epoch = "wrong".into();
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.events[0].node = "remote.node".into();
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.next = 0;
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.events[0].sequence = 0;
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.head = 0;
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.floor = 2;
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.available = false;
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.events[0].observation.reason = Some("x".repeat(4096));
        cases.push(p);
        let mut p = page(vec![]);
        p.gaps = (0..200)
            .map(|_| Gap {
                reason: "x".repeat(2000),
                unknown_loss: true,
                count: None,
            })
            .collect();
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.events.clear();
        p.next = 0;
        p.epoch = String::new();
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.events.clear();
        p.next = 0;
        p.epoch = "e".repeat(129);
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.events.clear();
        p.next = 0;
        p.epoch = "/private/epoch".into();
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.floor = 0;
        cases.push(p);
        let mut p = page(vec![]);
        p.floor = 2;
        cases.push(p);
        let mut p = page(vec![event(1)]);
        p.initial_omitted = 1;
        cases.push(p);
        for (i, p) in cases.into_iter().enumerate() {
            assert!(
                project_page(p, &query(), &s, NOW).is_err(),
                "invalid source accepted: {i}"
            );
        }
    }
    #[test]
    fn output_byte_boundary_preserves_unscanned_visible_record() {
        let s = Scope::new(&"a".repeat(128), "peer", None, false).unwrap();
        let mut events = Vec::new();
        for i in 1..=200 {
            let mut e = event(i);
            e.node = s.node().into();
            e.observation.from = Some(format!("{ID}/{}", "a".repeat(128)));
            e.observation.to = e.observation.from.clone();
            e.observation.message_id = Some("m".repeat(250));
            e.observation.thread_id = Some("t".repeat(250));
            events.push(e);
        }
        let mut p = page(events);
        p.node = s.node().into();
        let out = project_page(
            p,
            &ExportQuery {
                limit: 200,
                ..query()
            },
            &s,
            NOW,
        )
        .unwrap();
        let w = serde_json::to_value(&out).unwrap();
        assert!(
            serde_json::to_vec(&out).unwrap().len() <= 256 * 1024,
            "page byte limit exceeded"
        );
        assert!(out.events.len() < 200 && !out.events.is_empty());
        assert!(out.has_more);
        assert_eq!(
            out.next,
            out.events.last().unwrap().sequence,
            "cursor skipped visible record"
        );
        assert_eq!(w["next"].as_i64().unwrap() + 1, out.events.len() as i64 + 1);
    }
    #[test]
    fn correlation_ids_are_bounded_opaque_bus_tokens() {
        let s = scope(None, false);
        for invalid in [
            String::new(),
            "id with space".into(),
            "/private/path".into(),
            "id@node".into(),
            "x".repeat(513),
        ] {
            let mut e = event(1);
            e.observation.message_id = Some(invalid.clone());
            e.observation.thread_id = Some(invalid);
            let w = wire(vec![e], &s);
            assert!(
                w["events"][0].get("message_id").is_none(),
                "invalid correlation id leaked"
            );
            assert!(
                w["events"][0].get("thread_id").is_none(),
                "invalid thread id leaked"
            );
        }
        let mut e = event(1);
        e.observation.message_id = Some("safe_message-1".into());
        e.observation.thread_id = Some("t".repeat(512));
        let w = wire(vec![e], &s);
        assert_eq!(w["events"][0]["message_id"], "safe_message-1");
        assert_eq!(w["events"][0]["thread_id"].as_str().unwrap().len(), 512);
    }
    #[test]
    fn impossible_raw_continuation_is_refused() {
        let scope = scope(None, false);
        let query = ExportQuery {
            limit: 1,
            ..query()
        };
        let mut impossible = page(vec![event(1)]);
        impossible.has_more = true;
        assert!(
            project_page(impossible, &query, &scope, NOW).is_err(),
            "impossible raw continuation accepted"
        );
        let mut valid = page(vec![event(1)]);
        valid.has_more = true;
        valid.head = 2;
        let result = project_page(valid, &query, &scope, NOW).unwrap();
        assert!(result.has_more);
        assert_eq!(result.next, 1);
    }
    #[test]
    fn nested_and_envelope_schemas_reject_extra_fields() {
        let scope = scope(None, false);
        let base = wire(vec![event(1)], &scope);
        let mut event_extra = base.clone();
        event_extra["events"][0]["body"] = json!("private-canary");
        assert!(
            serde_json::from_value::<ExportPage>(event_extra).is_err(),
            "event schema weakened"
        );
        let mut page_extra = base;
        page_extra["path"] = json!("private-canary");
        assert!(
            serde_json::from_value::<ExportPage>(page_extra).is_err(),
            "page schema weakened"
        );
        let mut p = page(vec![]);
        p.gaps.push(Gap {
            reason: "writer_restart".into(),
            unknown_loss: true,
            count: None,
        });
        let mut gap_extra =
            serde_json::to_value(project_page(p, &query(), &scope, NOW).unwrap()).unwrap();
        gap_extra["gaps"][0]["detail"] = json!("private-canary");
        assert!(
            serde_json::from_value::<ExportPage>(gap_extra).is_err(),
            "gap schema weakened"
        );
        let mut snapshot_extra = serde_json::to_value(
            project_snapshot(&scope, vec![candidate(ID)], NOW, false).unwrap(),
        )
        .unwrap();
        snapshot_extra["environment"] = json!("private-canary");
        assert!(
            serde_json::from_value::<ExportSnapshot>(snapshot_extra).is_err(),
            "snapshot envelope schema weakened"
        );
    }
    #[test]
    fn known_classes_preserve_named_states() {
        let scope = scope(None, false);
        for kind in [
            "message_recorded",
            "recipient_resolved",
            "outcome_changed",
            "reply_recorded",
            "reply_push_outcome_changed",
            "record_removed",
            "record_transferred",
            "gap",
        ] {
            let mut e = event(1);
            e.observation.kind = kind.into();
            let w = wire(vec![e], &scope);
            assert_eq!(w["events"][0]["kind"], kind, "known kind was lost");
            assert_eq!(
                w["events"][0]["available"], "retained_at_capture",
                "known availability was lost"
            );
        }
        for outcome in [
            "delivered",
            "queued",
            "pending",
            "failed",
            "done",
            "accepted",
            "relayed",
            "stored",
            "pushed",
            "push_failed",
            "sender_gone",
            "expired",
        ] {
            let mut e = event(1);
            e.observation.outcome = Some(outcome.into());
            assert_eq!(
                wire(vec![e], &scope)["events"][0]["outcome"],
                outcome,
                "known outcome was lost"
            );
        }
        for reason in [
            "epoch_changed",
            "cursor_ahead",
            "cursor_evicted",
            "queue_loss",
            "sequence_gap",
            "writer_restart",
            "writer_unavailable",
            "capture_unavailable",
            "capture_overflow",
            "outbound",
            "queue_transfer",
        ] {
            let mut e = event(1);
            e.observation.reason = Some(reason.into());
            assert_eq!(
                wire(vec![e], &scope)["events"][0]["reason"],
                reason,
                "known reason was lost"
            );
        }
    }
    #[test]
    fn first_page_uses_explicit_zero_journal_cursor() {
        assert_eq!(
            query().journal_query(&scope(None, false)).unwrap().after,
            Some(0),
            "initial journal query selected implicit tail"
        );
    }
    #[test]
    fn canonical_endpoint_grammar_and_bounds_are_closed() {
        let scope = scope(None, false);
        for value in [
            "/private/path".into(),
            "bot@node/path".into(),
            format!("{ID}/with space"),
            format!("{ID}/ child"),
            format!("{ID}/child/other"),
            format!("{ID}/{}", "c".repeat(129)),
            format!("{ID}~{}2", "0".repeat(480)),
        ] {
            assert!(
                scope.canonical_endpoint(&value).is_none(),
                "invalid endpoint accepted: {value}"
            );
        }
        assert_eq!(
            scope.canonical_endpoint("svc:bot").as_deref(),
            Some("bot@local.node"),
            "service endpoint normalization failed"
        );
        assert_eq!(
            scope.canonical_endpoint("bot@remote.node").as_deref(),
            Some("bot@remote.node")
        );
    }
    #[test]
    fn invalid_source_times_are_omitted() {
        for invalid in [-1, i64::MIN, i64::MAX] {
            let mut e = event(1);
            e.observation.source_at = Some(invalid);
            let w = wire(vec![e], &scope(None, false));
            assert!(
                w["events"][0].get("source_at").is_none(),
                "invalid source timestamp leaked"
            );
        }
    }
    #[test]
    fn source_clock_skew_is_preserved_without_extending_ttl() {
        let mut e = event(1);
        e.observation.source_at = Some(NOW + 3600);
        let w = wire(vec![e], &scope(None, false));
        assert_eq!(
            w["events"][0]["source_at"],
            NOW + 3600,
            "source clock skew was hidden"
        );
    }
    #[test]
    fn snapshot_byte_boundary_is_partial_without_oversized_wire() {
        let records = (0..200)
            .map(|i| SnapshotRecord {
                label: Some("\u{1}".repeat(256)),
                ..candidate(&format!("svc{i}"))
            })
            .collect();
        let result = project_snapshot(&scope(None, true), records, NOW, false);
        assert!(result.is_ok(), "snapshot byte boundary must truncate");
        let out = result.unwrap();
        assert!(
            out.truncated && !out.endpoints.is_empty() && out.endpoints.len() < 200,
            "snapshot byte boundary was ignored"
        );
        assert!(
            serde_json::to_vec(&out).unwrap().len() <= 256 * 1024,
            "snapshot wire exceeded byte bound"
        );
        assert_eq!(serde_json::to_value(out).unwrap()["available"], "partial");
    }
    #[test]
    fn snapshot_labels_require_effective_opt_in_and_utf8_bound() {
        let mut c = candidate(ID);
        c.label = Some("界".repeat(100));
        for labels in [false, true] {
            let w = serde_json::to_value(
                project_snapshot(&scope(None, labels), vec![c.clone()], NOW, false).unwrap(),
            )
            .unwrap();
            let label = w["endpoints"][0].get("label");
            if labels {
                let label = label.unwrap().as_str().unwrap();
                assert!(label.len() <= 256, "label byte limit exceeded");
                assert_eq!(label.len(), 255);
            } else {
                assert!(label.is_none(), "label leaked without opt-in");
            }
        }
        assert_eq!(
            project_snapshot(&scope(Some(&[]), true), vec![c], NOW, false)
                .unwrap()
                .endpoints
                .len(),
            0
        );
    }
    #[test]
    fn snapshot_conflicts_are_independently_conservative() {
        for field in ["kind", "harness", "state"] {
            let a = candidate(ID);
            let mut b = a.clone();
            match field {
                "kind" => b.kind = EndpointKind::Service,
                "harness" => b.harness = Harness::Codex,
                _ => b.state = RegistrationState::Unknown,
            }
            let out = project_snapshot(&scope(None, true), vec![a, b], NOW, false).unwrap();
            let w = serde_json::to_value(out).unwrap();
            assert_eq!(
                w["endpoints"][0]["kind"], "unknown",
                "snapshot conflict was ignored: {field}"
            );
            assert_eq!(w["endpoints"][0]["harness"], "unknown");
            assert_eq!(w["endpoints"][0]["state"], "unknown");
            assert!(
                w["endpoints"][0].get("label").is_none(),
                "conflict label leaked"
            );
        }
        let a = candidate(ID);
        let b = SnapshotRecord {
            label: Some("different".into()),
            ..a.clone()
        };
        let w = serde_json::to_value(
            project_snapshot(&scope(None, true), vec![a, b], NOW, false).unwrap(),
        )
        .unwrap();
        assert!(
            w["endpoints"][0].get("label").is_none(),
            "duplicate labels fabricated"
        );
    }
    #[test]
    fn epoch_and_ahead_resets_are_independent() {
        let s = scope(None, false);
        for (epoch, after) in [("old", 1), ("epoch", 99)] {
            let q = ExportQuery {
                epoch: Some(epoch.into()),
                after,
                scope: Some(s.fingerprint().into()),
                ..query()
            };
            let result = project_page(page(vec![event(1)]), &q, &s, NOW);
            assert!(result.is_ok(), "reset did not backfill: {epoch}");
            assert_eq!(result.unwrap().next, 1);
        }
    }
    #[test]
    fn snapshot_is_bounded_sorted_partial_and_conservative_on_duplicates() {
        let s = scope(None, true);
        let mut a = candidate(ID);
        let mut b = a.clone();
        b.harness = Harness::Codex;
        b.kind = EndpointKind::Service;
        b.state = RegistrationState::Unknown;
        b.label = Some("other".into());
        let mut records = vec![candidate("bot"), b, a.clone()];
        let out = project_snapshot(&s, records.clone(), NOW, true).unwrap();
        records.reverse();
        assert_eq!(
            serde_json::to_value(&out).unwrap(),
            serde_json::to_value(project_snapshot(&s, records, NOW, true).unwrap()).unwrap()
        );
        let w = serde_json::to_value(out).unwrap();
        let first = &w["endpoints"][0];
        assert_eq!(first["kind"], "unknown", "conflicting identity fabricated");
        assert_eq!(first["harness"], "unknown");
        assert_eq!(first["state"], "unknown");
        assert!(first.get("label").is_none());
        assert_eq!(w["available"], "partial");
        let records = (0..201).map(|i| candidate(&format!("svc{i}"))).collect();
        let out = project_snapshot(&s, records, NOW, false).unwrap();
        assert_eq!(out.endpoints.len(), 200, "snapshot row limit exceeded");
        assert!(out.truncated);
        assert!(serde_json::to_vec(&out).unwrap().len() <= 256 * 1024);
        assert!(
            project_snapshot(&s, vec![a.clone(); 8 * 201 + 1], NOW, false).is_err(),
            "candidate work limit exceeded"
        );
        let future = SnapshotRecord {
            source_at: Some(i64::MAX),
            ..a.clone()
        };
        let future_wire =
            serde_json::to_value(project_snapshot(&s, vec![future], NOW, false).unwrap()).unwrap();
        assert!(
            future_wire["endpoints"][0].get("source_at").is_none(),
            "invalid snapshot timestamp leaked"
        );
        let mut schema =
            serde_json::to_value(project_snapshot(&s, vec![a.clone()], NOW, false).unwrap())
                .unwrap();
        schema["endpoints"][0]["cwd"] = json!("private-canary");
        assert!(
            serde_json::from_value::<ExportSnapshot>(schema).is_err(),
            "snapshot schema weakened"
        );
        a.source_at = Some(i64::MAX);
        a.id = "/private/path-canary".into();
        let w = serde_json::to_string(&project_snapshot(&s, vec![a], NOW, false).unwrap()).unwrap();
        assert!(!w.contains("canary"));
    }
}
