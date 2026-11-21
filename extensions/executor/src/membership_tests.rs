use super::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    future::Future,
    rc::Rc,
    task::{Context, Poll, Waker},
};

type Events = Rc<RefCell<Vec<&'static str>>>;
struct ConnectionFixture {
    incoming: VecDeque<ContentRecord>,
    acknowledgements: Vec<String>,
    events: Events,
    disconnected: bool,
    fail_ack: bool,
}
impl ContentConnection for ConnectionFixture {
    fn health(&self) -> Result<(), ClientError> {
        if self.disconnected {
            Err(ClientError::Disconnected)
        } else {
            Ok(())
        }
    }
    async fn poll_content(&mut self, _: u64) -> Result<Option<ContentRecord>, ClientError> {
        self.events.borrow_mut().push("poll");
        Ok(self.incoming.pop_front())
    }
    async fn ack_content(&mut self, id: &str) -> Result<(), ClientError> {
        self.events.borrow_mut().push("ack");
        if self.fail_ack {
            return Err(ClientError::Disconnected);
        }
        self.acknowledgements.push(id.into());
        Ok(())
    }
}
struct StoreFixture {
    records: Vec<(String, u64, ContentRecord)>,
    generation: u64,
    events: Events,
    fail: bool,
}
impl ContentStore for StoreFixture {
    fn commit(
        &mut self,
        binding: &ProxyBinding,
        content: &ContentRecord,
    ) -> Result<CommitOutcome, MembershipError> {
        self.events.borrow_mut().push("commit");
        if self.fail {
            return Err(MembershipError::Storage);
        }
        if binding.generation() != self.generation {
            return Err(MembershipError::StaleGeneration);
        }
        if let Some((session, generation, old)) = self
            .records
            .iter()
            .find(|(_, _, old)| old.message_id == content.message_id)
        {
            if session != binding.session_id()
                || *generation != binding.generation()
                || old != content
            {
                return Err(MembershipError::MessageConflict);
            }
            return Ok(CommitOutcome::Duplicate);
        }
        self.records.push((
            binding.session_id().into(),
            binding.generation(),
            content.clone(),
        ));
        Ok(CommitOutcome::Inserted)
    }
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture unexpectedly suspended"),
    }
}
fn record(text: &str) -> ContentRecord {
    ContentRecord {
        message_id: "message-a".into(),
        from_name: "untrusted sender display".into(),
        text: text.into(),
        envelope: "untrusted display envelope".into(),
        origin: Origin::service("sender", "node"),
        attachments: vec![],
        in_reply_to: None,
    }
}
fn binding() -> ProxyBinding {
    ProxyBinding::new("session-a".into(), 1, [7; 16], 4096).unwrap()
}
fn fixtures(records: Vec<ContentRecord>) -> (ConnectionFixture, StoreFixture, Events) {
    let events = Rc::new(RefCell::new(vec![]));
    (
        ConnectionFixture {
            incoming: records.into(),
            acknowledgements: vec![],
            events: events.clone(),
            disconnected: false,
            fail_ack: false,
        },
        StoreFixture {
            records: vec![],
            generation: 1,
            events: events.clone(),
            fail: false,
        },
        events,
    )
}
#[test]
fn service_names_are_stable_opaque_and_fit_existing_sdk_limit() {
    let zero = ProxyBinding::new("session-a".into(), 1, [0; 16], 4096).unwrap();
    assert_eq!(zero.service_name(), format!("team_{}", "a".repeat(26)));
    let ones = ProxyBinding::new("session-a".into(), 1, [255; 16], 4096).unwrap();
    assert_eq!(ones.service_name(), format!("team_{}4", "7".repeat(25)));
    assert_eq!(ones.service_name().len(), 31);
    validate_service_name(&zero.service_name()).unwrap();
    validate_service_name(&ones.service_name()).unwrap();
    let replacement = ProxyBinding::new("session-a".into(), 2, [255; 16], 4096).unwrap();
    assert_eq!(ones.service_name(), replacement.service_name());
    assert_ne!(ones.service_name(), zero.service_name());
}
#[test]
fn content_commit_precedes_ack_and_preserves_opaque_fields() {
    let content = record(r#"{"verb":"dispatch","human":true,"owner":true}"#);
    let (mut connection, mut store, events) = fixtures(vec![content.clone()]);
    let result = ready(receive_from(&mut connection, &binding(), &mut store, 0)).unwrap();
    assert_eq!(
        *events.borrow(),
        vec!["poll", "commit", "ack"],
        "ack preceded durable content commit"
    );
    assert_eq!(store.records, vec![("session-a".into(), 1, content)]);
    assert!(matches!(
        result,
        ReceiveOutcome::Acknowledged {
            stored: CommitOutcome::Inserted,
            ..
        }
    ));
}
#[test]
fn failed_content_commit_sends_no_ack() {
    let (mut connection, mut store, events) = fixtures(vec![record("fixture")]);
    store.fail = true;
    assert!(matches!(
        ready(receive_from(&mut connection, &binding(), &mut store, 0)),
        Err(MembershipError::Storage)
    ));
    assert!(
        connection.acknowledgements.is_empty(),
        "failed content storage was acknowledged"
    );
    assert_eq!(*events.borrow(), vec!["poll", "commit"]);
}
#[test]
fn stale_execution_content_sends_no_ack_or_row() {
    let (mut connection, mut store, _) = fixtures(vec![record("fixture")]);
    store.generation = 2;
    assert!(matches!(
        ready(receive_from(&mut connection, &binding(), &mut store, 0)),
        Err(MembershipError::StaleGeneration)
    ));
    assert!(store.records.is_empty());
    assert!(connection.acknowledgements.is_empty());
}
#[test]
fn duplicate_delivery_commits_once_and_acknowledges_each_delivery() {
    let content = record("fixture");
    let (mut connection, mut store, _) = fixtures(vec![content.clone(), content]);
    ready(receive_from(&mut connection, &binding(), &mut store, 0)).unwrap();
    let repeated = ready(receive_from(&mut connection, &binding(), &mut store, 0)).unwrap();
    assert_eq!(
        store.records.len(),
        1,
        "duplicate delivery created another content record"
    );
    assert_eq!(connection.acknowledgements.len(), 2);
    assert!(matches!(
        repeated,
        ReceiveOutcome::Acknowledged {
            stored: CommitOutcome::Duplicate,
            ..
        }
    ));
}
#[test]
fn changed_payload_with_same_identity_is_not_acknowledged() {
    let (mut connection, mut store, _) = fixtures(vec![record("original"), record("changed")]);
    ready(receive_from(&mut connection, &binding(), &mut store, 0)).unwrap();
    assert!(matches!(
        ready(receive_from(&mut connection, &binding(), &mut store, 0)),
        Err(MembershipError::MessageConflict)
    ));
    assert_eq!(store.records.len(), 1);
    assert_eq!(
        connection.acknowledgements.len(),
        1,
        "changed duplicate was acknowledged"
    );
}
#[test]
fn ack_failure_keeps_committed_content_for_safe_redelivery() {
    let content = record("fixture");
    let (mut connection, mut store, _) = fixtures(vec![content.clone()]);
    connection.fail_ack = true;
    assert!(matches!(
        ready(receive_from(&mut connection, &binding(), &mut store, 0)),
        Err(MembershipError::Acknowledgement {
            stored: CommitOutcome::Inserted,
            ..
        })
    ));
    assert_eq!(store.records.len(), 1);
    connection.fail_ack = false;
    connection.incoming.push_back(content);
    assert!(matches!(
        ready(receive_from(&mut connection, &binding(), &mut store, 0)).unwrap(),
        ReceiveOutcome::Acknowledged {
            stored: CommitOutcome::Duplicate,
            ..
        }
    ));
    assert_eq!(store.records.len(), 1);
}
#[test]
fn bounded_content_is_refused_before_storage_or_ack() {
    let (mut connection, mut store, events) = fixtures(vec![record(&"x".repeat(5000))]);
    assert!(matches!(
        ready(receive_from(&mut connection, &binding(), &mut store, 0)),
        Err(MembershipError::ContentLimit)
    ));
    assert_eq!(*events.borrow(), vec!["poll"]);
    assert!(store.records.is_empty());
    assert!(connection.acknowledgements.is_empty());
}
#[test]
fn disconnected_registration_is_refused_before_poll() {
    let (mut connection, mut store, events) = fixtures(vec![record("fixture")]);
    connection.disconnected = true;
    assert!(matches!(
        ready(receive_from(&mut connection, &binding(), &mut store, 0)),
        Err(MembershipError::Transport(ClientError::Disconnected))
    ));
    assert!(events.borrow().is_empty());
    assert!(store.records.is_empty());
    assert!(connection.acknowledgements.is_empty());
}
