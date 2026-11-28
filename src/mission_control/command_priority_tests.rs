use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{header, HeaderValue},
        Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use crate::enroll_oidc::signed_fixture::Fixture as Oidc;
use crate::observe_collector::tests::Fixture;

use super::authority::{Issued, Record, Scope};
use super::command::{self, CommandDouble, DoubleOutcome, ExactCommandAuthorityFixture};
use super::command_store::{self as store, State};
use super::command_wire::{CommandRequest, PreparedRequest};
use super::hub::Reset;
use super::protocol::Projection;
use super::tests::{command_double_transport_fixture, transport_owner_records};
use super::Issuer;

const WAIT: Duration = Duration::from_secs(5);
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Harness {
    collector: Fixture,
    owner: Issued,
    issuer: Arc<Issuer>,
    authority: Arc<ExactCommandAuthorityFixture>,
    double: Arc<CommandDouble>,
    clock: i64,
    _directory: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let oidc = Oidc::new_at(crate::storage::now_epoch_secs()).await;
        let (issuer, authority, double) = command_double_transport_fixture(&oidc, &directory).await;
        let (_, owner, _) = transport_owner_records(&issuer, &oidc.issuer());
        authority.grant(
            &owner.record.principal,
            json!({
                "node": "fixture.node", "endpoint": "claude-1@fixture.node",
                "state_epoch": "0a1b2c3d4e5f60718293a4b5c6d7e8f9", "incarnation": 3,
                "selector": {"kind": "execution", "session_id": "exec-alpha", "generation": 7}
            }),
        );
        let clock = command::now_ms();
        authority.freeze_clock(clock);
        let collector = Fixture::command_fixture(issuer.clone()).await;
        Self {
            collector,
            owner,
            issuer,
            authority,
            double,
            clock,
            _directory: directory,
        }
    }

    async fn socket(&self) -> Socket {
        let mut url = reqwest::Url::parse(&self.collector.url).unwrap();
        url.set_scheme("ws").unwrap();
        url.set_path("/v1/mission-control/session");
        let mut request = url.as_str().into_client_request().unwrap();
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("xmsg.mission-control.v1"),
        );
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.owner.handle)).unwrap(),
        );
        let (mut socket, _) = timeout(WAIT, connect_async(request))
            .await
            .unwrap()
            .unwrap();
        send(
            &mut socket,
            json!({"v":1,"type":"hello","id":1,"protocol":1,
                   "capabilities":["observe","commands"],"require":["observe","commands"]}),
        )
        .await;
        let hello = next_text(&mut socket).await;
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["capabilities"], json!(["observe", "commands"]));
        socket
    }

    async fn submit(&self, case: usize) -> (String, Value) {
        let id = format!("{case:032x}");
        let request: PreparedRequest = serde_json::from_value(json!({
            "request_id": id, "requested_at": self.clock, "verb": "send",
            "target": {
                "node":"fixture.node","endpoint":"claude-1@fixture.node",
                "state_epoch":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","incarnation":3,
                "selector":{"kind":"execution","session_id":"exec-alpha","generation":7}
            },
            "params":{"text":"Priority fixture."}
        }))
        .unwrap();
        let owner: &Record = &self.owner.record;
        let prepared = self
            .issuer
            .command(owner, "http", CommandRequest::Prepare { id: None, request })
            .unwrap();
        let reply = self
            .issuer
            .command(
                owner,
                "http",
                CommandRequest::Commit {
                    id: None,
                    request_id: id.clone(),
                    intent: prepared.body["intent"].as_str().unwrap().into(),
                    digest: prepared.body["digest"].as_str().unwrap().into(),
                },
            )
            .unwrap();
        assert_eq!(reply.body["outcome"], "effect_unknown");
        timeout(WAIT, self.double.submitted.acquire())
            .await
            .expect("executor double did not receive a command")
            .unwrap()
            .forget();
        (id, reply.body["receipt_id"].clone())
    }

    fn state(&self, id: &str) -> Option<State> {
        let state = self.issuer.authority.locked().unwrap();
        store::reservation(&state.conn, &self.owner.record.principal, id)
            .unwrap()
            .map(|row| row.state)
    }

    async fn await_state(&self, id: &str, wanted: State) {
        timeout(WAIT, async {
            while self.state(id) != Some(wanted) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reservation did not reach the expected state");
    }

    async fn lookup(&self, id: &str) -> Value {
        let client = reqwest::Client::builder().timeout(WAIT).build().unwrap();
        client
            .get(format!("{}/v1/receipts/{id}", self.collector.url))
            .bearer_auth(&self.owner.handle)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
}

async fn send(socket: &mut Socket, body: Value) {
    timeout(WAIT, socket.send(Message::Text(body.to_string().into())))
        .await
        .unwrap()
        .unwrap();
}

async fn next_frame(socket: &mut Socket) -> Message {
    timeout(WAIT, async {
        loop {
            let frame = socket
                .next()
                .await
                .expect("socket ended without a frame")
                .unwrap();
            match &frame {
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(text)
                    if serde_json::from_str::<Value>(text.as_str()).unwrap()["type"] == "tick" => {}
                _ => return frame,
            }
        }
    })
    .await
    .expect("socket did not send its next frame")
}

async fn next_text(socket: &mut Socket) -> Value {
    let Message::Text(text) = next_frame(socket).await else {
        panic!("expected a data frame");
    };
    serde_json::from_str(text.as_str()).unwrap()
}

async fn backlog_case(overflow: bool) {
    let test = Harness::new().await;
    let mut socket = test.socket().await;
    send(
        &mut socket,
        json!({"v": 1, "type": "subscribe", "id": 2,
                            "sub":"fleet", "scope":{"kind":"fleet"}}),
    )
    .await;
    assert_eq!(next_text(&mut socket).await["type"], "subscribed");
    loop {
        let snapshot = next_text(&mut socket).await;
        assert_eq!(snapshot["type"], "snapshot");
        if snapshot["final"] == true {
            break;
        }
    }

    let hub = test.collector.command_read_hub();
    let projection = Projection {
        scope: &Scope::Fleet,
        grants: &[Scope::Fleet],
        masked: &|_| false,
        activity: false,
    };
    let (snapshot, _) = hub.frozen(&projection, false).unwrap().unwrap();
    test.authority
        .data_send_pause
        .armed
        .store(true, Ordering::SeqCst);
    hub.inject_source_gap_for_test("fixture.node");
    timeout(WAIT, test.authority.data_send_pause.entered.acquire())
        .await
        .expect("the real socket did not start a data send")
        .unwrap()
        .forget();

    for _ in 0..2 {
        hub.queue_mask_canaries("fixture.node");
    }
    assert!(
        matches!(
            hub.after(snapshot.watermark, &projection, 8, false),
            Err(Reset::SlowConsumer)
        ),
        "positive control: observation backlog must exceed the queue bound"
    );

    let count = if overflow {
        test.issuer.config.receipt_lane_max + 1
    } else {
        1
    };
    *test.double.outcome.lock().unwrap() = Some(DoubleOutcome::Admitted);
    let mut receipts = Vec::new();
    for case in 1..=count {
        let (id, receipt) = test.submit(case).await;
        test.await_state(&id, State::Admitted).await;
        receipts.push((id, receipt));
    }
    test.authority.data_send_pause.release.add_permits(1);

    if overflow {
        let Message::Close(Some(close)) = next_frame(&mut socket).await else {
            panic!("a full receipt lane must close instead of emitting data or losing receipts");
        };
        assert_eq!(u16::from(close.code), 4408);
    } else {
        let reply = next_text(&mut socket).await;
        assert_eq!(
            reply["type"], "receipt",
            "a data or gap frame cannot overtake a final receipt"
        );
        assert_eq!(reply["receipt_id"], receipts[0].1);
        assert_eq!(reply["outcome"], "admitted");
        assert_eq!(next_text(&mut socket).await["type"], "event");
    }

    for (id, receipt) in receipts {
        let recovered = test.lookup(&id).await;
        assert_eq!(recovered["receipt_id"], receipt);
        assert_eq!(recovered["outcome"], "admitted");
    }
}

#[tokio::test]
async fn sc6_receipt_overtakes_data_or_closes_and_recovers() {
    backlog_case(false).await;
    backlog_case(true).await;
}

#[tokio::test]
async fn sc14_silence_stays_nonfinal_and_loss_is_final_unknown() {
    let test = Harness::new().await;
    let (id, receipt) = test.submit(1).await;
    let current = test.lookup(&id).await;
    assert_eq!(current["receipt_id"], receipt);
    assert_eq!(current["outcome"], "effect_unknown");
    assert_eq!(test.state(&id), Some(State::Submitting));
    let future = test.clock + 31 * 24 * 60 * 60 * 1_000;
    let cutoff = future - 30 * 24 * 60 * 60 * 1_000;
    {
        let state = test.issuer.authority.locked().unwrap();
        assert_eq!(store::compact(&state.conn, cutoff, future).unwrap(), 0);
    }
    assert_eq!(test.state(&id), Some(State::Submitting));
    assert_eq!(test.lookup(&id).await["receipt_id"], receipt);

    *test.double.outcome.lock().unwrap() = Some(DoubleOutcome::Lost);
    test.double.release.notify_one();
    test.await_state(&id, State::EffectUnknown).await;
    let final_receipt = test.lookup(&id).await;
    assert_eq!(final_receipt["receipt_id"], receipt);
    assert_eq!(final_receipt["outcome"], "effect_unknown");
    assert!(final_receipt.get("code").is_none());
    assert_eq!(test.double.requests.lock().unwrap().len(), 1);
}
