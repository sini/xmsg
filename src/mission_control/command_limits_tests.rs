use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header, Message},
};

use crate::enroll_oidc::signed_fixture::Fixture as Oidc;
use crate::observe_collector::tests::Fixture as Collector;

use super::admission::Refusal;
use super::authority::{Authority, DelegatedGrant, Grants, Issued, Record, Target};
use super::command::{self, CommandDouble, DoubleOutcome, ExactCommandAuthorityFixture, Reply};
use super::command_store as store;
use super::command_wire::{CommandRequest, PreparedRequest};
use super::tests::{scoped_transport_machine, transport_owner_records};
use super::{Config, Issuer, Prepared, Provider};

const WAIT: Duration = Duration::from_secs(5);
const NODE: &str = "fixture.node";
const ENDPOINT: &str = "claude-1@fixture.node";

fn target() -> Value {
    json!({
        "node":NODE,"endpoint":ENDPOINT,
        "state_epoch":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","incarnation":3,
        "selector":{"kind":"execution","session_id":"exec-alpha","generation":7}
    })
}

fn request_id(case: u128) -> String {
    format!("{case:032x}")
}

struct Harness {
    issuer: Arc<Issuer>,
    authority: Arc<ExactCommandAuthorityFixture>,
    double: Arc<CommandDouble>,
    owner: String,
    native: Issued,
    now: i64,
    _directory: tempfile::TempDir,
}

impl Harness {
    async fn new(setup: impl FnOnce(&mut Config)) -> Self {
        let directory = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let oidc = Oidc::new_at(crate::storage::now_epoch_secs()).await;
        let mut config: Config = serde_json::from_value(json!({
            "public_origin": "https://collector.example",
            "issuer": oidc.issuer(),
            "client_id": "web-client",
            "redirect_uri": "https://collector.example/login/callback",
            "allowlist": ["alice@example.org"],
            "native_client_id": "tui-client",
        }))
        .unwrap();
        setup(&mut config);
        config.validate().unwrap();
        let provider = Provider::discover_with_client(
            config.oidc(),
            &config.public_origin,
            false,
            oidc.http_client(),
        )
        .await
        .unwrap();
        let state =
            Authority::open(directory.path(), config.authority_config(vec![NODE.into()])).unwrap();
        let authority = Arc::new(ExactCommandAuthorityFixture::default());
        let double = Arc::new(CommandDouble::default());
        let issuer = Issuer::start_with_command_double_for_test(
            Prepared {
                config,
                provider,
                key: None,
            },
            state,
            authority.clone(),
            double.clone(),
        );
        issuer.recover_commands().unwrap();
        let (owner, native, _) = transport_owner_records(&issuer, &oidc.issuer());
        authority.grant(&native.record.principal, target());
        let now = command::now_ms();
        authority.freeze_clock(now);
        Self {
            issuer,
            authority,
            double,
            owner: owner.record.principal,
            native,
            now,
            _directory: directory,
        }
    }

    fn delegated(&self, holder: &str, held: bool) -> Issued {
        let issued = self
            .issuer
            .authority
            .mint_delegated(
                &self.owner,
                DelegatedGrant {
                    holder: holder.into(),
                    verbs: vec!["send".into()],
                    targets: vec![Target {
                        node: NODE.into(),
                        endpoint: ENDPOINT.into(),
                    }],
                    presenter: None,
                    expires_at: crate::storage::now_epoch_secs() + 60,
                    rate: 5,
                    read_scope: None,
                    confirm_verbs: Vec::new(),
                },
            )
            .unwrap();
        self.issuer
            .authority
            .allow_synthetic_for_test(&issued.handle);
        if held {
            self.issuer
                .authority
                .edit_fixture_record(&issued.record.record_id, |record| {
                    let Grants::Delegated { grant } = &mut record.grants else {
                        panic!("fixture grant must be delegated");
                    };
                    grant.confirm_verbs.push("send".into());
                });
        }
        self.authority.clear_bindings();
        self.authority.grant(&issued.record.principal, target());
        issued
    }

    fn prepare_at(&self, record: &Record, case: u128, requested_at: i64) -> Result<Reply, Refusal> {
        let request: PreparedRequest = serde_json::from_value(json!({
            "request_id":request_id(case), "requested_at":requested_at, "verb":"send",
            "target":target(), "params":{"text":"Capacity fixture."}
        }))
        .unwrap();
        self.issuer.command(
            record,
            "http",
            CommandRequest::Prepare { id: None, request },
        )
    }

    fn prepare(&self, record: &Record, case: u128) -> Reply {
        let prepared = self.prepare_at(record, case, self.now).unwrap();
        assert_eq!(prepared.body["type"], "prepared");
        prepared
    }

    fn commit(&self, record: &Record, prepared: &Reply) -> Result<Reply, Refusal> {
        self.issuer.command(
            record,
            "http",
            CommandRequest::Commit {
                id: None,
                request_id: prepared.body["request_id"].as_str().unwrap().into(),
                intent: prepared.body["intent"].as_str().unwrap().into(),
                digest: prepared.body["digest"].as_str().unwrap().into(),
            },
        )
    }

    fn lookup(&self, record: &Record, case: u128) -> Reply {
        self.issuer
            .command(
                record,
                "http",
                CommandRequest::Lookup {
                    id: None,
                    request_id: request_id(case),
                },
            )
            .unwrap()
    }

    fn assert_unclaimed(&self, record: &Record, prepared: &Reply) {
        let id = prepared.body["request_id"].as_str().unwrap();
        let token = prepared.body["intent"].as_str().unwrap();
        let state = self.issuer.authority.locked().unwrap();
        assert!(store::reservation(&state.conn, &record.principal, id)
            .unwrap()
            .is_none());
        assert!(
            !store::intent(&state.conn, &super::digest(token))
                .unwrap()
                .unwrap()
                .consumed
        );
    }

    async fn submitted(&self) {
        timeout(WAIT, self.double.submitted.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
    }
}

#[tokio::test]
async fn sc14_work_cap_refuses_fresh_commit_but_not_matching_replay() {
    let h = Harness::new(|c| {
        c.command_work_max_global = 6;
        c.command_work_max_per_record = 2;
    })
    .await;
    let record = &h.native.record;
    let first = h.prepare(record, 1);
    let other = h.prepare(record, 2);
    let rejected = h.prepare(record, 3);
    let receipt = h.commit(record, &first).unwrap();
    assert_eq!(receipt.body["outcome"], "effect_unknown");
    h.submitted().await;
    assert_eq!(
        h.commit(record, &other).unwrap().body["outcome"],
        "effect_unknown"
    );
    h.submitted().await;
    assert_eq!(
        h.commit(record, &rejected).err(),
        Some(Refusal::UNAVAILABLE),
        "work cap must refuse the first request past the per-record bound"
    );
    h.assert_unclaimed(record, &rejected);
    let repeated = h
        .commit(record, &first)
        .expect("matching consumed replay must remain available at work saturation");
    assert_eq!(repeated.body["receipt_id"], receipt.body["receipt_id"]);
    assert_eq!(repeated.body["lookup"], true);
    assert_eq!(h.lookup(record, 1).body, repeated.body);
    assert_eq!(h.double.requests.lock().unwrap().len(), 2);

    *h.double.outcome.lock().unwrap() = Some(DoubleOutcome::Admitted);
    h.double.release.notify_waiters();
    timeout(WAIT, async {
        while h.lookup(record, 1).body["outcome"] != "admitted"
            || h.lookup(record, 2).body["outcome"] != "admitted"
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        h.commit(record, &rejected).unwrap().body["outcome"],
        "effect_unknown"
    );
    h.submitted().await;
}

#[tokio::test]
async fn sc14_hold_cap_refuses_without_consuming_and_releases_on_decline() {
    let h = Harness::new(|c| {
        c.command_holds_max_global = 3;
        c.command_holds_max_per_record = 2;
    })
    .await;
    let a = h.delegated("holder-a", true);
    let b = h.delegated("holder-b", true);
    for case in [1, 2] {
        let prepared = h.prepare(&a.record, case);
        assert_eq!(
            h.commit(&a.record, &prepared).unwrap().body["outcome"],
            "held"
        );
    }
    let excess_a = h.prepare(&a.record, 3);
    assert_eq!(
        h.commit(&a.record, &excess_a).err(),
        Some(Refusal::UNAVAILABLE),
        "hold cap must refuse the first request past the per-record bound"
    );
    h.assert_unclaimed(&a.record, &excess_a);
    let third = h.prepare(&b.record, 4);
    assert_eq!(h.commit(&b.record, &third).unwrap().body["outcome"], "held");
    let excess_b = h.prepare(&b.record, 5);
    assert_eq!(
        h.commit(&b.record, &excess_b).err(),
        Some(Refusal::UNAVAILABLE),
        "hold cap must refuse past the collector-wide bound across records"
    );
    h.assert_unclaimed(&b.record, &excess_b);
    h.issuer
        .decide_command_for_test(&a.record.principal, &request_id(1), false)
        .unwrap();
    assert_eq!(h.lookup(&a.record, 1).body["code"], "declined");
    assert_eq!(
        h.commit(&a.record, &excess_a).unwrap().body["outcome"],
        "held"
    );
    assert!(h.double.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sc14_intent_cap_refuses_prepare_only_rows_at_exact_bound() {
    let h = Harness::new(|c| {
        c.command_intents_max_global = 3;
        c.command_intents_max_per_record = 2;
    })
    .await;
    let record = &h.native.record;
    h.prepare(record, 1);
    h.prepare(record, 2);
    assert_eq!(
        h.prepare_at(record, 3, h.now).err(),
        Some(Refusal::UNAVAILABLE),
        "prepare-only cap must refuse the first intent past the per-record bound"
    );
    let other = h.delegated("intent-holder", false);
    h.prepare(&other.record, 4);
    assert_eq!(
        h.prepare_at(&other.record, 5, h.now).err(),
        Some(Refusal::UNAVAILABLE),
        "prepare-only cap must enforce the collector-wide bound across records"
    );
    {
        let state = h.issuer.authority.locked().unwrap();
        assert_eq!(store::count_unused_intents(&state.conn, None).unwrap(), 3);
        assert_eq!(store::count_reserved(&state.conn, None).unwrap(), 0);
    }
    let later = h.now + h.issuer.config.intent_ttl_ms as i64;
    h.authority.freeze_clock(later);
    {
        let state = h.issuer.authority.locked().unwrap();
        store::compact(&state.conn, h.now, later).unwrap();
    }
    assert_eq!(
        h.prepare_at(record, 3, later).unwrap().body["type"],
        "prepared"
    );
    assert!(h.double.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sc14_reserved_cap_applies_across_records_and_releases_on_restart() {
    let h = Harness::new(|c| {
        c.command_reserved_max_global = 2;
        c.command_reserved_max_per_record = 2;
    })
    .await;
    h.authority.abandon.store(true, Ordering::SeqCst);
    let a = h.delegated("abandoned-a", false);
    let b = h.delegated("abandoned-b", false);
    let first = h.prepare(&a.record, 1);
    let second = h.prepare(&b.record, 2);
    let first_receipt = h.commit(&a.record, &first).unwrap();
    let second_receipt = h.commit(&b.record, &second).unwrap();
    let rejected = h.prepare(&b.record, 3);
    assert_eq!(
        h.commit(&b.record, &rejected).err(),
        Some(Refusal::UNAVAILABLE),
        "reserved cap must refuse the first request past the global bound"
    );
    h.assert_unclaimed(&b.record, &rejected);
    assert_eq!(
        h.lookup(&a.record, 1).body["receipt_id"],
        first_receipt.body["receipt_id"]
    );
    assert_eq!(
        h.lookup(&b.record, 2).body["receipt_id"],
        second_receipt.body["receipt_id"]
    );
    h.issuer.recover_commands().unwrap();
    assert_eq!(h.lookup(&a.record, 1).body["code"], "interrupted");
    assert_eq!(h.lookup(&b.record, 2).body["code"], "interrupted");
    assert_eq!(
        h.commit(&b.record, &rejected).unwrap().body["outcome"],
        "effect_unknown"
    );
    assert!(h.double.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sc4_future_skew_and_sc2_intent_expiry_are_exact() {
    let h = Harness::new(|_| {}).await;
    let record = &h.native.record;
    let bound = h.now + h.issuer.config.clock_skew_secs as i64 * 1000;
    let too_new = h.prepare_at(record, 1, bound + 1).unwrap();
    assert_eq!(
        too_new.body["code"], "expired_request",
        "future skew bound must reject one millisecond beyond the limit"
    );
    let prepared = h.prepare_at(record, 1, bound).unwrap();
    assert_eq!(prepared.body["type"], "prepared");
    let expires = prepared.body["expires_at"].as_i64().unwrap();
    h.authority.freeze_clock(expires);
    let denied = h.commit(record, &prepared).unwrap();
    assert_eq!(
        denied.body["code"], "intent_invalid",
        "unconsumed intent must be invalid at its expiry instant"
    );
    h.assert_unclaimed(record, &prepared);
    assert!(h.double.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sc11_machine_hello_never_grants_available_commands() {
    let h = Harness::new(|_| {}).await;
    let machine = scoped_transport_machine(&h.issuer, &h.owner);
    let collector = Collector::command_fixture(h.issuer.clone()).await;
    let mut url = reqwest::Url::parse(&collector.url).unwrap();
    url.set_scheme("ws").unwrap();
    url.set_path("/v1/mission-control/session");
    for (issued, expected) in [
        (&h.native, json!(["observe", "commands"])),
        (&machine, json!(["observe"])),
    ] {
        let mut request = url.as_str().into_client_request().unwrap();
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            "xmsg.mission-control.v1".parse().unwrap(),
        );
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", issued.handle).parse().unwrap(),
        );
        let (mut socket, _) = timeout(WAIT, connect_async(request))
            .await
            .unwrap()
            .unwrap();
        let hello = json!({"v":1,"type":"hello","id":1,"protocol":1,
                           "capabilities":["observe","commands"],"require":["observe"]});
        timeout(WAIT, socket.send(Message::Text(hello.to_string().into())))
            .await
            .unwrap()
            .unwrap();
        let Message::Text(payload) = timeout(WAIT, socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        else {
            panic!("expected hello text")
        };
        let response: Value = serde_json::from_str(payload.as_str()).unwrap();
        assert_eq!(response["type"], "hello");
        assert_eq!(
            response["capabilities"], expected,
            "machine must not receive commands when fixture authority is available"
        );
    }
}
