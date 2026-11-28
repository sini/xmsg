use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header, HeaderValue};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::enroll_oidc::signed_fixture::Fixture as Oidc;
use crate::observe_collector::tests::Fixture;
use crate::storage::now_epoch_secs;

use super::authority::{
    AuthorityError, DelegatedGrant, Grants, Issued, Scope, Target as GrantTarget,
};
use super::command::{CommandDouble, DoubleOutcome, ExactCommandAuthorityFixture};
use super::tests::{
    command_double_transport_fixture, exact_command_transport_fixture, transport_owner_records,
};
use super::Issuer;

const REQUEST_ID: &str = "6f1e2d3c4b5a69788796a5b4c3d2e1f0";
const STALE_ID: &str = "7f1e2d3c4b5a69788796a5b4c3d2e1f0";
const REMOVED_ID: &str = "8f1e2d3c4b5a69788796a5b4c3d2e1f0";
const WS_PROTOCOL: &str = "xmsg.mission-control.v1";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Carrier {
    collector: Fixture,
    http: Client,
    bearer: String,
    principal: String,
}

impl Carrier {
    async fn new(issuer: Arc<Issuer>, oidc: &Oidc) -> Self {
        let (_, native, _) = transport_owner_records(&issuer, &oidc.issuer());
        Self::with_issued(issuer, native).await
    }

    async fn with_issued(issuer: Arc<Issuer>, issued: Issued) -> Self {
        let collector = Fixture::command_fixture(issuer).await;
        let http = Client::builder().timeout(RESPONSE_TIMEOUT).build().unwrap();
        Self {
            collector,
            http,
            bearer: issued.handle,
            principal: issued.record.principal,
        }
    }

    fn post_request(&self, handle: &str, stage: &str, body: &Value) -> reqwest::RequestBuilder {
        self.http
            .post(format!(
                "{}/v1/mission-control/commands/{stage}",
                self.collector.url
            ))
            .bearer_auth(handle)
            .json(body)
    }

    async fn post(&self, stage: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .post_request(&self.bearer, stage, &body)
            .send()
            .await
            .unwrap();
        (response.status(), response.json().await.unwrap())
    }

    async fn lookup_wire(&self, handle: &str, request_id: &str) -> (StatusCode, String) {
        let response = self
            .http
            .get(format!("{}/v1/receipts/{request_id}", self.collector.url))
            .bearer_auth(handle)
            .send()
            .await
            .unwrap();
        (response.status(), response.text().await.unwrap())
    }

    async fn lookup(&self, request_id: &str) -> Value {
        let (status, body) = self.lookup_wire(&self.bearer, request_id).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "authorized receipt lookup was denied"
        );
        serde_json::from_str(&body).unwrap()
    }

    async fn ws(&self) -> Socket {
        self.ws_from(&self.bearer).await
    }

    async fn ws_from(&self, handle: &str) -> Socket {
        let mut url = reqwest::Url::parse(&self.collector.url).unwrap();
        url.set_scheme("ws").unwrap();
        url.set_path("/v1/mission-control/session");
        let mut request = url.as_str().into_client_request().unwrap();
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(WS_PROTOCOL),
        );
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {handle}")).unwrap(),
        );
        let (mut socket, _) = timeout(RESPONSE_TIMEOUT, connect_async(request))
            .await
            .unwrap()
            .unwrap();
        let hello = ws_exchange(
            &mut socket,
            1,
            json!({"v":1,"type":"hello","protocol":1,"capabilities":["commands"],"require":["commands"]}),
        )
        .await;
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["capabilities"], json!(["commands"]));
        socket
    }
}

async fn ws_next(socket: &mut Socket) -> Value {
    timeout(RESPONSE_TIMEOUT, async {
        loop {
            let message = socket.next().await.unwrap().unwrap();
            match message {
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(text.as_str()).unwrap();
                    if value["type"] != "tick" {
                        return value;
                    }
                }
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("unexpected WebSocket frame {other:?}"),
            }
        }
    })
    .await
    .expect("collector must deliver the reply without the settlement barrier")
}

async fn ws_exchange(socket: &mut Socket, id: u32, mut message: Value) -> Value {
    message["id"] = json!(id);
    timeout(
        RESPONSE_TIMEOUT,
        socket.send(Message::Text(message.to_string().into())),
    )
    .await
    .unwrap()
    .unwrap();
    let mut value = ws_next(socket).await;
    assert_eq!(value.as_object_mut().unwrap().remove("re"), Some(json!(id)));
    value
}

fn target() -> Value {
    json!({
        "node":"fixture.node","endpoint":"claude-1@fixture.node",
        "state_epoch":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","incarnation":3,
        "selector":{"kind":"execution","session_id":"exec-alpha","generation":7}
    })
}

fn prepare(request_id: &str, at: i64, target: &Value) -> Value {
    json!({
        "v":1,"type":"prepare","request_id":request_id,"requested_at":at,
        "verb":"send","target":target,"params":{"text":"Hello"}
    })
}

fn commit(prepared: &Value) -> Value {
    json!({
        "v":1,"type":"commit","request_id":prepared["request_id"],
        "intent":prepared["intent"],"digest":prepared["digest"]
    })
}

fn lookup(request_id: &str) -> Value {
    json!({"v":1,"type":"lookup","request_id":request_id})
}

async fn check_handoff(double: &CommandDouble) {
    timeout(RESPONSE_TIMEOUT, double.submitted.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert!(double.outcome.lock().unwrap().is_none());
}

fn release_admitted(double: &CommandDouble) {
    *double.outcome.lock().unwrap() = Some(DoubleOutcome::Admitted);
    double.release.notify_waiters();
}

#[tokio::test]
async fn sc9_http_and_ws_share_initial_handoff_and_settled_lookup() {
    let oidc = Oidc::new_at(now_epoch_secs()).await;
    let http_store = tempfile::tempdir().unwrap();
    let ws_store = tempfile::tempdir().unwrap();
    let (http_issuer, http_fixture, http_double) =
        command_double_transport_fixture(&oidc, &http_store).await;
    let (ws_issuer, ws_fixture, ws_double) =
        command_double_transport_fixture(&oidc, &ws_store).await;
    let http = Carrier::new(http_issuer, &oidc).await;
    let websocket = Carrier::new(ws_issuer, &oidc).await;
    let target = target();
    let prepared_at = now_epoch_secs() * 1000;
    for (carrier, fixture) in [(&http, &http_fixture), (&websocket, &ws_fixture)] {
        fixture.grant(&carrier.principal, target.clone());
        fixture.freeze_clock(prepared_at);
        fixture.enable_deterministic_ids();
    }
    let mut socket = websocket.ws().await;
    let request = prepare(REQUEST_ID, prepared_at, &target);
    let (http_prepared, ws_prepared) = tokio::join!(
        http.post("prepare", request.clone()),
        ws_exchange(&mut socket, 2, request.clone()),
    );
    assert_eq!(http_prepared.0, StatusCode::OK);
    assert_eq!(http_prepared.1, ws_prepared);
    assert_eq!(ws_prepared["type"], "prepared");
    assert_eq!(ws_prepared["presentation"]["selector"], target["selector"]);

    let mut changed_request = request.clone();
    changed_request["params"]["text"] = json!("The later intent must not replace the original");
    let (http_changed, ws_changed) = tokio::join!(
        http.post("prepare", changed_request.clone()),
        ws_exchange(&mut socket, 3, changed_request),
    );
    assert_eq!(http_changed.0, StatusCode::OK);
    assert_eq!(http_changed.1, ws_changed);
    assert_ne!(ws_changed["digest"], ws_prepared["digest"]);

    for fixture in [&http_fixture, &ws_fixture] {
        fixture.freeze_clock(prepared_at + 100);
    }
    let (http_initial, ws_initial) = tokio::join!(
        http.post("commit", commit(&http_prepared.1)),
        ws_exchange(&mut socket, 4, commit(&ws_prepared)),
    );
    assert_eq!(http_initial.0, StatusCode::OK);
    assert_eq!(http_initial.1, ws_initial);
    assert_eq!(ws_initial["type"], "receipt");
    assert_eq!(ws_initial["outcome"], "effect_unknown");
    assert_eq!(ws_initial["at"], prepared_at + 100);
    tokio::join!(check_handoff(&http_double), check_handoff(&ws_double));
    let mut canonical_request = request;
    let canonical_object = canonical_request.as_object_mut().unwrap();
    canonical_object.remove("v");
    canonical_object.remove("type");
    for double in [&http_double, &ws_double] {
        let inputs = double.requests.lock().unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(serde_json::to_value(&inputs[0]).unwrap(), canonical_request);
        assert_eq!(inputs[0].digest(), ws_prepared["digest"]);
    }

    for fixture in [&http_fixture, &ws_fixture] {
        fixture.freeze_clock(prepared_at + 200);
    }
    release_admitted(&http_double);
    release_admitted(&ws_double);
    let push = ws_next(&mut socket).await;
    assert!(push.get("re").is_none());
    assert_eq!(push["outcome"], "admitted");
    assert_eq!(push["receipt_id"], ws_initial["receipt_id"]);
    assert_eq!(push["at"], prepared_at + 200);

    let http_settled = timeout(RESPONSE_TIMEOUT, async {
        loop {
            let observed = http.lookup(REQUEST_ID).await;
            match observed["outcome"].as_str() {
                Some("admitted") => return observed,
                Some("effect_unknown") => tokio::task::yield_now().await,
                other => panic!("unexpected settled HTTP outcome {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    let ws_settled = ws_exchange(&mut socket, 5, lookup(REQUEST_ID)).await;
    assert_eq!(http_settled, ws_settled);
    let mut expected = push;
    expected["lookup"] = json!(true);
    assert_eq!(ws_settled, expected);
    assert_eq!(http_double.submitted.available_permits(), 0);
    assert_eq!(ws_double.submitted.available_permits(), 0);
}

struct CommandTransport {
    carrier: Carrier,
    socket: Option<Socket>,
}

impl CommandTransport {
    async fn prepare(&mut self, id: u32, request: Value) -> Value {
        if let Some(socket) = &mut self.socket {
            return ws_exchange(socket, id, request).await;
        }
        let (status, body) = self.carrier.post("prepare", request).await;
        assert!(matches!(status, StatusCode::OK | StatusCode::NOT_FOUND));
        if status == StatusCode::NOT_FOUND {
            assert_eq!(body["code"], "not_found_or_denied");
        }
        body
    }

    async fn commit(&mut self, id: u32, prepared: &Value) -> Value {
        let body = commit(prepared);
        if let Some(socket) = &mut self.socket {
            return ws_exchange(socket, id, body).await;
        }
        let (status, body) = self.carrier.post("commit", body).await;
        assert!(matches!(status, StatusCode::OK | StatusCode::NOT_FOUND));
        if status == StatusCode::NOT_FOUND {
            no_receipt(&body, "not_found_or_denied");
        }
        body
    }

    async fn lookup(&mut self, id: u32, request_id: &str) -> Value {
        if let Some(socket) = &mut self.socket {
            return ws_exchange(socket, id, lookup(request_id)).await;
        }
        self.carrier.lookup(request_id).await
    }
}

fn change_binding(fixture: &ExactCommandAuthorityFixture, principal: &str, target: Value) {
    fixture.clear_bindings();
    fixture.grant(principal, target);
}

#[tokio::test]
async fn oq13_exact_authority_checks_live_bindings_only_for_fresh_work() {
    for websocket in [false, true] {
        let oidc = Oidc::new_at(now_epoch_secs()).await;
        let store = tempfile::tempdir().unwrap();
        let (issuer, fixture) = exact_command_transport_fixture(&oidc, &store).await;
        let carrier = Carrier::new(issuer, &oidc).await;
        let principal = carrier.principal.clone();
        let target = target();
        fixture.grant(&principal, target.clone());
        let at = now_epoch_secs() * 1000;
        let socket = if websocket {
            Some(carrier.ws().await)
        } else {
            None
        };
        let mut transport = CommandTransport { carrier, socket };

        let original = prepare(REQUEST_ID, at, &target);
        let prepared = transport.prepare(2, original.clone()).await;
        let incumbent = transport.commit(3, &prepared).await;
        assert_eq!(incumbent["code"], "unattested");

        let mut next_generation = target.clone();
        next_generation["selector"]["generation"] = json!(8);
        let stale = transport.prepare(4, prepare(STALE_ID, at, &target)).await;
        assert_eq!(stale["type"], "prepared");
        change_binding(&fixture, &principal, next_generation.clone());
        let denied = transport.commit(5, &stale).await;
        assert_eq!(denied["code"], "target_changed");
        assert_eq!(denied["outcome"], "refused");

        let removed = transport
            .prepare(6, prepare(REMOVED_ID, at, &next_generation))
            .await;
        assert_eq!(removed["type"], "prepared");
        fixture.clear_bindings();
        let denied = transport.commit(7, &removed).await;
        assert_eq!(denied["code"], "denied");
        assert_eq!(denied["outcome"], "refused");

        let mut recovered = incumbent.clone();
        recovered["lookup"] = json!(true);
        assert_eq!(transport.lookup(8, REQUEST_ID).await, recovered);
        assert_eq!(transport.prepare(9, original.clone()).await, recovered);
        assert_eq!(transport.commit(10, &prepared).await, recovered);

        let mut rebound = target.clone();
        rebound["selector"]["session_id"] = json!("exec-beta");
        change_binding(&fixture, &principal, rebound);
        assert_eq!(transport.lookup(11, REQUEST_ID).await, recovered);
        assert_eq!(transport.prepare(12, original).await, recovered);
        assert_eq!(transport.commit(13, &prepared).await, recovered);
    }
}

#[tokio::test]
async fn oq13_same_node_mismatch_and_ambiguity_do_not_mint_intents() {
    let oidc = Oidc::new_at(now_epoch_secs()).await;
    let store = tempfile::tempdir().unwrap();
    let (issuer, fixture) = exact_command_transport_fixture(&oidc, &store).await;
    let carrier = Carrier::new(issuer.clone(), &oidc).await;
    let target = target();
    fixture.grant(&carrier.principal, target.clone());
    let at = now_epoch_secs() * 1000;

    let mut endpoint_mismatch = target.clone();
    endpoint_mismatch["endpoint"] = json!("claude-2@fixture.node");
    fixture.grants.lock().unwrap().push((
        carrier.principal.clone(),
        "fixture.node".to_owned(),
        "claude-2@fixture.node".to_owned(),
    ));
    let mut session_mismatch = target.clone();
    session_mismatch["selector"]["session_id"] = json!("exec-beta");
    let expected = carrier
        .post("prepare", prepare(REQUEST_ID, at, &endpoint_mismatch))
        .await;
    assert_eq!(expected.0, StatusCode::NOT_FOUND);
    assert_eq!(expected.1["code"], "not_found_or_denied");
    assert!(expected.1.get("intent").is_none());
    assert_eq!(
        carrier
            .post("prepare", prepare(REQUEST_ID, at, &session_mismatch))
            .await,
        expected
    );

    let mut socket = carrier.ws().await;
    let ws_denied = ws_exchange(&mut socket, 2, prepare(REQUEST_ID, at, &endpoint_mismatch)).await;
    assert_eq!(ws_denied["code"], "not_found_or_denied");
    assert!(ws_denied.get("intent").is_none());
    assert_eq!(
        ws_exchange(&mut socket, 3, prepare(REQUEST_ID, at, &session_mismatch)).await,
        ws_denied
    );

    fixture.grant(&carrier.principal, target.clone());
    assert_eq!(
        carrier
            .post("prepare", prepare(REQUEST_ID, at, &target))
            .await,
        expected
    );
    assert_eq!(
        ws_exchange(&mut socket, 4, prepare(REQUEST_ID, at, &target)).await,
        ws_denied
    );
    assert_eq!(counters(&issuer), (0, 0, 0));

    change_binding(&fixture, &carrier.principal, target.clone());
    let (status, prepared) = carrier
        .post("prepare", prepare(REQUEST_ID, at, &target))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(prepared["type"], "prepared");
    assert!(prepared["intent"].is_string());
}

fn counters(issuer: &Issuer) -> (i64, i64, i64) {
    issuer
        .authority
        .locked()
        .unwrap()
        .conn
        .query_row(
            "SELECT (SELECT count(*) FROM command_intents),
                    (SELECT count(*) FROM command_intents WHERE consumed = 1),
                    (SELECT count(*) FROM command_reservations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

#[tokio::test]
async fn sc9_intents_are_bound_to_carrier_connection_and_credential_record() {
    let oidc = Oidc::new_at(now_epoch_secs()).await;
    let store = tempfile::tempdir().unwrap();
    let (issuer, fixture) = exact_command_transport_fixture(&oidc, &store).await;
    let (browser, native, _) = transport_owner_records(&issuer, &oidc.issuer());
    let other = issuer
        .authority
        .issue_native(&browser.record.record_id)
        .unwrap();
    assert_eq!(native.record.principal, other.record.principal);
    assert_ne!(native.record.record_id, other.record.record_id);
    fixture.grant(&native.record.principal, target());
    let collector = Fixture::command_fixture(issuer.clone()).await;
    let carrier = Carrier {
        collector,
        http: Client::builder().timeout(RESPONSE_TIMEOUT).build().unwrap(),
        bearer: native.handle,
        principal: native.record.principal,
    };
    let at = now_epoch_secs() * 1000;
    let mut socket = carrier.ws().await;
    let ws_prepared = ws_exchange(&mut socket, 2, prepare(REQUEST_ID, at, &target())).await;
    let (status, http_prepared) = carrier
        .post("prepare", prepare(STALE_ID, at, &target()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let unused_ws = ws_exchange(&mut socket, 3, prepare(REMOVED_ID, at, &target())).await;
    assert_eq!(unused_ws["type"], "prepared");
    assert_eq!(counters(&issuer), (3, 0, 0));

    let http_denied = carrier.post("commit", commit(&ws_prepared)).await;
    assert_eq!(http_denied.0, StatusCode::OK);
    assert_eq!(http_denied.1["code"], "intent_invalid");
    let ws_denied = ws_exchange(&mut socket, 4, commit(&http_prepared)).await;
    assert_eq!(ws_denied["code"], "intent_invalid");

    let response = carrier
        .http
        .post(format!(
            "{}/v1/mission-control/commands/commit",
            carrier.collector.url
        ))
        .bearer_auth(other.handle)
        .json(&commit(&http_prepared))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let record_denied: Value = response.json().await.unwrap();
    assert_eq!(record_denied["code"], "intent_invalid");
    assert_eq!(counters(&issuer), (3, 0, 0));

    let incumbent = ws_exchange(&mut socket, 5, commit(&ws_prepared)).await;
    assert_eq!(incumbent["code"], "unattested");
    assert_eq!(counters(&issuer), (3, 1, 1));
    let wrong_carrier = carrier.post("commit", commit(&ws_prepared)).await;
    assert_eq!(wrong_carrier.1["code"], "intent_invalid");
    assert_ne!(wrong_carrier.1["receipt_id"], incumbent["receipt_id"]);

    socket.close(None).await.unwrap();
    for intent in [&ws_prepared, &unused_ws] {
        let wrong_carrier = carrier.post("commit", commit(intent)).await;
        assert_eq!(wrong_carrier.1["code"], "intent_invalid");
        assert_ne!(wrong_carrier.1["receipt_id"], incumbent["receipt_id"]);
    }
    let mut reconnected = carrier.ws().await;
    for (id, intent) in [(2, &ws_prepared), (3, &unused_ws)] {
        let wrong_socket = ws_exchange(&mut reconnected, id, commit(intent)).await;
        assert_eq!(wrong_socket["code"], "intent_invalid");
        assert_ne!(wrong_socket["receipt_id"], incumbent["receipt_id"]);
    }
    assert_eq!(counters(&issuer), (3, 1, 1));
}

fn grant(holder: &str, targets: &[&Value]) -> DelegatedGrant {
    DelegatedGrant {
        holder: holder.to_owned(),
        verbs: vec!["send".to_owned()],
        targets: targets
            .iter()
            .map(|target| GrantTarget {
                node: target["node"].as_str().unwrap().to_owned(),
                endpoint: target["endpoint"].as_str().unwrap().to_owned(),
            })
            .collect(),
        presenter: None,
        expires_at: now_epoch_secs() + 600,
        rate: 5,
        read_scope: None,
        confirm_verbs: Vec::new(),
    }
}

fn delegated(issuer: &Issuer, owner: &str, grant: DelegatedGrant) -> Issued {
    let holder = issuer.authority.mint_delegated(owner, grant).unwrap();
    issuer.authority.allow_synthetic_for_test(&holder.handle);
    holder
}

fn no_receipt(value: &Value, code: &str) {
    assert_eq!(value["type"], "error");
    assert_eq!(value["code"], code);
    for field in ["receipt_id", "outcome", "request_id"] {
        assert!(value.get(field).is_none());
    }
}

async fn assert_ws_invalidated(socket: &mut Socket) {
    let close = timeout(RESPONSE_TIMEOUT, async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Close(close) => return close,
                Message::Text(text) => {
                    let message: Value = serde_json::from_str(text.as_str()).unwrap();
                    assert_ne!(message["type"], "receipt");
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(u16::from(close.code), 4401 | 4403));
}

#[tokio::test]
async fn sc8_lookup_is_reauthorized_and_read_only_past_the_ring() {
    let oidc = Oidc::new_at(now_epoch_secs()).await;
    let store = tempfile::tempdir().unwrap();
    let (issuer, fixture) = exact_command_transport_fixture(&oidc, &store).await;
    let (browser, native, _) = transport_owner_records(&issuer, &oidc.issuer());
    let owner = browser.record.principal;
    let target = target();
    let foreign = delegated(&issuer, &owner, grant("foreign-holder", &[&target]));
    fixture.grant(&native.record.principal, target.clone());
    fixture.grants.lock().unwrap().push((
        foreign.record.principal.clone(),
        target["node"].as_str().unwrap().to_owned(),
        target["endpoint"].as_str().unwrap().to_owned(),
    ));
    let machine = issuer
        .authority
        .mint_machine(&owner, "readonly", vec![Scope::Fleet], None, 5)
        .unwrap();
    let id = native.record.record_id.clone();
    let carrier = Carrier::with_issued(issuer.clone(), native).await;
    let at = now_epoch_secs() * 1000;
    fixture.freeze_clock(at);
    let (status, prepared) = carrier
        .post("prepare", prepare(REQUEST_ID, at, &target))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, incumbent) = carrier.post("commit", commit(&prepared)).await;
    assert_eq!(incumbent["code"], "unattested");

    fixture.freeze_clock(at + 121_000);
    let before = counters(&issuer);
    let permits = fixture.permits.load(Ordering::SeqCst);
    let mut expected = incumbent;
    expected["lookup"] = json!(true);
    assert_eq!(carrier.lookup(REQUEST_ID).await, expected);
    let mut socket = carrier.ws().await;
    assert_eq!(
        ws_exchange(&mut socket, 2, lookup(REQUEST_ID)).await,
        expected
    );

    let denied = carrier.lookup_wire(&foreign.handle, REQUEST_ID).await;
    assert_eq!(denied.0, StatusCode::NOT_FOUND);
    assert_eq!(denied, carrier.lookup_wire(&foreign.handle, STALE_ID).await);
    let mut other_socket = carrier.ws_from(&foreign.handle).await;
    let denied = ws_exchange(&mut other_socket, 2, lookup(REQUEST_ID)).await;
    no_receipt(&denied, "not_found_or_denied");
    assert_eq!(
        denied,
        ws_exchange(&mut other_socket, 3, lookup(STALE_ID)).await
    );

    assert_eq!(
        carrier.lookup_wire(&machine.handle, REQUEST_ID).await.0,
        StatusCode::FORBIDDEN
    );
    issuer.authority.revoke(&id).unwrap();
    assert_eq!(
        carrier.lookup_wire(&carrier.bearer, REQUEST_ID).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_ws_invalidated(&mut socket).await;
    assert_eq!(counters(&issuer), before);
    assert_eq!(fixture.permits.load(Ordering::SeqCst), permits);
}

#[tokio::test]
async fn sc10_sc16_command_only_holder_recovers_without_an_owner_session() {
    for websocket in [false, true] {
        let oidc = Oidc::new_at(now_epoch_secs()).await;
        let store = tempfile::tempdir().unwrap();
        let (issuer, fixture, double) = command_double_transport_fixture(&oidc, &store).await;
        let (browser, native, _) = transport_owner_records(&issuer, &oidc.issuer());
        let owner = browser.record.principal;
        let target = target();
        let actor = delegated(&issuer, &owner, grant("command-only-holder", &[&target]));
        fixture.grant(&actor.record.principal, target.clone());
        issuer.authority.revoke(&browser.record.record_id).unwrap();
        issuer.authority.revoke(&native.record.record_id).unwrap();
        let actor_record = actor.record.record_id.clone();
        let carrier = Carrier::with_issued(issuer.clone(), actor).await;
        let at = now_epoch_secs() * 1000;
        fixture.freeze_clock(at);
        let mut socket = carrier.ws().await;
        let request = prepare(REQUEST_ID, at, &target);
        let prepared = if websocket {
            ws_exchange(&mut socket, 2, request.clone()).await
        } else {
            let response = carrier
                .post_request(&carrier.bearer, "prepare", &request)
                .header("Via", "spoofed-client-via")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            response.json().await.unwrap()
        };
        assert_eq!(prepared["type"], "prepared");
        let initial = if websocket {
            ws_exchange(&mut socket, 3, commit(&prepared)).await
        } else {
            let (status, receipt) = carrier.post("commit", commit(&prepared)).await;
            assert_eq!(status, StatusCode::OK);
            receipt
        };
        assert_eq!(initial["outcome"], "effect_unknown");
        check_handoff(&double).await;
        release_admitted(&double);
        let push = ws_next(&mut socket).await;
        assert_eq!(push["outcome"], "admitted");
        assert_eq!(push["receipt_id"], initial["receipt_id"]);
        assert!(push.get("re").is_none());
        for field in ["target", "node", "endpoint", "effect"] {
            assert!(push.get(field).is_none());
        }
        let before = counters(&issuer);
        let permits = fixture.permits.load(Ordering::SeqCst);
        let writes = fixture.writes.lock().unwrap().len();
        let mut expected = push;
        expected["lookup"] = json!(true);
        assert_eq!(carrier.lookup(REQUEST_ID).await, expected);
        assert_eq!(
            ws_exchange(&mut socket, 4, lookup(REQUEST_ID)).await,
            expected
        );
        if websocket {
            assert_eq!(
                ws_exchange(&mut socket, 5, commit(&prepared)).await,
                expected
            );
        } else {
            assert_eq!(carrier.post("commit", commit(&prepared)).await.1, expected);
        }

        let mut changed = target.clone();
        changed["incarnation"] = json!(4);
        change_binding(&fixture, &carrier.principal, changed);
        assert_eq!(carrier.post("prepare", request.clone()).await.1, expected);
        assert_eq!(ws_exchange(&mut socket, 6, request.clone()).await, expected);
        assert_eq!(carrier.lookup(REQUEST_ID).await, expected);
        assert_eq!(counters(&issuer), before);
        assert_eq!(fixture.permits.load(Ordering::SeqCst), permits);
        assert_eq!(fixture.writes.lock().unwrap().len(), writes);
        assert_eq!(double.requests.lock().unwrap().len(), 1);

        let audit = issuer.authority.audit_records().unwrap();
        for action in ["command_prepare", "command_commit", "command_lookup"] {
            assert!(audit.iter().any(|row| {
                row.action == action
                    && row.actor.as_deref() == Some("command-only-holder")
                    && row.on_behalf_of.as_deref() == Some(owner.as_str())
                    && row.via.is_none()
            }));
        }
        issuer.authority.revoke(&actor_record).unwrap();
        assert_ws_invalidated(&mut socket).await;
        for (stage, body) in [("prepare", request), ("commit", commit(&prepared))] {
            let (status, error) = carrier.post(stage, body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            no_receipt(&error, "unauthenticated");
        }
        assert_eq!(
            carrier.lookup_wire(&carrier.bearer, REQUEST_ID).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn sc11_delegated_command_bounds_refuse_without_submission() {
    let oidc = Oidc::new_at(now_epoch_secs()).await;
    let store = tempfile::tempdir().unwrap();
    let (issuer, fixture, double) = command_double_transport_fixture(&oidc, &store).await;
    let (browser, _, production_delegate) = transport_owner_records(&issuer, &oidc.issuer());
    let owner = browser.record.principal;
    let target = target();
    let mut other_target = target.clone();
    other_target["endpoint"] = json!("claude-2@fixture.node");
    other_target["selector"]["session_id"] = json!("exec-beta");
    let mut bounds = grant("limited", &[&target]);
    bounds.rate = 1;
    let actor = delegated(&issuer, &owner, bounds.clone());
    let record_id = actor.record.record_id.clone();
    fixture.grant(&actor.record.principal, target.clone());
    fixture.grant(&actor.record.principal, other_target.clone());
    let machine = issuer
        .authority
        .mint_machine(&owner, "read", vec![Scope::Fleet], None, 5)
        .unwrap();
    let mut node_only = bounds;
    node_only.targets[0].endpoint.clear();
    assert!(matches!(
        issuer.authority.mint_delegated(&owner, node_only),
        Err(AuthorityError::Invalid)
    ));

    let carrier = Carrier::with_issued(issuer.clone(), actor).await;
    let at = now_epoch_secs() * 1000;
    fixture.freeze_clock(at);
    let valid = prepare(REQUEST_ID, at, &target);
    let mut approval = valid.clone();
    approval["verb"] = json!("approve");
    let alternate = prepare(STALE_ID, at, &other_target);
    let mut socket = carrier.ws().await;

    issuer.authority.edit_fixture_record(&record_id, |record| {
        let Grants::Delegated { grant } = &mut record.grants else {
            panic!("fixture must be a delegated grant");
        };
        grant.verbs = vec!["stop".to_owned()];
    });
    let (status, error) = carrier.post("prepare", valid.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    no_receipt(&error, "not_found_or_denied");
    no_receipt(
        &ws_exchange(&mut socket, 2, valid.clone()).await,
        "not_found_or_denied",
    );
    issuer.authority.edit_fixture_record(&record_id, |record| {
        let Grants::Delegated { grant } = &mut record.grants else {
            panic!("fixture must be a delegated grant");
        };
        grant.verbs = vec!["send".to_owned()];
    });
    let (status, error) = carrier.post("prepare", alternate.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    no_receipt(&error, "not_found_or_denied");
    no_receipt(
        &ws_exchange(&mut socket, 3, alternate).await,
        "not_found_or_denied",
    );
    let (status, error) = carrier.post("prepare", approval.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    no_receipt(&error, "bad_message");
    no_receipt(&ws_exchange(&mut socket, 4, approval).await, "bad_message");
    no_receipt(
        &ws_exchange(
            &mut socket,
            5,
            json!({"v":1,"type":"subscribe","sub":"fleet","scope":{"kind":"fleet"}}),
        )
        .await,
        "not_found_or_denied",
    );

    for (handle, expected) in [
        (machine.handle.as_str(), StatusCode::FORBIDDEN),
        (
            production_delegate.handle.as_str(),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        for stage in ["prepare", "commit"] {
            let response = carrier
                .post_request(handle, stage, &valid)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            let body: Value = response.json().await.unwrap();
            no_receipt(
                &body,
                if expected == StatusCode::FORBIDDEN {
                    "forbidden"
                } else {
                    "unauthenticated"
                },
            );
        }
        assert_eq!(carrier.lookup_wire(handle, REQUEST_ID).await.0, expected);
    }

    issuer.authority.edit_fixture_record(&record_id, |record| {
        let Grants::Delegated { grant } = &mut record.grants else {
            panic!("fixture must be a delegated grant");
        };
        grant.expires_at = 0;
    });
    no_receipt(
        &carrier.post("prepare", valid.clone()).await.1,
        "not_found_or_denied",
    );
    issuer.authority.edit_fixture_record(&record_id, |record| {
        let Grants::Delegated { grant } = &mut record.grants else {
            panic!("fixture must be a delegated grant");
        };
        grant.expires_at = now_epoch_secs() + 600;
    });
    issuer.authority.fixture_entitlement(false);
    assert_eq!(
        carrier.post("prepare", valid.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    issuer.authority.fixture_entitlement(true);

    assert_eq!(counters(&issuer), (0, 0, 0));
    let (status, prepared) = carrier.post("prepare", valid.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(prepared["type"], "prepared");
    let (status, rate) = carrier
        .post("prepare", prepare(STALE_ID, at, &target))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    no_receipt(&rate, "rate_limited");
    no_receipt(
        &ws_exchange(&mut socket, 6, prepare(STALE_ID, at, &target)).await,
        "rate_limited",
    );

    issuer.authority.revoke(&record_id).unwrap();
    assert_ws_invalidated(&mut socket).await;
    assert_eq!(
        carrier.post("prepare", valid).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(counters(&issuer), (1, 0, 0));
    assert_eq!(fixture.permits.load(Ordering::SeqCst), 0);
    assert!(double.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sc16_narrowed_incumbent_denies_prepare_and_commit_without_consuming() {
    for websocket in [false, true] {
        let oidc = Oidc::new_at(now_epoch_secs()).await;
        let store = tempfile::tempdir().unwrap();
        let (issuer, fixture) = exact_command_transport_fixture(&oidc, &store).await;
        let (browser, _, _) = transport_owner_records(&issuer, &oidc.issuer());
        let first_target = target();
        let mut second_target = first_target.clone();
        second_target["endpoint"] = json!("claude-2@fixture.node");
        second_target["selector"]["session_id"] = json!("exec-beta");
        let actor = delegated(
            &issuer,
            &browser.record.principal,
            grant("narrowed-holder", &[&first_target, &second_target]),
        );
        let record_id = actor.record.record_id.clone();
        fixture.grant(&actor.record.principal, first_target.clone());
        fixture.grant(&actor.record.principal, second_target.clone());
        let carrier = Carrier::with_issued(issuer.clone(), actor).await;
        let at = now_epoch_secs() * 1000;
        fixture.freeze_clock(at);
        let socket = if websocket {
            Some(carrier.ws().await)
        } else {
            None
        };
        let mut transport = CommandTransport { carrier, socket };
        let original = prepare(REQUEST_ID, at, &first_target);
        let competing = prepare(REQUEST_ID, at, &second_target);
        let first = transport.prepare(2, original.clone()).await;
        let alternate = transport.prepare(3, competing.clone()).await;
        let equal = transport.prepare(4, original.clone()).await;
        assert_eq!(first["type"], "prepared");
        assert_eq!(alternate["type"], "prepared");
        assert_eq!(equal["type"], "prepared");
        assert_ne!(first["digest"], alternate["digest"]);
        assert_eq!(first["digest"], equal["digest"]);
        let incumbent = transport.commit(5, &first).await;
        assert_eq!(incumbent["code"], "unattested");

        let snapshot = || {
            let state = issuer.authority.locked().unwrap();
            state.conn
                .query_row(
                    "SELECT state || ':' || receipt_id || ':' || request_json FROM command_reservations",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
        };
        let before = snapshot();
        let writes = fixture.writes.lock().unwrap().len();
        assert_eq!(counters(&issuer), (3, 1, 1));
        issuer.authority.edit_fixture_record(&record_id, |record| {
            let Grants::Delegated { grant } = &mut record.grants else {
                panic!("fixture must be a delegated grant");
            };
            grant
                .targets
                .retain(|target| target.endpoint == "claude-2@fixture.node");
        });

        let narrowed = transport.prepare(6, competing).await;
        no_receipt(&narrowed, "not_found_or_denied");
        let audit = issuer.authority.audit_records().unwrap();
        let current_decision = audit
            .iter()
            .find(|row| {
                row.action == "command_prepare" && row.request_id.as_deref() == Some(REQUEST_ID)
            })
            .unwrap();
        assert_eq!(current_decision.outcome.as_deref(), Some("denied"));
        assert_eq!(
            current_decision.endpoint.as_deref(),
            Some("claude-2@fixture.node")
        );
        assert_eq!(transport.commit(7, &alternate).await, narrowed);
        assert_eq!(transport.commit(8, &equal).await, narrowed);
        assert_eq!(transport.prepare(9, original).await, narrowed);
        assert_eq!(transport.commit(10, &first).await, narrowed);
        match &mut transport.socket {
            Some(socket) => {
                assert_eq!(ws_exchange(socket, 11, lookup(REQUEST_ID)).await, narrowed);
            }
            None => {
                let denied = transport
                    .carrier
                    .lookup_wire(&transport.carrier.bearer, REQUEST_ID)
                    .await;
                assert_eq!(denied.0, StatusCode::NOT_FOUND);
                assert_eq!(serde_json::from_str::<Value>(&denied.1).unwrap(), narrowed);
            }
        }

        let mut other_socket = transport.carrier.ws().await;
        let wrong_carrier = if websocket {
            let (status, wrong_carrier) =
                transport.carrier.post("commit", commit(&alternate)).await;
            assert_eq!(status, StatusCode::OK);
            let wrong_connection = ws_exchange(&mut other_socket, 2, commit(&alternate)).await;
            assert_eq!(wrong_connection["code"], "intent_invalid");
            wrong_carrier
        } else {
            ws_exchange(&mut other_socket, 2, commit(&alternate)).await
        };
        assert_eq!(wrong_carrier["code"], "intent_invalid");
        assert_ne!(wrong_carrier["receipt_id"], incumbent["receipt_id"]);
        assert_eq!(counters(&issuer), (3, 1, 1));
        assert_eq!(snapshot(), before);
        assert_eq!(fixture.writes.lock().unwrap().len(), writes);
        assert_eq!(fixture.permits.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn sc16_new_grant_cannot_recover_or_redrive_prior_grant() {
    let oidc = Oidc::new_at(now_epoch_secs()).await;
    let store = tempfile::tempdir().unwrap();
    let (issuer, fixture, double) = command_double_transport_fixture(&oidc, &store).await;
    let (browser, _, _) = transport_owner_records(&issuer, &oidc.issuer());
    let owner = browser.record.principal;
    let target = target();
    let actor = delegated(&issuer, &owner, grant("same-holder", &[&target]));
    let original_record = actor.record.record_id.clone();
    fixture.grant(&actor.record.principal, target.clone());
    let carrier = Carrier::with_issued(issuer.clone(), actor).await;
    let at = now_epoch_secs() * 1000;
    fixture.freeze_clock(at);
    let mut socket = carrier.ws().await;
    let original = prepare(REQUEST_ID, at, &target);
    let (_, prepared) = carrier.post("prepare", original.clone()).await;
    let (_, initial) = carrier.post("commit", commit(&prepared)).await;
    assert_eq!(initial["outcome"], "effect_unknown");
    check_handoff(&double).await;
    fixture.freeze_clock(at + 100);
    *double.outcome.lock().unwrap() = Some(DoubleOutcome::Lost);
    double.release.notify_waiters();
    let unknown = ws_next(&mut socket).await;
    assert_eq!(unknown["outcome"], "effect_unknown");
    assert_eq!(unknown["receipt_id"], initial["receipt_id"]);
    assert_eq!(unknown["at"], at + 100);

    let replacement = delegated(&issuer, &owner, grant("same-holder", &[&target]));
    let different = delegated(&issuer, &owner, grant("another-holder", &[&target]));
    assert_ne!(replacement.record.principal, carrier.principal);
    for actor in [&replacement, &different] {
        change_binding(&fixture, &actor.record.principal, target.clone());
        let missing = carrier.lookup_wire(&actor.handle, REQUEST_ID).await;
        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(missing, carrier.lookup_wire(&actor.handle, STALE_ID).await);
        let mut other = carrier.ws_from(&actor.handle).await;
        let denied = ws_exchange(&mut other, 2, lookup(REQUEST_ID)).await;
        no_receipt(&denied, "not_found_or_denied");
    }

    let mut recovered = unknown;
    recovered["lookup"] = json!(true);
    assert_eq!(carrier.lookup(REQUEST_ID).await, recovered);
    assert_eq!(
        ws_exchange(&mut socket, 2, lookup(REQUEST_ID)).await,
        recovered
    );
    assert_eq!(counters(&issuer), (1, 1, 1));
    assert_eq!(double.requests.lock().unwrap().len(), 1);
    assert_eq!(fixture.permits.load(Ordering::SeqCst), 1);

    issuer
        .authority
        .edit_fixture_record(&original_record, |record| {
            record.absolute_expires_at = 0;
            record.idle_expires_at = 0;
        });
    for (stage, body) in [("prepare", original), ("commit", commit(&prepared))] {
        let (status, error) = carrier.post(stage, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        no_receipt(&error, "unauthenticated");
    }
    assert_eq!(
        carrier.lookup_wire(&carrier.bearer, REQUEST_ID).await.0,
        StatusCode::UNAUTHORIZED
    );
    let mut websocket = reqwest::Url::parse(&carrier.collector.url).unwrap();
    websocket.set_scheme("ws").unwrap();
    websocket.set_path("/v1/mission-control/session");
    let mut request = websocket.as_str().into_client_request().unwrap();
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(WS_PROTOCOL),
    );
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", carrier.bearer)).unwrap(),
    );
    let rejection = timeout(RESPONSE_TIMEOUT, connect_async(request))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        rejection,
        tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == 401
    ));
    assert_eq!(counters(&issuer), (1, 1, 1));
    assert_eq!(double.requests.lock().unwrap().len(), 1);
}

fn set_actor_target(issuer: &Issuer, record_id: &str, target: &Value, allowed: bool) {
    issuer.authority.edit_fixture_record(record_id, |record| {
        let Grants::Delegated { grant } = &mut record.grants else {
            panic!("fixture must be a delegated grant");
        };
        grant.targets = if allowed {
            vec![GrantTarget {
                node: target["node"].as_str().unwrap().to_owned(),
                endpoint: target["endpoint"].as_str().unwrap().to_owned(),
            }]
        } else {
            Vec::new()
        };
    });
}

#[tokio::test]
async fn sc16_http_and_ws_reply_handoff_recheck_stored_entitlement() {
    let oidc = Oidc::new_at(now_epoch_secs()).await;
    let store = tempfile::tempdir().unwrap();
    let (issuer, fixture) = exact_command_transport_fixture(&oidc, &store).await;
    let (browser, _, _) = transport_owner_records(&issuer, &oidc.issuer());
    let target = target();
    let actor = delegated(
        &issuer,
        &browser.record.principal,
        grant("handoff-holder", &[&target]),
    );
    let record_id = actor.record.record_id.clone();
    fixture.grant(&actor.record.principal, target.clone());
    let carrier = Carrier::with_issued(issuer.clone(), actor).await;
    let at = now_epoch_secs() * 1000;
    fixture.freeze_clock(at);
    let (_, prepared) = carrier
        .post("prepare", prepare(REQUEST_ID, at, &target))
        .await;
    assert_eq!(prepared["type"], "prepared");
    let (_, receipt) = carrier.post("commit", commit(&prepared)).await;
    assert_eq!(receipt["code"], "unattested");
    let mut expected = receipt;
    expected["lookup"] = json!(true);

    let mut current = target.clone();
    current["incarnation"] = json!(4);
    change_binding(&fixture, &carrier.principal, current);
    assert_eq!(carrier.lookup(REQUEST_ID).await, expected);

    let http_gate = fixture.arm_command_handoff();
    let request = carrier
        .http
        .get(format!(
            "{}/v1/receipts/{REQUEST_ID}",
            carrier.collector.url
        ))
        .bearer_auth(&carrier.bearer);
    let (result, ()) = tokio::join!(request.send(), async {
        timeout(RESPONSE_TIMEOUT, http_gate.entered.notified())
            .await
            .unwrap();
        set_actor_target(&issuer, &record_id, &target, false);
        http_gate.release.notify_one();
    });
    let error = result.expect_err("an HTTP receipt crossed the final entitlement fence");
    assert!(!error.is_timeout());
    assert_eq!(counters(&issuer), (1, 1, 1));

    set_actor_target(&issuer, &record_id, &target, true);
    let mut socket = carrier.ws().await;
    assert_eq!(
        ws_exchange(&mut socket, 2, lookup(REQUEST_ID)).await,
        expected
    );
    let reply_gate = fixture.arm_command_handoff();
    let (denied, ()) = tokio::join!(ws_exchange(&mut socket, 3, lookup(REQUEST_ID)), async {
        timeout(RESPONSE_TIMEOUT, reply_gate.entered.notified())
            .await
            .unwrap();
        set_actor_target(&issuer, &record_id, &target, false);
        reply_gate.release.notify_one();
    });
    no_receipt(&denied, "not_found_or_denied");

    set_actor_target(&issuer, &record_id, &target, true);
    assert_eq!(carrier.lookup(REQUEST_ID).await, expected);
    assert_eq!(counters(&issuer), (1, 1, 1));
    assert_eq!(fixture.permits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sc16_queued_final_push_is_fenced_without_changing_the_settled_row() {
    for close_socket in [false, true] {
        let oidc = Oidc::new_at(now_epoch_secs()).await;
        let store = tempfile::tempdir().unwrap();
        let (issuer, fixture, double) = command_double_transport_fixture(&oidc, &store).await;
        let (browser, _, _) = transport_owner_records(&issuer, &oidc.issuer());
        let target = target();
        let actor = delegated(
            &issuer,
            &browser.record.principal,
            grant("push-holder", &[&target]),
        );
        let record_id = actor.record.record_id.clone();
        fixture.grant(&actor.record.principal, target.clone());
        let carrier = Carrier::with_issued(issuer.clone(), actor).await;
        let at = now_epoch_secs() * 1000;
        fixture.freeze_clock(at);
        let mut socket = carrier.ws().await;
        let prepared = ws_exchange(&mut socket, 2, prepare(REQUEST_ID, at, &target)).await;
        assert_eq!(prepared["type"], "prepared");
        let pending = ws_exchange(&mut socket, 3, commit(&prepared)).await;
        assert_eq!(pending["outcome"], "effect_unknown");
        check_handoff(&double).await;

        fixture.freeze_clock(at + 100);
        let push_gate = fixture.arm_command_handoff();
        release_admitted(&double);
        timeout(RESPONSE_TIMEOUT, push_gate.entered.notified())
            .await
            .unwrap();
        if close_socket {
            socket.close(None).await.unwrap();
            drop(socket);
            push_gate.release.notify_one();
        } else {
            set_actor_target(&issuer, &record_id, &target, false);
            push_gate.release.notify_one();
            let denied = ws_exchange(&mut socket, 4, lookup(REQUEST_ID)).await;
            no_receipt(&denied, "not_found_or_denied");
            set_actor_target(&issuer, &record_id, &target, true);
        }

        let settled = carrier.lookup(REQUEST_ID).await;
        assert_eq!(settled["receipt_id"], pending["receipt_id"]);
        assert_eq!(settled["outcome"], "admitted");
        assert_eq!(settled["at"], at + 100);
        assert_eq!(counters(&issuer), (1, 1, 1));
        assert_eq!(fixture.permits.load(Ordering::SeqCst), 1);
        assert_eq!(double.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn sc5_private_client_recovers_a_real_collector_commit_after_response_loss() {
    use crate::mission_control_client::command_review::{CommandReview, CommitResult};
    let oidc = Oidc::new_at(now_epoch_secs()).await;
    let dir = tempfile::tempdir().unwrap();
    let (issuer, authority, double) = command_double_transport_fixture(&oidc, &dir).await;
    let carrier = Carrier::new(issuer.clone(), &oidc).await;
    authority.grant(&carrier.principal, target());
    let mut payload = prepare(REQUEST_ID, now_epoch_secs() * 1000, &target());
    payload["id"] = json!(2);
    let origin = reqwest::Url::parse(&carrier.collector.url).unwrap();
    let mut command = CommandReview::new(payload);
    let mut output = Vec::new();
    let (signal, gate) = tokio::sync::oneshot::channel();
    let review = command.review_session(&origin, &carrier.bearer, &mut output, 4096, || {
        assert!(signal.send(authority.arm_command_handoff()).is_ok());
        Some('\n')
    });
    let drop_receipt = async {
        let gate = gate.await.unwrap();
        gate.entered.notified().await;
        gate.drop_reply
            .store(true, std::sync::atomic::Ordering::SeqCst);
        gate.release.notify_one();
    };
    let (initial, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(review, drop_receipt)
    })
    .await
    .unwrap();
    assert_eq!(initial.unwrap(), CommitResult::EffectUnknown);
    let receipt = command
        .reconcile(&origin, &carrier.bearer)
        .await
        .expect("reconnected client sent a commit instead of lookup");
    let wire_actions: Vec<_> = issuer
        .authority
        .audit_records()
        .unwrap()
        .into_iter()
        .filter(|row| row.request_id.as_deref() == Some(REQUEST_ID))
        .map(|row| row.action)
        .collect();
    assert_eq!(
        wire_actions,
        ["command_lookup", "command_commit", "command_prepare"]
    );
    assert_eq!(receipt["request_id"], REQUEST_ID);
    assert_eq!(receipt["outcome"], "effect_unknown");
    assert_eq!(receipt["lookup"], true);
    check_handoff(&double).await;
    assert_eq!(double.submitted.available_permits(), 0);
    assert_eq!(
        authority.permits.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}
