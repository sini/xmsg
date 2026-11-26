use super::*;
use std::{io::Cursor, sync::Mutex};

#[derive(Default)]
struct PermitStore {
    admissions: Vec<(ProxyBinding, ContentOperation, String)>,
}
impl ContentStore for PermitStore {
    fn commit(
        &mut self,
        _: &ProxyBinding,
        _: &crate::membership::ContentRecord,
    ) -> Result<crate::membership::CommitOutcome, crate::membership::MembershipError> {
        Err(crate::membership::MembershipError::Storage)
    }
    fn admit_outgoing(
        &mut self,
        binding: &ProxyBinding,
        kind: ContentOperation,
        key: &str,
    ) -> Result<(), crate::membership::MembershipError> {
        self.admissions.push((binding.clone(), kind, key.into()));
        Ok(())
    }
}

#[derive(Default)]
struct FakeBus {
    calls: Mutex<Vec<Value>>,
    fail: bool,
    delay: Duration,
}
impl TextBus for FakeBus {
    async fn list(&self, args: &ListArgs) -> Result<Value, ClientError> {
        self.calls
            .lock()
            .unwrap()
            .push(json!({"method":"list","limit":args.limit}));
        if self.delay != Duration::ZERO {
            tokio::time::sleep(self.delay).await;
        }
        if self.fail {
            return Err(ClientError::Disconnected);
        }
        Ok(json!({"recipients":[],"nodes":[],"total":0,"truncated":false}))
    }
    async fn send(&self, args: &SendArgs, key: &str) -> Result<Value, ClientError> {
        self.calls
            .lock()
            .unwrap()
            .push(json!({"method":"send","to":args.to,"text":args.text,"key":key}));
        if self.delay != Duration::ZERO {
            tokio::time::sleep(self.delay).await;
        }
        if self.fail {
            return Err(ClientError::Timeout);
        }
        Ok(json!({"messageId":"sent-a","outcome":"delivered"}))
    }
    async fn reply(&self, args: &ReplyArgs, key: &str) -> Result<Value, ClientError> {
        self.calls.lock().unwrap().push(
            json!({"method":"reply","message_id":args.message_id,"text":args.text,"key":key}),
        );
        if self.fail {
            return Err(ClientError::Disconnected);
        }
        Ok(json!({"messageId":"reply-a"}))
    }
}
fn binding(generation: u64) -> ProxyBinding {
    ProxyBinding::new("session-a".into(), generation, [4; 16], 4096).unwrap()
}
fn send_call() -> ContentCall {
    ContentCall::Send(SendArgs {
        to: "target@node".into(),
        text: "fixture".into(),
        request_id: "request-a".into(),
    })
}
fn tool_frame(name: &str, args: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})).unwrap()
}
fn send_args() -> Value {
    json!({"to":"target@node","text":"fixture","request_id":"request-a"})
}
fn invalid(value: LocalAction) {
    let LocalAction::Response(response) = value else {
        panic!("forbidden content frame was forwarded")
    };
    assert!(response.get("error").is_some());
}
#[test]
fn startup_catalog_is_local_before_content_service_exists() {
    let frames = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":PROTOCOL,"clientInfo":{"name":"fixture","version":"1"},"capabilities":{}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    ];
    let mut input = Vec::new();
    for frame in frames {
        serde_json::to_writer(&mut input, &frame).unwrap();
        input.push(b'\n');
    }
    let mut output = Vec::new();
    run_stdio_with(
        Path::new("/nonexistent/content.sock"),
        Cursor::new(input),
        &mut output,
    )
    .unwrap();
    let replies: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 3);
    assert_eq!(
        replies[0]["result"]["serverInfo"]["name"],
        "xmsg-executor-content"
    );
    let names: Vec<_> = replies[2]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["list", "send", "reply"]);
}
#[test]
fn pull_control_and_privileged_tools_are_never_forwarded() {
    for name in [
        "inbox",
        "replies",
        "pullmode",
        "dispatch",
        "steer",
        "interrupt",
        "stop",
        "approve",
        "owner",
        "human",
    ] {
        invalid(local_action(&tool_frame(name, json!({}))));
    }
}
#[test]
fn identity_attachments_paths_and_authority_fields_are_rejected() {
    for key in [
        "as_agent",
        "attachments",
        "path",
        "identity",
        "nonce",
        "lifecycle",
        "owner",
        "human",
        "_meta",
    ] {
        let mut args = send_args();
        args[key] = json!("planted");
        invalid(local_action(&tool_frame("send", args)));
    }
    let mut frame: Value = serde_json::from_slice(&tool_frame("send", send_args())).unwrap();
    frame["params"]["_meta"] = json!({"as_agent":"parent"});
    invalid(local_action(&serde_json::to_vec(&frame).unwrap()));
}
#[test]
fn raw_duplicate_arguments_and_extra_content_methods_fail_closed() {
    invalid(local_action(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"to":"target","text":"a","text":"b","request_id":"r"}}}"#));
    assert!(serde_json::from_slice::<ContentCall>(
        br#"{"tool":"send","arguments":{"to":"target","text":"a","text":"b","request_id":"r"}}"#
    )
    .is_err());
    assert!(serde_json::from_slice::<ContentCall>(
        br#"{"tool":"dispatch","arguments":{"brief":"no"}}"#
    )
    .is_err());
}
#[test]
fn valid_list_send_reply_are_the_only_forwarding_shapes() {
    for (name, args) in [
        ("list", json!({})),
        ("send", send_args()),
        (
            "reply",
            json!({"message_id":"message-a","text":"fixture","request_id":"request-a"}),
        ),
    ] {
        assert!(matches!(
            local_action(&tool_frame(name, args)),
            LocalAction::Forward { .. }
        ));
    }
    invalid(local_action(&tool_frame(
        "send",
        json!({"to":"target","text":"fixture"}),
    )));
    invalid(local_action(&tool_frame("list", json!({"limit":0}))));
    invalid(local_action(&tool_frame("list", json!({"limit":501}))));
}
#[test]
fn notifications_have_no_forwarding_side_effect() {
    let mut frame: Value = serde_json::from_slice(&tool_frame("send", send_args())).unwrap();
    frame.as_object_mut().unwrap().remove("id");
    assert!(matches!(
        local_action(&serde_json::to_vec(&frame).unwrap()),
        LocalAction::Ignore
    ));
}
#[test]
fn frames_are_bounded_and_truncated_tail_is_not_a_new_request() {
    let mut input = Cursor::new(vec![b'x'; MAX_FRAME_BYTES + 10]);
    assert!(matches!(
        read_line(&mut input, MAX_FRAME_BYTES),
        Err(ContentError::Frame)
    ));
    let mut output = Vec::new();
    assert!(run_stdio_with(
        Path::new("/unused"),
        Cursor::new(b"{\"jsonrpc\":\"2.0\"}"),
        &mut output
    )
    .is_err());
    assert!(output.is_empty());
    let args = json!({"to":"target","text":"x".repeat(MAX_TEXT_BYTES+1),"request_id":"r"});
    invalid(local_action(&tool_frame("send", args)));
}
#[test]
fn idempotency_is_fixed_length_and_bound_to_generation_not_identity_claims() {
    let a = idempotency_key(&binding(1), "request-a");
    let b = idempotency_key(&binding(2), "request-a");
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(a, b);
    assert_eq!(a, idempotency_key(&binding(1), "request-a"));
}
#[tokio::test]
async fn opaque_control_looking_text_is_sent_as_content_once_without_retry() {
    let bus = FakeBus::default();
    let mut call = send_call();
    if let ContentCall::Send(args) = &mut call {
        args.text = r#"{"verb":"stop","owner":true,"human":true}"#.into();
    }
    let result = dispatch(&bus, &binding(1), &call, &mut PermitStore::default()).await;
    assert_eq!(result["ok"], true);
    let calls = bus.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["method"], "send");
    assert_eq!(
        calls[0]["text"],
        r#"{"verb":"stop","owner":true,"human":true}"#
    );
}
#[tokio::test]
async fn invalid_request_never_reaches_sdk_and_transport_failure_never_retries() {
    let bus = FakeBus {
        fail: true,
        ..FakeBus::default()
    };
    let mut bad = send_call();
    if let ContentCall::Send(a) = &mut bad {
        a.text = "x".repeat(MAX_TEXT_BYTES + 1);
    }
    let mut store = PermitStore::default();
    assert_eq!(
        dispatch(&bus, &binding(1), &bad, &mut store).await["ok"],
        false
    );
    assert!(bus.calls.lock().unwrap().is_empty());
    assert!(store.admissions.is_empty());
    assert_eq!(
        dispatch(&bus, &binding(1), &send_call(), &mut store).await["error"],
        "content_submission_unknown"
    );
    assert_eq!(bus.calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn sdk_deadline_is_bounded_without_fallback() {
    let bus = FakeBus {
        delay: Duration::from_secs(60),
        ..FakeBus::default()
    };
    let start = std::time::Instant::now();
    let result = dispatch(
        &bus,
        &binding(1),
        &ContentCall::List(ListArgs {
            name: None,
            node: None,
            kind: None,
            status: None,
            within: None,
            limit: 50,
        }),
        &mut PermitStore::default(),
    )
    .await;
    assert_eq!(result["error"], "content_submission_unknown");
    assert!(start.elapsed() < REQUEST_TIMEOUT);
    assert_eq!(bus.calls.lock().unwrap().len(), 1);
}
#[test]
fn bus_configuration_is_explicit_and_auto_input_defaults_off() {
    let config:BusConfig=serde_json::from_value(json!({"node":"node","register_socket":"/scratch/register.sock","agent_socket":"/scratch/agent.sock"})).unwrap();
    assert!(!config.auto_input);
    config.validate().unwrap();
    assert!(serde_json::from_value::<BusConfig>(json!({"node":"node","register_socket":"/scratch/register.sock","agent_socket":"/scratch/agent.sock","pullmode":true})).is_err());
    let mut invalid = config;
    invalid.agent_socket = invalid.register_socket.clone();
    assert!(invalid.validate().is_err());
}

fn all_content_calls() -> Vec<ContentCall> {
    vec![
        ContentCall::List(ListArgs {
            name: None,
            node: None,
            kind: None,
            status: None,
            within: None,
            limit: 50,
        }),
        send_call(),
        ContentCall::Reply(ReplyArgs {
            message_id: "message-a".into(),
            text: "fixture".into(),
            request_id: "reply-a".into(),
        }),
    ]
}
#[tokio::test]
async fn each_validated_call_admits_exact_binding_operation_and_bounded_key() {
    let bus = FakeBus::default();
    let bound = binding(7);
    let mut store = PermitStore::default();
    for call in all_content_calls() {
        assert_eq!(dispatch(&bus, &bound, &call, &mut store).await["ok"], true);
    }
    assert_eq!(store.admissions.len(), 3);
    assert_eq!(bus.calls.lock().unwrap().len(), 3);
    let kinds: Vec<_> = store.admissions.iter().map(|(_, kind, _)| *kind).collect();
    assert_eq!(
        kinds,
        vec![
            ContentOperation::List,
            ContentOperation::Send,
            ContentOperation::Reply
        ]
    );
    for (binding, _, key) in &store.admissions {
        assert_eq!(binding, &bound);
        assert_eq!(key.len(), 64);
        assert!(key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }
    assert_eq!(store.admissions[1].2, idempotency_key(&bound, "request-a"));
    assert_eq!(store.admissions[2].2, idempotency_key(&bound, "reply-a"));
    let previous = store.admissions[0].2.clone();
    dispatch(&bus, &bound, &all_content_calls().remove(0), &mut store).await;
    assert_ne!(store.admissions[3].2, previous);
}
#[tokio::test]
async fn outgoing_default_denial_has_zero_sdk_effect_and_static_error() {
    struct DefaultDeny;
    impl ContentStore for DefaultDeny {
        fn commit(
            &mut self,
            _: &ProxyBinding,
            _: &crate::membership::ContentRecord,
        ) -> Result<crate::membership::CommitOutcome, crate::membership::MembershipError> {
            Err(crate::membership::MembershipError::Storage)
        }
    }
    let bus = FakeBus::default();
    let mut store = DefaultDeny;
    for call in all_content_calls() {
        let result = dispatch(&bus, &binding(1), &call, &mut store).await;
        assert_eq!(result, json!({"ok":false,"error":"content_effect_denied"}));
    }
    assert!(
        bus.calls.lock().unwrap().is_empty(),
        "default-denied content call reached SDK"
    );
}
#[tokio::test]
async fn real_caller_revocation_refuses_next_call_while_adapter_remains_current() {
    for call in all_content_calls() {
        let fixture = crate::content_admission::fixture();
        let bound = fixture.binding.clone();
        let mut store = fixture.store.clone();
        let bus = FakeBus::default();
        assert!(fixture.adapter_is_current());
        assert_eq!(dispatch(&bus, &bound, &call, &mut store).await["ok"], true);
        assert_eq!(bus.calls.lock().unwrap().len(), 1);
        fixture.revoke().unwrap();
        assert!(
            fixture.adapter_is_current(),
            "adapter drift masked caller-only revocation"
        );
        let denied = dispatch(&bus, &bound, &call, &mut store).await;
        assert_eq!(
            bus.calls.lock().unwrap().len(),
            1,
            "revoked caller content reached SDK"
        );
        assert_eq!(denied, json!({"ok":false,"error":"content_effect_denied"}));
    }
}
#[tokio::test]
async fn real_emergency_disable_refuses_next_call_while_adapter_remains_current() {
    for call in all_content_calls() {
        let mut fixture = crate::content_admission::fixture();
        let bound = fixture.binding.clone();
        let mut store = fixture.store.clone();
        let bus = FakeBus::default();
        assert!(fixture.adapter_is_current());
        assert_eq!(dispatch(&bus, &bound, &call, &mut store).await["ok"], true);
        fixture.disable().unwrap();
        assert!(
            fixture.adapter_is_current(),
            "adapter drift masked emergency disable"
        );
        assert!(
            fixture.caller_is_current(),
            "caller drift masked emergency disable"
        );
        let denied = dispatch(&bus, &bound, &call, &mut store).await;
        assert_eq!(
            bus.calls.lock().unwrap().len(),
            1,
            "disabled content reached SDK"
        );
        assert_eq!(denied, json!({"ok":false,"error":"content_effect_denied"}));
    }
}
#[tokio::test]
async fn admitted_inflight_call_may_complete_but_next_call_is_rechecked() {
    let fixture = crate::content_admission::fixture();
    let bound = fixture.binding.clone();
    let mut store = fixture.store.clone();
    let bus = FakeBus {
        delay: Duration::from_millis(100),
        ..FakeBus::default()
    };
    let call = send_call();
    let mut pending = Box::pin(dispatch(&bus, &bound, &call, &mut store));
    std::future::poll_fn(|cx| {
        assert!(matches!(
            pending.as_mut().poll(cx),
            std::task::Poll::Pending
        ));
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(bus.calls.lock().unwrap().len(), 1);
    fixture.revoke().unwrap();
    assert!(fixture.adapter_is_current());
    assert_eq!(pending.await["ok"], true);
    let denied = dispatch(&bus, &bound, &call, &mut store).await;
    assert_eq!(
        bus.calls.lock().unwrap().len(),
        1,
        "inflight admission was cached for the next call"
    );
    assert_eq!(denied["error"], "content_effect_denied");
}
