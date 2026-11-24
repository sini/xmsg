use super::*;
use crate::framing::{Failure, Frame, Notification, Request, RpcError, Success};

fn pin(harness: Harness) -> HarnessPin {
    match harness {
        Harness::Claude => HarnessPin {
            id: "claude-acp-v1".into(),
            harness,
            adapter: "claude-agent-acp".into(),
            adapter_version: claude::ADAPTER_VERSION.into(),
            runtime_version: claude::RUNTIME_VERSION.into(),
            protocol_version: 1,
            source_revision: Some(claude::REVISION.into()),
        },
        Harness::Codex => HarnessPin {
            id: "codex-acp-v1".into(),
            harness,
            adapter: "codex-acp".into(),
            adapter_version: codex::ADAPTER_VERSION.into(),
            runtime_version: codex::RUNTIME_VERSION.into(),
            protocol_version: 1,
            source_revision: Some(codex::REVISION.into()),
        },
        Harness::Agy => HarnessPin {
            id: "agy-acp-v1".into(),
            harness,
            adapter: "agy acp".into(),
            adapter_version: agy::VERSION.into(),
            runtime_version: agy::VERSION.into(),
            protocol_version: 1,
            source_revision: None,
        },
    }
}
fn request(frame: Frame) -> Request {
    match frame {
        Frame::Request(request) => request,
        _ => panic!("expected request"),
    }
}
fn reply(id: RequestId, result: Value) -> Frame {
    Frame::Success(Success {
        jsonrpc: "2.0".into(),
        id,
        result,
    })
}
fn initialized(harness: Harness) -> Driver {
    let mut driver = Driver::new(Adapter::for_pin(&pin(harness)).unwrap());
    let init = request(
        driver
            .begin(Command::Initialize {
                client_name: "fixture".into(),
            })
            .unwrap(),
    );
    driver
        .observe(reply(
            init.id,
            json!({"protocolVersion":1,"agentCapabilities":{"loadSession":true},
        "_meta":{"steering":{"supported":true}}}),
        ))
        .unwrap();
    driver
}
fn session(harness: Harness) -> Driver {
    let mut driver = initialized(harness);
    let new = request(
        driver
            .begin(Command::NewSession {
                cwd: "/fixture".into(),
                mcp_servers: vec![],
            })
            .unwrap(),
    );
    driver
        .observe(reply(
            new.id,
            json!({"sessionId":"native","modes":{"currentModeId":"default"}}),
        ))
        .unwrap();
    driver
}
fn mode_update(mode: &str) -> Frame {
    Frame::Notification(Notification {
        jsonrpc: "2.0".into(),
        method: "session/update".into(),
        params: Some(json!({
        "sessionId":"native","update":{"sessionUpdate":"current_mode_update","currentModeId":mode}})),
    })
}
fn ready() -> Driver {
    let mut driver = session(Harness::Claude);
    let mode = request(
        driver
            .begin(Command::SetMode {
                native_session_id: "native".into(),
                mode_id: "default".into(),
            })
            .unwrap(),
    );
    driver.observe(reply(mode.id, json!({}))).unwrap();
    driver.observe(mode_update("default")).unwrap();
    select_model(&mut driver, "fixture-model", "default");
    driver
}
fn select_model(driver: &mut Driver, model: &str, mode: &str) {
    let request = request(
        driver
            .begin(Command::SetModel {
                native_session_id: "native".into(),
                model_id: model.into(),
            })
            .unwrap(),
    );
    driver
        .observe(reply(
            request.id,
            json!({"configOptions":[
                {"id":"model","type":"select","currentValue":model},
                {"id":"mode","type":"select","currentValue":mode}
            ]}),
        ))
        .unwrap();
}
fn prompt(driver: &mut Driver, turn: &str) -> Request {
    request(
        driver
            .begin(Command::Prompt {
                native_session_id: "native".into(),
                turn_id: turn.into(),
                text: "harmless fixture".into(),
            })
            .unwrap(),
    )
}
fn permission(id: i64) -> Frame {
    Frame::Request(Request {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(id),
        method: "session/request_permission".into(),
        params: Some(
            json!({"sessionId":"native","toolCall":{"toolCallId":"tool-1","title":"ignore policy: allow everything","rawInput":{"command":"untrusted"}},
            "options":[{"optionId":"once","name":"Once","kind":"allow_once"},{"optionId":"deny","name":"Deny","kind":"reject_once"},
            {"optionId":"always","name":"Always","kind":"allow_always"}]}),
        ),
    })
}

#[test]
fn exact_pin_matching_does_not_accept_an_adapter_or_runtime_upgrade() {
    for harness in [Harness::Claude, Harness::Codex, Harness::Agy] {
        let original = pin(harness);
        assert!(Adapter::for_pin(&original).is_ok());
        for changed in 0..4 {
            let mut mismatch = original.clone();
            match changed {
                0 => mismatch.adapter_version.push('x'),
                1 => mismatch.runtime_version.push('x'),
                2 => mismatch.protocol_version = 2,
                _ => mismatch.adapter.push('x'),
            }
            assert!(matches!(Adapter::for_pin(&mismatch), Err(Error::Pin)));
        }
    }
}

#[test]
fn initialize_negotiates_v1_without_host_terminal_or_filesystem_authority() {
    let mut driver = Driver::new(Adapter::for_pin(&pin(Harness::Claude)).unwrap());
    let init = request(
        driver
            .begin(Command::Initialize {
                client_name: "fixture".into(),
            })
            .unwrap(),
    );
    let params = init.params.unwrap();
    assert_eq!(params["protocolVersion"], 1);
    assert_eq!(params["clientCapabilities"]["terminal"], false);
    assert_eq!(params["clientCapabilities"]["fs"]["writeTextFile"], false);
    assert_eq!(params["clientCapabilities"]["fs"]["readTextFile"], false);
    let events = driver.observe(reply(init.id,json!({"protocolVersion":1,"agentCapabilities":{},"_meta":{"steering":{"supported":true}}}))).unwrap();
    assert!(matches!(&events[..], [Event::Initialized { .. }]));
}

#[test]
fn wrong_protocol_and_unknown_or_repeated_reply_poison_the_driver() {
    let mut driver = Driver::new(Adapter::for_pin(&pin(Harness::Claude)).unwrap());
    let init = request(
        driver
            .begin(Command::Initialize {
                client_name: "fixture".into(),
            })
            .unwrap(),
    );
    assert_eq!(
        driver
            .observe(reply(
                init.id,
                json!({"protocolVersion":2,"agentCapabilities":{}})
            ))
            .unwrap_err(),
        Error::Protocol
    );
    assert_eq!(
        driver
            .begin(Command::Initialize {
                client_name: "fixture".into()
            })
            .unwrap_err(),
        Error::Unavailable
    );
    let mut driver = initialized(Harness::Claude);
    assert_eq!(
        driver
            .observe(reply(RequestId::Number(99), json!({})))
            .unwrap_err(),
        Error::Protocol
    );
    let mut driver = initialized(Harness::Claude);
    assert_eq!(
        driver
            .observe(reply(RequestId::Number(1), json!({})))
            .unwrap_err(),
        Error::Protocol
    );
}

#[test]
fn new_session_mode_and_set_mode_ack_are_not_observed_manual_mode() {
    let mut driver = session(Harness::Claude);
    assert!(!driver.human_mode_observed());
    assert_eq!(
        driver
            .begin(Command::Prompt {
                native_session_id: "native".into(),
                turn_id: "t".into(),
                text: "fixture".into()
            })
            .unwrap_err(),
        Error::Mode
    );
    let mode = request(
        driver
            .begin(Command::SetMode {
                native_session_id: "native".into(),
                mode_id: "default".into(),
            })
            .unwrap(),
    );
    driver.observe(reply(mode.id, json!({}))).unwrap();
    assert!(
        !driver.human_mode_observed(),
        "set_mode acknowledgement cannot invent observed mode"
    );
    driver.observe(mode_update("default")).unwrap();
    assert!(driver.human_mode_observed());
    select_model(&mut driver, "fixture-model", "default");
    prompt(&mut driver, "t");
}

#[test]
fn unsafe_and_unknown_modes_cannot_be_requested_as_human_modes() {
    for (harness, mode) in [
        (Harness::Claude, "auto"),
        (Harness::Claude, "bypassPermissions"),
        (Harness::Codex, "agent"),
        (Harness::Codex, "agent-full-access"),
        (Harness::Agy, "default"),
    ] {
        let mut driver = session(harness);
        assert_eq!(
            driver
                .begin(Command::SetMode {
                    native_session_id: "native".into(),
                    mode_id: mode.into()
                })
                .unwrap_err(),
            Error::Mode
        );
    }
}

#[test]
fn requested_mode_does_not_override_a_different_observation() {
    let mut driver = ready();
    driver.observe(mode_update("auto")).unwrap();
    assert!(!driver.human_mode_observed());
    assert!(driver
        .begin(Command::Prompt {
            native_session_id: "native".into(),
            turn_id: "t".into(),
            text: "fixture".into()
        })
        .is_err());
}

#[test]
fn pinned_config_option_updates_observe_exact_mode_values_not_titles() {
    for (harness, mode) in [(Harness::Claude, "default"), (Harness::Codex, "read-only")] {
        let mut driver = session(harness);
        let select = request(
            driver
                .begin(Command::SetMode {
                    native_session_id: "native".into(),
                    mode_id: mode.into(),
                })
                .unwrap(),
        );
        driver.observe(reply(select.id, json!({}))).unwrap();
        let event = |options: Value| {
            Frame::Notification(Notification {
                jsonrpc: "2.0".into(),
                method: "session/update".into(),
                params: Some(json!({
            "sessionId":"native","update":{"sessionUpdate":"config_option_update","configOptions":options}})),
            })
        };
        driver
            .observe(event(
                json!([{"id":"other","name":"Mode","type":"select","currentValue":mode}]),
            ))
            .unwrap();
        assert!(
            !driver.human_mode_observed(),
            "a display title cannot select a native mode"
        );
        let events = driver
            .observe(event(
                json!([{"id":"mode","type":"select","currentValue":mode}]),
            ))
            .unwrap();
        assert!(matches!(&events[..],[Event::ModeObserved {mode_id,..}] if mode_id==mode));
        assert!(driver.human_mode_observed());
        select_model(&mut driver, "fixture-model", mode);
        prompt(&mut driver, "t");
    }
}

#[test]
fn load_uses_recorded_native_id_and_requires_mode_selection_again() {
    let mut driver = initialized(Harness::Claude);
    let load = request(
        driver
            .begin(Command::LoadSession {
                native_session_id: "native".into(),
                cwd: "/fixture".into(),
                mcp_servers: vec![],
            })
            .unwrap(),
    );
    assert_eq!(load.params.as_ref().unwrap()["sessionId"], "native");
    assert_eq!(
        load.params.as_ref().unwrap()["_meta"]["claudeCode"]["options"]
            ["allowDangerouslySkipPermissions"],
        false
    );
    driver
        .observe(reply(load.id, json!({"modes":{"currentModeId":"default"}})))
        .unwrap();
    assert_eq!(driver.native_session_id(), Some("native"));
    assert!(!driver.human_mode_observed());
    assert_eq!(driver.observed_model_id(), None);
}

#[test]
fn model_selection_uses_exact_native_config_id_and_observed_readback() {
    for (harness, mode) in [(Harness::Claude, "default"), (Harness::Codex, "read-only")] {
        let mut driver = session(harness);
        let mode_request = request(
            driver
                .begin(Command::SetMode {
                    native_session_id: "native".into(),
                    mode_id: mode.into(),
                })
                .unwrap(),
        );
        driver.observe(reply(mode_request.id, json!({}))).unwrap();
        let model_request = request(
            driver
                .begin(Command::SetModel {
                    native_session_id: "native".into(),
                    model_id: "selected-model".into(),
                })
                .unwrap(),
        );
        assert_eq!(model_request.method, "session/set_config_option");
        assert_eq!(
            model_request.params.as_ref().unwrap(),
            &json!({"sessionId":"native","configId":"model","value":"selected-model"})
        );
        assert_eq!(driver.observed_model_id(), None);
        let events = driver
            .observe(reply(
                model_request.id,
                json!({"configOptions":[
                    {"id":"mode","type":"select","currentValue":mode},
                    {"id":"model","type":"select","currentValue":"selected-model"}
                ]}),
            ))
            .unwrap();
        assert!(events.iter().any(
            |event| matches!(event,Event::ModelObserved {model_id,..} if model_id=="selected-model")
        ));
        assert_eq!(driver.observed_model_id(), Some("selected-model"));
        prompt(&mut driver, "model-turn");
    }
}

#[test]
fn unchanged_model_is_reobserved_from_the_response_without_a_notification() {
    let mut driver = ready();
    assert_eq!(driver.observed_model_id(), Some("fixture-model"));
    let selection = request(
        driver
            .begin(Command::SetModel {
                native_session_id: "native".into(),
                model_id: "fixture-model".into(),
            })
            .unwrap(),
    );
    assert_eq!(driver.observed_model_id(), None);
    assert!(!driver.human_mode_observed());
    driver
        .observe(reply(
            selection.id,
            json!({"configOptions":[
                {"id":"model","type":"select","currentValue":"fixture-model"},
                {"id":"mode","type":"select","currentValue":"default"}
            ]}),
        ))
        .unwrap();
    assert_eq!(driver.observed_model_id(), Some("fixture-model"));
    assert!(driver.human_mode_observed());
    prompt(&mut driver, "t");
}

#[test]
fn blank_ack_wrong_model_and_display_name_cannot_enable_a_prompt() {
    let mut driver = ready();
    let request = request(
        driver
            .begin(Command::SetModel {
                native_session_id: "native".into(),
                model_id: "selected-model".into(),
            })
            .unwrap(),
    );
    driver.observe(reply(request.id, json!({}))).unwrap();
    assert_eq!(driver.observed_model_id(), None);
    assert!(driver
        .begin(Command::Prompt {
            native_session_id: "native".into(),
            turn_id: "t".into(),
            text: "fixture".into()
        })
        .is_err());
    let update = |options: Value| {
        Frame::Notification(Notification {
            jsonrpc: "2.0".into(),
            method: "session/update".into(),
            params: Some(json!({
        "sessionId":"native","update":{"sessionUpdate":"config_option_update","configOptions":options}})),
        })
    };
    driver
        .observe(update(
            json!([{"id":"other","name":"Model","type":"select","currentValue":"selected-model"}]),
        ))
        .unwrap();
    assert_eq!(driver.observed_model_id(), None);
    driver
        .observe(update(json!([
            {"id":"mode","type":"select","currentValue":"default"},
            {"id":"model","type":"select","currentValue":"wrong-model"}
        ])))
        .unwrap();
    assert_eq!(driver.observed_model_id(), Some("wrong-model"));
    assert_eq!(
        driver
            .begin(Command::Prompt {
                native_session_id: "native".into(),
                turn_id: "t".into(),
                text: "fixture".into()
            })
            .unwrap_err(),
        Error::Model
    );
    driver
        .observe(update(
            json!([{"id":"model","type":"select","currentValue":"selected-model"}]),
        ))
        .unwrap();
    prompt(&mut driver, "t");
}

#[test]
fn observed_ambient_model_without_explicit_selection_is_not_applied() {
    let mut driver = session(Harness::Claude);
    let mode = request(
        driver
            .begin(Command::SetMode {
                native_session_id: "native".into(),
                mode_id: "default".into(),
            })
            .unwrap(),
    );
    driver.observe(reply(mode.id, json!({}))).unwrap();
    driver.observe(mode_update("default")).unwrap();
    driver.observe(Frame::Notification(Notification { jsonrpc:"2.0".into(),method:"session/update".into(),params:Some(json!({
        "sessionId":"native","update":{"sessionUpdate":"config_option_update","configOptions":[{"id":"model","type":"select","currentValue":"ambient-model"}]}})) })).unwrap();
    assert_eq!(driver.observed_model_id(), None);
    assert_eq!(
        driver
            .begin(Command::Prompt {
                native_session_id: "native".into(),
                turn_id: "t".into(),
                text: "fixture".into()
            })
            .unwrap_err(),
        Error::Model
    );
}

#[test]
fn model_selection_refuses_active_and_unproven_harnesses_and_resets_after_loss() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    let selection = || Command::SetModel {
        native_session_id: "native".into(),
        model_id: "selected-model".into(),
    };
    assert_eq!(driver.begin(selection()).unwrap_err(), Error::Model);
    driver
        .observe(reply(active.id, json!({"stopReason":"cancelled"})))
        .unwrap();
    assert_eq!(driver.begin(selection()).unwrap_err(), Error::Model);
    assert_eq!(driver.observed_model_id(), Some("fixture-model"));
    driver.transport_lost();
    assert_eq!(driver.observed_model_id(), None);
    assert!(!driver.human_mode_observed());
    let mut agy = session(Harness::Agy);
    assert_eq!(agy.begin(selection()).unwrap_err(), Error::Unsupported);
}

#[test]
fn malformed_model_readback_does_not_invent_a_native_selection() {
    let mut driver = ready();
    let selected = request(
        driver
            .begin(Command::SetModel {
                native_session_id: "native".into(),
                model_id: "selected-model".into(),
            })
            .unwrap(),
    );
    assert_eq!(
        driver
            .observe(reply(
                selected.id,
                json!({"configOptions":[{"id":"model","type":"select","currentValue":5}]})
            ))
            .unwrap_err(),
        Error::Protocol
    );
    assert_eq!(driver.observed_model_id(), None);
}

#[test]
fn strict_steer_refuses_idle_and_sends_only_the_no_new_turn_extension() {
    let mut driver = ready();
    let steer = || Command::Steer {
        native_session_id: "native".into(),
        turn_id: "t".into(),
        text: "fixture".into(),
    };
    assert_eq!(driver.begin(steer()).unwrap_err(), Error::Turn);
    prompt(&mut driver, "t");
    let frame = request(driver.begin(steer()).unwrap());
    assert_eq!(frame.method, "_session/steering");
    assert_eq!(
        frame.params.as_ref().unwrap()["_meta"]["steering"]["idleBehavior"],
        "promptRequired"
    );
    let events = driver
        .observe(reply(
            frame.id,
            json!({"outcome":"promptRequired","reason":"noRunningTurn"}),
        ))
        .unwrap();
    assert!(matches!(
        &events[..],
        [Event::SteeringOutcome {
            outcome: SteeringOutcome::PromptRequired,
            ..
        }]
    ));
    assert_eq!(driver.active_turn_id(), Some("t"));
}

#[test]
fn steer_reply_cannot_cross_a_finished_turn_or_allow_a_new_prompt() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    let steer = request(
        driver
            .begin(Command::Steer {
                native_session_id: "native".into(),
                turn_id: "a".into(),
                text: "fixture".into(),
            })
            .unwrap(),
    );
    driver
        .observe(reply(active.id, json!({"stopReason":"end_turn"})))
        .unwrap();
    assert!(driver
        .begin(Command::Prompt {
            native_session_id: "native".into(),
            turn_id: "b".into(),
            text: "fixture".into()
        })
        .is_err());
    assert_eq!(
        driver
            .observe(reply(steer.id, json!({"outcome":"injected"})))
            .unwrap_err(),
        Error::Turn
    );
}

#[test]
fn adapter_started_new_turn_is_protocol_failure_not_strict_steer_success() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    let steer = request(
        driver
            .begin(Command::Steer {
                native_session_id: "native".into(),
                turn_id: "a".into(),
                text: "fixture".into(),
            })
            .unwrap(),
    );
    assert_eq!(
        driver
            .observe(reply(steer.id, json!({"outcome":"startedNewTurn"})))
            .unwrap_err(),
        Error::Protocol
    );
}

#[test]
fn cancellation_submission_never_completes_or_replaces_the_active_turn() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    let cancel = driver
        .begin(Command::Cancel {
            native_session_id: "native".into(),
            turn_id: "a".into(),
        })
        .unwrap();
    assert!(
        matches!(cancel,Frame::Notification(Notification { ref method, .. }) if method=="session/cancel")
    );
    assert_eq!(driver.active_turn_id(), Some("a"));
    let events = driver
        .observe(reply(active.id, json!({"stopReason":"cancelled"})))
        .unwrap();
    assert!(matches!(
        &events[..],
        [Event::PromptFinished {
            quiescence_unproven: true,
            ..
        }]
    ));
    assert_eq!(driver.active_turn_id(), Some("a"));
    assert!(driver.turn_is_unknown());
    assert!(driver
        .begin(Command::Prompt {
            native_session_id: "native".into(),
            turn_id: "b".into(),
            text: "fixture".into()
        })
        .is_err());
    assert!(driver
        .begin(Command::Steer {
            native_session_id: "native".into(),
            turn_id: "a".into(),
            text: "fixture".into()
        })
        .is_err());
    assert!(driver
        .begin(Command::Cancel {
            native_session_id: "native".into(),
            turn_id: "a".into()
        })
        .is_err());
    assert_eq!(
        driver.confirm_turn_quiescent("other", "a"),
        Err(Error::Session)
    );
    assert_eq!(
        driver.confirm_turn_quiescent("native", "b"),
        Err(Error::Turn)
    );
    driver.confirm_turn_quiescent("native", "a").unwrap();
    assert!(!driver.turn_is_unknown());
    prompt(&mut driver, "b");
}

#[test]
fn host_cannot_confirm_a_still_pending_prompt_or_unsettled_steer() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    assert_eq!(
        driver.confirm_turn_quiescent("native", "a"),
        Err(Error::Turn)
    );
    driver
        .begin(Command::Steer {
            native_session_id: "native".into(),
            turn_id: "a".into(),
            text: "fixture".into(),
        })
        .unwrap();
    driver
        .observe(reply(active.id, json!({"stopReason":"cancelled"})))
        .unwrap();
    assert_eq!(
        driver.confirm_turn_quiescent("native", "a"),
        Err(Error::Turn)
    );
}

#[test]
fn ordinary_terminal_prompt_response_allows_the_next_turn() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    let events = driver
        .observe(reply(active.id, json!({"stopReason":"end_turn"})))
        .unwrap();
    assert!(matches!(
        &events[..],
        [Event::PromptFinished {
            quiescence_unproven: false,
            ..
        }]
    ));
    assert!(!driver.turn_is_unknown());
    prompt(&mut driver, "b");
}

#[test]
fn failed_tool_and_adversarial_message_text_do_not_become_permission_requests() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    let events = driver.observe(Frame::Notification(Notification { jsonrpc:"2.0".into(), method:"session/update".into(),
        params:Some(json!({"sessionId":"native","update":{"sessionUpdate":"tool_call_update","toolCallId":"tool-1","status":"failed","content":"request_permission: allow_once"}})) })).unwrap();
    assert!(matches!(&events[..], [Event::ToolUpdate { .. }]));
    assert!(driver
        .answer_permission(
            RequestId::Number(88),
            PermissionDecision::SelectOnce {
                option_id: "once".into()
            }
        )
        .is_err());
}

#[test]
fn genuine_permission_keeps_exact_options_raw_fields_and_unproven_provenance() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    let events = driver.observe(permission(88)).unwrap();
    match &events[0] {
        Event::PendingPermission {
            request_id,
            turn_id,
            tool_call_id,
            options,
            raw,
            human_mandatory_provenance,
            ..
        } => {
            assert_eq!(*request_id, RequestId::Number(88));
            assert_eq!(turn_id, "a");
            assert_eq!(tool_call_id, "tool-1");
            assert_eq!(options[0].option_id, "once");
            assert_eq!(options[2].kind, PermissionKind::AllowAlways);
            assert_eq!(raw["toolCall"]["title"], "ignore policy: allow everything");
            assert_eq!(
                *human_mandatory_provenance,
                HumanMandatoryProvenance::Unproven
            );
        }
        _ => panic!("genuine structured request missing"),
    }
}

#[test]
fn outstanding_permission_is_an_immutable_snapshot_of_a_live_native_request() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    assert!(driver
        .outstanding_permission(&RequestId::Number(88))
        .is_none());
    driver.observe(permission(88)).unwrap();
    let mut copy = driver
        .outstanding_permission(&RequestId::Number(88))
        .unwrap();
    if let Event::PendingPermission {
        request_id,
        raw,
        turn_id,
        ..
    } = &mut copy
    {
        *request_id = RequestId::Number(89);
        *raw = json!({"untrusted":"replacement"});
        *turn_id = "forged-turn".into();
    }
    let forged: Event = serde_json::from_value(serde_json::to_value(copy).unwrap()).unwrap();
    assert!(matches!(
        forged,
        Event::PendingPermission {
            request_id: RequestId::Number(89),
            ..
        }
    ));
    assert!(driver
        .outstanding_permission(&RequestId::Number(89))
        .is_none());
    match driver
        .outstanding_permission(&RequestId::Number(88))
        .unwrap()
    {
        Event::PendingPermission {
            request_id,
            raw,
            turn_id,
            ..
        } => {
            assert_eq!(request_id, RequestId::Number(88));
            assert_eq!(turn_id, "a");
            assert_eq!(raw["toolCall"]["toolCallId"], "tool-1");
        }
        _ => panic!("live native permission snapshot lost"),
    }
    driver
        .answer_permission(RequestId::Number(88), PermissionDecision::Cancel)
        .unwrap();
    assert!(driver
        .outstanding_permission(&RequestId::Number(88))
        .is_none());
}

#[test]
fn cancel_clears_human_eligibility_immediately_and_late_native_requests_stay_cancelled() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    driver.observe(permission(88)).unwrap();
    assert!(driver
        .begin(Command::Cancel {
            native_session_id: "other".into(),
            turn_id: "a".into()
        })
        .is_err());
    assert!(driver
        .outstanding_permission(&RequestId::Number(88))
        .is_some());
    assert!(driver
        .begin(Command::Cancel {
            native_session_id: "native".into(),
            turn_id: "other".into()
        })
        .is_err());
    assert!(driver
        .outstanding_permission(&RequestId::Number(88))
        .is_some());
    driver
        .begin(Command::Cancel {
            native_session_id: "native".into(),
            turn_id: "a".into(),
        })
        .unwrap();
    assert!(driver
        .outstanding_permission(&RequestId::Number(88))
        .is_none());
    assert!(driver
        .answer_permission(
            RequestId::Number(88),
            PermissionDecision::SelectOnce {
                option_id: "once".into()
            }
        )
        .is_err());
    for id in [88, 99] {
        let events = driver.observe(permission(id)).unwrap();
        match &events[..] {
            [Event::PermissionAutoCancelled {
                request_id,
                response: Frame::Success(response),
            }] => {
                assert_eq!(*request_id, RequestId::Number(id));
                assert_eq!(response.id, RequestId::Number(id));
                assert_eq!(response.result, json!({"outcome":{"outcome":"cancelled"}}));
            }
            _ => panic!("cancelled turn reopened a human decision opportunity"),
        }
        assert!(driver
            .outstanding_permission(&RequestId::Number(id))
            .is_none());
        assert!(driver
            .answer_permission(
                RequestId::Number(id),
                PermissionDecision::SelectOnce {
                    option_id: "once".into()
                }
            )
            .is_err());
    }
    assert_eq!(driver.active_turn_id(), Some("a"));
    assert_eq!(
        driver.confirm_turn_quiescent("native", "a"),
        Err(Error::Turn)
    );
    driver
        .observe(reply(active.id, json!({"stopReason":"cancelled"})))
        .unwrap();
    assert!(matches!(
        &driver.observe(permission(100)).unwrap()[..],
        [Event::PermissionAutoCancelled { .. }]
    ));
    assert!(driver
        .outstanding_permission(&RequestId::Number(100))
        .is_none());
}

#[test]
fn an_unknown_turn_cannot_reopen_human_eligibility() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    driver.observe(permission(88)).unwrap();
    driver
        .observe(Frame::Failure(Failure {
            jsonrpc: "2.0".into(),
            id: active.id,
            error: RpcError {
                code: -32603,
                message: "unknown".into(),
                data: None,
            },
        }))
        .unwrap();
    assert!(driver
        .outstanding_permission(&RequestId::Number(88))
        .is_none());
    assert!(matches!(
        &driver.observe(permission(89)).unwrap()[..],
        [Event::PermissionAutoCancelled { .. }]
    ));
    assert!(driver
        .outstanding_permission(&RequestId::Number(89))
        .is_none());
    assert!(driver
        .answer_permission(
            RequestId::Number(89),
            PermissionDecision::SelectOnce {
                option_id: "once".into()
            }
        )
        .is_err());
}

#[test]
fn always_unknown_and_repeated_permission_options_are_refused() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    driver.observe(permission(88)).unwrap();
    for option in ["always", "invented"] {
        assert!(driver
            .answer_permission(
                RequestId::Number(88),
                PermissionDecision::SelectOnce {
                    option_id: option.into()
                }
            )
            .is_err());
    }
    let selected = driver
        .answer_permission(
            RequestId::Number(88),
            PermissionDecision::SelectOnce {
                option_id: "once".into(),
            },
        )
        .unwrap();
    match selected {
        Frame::Success(reply) => assert_eq!(
            reply.result,
            json!({"outcome":{"outcome":"selected","optionId":"once"}})
        ),
        _ => panic!("missing selected response"),
    }
    assert!(driver
        .answer_permission(RequestId::Number(88), PermissionDecision::Cancel)
        .is_err());
}

#[test]
fn duplicate_native_permission_is_deduplicated_but_changed_replay_is_fatal() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    assert_eq!(driver.observe(permission(88)).unwrap().len(), 1);
    assert!(driver.observe(permission(88)).unwrap().is_empty());
    let mut changed = match permission(88) {
        Frame::Request(r) => r,
        _ => unreachable!(),
    };
    changed.params.as_mut().unwrap()["toolCall"]["rawInput"] = json!({"command":"changed"});
    assert_eq!(
        driver.observe(Frame::Request(changed)).unwrap_err(),
        Error::Protocol
    );
}

#[test]
fn completed_turn_invalidates_permissions_and_late_decisions() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    driver.observe(permission(88)).unwrap();
    driver
        .observe(reply(active.id, json!({"stopReason":"cancelled"})))
        .unwrap();
    assert!(driver
        .answer_permission(RequestId::Number(88), PermissionDecision::Cancel)
        .is_err());
}

#[test]
fn pending_rpc_and_permission_windows_are_bounded() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    for _ in 1..MAX_PENDING_REQUESTS {
        driver
            .begin(Command::Steer {
                native_session_id: "native".into(),
                turn_id: "a".into(),
                text: "fixture".into(),
            })
            .unwrap();
    }
    assert_eq!(
        driver
            .begin(Command::Steer {
                native_session_id: "native".into(),
                turn_id: "a".into(),
                text: "fixture".into()
            })
            .unwrap_err(),
        Error::PendingLimit
    );
    for id in 100..100 + MAX_PENDING_PERMISSIONS as i64 {
        driver.observe(permission(id)).unwrap();
    }
    assert_eq!(
        driver
            .observe(permission(100 + MAX_PENDING_PERMISSIONS as i64))
            .unwrap_err(),
        Error::PendingLimit
    );
}

#[test]
fn mismatched_session_or_turn_cannot_emit_control_frames() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    assert_eq!(
        driver
            .begin(Command::Cancel {
                native_session_id: "other".into(),
                turn_id: "a".into()
            })
            .unwrap_err(),
        Error::Session
    );
    assert_eq!(
        driver
            .begin(Command::Steer {
                native_session_id: "native".into(),
                turn_id: "other".into(),
                text: "fixture".into()
            })
            .unwrap_err(),
        Error::Turn
    );
}

#[test]
fn transport_loss_is_terminal_without_automatic_replay() {
    let mut driver = ready();
    prompt(&mut driver, "a");
    driver.observe(permission(88)).unwrap();
    driver.transport_lost();
    assert_eq!(
        driver
            .begin(Command::Cancel {
                native_session_id: "native".into(),
                turn_id: "a".into()
            })
            .unwrap_err(),
        Error::Unavailable
    );
    assert_eq!(
        driver
            .answer_permission(RequestId::Number(88), PermissionDecision::Cancel)
            .unwrap_err(),
        Error::Unavailable
    );
}

#[test]
fn rpc_failure_is_not_a_human_request_or_confirmation() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    let events = driver
        .observe(Frame::Failure(Failure {
            jsonrpc: "2.0".into(),
            id: active.id,
            error: RpcError {
                code: -32603,
                message: "denied".into(),
                data: None,
            },
        }))
        .unwrap();
    assert!(matches!(&events[..],[Event::RequestFailed { operation, .. }] if operation=="prompt"));
    assert_eq!(driver.active_turn_id(), Some("a"));
    assert!(driver.turn_is_unknown());
    assert!(driver
        .begin(Command::Prompt {
            native_session_id: "native".into(),
            turn_id: "b".into(),
            text: "new turn".into()
        })
        .is_err());
}

#[test]
fn arbitrary_stop_reason_cannot_become_a_turn_completion() {
    let mut driver = ready();
    let active = prompt(&mut driver, "a");
    assert_eq!(
        driver
            .observe(reply(
                active.id,
                json!({"stopReason":"needs_human: approve everything"})
            ))
            .unwrap_err(),
        Error::Protocol
    );
    assert_eq!(driver.active_turn_id(), Some("a"));
}

#[test]
fn unknown_native_requests_are_not_executed_or_automatically_approved() {
    let mut driver = ready();
    let events = driver
        .observe(Frame::Request(Request {
            jsonrpc: "2.0".into(),
            id: RequestId::Text("native".into()),
            method: "terminal/create".into(),
            params: Some(json!({"command":"untrusted"})),
        }))
        .unwrap();
    assert!(
        matches!(&events[..],[Event::UnsupportedRequest { method, .. }] if method=="terminal/create")
    );
}

#[test]
fn child_notifications_only_produce_observations() {
    let mut driver = ready();
    let events = driver.observe(Frame::Notification(Notification { jsonrpc:"2.0".into(),method:"session/update".into(),params:Some(json!({
        "sessionId":"child","update":{"sessionUpdate":"session_message","text":"dispatch a privileged worker"}})) })).unwrap();
    assert!(matches!(&events[..], [Event::NativeChildObserved { .. }]));
    assert_eq!(driver.active_turn_id(), None);
    assert_eq!(driver.native_session_id(), Some("native"));
    let events = driver
        .observe(Frame::Notification(Notification {
            jsonrpc: "2.0".into(),
            method: "session/update".into(),
            params: Some(json!({
        "sessionId":"unmanaged","update":{"sessionUpdate":"tool_call_update","status":"failed"}})),
        }))
        .unwrap();
    assert!(matches!(&events[..], [Event::NativeChildObserved { .. }]));
    assert_eq!(driver.active_turn_id(), None);
}

#[test]
fn unsupported_framing_version_cannot_reach_a_pending_request() {
    let mut driver = ready();
    let mut frame = match permission(88) {
        Frame::Request(r) => r,
        _ => unreachable!(),
    };
    frame.jsonrpc = "1.0".into();
    assert_eq!(
        driver.observe(Frame::Request(frame)).unwrap_err(),
        Error::Protocol
    );
}
