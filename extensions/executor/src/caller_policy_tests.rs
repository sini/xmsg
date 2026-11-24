use super::*;
use xmsg::client::caller_attribution::AuthorityStamp;
fn stamp(source: &str) -> AuthorityStamp {
    AuthorityStamp {
        source: source.into(),
        matched_pid: 47,
        matched_start: "123".into(),
        registration_digest: "a".repeat(64),
        root_generation: (source == "codex").then_some(1),
        child_generation: None,
    }
}
fn context() -> TrustedCallerContext {
    TrustedCallerContext {
        principal: "caller@node".into(),
        peer_uid: 123,
        binding: crate::auth::CallBinding {
            peer: crate::auth::PeerWitness {
                uid: 123,
                pid: Some(47),
            },
            call_nonce: 1,
            input_digest: "a".repeat(64),
        },
        scope: checked_scope(&stamp("codex"), &"b".repeat(32), &"c".repeat(64)).unwrap(),
    }
}
fn runtime() -> CallerRuntimeFacts {
    CallerRuntimeFacts {
        host: "host".into(),
        uid: 123,
        operating_system: "os".into(),
        architecture: "arch".into(),
        kernel: "kernel".into(),
        executor_sha256: "d".repeat(64),
        caller_artifact_sha256: "e".repeat(64),
        caller_configuration_sha256: "0".repeat(64),
        caller_pin_id: "caller-pin".into(),
        caller_runtime_version: "caller-version".into(),
        caller_mode: "caller-mode".into(),
        caller_protocol: "caller-protocol".into(),
    }
}
fn record() -> CallerQualification {
    CallerQualification {
        incarnation: Arc::new(()),
        id: "record-a".into(),
        revision: 1,
        principal: context().principal,
        scope: context().scope,
        runtime: runtime(),
        policy_revision: 1,
        expires_at: 200,
        revoked: false,
    }
}
fn eligible() -> CallerEligibility {
    CallerEligibility::fixture(vec![record()])
}
fn reference(provider: &CallerEligibility) -> CallerRecordReference {
    provider.qualify(&context(), &runtime(), 1, 100).unwrap()
}
#[test]
fn scoped_shapes_use_exact_measured_source_generation_rules() {
    for source in ["claude", "agy", "codex"] {
        assert!(checked_scope(&stamp(source), &"b".repeat(32), &"c".repeat(64)).is_ok());
    }
    let mut child = stamp("codex");
    child.child_generation = Some(2);
    assert!(checked_scope(&child, &"b".repeat(32), &"c".repeat(64)).is_ok());
    for source in ["pi", "svc", "unknown", ""] {
        assert_eq!(
            checked_scope(&stamp(source), &"b".repeat(32), &"c".repeat(64)),
            Err(MissingTrustProperty::ScopedCallerEvidence)
        );
    }
    for (source, root, child) in [
        ("claude", Some(1), None),
        ("agy", None, Some(1)),
        ("codex", None, None),
        ("codex", None, Some(1)),
        ("codex", Some(0), None),
        ("codex", Some(1), Some(0)),
    ] {
        let mut value = stamp(source);
        value.root_generation = root;
        value.child_generation = child;
        assert_eq!(
            checked_scope(&value, &"b".repeat(32), &"c".repeat(64)),
            Err(MissingTrustProperty::ScopedCallerEvidence)
        );
    }
}
#[test]
fn missing_scope_fields_or_attestor_bindings_refuse_context() {
    let original = stamp("codex");
    for field in 0..4 {
        let mut value = original.clone();
        match field {
            0 => value.matched_pid = 0,
            1 => value.matched_start.clear(),
            2 => value.registration_digest = "a".repeat(63),
            _ => value.matched_start = "bad\nstart".into(),
        };
        assert_eq!(
            checked_scope(&value, &"b".repeat(32), &"c".repeat(64)),
            Err(MissingTrustProperty::ScopedCallerEvidence)
        );
    }
    assert!(checked_scope(&original, "", &"c".repeat(64)).is_err());
    assert!(checked_scope(&original, &"b".repeat(32), "version-is-not-evidence").is_err());
    let binding = crate::auth::CallBinding {
        peer: crate::auth::PeerWitness {
            uid: 123,
            pid: Some(47),
        },
        call_nonce: 1,
        input_digest: "a".repeat(64),
    };
    let p = crate::auth::principal(
        &crate::auth::fake::FakeAttestor {
            principal: "caller@node".into(),
            wrong_binding: false,
        },
        &binding,
        123,
    )
    .unwrap();
    assert!(matches!(
        TrustedCallerContext::from_attestation(&p),
        Err(MissingTrustProperty::ScopedCallerEvidence)
    ));
}
#[test]
fn production_provider_has_no_protected_store_proof_even_with_same_uid_matching_data() {
    let mut provider = CallerEligibility::reviewed();
    provider.records.push(record());
    assert!(matches!(
        provider.qualify(&context(), &runtime(), 1, 100),
        Err(MissingTrustProperty::ProtectedPolicyStore)
    ));
    let r = reference(&eligible());
    assert_eq!(
        provider.revalidate(&r, &context(), &runtime(), 1, 100),
        Err(MissingTrustProperty::ProtectedPolicyStore)
    );
}
#[test]
fn trusted_fixture_qualifies_one_exact_record_and_reference() {
    let provider = eligible();
    let r = reference(&provider);
    assert_eq!(r.id(), "record-a");
    assert_eq!(r.revision(), 1);
    assert_eq!(context().principal(), "caller@node");
    assert_eq!(
        provider.revalidate(&r, &context(), &runtime(), 1, 100),
        Ok(())
    );
}
#[test]
fn no_record_or_ambiguous_records_never_select_a_fallback() {
    assert!(CallerEligibility::fixture(vec![])
        .qualify(&context(), &runtime(), 1, 100)
        .is_err());
    let mut other = record();
    other.id = "record-b".into();
    assert!(CallerEligibility::fixture(vec![record(), other])
        .qualify(&context(), &runtime(), 1, 100)
        .is_err());
    let mut duplicate = record();
    duplicate.revoked = true;
    assert!(CallerEligibility::fixture(vec![record(), duplicate])
        .qualify(&context(), &runtime(), 1, 100)
        .is_err());
}
#[test]
fn revoked_expired_removed_and_revision_changed_records_refuse_old_reference() {
    for change in 0..5 {
        let mut p = eligible();
        let r = reference(&p);
        match change {
            0 => p.fixture_record_mut("record-a").revoked = true,
            1 => p.fixture_record_mut("record-a").expires_at = 100,
            2 => p.records.clear(),
            3 => p.fixture_record_mut("record-a").revision = 2,
            _ => p.fixture_record_mut("record-a").id = "record-b".into(),
        };
        assert_eq!(
            p.revalidate(&r, &context(), &runtime(), 1, 100),
            Err(MissingTrustProperty::ExactCallerQualification)
        );
    }
    let p = eligible();
    let r = reference(&p);
    assert!(p.revalidate(&r, &context(), &runtime(), 1, 200).is_err());
    assert!(p.revalidate(&r, &context(), &runtime(), 1, 0).is_err());
}
#[test]
fn identical_replacement_or_another_provider_is_not_the_referenced_record() {
    let mut p = eligible();
    let r = reference(&p);
    p.fixture_replace_record("record-a", record());
    assert!(p.revalidate(&r, &context(), &runtime(), 1, 100).is_err());
    let p = eligible();
    let r = reference(&p);
    assert!(eligible()
        .revalidate(&r, &context(), &runtime(), 1, 100)
        .is_err());
}
#[test]
fn principal_and_every_scope_component_are_exact_without_pid_queries() {
    let p = eligible();
    let r = reference(&p);
    for field in 0..10 {
        let mut c = context();
        match field {
            0 => c.principal = "parent@node".into(),
            1 => c.scope.kind = ScopeKind::Claude,
            2 => c.scope.matched_pid = 48,
            3 => c.scope.matched_start = "124".into(),
            4 => c.scope.registration_digest = "1".repeat(64),
            5 => {
                c.scope.kind = ScopeKind::Codex {
                    root_generation: 2,
                    child_generation: None,
                }
            }
            6 => {
                c.scope.kind = ScopeKind::Codex {
                    root_generation: 1,
                    child_generation: Some(2),
                }
            }
            7 => c.scope.attestor_epoch = "2".repeat(32),
            8 => c.scope.context_digest = "3".repeat(64),
            _ => c.peer_uid = 124,
        };
        assert!(
            p.revalidate(&r, &c, &runtime(), 1, 100).is_err(),
            "scope component drift reused caller reference"
        );
    }
}
#[test]
fn runtime_artifact_config_policy_and_envelope_changes_refuse_reference() {
    let p = eligible();
    let r = reference(&p);
    for field in 0..12 {
        let mut f = runtime();
        match field {
            0 => f.host = "other".into(),
            1 => f.uid = 124,
            2 => f.operating_system = "other".into(),
            3 => f.architecture = "other".into(),
            4 => f.kernel = "other".into(),
            5 => f.executor_sha256 = "1".repeat(64),
            6 => f.caller_artifact_sha256 = "2".repeat(64),
            7 => f.caller_configuration_sha256 = "4".repeat(64),
            8 => f.caller_pin_id = "other-pin".into(),
            9 => f.caller_runtime_version = "other-version".into(),
            10 => f.caller_mode = "other-mode".into(),
            _ => f.caller_protocol = "other-protocol".into(),
        };
        assert!(
            p.revalidate(&r, &context(), &f, 1, 100).is_err(),
            "runtime drift reused caller reference"
        );
    }
    assert!(p.revalidate(&r, &context(), &runtime(), 2, 100).is_err());
}
#[test]
fn changed_record_cannot_be_remapped_by_updating_current_facts_to_match_it() {
    let mut p = eligible();
    let r = reference(&p);
    let mut f = runtime();
    f.caller_configuration_sha256 = "5".repeat(64);
    p.fixture_record_mut("record-a").runtime = f.clone();
    assert!(p.revalidate(&r, &context(), &f, 1, 100).is_err());
    let mut p = eligible();
    let r = reference(&p);
    p.fixture_record_mut("record-a").policy_revision = 2;
    assert!(p.revalidate(&r, &context(), &runtime(), 2, 100).is_err());
}
#[test]
fn admitted_context_revalidation_does_not_require_live_parent_access() {
    let p = eligible();
    let mut c = context();
    c.scope.matched_pid = u32::MAX;
    c.scope.matched_start = "opaque historical start".into();
    let mut rec = record();
    rec.scope = c.scope.clone();
    let p2 = CallerEligibility::fixture(vec![rec]);
    let r = p2.qualify(&c, &runtime(), 1, 100).unwrap();
    assert_eq!(p2.revalidate(&r, &c, &runtime(), 1, 101), Ok(()));
    drop(p);
}

#[test]
fn integration_fixture_uses_normal_comparisons_and_test_only_revocation() {
    let (mut provider, context, reference) =
        CallerEligibility::fixture_integration("worker", runtime()).unwrap();
    assert_eq!(context.scope.kind, ScopeKind::Claude);
    assert_eq!(context.scope.matched_pid, 44);
    assert_eq!(context.scope.matched_start, "fixture-start");
    assert_eq!(reference.id(), "fixture-caller");
    assert_eq!(reference.revision(), 1);
    assert_eq!(
        provider.revalidate(&reference, &context, &runtime(), 1, 100),
        Ok(())
    );
    provider.fixture_revoke(&reference).unwrap();
    assert!(provider
        .revalidate(&reference, &context, &runtime(), 1, 100)
        .is_err());
    let (mut provider, context, reference) =
        CallerEligibility::fixture_integration("worker", runtime()).unwrap();
    provider.fixture_replace(&reference).unwrap();
    assert!(provider
        .revalidate(&reference, &context, &runtime(), 1, 100)
        .is_err());
    let mut bad = runtime();
    bad.caller_configuration_sha256 = "unproven".into();
    assert!(CallerEligibility::fixture_integration("worker", bad).is_err());
}

#[test]
fn reference_never_transfers_to_another_authenticated_call_binding() {
    let provider = eligible();
    let old = reference(&provider);
    for change in 0..3 {
        let mut next = context();
        match change {
            0 => next.binding.call_nonce = 2,
            1 => next.binding.input_digest = "1".repeat(64),
            _ => next.binding.peer.pid = Some(48),
        };
        assert_eq!(
            provider.revalidate(&old, &next, &runtime(), 1, 100),
            Err(MissingTrustProperty::ExactCallerQualification),
            "old qualification reference transferred to another call binding"
        );
        let fresh = provider.qualify(&next, &runtime(), 1, 100).unwrap();
        assert_eq!(
            provider.revalidate(&fresh, &next, &runtime(), 1, 100),
            Ok(())
        );
    }
}
#[test]
fn journal_receipt_is_only_immutable_diagnostic_data() {
    let provider = eligible();
    let reference = reference(&provider);
    let mut receipt = reference.journal_receipt();
    assert_eq!(receipt["record_id"], "record-a");
    assert_eq!(receipt["record_revision"], 1);
    assert_eq!(receipt["context"]["binding"]["call_nonce"], 1);
    assert_eq!(
        receipt["context"]["binding"]["input_digest"],
        "a".repeat(64)
    );
    receipt["record_id"] = serde_json::json!("replacement");
    receipt["context"]["binding"]["call_nonce"] = serde_json::json!(999);
    assert_eq!(reference.id(), "record-a");
    assert_eq!(
        provider.revalidate(&reference, &context(), &runtime(), 1, 100),
        Ok(())
    );
}
