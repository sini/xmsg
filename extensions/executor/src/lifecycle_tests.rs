use super::*;
use crate::{
    acp::Adapter,
    auth::{Grant, GrantTarget, PeerWitness, ProvisionedCredentials},
    capability::{
        ProfileContract, ProtectionReport, ProtectionState, QualificationKey, ReviewMode,
        TrustProfile,
    },
    control::{AdminCommand, ControlService, DispatchTemplate, OwnerConfig, OwnerProfile},
    eligibility::AdapterQualification,
    framing::{Frame, Notification, Success},
    protocol::{
        EnvironmentBackend, EnvironmentDescriptor, Harness, Model, ResourceBudget, SendArgs, Verb,
        WorkspaceSpec,
    },
    runtime_config::{
        PinnedExecutable, ProgramConfig, RuntimeConfig, ServicePaths, WorkspaceConfig,
    },
    runtime_policy::RuntimePolicy,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
const OWNER: &[u8] = b"synthetic-owner-only-proof-0000000000";
const HUMAN: &[u8] = b"synthetic-human-only-proof-0000000000";
const EPOCH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    _dir: tempfile::TempDir,
    service: ControlService,
    configuration: RuntimeConfig,
    record: AdapterQualification,
    executor: std::sync::Arc<crate::runtime_config::ExecutableArtifact>,
    driver: Driver,
}
fn peer() -> PeerWitness {
    PeerWitness {
        uid: xmsg::client::current_uid(),
        pid: Some(std::process::id()),
    }
}
fn complete(driver: &mut Driver, command: Command, result: serde_json::Value) {
    let Frame::Request(request) = driver.begin(command).unwrap() else {
        panic!("fixture expected request")
    };
    driver
        .observe(Frame::Success(Success {
            jsonrpc: "2.0".into(),
            id: request.id,
            result,
        }))
        .unwrap();
}
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = |name: &str| dir.path().join(name);
    let file = path("fake-only-not-executed");
    std::fs::write(&file, b"fake-only-no-harness").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
    let executable = PinnedExecutable {
        path: file,
        sha256: hex::encode(Sha256::digest(b"fake-only-no-harness")),
    };
    let native_file = path("fake-native-not-executed");
    std::fs::write(&native_file, b"fake-only-no-harness").unwrap();
    std::fs::set_permissions(&native_file, std::fs::Permissions::from_mode(0o700)).unwrap();
    let native_executable = PinnedExecutable {
        path: native_file,
        sha256: executable.sha256.clone(),
    };
    let pin = crate::capability::builtin_pins()
        .unwrap()
        .pins
        .remove(0)
        .pin;
    let unknown = ProtectionState::Unknown {
        reason: "fake-only".into(),
    };
    let model = Model {
        provider: "fixture".into(),
        name: "no-model".into(),
    };
    let resolved = ResolvedDispatch {
        harness: Harness::Claude,
        model: model.clone(),
        environment: EnvironmentDescriptor {
            id: "environment".into(),
            executor: "local".into(),
            host: "fixture-host".into(),
            backend: EnvironmentBackend::Headless,
            project: "project".into(),
            profile: "safe".into(),
        },
        profile: ProfileContract {
            mode: TrustProfile::Safe,
            owner_selection_required: false,
            protections: ProtectionReport {
                hard_denials: unknown.clone(),
                human_checkpoints: unknown,
            },
        },
        qualification: QualificationKey {
            pin_id: pin.id.clone(),
            adapter_version: pin.adapter_version.clone(),
            runtime_version: pin.runtime_version.clone(),
            protocol_version: 1,
            profile: TrustProfile::Safe,
            native_mode: "default".into(),
            review_mode: ReviewMode::HumanOnly,
            protocol_schema: "fixture-schema".into(),
            model,
            effective_config_digest: "a".repeat(64),
        },
        workspace: WorkspaceSpec {
            repo_identity: "repo".into(),
            base_revision: "b".repeat(40),
            destination_selector: "owned".into(),
            context_refs: vec![],
            patch_ref: None,
        },
        required_capabilities: vec![],
        budget: ResourceBudget {
            worker_slots: 2,
            reviewer_slots: 0,
            max_wall_ms: 60000,
            max_content_bytes: 65536,
        },
    };
    let control = OwnerConfig {
        revision: 1,
        local_host: "fixture-host".into(),
        grants: vec![Grant {
            principal: "worker".into(),
            verb: Verb::Dispatch,
            target: GrantTarget::Team {
                team_id: "team".into(),
            },
        }],
        profiles: vec![OwnerProfile {
            id: "safe".into(),
            revision: "1".into(),
            project: "project".into(),
            harness: Harness::Claude,
            environment: "environment".into(),
            mode: TrustProfile::Safe,
            enabled: true,
            owner_selected: false,
        }],
        defaults: vec![DispatchTemplate {
            team_id: "team".into(),
            profile_id: "safe".into(),
            resolved,
            lifecycle_verbs: vec![
                Verb::Send,
                Verb::Steer,
                Verb::Interrupt,
                Verb::Resume,
                Verb::Status,
            ],
        }],
    };
    let mut configuration = RuntimeConfig {
        version: 1,
        control,
        paths: ServicePaths {
            journal: path("journal"),
            lifecycle_socket: path("life"),
            owner_socket: path("owner"),
            human_socket: path("human"),
            attribution_socket: path("attribution"),
            runtime_root: path("runtime"),
            owner_credential_file: path("owner-proof"),
            human_credential_file: path("human-proof"),
        },
        programs: vec![ProgramConfig {
            pin_id: pin.id.clone(),
            adapter: executable.clone(),
            native: native_executable,
            arguments: vec![],
            native_mode: "default".into(),
        }],
        workspaces: vec![WorkspaceConfig {
            repo_id: "repo".into(),
            repository: path("repo"),
            approved_root: path("workspaces"),
            base_revision: "b".repeat(40),
            destination_selector: "owned".into(),
        }],
    };
    let digest = configuration
        .effective_digest(&configuration.control.defaults[0].resolved)
        .unwrap();
    configuration.control.defaults[0]
        .resolved
        .qualification
        .effective_config_digest = digest;
    let (host, kernel) = crate::runtime_policy::runtime_envelope().unwrap();
    let executor = std::sync::Arc::new(
        crate::runtime_config::ExecutableArtifact::observe(&std::env::current_exe().unwrap())
            .unwrap(),
    );
    let record = AdapterQualification {
        key: configuration.control.defaults[0]
            .resolved
            .qualification
            .clone(),
        adapter_sha256: executable.sha256.clone(),
        native_sha256: executable.sha256,
        executor_sha256: executor.sha256.clone(),
        capabilities: vec![Capability::StrictSteer, Capability::PendingApproval],
        host,
        uid: xmsg::client::current_uid(),
        operating_system: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        kernel,
        policy_revision: 1,
        expires_at: 200,
        revoked: false,
    };
    let service = ControlService::open(
        &configuration.paths.journal,
        xmsg::client::current_uid(),
        configuration.control.clone(),
        ProvisionedCredentials::from_bytes(OWNER, HUMAN).unwrap(),
    )
    .unwrap()
    .fixture_attributed("worker");
    service.journal.lock().unwrap().runtime_policy =
        Some(std::sync::Arc::new(RuntimePolicy::fixture(
            configuration.clone(),
            vec![record.clone()],
            executor.clone(),
        )));
    service
        .lifecycle(
            peer(),
            ControlRequest::dispatch("dispatch".into(), "initial brief".into()),
            100,
        )
        .unwrap();
    let mut driver = Driver::new(Adapter::for_pin(&pin).unwrap());
    complete(
        &mut driver,
        Command::Initialize {
            client_name: "fixture".into(),
        },
        serde_json::json!({"protocolVersion":1,"agentCapabilities":{},"_meta":{"steering":{"supported":true}}}),
    );
    complete(
        &mut driver,
        Command::NewSession {
            cwd: "/fixture".into(),
            mcp_servers: vec![],
        },
        serde_json::json!({"sessionId":"native","modes":{"currentModeId":"default"}}),
    );
    complete(
        &mut driver,
        Command::SetMode {
            native_session_id: "native".into(),
            mode_id: "default".into(),
        },
        serde_json::json!({}),
    );
    driver.observe(Frame::Notification(Notification {jsonrpc:"2.0".into(),method:"session/update".into(),params:Some(serde_json::json!({"sessionId":"native","update":{"sessionUpdate":"config_option_update","configOptions":[{"id":"mode","type":"select","currentValue":"default"}]}}))})).unwrap();
    {
        let mut journal = service.journal.lock().unwrap();
        let lease = journal.reserve_launch(1, 100).unwrap();
        journal.commit_spawn_intent(&lease, 100).unwrap();
        journal
            .bind_native(
                &NativeBinding {
                    identity: lease.identity.clone(),
                    native_session_id: "native".into(),
                    transport_epoch: EPOCH.into(),
                    native_mode: "default".into(),
                    expires_at: 180,
                },
                100,
            )
            .unwrap();
        journal
            .mark_running(&lease.identity, std::process::id(), 0, 100)
            .unwrap();
    }
    Fixture {
        _dir: dir,
        service,
        configuration,
        record,
        executor,
        driver,
    }
}
fn queue(f: &Fixture) -> i64 {
    let reply = f
        .service
        .lifecycle(
            peer(),
            ControlRequest {
                version: 1,
                request_id: "send".into(),
                target: Some(Target::Execution {
                    session_id: "session-1".into(),
                    generation: 1,
                }),
                action: Action::Send(SendArgs {
                    text: "queued content".into(),
                    prefer_live: None,
                }),
                deadline: Some(170),
            },
            101,
        )
        .unwrap();
    assert!(matches!(
        reply.receipt.authorization,
        crate::protocol::Authorization::Allowed { .. }
    ));
    f.service
        .journal
        .lock()
        .unwrap()
        .queue_native(2, &|| Ok(101))
        .unwrap();
    2
}
fn state(f: &Fixture, id: i64) -> String {
    f.service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row(
            "SELECT state FROM native_operations WHERE admission_id=?1",
            [id],
            |r| r.get(0),
        )
        .unwrap()
}

fn submit(f: &mut Fixture, id: i64, epoch: &str) -> (Result<bool, ErrorCode>, Vec<u8>) {
    use std::io::Read;
    let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let result = {
        let mut io = crate::supervisor::DeadlineIo::new(
            &mut writer,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap();
        f.service.journal.lock().unwrap().submit_native(
            id,
            &mut f.driver,
            epoch,
            &|| Ok(102),
            &mut io,
        )
    };
    drop(writer);
    let mut wire = vec![];
    reader.read_to_end(&mut wire).unwrap();
    (result, wire)
}

#[test]
fn qualified_fake_queue_submits_one_real_serialized_frame_once() {
    let mut f = fixture();
    let id = queue(&f);
    let (result, wire) = submit(&mut f, id, EPOCH);
    assert!(result.unwrap());
    let frame: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(frame["method"], "session/prompt");
    assert_eq!(frame["params"]["prompt"][0]["text"], "queued content");
    let (replay, repeated_wire) = submit(&mut f, id, EPOCH);
    assert!(
        repeated_wire.is_empty(),
        "native submission replay wrote another frame"
    );
    assert_eq!(state(&f, id), "submitted");
    assert!(replay.is_err());
}

#[test]
fn losing_eligibility_after_queue_writes_no_native_frame_or_new_launch() {
    let mut f = fixture();
    let id = queue(&f);
    f.service.journal.lock().unwrap().runtime_policy = Some(std::sync::Arc::new(
        RuntimePolicy::reviewed(f.configuration.clone()).unwrap(),
    ));
    let (result, wire) = submit(&mut f, id, EPOCH);
    assert!(
        wire.is_empty(),
        "lost eligibility submitted queued native content"
    );
    assert_eq!(state(&f, id), "queued");
    let launches: i64 = f
        .service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row("SELECT COUNT(*) FROM executions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        launches, 1,
        "eligibility loss created replacement execution"
    );
    assert!(result.is_err());
}

#[test]
fn emergency_disable_blocks_queued_native_output_even_with_current_qualification() {
    let mut f = fixture();
    let id = queue(&f);
    f.service
        .admin(
            peer(),
            OWNER,
            AdminCommand::DisableRuntime {
                request_id: "disable".into(),
                expected_revision: 1,
            },
            102,
        )
        .unwrap();
    f.record.policy_revision = 2;
    f.service.journal.lock().unwrap().runtime_policy =
        Some(std::sync::Arc::new(RuntimePolicy::fixture(
            f.configuration.clone(),
            vec![f.record.clone()],
            f.executor.clone(),
        )));
    let (result, wire) = submit(&mut f, id, EPOCH);
    assert!(
        wire.is_empty(),
        "emergency disable submitted queued native content"
    );
    assert_eq!(state(&f, id), "queued");
    assert!(result.is_err());
}

#[test]
fn wrong_transport_epoch_cannot_consume_or_submit_queued_content() {
    let mut f = fixture();
    let id = queue(&f);
    let (result, wire) = submit(&mut f, id, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(
        wire.is_empty(),
        "wrong transport epoch wrote native content"
    );
    assert_eq!(state(&f, id), "queued");
    assert!(result.is_err());
}

#[test]
fn adapter_and_native_artifact_drift_each_block_queued_effects() {
    for native in [false, true] {
        let mut f = fixture();
        let id = queue(&f);
        let program = &f.configuration.programs[0];
        let file = if native {
            &program.native.path
        } else {
            &program.adapter.path
        };
        std::fs::write(file, b"changed artifact").unwrap();
        let (result, wire) = submit(&mut f, id, EPOCH);
        assert!(
            wire.is_empty(),
            "changed adapter/native artifact emitted a native frame"
        );
        assert_eq!(state(&f, id), "queued");
        assert!(result.is_err());
    }
}

#[test]
fn executor_artifact_record_cannot_carry_to_another_build() {
    let mut f = fixture();
    let id = queue(&f);
    f.record.executor_sha256 = "0".repeat(64);
    f.service.journal.lock().unwrap().runtime_policy =
        Some(std::sync::Arc::new(RuntimePolicy::fixture(
            f.configuration.clone(),
            vec![f.record.clone()],
            f.executor.clone(),
        )));
    let (result, wire) = submit(&mut f, id, EPOCH);
    assert!(
        wire.is_empty(),
        "qualification from another executor build emitted a native frame"
    );
    assert_eq!(state(&f, id), "queued");
    assert!(result.is_err());
}

#[test]
fn wedged_native_writer_releases_journal_for_owner_disable_and_status() {
    use std::{
        io::{Read, Write},
        sync::mpsc,
        time::{Duration, Instant},
    };
    let mut f = fixture();
    let id = queue(&f);
    let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    let mut blocked = false;
    for _ in 0..1_000_000 {
        match writer.write(&[0]) {
            Ok(1) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                blocked = true;
                break;
            }
            result => panic!("fixture socket fill failed: {result:?}"),
        }
    }
    assert!(blocked, "fixture did not reach actual socket backpressure");
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let service = &f.service;
    let driver = &mut f.driver;
    std::thread::scope(|scope| {
        let effect = scope.spawn(move || {
            let mut io = crate::supervisor::DeadlineIo::new(
                &mut writer,
                Instant::now() + Duration::from_millis(100),
            )
            .unwrap();
            io.fixture_before_poll(move || {
                let _ = entered_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
            });
            let result = service.journal.lock().unwrap().submit_native(
                id,
                driver,
                EPOCH,
                &|| Ok(102),
                &mut io,
            );
            let _ = done_tx.send(result);
            result
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(
                service.journal.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ),
            "writer fixture did not hold journal at effect boundary"
        );
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let status_attempt = attempt_tx.clone();
        let owner = scope.spawn(move || {
            let _ = attempt_tx.send(());
            service.admin(
                peer(),
                OWNER,
                AdminCommand::DisableRuntime {
                    request_id: "disable-wedged".into(),
                    expected_revision: 1,
                },
                103,
            )
        });
        let status = scope.spawn(move || {
            let _ = status_attempt.send(());
            service.lifecycle(
                peer(),
                ControlRequest {
                    version: 1,
                    request_id: "status-wedged".into(),
                    target: Some(Target::Execution {
                        session_id: "session-1".into(),
                        generation: 1,
                    }),
                    action: Action::Status(crate::protocol::ReadArgs {
                        max_events: 1,
                        max_text_bytes: 1024,
                    }),
                    deadline: Some(170),
                },
                103,
            )
        });
        attempt_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        attempt_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        release_tx.send(()).unwrap();
        if done_rx.recv_timeout(Duration::from_millis(200)).is_err() {
            reader.set_nonblocking(true).unwrap();
            let mut bytes = [0; 4096];
            loop {
                match reader.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("fixture drain failed: {error}"),
                }
            }
            let _completion = done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("fixture cleanup did not release native writer");
        }
        let result = effect.join().unwrap();
        let disabled = owner.join().unwrap();
        let inspected = status.join().unwrap();
        assert_eq!(
            disabled,
            Ok(2),
            "wedged native writer retained journal after deadline"
        );
        assert!(matches!(
            inspected.unwrap().receipt.authorization,
            crate::protocol::Authorization::Allowed { .. }
        ));
        let observed: String = service
            .journal
            .lock()
            .unwrap()
            .db
            .query_row(
                "SELECT state FROM native_operations WHERE admission_id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            observed, "unknown",
            "expired native write became a successful submission"
        );
        assert!(result.is_err());
    });
}
