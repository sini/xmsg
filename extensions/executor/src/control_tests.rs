use super::*;
use crate::auth::{fake::FakeAttestor, Grant, GrantTarget};
use crate::protocol::{Action, Authorization, Harness, SendArgs, Verb};
use std::os::unix::fs::PermissionsExt;

const OWNER: &[u8] = b"synthetic-owner-only-proof-0000000000";
const HUMAN: &[u8] = b"synthetic-human-only-proof-0000000000";
struct Fixture {
    _dir: tempfile::TempDir,
    service: ControlService,
}
fn grant(verb: Verb, session: &str, generation: u64) -> Grant {
    Grant {
        principal: "worker".into(),
        verb,
        target: GrantTarget::Session {
            session_id: session.into(),
            generation,
        },
    }
}
fn config(grants: Vec<Grant>) -> OwnerConfig {
    OwnerConfig {
        revision: 1,
        local_host: "host-a".into(),
        grants,
        profiles: vec![OwnerProfile {
            id: "safe".into(),
            revision: "1".into(),
            project: "project".into(),
            harness: Harness::Claude,
            environment: "environment-a".into(),
            mode: TrustProfile::Safe,
            enabled: true,
            owner_selected: false,
        }],
        defaults: vec![],
    }
}
fn fixture(configuration: OwnerConfig) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut service = ControlService::open(
        &dir.path().join("journal.db"),
        uid(),
        configuration,
        ProvisionedCredentials::from_bytes(OWNER, HUMAN).unwrap(),
    )
    .unwrap();
    service.attestor = Box::new(FakeAttestor {
        principal: "worker".into(),
        wrong_binding: false,
    });
    service
        .journal
        .lock()
        .unwrap()
        .db
        .execute(
            "INSERT INTO sessions VALUES('session-a','team-a',1,'turn-a','running','safe')",
            [],
        )
        .unwrap();
    Fixture { _dir: dir, service }
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn peer() -> PeerWitness {
    PeerWitness {
        uid: uid(),
        pid: Some(123),
    }
}

struct EchoPeer(std::process::Child);
impl Drop for EchoPeer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct AtomicBridgeClock(std::sync::Arc<std::sync::atomic::AtomicI64>);
impl WallClock for AtomicBridgeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn run_scripted_bridge(
    mutate: impl FnOnce(&mut xmsg::client::caller_attribution::Reply) + Send,
) -> (serde_json::Value, i64) {
    run_scripted_bridge_clock(mutate, None, false)
}
fn run_scripted_bridge_clock(
    mutate: impl FnOnce(&mut xmsg::client::caller_attribution::Reply) + Send,
    clock: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
    post_query_wait: bool,
) -> (serde_json::Value, i64) {
    use std::{
        io::{Read, Write},
        os::fd::AsFd,
        os::unix::net::{UnixListener, UnixStream},
        time::Instant,
    };
    use xmsg::client::caller_attribution::{self as wire, AuthorityStamp, Reply};
    let base = std::path::Path::new("/tmp").canonicalize().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("xa-")
        .tempdir_in(base)
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let life_path = directory.path().join("life.sock");
    let query_path = directory.path().join("query.sock");
    let life = UnixListener::bind(&life_path).unwrap();
    let query = UnixListener::bind(&query_path).unwrap();
    query.set_nonblocking(true).unwrap();
    for socket in [&life_path, &query_path] {
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    f.service.bridge = Some(DaemonAttributionConfig {
        query_socket: query_path,
        lifecycle_socket: life_path.clone(),
        expected_uid: uid(),
    });
    let clock =
        clock.unwrap_or_else(|| std::sync::Arc::new(std::sync::atomic::AtomicI64::new(100)));
    f.service.clock = Box::new(AtomicBridgeClock(clock.clone()));
    let (at_tx, at_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    if post_query_wait {
        *f.service.after_attestation.lock().unwrap() = Some(Box::new(move || {
            at_tx.send(()).unwrap();
            resume_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
        }));
    }
    let held_journal = post_query_wait.then(|| f.service.journal.lock().unwrap());
    let response = std::thread::scope(|scope| {
        let script = scope.spawn(move || {
            let deadline = Instant::now() + std::time::Duration::from_secs(2);
            let stream = loop {
                match query.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err("executor did not reach the scripted query socket");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => return Err("scripted query accept failed"),
                }
            };
            let (request, original) = wire::receive_query(&stream, deadline).unwrap();
            let (peer_uid, peer_pid) = wire::socket_peer(original.as_fd()).unwrap();
            let mut reply = Reply::Ok {
                v: wire::VERSION,
                runtime_epoch: request.runtime_epoch,
                call_nonce: request.call_nonce,
                input_digest: request.input_digest,
                context_digest: request.context_digest,
                peer_uid,
                peer_pid: peer_pid.unwrap(),
                principal: "worker".into(),
                authority_stamp: Box::new(AuthorityStamp {
                    source: "scripted-test".into(),
                    matched_pid: peer_pid.unwrap(),
                    matched_start: "fixture".into(),
                    registration_digest: "d".repeat(64),
                    root_generation: None,
                    child_generation: None,
                }),
            };
            mutate(&mut reply);
            wire::send_reply(&stream, &reply, deadline).unwrap();
            Ok(())
        });
        let mut client = UnixStream::connect(life_path).unwrap();
        let (server, _) = life.accept().unwrap();
        let handler = scope.spawn(|| f.service.handle_lifecycle_connection(server).unwrap());
        let body = serde_json::to_vec(&LifecycleCall {
            request: send("real-socket"),
            caller_context: None,
        })
        .unwrap();
        client.write_all(&body).unwrap();
        client.write_all(b"\n").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let reached_barrier = !post_query_wait
            || at_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .is_ok();
        if post_query_wait {
            clock.store(201, Ordering::SeqCst);
            drop(held_journal);
            if reached_barrier {
                resume_tx.send(()).unwrap();
            }
        }
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut result = String::new();
        client.read_to_string(&mut result).unwrap();
        handler.join().unwrap();
        let script = script.join().unwrap();
        assert!(
            reached_barrier,
            "executor missed the admission barrier: {result}"
        );
        assert!(script.is_ok(), "{script:?}; executor response: {result}");
        serde_json::from_str(&result).unwrap()
    });
    (response, count(&f.service, "admissions"))
}

#[test]
fn bridge_scripted_socket_positive_admits_bound_principal() {
    let (reply, rows) = run_scripted_bridge(|_| {});
    assert_eq!(
        rows, 1,
        "valid bound scripted response did not reach admission"
    );
    assert_eq!(reply["status"], "ok");

    use xmsg::client::caller_attribution::{FailureReason, Reply, VERSION};
    let (reply, rows) = run_scripted_bridge(|reply| {
        *reply = Reply::Unavailable {
            v: VERSION,
            reason: FailureReason::Unsupported,
        };
    });
    assert_eq!(reply["code"], "attestation_unavailable");
    assert_eq!(rows, 0, "unavailable attribution reached durable admission");
}

#[test]
fn bridge_reply_from_previous_service_epoch_is_refused() {
    use xmsg::client::caller_attribution::Reply;

    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let first = captured.clone();
    let (reply, rows) = run_scripted_bridge(move |reply| {
        let Reply::Ok { runtime_epoch, .. } = reply else {
            panic!("scripted peer expected an eligible reply");
        };
        *first.lock().unwrap() = Some(runtime_epoch.clone());
    });
    assert_eq!(reply["status"], "ok");
    assert_eq!(rows, 1);

    let epoch = captured.lock().unwrap().take().unwrap();
    let (reply, rows) = run_scripted_bridge(move |reply| {
        let Reply::Ok { runtime_epoch, .. } = reply else {
            panic!("second invocation expected an eligible reply");
        };
        assert_ne!(*runtime_epoch, epoch);
        *runtime_epoch = epoch;
    });
    assert_eq!(reply["code"], "attestation_binding");
    assert_eq!(rows, 0, "a prior service reply reached durable admission");
}

#[test]
fn bridge_wrong_epoch_has_no_admission_even_with_valid_grant() {
    let (reply, rows) = run_scripted_bridge(|reply| {
        if let xmsg::client::caller_attribution::Reply::Ok { runtime_epoch, .. } = reply {
            *runtime_epoch = "f".repeat(32);
        }
    });
    assert_eq!(rows, 0, "wrong epoch reached durable admission");
    assert_eq!(reply["code"], "attestation_binding");
}
#[test]
fn bridge_wrong_nonce_has_no_admission_even_with_valid_grant() {
    let (reply, rows) = run_scripted_bridge(|reply| {
        if let xmsg::client::caller_attribution::Reply::Ok { call_nonce, .. } = reply {
            *call_nonce += 1;
        }
    });
    assert_eq!(rows, 0, "wrong nonce reached durable admission");
    assert_eq!(reply["code"], "attestation_binding");
}
#[test]
fn bridge_wrong_request_digest_has_no_admission_even_with_valid_grant() {
    let (reply, rows) = run_scripted_bridge(|reply| {
        if let xmsg::client::caller_attribution::Reply::Ok { input_digest, .. } = reply {
            *input_digest = "e".repeat(64);
        }
    });
    assert_eq!(rows, 0, "wrong request digest reached durable admission");
    assert_eq!(reply["code"], "attestation_binding");
}
#[test]
fn bridge_wrong_context_digest_has_no_admission_even_with_valid_grant() {
    let (reply, rows) = run_scripted_bridge(|reply| {
        if let xmsg::client::caller_attribution::Reply::Ok { context_digest, .. } = reply {
            *context_digest = "e".repeat(64);
        }
    });
    assert_eq!(rows, 0, "wrong context digest reached durable admission");
    assert_eq!(reply["code"], "attestation_binding");
}
#[test]
fn bridge_expiry_during_scripted_reply_has_no_admission() {
    let clock = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(100));
    let script_clock = clock.clone();
    let (reply, rows) = run_scripted_bridge_clock(
        move |_| {
            script_clock.store(201, Ordering::SeqCst);
        },
        Some(clock),
        false,
    );
    assert_eq!(rows, 0, "expired during query reached durable admission");
    assert_eq!(
        reply["result"]["receipt"]["authorization"]["code"],
        "deadline_expired"
    );
}
#[test]
fn bridge_expiry_after_query_before_admission_lock_has_no_admission() {
    let (reply, rows) = run_scripted_bridge_clock(|_| {}, None, true);
    assert_eq!(
        rows, 0,
        "expiry after query lock wait reached durable admission"
    );
    assert_eq!(
        reply["result"]["receipt"]["authorization"]["code"],
        "deadline_expired"
    );
}
#[test]
#[ignore = "test-only captured/reaped live alternate peer for attribution echo controls"]
fn bridge_live_peer_fixture() {
    use std::io::Read;
    let mut byte = [0];
    let _ = std::io::stdin().read(&mut byte);
}
#[test]
fn bridge_wrong_live_peer_has_no_admission_even_with_valid_grant() {
    use std::process::{Command, Stdio};
    let mut peer = EchoPeer(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "control::tests::bridge_live_peer_fixture",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let pid = peer.0.id();
    let (reply, rows) = run_scripted_bridge(|reply| {
        if let xmsg::client::caller_attribution::Reply::Ok { peer_pid, .. } = reply {
            *peer_pid = pid;
        }
    });
    drop(peer.0.stdin.take());
    let _ = peer.0.wait();
    assert_eq!(rows, 0, "wrong live peer reached durable admission");
    assert_eq!(reply["code"], "attestation_binding");
}
fn send(id: &str) -> ControlRequest {
    ControlRequest {
        version: 1,
        request_id: id.into(),
        target: Some(Target::Execution {
            session_id: "session-a".into(),
            generation: 1,
        }),
        action: Action::Send(SendArgs {
            text: "fixture intent".into(),
            prefer_live: None,
        }),
        deadline: Some(200),
    }
}
fn count(service: &ControlService, table: &str) -> i64 {
    service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn assert_denied(f: &Fixture, request: ControlRequest) {
    let reply = f.service.lifecycle(peer(), request, 100).unwrap();
    assert_eq!(
        count(&f.service, "admissions"),
        0,
        "unauthorized admission effect reached journal"
    );
    assert!(matches!(
        reply.receipt.authorization,
        Authorization::Denied { .. }
    ));
}
#[test]
fn missing_grant_has_no_admission_effect() {
    assert_denied(&fixture(config(vec![])), send("missing"));
}
#[test]
fn wrong_verb_has_no_admission_effect() {
    assert_denied(
        &fixture(config(vec![grant(Verb::Stop, "session-a", 1)])),
        send("verb"),
    );
}
#[test]
fn wrong_target_has_no_admission_effect() {
    assert_denied(
        &fixture(config(vec![grant(Verb::Send, "other", 1)])),
        send("target"),
    );
}
#[test]
fn stale_generation_has_no_admission_effect() {
    let f = fixture(config(vec![grant(Verb::Send, "session-a", 2)]));
    let mut r = send("generation");
    r.target = Some(Target::Execution {
        session_id: "session-a".into(),
        generation: 2,
    });
    assert_denied(&f, r);
}
#[test]
fn stale_turn_has_no_admission_effect() {
    let f = fixture(config(vec![Grant {
        principal: "worker".into(),
        verb: Verb::Steer,
        target: GrantTarget::Turn {
            session_id: "session-a".into(),
            generation: 1,
            turn_id: "turn-b".into(),
        },
    }]));
    let mut r = send("turn");
    r.action = Action::Steer(crate::protocol::SteerArgs {
        text: "fixture".into(),
    });
    r.target = Some(Target::Turn {
        session_id: "session-a".into(),
        generation: 1,
        turn_id: "turn-b".into(),
    });
    assert_denied(&f, r);
}
#[test]
fn expired_request_has_no_admission_effect() {
    let f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    let mut r = send("expired");
    r.deadline = Some(99);
    assert_denied(&f, r);
}
#[test]
fn revoked_profile_has_no_admission_effect() {
    let mut c = config(vec![grant(Verb::Send, "session-a", 1)]);
    c.profiles[0].enabled = false;
    assert_denied(&fixture(c), send("profile"));
}
#[test]
fn ambient_parent_binding_has_no_admission_effect() {
    let mut f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    f.service.attestor = Box::new(FakeAttestor {
        principal: "worker".into(),
        wrong_binding: true,
    });
    let result = f.service.lifecycle(peer(), send("parent"), 100);
    assert_eq!(
        count(&f.service, "admissions"),
        0,
        "ambient authority reached admission"
    );
    assert_eq!(result.unwrap_err(), ErrorCode::AttestationBinding);
}
#[test]
fn wrong_peer_uid_has_no_admission_effect() {
    let f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    let result = f.service.lifecycle(
        PeerWitness {
            uid: uid().wrapping_add(1),
            pid: Some(123),
        },
        send("uid"),
        100,
    );
    assert_eq!(
        count(&f.service, "admissions"),
        0,
        "wrong UID reached admission"
    );
    assert_eq!(result.unwrap_err(), ErrorCode::PeerUid);
}
#[test]
fn changed_request_id_is_conflict_not_replay_or_effect() {
    let f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    f.service.lifecycle(peer(), send("same"), 100).unwrap();
    let mut r = send("same");
    if let Action::Send(a) = &mut r.action {
        a.text = "different".into()
    };
    let result = f.service.lifecycle(peer(), r, 100);
    let replay_count: i64 = f
        .service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE event='historical_replay'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        replay_count, 0,
        "changed request incorrectly published historical receipt"
    );
    assert_eq!(count(&f.service, "admissions"), 1);
    assert_eq!(result.unwrap_err(), ErrorCode::RequestConflict);
}
#[test]
fn replay_is_historical_and_does_not_repeat_admission() {
    let f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    let first = f.service.lifecycle(peer(), send("same"), 100).unwrap();
    let second = f.service.lifecycle(peer(), send("same"), 101).unwrap();
    assert!(!first.historical);
    assert!(second.historical && second.replayed);
    assert_eq!(count(&f.service, "admissions"), 1);
}
#[test]
fn denied_id_does_not_reopen_when_policy_changes() {
    let f = fixture(config(vec![]));
    f.service.lifecycle(peer(), send("denied"), 100).unwrap();
    let mut c = config(vec![grant(Verb::Send, "session-a", 1)]);
    c.revision = 2;
    f.service
        .admin(
            peer(),
            OWNER,
            AdminCommand::ReplacePolicy {
                request_id: "admin".into(),
                expected_revision: 1,
                configuration: c,
            },
            101,
        )
        .unwrap();
    let replay = f.service.lifecycle(peer(), send("denied"), 102).unwrap();
    assert!(replay.historical);
    assert_eq!(count(&f.service, "admissions"), 0);
    f.service.lifecycle(peer(), send("fresh"), 102).unwrap();
    assert_eq!(count(&f.service, "admissions"), 1);
}
#[test]
fn owner_and_human_credentials_are_distinct() {
    let f = fixture(config(vec![]));
    let result = f.service.admin(
        peer(),
        HUMAN,
        AdminCommand::RevokeProfile {
            request_id: "admin".into(),
            expected_revision: 1,
            profile_id: "safe".into(),
        },
        100,
    );
    let revision: i64 = f
        .service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row("SELECT revision FROM configuration", [], |r| r.get(0))
        .unwrap();
    assert_eq!(revision, 1, "human proof changed owner policy");
    assert_eq!(result.unwrap_err(), ErrorCode::CredentialDenied);
}
#[test]
fn concurrent_same_id_admits_once() {
    let f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    f.service
                        .lifecycle(peer(), send("concurrent"), 100)
                        .unwrap()
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
    assert_eq!(count(&f.service, "admissions"), 1);
}
#[test]
fn production_attestor_is_unavailable_even_for_owner_uid() {
    let mut f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    f.service.attestor = Box::new(auth::Unavailable);
    let result = f.service.lifecycle(peer(), send("unavailable"), 100);
    assert_eq!(count(&f.service, "admissions"), 0);
    assert_eq!(result.unwrap_err(), ErrorCode::AttestationUnavailable);
}

fn approve(id: &str) -> ControlRequest {
    ControlRequest {
        version: 1,
        request_id: id.into(),
        target: Some(Target::Turn {
            session_id: "session-a".into(),
            generation: 1,
            turn_id: "turn-a".into(),
        }),
        action: Action::Approve(crate::protocol::ApproveArgs {
            approval_id: "pending-a".into(),
            operation_digest: "a".repeat(64),
            policy_revision: "1".into(),
            expires_at: 200,
            option_id: "allow-once".into(),
            decision: crate::protocol::Decision::AllowOnce,
        }),
        deadline: Some(200),
    }
}
fn pending(f: &Fixture) {
    f.service.journal.lock().unwrap().db.execute("INSERT INTO approvals VALUES('pending-a','session-a',1,'turn-a',?1,'1',200,'allow-once',0)",["a".repeat(64)]).unwrap();
}
fn consumed(f: &Fixture) -> i64 {
    f.service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row(
            "SELECT consumed FROM approvals WHERE id='pending-a'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
#[test]
fn agent_grant_cannot_replace_human_channel() {
    let f = fixture(config(vec![grant(Verb::Approve, "session-a", 1)]));
    pending(&f);
    assert_denied(&f, approve("agent"));
    assert_eq!(consumed(&f), 0);
}
#[test]
fn human_channel_rejects_owner_credential_without_consumption() {
    let f = fixture(config(vec![]));
    pending(&f);
    let result = f.service.human(peer(), OWNER, approve("wrong-role"), 100);
    assert_eq!(consumed(&f), 0, "owner proof consumed human pending action");
    assert_eq!(result.unwrap_err(), ErrorCode::CredentialDenied);
}
#[test]
fn human_pending_digest_is_bound_to_exact_operation() {
    let f = fixture(config(vec![]));
    pending(&f);
    let mut r = approve("digest");
    if let Action::Approve(a) = &mut r.action {
        a.operation_digest = "b".repeat(64)
    };
    let result = f.service.human(peer(), HUMAN, r, 100);
    assert_eq!(consumed(&f), 0, "wrong operation consumed pending action");
    assert_eq!(result.unwrap_err(), ErrorCode::PendingMismatch);
}
#[test]
fn human_pending_deadline_cannot_expire_before_consumption() {
    let f = fixture(config(vec![]));
    pending(&f);
    let mut r = approve("expiry");
    r.deadline = Some(99);
    let result = f.service.human(peer(), HUMAN, r, 100);
    assert_eq!(consumed(&f), 0, "expired envelope consumed pending action");
    assert_eq!(result.unwrap_err(), ErrorCode::DeadlineExpired);
}
#[test]
fn human_pending_policy_revision_is_current() {
    let mut c = config(vec![]);
    c.revision = 2;
    let f = fixture(c);
    pending(&f);
    let result = f.service.human(peer(), HUMAN, approve("policy"), 100);
    assert_eq!(consumed(&f), 0, "stale policy consumed pending action");
    assert_eq!(result.unwrap_err(), ErrorCode::PendingMismatch);
}
#[test]
fn human_pending_generation_is_current() {
    let f = fixture(config(vec![]));
    pending(&f);
    f.service
        .journal
        .lock()
        .unwrap()
        .db
        .execute("UPDATE sessions SET generation=2", [])
        .unwrap();
    let result = f.service.human(peer(), HUMAN, approve("generation"), 100);
    assert_eq!(consumed(&f), 0, "stale generation consumed pending action");
    assert_eq!(result.unwrap_err(), ErrorCode::StaleGeneration);
}
#[test]
fn human_pending_turn_is_current() {
    let f = fixture(config(vec![]));
    pending(&f);
    f.service
        .journal
        .lock()
        .unwrap()
        .db
        .execute("UPDATE sessions SET active_turn='turn-b'", [])
        .unwrap();
    let result = f.service.human(peer(), HUMAN, approve("turn"), 100);
    assert_eq!(consumed(&f), 0, "stale turn consumed pending action");
    assert_eq!(result.unwrap_err(), ErrorCode::StaleTurn);
}
#[test]
fn human_pending_consumed_once_and_replay_is_historical() {
    let f = fixture(config(vec![]));
    pending(&f);
    let first = f
        .service
        .human(peer(), HUMAN, approve("decision"), 100)
        .unwrap();
    assert!(!first.historical);
    let second = f
        .service
        .human(peer(), HUMAN, approve("decision"), 101)
        .unwrap();
    assert!(second.historical);
    assert_eq!(consumed(&f), 1);
    let result = f.service.human(peer(), HUMAN, approve("fresh"), 102);
    assert_eq!(
        count(&f.service, "requests"),
        1,
        "consumed action produced a second receipt"
    );
    assert_eq!(result.unwrap_err(), ErrorCode::AlreadyConsumed);
}
#[test]
fn human_pending_requires_enabled_profile() {
    let mut c = config(vec![]);
    c.profiles[0].enabled = false;
    let f = fixture(c);
    pending(&f);
    let result = f.service.human(peer(), HUMAN, approve("profile"), 100);
    assert_eq!(consumed(&f), 0, "revoked profile consumed pending action");
    assert_eq!(result.unwrap_err(), ErrorCode::ProfileDenied);
}
#[test]
fn production_unix_handler_denies_without_host_attestation() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut f = fixture(config(vec![grant(Verb::Send, "session-a", 1)]));
    f.service.attestor = Box::new(auth::Unavailable);
    let (mut client, server) = UnixStream::pair().unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| f.service.handle_lifecycle_connection(server).unwrap());
        let mut wire = serde_json::to_vec(&send("wire")).unwrap();
        wire.push(b'\n');
        client.write_all(&wire).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert!(reply.contains("attestation_unavailable"));
        worker.join().unwrap();
    });
    assert_eq!(count(&f.service, "admissions"), 0);
}
#[test]
fn credentials_and_database_permissions_have_transport_bounds() {
    assert!(ProvisionedCredentials::from_bytes(&[b'x'; 129], HUMAN).is_err());
    let mut proof = OWNER.to_vec();
    proof[5] = b'\n';
    assert!(ProvisionedCredentials::from_bytes(&proof, HUMAN).is_err());
    let f = fixture(config(vec![]));
    assert_eq!(
        std::fs::metadata(f._dir.path().join("journal.db"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

fn template() -> DispatchTemplate {
    use crate::capability::{
        ProfileContract, ProtectionReport, ProtectionState, QualificationKey, ReviewMode,
    };
    use crate::protocol::{
        EnvironmentBackend, EnvironmentDescriptor, Model, ResourceBudget, WorkspaceSpec,
    };
    let unknown = ProtectionState::Unknown {
        reason: "unproven fixture".into(),
    };
    DispatchTemplate {
        team_id: "team-a".into(),
        profile_id: "safe".into(),
        resolved: ResolvedDispatch {
            harness: Harness::Claude,
            model: Model {
                provider: "fake".into(),
                name: "fake".into(),
            },
            environment: EnvironmentDescriptor {
                id: "environment-a".into(),
                executor: "local".into(),
                host: "host-a".into(),
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
                pin_id: "unproven".into(),
                adapter_version: "fake".into(),
                runtime_version: "fake".into(),
                protocol_version: 1,
                profile: TrustProfile::Safe,
                native_mode: "fake".into(),
                review_mode: ReviewMode::HumanOnly,
                protocol_schema: "fake".into(),
                model: Model {
                    provider: "fake".into(),
                    name: "fake".into(),
                },
                effective_config_digest: "a".repeat(64),
            },
            workspace: WorkspaceSpec {
                repo_identity: "fixture-repo".into(),
                base_revision: "b".repeat(40),
                destination_selector: "fixture".into(),
                context_refs: vec![],
                patch_ref: None,
            },
            required_capabilities: vec![],
            budget: ResourceBudget {
                worker_slots: 8,
                reviewer_slots: 1,
                max_wall_ms: 1000,
                max_content_bytes: 1024,
            },
        },
    }
}
#[test]
fn malformed_default_profile_is_rejected_atomically() {
    let f = fixture(config(vec![]));
    let mut c = config(vec![]);
    c.revision = 2;
    let mut d = template();
    d.resolved.environment.project = "other-project".into();
    c.defaults.push(d);
    let result = f.service.admin(
        peer(),
        OWNER,
        AdminCommand::ReplacePolicy {
            request_id: "bad-default".into(),
            expected_revision: 1,
            configuration: c,
        },
        100,
    );
    let revision: i64 = f
        .service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row("SELECT revision FROM configuration", [], |r| r.get(0))
        .unwrap();
    assert_eq!(revision, 1, "mismatched default replaced owner policy");
    assert_eq!(count(&f.service, "audit"), 0);
    assert_eq!(result.unwrap_err(), ErrorCode::InvalidConfiguration);
}
#[test]
fn dispatch_admits_intent_with_resolved_defaults_without_runtime_effect() {
    let mut c = config(vec![Grant {
        principal: "worker".into(),
        verb: Verb::Dispatch,
        target: GrantTarget::Team {
            team_id: "team-a".into(),
        },
    }]);
    c.defaults.push(template());
    let f = fixture(c);
    let reply = f
        .service
        .lifecycle(
            peer(),
            ControlRequest::dispatch("dispatch".into(), "fixture brief".into()),
            100,
        )
        .unwrap();
    assert_eq!(count(&f.service, "admissions"), 1);
    assert_eq!(count(&f.service, "sessions"), 2);
    assert!(matches!(
        reply.receipt.submission,
        crate::protocol::Submission::NotAttempted
    ));
    assert!(matches!(
        reply.receipt.observed_effect,
        crate::protocol::ObservedEffect::NotObserved
    ));
}

fn reopen(f: Fixture, configuration: OwnerConfig) -> Fixture {
    let Fixture { _dir, service } = f;
    drop(service);
    let mut service = ControlService::open(
        &_dir.path().join("journal.db"),
        uid(),
        configuration,
        ProvisionedCredentials::from_bytes(OWNER, HUMAN).unwrap(),
    )
    .unwrap();
    service.attestor = Box::new(FakeAttestor {
        principal: "worker".into(),
        wrong_binding: false,
    });
    Fixture { _dir, service }
}
#[test]
fn resolved_admission_survives_policy_change_and_reopen() {
    let mut c = config(vec![Grant {
        principal: "worker".into(),
        verb: Verb::Dispatch,
        target: GrantTarget::Team {
            team_id: "team-a".into(),
        },
    }]);
    c.defaults.push(template());
    let f = fixture(c.clone());
    let request = ControlRequest::dispatch("durable-dispatch".into(), "fixture".into());
    let first = f.service.lifecycle(peer(), request.clone(), 100).unwrap();
    let expected = first.dispatch.unwrap();
    assert_eq!(expected.session_id, "session-1");
    c.revision = 2;
    c.defaults[0].resolved.model.name = "new-model".into();
    c.defaults[0].resolved.workspace.base_revision = "c".repeat(40);
    c.defaults[0].resolved.budget.max_wall_ms = 2000;
    c.defaults[0].resolved.qualification.pin_id = "new-pin".into();
    f.service
        .admin(
            peer(),
            OWNER,
            AdminCommand::ReplacePolicy {
                request_id: "change-defaults".into(),
                expected_revision: 1,
                configuration: c.clone(),
            },
            101,
        )
        .unwrap();
    let f = reopen(f, c);
    let replay = f.service.lifecycle(peer(), request, 102).unwrap();
    assert!(replay.historical);
    let actual = replay.dispatch.unwrap();
    assert_eq!(
        actual.session_id, expected.session_id,
        "created session identity was lost"
    );
    assert_eq!(
        actual.resolved, expected.resolved,
        "historical admission inherited current defaults"
    );
    let (resolved, session_id): (String, String) = f
        .service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row("SELECT resolved,session_id FROM admissions", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(
        resolved,
        serde_json::to_string(&expected.resolved).unwrap(),
        "resolved admission payload was not durable"
    );
    assert_eq!(
        serde_json::from_str::<ResolvedDispatch>(&resolved).unwrap(),
        expected.resolved
    );
    assert_eq!(session_id, expected.session_id);
}
#[test]
fn exact_human_decisions_survive_reopen_without_credentials() {
    use crate::protocol::Decision;
    for decision in [Decision::AllowOnce, Decision::Deny, Decision::Escalate] {
        let f = fixture(config(vec![]));
        pending(&f);
        let mut request = approve("durable-decision");
        if let Action::Approve(a) = &mut request.action {
            a.decision = decision.clone()
        };
        f.service
            .human(peer(), HUMAN, request.clone(), 100)
            .unwrap();
        let f = reopen(f, config(vec![]));
        let (stored, body): (String, String) = f
            .service
            .journal
            .lock()
            .unwrap()
            .db
            .query_row("SELECT decision,payload FROM decisions", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Decision>(&stored).unwrap(),
            decision,
            "exact human meaning was lost"
        );
        assert_eq!(
            serde_json::from_str::<ControlRequest>(&body).unwrap(),
            request
        );
        assert!(!body.contains(std::str::from_utf8(HUMAN).unwrap()));
        assert!(!body.contains(std::str::from_utf8(OWNER).unwrap()));
        let receipt = f.service.human(peer(), HUMAN, request, 101).unwrap();
        assert!(receipt.historical);
        assert_eq!(receipt.decision.unwrap().decision, decision);
        assert_eq!(consumed(&f), 1);
    }
}
#[test]
fn environment_and_executor_selectors_are_distinct() {
    let mut c = config(vec![Grant {
        principal: "worker".into(),
        verb: Verb::Dispatch,
        target: GrantTarget::Team {
            team_id: "team-a".into(),
        },
    }]);
    c.defaults.push(template());
    let f = fixture(c);
    let mut request = ControlRequest::dispatch("right-environment".into(), "fixture".into());
    if let Action::Dispatch(a) = &mut request.action {
        a.requested.environment_selector = Some("environment-a".into());
        a.requested.executor_selector = Some("local".into());
    }
    f.service.lifecycle(peer(), request, 100).unwrap();
    assert_eq!(count(&f.service, "admissions"), 1);
    let mut request = ControlRequest::dispatch("wrong-environment".into(), "fixture".into());
    if let Action::Dispatch(a) = &mut request.action {
        a.requested.environment_selector = Some("local".into())
    };
    let reply = f.service.lifecycle(peer(), request, 100).unwrap();
    assert_eq!(
        count(&f.service, "admissions"),
        1,
        "executor selector was accepted as environment identity"
    );
    assert!(matches!(
        reply.receipt.authorization,
        Authorization::Denied { .. }
    ));
}

#[test]
fn human_pending_expiry_is_checked_at_consumption() {
    let f = fixture(config(vec![]));
    pending(&f);
    f.service
        .journal
        .lock()
        .unwrap()
        .db
        .execute("UPDATE approvals SET expires_at=99", [])
        .unwrap();
    let mut request = approve("expired-pending");
    if let Action::Approve(a) = &mut request.action {
        a.expires_at = 99
    };
    let result = f.service.human(peer(), HUMAN, request, 100);
    assert_eq!(consumed(&f), 0, "expired pending action was consumed");
    assert_eq!(result.unwrap_err(), ErrorCode::DeadlineExpired);
}

#[test]
fn grant_for_other_principal_has_no_admission_effect() {
    let mut other = grant(Verb::Send, "session-a", 1);
    other.principal = "parent".into();
    assert_denied(&fixture(config(vec![other])), send("principal-scope"));
}

#[test]
fn tighter_caller_budget_survives_reopen_and_limits_admission() {
    let mut c = config(vec![Grant {
        principal: "worker".into(),
        verb: Verb::Dispatch,
        target: GrantTarget::Team {
            team_id: "team-a".into(),
        },
    }]);
    c.defaults.push(template());
    let wanted = crate::protocol::ResourceBudget {
        worker_slots: 4,
        reviewer_slots: 0,
        max_wall_ms: 100,
        max_content_bytes: 128,
    };
    let f = fixture(c.clone());
    let mut request = ControlRequest::dispatch("bounded-dispatch".into(), "fixture".into());
    if let Action::Dispatch(a) = &mut request.action {
        a.requested.budget = Some(wanted.clone());
    }
    let receipt = f.service.lifecycle(peer(), request, 100).unwrap();
    let f = reopen(f, c);
    let stored: String = f
        .service
        .journal
        .lock()
        .unwrap()
        .db
        .query_row("SELECT resolved FROM admissions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<ResolvedDispatch>(&stored)
            .unwrap()
            .budget,
        wanted,
        "caller budget widened in durable admission"
    );
    assert_eq!(receipt.dispatch.unwrap().resolved.budget, wanted);
    let mut request = ControlRequest::dispatch("tighter-quota".into(), "fixture".into());
    if let Action::Dispatch(a) = &mut request.action {
        a.requested.budget = Some(crate::protocol::ResourceBudget {
            worker_slots: 1,
            ..wanted
        });
    }
    let denied = f.service.lifecycle(peer(), request, 101).unwrap();
    assert_eq!(
        count(&f.service, "admissions"),
        1,
        "effective caller quota was ignored"
    );
    assert!(matches!(
        denied.receipt.authorization,
        Authorization::Denied { .. }
    ));
}

fn grant_arm_fixture(
    target: GrantTarget,
    verb: Verb,
    session_id: &str,
    generation: i64,
    turn_id: &str,
) -> Fixture {
    let f = fixture(config(vec![Grant {
        principal: "worker".into(),
        verb,
        target,
    }]));
    f.service
        .journal
        .lock()
        .unwrap()
        .db
        .execute(
            "UPDATE sessions SET id=?1,generation=?2,active_turn=?3",
            rusqlite::params![session_id, generation, turn_id],
        )
        .unwrap();
    f
}
fn grant_arm_request(verb: Verb, target: Target) -> ControlRequest {
    let action = match verb {
        Verb::Send => Action::Send(SendArgs {
            text: "fixture".into(),
            prefer_live: None,
        }),
        Verb::Steer => Action::Steer(crate::protocol::SteerArgs {
            text: "fixture".into(),
        }),
        Verb::Interrupt => Action::Interrupt(crate::protocol::EmptyArgs::default()),
        _ => panic!("unsupported test verb"),
    };
    ControlRequest {
        version: 1,
        request_id: "grant-arm".into(),
        target: Some(target),
        action,
        deadline: Some(200),
    }
}
fn assert_grant_refused(f: &Fixture, request: ControlRequest) {
    let reply = f.service.lifecycle(peer(), request, 100).unwrap();
    assert_eq!(
        count(&f.service, "admissions"),
        0,
        "grant target mismatch reached admission"
    );
    let Authorization::Denied { code } = reply.receipt.authorization else {
        panic!("missing grant denial")
    };
    assert_eq!(
        code,
        ErrorCode::GrantDenied.to_string(),
        "later state guard masked grant arm"
    );
}
fn assert_grant_admitted(f: &Fixture, request: ControlRequest) {
    let reply = f.service.lifecycle(peer(), request, 100).unwrap();
    assert_eq!(
        count(&f.service, "admissions"),
        1,
        "valid grant arm refused admission"
    );
    assert!(matches!(
        reply.receipt.authorization,
        Authorization::Allowed { .. }
    ));
}
fn session_grant() -> GrantTarget {
    GrantTarget::Session {
        session_id: "session-a".into(),
        generation: 1,
    }
}
fn turn_grant() -> GrantTarget {
    GrantTarget::Turn {
        session_id: "session-a".into(),
        generation: 1,
        turn_id: "turn-a".into(),
    }
}
fn addressed_turn(session: &str, generation: u64, turn: &str) -> Target {
    Target::Turn {
        session_id: session.into(),
        generation,
        turn_id: turn.into(),
    }
}
#[test]
fn session_grant_turn_valid_generation_admits_steer_and_interrupt() {
    for verb in [Verb::Steer, Verb::Interrupt] {
        let f = grant_arm_fixture(session_grant(), verb.clone(), "session-a", 1, "turn-a");
        assert_grant_admitted(
            &f,
            grant_arm_request(verb, addressed_turn("session-a", 1, "turn-a")),
        );
    }
}
#[test]
fn session_grant_turn_new_generation_has_no_admission_effect() {
    for verb in [Verb::Steer, Verb::Interrupt] {
        let f = grant_arm_fixture(session_grant(), verb.clone(), "session-a", 2, "turn-a");
        assert_grant_refused(
            &f,
            grant_arm_request(verb, addressed_turn("session-a", 2, "turn-a")),
        );
    }
}
#[test]
fn session_grant_turn_other_session_has_no_admission_effect() {
    let f = grant_arm_fixture(session_grant(), Verb::Steer, "session-b", 1, "turn-a");
    assert_grant_refused(
        &f,
        grant_arm_request(Verb::Steer, addressed_turn("session-b", 1, "turn-a")),
    );
}
#[test]
fn session_grant_execution_valid_binding_admits_send() {
    let f = grant_arm_fixture(session_grant(), Verb::Send, "session-a", 1, "turn-a");
    assert_grant_admitted(
        &f,
        grant_arm_request(
            Verb::Send,
            Target::Execution {
                session_id: "session-a".into(),
                generation: 1,
            },
        ),
    );
}
#[test]
fn session_grant_execution_new_generation_has_no_admission_effect() {
    let f = grant_arm_fixture(session_grant(), Verb::Send, "session-a", 2, "turn-a");
    assert_grant_refused(
        &f,
        grant_arm_request(
            Verb::Send,
            Target::Execution {
                session_id: "session-a".into(),
                generation: 2,
            },
        ),
    );
}
#[test]
fn session_grant_execution_other_session_has_no_admission_effect() {
    let f = grant_arm_fixture(session_grant(), Verb::Send, "session-b", 1, "turn-a");
    assert_grant_refused(
        &f,
        grant_arm_request(
            Verb::Send,
            Target::Execution {
                session_id: "session-b".into(),
                generation: 1,
            },
        ),
    );
}
#[test]
fn turn_grant_turn_valid_binding_admits_steer() {
    let f = grant_arm_fixture(turn_grant(), Verb::Steer, "session-a", 1, "turn-a");
    assert_grant_admitted(
        &f,
        grant_arm_request(Verb::Steer, addressed_turn("session-a", 1, "turn-a")),
    );
}
#[test]
fn turn_grant_turn_other_session_has_no_admission_effect() {
    let f = grant_arm_fixture(turn_grant(), Verb::Steer, "session-b", 1, "turn-a");
    assert_grant_refused(
        &f,
        grant_arm_request(Verb::Steer, addressed_turn("session-b", 1, "turn-a")),
    );
}
#[test]
fn turn_grant_turn_new_generation_has_no_admission_effect() {
    let f = grant_arm_fixture(turn_grant(), Verb::Steer, "session-a", 2, "turn-a");
    assert_grant_refused(
        &f,
        grant_arm_request(Verb::Steer, addressed_turn("session-a", 2, "turn-a")),
    );
}
#[test]
fn turn_grant_turn_other_turn_has_no_admission_effect() {
    let f = grant_arm_fixture(turn_grant(), Verb::Steer, "session-a", 1, "turn-b");
    assert_grant_refused(
        &f,
        grant_arm_request(Verb::Steer, addressed_turn("session-a", 1, "turn-b")),
    );
}
fn team_grant_fixture(requested: &str) -> Fixture {
    let mut c = config(vec![Grant {
        principal: "worker".into(),
        verb: Verb::Dispatch,
        target: GrantTarget::Team {
            team_id: "team-a".into(),
        },
    }]);
    let mut d = template();
    d.team_id = requested.into();
    c.defaults.push(d);
    fixture(c)
}
fn team_grant_request(requested: &str) -> ControlRequest {
    let mut r = ControlRequest::dispatch("grant-team".into(), "fixture".into());
    r.target = Some(Target::Team {
        team_id: requested.into(),
    });
    r
}
#[test]
fn team_grant_team_valid_binding_admits_dispatch() {
    assert_grant_admitted(&team_grant_fixture("team-a"), team_grant_request("team-a"));
}
#[test]
fn team_grant_team_other_team_has_no_admission_effect() {
    assert_grant_refused(&team_grant_fixture("team-b"), team_grant_request("team-b"));
}

#[test]
fn cross_kind_grant_has_no_admission_effect() {
    let f = grant_arm_fixture(
        GrantTarget::Team {
            team_id: "team-a".into(),
        },
        Verb::Steer,
        "session-a",
        1,
        "turn-a",
    );
    assert_grant_refused(
        &f,
        grant_arm_request(Verb::Steer, addressed_turn("session-a", 1, "turn-a")),
    );
}
