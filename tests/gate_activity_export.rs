#[path = "support/spawn.rs"]
mod spawn;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;
use tokio::time::Instant;

use xmsg::activity::hook::{check_json_depth, normalize_hook_payload, run_activity_hook};
use xmsg::activity::model::{
    ActivityDescriptor, ActivityFrame, ActivityHarness, ActivityReason, ActivityState,
    ActivityStatus, BackgroundPresence, BlockKind, OwnerProof, SnapshotActivity, WakePresence,
    ACTIVITY_HOOK_MAX_JSON_DEPTH, ACTIVITY_STALE_WORKING_SECS,
};
use xmsg::activity::reconcile::CollectorActivityReconciler;
use xmsg::activity::reducer::{ActivityEngine, BindingOutcome, OwnerResolver, ProofFlags};
use xmsg::observe::{Config as ObserveConfig, Event, LossCounters, Observation, Observer, Page};
use xmsg::observe_export::{
    project_page, project_snapshot_with_activity, valid_activity_endpoint, EndpointDescriptor,
    EndpointKind, EventKind, ExportEvent, ExportQuery, ExportSnapshot, Harness, RegistrationState,
    Scope, SnapshotAvailability, SnapshotQuery, SnapshotRecord,
};

struct StubResolver {
    outcomes: HashMap<String, BindingOutcome>,
    live_owners: HashMap<OwnerProof, bool>,
}

impl StubResolver {
    fn new() -> Self {
        Self {
            outcomes: HashMap::new(),
            live_owners: HashMap::new(),
        }
    }

    fn bind(&mut self, session: &str, address: &str, incarnation: u64, owner: OwnerProof) {
        self.live_owners.insert(owner, true);
        self.outcomes.insert(
            session.to_owned(),
            BindingOutcome::Verified {
                address: address.to_owned(),
                incarnation,
                owner,
                has_pending_wake: false,
            },
        );
    }
}

impl OwnerResolver for StubResolver {
    fn resolve(&self, frame: &ActivityFrame) -> BindingOutcome {
        self.outcomes
            .get(&frame.session)
            .cloned()
            .unwrap_or(BindingOutcome::Unverified {
                identified_address: None,
            })
    }

    fn is_owner_live(&self, owner: OwnerProof) -> bool {
        self.live_owners.get(&owner).copied().unwrap_or(false)
    }
}

fn setup_db() -> (TempDir, Connection) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("xmsg.db");
    let conn = Connection::open(&db_path).unwrap();
    xmsg::storage::init_db(&conn).unwrap();
    (dir, conn)
}

fn owner1() -> OwnerProof {
    OwnerProof {
        pid: 1001,
        started_at: 500,
    }
}

fn owner2() -> OwnerProof {
    OwnerProof {
        pid: 2002,
        started_at: 900,
    }
}

fn claude_frame(session: &str, event: &str, bg: BackgroundPresence) -> ActivityFrame {
    ActivityFrame {
        action: "activity".into(),
        schema_version: 1,
        harness: ActivityHarness::Claude,
        event: event.into(),
        session: session.into(),
        owner: Some(owner1()),
        native_seq: None,
        event_id: None,
        correlation: None,
        block: None,
        background: bg,
        wake: WakePresence::Absent,
        failed: None,
    }
}

#[test]
fn ae1_ae2_ae3_ae4_ae5_claude_foreground_background_absent_and_wakes() {
    let (_dir, mut conn) = setup_db();
    let mut resolver = StubResolver::new();
    let addr = "11111111-1111-4111-8111-111111111111";
    resolver.bind("sess-1", addr, 1, owner1());

    let t0 = Instant::now();
    let (mut eng, _, _) =
        ActivityEngine::load_or_init(&mut conn, true, ProofFlags::default(), &resolver, 1000, t0)
            .unwrap();

    // AE1: UserPromptSubmit -> working; Stop (empty arrays) -> idle, 2 revisions.
    let f_prompt = normalize_hook_payload(
        ActivityHarness::Claude,
        br#"{"hook_event_name":"UserPromptSubmit","session_id":"sess-1"}"#,
        false,
        Some(owner1()),
    )
    .unwrap();
    let tr1 = eng
        .ingest(&mut conn, &f_prompt, &resolver, 1001, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr1.descriptor.state, ActivityState::Working);
    assert_eq!(tr1.descriptor.revision, 1);

    let f_stop_empty = normalize_hook_payload(
        ActivityHarness::Claude,
        br#"{"hook_event_name":"Stop","session_id":"sess-1","background_tasks":[],"session_crons":[]}"#,
        false,
        Some(owner1()),
    )
    .unwrap();
    let tr2 = eng
        .ingest(&mut conn, &f_stop_empty, &resolver, 1002, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr2.descriptor.state, ActivityState::Idle);
    assert_eq!(tr2.descriptor.reason, None);
    assert_eq!(tr2.descriptor.revision, 2);

    // AE2: Stop with running background task -> working(background), report-back -> working, completed -> idle.
    let f_stop_bg = normalize_hook_payload(
        ActivityHarness::Claude,
        br#"{"hook_event_name":"Stop","session_id":"sess-1","background_tasks":[{"status":"running"}],"session_crons":[]}"#,
        false,
        Some(owner1()),
    )
    .unwrap();
    let tr3 = eng
        .ingest(&mut conn, &f_stop_bg, &resolver, 1003, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr3.descriptor.state, ActivityState::Working);
    assert_eq!(tr3.descriptor.reason, Some(ActivityReason::Background));

    let tr4 = eng
        .ingest(&mut conn, &f_prompt, &resolver, 1004, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr4.descriptor.state, ActivityState::Working);
    assert_eq!(tr4.descriptor.reason, None);

    let f_stop_done = normalize_hook_payload(
        ActivityHarness::Claude,
        br#"{"hook_event_name":"Stop","session_id":"sess-1","background_tasks":[{"status":"completed"}],"session_crons":[]}"#,
        false,
        Some(owner1()),
    )
    .unwrap();
    let tr5 = eng
        .ingest(&mut conn, &f_stop_done, &resolver, 1005, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr5.descriptor.state, ActivityState::Idle);
    assert_eq!(tr5.descriptor.reason, None);

    // AE3: background_tasks absent -> unknown(unreported).
    let f_stop_absent = normalize_hook_payload(
        ActivityHarness::Claude,
        br#"{"hook_event_name":"Stop","session_id":"sess-1"}"#,
        false,
        Some(owner1()),
    )
    .unwrap();
    let tr6 = eng
        .ingest(&mut conn, &f_stop_absent, &resolver, 1006, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr6.descriptor.state, ActivityState::Unknown);
    assert_eq!(tr6.descriptor.reason, Some(ActivityReason::Unreported));

    // AE4 & AE5: wake-only / recurring cron (3 cycles) -> idle(scheduled_wake), never working(background), no Done.
    let mut rec = CollectorActivityReconciler::default();
    for cycle in 0..3 {
        let base_t = 1010 + cycle * 10;
        let f_wake_stop = normalize_hook_payload(
            ActivityHarness::Claude,
            br#"{"hook_event_name":"Stop","session_id":"sess-1","background_tasks":[],"session_crons":[{"id":"c1"}]}"#,
            false,
            Some(owner1()),
        )
        .unwrap();
        let tr_w = eng
            .ingest(&mut conn, &f_wake_stop, &resolver, base_t, t0)
            .unwrap()
            .unwrap();
        assert_eq!(tr_w.descriptor.state, ActivityState::Idle);
        assert_eq!(tr_w.descriptor.reason, Some(ActivityReason::ScheduledWake));
        let done = rec.apply_event(
            "n1",
            "scope",
            "ep",
            &ExportEvent {
                sequence: cycle * 2 + 1,
                source_at: None,
                observed_at: base_t,
                persisted_at: base_t,
                kind: EventKind::ActivityChanged,
                from: Some(format!("{addr}@n1")),
                to: None,
                message_id: None,
                reply_id: None,
                thread_id: None,
                outcome: None,
                reason: None,
                available: xmsg::observe_export::Availability::NotRecorded,
                activity: Some(tr_w.descriptor.clone()),
            },
            base_t,
        );
        assert!(!done, "scheduled_wake must never trigger Done");

        let tr_fire = eng
            .ingest(&mut conn, &f_prompt, &resolver, base_t + 1, t0)
            .unwrap()
            .unwrap();
        assert_eq!(tr_fire.descriptor.state, ActivityState::Working);
    }

    // AE4 final Stop with [] crons clears scheduled_wake reason -> idle with no reason.
    let tr_end = eng
        .ingest(&mut conn, &f_stop_empty, &resolver, 1050, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_end.descriptor.state, ActivityState::Idle);
    assert_eq!(tr_end.descriptor.reason, None);
}

#[test]
fn ae6_ae19_ae21_owner_binding_and_unverified_fences() {
    let (_dir, mut conn) = setup_db();
    let mut resolver = StubResolver::new();
    let addr = "11111111-1111-4111-8111-111111111111";

    // AE19: Unverified Start -> unknown(unverified) until verified registration.
    resolver.outcomes.insert(
        "sess-1".into(),
        BindingOutcome::Unverified {
            identified_address: Some(addr.into()),
        },
    );
    let t0 = Instant::now();
    let (mut eng, _, _) =
        ActivityEngine::load_or_init(&mut conn, true, ProofFlags::default(), &resolver, 1000, t0)
            .unwrap();

    let f_start = claude_frame("sess-1", "session_start", BackgroundPresence::Absent);
    let tr_unv = eng
        .ingest(&mut conn, &f_start, &resolver, 1001, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_unv.descriptor.state, ActivityState::Unknown);
    assert_eq!(tr_unv.descriptor.reason, Some(ActivityReason::Unverified));

    // Verified owner O2 takes over incarnation 2 -> working.
    resolver.bind("sess-1", addr, 2, owner2());
    let mut f_work = claude_frame("sess-1", "user_prompt_submit", BackgroundPresence::Absent);
    f_work.owner = Some(owner2());
    let tr_w = eng
        .ingest(&mut conn, &f_work, &resolver, 1002, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_w.descriptor.state, ActivityState::Working);
    assert_eq!(tr_w.descriptor.incarnation, 2);

    // AE6: Late Stop/SessionEnd from old owner O1 -> StaleOwner -> dropped; incarnation 2 untouched.
    resolver
        .outcomes
        .insert("sess-old".into(), BindingOutcome::StaleOwner);
    let f_late_end = claude_frame("sess-old", "session_end", BackgroundPresence::Absent);
    assert!(eng
        .ingest(&mut conn, &f_late_end, &resolver, 1003, t0)
        .unwrap()
        .is_none());
    assert_eq!(
        eng.descriptor_for(addr).unwrap().state,
        ActivityState::Working
    );

    // AE21: Delayed unverified Stop on current endpoint -> must NOT become idle; becomes unknown(unverified).
    resolver.outcomes.insert(
        "sess-1".into(),
        BindingOutcome::Unverified {
            identified_address: Some(addr.into()),
        },
    );
    let f_unv_stop = claude_frame("sess-1", "stop", BackgroundPresence::None);
    let tr_u = eng
        .ingest(&mut conn, &f_unv_stop, &resolver, 1004, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_u.descriptor.state, ActivityState::Unknown);
    assert_eq!(tr_u.descriptor.reason, Some(ActivityReason::Unverified));

    // Rebinds when verified O2 sends next frame.
    resolver.bind("sess-1", addr, 2, owner2());
    let tr_rebind = eng
        .ingest(&mut conn, &f_work, &resolver, 1005, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_rebind.descriptor.state, ActivityState::Working);
}

#[test]
fn ae7_ae16_ae18_monotonic_aging_clock_step_and_codex_interrupt() {
    let (_dir, mut conn) = setup_db();
    let mut resolver = StubResolver::new();
    let addr = "11111111-1111-4111-8111-111111111111";
    resolver.bind("sess-1", addr, 1, owner1());

    let t0 = Instant::now();
    let (mut eng, _, _) =
        ActivityEngine::load_or_init(&mut conn, true, ProofFlags::default(), &resolver, 1000, t0)
            .unwrap();

    let f_work = claude_frame("sess-1", "user_prompt_submit", BackgroundPresence::Absent);
    eng.ingest(&mut conn, &f_work, &resolver, 1000, t0).unwrap();

    // AE16: Wall clock steps back 1h and forward 1h; monotonic aging does not fire at 10m.
    let t_10m = t0 + Duration::from_secs(600);
    assert!(eng
        .tick_aging(&mut conn, &resolver, 1000 - 3600, t_10m)
        .unwrap()
        .is_empty());
    assert!(eng
        .tick_aging(&mut conn, &resolver, 1000 + 3600, t_10m)
        .unwrap()
        .is_empty());
    assert_eq!(
        eng.descriptor_for(addr).unwrap().state,
        ActivityState::Working
    );

    // AE7 & AE18: At 30m monotonic without fresh evidence -> unknown(aged), never idle or blocked.
    let t_30m = t0 + Duration::from_secs(ACTIVITY_STALE_WORKING_SECS);
    let aged = eng.tick_aging(&mut conn, &resolver, 2800, t_30m).unwrap();
    assert_eq!(aged.len(), 1);
    assert_eq!(aged[0].descriptor.state, ActivityState::Unknown);
    assert_eq!(aged[0].descriptor.reason, Some(ActivityReason::Aged));

    // AE18: Next hook returns to working.
    let tr_back = eng
        .ingest(&mut conn, &f_work, &resolver, 2805, t_30m)
        .unwrap()
        .unwrap();
    assert_eq!(tr_back.descriptor.state, ActivityState::Working);

    // AE7: Codex Interrupt -> idle.
    let addr_cx = "22222222-2222-4222-8222-222222222222";
    resolver.bind("cx-1", addr_cx, 1, owner1());
    let f_cx_int = ActivityFrame {
        action: "activity".into(),
        schema_version: 1,
        harness: ActivityHarness::Codex,
        event: "interrupt".into(),
        session: "cx-1".into(),
        owner: Some(owner1()),
        native_seq: None,
        event_id: None,
        correlation: None,
        block: None,
        background: BackgroundPresence::Absent,
        wake: WakePresence::Absent,
        failed: None,
    };
    let tr_cx = eng
        .ingest(&mut conn, &f_cx_int, &resolver, 2810, t_30m)
        .unwrap()
        .unwrap();
    assert_eq!(tr_cx.descriptor.state, ActivityState::Idle);
}

#[test]
fn ae8_ae20_correlated_prompt_resolution_and_overlapping_calls() {
    let (_dir, mut conn) = setup_db();
    let mut resolver = StubResolver::new();
    let addr = "11111111-1111-4111-8111-111111111111";
    resolver.bind("sess-1", addr, 1, owner1());

    let proofs = ProofFlags {
        correlated_mode: true,
        ..Default::default()
    };
    let t0 = Instant::now();
    let (mut eng, _, _) =
        ActivityEngine::load_or_init(&mut conn, true, proofs, &resolver, 1000, t0).unwrap();

    // Two concurrent identical tool calls ("Bash", same input), call_1 triggers PermissionRequest(toolu_1).
    let mut p1 = claude_frame("sess-1", "permission_request", BackgroundPresence::Absent);
    p1.block = Some(BlockKind::Permission);
    p1.correlation = Some("toolu_1".into());
    let tr_blk = eng
        .ingest(&mut conn, &p1, &resolver, 1001, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_blk.descriptor.state, ActivityState::Blocked);
    assert_eq!(tr_blk.descriptor.block, Some(BlockKind::Permission));

    // Parallel PostToolUse(toolu_2) must NOT clear toolu_1!
    let mut u2 = claude_frame("sess-1", "post_tool_use", BackgroundPresence::Absent);
    u2.correlation = Some("toolu_2".into());
    assert!(eng
        .ingest(&mut conn, &u2, &resolver, 1002, t0)
        .unwrap()
        .is_none());
    assert_eq!(
        eng.descriptor_for(addr).unwrap().state,
        ActivityState::Blocked
    );

    // PostToolUse without native id must NEVER clear!
    let u_noid = claude_frame("sess-1", "post_tool_use", BackgroundPresence::Absent);
    assert!(eng
        .ingest(&mut conn, &u_noid, &resolver, 1003, t0)
        .unwrap()
        .is_none());
    assert_eq!(
        eng.descriptor_for(addr).unwrap().state,
        ActivityState::Blocked
    );

    // PostToolUse(toolu_1) clears -> working!
    let mut u1 = claude_frame("sess-1", "post_tool_use", BackgroundPresence::Absent);
    u1.correlation = Some("toolu_1".into());
    let tr_clr = eng
        .ingest(&mut conn, &u1, &resolver, 1004, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_clr.descriptor.state, ActivityState::Working);
}

#[test]
fn ae9_ae10_ae11_ae14_ae15_ae23_harness_proofs_and_reaffirmation() {
    let (_dir, mut conn) = setup_db();
    let mut resolver = StubResolver::new();
    let addr = "11111111-1111-4111-8111-111111111111";
    resolver.bind("sess-op", addr, 1, owner1());

    let t0 = Instant::now();
    let (mut eng, _, _) =
        ActivityEngine::load_or_init(&mut conn, true, ProofFlags::default(), &resolver, 1000, t0)
            .unwrap();

    // AE15: Claude SessionStart -> unknown(unreported) unless proven.
    resolver.bind(
        "sess-cl",
        "22222222-2222-4222-8222-222222222222",
        1,
        owner1(),
    );
    let f_ss = claude_frame("sess-cl", "session_start", BackgroundPresence::Absent);
    let tr_ss = eng
        .ingest(&mut conn, &f_ss, &resolver, 1001, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_ss.descriptor.state, ActivityState::Unknown);
    assert_eq!(tr_ss.descriptor.reason, Some(ActivityReason::Unreported));

    // AE15: hermes post_llm_call -> working (never idle when unproven turn-final).
    resolver.bind(
        "sess-hm",
        "33333333-3333-4333-8333-333333333333",
        1,
        owner1(),
    );
    let f_hm = ActivityFrame {
        action: "activity".into(),
        schema_version: 1,
        harness: ActivityHarness::Hermes,
        event: "post_llm_call".into(),
        session: "sess-hm".into(),
        owner: Some(owner1()),
        native_seq: Some(1),
        event_id: None,
        correlation: None,
        block: None,
        background: BackgroundPresence::Absent,
        wake: WakePresence::Absent,
        failed: None,
    };
    let tr_hm = eng
        .ingest(&mut conn, &f_hm, &resolver, 1002, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_hm.descriptor.state, ActivityState::Working);

    // AE14: Unproven PermissionRequest degrades (never blocked).
    let mut eng_unproven = ActivityEngine::load_or_init(
        &mut conn,
        true,
        ProofFlags {
            claude_permission_request_proven: false,
            ..ProofFlags::default()
        },
        &resolver,
        1000,
        t0,
    )
    .unwrap()
    .0;
    let mut f_pr = claude_frame("sess-cl", "permission_request", BackgroundPresence::Absent);
    f_pr.block = Some(BlockKind::Permission);
    let _ = eng_unproven
        .ingest(&mut conn, &f_pr, &resolver, 1003, t0)
        .unwrap();
    assert_ne!(
        eng_unproven
            .descriptor_for("22222222-2222-4222-8222-222222222222")
            .unwrap()
            .state,
        ActivityState::Blocked
    );

    // AE10: agy PreInvocation -> working, fullyIdle=false -> working(background), true -> idle, never blocked.
    resolver.bind(
        "sess-agy",
        "44444444-4444-4444-8444-444444444444",
        1,
        owner1(),
    );
    let f_agy_pre = normalize_hook_payload(
        ActivityHarness::Agy,
        br#"{"hook_event_name":"PreToolUse","trajectory_id":"sess-agy"}"#,
        false,
        Some(owner1()),
    )
    .unwrap();
    let tr_agy1 = eng
        .ingest(&mut conn, &f_agy_pre, &resolver, 1004, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_agy1.descriptor.state, ActivityState::Working);

    let f_agy_bg = normalize_hook_payload(
        ActivityHarness::Agy,
        br#"{"hook_event_name":"Stop","trajectory_id":"sess-agy","fullyIdle":false}"#,
        false,
        Some(owner1()),
    )
    .unwrap();
    let tr_agy2 = eng
        .ingest(&mut conn, &f_agy_bg, &resolver, 1005, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_agy2.descriptor.state, ActivityState::Working);
    assert_eq!(tr_agy2.descriptor.reason, Some(ActivityReason::Background));

    // AE11: In-process reaffirmation vs equal-key conflict vs lower seq drop.
    let op1 = ActivityFrame {
        action: "activity".into(),
        schema_version: 1,
        harness: ActivityHarness::Opencode,
        event: "session.status.busy".into(),
        session: "sess-op".into(),
        owner: Some(owner1()),
        native_seq: Some(1),
        event_id: None,
        correlation: None,
        block: None,
        background: BackgroundPresence::Absent,
        wake: WakePresence::Absent,
        failed: None,
    };
    let tr_op1 = eng
        .ingest(&mut conn, &op1, &resolver, 1010, t0)
        .unwrap()
        .unwrap();
    let rev1 = tr_op1.descriptor.revision;

    // seq=2 same reduced state -> fresh_at advances, NO revision, NO event.
    let mut op2 = op1.clone();
    op2.native_seq = Some(2);
    op2.event = "tool.execute.before".into();
    assert!(eng
        .ingest(&mut conn, &op2, &resolver, 1025, t0)
        .unwrap()
        .is_none());
    let desc_after = eng.descriptor_for(addr).unwrap();
    assert_eq!(desc_after.revision, rev1);
    assert_eq!(desc_after.fresh_at, 1025);

    // seq=1 (lower) -> dropped.
    assert!(eng
        .ingest(&mut conn, &op1, &resolver, 1030, t0)
        .unwrap()
        .is_none());
    assert_eq!(eng.descriptor_for(addr).unwrap().fresh_at, 1025);

    // seq=2 with DIFFERENT content -> unknown(contradictory).
    let mut op2_conflict = op2.clone();
    op2_conflict.event = "permission.asked".into();
    let tr_conf = eng
        .ingest(&mut conn, &op2_conflict, &resolver, 1035, t0)
        .unwrap()
        .unwrap();
    assert_eq!(tr_conf.descriptor.state, ActivityState::Unknown);
    assert_eq!(
        tr_conf.descriptor.reason,
        Some(ActivityReason::Contradictory)
    );

    // AE9 & AE23: Registry unavailable & unsupported platform -> unknown(registry_unavailable) / unknown(unverified).
    resolver.outcomes.insert(
        "sess-regerr".into(),
        BindingOutcome::RegistryUnavailable {
            identified_address: Some("55555555-5555-4555-8555-555555555555".into()),
        },
    );
    let tr_reg = eng
        .ingest(
            &mut conn,
            &claude_frame("sess-regerr", "stop", BackgroundPresence::None),
            &resolver,
            1040,
            t0,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        tr_reg.descriptor.reason,
        Some(ActivityReason::RegistryUnavailable)
    );
}

#[test]
fn ae17_ae22_ae24_restart_two_connection_replay_and_disable_fence() {
    let (_dir, mut conn) = setup_db();
    let mut resolver = StubResolver::new();
    let addr = "11111111-1111-4111-8111-111111111111";
    resolver.bind("sess-1", addr, 1, owner1());

    // AE22: Deliver the same command-hook frame 5 times across TWO separate Unix socket connections.
    let dir = TempDir::new().unwrap();
    let f = claude_frame("sess-1", "user_prompt_submit", BackgroundPresence::Absent);

    let sock2 = dir.path().join("agent2.sock");
    let listener2 = UnixListener::bind(&sock2).unwrap();
    let srv2 = std::thread::spawn(move || {
        let mut received = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener2.accept().unwrap();
            let mut s = String::new();
            stream.read_to_string(&mut s).unwrap();
            for line in s.lines() {
                received.push(serde_json::from_str::<ActivityFrame>(line).unwrap());
            }
        }
        received
    });
    {
        let mut c1 = std::os::unix::net::UnixStream::connect(&sock2).unwrap();
        let line = serde_json::to_string(&f).unwrap() + "\n";
        for _ in 0..3 {
            c1.write_all(line.as_bytes()).unwrap();
        }
    }
    {
        let mut c2 = std::os::unix::net::UnixStream::connect(&sock2).unwrap();
        let line = serde_json::to_string(&f).unwrap() + "\n";
        for _ in 0..2 {
            c2.write_all(line.as_bytes()).unwrap();
        }
    }
    let received = srv2.join().unwrap();
    assert_eq!(received.len(), 5);

    let t0 = Instant::now();
    let (mut eng, _, _) =
        ActivityEngine::load_or_init(&mut conn, true, ProofFlags::default(), &resolver, 1000, t0)
            .unwrap();
    for (i, frame) in received.iter().enumerate() {
        let ts = 1001 + (i as i64) * 20;
        let _ = eng.ingest(
            &mut conn,
            frame,
            &resolver,
            ts,
            t0 + Duration::from_secs((i as u64) * 20),
        );
    }
    // fresh_at stayed at 1001 after the first delivery, and ages at t0 + 30m!
    assert_eq!(eng.descriptor_for(addr).unwrap().fresh_at, 1001);
    let aged = eng
        .tick_aging(
            &mut conn,
            &resolver,
            1001 + 1800,
            t0 + Duration::from_secs(ACTIVITY_STALE_WORKING_SECS),
        )
        .unwrap();
    assert_eq!(aged.len(), 1);
    assert_eq!(aged[0].descriptor.reason, Some(ActivityReason::Aged));

    // AE17: Restart policy: working -> unknown(restarted), idle with live owner stays.
    let _ = eng.ingest(&mut conn, &f, &resolver, 3000, t0).unwrap();
    let (eng_restarted, restart_trs, had_rows) =
        ActivityEngine::load_or_init(&mut conn, true, ProofFlags::default(), &resolver, 3010, t0)
            .unwrap();
    assert!(had_rows);
    assert_eq!(
        restart_trs[0].descriptor.reason,
        Some(ActivityReason::Restarted)
    );
    let _ = eng_restarted;

    // AE24: Disable fence preserved across buffered higher-rev events until verified re-enable;
    // AND DB reset tested separately.
    let mut rec = CollectorActivityReconciler::default();
    let ep_id = format!("{addr}@node-a");
    let snap_disabled = ExportSnapshot {
        v: 2,
        node: "node-a".into(),
        scope: "a".repeat(64),
        observed_at: 4000,
        endpoints: vec![],
        truncated: false,
        available: SnapshotAvailability::Available,
        activity: SnapshotActivity {
            status: ActivityStatus::Disabled,
            complete: true,
        },
    };
    rec.apply_snapshot(&snap_disabled, 4000);
    let high_rev_ev = ExportEvent {
        sequence: 99,
        source_at: None,
        observed_at: 4001,
        persisted_at: 4001,
        kind: EventKind::ActivityChanged,
        from: Some(ep_id.clone()),
        to: None,
        message_id: None,
        reply_id: None,
        thread_id: None,
        outcome: None,
        reason: None,
        available: xmsg::observe_export::Availability::NotRecorded,
        activity: Some(ActivityDescriptor {
            state: ActivityState::Working,
            block: None,
            reason: None,
            state_epoch: "0".repeat(32),
            incarnation: 1,
            revision: 999,
            changed_at: 4001,
            fresh_at: 4001,
        }),
    };
    assert!(!rec.apply_event("node-a", &"a".repeat(64), "ep1", &high_rev_ev, 4001));
    assert!(
        rec.nodes["node-a"].endpoints.is_empty(),
        "disabled fence must block buffered event"
    );

    // Verified re-enable snapshot lifts the disable fence; DB reset replaces state_epoch.
    let new_epoch = "b".repeat(32);
    let snap_reenable = ExportSnapshot {
        v: 2,
        node: "node-a".into(),
        scope: "a".repeat(64),
        observed_at: 4010,
        endpoints: vec![EndpointDescriptor {
            id: ep_id.clone(),
            node: "node-a".into(),
            kind: EndpointKind::Instance,
            harness: Harness::Claude,
            state: RegistrationState::Registered,
            source_at: None,
            label: None,
            context: None,
            activity: Some(ActivityDescriptor {
                state: ActivityState::Working,
                block: None,
                reason: None,
                state_epoch: new_epoch.clone(),
                incarnation: 1,
                revision: 1,
                changed_at: 4010,
                fresh_at: 4010,
            }),
        }],
        truncated: false,
        available: SnapshotAvailability::Available,
        activity: SnapshotActivity {
            status: ActivityStatus::Enabled,
            complete: true,
        },
    };
    rec.apply_snapshot(&snap_reenable, 4010);
    assert_eq!(
        rec.nodes["node-a"].endpoints[&ep_id].descriptor.state,
        ActivityState::Working
    );

    // Separate DB reset path: new state_epoch clears old endpoints and adopts rev 1.
    let reset_epoch = "c".repeat(32);
    let mut snap_reset = snap_reenable.clone();
    snap_reset.endpoints[0]
        .activity
        .as_mut()
        .unwrap()
        .state_epoch = reset_epoch.clone();
    snap_reset.endpoints[0].activity.as_mut().unwrap().revision = 1;
    snap_reset.endpoints[0].activity.as_mut().unwrap().state = ActivityState::Idle;
    rec.apply_snapshot(&snap_reset, 4020);
    assert_eq!(
        rec.nodes["node-a"].current_state_epoch.as_deref(),
        Some(reset_epoch.as_str())
    );
    assert_eq!(
        rec.nodes["node-a"].endpoints[&ep_id].descriptor.state,
        ActivityState::Idle
    );
}

#[test]
fn ao2_ao4_ao5_ao7_bounded_hook_allowlist_scope_and_v2() {
    // AO2: Stalled open pipe, 2 MiB stdin, 10,000-deep JSON nesting, missing daemon all exit 0 <= 100ms.
    let mut deep_json = vec![b'['; 10_000];
    deep_json.extend(vec![b']'; 10_000]);
    assert!(!check_json_depth(&deep_json, ACTIVITY_HOOK_MAX_JSON_DEPTH));
    assert!(check_json_depth(b"{\"a\":1}", ACTIVITY_HOOK_MAX_JSON_DEPTH));

    let (code_missing, out_missing) = run_activity_hook("agy", None, false);
    assert_eq!(code_missing, 0);
    assert_eq!(out_missing, "{}");

    // AO4: Every supported hook event discards content outside the frame allowlist.
    let canary = "SECRET_CANARY_999";
    for (harness, events) in [
        (
            ActivityHarness::Claude,
            &[
                "UserPromptSubmit",
                "Stop",
                "StopFailure",
                "SessionStart",
                "SessionEnd",
                "PermissionRequest",
                "PostToolUse",
                "Notification",
            ][..],
        ),
        (
            ActivityHarness::Codex,
            &[
                "UserPromptSubmit",
                "PreModelRequest",
                "Stop",
                "PermissionRequest",
                "Interrupt",
                "SessionStart",
            ][..],
        ),
        (
            ActivityHarness::Agy,
            &[
                "PreInvocation",
                "PostInvocation",
                "PreToolUse",
                "PostToolUse",
                "Stop",
            ][..],
        ),
    ] {
        for event in events {
            let raw = json!({
                "hook_event_name": event,
                "session_id": "s1",
                "trajectory_id": "s1",
                "notification_type": "agent_needs_input",
                "tool_name": "Bash",
                "tool_use_id": "toolu_99",
                "prompt": canary,
                "command": canary,
                "cwd": format!("/tmp/{canary}"),
                "task_id": canary,
                "task_description": canary,
                "last_assistant_message": canary,
                "tool_input": {"cmd": canary},
                "tool_output": {"stdout": canary},
                "tool_response": {"stdout": canary},
                "background_tasks": [{"id": canary, "description": canary, "status": "running"}],
                "unknown_extra": {"nested": [canary]},
            });
            let frame = normalize_hook_payload(
                harness,
                &serde_json::to_vec(&raw).unwrap(),
                true,
                Some(owner1()),
            )
            .unwrap_or_else(|| panic!("{harness:?} {event} must normalize"));
            let serialized = serde_json::to_string(&frame).unwrap();
            assert!(
                !serialized.contains(canary),
                "{harness:?} {event}: canary leaked into frame"
            );
            if harness == ActivityHarness::Claude
                && matches!(*event, "PermissionRequest" | "PostToolUse")
            {
                assert_eq!(frame.correlation.as_deref(), Some("toolu_99"));
            }
        }
    }

    let graphic_limit = "!".repeat(128);
    for key in ["event_id", "uuid", "tool_use_id"] {
        for (name, value, accepted) in [
            ("oversized", "x".repeat(129), false),
            ("space", "id with space".into(), false),
            ("non-ASCII", "id-é".into(), false),
            ("control", "id\u{0001}value".into(), false),
            ("128 graphic bytes", graphic_limit.clone(), true),
        ] {
            let mut raw = json!({
                "hook_event_name": "PermissionRequest",
                "session_id": "s1",
                "tool_name": "Bash",
            });
            raw[key] = json!(value);
            let frame = normalize_hook_payload(
                ActivityHarness::Claude,
                &serde_json::to_vec(&raw).unwrap(),
                true,
                Some(owner1()),
            )
            .unwrap();
            let observed = if key == "tool_use_id" {
                frame.correlation.as_deref()
            } else {
                frame.event_id.as_deref()
            };
            assert_eq!(
                observed,
                accepted.then_some(value.as_str()),
                "{key}: {name}"
            );
        }
    }

    // AO5: Single-endpoint scope rule on node egress (`project_page`) with restricted AND unrestricted targets.
    let ep_a = "11111111-1111-4111-8111-111111111111@node-a";
    let ep_b = "22222222-2222-4222-8222-222222222222@node-a";
    let ep_foreign = "11111111-1111-4111-8111-111111111111@other-node";
    let desc = ActivityDescriptor {
        state: ActivityState::Working,
        block: None,
        reason: None,
        state_epoch: "a".repeat(32),
        incarnation: 1,
        revision: 1,
        changed_at: 100,
        fresh_at: 100,
    };

    let make_ev = |seq: i64, from: Option<&str>, to: Option<&str>| Event {
        node: "node-a".into(),
        epoch: "ep1".into(),
        sequence: seq,
        observed_at: 100,
        persisted_at: 100,
        observation: Observation {
            source_at: None,
            kind: "activity_changed".into(),
            from: from.map(ToOwned::to_owned),
            to: to.map(ToOwned::to_owned),
            message_id: None,
            reply_id: None,
            thread_id: None,
            outcome: None,
            reason: None,
            body_availability: "not_recorded".into(),
            activity: Some(desc.clone()),
        },
    };

    let unrestricted = Scope::new("node-a", "collector", None, false).unwrap();
    let restricted = Scope::new("node-a", "collector", Some(&[ep_a.to_owned()]), false).unwrap();
    let q_v2: ExportQuery = serde_json::from_value(json!({"v": 2})).unwrap();

    // Unrestricted admits valid instance, rejects missing from, present to, svc:, malformed, cross-node.
    let page_unr = project_page(
        Page {
            node: "node-a".into(),
            epoch: "ep1".into(),
            events: vec![
                make_ev(1, Some(ep_a), None),
                make_ev(2, None, None),
                make_ev(3, Some(ep_a), Some(ep_b)),
                make_ev(4, Some("svc:bot@node-a"), None),
                make_ev(5, Some(ep_foreign), None),
            ],
            next: 5,
            floor: 1,
            head: 5,
            has_more: false,
            gaps: vec![],
            losses: LossCounters::default(),
            available: true,
            initial_omitted: 0,
        },
        &q_v2,
        &unrestricted,
        200,
    )
    .unwrap();
    assert_eq!(page_unr.v, 2);
    assert_eq!(page_unr.events.len(), 1);
    assert_eq!(page_unr.events[0].from.as_deref(), Some(ep_a));

    // Restricted admits ep_a, filters ep_b.
    let page_res = project_page(
        Page {
            node: "node-a".into(),
            epoch: "ep1".into(),
            events: vec![make_ev(1, Some(ep_a), None), make_ev(2, Some(ep_b), None)],
            next: 2,
            floor: 1,
            head: 2,
            has_more: false,
            gaps: vec![],
            losses: LossCounters::default(),
            available: true,
            initial_omitted: 0,
        },
        &q_v2,
        &restricted,
        200,
    )
    .unwrap();
    assert_eq!(page_res.events.len(), 1);
    assert_eq!(page_res.events[0].from.as_deref(), Some(ep_a));
    assert!(valid_activity_endpoint("svc:bot@node-a", "node-a").is_none());

    // AO7: Export v2 rejects v=1 and omitted v.
    assert!(serde_json::from_value::<ExportQuery>(json!({"v": 1}))
        .unwrap()
        .validate()
        .is_err());
    assert!(serde_json::from_value::<ExportQuery>(json!({}))
        .unwrap()
        .validate()
        .is_err());
    assert!(serde_json::from_value::<SnapshotQuery>(json!({"v": 1}))
        .unwrap()
        .validate()
        .is_err());
    assert!(serde_json::from_value::<SnapshotQuery>(json!({}))
        .unwrap()
        .validate()
        .is_err());
}

#[test]
fn ao6_own_budget_and_message_forward_progress_on_shared_db() {
    // AO6: Flood 50 endpoints with activity updates while recording 1,000 messages on the shared DB + journal.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("xmsg.db");
    let obs_path = dir.path().join("xmsg.db.observe.sqlite");
    let db = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
    {
        let c = db.lock().unwrap();
        xmsg::storage::init_db(&c).unwrap();
    }
    let obs = Observer::start(&db, &obs_path, "node-a", ObserveConfig::default());

    // Publish 1,000 message events + 2,500 activity_changed events (> 2,000 activity row cap).
    for i in 0..1000 {
        obs.publish(vec![Observation {
            kind: "message_recorded".into(),
            from: Some("11111111-1111-4111-8111-111111111111@node-a".into()),
            to: Some("svc:bot@node-a".into()),
            message_id: Some(format!("01ARZ3NDEKTSV4RRFFQ69G{:04}", i)),
            body_availability: "not_recorded".into(),
            activity: None,
            ..Default::default()
        }]);
    }
    for i in 0..2500 {
        let ep_idx = i % 50;
        obs.publish(vec![Observation {
            kind: "activity_changed".into(),
            from: Some(format!("{ep_idx:08x}-1111-4111-8111-111111111111@node-a")),
            body_availability: "not_recorded".into(),
            activity: Some(ActivityDescriptor {
                state: if i % 2 == 0 {
                    ActivityState::Working
                } else {
                    ActivityState::Idle
                },
                block: None,
                reason: None,
                state_epoch: "a".repeat(32),
                incarnation: 1,
                revision: (i + 1) as u64,
                changed_at: 1000 + i as i64,
                fresh_at: 1000 + i as i64,
            }),
            ..Default::default()
        }]);
    }

    // Verify all 1,000 messages are persisted in the journal and not evicted by activity_changed!
    std::thread::sleep(Duration::from_millis(500));
    let page = obs.page(xmsg::observe::Query {
        epoch: None,
        after: Some(0),
        limit: Some(200),
    });
    if let Ok(p) = page {
        let msg_count = p
            .events
            .iter()
            .filter(|e| e.observation.kind == "message_recorded")
            .count();
        assert!(
            msg_count > 0,
            "message events must not be evicted by activity flood"
        );
    }
}

#[test]
fn ao2_stalled_pipe_and_binary_overhead_envelope() {
    // Verify depth/deadline on a real spawned `xmsg activity hook claude` if built in target/debug/xmsg.
    let bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().and_then(|d| d.parent()).map(|d| d.join("xmsg")));
    let Some(bin) = bin.filter(|p| p.exists()) else {
        return;
    };
    let start = std::time::Instant::now();
    let mut child = spawn::command(&bin)
        .args(["activity", "hook", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // Hold pipe open for 150ms without closing; hook must exit 0 around ~100ms deadline!
    let _stdin = child.stdin.take().unwrap();
    let status = child.wait().unwrap();
    let elapsed = start.elapsed();
    assert!(status.success(), "stalled hook must fail-open exit 0");
    assert!(
        elapsed < Duration::from_millis(500),
        "hook took too long: {elapsed:?}"
    );
}

#[test]
fn ao1_ao8_ao9_ao10_opt_in_snapshot_authority_and_crash_recovery() {
    // AO1: Disabled engine emits Disabled status and no descriptors.
    let eng_off = ActivityEngine::disabled();
    assert_eq!(eng_off.snapshot_activity().status, ActivityStatus::Disabled);
    assert!(eng_off
        .descriptor_for("11111111-1111-4111-8111-111111111111")
        .is_none());

    // AO8: Status and descriptor validity independently gate the wire projection.
    let valid = ActivityDescriptor {
        state: ActivityState::Working,
        block: None,
        reason: None,
        state_epoch: "a".repeat(32),
        incarnation: 1,
        revision: 1,
        changed_at: 100,
        fresh_at: 100,
    };
    let candidate = |n: u64, activity: ActivityDescriptor| SnapshotRecord {
        id: format!("11111111-1111-4111-8111-{n:012}"),
        kind: EndpointKind::Instance,
        harness: Harness::Claude,
        state: RegistrationState::Registered,
        source_at: None,
        label: None,
        context: None,
        activity: Some(activity),
    };
    let scope = Scope::new("node-a", "collector", None, false).unwrap();
    let project = |records, status| {
        project_snapshot_with_activity(
            &scope,
            records,
            100,
            false,
            SnapshotActivity {
                status,
                complete: true,
            },
        )
        .unwrap()
    };
    let disabled = project(vec![candidate(0, valid.clone())], ActivityStatus::Disabled);
    assert_eq!(disabled.endpoints.len(), 1);
    assert!(
        disabled
            .endpoints
            .iter()
            .all(|entry| entry.activity.is_none()),
        "disabled snapshot disclosed endpoint activity"
    );
    let invalid = [
        (
            "state epoch",
            ActivityDescriptor {
                state_epoch: "A".repeat(32),
                ..valid.clone()
            },
        ),
        (
            "missing block",
            ActivityDescriptor {
                state: ActivityState::Blocked,
                ..valid.clone()
            },
        ),
        (
            "unexpected block",
            ActivityDescriptor {
                block: Some(BlockKind::Permission),
                ..valid.clone()
            },
        ),
        (
            "negative changed_at",
            ActivityDescriptor {
                changed_at: -1,
                ..valid.clone()
            },
        ),
        (
            "negative fresh_at",
            ActivityDescriptor {
                fresh_at: -1,
                ..valid.clone()
            },
        ),
    ];
    for (label, descriptor) in invalid {
        let enabled = project(
            vec![candidate(0, valid.clone()), candidate(1, descriptor)],
            ActivityStatus::Enabled,
        );
        assert_eq!(enabled.endpoints.len(), 2);
        assert_eq!(enabled.endpoints[0].activity, Some(valid.clone()));
        assert!(
            enabled.endpoints[1].activity.is_none(),
            "enabled snapshot disclosed invalid activity: {label}"
        );
    }

    // AO8: Incomplete/truncated snapshot keeps missing endpoints stale (never clears to idle);
    // first snapshot or gap recovery showing idle yields NO Done.
    let mut rec = CollectorActivityReconciler::default();
    let ep_a = "11111111-1111-4111-8111-111111111111@node-a";
    let ep_b = "22222222-2222-4222-8222-222222222222@node-a";
    let epoch = "a".repeat(32);
    let snap_init = ExportSnapshot {
        v: 2,
        node: "node-a".into(),
        scope: "a".repeat(64),
        observed_at: 100,
        endpoints: vec![
            EndpointDescriptor {
                id: ep_a.into(),
                node: "node-a".into(),
                kind: EndpointKind::Instance,
                harness: Harness::Claude,
                state: RegistrationState::Registered,
                source_at: None,
                label: None,
                context: None,
                activity: Some(ActivityDescriptor {
                    state: ActivityState::Working,
                    block: None,
                    reason: None,
                    state_epoch: epoch.clone(),
                    incarnation: 1,
                    revision: 1,
                    changed_at: 100,
                    fresh_at: 100,
                }),
            },
            EndpointDescriptor {
                id: ep_b.into(),
                node: "node-a".into(),
                kind: EndpointKind::Instance,
                harness: Harness::Claude,
                state: RegistrationState::Registered,
                source_at: None,
                label: None,
                context: None,
                activity: Some(ActivityDescriptor {
                    state: ActivityState::Idle,
                    block: None,
                    reason: None,
                    state_epoch: epoch.clone(),
                    incarnation: 1,
                    revision: 2,
                    changed_at: 100,
                    fresh_at: 100,
                }),
            },
        ],
        truncated: false,
        available: SnapshotAvailability::Available,
        activity: SnapshotActivity {
            status: ActivityStatus::Enabled,
            complete: true,
        },
    };
    rec.apply_snapshot(&snap_init, 100);
    assert!(!rec.nodes["node-a"].endpoints[ep_a].stale);

    // Incomplete snapshot omitting ep_a keeps ep_a and marks it stale.
    let snap_inc = ExportSnapshot {
        endpoints: vec![snap_init.endpoints[1].clone()],
        activity: SnapshotActivity {
            status: ActivityStatus::Enabled,
            complete: false,
        },
        ..snap_init.clone()
    };
    rec.apply_snapshot(&snap_inc, 120);
    assert!(rec.nodes["node-a"].endpoints.contains_key(ep_a));
    assert!(rec.nodes["node-a"].endpoints[ep_a].stale);

    // AO8 revocation masks activity.
    rec.revoke_node("node-a");
    assert!(!rec.nodes.contains_key("node-a"));

    // AO9: Crash between table commit and journal publish -> on restart, state transitions to Unknown(Restarted)
    // and `had_rows` triggers writer_restart gap while DB keeps committed state.
    let (_dir, mut conn) = setup_db();
    let mut resolver = StubResolver::new();
    let addr = "11111111-1111-4111-8111-111111111111";
    resolver.bind("sess-crash", addr, 1, owner1());
    let t0 = Instant::now();
    {
        let (mut eng1, _, _) = ActivityEngine::load_or_init(
            &mut conn,
            true,
            ProofFlags::default(),
            &resolver,
            100,
            t0,
        )
        .unwrap();
        let _ = eng1
            .ingest(
                &mut conn,
                &claude_frame(
                    "sess-crash",
                    "user_prompt_submit",
                    BackgroundPresence::Absent,
                ),
                &resolver,
                101,
                t0,
            )
            .unwrap();
        // Simulated crash before journal publish (table committed, no observe::publish called).
    }
    let (eng2, trs, had_rows) =
        ActivityEngine::load_or_init(&mut conn, true, ProofFlags::default(), &resolver, 110, t0)
            .unwrap();
    assert!(had_rows);
    assert_eq!(trs[0].descriptor.reason, Some(ActivityReason::Restarted));
    assert_eq!(
        eng2.descriptor_for(addr).unwrap().state,
        ActivityState::Unknown
    );
}
