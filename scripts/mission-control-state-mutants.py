#!/usr/bin/env python3
"""Run exact Mission Control state and carrier oracles against isolated source edits."""

import argparse
import os
import runpy
import shutil
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATCH = runpy.run_path(str(ROOT / "scripts/mission-control-wire-mutants.py"))["run"]

COMMAND = "src/mission_control/command.rs"
STORE = "src/mission_control/command_store.rs"
AUTHORITY = "src/mission_control/authority.rs"
WIRE = "src/mission_control/command_wire.rs"
WEBSOCKET = "src/mission_control/websocket.rs"
CLIENT = "src/mission_control_client/command_review.rs"
STATE_TEST = "mission_control::command::tests::"
STORE_TEST = "mission_control::command_store::tests::"
TRANSPORT_TEST = "mission_control::command_transport_tests::"
PRIORITY_TEST = "mission_control::command_priority_tests::"
CLIENT_TEST = "mission_control_client::command_review::tests::"

FRESH_AUTH = """        let checked = self
            .command_entitled(&state, &record.record_id, &request)
            .map_err(|_| "denied")
            .and_then(|_| self.commands.binding(&request.target));"""
EXISTS = """                if let Some(row) =
                    store::reservation(&state.conn, &record.principal, &request.request_id)"""
FRESH_BINDING = """                if let Err(code) = self.commands.binding(&request.target) {
                    return if code == "target_changed" {
                        refused(
                            &self.commands,
                            id,
                            &request.request_id,
                            code,
                            at,
                            Some(request.clone()),
                        )
                    } else {
                        Err(Refusal::NOT_FOUND)
                    };
                }
"""
AGE_CHECK = """                let requested = request.requested_at as i64;
                if requested < at.saturating_sub(self.config.request_max_age_secs as i64 * 1000)
                    || requested > at.saturating_add(self.config.clock_skew_secs as i64 * 1000)
                {
                    return refused(
                        &self.commands,
                        id,
                        &request.request_id,
                        "expired_request",
                        at,
                        Some(request.clone()),
                    );
                }
"""
CAS_TEST = "sc2_sc4_one_submit_owner_for_same_and_independent_intents"
CLOCK_TEST = "sc15_unchanged_retry_uses_reservation_before_age_and_expires_after_compaction"
COMPACT_TEST = "compaction_keeps_live_rows_and_respects_both_final_timestamps"
FRESH_TEST = "oq13_exact_authority_checks_live_bindings_only_for_fresh_work"
SAME_NODE_TEST = "oq13_same_node_mismatch_and_ambiguity_do_not_mint_intents"
DELEGATED_BOUNDS = TRANSPORT_TEST + "sc11_delegated_command_bounds_refuse_without_submission"
HOLDER_RECOVERY = TRANSPORT_TEST + "sc10_sc16_command_only_holder_recovers_without_an_owner_session"
NARROWED_INCUMBENT = TRANSPORT_TEST + "sc16_narrowed_incumbent_denies_prepare_and_commit_without_consuming"
CRASH_SETTLEMENT = """            let result = store::transition(
                &state.conn,"""
LOOKUP_ROW = """            CommandRequest::Lookup { id, request_id } => {
                state.command_record(&record.record_id)?;
                let row = store::reservation(&state.conn, &record.principal, &request_id)"""


def edit(file, old, new):
    return file, old, new


POST_CAS_REWRITE = edit(
    COMMAND,
    CRASH_SETTLEMENT,
    """            let (to, code) = if state.command_record(&row.record_id).is_err() {
                (Phase::Refused, Some("denied"))
            } else {
                (to, code)
            };
""" + CRASH_SETTLEMENT,
)


CASES = {
    "m-sc1-skip-fresh-authorization": (
        STATE_TEST + "sc1_revocation_is_ordered_by_the_submit_cas",
        'right: "denied"',
        (edit(COMMAND, FRESH_AUTH, "        let checked = self.commands.binding(&request.target);"),),
    ),
    "m-sc1b-revoke-after-cas-rewrites-settlement": (
        STATE_TEST + "sc1_revocation_is_ordered_by_the_submit_cas",
        "post-CAS revocation rewrote the outcome",
        (
            POST_CAS_REWRITE,
        ),
    ),
    "m-sc2-consume-after-executor-reply": (
        STATE_TEST + "sc2_in_flight_owner_recovers_after_intent_deadline",
        "in-flight owner lost receipt after intent TTL",
        (
            edit(
                COMMAND,
                """            if !store::insert_reservation(&tx, &row).map_err(store_error)?
                || !store::consume_intent(&tx, &hash).map_err(store_error)?
            {""",
                """            if !store::insert_reservation(&tx, &row).map_err(store_error)? {""",
            ),
            edit(
                COMMAND,
                "            self.spawn_command_double(row.clone(), request.clone(), slot);",
                "            self.spawn_command_double(row.clone(), request.clone(), slot, Some(hash));",
            ),
            edit(
                COMMAND,
                """        drop(slot);
        Ok(stored(id, &row, false, request))""",
                """        drop(slot);
        store::consume_intent(&state.conn, &hash).map_err(store_error)?;
        Ok(stored(id, &row, false, request))""",
            ),
            edit(
                COMMAND,
                '                        slot.take().expect("submit owns a slot"),',
                '                        slot.take().expect("submit owns a slot"),\n                        None,',
            ),
            edit(
                COMMAND,
                """        slot: WorkSlot,
    ) {""",
                """        slot: WorkSlot,
        deferred_hash: Option<[u8; 32]>,
    ) {""",
            ),
            edit(
                COMMAND,
                """            let result = store::transition(
                &state.conn,""",
                """            if let Some(hash) = deferred_hash {
                let _ = store::consume_intent(&state.conn, &hash);
            }
            let result = store::transition(
                &state.conn,""",
            ),
        ),
    ),
    "m-sc2b-same-intent-race-loser-invalid": (
        STATE_TEST + CAS_TEST,
        "matching race loser did not receive the incumbent receipt",
        (
            edit(
                COMMAND,
                """            let frozen = decode(&row.request_json)?;
            self.command_entitled(&state, &record.record_id, &frozen)?;
            if !binding.consumed""",
                """            let frozen = decode(&row.request_json)?;
            self.command_entitled(&state, &record.record_id, &frozen)?;
            if binding.consumed && matches!(row.state, Phase::Reserved | Phase::Submitting) {
                return refused(&self.commands, id, request_id, "intent_invalid", at, None);
            }
            if !binding.consumed""",
            ),
        ),
    ),
    "m-sc3-ignore-target-generation": (
        STATE_TEST + "sc3_each_generation_component_fences_a_prepared_intent",
        "generation check was lost before submit",
        (edit(COMMAND, "            if binding != target {", "            if false {"),),
    ),
    "m-sc4a-skip-commit-digest-check": (
        STATE_TEST + CAS_TEST,
        'assertion failed: replies.iter().any(|reply| reply.body["code"] == "conflict")',
        (edit(COMMAND, "            return if row.digest == digest {", "            return if true {"),),
    ),
    "m-sc4a-key-uses-request-id-alone": (
        STATE_TEST + "sc4_changed_prepare_conflicts_with_an_existing_reservation",
        "request ID collision incorrectly crossed principals",
        (
            edit(STORE, "    PRIMARY KEY (principal, request_id),", "    PRIMARY KEY (request_id),"),
            edit(STORE, "         ON CONFLICT(principal, request_id) DO NOTHING", "         ON CONFLICT(request_id) DO NOTHING"),
        ),
    ),
    "m-sc4b-repeated-prepare-returns-different-digest": (
        STATE_TEST + "sc4_changed_prepare_conflicts_with_an_existing_reservation",
        "changed prepare disclosed the incumbent receipt",
        (edit(COMMAND, "                    if row.digest == digest {", "                    if true {"),),
    ),
    "m-sc4c-include-digest-in-reservation-identity": (
        STATE_TEST + CAS_TEST,
        'assertion failed: replies.iter().any(|reply| reply.body["code"] == "conflict")',
        (
            edit(STORE, "    PRIMARY KEY (principal, request_id),", "    PRIMARY KEY (principal, request_id, digest),"),
            edit(STORE, "         ON CONFLICT(principal, request_id) DO NOTHING", "         ON CONFLICT(principal, request_id, digest) DO NOTHING"),
            edit(
                STORE,
                "#[derive(Clone, Copy, Debug)]\npub(super) struct Transition",
                """pub(super) fn reservation_with_digest(
    conn: &Connection,
    principal: &str,
    request_id: &str,
    digest: &str,
) -> Result<Option<Reservation>> {
    conn.query_row(
        "SELECT principal, record_id, request_id, request_json, digest, receipt_id, requested_at,
                state, code, at, held_at, pending_hold
         FROM command_reservations WHERE principal = ? AND request_id = ? AND digest = ?",
        params![principal, request_id, digest],
        reservation_row,
    )
    .optional()
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Transition""",
            ),
            edit(
                COMMAND,
                "        let incumbent =\n            store::reservation(&state.conn, &record.principal, request_id).map_err(store_error)?;",
                "        let incumbent = store::reservation_with_digest(&state.conn, &record.principal, request_id, digest).map_err(store_error)?;",
            ),
            edit(
                COMMAND,
                """        let row = store::reservation(&state.conn, &record.principal, request_id)
            .map_err(store_error)?
            .ok_or(Refusal::UNAVAILABLE)?;
        #[cfg(test)]
        if to == Phase::Submitting {""",
                """        let row = store::reservation_with_digest(&state.conn, &record.principal, request_id, &row.digest)
            .map_err(store_error)?
            .ok_or(Refusal::UNAVAILABLE)?;
        #[cfg(test)]
        if to == Phase::Submitting {""",
            ),
            edit(
                COMMAND,
                """        if !store::transition(
            &state.conn,
            &row.principal,
            &row.request_id,
            store::Transition {
                from: Phase::Reserved,
                to,
                code,
                now: at,
                held_at: (to == Phase::Held).then_some(at),
            },
        )
        .map_err(store_error)?
        {""",
                """        let changed = state.conn.execute(
            "UPDATE command_reservations SET state = ?, code = ?, at = ?, held_at = ?, pending_hold = 0
             WHERE principal = ? AND request_id = ? AND digest = ? AND state = 'reserved'",
            rusqlite::params![to.as_str(), code, at, (to == Phase::Held).then_some(at),
                row.principal, row.request_id, row.digest],
        ).map_err(store_error)?;
        if changed != 1 {""",
            ),
        ),
    ),
    "m-sc5-resend-commit-on-reconnect": (
        TRANSPORT_TEST + "sc5_private_client_recovers_a_real_collector_commit_after_response_loss",
        "reconnected client sent a commit instead of lookup",
        (
            edit(
                CLIENT,
                """        let mut socket = connect(origin, handle).await?;
        let lookup = json!({""",
                """        let mut socket = connect(origin, handle).await?;
        send(&mut socket, self.sent_commit.as_ref().unwrap()).await?;
        let lookup = json!({""",
            ),
        ),
    ),
    "m-sc6-send-ordinary-data-before-queued-receipts": (
        PRIORITY_TEST + "sc6_receipt_overtakes_data_or_closes_and_recovers",
        "a data or gap frame cannot overtake a final receipt",
        (
            edit(
                WEBSOCKET,
                "        for _ in 0..reader.issuer.config.receipt_lane_max {",
                "        for _ in 0..0 {",
            ),
        ),
    ),
    "m-sc7-prepare-from-blocked-observation": (
        "observe_collector::tests::mission_control_sc7_activity_never_prepares_a_command",
        "event caused intent before any prepare",
        (
            edit(
                COMMAND,
                "    pub(super) fn command_entitled(",
                """    #[cfg(test)]
    pub(super) fn preprepare_blocked_event(self: &Arc<Self>, record: &Record, payload: &str) -> Option<Reply> {
        let event: Value = serde_json::from_str(payload).ok()?;
        if event["type"] != "event" || event["delta"]["event"]["activity"]["block"] != "permission" {
            return None;
        }
        let fixture = self.commands.fixture.as_ref()?;
        let target = fixture.bindings.lock().ok()?.first()?.clone();
        let request: PreparedRequest = serde_json::from_value(json!({
            "request_id":"00000000000000000000000000000001",
            "requested_at":self.commands.now(),
            "verb":"send",
            "target":target,
            "params":{"text":"Fixture command"}
        })).ok()?;
        self.command(record, "ws-mutant", CommandRequest::Prepare { id: None, request }).ok()
    }

    pub(super) fn command_entitled(""",
            ),
            edit(
                WEBSOCKET,
                "        for _ in 0..reader.issuer.config.receipt_lane_max {",
                """        #[cfg(test)]
        if let Some(reply) = reader.issuer.preprepare_blocked_event(&reader.record, &payload) {
            send_command_push(socket, writer, reply).await?;
        }
        for _ in 0..reader.issuer.config.receipt_lane_max {""",
            ),
        ),
    ),
    "m-sc8-look-up-by-request-id-alone": (
        TRANSPORT_TEST + "sc8_lookup_is_reauthorized_and_read_only_past_the_ring",
        "right: 404",
        (
            edit(
                COMMAND,
                LOOKUP_ROW,
                """            CommandRequest::Lookup { id, request_id } => {
                state.command_record(&record.record_id)?;
                let owner: String = state.conn.query_row(
                    "SELECT principal FROM command_reservations WHERE request_id = ? LIMIT 1",
                    [&request_id],
                    |row| row.get(0),
                ).map_err(|_| Refusal::NOT_FOUND)?;
                let row = store::reservation(&state.conn, &owner, &request_id)""",
            ),
        ),
    ),
    "m-sc9-http-intent-ignores-record-binding": (
        TRANSPORT_TEST + "sc9_intents_are_bound_to_carrier_connection_and_credential_record",
        'right: "intent_invalid"',
        (
            edit(
                COMMAND,
                "                    && row.record_id == record.record_id",
                '                    && (carrier == "http" || row.record_id == record.record_id)',
            ),
        ),
    ),
    "m-sc9b-submit-latest-prepared-params": (
        TRANSPORT_TEST + "sc9_http_and_ws_share_initial_handoff_and_settled_lookup",
        "The later intent must not replace the original",
        (
            edit(
                COMMAND,
                "            self.spawn_command_double(row.clone(), request.clone(), slot);",
                """            let latest: String = state.conn.query_row(
                "SELECT request_json FROM command_intents
                 WHERE principal = ? AND request_id = ? ORDER BY rowid DESC LIMIT 1",
                rusqlite::params![record.principal, request_id],
                |row| row.get(0),
            ).map_err(store_error)?;
            let submitted = PreparedRequest {
                params: decode(&latest)?.params,
                ..request.clone()
            };
            self.spawn_command_double(row.clone(), submitted, slot);""",
            ),
        ),
    ),
    "m-sc9c-http-ignores-transport-binding": (
        TRANSPORT_TEST + "sc9_intents_are_bound_to_carrier_connection_and_credential_record",
        'right: "intent_invalid"',
        (edit(COMMAND, "                    && row.transport == carrier", '                    && (carrier == "http" || row.transport == carrier)'),),
    ),
    "m-sc10-require-the-delegating-owner-online": (
        HOLDER_RECOVERY,
        "right: 200",
        (
            edit(
                COMMAND,
                """                grant.expires_at > crate::storage::now_epoch_secs()
                    && grant.verbs.iter().any(|verb| verb == "send")""",
                """                let live_owner: bool = state.conn.query_row(
                    "SELECT EXISTS (SELECT 1 FROM records
                     WHERE json_extract(record, '$.principal') = ?
                       AND json_extract(record, '$.class') IN ('browser', 'native')
                       AND NOT json_extract(record, '$.revoked'))",
                    [record.on_behalf_of.as_deref()],
                    |row| row.get(0),
                ).unwrap_or(false);
                live_owner && grant.expires_at > crate::storage::now_epoch_secs()
                    && grant.verbs.iter().any(|verb| verb == "send")""",
            ),
        ),
    ),
    "m-sc11-delegated-target-matches-node-alone": (
        DELEGATED_BOUNDS,
        "right: 404",
        (edit(COMMAND, "                        allowed.node == target.node && allowed.endpoint == target.endpoint", "                        allowed.node == target.node"),),
    ),
    "m-sc11b-remove-production-delegated-admission-guard": (
        DELEGATED_BOUNDS,
        "right: 401",
        (edit(AUTHORITY, "        let delegated_disabled = record.class == Class::Delegated;", "        let delegated_disabled = false;"),),
    ),
    "m-sc12-submit-held-immediately": (
        STATE_TEST + "sc12_held_confirm_and_decline_each_settle_once",
        'right: "held"',
        (edit(COMMAND, "            Ok(()) if pending_hold => (Phase::Held, None),\n", ""),),
    ),
    "m-sc12b-confirm-an-expired-unswept-hold": (
        STATE_TEST + "sc12_held_confirm_and_decline_each_settle_once",
        "expired unswept reservation accepted confirmation",
        (
            edit(
                COMMAND,
                "        let (to, code) = if at >= deadline {",
                "        let (to, code) = if decision != HeldDecision::Confirm && at >= deadline {",
            ),
        ),
    ),
    "m-sc12c-revoke-after-confirm-rewrites-settlement": (
        STATE_TEST + "sc12_held_confirm_and_decline_each_settle_once",
        "post-confirm revocation rewrote the executor disposition",
        (POST_CAS_REWRITE,),
    ),
    "m-sc12d-expiry-overwrites-a-submitting-reservation": (
        STATE_TEST + "sc12_held_confirm_and_decline_each_settle_once",
        "stale expiry sweep overwrote a submitting reservation",
        (
            edit(
                COMMAND,
                """                from: Phase::Held,
                to: Phase::Refused,
                code: Some("confirmation_expired"),""",
                """                from: store::reservation(&state.conn, &candidate.principal, &candidate.request_id)
                    .map_err(store_error)?
                    .ok_or(Refusal::UNAVAILABLE)?.state,
                to: Phase::Refused,
                code: Some("confirmation_expired"),""",
            ),
        ),
    ),
    "m-sc12e-map-confirmed-target-change-to-denied": (
        STATE_TEST + "sc12_held_confirm_and_decline_each_settle_once",
        "changed target lost the target_changed refusal",
        (
            edit(
                COMMAND,
                """            match checked {
                Err(code) => (Phase::Refused, Some(code)),""",
                """            match checked {
                Err(code) => (Phase::Refused, Some(if code == "target_changed" { "denied" } else { code })),""",
            ),
        ),
    ),
    "m-sc13-require-server-gesture": (
        HOLDER_RECOVERY,
        "right: 200",
        (
            edit(
                WIRE,
                '    let kind = fields.remove("type").ok_or_else(|| bad(id))?;',
                """    let kind = fields.remove("type").ok_or_else(|| bad(id))?;
    if kind.as_str() == Some("commit") && fields.remove("gesture") != Some(Value::Bool(true)) {
        return Err(bad(id));
    }""",
            ),
        ),
    ),
    "m-sc14b-report-lost-reply-as-not-admitted": (
        PRIORITY_TEST + "sc14_silence_stays_nonfinal_and_loss_is_final_unknown",
        "reservation did not reach the expected state",
        (
            edit(
                COMMAND,
                "                DoubleOutcome::Lost => (Phase::EffectUnknown, None),",
                '                DoubleOutcome::Lost => (Phase::Refused, Some("executor_unreachable")),',
            ),
        ),
    ),
    "m-sc15a-retain-final-rows-only-for-the-read-ring": (
        STATE_TEST + CLOCK_TEST,
        "reservation was not checked before request age",
        (
            edit(
                STORE,
                "pub(super) fn compact(conn: &Connection, cutoff: i64, now: i64) -> Result<usize> {",
                """pub(super) fn compact(conn: &Connection, cutoff: i64, now: i64) -> Result<usize> {
    let cutoff = cutoff.max(now.saturating_sub(120_000));""",
            ),
        ),
    ),
    "m-sc15b-skip-age-bound-after-compaction": (
        STATE_TEST + CLOCK_TEST,
        'right: "expired_request"',
        (
            edit(
                COMMAND,
                """                if requested < at.saturating_sub(self.config.request_max_age_secs as i64 * 1000)
                    || requested > at.saturating_add(self.config.clock_skew_secs as i64 * 1000)""",
                "                if requested > at.saturating_add(self.config.clock_skew_secs as i64 * 1000)",
            ),
        ),
    ),
    "m-sc15c-check-age-before-incumbent": (
        STATE_TEST + CLOCK_TEST,
        "reservation was not checked before request age",
        (
            edit(COMMAND, AGE_CHECK, ""),
            edit(COMMAND, EXISTS, AGE_CHECK + EXISTS),
        ),
    ),
    "m-sc15d-purge-by-request-time-alone": (
        STORE_TEST + COMPACT_TEST,
        "right: 1",
        (
            edit(
                STORE,
                """             WHERE state IN ('admitted', 'refused', 'effect_unknown')
               AND requested_at < ?1 AND at < ?1""",
                "             WHERE requested_at < ?1",
            ),
        ),
    ),
    "m-sc15e-expire-consumed-bindings": (
        STATE_TEST + CLOCK_TEST,
        "consumed binding disappeared during receipt retention",
        (edit(STORE, "WHERE consumed = 0 AND expires_at <= ?", "WHERE expires_at <= ?"),),
    ),
    "m-sc16a-require-read-scope-for-lookup": (
        HOLDER_RECOVERY,
        "right: 200",
        (
            edit(
                COMMAND,
                LOOKUP_ROW,
                """            CommandRequest::Lookup { id, request_id } => {
                state.command_record(&record.record_id)?;
                if matches!(&record.grants, Grants::Delegated { grant } if grant.read_scope.is_none()) {
                    return Err(Refusal::NOT_FOUND);
                }
                let row = store::reservation(&state.conn, &record.principal, &request_id)""",
            ),
        ),
    ),
    "m-sc16b-reject-matching-consumed-replay": (
        TRANSPORT_TEST + "sc10_sc16_command_only_holder_recovers_without_an_owner_session",
        '"intent_invalid"',
        (
            edit(
                COMMAND,
                "                    && (row.consumed || row.expires_at > at)",
                "                    && !row.consumed && row.expires_at > at",
            ),
        ),
    ),
    "m-sc16c-resolve-target-before-incumbent": (
        HOLDER_RECOVERY,
        '"target_changed"',
        (
            edit(COMMAND, FRESH_BINDING, ""),
            edit(COMMAND, EXISTS, FRESH_BINDING + EXISTS),
        ),
    ),
    "m-sc16f-skip-prepare-incumbent-entitlement": (
        NARROWED_INCUMBENT,
        'right: Some("denied")',
        (edit(COMMAND, "                    self.command_entitled(&state, &record.record_id, &incumbent)?;\n", ""),),
    ),
    "m-sc16g-skip-commit-incumbent-entitlement": (
        NARROWED_INCUMBENT,
        "right: (3, 1, 1)",
        (edit(COMMAND, "            self.command_entitled(&state, &record.record_id, &frozen)?;\n", ""),),
    ),
    "oq13-match-binding-by-node-alone": (
        TRANSPORT_TEST + SAME_NODE_TEST,
        "right: 404",
        (edit(COMMAND, "                binding.node == target.node && binding.endpoint == target.endpoint", "                binding.node == target.node"),),
    ),
    "oq13-allow-ambiguous-binding": (
        TRANSPORT_TEST + SAME_NODE_TEST,
        "not_found_or_denied",
        (
            edit(
                COMMAND,
                """            if candidates.next().is_some()
                || binding.selector.session_id != target.selector.session_id
            {""",
                "            if binding.selector.session_id != target.selector.session_id {",
            ),
        ),
    ),
    "oq13-ignore-executor-generation": (
        TRANSPORT_TEST + FRESH_TEST,
        'right: "target_changed"',
        (
            edit(
                COMMAND,
                "            if binding != target {",
                """            if binding.state_epoch != target.state_epoch
                || binding.incarnation != target.incarnation
            {""",
            ),
        ),
    ),
    "oq13-require-current-binding-for-lookup": (
        TRANSPORT_TEST + FRESH_TEST,
        "right: 200",
        (
            edit(
                COMMAND,
                """                self.command_entitled(&state, &record.record_id, &request)?;
                Ok(stored(id, &row, true, request))""",
                """                self.command_entitled(&state, &record.record_id, &request)?;
                if self.commands.binding(&request.target).is_err() {
                    return Err(Refusal::NOT_FOUND);
                }
                Ok(stored(id, &row, true, request))""",
            ),
        ),
    ),
}


def apply(tree, edits):
    originals = {}
    rewritten = {}
    for filename, old, new in edits:
        source = tree / filename
        if source not in originals:
            originals[source] = source.read_text()
            rewritten[source] = originals[source]
        if rewritten[source].count(old) != 1:
            raise RuntimeError(f"{filename}: source anchor is not unique: {old!r}")
        rewritten[source] = rewritten[source].replace(old, new, 1)
    for source, contents in rewritten.items():
        source.write_text(contents)
    return originals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--case", choices=tuple(CASES), action="append")
    selection.add_argument("--shard", metavar="INDEX/TOTAL", help="zero-based shard")
    args = parser.parse_args()
    selected = args.case or tuple(CASES)
    if args.shard is not None:
        try:
            index, total = map(int, args.shard.split("/"))
        except ValueError:
            parser.error("--shard must be INDEX/TOTAL")
        if not 0 <= index < total <= len(CASES):
            parser.error("--shard requires 0 <= INDEX < TOTAL <= number of cases")
        selected = tuple(CASES)[index::total]
    artifacts = ROOT / ".artifacts" / "mission-control-state-mutants"
    artifacts.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("CARGO_BUILD_JOBS", "8")
    os.environ.setdefault("CARGO_TARGET_DIR", str(ROOT / "target"))
    with tempfile.TemporaryDirectory(prefix="mission-control-state-mutants-") as temp:
        tree = Path(temp)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, tree / name)
        for name in ("src", "tests", "assets"):
            shutil.copytree(ROOT / name, tree / name)
        for name in selected:
            test, _, _ = CASES[name]
            MATCH(tree, artifacts, f"{name}-control", test)
        for name in selected:
            test, reason, edits = CASES[name]
            originals = apply(tree, edits)
            try:
                MATCH(tree, artifacts, name, test, reason)
            finally:
                for source, contents in originals.items():
                    source.write_text(contents)
        for name in selected:
            test, _, _ = CASES[name]
            MATCH(tree, artifacts, f"{name}-restored", test)
        print(f"mission-control-state-mutants-complete: {len(selected)}/{len(CASES)}", flush=True)


if __name__ == "__main__":
    main()
