#!/usr/bin/env python3
"""Verify PR 4 pairing source mutants turn their paired oracle tests RED and restore GREEN."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CASES = [
    (
        "q2-1-skip-exporter-check",
        "src/pairing/ceremony.rs",
        "    if t.exporter != inputs.exporter {",
        "    if false && t.exporter != inputs.exporter {",
        ["cargo", "test", "--locked", "--lib", "pairing::ceremony::tests::q2_1_mismatched_exporter_in_transcript_is_refused_by_initiator"],
        False,
    ),
    (
        "q2-2-remove-frame-limit",
        "src/pairing/ceremony.rs",
        "    if len > MAX_FRAME_BYTES {",
        "    if false && len > MAX_FRAME_BYTES {",
        ["cargo", "test", "--locked", "--lib", "pairing::ceremony::tests::frame_over_8192_bytes_is_rejected_as_frame_too_large"],
        False,
    ),
    (
        "q2-3b-initiator-admits-inbound",
        "src/pairing/service.rs",
        "            .any(|i| i.role == IntentRole::Responder && i.deadline > now)",
        "            .any(|i| i.deadline > now)",
        ["cargo", "test", "--locked", "--features", "test-hooks", "--test", "pairing_ceremony", "q2_3b_and_q2_5a_5b_intent_role_reconfirm_conflict_and_32_cap"],
        False,
    ),
    (
        "q2-5a-skip-intent-conflict",
        "src/pairing/service.rs",
        "                if existing.role == role",
        "                if true || existing.role == role",
        ["cargo", "test", "--locked", "--features", "test-hooks", "--test", "pairing_ceremony", "q2_3b_and_q2_5a_5b_intent_role_reconfirm_conflict_and_32_cap"],
        False,
    ),
    (
        "q2-5c-shared-in-out-budget",
        "src/pairing/budgets.rs",
        "            inbound: AttemptLimiter::new(MAX_INBOUND_STARTS_PER_MIN, MAX_INBOUND_CONCURRENT),\n            outbound: AttemptLimiter::new(MAX_OUTBOUND_STARTS_PER_MIN, MAX_OUTBOUND_CONCURRENT),",
        "            inbound: AttemptLimiter::new(MAX_INBOUND_STARTS_PER_MIN, MAX_INBOUND_CONCURRENT),\n            outbound: AttemptLimiter::new(0, 0),",
        ["cargo", "test", "--locked", "--lib", "pairing::budgets::tests::inbound_exhaustion_leaves_outbound_budget_intact"],
        False,
    ),
    (
        "q2-12-leave-mdns-window-open",
        "src/discovery/mdns.rs",
        "    pub fn close_announce_window(&mut self, now: Instant) -> bool {\n        if self.window_until.take().is_none() {",
        "    pub fn close_announce_window(&mut self, now: Instant) -> bool {\n        if true || self.window_until.take().is_none() {",
        ["cargo", "test", "--locked", "--features", "test-hooks", "--test", "pairing_ceremony", "q2_12_mdns_timed_window_closes_through_close_announce_window"],
        False,
    ),
    (
        "q2-14-ignore-bare-deferred-keys",
        "src/fed.rs",
        '                        if k == "auto_accept"',
        '                        if false && k == "auto_accept"',
        ["cargo", "test", "--locked", "--features", "test-hooks", "--test", "pairing_ceremony", "q2_14_peers_file_rejects_deferred_preference_keys_in_both_forms"],
        False,
    ),
    (
        "q2-15c2-retry-flag-without-tx",
        "src/pairing/service.rs",
        '            let msg = "injected startup-cancel transaction failure".to_string();\n            *self.startup_cancel_error.lock().unwrap() = Some(msg.clone());\n            self.startup_cancel_done.store(false, Ordering::SeqCst);\n            return Err(PairingError::StartupCancelFailed(msg));',
        '            self.startup_cancel_done.store(true, Ordering::SeqCst);\n            return Ok(0);',
        ["cargo", "test", "--locked", "--features", "test-hooks", "--test", "pairing_ceremony", "q2_15c2_startup_cancel_failure_blocks_ceremonies_allows_revocation_and_recovers"],
        False,
    ),
    (
        "q2-17-accept-non-ed25519-spki",
        "src/pairing/ceremony.rs",
        "    if extract_ed25519_pubkey(&spki).is_err() {",
        "    if false && extract_ed25519_pubkey(&spki).is_err() {",
        ["cargo", "test", "--locked", "--lib", "pairing::ceremony::tests::p256_peer_matching_pinned_hash_is_refused_with_key_algorithm"],
        False,
    ),
]


def run_cmd(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()

    if args.list:
        for name, *_ in CASES:
            print(name)
        return 0

    selected = [c for c in CASES if not args.case or c[0] in args.case]
    for name, rel_path, old, new, cmd, skip_syntax in selected:
        if skip_syntax:
            continue
        p = ROOT / rel_path
        orig = p.read_text()
        assert orig.count(old) == 1, f"{name}: anchor not unique in {rel_path}"
        try:
            p.write_text(orig.replace(old, new, 1))
            red = run_cmd(cmd)
            if red.returncode == 0:
                print(f"SURVIVED: {name}", file=sys.stderr)
                return 1
            red_line = next(
                (l for l in (red.stdout + red.stderr).splitlines() if "FAILED" in l or "error" in l.lower()),
                f"exit={red.returncode}",
            )
        finally:
            p.write_text(orig)
        green = run_cmd(cmd)
        if green.returncode != 0:
            print(f"GREEN FAILED AFTER RESTORE: {name}\n{green.stdout}\n{green.stderr}", file=sys.stderr)
            return 1
        print(f"MUTANT {name}: RED ({red_line.strip()}) -> GREEN")
    print(f"pairing-pr4-mutants-complete:{len([c for c in selected if not c[5]])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
