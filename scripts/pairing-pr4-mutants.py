#!/usr/bin/env python3
"""Verify all 44 PR 4 pairing source mutants turn their paired oracle tests RED and restore GREEN."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def lib_test(name: str):
    return ["cargo", "test", "--locked", "--lib", name]


def int_test(name: str):
    return [
        "cargo",
        "test",
        "--locked",
        "--features",
        "test-hooks",
        "--test",
        "pairing_ceremony",
        name,
    ]


CASES = [
    # 1. Q2-1: skip exporter check
    (
        "q2-1-skip-exporter-check",
        "src/pairing/ceremony.rs",
        "    if t.exporter != inputs.exporter {",
        "    if false && t.exporter != inputs.exporter {",
        lib_test("pairing::ceremony::tests::q2_1_mismatched_exporter_in_transcript_is_refused_by_initiator"),
        False,
    ),
    # 2. Q2-2: remove 8192-byte frame limit
    (
        "q2-2-remove-frame-limit",
        "src/pairing/ceremony.rs",
        "    if len > MAX_FRAME_BYTES {",
        "    if false && len > MAX_FRAME_BYTES {",
        lib_test("pairing::ceremony::tests::frame_over_8192_bytes_is_rejected_as_frame_too_large"),
        False,
    ),
    # 3. Q2-3a: skip no-intent gate on inbound ClientHello
    (
        "q2-3a-full-handshake-no-intent",
        "src/fed.rs",
        "                if !rt.service.has_live_responder_intent() {",
        "                if false && !rt.service.has_live_responder_intent() {",
        int_test("q2_3a_and_q2_4b_no_intent_eof_and_unsupported_alpn_refused"),
        False,
    ),
    # 4. Q2-3b: initiator intent admits inbound
    (
        "q2-3b-initiator-admits-inbound",
        "src/pairing/service.rs",
        "            .any(|i| i.role == IntentRole::Responder && &i.peer_id == peer_id && i.deadline > now)",
        "            .any(|i| &i.peer_id == peer_id && i.deadline > now)",
        int_test("q2_3b_and_q2_5a_5b_intent_role_reconfirm_conflict_and_32_cap"),
        False,
    ),
    # 5. Q2-4: route pairing ALPN into fed
    (
        "q2-4-route-pairing-to-fed",
        "src/fed.rs",
        "            if offers_pairing_alpn {",
        "            if false && offers_pairing_alpn {",
        int_test("q2_3a_and_q2_4b_no_intent_eof_and_unsupported_alpn_refused"),
        False,
    ),
    # 6. Q2-4b: skip negotiated-ALPN check
    (
        "q2-4b-skip-alpn-check",
        "src/pairing/service.rs",
        "            if tls.get_ref().1.alpn_protocol() != Some(PAIRING_ALPN) {",
        "            if false && tls.get_ref().1.alpn_protocol() != Some(PAIRING_ALPN) {",
        int_test("q2_3a_and_q2_4b_no_intent_eof_and_unsupported_alpn_refused"),
        False,
    ),
    # 7. Q2-5a: key per-peer intent check by intent ID / skip conflict
    (
        "q2-5a-skip-intent-conflict",
        "src/pairing/service.rs",
        "                if existing.role == role",
        "                if true || existing.role == role",
        int_test("q2_3b_and_q2_5a_5b_intent_role_reconfirm_conflict_and_32_cap"),
        False,
    ),
    # 8. Q2-5b: off-by-one on 32 pending intent cap
    (
        "q2-5b-off-by-one-intent-cap",
        "src/pairing/store.rs",
        "    if pending.len() >= MAX_PENDING_INTENTS {",
        "    if pending.len() > MAX_PENDING_INTENTS {",
        int_test("q2_3b_and_q2_5a_5b_intent_role_reconfirm_conflict_and_32_cap"),
        False,
    ),
    # 9. Q2-5c: shared inbound and outbound budget
    (
        "q2-5c-shared-in-out-budget",
        "src/pairing/budgets.rs",
        "            inbound: AttemptLimiter::new(MAX_INBOUND_STARTS_PER_MIN, MAX_INBOUND_CONCURRENT),\n            outbound: AttemptLimiter::new(MAX_OUTBOUND_STARTS_PER_MIN, MAX_OUTBOUND_CONCURRENT),",
        "            inbound: AttemptLimiter::new(MAX_INBOUND_STARTS_PER_MIN, MAX_INBOUND_CONCURRENT),\n            outbound: AttemptLimiter::new(0, 0),",
        lib_test("pairing::budgets::tests::inbound_exhaustion_leaves_outbound_budget_intact"),
        False,
    ),
    # 10. Q2-5d: refund outbound counter on failure
    (
        "q2-5d-refund-outbound-on-fail",
        "src/pairing/budgets.rs",
        "        // Starts are never refunded on failure (Q2-5d).",
        "        self.starts.pop_back();",
        lib_test("pairing::budgets::tests::failed_outbound_attempts_never_refund_60s_budget"),
        False,
    ),
    # 11. Q2-5e: drop ceremony slot guard immediately
    (
        "q2-5e-drop-ceremony-slot-guard",
        "src/pairing/service.rs",
        "        let Some(_ceremony_guard) = self.ceremony_slots.try_acquire(intent.intent_id) else {",
        "        let Some(_) = self.ceremony_slots.try_acquire(intent.intent_id) else {",
        int_test("q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics"),
        False,
    ),
    # 12. Q2-6: extend monotonic intent deadline
    (
        "q2-6-extend-monotonic-deadline",
        "src/pairing/service.rs",
        "        let deadline = tokio::time::Instant::now()\n            + Duration::from_secs(u64::from(MAX_CEREMONY_WINDOW_SECS));",
        "        let deadline = tokio::time::Instant::now() + Duration::from_secs(86400);",
        int_test("q2_6_monotonic_120s_deadline_expires_intent"),
        False,
    ),
    # 13. Q2-7a: skip loading manual grants in merge_snapshot
    (
        "q2-7a-skip-publication-after-commit",
        "src/pairing/store.rs",
        "    peers.manual_grants = manual_grants;",
        "    peers.manual_grants = Vec::new();",
        int_test("safety_1_and_q2_9_authorize_peer_op_is_single_decision_point_default_deny"),
        False,
    ),
    # 14. Q2-7b: omit revocation mark on remove
    (
        "q2-7b-omit-revocation-mark",
        "src/pairing/store.rs",
        '    let mark_scope = MarkScope::Grant {\n        device: subject,\n        grant_id: *grant_id,\n    };\n    if let Some(reg) = revocations {\n        reg.insert_mark(mark_scope.clone(), revision);',
        '    let mark_scope = MarkScope::Grant {\n        device: subject,\n        grant_id: *grant_id,\n    };\n    if let Some(reg) = revocations {\n        let _ = &reg;',
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 15. Q2-7c: drop lower-revision install refusal
    (
        "q2-7c-drop-rev-guard",
        "src/fed.rs",
        "        if merged.authority_revision < installed {",
        "        if false && merged.authority_revision < installed {",
        lib_test("fed::pairing_publish_tests::a_generation_older_than_the_installed_one_is_refused_and_records_nothing"),
        False,
    ),
    # 16. Q2-7d: startup builds without store merge
    (
        "q2-7d-startup-files-only",
        "src/pairing/store.rs",
        "    let blocked_set = blocked_devices(&tx)?;",
        "    let blocked_set = HashSet::new();",
        lib_test("pairing::store::tests::durable_block_reaches_every_deny_check_of_the_next_policy_generation"),
        False,
    ),
    # 17. Q2-7e: remove marks whole device
    (
        "q2-7e-remove-marks-whole-device",
        "src/pairing/store.rs",
        "                    MarkScope::Grant {\n                        device: d,\n                        grant_id: gid,\n                    } => grant_id == Some(gid) && d.is_none_or(|dev| dev == *device),",
        "                    MarkScope::Grant { device: d, .. } => d.is_none_or(|dev| dev == *device),",
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 18. Q2-7f: retire marks at install even when older token lives
    (
        "q2-7f-presence-only-marks",
        "src/pairing/store.rs",
        "            min_live_rev.is_some_and(|min_r| min_r < m.revision)",
        "            false",
        int_test("m10_block_device_publishes_update_and_refuses_at_admission_and_permit_fence"),
        False,
    ),
    # 19. Q2-7g: drop mark unconditionally on commit error
    (
        "q2-7g-drop-mark-on-commit-error",
        "src/pairing/store.rs",
        "                    Ok(r) if r >= revision => return Ok(revision),\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// Lifts a block",
        "                    Ok(r) if false && r >= revision => {\n                        let _ = r;\n                        return Ok(revision);\n                    }\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => reg.drop_mark(&mark_scope, revision),\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// Lifts a block",
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 20. Q2-7h: skip fresh mark check at permit point
    (
        "q2-7h-reuse-earlier-mark-check",
        "src/fed.rs",
        "            if revocations.has_blocking_mark(&dev, Some(&grant.grant_id), peers.authority_revision)",
        "            if false && revocations.has_blocking_mark(&dev, Some(&grant.grant_id), peers.authority_revision)",
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 21. Q2-7i: ignore test clock / expiry at permit
    (
        "q2-7i-eval-expiry-at-earlier-check",
        "src/pairing/auth.rs",
        "        && g.not_after.is_none_or(|end| ctx.now < end)",
        "        && (true || g.not_after.is_none_or(|end| ctx.now < end))",
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 22. Q2-8: skip removed-grant check at activation
    (
        "q2-8-trust-in-memory-intent",
        "src/pairing/store.rs",
        "    if removed_in(&tx, &grant_id)? {",
        "    if false && removed_in(&tx, &grant_id)? {",
        lib_test("pairing::store::tests::p6_removal_wins_over_retry_and_survives_restart"),
        False,
    ),
    # 23. Q2-9: map contact to owner-device scope
    (
        "q2-9-map-contact-to-owner-device",
        "src/pairing/auth.rs",
        "                Operation::SessionList => *profile == PairingProfile::OwnerDevice,",
        "                Operation::SessionList => true,",
        int_test("safety_1_and_q2_9_authorize_peer_op_is_single_decision_point_default_deny"),
        False,
    ),
    # 24. Q2-10: skip exposure digest check on receipt
    (
        "q2-10-compare-both-receipts-local-e",
        "src/pairing/codec.rs",
        "    if receipt.exposure_policy_sha256 != expected_offer.exposure_policy_sha256 {",
        "    if false && receipt.exposure_policy_sha256 != expected_offer.exposure_policy_sha256 {",
        lib_test("pairing::ceremony::tests::q2_10_mismatched_exposure_digest_in_receipt_is_rejected"),
        False,
    ),
    # 25. Q2-11: same-UID-only check (skip PID/starttime check)
    (
        "q2-11-same-uid-only-check",
        "src/http.rs",
        "    let Some(pid) = cred.pid else {",
        "    if true { return Ok(()); }\n    let Some(pid) = cred.pid else {",
        int_test("q2_11_tcp_router_returns_404_and_unix_router_mounts_pairing"),
        False,
    ),
    # 26. Q2-12: leave mDNS window open after cancel/expiry
    (
        "q2-12-leave-mdns-window-open",
        "src/discovery/mdns.rs",
        "    pub fn close_announce_window(&mut self, now: Instant) -> bool {\n        if self.window_until.take().is_none() {",
        "    pub fn close_announce_window(&mut self, now: Instant) -> bool {\n        if true || self.window_until.take().is_none() {",
        int_test("q2_12_mdns_timed_window_closes_through_close_announce_window"),
        False,
    ),
    # 27. Q2-13a: omit key-algorithm check in ceremony
    (
        "q2-13a-omit-key-alg-doctor",
        "src/pairing/ceremony.rs",
        "    if extract_ed25519_pubkey(&spki).is_err() {",
        "    if false && extract_ed25519_pubkey(&spki).is_err() {",
        lib_test("pairing::ceremony::tests::p256_peer_matching_pinned_hash_is_refused_with_key_algorithm"),
        False,
    ),
    # 28. Q2-13b: drop coexistence warn in doctor
    (
        "q2-13b-drop-coexistence-warn",
        "src/pairing/service.rs",
        "            if g.provenance == \"legacy_unilateral\" && manual_peers.contains(&g.peer_id) {",
        "            if false && g.provenance == \"legacy_unilateral\" && manual_peers.contains(&g.peer_id) {",
        int_test("q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics"),
        False,
    ),
    # 29. Q2-13c: omit receive_path warn on initiator-only node
    (
        "q2-13c-receive-path-peers-file-only",
        "src/pairing/service.rs",
        "        let receive_path = if (!has_fed_listen || fed.is_leaf) && manual_count > 0 {",
        "        let receive_path = if false && (!has_fed_listen || fed.is_leaf) && manual_count > 0 {",
        int_test("q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics"),
        False,
    ),
    # 30. Q2-13d: report authority from installed revision only
    (
        "q2-13d-doctor-installed-rev-only",
        "src/pairing/service.rs",
        "        let authority = if installed_rev == committed_rev {",
        "        let authority = if true || installed_rev == committed_rev {",
        int_test("q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics"),
        False,
    ),
    # 31. Q2-13e: include peer ID in refusal counters
    (
        "q2-13e-include-peer-id-in-refusals",
        "src/pairing/budgets.rs",
        "        *guard.entry(code.to_string()).or_insert(0) += 1;",
        "        *guard.entry(format!(\"{code}:xmsg-spki1:leaked\")).or_insert(0) += 1;",
        lib_test("pairing::budgets::tests::refusal_counters_record_codes_without_peer_ids"),
        False,
    ),
    # 32. Q2-13f: count only unexpired grants in doctor
    (
        "q2-13f-count-unexpired-only-in-doctor",
        "src/pairing/store.rs",
        "           AND g.not_after IS NOT NULL AND g.not_after <= ?1",
        "           AND 0 = 1 AND g.not_after <= ?1",
        int_test("q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics"),
        False,
    ),
    # 33. Q2-14: ignore bare deferred keys in peers file
    (
        "q2-14-ignore-bare-deferred-keys",
        "src/fed.rs",
        '                        if k == "auto_accept"',
        '                        if false && k == "auto_accept"',
        int_test("q2_14_peers_file_rejects_deferred_preference_keys_in_both_forms"),
        False,
    ),
    # 34. Q2-15: skip reserve_capacity in ceremony
    (
        "q2-15-reserve-in-intent-or-activation",
        "src/pairing/ceremony.rs",
        "    // §5.3: reserve_capacity runs after T validates and BEFORE signing ReceiptI.\n    reserve_capacity_cb(inputs.intent_id, i64::from(inputs.now_utc))?;",
        "    let _ = reserve_capacity_cb(inputs.intent_id, i64::from(inputs.now_utc));",
        lib_test("pairing::ceremony::tests::q2_15_reserve_capacity_failure_refuses_before_signing_receipt"),
        False,
    ),
    # 35. Q2-15b: release blocked grant slot
    (
        "q2-15b-release-blocked-grant-slot",
        "src/pairing/store.rs",
        "        \"SELECT (SELECT COUNT(*) FROM pairing_grants g WHERE g.provenance = 'manual_authenticated_oob'",
        "        \"SELECT (SELECT COUNT(*) FROM pairing_grants g WHERE g.provenance = 'manual_authenticated_oob' AND NOT EXISTS (SELECT 1 FROM pairing_device_blocks b WHERE b.device_id = g.subject)",
        int_test("q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics"),
        False,
    ),
    # 36. Q2-15c: omit startup cancel open intents
    (
        "q2-15c-omit-startup-cancel",
        "src/pairing/service.rs",
        "            store::cancel_open_intents(&db)",
        "            let _ = &db; Ok::<usize, StoreError>(0)",
        int_test("q2_15c2_startup_cancel_failure_blocks_ceremonies_allows_revocation_and_recovers"),
        False,
    ),
    # 37. Q2-15c2: allow accept/start when startup cancel failed
    (
        "q2-15c2-serve-on-startup-cancel-fail",
        "src/pairing/service.rs",
        "        if !self.is_startup_cancel_done() {\n            self.attempt_startup_cancel(fed)?;",
        "        if false && !self.is_startup_cancel_done() {\n            self.attempt_startup_cancel(fed)?;",
        int_test("q2_15c2_startup_cancel_failure_blocks_ceremonies_allows_revocation_and_recovers"),
        False,
    ),
    # 38. Q2-15d: exclude expired grants from slot count
    (
        "q2-15d-exclude-expired-grants",
        "src/pairing/store.rs",
        "            AND NOT EXISTS (SELECT 1 FROM pairing_removed_grants r WHERE r.grant_id = g.grant_id)\"",
        "            AND g.not_after IS NULL AND NOT EXISTS (SELECT 1 FROM pairing_removed_grants r WHERE r.grant_id = g.grant_id)\"",
        int_test("q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics"),
        False,
    ),
    # 39. Q2-15e: filter open cap_reserved by expires_at > now
    (
        "q2-15e-count-reservations-by-expires-at",
        "src/pairing/store.rs",
        "              + (SELECT COUNT(*) FROM pairing_intents WHERE state = 'open' AND cap_reserved = 1",
        "              + (SELECT COUNT(*) FROM pairing_intents WHERE state = 'open' AND cap_reserved = 1 AND expires_at > 9999999999",
        lib_test("pairing::store::tests::an_intent_expired_in_real_time_still_holds_its_reservation"),
        False,
    ),
    # 40. Q2-16: check expiry on unblock instead of unremoved
    (
        "q2-16-check-expiry-on-unblock",
        "src/pairing/store.rs",
        "             AND g.provenance = 'manual_authenticated_oob'\n             AND NOT EXISTS (SELECT 1 FROM pairing_removed_grants r WHERE r.grant_id = g.grant_id)\"",
        "             AND g.provenance = 'manual_authenticated_oob'\n             AND NOT EXISTS (SELECT 1 FROM pairing_removed_grants r WHERE r.grant_id = g.grant_id)\n             AND (g.not_after IS NULL OR g.not_after > CAST(strftime('%s','now') AS INTEGER))\"",
        int_test("q2_5e_and_q2_13_ceremony_busy_and_doctor_diagnostics"),
        False,
    ),
    # 41. Q2-16b: check file deny incorrectly on unblock
    (
        "q2-16b-use-legacy-store-rows",
        "src/pairing/store.rs",
        "    if !installed_file_policy.deny.spkis.contains(&hex_id) {",
        "    if false && !installed_file_policy.deny.spkis.contains(&hex_id) {",
        lib_test("pairing::store::tests::a_refused_unblock_changes_nothing_and_the_file_deny_excuses_file_rights"),
        False,
    ),
    # 42. Q2-16c: check pin only, skip CA on unblock
    (
        "q2-16c-check-pin-only-skip-ca",
        "src/pairing/store.rs",
        "        if !installed_file_policy.ca_peers().is_empty() || installed_file_policy.hub.is_some() {",
        "        if false && (!installed_file_policy.ca_peers().is_empty() || installed_file_policy.hub.is_some()) {",
        lib_test("pairing::store::tests::a_refused_unblock_changes_nothing_and_the_file_deny_excuses_file_rights"),
        False,
    ),
    # 43. Q2-16d: unblock without publication mutex
    (
        "q2-16d-read-legacy-outside-mutex",
        "src/fed.rs",
        "    pub fn unblock_device(&self, device: &crate::pairing::auth::DeviceId) -> Result<u64, AppError> {\n        let _publication = self.publication.lock().unwrap_or_else(|e| e.into_inner());",
        "    pub fn unblock_device(&self, device: &crate::pairing::auth::DeviceId) -> Result<u64, AppError> {",
        lib_test("fed::pairing_publish_tests::no_file_rebuild_installs_while_an_unblock_proves_and_commits"),
        False,
    ),
    # 44. Q2-17: accept non-Ed25519 SPKI
    (
        "q2-17-accept-non-ed25519-spki",
        "src/pairing/ceremony.rs",
        "    if extract_ed25519_pubkey(&spki).is_err() {",
        "    if false && extract_ed25519_pubkey(&spki).is_err() {",
        lib_test("pairing::ceremony::tests::p256_peer_matching_pinned_hash_is_refused_with_key_algorithm"),
        False,
    ),
    # 45. M10 (Q2-7a): block_device skips publish_pairing_update after commit
    (
        "q2-7a-block-skip-publication-after-commit",
        "src/pairing/service.rs",
        '        for id in matching_ids {\n            self.finish_cancelled_live_intent(fed, &id, "device blocked");\n        }\n\n        let installed_rev = fed.publish_pairing_update(committed_rev).await?;',
        '        for id in matching_ids {\n            self.finish_cancelled_live_intent(fed, &id, "device blocked");\n        }\n\n        let installed_rev = committed_rev;',
        int_test("m10_block_device_publishes_update_and_refuses_at_admission_and_permit_fence"),
        False,
    ),
    # 46. R1: install() registers a fresh token instead of dyn_tls.peers.generation_token
    (
        "r1-install-clones-new-token",
        "src/fed.rs",
        "        let token = dyn_tls.peers.generation_token.clone();",
        "        let token = Arc::new(crate::pairing::store::GenerationToken::new(dyn_tls.peers.authority_revision));",
        int_test("m10_block_device_publishes_update_and_refuses_at_admission_and_permit_fence"),
        False,
    ),
    # 47. R2: policy-only rebuild omits own_device_id from credential
    (
        "r2-policy-rebuild-omits-own-device-id",
        "src/fed.rs",
        "        merged.own_device_id = crate::pairing::ceremony::ed25519_device_id_from_cert(&inputs.certs[0])\n            .ok()\n            .map(|d| d.0);",
        "        merged.own_device_id = None;",
        int_test("r2_foreign_issuer_grant_refused_after_file_and_policy_only_rebuild"),
        False,
    ),
    # 48. R4: drop mark on read-back error in block_device_with_marks
    (
        "r4-block-drop-mark-on-read-error",
        "src/pairing/store.rs",
        '        Err(err) => {\n            if let Some(reg) = revocations {\n                #[cfg(any(test, feature = "test-hooks"))]\n                let read_res = if reg\n                    .inject_rev_read_error\n                    .swap(false, std::sync::atomic::Ordering::SeqCst)\n                {\n                    Err(StoreError::Invalid("injected revision read-back error"))\n                } else {\n                    authority_revision(conn)\n                };\n                #[cfg(not(any(test, feature = "test-hooks")))]\n                let read_res = authority_revision(conn);\n                match read_res {\n                    Ok(r) if r >= revision => return Ok(revision),\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// Lifts a block',
        '        Err(err) => {\n            if let Some(reg) = revocations {\n                #[cfg(any(test, feature = "test-hooks"))]\n                let read_res = if reg\n                    .inject_rev_read_error\n                    .swap(false, std::sync::atomic::Ordering::SeqCst)\n                {\n                    Err(StoreError::Invalid("injected revision read-back error"))\n                } else {\n                    authority_revision(conn)\n                };\n                #[cfg(not(any(test, feature = "test-hooks")))]\n                let read_res = authority_revision(conn);\n                match read_res {\n                    Ok(r) if r >= revision => return Ok(revision),\n                    Ok(_) | Err(_) => reg.drop_mark(&mark_scope, revision),\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// Lifts a block',
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 50. R5: reply-attachment fetch passes wildcard principal for legacy peer
    (
        "r5-legacy-attachment-passes-wildcard-principal",
        "src/fed.rs",
        '        principal: if peers.is_manual_peer(peer) {\n            Some("*")\n        } else {\n            config.principals.first().map(String::as_str)\n        },',
        '        principal: Some("*"),',
        int_test("r5_legacy_reply_attachment_with_non_empty_principals_allowed"),
        False,
    ),
    # 51. N11: observe_fed ignores authorize_peer_op error
    (
        "n11-observe-fed-ignores-authorize-err",
        "src/observe_fed.rs",
        "            crate::pairing::auth::Operation::Observe,\n            &crate::pairing::auth::Resource::default(),\n        )\n        .map_err(|_| denied())?;",
        "            crate::pairing::auth::Operation::Observe,\n            &crate::pairing::auth::Resource::default(),\n        )\n        .ok();",
        int_test("n30_and_n11_pending_block_mark_denies_legacy_peer_send_and_observe"),
        False,
    ),
    # 52. N12: handoff ignores authorize_peer_op error
    (
        "n12-handoff-ignores-authorize-err",
        "src/handoff.rs",
        "    fs.authorize_peer_op(\n        &peers_perm,\n        &peer,\n        crate::pairing::auth::Operation::Handoff,\n        &crate::pairing::auth::Resource::default(),\n    )?;",
        "    let _ = fs.authorize_peer_op(\n        &peers_perm,\n        &peer,\n        crate::pairing::auth::Operation::Handoff,\n        &crate::pairing::auth::Resource::default(),\n    );",
        int_test("n12_handoff_refuses_observe_only_and_manual_contact_via_shared_decision"),
        False,
    ),
    # 53. N16: expired manual grant stays admitted
    (
        "n16-expired-grant-admitted",
        "src/fed.rs",
        "                && g.active\n                && !self.manual_removed.contains(&g.grant_id)\n                && g.not_after.is_none_or(|end| now < end)",
        "                && g.active\n                && !self.manual_removed.contains(&g.grant_id)",
        int_test("n16_n18_n28_expired_collision_and_outbound_pin_exclusion"),
        False,
    ),
    # 54. N18: colliding manual grant gets a second dialable name
    (
        "n18-manual-grant-second-dial-name",
        "src/fed.rs",
        "        if self.peers_by_name.contains_key(name) || self.name_by_pin.contains_key(&hex_pin) {",
        "        if self.peers_by_name.contains_key(name) {",
        int_test("n16_n18_n28_expired_collision_and_outbound_pin_exclusion"),
        False,
    ),
    # 55. N19: insert revocation mark after COMMIT instead of before
    (
        "n19-insert-mark-after-commit",
        "src/pairing/store.rs",
        '    let mark_scope = MarkScope::Device(*device);\n    if let Some(reg) = revocations {\n        reg.insert_mark(mark_scope.clone(), revision);\n        #[cfg(any(test, feature = "test-hooks"))]\n        if let Some(cb) = reg\n            .before_commit_hook\n            .lock()\n            .unwrap_or_else(|e| e.into_inner())\n            .as_ref()\n            .cloned()\n        {\n            cb();\n        }\n    }',
        '    let mark_scope = MarkScope::Device(*device);\n    if let Some(reg) = revocations {\n        #[cfg(any(test, feature = "test-hooks"))]\n        if let Some(cb) = reg\n            .before_commit_hook\n            .lock()\n            .unwrap_or_else(|e| e.into_inner())\n            .as_ref()\n            .cloned()\n        {\n            cb();\n        }\n        reg.insert_mark(mark_scope.clone(), revision);\n    }',
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 56. N20: ambiguous COMMIT never treats committed revision as Ok(revision)
    (
        "n20-ambiguous-commit-never-returns-ok",
        "src/pairing/store.rs",
        "                    Ok(r) if r >= revision => return Ok(revision),\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// Lifts a block",
        "                    Ok(r) if false && r >= revision => return Ok(revision),\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// Lifts a block",
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 57. N24: install() skips revocations.register_token(&token)
    (
        "n24-install-skips-register-token",
        "src/fed.rs",
        "            revocations.register_token(&token);",
        "            let _ = &token;",
        int_test("m10_block_device_publishes_update_and_refuses_at_admission_and_permit_fence"),
        False,
    ),
    # 58. N28: pinned_entries() skips active manual grants
    (
        "n28-pinned-entries-skips-manual",
        "src/fed.rs",
        "            if self.has_active_manual_grant(&g.subject, now) {",
        "            if false && self.has_active_manual_grant(&g.subject, now) {",
        int_test("n16_n18_n28_expired_collision_and_outbound_pin_exclusion"),
        False,
    ),
    # 59. N30: pending block mark checked only for manual peers
    (
        "n30-pending-block-manual-only",
        "src/fed.rs",
        "        if let Some(dev) = peer_dev {",
        "        if let Some(dev) = peer_dev.filter(|_| peers.is_manual_peer(peer_name)) {",
        int_test("n30_and_n11_pending_block_mark_denies_legacy_peer_send_and_observe"),
        False,
    ),
    # 60. G2/N19-remove: remove_with_marks inserts mark after COMMIT
    (
        "n19-remove-insert-mark-after-commit",
        "src/pairing/store.rs",
        '    let mark_scope = MarkScope::Grant {\n        device: subject,\n        grant_id: *grant_id,\n    };\n    if let Some(reg) = revocations {\n        reg.insert_mark(mark_scope.clone(), revision);\n        #[cfg(any(test, feature = "test-hooks"))]\n        if let Some(cb) = reg\n            .before_commit_hook\n            .lock()\n            .unwrap_or_else(|e| e.into_inner())\n            .as_ref()\n            .cloned()\n        {\n            cb();\n        }\n    }',
        '    let mark_scope = MarkScope::Grant {\n        device: subject,\n        grant_id: *grant_id,\n    };\n    if let Some(reg) = revocations {\n        #[cfg(any(test, feature = "test-hooks"))]\n        if let Some(cb) = reg\n            .before_commit_hook\n            .lock()\n            .unwrap_or_else(|e| e.into_inner())\n            .as_ref()\n            .cloned()\n        {\n            cb();\n        }\n        reg.insert_mark(mark_scope.clone(), revision);\n    }',
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 61. G2/N20-remove: remove_with_marks ambiguous COMMIT never treats committed revision as Ok
    (
        "n20-remove-ambiguous-commit-never-returns-ok",
        "src/pairing/store.rs",
        "                    Ok(r) if r >= revision => return Ok(revision),\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// A durable full-ID block",
        "                    Ok(r) if false && r >= revision => return Ok(revision),\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// A durable full-ID block",
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 62. G2/Q2-7g-remove: remove_with_marks returns Ok(rev) but drops mark
    (
        "q2-7g-remove-returns-ok-but-drops-mark",
        "src/pairing/store.rs",
        "                    Ok(r) if r >= revision => return Ok(revision),\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// A durable full-ID block",
        "                    Ok(r) if r >= revision => {\n                        reg.drop_mark(&mark_scope, revision);\n                        return Ok(revision);\n                    }\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// A durable full-ID block",
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
    # 63. G3/Q2-7g-block: block_device_with_marks returns Ok(rev) but drops mark
    (
        "q2-7g-block-returns-ok-but-drops-mark",
        "src/pairing/store.rs",
        "                    Ok(r) if r >= revision => return Ok(revision),\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// Lifts a block",
        "                    Ok(r) if r >= revision => {\n                        reg.drop_mark(&mark_scope, revision);\n                        return Ok(revision);\n                    }\n                    Ok(_) => reg.drop_mark(&mark_scope, revision),\n                    Err(_) => {\n                        // Ambiguous COMMIT and read-back failed: keep the mark fail-closed.\n                    }\n                }\n            }\n            Err(err)\n        }\n    }\n}\n\n/// Lifts a block",
        int_test("safety_5_permit_fence_refuses_mark_and_expiry_planted_after_admission"),
        False,
    ),
]


def run_cmd(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def parse_shard(spec: str) -> tuple[int, int]:
    parts = spec.split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"invalid --shard {spec!r}; expected <index>/<total>")
    index, total = int(parts[0]), int(parts[1])
    if total <= 0 or index < 0 or index >= total:
        raise ValueError(f"invalid --shard {spec!r}; index must satisfy 0 <= index < total")
    return index, total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--shard", help="Run shard <index>/<total> (0-indexed)")
    parser.add_argument("--manifest-out", type=Path, help="Write JSON completion manifest")
    args = parser.parse_args()

    if args.list:
        for name, *_ in CASES:
            print(name)
        return 0

    selected = [c for c in CASES if not c[5] and (not args.case or c[0] in args.case)]
    shard_info = None
    if args.shard:
        shard_idx, shard_total = parse_shard(args.shard)
        shard_info = (shard_idx, shard_total)
        selected = [c for i, c in enumerate(selected) if i % shard_total == shard_idx]

    completed_cases = []
    for name, rel_path, old, new, cmd, skip_syntax in selected:
        if skip_syntax:
            continue
        p = ROOT / rel_path
        orig = p.read_text()
        assert orig.count(old) == 1, f"{name}: anchor not unique in {rel_path} (count={orig.count(old)})"
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
        if green.returncode != 0 or "0 passed; 0 failed;" in green.stdout:
            print(f"GREEN FAILED AFTER RESTORE (or 0 tests matched): {name}\n{green.stdout}\n{green.stderr}", file=sys.stderr)
            return 1
        print(f"MUTANT {name}: RED ({red_line.strip()}) -> GREEN")
        completed_cases.append({"name": name, "red": True, "green": True})

    if args.manifest_out is not None:
        manifest = {"cases": completed_cases}
        if shard_info is not None:
            manifest["shard"] = shard_info[0]
            manifest["shards"] = shard_info[1]
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"pairing-pr4-mutants-complete:{len(completed_cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
