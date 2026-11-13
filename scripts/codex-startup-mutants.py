"""VA41 source mutants, each built and executed in an isolated artifact directory."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
TEST_FILE = "tests/gate_ha9_codex.rs"
SEED = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
NONCE = uuid.uuid4().hex


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"expected one mutation site: {old!r}")
    return text.replace(old, new)


# Every case changes production source; test-only markers prove the selected artifact ran.
CASES = {'message-trigger': ('src/surface.rs',
                     '            crate::codex::recover_restart_root(local, '
                     '&session.session_id).await;',
                     '',
                     'va41_restart_queued_message_wakes_without_mcp_or_hook'),
 'retry-schedule': ('src/codex.rs',
                    '        recover_restart_roots(&state).await;',
                    '',
                    'va41_unavailable_relay_retries_without_another_message'),
 'seed-overwrites-prior-pending': ('src/storage.rs',
                                   'UPDATE codex_roots SET restart_pending = CASE WHEN revoked != '
                                   '0 THEN 0 ELSE restart_pending OR active END',
                                   'UPDATE codex_roots SET restart_pending = CASE WHEN revoked != '
                                   '0 THEN 0 ELSE active END',
                                   'va41_repeated_restart_retains_pending_recovery'),
 'startup-unrevokes': ('src/storage.rs',
                       'UPDATE codex_roots SET restart_pending = CASE WHEN revoked != 0 THEN 0 '
                       'ELSE restart_pending OR active END',
                       'UPDATE codex_roots SET revoked = 0, restart_pending = 1',
                       'va41_restart_revoked_root_never_wakes'),
 'reopen-deliberate-parking': ('src/storage.rs',
                               'UPDATE codex_roots SET restart_pending = CASE WHEN revoked != 0 '
                               'THEN 0 ELSE restart_pending OR active END',
                               'UPDATE codex_roots SET restart_pending = CASE WHEN revoked != 0 '
                               'THEN 0 ELSE 1 END',
                               'va41_deliberate_session_end_is_not_restart_recovery'),
 'fresh-writer-witness': ('src/codex.rs',
                          'pub fn owner_holds_lock_inode(\n'
                          '    proc_root: &Path,\n'
                          '    owner_pid: u32,\n'
                          '    owner_starttime: &str,\n'
                          '    expected_lock_path: &Path,\n'
                          '    expected_dev: u64,\n'
                          '    expected_ino: u64,\n'
                          ') -> bool {\n'
                          '    let euid = effective_uid();',
                          'pub fn owner_holds_lock_inode(\n'
                          '    proc_root: &Path,\n'
                          '    owner_pid: u32,\n'
                          '    owner_starttime: &str,\n'
                          '    expected_lock_path: &Path,\n'
                          '    expected_dev: u64,\n'
                          '    expected_ino: u64,\n'
                          ') -> bool {\n'
                          '    return true;\n'
                          '    let euid = effective_uid();',
                          'va41_restart_moved_writer_lock_keeps_queue_and_never_wakes'),
 'rollout-id-check': ('src/codex.rs',
                      '        if name_mentions_target && id_str != target_id {\n'
                      '            return Err(RolloutLookupError::Invalid(format!(\n'
                      '                "XB2: rollout {name} has payload.id={id_str:?} != expected '
                      '{target_id:?}"\n'
                      '            )));\n'
                      '        }\n'
                      '        if id_str != target_id {\n'
                      '            continue;\n'
                      '        }\n',
                      '',
                      'va41_bad_rollout_remains_queued_and_awaiting_reattestation'),
 'false-live-status': ('src/surface.rs',
                       '"awaiting_reattestation"',
                       '"live"',
                       'va41_bad_rollout_remains_queued_and_awaiting_reattestation'),
 'retry-owner-change': ('src/codex.rs',
                        'return Err(("owner_changed", true));',
                        'return Err(("owner_changed", false));',
                        'va41_owner_starttime_change_clears_recovery_durably'),
 'clear-after-first-handoff': ('src/codex.rs',
                               'Ok(("delivered", _)) => {}',
                               'Ok(("delivered", _)) => return Ok(()),',
                               'va41_eight_item_bound_retains_recovery_until_scheduled_remainder'),
 'nine-envelope-drain': ('src/codex.rs',
                         'for _ in 0..MAX_CODEX_HOOK_DRAIN_ENVELOPES {',
                         'for _ in 0..9 {',
                         'va41_eight_item_bound_retains_recovery_until_scheduled_remainder'),
 'duplicate-reservation': ('src/storage.rs',
                           "UPDATE codex_handoff SET state = 'inflight', carrier = 'push', "
                           'updated_at = ?4',
                           "UPDATE codex_handoff SET state = 'pending', carrier = 'push', "
                           'updated_at = ?4',
                           'va41_auto_recovery_races_mcp_and_hook_with_one_carrier'),
 'main-retry-spawn': ('src/main.rs',
                      '            bg_tasks.push(tokio::spawn(xmsg::codex::run_restart_recovery(\n'
                      '                state.clone(),\n'
                      '            )));',
                      '',
                      'va41_cli_starts_production_retry_scheduler_without_new_message'),
 'cancelled-owned-custody': ('src/surface.rs',
                             'impl Drop for CodexPushReservationGuard {\n'
                             '    fn drop(&mut self) {\n'
                             '        if !self.armed {',
                             'impl Drop for CodexPushReservationGuard {\n'
                             '    fn drop(&mut self) {\n'
                             '        if true {',
                             'va41_cancelled_owned_push_becomes_unknown_and_next_item_recovers'),
 'cancelled-attempt-stuck': ('src/codex.rs',
                             'impl Drop for RestartAttemptGuard {\n'
                             '    fn drop(&mut self) {\n'
                             '        if !self.armed {',
                             'impl Drop for RestartAttemptGuard {\n'
                             '    fn drop(&mut self) {\n'
                             '        if true {',
                             'va41_cancelled_owned_push_becomes_unknown_and_next_item_recovers'),
 'repeat-failure-log': ('src/codex.rs',
                        'if candidate.last_class != Some(class) {',
                        'if true {',
                        'va41_repeated_failure_logs_only_class_transition_without_values'),
 'log-owner-value': ('src/codex.rs',
                     'tracing::info!(class, "codex startup recovery");',
                     'tracing::info!(class, owner_pid = candidate.owner_pid, "codex startup '
                     'recovery");',
                     'va41_repeated_failure_logs_only_class_transition_without_values'),
 'unknown-orphans-next-item': ('src/codex.rs',
                               'return Err(("handoff_unknown", false))',
                               'return Err(("handoff_unknown", true))',
                               'va41_unknown_handoff_does_not_orphan_later_pending_item'),
 'fresh-trusted-executable': ('src/codex.rs',
                              '|| is_trusted_codex_owner_step(&config, candidate.owner_pid, '
                              '&candidate.owner_starttime)\n'
                              '                .is_none()',
                              '|| false',
                              'va41_owner_starttime_change_clears_recovery_durably')}

TESTS = (
    "va41_restart_queued_message_wakes_without_mcp_or_hook",
    "va41_restart_revoked_root_never_wakes",
    "va41_restart_moved_writer_lock_keeps_queue_and_never_wakes",
    "va41_unavailable_relay_retries_without_another_message",
    "va41_repeated_restart_retains_pending_recovery",
    "va41_deliberate_session_end_is_not_restart_recovery",
    "va41_bad_rollout_remains_queued_and_awaiting_reattestation",
    "va41_auto_recovery_races_mcp_and_hook_with_one_carrier",
    "va41_owner_starttime_change_clears_recovery_durably",
    "va41_eight_item_bound_retains_recovery_until_scheduled_remainder",
    "va41_repeated_failure_logs_only_class_transition_without_values",
    "va41_cancelled_owned_push_becomes_unknown_and_next_item_recovers",
    "va41_cli_starts_production_retry_scheduler_without_new_message",
    "va41_unknown_handoff_does_not_orphan_later_pending_item",
)


def arm(name, mutation, seed):
    with tempfile.TemporaryDirectory(prefix=f"va41-{name}-") as scratch:
        checkout = Path(scratch) / "source"
        checkout.mkdir()
        files = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for relative in filter(None, files):
            dest = checkout / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, dest)
        selected = "va41_" if mutation is None else mutation[3]
        if mutation:
            file, old, new, _ = mutation
            dest = checkout / file
            dest.write_text(replace_once(dest.read_text(), old, new))
        marker = f"va41-arm:{NONCE}:{name}"
        test = checkout / TEST_FILE
        original = test.read_text()
        if mutation is None:
            instrumented, count = re.subn(r"async fn (va41_\w+)\(\) \{", lambda m: m[0] + f'\n    eprintln!("{marker}:{m[1]}");', original)
            if count != len(TESTS):
                raise RuntimeError(f"VA41 control inventory changed: {count}")
        else:
            instrumented = replace_once(original, f"async fn {selected}() {{", f'async fn {selected}() {{\n    eprintln!("{marker}");')
        test.write_text(instrumented)
        source_hash = hashlib.sha256()
        for relative in sorted(filter(None, files)):
            source_hash.update(relative.encode())
            source_hash.update((checkout / relative).read_bytes())
        target = Path(scratch) / "target"
        target.mkdir()
        # Reuse only dependency compilation, in a distinct directory per arm.
        shutil.copytree(seed / "debug", target / "debug", symlinks=True)
        env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CARGO_BUILD_JOBS": "4"}
        subprocess.run(["cargo", "clean", "-p", "xmsg"], cwd=checkout, env=env, check=True, capture_output=True)
        build = subprocess.run(["cargo", "test", "--offline", "--locked", "--test", "gate_ha9_codex", "--no-run", "--message-format=json"], cwd=checkout, env=env, text=True, capture_output=True, timeout=900)
        if build.returncode:
            raise RuntimeError(f"{name}: build failure is not a killed mutant:\n{build.stderr}")
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        binaries = [a for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("target", {}).get("name") == "gate_ha9_codex" and a.get("executable")]
        libraries = [a for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("target", {}).get("name") == "xmsg" and "lib" in a.get("target", {}).get("kind", [])]
        mains = [a for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("target", {}).get("name") == "xmsg" and "bin" in a.get("target", {}).get("kind", []) and a.get("executable")]
        if len(binaries) != 1 or binaries[0]["fresh"] or len(libraries) != 1 or libraries[0]["fresh"] or len(mains) != 1 or mains[0]["fresh"]:
            raise RuntimeError(f"{name}: missing freshly built test/library/main")
        binary = Path(binaries[0]["executable"])
        result = subprocess.run([str(binary), selected, *(["--exact"] if mutation else []), "--nocapture"], cwd=checkout, env=env, text=True, capture_output=True, timeout=60)
        output = result.stdout + result.stderr
        if marker not in output or ("running 1 test" if mutation else f"running {len(TESTS)} tests") not in output:
            raise RuntimeError(f"{name}: intended compiled arm did not execute: {output}")
        if result.returncode != (0 if mutation is None else 101):
            raise RuntimeError(f"{name}: unexpected test outcome {result.returncode}: {output}")
        print(json.dumps({"nonce": NONCE, "arm": name, "source_sha256": source_hash.hexdigest(), "artifact": str(binary), "artifact_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "main_artifact_sha256": hashlib.sha256(Path(mains[0]["executable"]).read_bytes()).hexdigest(), "target": str(target), "exit": result.returncode, "marker": marker}), flush=True)
        print(output, flush=True)


def main():
    subprocess.run(
        ["cargo", "test", "--locked", "--test", "gate_ha9_codex", "--no-run"],
        cwd=ROOT,
        env={**os.environ, "CARGO_TARGET_DIR": str(SEED), "CARGO_BUILD_JOBS": "4"},
        check=True,
        timeout=900,
    )
    # Freeze the dependency seed before running arms; do not share mutable build directories.
    arm("control", None, SEED)
    if not CASES:
        raise RuntimeError("no source mutants registered")
    for name, mutation in CASES.items():
        arm(name, mutation, SEED)
        arm(f"{name}-restored", None, SEED)
    print(f"VA41 {len(CASES)}/{len(CASES)} source mutants killed; control GREEN", flush=True)


if __name__ == "__main__":
    main()
