"""XR8 source mutants, each built and executed in an isolated artifact directory."""
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
AUTOMATIC = "xr8_automatic_admission_errors_recover_on_next_attestation"
HISTORY = "xr8_resume_ignores_historical_file_identity_after_unrevoke"
LIVE = "xr8_metadata_failure_is_recoverable_without_operator_unrevoke"
SEED = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
NONCE = uuid.uuid4().hex


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"expected one mutation site: {old!r}")
    return text.replace(old, new)


def automatic_site(reason):
    old = f'self.park_root_for_resume(root_id);\n                    format!("codex root {{root_id}} {reason}'
    return ("src/codex.rs", old, old.replace("park_root_for_resume", "revoke_by_operator"), AUTOMATIC)


CASES = {
    "O1-dev-only-reboot": ("src/codex.rs", "        let prior = self.stale_roots.get(root_id).cloned();", "        let prior = self.stale_roots.get(root_id).cloned();\n        if prior.as_ref().is_some_and(|p| p.rollout_dev != rollout_meta.rollout_dev && p.rollout_ino == rollout_meta.rollout_ino) { return Err(\"device changed with same inode\".into()); }", HISTORY),
    "O2-sweep-operator": ("src/codex.rs", "let _ = self.park_root_for_resume(&id);", "let _ = self.revoke_by_operator(&id);", "xr8_sweep_lease_loss_is_recoverable"),
    "O3-park-unrevokes": ("src/codex.rs", "pub fn park_root_for_resume(&mut self, root_id: &str) -> Option<(u32, u64)> {", "pub fn park_root_for_resume(&mut self, root_id: &str) -> Option<(u32, u64)> {\n        self.revoked_by_operator.remove(root_id);", "c17_resume_reattestation_all_cases_and_revoked_by_operator_with_valid_witness"),
    "O4-sqlite-only-operator": ("src/agent.rs", 'let _ = crate::storage::park_codex_root(&db, session_id);\n                    }\n                    Err(AppError::NotRecipient(format!(\n                        "unsupported or missing SessionStart source', 'let _ = crate::storage::invalidate_codex_root(&db, session_id);\n                    }\n                    Err(AppError::NotRecipient(format!(\n                        "unsupported or missing SessionStart source', AUTOMATIC),
    "direct-parentage": ("src/codex.rs", "if actual_parent != expected_parent {", "if false {", "c5_c6_server_enforcement_and_direct_child_admission"),
    "nested-meta-provenance": ("src/mcp.rs", '.and_then(|p| p.get("_meta"))', '.and_then(|p| p.get("arguments").and_then(|a| a.get("_meta")).or_else(|| p.get("_meta")))', "c1_xh1_and_metadata_boundary_sidecar_before_server"),
    "historical-dev": ("src/codex.rs", "        let prior = self.stale_roots.get(root_id).cloned();", "        let prior = self.stale_roots.get(root_id).cloned();\n        if prior.as_ref().is_some_and(|p| p.rollout_dev != rollout_meta.rollout_dev) { return Err(\"historical device mismatch\".into()); }", HISTORY),
    "historical-inode": ("src/codex.rs", "        let prior = self.stale_roots.get(root_id).cloned();", "        let prior = self.stale_roots.get(root_id).cloned();\n        if prior.as_ref().is_some_and(|p| p.rollout_ino != rollout_meta.rollout_ino) { return Err(\"historical inode mismatch\".into()); }", "xr8_valid_rollout_replacement_keeps_root_and_child_usable"),
    "fresh-live-operator": automatic_site("rollout revalidation failed"),
    "resume-live-operator": automatic_site("rollout verification failed on resume"),
    "fresh-invalid-operator": ("src/codex.rs", "if matches!(e, RolloutLookupError::Invalid(_)) {\n                    self.park_root_for_resume(root_id);", "if matches!(e, RolloutLookupError::Invalid(_)) {\n                    self.revoke_by_operator(root_id);", AUTOMATIC),
    "resume-invalid-operator": ("src/codex.rs", "Err(RolloutLookupError::Invalid(e)) => {\n                self.park_root_for_resume(root_id);", "Err(RolloutLookupError::Invalid(e)) => {\n                self.revoke_by_operator(root_id);", AUTOMATIC),
    "validation-operator": ("src/codex.rs", 'self.park_root_for_resume(root_id);\n                return Err(format!(\n                    "codex root {root_id} rollout verification failed:', 'self.revoke_by_operator(root_id);\n                return Err(format!(\n                    "codex root {root_id} rollout verification failed:', LIVE),
    "unsupported-source-operator": ("src/agent.rs", "let _ = rt.store.park_root_for_resume(session_id);", "let _ = rt.store.revoke_by_operator(session_id);", AUTOMATIC),
}


def arm(name, mutation, seed):
    with tempfile.TemporaryDirectory(prefix=f"xr8-{name}-") as scratch:
        checkout = Path(scratch) / "source"
        checkout.mkdir()
        files = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for relative in filter(None, files):
            dest = checkout / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, dest)
        selected = "xr8_" if mutation is None else mutation[3]
        if mutation:
            file, old, new, _ = mutation
            dest = checkout / file
            dest.write_text(replace_once(dest.read_text(), old, new))
        marker = f"xr8-arm:{NONCE}:{name}"
        test = checkout / TEST_FILE
        original = test.read_text()
        if mutation is None:
            instrumented, count = re.subn(r"async fn (xr8_\w+)\(\) \{", lambda m: m[0] + f'\n    eprintln!("{marker}:{m[1]}");', original)
            if count != 6:
                raise RuntimeError(f"XR8 control inventory changed: {count}")
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
        if len(binaries) != 1 or binaries[0]["fresh"] or len(libraries) != 1 or libraries[0]["fresh"]:
            raise RuntimeError(f"{name}: missing freshly built test/library")
        binary = Path(binaries[0]["executable"])
        result = subprocess.run([str(binary), selected, *(["--exact"] if mutation else []), "--nocapture"], cwd=checkout, env=env, text=True, capture_output=True, timeout=60)
        output = result.stdout + result.stderr
        if marker not in output or ("running 1 test" if mutation else "running 6 tests") not in output:
            raise RuntimeError(f"{name}: intended compiled arm did not execute: {output}")
        if result.returncode != (0 if mutation is None else 101):
            raise RuntimeError(f"{name}: unexpected test outcome {result.returncode}: {output}")
        print(json.dumps({"nonce": NONCE, "arm": name, "source_sha256": source_hash.hexdigest(), "artifact": str(binary), "artifact_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "target": str(target), "exit": result.returncode, "marker": marker}), flush=True)
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
    for name, mutation in CASES.items():
        arm(name, mutation, SEED)
    print(f"XR8 {len(CASES)}/{len(CASES)} source mutants killed; control GREEN", flush=True)


if __name__ == "__main__":
    main()
