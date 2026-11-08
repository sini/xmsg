"""XA6 single-site source mutants, each built and executed in an isolated artifact directory."""
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
TEST_FILE = "tests/e2e_agy_delivery.rs"
EXIT_ZERO_BODY = "xa6_exit_zero_body_with_trigger_phrases_delivers_without_stale_and_records_message"
STALE_QUEUE_REARM = "xa6_genuine_auth_failure_marks_stale_queues_records_message_rearms_watcher_and_flushes"
NONZERO_RESPONSE_ONLY = "xa6_nonzero_exit_phrases_in_response_without_error_field_not_stale"
NONZERO_STDERR_PHRASES = "xa6_nonzero_exit_phrases_on_stderr_with_non_auth_error_not_stale"
SEED = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
NONCE = uuid.uuid4().hex


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"expected one mutation site: {old!r}")
    return text.replace(old, new)


CASES = {
    "M1-scan-stdout-again": (
        "src/agy.rs",
        '    if output.status.success() {\n        return Ok(());\n    }\n\n    let stderr_excerpt: String = String::from_utf8_lossy(&output.stderr)\n        .chars()\n        .take(200)\n        .collect();\n    let parsed_error: Option<String> = serde_json::from_slice::<serde_json::Value>(&output.stdout)\n        .ok()\n        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string));\n    let error_str = parsed_error.as_deref().unwrap_or("");',
        '    let stderr_excerpt = String::new();\n    let stdout_raw = String::from_utf8_lossy(&output.stdout);\n    let error_str: &str = &stdout_raw;',
        EXIT_ZERO_BODY,
    ),
    "M2-has-credentials-ignores-is-stale": (
        "src/agy.rs",
        "    pub fn has_credentials(&self) -> bool {\n        self.credentials.as_ref().is_some_and(|c| !c.is_stale)\n    }",
        "    pub fn has_credentials(&self) -> bool {\n        self.credentials.is_some()\n    }",
        STALE_QUEUE_REARM,
    ),
    "M3-drop-or-error-instead-of-queue": (
        "src/surface.rs",
        '                    Ok(_) => return Ok((session.session_id.clone(), "agy", "delivered")),\n                    Err(AppError::CredentialsStale(_)) => {}\n                    Err(e) => return Err(e),',
        '                    Ok(_) => return Ok((session.session_id.clone(), "agy", "delivered")),\n                    Err(e) => return Err(e),',
        STALE_QUEUE_REARM,
    ),
    "M4-push-reply-sender-gone-on-stale": (
        "src/surface.rs",
        '                            Ok(()) => return "pushed",\n                            Err(AppError::CredentialsStale(_)) => {}\n                            Err(AppError::Gone { .. }) => return "sender_gone",',
        '                            Ok(()) => return "pushed",\n                            Err(AppError::Gone { .. }) | Err(AppError::CredentialsStale(_)) => return "sender_gone",',
        STALE_QUEUE_REARM,
    ),
    "M5-proc-watcher-no-rearm-on-escrow": (
        "src/agy.rs",
        "                res = escrow_rx.changed() => {\n                    if res.is_err() {\n                        return;\n                    }\n                    armed.extend(stale_agy_conversations(&store));",
        "                res = escrow_rx.changed() => {\n                    if res.is_err() {\n                        return;\n                    }",
        STALE_QUEUE_REARM,
    ),
    "M6-classify-raw-stdout-instead-of-parsed-error": (
        "src/agy.rs",
        '    let error_str = parsed_error.as_deref().unwrap_or("");',
        '    let stdout_raw = String::from_utf8_lossy(&output.stdout);\n    let error_str: &str = &stdout_raw;',
        NONZERO_RESPONSE_ONLY,
    ),
    "M7-classify-from-stderr": (
        "src/agy.rs",
        '    let error_str = parsed_error.as_deref().unwrap_or("");',
        '    let stderr_raw = String::from_utf8_lossy(&output.stderr);\n    let error_str: &str = &stderr_raw;',
        NONZERO_STDERR_PHRASES,
    ),
}


def arm(name, mutation, seed):
    with tempfile.TemporaryDirectory(prefix=f"xa6-{name}-") as scratch:
        checkout = Path(scratch) / "source"
        checkout.mkdir()
        files = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for relative in filter(None, files):
            dest = checkout / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, dest)
        selected = "xa6_" if mutation is None else mutation[3]
        if mutation:
            file, old, new, _ = mutation
            dest = checkout / file
            dest.write_text(replace_once(dest.read_text(), old, new))
        marker = f"xa6-arm:{NONCE}:{name}"
        test = checkout / TEST_FILE
        original = test.read_text()
        if mutation is None:
            instrumented, count = re.subn(
                r"async fn (xa6_\w+)\(\) \{",
                lambda m: m[0] + f'\n    eprintln!("{marker}:{m[1]}");',
                original,
            )
            if count != 5:
                raise RuntimeError(f"XA6 control inventory changed: {count}")
        else:
            instrumented = replace_once(
                original,
                f"async fn {selected}() {{",
                f'async fn {selected}() {{\n    eprintln!("{marker}");',
            )
        test.write_text(instrumented)
        source_hash = hashlib.sha256()
        for relative in sorted(filter(None, files)):
            source_hash.update(relative.encode())
            source_hash.update((checkout / relative).read_bytes())
        target = Path(scratch) / "target"
        target.mkdir()
        shutil.copytree(seed / "debug", target / "debug", symlinks=True)
        env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CARGO_BUILD_JOBS": "4"}
        subprocess.run(
            ["cargo", "clean", "-p", "xmsg"],
            cwd=checkout,
            env=env,
            check=True,
            capture_output=True,
        )
        build = subprocess.run(
            [
                "cargo",
                "test",
                "--offline",
                "--locked",
                "--test",
                "e2e_agy_delivery",
                "--no-run",
                "--message-format=json",
            ],
            cwd=checkout,
            env=env,
            text=True,
            capture_output=True,
            timeout=900,
        )
        if build.returncode:
            raise RuntimeError(f"{name}: build failure is not a killed mutant:\n{build.stderr}")
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        binaries = [
            a
            for a in artifacts
            if a.get("reason") == "compiler-artifact"
            and a.get("target", {}).get("name") == "e2e_agy_delivery"
            and a.get("executable")
        ]
        libraries = [
            a
            for a in artifacts
            if a.get("reason") == "compiler-artifact"
            and a.get("target", {}).get("name") == "xmsg"
            and "lib" in a.get("target", {}).get("kind", [])
        ]
        if len(binaries) != 1 or binaries[0]["fresh"] or len(libraries) != 1 or libraries[0]["fresh"]:
            raise RuntimeError(f"{name}: missing freshly built test/library")
        binary = Path(binaries[0]["executable"])
        result = subprocess.run(
            [str(binary), selected, *(["--exact"] if mutation else []), "--nocapture"],
            cwd=checkout,
            env=env,
            text=True,
            capture_output=True,
            timeout=60,
        )
        output = result.stdout + result.stderr
        if marker not in output or ("running 1 test" if mutation else "running 5 tests") not in output:
            raise RuntimeError(f"{name}: intended compiled arm did not execute: {output}")
        if result.returncode != (0 if mutation is None else 101):
            raise RuntimeError(f"{name}: unexpected test outcome {result.returncode}: {output}")
        print(
            json.dumps(
                {
                    "nonce": NONCE,
                    "arm": name,
                    "source_sha256": source_hash.hexdigest(),
                    "artifact": str(binary),
                    "artifact_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "target": str(target),
                    "exit": result.returncode,
                    "marker": marker,
                }
            ),
            flush=True,
        )
        print(output, flush=True)


def main():
    arm("control", None, SEED)
    for name, mutation in CASES.items():
        arm(name, mutation, SEED)
    print(f"XA6 {len(CASES)}/{len(CASES)} source mutants killed; control GREEN", flush=True)


if __name__ == "__main__":
    main()
