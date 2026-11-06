"""Single-site source mutants for the shared transport; no runtime mutation flags."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("bounded-read", "src/client/mod.rs", ".take(self.max_frame_bytes as u64 + 1)", "", "oversized_and_unterminated_frames_are_refused"),
    ("registration-deadline", "src/client/mod.rs", "timeout(options.operation_timeout, async", "timeout(Duration::from_secs(60), async", "registration_deadline_is_a_client_error"),
    ("required-origin", "src/client/mod.rs", "let parsed: ServiceResponse = match serde_json::from_value(response)", 'let parsed: ServiceResponse = match serde_json::from_value({ let mut response = response; response.as_object_mut().unwrap().entry("origin").or_insert(serde_json::json!({"node":"fixture"})); response })', "delivery_requires_origin_and_preserves_all_origin_kinds"),
    ("wrong-registration-node", "src/client/mod.rs", 'is_some_and(|node| node != &registration.node)', 'is_some_and(|_node| false)', "missing_or_wrong_registration_identity_is_refused"),
    ("agent-version", "src/client/mod.rs", "schema_version: Some(SCHEMA_VERSION),", "schema_version: None,", "socket_specific_exact_frame_keys"),
    ("forbidden-sender-field", "src/client/mod.rs", "as_agent: None,", 'as_agent: Some("injected".to_owned()),', "socket_specific_exact_frame_keys"),
    ("normal-edge-leak", "Cargo.toml", 'client = []', 'client = ["dep:rusqlite"]', "@graph"),
    ("self-dev-default-leak", "Cargo.toml", 'xmsg = { path = ".", default-features = false, features = ["test-hooks"] }', 'xmsg = { path = ".", features = ["test-hooks"] }', "@feature"),
    ("live-wrong-revision", "ci/xmsg-pin.toml", "9b5bd5e241554d345bcb394cc5dfffcf4fa0ee9b", "9d1f5fa38356a8f9208594db951c8e6502fe8e5d", "@live"),
    ("live-agent-version", "src/client/mod.rs", "pub const SCHEMA_VERSION: u32 = 2;", "pub const SCHEMA_VERSION: u32 = 3;", "@live"),
    ("live-register-version", "src/client/mod.rs", "serde_json::to_vec(request)", 'serde_json::to_vec(&{ let mut v = serde_json::to_value(request).unwrap(); v.as_object_mut().unwrap().insert("schema_version".into(), serde_json::json!(2)); v })', "@live"),
    ("live-register-skip-service-name-validation", "src/svc.rs", "if let Err(e) = crate::claim::validate_service_name(&name) {", "if let Err(e) = Ok::<(), AppError>(()) {", "@live"),
    ("live-register-allow-second-service-per-process", "src/svc.rs", "existing.session_id != session_id", "false", "@live"),
    ("live-check-origin-skip-service-name-validation", "src/fed.rs", "(Some(name), None) => crate::claim::validate_service_name(name),", "(Some(_name), None) => Ok(()),", "@live"),
    ("live-register-declared-reply-ttl", "src/svc.rs", "let reply_ttl_secs = state.reply_ttl.as_secs();", "let reply_ttl_secs = storage::DEFAULT_REPLY_TTL_SECS;", "@live"),
    ("live-register-declared-idempotency-ttl", "src/svc.rs", "let idempotency_ttl_secs = state.idempotency_ttl.as_secs();", "let idempotency_ttl_secs = storage::DEFAULT_IDEMPOTENCY_TTL_SECS;", "@live"),
    ("live-register-declared-svc-queue-cap", "src/svc.rs", "let svc_queue_cap = storage::svc_queue_cap_for_db(&state.db);", "let svc_queue_cap = storage::MAX_SVC_QUEUE_PER_SESSION;", "@live"),
    ("client-validate-service-name", "src/client/mod.rs", 'if name == "xmsg" {', "if false {", "exported_service_name_validator_matches_mesh_and_refusals"),
    ("live-skip", "tests/shared_client_live.rs", "let baseline = PathBuf::from", "return; let baseline = PathBuf::from", "@live"),
    ("agent-deadline", "src/client/mod.rs", "timeout(self.options.operation_timeout, async", "timeout(Duration::from_secs(60), async", "agent_deadline_is_unknown_not_a_confirmed_refusal"),
    ("registration-address-fallback", "src/client/mod.rs", "serde_json::from_value(response).map_err(|_| ClientError::Protocol)?", 'serde_json::from_value({ let mut r = response; r.as_object_mut().unwrap().entry("address").or_insert(serde_json::json!(format!("{}@{}", options.service, options.expected_node.as_deref().unwrap()))); r }).map_err(|_| ClientError::Protocol)?', "missing_or_wrong_registration_identity_is_refused"),
    ("registration-lifetime", "src/client/mod.rs", "live.store(false, Ordering::Release);", "live.store(true, Ordering::Release);", "long_poll_does_not_block_agent_and_handle_expires_with_registration"),
    ("missing-test-target", "Cargo.toml", '[[test]]\nname = "agent_sock"\npath = "tests/agent_sock.rs"\nrequired-features = ["daemon"]', "", "@graph"),
    ("empty-registration-node", "src/client/mod.rs", "|| registration.node.is_empty()", "|| false", "registration_identity_modes"),
    ("ignored-daemon-uid", "src/client/mod.rs", "let parent = file.parent()", "let expected_uid = unsafe { libc::geteuid() }; let parent = file.parent()", "registration_identity_modes"),
    ("poll-deadline", "src/client/mod.rs", "timeout(wait, connection.exchange(&frame))", "timeout(Duration::from_secs(3600), connection.exchange(&frame))", "service_deadlines_expire_and_drop_registration"),
]


def run(directory, test):
    env = {**os.environ, "CARGO_TARGET_DIR": str(ROOT / "target" / "client-mutants")}
    if test == "@graph":
        return subprocess.run(["python3", "scripts/client-graph.py"], cwd=directory, env=env, capture_output=True, text=True, timeout=60)
    profile = env.get("CARGO_PROFILE", "dev")
    # Clear only this package: copied source trees must not reuse a prior mutant binary.
    subprocess.run(["cargo", "clean", "-p", "xmsg", "--profile", profile], cwd=directory, env=env, check=True, capture_output=True, timeout=120)
    argv = ["cargo", "test", "--locked", "--profile", profile]
    if test == "@live":
        argv += ["--test", "shared_client_live"]
        target, selected, runtime_args = "shared_client_live", "pinned_and_candidate_service_contract", ["--ignored", "--nocapture"]
    elif test == "@feature":
        argv += ["--no-default-features", "--features", "client", "--lib"]
        target, selected, runtime_args = "xmsg", "client::feature_tests::no_daemon", ["--ignored"]
    else:
        argv += ["--no-default-features", "--features", "client", "--test", "shared_client"]
        target, selected, runtime_args = "shared_client", test, []
    # Compilation has a separate budget; a build timeout is never a rejecting test.
    build = subprocess.run([*argv, "--no-run", "--message-format=json"], cwd=directory, env=env, capture_output=True, text=True, timeout=900)
    if build.returncode:
        return build
    executables = []
    for line in build.stdout.splitlines():
        try:
            artifact = json.loads(line)
        except json.JSONDecodeError:
            continue
        if artifact.get("reason") == "compiler-artifact" and artifact.get("target", {}).get("name") == target and artifact.get("profile", {}).get("test") and artifact.get("executable"):
            executables.append(artifact["executable"])
    assert len(executables) == 1 and Path(executables[0]).is_file(), ("missing intended test executable", target, build.stdout)
    return subprocess.run([executables[0], selected, "--exact", *runtime_args], cwd=directory, env=env, capture_output=True, text=True, timeout=90 if test == "@live" else 30)


def main():
    live = "--live" in sys.argv[1:]
    cases = [case for case in CASES if (case[-1] == "@live") == live]
    for name, filename, old, new, test in cases:
        with tempfile.TemporaryDirectory(prefix="xmsg-client-mutant-") as directory:
            dest = Path(directory)
            for file in ("Cargo.toml", "Cargo.lock"):
                shutil.copy2(ROOT / file, dest / file)
            for folder in ("src", "tests", "scripts", "ci"):
                shutil.copytree(ROOT / folder, dest / folder)
            green = run(dest, test)
            marker = "forbidden dependencies absent with live daemon positive control" if test == "@graph" else "1 passed; 0 failed; 0 ignored"
            assert green.returncode == 0 and marker in green.stdout and (test != "@live" or "shared-client: verified baseline and candidate service contract completed" in green.stdout), (name, "invalid green", green.stdout, green.stderr)
            source = dest / filename
            text = source.read_text()
            expected_count = 3 if name in ("forbidden-sender-field", "agent-version") else 1
            assert text.count(old) == expected_count, (name, text.count(old))
            source.write_text(text.replace(old, new, 1))
            red = run(dest, test)
            if test == "@graph":
                reason = "test target inventory mismatch" if name == "missing-test-target" else "rusqlite"
                assert red.returncode == 1 and "AssertionError" in red.stderr and reason in red.stderr, (name, red.stdout, red.stderr)
            elif name == "live-skip":
                assert red.returncode == 0 and "1 passed; 0 failed; 0 ignored" in red.stdout and "shared-client: verified baseline and candidate service contract completed" not in red.stdout, (name, red.stdout, red.stderr)
            else:
                failed = "pinned_and_candidate_service_contract" if test == "@live" else ("client::feature_tests::no_daemon" if test == "@feature" else test)
                assert red.returncode == 101 and f"test {failed} ... FAILED" in red.stdout, (name, "survived or wrong red", red.stdout, red.stderr)
            evidence = ROOT / ".artifacts" / "client-mutants"
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / (name + ".log")).write_text(red.stdout + red.stderr)
            print(name + ": GREEN baseline, RED intended test", flush=True)
    print(f"{len(cases)}/{len(cases)} shared-client mutants killed", flush=True)


if __name__ == "__main__":
    main()
