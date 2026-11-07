"""Single-site source mutants for the shared transport; no runtime mutation flags."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import hashlib
import uuid

RUN_NONCE = uuid.uuid4().hex
ARTIFACT_VARIANTS = {}


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)

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
    ("live-reregister-eof-clobbers-newer-token", "src/svc.rs", "&& info.token == my_token", "", "@live"),
    ("live-check-origin-skip-service-name-validation", "src/fed.rs", "(Some(name), None) => crate::claim::validate_service_name(name),", "(Some(_name), None) => Ok(()),", "@live"),
    ("live-register-declared-reply-ttl", "src/svc.rs", "let reply_ttl_secs = state.reply_ttl.as_secs();", "let reply_ttl_secs = storage::DEFAULT_REPLY_TTL_SECS;", "@live"),
    ("live-register-declared-idempotency-ttl", "src/svc.rs", "let idempotency_ttl_secs = state.idempotency_ttl.as_secs();", "let idempotency_ttl_secs = storage::DEFAULT_IDEMPOTENCY_TTL_SECS;", "@live"),
    ("live-register-declared-svc-queue-cap", "src/svc.rs", "let svc_queue_cap = storage::svc_queue_cap_for_db(&state.db);", "let svc_queue_cap = storage::MAX_SVC_QUEUE_PER_SESSION;", "@live"),
    ("live-register-declared-max-body-bytes", "src/svc.rs", "let max_body_bytes = state.max_body;", "let max_body_bytes = storage::DEFAULT_MAX_BODY_BYTES;", "@live"),
    ("client-validate-service-name", "src/client/mod.rs", 'if name == "xmsg" {', "if false {", "exported_service_name_validator_matches_mesh_and_refusals"),
    ("live-skip", "tests/shared_client_live.rs", "let baseline = PathBuf::from", "return; let baseline = PathBuf::from", "@live"),
    ("agent-deadline", "src/client/mod.rs", "timeout(self.options.operation_timeout, async", "timeout(Duration::from_secs(60), async", "agent_deadline_is_unknown_not_a_confirmed_refusal"),
    ("registration-address-fallback", "src/client/mod.rs", "serde_json::from_value(response).map_err(|_| ClientError::Protocol)?", 'serde_json::from_value({ let mut r = response; r.as_object_mut().unwrap().entry("address").or_insert(serde_json::json!(format!("{}@{}", options.service, options.expected_node.as_deref().unwrap()))); r }).map_err(|_| ClientError::Protocol)?', "missing_or_wrong_registration_identity_is_refused"),
    ("registration-lifetime", "src/client/mod.rs", "live.dispose();", "();", "long_poll_does_not_block_agent_and_handle_expires_with_registration"),
    ("missing-test-target", "Cargo.toml", '[[test]]\nname = "agent_sock"\npath = "tests/agent_sock.rs"\nrequired-features = ["daemon"]', "", "@graph"),
    ("empty-registration-node", "src/client/mod.rs", "|| registration.node.is_empty()", "|| false", "registration_identity_modes"),
    ("ignored-daemon-uid", "src/client/mod.rs", "let parent = file.parent()", "let expected_uid = unsafe { libc::geteuid() }; let parent = file.parent()", "registration_identity_modes"),
    ("poll-deadline", "src/client/mod.rs", "timeout(wait, connection.exchange(&frame))", "timeout(Duration::from_secs(3600), connection.exchange(&frame))", "service_deadlines_expire_and_drop_registration"),
    ("health-pending-preservation", "src/client/health.rs", "libc::MSG_PEEK | libc::MSG_DONTWAIT", "libc::MSG_DONTWAIT", "registration_health_preserves_pending_frames_and_detects_shutdown"),
    ("health-shutdown-behind-data", "src/client/health.rs", "if shutdown(fd)? {", "if false {", "registration_health_preserves_pending_frames_and_detects_shutdown"),
    ("health-post-failure", "src/client/mod.rs", "if result.is_err() {\n            self.health()?;\n        }", "if false { self.health()?; }", "registration_health_distinguishes_refusal_from_disconnect_after_request"),
    ("health-accepted-receipt", "src/client/mod.rs", "if result.is_err() {", "if true {", "registration_health_distinguishes_refusal_from_disconnect_after_request"),
    ("health-no-wire-effects", "src/client/health.rs", "let mut byte = 0_u8;", 'let frame = b"{\\"action\\":\\"poll\\",\\"waitSecs\\":0}\\n"; unsafe { libc::send(fd, frame.as_ptr().cast(), frame.len(), libc::MSG_DONTWAIT); } let mut byte = 0_u8;', "registration_health_is_idle_and_snapshots_die_with_owner"),
    ("health-idle-eof", "src/client/health.rs", "return Err(ClientError::Disconnected);", "return Ok(());", "registration_health_detects_idle_eof_and_half_close"),
    ("health-disposal-reuse", "src/client/health.rs", "*self.descriptor.lock().unwrap_or_else(|e| e.into_inner()) = None;", "();", "@health-disposal"),
    ("live-health-eof", "src/client/mod.rs", "self.live.check()", "Ok(())", "@live"),
    ("health-timeout-recheck", "src/client/mod.rs", ".map_err(|_| ClientError::Timeout)\n        .and_then(|result| result)", ".map_err(|_| ClientError::Timeout)?", "registration_health_rechecks_after_an_agent_timeout"),
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
    elif test == "@health-disposal":
        argv += ["--no-default-features", "--features", "client", "--lib"]
        target, selected, runtime_args = "xmsg", "client::health::tests::disposed_descriptor_cannot_become_a_new_registration", []
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
            if artifact.get("fresh") is not False:
                raise RuntimeError(("cached intended test executable", target))
            executables.append(artifact["executable"])
    require(len(executables) == 1 and Path(executables[0]).is_file(), ("missing intended test executable", target, build.stdout))
    executable = Path(executables[0])
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    source = hashlib.sha256()
    for file in sorted(file for folder in ("src", "tests", "ci") for file in (Path(directory) / folder).rglob("*") if file.is_file()):
        source.update(str(file.relative_to(directory)).encode())
        source.update(file.read_bytes())
    for file in ("Cargo.toml", "Cargo.lock"):
        source.update((Path(directory) / file).read_bytes())
    variant = source.hexdigest()
    if digest in ARTIFACT_VARIANTS and ARTIFACT_VARIANTS[digest] != variant:
        raise RuntimeError("test executable hash reused across source variants")
    ARTIFACT_VARIANTS[digest] = variant
    print(f"artifact nonce={RUN_NONCE} test={selected} path={executable} mtime_ns={executable.stat().st_mtime_ns} sha256={digest} source={variant}", flush=True)
    return subprocess.run([str(executable), selected, "--exact", *runtime_args], cwd=directory, env=env, capture_output=True, text=True, timeout=90 if test == "@live" else 30)


def main():
    live = "--live" in sys.argv[1:]
    cases = [case for case in CASES if (case[-1] == "@live") == live]
    require(len(cases) == (13 if live else 24), "client mutant inventory count changed")
    require(len({case[0] for case in CASES}) == len(CASES), "duplicate client mutant names")
    for name, filename, old, new, test in cases:
        with tempfile.TemporaryDirectory(prefix="xmsg-client-mutant-") as directory:
            dest = Path(directory)
            for file in ("Cargo.toml", "Cargo.lock"):
                shutil.copyfile(ROOT / file, dest / file)
            for folder in ("src", "tests", "scripts", "ci"):
                shutil.copytree(ROOT / folder, dest / folder, copy_function=shutil.copyfile)
            green = run(dest, test)
            marker = "forbidden dependencies absent with live daemon positive control" if test == "@graph" else "1 passed; 0 failed; 0 ignored"
            require(green.returncode == 0 and marker in green.stdout and (test != "@live" or "shared-client: verified baseline and candidate service contract completed" in green.stdout), (name, "invalid green", green.stdout, green.stderr))
            source = dest / filename
            text = source.read_text()
            expected_count = 3 if name in ("forbidden-sender-field", "agent-version") else (2 if name == "live-health-eof" else 1)
            require(text.count(old) == expected_count, (name, text.count(old)))
            source.write_text(text.replace(old, new, 1))
            red = run(dest, test)
            if test == "@graph":
                reason = "test target inventory mismatch" if name == "missing-test-target" else "rusqlite"
                require(red.returncode == 1 and "AssertionError" in red.stderr and reason in red.stderr, (name, red.stdout, red.stderr))
            elif name == "live-skip":
                require(red.returncode == 0 and "1 passed; 0 failed; 0 ignored" in red.stdout and "shared-client: verified baseline and candidate service contract completed" not in red.stdout, (name, red.stdout, red.stderr))
            else:
                failed = "pinned_and_candidate_service_contract" if test == "@live" else ("client::feature_tests::no_daemon" if test == "@feature" else ("client::health::tests::disposed_descriptor_cannot_become_a_new_registration" if test == "@health-disposal" else test))
                require(red.returncode == 101 and f"test {failed} ... FAILED" in red.stdout, (name, "survived or wrong red", red.stdout, red.stderr))
            evidence = ROOT / ".artifacts" / "client-mutants"
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / (name + ".log")).write_text(red.stdout + red.stderr)
            print(name + ": GREEN baseline, RED intended test", flush=True)
    print(f"{len(cases)}/{len(cases)} shared-client mutants killed", flush=True)


if __name__ == "__main__":
    main()
