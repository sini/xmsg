"""Single-site source mutants for the shared transport; no runtime mutation flags."""
import argparse
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import hashlib
import uuid
import re
import time

RUN_NONCE = uuid.uuid4().hex
ARTIFACT_VARIANTS = {}


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)

ROOT = Path(__file__).resolve().parents[1]
TARGET_DIR = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
if not TARGET_DIR.is_absolute():
    TARGET_DIR = ROOT / TARGET_DIR
TARGET_DIR = TARGET_DIR.resolve()
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
    ("live-reregister-eof-clobbers-newer-token", "src/svc.rs", ".is_some_and(|info| info.token == self.token)", ".is_some_and(|_| true)", "@live"),
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
    ("health-shutdown-behind-data", "src/client/health.rs", "shutdown(fd)? || ", "", "registration_health_preserves_pending_frames_and_detects_shutdown"),
    ("health-post-failure", "src/client/mod.rs", "if result.is_err() {\n            if let Err(ClientError::Disconnected) = self.health() {\n                return Err(ClientError::Disconnected);\n            }\n        }", "if false { self.health()?; }", "registration_health_distinguishes_refusal_from_disconnect_after_request"),
    ("health-recheck-preserves-error", "src/client/mod.rs", "if let Err(ClientError::Disconnected) = self.health() {\n                return Err(ClientError::Disconnected);\n            }", "self.health()?;", "registration_health_probe_io_error_does_not_mask_agent_error"),
    ("health-lock-across-io", "src/client/mod.rs", "        let mut response = Vec::new();\n        (&mut self.stream)\n            .take(self.max_frame_bytes as u64 + 1)\n            .read_until(b'\\n', &mut response)\n            .await?;", "        struct Hold<'a>(Option<std::sync::MutexGuard<'a, Option<std::os::fd::RawFd>>>); unsafe impl Send for Hold<'_> {} let _hold = Hold(self.registration.as_ref().map(|h| h.descriptor.lock().unwrap()));\n        let mut response = Vec::new();\n        (&mut self.stream)\n            .take(self.max_frame_bytes as u64 + 1)\n            .read_until(b'\\n', &mut response)\n            .await?;\n        drop(_hold);", "registration_health_can_race_a_split_response_reader"),
    ("health-accepted-receipt", "src/client/mod.rs", "if result.is_err() {", "if true {", "registration_health_distinguishes_refusal_from_disconnect_after_request"),
    ("health-no-wire-effects", "src/client/health.rs", "let mut byte = 0_u8;", 'let frame = b"{\\"action\\":\\"poll\\",\\"waitSecs\\":0}\\n"; unsafe { libc::send(fd, frame.as_ptr().cast(), frame.len(), libc::MSG_DONTWAIT); } let mut byte = 0_u8;', "registration_health_is_idle_and_snapshots_die_with_owner"),
    ("health-idle-eof", "src/client/health.rs", "return Err(ClientError::Disconnected);", "return Ok(());", "registration_health_detects_idle_eof_and_half_close"),
    ("health-disposal-reuse", "src/client/health.rs", "*self.descriptor.lock().unwrap_or_else(|e| e.into_inner()) = None;", "();", "@health-disposal"),
    ("live-health-eof", "src/client/mod.rs", "self.live.check()", "Ok(())", "@live"),
    ("health-timeout-recheck", "src/client/mod.rs", ".map_err(|_| ClientError::Timeout)\n        .and_then(|result| result)", ".map_err(|_| ClientError::Timeout)?", "registration_health_rechecks_after_an_agent_timeout"),
    ("health-peek-eof", "src/client/health.rs", "Ok(result == 0)", "Ok(false)", "@health-peek"),
    ("xr7-discard-db-error", "src/agent.rs", 'crate::storage::unrevoke_codex_root_by_operator(&db, sid).map_err(|e| {\n                AppError::Internal(format!("failed to persist codex unrevoke for \'{sid}\': {e}"))\n            })?;', "let _ = crate::storage::unrevoke_codex_root_by_operator(&db, sid);", "@codex-revoke"),
    ("xr7-connect-failure-ok", "src/agent.rs", "let resp = crate::mcp::call_agent_sock(&sock_path, &frame)?;", "let Ok(resp) = crate::mcp::call_agent_sock(&sock_path, &frame) else { return Ok(()); };", "@codex-revoke"),
]


LIVE_TESTS = ("@live", "@codex-revoke")


def is_daemon_mutation(changed_source):
    return changed_source is not None and changed_source.startswith("src/") and not changed_source.startswith("src/client/")


def validate_case(name, changed_source, test, *, app_present=None):
    if is_daemon_mutation(changed_source):
        require(test in LIVE_TESTS, ("daemon-source mutant requires live daemon hash evidence", name, changed_source, test))
        if app_present is not None:
            require(app_present, ("daemon-source mutant missing daemon binary hash guard", name, changed_source, test))


def self_test_daemon_hash_guard():
    for bad_args, expected_reason in (
        (("synthetic-daemon-nonlive", "src/svc.rs", "socket_specific_exact_frame_keys"), "daemon-source mutant requires live daemon hash evidence"),
        (("synthetic-daemon-no-app", "src/svc.rs", "@live"), "daemon-source mutant missing daemon binary hash guard"),
    ):
        kwargs = {"app_present": False} if expected_reason.endswith("hash guard") else {}
        try:
            validate_case(*bad_args, **kwargs)
        except RuntimeError as error:
            require(
                isinstance(error.args[0], tuple) and error.args[0][0] == expected_reason,
                ("unexpected self-test error", error.args),
            )
        else:
            raise RuntimeError(("daemon hash guard self-test failed to reject", bad_args))
    validate_case("synthetic-client-nonlive", "src/client/mod.rs", "socket_specific_exact_frame_keys", app_present=False)
    for name, filename, _old, _new, test in CASES:
        validate_case(name, filename, test)


def run(directory, test, *, changed_source=None, label="probe"):
    if test == "@graph":
        return run_marked(directory, test, changed_source, None)
    if test == "@live":
        entry, selected = "tests/shared_client_live.rs", "pinned_and_candidate_service_contract"
    elif test == "@codex-revoke":
        entry, selected = "tests/gate_ha9_codex.rs", "xr7_codex_unrevoke_cli_and_sqlite_first_persistence"
    elif test in ("@feature", "@health-disposal", "@health-peek"):
        entry = "src/client/mod.rs" if test == "@feature" else "src/client/health.rs"
        selected = {"@feature": "no_daemon", "@health-disposal": "disposed_descriptor_cannot_become_a_new_registration", "@health-peek": "peek_observes_idle_data_and_eof_without_consumption"}[test]
    else:
        entry, selected = "tests/shared_client.rs", test
    source = Path(directory) / entry
    original = source.read_text()
    marker = f"client-mutant-arm:{RUN_NONCE}:{label}:{uuid.uuid4().hex}"
    inserted = f'\n    eprintln!({json.dumps(marker)});'
    if test in LIVE_TESTS:
        inserted += '\n    eprintln!("client-mutant-app:{}", env!("CARGO_BIN_EXE_xmsg"));'
    instrumented, count = re.subn(rf"\bfn {re.escape(selected)}\(\)\s*\{{", lambda match: match[0] + inserted, original)
    require(count == 1, ("missing named marker site", entry, selected))
    source.write_text(instrumented)
    try:
        result = run_marked(directory, test, changed_source, marker)
        if result.returncode in (0, 101):
            require(marker in result.stdout + result.stderr, ("compiled arm marker not executed", label, result.stdout, result.stderr))
        return result
    finally:
        source.write_text(original)


def report_build(output, *, marker, started, target_dir, result):
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    artifacts = []
    for line in (output or "").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("reason") == "compiler-artifact":
            artifacts.append(item)
    dependencies = [item for item in artifacts if not item.get("package_id", "").startswith("path+file:")]
    print("client-build-timing " + json.dumps({
        "arm": marker, "seconds": round(time.monotonic() - started, 3),
        "target_dir": str(target_dir), "result": result,
        "fresh_dependencies": len({item["package_id"] for item in dependencies if item.get("fresh")}),
        "rebuilt_dependencies": sorted({item["package_id"] for item in dependencies if item.get("fresh") is False}),
    }, sort_keys=True), flush=True)


def run_marked(directory, test, changed_source, marker):
    env = {**os.environ, "CARGO_TARGET_DIR": str(TARGET_DIR)}
    if test == "@graph":
        return subprocess.run(["python3", "scripts/client-graph.py"], cwd=directory, env=env, capture_output=True, text=True, timeout=60)
    profile = env.get("CARGO_PROFILE", "dev")
    # Clear only this package: copied source trees must not reuse a prior mutant binary.
    subprocess.run(["cargo", "clean", "-p", "xmsg", "--profile", profile], cwd=directory, env=env, check=True, capture_output=True, timeout=120)
    argv = ["cargo", "test", "--locked", "--profile", profile]
    if test == "@live":
        argv += ["--test", "shared_client_live"]
        target, selected, runtime_args = "shared_client_live", "pinned_and_candidate_service_contract", ["--ignored", "--nocapture"]
    elif test == "@codex-revoke":
        argv += ["--test", "gate_ha9_codex"]
        target, selected, runtime_args = "gate_ha9_codex", "xr7_codex_unrevoke_cli_and_sqlite_first_persistence", ["--nocapture"]
    elif test == "@feature":
        argv += ["--no-default-features", "--features", "client", "--lib"]
        target, selected, runtime_args = "xmsg", "client::feature_tests::no_daemon", ["--ignored"]
    elif test == "@health-disposal":
        argv += ["--no-default-features", "--features", "client", "--lib"]
        target, selected, runtime_args = "xmsg", "client::health::tests::disposed_descriptor_cannot_become_a_new_registration", []
    elif test == "@health-peek":
        argv += ["--no-default-features", "--features", "client", "--lib"]
        target, selected, runtime_args = "xmsg", "client::health::tests::peek_observes_idle_data_and_eof_without_consumption", []
    else:
        argv += ["--no-default-features", "--features", "client", "--test", "shared_client"]
        target, selected, runtime_args = "shared_client", test, []
    # Compilation has a separate budget; a build timeout is never a rejecting test.
    started = time.monotonic()
    print(f"client-build-start arm={marker} target={env['CARGO_TARGET_DIR']} profile={profile}", flush=True)
    try:
        build = subprocess.run([*argv, "--no-run", "--message-format=json"], cwd=directory, env=env, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired as error:
        report_build(error.stdout, marker=marker, started=started, target_dir=env["CARGO_TARGET_DIR"], result="build-timeout-not-a-kill")
        raise
    report_build(build.stdout, marker=marker, started=started, target_dir=env["CARGO_TARGET_DIR"], result=build.returncode)
    if build.returncode:
        return build
    executables = []
    artifacts = []
    for line in build.stdout.splitlines():
        try:
            artifact = json.loads(line)
        except json.JSONDecodeError:
            continue
        if artifact.get("reason") == "compiler-artifact":
            artifacts.append(artifact)
        if artifact.get("reason") == "compiler-artifact" and artifact.get("target", {}).get("name") == target and artifact.get("profile", {}).get("test") and artifact.get("executable"):
            if artifact.get("fresh") is not False:
                raise RuntimeError(("cached intended test executable", target))
            executables.append(artifact["executable"])
    require(len(executables) == 1 and Path(executables[0]).is_file(), ("missing intended test executable", target, build.stdout))
    if target != "xmsg":
        libraries = [item for item in artifacts if item.get("target", {}).get("name") == "xmsg" and "lib" in item.get("target", {}).get("kind", []) and not item.get("profile", {}).get("test")]
        require(len(libraries) == 1 and libraries[0].get("fresh") is False, ("cached or missing changed library", target))
    app = None
    daemon_mutation = is_daemon_mutation(changed_source)
    if test in LIVE_TESTS:
        apps = [item for item in artifacts if item.get("target", {}).get("name") == "xmsg" and not item.get("profile", {}).get("test") and item.get("executable")]
        require(len(apps) == 1 and apps[0].get("fresh") is False, "cached or missing candidate daemon")
        app = Path(apps[0]["executable"])
    validate_case(marker, changed_source, test, app_present=(app is not None))
    executable = Path(executables[0])
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    source = hashlib.sha256()
    for file in sorted(file for folder in ("src", "tests", "ci") for file in (Path(directory) / folder).rglob("*") if file.is_file()):
        source.update(str(file.relative_to(directory)).encode())
        source.update(file.read_bytes())
    for file in ("Cargo.toml", "Cargo.lock"):
        source.update((Path(directory) / file).read_bytes())
    variant = source.hexdigest()
    # Test executable uniqueness and execution are enforced by the per-arm UUID marker
    # injected in run(); ARTIFACT_VARIANTS guards the un-instrumented candidate daemon binary.
    print(f"artifact nonce={RUN_NONCE} arm={marker} kind=test test={selected} path={executable} mtime_ns={executable.stat().st_mtime_ns} sha256={digest} source={variant}", flush=True)
    if app is not None:
        app_digest = hashlib.sha256(app.read_bytes()).hexdigest()
        app_source = hashlib.sha256()
        for file in sorted((Path(directory) / "src").rglob("*.rs")):
            app_source.update(str(file.relative_to(directory)).encode())
            app_source.update(file.read_bytes())
        app_variant = app_source.hexdigest()
        if daemon_mutation:
            if ("app", app_digest) in ARTIFACT_VARIANTS and ARTIFACT_VARIANTS[("app", app_digest)] != app_variant:
                raise RuntimeError("daemon executable hash reused across daemon source variants")
            ARTIFACT_VARIANTS[("app", app_digest)] = app_variant
        print(f"artifact nonce={RUN_NONCE} arm={marker} kind=app test={selected} path={app} mtime_ns={app.stat().st_mtime_ns} sha256={app_digest} source={app_variant}", flush=True)
    result = subprocess.run([str(executable), selected, "--exact", "--show-output", *runtime_args], cwd=directory, env=env, capture_output=True, text=True, timeout=90 if test in LIVE_TESTS else 30)
    if app is not None:
        require(f"client-mutant-app:{app}" in result.stdout + result.stderr, "test did not execute the built candidate path")
    return result


def require_cached_builds(log, expected):
    prefix = "client-build-timing "
    rows = [json.loads(line[len(prefix):]) for line in Path(log).read_text().splitlines() if line.startswith(prefix)]
    require(len(rows) == expected, ("build timing inventory mismatch", len(rows), expected))
    require(all(row["result"] == 0 and not row["rebuilt_dependencies"] for row in rows), ("mutant arm rebuilt dependencies", rows))
    print(f"client-build-cache-complete:{expected} arms; zero dependency rebuilds", flush=True)


def main():
    self_test_daemon_hash_guard()
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--shard", type=int, choices=(0, 1))
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    live = args.live
    require(args.shard is None or live, "sharding requires --live")
    cases = [case for case in CASES if (case[-1] in LIVE_TESTS) == live]
    require(len(cases) == (15 if live else 27), "client mutant inventory count changed")
    require(len({case[0] for case in CASES}) == len(CASES), "duplicate client mutant names")
    if args.shard is not None:
        cases = cases[args.shard::2]
        require(len(cases) == (8 if args.shard == 0 else 7), "shard inventory changed")
    completed = []
    for name, filename, old, new, test in cases:
        with tempfile.TemporaryDirectory(prefix="xmsg-client-mutant-") as directory:
            dest = Path(directory)
            for file in ("Cargo.toml", "Cargo.lock"):
                shutil.copyfile(ROOT / file, dest / file)
            for folder in ("src", "tests", "scripts", "ci"):
                shutil.copytree(ROOT / folder, dest / folder, copy_function=shutil.copyfile)
            green = run(dest, test, changed_source=filename, label=f"{name}:baseline")
            marker = "forbidden dependencies absent with live daemon positive control" if test == "@graph" else "1 passed; 0 failed; 0 ignored"
            require(green.returncode == 0 and marker in green.stdout and (test != "@live" or "shared-client: verified baseline and candidate service contract completed" in green.stdout), (name, "invalid green", green.stdout, green.stderr))
            source = dest / filename
            text = source.read_text()
            if name in ("forbidden-sender-field", "agent-version"):
                start = text.index("    pub async fn send_with_attachments(")
                end = text.index("    pub async fn reply(", start)
                send = text[start:end]
                require(send.count(old) == 1, (name, send.count(old)))
                source.write_text(text[:start] + send.replace(old, new, 1) + text[end:])
            else:
                expected_count = 2 if name == "live-health-eof" else 1
                require(text.count(old) == expected_count, (name, text.count(old)))
                source.write_text(text.replace(old, new, 1))
            red = run(dest, test, changed_source=filename, label=f"{name}:mutant")
            if test == "@graph":
                reason = "test target inventory mismatch" if name == "missing-test-target" else "rusqlite"
                require(red.returncode == 1 and "AssertionError" in red.stderr and reason in red.stderr, (name, red.stdout, red.stderr))
            elif name == "live-skip":
                require(red.returncode == 0 and "1 passed; 0 failed; 0 ignored" in red.stdout and "shared-client: verified baseline and candidate service contract completed" not in red.stdout, (name, red.stdout, red.stderr))
            else:
                failed = "pinned_and_candidate_service_contract" if test == "@live" else ("xr7_codex_unrevoke_cli_and_sqlite_first_persistence" if test == "@codex-revoke" else ("client::feature_tests::no_daemon" if test == "@feature" else ("client::health::tests::disposed_descriptor_cannot_become_a_new_registration" if test == "@health-disposal" else test)))
                if test == "@health-peek":
                    failed = "client::health::tests::peek_observes_idle_data_and_eof_without_consumption"
                require(red.returncode == 101 and f"test {failed} ... FAILED" in red.stdout, (name, "survived or wrong red", red.stdout, red.stderr))
                if name == "health-lock-across-io":
                    require("health lock held across I/O" in red.stdout + red.stderr, (name, "missing named deadlock assertion", red.stdout, red.stderr))
            evidence = ROOT / ".artifacts" / "client-mutants"
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / (name + ".log")).write_text(red.stdout + red.stderr)
            completed.append({"name": name, "baseline": True, "red": True})
            print(name + ": GREEN baseline, RED intended test", flush=True)
    if args.manifest:
        args.manifest.write_text(json.dumps({"shard": args.shard, "cases": completed}, indent=2) + "\n")
    print(f"{len(cases)}/{len(cases)} shared-client mutants killed", flush=True)


if __name__ == "__main__":
    main()
