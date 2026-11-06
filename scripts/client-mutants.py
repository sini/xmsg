"""Single-site source mutants for the shared transport; no runtime mutation flags."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("bounded-read", "src/client/mod.rs", ".take(self.max_frame_bytes as u64 + 1)", "", "oversized_and_unterminated_frames_are_refused"),
    ("registration-deadline", "src/client/mod.rs", "timeout(options.operation_timeout, async", "timeout(Duration::from_secs(60), async", "registration_deadline_is_a_client_error"),
    ("required-origin", "src/client/mod.rs", "let parsed: ServiceResponse = match serde_json::from_value(response)", 'let parsed: ServiceResponse = match serde_json::from_value({ let mut response = response; response.as_object_mut().unwrap().entry("origin").or_insert(serde_json::json!({"node":"fixture"})); response })', "delivery_requires_origin_and_preserves_all_origin_kinds"),
    ("wrong-registration-node", "src/client/mod.rs", "registration.node != expected.node", 'false', "missing_or_wrong_registration_identity_is_refused"),
    ("agent-version", "src/client/mod.rs", "schema_version: Some(SCHEMA_VERSION),", "schema_version: None,", "socket_specific_exact_frame_keys"),
    ("forbidden-sender-field", "src/client/mod.rs", "as_agent: None,", 'as_agent: Some("injected".to_owned()),', "socket_specific_exact_frame_keys"),
]


def run(directory, test):
    subprocess.run(["cargo", "clean", "-p", "xmsg", "--target-dir", str(ROOT / "target" / "client-mutants")], cwd=directory, check=True, capture_output=True)
    return subprocess.run(["cargo", "test", "--locked", "--no-default-features", "--features", "client", "--test", "shared_client", test, "--", "--exact"], cwd=directory,
                          env={**os.environ, "CARGO_TARGET_DIR": str(ROOT / "target" / "client-mutants")}, text=True, capture_output=True, timeout=120)


def main():
    for name, filename, old, new, test in CASES:
        with tempfile.TemporaryDirectory(prefix="xmsg-client-mutant-") as directory:
            dest = Path(directory)
            for file in ("Cargo.toml", "Cargo.lock"):
                shutil.copy2(ROOT / file, dest / file)
            for folder in ("src", "tests"):
                shutil.copytree(ROOT / folder, dest / folder)
            green = run(dest, test)
            assert green.returncode == 0 and "1 passed; 0 failed; 0 ignored" in green.stdout, (name, "invalid green", green.stdout, green.stderr)
            source = dest / filename
            text = source.read_text()
            count = text.count(old)
            # Send and reply each have the same optional identity fields; mutate only send.
            if name in ("forbidden-sender-field", "agent-version"):
                assert count == 3, count
            else:
                assert count == 1, (name, count)
            source.write_text(text.replace(old, new, 1))
            red = run(dest, test)
            assert red.returncode == 101 and f"test {test} ... FAILED" in red.stdout, (name, "survived or wrong red", red.stdout, red.stderr)
            evidence = ROOT / ".artifacts" / "client-mutants"
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / (name + ".log")).write_text(red.stdout + red.stderr)
            print(name + ": GREEN baseline, RED intended test", flush=True)
    print(f"{len(CASES)}/{len(CASES)} shared-client mutants killed", flush=True)


if __name__ == "__main__":
    main()
