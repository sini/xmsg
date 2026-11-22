"""Exercise read-only CA diagnostics against source faults on the native host."""
import json
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PENDING = "enroll::protocol_tests::device_tests::diagnostic_pending_count_is_private_and_does_not_prune"
CA = "ca_health::tests::"
CASES = [
    ("expired-root", "src/ca_health.rs", "if after <= now {", "if false {", CA + "root_expiry_boundaries", "root expiry boundary"),
    ("near-root", "src/ca_health.rs", "else if remaining <= warning_window {", "else if false {", CA + "root_expiry_boundaries", "root expiry boundary"),
    ("fifo-key-read", "src/ca_health.rs", 'let key = directory.join("root.key");', 'let key = directory.join("root.key");\n    let _ = fs::read(&key);', CA + "signing_key_fifo_is_never_opened", "diagnostic opened or blocked on signing-key FIFO"),
    ("pending-prune", "src/enroll_device.rs", None, None, PENDING, "diagnostic pruned expired session store"),
    ("pending-privacy", "src/ca_health.rs", "let count = service.pending_device_approval_count();", 'report.add("pending_rows", "warn", &serde_json::to_string(&service.pending_device_requests()).unwrap());\n        let count = service.pending_device_approval_count();', PENDING, "diagnostic serialized pending identity or code canary"),
]
if platform.system() == "Linux":
    CASES.append(("regular-key-read", "src/ca_health.rs", 'let key = directory.join("root.key");', 'let key = directory.join("root.key");\n    let _ = fs::read(&key);', CA + "signing_key_regular_file_is_never_opened", "diagnostic opened or accessed regular signing key"))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(tree, selected, label, artifacts):
    command = ["cargo", "test", "--locked", "--color", "never", "--lib", selected, "--", "--exact", "--nocapture"]
    result = subprocess.run(command, cwd=tree, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    (artifacts / (label + ".log")).write_text(result.stdout)
    return result


def green(tree, selected, label, artifacts):
    result = run(tree, selected, label, artifacts)
    require(result.returncode == 0 and "1 passed; 0 failed; 0 ignored" in result.stdout, f"{label}: baseline/restore failed\n{result.stdout}")
    print(f"{label}: GREEN 1 passed; 0 failed; 0 ignored", flush=True)


def asset_hashes(root):
    return {str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in (root / "assets").rglob("*") if f.is_file()}


def main():
    artifacts = ROOT / ".artifacts" / "ca-health-mutants"
    artifacts.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("CARGO_TARGET_DIR", str(ROOT / "target"))
    os.environ.setdefault("CARGO_BUILD_JOBS", "4")
    completed = []
    with tempfile.TemporaryDirectory(prefix="ca-health-mutants-") as temp:
        tree = Path(temp)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, tree / name)
        for name in ("src", "tests", "scripts", "ci", "assets"):
            if (ROOT / name).exists():
                shutil.copytree(ROOT / name, tree / name)
        compile_assets = asset_hashes(ROOT)
        require(asset_hashes(tree) == compile_assets, "compile assets differ after source copy")
        for name, filename, old, new, selected, reason in CASES:
            source = tree / filename
            original = source.read_text()
            if name == "pending-prune":
                start = original.index("    pub(crate) fn pending_device_approval_count(&self) -> usize {")
                end = original.index("    pub(crate) fn pending_device_requests", start)
                old = original[start:end]
                new = "    pub(crate) fn pending_device_approval_count(&self) -> usize {\n        self.pending_device_requests().len()\n    }\n\n"
            green(tree, selected, name + "-baseline", artifacts)
            require(original.count(old) == 1, f"{name}: source anchor is not unique")
            source.write_text(original.replace(old, new, 1))
            try:
                result = run(tree, selected, name + "-fault", artifacts)
                require(result.returncode == 101 and f"test {selected} ... FAILED" in result.stdout and reason in result.stdout,
                        f"{name}: intended assertion did not kill source fault\n{result.stdout}")
                print(f"{name}: RED {reason}", flush=True)
            finally:
                source.write_text(original)
            green(tree, selected, name + "-restored", artifacts)
            require(asset_hashes(tree) == compile_assets, "compile assets changed during source gate")
            completed.append(name)
    manifest = {"system": platform.system(), "machine": platform.machine(), "native": True, "completed": completed, "compile_assets_sha256": compile_assets}
    (artifacts / "completion.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    print("ca-health-source-faults-complete " + json.dumps(manifest, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
