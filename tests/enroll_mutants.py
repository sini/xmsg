"""Immutable-tree enrollment source gates with per-variant build isolation."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def command(args, cwd, env, seconds, log):
    try:
        result = subprocess.run(args, cwd=cwd, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=seconds, check=False)
    except subprocess.TimeoutExpired as error:
        log.write_text(str(error))
        raise AssertionError("timeout is not a mutant kill") from error
    log.write_text(result.stdout)
    return result


def source_copy(destination):
    destination.mkdir()
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copyfile(ROOT / name, destination / name)
    for name in ("src", "tests"):
        shutil.copytree(ROOT / name, destination / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def edit(tree, item):
    filename = item["file"]
    relative = Path(filename)
    assert not relative.is_absolute() and relative.parts[0] == "src" and ".." not in relative.parts
    assert "tests" not in relative.parts and not relative.stem.endswith("_tests") and "fixture" not in filename
    file = tree / filename
    text = file.read_text()
    start = text.index(item["start"]) if item.get("start") else 0
    end = text.index(item["end"], start) if item.get("end") else len(text)
    fragment = text[start:end]
    assert fragment.count(item["needle"]) == 1, (filename, item, "ambiguous source site")
    offset = start + fragment.index(item["needle"])
    # All selected sites must precede test-only sections in their source scope.
    for match in re.finditer(r"#\[cfg\(test\)\]", text):
        following = text[match.end():].lstrip()
        if following.startswith("mod ") or following.startswith("pub(crate) mod "):
            assert offset < match.start(), "a test body is not a production fault"
    assert item["needle"] != item["replacement"]
    file.write_text(text[:start] + fragment.replace(item["needle"], item["replacement"], 1) + text[end:])


def instrument(tree, case, nonce):
    marker = f"enroll-arm nonce={nonce} case={case['label']}"
    file = tree / case["test_file"]
    text = file.read_text()
    name = case["test"].split("::")[-1]
    pattern = rf"(\b(?:async\s+)?fn\s+{re.escape(name)}\s*\([^)]*\)\s*\{{)"
    text, count = re.subn(pattern, lambda m: m[0] + f'\n eprintln!("{marker}");', text)
    assert count == 1, (case["test"], "named test instrumentation missing")
    file.write_text(text)
    lib = tree / "src/lib.rs"
    lib.write_text(lib.read_text() + f'\n#[cfg(test)]\n#[test]\nfn enrollment_build_nonce_receipt() {{ eprintln!("enroll-build nonce={nonce}"); }}\n')
    return marker


def seed_target(seed, target):
    # A reflink is an independent inode. Never hard-link mutable Cargo outputs.
    if seed is None:
        target.mkdir()
        return
    copied = subprocess.run(["cp", "-a", "--reflink=auto", str(seed), str(target)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if copied.returncode:
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(seed, target, symlinks=True)
    assert target.resolve() != seed.resolve()


def build(tree, target, case, env, logs, label, cached=False):
    targets = ["lib"] if case["target"] == "lib" else ["lib", case["target"]]
    args = ["cargo", "test", "--locked", "--offline", "--no-run", "--message-format=json", "--lib"]
    if case["target"] != "lib":
        args += ["--test", case["target"]]
    result = command(args, tree, env, 300, logs / f"{label}-build.log")
    assert result.returncode == 0, "compiler failure is not a mutant kill"
    found = {}
    for line in result.stdout.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if value.get("reason") != "compiler-artifact" or not value.get("executable"):
            continue
        if not value.get("profile", {}).get("test"):
            continue
        name = "lib" if value["target"]["kind"] == ["lib"] else value["target"]["name"]
        if name not in targets:
            continue
        file = Path(value["executable"])
        assert file.resolve().is_relative_to(target.resolve()), "artifact escaped variant target"
        assert value["fresh"] == cached, (label, name, "fresh/cached artifact guard failed")
        found[name] = {"file": str(file), "sha256": digest(file), "mtime_ns": file.stat().st_mtime_ns}
    assert set(found) == set(targets), (label, found, targets)
    return found


def execute(tree, artifact, test, marker, expected, env, file, literal=None):
    binary = Path(artifact["file"])
    assert digest(binary) == artifact["sha256"], "artifact changed before execution"
    result = command([str(binary), test, "--exact", "--nocapture"], tree, env, 120, file)
    assert marker in result.stdout, "compiled nonce was not executed"
    assert result.returncode == expected, (test, result.returncode, expected, result.stdout[-2000:])
    if expected == 101:
        assert f"test {test} ... FAILED" in result.stdout
        assert literal and literal in result.stdout, "intended assertion did not kill source fault"
        assert not any(x in literal for x in ("Elapsed(())", "TimedOut", "timed out")), "timeout is not a kill"
    else:
        assert "1 passed; 0 failed" in result.stdout
    assert digest(binary) == artifact["sha256"], "artifact changed during execution"
    return result


def variant(work, evidence, case, red, seed=None, gate=None):
    nonce = uuid.uuid4().hex
    label = case["label"] + ("-red" if red else "-restored")
    directory = work / (label + "-" + nonce)
    directory.mkdir()
    tree, target = directory / "tree", directory / "target"
    source_copy(tree)
    if red:
        for item in case["edits"]:
            edit(tree, item)
    production = {item["file"]: digest(tree / item["file"]) for item in case["edits"]}
    marker = instrument(tree, case, nonce)
    seed_target(seed, target)
    env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_CODEGEN_UNITS": "256"}
    artifacts = build(tree, target, case, env, evidence, label)
    execute(tree, artifacts["lib"], "enrollment_build_nonce_receipt", f"enroll-build nonce={nonce}", 0,
            env, evidence / f"{label}-nonce.log")
    if gate is not None:
        gate.wait(timeout=120)
    execute_started = time.monotonic()
    result = execute(tree, artifacts[case["target"]], case["test"], marker, 101 if red else 0,
                     env, evidence / f"{label}.log", case.get("expected_literal"))
    return directory, target, {"label": case["label"], "red": red, "status": result.returncode,
                              "nonce": nonce, "production": production, "artifacts": artifacts,
                              "assertion": case.get("expected_literal") if red else None,
                              "execute_started": execute_started, "execute_finished": time.monotonic()}


def isolation(work, evidence, case, seed):
    gate = threading.Barrier(2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        left = pool.submit(variant, work, evidence, {**case, "label": "isolation-stock"}, False, seed, gate)
        right = pool.submit(variant, work, evidence, {**case, "label": "isolation-fault"}, True, seed, gate)
        a, b = left.result(), right.result()
    assert a[1] != b[1]
    assert a[2]["nonce"] != b[2]["nonce"]
    assert max(a[2]["execute_started"], b[2]["execute_started"]) < min(a[2]["execute_finished"], b[2]["execute_finished"]), "isolation executions did not overlap"
    for result in (a, b):
        shutil.rmtree(result[0])
    (evidence / "forced-concurrency-isolation.json").write_text(json.dumps([a[2], b[2]], indent=2) + "\n")
    print("enrollment-forced-concurrency-isolation:passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=ROOT / "tests/enroll_mutants.json")
    parser.add_argument("--evidence", type=Path, default=ROOT / ".artifacts/enrollment-gates")
    parser.add_argument("--case", action="append")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    cases = json.loads(args.cases.read_text())
    assert cases and len({c["label"] for c in cases}) == len(cases)
    if args.case:
        cases = [c for c in cases if c["label"] in args.case]
        assert len(cases) == len(set(args.case)), "unknown case"
    args.evidence.mkdir(parents=True, exist_ok=True)
    tracked = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"]).decode().strip("\0").split("\0")
    source_hashes = {name: digest(ROOT / name) for name in tracked}
    for case in cases:
        for item in case["edits"]:
            assert item["file"] in source_hashes, "untracked production source"
    results = []
    with tempfile.TemporaryDirectory(prefix="xmsg-enroll-gates-") as temporary:
        work = Path(temporary)
        for index, case in enumerate(cases):
            tree = work / str(index)
            source_copy(tree)
            for item in case["edits"]:
                edit(tree, item)
            instrument(tree, case, "preflight")
            shutil.rmtree(tree)
        print(f"enrollment-source-preflight:{len(cases)}", flush=True)
        if args.preflight:
            return
        seed_directory, seed, baseline = variant(work, args.evidence, {**cases[0], "label": "baseline"}, False)
        results.append(baseline)
        seed_env = {**os.environ, "CARGO_TARGET_DIR": str(seed), "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_CODEGEN_UNITS": "256"}
        cached_refused = False
        try:
            build(seed_directory / "tree", seed, cases[0], seed_env, args.evidence, "cached-refusal")
        except AssertionError as error:
            assert "fresh/cached artifact guard failed" in str(error)
            cached_refused = True
        assert cached_refused, "a reused Cargo artifact was not refused"
        build(seed_directory / "tree", seed, cases[0], seed_env, args.evidence, "cached-positive", cached=True)
        (args.evidence / "cached-artifact-control.json").write_text(json.dumps({"cached_refused": True}) + "\n")
        isolation(work, args.evidence, cases[0], seed)
        for case in cases:
            for red in (True, False):
                directory, _, result = variant(work, args.evidence, case, red, seed)
                results.append(result)
                shutil.rmtree(directory)
                print(f"enrollment-source-arm:{case['label']}:{'RED101' if red else 'GREEN0'}", flush=True)
            assert all(digest(ROOT / name) == value for name, value in source_hashes.items()), "immutable source changed"
        shutil.rmtree(seed_directory)
    (args.evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    assert len(results) == 1 + 2 * len(cases)
    mode = "partial" if args.case else "complete"
    print(f"enrollment-source-{mode}:{len(cases)}", flush=True)


if __name__ == "__main__":
    main()
