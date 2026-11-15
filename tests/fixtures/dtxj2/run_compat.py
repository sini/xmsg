"""Build independent newer/older fixtures and verify stored-kind compatibility."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from prepare_compat import prepare


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def source_digest(source):
    files = [source / "Cargo.toml", source / "Cargo.lock"]
    for directory in ("src", "tests"):
        files.extend(file for file in (source / directory).rglob("*")
                     if file.is_file() and "__pycache__" not in file.parts
                     and file.suffix != ".pyc")
    sha = hashlib.sha256()
    for file in sorted(files):
        sha.update(str(file.relative_to(source)).encode() + b"\0")
        sha.update(file.read_bytes() + b"\0")
    return sha.hexdigest()


def command(args, cwd, env, log, timeout):
    print("running " + " ".join(map(str, args)), flush=True)
    with log.open("w") as output:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        print(log.read_text(), flush=True)
        raise RuntimeError(f"command exited {result.returncode}: {log}")
    return result.returncode


def build(source, target, seed, output, variant):
    if seed:
        shutil.copytree(seed, target, symlinks=True)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    if seed:
        command(["cargo", "clean", "--package", "xmsg", "--target-dir", str(target)],
                source, env, output / f"{variant}-clean.log", 300)
    args = ["cargo", "build", "--locked", "--offline", "--bin",
            "dtxj2-store-compat", "--message-format=json"]
    print("building " + variant + " with an independent target directory", flush=True)
    with (output / f"{variant}-build.jsonl").open("w") as stdout, \
            (output / f"{variant}-build.stderr").open("w") as stderr:
        result = subprocess.run(args, cwd=source, env=env, stdout=stdout,
                                stderr=stderr, timeout=3600)
    if result.returncode:
        print((output / f"{variant}-build.stderr").read_text(), flush=True)
        raise RuntimeError(f"{variant} build exited {result.returncode}")
    artifacts = [json.loads(line) for line in
                 (output / f"{variant}-build.jsonl").read_text().splitlines()]
    artifacts = [item for item in artifacts if item.get("reason") == "compiler-artifact"
                 and item["target"]["name"] == "dtxj2-store-compat"
                 and item.get("executable")]
    assert len(artifacts) == 1, f"{variant}: missing or ambiguous helper artifact"
    artifact = artifacts[0]
    assert artifact["fresh"] is False, f"{variant}: reused candidate helper binary"
    binary = Path(artifact["executable"]).resolve(strict=True)
    assert binary.is_relative_to(target.resolve()), f"{variant}: binary outside target"
    receipt = {"variant": variant, "source_sha256": source_digest(source),
               "event_enum_sha256": digest(source / "src/observe_export.rs"),
               "helper_source_sha256": digest(source / "tests/fixtures/dtxj2/store_compat.rs"),
               "manifest_sha256": digest(source / "Cargo.toml"),
               "lock_sha256": digest(source / "Cargo.lock"),
               "binary": str(binary), "binary_sha256": digest(binary),
               "cargo_fresh": artifact["fresh"], "build_exit": result.returncode,
               "synthetic_variant": "FutureWriterFixture" if variant == "newer" else None}
    (output / f"{variant}-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt), flush=True)
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-seed", type=Path)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    seed = args.artifact_seed.resolve(strict=True) if args.artifact_seed else None
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    binaries = {}
    for variant in ("older", "newer"):
        tree = output / variant
        prepare(source, tree, variant == "newer")
        binaries[variant] = build(tree, output / f"{variant}-target", seed, output, variant)
    known, future = output / "known-store", output / "future-store"
    known.mkdir(mode=0o700)
    future.mkdir(mode=0o700)
    results = []
    for variant, mode, store in [("older", "write-known", known),
                                  ("older", "read-known", known),
                                  ("newer", "write-newer", future),
                                  ("older", "read-unknown", future),
                                  ("newer", "read-newer", future)]:
        code = command([str(binaries[variant]), mode, str(store)], source,
                       os.environ.copy(), output / f"{mode}.log", 60)
        results.append({"variant": variant, "mode": mode, "exit": code})
        print(f"{variant} {mode}: exit {code}", flush=True)
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("all five compatibility modes passed", flush=True)


if __name__ == "__main__":
    main()
