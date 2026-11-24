"""Actual pinned B0/current production Store+render downgrade harness (no OIDC)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def verify_old(source):
    pin = json.loads((Path(__file__).parent / "old-source.json").read_text())
    actual = {str(f.relative_to(source)): digest(f) for f in (source / "src").rglob("*") if f.is_file()}
    assert actual == pin["src_sha256"], "old production source differs from pinned B0"
    return pin


def run(args, cwd, env, log, timeout=120):
    with log.open("w") as stream:
        result = subprocess.run(list(map(str,args)), cwd=cwd, env=env,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    assert result.returncode == 0, f"exit {result.returncode}: {log}\n{log.read_text()}"
    return log.read_text().strip()


def artifacts(messages, target):
    relevant = [m for m in messages if m.get("reason") == "compiler-artifact"
                and m["target"]["name"] in ("xmsg", "reverse-store-compat")]
    libraries = [m for m in relevant if "lib" in m["target"]["kind"]]
    helpers = [m for m in relevant if m.get("executable") and m["target"]["name"] == "reverse-store-compat"]
    assert len(libraries) == len(helpers) == 1, "missing independent library/helper build"
    assert not libraries[0]["fresh"] and not helpers[0]["fresh"], "cached package artifact refused"
    for filename in libraries[0]["filenames"]:
        assert Path(filename).resolve(strict=True).is_relative_to(target.resolve()), "library outside independent target refused"
    binary = Path(helpers[0]["executable"]).resolve(strict=True)
    assert binary.is_relative_to(target.resolve()), "binary outside independent target refused"
    assert "/release/" not in str(binary), "release artifact cannot seed a dev proof"
    return binary, libraries[0]


def controls(binary, library, target):
    helper = {"reason":"compiler-artifact","target":{"name":"reverse-store-compat","kind":["bin"]},
              "fresh":False,"executable":str(binary)}
    for name, changed in (("cached-helper",dict(helper,fresh=True)),
                          ("outside-target",dict(helper,executable=str(Path(__file__).resolve())))):
        try:
            artifacts([library,changed],target)
        except AssertionError:
            continue
        raise AssertionError(f"{name} refusal control failed")
    try:
        artifacts([dict(library,fresh=True),helper],target)
    except AssertionError:
        return ["cached-helper refused", "cached-library refused", "outside-target refused"]
    raise AssertionError("cached-library refusal control failed")


def configure_vendor_cargo_home(output, variant, vendor_dir):
    cargo_home = output / f"{variant}-cargo-home"
    cargo_home.mkdir(mode=0o700)
    vendor_config = vendor_dir / "config.toml"
    if vendor_config.is_file():
        config_text = vendor_config.read_text()
    else:
        escaped = json.dumps(str(vendor_dir))
        config_text = (
            '[source.crates-io]\n'
            'replace-with = "vendored-sources"\n'
            '[source.vendored-sources]\n'
            f'directory = {escaped}\n'
        )
    (cargo_home / "config.toml").write_text(config_text)
    return cargo_home


def build(source, output, variant, seed, candidate, vendor_dir=None):
    tree, target = output / variant, output / f"{variant}-target"
    tree.mkdir()
    for name in ("Cargo.toml","Cargo.lock"):
        shutil.copy2(source/name,tree/name)
    for name in ("src","tests"):
        shutil.copytree(source/name,tree/name,ignore=shutil.ignore_patterns("__pycache__","*.pyc"))
    if (source / "assets").exists():
        shutil.copytree(source / "assets", tree / "assets")
    if (source / "web/mc-roster/assets").exists():
        shutil.copytree(source / "web/mc-roster/assets", tree / "web/mc-roster/assets")
    expected_assets = {str(f.relative_to(source)):digest(f) for f in (source/"assets").rglob("*") if f.is_file()}
    assert {str(f.relative_to(tree)):digest(f) for f in (tree/"assets").rglob("*") if f.is_file()} == expected_assets, "compile assets differ after source copy"
    for directory in tree.rglob("*"):
        if directory.is_dir():
            directory.chmod(directory.stat().st_mode | 0o200)
    if not candidate:
        verify_old(tree)
    helper = tree / "tests/fixtures/reverse_observe/store_compat.rs"
    helper.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(Path(__file__).parent / "store_compat.rs",helper)
    helper.chmod(0o600)
    helper.write_text(helper.read_text().replace("cfg(candidate)", "cfg(all())" if candidate else "cfg(any())").replace("cfg(not(candidate))", "cfg(any())" if candidate else "cfg(all())"))
    manifest = tree / "Cargo.toml"
    manifest.chmod(0o600)
    manifest.write_text(manifest.read_text()+'\n[[bin]]\nname = "reverse-store-compat"\npath = "tests/fixtures/reverse_observe/store_compat.rs"\nrequired-features = ["daemon"]\n')
    if seed:
        assert "release" not in seed.parts, "release seed refused"
        shutil.copytree(seed,target,symlinks=True)
    env = os.environ.copy()
    if vendor_dir is not None:
        env["CARGO_HOME"] = str(configure_vendor_cargo_home(output, variant, vendor_dir))
        env["CARGO_NET_OFFLINE"] = "true"
    env["CARGO_TARGET_DIR"] = str(target)
    nonce = secrets.token_hex(16)
    env["REVERSE_BUILD_NONCE"] = nonce
    run(["cargo","clean","--package","xmsg","--target-dir",target],tree,env,output/f"{variant}-clean.log")
    with (output/f"{variant}-build.jsonl").open("w") as stdout, (output/f"{variant}-build.stderr").open("w") as stderr:
        result = subprocess.run(["cargo","build","--profile","dev","-j4","--locked","--offline","--bin","reverse-store-compat","--message-format=json"],
                                cwd=tree,env=env,stdout=stdout,stderr=stderr,timeout=3600)
    assert result.returncode == 0, f"{variant} build exit {result.returncode}: {output}/{variant}-build.stderr"
    messages = [json.loads(line) for line in (output/f"{variant}-build.jsonl").read_text().splitlines()]
    binary, library = artifacts(messages,target)
    assert run([binary,"nonce"],tree,env,output/f"{variant}-nonce.log") == nonce, "executed helper nonce differs"
    cached = subprocess.run(["cargo","build","--profile","dev","-j4","--locked","--offline","--bin","reverse-store-compat","--message-format=json"],
                            cwd=tree,env=env,capture_output=True,text=True,timeout=120)
    (output/f"{variant}-cached-build.jsonl").write_text(cached.stdout)
    (output/f"{variant}-cached-build.stderr").write_text(cached.stderr)
    assert cached.returncode == 0, "cached-artifact refusal control failed to build"
    try:
        artifacts([json.loads(line) for line in cached.stdout.splitlines()],target)
    except AssertionError as error:
        assert str(error) == "cached package artifact refused", str(error)
    else:
        raise AssertionError("actual cached Cargo build was accepted")
    source_hashes = {str(f.relative_to(tree)):digest(f) for f in (tree/"src").rglob("*") if f.is_file()}
    asset_hashes = {str(f.relative_to(tree)):digest(f) for f in (tree/"assets").rglob("*") if f.is_file()}
    assert asset_hashes == expected_assets, "compile assets changed during build"
    receipt = {"variant":variant,"production_src_sha256":source_hashes,"compile_assets_sha256":asset_hashes,"helper_sha256":digest(helper),
               "manifest_sha256":digest(manifest),"lock_sha256":digest(tree/"Cargo.lock"),
               "vendor_dir":str(vendor_dir) if vendor_dir is not None else None,
               "seeded":seed is not None,
               "binary_sha256":digest(binary),"library_sha256":{str(Path(f).name):digest(Path(f)) for f in library["filenames"]},
               "binary":str(binary),"nonce":nonce,"library_fresh":False,"helper_fresh":False,
               "actual_cached_build_refused":True,
               "refusal_controls":controls(binary,library,target)}
    (output/f"{variant}-receipt.json").write_text(json.dumps(receipt,indent=2)+'\n')
    print(f"{variant}: fresh independent library/helper; executed nonce; artifact refusal controls passed",flush=True)
    return binary


def census(store):
    import sqlite3
    dbs = list(store.glob("*.sqlite*")) + list(store.glob("*.db"))
    assert len(dbs) == 1, f"unexpected store files: {list(store.iterdir())}"
    with sqlite3.connect(dbs[0]) as db:
        assert db.execute("SELECT count(*) FROM nodes").fetchone()[0] <= 64
        return {"events":db.execute("SELECT hex(json) FROM events ORDER BY node,sequence").fetchall(),
                "snapshots":db.execute("SELECT hex(snapshot) FROM nodes WHERE snapshot IS NOT NULL ORDER BY node").fetchall()}


def isolation_controls(output):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    barrier = Barrier(2)
    shared = output / "shared-output-control"
    def claim(index):
        private = output / f"isolated-output-control-{index}"
        private.mkdir(exist_ok=False)
        barrier.wait(timeout=10)
        try:
            shared.mkdir(exist_ok=False)
            return "created"
        except FileExistsError:
            return "refused"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, (0, 1)))
    assert sorted(results) == ["created", "refused"], "concurrent shared-output refusal failed"
    receipt = {"concurrent_shared_output": results, "independent_output_roots": 2}
    (output / "isolation-controls.json").write_text(json.dumps(receipt, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--old-source",type=Path,required=True)
    parser.add_argument("--old-vendor",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--artifact-seed",type=Path)
    parser.add_argument("--old-build-only",action="store_true")
    args = parser.parse_args()
    source, old, output = args.source.resolve(),args.old_source.resolve(),args.output.resolve()
    assert source != old and not source.is_relative_to(output) and not old.is_relative_to(output)
    seed = args.artifact_seed.resolve(strict=True) if args.artifact_seed else None
    assert seed is None or not output.is_relative_to(seed), "output must be outside artifact seed"
    old_vendor = args.old_vendor.resolve(strict=True) if args.old_vendor else None
    assert old_vendor is None or not output.is_relative_to(old_vendor), "output must be outside old vendor dir"
    pin = verify_old(old)
    old_seed = seed if (seed is not None and digest(old / "Cargo.lock") == digest(source / "Cargo.lock")) else None
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    isolation_controls(output)
    older = build(old,output,"old",old_seed,False,vendor_dir=old_vendor)
    if args.old_build_only:
        print("old-only construction check; candidate/downgrade NOT executed")
        return
    newer = build(source,output,"candidate",seed,True)
    results = []
    for scenario in ("direct","saved"):
        store = output/f"{scenario}-store"
        store.mkdir(mode=0o700)
        before = None
        for binary, mode in ((newer,"write"),(older,scenario),(newer,"upgrade")):
            text = run([binary,mode,store],source,os.environ.copy(),output/f"{scenario}-{mode}.log")
            data = census(store)
            if mode == "write":
                before = data
            elif mode == "upgrade":
                assert before == data, "canonical event/snapshot JSON changed across downgrade and fresh upgrade"
            results.append({"scenario":scenario,"mode":mode,"exit":0,"output":text})
            print(f"{scenario}/{mode}: exit 0 {text}",flush=True)
    refresh_store = output / "rollback-refresh-store"
    refresh_store.mkdir(mode=0o700)
    for binary, mode in ((newer, "refresh_write"), (older, "refresh_old"), (newer, "refresh_read")):
        text = run([binary, mode, refresh_store], source, os.environ.copy(), output / f"rollback-refresh-{mode}.log")
        results.append({"scenario": "rollback_refresh", "mode": mode, "exit": 0, "output": text})
        print(f"rollback_refresh/{mode}: exit 0 {text}", flush=True)
    (output/"results.json").write_text(json.dumps({"old_revision":pin["revision"],"scope":"production Store/render; no live OIDC acceptance","results":results},indent=2)+'\n')


if __name__ == "__main__":
    main()
