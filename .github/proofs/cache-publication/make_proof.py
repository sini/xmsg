"""Generate and guard a throwaway PR-event proof; never dispatch or publish anything."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import contextlib
import io
import shutil
import tempfile
from types import SimpleNamespace
import subprocess

import publish_contract as contract

CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
WORKFLOW = ".github/workflows/cache-publication-proof.yml"
HELPERS = ".github/proofs/cache-publication"
PATHS = "/tmp/attic-proof-paths"
VARIANTS = ("baseline", "candidate", "timeout")


def publish(record, variant):
    step = copy.deepcopy(record["base" if variant == "baseline" else "candidate"])
    step["if"] = "${{ github.event_name == 'pull_request' }}"
    step["env"] = {"ATTIC_TOKEN": "proof-dummy-token"}
    step["run"] = step["run"].replace("/tmp/attic-paths", PATHS)
    if variant == "timeout":
        step["timeout-minutes"] = 1
    return step


def warning(record):
    step = copy.deepcopy(record["warning"])
    step["id"] = "attic_warn"
    return step


def checkout_steps(candidate):
    return [
        {"name": "Check out throwaway proof", "uses": CHECKOUT,
         "with": {"ref": "${{ github.event.pull_request.head.sha }}", "fetch-depth": 0}},
        {"name": "Check out pinned candidate source", "uses": CHECKOUT,
         "with": {"ref": candidate, "path": "source", "fetch-depth": 0}},
        {"name": "Guard all eight source definitions and proof transformations", "id": "source_guard",
         "run": f"python3 {HELPERS}/make_proof.py guard --repo source --proof-root ."},
    ]


def child_ids(value, variant):
    result = []
    for row in value["children"]:
        for shard in row["shards"]:
            result.append((f"{variant}_{row['job'].replace('-', '_')}" + (f"_{shard}" if shard is not None else ""), row["job"], shard))
    return result


def workflow(value, prefix):
    record = next(row for row in value["records"] if row["file"] == "ci.yml" and row["job"] == "deps")
    generated = {}
    for variant in VARIANTS:
        outputs = {"guard": "${{ steps.source_guard.outcome }}", "proof_checked": "${{ steps.proof_check.outputs.checked }}"}
        proof_env = {}
        if variant != "baseline":
            for key, expression in (
                ("publish_outcome", "steps.attic_publish.outcome"),
                ("publish_conclusion", "steps.attic_publish.conclusion"),
                ("warning_outcome", "steps.attic_warn.outcome"),
                ("attempts", "steps.attic_publish.outputs.attempts"),
            ):
                outputs[key] = "${{ " + expression + " }}"
                proof_env[key.upper()] = "${{ " + expression + " }}"
        steps = checkout_steps(value["candidate"])
        steps.append({"name": "Install hermetic cache shims and fixture paths",
                      "run": f"python3 {HELPERS}/make_proof.py setup"})
        steps.append(publish(record, variant))
        if variant != "baseline":
            steps.append(warning(record))
        assertion = {"name": "Assert actual engine and retry observations", "id": "proof_check", "if": "${{ always() }}",
                     "run": f"python3 {HELPERS}/make_proof.py assert-job --variant {variant}"}
        if proof_env:
            assertion["env"] = proof_env
        steps.append(assertion)
        generated[variant + "_deps"] = {
            "if": "${{ startsWith(github.head_ref, '" + prefix + "') }}",
            "runs-on": "ubuntu-latest", "timeout-minutes": 4,
            "defaults": {"run": {"shell": "bash"}},
            "env": {"PROOF_MODE": "hang" if variant == "timeout" else "failure",
                    "PROOF_LOG": "/tmp/attic-proof-calls.jsonl"},
            "outputs": outputs, "steps": steps,
        }
        if variant != "timeout":
            for name, source_job, shard in child_ids(value, variant):
                generated[name] = {
                    "needs": [variant + "_deps"], "runs-on": "ubuntu-latest", "timeout-minutes": 2,
                    "outputs": {"marker": "${{ steps.canary.outputs.marker }}"},
                    "steps": [{"id": "canary", "name": f"Canary for {source_job} shard {shard}", "shell": "bash",
                               "run": 'echo "marker=ran" >> "$GITHUB_OUTPUT"'}],
                }
    dependencies = list(generated)
    generated["proof_collector"] = {
        "if": "${{ always() && startsWith(github.head_ref, '" + prefix + "') }}",
        "needs": dependencies, "runs-on": "ubuntu-latest", "timeout-minutes": 4,
        "defaults": {"run": {"shell": "bash"}},
        "steps": checkout_steps(value["candidate"]) + [
            {"name": "Assert baseline RED and candidate plus timeout GREEN",
             "env": {"PROOF_NEEDS": "${{ toJSON(needs) }}"},
             "run": f"python3 {HELPERS}/make_proof.py collect --proof-root ."}],
    }
    return {"name": "Cache publication engine proof (expected baseline RED)",
            "on": {"pull_request": {"branches": ["main"]}},
            "permissions": {"contents": "read"}, "jobs": generated}


def suppressed(text, prefix):
    lines = text.splitlines(keepends=True)
    for _, (begin, end) in sorted(contract.jobs(text).items(), key=lambda row: row[1][0], reverse=True):
        indexes = [i for i in range(begin + 1, end) if re.match(r"    if: ", lines[i])]
        assert len(indexes) <= 1
        original = "true"
        if indexes:
            original = lines[indexes[0]].split("if: ", 1)[1].strip()
            if original.startswith("${{") and original.endswith("}}"):
                original = original[3:-2].strip()
        condition = "    if: ${{ !startsWith(github.head_ref, '" + prefix + "') && (" + original + ") }}\n"
        if indexes:
            lines[indexes[0]] = condition
        else:
            lines.insert(begin + 1, condition)
    return "".join(lines)


def normal_workflows(repo, candidate):
    files = contract.git(repo, "ls-tree", "--name-only", candidate, ".github/workflows/").splitlines()
    assert files and all(name.endswith((".yml", ".yaml")) for name in files)
    return {name: contract.git(repo, "show", f"{candidate}:{name}") for name in files}


def manifest(repo, base, candidate, prefix):
    value = contract.contract(repo, base, candidate)
    normal = normal_workflows(repo, candidate)
    return {"contract": value, "proof_prefix": prefix,
            "normal_workflows": {name: {"canonical": contract.sha(text), "suppressed": contract.sha(suppressed(text, prefix))}
                                 for name, text in normal.items()},
            "helper_hashes": {name: contract.sha(Path(__file__).with_name(name).read_text())
                              for name in ("make_proof.py", "publish_contract.py")}}


def generate(args):
    base = contract.git(args.repo, "rev-parse", args.base).strip()
    candidate = contract.git(args.repo, "rev-parse", args.candidate).strip()
    assert re.fullmatch(r"[0-9a-f]{40}", base) and re.fullmatch(r"[0-9a-f]{40}", candidate)
    out = args.out.resolve()
    assert out != args.repo.resolve(), "proof output may not be the production tree"
    if not args.preview:
        branch = contract.git(out, "rev-parse", "--abbrev-ref", "HEAD").strip()
        assert branch.startswith(args.proof_prefix), ("not a throwaway proof branch", branch)
        assert contract.git(out, "rev-parse", "HEAD").strip() == candidate, "start proof worktree from candidate"
        assert not contract.git(out, "status", "--porcelain").strip(), "proof worktree must start clean"
    value = manifest(args.repo, base, candidate, args.proof_prefix)
    for filename, text in normal_workflows(args.repo, candidate).items():
        target = out / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(suppressed(text, args.proof_prefix))
    directory = out / HELPERS
    directory.mkdir(parents=True, exist_ok=True)
    for filename in ("make_proof.py", "publish_contract.py"):
        (directory / filename).write_text(Path(__file__).with_name(filename).read_text())
    (directory / "manifest.json").write_text(json.dumps(value, indent=2) + "\n")
    (out / WORKFLOW).write_text(json.dumps(workflow(value["contract"], args.proof_prefix), indent=2) + "\n")
    print("generated proof overlay only:", out)


def guard(args):
    root = args.proof_root
    expected = json.loads((root / HELPERS / "manifest.json").read_text())
    value = expected["contract"]
    actual = contract.contract(args.repo, value["base"], value["candidate"])
    assert actual == value, "canonical source hash/inventory changed"
    for filename, digest in expected["helper_hashes"].items():
        assert contract.sha((root / HELPERS / filename).read_text()) == digest, (filename, "helper drift")
    normal = normal_workflows(args.repo, value["candidate"])
    assert set(normal) == set(expected["normal_workflows"])
    for filename, text in normal.items():
        assert expected["normal_workflows"][filename]["canonical"] == contract.sha(text)
        transformed = suppressed(text, expected["proof_prefix"])
        assert expected["normal_workflows"][filename]["suppressed"] == contract.sha(transformed)
        assert (root / filename).read_text() == transformed, (filename, "suppression drift")
    assert set(str(p.relative_to(root)) for p in (root / ".github/workflows").iterdir()) == set(normal) | {WORKFLOW}
    observed = json.loads((root / WORKFLOW).read_text())
    assert observed == workflow(value, expected["proof_prefix"]), "proof transformation or graph drift"
    print("source-and-overlay-guard: all8 canonical definitions; only approved transforms; exact child graph")


def setup():
    directory = Path(os.environ["RUNNER_TEMP"]) / "attic-proof-bin"
    contract.shim_files(directory)
    Path(PATHS).write_text("/nix/store/proof-a\n/nix/store/proof-b\n")
    with open(os.environ["GITHUB_PATH"], "a") as output:
        output.write(str(directory) + "\n")
    Path(os.environ["PROOF_LOG"]).write_text("")


def assert_job(variant):
    calls = [json.loads(line) for line in Path(os.environ["PROOF_LOG"]).read_text().splitlines()]
    pushes = sum(row["kind"] == "push" for row in calls)
    assert sum(row["kind"] == "login" for row in calls) == 1, calls
    if variant == "baseline":
        assert pushes == 3, calls
    else:
        assert os.environ["PUBLISH_OUTCOME"] == "failure"
        assert os.environ["PUBLISH_CONCLUSION"] == "success"
        assert os.environ["WARNING_OUTCOME"] == "success"
        attempts = int(os.environ["ATTEMPTS"])
        assert attempts == pushes
        assert attempts == 3 if variant == "candidate" else 1 <= attempts <= 3
        print(f"actual warning step succeeded: Attic cache ci publication failed; attempts started: {attempts}")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write("checked=true\n")
    print(f"engine-observation: {variant}, actual push calls={pushes}")


def collect(root):
    value = json.loads((root / HELPERS / "manifest.json").read_text())["contract"]
    needs = json.loads(os.environ["PROOF_NEEDS"])
    expected = {variant + "_deps" for variant in VARIANTS}
    expected |= {name for variant in ("baseline", "candidate") for name, _, _ in child_ids(value, variant)}
    assert set(needs) == expected, "dropped or extra dependency/canary"
    for variant in VARIANTS:
        dependency = needs[variant + "_deps"]
        assert dependency["result"] == ("failure" if variant == "baseline" else "success"), dependency
        assert dependency["outputs"]["guard"] == "success"
        assert dependency["outputs"]["proof_checked"] == "true"
        if variant != "baseline":
            values = dependency["outputs"]
            assert values["publish_outcome"] == "failure" and values["publish_conclusion"] == "success"
            assert values["warning_outcome"] == "success"
            attempts = int(values["attempts"])
            assert attempts == 3 if variant == "candidate" else 1 <= attempts <= 3
        if variant != "timeout":
            for name, _, _ in child_ids(value, variant):
                assert needs[name]["result"] == ("skipped" if variant == "baseline" else "success"), (name, needs[name])
                if variant == "candidate": assert needs[name]["outputs"].get("marker") == "ran"
    print("engine-proof-complete: baselineRED+childrenSKIPPED; candidateGREEN+allchildrenRUN; timeoutGREEN+actualattempts")


def proof_controls(args):
    root, results = args.proof_root, []
    with contextlib.redirect_stdout(io.StringIO()):
        guard(SimpleNamespace(repo=args.repo, proof_root=root))
    mutations = (
        ("candidate-coe", lambda w: w["jobs"]["candidate_deps"]["steps"][4].update({"continue-on-error": False})),
        ("candidate-bound", lambda w: w["jobs"]["candidate_deps"]["steps"][4].update({"timeout-minutes": 11})),
        ("timeout-bound", lambda w: w["jobs"]["timeout_deps"]["steps"][4].update({"timeout-minutes": 2})),
        ("publish-id", lambda w: w["jobs"]["candidate_deps"]["steps"][4].update({"id": "wrong"})),
        ("publish-env", lambda w: w["jobs"]["candidate_deps"]["steps"][4].update({"env": {"ATTIC_TOKEN": "wrong"}})),
        ("publish-run", lambda w: w["jobs"]["candidate_deps"]["steps"][4].update({"run": "echo wrong"})),
        ("baseline-coe", lambda w: w["jobs"]["baseline_deps"]["steps"][4].update({"continue-on-error": True})),
        ("warning-if", lambda w: w["jobs"]["candidate_deps"]["steps"][5].update({"if": "${{ success() }}"})),
        ("warning-id", lambda w: w["jobs"]["candidate_deps"]["steps"][5].update({"id": "wrong"})),
        ("warning-run", lambda w: w["jobs"]["candidate_deps"]["steps"][5].update({"run": "echo wrong cache"})),
        ("missing-canary", lambda w: w["jobs"].pop("candidate_tests")),
        ("wrong-child-edge", lambda w: w["jobs"]["candidate_tests"].update({"needs": ["baseline_deps"]})),
    )
    for name, mutate in mutations:
        with tempfile.TemporaryDirectory(prefix="attic-overlay-control-") as temporary:
            cloned = Path(temporary)
            shutil.copytree(root / ".github", cloned / ".github")
            location = cloned / WORKFLOW
            data = json.loads(location.read_text())
            mutate(data)
            location.write_text(json.dumps(data))
            try:
                guard(SimpleNamespace(repo=args.repo, proof_root=cloned))
            except AssertionError:
                results.append({"kind": "overlay", "fault": name, "rejected": True})
            else:
                raise AssertionError((name, "overlay fault survived"))
    for name in ("normal-suppression", "source-inventory", "helper-hash"):
        with tempfile.TemporaryDirectory(prefix="attic-overlay-control-") as temporary:
            cloned = Path(temporary)
            shutil.copytree(root / ".github", cloned / ".github")
            if name == "normal-suppression":
                location = cloned / ".github/workflows/ci.yml"
                location.write_text(location.read_text() + "# unapproved suppression drift\n")
            elif name == "source-inventory":
                location = cloned / HELPERS / "manifest.json"
                data = json.loads(location.read_text())
                data["contract"]["records"].pop()
                location.write_text(json.dumps(data))
            else:
                location = cloned / HELPERS / "publish_contract.py"
                location.write_text(location.read_text() + "# unapproved helper drift\n")
            try:
                guard(SimpleNamespace(repo=args.repo, proof_root=cloned))
            except AssertionError:
                results.append({"kind": "overlay", "fault": name, "rejected": True})
            else:
                raise AssertionError((name, "guard fault survived"))
    value = json.loads((root / HELPERS / "manifest.json").read_text())["contract"]
    stock = {}
    for variant in VARIANTS:
        outputs = {"guard": "success", "proof_checked": "true"}
        if variant != "baseline":
            outputs.update(publish_outcome="failure", publish_conclusion="success", warning_outcome="success", attempts="3" if variant == "candidate" else "1")
        stock[variant + "_deps"] = {"result": "failure" if variant == "baseline" else "success", "outputs": outputs}
        if variant != "timeout":
            for name, _, _ in child_ids(value, variant):
                stock[name] = {"result": "skipped" if variant == "baseline" else "success", "outputs": {} if variant == "baseline" else {"marker": "ran"}}
    previous = os.environ.get("PROOF_NEEDS")
    try:
        os.environ["PROOF_NEEDS"] = json.dumps(stock)
        with contextlib.redirect_stdout(io.StringIO()):
            collect(root)
        results.append({"kind": "synthetic-collector", "control": "stock", "passed": True})
        faults = (
            ("baseline-not-red", lambda n: n["baseline_deps"].update(result="success")),
            ("candidate-not-green", lambda n: n["candidate_deps"].update(result="failure")),
            ("timeout-not-green", lambda n: n["timeout_deps"].update(result="failure")),
            ("bad-publish-outcome", lambda n: n["candidate_deps"]["outputs"].update(publish_outcome="success")),
            ("bad-publish-conclusion", lambda n: n["candidate_deps"]["outputs"].update(publish_conclusion="failure")),
            ("warning-skipped", lambda n: n["candidate_deps"]["outputs"].update(warning_outcome="skipped")),
            ("attempts-not-three", lambda n: n["candidate_deps"]["outputs"].update(attempts="2")),
            ("timeout-attempts-zero", lambda n: n["timeout_deps"]["outputs"].update(attempts="0")),
            ("timeout-attempts-four", lambda n: n["timeout_deps"]["outputs"].update(attempts="4")),
            ("source-guard-failed", lambda n: n["candidate_deps"]["outputs"].update(guard="failure")),
            ("proof-unchecked", lambda n: n["candidate_deps"]["outputs"].update(proof_checked="false")),
            ("baseline-child-ran", lambda n: n["baseline_tests"].update(result="success")),
            ("candidate-child-skipped", lambda n: n["candidate_tests"].update(result="skipped")),
            ("canary-marker-missing", lambda n: n["candidate_tests"].update(outputs={})),
            ("case-dropped", lambda n: n.pop("candidate_tests")),
        )
        for name, mutate in faults:
            data = copy.deepcopy(stock)
            mutate(data)
            os.environ["PROOF_NEEDS"] = json.dumps(data)
            try:
                with contextlib.redirect_stdout(io.StringIO()): collect(root)
            except AssertionError:
                results.append({"kind": "synthetic-collector", "fault": name, "rejected": True})
            else:
                raise AssertionError((name, "collector fault survived"))
    finally:
        if previous is None: os.environ.pop("PROOF_NEEDS", None)
        else: os.environ["PROOF_NEEDS"] = previous
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "proof-guard-controls.json").write_text(json.dumps(results, indent=2) + "\n")
    print("proof-guard-controls: stock GREEN;15 overlay faults+15 synthetic collector faults rejected; NOT a GitHub engine result")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("generate")
    create.add_argument("--repo", type=Path, required=True)
    create.add_argument("--base", required=True)
    create.add_argument("--candidate", required=True)
    create.add_argument("--out", type=Path, required=True)
    create.add_argument("--proof-prefix", default="5dzj-5-proof")
    create.add_argument("--preview", action="store_true")
    check = sub.add_parser("guard")
    check.add_argument("--repo", type=Path, required=True)
    check.add_argument("--proof-root", type=Path, required=True)
    sub.add_parser("setup")
    assertion = sub.add_parser("assert-job")
    assertion.add_argument("--variant", choices=VARIANTS, required=True)
    collector = sub.add_parser("collect")
    collector.add_argument("--proof-root", type=Path, required=True)
    controls = sub.add_parser("controls")
    controls.add_argument("--repo", type=Path, required=True)
    controls.add_argument("--proof-root", type=Path, required=True)
    controls.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "generate": generate(args)
    elif args.command == "guard": guard(args)
    elif args.command == "setup": setup()
    elif args.command == "assert-job": assert_job(args.variant)
    elif args.command == "controls": proof_controls(args)
    else: collect(args.proof_root)


if __name__ == "__main__": main()
