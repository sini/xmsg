"""Guard the bounded best-effort cache publication patch and run its actual scripts."""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

FILES = ("ci.yml", "macos.yml", "oci.yml")
EXPECTED = {"ci.yml": {"deps", "package", "shared-client", "tests", "shared-client-compat"},
            "macos.yml": {"package", "tests"}, "oci.yml": {"oci"}}
PUBLISH = "Push to Attic cache"
WARNING = "Warn on Attic cache publication failure"
ATTEMPT_ZERO = 'echo "attempts=0" >> "$GITHUB_OUTPUT"\n'
ATTEMPT_NEXT = 'echo "attempts=$i" >> "$GITHUB_OUTPUT"; '
WARNING_IF = "${{ always() && steps.attic_publish.outcome == 'failure' }}"
WARNING_RUN = 'echo "::warning::Attic cache ci publication failed; attempts started: ${{ steps.attic_publish.outputs.attempts || \'unknown\' }}"\n'


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True)


def source(repo, revision, filename):
    relative = ".github/workflows/" + filename
    return (Path(repo) / relative).read_text() if revision == "WORKTREE" else git(repo, "show", f"{revision}:{relative}")


def jobs(text):
    lines = text.splitlines(keepends=True)
    begin = lines.index("jobs:\n") + 1
    indexes = [(i, match.group(1)) for i in range(begin, len(lines))
               if (match := re.fullmatch(r"  ([\w-]+):\n", lines[i]))]
    return {name: (start, indexes[n + 1][0] if n + 1 < len(indexes) else len(lines))
            for n, (start, name) in enumerate(indexes)}


def steps(text):
    lines = text.splitlines(keepends=True)
    result = []
    for job, (begin, end) in jobs(text).items():
        indexes = [i for i in range(begin, end) if re.match(r"      - (?:name|uses|id): ", lines[i])]
        for index, begin in enumerate(indexes):
            finish = indexes[index + 1] if index + 1 < len(indexes) else end
            match = re.fullmatch(r"      - name: (.+)\n", lines[begin])
            if match:
                result.append({"job": job, "name": match.group(1), "begin": begin, "end": finish,
                               "block": "".join(lines[begin:finish])})
    return result


def scalar(block, key):
    lines = block.splitlines(keepends=True)
    marker = f"        {key}: |\n"
    assert lines.count(marker) == 1, (key, "missing or ambiguous literal scalar")
    content = []
    for line in lines[lines.index(marker) + 1:]:
        if line.strip() and not line.startswith("          "):
            break
        content.append(line[10:] if line.startswith("          ") else line)
    return "".join(content).rstrip("\n") + "\n"


def attrs(block):
    return dict(re.findall(r"^        ([\w-]+): (.*)$", block, re.MULTILINE))


def publish_step(block):
    values = attrs(block)
    result = {"name": PUBLISH, "if": values["if"], "env": {"ATTIC_TOKEN": "${{ secrets.ATTIC_TOKEN }}"},
              "run": scalar(block, "run")}
    if "id" in values:
        result["id"] = values["id"]
    if "timeout-minutes" in values:
        result["timeout-minutes"] = int(values["timeout-minutes"])
    if "continue-on-error" in values:
        assert values["continue-on-error"] in ("true", "false")
        result["continue-on-error"] = values["continue-on-error"] == "true"
    return result


def warning_step(block):
    return {"name": WARNING, "if": attrs(block)["if"], "run": scalar(block, "run")}


def remove_approved(publish, warning):
    values = attrs(publish)
    assert values["id"] == "attic_publish"
    assert values["timeout-minutes"] == "10"
    assert values["continue-on-error"] == "true"
    run = scalar(publish, "run")
    assert run.startswith(ATTEMPT_ZERO), "attempt-zero must precede all checks"
    assert run.count(ATTEMPT_NEXT) == 1
    assert "for i in 1 2 3; do " + ATTEMPT_NEXT in run, "counter must stay in the retry loop"
    assert warning_step(warning) == {"name": WARNING, "if": WARNING_IF, "run": WARNING_RUN}
    prefix = "      - name: " + WARNING + "\n        if: " + WARNING_IF + "\n        run: |\n          " + WARNING_RUN
    assert warning.startswith(prefix), "unexpected warning fields"
    assert not warning[len(prefix):].strip(), "unexpected warning content"
    for line in ("        id: attic_publish\n", "        timeout-minutes: 10\n", "        continue-on-error: true\n",
                 "          " + ATTEMPT_ZERO):
        assert publish.count(line) == 1
        publish = publish.replace(line, "", 1)
    return publish.replace(ATTEMPT_NEXT, "", 1), warning[len(prefix):]


def graph(text):
    lines = text.splitlines(keepends=True)
    result = []
    for name, (begin, end) in jobs(text).items():
        block = "".join(lines[begin:end])
        match = re.search(r"^    needs: \[(.*?)\]$", block, re.MULTILINE)
        needs = [item.strip() for item in match.group(1).split(",")] if match else []
        if "deps" not in needs:
            continue
        assert needs == ["deps"], (name, "changed dependency graph")
        matrix = re.search(r"^        shard: \[(.*?)\]$", block, re.MULTILINE)
        shards = [int(item.strip()) for item in matrix.group(1).split(",")] if matrix else [None]
        result.append({"job": name, "shards": shards, "job_sha256": sha(block)})
    assert {row["job"] for row in result} == {"package", "shared-client", "tests", "shared-client-compat"}
    assert next(row["shards"] for row in result if row["job"] == "shared-client-compat") == [0, 1]
    return result


def contract(repo, base, candidate):
    records, workflow_hashes = [], {}
    for filename in FILES:
        before, after = source(repo, base, filename), source(repo, candidate, filename)
        old = {row["job"]: row for row in steps(before) if row["name"] == PUBLISH}
        current = {row["job"]: row for row in steps(after) if row["name"] == PUBLISH}
        warns = {row["job"]: row for row in steps(after) if row["name"] == WARNING}
        assert set(old) == set(current) == set(warns) == EXPECTED[filename], (filename, "inventory changed")
        replacements = []
        for job in sorted(old):
            previous, publish, warning = old[job], current[job], warns[job]
            assert publish["end"] == warning["begin"], (filename, job, "warning not adjacent")
            cleaned, separator = remove_approved(publish["block"], warning["block"])
            assert cleaned + separator == previous["block"], (filename, job, "publish commands or condition changed")
            assert not ({"id", "timeout-minutes", "continue-on-error"} & attrs(previous["block"]).keys())
            replacements += [(publish["begin"], publish["end"], cleaned), (warning["begin"], warning["end"], separator)]
            records.append({"file": filename, "job": job,
                            "base_block_sha256": sha(previous["block"]), "base_run_sha256": sha(scalar(previous["block"], "run")),
                            "candidate_block_sha256": sha(publish["block"]), "candidate_run_sha256": sha(scalar(publish["block"], "run")),
                            "warning_block_sha256": sha(warning["block"]),
                            "base": publish_step(previous["block"]), "candidate": publish_step(publish["block"]),
                            "warning": warning_step(warning["block"])})
        normalized = after.splitlines(keepends=True)
        for begin, end, replacement in sorted(replacements, reverse=True):
            normalized[begin:end] = [replacement]
        normalized = "".join(normalized)
        assert normalized == before, "unapproved workflow edit:\n" + "".join(difflib.unified_diff(before.splitlines(True), normalized.splitlines(True)))
        workflow_hashes[filename] = {"base": sha(before), "candidate": sha(after), "normalized": sha(normalized)}
    assert len(records) == 8
    return {"version": 1, "base": base, "candidate": candidate, "records": records,
            "workflows": workflow_hashes, "children": graph(source(repo, candidate, "ci.yml"))}


SHIM = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
mode, log = os.environ['PROOF_MODE'], pathlib.Path(os.environ['PROOF_LOG'])
def record(kind, values):
    with log.open('a') as output: output.write(json.dumps({'kind':kind,'args':values})+'\n')
if name == 'nix':
    assert args[:5] == ['shell','--inputs-from','.','nixpkgs#attic-client','-c'], args
    command = args[5:]
    assert command and command[0] in ('attic','xargs','sh'), command
    os.execvp(command[0], command)
elif name == 'attic':
    if args[:1] == ['login']:
        assert args[1:3] == ['ci','https://attic.json64.dev'] and args[3:] == ['proof-dummy-token'], 'unexpected login'
        record('login',['ci'])
        sys.exit(19 if mode == 'login-failure' else 0)
    assert args[:2] == ['push','ci'] and len(args) > 2, args
    record('push',args[:2])
    if mode == 'hang': time.sleep(600)
    sys.exit(0 if mode == 'success' else 31)
elif name == 'sleep': record('sleep',args)
else: raise AssertionError(name)
'''


def shim_files(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("nix", "attic", "sleep"):
        item = directory / name
        item.write_text(SHIM)
        item.chmod(0o755)


def local_controls(value, output):
    output.mkdir(parents=True, exist_ok=True)
    records = []
    tools = {name: shutil.which(name) for name in ("bash", "sh", "xargs", "python3")}
    assert all(tools.values()), tools
    tool_path = ":".join(sorted({str(Path(item).parent) for item in tools.values()}))
    for row in value["records"]:
        for phase in ("base", "candidate"):
            for mode in ("failure", "success", "login-failure", "missing-token", "no-path"):
                with tempfile.TemporaryDirectory(prefix="attic-contract-") as temporary:
                    root = Path(temporary)
                    shim_files(root / "bin")
                    paths = root / "paths"
                    if mode != "no-path": paths.write_text("/nix/store/proof-a\n/nix/store/proof-b\n")
                    run = row[phase]["run"].replace("/tmp/attic-paths", str(paths))
                    env = os.environ.copy()
                    env.update(PATH=str(root / "bin") + ":" + tool_path, ATTIC_TOKEN="" if mode == "missing-token" else "proof-dummy-token",
                               GITHUB_OUTPUT=str(root / "outputs"), PROOF_MODE=mode, PROOF_LOG=str(root / "calls"))
                    result = subprocess.run([tools["bash"], "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", run], env=env,
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                    calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()] if (root / "calls").exists() else []
                    attempts = [int(line.split("=", 1)[1]) for line in (root / "outputs").read_text().splitlines()] if (root / "outputs").exists() else []
                    count = sum(call["kind"] == "push" for call in calls)
                    expected = 3 if mode == "failure" else 1 if mode == "success" else 0
                    assert count == expected, (row["file"], row["job"], phase, mode, result.stdout)
                    assert (result.returncode != 0) == (mode in ("failure", "login-failure")), (mode, result.returncode)
                    assert attempts == (list(range(expected + 1)) if phase == "candidate" else []), (phase, mode, attempts)
                    if mode == "failure":
                        assert [call["args"] for call in calls if call["kind"] == "sleep"] == [["10"], ["20"], ["30"]]
                    records.append({"file": row["file"], "job": row["job"], "phase": phase, "mode": mode,
                                    "exit": result.returncode, "pushes": count, "attempt_outputs": attempts, "calls": calls})
    assert len(records) == 80
    (output / "local-controls.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"publish-contract-controls: {len(records)} passed; all 8 definitions, base and candidate")


def contract_controls(repo, base, output):
    from unittest.mock import patch
    originals = {name: source(repo, "WORKTREE", name) for name in FILES}
    real_source = source
    results = []
    contract(repo, base, "WORKTREE")
    mutations = (
        ("publish-id", "        id: attic_publish\n", "        id: wrong_id\n"),
        ("bound", "        timeout-minutes: 10\n", "        timeout-minutes: 11\n"),
        ("continue-on-error", "        continue-on-error: true\n", "        continue-on-error: false\n"),
        ("attempt-zero", "          " + ATTEMPT_ZERO, ""),
        ("attempt-loop", ATTEMPT_NEXT, ATTEMPT_NEXT.replace("$i", "9")),
        ("condition", "        if: (github.event_name", "        if: (false && github.event_name"),
        ("path-set", "/tmp/attic-paths", "/tmp/wrong-paths"),
        ("cache-name", "attic push ci", "attic push other"),
        ("retry-count", "for i in 1 2 3;", "for i in 1 2;"),
        ("extra-id", "        id: attic_publish\n", "        id: attic_publish\n        unexpected: true\n"),
    )
    for filename, original in originals.items():
        definitions = [row for row in steps(original) if row["name"] == PUBLISH]
        for row in definitions:
            for label, old, new in mutations:
                block = row["block"]
                assert old in block, label
                replacement = block.replace(old, new, 1)
                lines = original.splitlines(keepends=True)
                lines[row["begin"]:row["end"]] = [replacement]
                changed = "".join(lines)
                def reader(actual_repo, revision, actual_file):
                    return changed if revision == "WORKTREE" and actual_file == filename else real_source(actual_repo, revision, actual_file)
                with patch(__name__ + ".source", reader):
                    try:
                        contract(repo, base, "WORKTREE")
                    except (AssertionError, KeyError):
                        results.append({"file": filename, "job": row["job"], "fault": label, "rejected": True})
                    else:
                        raise AssertionError((filename, row["job"], label, "contract drift survived"))
    output.mkdir(parents=True, exist_ok=True)
    (output / "contract-guard-controls.json").write_text(json.dumps(results, indent=2) + "\n")
    assert len(results) == 80
    print("contract-guard-controls: stock GREEN;80 source drift faults rejected across all8 definitions")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("validate", "controls", "guard-controls"))
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", default="WORKTREE")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    value = contract(args.repo, args.base, args.candidate)
    if args.command == "controls": local_controls(value, args.out)
    elif args.command == "guard-controls": contract_controls(args.repo, args.base, args.out)
    else:
        args.out.write_text(json.dumps(value, indent=2) + "\n")
        print("publish-contract: all 8 definitions; whole workflows normalize byte-identical")


if __name__ == "__main__": main()
