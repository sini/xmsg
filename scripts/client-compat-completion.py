"""Require both completed compatibility shards and the exact live case inventory."""
import argparse
import json
from pathlib import Path
import runpy


def check(manifests):
    runner = runpy.run_path(str(Path(__file__).with_name("client-mutants.py")))
    expected = [case[0] for case in runner["CASES"] if case[-1] in runner["LIVE_TESTS"]]
    if len(expected) != 15 or len(set(expected)) != 15:
        raise ValueError("canonical live inventory must contain exactly 15 unique cases")
    if len(manifests) != 2 or {row["shard"] for row in manifests} != {0, 1}:
        raise ValueError("completion requires exactly shards 0 and 1")
    completed = []
    for manifest in manifests:
        cases = manifest["cases"]
        names = [row["name"] for row in cases]
        if names != expected[manifest["shard"]::2]:
            raise ValueError("compatibility shard inventory mismatch")
        if not all(row.get(phase) is True for row in cases for phase in ("baseline", "red")):
            raise ValueError("incomplete baseline/RED evidence")
        completed.extend(names)
    if len(completed) != 15 or set(completed) != set(expected):
        raise ValueError("compatibility completion union is not the exact 15-case inventory")
    print("shared-client-compat-completion:15/15 baseline / RED")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifests", nargs=2, type=Path)
    args = parser.parse_args()
    check([json.loads(file.read_text()) for file in args.manifests])


if __name__ == "__main__":
    main()
