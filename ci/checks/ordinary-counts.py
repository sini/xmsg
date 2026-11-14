"""Check the ordinary suite's measured counts and complete integration target inventory."""
import argparse
import json
from pathlib import Path
import re
import tomllib


def check(expected, platform, cargo, log):
    targets = [row["path"] for row in cargo["test"]]
    required = expected["integration_targets"]
    if len(targets) != len(set(targets)) or sorted(targets) != required:
        raise ValueError("ordinary test target inventory mismatch")
    executed = re.findall(r"^\s*Running (tests/\S+\.rs) \(", log, re.MULTILINE)
    if sorted(executed) != required:
        raise ValueError("ordinary executed target inventory mismatch")
    rows = [tuple(map(int, row)) for row in re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log, re.MULTILINE)]
    actual = dict(zip(("passed", "failed", "ignored"), (sum(row[i] for row in rows) for i in range(3))))
    actual["summaries"] = len(rows)
    if actual != expected["platforms"][platform]:
        raise ValueError(f"ordinary result counts mismatch: {actual}")
    print("ordinary-suite-complete " + json.dumps({"platform": platform, "targets": len(targets), **actual}, sort_keys=True))
    return actual


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--platform", choices=("linux", "darwin"), required=True)
    parser.add_argument("--cargo-toml", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    check(json.loads(args.expected.read_text()), args.platform,
          tomllib.loads(args.cargo_toml.read_text()), args.log.read_text())


if __name__ == "__main__":
    main()
