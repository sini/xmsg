"""Validate this standalone package's executed inventory and record measured platform totals."""
import argparse
import json
from pathlib import Path
import re


def census(inventory, listing, results, platform):
    listed = sorted(re.findall(r"^([A-Za-z_][A-Za-z0-9_:]*): test$", listing, re.M))
    executed = sorted(re.findall(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ok$", results, re.M))
    if not inventory or len(inventory) != len(set(inventory)) or sorted(inventory) != listed or listed != executed:
        raise ValueError("executor inventory mismatch")
    rows = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", results, re.M)
    if not rows:
        raise ValueError("executor result summaries missing")
    passed, failed, ignored = [sum(int(row[i]) for row in rows) for i in range(3)]
    if failed or ignored or passed != len(inventory):
        raise ValueError("executor result totals mismatch")
    return {"platform": platform, "passed": passed, "failed": failed, "ignored": ignored,
            "summaries": len(rows), "tests": executed, "evidence_class": "fake_only"}


def controls():
    listing = "planted: test\n"
    result = "test planted ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
    assert census(["planted"], listing, result, "control")["passed"] == 1
    for bad in ["", result.replace("1 passed", "2 passed"), result.replace("planted ... ok", "other ... ok")]:
        try:
            census(["planted"], listing, bad, "control")
        except ValueError:
            continue
        raise AssertionError("census negative control survived")
    print("executor census controls: positive and 3 negatives passed")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--inventory", type=Path)
    p.add_argument("--listing", type=Path)
    p.add_argument("--results", type=Path)
    p.add_argument("--platform", choices=["linux", "darwin"])
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    if a.self_test:
        controls()
        return
    record = census(json.loads(a.inventory.read_text()), a.listing.read_text(), a.results.read_text(), a.platform)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(record, indent=2) + "\n")
    print("executor measured census: " + json.dumps({k: v for k, v in record.items() if k != "tests"}, sort_keys=True))


if __name__ == "__main__":
    main()
