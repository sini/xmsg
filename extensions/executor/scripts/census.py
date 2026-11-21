"""Validate this standalone package's executed inventory and record measured platform totals."""
import argparse
import json
from pathlib import Path
import re


HELPER_ENTRYPOINTS = {"supervisor::tests::fixture_process_entrypoint", "control::tests::bridge_live_peer_fixture"}

def census(inventory, listing, results, platform):
    listed = sorted(re.findall(r"^([A-Za-z_][A-Za-z0-9_:]*): test$", listing, re.M))
    executed = sorted(re.findall(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ok$", results, re.M))
    ignored_helpers = sorted(re.findall(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ignored(?:,.*)?$", results, re.M))
    expected_helpers = sorted(set(listed) & HELPER_ENTRYPOINTS)
    functional = sorted(set(listed) - HELPER_ENTRYPOINTS)
    if not inventory or len(inventory) != len(set(inventory)) or sorted(inventory) != listed or functional != executed or ignored_helpers != expected_helpers:
        raise ValueError("executor inventory mismatch")
    rows = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", results, re.M)
    if not rows:
        raise ValueError("executor result summaries missing")
    passed, failed, ignored = [sum(int(row[i]) for row in rows) for i in range(3)]
    if failed or ignored != len(expected_helpers) or passed + ignored != len(inventory):
        raise ValueError("executor result totals mismatch")
    return {"platform": platform, "passed": passed, "failed": failed, "ignored": ignored,
            "summaries": len(rows), "tests": executed, "ignored_helper_entrypoints": expected_helpers, "evidence_class": "fake_only"}


def controls():
    listing = "planted: test\n"
    result = "test planted ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
    assert census(["planted"], listing, result, "control")["passed"] == 1
    helper = next(iter(HELPER_ENTRYPOINTS))
    helper_listing = listing + helper + ": test\n"
    helper_result = result.replace("0 ignored", "1 ignored") + "test " + helper + " ... ignored, test-only subprocess fixture entrypoint\n"
    measured = census(["planted", helper], helper_listing, helper_result, "control")
    assert measured["passed"] == 1 and measured["ignored_helper_entrypoints"] == [helper]
    for bad in ["", result.replace("1 passed", "2 passed"), result.replace("planted ... ok", "other ... ok"), result.replace("planted ... ok", "planted ... ignored")]:
        try:
            census(["planted"], listing, bad, "control")
        except ValueError:
            continue
        raise AssertionError("census negative control survived")
    print("executor census controls: 2 positives and 4 negatives passed")


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
