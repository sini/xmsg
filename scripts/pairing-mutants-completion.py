#!/usr/bin/env python3
"""Require all pairing-mutants shards and the exact 62-case manifest union."""

import argparse
import json
from pathlib import Path
import runpy


def expected_cases() -> list[str]:
    runner = runpy.run_path(str(Path(__file__).with_name("pairing-pr4-mutants.py")))
    expected = [case[0] for case in runner["CASES"] if not case[5]]
    if len(expected) != 62 or len(set(expected)) != 62:
        raise ValueError(
            f"canonical pairing mutant manifest must contain 62 unique active cases, got {len(expected)}"
        )
    return expected


def check(manifests: list[dict], expected_shards: int) -> None:
    expected = expected_cases()
    if len(manifests) != expected_shards:
        raise ValueError(
            f"completion requires exactly {expected_shards} shard manifests, got {len(manifests)}"
        )
    seen_shards = set()
    completed: list[str] = []
    for manifest in manifests:
        shard = manifest.get("shard")
        shards = manifest.get("shards")
        if shards != expected_shards or not isinstance(shard, int) or not (0 <= shard < expected_shards):
            raise ValueError(f"invalid shard metadata: shard={shard!r}, shards={shards!r}")
        if shard in seen_shards:
            raise ValueError(f"duplicate shard manifest for shard {shard}")
        seen_shards.add(shard)

        cases = manifest.get("cases", [])
        names = [row["name"] for row in cases]
        want = [name for idx, name in enumerate(expected) if idx % expected_shards == shard]
        if names != want:
            raise ValueError(
                f"shard {shard} inventory mismatch: got {len(names)} cases, expected {len(want)}"
            )
        if not all(row.get("red") is True and row.get("green") is True for row in cases):
            raise ValueError(f"shard {shard} has incomplete RED/GREEN evidence")
        completed.extend(names)

    if seen_shards != set(range(expected_shards)):
        raise ValueError(f"missing shard(s): {sorted(set(range(expected_shards)) - seen_shards)}")
    if len(completed) != len(expected) or set(completed) != set(expected):
        raise ValueError(
            f"pairing mutants completion union is {len(completed)}/{len(expected)} cases"
        )
    print(f"pairing-pr4-mutants-complete:{len(completed)}")


def self_test() -> None:
    expected = expected_cases()
    full = [
        {
            "shard": s,
            "shards": 4,
            "cases": [
                {"name": name, "red": True, "green": True}
                for idx, name in enumerate(expected)
                if idx % 4 == s
            ],
        }
        for s in range(4)
    ]
    check(full, 4)

    # Red control 1: one shard skipped
    try:
        check(full[:3], 4)
        raise AssertionError("skipped shard must fail completion")
    except ValueError:
        pass

    # Red control 2: shard drops one mutant
    truncated = [dict(m) for m in full]
    truncated[2] = {**truncated[2], "cases": truncated[2]["cases"][:-1]}
    try:
        check(truncated, 4)
        raise AssertionError("truncated shard must fail completion")
    except ValueError:
        pass

    # Red control 3: mutant did not fail RED
    no_red = [dict(m) for m in full]
    bad_cases = list(no_red[0]["cases"])
    bad_cases[0] = {**bad_cases[0], "red": False}
    no_red[0] = {**no_red[0], "cases": bad_cases}
    try:
        check(no_red, 4)
        raise AssertionError("non-RED mutant must fail completion")
    except ValueError:
        pass

    print("pairing-mutants-completion self-test: ok")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shards", type=int, default=4)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("manifests", nargs="*", type=Path)
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    if not args.manifests:
        parser.error("at least one manifest path is required unless --self-test is set")

    check([json.loads(p.read_text()) for p in args.manifests], args.shards)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
