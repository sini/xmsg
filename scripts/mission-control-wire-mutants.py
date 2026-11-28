#!/usr/bin/env python3
"""Run Mission Control wire oracles against isolated production source changes."""

import argparse
import math
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS = "mission_control::command_wire::tests"
PATH = "src/mission_control"
CASES = (
    (
        "oq13-integral-float",
        f"{PATH}/request.rs",
        "    fn visit_str<E: de::Error>",
        """    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        if value.fract() == 0.0 && (0.0..=SAFE_INTEGER as f64).contains(&value) {
            Ok((value as u64).into())
        } else {
            Err(E::custom("integer outside protocol range"))
        }
    }

    fn visit_str<E: de::Error>""",
        "oq13_generation_spellings_and_range",
        "accepted invalid generation 7.0",
    ),
    (
        "oq13-drop-selector-from-digest",
        f"{PATH}/command_wire.rs",
        "    pub selector: Selector,",
        "    #[serde(skip_serializing)]\n    pub selector: Selector,",
        "oq13_digest_matches_frozen_selector_and_http_prepare",
        "canonical digest lost its selector",
    ),
    (
        "m12-accept-noncanonical-zero",
        f"{PATH}/request.rs",
        "    fn visit_str<E: de::Error>",
        """    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        if value >= 0 { Ok((value as u64).into()) } else { Err(E::custom("signed")) }
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        if value == 0.0 { Ok(0u64.into()) } else { Err(E::custom("float")) }
    }

    fn visit_str<E: de::Error>""",
        "oq13_unsigned_fields_reject_noncanonical_zero",
        "accepted noncanonical zero spelling \"incarnation\":-0",
    ),
    (
        "m23-leave-bidi-isolates-unescaped",
        "src/mission_control_client/command_review.rs",
        r"'\u{2066}'..='\u{206f}'",
        r"'\u{206a}'..='\u{206f}'",
        "mission_control_client::command_review::tests::sc13_full_escaped_review_precedes_key_and_commit",
        "full review left control or bidi characters unescaped",
    ),
    (
        "m36-allow-executor-text-limit-plus-one",
        f"{PATH}/command_wire.rs",
        "self.params.text.len() <= MAX_EXECUTOR_TEXT_BYTES",
        "self.params.text.len() <= MAX_EXECUTOR_TEXT_BYTES + 1",
        "oq13_executor_text_limit_applies_with_raised_string_limit",
        "accepted text one byte over the executor limit",
    ),
    (
        "m37-allow-session-id-limit-plus-one",
        f"{PATH}/command_wire.rs",
        "self.target.selector.session_id.len() <= 128",
        "self.target.selector.session_id.len() <= 129",
        "oq13_session_id_limits_utf8_bytes",
        "accepted a 129-byte executor session ID",
    ),
)


def rust_limit(path, constant):
    pattern = rf"^(?:pub )?const {constant}: usize = ([0-9_* ]+);$"
    matches = re.findall(pattern, path.read_text(), flags=re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError(f"{path}: cannot read a unique numeric {constant}")
    return math.prod(int(piece.replace("_", "")) for piece in matches[0].split("*"))


def check_executor_limit(root):
    # Cargo packages omit the nested executor crate, so check their limits in the source tree.
    wire_limit = rust_limit(root / PATH / "command_wire.rs", "MAX_EXECUTOR_TEXT_BYTES")
    executor_limit = rust_limit(
        root / "extensions/executor/src/protocol.rs", "MAX_TEXT_BYTES"
    )
    if wire_limit != executor_limit:
        raise RuntimeError(
            f"command wire text limit {wire_limit} differs from executor limit {executor_limit}"
        )
    print(f"executor-text-limit: GREEN {wire_limit} bytes", flush=True)


def run(tree, artifacts, label, selected, reason=None):
    command = ["cargo", "test", "--locked", "--color", "never", "--lib", selected]
    if selected != TESTS:
        command += ["--", "--exact"]
    result = subprocess.run(
        command,
        cwd=tree,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=900,
        check=False,
    )
    output = result.stdout
    (artifacts / f"{label}.log").write_text(output)
    if reason is None:
        passed = "test result: ok." in output and "0 passed;" not in output
        if result.returncode != 0 or not passed:
            raise RuntimeError(f"{label}: test control failed\n{output}")
        print(f"{label}: GREEN", flush=True)
        return
    if (
        result.returncode != 101
        or f"test {selected} ... FAILED" not in output
        or "test result: FAILED. 0 passed; 1 failed;" not in output
        or reason not in output
    ):
        raise RuntimeError(f"{label}: intended oracle did not kill source change\n{output}")
    print(f"{label}: RED {reason}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=tuple(case[0] for case in CASES), action="append")
    args = parser.parse_args()
    cases = [case for case in CASES if not args.case or case[0] in args.case]
    check_executor_limit(ROOT)
    artifacts = ROOT / ".artifacts" / "mission-control-wire-mutants"
    artifacts.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("CARGO_BUILD_JOBS", "8")
    os.environ.setdefault("CARGO_TARGET_DIR", str(ROOT / "target"))
    with tempfile.TemporaryDirectory(prefix="mission-control-wire-mutants-") as temp:
        tree = Path(temp)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, tree / name)
        for name in ("src", "tests", "assets"):
            shutil.copytree(ROOT / name, tree / name)
        run(tree, artifacts, "control", TESTS)
        for name, filename, old, new, test, reason in cases:
            source = tree / filename
            original = source.read_text()
            if original.count(old) != 1:
                raise RuntimeError(f"{name}: source anchor is not unique")
            selected = test if "::" in test else f"{TESTS}::{test}"
            source.write_text(original.replace(old, new, 1))
            try:
                run(tree, artifacts, name, selected, reason)
            finally:
                source.write_text(original)
            run(tree, artifacts, f"{name}-restored", selected)
        print(f"mission-control-wire-mutants-complete: {len(cases)}/{len(CASES)}", flush=True)


if __name__ == "__main__":
    main()
