#!/usr/bin/env python3
"""Run Mission Control wire oracles against isolated production source changes."""

import os
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
)


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
        for name, filename, old, new, test, reason in CASES:
            source = tree / filename
            original = source.read_text()
            if original.count(old) != 1:
                raise RuntimeError(f"{name}: source anchor is not unique")
            selected = f"{TESTS}::{test}"
            source.write_text(original.replace(old, new, 1))
            try:
                run(tree, artifacts, name, selected, reason)
            finally:
                source.write_text(original)
            run(tree, artifacts, f"{name}-restored", selected)
        print(f"mission-control-wire-mutants-complete: {len(CASES)}/{len(CASES)}", flush=True)


if __name__ == "__main__":
    main()
