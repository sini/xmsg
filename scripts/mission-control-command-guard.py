"""Check that Mission Control command fixtures cannot enter a shipped build."""

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ISSUER = "src/mission_control.rs"
COMMAND = "src/mission_control/command.rs"
NATIVE = "src/mission_control_client.rs"
REVIEW = "src/mission_control_client/command_review.rs"
CLI = "src/main.rs"
FEATURE_CONTROL = "src/discovery/mod.rs"
CONSTRUCTORS = (
    "start_with_command_authority_for_test",
    "start_with_command_double_for_test",
)
GATE = "#[cfg(test)]"
GATES = (
    *((ISSUER, "fn", name) for name in CONSTRUCTORS),
    (COMMAND, "struct", "ExactCommandAuthorityFixture"),
    (NATIVE, "mod", "command_review"),
)


class GuardFailure(Exception):
    pass


def item_pattern(kind, name):
    return re.compile(
        rf"(?m)^[ \t]*(?:pub(?:\([^()]+\))?\s+)?(?:async\s+)?{kind}\s+{name}\b"
    )


def item_gate(source, kind, name):
    matches = list(item_pattern(kind, name).finditer(source))
    if len(matches) != 1:
        raise GuardFailure(f"{name}: expected one {kind} definition, got {len(matches)}")
    attrs = []
    for line in reversed(source[: matches[0].start()].splitlines()):
        line = line.strip()
        if not line.startswith("#["):
            break
        attrs.append(line)
    guards = [attr for attr in attrs if attr.startswith(("#[cfg(", "#[cfg_attr("))]
    if guards != [GATE]:
        raise GuardFailure(f"{name}: expected only {GATE}, got {guards}")
    return matches[0]


def verify(sources):
    for filename, kind, name in GATES:
        item_gate(sources[filename], kind, name)

    if not item_pattern("struct", "CommandReview").search(sources[REVIEW]):
        raise GuardFailure("CommandReview: test-module source control missing")

    # The declaration is the native CLI's only reference to the review module.
    module = item_gate(sources[NATIVE], "mod", "command_review")
    for filename in (NATIVE, CLI):
        source = sources[filename]
        if filename == NATIVE:
            source = source[: module.start()] + source[module.end() :]
        for name in (
            "CommandReview",
            "command_review",
            "review_session",
            *CONSTRUCTORS,
            "ExactCommandAuthorityFixture",
        ):
            if re.search(rf"\b{re.escape(name)}\b", source):
                raise GuardFailure(f"{filename}: shipped CLI/key path references {name}")

    cargo = tomllib.loads(sources["Cargo.toml"])
    if "test-hooks" not in cargo["features"] or "test-hooks" not in cargo[
        "dev-dependencies"
    ]["xmsg"]["features"]:
        raise GuardFailure("test-hooks Cargo feature and self dev-dependency control missing")
    if not re.search(r'cfg\([^\n]*feature\s*=\s*"test-hooks"', sources[FEATURE_CONTROL]):
        raise GuardFailure("test-hooks Rust source control missing")


def expect_red(sources, filename, changed, label):
    if changed == sources[filename]:
        raise GuardFailure(f"{label}: source change did not apply")
    try:
        verify({**sources, filename: changed})
    except GuardFailure:
        print(f"RED {label}")
    else:
        raise GuardFailure(f"{label}: source fault passed")


def controls(sources):
    for filename, kind, name in GATES:
        source = sources[filename]
        item = item_gate(source, kind, name)
        start = source.rindex(GATE, 0, item.start())
        end = start + len(GATE)
        expect_red(sources, filename, source[:start] + source[end:], f"{name}: gate removed")
        expect_red(
            sources,
            filename,
            source[:start] + '#[cfg(any(test, feature = "test-hooks"))]' + source[end:],
            f"{name}: gate widened to test-hooks",
        )
    for filename in (CLI, NATIVE):
        expect_red(
            sources,
            filename,
            sources[filename] + "\nuse crate::mission_control_client::command_review::CommandReview;\n",
            f"{filename}: shipped review reference",
        )


def main():
    files = {filename for filename, _, _ in GATES} | {REVIEW, CLI, FEATURE_CONTROL, "Cargo.toml"}
    try:
        sources = {filename: (ROOT / filename).read_text(encoding="utf-8") for filename in files}
        verify(sources)
        print("GREEN production constructor and native review isolation")
        controls(sources)
    except (GuardFailure, OSError, ValueError, KeyError, TypeError) as error:
        print(f"mission-control command guard: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
