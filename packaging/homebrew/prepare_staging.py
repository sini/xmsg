#!/usr/bin/env python3
"""Per-user staging preparation, durable staging cache, LaunchAgent plist emission,
and monotonic upgrade/rollback verification for Homebrew-installed xmsg on macOS.

Uses Apple CLT `/usr/bin/python3` (stdlib only) and queries the installed opt
binary's shared resolver (`xmsg doctor --json`) to verify durable roots before
writing private staging cache material or LaunchAgent configuration.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import subprocess
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import verify_staging  # noqa: E402

STAGE_VERSION_RE = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)\.([1-9][0-9]*)$")
HOMEBREW_SERVICE_LABEL = "homebrew.mxcl.xmsg"


class PrepareError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def parse_stage_version(version: str) -> tuple[int, int, int, int]:
    m = STAGE_VERSION_RE.match(version)
    if not m:
        raise PrepareError("invalid_stage_version", f"expected <major>.<minor>.<patch>.<run_number>, got {version!r}")
    return tuple(int(g) for g in m.groups())  # type: ignore[return-value]


def ensure_private_dir(path: pathlib.Path) -> pathlib.Path:
    if path.is_symlink():
        raise PrepareError("unsafe_private_dir", f"directory must not be a symlink: {path}")
    if path.exists():
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode):
            raise PrepareError("unsafe_private_dir", f"path exists and is not a directory: {path}")
        if st.st_uid != os.geteuid():
            raise PrepareError("unsafe_private_dir", f"wrong owner uid={st.st_uid} on {path}")
        if (st.st_mode & 0o777) != 0o700:
            raise PrepareError("unsafe_private_dir", f"unsafe mode {oct(st.st_mode & 0o777)} on {path}")
        return path.resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(path, 0o700)
    return path.resolve()


def create_private_file_if_missing(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise PrepareError("unsafe_log_file", f"log file must not be a symlink: {path}")
    flags = os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    os.close(fd)
    st = os.lstat(path)
    if st.st_uid != os.geteuid():
        raise PrepareError("unsafe_log_file", f"log file owner mismatch on {path}")
    if (st.st_mode & 0o077) != 0:
        raise PrepareError("unsafe_log_file", f"log file has group/other permissions {oct(st.st_mode & 0o777)}: {path}")


def query_installed_resolver(
    xmsg_bin: pathlib.Path,
    *,
    db_path: pathlib.Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict:
    cmd = [str(xmsg_bin), "doctor", "--json"]
    if db_path is not None:
        cmd.extend(["--db-path", str(db_path)])
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    if not proc.stdout.strip():
        raise PrepareError(
            "resolver_unavailable",
            f"installed binary doctor --json produced no JSON output (rc={proc.returncode}): {proc.stderr.strip()}",
        )
    try:
        return json.loads(proc.stdout)
    except Exception as exc:
        raise PrepareError("resolver_unavailable", f"invalid JSON from doctor --json: {exc}") from exc


def write_launch_agent_plist(
    plist_path: pathlib.Path,
    *,
    xmsg_bin: pathlib.Path,
    serve_args: list[str],
    stdout_log: pathlib.Path,
    stderr_log: pathlib.Path,
    env_vars: dict[str, str] | None = None,
) -> None:
    payload: dict = {
        "Label": HOMEBREW_SERVICE_LABEL,
        "ProgramArguments": [str(xmsg_bin), "serve", *serve_args],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "Umask": 63,  # octal 0077
        "StandardOutPath": str(stdout_log),
        "StandardErrorPath": str(stderr_log),
    }
    if env_vars:
        payload["EnvironmentVariables"] = env_vars
    plist_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_path = plist_path.with_suffix(".plist.tmp")
    tmp_path.write_bytes(plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True))
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, plist_path)

    lint = subprocess.run(["plutil", "-lint", str(plist_path)], capture_output=True, text=True, check=False)
    if lint.returncode != 0:
        raise PrepareError("invalid_plist", f"plutil -lint failed: {lint.stdout.strip()} {lint.stderr.strip()}")


def cmd_prepare(args: argparse.Namespace) -> int:
    os.umask(0o077)
    xmsg_bin = args.xmsg_bin.resolve()
    if not xmsg_bin.is_file():
        raise PrepareError("missing_installed_binary", f"installed xmsg binary not found: {xmsg_bin}")

    receipt_path = args.verified_dir / "verified-receipt.json"
    if not receipt_path.is_file():
        raise PrepareError("missing_verified_receipt", f"verified-receipt.json not found in {args.verified_dir}")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    expected_sha = receipt["source_sha"]
    stage_version = receipt["stage_version"]
    parse_stage_version(stage_version)

    # Verify the installed opt binary offline before using it or caching material.
    try:
        verify_staging.verify_macho_arm64(xmsg_bin)
        verify_staging.verify_embedded_revision(xmsg_bin, expected_sha)
        verify_staging.verify_codesign(xmsg_bin)
    except verify_staging.PreflightError as exc:
        raise PrepareError(exc.code, exc.detail) from exc

    archive_src = pathlib.Path(receipt["archive_path"])
    manifest_src = pathlib.Path(receipt["manifest_path"])
    formula_src = pathlib.Path(receipt["formula_path"])
    try:
        verify_staging.verify_formula_integrity(
            formula_src.read_text(encoding="utf-8"),
            expected_archive_path=archive_src,
            expected_stage_version=stage_version,
        )
    except verify_staging.PreflightError as exc:
        raise PrepareError(exc.code, exc.detail) from exc

    # Verify durable state root through the installed binary's shared resolver.
    db_pin = args.db_path
    doc = query_installed_resolver(xmsg_bin, db_path=db_pin)
    resolved_state_str = (doc.get("install") or {}).get("profile_state_root")
    if args.state_root is not None:
        state_root = ensure_private_dir(args.state_root)
        if resolved_state_str is not None:
            resolved_state = pathlib.Path(resolved_state_str).resolve()
            if resolved_state != state_root:
                raise PrepareError(
                    "state_root_mismatch",
                    f"requested state_root {state_root} disagrees with installed resolver {resolved_state}",
                )
    else:
        if not resolved_state_str:
            raise PrepareError("state_root_unresolved", "installed doctor --json did not report profile_state_root")
        state_root = ensure_private_dir(pathlib.Path(resolved_state_str))

    cache_root = ensure_private_dir(state_root / "staging-cache")
    version_cache = ensure_private_dir(cache_root / stage_version)

    cached_archive = version_cache / archive_src.name
    cached_manifest = version_cache / "manifest.json"
    cached_receipt = version_cache / "verified-receipt.json"
    cached_formula = version_cache / "xmsg.rb"
    for src, dst in (
        (archive_src, cached_archive),
        (manifest_src, cached_manifest),
        (receipt_path, cached_receipt),
    ):
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o600)

    # Re-render cached formula pointing to the durable cached archive so cached rollback survives scratch cleanup.
    cached_formula_text = verify_staging.render_formula_from_template(
        args.formula_template,
        stage_version=stage_version,
        archive_path=cached_archive,
        archive_sha256=receipt["archive_sha256"],
        source_sha=expected_sha,
    )
    verify_staging.verify_formula_integrity(
        cached_formula_text,
        expected_archive_path=cached_archive,
        expected_stage_version=stage_version,
    )
    cached_formula.write_text(cached_formula_text, encoding="utf-8")
    os.chmod(cached_formula, 0o600)

    logs_dir = ensure_private_dir(args.logs_dir if args.logs_dir is not None else state_root / "logs")
    stdout_log = logs_dir / "stdout.log"
    stderr_log = logs_dir / "stderr.log"
    create_private_file_if_missing(stdout_log)
    create_private_file_if_missing(stderr_log)

    serve_args: list[str] = []
    if db_pin is not None:
        serve_args.extend(["--db-path", str(db_pin.resolve())])
    elif args.pin_resolved_db:
        serve_args.extend(["--db-path", str(state_root / "xmsg.db")])

    plist_out = args.plist_out if args.plist_out is not None else state_root / f"{HOMEBREW_SERVICE_LABEL}.plist"
    write_launch_agent_plist(
        plist_out,
        xmsg_bin=xmsg_bin,
        serve_args=serve_args,
        stdout_log=stdout_log,
        stderr_log=stderr_log,
    )

    out = {
        "status": "prepared",
        "stage_version": stage_version,
        "source_sha": expected_sha,
        "state_root": str(state_root),
        "staging_cache_dir": str(version_cache),
        "cached_formula": str(cached_formula),
        "cached_archive": str(cached_archive),
        "logs_dir": str(logs_dir),
        "stdout_log": str(stdout_log),
        "stderr_log": str(stderr_log),
        "plist_path": str(plist_out.resolve()),
        "service_label": HOMEBREW_SERVICE_LABEL,
        "umask": 63,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_check_upgrade(args: argparse.Namespace) -> int:
    cur_tuple = parse_stage_version(args.current_version)
    cand_tuple = parse_stage_version(args.candidate_version)
    if cand_tuple <= cur_tuple:
        raise PrepareError(
            "non_monotonic_stage_version",
            f"candidate stage version {args.candidate_version} is not strictly greater than current {args.current_version}",
        )

    rollback_dir = args.state_root / "staging-cache" / args.current_version
    if not rollback_dir.is_dir():
        raise PrepareError(
            "missing_rollback_bundle",
            f"retained verified rollback bundle missing for {args.current_version} at {rollback_dir}",
        )
    rollback_formula = rollback_dir / "xmsg.rb"
    rollback_manifest = rollback_dir / "manifest.json"
    rollback_receipt = rollback_dir / "verified-receipt.json"
    for p in (rollback_formula, rollback_manifest, rollback_receipt):
        if not p.is_file():
            raise PrepareError("missing_rollback_bundle", f"rollback bundle incomplete, missing {p}")
    rm = json.loads(rollback_manifest.read_text(encoding="utf-8"))
    rollback_archive = rollback_dir / rm["archive_name"]
    if not rollback_archive.is_file():
        raise PrepareError("missing_rollback_bundle", f"rollback archive missing: {rollback_archive}")
    try:
        verify_staging.verify_formula_integrity(
            rollback_formula.read_text(encoding="utf-8"),
            expected_archive_path=rollback_archive,
            expected_stage_version=args.current_version,
        )
    except verify_staging.PreflightError as exc:
        raise PrepareError("corrupt_rollback_bundle", exc.detail) from exc

    print(
        json.dumps(
            {
                "status": "upgrade_allowed",
                "current_version": args.current_version,
                "candidate_version": args.candidate_version,
                "rollback_formula": str(rollback_formula.resolve()),
                "rollback_archive": str(rollback_archive.resolve()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Per-user staging preparation and upgrade order verifier.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_prep = sub.add_parser("prepare", help="Verify installed binary, stage durable cache, logs, and LaunchAgent plist.")
    p_prep.add_argument("--xmsg-bin", type=pathlib.Path, required=True)
    p_prep.add_argument("--verified-dir", type=pathlib.Path, required=True)
    p_prep.add_argument("--formula-template", type=pathlib.Path, required=True)
    p_prep.add_argument("--state-root", type=pathlib.Path, default=None)
    p_prep.add_argument("--db-path", type=pathlib.Path, default=None)
    p_prep.add_argument("--logs-dir", type=pathlib.Path, default=None)
    p_prep.add_argument("--plist-out", type=pathlib.Path, default=None)
    p_prep.add_argument("--pin-resolved-db", action="store_true")
    p_prep.set_defaults(func=cmd_prepare)

    p_upg = sub.add_parser("check-upgrade", help="Verify monotonic stage version and retained rollback bundle.")
    p_upg.add_argument("--state-root", type=pathlib.Path, required=True)
    p_upg.add_argument("--current-version", required=True)
    p_upg.add_argument("--candidate-version", required=True)
    p_upg.set_defaults(func=cmd_check_upgrade)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PrepareError as err:
        print(f"XMSG_PREPARE_ERROR: {err.code}: {err.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
