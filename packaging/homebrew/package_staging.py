#!/usr/bin/env python3
"""Package a native macOS arm64 staging artifact for sini/xmsg.

Uses Python 3 stdlib and Apple CLT tools (`otool`, `codesign`, `git`) only.
Verifies checkout SHA, Mach-O architecture, linker signature, and embedded
`__DATA,__xmsg_rev` section before packing the deterministic inner tarball
and manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import zipfile

DEFAULT_SKILL_ASSET = "assets/claude/xmsg/SKILL.md"
PACKED_BINARY_REL = "bin/xmsg"
PACKED_SKILL_REL = "share/xmsg/claude/xmsg/SKILL.md"
REVISION_PREFIX = b"XMSG-REV-V1:"
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
CARGO_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_cargo_version(repo_root: pathlib.Path) -> str:
    cargo_toml = (repo_root / "Cargo.toml").read_text(encoding="utf-8")
    in_package = False
    for line in cargo_toml.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if in_package:
            m = CARGO_VERSION_RE.match(line)
            if m:
                return m.group(1)
    raise RuntimeError("failed to parse [package] version from Cargo.toml")


def verify_macho_arm64(binary: pathlib.Path) -> None:
    proc = subprocess.run(
        ["otool", "-hv", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"otool -hv failed on {binary}: {proc.stderr.strip()}")
    tokens = proc.stdout.split()
    if "MH_MAGIC_64" not in tokens or "ARM64" not in tokens or "EXECUTE" not in tokens:
        raise RuntimeError(f"binary is not a 64-bit arm64 Mach-O executable: {proc.stdout.strip()}")


def read_embedded_revision(binary: pathlib.Path) -> str:
    proc = subprocess.run(
        ["otool", "-s", "__DATA", "__xmsg_rev", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"otool -s __DATA __xmsg_rev failed: {proc.stderr.strip()}")
    raw = bytearray()
    for line in proc.stdout.splitlines():
        if "\t" not in line and not re.match(r"^[0-9a-fA-F]{8,16}\s+", line):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        # First token is virtual address; remaining tokens are hex bytes (2 chars) or 32-bit words (8 chars).
        for tok in parts[1:]:
            if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
                raw.append(int(tok, 16))
            elif len(tok) == 8 and all(c in "0123456789abcdefABCDEF" for c in tok):
                raw.extend(int(tok, 16).to_bytes(4, "little"))
            else:
                break
    if not raw.startswith(REVISION_PREFIX):
        raise RuntimeError("Mach-O __DATA,__xmsg_rev section missing XMSG-REV-V1: prefix")
    rest = bytes(raw[len(REVISION_PREFIX) :])
    nul = rest.find(0)
    if nul <= 0:
        raise RuntimeError("Mach-O __DATA,__xmsg_rev section missing NUL-terminated payload")
    return rest[:nul].decode("ascii")


def verify_codesign(binary: pathlib.Path) -> None:
    proc = subprocess.run(
        ["codesign", "--verify", "--strict", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"codesign --verify failed on {binary}: {proc.stderr.strip()}")


def write_deterministic_tarball(
    output_tar_gz: pathlib.Path,
    binary: pathlib.Path,
    skill: pathlib.Path,
) -> dict[str, str]:
    entries = [
        (PACKED_BINARY_REL, binary.read_bytes(), 0o755),
        (PACKED_SKILL_REL, skill.read_bytes(), 0o644),
    ]
    asset_hashes: dict[str, str] = {}
    with output_tar_gz.open("wb") as raw_fh:
        # Use gzip with mtime=0 for byte-deterministic archives.
        import gzip

        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
                for relpath, data, mode in sorted(entries, key=lambda e: e[0]):
                    info = tarfile.TarInfo(name=relpath)
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    tf.addfile(info, io.BytesIO(data))
                    asset_hashes[relpath] = sha256_bytes(data)
    os.chmod(output_tar_gz, 0o600)
    return asset_hashes


def pack_outer_zip(outer_zip: pathlib.Path, archive_path: pathlib.Path, manifest_path: pathlib.Path) -> str:
    with zipfile.ZipFile(outer_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in (archive_path, manifest_path):
            zi = zipfile.ZipInfo(filename=p.name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.external_attr = 0o100644 << 16
            zf.writestr(zi, p.read_bytes())
    os.chmod(outer_zip, 0o600)
    return sha256_file(outer_zip)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package a native macOS arm64 xmsg staging artifact.")
    parser.add_argument("--repo-root", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--skill-asset", type=pathlib.Path, default=None)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--run-number", type=int, required=True)
    parser.add_argument("--repository", default="sini/xmsg")
    parser.add_argument("--repository-id", type=int, required=True)
    parser.add_argument("--head-repository-id", type=int, required=True)
    parser.add_argument("--workflow-id", type=int, required=True)
    parser.add_argument("--workflow-path", default=".github/workflows/macos-staging.yml")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, default=1)
    parser.add_argument("--artifact-name", default="xmsg-macos-arm64-staging")
    parser.add_argument("--toolchain", default=None)
    parser.add_argument("--outer-zip", type=pathlib.Path, default=None)
    parser.add_argument("--skip-git-head-check", action="store_true")
    args = parser.parse_args(argv)

    repo_root = args.repo_root.resolve()
    if not HEX40_RE.match(args.expected_sha):
        raise SystemExit(f"expected_sha must be 40 lowercase hex chars, got {args.expected_sha!r}")
    if not HEX40_RE.match(args.workflow_head_sha):
        raise SystemExit(f"workflow_head_sha must be 40 lowercase hex chars, got {args.workflow_head_sha!r}")
    if args.run_number < 1:
        raise SystemExit("--run-number must be >= 1")

    if args.skip_git_head_check:
        checkout_sha = args.expected_sha
    else:
        checkout_sha = subprocess.check_output(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    if checkout_sha != args.expected_sha:
        raise SystemExit(f"checkout SHA mismatch: HEAD={checkout_sha} != expected={args.expected_sha}")
    if args.workflow_head_sha != checkout_sha:
        raise SystemExit(
            f"workflow head SHA mismatch: workflow_head_sha={args.workflow_head_sha} != checkout_sha={checkout_sha}"
        )

    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    skill = (args.skill_asset if args.skill_asset is not None else repo_root / DEFAULT_SKILL_ASSET).resolve()
    if not skill.is_file():
        raise SystemExit(
            f"required version-matched Claude skill asset not found at {skill} "
            f"(expected canonical path {DEFAULT_SKILL_ASSET})"
        )

    verify_macho_arm64(binary)
    embedded_rev = read_embedded_revision(binary)
    if embedded_rev != checkout_sha:
        raise SystemExit(
            f"embedded Mach-O revision mismatch before packing: embedded={embedded_rev!r} != checkout={checkout_sha!r}"
        )
    verify_codesign(binary)

    cargo_version = read_cargo_version(repo_root)
    stage_version = f"{cargo_version}.{args.run_number}"
    toolchain = args.toolchain or subprocess.check_output(["rustc", "--version"], text=True).strip()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(args.output_dir, 0o700)
    archive_name = f"xmsg-{stage_version}-arm64-macos.tar.gz"
    archive_path = args.output_dir / archive_name
    asset_hashes = write_deterministic_tarball(archive_path, binary, skill)
    archive_sha256 = sha256_file(archive_path)

    manifest = {
        "schema_version": 1,
        "stage_version": stage_version,
        "cargo_version": cargo_version,
        "workflow_run_number": args.run_number,
        "checkout_sha": checkout_sha,
        "workflow_head_sha": args.workflow_head_sha,
        "build_revision": embedded_rev,
        "target": "aarch64-apple-darwin",
        "toolchain": toolchain,
        "archive_name": archive_name,
        "archive_sha256": archive_sha256,
        "assets": asset_hashes,
        "workflow": {
            "repository": args.repository,
            "repository_id": args.repository_id,
            "head_repository_id": args.head_repository_id,
            "workflow_id": args.workflow_id,
            "workflow_path": args.workflow_path,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "artifact_name": args.artifact_name,
        },
    }
    manifest_path = args.output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(manifest_path, 0o600)

    result = {
        "stage_version": stage_version,
        "archive_path": str(archive_path),
        "archive_sha256": archive_sha256,
        "manifest_path": str(manifest_path),
    }
    if args.outer_zip is not None:
        outer_digest = pack_outer_zip(args.outer_zip, archive_path, manifest_path)
        result["outer_zip"] = str(args.outer_zip)
        result["outer_digest"] = f"sha256:{outer_digest}"
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
