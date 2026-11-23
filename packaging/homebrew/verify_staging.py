#!/usr/bin/env python3
"""Standalone pre-execution preflight verifier and formula generator for macOS arm64 xmsg staging.

Uses Apple CLT `/usr/bin/python3` (stdlib only), `otool`, and `codesign`.
Never executes downloaded binaries and never loads downloaded Ruby before every
origin, digest, archive-safety, Mach-O, embedded-revision, signature, and
formula integrity check has passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile

REVISION_PREFIX = b"XMSG-REV-V1:"
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
STAGE_VERSION_RE = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)\.([1-9][0-9]*)$")
ARCHIVE_NAME_RE = re.compile(r"^xmsg-[0-9]+\.[0-9]+\.[0-9]+\.[1-9][0-9]*-arm64-macos\.tar\.gz$")
EXPECTED_INNER_ENTRIES = frozenset({"bin/xmsg", "share/xmsg/claude/xmsg/SKILL.md"})
FORMULA_URL_RE = re.compile(r'^\s*url\s+"([^"]+)"\s*$', re.MULTILINE)
FORMULA_SHA_RE = re.compile(r'^\s*sha256\s+"([0-9a-f]{64})"\s*$', re.MULTILINE)
FORMULA_VER_RE = re.compile(r'^\s*version\s+"([^"]+)"\s*$', re.MULTILINE)


class PreflightError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_clt_prereqs() -> None:
    for tool in ("otool", "codesign"):
        if shutil.which(tool) is None:
            raise PreflightError("prereq_missing", f"required Apple CLT tool not found in PATH: {tool}")


def validate_private_scratch_dir(scratch_dir: pathlib.Path) -> pathlib.Path:
    if scratch_dir.is_symlink():
        raise PreflightError("unsafe_scratch_dir", f"scratch directory must not be a symlink: {scratch_dir}")
    if not scratch_dir.exists():
        raise PreflightError("unsafe_scratch_dir", f"scratch directory must exist before preflight: {scratch_dir}")
    st = os.lstat(scratch_dir)
    if not stat.S_ISDIR(st.st_mode):
        raise PreflightError("unsafe_scratch_dir", f"scratch path is not a directory: {scratch_dir}")
    if st.st_uid != os.geteuid():
        raise PreflightError(
            "unsafe_scratch_dir",
            f"scratch directory owner uid={st.st_uid} != euid={os.geteuid()}: {scratch_dir}",
        )
    if (st.st_mode & 0o777) != 0o700:
        raise PreflightError(
            "unsafe_scratch_dir",
            f"scratch directory must have mode 0700, got {oct(st.st_mode & 0o777)}: {scratch_dir}",
        )
    return scratch_dir.resolve()


def fetch_github_json(url: str, token: str | None = None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "xmsg-staging-verifier",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status != 200:
                raise PreflightError("artifact_origin_mismatch", f"GitHub API returned HTTP {resp.status} for {url}")
            return json.loads(resp.read().decode("utf-8"))
    except PreflightError:
        raise
    except Exception as exc:
        raise PreflightError("artifact_origin_mismatch", f"failed to fetch GitHub metadata from {url}: {exc}") from exc


def load_run_and_artifact_metadata(args: argparse.Namespace) -> tuple[dict, dict]:
    if args.run_metadata_file is not None or args.artifact_metadata_file is not None:
        if args.run_metadata_file is None or args.artifact_metadata_file is None:
            raise PreflightError(
                "artifact_origin_mismatch",
                "both --run-metadata-file and --artifact-metadata-file are required for offline verification",
            )
        try:
            run_meta = json.loads(args.run_metadata_file.read_text(encoding="utf-8"))
            art_meta = json.loads(args.artifact_metadata_file.read_text(encoding="utf-8"))
        except Exception as exc:
            raise PreflightError("artifact_origin_mismatch", f"failed to parse metadata fixture JSON: {exc}") from exc
        return run_meta, art_meta

    if not args.live_github_api:
        raise PreflightError(
            "artifact_origin_mismatch",
            "missing independent run/artifact metadata (supply fixture files or --live-github-api)",
        )

    api_base = args.github_api_base.rstrip("/")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    run_url = f"{api_base}/repos/{args.expected_repo}/actions/runs/{args.expected_run_id}/attempts/{args.expected_run_attempt}"
    art_url = f"{api_base}/repos/{args.expected_repo}/actions/artifacts/{args.expected_artifact_id}"
    return fetch_github_json(run_url, token), fetch_github_json(art_url, token)


def verify_origin_binding(
    run_meta: dict,
    art_meta: dict,
    *,
    expected_repo: str,
    expected_repo_id: int,
    expected_workflow_id: int,
    expected_workflow_path: str,
    expected_run_id: int,
    expected_run_attempt: int,
    expected_artifact_id: int,
    expected_source_sha: str,
) -> None:
    """Verify independent upstream GitHub run & artifact provenance before reading any download."""
    repo_obj = run_meta.get("repository") or {}
    head_repo_obj = run_meta.get("head_repository") or {}

    if repo_obj.get("full_name") != expected_repo:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"repository full_name mismatch: got {repo_obj.get('full_name')!r}, expected {expected_repo!r}",
        )
    if repo_obj.get("id") != expected_repo_id:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"repository id mismatch: got {repo_obj.get('id')!r}, expected {expected_repo_id}",
        )
    if head_repo_obj.get("id") != expected_repo_id:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"fork or foreign head repository refused: head_repository.id={head_repo_obj.get('id')!r} != {expected_repo_id}",
        )
    if run_meta.get("workflow_id") != expected_workflow_id:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"workflow_id mismatch: got {run_meta.get('workflow_id')!r}, expected {expected_workflow_id}",
        )
    if run_meta.get("path") != expected_workflow_path:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"workflow path mismatch: got {run_meta.get('path')!r}, expected {expected_workflow_path!r}",
        )
    if run_meta.get("id") != expected_run_id:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"run id mismatch: got {run_meta.get('id')!r}, expected {expected_run_id}",
        )
    if run_meta.get("run_attempt") != expected_run_attempt:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"run attempt mismatch: got {run_meta.get('run_attempt')!r}, expected {expected_run_attempt}",
        )
    if run_meta.get("status") != "completed" or run_meta.get("conclusion") != "success":
        raise PreflightError(
            "artifact_origin_mismatch",
            f"workflow run not completed successfully: status={run_meta.get('status')!r} conclusion={run_meta.get('conclusion')!r}",
        )
    if run_meta.get("head_sha") != expected_source_sha:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"workflow run head_sha mismatch: got {run_meta.get('head_sha')!r}, expected {expected_source_sha!r}",
        )

    if art_meta.get("id") != expected_artifact_id:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"artifact id mismatch: got {art_meta.get('id')!r}, expected {expected_artifact_id}",
        )
    if art_meta.get("expired") is not False:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"artifact is expired or expiry is unknown: expired={art_meta.get('expired')!r}",
        )
    art_run = art_meta.get("workflow_run") or {}
    if art_run.get("id") != expected_run_id:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"artifact workflow_run.id mismatch: got {art_run.get('id')!r}, expected {expected_run_id}",
        )
    if art_run.get("repository_id") is not None and art_run.get("repository_id") != expected_repo_id:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"artifact workflow_run.repository_id mismatch: got {art_run.get('repository_id')!r}",
        )
    if art_run.get("head_repository_id") is not None and art_run.get("head_repository_id") != expected_repo_id:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"artifact workflow_run.head_repository_id mismatch (fork): got {art_run.get('head_repository_id')!r}",
        )
    if art_run.get("head_sha") != expected_source_sha:
        raise PreflightError(
            "artifact_origin_mismatch",
            f"artifact workflow_run.head_sha mismatch: got {art_run.get('head_sha')!r}, expected {expected_source_sha!r}",
        )


def verify_outer_artifact_digest(artifact_zip: pathlib.Path, art_meta: dict) -> str:
    digest_field = art_meta.get("digest")
    if not isinstance(digest_field, str) or not digest_field.startswith("sha256:"):
        raise PreflightError(
            "artifact_digest_mismatch",
            f"independent artifact metadata missing sha256 digest: {digest_field!r}",
        )
    expected_hex = digest_field[len("sha256:") :]
    if not HEX64_RE.match(expected_hex):
        raise PreflightError("artifact_digest_mismatch", f"malformed artifact sha256 digest: {digest_field!r}")
    if not artifact_zip.is_file() or artifact_zip.is_symlink():
        raise PreflightError("artifact_digest_mismatch", f"outer artifact file missing or symlink: {artifact_zip}")
    actual_hex = sha256_file(artifact_zip)
    if actual_hex != expected_hex:
        raise PreflightError(
            "artifact_digest_mismatch",
            f"outer artifact digest mismatch: actual=sha256:{actual_hex} expected={digest_field}",
        )
    return actual_hex


def _check_safe_relpath(name: str) -> pathlib.PurePosixPath:
    if not name or name.startswith("/") or name.startswith("\\") or "\x00" in name:
        raise PreflightError("archive_entry_rejected", f"unsafe archive path: {name!r}")
    p = pathlib.PurePosixPath(name)
    if any(part in ("..", ".", "") for part in p.parts):
        raise PreflightError("archive_entry_rejected", f"escaping or non-canonical archive path: {name!r}")
    return p


def safe_extract_outer_zip(artifact_zip: pathlib.Path, dest_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Validate every outer zip entry before writing any byte; extract only manifest.json + inner tarball."""
    try:
        with zipfile.ZipFile(artifact_zip, "r") as zf:
            infos = zf.infolist()
            seen: set[str] = set()
            archive_entry: str | None = None
            has_manifest = False
            for info in infos:
                name = info.filename
                if info.is_dir():
                    raise PreflightError("archive_entry_rejected", f"unexpected directory in outer zip: {name!r}")
                p = _check_safe_relpath(name)
                if len(p.parts) != 1:
                    raise PreflightError("archive_entry_rejected", f"nested path rejected in outer zip: {name!r}")
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode != 0 and not stat.S_ISREG(unix_mode):
                    raise PreflightError(
                        "archive_entry_rejected",
                        f"non-regular entry rejected in outer zip: {name!r} mode={oct(unix_mode)}",
                    )
                if name in seen:
                    raise PreflightError("archive_entry_rejected", f"duplicate entry in outer zip: {name!r}")
                seen.add(name)
                if name == "manifest.json":
                    has_manifest = True
                elif ARCHIVE_NAME_RE.match(name) and archive_entry is None:
                    archive_entry = name
                else:
                    raise PreflightError("archive_entry_rejected", f"unexpected entry in outer zip: {name!r}")

            if not has_manifest or archive_entry is None or len(seen) != 2:
                raise PreflightError(
                    "archive_entry_rejected",
                    f"outer zip must contain exactly manifest.json and one inner tarball, got {sorted(seen)}",
                )

            out_manifest = dest_dir / "manifest.json"
            out_archive = dest_dir / archive_entry
            for name, target in (("manifest.json", out_manifest), (archive_entry, out_archive)):
                data = zf.read(name)
                target.write_bytes(data)
                os.chmod(target, 0o600)
            return out_manifest, out_archive
    except PreflightError:
        raise
    except Exception as exc:
        raise PreflightError("archive_entry_rejected", f"failed to inspect outer zip: {exc}") from exc


def safe_extract_inner_tarball(archive_path: pathlib.Path, extract_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    """Validate every inner tar entry BEFORE extracting any byte."""
    extract_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(extract_dir, 0o700)
    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            members = tf.getmembers()
            seen: set[str] = set()
            for m in members:
                _check_safe_relpath(m.name)
                if m.issym() or m.islnk() or not m.isfile():
                    raise PreflightError(
                        "archive_entry_rejected",
                        f"non-regular/symlink entry rejected in inner tarball: {m.name!r}",
                    )
                if m.name in seen:
                    raise PreflightError("archive_entry_rejected", f"duplicate entry in inner tarball: {m.name!r}")
                if m.name not in EXPECTED_INNER_ENTRIES:
                    raise PreflightError("archive_entry_rejected", f"unexpected entry in inner tarball: {m.name!r}")
                seen.add(m.name)

            if seen != EXPECTED_INNER_ENTRIES:
                raise PreflightError(
                    "archive_entry_rejected",
                    f"inner tarball entry set mismatch: got {sorted(seen)}, expected {sorted(EXPECTED_INNER_ENTRIES)}",
                )

            extracted: dict[str, pathlib.Path] = {}
            for m in members:
                target = (extract_dir / m.name).resolve()
                if not str(target).startswith(str(extract_dir.resolve()) + os.sep):
                    raise PreflightError("archive_entry_rejected", f"tar extraction escaped scratch dir: {m.name!r}")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fh = tf.extractfile(m)
                if fh is None:
                    raise PreflightError("archive_entry_rejected", f"unreadable member in inner tarball: {m.name!r}")
                target.write_bytes(fh.read())
                os.chmod(target, 0o700 if m.name == "bin/xmsg" else 0o600)
                extracted[m.name] = target
            return extracted
    except PreflightError:
        raise
    except Exception as exc:
        raise PreflightError("archive_entry_rejected", f"failed to inspect inner tarball: {exc}") from exc


def verify_manifest_and_digests(
    manifest_path: pathlib.Path,
    archive_path: pathlib.Path,
    extracted: dict[str, pathlib.Path],
    *,
    expected_source_sha: str,
    expected_repo: str,
    expected_repo_id: int,
    expected_workflow_id: int,
    expected_workflow_path: str,
    expected_run_id: int,
    expected_run_attempt: int,
) -> tuple[dict, str]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PreflightError("manifest_mismatch", f"invalid manifest.json: {exc}") from exc

    if manifest.get("schema_version") != 1:
        raise PreflightError("manifest_mismatch", f"unsupported manifest schema_version: {manifest.get('schema_version')!r}")
    stage_version = manifest.get("stage_version")
    if not isinstance(stage_version, str) or not STAGE_VERSION_RE.match(stage_version):
        raise PreflightError("manifest_mismatch", f"invalid stage_version: {stage_version!r}")
    if manifest.get("target") != "aarch64-apple-darwin":
        raise PreflightError("manifest_mismatch", f"unexpected target: {manifest.get('target')!r}")
    for field in ("checkout_sha", "workflow_head_sha", "build_revision"):
        if manifest.get(field) != expected_source_sha:
            raise PreflightError(
                "manifest_mismatch",
                f"manifest {field}={manifest.get(field)!r} != expected {expected_source_sha!r}",
            )
    if manifest.get("archive_name") != archive_path.name:
        raise PreflightError(
            "manifest_mismatch",
            f"manifest archive_name={manifest.get('archive_name')!r} != actual {archive_path.name!r}",
        )

    wf = manifest.get("workflow") or {}
    if (
        wf.get("repository") != expected_repo
        or wf.get("repository_id") != expected_repo_id
        or wf.get("head_repository_id") != expected_repo_id
        or wf.get("workflow_id") != expected_workflow_id
        or wf.get("workflow_path") != expected_workflow_path
        or wf.get("run_id") != expected_run_id
        or wf.get("run_attempt") != expected_run_attempt
    ):
        raise PreflightError("manifest_mismatch", f"manifest workflow provenance disagrees with pinned run: {wf!r}")

    actual_archive_sha = sha256_file(archive_path)
    if manifest.get("archive_sha256") != actual_archive_sha:
        raise PreflightError(
            "manifest_mismatch",
            f"inner archive sha256 mismatch: manifest={manifest.get('archive_sha256')!r} actual={actual_archive_sha!r}",
        )

    assets = manifest.get("assets")
    if not isinstance(assets, dict) or set(assets.keys()) != EXPECTED_INNER_ENTRIES:
        raise PreflightError("manifest_mismatch", f"manifest assets keys mismatch: {assets!r}")
    for rel, expected_asset_sha in assets.items():
        actual_asset_sha = sha256_file(extracted[rel])
        if actual_asset_sha != expected_asset_sha:
            raise PreflightError(
                "manifest_mismatch",
                f"asset digest mismatch for {rel}: manifest={expected_asset_sha!r} actual={actual_asset_sha!r}",
            )

    return manifest, actual_archive_sha


def verify_macho_arm64(binary: pathlib.Path) -> None:
    proc = subprocess.run(["otool", "-hv", str(binary)], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise PreflightError("macho_arch_mismatch", f"otool -hv failed: {proc.stderr.strip()}")
    tokens = proc.stdout.split()
    if "MH_MAGIC_64" not in tokens or "ARM64" not in tokens or "EXECUTE" not in tokens:
        raise PreflightError(
            "macho_arch_mismatch",
            f"binary is not a 64-bit arm64 Mach-O executable: {proc.stdout.strip()}",
        )


def read_embedded_revision(binary: pathlib.Path) -> str:
    proc = subprocess.run(
        ["otool", "-s", "__DATA", "__xmsg_rev", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise PreflightError("embedded_revision_mismatch", f"otool -s __DATA __xmsg_rev failed: {proc.stderr.strip()}")
    raw = bytearray()
    for line in proc.stdout.splitlines():
        if "\t" not in line and not re.match(r"^[0-9a-fA-F]{8,16}\s+", line):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        for tok in parts[1:]:
            if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
                raw.append(int(tok, 16))
            elif len(tok) == 8 and all(c in "0123456789abcdefABCDEF" for c in tok):
                raw.extend(int(tok, 16).to_bytes(4, "little"))
            else:
                break
    if not raw.startswith(REVISION_PREFIX):
        raise PreflightError(
            "embedded_revision_mismatch",
            "Mach-O __DATA,__xmsg_rev section missing XMSG-REV-V1: magic prefix",
        )
    rest = bytes(raw[len(REVISION_PREFIX) :])
    nul = rest.find(0)
    if nul <= 0:
        raise PreflightError("embedded_revision_mismatch", "Mach-O __DATA,__xmsg_rev section missing NUL terminator")
    try:
        return rest[:nul].decode("ascii")
    except UnicodeDecodeError as exc:
        raise PreflightError("embedded_revision_mismatch", f"non-ASCII embedded revision: {exc}") from exc


def verify_embedded_revision(binary: pathlib.Path, expected_source_sha: str) -> str:
    """Read and verify the offline Mach-O __DATA,__xmsg_rev revision (never trust labels alone)."""
    embedded = read_embedded_revision(binary)
    if embedded != expected_source_sha:
        raise PreflightError(
            "embedded_revision_mismatch",
            f"Mach-O __DATA,__xmsg_rev={embedded!r} does not match expected source SHA {expected_source_sha!r}",
        )
    return embedded


def verify_codesign(binary: pathlib.Path) -> None:
    proc = subprocess.run(["codesign", "--verify", "--strict", str(binary)], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise PreflightError("codesign_verify_failed", f"codesign --verify --strict failed: {proc.stderr.strip()}")


def render_formula_from_template(
    template_path: pathlib.Path,
    *,
    stage_version: str,
    archive_path: pathlib.Path,
    archive_sha256: str,
    source_sha: str,
) -> str:
    tmpl = template_path.read_text(encoding="utf-8")
    abs_archive = archive_path.resolve()
    archive_url = "file://" + urllib.parse.quote(str(abs_archive), safe="/")
    rendered = (
        tmpl.replace("@@STAGE_VERSION@@", stage_version)
        .replace("@@ARCHIVE_URL@@", archive_url)
        .replace("@@ARCHIVE_SHA256@@", archive_sha256)
        .replace("@@SOURCE_SHA@@", source_sha)
    )
    if "@@" in rendered:
        raise PreflightError("formula_checksum_mismatch", "unsubstituted placeholder remaining in generated formula")
    return rendered


def verify_formula_integrity(
    formula_text: str,
    *,
    expected_archive_path: pathlib.Path,
    expected_stage_version: str,
) -> None:
    """Verify generated formula URL, version, and SHA-256 against the verified archive bytes before Brew loads Ruby."""
    url_m = FORMULA_URL_RE.search(formula_text)
    sha_m = FORMULA_SHA_RE.search(formula_text)
    ver_m = FORMULA_VER_RE.search(formula_text)
    if not url_m or not sha_m or not ver_m:
        raise PreflightError("formula_checksum_mismatch", "formula missing required url, version, or sha256 fields")

    formula_url = url_m.group(1)
    formula_sha = sha_m.group(1)
    formula_ver = ver_m.group(1)

    if formula_ver != expected_stage_version:
        raise PreflightError(
            "formula_checksum_mismatch",
            f"formula version={formula_ver!r} != expected stage version {expected_stage_version!r}",
        )

    parsed = urllib.parse.urlparse(formula_url)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        raise PreflightError("formula_checksum_mismatch", f"formula URL must be local file:// URL, got {formula_url!r}")
    url_path = pathlib.Path(urllib.parse.unquote(parsed.path)).resolve()
    expected_resolved = expected_archive_path.resolve()
    if url_path != expected_resolved:
        raise PreflightError(
            "formula_checksum_mismatch",
            f"formula URL path {url_path} != verified archive path {expected_resolved}",
        )

    actual_archive_sha = sha256_file(expected_resolved)
    if formula_sha != actual_archive_sha:
        raise PreflightError(
            "formula_checksum_mismatch",
            f"formula sha256={formula_sha} disagrees with verified archive sha256={actual_archive_sha}",
        )


def cmd_preflight(args: argparse.Namespace) -> int:
    check_clt_prereqs()
    scratch_dir = validate_private_scratch_dir(args.scratch_dir)
    if not HEX40_RE.match(args.expected_source_sha):
        raise PreflightError("artifact_origin_mismatch", f"invalid expected_source_sha: {args.expected_source_sha!r}")

    run_meta, art_meta = load_run_and_artifact_metadata(args)
    verify_origin_binding(
        run_meta,
        art_meta,
        expected_repo=args.expected_repo,
        expected_repo_id=args.expected_repo_id,
        expected_workflow_id=args.expected_workflow_id,
        expected_workflow_path=args.expected_workflow_path,
        expected_run_id=args.expected_run_id,
        expected_run_attempt=args.expected_run_attempt,
        expected_artifact_id=args.expected_artifact_id,
        expected_source_sha=args.expected_source_sha,
    )
    outer_sha = verify_outer_artifact_digest(args.artifact_zip, art_meta)

    unpacked_dir = scratch_dir / "unpacked"
    unpacked_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(unpacked_dir, 0o700)
    manifest_path, archive_path = safe_extract_outer_zip(args.artifact_zip, unpacked_dir)

    inspect_dir = scratch_dir / "inspect"
    extracted = safe_extract_inner_tarball(archive_path, inspect_dir)
    manifest, inner_sha = verify_manifest_and_digests(
        manifest_path,
        archive_path,
        extracted,
        expected_source_sha=args.expected_source_sha,
        expected_repo=args.expected_repo,
        expected_repo_id=args.expected_repo_id,
        expected_workflow_id=args.expected_workflow_id,
        expected_workflow_path=args.expected_workflow_path,
        expected_run_id=args.expected_run_id,
        expected_run_attempt=args.expected_run_attempt,
    )

    binary = extracted["bin/xmsg"]
    verify_macho_arm64(binary)
    embedded_rev = verify_embedded_revision(binary, args.expected_source_sha)
    verify_codesign(binary)

    stage_version = manifest["stage_version"]
    formula_text = render_formula_from_template(
        args.formula_template,
        stage_version=stage_version,
        archive_path=archive_path,
        archive_sha256=inner_sha,
        source_sha=embedded_rev,
    )
    verify_formula_integrity(
        formula_text,
        expected_archive_path=archive_path,
        expected_stage_version=stage_version,
    )

    formula_out = scratch_dir / "xmsg.rb"
    formula_out.write_text(formula_text, encoding="utf-8")
    os.chmod(formula_out, 0o600)

    receipt = {
        "schema_version": 1,
        "status": "verified",
        "repository": args.expected_repo,
        "repository_id": args.expected_repo_id,
        "workflow_id": args.expected_workflow_id,
        "workflow_path": args.expected_workflow_path,
        "run_id": args.expected_run_id,
        "run_attempt": args.expected_run_attempt,
        "artifact_id": args.expected_artifact_id,
        "outer_artifact_digest": f"sha256:{outer_sha}",
        "stage_version": stage_version,
        "source_sha": embedded_rev,
        "archive_path": str(archive_path.resolve()),
        "archive_sha256": inner_sha,
        "manifest_path": str(manifest_path.resolve()),
        "formula_path": str(formula_out.resolve()),
        "formula_sha256": sha256_file(formula_out),
    }
    receipt_path = scratch_dir / "verified-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(receipt_path, 0o600)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def cmd_verify_formula(args: argparse.Namespace) -> int:
    formula_text = args.formula.read_text(encoding="utf-8")
    verify_formula_integrity(
        formula_text,
        expected_archive_path=args.archive,
        expected_stage_version=args.expected_stage_version,
    )
    print(json.dumps({"status": "formula_verified", "formula": str(args.formula.resolve())}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone pre-execution preflight verifier for xmsg macOS staging.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_pre = sub.add_parser("preflight", help="Verify origin, digests, Mach-O, revision, codesign, and generate formula.")
    p_pre.add_argument("--artifact-zip", type=pathlib.Path, required=True)
    p_pre.add_argument("--scratch-dir", type=pathlib.Path, required=True)
    p_pre.add_argument("--formula-template", type=pathlib.Path, required=True)
    p_pre.add_argument("--expected-repo", default="sini/xmsg")
    p_pre.add_argument("--expected-repo-id", type=int, required=True)
    p_pre.add_argument("--expected-workflow-id", type=int, required=True)
    p_pre.add_argument("--expected-workflow-path", default=".github/workflows/macos-staging.yml")
    p_pre.add_argument("--expected-run-id", type=int, required=True)
    p_pre.add_argument("--expected-run-attempt", type=int, default=1)
    p_pre.add_argument("--expected-artifact-id", type=int, required=True)
    p_pre.add_argument("--expected-source-sha", required=True)
    p_pre.add_argument("--run-metadata-file", type=pathlib.Path, default=None)
    p_pre.add_argument("--artifact-metadata-file", type=pathlib.Path, default=None)
    p_pre.add_argument("--live-github-api", action="store_true")
    p_pre.add_argument("--github-api-base", default="https://api.github.com")
    p_pre.set_defaults(func=cmd_preflight)

    p_form = sub.add_parser("verify-formula", help="Verify formula checksum and source URL against verified archive.")
    p_form.add_argument("--formula", type=pathlib.Path, required=True)
    p_form.add_argument("--archive", type=pathlib.Path, required=True)
    p_form.add_argument("--expected-stage-version", required=True)
    p_form.set_defaults(func=cmd_verify_formula)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PreflightError as err:
        print(f"XMSG_STAGING_ERROR: {err.code}: {err.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
