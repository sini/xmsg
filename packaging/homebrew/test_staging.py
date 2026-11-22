#!/usr/bin/env python3
"""Native macOS arm64 S5 (Brew version ordering & data preservation),
S9 (origin, outer/inner/asset digests, Mach-O arm64, embedded revision,
codesign, formula integrity, fork refusal), and S9d (effective umask) gate suite.

Uses Apple CLT `/usr/bin/python3` (stdlib only), `otool`, `codesign`, `plutil`,
`sqlite3`, and real Homebrew in a disposable local tap. Runs completely offline
with fixture metadata (no live GitHub API calls).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import plistlib
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
TEMPLATE_PATH = SCRIPT_DIR / "xmsg.rb.tmpl"
PACKAGE_SCRIPT = SCRIPT_DIR / "package_staging.py"
VERIFY_SCRIPT = SCRIPT_DIR / "verify_staging.py"
PREPARE_SCRIPT = SCRIPT_DIR / "prepare_staging.py"

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import package_staging  # noqa: E402
import verify_staging  # noqa: E402

REPO_NAME = "sini/xmsg"
REPO_ID = 987654321
FORK_REPO_ID = 111222333
WORKFLOW_ID = 424242
WORKFLOW_PATH = ".github/workflows/macos-staging.yml"


def make_private_dir(path: pathlib.Path) -> pathlib.Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def brew_env() -> dict[str, str]:
    env = os.environ.copy()
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    env["HOMEBREW_NO_INSTALL_CLEANUP"] = "1"
    env["HOMEBREW_NO_ENV_HINTS"] = "1"
    env["HOMEBREW_NO_ANALYTICS"] = "1"
    env["HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK"] = "1"
    return env


def run_cmd(cmd: list[str], *, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    if check and proc.returncode != 0:
        raise AssertionError(
            f"command failed (rc={proc.returncode}): {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def make_metadata_fixtures(
    out_dir: pathlib.Path,
    *,
    outer_zip: pathlib.Path,
    source_sha: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    repo_name: str = REPO_NAME,
    repo_id: int = REPO_ID,
    head_repo_id: int = REPO_ID,
    workflow_id: int = WORKFLOW_ID,
    workflow_path: str = WORKFLOW_PATH,
    status: str = "completed",
    conclusion: str = "success",
    expired: bool = False,
    digest_override: str | None = None,
) -> tuple[pathlib.Path, pathlib.Path]:
    actual_digest = digest_override or f"sha256:{verify_staging.sha256_file(outer_zip)}"
    run_meta = {
        "id": run_id,
        "run_attempt": run_attempt,
        "workflow_id": workflow_id,
        "path": workflow_path,
        "status": status,
        "conclusion": conclusion,
        "head_sha": source_sha,
        "repository": {"id": repo_id, "full_name": repo_name},
        "head_repository": {"id": head_repo_id, "full_name": repo_name if head_repo_id == repo_id else "fork-user/xmsg"},
    }
    art_meta = {
        "id": artifact_id,
        "name": "xmsg-macos-arm64-staging",
        "expired": expired,
        "digest": actual_digest,
        "workflow_run": {
            "id": run_id,
            "repository_id": repo_id,
            "head_repository_id": head_repo_id,
            "head_sha": source_sha,
        },
    }
    run_file = out_dir / "run_meta.json"
    art_file = out_dir / "art_meta.json"
    run_file.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
    art_file.write_text(json.dumps(art_meta, indent=2), encoding="utf-8")
    return run_file, art_file


def build_staged_zip(
    work_dir: pathlib.Path,
    *,
    binary: pathlib.Path,
    skill: pathlib.Path,
    source_sha: str,
    run_number: int,
    run_id: int,
    head_repo_id: int = REPO_ID,
) -> tuple[pathlib.Path, dict]:
    out_dir = make_private_dir(work_dir / f"pkg-r{run_number}")
    outer_zip = work_dir / f"artifact-r{run_number}.zip"
    proc = run_cmd(
        [
            sys.executable,
            str(PACKAGE_SCRIPT),
            "--repo-root",
            str(REPO_ROOT),
            "--binary",
            str(binary),
            "--skill-asset",
            str(skill),
            "--output-dir",
            str(out_dir),
            "--expected-sha",
            source_sha,
            "--workflow-head-sha",
            source_sha,
            "--run-number",
            str(run_number),
            "--repository",
            REPO_NAME,
            "--repository-id",
            str(REPO_ID),
            "--head-repository-id",
            str(head_repo_id),
            "--workflow-id",
            str(WORKFLOW_ID),
            "--workflow-path",
            WORKFLOW_PATH,
            "--run-id",
            str(run_id),
            "--run-attempt",
            "1",
            "--outer-zip",
            str(outer_zip),
            "--skip-git-head-check",
        ]
    )
    return outer_zip, json.loads(proc.stdout)


def make_wrong_revision_binary(src_binary: pathlib.Path, dst_binary: pathlib.Path, old_sha: str, new_sha: str) -> None:
    """Create a valid ad-hoc signed arm64 Mach-O binary carrying a different embedded revision."""
    data = src_binary.read_bytes()
    old_marker = b"XMSG-REV-V1:" + old_sha.encode("ascii")
    new_marker = b"XMSG-REV-V1:" + new_sha.encode("ascii")
    assert len(old_marker) == len(new_marker), "revision length mismatch"
    count = data.count(old_marker)
    assert count >= 1, f"expected embedded revision marker {old_marker!r} in {src_binary}"
    dst_binary.write_bytes(data.replace(old_marker, new_marker))
    os.chmod(dst_binary, 0o755)
    # Re-sign ad-hoc so codesign --verify --strict PASSES and ONLY embedded_revision_mismatch catches it!
    run_cmd(["codesign", "--force", "--sign", "-", str(dst_binary)])
    assert package_staging.read_embedded_revision(dst_binary) == new_sha
    package_staging.verify_codesign(dst_binary)


def make_brew_sentinel(sentinel_dir: pathlib.Path) -> tuple[pathlib.Path, dict[str, str]]:
    make_private_dir(sentinel_dir)
    marker = sentinel_dir / "brew-was-invoked"
    brew_shim = sentinel_dir / "brew"
    brew_shim.write_text(f"#!/bin/sh\necho invoked > '{marker}'\nexit 99\n", encoding="utf-8")
    os.chmod(brew_shim, 0o755)
    env = os.environ.copy()
    env["PATH"] = f"{sentinel_dir}:{env.get('PATH', '')}"
    return marker, env


def run_s9_negative_controls(
    tmp: pathlib.Path,
    *,
    binary: pathlib.Path,
    skill: pathlib.Path,
    source_sha: str,
) -> None:
    print("== S9 negative controls (wrong-origin/fork, wrong-revision, tampered-formula, unsafe-archive) ==")
    sentinel_marker, sentinel_env = make_brew_sentinel(tmp / "sentinel-bin")

    # 1. Internally consistent wrong-origin & fork-PR fixtures (Q6 / M-S9c):
    #    Independently reported outer digest MATCHES downloaded bytes; ONLY origin binding fails!
    valid_zip, pkg_info = build_staged_zip(
        tmp / "neg-origin-src",
        binary=binary,
        skill=skill,
        source_sha=source_sha,
        run_number=700,
        run_id=70001,
    )
    wrong_origin_cases = [
        ("fork_pr_head_repo", {"head_repo_id": FORK_REPO_ID}),
        ("wrong_workflow_path", {"workflow_path": ".github/workflows/evil.yml"}),
        ("wrong_run_id", {"run_id": 79999}),
        ("expired_artifact", {"expired": True}),
        ("failed_conclusion", {"conclusion": "failure"}),
    ]
    for label, overrides in wrong_origin_cases:
        case_dir = make_private_dir(tmp / f"neg-origin-{label}")
        scratch = make_private_dir(case_dir / "scratch")
        run_file, art_file = make_metadata_fixtures(
            case_dir,
            outer_zip=valid_zip,
            source_sha=source_sha,
            run_id=overrides.get("run_id", 70001),
            run_attempt=1,
            artifact_id=80001,
            head_repo_id=overrides.get("head_repo_id", REPO_ID),
            workflow_path=overrides.get("workflow_path", WORKFLOW_PATH),
            conclusion=overrides.get("conclusion", "success"),
            expired=overrides.get("expired", False),
        )
        proc = run_cmd(
            [
                sys.executable,
                str(VERIFY_SCRIPT),
                "preflight",
                "--artifact-zip",
                str(valid_zip),
                "--scratch-dir",
                str(scratch),
                "--formula-template",
                str(TEMPLATE_PATH),
                "--expected-repo",
                REPO_NAME,
                "--expected-repo-id",
                str(REPO_ID),
                "--expected-workflow-id",
                str(WORKFLOW_ID),
                "--expected-workflow-path",
                WORKFLOW_PATH,
                "--expected-run-id",
                "70001",
                "--expected-run-attempt",
                "1",
                "--expected-artifact-id",
                "80001",
                "--expected-source-sha",
                source_sha,
                "--run-metadata-file",
                str(run_file),
                "--artifact-metadata-file",
                str(art_file),
            ],
            env=sentinel_env,
            check=False,
        )
        assert proc.returncode != 0, f"M-S9c ({label}): wrong-origin fixture unexpectedly passed!"
        assert "artifact_origin_mismatch" in proc.stderr, (
            f"M-S9c ({label}): expected artifact_origin_mismatch diagnostic, got: {proc.stderr}"
        )
        assert not (scratch / "xmsg.rb").exists(), f"M-S9c ({label}): formula must not be generated on origin refusal"
        assert not sentinel_marker.exists(), f"M-S9c ({label}): brew must never be invoked on preflight refusal"
    print("  [ok] wrong-origin & fork-PR fixtures refused with artifact_origin_mismatch (zero Brew calls)")

    # 2. Valid-checksum wrong-embedded-revision fixture (C5 / M-S9b):
    #    Approved origin, matching outer/inner/asset checksums, valid ad-hoc codesign, manifest lies
    #    with expected source_sha, ONLY Mach-O __DATA,__xmsg_rev carries a different SHA!
    wrong_rev_dir = make_private_dir(tmp / "neg-wrong-rev")
    other_sha = "deadbeef" * 5
    if other_sha == source_sha:
        other_sha = "cafebabe" * 5
    wrong_bin = wrong_rev_dir / "xmsg-wrong-rev"
    make_wrong_revision_binary(binary, wrong_bin, source_sha, other_sha)

    tar_path = wrong_rev_dir / "xmsg-0.1.0.701-arm64-macos.tar.gz"
    asset_hashes = package_staging.write_deterministic_tarball(tar_path, wrong_bin, skill)
    tar_sha = package_staging.sha256_file(tar_path)
    lying_manifest = {
        "schema_version": 1,
        "stage_version": "0.1.0.701",
        "cargo_version": "0.1.0",
        "workflow_run_number": 701,
        "checkout_sha": source_sha,
        "workflow_head_sha": source_sha,
        "build_revision": source_sha,  # lies to match labels!
        "target": "aarch64-apple-darwin",
        "toolchain": "rustc fixture",
        "archive_name": tar_path.name,
        "archive_sha256": tar_sha,
        "assets": asset_hashes,
        "workflow": {
            "repository": REPO_NAME,
            "repository_id": REPO_ID,
            "head_repository_id": REPO_ID,
            "workflow_id": WORKFLOW_ID,
            "workflow_path": WORKFLOW_PATH,
            "run_id": 70002,
            "run_attempt": 1,
            "artifact_name": "xmsg-macos-arm64-staging",
        },
    }
    lying_manifest_path = wrong_rev_dir / "manifest.json"
    lying_manifest_path.write_text(json.dumps(lying_manifest, indent=2), encoding="utf-8")
    wrong_rev_zip = wrong_rev_dir / "wrong-rev.zip"
    package_staging.pack_outer_zip(wrong_rev_zip, tar_path, lying_manifest_path)

    run_file2, art_file2 = make_metadata_fixtures(
        wrong_rev_dir,
        outer_zip=wrong_rev_zip,
        source_sha=source_sha,
        run_id=70002,
        run_attempt=1,
        artifact_id=80002,
    )
    scratch2 = make_private_dir(wrong_rev_dir / "scratch")
    proc_rev = run_cmd(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            "preflight",
            "--artifact-zip",
            str(wrong_rev_zip),
            "--scratch-dir",
            str(scratch2),
            "--formula-template",
            str(TEMPLATE_PATH),
            "--expected-repo",
            REPO_NAME,
            "--expected-repo-id",
            str(REPO_ID),
            "--expected-workflow-id",
            str(WORKFLOW_ID),
            "--expected-workflow-path",
            WORKFLOW_PATH,
            "--expected-run-id",
            "70002",
            "--expected-run-attempt",
            "1",
            "--expected-artifact-id",
            "80002",
            "--expected-source-sha",
            source_sha,
            "--run-metadata-file",
            str(run_file2),
            "--artifact-metadata-file",
            str(art_file2),
        ],
        env=sentinel_env,
        check=False,
    )
    assert proc_rev.returncode != 0, "M-S9b: wrong embedded revision unexpectedly passed preflight!"
    assert "embedded_revision_mismatch" in proc_rev.stderr, (
        f"M-S9b: expected embedded_revision_mismatch diagnostic, got: {proc_rev.stderr}"
    )
    assert not (scratch2 / "xmsg.rb").exists(), "M-S9b: formula must not be generated on revision mismatch"
    assert not sentinel_marker.exists(), "M-S9b: brew must never be invoked on revision mismatch"
    print("  [ok] valid-checksum wrong-revision binary refused with embedded_revision_mismatch")

    # 3. Tampered formula checksum fixture (C9 / M-S9):
    #    Valid archive, formula sha256 altered by 1 hex nibble -> verifier MUST refuse BEFORE Brew!
    tamper_dir = make_private_dir(tmp / "neg-tamper-formula")
    verified_archive = pathlib.Path(pkg_info["archive_path"])
    good_formula = verify_staging.render_formula_from_template(
        TEMPLATE_PATH,
        stage_version=pkg_info["stage_version"],
        archive_path=verified_archive,
        archive_sha256=pkg_info["archive_sha256"],
        source_sha=source_sha,
    )
    bad_sha = ("0" if pkg_info["archive_sha256"][0] != "0" else "1") + pkg_info["archive_sha256"][1:]
    tampered_formula = good_formula.replace(pkg_info["archive_sha256"], bad_sha)
    tampered_formula_path = tamper_dir / "xmsg.rb"
    tampered_formula_path.write_text(tampered_formula, encoding="utf-8")

    proc_form = run_cmd(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            "verify-formula",
            "--formula",
            str(tampered_formula_path),
            "--archive",
            str(verified_archive),
            "--expected-stage-version",
            pkg_info["stage_version"],
        ],
        env=sentinel_env,
        check=False,
    )
    assert proc_form.returncode != 0, "M-S9: tampered formula checksum unexpectedly passed verify-formula!"
    assert "formula_checksum_mismatch" in proc_form.stderr, (
        f"M-S9: expected formula_checksum_mismatch diagnostic, got: {proc_form.stderr}"
    )
    assert not sentinel_marker.exists(), "M-S9: brew must never be invoked on formula checksum mismatch"
    print("  [ok] tampered formula checksum refused with formula_checksum_mismatch before Brew")

    # 4. Archive path traversal & symlink rejection BEFORE extraction:
    bad_arch_dir = make_private_dir(tmp / "neg-bad-archive")
    traversal_zip = bad_arch_dir / "traversal.zip"
    with zipfile.ZipFile(traversal_zip, "w") as zf:
        zf.writestr("../escape.txt", b"boom")
    run_file3, art_file3 = make_metadata_fixtures(
        bad_arch_dir,
        outer_zip=traversal_zip,
        source_sha=source_sha,
        run_id=70003,
        run_attempt=1,
        artifact_id=80003,
    )
    scratch3 = make_private_dir(bad_arch_dir / "scratch")
    proc_trav = run_cmd(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            "preflight",
            "--artifact-zip",
            str(traversal_zip),
            "--scratch-dir",
            str(scratch3),
            "--formula-template",
            str(TEMPLATE_PATH),
            "--expected-repo",
            REPO_NAME,
            "--expected-repo-id",
            str(REPO_ID),
            "--expected-workflow-id",
            str(WORKFLOW_ID),
            "--expected-workflow-path",
            WORKFLOW_PATH,
            "--expected-run-id",
            "70003",
            "--expected-run-attempt",
            "1",
            "--expected-artifact-id",
            "80003",
            "--expected-source-sha",
            source_sha,
            "--run-metadata-file",
            str(run_file3),
            "--artifact-metadata-file",
            str(art_file3),
        ],
        env=sentinel_env,
        check=False,
    )
    assert proc_trav.returncode != 0 and "archive_entry_rejected" in proc_trav.stderr, (
        f"traversal zip must fail with archive_entry_rejected, got: {proc_trav.stderr}"
    )
    assert not (bad_arch_dir / "escape.txt").exists(), "traversal zip wrote outside scratch!"

    # Inner tarball containing symlink entry must also be rejected before extraction.
    symlink_tar = bad_arch_dir / "xmsg-0.1.0.704-arm64-macos.tar.gz"
    with symlink_tar.open("wb") as raw_fh:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
                ti = tarfile.TarInfo("bin/xmsg")
                ti.type = tarfile.SYMTYPE
                ti.linkname = "/bin/sh"
                tf.addfile(ti)
    sym_manifest = bad_arch_dir / "manifest.json"
    sym_manifest.write_text("{}", encoding="utf-8")
    sym_zip = bad_arch_dir / "symlink.zip"
    package_staging.pack_outer_zip(sym_zip, symlink_tar, sym_manifest)
    run_file4, art_file4 = make_metadata_fixtures(
        bad_arch_dir,
        outer_zip=sym_zip,
        source_sha=source_sha,
        run_id=70004,
        run_attempt=1,
        artifact_id=80004,
    )
    scratch4 = make_private_dir(bad_arch_dir / "scratch-sym")
    proc_sym = run_cmd(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            "preflight",
            "--artifact-zip",
            str(sym_zip),
            "--scratch-dir",
            str(scratch4),
            "--formula-template",
            str(TEMPLATE_PATH),
            "--expected-repo",
            REPO_NAME,
            "--expected-repo-id",
            str(REPO_ID),
            "--expected-workflow-id",
            str(WORKFLOW_ID),
            "--expected-workflow-path",
            WORKFLOW_PATH,
            "--expected-run-id",
            "70004",
            "--expected-run-attempt",
            "1",
            "--expected-artifact-id",
            "80004",
            "--expected-source-sha",
            source_sha,
            "--run-metadata-file",
            str(run_file4),
            "--artifact-metadata-file",
            str(art_file4),
        ],
        env=sentinel_env,
        check=False,
    )
    assert proc_sym.returncode != 0 and "archive_entry_rejected" in proc_sym.stderr, (
        f"symlink tarball must fail with archive_entry_rejected, got: {proc_sym.stderr}"
    )
    print("  [ok] traversal zip & symlink tarball refused with archive_entry_rejected before extraction")


def run_s9d_umask_check(tmp: pathlib.Path, installed_bin: pathlib.Path) -> None:
    print("== S9d native installed-binary effective_umask=077 check under inherited 0022 ==")
    state_dir = make_private_dir(tmp / "s9d-state")
    run_dir = make_private_dir(tmp / "s9d-run")
    fake_home = make_private_dir(tmp / "s9d-home")
    db_path = state_dir / "xmsg.db"
    http_sock = run_dir / "http.sock"
    agent_sock = run_dir / "agent.sock"
    reg_sock = run_dir / "register.sock"

    env = os.environ.copy()
    for k in list(env.keys()):
        if k.startswith("XMSG_") or k.startswith("ANTIGRAVITY_"):
            env.pop(k, None)
    env["HOME"] = str(fake_home)
    env["XDG_RUNTIME_DIR"] = str(run_dir)
    env["NO_COLOR"] = "1"
    env["RUST_LOG"] = "xmsg=info"

    proc = subprocess.Popen(
        [
            str(installed_bin),
            "serve",
            "--db-path",
            str(db_path),
            "--http-sock",
            str(http_sock),
            "--agent-sock",
            str(agent_sock),
            "--register-sock",
            str(reg_sock),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        preexec_fn=lambda: os.umask(0o022),
    )
    try:
        deadline = time.monotonic() + 10.0
        connected = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(str(http_sock))
                s.close()
                connected = True
                break
            except OSError:
                time.sleep(0.05)
        assert connected, f"S9d: installed binary did not bind {http_sock}"
    finally:
        proc.kill()
        out_bytes, err_bytes = proc.communicate(timeout=5)

    log_text = out_bytes.decode("utf-8", errors="replace")
    assert "starting xmsg server" in log_text and (
        'effective_umask="077"' in log_text or "effective_umask=077" in log_text
    ), f"M-S9d: installed binary startup log missing effective_umask=077:\nSTDOUT:\n{log_text}\nSTDERR:\n{err_bytes.decode(errors='replace')}"

    for path in (db_path, state_dir / "serve.lock"):
        mode = stat.S_IMODE(os.lstat(path).st_mode)
        assert (mode & 0o077) == 0, f"M-S9d: {path} created with permissive mode {oct(mode)} under inherited umask 0022"
    print("  [ok] installed opt binary logged effective_umask=077 and kept umask-only files private")


def run_s5_and_s9_real_homebrew(
    tmp: pathlib.Path,
    *,
    binary: pathlib.Path,
    skill: pathlib.Path,
    source_sha: str,
) -> None:
    print("== S9 positive + S5 real Homebrew disposable tap install, upgrade, data preservation, cached rollback ==")
    benv = brew_env()

    # Guard against colliding with a pre-installed Homebrew `xmsg` formula on a developer machine.
    existing = run_cmd(["brew", "list", "--formula", "xmsg"], env=benv, check=False)
    if existing.returncode == 0:
        raise RuntimeError("refusing to touch pre-existing Homebrew `xmsg` installation")

    brew_prefix = pathlib.Path(run_cmd(["brew", "--prefix"], env=benv).stdout.strip())
    tap_user = f"xmsgstage{os.getpid()}"
    tap_repo = "local"
    tap_name = f"{tap_user}/{tap_repo}"
    formula_ref = f"{tap_name}/xmsg"

    # Build a local git repository to serve as Homebrew's disposable local tap source.
    local_tap_src = make_private_dir(tmp / "local-tap-src")
    local_formula_dir = local_tap_src / "Formula"
    local_formula_dir.mkdir(parents=True, exist_ok=True)
    run_cmd(["git", "-C", str(local_tap_src), "init", "-b", "main"])
    git_id = ["-c", "user.name=xmsg-staging-ci", "-c", "user.email=xmsg-staging-ci@localhost"]

    def commit_tap_formula(formula_src: pathlib.Path, message: str) -> None:
        shutil.copyfile(formula_src, local_formula_dir / "xmsg.rb")
        run_cmd(["git", "-C", str(local_tap_src), "add", "Formula/xmsg.rb"])
        run_cmd(["git", "-C", str(local_tap_src), *git_id, "commit", "-m", message])

    v1_run_num = 10
    v2_run_num = 11
    v1_zip, v1_pkg = build_staged_zip(
        tmp / "s5-v1-build",
        binary=binary,
        skill=skill,
        source_sha=source_sha,
        run_number=v1_run_num,
        run_id=90001,
    )
    v2_zip, v2_pkg = build_staged_zip(
        tmp / "s5-v2-build",
        binary=binary,
        skill=skill,
        source_sha=source_sha,
        run_number=v2_run_num,
        run_id=90002,
    )
    v1_ver = v1_pkg["stage_version"]
    v2_ver = v2_pkg["stage_version"]

    v1_scratch = make_private_dir(tmp / "s5-v1-scratch")
    v1_run_f, v1_art_f = make_metadata_fixtures(
        tmp / "s5-v1-meta" if make_private_dir(tmp / "s5-v1-meta") else tmp,
        outer_zip=v1_zip,
        source_sha=source_sha,
        run_id=90001,
        run_attempt=1,
        artifact_id=91001,
    )
    run_cmd(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            "preflight",
            "--artifact-zip",
            str(v1_zip),
            "--scratch-dir",
            str(v1_scratch),
            "--formula-template",
            str(TEMPLATE_PATH),
            "--expected-repo",
            REPO_NAME,
            "--expected-repo-id",
            str(REPO_ID),
            "--expected-workflow-id",
            str(WORKFLOW_ID),
            "--expected-workflow-path",
            WORKFLOW_PATH,
            "--expected-run-id",
            "90001",
            "--expected-run-attempt",
            "1",
            "--expected-artifact-id",
            "91001",
            "--expected-source-sha",
            source_sha,
            "--run-metadata-file",
            str(v1_run_f),
            "--artifact-metadata-file",
            str(v1_art_f),
        ]
    )

    v2_scratch = make_private_dir(tmp / "s5-v2-scratch")
    v2_run_f, v2_art_f = make_metadata_fixtures(
        make_private_dir(tmp / "s5-v2-meta"),
        outer_zip=v2_zip,
        source_sha=source_sha,
        run_id=90002,
        run_attempt=1,
        artifact_id=91002,
    )
    run_cmd(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            "preflight",
            "--artifact-zip",
            str(v2_zip),
            "--scratch-dir",
            str(v2_scratch),
            "--formula-template",
            str(TEMPLATE_PATH),
            "--expected-repo",
            REPO_NAME,
            "--expected-repo-id",
            str(REPO_ID),
            "--expected-workflow-id",
            str(WORKFLOW_ID),
            "--expected-workflow-path",
            WORKFLOW_PATH,
            "--expected-run-id",
            "90002",
            "--expected-run-attempt",
            "1",
            "--expected-artifact-id",
            "91002",
            "--expected-source-sha",
            source_sha,
            "--run-metadata-file",
            str(v2_run_f),
            "--artifact-metadata-file",
            str(v2_art_f),
        ]
    )

    try:
        # 1. Tap the disposable local git repo and install v1 via real Homebrew.
        commit_tap_formula(v1_scratch / "xmsg.rb", f"stage {v1_ver}")
        run_cmd(["brew", "tap", tap_name, str(local_tap_src)], env=benv)
        tap_repo_dir = pathlib.Path(run_cmd(["brew", "--repository", tap_name], env=benv).stdout.strip())
        run_cmd(["brew", "install", formula_ref], env=benv)

        ver_v1_out = run_cmd(["brew", "list", "--versions", formula_ref], env=benv).stdout.strip()
        assert v1_ver in ver_v1_out, f"expected Homebrew installed version {v1_ver}, got: {ver_v1_out}"

        opt_bin = brew_prefix / "opt" / "xmsg" / "bin" / "xmsg"
        opt_skill = brew_prefix / "opt" / "xmsg" / "share" / "xmsg" / "claude" / "xmsg" / "SKILL.md"
        assert opt_bin.is_file(), f"installed opt binary missing: {opt_bin}"
        assert opt_skill.is_file(), f"installed version-matched skill missing: {opt_skill}"
        assert verify_staging.sha256_file(opt_skill) == verify_staging.sha256_file(skill), (
            "installed skill asset SHA-256 disagrees with packed asset"
        )
        verify_staging.verify_macho_arm64(opt_bin)
        verify_staging.verify_embedded_revision(opt_bin, source_sha)
        verify_staging.verify_codesign(opt_bin)
        print(f"  [ok] disposable local tap installed {ver_v1_out} and verified opt binary + skill")

        # 2. Run per-user prepare_staging.py against the installed opt binary & isolated state root.
        state_root = make_private_dir(tmp / "durable-state")
        logs_dir = make_private_dir(tmp / "durable-logs")
        plist_out = tmp / "launch-agent" / "homebrew.mxcl.xmsg.plist"
        db_path = state_root / "xmsg.db"
        prep_v1 = json.loads(
            run_cmd(
                [
                    sys.executable,
                    str(PREPARE_SCRIPT),
                    "prepare",
                    "--xmsg-bin",
                    str(opt_bin),
                    "--verified-dir",
                    str(v1_scratch),
                    "--formula-template",
                    str(TEMPLATE_PATH),
                    "--state-root",
                    str(state_root),
                    "--db-path",
                    str(db_path),
                    "--logs-dir",
                    str(logs_dir),
                    "--plist-out",
                    str(plist_out),
                ]
            ).stdout
        )
        assert prep_v1["status"] == "prepared"
        assert prep_v1["umask"] == 63
        assert stat.S_IMODE(os.lstat(logs_dir / "stdout.log").st_mode) == 0o600
        assert stat.S_IMODE(os.lstat(logs_dir / "stderr.log").st_mode) == 0o600
        plist_data = plistlib.loads(plist_out.read_bytes())
        assert plist_data["Label"] == "homebrew.mxcl.xmsg"
        assert plist_data["Umask"] == 63
        assert plist_data["ProgramArguments"][0] == str(opt_bin.resolve())
        print("  [ok] prepare_staging.py verified resolver, staged durable cache, 0600 logs, and valid LaunchAgent plist")

        # 3. Seed durable witness DB in state_root and exercise S9d on the installed opt binary.
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE witness (id INTEGER PRIMARY KEY, val TEXT NOT NULL)")
        conn.execute("INSERT INTO witness (id, val) VALUES (1, 'preserve-across-brew-upgrade')")
        conn.commit()
        conn.close()
        os.chmod(db_path, 0o600)
        db_bytes_before = db_path.read_bytes()

        run_s9d_umask_check(tmp, opt_bin)

        # 4. S5 monotonic ordering enforcement: refuse non-monotonic (equal/lower), allow v2 > v1.
        non_mono = run_cmd(
            [
                sys.executable,
                str(PREPARE_SCRIPT),
                "check-upgrade",
                "--state-root",
                str(state_root),
                "--current-version",
                v1_ver,
                "--candidate-version",
                v1_ver,
            ],
            check=False,
        )
        assert non_mono.returncode != 0 and "non_monotonic_stage_version" in non_mono.stderr, (
            f"equal stage version must be refused, got: {non_mono.stderr}"
        )
        upg_check = json.loads(
            run_cmd(
                [
                    sys.executable,
                    str(PREPARE_SCRIPT),
                    "check-upgrade",
                    "--state-root",
                    str(state_root),
                    "--current-version",
                    v1_ver,
                    "--candidate-version",
                    v2_ver,
                ]
            ).stdout
        )
        assert upg_check["status"] == "upgrade_allowed"
        cached_v1_formula = pathlib.Path(upg_check["rollback_formula"])
        assert cached_v1_formula.is_file()

        # 5. Update disposable tap formula to v2, verify real Homebrew sees v2 > v1, and run `brew upgrade`.
        commit_tap_formula(v2_scratch / "xmsg.rb", f"stage {v2_ver}")
        run_cmd(["git", "-C", str(tap_repo_dir), "pull", "--ff-only"])
        outdated = run_cmd(["brew", "outdated", "--formula", formula_ref], env=benv).stdout
        assert "xmsg" in outdated, f"S5: Homebrew did not order {v2_ver} > {v1_ver}; brew outdated={outdated!r}"
        run_cmd(["brew", "upgrade", formula_ref], env=benv)
        ver_v2_out = run_cmd(["brew", "list", "--versions", formula_ref], env=benv).stdout.strip()
        assert v2_ver in ver_v2_out, f"S5: expected upgraded version {v2_ver}, got: {ver_v2_out}"
        verify_staging.verify_embedded_revision(opt_bin, source_sha)
        assert db_path.read_bytes() == db_bytes_before, "S5: durable DB bytes changed during brew upgrade!"
        print(f"  [ok] real Homebrew ordered {v2_ver} > {v1_ver}, upgraded cleanly, preserved durable DB")

        # 6. Cached rollback test: delete v1 scratch dir so rollback MUST come from durable staging-cache!
        shutil.rmtree(v1_scratch)
        assert not v1_scratch.exists()
        commit_tap_formula(cached_v1_formula, f"rollback {v1_ver}")
        run_cmd(["git", "-C", str(tap_repo_dir), "pull", "--ff-only"])
        run_cmd(["brew", "uninstall", "--force", formula_ref], env=benv)
        run_cmd(["brew", "install", formula_ref], env=benv)
        ver_rb_out = run_cmd(["brew", "list", "--versions", formula_ref], env=benv).stdout.strip()
        assert v1_ver in ver_rb_out, f"S5 rollback: expected {v1_ver}, got: {ver_rb_out}"
        verify_staging.verify_embedded_revision(opt_bin, source_sha)
        assert db_path.read_bytes() == db_bytes_before, "S5 rollback: durable DB bytes changed during rollback!"
        print(f"  [ok] cached rollback restored {ver_rb_out} from durable staging-cache with durable DB intact")
    finally:
        run_cmd(["brew", "uninstall", "--force", formula_ref], env=benv, check=False)
        run_cmd(["brew", "untap", tap_name], env=benv, check=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run native macOS S5, S9, and S9d staging gate tests.")
    parser.add_argument("--binary", type=pathlib.Path, required=True, help="Compiled arm64 release xmsg binary.")
    parser.add_argument("--source-sha", required=True, help="40-hex revision embedded in --binary.")
    parser.add_argument(
        "--skill-asset",
        type=pathlib.Path,
        default=None,
        help="Path to canonical SKILL.md (defaults to assets/claude/xmsg/SKILL.md).",
    )
    parser.add_argument(
        "--skip-brew",
        action="store_true",
        help="Run offline preflight/negative controls only (for fast mutant checks on verify_staging.py).",
    )
    args = parser.parse_args(argv)

    binary = args.binary.resolve()
    skill = (args.skill_asset if args.skill_asset is not None else REPO_ROOT / package_staging.DEFAULT_SKILL_ASSET).resolve()
    if not skill.is_file():
        raise SystemExit(
            f"canonical Claude skill asset missing at {skill} (expected {package_staging.DEFAULT_SKILL_ASSET})"
        )

    with tempfile.TemporaryDirectory(prefix="xmsg-s5-s9-") as td:
        tmp = pathlib.Path(td)
        run_s9_negative_controls(tmp, binary=binary, skill=skill, source_sha=args.source_sha)
        if not args.skip_brew:
            run_s5_and_s9_real_homebrew(tmp, binary=binary, skill=skill, source_sha=args.source_sha)
        else:
            # Offline full positive preflight + prepare + plist + check-upgrade + S9d without mutating Homebrew Taps.
            v1_zip, v1_pkg = build_staged_zip(
                tmp / "offline-v1",
                binary=binary,
                skill=skill,
                source_sha=args.source_sha,
                run_number=10,
                run_id=95001,
            )
            v1_scratch = make_private_dir(tmp / "offline-v1-scratch")
            v1_run_f, v1_art_f = make_metadata_fixtures(
                make_private_dir(tmp / "offline-v1-meta"),
                outer_zip=v1_zip,
                source_sha=args.source_sha,
                run_id=95001,
                run_attempt=1,
                artifact_id=96001,
            )
            run_cmd(
                [
                    sys.executable,
                    str(VERIFY_SCRIPT),
                    "preflight",
                    "--artifact-zip",
                    str(v1_zip),
                    "--scratch-dir",
                    str(v1_scratch),
                    "--formula-template",
                    str(TEMPLATE_PATH),
                    "--expected-repo",
                    REPO_NAME,
                    "--expected-repo-id",
                    str(REPO_ID),
                    "--expected-workflow-id",
                    str(WORKFLOW_ID),
                    "--expected-workflow-path",
                    WORKFLOW_PATH,
                    "--expected-run-id",
                    "95001",
                    "--expected-run-attempt",
                    "1",
                    "--expected-artifact-id",
                    "96001",
                    "--expected-source-sha",
                    args.source_sha,
                    "--run-metadata-file",
                    str(v1_run_f),
                    "--artifact-metadata-file",
                    str(v1_art_f),
                ]
            )
            state_root = make_private_dir(tmp / "offline-state")
            logs_dir = make_private_dir(tmp / "offline-logs")
            plist_out = tmp / "offline-la" / "homebrew.mxcl.xmsg.plist"
            prep = json.loads(
                run_cmd(
                    [
                        sys.executable,
                        str(PREPARE_SCRIPT),
                        "prepare",
                        "--xmsg-bin",
                        str(binary),
                        "--verified-dir",
                        str(v1_scratch),
                        "--formula-template",
                        str(TEMPLATE_PATH),
                        "--state-root",
                        str(state_root),
                        "--db-path",
                        str(state_root / "xmsg.db"),
                        "--logs-dir",
                        str(logs_dir),
                        "--plist-out",
                        str(plist_out),
                    ]
                ).stdout
            )
            assert prep["status"] == "prepared" and prep["umask"] == 63
            assert stat.S_IMODE(os.lstat(logs_dir / "stdout.log").st_mode) == 0o600
            assert stat.S_IMODE(os.lstat(logs_dir / "stderr.log").st_mode) == 0o600
            plist_data = plistlib.loads(plist_out.read_bytes())
            assert plist_data["Label"] == "homebrew.mxcl.xmsg" and plist_data["Umask"] == 63
            v1_ver = v1_pkg["stage_version"]
            v2_ver = f"{v1_ver.rsplit('.', 1)[0]}.11"
            non_mono = run_cmd(
                [
                    sys.executable,
                    str(PREPARE_SCRIPT),
                    "check-upgrade",
                    "--state-root",
                    str(state_root),
                    "--current-version",
                    v1_ver,
                    "--candidate-version",
                    v1_ver,
                ],
                check=False,
            )
            assert non_mono.returncode != 0 and "non_monotonic_stage_version" in non_mono.stderr
            upg = json.loads(
                run_cmd(
                    [
                        sys.executable,
                        str(PREPARE_SCRIPT),
                        "check-upgrade",
                        "--state-root",
                        str(state_root),
                        "--current-version",
                        v1_ver,
                        "--candidate-version",
                        v2_ver,
                    ]
                ).stdout
            )
            assert upg["status"] == "upgrade_allowed"
            print("  [ok] offline preflight, prepare_staging.py, plutil -lint, and check-upgrade passed")
            run_s9d_umask_check(tmp, binary)

    print("ALL S5/S9/S9d STAGING GATES PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
