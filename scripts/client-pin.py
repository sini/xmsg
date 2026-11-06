"""Drive source provenance at the Nix fetch layer, including a warm-store mutant."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
EXPR = '''let
  root = builtins.getEnv "XMSG_PIN_PROBE_ROOT";
  ci = builtins.getFlake ("path:" + root + "/ci");
  pkgs = ci.inputs.nixpkgs.legacyPackages.${builtins.currentSystem};
  pin = builtins.fromTOML (builtins.readFile (root + "/ci/xmsg-pin.toml"));
in import (root + "/ci/xmsg-source.nix") { inherit pkgs pin; }'''


class UnboundRevision(AssertionError):
    pass


def nix(tree, build):
    argv = ["nix", "build", "--no-link", "--print-out-paths"] if build else ["nix", "eval", "--raw"]
    expr = EXPR if build else f"({EXPR}).outPath"
    return subprocess.run([*argv, "--impure", "--expr", expr], env={**os.environ, "XMSG_PIN_PROBE_ROOT": str(tree)}, capture_output=True, text=True, timeout=180)


def probe(tree):
    pin_file = tree / "ci/xmsg-pin.toml"
    original = pin_file.read_text()
    pin = tomllib.loads(original)
    good = nix(tree, True)
    assert good.returncode == 0, ("good source fetch failed", good.stderr[-2000:])
    good_path = good.stdout.strip().splitlines()[-1]
    wrong = next(rev for rev in ("9d1f5fa38356a8f9208594db951c8e6502fe8e5d", "9b5bd5e241554d345bcb394cc5dfffcf4fa0ee9b") if rev != pin["revision"])
    assert original.count(pin["revision"]) == 1
    pin_file.write_text(original.replace(pin["revision"], wrong))
    assert tomllib.loads(pin_file.read_text())["source_hash"] == pin["source_hash"]
    bad_path = nix(tree, False)
    assert bad_path.returncode == 0, bad_path.stderr[-2000:]
    if bad_path.stdout.strip() == good_path:
        raise UnboundRevision("revision changed but fixed-output identity stayed equal")
    bad = nix(tree, True)
    assert bad.returncode != 0 and "hash mismatch" in bad.stderr.lower(), ("wrong revision was not rejected at fetch", bad.stdout, bad.stderr[-2000:])


def copy(destination):
    shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", ".worktrees", "target", ".artifacts", "result*", "__pycache__"))


def main():
    with tempfile.TemporaryDirectory(prefix="xmsg-pin-probe-") as temp:
        root = Path(temp)
        good = root / "control"
        copy(good)
        probe(good)
        print("Nix provenance: original revision GREEN; changed revision with unchanged hash RED at fetch", flush=True)
        mutant = root / "mutant"
        copy(mutant)
        helper = mutant / "ci/xmsg-source.nix"
        source = helper.read_text()
        line = '  name = "xmsg-${pin.revision}-source";\n'
        assert source.count(line) == 1
        helper.write_text(source.replace(line, ""))
        try:
            probe(mutant)
        except UnboundRevision:
            print("Nix source mutant: omitting revision from fetch identity makes the provenance oracle RED", flush=True)
        else:
            raise AssertionError("fetch-identity source mutant survived")


if __name__ == "__main__":
    main()
