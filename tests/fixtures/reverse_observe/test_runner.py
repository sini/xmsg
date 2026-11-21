"""No-build controls for destructive artifact setup mistakes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_compat


class OutputGuardTests(unittest.TestCase):
    def test_seed_cannot_contain_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = root / "seed"
            seed.mkdir()
            for output in (seed, seed / "nested" / "output"):
                with self.subTest(output=output), \
                        patch("sys.argv", ["run_compat.py", "--source", str(root / "candidate"),
                              "--old-source", str(root / "old"), "--output", str(output),
                              "--artifact-seed", str(seed)]), \
                        patch.object(run_compat, "verify_old") as verify, \
                        patch.object(run_compat, "build") as build:
                    with self.assertRaisesRegex(AssertionError, "output must be outside artifact seed"):
                        run_compat.main()
                    verify.assert_not_called()
                    build.assert_not_called()
            self.assertEqual(list(seed.iterdir()), [])

    def test_divergent_lock_skips_old_seed_and_passes_old_vendor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, old, seed, vendor = (
                root / "candidate",
                root / "old",
                root / "seed",
                root / "old-vendor",
            )
            for path in (candidate, old, seed, vendor):
                path.mkdir()
            (candidate / "Cargo.lock").write_text('version = 4\n# candidate\n')
            (old / "Cargo.lock").write_text('version = 4\n# old\n')
            output = root / "out"
            with patch(
                "sys.argv",
                [
                    "run_compat.py",
                    "--source",
                    str(candidate),
                    "--old-source",
                    str(old),
                    "--old-vendor",
                    str(vendor),
                    "--output",
                    str(output),
                    "--artifact-seed",
                    str(seed),
                    "--old-build-only",
                ],
            ), patch.object(run_compat, "verify_old", return_value={"revision": "old"}), patch.object(
                run_compat, "isolation_controls"
            ), patch.object(
                run_compat, "build"
            ) as build:
                run_compat.main()
            build.assert_called_once_with(
                old.resolve(),
                output.resolve(),
                "old",
                None,
                False,
                vendor_dir=vendor.resolve(),
            )

    def test_matching_lock_reuses_old_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, old, seed, vendor = (
                root / "candidate",
                root / "old",
                root / "seed",
                root / "old-vendor",
            )
            for path in (candidate, old, seed, vendor):
                path.mkdir()
            lock = 'version = 4\n# identical\n'
            (candidate / "Cargo.lock").write_text(lock)
            (old / "Cargo.lock").write_text(lock)
            output = root / "out"
            with patch(
                "sys.argv",
                [
                    "run_compat.py",
                    "--source",
                    str(candidate),
                    "--old-source",
                    str(old),
                    "--old-vendor",
                    str(vendor),
                    "--output",
                    str(output),
                    "--artifact-seed",
                    str(seed),
                    "--old-build-only",
                ],
            ), patch.object(run_compat, "verify_old", return_value={"revision": "old"}), patch.object(
                run_compat, "isolation_controls"
            ), patch.object(
                run_compat, "build"
            ) as build:
                run_compat.main()
            build.assert_called_once_with(
                old.resolve(),
                output.resolve(),
                "old",
                seed.resolve(),
                False,
                vendor_dir=vendor.resolve(),
            )

    def test_configure_vendor_cargo_home_crane_and_plain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crane_vendor = root / "crane-vendor"
            crane_vendor.mkdir()
            crane_cfg = '[source.crates-io]\nreplace-with = "nix-sources-abc"\n'
            (crane_vendor / "config.toml").write_text(crane_cfg)
            crane_home = run_compat.configure_vendor_cargo_home(root, "old-crane", crane_vendor)
            self.assertEqual((crane_home / "config.toml").read_text(), crane_cfg)

            plain_vendor = root / "plain-vendor"
            plain_vendor.mkdir()
            plain_home = run_compat.configure_vendor_cargo_home(root, "old-plain", plain_vendor)
            plain_cfg = (plain_home / "config.toml").read_text()
            self.assertIn('replace-with = "vendored-sources"', plain_cfg)
            self.assertIn(str(plain_vendor), plain_cfg)


if __name__ == "__main__":
    unittest.main()
