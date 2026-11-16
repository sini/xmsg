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


if __name__ == "__main__":
    unittest.main()
