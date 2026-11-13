"""Exercise exact completion, dropped cases and incomplete proof rejection."""
import copy
import runpy
import unittest
from pathlib import Path

MODULE = runpy.run_path(str(Path(__file__).with_name("client-compat-completion.py")))
RUNNER = runpy.run_path(str(Path(__file__).with_name("client-mutants.py")))
NAMES = [case[0] for case in RUNNER["CASES"] if case[-1] in RUNNER["LIVE_TESTS"]]


def manifests():
    return [{"shard": shard, "cases": [dict(name=name, baseline=True, red=True)
             for name in NAMES[shard::2]]} for shard in (0, 1)]


class CompletionTests(unittest.TestCase):
    def test_complete_union(self):
        self.assertEqual([len(row["cases"]) for row in manifests()], [8, 7])
        MODULE["check"](manifests())

    def test_dropped_case(self):
        rows = manifests()
        rows[0]["cases"].pop()
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            MODULE["check"](rows)

    def test_duplicate_or_wrong_shard(self):
        rows = manifests()
        rows[1]["cases"][0] = copy.deepcopy(rows[0]["cases"][0])
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            MODULE["check"](rows)
        with self.assertRaisesRegex(ValueError, "exactly shards"):
            MODULE["check"]([rows[0], rows[0]])

    def test_each_phase_required(self):
        for phase in ("baseline", "red"):
            rows = manifests()
            rows[0]["cases"][0][phase] = False
            with self.assertRaisesRegex(ValueError, "incomplete"):
                MODULE["check"](rows)


if __name__ == "__main__":
    unittest.main()
