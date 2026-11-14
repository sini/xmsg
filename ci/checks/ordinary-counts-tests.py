"""Controls for missing targets, ignored tests and incomplete ordinary-suite output."""
from pathlib import Path
import runpy
import unittest

CHECK = runpy.run_path(str(Path(__file__).with_name("ordinary-counts.py")))["check"]
EXPECTED = {"integration_targets": ["tests/example.rs"], "platforms": {
    "linux": {"passed": 2, "failed": 0, "ignored": 1, "summaries": 4}}}
CARGO = {"test": [{"path": "tests/example.rs"}]}
LOG = """     Running unittests src/lib.rs (target/debug/deps/lib)
test result: ok. 0 passed; 0 failed; 0 ignored;
     Running unittests src/main.rs (target/debug/deps/bin)
test result: ok. 0 passed; 0 failed; 0 ignored;
     Running tests/example.rs (target/debug/deps/example)
test result: ok. 2 passed; 0 failed; 1 ignored;
   Doc-tests xmsg
test result: ok. 0 passed; 0 failed; 0 ignored;
"""


class CountTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(CHECK(EXPECTED, "linux", CARGO, LOG)["passed"], 2)

    def test_dropped_target(self):
        with self.assertRaisesRegex(ValueError, "test target inventory mismatch"):
            CHECK(EXPECTED, "linux", {"test": []}, LOG)

    def test_target_not_executed(self):
        with self.assertRaisesRegex(ValueError, "executed target inventory mismatch"):
            CHECK(EXPECTED, "linux", CARGO, LOG.replace("Running tests/example.rs", "Running tests/other.rs"))

    def test_wrong_pass_ignore_and_missing_summary(self):
        for wrong in (LOG.replace("2 passed", "1 passed"), LOG.replace("1 ignored", "0 ignored"),
                      LOG.rsplit("test result:", 1)[0]):
            with self.assertRaisesRegex(ValueError, "result counts mismatch"):
                CHECK(EXPECTED, "linux", CARGO, wrong)


if __name__ == "__main__":
    unittest.main()
