"""Offline fail-closed checks; never count these as integrated scenarios."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sprint2_verifier", HERE / "verify.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class FailClosed(unittest.TestCase):
    def test_missing_witness(self):
        with self.assertRaisesRegex(ValueError, "missing/duplicate"):
            runner.witness('{"scenario":"missing","operationId":"1","history":["SETTLED"]}',
                           ("missing", "divergent"))

    def test_wrong_mechanism(self):
        with self.assertRaisesRegex(ValueError, "TLS group mismatch"):
            runner.witness('{"scenario":"x","operationId":"1","history":["SETTLED"],'
                           '"group":"X25519MLKEM768"}', ("x",))

    def test_duplicate_witness(self):
        row = '{"scenario":"x","operationId":"1","history":["SETTLED"]}'
        with self.assertRaisesRegex(ValueError, "missing/duplicate"):
            runner.witness(row + "\n" + row, ("x",))

    def test_missing_operation_is_not_success(self):
        with self.assertRaisesRegex(ValueError, "missing operation/history"):
            runner.witness('{"scenario":"x","history":["SETTLED"]}', ("x",))

    def test_recovery_requires_every_disallowed_subcase(self):
        import json
        modes = ("unsigned", "wrong-correlation", "bad-signature", "schema", "forbidden")
        rows = [dict(scenario="disallowed", operationId=str(n + 1),
                     history=["SENT"], nonRetryableMode=mode)
                for n, mode in enumerate(modes)]
        actual = runner.witness("\n".join(map(json.dumps, rows)), ("disallowed",))
        self.assertEqual(len(actual), 5)
        rows[-1]["nonRetryableMode"] = "unsigned"
        with self.assertRaisesRegex(ValueError, "missing non-retryable negative"):
            runner.witness("\n".join(map(json.dumps, rows)), ("disallowed",))

    def test_legacy_migration_requires_three_distinct_operations(self):
        import json
        rows = [dict(scenario="migration", operationId=str(n),
                     history=["SENT"], migratedBlockedWithoutWire=(n == 2))
                for n in range(3)]
        self.assertEqual(len(runner.witness("\n".join(map(json.dumps, rows)),
                                            ("migration",))), 3)
        rows[1]["operationId"] = rows[0]["operationId"]
        with self.assertRaisesRegex(ValueError, "missing legacy migration branch"):
            runner.witness("\n".join(map(json.dumps, rows)), ("migration",))

    def test_injected_failure_exit_and_report(self):
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "result.json"
            result = subprocess.run([sys.executable, "-B", str(HERE / "verify.py"),
                                     "--inject-failure", "--report", str(report)],
                                    capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('"result": "FAILED"', report.read_text(encoding="utf-8"))
            self.assertIn("injected failure", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
