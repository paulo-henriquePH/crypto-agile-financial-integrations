"""Run the existing unittest suite without exporting assertion data or traces."""

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
import json
import os
import sys
import unittest


class Result(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.cases = {}

    def startTest(self, test):
        super().startTest(test)
        self.cases[test.id()] = {"status": "incomplete", "subcases": []}

    def mark(self, test, status):
        # A failing setUpClass has no enclosing startTest, but is still a failure.
        self.cases.setdefault(test.id(), {"subcases": []})["status"] = status

    def addSuccess(self, test):
        super().addSuccess(test)
        self.mark(test, "passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.mark(test, "failed")

    def addError(self, test, err):
        super().addError(test, err)
        self.mark(test, "error")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        # unittest uses the subtest display name in test.id(); never log params.
        parent = getattr(test, "test_case", None)
        self.mark(parent if parent is not None else test, "skipped")

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.mark(test, "expected-failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.mark(test, "unexpected-success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        status = "passed" if err is None else "failed"
        self.cases[test.id()]["subcases"].append(status)
        if err is not None:
            self.mark(test, status)


def main():
    target, expected = sys.argv[1:]
    result = Result()
    with open(os.devnull, "w") as quiet, redirect_stdout(quiet), redirect_stderr(quiet):
        suite = unittest.defaultTestLoader.discover("tests/contracts", pattern=target)
        suite.run(result)
    counts = Counter(case["status"] for case in result.cases.values())
    print(json.dumps({
        "expected": int(expected), "testsRun": result.testsRun,
        "skips": len(result.skipped), "outcomes": counts, "cases": result.cases,
    }))
    # Count actual starts and per-method outcomes; skips/expected failures do not qualify.
    return 0 if (result.testsRun == int(expected) == counts["passed"] == len(result.cases)
                 and result.wasSuccessful() and not result.skipped) else 1


if __name__ == "__main__":
    sys.exit(main())
