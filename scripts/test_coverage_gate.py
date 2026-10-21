import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import coverage_gate  # noqa: E402


def run_gate(summary, min_percent):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "summary.json")
        with open(path, "w") as f:
            json.dump(summary, f)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = coverage_gate.main([path, "--min", str(min_percent)])
        return code, out.getvalue(), err.getvalue()


def summary_with(percent):
    return {"data": [{"totals": {"lines": {"percent": percent}}}]}


class CoverageGateTest(unittest.TestCase):
    def test_passes_at_or_above_min(self):
        code, out, _ = run_gate(summary_with(80.0), 80)
        self.assertEqual(code, 0)
        self.assertIn("80", out)

    def test_fails_below_min(self):
        code, _, _ = run_gate(summary_with(79.99), 80)
        self.assertEqual(code, 1)

    def test_rejects_malformed_summary(self):
        code, _, err = run_gate({}, 80)
        self.assertEqual(code, 2)
        self.assertTrue(err.strip())


if __name__ == "__main__":
    unittest.main()
