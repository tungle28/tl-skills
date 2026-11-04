"""Regression tests for harness_metrics.py matching.

Incident: the adjudicator mapped a restatement ("name differs from folder") to the GT item that
another finding ("invalid name") already stated. The override took that GT first and left the
exact finding unmatched, so it came back as unadjudicated on every re-run.

Run:  python -m unittest discover -s <skill>/scripts/tests -v
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import harness_metrics  # noqa: E402

GT = [{"id": "GT-01", "file": "SKILL.md", "line_start": 2, "line_end": 2, "category": "name-format"}]
FINDINGS = [{"id": "F-001", "file": "SKILL.md", "line_start": 2, "category": "name-format"},
            {"id": "F-002", "file": "SKILL.md", "line_start": 2, "category": "name-folder-mismatch"}]


def match(adj):
    return harness_metrics.match_run(FINDINGS, GT, 3, adj, "run1")


class AdjudicatedDuplicates(unittest.TestCase):
    def test_dup_decision_leaves_gt_to_the_stating_finding(self):
        out = match({"run1:F-002": "dup:GT-01"})
        self.assertEqual(out, {"F-001": "GT-01", "F-002": "dup:GT-01"})

    def test_plain_gt_decision_still_claims_the_gt(self):
        out = match({"run1:F-002": "GT-01"})
        self.assertEqual(out["F-002"], "GT-01")
        self.assertEqual(out["F-001"], "dup:GT-01")


if __name__ == "__main__":
    unittest.main()
