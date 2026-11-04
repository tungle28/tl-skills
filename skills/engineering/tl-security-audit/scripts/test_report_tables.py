#!/usr/bin/env python3
"""Tests for the report table rules (references/report-tables.md).

    python3 test_report_tables.py
"""
import unittest

import re

from findings import detail, md_cell, md_text, normalize_md_tables, table

HEAD = "| A | B |\n|---|---|\n"


def body(md):
    """Data rows of the first table in md."""
    return [l for l in md.split("\n") if l.startswith("|")][2:]


class Cells(unittest.TestCase):
    def test_cell_rules(self):
        self.assertEqual(md_cell(None), "-")
        self.assertEqual(md_cell(""), "-")
        self.assertEqual(md_cell("a\nb"), "a b")
        self.assertEqual(md_cell("a|b"), "a\\|b")
        self.assertEqual(md_cell("`x|y`"), "`x\\|y`")
        self.assertEqual(md_cell("List<int> ok"), "`List<int>` ok")
        self.assertEqual(md_cell("`odd"), "'odd")

    def test_table_width(self):
        t = table([["1"], ["1", "2", "3"]], ["A", "B"])
        self.assertEqual(body(t), ["| 1 | - |", "| 1 | 2 |"])


class Repair(unittest.TestCase):
    def check(self, row, expected, repaired):
        md, problems = normalize_md_tables(HEAD + row)
        self.assertEqual(body(md), [expected])
        self.assertEqual(bool(problems), repaired)

    def test_pipe_in_code_unescaped(self):
        self.check("| `x|y` | z |", "| `x\\|y` | z |", True)

    def test_pipe_in_code_escaped(self):
        self.check("| `x\\|y` | z |", "| `x\\|y` | z |", False)

    def test_pipe_in_text_escaped(self):
        self.check("| a \\| b | z |", "| a \\| b | z |", False)

    def test_missing_cell(self):
        self.check("| only |", "| only | - |", True)

    def test_overflow_kept_in_last_cell(self):
        self.check("| a | b | c |", "| a | b \\| c |", True)

    def test_separator_wider_than_header_keeps_data(self):
        md, problems = normalize_md_tables("| A | B |\n|---|---|---|\n| 1 | 2 | 3 |")
        rows = [l for l in md.split("\n") if l.startswith("|")]
        self.assertEqual(rows[0], "| A | B | - |")
        self.assertEqual(rows[2], "| 1 | 2 | 3 |")
        self.assertTrue(problems)

    def test_one_column_overflow_kept(self):
        md, problems = normalize_md_tables("| A |\n|---|\n| 1 | 2 | 3 |")
        rows = [l for l in md.split("\n") if l.startswith("|")]
        self.assertEqual(rows[2], "| 1 \\| 2 \\| 3 |")
        self.assertTrue(problems)

    def test_table_in_code_fence_untouched(self):
        md = "```markdown\n" + HEAD + "| `x|y` | z |\n```"
        out, problems = normalize_md_tables(md)
        self.assertEqual(out, md)
        self.assertEqual(problems, [])

    def test_idempotent(self):
        t = table([["`x|y`", "List<int>", None, "a\nb"]], ["A", "B", "C", "D"])
        self.assertEqual(normalize_md_tables(t), (t, []))


class FreeText(unittest.TestCase):
    PAYLOADS = ["<img src=x onerror=alert(1)>", "<script>alert(1)</script>"]

    def live_tags(self, s):
        """Angle-bracket text left outside code spans."""
        return re.findall(r"[<>]", "".join(s.split("`")[0::2]))

    def test_md_text_wraps_tags(self):
        for p in self.PAYLOADS:
            self.assertEqual(self.live_tags(md_text(f"echo {p} done")), [])
        self.assertEqual(md_text("keep `<b>` and a|b"), "keep `<b>` and a|b")

    def test_md_text_idempotent(self):
        for p in self.PAYLOADS:
            once = md_text(p)
            self.assertEqual(md_text(once), once)

    def test_detail_has_no_live_tags(self):
        for p in self.PAYLOADS:
            f = {"id": "X-1", "title": f"t {p}", "file": "a.php", "line_start": 1, "line_end": 1,
                 "owasp": "A05", "severity": "high", "confidence": "high", "requires": "none",
                 "kind": "vulnerability", "status": "confirmed", "sources": ["r"], "from_hits": [],
                 "evidence": p, "attack_scenario": p, "impact": p, "fix": p, "note": p,
                 "verification_note": p}
            self.assertEqual(self.live_tags(detail(f)), [])


if __name__ == "__main__":
    unittest.main()
