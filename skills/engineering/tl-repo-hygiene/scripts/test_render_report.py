"""Tests for render_report.py and record_fix.py: python -m pytest -q (or run this file)."""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

DATA = {
    "project": "demo", "root": "/x/demo", "generated": "2026-01-01T10:00:00", "language": "vi",
    "summary": "Tóm tắt <b>", "skipped": ["node_modules"],
    "checks_run": [{"command": "pytest -q", "result": "pass", "note": "48 passed"}],
    "fixed": [{"id": "F1", "category": "broken", "severity": "high", "title": "Link hỏng",
               "files": ["README.md:3"], "what": "Sửa link", "verify": "check_links: 0"}],
    "proposals": [
        {"id": "P1", "category": "token-waste", "severity": "high", "title": "AGENTS.md trùng CLAUDE.md",
         "evidence": [{"file": "AGENTS.md", "line": 40, "note": "dup"}], "problem": "Trùng", "recommendation": "Gộp",
         "effort": "S", "saving_tokens": 1200},
        {"id": "P2", "category": "broken", "severity": "medium", "title": "Lệnh test sai",
         "evidence": ["docs/dev.md:12"], "problem": "Sai", "recommendation": "Sửa", "effort": "S"},
        {"id": "P3", "category": "obsolete", "severity": "low", "title": "Script cũ",
         "problem": "Không dùng", "recommendation": "Xoá"},
    ],
}


def run(script, *args):
    return subprocess.run([sys.executable, "-I", str(HERE / script), *args], capture_output=True, text=True,
                          encoding="utf-8")


class Report(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "findings.json").write_text(json.dumps(DATA, ensure_ascii=False), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def render(self):
        r = run("render_report.py", str(self.d / "findings.json"), "--out", str(self.d / "report.html"))
        self.assertEqual(r.returncode, 0, r.stderr)
        return r, (self.d / "report.html").read_text(encoding="utf-8")

    def test_without_fixes(self):
        r, page = self.render()
        self.assertIn("1 fixed, 3 proposals", r.stdout)
        self.assertNotIn("fix-results", page.split("<body>")[1].split("<script>")[0])
        self.assertEqual(page.count('class="card prop'), 3)
        self.assertIn('data-loc="AGENTS.md:40"', page)                 # copied with the decision
        self.assertIn('data-loc="docs/dev.md:12"', page)
        self.assertIn("Tóm tắt &lt;b&gt;", page)                       # escaped
        self.assertIn("record_fix.py", page)                           # the copied instruction names it

    def test_fixes_move_and_mark_proposals(self):
        fx = str(self.d / "fixes.json")
        self.assertNotEqual(run("record_fix.py", fx, "--id", "P1", "--status", "fixed", "--what", "x").returncode, 0)
        run("record_fix.py", fx, "--id", "P1", "--status", "fixed", "--what", "Gộp vào CLAUDE.md",
            "--verify", "wc -l: 120 -> 60", "--files", "AGENTS.md,CLAUDE.md", "--commit", "abc1234")
        run("record_fix.py", fx, "--id", "P2", "--status", "failed", "--what", "Cần quyết định của chủ repo")
        run("record_fix.py", fx, "--id", "P9", "--status", "partial", "--what", "typo")
        r, page = self.render()
        self.assertIn("P9", r.stderr)                                  # unknown id is reported
        self.assertIn("2 proposals, 1 applied after review", r.stdout)
        self.assertEqual(page.count('class="card prop'), 2)            # P1 left the decision list
        fixed = page.split("Đã tự sửa (2)")[1]
        self.assertIn("Gộp vào CLAUDE.md", fixed)
        self.assertIn("Áp dụng sau khi duyệt", fixed)
        self.assertIn("<summary>Đề xuất gốc</summary>", fixed)
        p2 = re.search(r'<article class="card prop[^>]*data-id="P2".*?</article>', page, re.S).group(0)
        self.assertIn("Sửa chưa được", p2)
        self.assertIn("Cần quyết định của chủ repo", p2)
        self.assertIn("1 đã sửa · 0 sửa một phần · 1 chưa sửa được", page)
        self.assertIn("<b>2</b><span>Đã tự sửa</span>", page)         # tile counts the applied one

    def test_all_proposals_fixed_hides_bar(self):
        fx = str(self.d / "fixes.json")
        for pid in ("P1", "P2", "P3"):
            run("record_fix.py", fx, "--id", pid, "--status", "fixed", "--what", "done", "--verify", "ok")
        _, page = self.render()
        self.assertEqual(page.count('class="card prop'), 0)
        self.assertIn('document.querySelector(".bar").hidden = true', page)
        self.assertIn(".bar[hidden] { display:none; }", page)


if __name__ == "__main__":
    unittest.main()
