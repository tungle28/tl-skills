#!/usr/bin/env python3
"""Tests for aggregate_findings.py's extra findings.json keys and render_html.py --template card.

    python3 test_render_card.py
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def finding(fid, sev, conf="high", **extra):
    return {"id": fid, "file": f"src/{fid}.ts", "line_start": 10, "line_end": 12, "severity": sev,
            "category": "correctness", "confidence": conf, "in_diff": True, "title": f"Title {fid}",
            "evidence": "x <y>", "why": f"Why {fid}", "scenario": f"Scenario {fid}",
            "suggestion": f"Fix {fid}", **extra}


def run(script, *args):
    return subprocess.run([sys.executable, str(HERE / script), *args], capture_output=True, text=True,
                          encoding="utf-8")


class Card(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = Path(self.tmp.name)
        (d / "findings").mkdir()
        (d / "verify").mkdir()
        (d / "manifest.json").write_text(json.dumps(
            {"mode": "changeset", "pr": "7", "repo_root": "/x/app", "base": "origin/main", "head": "pr-7",
             "stats": {"files": 3, "added": 20, "deleted": 4, "tests_touched": 1}}), encoding="utf-8")
        (d / "findings" / "S01.json").write_text(json.dumps({
            "shard": "S01", "coverage": {"reviewed": ["a.ts", "b.ts"], "skipped": "gen/*"},
            "positives": ["Auth checked first"],
            "findings": [finding("S01-001", "major"), finding("S01-002", "major"),
                         finding("S01-003", "blocker"), finding("S01-004", "minor")]}), encoding="utf-8")
        (d / "verify" / "V01.json").write_text(json.dumps([
            {"id": "S01-001", "verdict": "confirmed", "severity": "minor", "note": "Guarded upstream"},
            {"id": "S01-002", "verdict": "rejected", "note": "Wrong branch"}]), encoding="utf-8")
        r = run("aggregate_findings.py", "--dir", str(d), "--lang", "en")
        self.assertIn(r.returncode, (0, 2), r.stderr)

    def tearDown(self):
        self.tmp.cleanup()

    def test_findings_json_keeps_card_data(self):
        doc = json.loads((self.d / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["rejected"], 1)
        self.assertEqual([f["id"] for f in doc["rejected_findings"]], ["S01-002"])
        self.assertEqual(doc["rejected_findings"][0]["verify_note"], "Wrong branch")
        moved = next(f for f in doc["findings"] if f["id"] == "S01-001")
        self.assertEqual((moved["original_severity"], moved["severity"]), ("major", "minor"))
        self.assertEqual(doc["coverage"][0]["shard"], "S01")
        self.assertEqual(doc["positives"], ["Auth checked first"])

    def test_card_page(self):
        out = self.d / "card.html"
        r = run("render_html.py", "--dir", str(self.d), "--template", "card", "-o", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        page = out.read_text(encoding="utf-8")
        self.assertIn("Code review PR #7 · app", page)
        # The unverified blocker waits for confirmation; the rejected one is listed with its reason.
        self.assertIn('<article class="f wait"><header><span class="id">S01-003</span>', page)
        self.assertIn('<article class="f drop"><header><span class="id">S01-002</span>', page)
        self.assertIn("Why rejected</dt><dd>Wrong branch", page)
        self.assertIn("Initial: major", page)
        self.assertIn("x &lt;y&gt;", page)
        self.assertIn("S01: skipped gen/*", page)
        self.assertNotIn("<script", page)
        self.assertNotIn("http", page.split("<body>")[1])

    def test_old_findings_json_still_renders(self):
        doc = json.loads((self.d / "findings.json").read_text(encoding="utf-8"))
        for k in ("rejected_findings", "coverage", "positives"):
            doc.pop(k)
        (self.d / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
        r = run("render_html.py", "--dir", str(self.d), "--template", "card", "--lang", "vi",
                "-o", str(self.d / "vi.html"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Bị verifier bác", (self.d / "vi.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
