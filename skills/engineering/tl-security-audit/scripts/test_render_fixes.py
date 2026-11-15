#!/usr/bin/env python3
"""Tests for render_html.py with a fixes.json from record_fix.py: secrets quoted in fix notes are masked.

    python3 test_render_fixes.py
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from common import secret_digest

HERE = Path(__file__).resolve().parent
SECRET = "sk_live_9fQ2xW7pL4mZ8tR1"  # fake: digest recorded as if the scan had found it


def run(script, *args):
    return subprocess.run([sys.executable, str(HERE / script), *args], capture_output=True, text=True,
                          encoding="utf-8")


class FixesRedaction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name) / "repo"
        root.mkdir()
        run_dir = self.run_dir = Path(self.tmp.name) / "run"
        (run_dir / "scan").mkdir(parents=True)
        (run_dir / "state.json").write_text(json.dumps({"root": str(root), "lang": "en"}), encoding="utf-8")
        (run_dir / "scan" / "secret_digests.json").write_text(json.dumps(
            [{"sha256": secret_digest(SECRET), "len": len(SECRET), "ws": False}]), encoding="utf-8")
        (run_dir / "merged.json").write_text(json.dumps({"findings": [
            {"id": "SEC-001", "severity": "high", "title": "Hard-coded API key", "file": "src/pay.ts",
             "line_start": 3, "status": "confirmed", "owasp": "A04", "confidence": "high"}]}), encoding="utf-8")
        (run_dir / "report.md").write_text("# Security report\n\n## Summary\n\nOne finding.\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_secret_in_fix_note_is_masked(self):
        fx = self.run_dir / "fixes.json"
        r = run("record_fix.py", str(fx), "--id", "SEC-001", "--status", "fixed",
                "--what", f"Moved {SECRET} to the vault", "--verify", f"grep {SECRET}: no hits")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = self.run_dir / "report.html"
        r = run("render_html.py", "--run-dir", str(self.run_dir), "-o", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 fixed", r.stdout)
        page = out.read_text(encoding="utf-8")
        self.assertNotIn(SECRET, page)
        self.assertIn("chars redacted]", page)
        data = json.loads(page.split('<script type="application/json" id="data">')[1].split("</script>")[0])
        fix = data["rows"][0]["fix"]
        self.assertEqual(fix["status"], "fixed")
        self.assertNotIn(SECRET, fix["what"] + fix["verify"])


if __name__ == "__main__":
    unittest.main()
