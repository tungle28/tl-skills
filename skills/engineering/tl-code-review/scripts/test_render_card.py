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

    def test_run_path_is_relative_to_repository_root(self):
        import render_html

        review_repo = self.d / "checkout"
        run = review_repo / ".code-review" / "runs" / "20261117-test"
        run.mkdir(parents=True)
        (review_repo / ".git").mkdir()
        self.assertEqual(render_html.display_run_path(run), ".code-review/runs/20261117-test")
        # A linked worktree stores .git as a file, which is still a valid repo marker.
        worktree = self.d / "linked" / ".code-review" / "runs" / "wt-1"
        worktree.mkdir(parents=True)
        git_file = worktree.parents[2] / ".git"
        git_file.write_text("gitdir: ../main/.git/worktrees/linked\n", encoding="utf-8")
        self.assertEqual(render_html.display_run_path(worktree), ".code-review/runs/wt-1")

    def test_run_path_fallbacks_and_storage_key(self):
        import render_html

        suffix = self.d / "copied" / ".code-review" / "runs" / "run-1"
        suffix.mkdir(parents=True)
        (self.d / "copied" / ".git").mkdir()
        self.assertEqual(render_html.display_run_path(suffix), ".code-review/runs/run-1")
        self.assertEqual(render_html.display_run_path(r"Z:\tl-render-standalone\run-2"), "run-2")
        key1 = render_html.decision_storage_key(suffix)
        other_checkout = self.d / "other" / ".code-review" / "runs" / "run-1"
        other_checkout.mkdir(parents=True)
        (self.d / "other" / ".git").mkdir()
        self.assertNotEqual(key1, render_html.decision_storage_key(other_checkout))
        self.assertNotIn(str(suffix.resolve()), key1)
        self.assertEqual(render_html.display_run_path(r"C:\repo\.code-review\runs\run-3"),
                         ".code-review/runs/run-3")
        key_a = render_html.decision_storage_key(suffix, r"C:\a\app", "abc")
        key_b = render_html.decision_storage_key(suffix, r"C:\b\app", "abc")
        self.assertNotEqual(key_a, key_b)

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
        self.assertIn(f"<code>{self.d.name}</code>", page)
        self.assertIn("<code>pr-7</code>", page)  # Head remains the reviewed commit/ref.
        self.assertNotIn(str(self.d.resolve()), page)

    def test_tabs_page_does_not_embed_absolute_run_path(self):
        out = self.d / "tabs.html"
        r = run("render_html.py", "--dir", str(self.d), "-o", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        page = out.read_text(encoding="utf-8")
        data = json.loads(page.split('<script type="application/json" id="data">')[1].split("</script>")[0])
        self.assertNotIn(str(self.d.resolve()), page)
        self.assertRegex(data["handoff"]["key"], r"^review:[0-9a-f]{16}$")
        self.assertIn(self.d.name, data["handoff"]["head"])

    def test_card_page_shows_recorded_fixes(self):
        fx = self.d / "fixes.json"
        run("record_fix.py", str(fx), "--id", "S01-004", "--status", "fixed", "--what", "Guarded <null>",
            "--verify", "pytest: 3 passed", "--files", "src/a.ts", "--commit", "abc1234")
        run("record_fix.py", str(fx), "--id", "S01-003", "--status", "failed", "--what", "needs a schema change")
        run("record_fix.py", str(fx), "--id", "NOPE-1", "--status", "partial", "--what", "typo id")
        out = self.d / "card.html"
        r = run("render_html.py", "--dir", str(self.d), "--template", "card", "-o", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NOPE-1", r.stderr)                                   # unknown id is reported
        self.assertIn("1 fixed", r.stdout)
        page = out.read_text(encoding="utf-8")
        self.assertIn('<span class="badge b-ok">Fixed</span>', page)
        self.assertIn('<span class="badge b-bad">Not fixed</span>', page)
        self.assertIn("Fix result</dt><dd>Guarded &lt;null&gt;", page)
        self.assertNotIn("Guarded <null>", page)
        self.assertIn("<code>abc1234</code>", page)
        self.assertIn('<div class="n ok">1</div><div class="l">Fixed since</div>', page)

    def test_old_findings_json_still_renders(self):
        doc = json.loads((self.d / "findings.json").read_text(encoding="utf-8"))
        for k in ("rejected_findings", "coverage", "positives"):
            doc.pop(k)
        (self.d / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
        r = run("render_html.py", "--dir", str(self.d), "--template", "card", "--lang", "vi",
                "-o", str(self.d / "vi.html"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Bị verifier bác", (self.d / "vi.html").read_text(encoding="utf-8"))


class Lang(unittest.TestCase):
    """--lang takes any BCP-47 tag: region subtags map to their language, others fall back to en.
    A bad argument never exits 2, which is the 'request changes' CI code."""
    setUp, tearDown = Card.setUp, Card.tearDown

    def aggregate(self, *args):
        r = run("aggregate_findings.py", "--dir", str(self.d), *args)
        self.assertIn(r.returncode, (0, 2), r.stderr)
        self.assertNotIn("invalid choice", r.stderr)
        return r, (self.d / "report.md").read_text(encoding="utf-8")

    def test_tabs_page_has_decisions_and_copy_for_agent(self):
        out = self.d / "tabs.html"
        r = run("render_html.py", "--dir", str(self.d), "--lang", "vi-VN", "-o", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        page = out.read_text(encoding="utf-8")
        data = json.loads(page.split('<script type="application/json" id="data">')[1].split("</script>")[0])
        self.assertEqual(data["text"]["copy"], "Sao chép cho agent")      # vi-VN -> vi labels
        self.assertNotIn(str(self.d.resolve()), data["handoff"]["head"])
        self.assertTrue(data["handoff"]["key"].startswith("review:"))
        self.assertLessEqual({"S01-003", "S01-004"}, {r["id"] for r in data["rows"]})
        for needle in ('id="cards"', 'class="dock"', 'id="copy"', "card sv'", 'name="d'):
            self.assertIn(needle, page)
        self.assertNotIn('<tbody id="rows">', page)                        # no findings table any more

    def test_record_fix_moves_finding_to_fixed(self):
        fx = self.d / "fixes.json"
        r = run("record_fix.py", str(fx), "--id", "S01-003", "--status", "fixed", "--what", "Guarded <null>",
                "--verify", "pytest: 3 passed", "--files", "src/a.ts, src/b.ts", "--commit", "abc1234")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run("record_fix.py", str(fx), "--id", "S01-004", "--status", "fixed", "--what", "x")
        self.assertNotEqual(r.returncode, 0)                                # fixed without --verify is refused
        run("record_fix.py", str(fx), "--id", "S01-004", "--status", "failed", "--what", "needs a schema change")
        run("record_fix.py", str(fx), "--id", "NOPE-1", "--status", "partial", "--what", "typo id")
        run("record_fix.py", str(fx), "--id", "S01-003", "--status", "fixed", "--what", "Guarded again",
            "--verify", "pytest: 4 passed")                                 # same id replaces the entry
        doc = json.loads(fx.read_text(encoding="utf-8"))
        self.assertEqual([e["id"] for e in doc["fixes"]], ["S01-003", "S01-004", "NOPE-1"])
        self.assertEqual(doc["fixes"][0]["what"], "Guarded again")
        out = self.d / "tabs.html"
        r = run("render_html.py", "--dir", str(self.d), "--lang", "vi", "-o", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NOPE-1", r.stderr)                                   # unknown id is reported
        self.assertIn("1 fixed", r.stdout)
        page = out.read_text(encoding="utf-8")
        data = json.loads(page.split('<script type="application/json" id="data">')[1].split("</script>")[0])
        fix = {x["id"]: x.get("fix") for x in data["rows"]}
        self.assertEqual(fix["S01-003"]["status"], "fixed")
        self.assertEqual(fix["S01-004"]["status"], "failed")
        self.assertIn('id="fixed-head"', page)
        self.assertIn('id="tiles"', page)
        self.assertNotIn("Guarded <null>", page.split('<script type="application/json"')[0].replace(
            "Guarded &lt;null&gt;", ""))                                    # escaped wherever it is shown
        self.assertIn('<section class="fix-results" id="fix-results"><h2>Kết quả sửa</h2>', page)
        self.assertIn("1 đã sửa · 0 sửa một phần · 1 chưa sửa được", page)  # NOPE-1 is not counted
        self.assertIn('<a href="#fix-results">Kết quả sửa</a>', page)       # first entry of the nav

    def test_unsupported_lang_falls_back_to_en(self):
        r, report = self.aggregate("--lang", "ja")
        self.assertIn("Code Review Report", report)
        self.assertIn("falling back to en", r.stderr)

    def test_region_subtag(self):
        _, report = self.aggregate("--lang", "vi-VN")
        self.assertIn("Báo cáo Code Review", report)

    def test_usage_error_is_not_exit_2(self):
        r = run("aggregate_findings.py", "--dir", str(self.d), "--max-nits", "many")
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_post_review_and_compare_accept_any_lang(self):
        r = run("post_review.py", "--dir", str(self.d), "--format", "markdown", "--lang", "fr-CA")
        self.assertNotIn("invalid choice", r.stderr)
        self.assertIn("falling back to en", r.stderr)
        r = run("compare_runs.py", "--base", str(self.d / "nope"), "--list", "--lang", "ja")
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
