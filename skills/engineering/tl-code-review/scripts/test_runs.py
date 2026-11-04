#!/usr/bin/env python3
"""Tests for per-run folders (resolve_scope.py, run_dir.py, script defaults) and compare_runs.py.

    python3 test_runs.py
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(script, *args, cwd=None):
    return subprocess.run([sys.executable, str(HERE / script), *args], capture_output=True, text=True,
                          encoding="utf-8", cwd=cwd)


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def finding(fid, sev, file="src/a.ts", line=10, title=None, category="correctness"):
    return {"id": fid, "file": file, "line_start": line, "line_end": line + 2, "severity": sev,
            "category": category, "confidence": "high", "in_diff": True, "title": title or f"Title {fid}",
            "why": "w"}


def run_with(d, findings, head_sha="abc"):
    """A finished run folder holding an aggregated findings.json."""
    (d / "findings").mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps({"mode": "changeset", "base_sha": "b", "head_sha": head_sha}),
                                     encoding="utf-8")
    (d / "findings" / "S01.json").write_text(json.dumps({"shard": "S01", "findings": findings}), encoding="utf-8")
    r = run("aggregate_findings.py", "--dir", str(d))
    assert r.returncode in (0, 2), r.stderr


class Runs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        repo = self.repo = Path(self.tmp.name)
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "t@t"); git(repo, "config", "user.name", "t")
        (repo / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        git(repo, "add", "."); git(repo, "commit", "-qm", "base")
        (repo / "a.py").write_text("def f():\n    return 2\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def scope(self, *extra):
        r = run("resolve_scope.py", "--mode", "uncommitted", *extra, cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        line = next(x for x in r.stdout.splitlines() if x.startswith("RUN_DIR: "))
        return Path(line[len("RUN_DIR: "):])

    def test_each_run_gets_its_own_folder(self):
        first, second = self.scope(), self.scope()
        self.assertNotEqual(first, second)
        self.assertEqual(first.parent, self.repo / ".code-review" / "runs")
        self.assertTrue((first / "manifest.json").exists() and (second / "manifest.json").exists())
        latest = (self.repo / ".code-review" / "latest").read_text(encoding="utf-8").strip()
        self.assertEqual(latest, f"runs/{second.name}")
        self.assertIn("/.code-review/", (self.repo / ".git" / "info" / "exclude").read_text(encoding="utf-8"))

    def test_scripts_default_to_the_latest_run(self):
        first, second = self.scope(), self.scope()
        r = run("plan_shards.py", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((second / "shards.json").exists())
        self.assertFalse((first / "shards.json").exists())
        self.assertFalse((self.repo / ".code-review" / "shards.json").exists())

    def test_run_dir_reuses_a_folder(self):
        first = self.scope()
        self.scope()
        again = self.scope("--run-dir", str(first))
        self.assertEqual(again.resolve(), first.resolve())
        latest = (self.repo / ".code-review" / "latest").read_text(encoding="utf-8").strip()
        self.assertEqual(latest, f"runs/{first.name}")

    def test_failed_run_leaves_no_folder(self):
        r = run("resolve_scope.py", "--mode", "changeset", "--base", "no-such-ref", cwd=self.repo)
        self.assertNotEqual(r.returncode, 0)
        runs = self.repo / ".code-review" / "runs"
        self.assertEqual(list(runs.iterdir()) if runs.exists() else [], [])

    def test_prune_keeps_newest_and_latest(self):
        git(self.repo, "commit", "-qam", "change")
        git(self.repo, "checkout", "-qb", "feature")
        (self.repo / "a.py").write_text("def f():\n    return 3\n", encoding="utf-8")
        git(self.repo, "commit", "-qam", "feature")
        git(self.repo, "checkout", "-q", "main")
        (self.repo / "a.py").write_text("def f():\n    return 4\n", encoding="utf-8")
        # the oldest run reviews a branch that is not checked out, so it has a head/ worktree
        r = run("resolve_scope.py", "--mode", "changeset", "--base", "main", "--head", "feature",
                "--label", "wt", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        wt_run = Path(next(x for x in r.stdout.splitlines() if x.startswith("RUN_DIR: "))[9:])
        self.assertTrue((wt_run / "head" / ".git").exists())
        made = [self.scope() for _ in range(3)]
        base = str(self.repo / ".code-review")
        dry = run("compare_runs.py", "--base", base, "--prune", "1")
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertTrue(all(m.exists() for m in made))  # dry run deletes nothing
        (self.repo / ".code-review" / "latest").write_text(f"runs/{made[0].name}\n", encoding="utf-8")
        r = run("compare_runs.py", "--base", base, "--prune", "1", "--confirm")
        self.assertEqual(r.returncode, 0, r.stderr)
        left = sorted(p.name for p in (self.repo / ".code-review" / "runs").iterdir())
        self.assertEqual(left, sorted({made[0].name, made[-1].name}))
        worktrees = subprocess.run(["git", "worktree", "list"], cwd=self.repo, capture_output=True,
                                   text=True).stdout
        self.assertNotIn(wt_run.name, worktrees)

    def branch_run(self, *extra):
        r = run("resolve_scope.py", "--mode", "changeset", "--base", "main", "--head", "feature", *extra, cwd=self.repo)
        line = next((x for x in r.stdout.splitlines() if x.startswith("RUN_DIR: ")), "")
        return r, Path(line[len("RUN_DIR: "):]) if line else None

    def test_since_run_reviews_only_later_commits(self):
        git(self.repo, "commit", "-qam", "main change")
        git(self.repo, "checkout", "-qb", "feature")
        (self.repo / "b.py").write_text("B = 1\n", encoding="utf-8")
        git(self.repo, "add", "."); git(self.repo, "commit", "-qm", "add b")
        git(self.repo, "checkout", "-q", "main")
        r, first = self.branch_run()
        self.assertEqual(r.returncode, 0, r.stderr)
        reviewed = json.loads((first / "manifest.json").read_text(encoding="utf-8"))["head_sha"]
        self.assertTrue(reviewed)
        runs = self.repo / ".code-review" / "runs"

        # nothing pushed since: stop, say so, leave no folder
        r, _ = self.branch_run("--since-run", "latest")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("nothing new since", r.stderr)
        self.assertEqual(len(list(runs.iterdir())), 1)

        git(self.repo, "checkout", "-q", "feature")
        (self.repo / "c.py").write_text("C = 1\n", encoding="utf-8")
        git(self.repo, "add", "."); git(self.repo, "commit", "-qm", "add c")
        git(self.repo, "checkout", "-q", "main")
        r, second = self.branch_run("--since-run", "latest")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads((second / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual([f["path"] for f in m["files"]], ["c.py"])  # b.py was reviewed already
        self.assertEqual((m["base_sha"], m["since_run"]["head_sha"], m["since_run"]["run"]), (reviewed, reviewed, first.name))
        self.assertTrue(second.name.endswith("-since"))
        self.assertIn("add c", "\n".join(m["intent"]))

        # a rewritten branch: the old head is no ancestor, so the diff since it would mix in other commits
        git(self.repo, "checkout", "-q", "feature")
        git(self.repo, "reset", "-q", "--hard", "main")
        (self.repo / "d.py").write_text("D = 1\n", encoding="utf-8")
        git(self.repo, "add", "."); git(self.repo, "commit", "-qm", "rewritten")
        git(self.repo, "checkout", "-q", "main")
        r, _ = self.branch_run("--since-run", str(second))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not an ancestor", r.stderr)

    def test_since_run_needs_a_recorded_head(self):
        old = self.repo / ".code-review" / "runs" / "20260101-000000-old"
        old.mkdir(parents=True)
        (old / "manifest.json").write_text(json.dumps({"mode": "changeset", "head": "refs/x"}), encoding="utf-8")
        git(self.repo, "branch", "feature")
        r, _ = self.branch_run("--since-run", str(old))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("records no head_sha", r.stderr)

    def test_runs_in_one_second_keep_their_order(self):
        sys.path.insert(0, str(HERE))
        import run_dir
        base = self.repo / ".code-review"
        made = [run_dir.new_run(base, label) for label in ("zz", "aa", "mm")]  # labels against age order
        self.assertEqual(run_dir.list_runs(base), made)
        old = base / "runs" / "20000101-000000-manual"   # no creation file: an older version or by hand
        old.mkdir()
        self.assertEqual(run_dir.list_runs(base)[0], old)

    def test_baseline_is_shared_across_runs(self):
        d = self.repo / ".code-review" / "runs" / "20260101-000000-x"
        run_with(d, [finding("S01-001", "major")])
        r = run("aggregate_findings.py", "--dir", str(d), "--write-baseline")
        self.assertIn(r.returncode, (0, 2), r.stderr)
        self.assertTrue((self.repo / ".code-review" / "baseline.json").exists())


class Compare(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name) / ".code-review"
        self.old = self.base / "runs" / "20260101-000000-pr1"
        self.new = self.base / "runs" / "20260102-000000-pr1"

    def tearDown(self):
        self.tmp.cleanup()

    def compare(self, *args):
        r = run("compare_runs.py", "--base", str(self.base), *args)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads((self.new / "compare.json").read_text(encoding="utf-8"))

    def test_pairs_new_gone_and_changed(self):
        run_with(self.old, [
            finding("S01-001", "major", title="Order saved without lock"),
            finding("S01-002", "major", file="src/b.ts", title="Missing tenant filter in list"),
            finding("S01-003", "minor", file="src/c.ts", title="Unused import")])
        run_with(self.new, [
            # same defect, reworded and a few lines away
            finding("S02-004", "major", line=12, title="Order is saved without a lock"),
            finding("S02-005", "minor", file="src/b.ts", title="Tenant filter missing in list query"),
            finding("S02-006", "major", file="src/d.ts", title="Refund twice on retry")])
        (self.base / "latest").write_text(f"runs/{self.new.name}\n", encoding="utf-8")
        doc = self.compare()  # latest vs the run before it
        self.assertTrue(doc["same_code"])
        self.assertEqual(doc["new_findings"], ["S02-006"])
        self.assertEqual(doc["gone"], ["S01-003"])
        self.assertEqual(doc["changed"], [{"old": "S01-002", "new": "S02-005", "from": "major", "to": "minor"}])
        self.assertEqual(doc["kept"], [{"old": "S01-001", "new": "S02-004"}])
        self.assertIn("Refund twice on retry", (self.new / "compare.md").read_text(encoding="utf-8"))

    def test_pairs_across_languages_by_code_names(self):
        # One defect, reported in English as api-contract and in Vietnamese as correctness.
        en = finding("X-001", "blocker", line=56, category="api-contract",
                     title="Enrollment and activate disagree on pharmacy-order source_id")
        en["evidence"] = "createPharmacyOrderForLine(r, { sourceId: rx.id })"
        vi = finding("S04-001", "major", line=62, title="Đơn thuốc chỉ tạo được 1 order dù có nhiều dòng")
        vi["evidence"] = "await createPharmacyOrderForLine(r, { sourceId: rx.id, item })"
        other = finding("X-002", "major", line=62, category="tests", title="Không có test cho luồng enrollment")
        run_with(self.old, [en, other])
        run_with(self.new, [vi])
        doc = self.compare("--old", str(self.old), "--new", str(self.new))
        self.assertEqual(doc["changed"], [{"old": "X-001", "new": "S04-001", "from": "blocker", "to": "major"}])
        self.assertEqual(doc["gone"], ["X-002"])

    def test_incremental_run_says_gone_is_out_of_scope(self):
        run_with(self.old, [finding("S01-001", "major")])
        run_with(self.new, [finding("S01-001", "major", file="src/new.ts")], head_sha="def")
        m = json.loads((self.new / "manifest.json").read_text(encoding="utf-8"))
        m["since_run"] = {"run": self.old.name, "head_sha": "abc12345"}
        (self.new / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
        doc = self.compare("--old", str(self.old), "--new", str(self.new))
        self.assertEqual(doc["since_run"]["run"], self.old.name)
        self.assertIn("out of its scope, not fixed", (self.new / "compare.md").read_text(encoding="utf-8"))

    def test_nearby_defects_with_nothing_in_common_do_not_pair(self):
        old = finding("S01-001", "major", line=40, title="Refund amount rounded twice")
        old["evidence"] = "roundAmount(total)"
        new = finding("S01-001", "major", line=44, title="Lock released before commit")
        new["evidence"] = "releaseLock(order_id)"
        run_with(self.old, [old])
        run_with(self.new, [new])
        doc = self.compare("--old", str(self.old), "--new", str(self.new))
        self.assertEqual((doc["new_findings"], doc["gone"], doc["kept"]), (["S01-001"], ["S01-001"], []))

    def test_previous_run_is_by_creation_not_name(self):
        sys.path.insert(0, str(HERE))
        import run_dir
        # one second, labels out of age order: by name the run before "mm" would be "aa", the oldest
        first, second, third = (run_dir.new_run(self.base, label) for label in ("aa", "zz", "mm"))
        self.new = third   # compare.json lands here
        for d in (first, second, third):
            (d / "findings").mkdir(exist_ok=True)
            (d / "manifest.json").write_text(json.dumps({"mode": "changeset", "head_sha": "abc"}), encoding="utf-8")
            (d / "findings" / "S01.json").write_text(json.dumps({"shard": "S01", "findings": [finding("S01-001", "major")]}),
                                                     encoding="utf-8")
            r = run("aggregate_findings.py", "--dir", str(d))
            self.assertIn(r.returncode, (0, 2), r.stderr)
        doc = self.compare("--new", str(third))
        self.assertEqual(Path(doc["old"]).name, second.name)

    def test_different_files_never_pair(self):
        run_with(self.old, [finding("S01-001", "major", file="src/a.ts", title="Same words here")])
        run_with(self.new, [finding("S01-001", "major", file="src/z.ts", title="Same words here")], head_sha="def")
        doc = self.compare("--old", str(self.old), "--new", str(self.new), "--lang", "vi")
        self.assertFalse(doc["same_code"])
        self.assertEqual((doc["new_findings"], doc["gone"]), (["S01-001"], ["S01-001"]))

    def test_list(self):
        run_with(self.old, [finding("S01-001", "blocker")])
        r = run("compare_runs.py", "--base", str(self.base), "--list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("20260101-000000-pr1", r.stdout)
        self.assertIn("blocker=1", r.stdout)


if __name__ == "__main__":
    unittest.main()
