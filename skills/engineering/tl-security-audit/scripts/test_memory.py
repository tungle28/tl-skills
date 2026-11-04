#!/usr/bin/env python3
"""Tests for cross-run memory (memory.py): triage matching and the diff against a previous run.

    python3 test_memory.py
"""
import json
import tempfile
import unittest
from pathlib import Path

import memory
from memory import Sources, apply_triage, diff_runs, line_hash, propose, same_code, triage_hit

CODE = "import crypto\n\nexport function hashPassword(pw) {\n  return crypto.createHash('md5').update(pw).digest('hex');\n}\n"


class Repo:
    def __init__(self, test):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def triage(self, entries):
        self.write(".security-audit/triage.yml", memory.yaml.safe_dump(entries))


def finding(fid="F-1", line=4, **kw):
    return {"id": fid, "file": "src/auth.ts", "line_start": line, "line_end": line, "cwe": "CWE-328",
            "owasp": "A04", "category": None, "status": "unverified", **kw}


class Fingerprint(unittest.TestCase):
    def test_trivial_lines_carry_no_identity(self):
        self.assertIsNone(line_hash("  }  "))
        self.assertIsNone(line_hash("return;"[:5]))
        self.assertEqual(line_hash("a = b(c)"), line_hash("  a  =  b( c )\t"))

    def test_same_code_needs_half_of_shorter(self):
        self.assertTrue(same_code(["a"], ["a", "b", "c"]))
        self.assertFalse(same_code(["a", "b", "c"], ["a", "x", "y"]))
        self.assertFalse(same_code([], ["a"]))


class Triage(unittest.TestCase):
    def setUp(self):
        self.r = Repo(self)
        self.r.write("src/auth.ts", CODE)
        fp = Sources(self.r.root).hashes("src/auth.ts", 4)
        self.entry = {"id": "T001", "verdict": "false-positive", "file": "src/auth.ts", "cwe": "CWE-328",
                      "owasp": "A04", "lines": fp, "reason": "cache key", "rules": ["js-weak-hash"]}

    def test_matches_after_line_shift(self):
        self.r.triage([self.entry])
        self.r.write("src/auth.ts", "// new header\n// more\n" + CODE)
        fs = [finding(line=6)]
        self.assertEqual(apply_triage(fs, self.r.root), 1)
        self.assertEqual(fs[0]["status"], "known-fp")

    def test_changed_code_is_reviewed_again(self):
        self.r.triage([self.entry])
        self.r.write("src/auth.ts", CODE.replace("md5", "sha1"))
        fs = [finding()]
        self.assertEqual(apply_triage(fs, self.r.root), 0)
        self.assertEqual(fs[0]["status"], "unverified")

    def test_partial_edit_of_recorded_span_is_reviewed_again(self):
        # a two-line decision; the fix edits one line and keeps the signature: half still overlaps,
        # but the decision was about the old code
        src = Sources(self.r.root)
        self.r.triage([{**self.entry, "lines": src.hashes("src/auth.ts", 3, 4)}])
        self.r.write("src/auth.ts", CODE.replace("md5", "sha256"))
        fs = [finding(line=3, line_end=4)]
        self.assertEqual(apply_triage(fs, self.r.root), 0)

    def test_rule_scoped_entry_does_not_hide_reviewer_finding(self):
        # learned from a dismissed js-weak-hash hit: a reviewer's CWE-328 finding on that line stays live
        self.r.triage([{**self.entry, "match": "rule", "category": "js-weak-hash", "rules": []}])
        fs = [finding(category="crypto-data-protection"), finding("R-H1", category="js-weak-hash")]
        self.assertEqual(apply_triage(fs, self.r.root), 1)
        self.assertEqual([f["status"] for f in fs], ["unverified", "known-fp"])

    def test_other_class_same_line_not_matched(self):
        self.r.triage([self.entry])
        fs = [finding(cwe="CWE-89", owasp="A05")]
        self.assertEqual(apply_triage(fs, self.r.root), 0)

    def test_expired_and_reasonless_entries_ignored(self):
        self.r.triage([{**self.entry, "until": "2000-01-01"}, {**self.entry, "id": "T002", "reason": ""}])
        self.assertEqual(apply_triage([finding()], self.r.root), 0)

    def test_scan_hit_skipped_only_for_listed_rules(self):
        src = Sources(self.r.root)
        hit = {"file": "src/auth.ts", "line": 4, "rule_id": "js-weak-hash"}
        self.assertIn("T001", triage_hit(hit, [self.entry], src))
        self.assertIsNone(triage_hit({**hit, "rule_id": "js-other"}, [self.entry], src))
        self.assertIsNone(triage_hit(hit, [{**self.entry, "verdict": "accepted-risk"}], src))


class Propose(unittest.TestCase):
    def test_duplicates_are_not_learned(self):
        r = Repo(self)
        r.write("src/auth.ts", CODE)
        run = r.root / "run"
        (run / "scan").mkdir(parents=True)
        (run / "scan" / "hits.json").write_text(json.dumps({"hits": [
            {"hit_id": "H1", "file": "src/auth.ts", "line": 4, "rule_id": "js-weak-hash"}]}))
        doc = {"findings": [
            {**finding("F-1", line=3, line_end=4), "status": "verified"},
            {**finding("F-2", line=4), "status": "rejected", "verification_note": "not exploitable"},  # on F-1's lines
            {**finding("F-3", line=1), "status": "rejected", "verification_note": "Trùng lặp với F-9; gộp vào F-9"},
            {**finding("F-4", line=1), "status": "rejected",
             "verification_note": "cache key, not a password; StreamReader trùng khớp mẫu sink"}],
            "dismissed": [{"hit_id": "H1", "rule_id": "js-weak-hash", "file": "src/auth.ts", "line": 4,
                           "reason": "duplicate of F-1"}]}
        props, skipped = propose(run, doc, Sources(r.root))
        self.assertEqual([p["from"] for p in props], ["F-4"])
        self.assertEqual({s["from"] for s in skipped}, {"F-2", "F-3", "H1"})


class Diff(unittest.TestCase):
    def test_new_persisting_and_gone(self):
        r = Repo(self)
        r.write("src/auth.ts", CODE)
        r.write("src/other.ts", "const token = readToken(request.headers);\nconst q = 'SELECT ' + id;\n")
        src = Sources(r.root)
        # F-3 spans the unchanged line 1 and the fixed line 2 (a fix that keeps the signature line)
        old = [finding("F-1"), {**finding("F-2", 1), "file": "src/other.ts", "cwe": "CWE-201"},
               {**finding("F-3", 1, line_end=2), "file": "src/other.ts", "cwe": "CWE-89"}]
        for f in old:
            f["fp"] = src.hashes(f["file"], f["line_start"], f["line_end"])
        runs = r.root / ".security-run"
        for name, created in (("r1", "2026-01-01"), ("r2", "2026-02-01")):
            (runs / name).mkdir(parents=True)
            (runs / name / "state.json").write_text(json.dumps({"root": str(r.root), "created_at": created}))
        (runs / "r1" / "merged.json").write_text(json.dumps({"findings": old}))
        (runs / "r1" / "report.md").write_text("x")
        r.write("src/other.ts", "const token = readToken(request.headers);\nconst q = db.query('SELECT $1', [id]);\n")
        cur = [{**finding("F-7"), "fp": src.hashes("src/auth.ts", 4)},
               {**finding("F-8", 3), "cwe": "CWE-20", "fp": ["zzz"]}]
        doc = {"findings": cur}
        d = diff_runs(runs / "r2", doc, {"root": str(r.root), "created_at": "2026-02-01"}, {"scope": {"kind": "full"}})
        self.assertEqual((d["new"], d["persisting"]), (1, 1))
        self.assertEqual(cur[0]["baseline_id"], "F-1")
        why = {g["id"]: g["reason"] for g in d["gone"]}
        self.assertEqual(why["F-2"], "code unchanged, not reported")
        self.assertEqual(why["F-3"], "code changed")

    def _runs(self, r, old):
        runs = r.root / ".security-run"
        for name, created in (("r1", "2026-01-01"), ("r2", "2026-02-01")):
            (runs / name).mkdir(parents=True)
            (runs / name / "state.json").write_text(json.dumps({"root": str(r.root), "created_at": created}))
        (runs / "r1" / "merged.json").write_text(json.dumps({"findings": old}))
        (runs / "r1" / "report.md").write_text("x")
        return runs / "r2", {"root": str(r.root), "created_at": "2026-02-01"}

    def test_best_pair_wins_over_first_match(self):
        r = Repo(self)
        r.write("Dockerfile", "FROM node:18-alpine\nWORKDIR /app\nCOPY . .\nCOPY .env .env\nCMD node server.js\n")
        src = Sources(r.root)
        mk = lambda fid, cwe, cat: {"id": fid, "file": "Dockerfile", "line_start": 1, "line_end": 5, "cwe": cwe,
                                    "category": cat, "owasp": "A02", "status": "verified",
                                    "fp": src.hashes("Dockerfile", 1, 5)}
        old = [mk("O-root", "CWE-250", "containers"), mk("O-env", "CWE-538", "secrets")]
        cur = [mk("N-env", "CWE-538", "containers"), mk("N-root", "CWE-250", "containers")]
        run, st = self._runs(r, old)
        d = diff_runs(run, {"findings": cur}, st, {"scope": {"kind": "full"}})
        self.assertEqual({f["id"]: f["baseline_id"] for f in cur}, {"N-env": "O-env", "N-root": "O-root"})
        self.assertEqual(d["gone"], [])

    def test_restated_elsewhere_is_not_a_miss(self):
        r = Repo(self)
        r.write("src/app.ts", "app.use(express.json({ limit: '1mb' }));\n")
        r.write("src/routes/auth.ts", "router.post('/login', async (req, res) => {\n")
        src = Sources(r.root)
        old = [{"id": "O-1", "file": "src/app.ts", "line_start": 1, "line_end": 1, "cwe": "CWE-307",
                "category": "rate-limiting-dos", "owasp": "A07", "status": "verified", "fp": src.hashes("src/app.ts", 1)}]
        cur = [{"id": "N-1", "file": "src/routes/auth.ts", "line_start": 1, "line_end": 1, "cwe": "CWE-307",
                "category": "rate-limiting-dos", "owasp": "A07", "status": "verified",
                "fp": src.hashes("src/routes/auth.ts", 1)}]
        run, st = self._runs(r, old)
        d = diff_runs(run, {"findings": cur}, st, {"scope": {"kind": "full"}})
        self.assertTrue(d["gone"][0]["reason"].startswith("code unchanged, reported differently (N-1"))

    def test_no_baseline(self):
        r = Repo(self)
        (r.root / "run").mkdir()
        self.assertIsNone(diff_runs(r.root / "run", {"findings": []}, {"root": str(r.root), "created_at": "x"}, {}))


if __name__ == "__main__":
    unittest.main()
