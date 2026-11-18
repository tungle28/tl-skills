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

    def test_same_cwe_in_another_file_is_a_possible_miss(self):
        # Run 20261115 (agoyu): baseline S126-002 (EloquentOpenApiService.php:213-222, international
        # rates, CWE-639) was filed as "reported differently (S67-004 RoomTemporaryController.php)"
        # only because both were access-control/CWE-639, so it left the report and the possible-miss
        # list. A finding in another file that even cites these lines (S121-003, domestic rates) is
        # another API: location decides; the other finding is only named as a hint.
        r = Repo(self)
        r.write("Services/OpenApiService.php", "<?php\nclass OpenApiService {\n  function updateRate($rateId, $data) {\n"
                "    return $this->rates->update($rateId, $data);\n  }\n}\n")
        r.write("Controllers/DomesticController.php", "<?php\nclass DomesticController {\n  function update($id) {\n"
                "    return DomesticRate::find($id)->update(request()->all());\n  }\n}\n")
        src = Sources(r.root)
        old = [{"id": "S126-002", "file": "Services/OpenApiService.php", "line_start": 3, "line_end": 4,
                "cwe": "CWE-639", "category": "access-control", "owasp": "A01", "status": "verified", "severity": "high",
                "fp": src.hashes("Services/OpenApiService.php", 3, 4)}]
        cur = [{"id": "S121-003", "file": "Controllers/DomesticController.php", "line_start": 3, "line_end": 4,
                "cwe": "CWE-639", "category": "access-control", "owasp": "A01", "status": "verified", "severity": "high",
                "related": [{"file": "Services/OpenApiService.php", "line_start": 3, "line_end": 4}],
                "fp": src.hashes("Controllers/DomesticController.php", 3, 4)}]
        run, st = self._runs(r, old)
        d = diff_runs(run, {"findings": cur}, st, {"scope": {"kind": "full"}})
        g = d["gone"][0]
        self.assertEqual(g["id"], "S126-002")
        self.assertTrue(g["reason"].startswith("code unchanged, not reported"), g["reason"])
        self.assertTrue(g.get("possible_miss"))
        self.assertIn("S121-003", g["reason"])  # named as a hint to check, not as the match
        self.assertEqual(cur[0]["delta"], "new")

    def test_restated_at_the_same_place_is_reported_differently(self):
        # two findings of one Dockerfile merged into one a few lines further down
        r = Repo(self)
        r.write("Dockerfile", "FROM node:18-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\nUSER root\nCMD node server.js\n")
        src = Sources(r.root)
        old = [{"id": "O-1", "file": "Dockerfile", "line_start": 1, "line_end": 1, "cwe": "CWE-1104",
                "category": "containers", "owasp": "A02", "status": "verified", "fp": src.hashes("Dockerfile", 1)}]
        cur = [{"id": "N-1", "file": "Dockerfile", "line_start": 5, "line_end": 6, "cwe": "CWE-250",
                "category": "containers", "owasp": "A02", "status": "verified", "fp": src.hashes("Dockerfile", 5, 6)}]
        run, st = self._runs(r, old)
        d = diff_runs(run, {"findings": cur}, st, {"scope": {"kind": "full"}})
        self.assertTrue(d["gone"][0]["reason"].startswith("code unchanged, reported differently (N-1"))
        self.assertNotIn("possible_miss", d["gone"][0])

    def test_downgraded_finding_is_a_severity_change_not_gone(self):
        # Run 20261115 (agoyu): S05-001 was high at AgoyuUserController.php:140-219 (CWE-269) and is
        # still reported, medium, at 212-219 (CWE-862). The fingerprints (first lines of each span)
        # differ, so the report listed it as gone and the current one as new.
        r = Repo(self)
        body = "".join(f"    $step{i} = $this->service->handle($request, {i});\n" for i in range(1, 40))
        r.write("Controllers/UserController.php", "<?php\nclass UserController {\n  public function store($request) {\n"
                + body + "    return $this->users->assignRole($request->input('role'));\n  }\n}\n")
        src = Sources(r.root)
        old = [{"id": "S05-001", "file": "Controllers/UserController.php", "line_start": 3, "line_end": 44,
                "cwe": "CWE-269", "category": "access-control", "owasp": "A01", "status": "verified", "severity": "high",
                "title": "Route creates users and changes roles without a permission check",
                "fp": src.hashes("Controllers/UserController.php", 3, 44)}]
        lines = src.lines("Controllers/UserController.php")
        r.write("Controllers/UserController.php", "\n".join([lines[0], "// a line added above: code moved down"]
                                                            + lines[1:]) + "\n")
        src = Sources(r.root)
        cur = [{"id": "S05-001", "file": "Controllers/UserController.php", "line_start": 38, "line_end": 45,
                "cwe": "CWE-862", "category": "access-control", "owasp": "A01", "status": "verified", "severity": "medium",
                "title": "Role change without permission check", "fp": src.hashes("Controllers/UserController.php", 38, 45)}]
        run, st = self._runs(r, old)
        d = diff_runs(run, {"findings": cur}, st, {"scope": {"kind": "full"}})
        self.assertEqual(d["gone"], [])
        self.assertEqual((cur[0]["delta"], cur[0]["baseline_id"], cur[0]["baseline_severity"]),
                         ("persisting", "S05-001", "high"))
        self.assertEqual([(c["baseline_id"], c["from"], c["to"]) for c in d["severity_changed"]],
                         [("S05-001", "high", "medium")])

    def test_report_lists_severity_change_and_possible_miss(self):
        # report.md, "Changes Since Previous Run": a downgraded finding is shown as a severity change,
        # never as gone; a finding matched only by CWE elsewhere stays a possible miss in Coverage Gaps
        import findings
        r = Repo(self)
        r.write("a.php", "<?php\nfunction updateRate($rateId, $data) {\n  return Rate::find($rateId)->update($data);\n}\n")
        r.write("b.php", "<?php\nfunction updateUser($request) {\n  $user->assignRole($request->input('role'));\n"
                         "  return $user->save();\n}\n")
        src = Sources(r.root)
        base = {"owasp": "A01", "category": "access-control", "status": "verified", "kind": "vulnerability",
                "evidence": "e", "attack_scenario": "a", "impact": "i", "fix": "f", "confidence": "high",
                "requires": "user", "sources": ["S1"], "from_hits": [], "priority": 1}
        old = [{**base, "id": "OLD-RATE", "title": "rate IDOR", "file": "a.php", "line_start": 2, "line_end": 3,
                "cwe": "CWE-639", "severity": "high", "fp": src.hashes("a.php", 2, 3)},
               {**base, "id": "OLD-ROLE", "title": "role change", "file": "b.php", "line_start": 2, "line_end": 4,
                "cwe": "CWE-269", "severity": "high", "fp": src.hashes("b.php", 2, 4)}]
        cur = [{**base, "id": "NEW-ROLE", "title": "role change", "file": "b.php", "line_start": 3, "line_end": 3,
                "cwe": "CWE-862", "severity": "medium", "fp": src.hashes("b.php", 3)},
               {**base, "id": "NEW-OTHER", "title": "other IDOR", "file": "c.php", "line_start": 1, "line_end": 1,
                "cwe": "CWE-639", "severity": "high", "fp": []}]
        run, st = self._runs(r, old)
        run.mkdir(exist_ok=True)
        (run / "state.json").write_text(json.dumps(st))
        (run / "inventory.json").write_text(json.dumps({"root": str(r.root), "scope": {"kind": "full"}, "files": []}))
        (run / "merged.json").write_text(json.dumps({"findings": cur}))
        findings.cmd_report(run)
        md = (run / "report.md").read_text(encoding="utf-8")
        changes = md.split("## Changes Since Previous Run")[1].split("\n## ")[0]
        self.assertIn("| OLD-ROLE | NEW-ROLE | role change |", changes)
        self.assertIn("high → medium", changes)
        gone_rows = [l for l in changes.split("No longer reported:")[1].splitlines() if l.startswith("| OLD")]
        self.assertEqual([l.split("|")[1].strip() for l in gone_rows], ["OLD-RATE"])
        gaps = md.split("## Coverage Gaps")[1].split("\n## ")[0]
        self.assertIn("OLD-RATE", gaps)

    def test_no_baseline(self):
        r = Repo(self)
        (r.root / "run").mkdir()
        self.assertIsNone(diff_runs(r.root / "run", {"findings": []}, {"root": str(r.root), "created_at": "x"}, {}))


if __name__ == "__main__":
    unittest.main()
