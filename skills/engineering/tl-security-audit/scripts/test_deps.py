#!/usr/bin/env python3
"""Tests for deps.py's govulncheck -json parsing (reachability levels).

    python3 test_deps.py
"""
import json
import unittest

from deps import parse_govulncheck
from findings import dep_impact


def msg(osv, *frames, fixed="v1.2.3"):
    return json.dumps({"finding": {"osv": osv, "fixed_version": fixed, "trace": list(frames)}}, indent=2)


MOD = {"module": "golang.org/x/net", "version": "v0.1.0"}
PKG = {**MOD, "package": "golang.org/x/net/html"}
SYM = {**PKG, "function": "Parse", "position": {"line": 10}}
MAIN = {"module": "example.com/app", "package": "example.com/app", "function": "main"}

# A symbol-level scan: config/progress/osv messages, then module, package and symbol findings
# (one per call stack) for GO-1, and only module + package findings for GO-2 (imported, not called).
STREAM = "\n".join([
    json.dumps({"config": {"protocol_version": "v1.0.0", "scan_level": "symbol"}}, indent=2),
    json.dumps({"progress": {"message": "Scanning your code..."}}, indent=2),
    json.dumps({"osv": {"id": "GO-1", "details": "x { y }"}}, indent=2),
    msg("GO-1", MOD), msg("GO-1", PKG), msg("GO-1", SYM, MAIN), msg("GO-1", SYM, {**MAIN, "function": "run"}),
    msg("GO-2", {**MOD, "module": "golang.org/x/text"}),
    msg("GO-2", {**PKG, "module": "golang.org/x/text", "package": "golang.org/x/text/language"}),
    msg("GO-3", {**MOD, "module": "example.com/lib"}, fixed=""),
])


class Govulncheck(unittest.TestCase):
    def setUp(self):
        self.by = {(v["package"], v["advisory"]): v for v in parse_govulncheck(STREAM)}

    def test_one_entry_per_module_and_advisory(self):
        self.assertEqual(len(self.by), 3)

    def test_called_symbol_is_reachable(self):
        v = self.by[("golang.org/x/net", "GO-1")]
        self.assertEqual((v["reachability"], v["severity"]), ("symbol", "high"))
        self.assertEqual(v["summary"], "reachable (call path found)")
        self.assertEqual(v["fixed_in"], "v1.2.3")

    def test_imported_not_called_is_not_reachable(self):
        v = self.by[("golang.org/x/text", "GO-2")]
        self.assertEqual((v["reachability"], v["severity"]), ("package", "medium"))
        self.assertEqual(v["summary"], "imported, not called")

    def test_required_module_only(self):
        v = self.by[("example.com/lib", "GO-3")]
        self.assertEqual((v["reachability"], v["severity"]), ("module", "low"))

    def test_impact_names_reachability(self):
        self.assertIn("call path", dep_impact([self.by[("golang.org/x/net", "GO-1")]]))
        self.assertIn("imported but no vulnerable symbol", dep_impact([self.by[("golang.org/x/text", "GO-2")]]))
        self.assertIn("Depends on", dep_impact([{"tool": "npm audit"}]))

    def test_garbage_and_empty(self):
        self.assertEqual(parse_govulncheck(""), [])
        self.assertEqual(parse_govulncheck(None), [])
        self.assertEqual(len(parse_govulncheck("not json\n" + msg("GO-9", SYM))), 1)


if __name__ == "__main__":
    unittest.main()
