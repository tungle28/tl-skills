#!/usr/bin/env python3
"""Tests for the taint phase's engine handling: inventory-driven excludes, the bounded process tree
(timeout / memory limit kill every engine process) and Vue/Svelte single-file components.

    python3 test_taint.py

Most tests use a fake engine (a Python program) and need no OpenGrep; the one end-to-end test of a
.vue flow runs only when OpenGrep or Semgrep is installed.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import proctree
import taint
from engine import find_engine

SCRIPTS = Path(__file__).resolve().parent

# Run as `python scan --config ... <targets>` from a folder holding scan/__main__.py, so the argv the
# pipeline builds for the real engine reaches this program unchanged.
FAKE_ENGINE = r'''
import json, os, subprocess, sys, time
log = os.environ.get("FAKE_ENGINE_LOG")
if log:
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(sys.argv[1:]) + "\n")
mode = os.environ.get("FAKE_ENGINE_MODE", "ok")
if mode == "hang":
    # like opengrep-core: a worker that inherits the engine's stdout and outlives a killed parent
    subprocess.Popen([sys.executable, "-c",
                      "import sys, time; time.sleep(4); open(sys.argv[1], 'w').write('still alive')",
                      os.environ["FAKE_ENGINE_MARKER"]])
    time.sleep(60)
if mode == "eat":
    hog = []
    try:
        for _ in range(60):
            hog.append(bytearray(20 * 1024 * 1024))
            time.sleep(0.05)
    except MemoryError:
        pass
    time.sleep(60)
if mode == "eat-and-exit":  # a short scan over the limit: done before any memory poll could see it
    hog = []
    try:
        for _ in range(15):
            hog.append(bytearray(20 * 1024 * 1024))
    except MemoryError:
        pass
    print(json.dumps({"results": [{"check_id": "x"}], "errors": []}))
    sys.exit(0)
if mode == "workers-eat-and-exit":  # like OpenGrep workers: each below the cap, together above it
    code = ("import time\ntry:\n    hog = bytearray(80 * 1024 * 1024)\nexcept MemoryError:\n    pass\n"
            "time.sleep(0.5)\n")
    workers = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(3)]
    for w in workers:
        w.wait()
    print(json.dumps({"results": [{"check_id": "x"}], "errors": []}))
    sys.exit(0)
print(json.dumps({"results": [], "errors": []}))
'''
FAKE = {"exe": sys.executable, "kind": "opengrep", "version": "fake", "intrafile": True}


class FakeEngineCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        (self.tmp / "scan").mkdir()
        (self.tmp / "scan" / "__main__.py").write_text(FAKE_ENGINE, encoding="utf-8")
        cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, cwd)
        self.log = self.tmp / "argv.jsonl"
        env = mock.patch.dict(os.environ, {"FAKE_ENGINE_LOG": str(self.log), "FAKE_ENGINE_MODE": "ok",
                                           "FAKE_ENGINE_MARKER": str(self.tmp / "marker")})
        env.start()
        self.addCleanup(env.stop)

    def calls(self):
        return [json.loads(l) for l in self.log.read_text(encoding="utf-8").splitlines()] if self.log.exists() else []


def excludes_of(argv):
    return [argv[i + 1] for i, x in enumerate(argv) if x == "--exclude"]


class SkippedFilesAreExcluded(FakeEngineCase):
    """Bug: taint ran OpenGrep on the repo root excluding only vendor roots and `*.min.js`, so a
    minified bundle the inventory had skipped (agoyu resources/assets/core/js/core.js, 695 KB on one
    line, no `.min`) was still parsed and stalled the JavaScript round."""

    def test_minified_bundle_skipped_by_inventory_is_passed_as_exclude(self):
        repo, run = self.tmp / "repo", self.tmp / "run"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "app.js").write_text("const express = require('express');\n"
                                             "function h(req, res) { res.send(req.query.q); }\n", encoding="utf-8")
        bundle = repo / "resources" / "assets" / "core" / "js" / "core.js"
        bundle.parent.mkdir(parents=True)
        bundle.write_text("!function(t){" + "var a=t.x||{};" * 400 + "}(window);\n", encoding="utf-8")
        subprocess.run([sys.executable, str(SCRIPTS / "inventory.py"), "--root", str(repo), "--run-dir", str(run)],
                       check=True, capture_output=True)
        with mock.patch.object(taint, "find_engine", return_value=FAKE):
            taint.cmd_run(SimpleNamespace(run_dir=str(run), depth=1, max_targets=10, timeout=5,
                                          include_vendor=False, max_memory_mb=0))
        calls = self.calls()
        self.assertTrue(calls, "engine was not run")
        for argv in calls:
            self.assertIn("resources/assets/core/js/core.js", excludes_of(argv))
            self.assertNotIn("src/app.js", excludes_of(argv))

    def test_taint_excludes_rules(self):
        inv = {"vendor_roots": ["public/themes"], "exclude_globs": ["docs/*"],
               "skipped_files": [{"path": "a/core.js", "lang": "javascript", "reason": "minified"},
                                 {"path": "public/themes/x/big.js", "lang": "javascript", "reason": "large"},
                                 {"path": "lib/x.min.js", "lang": "javascript", "reason": "generated"},
                                 {"path": "data/huge.sql", "lang": "sql", "reason": "large"},
                                 {"path": "a/[id]/!page.js", "lang": "javascript", "reason": "minified"}]}
        pats, left = taint.taint_excludes(inv, {"javascript", "php"})
        self.assertEqual(left, 0)
        self.assertIn("public/themes", pats)
        self.assertIn("docs/*", pats)
        self.assertIn("*.min.js", pats)
        self.assertIn("a/core.js", pats)
        self.assertIn(r"a/\[id\]/!page.js", pats)  # gitignore metacharacters taken literally
        self.assertNotIn("public/themes/x/big.js", pats)  # already under an excluded vendor root
        self.assertNotIn("lib/x.min.js", pats)  # covered by *.min.js
        self.assertNotIn("data/huge.sql", pats)  # not a taint language
        pats, _ = taint.taint_excludes(inv, {"javascript"}, include_vendor=True)
        self.assertIn("public/themes/x/big.js", pats)

    def test_command_line_budget(self):
        inv = {"skipped_files": [{"path": f"very/long/folder/name/number/{i:05d}/bundle.js", "lang": "javascript"}
                                 for i in range(2000)]}
        pats, left = taint.taint_excludes(inv, {"javascript"})
        self.assertGreater(left, 0)
        self.assertLessEqual(sum(len(p) + 12 for p in pats if p.startswith("very/")), taint.EXCLUDE_ARG_BUDGET)


class BoundedEngineRun(FakeEngineCase):
    """Bug: run_engine used subprocess.run(timeout=...), which kills the direct child only. The
    OpenGrep worker kept the stdout pipe open, so a 1200 s timeout returned after ~3 hours (agoyu run
    20261104: round0_javascript "timed out after 1200s", phase took 10563 s)."""

    def test_timeout_kills_the_whole_tree_and_returns_at_once(self):
        os.environ["FAKE_ENGINE_MODE"] = "hang"
        t0 = time.time()
        res, errs, _ = taint.run_engine(FAKE, [], self.tmp, self.tmp, "round0_javascript", 20, wall=2)
        took = time.time() - t0
        self.assertLess(took, 15, f"run_engine returned after {took:.1f}s")
        self.assertEqual(res, [])
        self.assertTrue(any("timed out after 2s" in e and "process tree killed" in e for e in errs), errs)
        time.sleep(max(0.0, 6 - (time.time() - t0)))  # the worker would write its marker after 4 s
        self.assertFalse((self.tmp / "marker").exists(), "the engine's worker process survived the timeout")

    def test_memory_limit_kills_the_tree(self):
        os.environ["FAKE_ENGINE_MODE"] = "eat"
        t0 = time.time()
        res, errs, _ = taint.run_engine(FAKE, [], self.tmp, self.tmp, "round0_php", 20, wall=40, max_memory_mb=150)
        self.assertLess(time.time() - t0, 30)
        self.assertTrue(any("memory limit of 150 MB" in e for e in errs), errs)
        argv = self.calls()[0]
        self.assertEqual(argv[argv.index("--max-memory") + 1], "150")  # the engine's own cap, too

    def test_memory_limit_fails_closed_when_the_tree_cannot_be_measured(self):
        # review r1: when the Job object could not be created/assigned (Windows) or `ps` is missing
        # (POSIX), the tree's memory was not measured and the limit silently became the engine's
        # per-file cap only. Now the run stops and says so; --max-memory-mb 0 opts out.
        os.environ["FAKE_ENGINE_MODE"] = "hang"
        unmeasurable = [mock.patch.object(proctree, "_Job", side_effect=OSError("no job object")),
                        mock.patch.object(proctree, "_group_rss_mb", return_value=None)]
        for p in unmeasurable:
            p.start()
            self.addCleanup(p.stop)
        t0 = time.time()
        res, errs, _ = taint.run_engine(FAKE, [], self.tmp, self.tmp, "round0_javascript", 20, wall=30,
                                        max_memory_mb=500)
        self.assertLess(time.time() - t0, 15)
        self.assertEqual(res, [])
        self.assertTrue(any("could not be enforced" in e and "process tree killed" in e for e in errs), errs)
        time.sleep(max(0.0, 6 - (time.time() - t0)))
        self.assertFalse((self.tmp / "marker").exists(), "the engine's worker process survived")
        os.environ["FAKE_ENGINE_MODE"] = "ok"  # without a limit there is nothing to enforce: it runs
        res, errs, _ = taint.run_engine(FAKE, [], self.tmp, self.tmp, "ok", 20, wall=30, max_memory_mb=0)
        self.assertEqual((res, errs), ([], []))

    def exit_before_first_poll(self):
        """Make the engine finish before run_tree's poll loop starts: deterministic, not a race."""
        if proctree.WINDOWS:  # Job assigned while the process runs, then it ends before the loop
            assign = proctree._Job.assign

            def assign_then_wait(job, proc):
                ok = assign(job, proc)
                proc.wait()
                return ok
            p = mock.patch.object(proctree._Job, "assign", assign_then_wait)
        else:
            popen = subprocess.Popen

            def popen_then_wait(*a, **k):
                proc = popen(*a, **k)
                proc.wait()
                return proc
            p = mock.patch.object(proctree.subprocess, "Popen", side_effect=popen_then_wait)
        p.start()
        self.addCleanup(p.stop)

    def test_fast_exit_without_measurement_still_fails_closed(self):
        # review r2: an engine that exited before the first poll skipped the "unmeasured" check and its
        # output was accepted although the limit was never enforced
        os.environ["FAKE_ENGINE_MODE"] = "ok"
        popen = subprocess.Popen

        def popen_then_wait(*a, **k):
            proc = popen(*a, **k)
            proc.wait()
            return proc
        for p in (mock.patch.object(proctree, "_Job", side_effect=OSError("no job object")),
                  mock.patch.object(proctree, "_group_rss_mb", return_value=None),
                  mock.patch.object(proctree.subprocess, "Popen", side_effect=popen_then_wait)):
            p.start()
            self.addCleanup(p.stop)
        r = proctree.run_tree([sys.executable, "scan"], 30, max_memory_mb=500)
        self.assertEqual(r["killed"], "unmeasured")
        res, errs, _ = taint.run_engine(FAKE, [], self.tmp, self.tmp, "round0_php", 20, wall=30, max_memory_mb=500)
        self.assertEqual(res, [])
        self.assertTrue(any("could not be enforced" in e for e in errs), errs)

    @unittest.skipUnless(proctree.WINDOWS, "an enforced whole-tree limit needs a Windows Job object")
    def test_fast_exit_over_the_limit_is_a_memory_kill(self):
        # review r2: with the tree measured, a peak over the limit reached by a run that ended before
        # the first poll was never compared with the limit, and its results were accepted
        os.environ["FAKE_ENGINE_MODE"] = "eat-and-exit"
        self.exit_before_first_poll()
        res, errs, _ = taint.run_engine(FAKE, [], self.tmp, self.tmp, "round0_php", 20, wall=30, max_memory_mb=150)
        self.assertEqual(res, [])
        self.assertTrue(any("exceeded the memory limit of 150 MB" in e for e in errs), errs)

    def test_fast_exit_with_workers_together_over_the_limit(self):
        # review r3: three workers of 80 MB each (below the 150 MB cap alone, above it together) in a
        # run that ends before the first poll. r2 accepted it on POSIX on the strength of getrusage,
        # the peak of one reaped child. Windows: the Job object sees the whole tree -> memory kill.
        # POSIX: there is no whole-tree limit, so the result says "sampled" instead of claiming one.
        os.environ["FAKE_ENGINE_MODE"] = "workers-eat-and-exit"
        self.exit_before_first_poll()
        r = proctree.run_tree([sys.executable, "scan"], 30, max_memory_mb=150)
        if proctree.WINDOWS:
            self.assertEqual((r["killed"], r["memory_limit"]), ("memory", "enforced"))
            self.assertGreaterEqual(r["peak_memory_mb"], 150)
        else:
            self.assertEqual((r["killed"], r["memory_limit"]), (None, "sampled"))

    def test_sampled_memory_limit_is_a_coverage_gap(self):
        # how a POSIX run is reported, checked on every platform
        sampled = {"returncode": 0, "killed": None, "seconds": 0.1, "peak_memory_mb": 10, "memory_limit": "sampled",
                   "stdout": json.dumps({"results": [], "errors": []}), "stderr": ""}
        spec = {"language": "javascript", "engine_languages": ["javascript"], "inventory_languages": ["javascript"],
                "function_scopes": ["function $SAFN(..., $SAP, ...) { ... }"], "sources": [{"pattern": "location.hash"}],
                "sinks": {"xss": {"title": "t", "owasp": "A05", "cwe": "CWE-79", "severity": "high", "message": "m",
                                  "fix": "f", "sinks": [{"pattern": "$EL.innerHTML = $X"}]}}}
        with mock.patch.object(taint, "run_tree", return_value=sampled):
            r = taint.analyze(self.tmp, {"javascript": spec}, FAKE, self.tmp, {"javascript": ["a.js"]}, depth=1,
                              max_memory_mb=150)
        self.assertEqual(r["stats"]["memory_limit"], "sampled")
        self.assertTrue(any("only sampled" in g for g in r["gaps"]), r["gaps"])

    def test_run_that_reached_the_limit_is_a_partial_gap(self):
        # a run that finished at the limit kept its results: the gap says "may be missing", not "missing"
        spec = {"language": "javascript", "engine_languages": ["javascript"], "inventory_languages": ["javascript"],
                "function_scopes": ["function $SAFN(..., $SAP, ...) { ... }"], "sources": [{"pattern": "location.hash"}],
                "sinks": {"xss": {"title": "t", "owasp": "A05", "cwe": "CWE-79", "severity": "high", "message": "m",
                                  "fix": "f", "sinks": [{"pattern": "$EL.innerHTML = $X"}]}}}
        reached = ([], ["round0_javascript: engine reached the memory limit of 150 MB, some files may be missing"], 0.1)
        with mock.patch.object(taint, "run_engine", return_value=reached):
            r = taint.analyze(self.tmp, {"javascript": spec}, FAKE, self.tmp, {"javascript": ["a.js"]}, depth=1,
                              max_memory_mb=150)
        gaps = [g for g in r["gaps"] if "round0_javascript" in g]
        self.assertTrue(gaps and all("may be missing" in g and "its flows are missing" not in g for g in gaps), gaps)

    def test_normal_run_returns_results(self):
        meter = {}
        res, errs, _ = taint.run_engine(FAKE, [], self.tmp, self.tmp, "ok", 20, wall=30, meter=meter)
        self.assertEqual((res, errs), ([], []))

    def test_killed_round_is_a_coverage_gap(self):
        os.environ["FAKE_ENGINE_MODE"] = "hang"
        spec = {"language": "javascript", "engine_languages": ["javascript"], "inventory_languages": ["javascript"],
                "function_scopes": ["function $SAFN(..., $SAP, ...) { ... }"], "sources": [{"pattern": "location.hash"}],
                "sinks": {"xss": {"title": "t", "owasp": "A05", "cwe": "CWE-79", "severity": "high", "message": "m",
                                  "fix": "f", "sinks": [{"pattern": "$EL.innerHTML = $X"}]}}}
        r = taint.analyze(self.tmp, {"javascript": spec}, FAKE, self.tmp, {"javascript": ["a.js"]}, depth=1, wall=2)
        self.assertTrue(any("round0_javascript" in g and "flows are missing" in g for g in r["gaps"]), r["gaps"])


VUE = """<template>
  <div>
    <input v-model="q" />
    <div ref="out"></div>
  </div>
</template>

<script>
export default {
  mounted() {
    const q = new URLSearchParams(location.search).get("q");
    this.$refs.out.innerHTML = q;
  },
};
</script>

<style scoped>
div { color: red; }
</style>
"""


class SingleFileComponents(unittest.TestCase):
    """Bug: OpenGrep does not read .vue files, so a Vue-only repository (agoyu front-end-components,
    run 20261116-114409-fec, 35 .vue files) got 0 taint flows reported as a clean run."""

    def test_script_kept_at_its_lines_rest_blanked(self):
        code, lang = taint.sfc_script(VUE)
        self.assertEqual(lang, "javascript")
        src, out = VUE.splitlines(), code.splitlines()
        self.assertEqual(len(out), len(src))
        self.assertEqual(out[11], src[11])  # this.$refs.out.innerHTML = q;
        self.assertNotIn("template", code)
        self.assertNotIn("color", code)
        self.assertNotIn("<script", code)
        code, lang = taint.sfc_script('<script setup lang="ts">\nconst a: number = 1;\n</script>\n')
        self.assertEqual(lang, "typescript")
        self.assertEqual(taint.sfc_script("<template><p/></template>\n"), (None, None))

    def test_tsx_script_keeps_the_tsx_parser(self):
        # review r1: lang="tsx" was mirrored as .ts, so the engine parsed JSX with the TypeScript parser
        self.assertEqual(taint.sfc_script('<script lang="tsx">\nconst a = <b>{x}</b>;\n</script>\n')[1], "tsx")
        self.assertEqual(taint.sfc_script('<script lang="ts">\nexport type A = 1;\n</script>\n'
                                          '<script setup lang="tsx">\nconst a = <b/>;\n</script>\n')[1], "tsx")
        self.assertEqual(taint.sfc_script('<script lang="typescript">\nlet a = 1;\n</script>\n')[1], "typescript")
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as mirror:
            Path(root, "A.vue").write_text('<script lang="tsx">\nconst a = <b>{x}</b>;\n</script>\n', encoding="utf-8")
            taint.build_sfc_mirror(root, ["A.vue"], mirror)
            out = Path(mirror) / "A.vue.tsx"
            self.assertTrue(out.exists())
            self.assertEqual(taint.rel(root, str(out), mirror), "A.vue")

    def test_mirror_paths_map_back_to_the_component(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as mirror:
            (Path(root) / "src").mkdir()
            (Path(root) / "src" / "Search.vue").write_text(VUE, encoding="utf-8")
            texts = taint.build_sfc_mirror(root, ["src/Search.vue", "src/app.js"], mirror)
            self.assertEqual(list(texts), ["src/Search.vue"])
            out = Path(mirror) / "src" / "Search.vue.js"
            self.assertTrue(out.exists())
            self.assertEqual(taint.rel(root, str(out), mirror), "src/Search.vue")
            self.assertEqual(taint.rel(root, str(Path(root) / "src" / "app.js"), mirror), "src/app.js")

    @unittest.skipUnless(find_engine(), "needs OpenGrep or Semgrep (scripts/engine.py install)")
    def test_flow_inside_a_vue_component_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, run = Path(tmp) / "repo", Path(tmp) / "run"
            (repo / "src").mkdir(parents=True)
            (repo / "src" / "Search.vue").write_text(VUE, encoding="utf-8")
            subprocess.run([sys.executable, str(SCRIPTS / "inventory.py"), "--root", str(repo), "--run-dir", str(run)],
                           check=True, capture_output=True)
            taint.cmd_run(SimpleNamespace(run_dir=str(run), depth=1, max_targets=10, timeout=20,
                                          include_vendor=False, max_memory_mb=0))
            doc = json.loads((run / "scan" / "taint.json").read_text(encoding="utf-8"))
            self.assertIn(("src/Search.vue", 12, "xss"), [(h["file"], h["line"], h["taint_kind"]) for h in doc["hits"]],
                          doc.get("errors"))
            self.assertTrue(any(".vue/.svelte" in g for g in doc["gaps"]))  # templates: stated, not implied


if __name__ == "__main__":
    unittest.main()
