#!/usr/bin/env python3
"""Trigger eval against the INSTALLED skill via `claude -p` — a cross-platform run_eval.py stand-in.

skill-creator's run_eval.py polls the subprocess pipe with select(), which Windows does not support
for pipes, and it tests a temporary command copy that competes with an installed skill of the same
description. This runner reads the stream line by line (works everywhere) and counts a trigger when
the named skill is invoked (Skill tool, or a Read of its installed SKILL.md outside cwd) within the
first few tool calls.
Install the version under test first; its installed description is what gets measured.

  python run_trigger.py --evals trigger_evals.json --skill tl-goal-griller --cwd <repo> --out trigger_run.json

Output is run_eval.py-compatible (feed it to trigger_metrics.py), plus a per-run "fired" list that
names whatever skill or tool ran instead — the near-miss owners, which is useful for the scorecard.
"""
import argparse, json, os, shutil, subprocess, sys, threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import read_json, utf8_stdio, write_json  # noqa: E402

MAX_TOOLS = 15  # the model often explores the repo for 5-8 calls before consulting a skill


def find_claude(override=None):
    if override:
        return override
    exe = shutil.which("claude")
    if not exe:
        sys.exit("claude CLI not found on PATH (install: npm i -g @anthropic-ai/claude-code) — "
                 "mark trigger metrics `not measured` instead of estimating them")
    # On Windows the npm shim is a .cmd; cmd.exe re-parses its arguments, which mangles queries
    # containing quotes, & or non-ASCII text. Call the real binary behind the shim instead.
    if exe.lower().endswith((".cmd", ".bat")):
        real = Path(exe).parent / "node_modules" / "@anthropic-ai" / "claude-code" / "bin" / "claude.exe"
        if real.exists():
            return str(real)
    return exe


def run_query(claude, query, skill, cwd, timeout, model, max_tools=MAX_TOOLS):
    cmd = [claude, "-p", query, "--output-format", "stream-json", "--verbose"]
    if model:
        cmd += ["--model", model]
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}  # allow nesting in a session
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                         cwd=cwd, env=env)
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    tools = []
    try:
        for raw in p.stdout:
            try:
                ev = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                continue
            if ev.get("type") == "assistant":
                for c in ev.get("message", {}).get("content", []):
                    if c.get("type") != "tool_use":
                        continue
                    name, inp = c.get("name", ""), c.get("input", {})
                    if name == "Skill":
                        tools.append("skill:" + str(inp.get("skill", "")))
                    elif name == "Read" and is_skill_read(str(inp.get("file_path", "")), cwd):
                        tools.append("read:" + str(inp.get("file_path", "")))
                    else:
                        tools.append("tool:" + name)
                if any(t.startswith(("skill:", "read:")) for t in tools) or len(tools) >= max_tools:
                    break
            elif ev.get("type") == "result":
                break
    finally:
        timer.cancel()
        if p.poll() is None:
            p.kill()
    skills = [t for t in tools if t.startswith(("skill:", "read:"))]
    fired = skills[0] if skills else ("none" if not tools else "no-skill(" + ",".join(tools) + ")")
    return bool(skills) and fired_name(fired) == skill, fired


def is_skill_read(file_path, cwd):
    """A Read of an installed skill's SKILL.md, not of a project file that happens to be one.

    A SKILL.md inside cwd is the user's work (e.g. the skill being evaluated), so reading it is an
    ordinary tool call and must not end the run or count as the model consulting a skill."""
    if Path(file_path).name != "SKILL.md":
        return False
    try:
        Path(file_path).resolve().relative_to(Path(cwd).resolve())
        return False
    except ValueError:
        return True


def fired_name(fired):
    """Skill name from a "skill:<name>" or "read:<dir>/<name>/SKILL.md" entry; a plugin prefix
    ("plugin:name") is dropped. Exact names, so a path that merely contains the name doesn't match."""
    kind, _, rest = fired.partition(":")
    if kind == "skill":
        return rest.rsplit(":", 1)[-1]
    if kind == "read":
        return Path(rest).parent.name
    return ""


def evaluate(claude, items, skill, cwd, runs=3, workers=6, timeout=150, threshold=0.5, model=None,
             max_tools=MAX_TOOLS):
    """Run every query `runs` times; return run_eval.py-shaped result rows (plus "fired")."""
    got = {i: [] for i in range(len(items))}
    with ThreadPoolExecutor(workers) as ex:
        futs = {ex.submit(run_query, claude, it["query"], skill, cwd, timeout, model, max_tools): i
                for i, it in enumerate(items) for _ in range(runs)}
        for f, i in futs.items():
            got[i].append(f.result())
    results = []
    for i, it in enumerate(items):
        trig = [t for t, _ in got[i]]
        rate = sum(trig) / len(trig)
        results.append({"query": it["query"], "should_trigger": it["should_trigger"],
                        "trigger_rate": rate, "triggers": sum(trig), "runs": len(trig),
                        "pass": (rate >= threshold) == bool(it["should_trigger"]),
                        "fired": [w for _, w in got[i]]})
    return results


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser()
    ap.add_argument("--evals", required=True, type=Path)
    ap.add_argument("--skill", required=True, help="installed skill name to detect")
    ap.add_argument("--cwd", required=True, help="project dir the queries run in (e.g. a fixture repo)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=150, help="seconds per query run")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--model")
    ap.add_argument("--max-tools", type=int, default=MAX_TOOLS,
                    help="non-skill tool calls before a run counts as not triggered")
    ap.add_argument("--claude", help="path to the claude executable (default: found on PATH)")
    a = ap.parse_args()

    items = read_json(a.evals)
    items = items.get("evals", items) if isinstance(items, dict) else items
    results = evaluate(find_claude(a.claude), items, a.skill, a.cwd, a.runs, a.workers, a.timeout,
                       a.threshold, a.model, a.max_tools)
    summary = {"total": len(results), "passed": sum(r["pass"] for r in results),
               "failed": sum(not r["pass"] for r in results)}
    write_json(a.out, {"skill_name": a.skill, "runner": "tl-skill-eval run_trigger.py (installed skill)",
                       "results": results, "summary": summary})
    print(summary)


if __name__ == "__main__":
    main()
