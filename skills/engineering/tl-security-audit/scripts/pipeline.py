#!/usr/bin/env python3
"""Pipeline entry point. State lives on disk so a run can be resumed after a crash, a context
reset, or a sub-agent failure, and every phase's output can be inspected.

  pipeline.py init   --root <repo> [--mode audit|fix] [--lang vi|en|...] [--authorization "..."]
                    [--rules-dir D]... [--semgrep-dir D]... [--run-dir D] [inventory opts...]
  pipeline.py run    <inventory|taint|scan|deps|merge|verify-queue|report> --run-dir D [phase opts]
  pipeline.py run    <scripted|collect|finish> --run-dir D   (composites: phases 1-3 / merge+queue / report)
  pipeline.py run    extend-shards --run-dir D --max-shards N (0 = all): change the review cap after
                    the scan; re-ranks and rewrites shards.json, keeping finished shard files
  pipeline.py status --run-dir D
  pipeline.py mark   <phase> <status> --run-dir D [--note ...]
"""
import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from common import PHASES, load_state, mark, read_json, save_state, now_iso, write_json

HERE = Path(__file__).resolve().parent
LARGE_LOC = 60_000
LARGE_SHARDS = 24
SOLO_LOC = 5_000
SCRIPTED = ("inventory", "taint", "scan", "deps", "merge", "verify-queue", "report")


def sh(script, *args):
    return subprocess.run([sys.executable, str(HERE / script), *args], cwd=HERE).returncode == 0


def cmd_init(a, extra):
    root = Path(a.root).resolve()
    run = Path(a.run_dir) if a.run_dir else root / ".security-run" / datetime.now().strftime("%Y%m%d-%H%M%S")
    run.mkdir(parents=True, exist_ok=True)
    for d in ("findings", "verification", "scan"):
        (run / d).mkdir(exist_ok=True)
    save_state(run, {"root": str(root), "mode": a.mode, "lang": a.lang, "created_at": now_iso(),
                     "authorization": a.authorization, "rules_dirs": [str(Path(d).resolve()) for d in a.rules_dir],
                     "semgrep_dirs": [str(Path(d).resolve()) for d in a.semgrep_dir],
                     "inventory_args": extra,
                     **({"baseline": str(Path(a.baseline).resolve())} if a.baseline else {}), "phases": {p: {"status": "pending"} for p in PHASES}})
    print(f"RUN_DIR={run}")
    print(f"LANG={a.lang}")
    exclude_run_dir(root, run)


def exclude_run_dir(root, run):
    """Keep the run dir (it maps where the weaknesses are) out of `git status` and out of any
    accidental commit, without touching a tracked file: add it to .git/info/exclude (local-only).
    A clean tree is also a precondition of fix mode."""
    try:
        rel = run.resolve().relative_to(root)
    except ValueError:
        return  # run dir outside the repo
    try:
        git_dir = subprocess.run(["git", "-C", str(root), "rev-parse", "--git-dir"],
                                 capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("note: not a git repository — keep the run directory out of version control yourself")
        return
    entry = "/" + rel.parts[0] + "/"
    excl = (Path(git_dir) if Path(git_dir).is_absolute() else root / git_dir) / "info" / "exclude"
    lines = excl.read_text(encoding="utf-8").splitlines() if excl.exists() else []
    if entry not in lines:
        excl.parent.mkdir(parents=True, exist_ok=True)
        with open(excl, "a", encoding="utf-8") as f:
            f.write(("" if not lines or lines[-1] == "" else "\n") + entry + "\n")
        print(f"added '{entry}' to {excl.as_posix()} (local git exclude; no tracked file changed)")


def gate(run):
    inv = read_json(run / "inventory.json", {})
    shards = read_json(run / "shards.json", [])
    loc = inv.get("totals", {}).get("reviewable_loc", 0)
    if loc > LARGE_LOC or len(shards) > LARGE_SHARDS:
        print(f"GATE: large scope ({loc} LOC, {len(shards)} shards). Before review, ask the user to "
              f"narrow scope or cap review with --max-shards (top-N by risk weight after the scan).")
    try:
        from engine import find_engine
        if not find_engine():
            print("GATE: no taint engine. Ask the user before installing OpenGrep "
                  "(python3 scripts/engine.py install; on Windows: python) — in a disposable sandbox "
                  "install directly; otherwise the taint phase is skipped with a coverage gap.")
    except ImportError:
        pass
    if inv.get("totals", {}).get("files", 0) == 0:
        print("GATE: nothing to scan — check --root and excludes.")


def review_mode(run):
    """Decide who reviews and record it. A small whole-repo audit fits in one shard; a shard
    reviewer and a surface reviewer would then read the same files twice."""
    inv = read_json(run / "inventory.json", {})
    shards = read_json(run / "shards.json", [])
    scope = inv.get("scope", {})
    loc = inv.get("totals", {}).get("reviewable_loc", 0)
    if scope.get("kind", "full") != "full":
        mode = "sharded"  # changeset/module: shard reviewers only; no surface review unless asked
    elif len(shards) == 1 and loc <= SOLO_LOC and scope.get("whole_repo", True):
        mode = "solo"
    else:
        mode = "sharded"
    st = load_state(run)
    st["review_mode"] = mode
    save_state(run, st)
    print(f"REVIEW_MODE={mode}" + (f" (one shard, {loc} LOC: dispatch one surface reviewer with MODE=solo)"
                                   if mode == "solo" else ""))
    return mode


def run_phase(run, st, phase, passthrough):
    target = {"verify-queue": "verify"}.get(phase, phase)
    mark(run, target, "running")
    if phase == "inventory":
        ok = sh("inventory.py", "--root", st["root"], "--run-dir", str(run), *st.get("inventory_args", []))
    elif phase == "taint":
        ok = sh("taint.py", "--run-dir", str(run), *passthrough)
    elif phase == "scan":
        ok = sh("scan.py", "--run-dir", str(run))
    elif phase == "deps":
        ok = sh("deps.py", "--run-dir", str(run), *passthrough)
    else:  # merge, verify-queue, report
        args = list(passthrough)
        if phase == "verify-queue" and st.get("review_mode") == "solo" and "--scope" not in args:
            args += ["--scope", "strict"]
        ok = sh("findings.py", phase, "--run-dir", str(run), *args)
    status = ("queued" if phase == "verify-queue" else "done") if ok else "failed"
    if ok and phase == "taint":
        t = read_json(run / "scan" / "taint.json", {})
        if t.get("status") == "skipped":
            mark(run, target, "skipped", t.get("reason"))
            return True
    mark(run, target, status)
    if ok and phase == "inventory":
        gate(run)
    if ok and phase == "scan":
        review_mode(run)
    return ok


# Composite steps: one orchestrator turn instead of three or four.
COMPOSITE = {
    "scripted": ("inventory", "taint", "scan", "deps"),  # Phase 1-3
    "collect": ("merge", "verify-queue"),               # after all reviewers wrote their files
    "finish": ("report",),                              # after all verifiers wrote their verdicts
}
TAINT_OPTS = ("--depth", "--max-targets", "--max-memory-mb")


def cmd_run(a):
    run = Path(a.run_dir)
    st = load_state(run)
    if not st:
        sys.exit("no state.json — run 'init' first")
    phase = a.phase
    if phase == "extend-shards":
        sys.exit(0 if extend_shards(run, st, a.passthrough) else 1)
    if phase not in SCRIPTED and phase not in COMPOSITE:
        sys.exit(f"'{phase}' is not a scripted phase (review/verify/fix are done by agents); "
                 f"scripted: {', '.join(SCRIPTED)}; composite: {', '.join(COMPOSITE)}")
    if phase not in COMPOSITE:
        sys.exit(0 if run_phase(run, st, phase, a.passthrough) else 1)
    if phase == "collect":
        # --partial: shard reviewers are done, the surface reviewer is still running. Merge and queue
        # what exists so verifiers can start; the final `collect` appends batches for the rest.
        partial = "--partial" in a.passthrough
        a.passthrough = [x for x in a.passthrough if x != "--partial"]
        if partial:
            st["verify_partial"] = True
            save_state(run, st)
        else:
            mark(run, "review", "done")
        # a second collect must not renumber batches from V01 over verdicts already written
        dispatched = load_state(run).get("verify_partial") or any((run / "verification").glob("V*.json"))
        if dispatched and (run / "verify_queue.json").exists() and "--append" not in a.passthrough:
            a.passthrough = a.passthrough + ["--append"]
    if phase == "finish":
        mark(run, "verify", "done")
    taint_args, other_args, it = [], [], iter(a.passthrough)
    for x in it:  # route each option to the phase that owns it
        if x in TAINT_OPTS:
            taint_args += [x, next(it, "")]
        else:
            other_args.append(x)
    for p in COMPOSITE[phase]:
        extra = {"taint": taint_args, "deps": other_args}.get(p, []) if phase == "scripted" else a.passthrough
        print(f"== {p}")
        if not run_phase(run, load_state(run), p, extra):
            sys.exit(f"phase {p} failed — fix it, then re-run `run {p}` and continue")
    sys.exit(0)


def extend_shards(run, st, args):
    """Raise (or lift, with 0) the --max-shards cap after the scan without re-running inventory."""
    if "--max-shards" not in args or args.index("--max-shards") + 1 >= len(args):
        sys.exit("usage: run extend-shards --run-dir D --max-shards N   (0 = review all shards)")
    cap = int(args[args.index("--max-shards") + 1])
    inv = read_json(run / "inventory.json")
    if not inv:
        sys.exit("inventory.json missing — run 'scripted' first")
    if not (run / "shards_all.json").exists():
        sys.exit("shards_all.json missing (scan ran with an older version) — re-run `run scripted` "
                 "with the new --max-shards instead")
    inv["max_shards"] = cap
    inv["scope"]["max_shards"] = cap or None
    write_json(run / "inventory.json", inv)
    if not run_phase(run, st, "scan", []):
        return False
    done = {p.stem for p in (run / "findings").glob("S*.json") if parses(p)}
    todo = [s["id"] for s in read_json(run / "shards.json", []) if s["id"] not in done]
    print(f"shards to review now: {', '.join(todo) or 'none'}")
    return True


def parses(path):
    """A half-written file from a timed-out agent is not 'done' — it must be re-dispatched."""
    try:
        return read_json(path) is not None
    except ValueError:
        return False


def cmd_status(a):
    run = Path(a.run_dir)
    st = load_state(run)
    if not st:
        sys.exit("no state.json")
    print(f"root={st['root']} mode={st['mode']} lang={st.get('lang', 'en')} updated={st.get('updated_at')}")
    if st.get("authorization"):
        print(f"authorization={st['authorization']}")
    for p in PHASES:
        ph = st["phases"].get(p, {})
        print(f"  {p:<10} {ph.get('status', 'pending'):<9} {ph.get('note', '')}")
    shards = read_json(run / "shards.json", [])
    if shards:
        done = {p.stem for p in (run / "findings").glob("S*.json") if parses(p)}
        pending = [s["id"] for s in shards if s["id"] not in done]
        surf = parses(run / "findings" / "surface.json") if (run / "findings" / "surface.json").exists() else False
        mode = st.get("review_mode", "sharded")
        print(f"review ({mode}): shards done {len(shards) - len(pending)}/{len(shards)}; surface {'done' if surf else 'pending'}"
              + (" — one surface reviewer (MODE=solo) writes both" if mode == "solo" else ""))
        if pending:
            print("  pending shards:", ", ".join(pending))
    q = read_json(run / "verify_queue.json")
    if q:
        done = {p.stem for p in (run / "verification").glob("V*.json") if parses(p)}
        pend = [b["batch"] for b in q["batches"] if b["batch"] not in done]
        print(f"verify: batches done {len(q['batches']) - len(pend)}/{len(q['batches'])}"
              + (f"; pending: {', '.join(pend)}" if pend else ""))
    nxt = next((p for p in PHASES[:-1] if st["phases"].get(p, {}).get("status") not in ("done", "skipped")), None)
    print(f"next: {nxt or ('fix (only if requested)' if st['mode'] == 'fix' else 'finished')}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--root", required=True)
    i.add_argument("--mode", choices=["audit", "fix"], default="audit")
    i.add_argument("--lang", default="en", help="user's language (BCP-47) for all human-readable content")
    i.add_argument("--authorization", default="", help="who owns / authorized this audit (recorded in the report)")
    i.add_argument("--rules-dir", action="append", default=[], help="extra pattern-rule directory")
    i.add_argument("--semgrep-dir", action="append", default=[], help="extra semgrep rule directory")
    i.add_argument("--run-dir")
    i.add_argument("--baseline", help="earlier run dir to diff against (default: newest finished run of this repo)")
    r = sub.add_parser("run")
    r.add_argument("phase")
    r.add_argument("--run-dir", required=True)
    s = sub.add_parser("status")
    s.add_argument("--run-dir", required=True)
    m = sub.add_parser("mark")
    m.add_argument("phase", choices=PHASES)
    m.add_argument("status", choices=["pending", "running", "done", "failed", "skipped"])
    m.add_argument("--run-dir", required=True)
    m.add_argument("--note")
    a, extra = ap.parse_known_args()
    if a.run_dir:
        # child scripts run with cwd=HERE, so a relative --run-dir would land inside the skill folder
        a.run_dir = str(Path(a.run_dir).resolve())
    if a.cmd == "init":
        cmd_init(a, extra)
    elif a.cmd == "run":
        a.passthrough = extra
        cmd_run(a)
    elif extra:
        ap.error(f"unrecognized arguments: {extra}")
    elif a.cmd == "status":
        cmd_status(a)
    else:
        mark(Path(a.run_dir), a.phase, a.status, a.note)
        print(f"{a.phase} -> {a.status}")


if __name__ == "__main__":
    main()
