#!/usr/bin/env python3
"""Run skill-creator's description-optimization loop (run_loop.py) on Windows, unchanged.

run_loop.py itself is portable, but what it calls is not, on Windows:
  - run_eval() polls the subprocess pipe with select(), which Windows supports only for sockets;
  - improve_description() starts "claude" without a shell, so the npm .cmd shim is not found,
    and decodes its output with the console code page;
  - every read_text()/write_text() uses cp1252 and breaks on Vietnamese eval sets.
This wrapper re-executes itself in UTF-8 mode, imports skill-creator's run_loop, swaps in a
line-reading run_eval (from run_trigger.py) and a portable claude call, then hands over to
run_loop.main() with the remaining arguments. The loop logic, report and output are skill-creator's.

A candidate description is tested through one temporary project command, as run_eval.py does.
An installed skill with the same name competes with it and skews the score, so the wrapper refuses
to start while one is installed unless --hide-installed is given: that moves the installed copy
out of the skills directory for the run and always moves it back (also after a crash, next start).

  python run_loop_compat.py --hide-installed -- --eval-set trigger_evals.json \
      --skill-path <skill> --model <model-id> --max-iterations 5 --timeout 150 --verbose
"""
import argparse, json, os, shutil, subprocess, sys, uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
HIDE_ROOT = Path.home() / ".claude" / ".tl-skill-eval-hidden"
MIN_TIMEOUT = 120  # run_trigger scans the first tool calls; run_loop's default of 30s is too short


def reexec_utf8():
    if not sys.flags.utf8_mode:
        sys.exit(subprocess.call([sys.executable, "-X", "utf8", *sys.argv]))


def find_skill_creator(explicit):
    if explicit:
        cands = [Path(explicit)]
    else:
        home = Path.home() / ".claude"
        cands = [home / "skills" / "skill-creator", Path.cwd() / ".claude" / "skills" / "skill-creator"]
        for pat in ("*/skill-creator", "*/*/skill-creator"):                  # synced skill bundles
            cands += sorted((home / "skills").glob(pat))
        cands += sorted((home / "plugins").glob("**/skill-creator"))         # plugin installs
    for c in cands:
        if (c / "scripts" / "run_loop.py").exists() and ".trash" not in c.parts:
            return c
    sys.exit("skill-creator not found; pass --skill-creator <dir containing scripts/run_loop.py>")


class HiddenInstalls:
    """Move installed copies of the skill out of every skills dir for the run; always restore."""

    def __init__(self, name, project_root):
        self.name = name
        dirs = [Path.home() / ".claude" / "skills", Path(project_root) / ".claude" / "skills"]
        # project_root can be the home dir itself (find_project_root walks up to ~/.claude)
        self.dirs = list({d.resolve(): d for d in dirs}.values())
        self.moved = []

    def installed(self):
        return [d / self.name for d in self.dirs if (d / self.name / "SKILL.md").exists()]

    @staticmethod
    def restore_stale():
        if not HIDE_ROOT.exists():
            return
        for rec in HIDE_ROOT.glob("*.json"):
            info = json.loads(rec.read_text(encoding="utf-8"))
            src, dst = Path(info["stash"]), Path(info["origin"])
            if src.exists() and not dst.exists():
                shutil.move(str(src), str(dst))
                print(f"restored {dst} (hidden by an interrupted earlier run)", file=sys.stderr)
            rec.unlink()

    def __enter__(self):
        HIDE_ROOT.mkdir(parents=True, exist_ok=True)
        try:
            for origin in self.installed():
                key = uuid.uuid4().hex[:8]
                stash = HIDE_ROOT / f"{self.name}-{key}"
                (HIDE_ROOT / f"{key}.json").write_text(
                    json.dumps({"origin": str(origin), "stash": str(stash)}), encoding="utf-8")
                shutil.move(str(origin), str(stash))
                self.moved.append((origin, stash, key))
                print(f"hid installed {origin} for the run", file=sys.stderr)
        except BaseException:
            self.__exit__()  # a with-block never calls __exit__ when __enter__ raises
            raise
        return self

    def __exit__(self, *exc):
        for origin, stash, key in self.moved:
            if stash.exists() and not origin.exists():
                shutil.move(str(stash), str(origin))
            (HIDE_ROOT / f"{key}.json").unlink(missing_ok=True)
            print(f"restored {origin}", file=sys.stderr)
        if HIDE_ROOT.exists() and not any(HIDE_ROOT.iterdir()):
            HIDE_ROOT.rmdir()


def make_run_eval(claude, run_trigger):
    """run_eval.run_eval replacement: same signature and return shape, portable stream reading."""

    def run_eval(eval_set, skill_name, description, num_workers, timeout, project_root,
                 runs_per_query=1, trigger_threshold=0.5, model=None):
        cmd_name = f"{skill_name}-skill-{uuid.uuid4().hex[:8]}"
        cmd_dir = Path(project_root) / ".claude" / "commands"
        cmd_dir.mkdir(parents=True, exist_ok=True)
        cmd_file = cmd_dir / f"{cmd_name}.md"
        indented = "\n  ".join(description.split("\n"))
        # one command file per description (run_eval.py writes one per run, so parallel runs
        # see several identical copies and a hit on a sibling's copy is scored as a miss)
        cmd_file.write_text(f"---\ndescription: |\n  {indented}\n---\n\n# {skill_name}\n\n"
                            f"This skill handles: {description}\n", encoding="utf-8")
        try:
            results = run_trigger.evaluate(claude, eval_set, cmd_name, os.getcwd(),  # queries see the fixture
                                           runs_per_query, num_workers, max(timeout, MIN_TIMEOUT),
                                           trigger_threshold, model)
        finally:
            cmd_file.unlink(missing_ok=True)
        for r in results:
            r.pop("fired", None)  # keep run_eval.py's exact row shape for the report generator
        passed = sum(r["pass"] for r in results)
        return {"skill_name": skill_name, "description": description, "results": results,
                "summary": {"total": len(results), "passed": passed, "failed": len(results) - passed}}

    return run_eval


def make_call_claude(claude):
    def _call_claude(prompt, model, timeout=300):
        cmd = [claude, "-p", "--output-format", "text"] + (["--model", model] if model else [])
        env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
        r = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=env, timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError(f"claude -p exited {r.returncode}\nstderr: {r.stderr}")
        return r.stdout

    return _call_claude


def main():
    reexec_utf8()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                 epilog="Arguments after -- go to skill-creator's run_loop.py.")
    ap.add_argument("--skill-creator", help="skill-creator dir (default: searched under ~/.claude)")
    ap.add_argument("--claude", help="path to the claude executable (default: found on PATH)")
    ap.add_argument("--hide-installed", action="store_true",
                    help="move an installed copy of the skill aside for the run (restored afterwards)")
    own, rest = ap.parse_known_args()
    if rest[:1] == ["--"]:
        rest = rest[1:]

    sys.path.insert(0, str(HERE))
    import run_trigger  # noqa: E402
    claude = run_trigger.find_claude(own.claude)

    sc = find_skill_creator(own.skill_creator)
    sys.path.insert(0, str(sc))
    import scripts.improve_description as improve  # noqa: E402
    import scripts.run_loop as loop  # noqa: E402
    from scripts.utils import parse_skill_md  # noqa: E402

    loop.run_eval = make_run_eval(claude, run_trigger)
    improve._call_claude = make_call_claude(claude)

    sp = rest[rest.index("--skill-path") + 1] if "--skill-path" in rest else None
    if not sp:
        sys.exit("--skill-path is required (after --)")
    name = parse_skill_md(Path(sp))[0]
    HiddenInstalls.restore_stale()
    hidden = HiddenInstalls(name, loop.find_project_root())
    if hidden.installed() and not own.hide_installed:
        sys.exit(f"'{name}' is installed at {', '.join(map(str, hidden.installed()))}; it would compete "
                 "with the candidate descriptions. Re-run with --hide-installed (restored afterwards).")

    sys.argv = [str(sc / "scripts" / "run_loop.py"), *rest]
    with hidden:
        loop.main()


if __name__ == "__main__":
    main()
