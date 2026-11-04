"""
run_dir.py — where a tl-code-review run keeps its artifacts.

Each harness run gets its own folder, <repo>/.code-review/runs/<YYYYMMDD-HHMMSS>-<label>/, so a new
run never reads findings an earlier run left behind, and earlier runs stay for compare_runs.py.
.code-review/latest holds the newest run's path (relative to .code-review/); a script given no
--dir / --manifest works in that run. Without a `latest` file the flat legacy layout
(.code-review/ itself) is used. Things shared by every run (baseline.json) stay in .code-review/.
"""
import re
import shutil
import subprocess
import time
from pathlib import Path

BASE = ".code-review"


def label_for(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text or "").strip("-.")[:40] or "run"


CREATED = "created"   # a run's creation time in nanoseconds: its order, since names tie within a second


def new_run(base, label):
    """Create base/runs/<timestamp>-<label>/ and return it."""
    runs = Path(base) / "runs"
    stem = f"{time.strftime('%Y%m%d-%H%M%S')}-{label_for(label)}"
    d, n = runs / stem, 2
    while d.exists():  # two runs in the same second
        d, n = runs / f"{stem}-{n}", n + 1
    d.mkdir(parents=True)
    (d / CREATED).write_text(f"{time.time_ns()}\n", encoding="utf-8")
    return d


def set_latest(base, run):
    """Point base/latest at run; a run that is base itself (flat layout) removes the pointer."""
    base, run = Path(base).resolve(), Path(run).resolve()
    ptr = base / "latest"
    if run == base:
        ptr.unlink(missing_ok=True)
        return
    try:
        rel = run.relative_to(base)
    except ValueError:
        return  # a run folder outside .code-review/ is used only when named explicitly
    ptr.write_text(rel.as_posix() + "\n", encoding="utf-8")


def latest(base=BASE):
    """The newest run folder, or base itself when no run was recorded."""
    base = Path(base)
    try:
        rel = (base / "latest").read_text(encoding="utf-8").strip()
    except OSError:
        return base
    return base / rel if rel and (base / rel).is_dir() else base


def shared_dir(run):
    """The .code-review/ folder a run belongs to (for files shared across runs)."""
    run = Path(run)
    return run.parent.parent if run.parent.name == "runs" else run


def created(run):
    """When a run was created (ns), or 0 for a folder made by hand or by an older version."""
    try:
        return int((Path(run) / CREATED).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def list_runs(base=BASE):
    """Run folders, oldest first: by the second in their name, then by creation time within it (the label
    after the second sorts alphabetically, not by age)."""
    runs = Path(base) / "runs"
    if not runs.is_dir():
        return []
    return sorted((p for p in runs.iterdir() if p.is_dir()), key=lambda p: (p.name[:15], created(p), p.name))


def discard(run, repo_root):
    """Delete a run folder, unregistering its head/ worktree from git first."""
    run = Path(run)
    if (run / "head" / ".git").exists():
        subprocess.run(["git", "worktree", "remove", "--force", str(run / "head")], cwd=repo_root,
                       capture_output=True)
    shutil.rmtree(run, ignore_errors=True)
    subprocess.run(["git", "worktree", "prune"], cwd=repo_root, capture_output=True)
