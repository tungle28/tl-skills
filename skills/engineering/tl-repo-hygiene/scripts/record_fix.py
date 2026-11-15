"""Record the outcome of fixing one finding, so the HTML report can show it under "Fixed".

    python record_fix.py <fixes.json> --id SEC-004 --status fixed \
        --what "Parameterised the query in getUser" --verify "pytest tests/users: 12 passed" \
        --files src/users/repo.ts,tests/users/test_repo.py [--commit abc1234]

One entry per finding id; recording the same id again replaces it. Parallel calls on the same file
are safe: each takes <fixes.json>.lock while it reads, updates and writes. Status: fixed (done and
verified), partial (some of it done, or done but not verified), failed (tried, not done; say why in
--what). Then render the report again: the page reads fixes.json from where its skill looks for it
(the run folder for tl-security-audit, tl-code-refactor and tl-code-review; next to the report as
<report>.fixes.json for tl-seo-audit and tl-monitoring-audit; next to findings.json for tl-repo-hygiene).

Identical in tl-security-audit, tl-code-refactor, tl-code-review, tl-seo-audit, tl-monitoring-audit
and tl-repo-hygiene (each skill installs on its own). Standard library only.
"""
import argparse
import json
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

STATUSES = ("fixed", "partial", "failed")
LOCK_WAIT = 30    # seconds to wait for another record_fix.py on the same file
LOCK_STALE = 120  # a lock older than this was left by a killed run and is taken over


@contextmanager
def locked(path):
    """Hold <path>.lock (created exclusively) so parallel calls cannot lose each other's entries."""
    lock = Path(str(path) + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + LOCK_WAIT
    while True:
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            break
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > LOCK_STALE:
                    lock.unlink()
                    continue
            except FileNotFoundError:
                continue  # released between the two calls
            if time.monotonic() > deadline:
                sys.exit(f"error: {lock} is held by another record_fix.py; retry, or delete it if none is "
                         "running (nothing was written)")
            time.sleep(0.05)
    try:
        yield
    finally:
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def load(path):
    """{id: entry} from fixes.json; a missing file is empty, a broken one stops the script."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        doc = json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as err:
        sys.exit(f"error: cannot read {p}: {err} (fix or delete it; nothing was written)")
    items = doc.get("fixes", []) if isinstance(doc, dict) else []
    return {str(x["id"]): x for x in items if isinstance(x, dict) and x.get("id")}


def save(path, entries):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({"fixes": list(entries.values())}, indent=2, ensure_ascii=False)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=p.name, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data + "\n")
    os.replace(tmp, p)  # a reader never sees a half-written file


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fixes", help="fixes.json to update (created if missing)")
    ap.add_argument("--id", required=True, help="finding id exactly as in the report")
    ap.add_argument("--status", required=True, choices=STATUSES)
    ap.add_argument("--what", required=True, help="what was changed (or why it was not), one or two sentences")
    ap.add_argument("--verify", default="", help="how it was verified: command and result")
    ap.add_argument("--files", default="", help="changed files, comma-separated")
    ap.add_argument("--commit", default="", help="commit id, if committed")
    a = ap.parse_args()
    if a.status == "fixed" and not a.verify.strip():
        sys.exit("error: --status fixed needs --verify (record it as partial if it was not verified)")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    with locked(a.fixes):
        entries = load(a.fixes)
        entries[a.id] = {"id": a.id, "status": a.status, "what": a.what.strip(), "verify": a.verify.strip(),
                         "files": [f.strip() for f in a.files.split(",") if f.strip()], "commit": a.commit.strip(),
                         "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        save(a.fixes, entries)
    counts = {s: sum(1 for e in entries.values() if e["status"] == s) for s in STATUSES}
    print(f"{Path(a.fixes).resolve()}: {a.id} {a.status} — " + ", ".join(f"{n} {s}" for s, n in counts.items()))


if __name__ == "__main__":
    main()
