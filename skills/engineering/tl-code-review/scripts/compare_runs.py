#!/usr/bin/env python3
"""
compare_runs.py — compare the findings of two tl-code-review runs.

Reads <run>/findings.json (written by aggregate_findings.py) of an older and a newer run and
pairs their findings: same fingerprint first, then same file with similar titles, or nearby lines
plus some shared title words or shared code names (these survive a run written in another
language); nearby lines and a related category alone never pair. Each finding ends up as
  new        only in the newer run
  gone       only in the older run (fixed, or not found again — the report says which is likely)
  kept       in both; a severity change is shown
Writes <new run>/compare.md and compare.json.

Usage
  python compare_runs.py                         # latest run vs the run before it
  python compare_runs.py --old <run> --new <run> # two given run folders
  python compare_runs.py --list                  # runs under .code-review/runs with their verdicts
  python compare_runs.py --prune 5               # dry run: the runs beyond the newest 5
  python compare_runs.py --prune 5 --confirm     # delete them (their head/ worktrees too)
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under `python -I`
import run_dir  # noqa: E402
from aggregate_findings import (RELATED_CATEGORIES, SEV_ICON, SEV_ORDER, fingerprint,  # noqa: E402
                                load_json, title_words)

L10N = {
    "en": {"title": "Review run comparison", "old": "Older run", "new": "Newer run",
           "same_code": "Both runs reviewed the same commits: a finding missing from one run was not found again "
                        "by it (review variance), not fixed.",
           "diff_code": "The reviewed commits differ: a gone finding may be fixed or simply not found again.",
           "s_new": "New — only in the newer run", "s_gone": "Gone — only in the older run",
           "since": "The newer run reviewed only the commits after {sha} (re-review since {run}): a gone finding in code "
                    "those commits did not touch is out of its scope, not fixed.",
           "s_changed": "Kept, severity changed", "s_kept": "Kept, same severity", "none": "None."},
    "vi": {"title": "So sánh hai lần review", "old": "Lần chạy cũ", "new": "Lần chạy mới",
           "same_code": "Hai lần chạy review cùng commit: finding thiếu ở một lần là do lần đó không tìm lại được "
                        "(độ dao động của review), không phải đã sửa.",
           "diff_code": "Commit được review khác nhau: finding biến mất có thể đã được sửa hoặc chỉ là không tìm lại được.",
           "s_new": "Mới — chỉ có ở lần chạy mới", "s_gone": "Biến mất — chỉ có ở lần chạy cũ",
           "since": "Lần chạy mới chỉ review các commit sau {sha} (review lại từ lần {run}): finding biến mất ở code mà "
                    "các commit đó không đụng tới là nằm ngoài phạm vi, không phải đã sửa.",
           "s_changed": "Còn, đổi mức độ", "s_kept": "Còn, giữ mức độ", "none": "Không có."},
}


def lines_near(a, b, slack):
    a1, a2 = a.get("line_start", 0), a.get("line_end", a.get("line_start", 0))
    b1, b2 = b.get("line_start", 0), b.get("line_end", b.get("line_start", 0))
    return bool(a1 and b1) and a1 - slack <= b2 and b1 - slack <= a2


CODE_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")


def code_names(f):
    """Code names in a finding's text (snake_case or camelCase), spelled alike: source_id == sourceId.
    They do not depend on the language the finding was written in, unlike its title words."""
    text = " ".join(str(f.get(k) or "") for k in ("title", "evidence", "why", "suggestion"))
    return {n.replace("_", "").lower() for n in CODE_RX.findall(text)
            if "_" in n.strip("_") or re.search(r"[a-z][A-Z]", n)}


def similarity(a, b, slack):
    """0 when a and b are not the same issue, else a score (higher is a better match)."""
    if a.get("file") != b.get("file"):
        return 0
    ta, tb = title_words(a), title_words(b)
    jaccard = len(ta & tb) / max(len(ta | tb), 1)
    ca, cb = code_names(a), code_names(b)
    code = len(ca & cb) / max(len(ca | cb), 1)
    cats = {a.get("category"), b.get("category")}
    related = len(cats) == 1 or any(cats <= g for g in RELATED_CATEGORIES)
    near = lines_near(a, b, slack)
    # place alone (nearby lines, a related category) is not enough: a new defect beside a fixed one would show as
    # kept, never as new. Nearby findings also need shared title words or shared code names.
    if jaccard >= 0.5 or (near and (jaccard >= 0.2 or code >= 0.2)):
        return jaccard + 2 * code + (1 if near else 0) + (0.5 if related else 0)
    return 0


def pair(old, new, slack):
    """Greedy best-first matching; returns (pairs, only_old, only_new)."""
    for f in old + new:
        f.setdefault("fingerprint", fingerprint(f))
    pairs, used_old, used_new = [], set(), set()
    by_fp = {}
    for i, f in enumerate(old):
        by_fp.setdefault(f["fingerprint"], []).append(i)
    for j, f in enumerate(new):
        for i in by_fp.get(f["fingerprint"], []):
            if i not in used_old:
                pairs.append((i, j)); used_old.add(i); used_new.add(j)
                break
    scored = sorted(((similarity(old[i], new[j], slack), i, j) for i in range(len(old)) for j in range(len(new))
                     if i not in used_old and j not in used_new), reverse=True)
    for score, i, j in scored:
        if score and i not in used_old and j not in used_new:
            pairs.append((i, j)); used_old.add(i); used_new.add(j)
    return ([(old[i], new[j]) for i, j in pairs], [f for i, f in enumerate(old) if i not in used_old],
            [f for j, f in enumerate(new) if j not in used_new])


def loc(f):
    return f.get("file", "?") + (f":{f['line_start']}" if f.get("line_start") else "")


def by_severity(items):
    return sorted(items, key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), loc(f)))


def summary(run):
    data = load_json(Path(run) / "findings.json", {}) or {}
    counts = {s: sum(1 for f in data.get("findings", []) if f.get("severity") == s) for s in SEV_ORDER}
    return data.get("verdict", "(not aggregated)"), counts


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default=run_dir.BASE, help="the .code-review folder (default: .code-review)")
    ap.add_argument("--old", help="older run folder (default: the run before --new)")
    ap.add_argument("--new", help="newer run folder (default: the latest run)")
    ap.add_argument("--lang", choices=["en", "vi"], default="en")
    ap.add_argument("--list", action="store_true", help="list the runs and exit")
    ap.add_argument("--prune", type=int, metavar="KEEP", help="delete all but the newest KEEP runs (dry run)")
    ap.add_argument("--confirm", action="store_true", help="with --prune: actually delete")
    a = ap.parse_args()
    T = L10N[a.lang]

    runs = run_dir.list_runs(a.base)
    if a.list:
        for r in runs:
            verdict, counts = summary(r)
            print(f"{r.name}  {verdict}  " + " ".join(f"{k}={v}" for k, v in counts.items()))
        return
    if a.prune is not None:
        latest = run_dir.latest(a.base).resolve()
        doomed = [r for r in runs[:max(len(runs) - max(a.prune, 0), 0)] if r.resolve() != latest]
        for r in doomed:
            if a.confirm:
                run_dir.discard(r, Path(a.base).resolve().parent)
            print(f"[compare] {'deleted' if a.confirm else 'would delete'} {r}")
        kept = len(runs) - len(doomed)
        print(f"[compare] {len(doomed)} run(s) {'deleted' if a.confirm else 'to delete (add --confirm)'}, {kept} kept")
        return
    new = Path(a.new) if a.new else run_dir.latest(a.base)
    if a.old:
        old = Path(a.old)
    else:
        done = [r for r in runs if (r / "findings.json").exists() and r.resolve() != new.resolve()]
        order = {r.resolve(): i for i, r in enumerate(runs)}   # list_runs: oldest first, by creation
        at = order.get(new.resolve(), len(runs))
        earlier = [r for r in done if order[r.resolve()] < at] or done
        if not earlier:
            sys.exit("[compare] no earlier aggregated run to compare with (use --old)")
        old = earlier[-1]
    fo, fn = load_json(old / "findings.json"), load_json(new / "findings.json")
    if fo is None or fn is None:
        sys.exit(f"[compare] findings.json missing in {old if fo is None else new} — run aggregate_findings.py first")

    mo, mn = load_json(old / "manifest.json", {}) or {}, load_json(new / "manifest.json", {}) or {}
    same_code = bool(mo.get("head_sha")) and mo.get("head_sha") == mn.get("head_sha") \
        and mo.get("base_sha") == mn.get("base_sha")
    # Two reviewers cite different lines of one function; when the code changed between runs, lines
    # shift as well, so allow more distance then.
    pairs, gone, added = pair(fo.get("findings", []), fn.get("findings", []), 10 if same_code else 25)
    changed = [(o, n) for o, n in pairs if o.get("severity") != n.get("severity")]
    kept = [(o, n) for o, n in pairs if o.get("severity") == n.get("severity")]

    L = [f"# {T['title']}\n\n"]
    for key, run, m, data in (("old", old, mo, fo), ("new", new, mn, fn)):
        sha = (m.get("head_sha") or "")[:8]
        L.append(f"- **{T[key]}:** `{run.name}` · {data.get('verdict', '?')}" + (f" · head `{sha}`" if sha else "") + "\n")
    L.append(f"\n{T['same_code'] if same_code else T['diff_code']}\n")
    if mn.get("since_run"):
        L.append("\n" + T["since"].format(sha=mn["since_run"]["head_sha"][:8], run=mn["since_run"]["run"]) + "\n")
    L.append(f"\nnew: {len(added)} · gone: {len(gone)} · severity changed: {len(changed)} · kept: {len(kept)}\n")

    def one(f):
        return f"- {SEV_ICON.get(f.get('severity'), '')} {f.get('severity')} [{f.get('id')}] `{loc(f)}` {f.get('title', '')}\n"

    for title, items in ((T["s_new"], by_severity(added)), (T["s_gone"], by_severity(gone))):
        L.append(f"\n## {title}\n\n")
        L += [one(f) for f in items] or [T["none"] + "\n"]
    L.append(f"\n## {T['s_changed']}\n\n")
    L += [f"- {o.get('severity')} → {n.get('severity')} [{o.get('id')} → {n.get('id')}] `{loc(n)}` {n.get('title', '')}\n"
          for o, n in changed] or [T["none"] + "\n"]
    L.append(f"\n## {T['s_kept']}\n\n")
    L += [f"- {SEV_ICON.get(n.get('severity'), '')} [{o.get('id')} → {n.get('id')}] `{loc(n)}` {n.get('title', '')}\n"
          for o, n in sorted(kept, key=lambda p: (SEV_ORDER.get(p[1].get("severity"), 9), loc(p[1])))] or [T["none"] + "\n"]

    (new / "compare.md").write_text("".join(L), encoding="utf-8")
    ids = lambda fs: [f.get("id") for f in fs]  # noqa: E731
    (new / "compare.json").write_text(json.dumps({
        "old": str(old), "new": str(new), "same_code": same_code, "since_run": mn.get("since_run"),
        "new_findings": ids(added), "gone": ids(gone),
        "changed": [{"old": o.get("id"), "new": n.get("id"), "from": o.get("severity"), "to": n.get("severity")}
                    for o, n in changed],
        "kept": [{"old": o.get("id"), "new": n.get("id")} for o, n in kept]}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    print(f"[compare] {old.name} -> {new.name}: new={len(added)} gone={len(gone)} "
          f"changed={len(changed)} kept={len(kept)} same_code={same_code}")
    print(f"[compare] report -> {new / 'compare.md'}")


if __name__ == "__main__":
    main()
