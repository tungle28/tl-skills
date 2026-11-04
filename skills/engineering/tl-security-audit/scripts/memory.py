#!/usr/bin/env python3
"""Cross-run memory for tl-security-audit: triage decisions that carry over, and a diff against the
previous run.

Triage file: <repo>/.security-audit/triage.yml — one entry per decision a person approved:

  - id: T001
    verdict: false-positive        # or accepted-risk
    file: src/Orders/OrderController.cs
    category: cs-sql-concat        # rule id or check id; cwe/owasp also match
    rules: [cs-sql-concat]         # optional: scanner rules whose hits here are skipped at scan time
    match: rule                    # optional: only findings of those rules (set for dismissed scanner hits)
    cwe: CWE-89
    owasp: A05
    title: SQL built by string concatenation
    lines: [3f9a0c1b2d4e, ...]     # hashes of the flagged code lines (whitespace removed)
    reason: value is an enum name, never user input
    recorded: 2026-11-04
    run: 20261104-101500
    until: 2027-05-03              # optional (default for accepted-risk: +180 days); expired = ignored

An entry matches a finding in the same file, of the same class (category, CWE or OWASP), whose code
lines overlap the entry's (at least half of the shorter set), while every line the entry recorded
still exists in the file. When any of them changes the entry stops matching and the site is reviewed
again — a decision is never trusted past the code it was about.

  memory.py learn --run-dir D                      propose entries from this run (writes triage_proposed.yml)
  memory.py learn --run-dir D --apply P001,P003    append approved proposals (or `all`) to triage.yml
  memory.py learn --run-dir D --accept F-ID --reason "..." [--until YYYY-MM-DD]
                                                   record an accepted risk for a live finding
  memory.py list  --root R                         show the triage file with expiry status
"""
import argparse
import hashlib
import re
import sys
from datetime import date, timedelta
from pathlib import Path

from common import load_state, read_json

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

TRIAGE_REL = Path(".security-audit") / "triage.yml"
VERDICTS = ("false-positive", "accepted-risk")
TRIAGED_STATUS = {"false-positive": "known-fp", "accepted-risk": "accepted-risk"}
MAX_SPAN = 12          # lines hashed per finding (a whole-function span would match too much)
MIN_LINE = 6           # shorter normalized lines (`}`, `return;`, `else {`) carry no identity
ACCEPT_DAYS = 180
NOT_LIVE = ("rejected", "out-of-scope", "known-fp", "accepted-risk")


# ------------------------------------------------------------------ fingerprints

def line_hash(line):
    s = re.sub(r"\s+", "", line)
    if len(s) < MIN_LINE or not re.search(r"\w", s):
        return None
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]


class Sources:
    """Reads repository files once per run."""

    def __init__(self, root):
        self.root, self.cache = Path(root), {}

    def lines(self, rel):
        if rel not in self.cache:
            try:
                self.cache[rel] = (self.root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self.cache[rel] = None
        return self.cache[rel]

    def hashes(self, rel, start, end=None):
        lines = self.lines(rel)
        if not lines or not start:
            return []
        end = min(end or start, start + MAX_SPAN - 1, len(lines))
        out = []
        for ln in range(max(start, 1), end + 1):
            h = line_hash(lines[ln - 1])
            if h and h not in out:
                out.append(h)
        return out

    def file_hashes(self, rel):
        lines = self.lines(rel)
        return None if lines is None else {h for h in map(line_hash, lines) if h}


def fingerprint(src, f):
    return src.hashes(f["file"], f.get("line_start"), f.get("line_end"))


def same_code(a, b):
    a, b = set(a or []), set(b or [])
    if not a or not b:
        return False
    return len(a & b) * 2 >= min(len(a), len(b))


def same_class(x, y):
    for k in ("category", "cwe", "owasp"):
        if x.get(k) and x.get(k) == y.get(k):
            return True
    return False


# ------------------------------------------------------------------ triage file

def triage_path(root):
    return Path(root) / TRIAGE_REL


def load_triage(root, include_expired=False):
    p = triage_path(root)
    if not p.exists():
        return []
    if yaml is None:
        print("WARNING: PyYAML missing — .security-audit/triage.yml not applied (pip install pyyaml)")
        return []
    items = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    today = date.today().isoformat()
    out = []
    for e in items if isinstance(items, list) else []:
        if not isinstance(e, dict) or e.get("verdict") not in VERDICTS or not e.get("file") \
                or not e.get("lines") or not e.get("reason"):
            continue  # incomplete entries are ignored on purpose, like reason-less suppressions
        e["expired"] = bool(e.get("until") and str(e["until"]) < today)
        if include_expired or not e["expired"]:
            out.append(e)
    return out


def unchanged(e, src):
    """Every line the decision was made about still exists in the file (anywhere: shifts are fine)."""
    hashes = src.file_hashes(e["file"])
    return hashes is not None and set(e["lines"]) <= hashes


def match_triage(f, fp, entries, src):
    for e in entries:
        if e.get("match") == "rule":  # learned from a dismissed scanner hit: only that rule's findings
            if f.get("category") not in {e.get("category"), *(e.get("rules") or [])}:
                continue
        elif not same_class(e, f):
            continue
        if e["file"] == f["file"] and same_code(e["lines"], fp) and unchanged(e, src):
            return e
    return None


def triage_hit(hit, entries, src):
    """Scan phase: a scanner hit a person already called a false positive is not sent to reviewers."""
    if not entries:
        return None
    fp = src.hashes(hit["file"], hit.get("line"))
    for e in entries:
        # only the same rule: a reviewer's false-positive verdict on a broader finding says nothing
        # about a different rule firing on the same line
        rules = {e.get("category"), *(e.get("rules") or [])}
        if e["verdict"] == "false-positive" and e["file"] == hit["file"] and hit.get("rule_id") in rules \
                and same_code(e["lines"], fp) and unchanged(e, src):
            return f"triage.yml {e.get('id', '?')}: {e['reason']}"
    return None


def apply_triage(findings, root):
    """Merge phase: give every finding a fingerprint and mark those covered by a triage decision."""
    src, entries = Sources(root), load_triage(root)
    n = 0
    for f in findings:
        f["fp"] = fingerprint(src, f)
        if f["status"] == "out-of-scope" or f["id"].startswith("DEP-"):
            continue
        e = match_triage(f, f["fp"], entries, src)
        if e:
            f["status"] = TRIAGED_STATUS[e["verdict"]]
            f["triage"] = {"id": e.get("id"), "verdict": e["verdict"], "reason": e["reason"],
                           "recorded": str(e.get("recorded", "")), "until": str(e.get("until") or "")}
            n += 1
    return n


# ------------------------------------------------------------------ diff against a previous run

def find_baseline(run, st):
    """Explicit `baseline` in state.json, else the newest finished sibling run of the same repo."""
    if st.get("baseline"):
        b = Path(st["baseline"])
        return b if (b / "merged.json").exists() else None
    best = None
    for d in Path(run).resolve().parent.iterdir():
        if d.resolve() == Path(run).resolve() or not (d / "merged.json").exists() or not (d / "report.md").exists():
            continue
        bst = load_state(d)
        if bst.get("root") != st.get("root") or str(bst.get("created_at", "")) >= str(st.get("created_at", "~")):
            continue
        if not best or str(bst.get("created_at", "")) > str(load_state(best).get("created_at", "")):
            best = d
    return best


def _matches(old, new):
    if old["file"] != new["file"] or not same_class(old, new):
        return False
    if old.get("fp") and new.get("fp"):
        return same_code(old["fp"], new["fp"])
    return abs((old.get("line_start") or 0) - (new.get("line_start") or 0)) <= 15  # older run without fp


def _pair_score(old, new):
    """How well two matching findings fit: same CWE > same category > same OWASP, then code overlap."""
    a, b = set(old.get("fp") or []), set(new.get("fp") or [])
    overlap = len(a & b) / max(min(len(a), len(b)), 1) if a and b else 0
    return (4 * (bool(old.get("cwe")) and old.get("cwe") == new.get("cwe"))
            + 2 * (bool(old.get("category")) and old.get("category") == new.get("category"))
            + (old.get("owasp") == new.get("owasp")) + overlap)


def _similar(o, cur):
    """A current finding that likely restates `o` differently (other file, merged or split): same
    CWE and category anywhere (rate limiting anchored at app.ts, then at the login route), or same
    file and category (two Dockerfile findings merged into one)."""
    for f in cur:
        same_cat = bool(o.get("category")) and f.get("category") == o["category"]
        if same_cat and (f["file"] == o["file"] or (o.get("cwe") and f.get("cwe") == o["cwe"])):
            return f
    return None


def diff_runs(run, doc, st, inv):
    """Tag each current finding new/persisting; classify each finding of the previous run that is
    gone. Returns a summary dict (also stored in merged.json) or None when there is no baseline."""
    base = find_baseline(run, st)
    if not base:
        return None
    old = [f for f in (read_json(base / "merged.json", {}) or {}).get("findings", [])
           if f.get("status") not in NOT_LIVE and not f["id"].startswith("DEP-")]
    cur = [f for f in doc["findings"] if not f["id"].startswith("DEP-") and f["status"] != "out-of-scope"]
    kind = inv.get("scope", {}).get("kind", "full")
    in_scope = {x["path"] for x in inv.get("files", []) if x.get("in_scope")}
    src = Sources(st["root"])
    # best pairs first: a greedy first-match lets a finding take a weaker partner (a `.env` finding
    # paired with the root-user finding of the same Dockerfile), leaving one "new" and one "gone"
    pairs = sorted(((_pair_score(o, f), i, j) for i, o in enumerate(old) for j, f in enumerate(cur) if _matches(o, f)),
                   key=lambda p: -p[0])
    seen, taken = set(), set()
    for _, i, j in pairs:
        if i in seen or j in taken:
            continue
        seen.add(i)
        taken.add(j)
        cur[j]["delta"] = "persisting"
        cur[j]["baseline_id"] = old[i]["id"]
    for j, f in enumerate(cur):
        if j not in taken:
            f["delta"] = "new"
    live = [f for f in cur if f["status"] not in NOT_LIVE]
    gone = []
    for i, o in enumerate(old):
        if i in seen or (kind != "full" and o["file"] not in in_scope):
            continue
        hashes = src.file_hashes(o["file"])
        if hashes is None:
            why = "file removed"
        elif o.get("fp") and not set(o["fp"]) <= hashes:
            # any flagged line edited = changed: a fix usually keeps the function signature line
            why = "code changed"  # likely fixed — confirm
        elif _similar(o, live):
            s = _similar(o, live)
            why = f"code unchanged, reported differently ({s['id']} `{s['file']}:{s['line_start']}`)"
        elif o.get("fp"):
            why = "code unchanged, not reported"  # likely missed this run — re-check
        else:
            why = "not reported (no fingerprint in baseline)"
        gone.append({"id": o["id"], "title": o.get("title", ""), "file": o["file"], "line_start": o.get("line_start"),
                     "severity": o.get("severity"), "reason": why})
    return {"baseline": str(base), "baseline_created": load_state(base).get("created_at"),
            "new": sum(1 for f in live if f.get("delta") == "new"),
            "persisting": sum(1 for f in live if f.get("delta") == "persisting"),
            "gone": gone}


# ------------------------------------------------------------------ learn

def _entry(f, verdict, reason, run_name, until=None):
    e = {"verdict": verdict, "file": f["file"], "category": f.get("category"), "cwe": f.get("cwe"),
         "owasp": f.get("owasp"), "title": f.get("title"), "severity": f.get("severity"),
         "lines": f.get("fp") or [], "reason": reason, "recorded": date.today().isoformat(), "run": run_name}
    # scanner rules folded into this finding ("rule:js-weak-hash", "taint:py-sqli"): their hits on
    # this code are skipped at the next scan instead of being re-triaged
    rules = sorted({s.split(":", 1)[1] for s in f.get("sources", []) if ":" in s} - {f.get("category")})
    if rules:
        e["rules"] = rules
    if until:
        e["until"] = until
    return {k: v for k, v in e.items() if v not in (None, "")}


# A rejection "because another finding already says this" is not a verdict on the code: learning it
# as a false positive would hide the real finding on the same lines in the next run.
DUPLICATE_RE = re.compile(r"\bdup(licate|lication|e)?s?\b|same root cause|already (reported|covered|filed)|"
                          r"merged? (into|with)|folded into|restat|trùng (lặp|với)|gộp (vào|với|chung)|đã (được )?báo|cùng (nguyên nhân|lỗi)",
                          re.I)


def _overlaps_live(f, doc):
    for x in doc.get("findings", []):
        if x is f or x["status"] in NOT_LIVE or x["file"] != f["file"]:
            continue
        if x["line_start"] <= f["line_end"] and f["line_start"] <= x["line_end"]:
            return x
    return None


def propose(run, doc, src):
    """Candidate triage entries from this run, plus what was left out and why."""
    out, skipped, run_name = [], [], Path(run).name
    for f in doc.get("findings", []):
        if f["status"] != "rejected" or f["id"].startswith("DEP-"):
            continue
        note = f.get("verification_note") or ""
        live = _overlaps_live(f, doc)
        if DUPLICATE_RE.search(note) or live:
            skipped.append({"from": f["id"], "why": "duplicate" if DUPLICATE_RE.search(note)
                            else f"a live finding ({live['id']}) is on the same lines"})
            continue
        f = {**f, "fp": f.get("fp") or fingerprint(src, f)}
        out.append({**_entry(f, "false-positive", note or "rejected by verifier", run_name), "from": f["id"]})
    hits = {h["hit_id"]: h for h in (read_json(Path(run) / "scan" / "hits.json", {}) or {}).get("hits", [])}
    for d in doc.get("dismissed", []):
        if DUPLICATE_RE.search(d.get("reason") or ""):
            skipped.append({"from": d["hit_id"], "why": "duplicate"})
            continue
        h = hits.get(d["hit_id"], {})
        f = {"file": d["file"], "category": d["rule_id"], "cwe": h.get("cwe"), "owasp": h.get("owasp"),
             "title": h.get("title"), "severity": h.get("severity"), "fp": src.hashes(d["file"], d["line"])}
        # a reviewer dismissed one scanner rule's hit: the decision covers that rule only, never a
        # reviewer finding of the same class on the same line
        out.append({**_entry(f, "false-positive", d.get("reason") or "dismissed by reviewer", run_name),
                    "match": "rule", "from": d["hit_id"]})
    for p in out:
        if not p.get("lines"):
            skipped.append({"from": p["from"], "why": "no code line to anchor on"})
    out = [p for p in out if p.get("lines")]
    for i, p in enumerate(out, 1):
        p["pid"] = f"P{i:03d}"
    return out, skipped


def _append(root, entries):
    p = triage_path(root)
    cur = load_triage(root, include_expired=True)
    nums = [int(m.group(1)) for e in cur for m in [re.match(r"T(\d+)$", str(e.get("id", "")))] if m]
    nxt = max(nums, default=0) + 1
    known = {(e["file"], e.get("category"), tuple(e["lines"])) for e in cur}
    added = []
    for e in entries:
        key = (e["file"], e.get("category"), tuple(e["lines"]))
        if key in known:
            continue
        known.add(key)
        added.append({"id": f"T{nxt:03d}", **{k: v for k, v in e.items() if k not in ("pid", "from")}})
        nxt += 1
    if added:
        p.parent.mkdir(parents=True, exist_ok=True)
        text = p.read_text(encoding="utf-8") if p.exists() else (
            "# tl-security-audit triage decisions — carried over to later runs (see scripts/memory.py).\n"
            "# accepted-risk entries describe real weaknesses: keep this file where the code is private.\n")
        if text and not text.endswith("\n"):
            text += "\n"
        text += yaml.safe_dump(added, sort_keys=False, allow_unicode=True, width=120)
        p.write_text(text, encoding="utf-8")
    return added


def cmd_learn(a):
    if yaml is None:
        sys.exit("PyYAML is required: pip install pyyaml")
    run = Path(a.run_dir).resolve()
    st, doc = load_state(run), read_json(run / "merged.json")
    if not doc:
        sys.exit("merged.json missing — finish the run first")
    root, src = st["root"], Sources(st["root"])
    if a.accept:
        if not a.reason:
            sys.exit("--accept needs --reason (who accepted the risk and why)")
        f = next((x for x in doc["findings"] if x["id"] == a.accept or a.accept in x.get("merged_ids", [])), None)
        if not f:
            sys.exit(f"no finding {a.accept} in merged.json")
        f = {**f, "fp": f.get("fp") or fingerprint(src, f)}
        if not f["fp"]:
            sys.exit(f"{a.accept}: no code lines to anchor on at {f['file']}:{f['line_start']}")
        until = a.until or (date.today() + timedelta(days=ACCEPT_DAYS)).isoformat()
        added = _append(root, [_entry(f, "accepted-risk", a.reason, run.name, until)])
        print(f"{'added ' + added[0]['id'] if added else 'already recorded'}: accepted-risk {a.accept} until {until} "
              f"-> {triage_path(root)}")
        return
    props_file = run / "triage_proposed.yml"
    if a.apply:
        props = yaml.safe_load(props_file.read_text(encoding="utf-8")) if props_file.exists() else None
        if not props:
            sys.exit("no triage_proposed.yml — run `learn` without --apply first")
        want = None if a.apply == "all" else {x.strip() for x in a.apply.split(",")}
        sel = [p for p in props if want is None or p["pid"] in want or p.get("from") in want]
        added = _append(root, sel)
        print(f"added {len(added)} entries ({', '.join(e['id'] for e in added) or 'all already recorded'}) "
              f"-> {triage_path(root)}")
        return
    props, skipped = propose(run, doc, src)
    props_file.write_text(yaml.safe_dump(props, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
    print(f"{len(props)} proposals -> {props_file}")
    if skipped:
        print(f"not proposed ({len(skipped)}): " + "; ".join(f"{x['from']} ({x['why']})" for x in skipped))
    print(f"{'pid':<5} {'from':<10} {'sev':<8} location  title — reason")
    for p in props:
        print(f"{p['pid']:<5} {p['from']:<10} {p.get('severity', '-'):<8} {p['file']}  "
              f"{str(p.get('title', ''))[:60]} — {str(p['reason'])[:80]}")
    if props:
        print("Show these to the user; apply only the ones they approve: "
              "memory.py learn --run-dir D --apply P001,P002 (or all)")


def cmd_list(a):
    entries = load_triage(a.root, include_expired=True)
    print(f"{len(entries)} entries in {triage_path(a.root)}")
    for e in entries:
        print(f"{e.get('id', '?'):<5} {e['verdict']:<15} {'EXPIRED ' if e['expired'] else ''}{e['file']}  "
              f"{e.get('category', '')}  until={e.get('until', '-')} — {str(e['reason'])[:80]}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    le = sub.add_parser("learn")
    le.add_argument("--run-dir", required=True)
    le.add_argument("--apply", help="comma-separated proposal ids (P001) or source ids, or 'all'")
    le.add_argument("--accept", help="finding id to record as an accepted risk")
    le.add_argument("--reason")
    le.add_argument("--until", help="expiry date YYYY-MM-DD (accepted-risk default: +180 days)")
    li = sub.add_parser("list")
    li.add_argument("--root", required=True)
    a = ap.parse_args()
    cmd_learn(a) if a.cmd == "learn" else cmd_list(a)


if __name__ == "__main__":
    main()
