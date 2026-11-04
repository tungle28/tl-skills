#!/usr/bin/env python3
"""Phases merge / verify-queue / report.

merge        reviewer findings + scanner hits (triaged or not) + dependency results -> merged.json
verify-queue pick the findings worth an adversarial second look -> verify_queue.json
report       apply verifier verdicts, render report.md (English headings; content as written)
"""
import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from common import (CONFIDENCES, OWASP_2025, SEV_WEIGHT, SEVERITIES, load_state, now_iso, read_json,
                    redact, secret_digest, write_json)
from memory import NOT_LIVE, apply_triage, diff_runs
from ruleset import entropy, load_rules

KINDS = ("vulnerability", "weakness", "hardening", "cost-risk")
REQUIRES = {"none": 1.5, "user": 1.2, "privileged": 0.8, "internal": 0.7, "local": 0.6, "unknown": 1.0}
CONF_F = {"high": 1.0, "medium": 0.75, "low": 0.4}
REQUIRED = ("id", "kind", "owasp", "title", "file", "line_start", "evidence", "attack_scenario",
            "impact", "fix", "severity", "confidence")


# ------------------------------------------------------------------ helpers

TOKEN_SPLIT = re.compile(r"[\s'\"`;,()=:<>\[\]{}|“”‘’]+")
TOKEN_STRIP = "*_.,!?…/@"


def load_digests(run):
    """secret_digests.json as {length: {sha256}}. Entries are {"sha256", "len", "ws"}; "ws" marks a
    value with whitespace in it. A run from before lengths were recorded holds bare sha256 strings,
    kept under the key None and matched token by token."""
    by_len = defaultdict(set)
    for e in read_json(run / "scan" / "secret_digests.json", []):
        if isinstance(e, dict) and e.get("sha256") and e.get("len"):
            by_len[(int(e["len"]), bool(e.get("ws")))].add(e["sha256"])
        elif isinstance(e, str):
            by_len[None].add(e)
    return dict(by_len)


def secret_rules(run):
    """What merge/report use to mask secrets agents quoted in their own text: the run's secret rules
    (for secrets the scanner missed) and the digests of every secret the scanner found (so a value
    quoted out of context, e.g. `Password=...` without its connection string, is still caught)."""
    st = load_state(run)
    rules, _ = load_rules(st.get("root"), st.get("rules_dirs", []))
    return {"rules": [r for r in rules.values() if r.get("secret") and r.get("_pattern")],
            "digests": load_digests(run)}


def _digest_hits(text, digests):
    """Every substring of text whose sha256 the scan recorded. With the length known, each window of
    that length is hashed, so the value is found however it is wrapped (**bold**, “quotes”, a URL,
    trailing …). Windows with whitespace are skipped unless the secret itself had some."""
    found, next_ws = set(), None
    for key, hashes in digests.items():
        if key is None:  # legacy digests without a length: whole tokens, with wrapping stripped
            for tok in set(TOKEN_SPLIT.split(text)):
                for cand in {tok, tok.strip(TOKEN_STRIP), tok.rstrip(TOKEN_STRIP)}:
                    if len(cand) >= 8 and secret_digest(cand) in hashes:
                        found.add(cand)
            continue
        n, has_ws = key
        if n < 8 or n > len(text):
            continue
        if next_ws is None:  # next_ws[i] = index of the first whitespace at or after i
            next_ws, nxt = [0] * (len(text) + 1), len(text)
            next_ws[len(text)] = nxt
            for i in range(len(text) - 1, -1, -1):
                if text[i].isspace():
                    nxt = i
                next_ws[i] = nxt
        for i in range(len(text) - n + 1):
            if not has_ws and next_ws[i] < i + n:
                continue
            cand = text[i:i + n]
            if secret_digest(cand) in hashes:
                found.add(cand)
    return found


def redact_text(text, red):
    """Mask every value a secret rule matches or whose digest the scan recorded. Scanner snippets are
    redacted at scan time, but a reviewer or the narrative can still quote the value."""
    if red["digests"]:
        for value in sorted(_digest_hits(text, red["digests"]), key=len, reverse=True):
            text = text.replace(value, redact(value))
    for r in red["rules"]:
        for m in list(r["_pattern"].finditer(text)):
            value = m.group(int(r.get("secret_group", 0))) or ""
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            line = text[start:] if end < 0 else text[start:end]
            if len(value) < 8 or "redacted]" in value:
                continue
            if r.get("_pattern_not") and r["_pattern_not"].search(line):
                continue
            if r.get("entropy_min") and entropy(value) < float(r["entropy_min"]):
                continue
            text = text.replace(value, redact(value))
    return text


def redact_obj(obj, rules):
    if isinstance(obj, str):
        return redact_text(obj, rules)
    if isinstance(obj, list):
        return [redact_obj(x, rules) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v, rules) for k, v in obj.items()}
    return obj


def _lower(v):
    return v.strip().lower() if isinstance(v, str) else v


def _not_reviewed(x):
    """Schema: 'path — reason' strings. Reviewers also write {"file", "reason"} objects; accept both."""
    if isinstance(x, dict):
        path = x.get("file") or x.get("path") or "?"
        return f"{path} — {x['reason']}" if x.get("reason") else str(path)
    return str(x)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def norm(f, errors, origin):
    if not isinstance(f, dict):
        errors.append({"origin": origin, "id": None, "missing": list(REQUIRED)})
        return None
    miss = [k for k in REQUIRED if f.get(k) in (None, "")]
    if "line_start" not in miss and _int(f["line_start"]) is None:
        miss.append("line_start")
    if miss:
        errors.append({"origin": origin, "id": f.get("id"), "missing": miss})
        return None
    f = dict(f)
    # Case slips ("Critical", "a01") are normalized, never silently downgraded to a default.
    for k in ("severity", "confidence", "kind", "requires"):
        f[k] = _lower(f.get(k))
    coerced = [k for k, ok in (("severity", SEVERITIES), ("confidence", CONFIDENCES), ("kind", KINDS))
               if f[k] not in ok]
    f["severity"] = f["severity"] if f["severity"] in SEVERITIES else "medium"
    f["confidence"] = f["confidence"] if f["confidence"] in CONFIDENCES else "low"
    f["kind"] = f["kind"] if f["kind"] in KINDS else "weakness"
    f["requires"] = f.get("requires") if f.get("requires") in REQUIRES else "unknown"
    ow = str(f["owasp"]).strip().upper()[:3]
    if ow not in OWASP_2025:
        coerced.append("owasp")
    f["owasp"] = ow if ow in OWASP_2025 else "A06"
    if coerced:
        errors.append({"origin": origin, "id": f.get("id"), "missing": [], "coerced": coerced})
    f["line_start"] = _int(f["line_start"])
    f["line_end"] = _int(f.get("line_end")) or f["line_start"]
    if f["line_end"] < f["line_start"]:
        f["line_start"], f["line_end"] = f["line_end"], f["line_start"]
    f.setdefault("sources", [origin])
    f.setdefault("status", "unverified")
    f.setdefault("from_hits", [])
    return f


def trace_md(trace):
    icon = {"source": "source", "step": "step", "call": "call", "enter": "enter", "sink": "sink"}
    return " → ".join(f"{icon.get(t['role'], t['role'])} `{t['file']}:{t['line']}`" +
                      (f" ({t['text'][:50]})" if t.get("text") and t["role"] in ("source", "enter", "sink") else "")
                      for t in trace)


def from_hit(h, status):
    ev = f"`{h['snippet']}`" if h.get("snippet") else h.get("message", "")
    if h.get("trace"):
        ev = f"Flow: {trace_md(h['trace'])}" + (f" (+{h['other_sources']} other sources)" if h.get("other_sources") else "")
    return {"id": f"R-{h['hit_id']}", "kind": "weakness", "category": h["rule_id"], "owasp": h.get("owasp") or "A06",
            "cwe": h.get("cwe"), "title": h["title"], "file": h["file"], "line_start": h["line"],
            "line_end": h["line"], "evidence": ev, **({"trace": h["trace"]} if h.get("trace") else {}),
            "attack_scenario": h.get("message", "") + (f" Source: `{h['trace'][0]['file']}:{h['trace'][0]['line']}`."
                                                       if h.get("trace") and h["trace"][0]["role"] == "source" else ""),
            "impact": h.get("impact") or h.get("message", ""), "fix": h.get("fix", ""),
            "severity": h.get("severity", "medium"), "confidence": h.get("confidence", "medium"),
            "requires": "unknown", "sources": [h.get("source", "rule") + ":" + h["rule_id"]],
            "status": status, "from_hits": [h["hit_id"]], **({"note": h["note"]} if h.get("note") else {})}


SCANNER_STATUSES = ("untriaged", "unreviewed", "scanner", "out-of-scope")


def _span_share(a, b):
    """Overlapping lines as a share of the longer span (1.0 = the same range)."""
    inter = min(a["line_end"], b["line_end"]) - max(a["line_start"], b["line_start"]) + 1
    return max(inter, 0) / max(a["line_end"] - a["line_start"] + 1, b["line_end"] - b["line_start"] + 1)


def _points_at(a, b):
    """True when a's primary location is one of b's related locations (a flaw reported at the
    repository by one reviewer and at the service, citing that repository line, by another).
    A systemic finding that lists many related sites ("tenant filter is by convention; these
    repositories miss it") must not swallow the concrete findings it cites."""
    related = b.get("related") or []
    if len(related) > 3:
        return False
    for r in related:
        if not isinstance(r, dict) or r.get("file") != a["file"]:
            continue
        rs = _int(r.get("line_start")) or 0
        re_ = _int(r.get("line_end")) or rs
        if rs and rs <= a["line_end"] + 3 and a["line_start"] <= re_ + 3:
            return True
    return False


def same_flaw_across_reviewers(a, b):
    if a["file"] != b["file"]:
        return bool(a.get("cwe")) and a.get("cwe") == b.get("cwe") and (_points_at(a, b) or _points_at(b, a))
    share = _span_share(a, b)
    if a.get("cwe") and a.get("cwe") == b.get("cwe"):
        return True  # same weakness on overlapping or nearby lines
    if share <= 0:
        return False
    # Reviewers disagree on the OWASP class of one flaw (A03 from the 2021 list vs A05) and on its
    # CWE (CWE-327 vs CWE-328), so near-identical spans decide; half-overlapping spans (a race and a
    # missing sign check in one handler) stay separate.
    same_class = (a.get("category") and a.get("category") == b.get("category")) or a["owasp"] == b["owasp"]
    return bool(same_class) and share >= 0.8


def overlaps(a, b, slack=3):
    if a["status"] not in SCANNER_STATUSES and b["status"] not in SCANNER_STATUSES \
            and a["file"] != b["file"] and not set(a.get("sources", [])) & set(b.get("sources", [])):
        return same_flaw_across_reviewers(a, b)
    if not (a["file"] == b["file"] and a["line_start"] <= b["line_end"] + slack
            and b["line_start"] <= a["line_end"] + slack):
        return False
    both_scanner = a["status"] in SCANNER_STATUSES and b["status"] in SCANNER_STATUSES
    if both_scanner:  # two raw hits: only the same line + same weakness is a true duplicate
        return a["line_start"] == b["line_start"] and bool(a.get("cwe")) and a.get("cwe") == b.get("cwe") \
            and a.get("category") != b.get("category") or (a.get("category") == b.get("category")
                                                             and a["title"] == b["title"] and a["line_start"] == b["line_start"])
    if a["status"] not in SCANNER_STATUSES and b["status"] not in SCANNER_STATUSES:
        # Two reviewer findings. One reviewer listing two findings means two problems (a race and a
        # missing sign check in the same handler, two secrets on adjacent lines), so only findings
        # from different reviewers can be duplicates. Reviewers pick different CWEs for the same flaw
        # (CWE-345 vs CWE-347, CWE-862 vs CWE-285), so on truly overlapping lines the OWASP class
        # decides, backed by the same CWE, the same check id or near-identical spans.
        if set(a.get("sources", [])) & set(b.get("sources", [])):
            return a["title"].lower() == b["title"].lower()
        return same_flaw_across_reviewers(a, b)
    # Same weakness nearby => duplicate. Empty ids never match (None == None would merge unrelated
    # findings that simply have no category/CWE).
    if (a.get("cwe") and a.get("cwe") == b.get("cwe")) or (a.get("category") and a.get("category") == b.get("category")):
        return True
    if a["owasp"] == b["owasp"] and a["title"].lower() == b["title"].lower():
        return True
    # A reviewer finding absorbs an untriaged scanner hit of the same OWASP class only when the lines
    # really overlap (no slack) and the CWEs don't contradict — otherwise a distinct flaw a few lines
    # away (command injection next to SQL injection, both A05) would silently vanish from the report.
    lines_overlap = a["line_start"] <= b["line_end"] and b["line_start"] <= a["line_end"]
    cwe_conflict = bool(a.get("cwe") and b.get("cwe") and a["cwe"] != b["cwe"])
    return (a["owasp"] == b["owasp"] and lines_overlap and not cwe_conflict
            and ((a["status"] in SCANNER_STATUSES) != (b["status"] in SCANNER_STATUSES)))


def score(f):
    return round(SEV_WEIGHT[f["severity"]] * CONF_F[f["confidence"]] * REQUIRES.get(f["requires"], 1.0), 2)


# ------------------------------------------------------------------ Markdown tables
# Cell rules (references/report-tables.md) hold for both renderers of report.md: GFM (markdown-it,
# GitHub, tl-md-to-html) and render_html.py. One line per cell, every `|` escaped (GFM splits inside
# code spans too), `<`/`>` only inside code (raw, GFM would read `List<int>` as an HTML tag), even
# number of backticks (render_html.py toggles code on each one), empty cell = `-`.
_ANGLE_TOKEN = re.compile(r"[^\s`]*[<>][^\s`]*")


def md_cell(value):
    s = "-" if value is None else str(value)
    s = re.sub(r"\s+", " ", s.replace("\\|", "|")).strip()  # re-escaped below: idempotent
    if s.count("`") % 2:
        s = s.replace("`", "'")
    parts = s.split("`")  # even indexes are outside code spans
    for i in range(0, len(parts), 2):
        parts[i] = _ANGLE_TOKEN.sub(lambda m: f"`{m.group(0)}`", parts[i])
    s = "`".join(parts).replace("|", "\\|")
    return s or "-"


def table(rows, headers):
    """GFM pipe table with exactly len(headers) cells per row (see references/report-tables.md)."""
    n = len(headers)
    out = ["| " + " | ".join(md_cell(h) for h in headers) + " |", "|" + "---|" * n]
    for r in rows:
        cells = [md_cell(c) for c in r][:n]
        out.append("| " + " | ".join(cells + ["-"] * (n - len(cells))) + " |")
    return "\n".join(out)


def _row_body(line):
    s = line.strip()
    s = s[1:] if s.startswith("|") else s
    return s[:-1] if s.endswith("|") and not s.endswith("\\|") else s


def _split_gfm(line):
    """How GFM renderers split a row: on every `|` not escaped by a backslash, code spans included."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", _row_body(line))]


def _split_code_aware(line, maxsplit=None):
    """How the writer meant the row: a `|` inside a code span is content (render_html.py splits this
    way). An escaped pipe stays escaped; md_cell normalizes it."""
    s, cells, buf, in_code, i = _row_body(line), [], "", False, 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and s[i + 1:i + 2] == "|":
            buf += "\\|"
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code and (maxsplit is None or len(cells) < maxsplit):
            cells.append(buf.strip())
            buf = ""
        else:
            buf += ch
        i += 1
    return cells + [buf.strip()]


def _cells(line, n):
    """Cells of an agent-written row and whether it breaks the rules. Prefer the writer's intent
    (code-aware split); fall back to the GFM split; then fold overflow into the last cell."""
    gfm, code = _split_gfm(line), _split_code_aware(line)
    if len(code) == n:
        return code, len(gfm) != n  # an unescaped `|` inside backticks breaks GFM renderers
    if len(gfm) == n:
        return gfm, False
    return (_split_code_aware(line, maxsplit=n - 1) if len(code) > n else code), True


_SEP_ROW = re.compile(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")


def normalize_md_tables(md):
    """Re-emit every pipe table in `md` (outside code fences) under the cell rules, with blank lines
    around it. Returns (markdown, [problems found]) so agent-written tables (surface.md, narrative)
    are fixed and reported instead of breaking the HTML."""
    lines, out, problems, i, fence = md.split("\n"), [], [], 0, False
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("```"):
            fence = not fence
        if fence or not (s.startswith("|") and i + 1 < len(lines) and _SEP_ROW.match(lines[i + 1].strip())):
            out.append(lines[i])
            i += 1
            continue
        n = len(_split_gfm(lines[i + 1]))  # the separator row fixes the column count
        head, bad = _cells(s, n)
        if bad:
            problems.append(f"table '{head[0]}…': header does not match the separator row")
        head = head + ["-"] * (n - len(head))  # emit n columns: table() would cut rows to len(head)
        rows, i = [], i + 2
        while i < len(lines) and lines[i].strip().startswith("|"):
            cells, bad = _cells(lines[i], n)
            if bad:
                problems.append(f"table '{head[0]}…': row needs repair (unescaped | or {n} cells expected): "
                                f"{lines[i].strip()[:60]}")
            rows.append(cells)
            i += 1
        if out and out[-1].strip():
            out.append("")
        out.append(table(rows, head))
        if i < len(lines) and lines[i].strip():
            out.append("")
    return "\n".join(out), problems


def loc(f):
    return f"`{f['file']}:{f['line_start']}" + (f"-{f['line_end']}`" if f["line_end"] != f["line_start"] else "`")


def bar(n, mx, width=20):
    return "█" * max(1 if n else 0, round(width * n / mx)) if mx else ""


# ------------------------------------------------------------------ merge

def cmd_merge(run):
    inv = read_json(run / "inventory.json", {})
    kind = inv.get("scope", {}).get("kind", "full")
    in_scope_files = {f["path"] for f in inv.get("files", []) if f.get("in_scope")}
    hits ={h["hit_id"]: h for h in read_json(run / "scan" / "hits.json", {"hits": []})["hits"]}
    deps = read_json(run / "deps.json", {})
    errors, findings, coverage, dismissed = [], [], [], []
    triaged, gate_answers = {}, {}

    for p in sorted((run / "findings").glob("*.json")):
        try:
            doc = read_json(p, {})
        except ValueError as e:  # half-written file from a crashed/timed-out reviewer
            errors.append({"origin": p.name, "id": None, "missing": [], "unreadable": f"invalid JSON: {e}"})
            coverage.append({"reviewer": p.stem, "shard": None, "file": p.name, "files_reviewed": 0,
                             "not_reviewed": [], "notes": "unreadable output — re-dispatch this reviewer"})
            continue
        if not isinstance(doc, dict):
            errors.append({"origin": p.name, "id": None, "missing": [], "unreadable": "top level is not an object"})
            continue
        origin = doc.get("reviewer", p.stem)
        coverage.append({"reviewer": origin, "shard": doc.get("shard"), "file": p.name,
                         "files_reviewed": len(doc.get("files_reviewed", [])),
                         "not_reviewed": [_not_reviewed(x) for x in doc.get("not_reviewed") or []],
                         "notes": doc.get("notes", "")})
        for t in doc.get("triage", []):
            if isinstance(t, dict):
                triaged[t.get("hit_id")] = {**t, "verdict": _lower(t.get("verdict"))}
        for g in doc.get("gates", []):
            if isinstance(g, dict):
                gate_answers[g.get("hit_id")] = {**g, "verdict": _lower(g.get("verdict"))}
        for f in doc.get("findings", []):
            nf = norm(f, errors, p.stem)  # per output file (S01, S02, surface): every shard reviewer is a separate source
            if nf:
                findings.append(nf)

    # Scanner findings: confirmed -> already folded into a reviewer finding; dismissed -> listed;
    # untouched -> kept, labelled so the report shows no human/agent looked at them.
    for hid, h in hits.items():
        if h["type"] != "finding":
            continue
        t = triaged.get(hid)
        if t and t.get("verdict") == "dismissed":
            dismissed.append({"hit_id": hid, "rule_id": h["rule_id"], "file": h["file"], "line": h["line"],
                              "reason": t.get("reason", "")})
            continue
        if t and t.get("verdict") in ("confirmed", "duplicate") and t.get("finding_id"):
            for f in findings:
                if f["id"] == t["finding_id"]:
                    src = f"{h.get('source', 'rule')}:{h['rule_id']}"
                    if hid not in f["from_hits"]:
                        f["from_hits"].append(hid)
                    if src not in f["sources"]:
                        f["sources"].append(src)
            continue
        if h.get("in_review_scope"):
            status = "untriaged"
        elif kind != "full" and not h.get("secret"):
            status = "out-of-scope"  # scoped run: shown separately, not mixed into the findings
        else:
            status = "unreviewed"
        f = from_hit(h, status)
        if kind != "full" and status == "unreviewed":
            # a secret outside a scoped run stays in the findings (a leak is a leak) but must not
            # read as something the changeset introduced
            f["title"] = "[outside review scope] " + f["title"]
        findings.append(f)

    # Dependencies: hygiene findings + one finding per vulnerable package.
    for i, h in enumerate(deps.get("hygiene", []), 1):
        f = from_hit({**h, "hit_id": f"D{i:03d}"}, "scanner")
        f["id"], f["kind"] = f"DEP-H{i:03d}", "weakness"
        findings.append(f)
    by_pkg = defaultdict(list)
    for v in deps.get("vulnerabilities", []):
        by_pkg[(v.get("ecosystem"), v.get("package"), v.get("version"))].append(v)
    for i, ((eco, pkg, ver), vs) in enumerate(sorted(by_pkg.items(), key=lambda kv: str(kv[0])), 1):
        sev = min((v["severity"] for v in vs), key=SEVERITIES.index)
        adv = ", ".join(str(v.get("advisory")) for v in vs[:5]) + (" …" if len(vs) > 5 else "")
        findings.append({"id": f"DEP-V{i:03d}", "kind": "vulnerability", "category": "vulnerable-dependency",
                         "owasp": "A03", "cwe": "CWE-1395", "title": f"{pkg} {ver or ''} has {len(vs)} known advisories",
                         "file": vs[0].get("manifest") or "dependencies", "line_start": 1, "line_end": 1,
                         "evidence": adv, "attack_scenario": "; ".join(v.get("summary", "") for v in vs[:3] if v.get("summary")) or adv,
                         "impact": "Depends on whether the vulnerable code path is reachable from this application.",
                         "fix": "Upgrade to a fixed version" + (f" ({vs[0].get('fixed_in')})" if vs[0].get("fixed_in") else "")
                                + "; if transitive, bump the direct parent or add an override/resolution.",
                         "severity": sev, "confidence": "high" if any(v["tool"] == "govulncheck" for v in vs) else "medium",
                         "requires": "unknown", "sources": sorted({v["tool"] for v in vs}), "status": "scanner",
                         "from_hits": [], "ecosystem": eco, "transitive": any(v.get("transitive") for v in vs)})

    if kind != "full":  # scoped run: dependency findings on manifests outside the scope are pre-existing
        for f in findings:
            if f["id"].startswith("DEP-") and f.get("file") not in in_scope_files:
                f["status"] = "out-of-scope"

    # Dedupe overlapping findings; independent agreement raises confidence.
    merged = []
    for f in sorted(findings, key=lambda x: (x["file"], x["line_start"], SEVERITIES.index(x["severity"]))):
        dup = next((m for m in merged if overlaps(m, f)), None)
        if not dup:
            merged.append(f)
            continue
        if f.get("trace") and not dup.get("trace") and dup["status"] in SCANNER_STATUSES and f["status"] in SCANNER_STATUSES:
            keep_sources, keep_hits, keep_id = dup["sources"], dup["from_hits"], dup["id"]
            sev = min(dup["severity"], f["severity"], key=SEVERITIES.index)
            dup.clear()
            dup.update(f)
            dup["severity"] = sev
            dup["sources"] = sorted(set(keep_sources) | set(f["sources"]))
            dup["from_hits"] = sorted(set(keep_hits) | set(f["from_hits"]))
            dup.setdefault("merged_ids", []).append(keep_id)
            if dup["confidence"] != "high":  # pattern rule + dataflow agree
                dup["confidence"] = CONFIDENCES[max(0, CONFIDENCES.index(dup["confidence"]) - 1)]
            continue
        if dup["status"] in SCANNER_STATUSES and f["status"] not in SCANNER_STATUSES:
            keep = {k: dup[k] for k in ("sources", "from_hits", "severity") if k in dup}
            keep_id = dup["id"]
            dup.clear()
            dup.update(f)
            dup["sources"] = sorted(set(keep["sources"]) | set(f["sources"]))
            dup["from_hits"] = sorted(set(keep["from_hits"]) | set(f["from_hits"]))
            dup.setdefault("merged_ids", []).append(keep_id)
            continue  # the reviewer's judgement (incl. severity) wins over the raw rule
        if SEVERITIES.index(f["severity"]) < SEVERITIES.index(dup["severity"]):
            dup["severity"] = f["severity"]
        dup["sources"] = sorted(set(dup["sources"]) | set(f["sources"]))
        dup["from_hits"] = sorted(set(dup["from_hits"]) | set(f["from_hits"]))
        dup.setdefault("merged_ids", []).append(f["id"])
        if len({s.split(":")[0] for s in dup["sources"]}) > 1 and dup["confidence"] != "high":
            dup["confidence"] = CONFIDENCES[max(0, CONFIDENCES.index(dup["confidence"]) - 1)]
    # Decisions from earlier runs (.security-audit/triage.yml) on code that has not changed since.
    n_triaged = apply_triage(merged, load_state(run).get("root") or inv.get("root", "."))
    for f in merged:
        f["priority"] = score(f)
    merged.sort(key=lambda f: -f["priority"])

    gates = [h for h in hits.values() if h["type"] == "gate"]
    gate_summary = {
        "total": len(gates),
        "in_scope": sum(1 for g in gates if g.get("in_review_scope")),
        "answered": sum(1 for g in gates if g["hit_id"] in gate_answers),
        "clear": sum(1 for a in gate_answers.values() if a.get("verdict") == "clear"),
        "candidate": sum(1 for a in gate_answers.values() if a.get("verdict") == "candidate"),
        "unknown": sum(1 for a in gate_answers.values() if a.get("verdict") == "unknown"),
        "unanswered_in_scope": [g["hit_id"] for g in gates if g.get("in_review_scope") and g["hit_id"] not in gate_answers],
        "by_rule": dict(Counter(g["rule_id"] for g in gates)),
    }
    merged = redact_obj(merged, secret_rules(run))
    write_json(run / "merged.json", {"generated_at": now_iso(), "findings": merged, "dismissed": dismissed,
                                     "coverage": coverage, "merge_errors": errors, "gates": gate_summary})
    st = Counter(f["status"] for f in merged)
    print(f"merged={len(merged)} ({dict(st)}) dismissed={len(dismissed)} schema_errors={len(errors)} "
          f"gates answered {gate_summary['answered']}/{gate_summary['in_scope']} in scope"
          + (f" known-from-triage.yml={n_triaged}" if n_triaged else ""))
    dropped = sum(1 for e in errors if e.get("missing") or e.get("unreadable"))
    if errors:
        print(f"schema problems: {dropped} dropped/unreadable, {len(errors) - dropped} coerced "
              "(fix the reviewer file or re-dispatch, then re-run merge)")
    for e in errors[:10]:
        print("  schema:", e)
    # A compact list, so the orchestrator can challenge findings without writing its own script.
    live = [f for f in merged if f["status"] not in NOT_LIVE]
    print(f"\n{'id':<10} {'sev':<8} {'conf':<6} {'status':<10} location  title")
    for f in live[:60]:
        also = f" (+{','.join(f['merged_ids'])})" if f.get("merged_ids") else ""
        print(f"{f['id']:<10} {f['severity']:<8} {f['confidence']:<6} {f['status']:<10} "
              f"{f['file']}:{f['line_start']}  {str(f['title'])[:90]}{also}")
    if len(live) > 60:
        print(f"... {len(live) - 60} more in merged.json")


# ------------------------------------------------------------------ verify

def cmd_verify_queue(run, top_k, batch_size, scope="default", append=False):
    doc = read_json(run / "merged.json")
    if not doc:
        sys.exit("merged.json missing — run 'merge' first")
    # append (second wave): keep the batches already dispatched and queue only findings none of
    # them covers — by id or by an id this finding absorbed when the new reviewer output was merged
    old = read_json(run / "verify_queue.json", {}).get("batches", []) if append else []
    queued = {i for b in old for i in b["ids"]}
    live = [f for f in doc["findings"] if f["status"] not in NOT_LIVE
            and not f["id"].startswith("DEP-")  # dependency advisories are verified by the tool, not by reading
            and f["id"] not in queued and not queued & set(f.get("merged_ids", []))]
    if scope == "strict":
        # solo mode: one opus-tier reviewer already read every file with the rubric, so verify where
        # being wrong is most expensive (critical, cost-risk) or where the reviewer itself was unsure
        q = [f for f in live if f["severity"] == "critical" or f["kind"] == "cost-risk" or f["confidence"] == "low"
             or (f["severity"] == "high" and f["confidence"] != "high")]
    else:
        q = [f for f in live if f["severity"] in ("critical", "high")
             or (f["severity"] == "medium" and f["confidence"] == "low") or f["kind"] == "cost-risk"]
    q = q[:top_k]
    # A second verifier for a handful of leftovers costs a whole agent; one larger batch is cheaper.
    if len(q) <= batch_size + batch_size // 2:
        batch_size = max(len(q), 1)
    # each batch carries a copy of its findings: a later merge rewrites merged.json while this
    # batch's verifier may still be reading
    batches = [{"batch": f"V{len(old) + i // batch_size + 1:02d}", "ids": [f["id"] for f in q[i:i + batch_size]],
                "findings": q[i:i + batch_size]}
               for i in range(0, len(q), batch_size)]
    write_json(run / "verify_queue.json", {"generated_at": now_iso(), "batches": old + batches})
    new = ", ".join(b["batch"] for b in batches) or "none"
    print(f"verify queue: {len(q)} findings in {len(batches)} {'new ' if append else ''}batches ({new})")


def apply_verification(doc, run):
    by_id = {f["id"]: f for f in doc["findings"]}
    for f in doc["findings"]:  # a verdict on a finding that a later merge folded into another one
        for m in f.get("merged_ids", []):
            by_id.setdefault(m, f)
    n = 0
    allowed = {"severity": SEVERITIES, "confidence": CONFIDENCES, "requires": REQUIRES, "kind": KINDS}
    for p in sorted((run / "verification").glob("*.json")):
        try:
            vdoc = read_json(p, {})
        except ValueError as e:
            print(f"WARNING: {p.name} is not valid JSON ({e}) — batch ignored; re-dispatch it")
            continue
        for v in vdoc.get("verdicts", []) if isinstance(vdoc, dict) else []:
            if not isinstance(v, dict):
                continue
            verdict = _lower(v.get("verdict"))
            f = by_id.get(v.get("id"))
            if not f or verdict not in ("confirmed", "rejected", "adjusted"):
                print(f"WARNING: {p.name}: ignored verdict {v!r} (unknown id, or verdict not "
                      "confirmed/rejected/adjusted)")
                continue
            n += 1
            f["status"] = {"confirmed": "verified", "rejected": "rejected", "adjusted": "verified"}[verdict]
            f["verification_note"] = v.get("note", "")
            for k, ok in allowed.items():
                val = _lower(v.get(k))
                if val in ok:
                    f[k] = val
                elif val:
                    print(f"WARNING: {p.name}: {v.get('id')}: ignored {k}={v.get(k)!r}")
            f["priority"] = score(f)
    doc["findings"].sort(key=lambda f: -f["priority"])
    return n


# ------------------------------------------------------------------ report

def detail(f):
    extra = []
    if f.get("cwe"):
        extra.append(f["cwe"])
    head = (f"#### {f['id']} · {f['title']}\n"
            f"{loc(f)} · {f['owasp']} {OWASP_2025.get(f['owasp'], '')} · {' · '.join(extra) + ' · ' if extra else ''}"
            f"**{f['severity']}** · confidence {f['confidence']} · requires {f['requires']} · {f['kind']} · {f['status']}"
            + (f" · {f['delta']}" + (f" (was {f['baseline_id']})" if f.get("baseline_id") else "") if f.get("delta") else "")
            + "\n")
    body = [f"- **Evidence:** {f['evidence']}", f"- **Attack scenario:** {f['attack_scenario']}",
            f"- **Impact:** {f['impact']}", f"- **Fix:** {f['fix']}",
            f"- **Sources:** {', '.join(f['sources'])}" + (f" (hits {', '.join(f['from_hits'][:6])})" if f["from_hits"] else "")]
    if f.get("note"):
        body.append(f"- **Note:** {f['note']}")
    if f.get("verification_note"):
        body.append(f"- **Verification:** {f['status']} — {f['verification_note']}")
    return head + "\n" + "\n".join(body) + "\n"


def cmd_report(run):
    doc = read_json(run / "merged.json")
    if not doc:
        sys.exit("merged.json missing — run 'merge' first")
    n_ver = apply_verification(doc, run)
    # Verifier notes arrive after merge redacted the reviewers' text; mask them before persisting.
    red = secret_rules(run)
    doc = redact_obj(doc, red)
    inv = read_json(run / "inventory.json", {})
    st = read_json(run / "state.json", {})
    delta = diff_runs(run, doc, st, inv) if st.get("root") else None
    doc["delta"] = delta
    write_json(run / "merged.json", doc)
    tools = read_json(run / "scan" / "tools.json", []) + read_json(run / "deps.json", {}).get("tools", [])
    narr = read_json(run / "narrative.json", {})
    shards = read_json(run / "shards.json", [])
    suppressed = read_json(run / "scan" / "suppressed.json", []) + read_json(run / "deps.json", {}).get("suppressed", [])
    surface_md = (run / "surface.md").read_text(encoding="utf-8") if (run / "surface.md").exists() else ""
    live = [f for f in doc["findings"] if f["status"] not in NOT_LIVE]
    known = [f for f in doc["findings"] if f["status"] in ("known-fp", "accepted-risk")]
    oos = [f for f in doc["findings"] if f["status"] == "out-of-scope"]
    rejected = [f for f in doc["findings"] if f["status"] == "rejected"]
    scope = inv.get("scope", {})
    g = doc.get("gates", {})

    L = [f"# Security Audit Report — {Path(inv.get('root', '.')).name}", ""]
    t = inv.get("totals", {})
    refs = scope.get("diff_refs") or {}
    L.append(table([[now_iso(), scope.get("kind", "full") + (f" vs `{scope['diff_base']}` "
                                                              f"({refs.get('merge_base')}→{refs.get('head')})" if refs else ""),
                     f"{t.get('reviewable_files', '?')}/{t.get('files', '?')}", ", ".join(sorted(inv.get("languages", {}))),
                     ", ".join(inv.get("frameworks", [])) or "-", len(live), len(rejected), n_ver]],
                   ["Generated", "Scope", "Files reviewed / scanned", "Languages", "Frameworks",
                    "Findings", "Rejected", "Verified"]))
    if st.get("authorization"):
        L += ["", f"Authorization: {st['authorization']}"]
    L += ["", "## Executive Summary", "", narr.get("executive_summary", "_(orchestrator: write narrative.json → executive_summary)_"), ""]

    # Coverage first: a partial review must never read like a clean one.
    L += ["## Coverage Gaps", ""]
    gaps = []
    for tl in tools:
        if tl.get("status") in ("failed", "skipped") and not str(tl.get("reason", "")).startswith("no "):
            gaps.append(f"- `{tl['tool']}` **{tl['status']}** — {tl.get('reason', '')}")
        if tl.get("rule_errors") or tl.get("check_errors"):
            gaps.append(f"- {len(tl.get('rule_errors', [])) + len(tl.get('check_errors', []))} rule/check files failed to load (see scan/tools.json)")
    deps = read_json(run / "deps.json", {})
    t_tool = next((t for t in tools if t.get("tool") == "taint"), None)
    if not t_tool or t_tool.get("status") != "ran":
        gaps.append("- **Taint analysis did not run** — injection/SSRF/path findings rely on single-line patterns only"
                    + (f" ({t_tool.get('reason')})" if t_tool and t_tool.get("reason") else "") + ".")
    else:
        if t_tool.get("engine") == "semgrep":
            gaps.append("- Taint engine is Semgrep CE: no cross-function flows inside a file (install OpenGrep).")
        langs = set(t_tool.get("languages") or [])
        present = {"csharp", "javascript", "typescript", "python", "go", "dart"} & set(inv.get("languages", {}))
        fam = {"typescript": "javascript"}
        missing = sorted({fam.get(l, l) for l in present} - langs)
        if missing:
            gaps.append(f"- No taint rule pack for: {', '.join(missing)}")
        if t_tool.get("errors"):
            gaps.append(f"- Taint engine reported {t_tool['errors']} errors (see scan/taint.json)")
        gaps.append(f"- Cross-file taint follows calls by name + argument position up to depth "
                    f"{read_json(run / 'scan' / 'taint.json', {}).get('depth', 3)}; dynamic dispatch, reflection, "
                    "DI by string, queues and HTTP hops between services are not followed.")
    if deps.get("ecosystems") and not deps.get("vuln_audit_ran"):
        gaps.append("- **No dependency vulnerability audit ran** — known CVEs in dependencies were not checked.")
    done = {c.get("shard") for c in doc.get("coverage", []) if c.get("shard")}
    missing = [s["id"] for s in shards if s["id"] not in done]
    if missing:
        gaps.append(f"- Shards not reviewed: {', '.join(missing)}")
    if scope.get("deferred_shards"):
        d = scope["deferred_shards"]
        gaps.append(f"- Deferred by --max-shards: {len(d)} shards, {sum(x['loc'] for x in d)} LOC (lower risk weight)")
    nr = [p for c in doc.get("coverage", []) for p in c.get("not_reviewed", [])]
    if nr:
        gaps.append(f"- Files skipped inside reviewed shards: {len(nr)} — {', '.join(nr[:8])}")
    if g.get("unanswered_in_scope"):
        gaps.append(f"- Gate sites not answered by any reviewer: {len(g['unanswered_in_scope'])}")
    if g.get("total", 0) == 0:
        gaps.append("- Zero gate sites were tagged — deep (authorization / business-logic) review had no anchors; "
                    "this is not evidence that access control is correct.")
    unt = sum(1 for f in live if f["status"] in ("untriaged", "unreviewed"))
    if unt:
        gaps.append(f"- {unt} scanner findings were not triaged by a reviewer (status untriaged/unreviewed)")
    unv = [f["id"] for f in live if f["severity"] in ("critical", "high") and f["status"] not in ("verified", "scanner")]
    if unv:
        gaps.append(f"- {len(unv)} critical/high findings not verified: {', '.join(unv[:10])}" + (" …" if len(unv) > 10 else ""))
    if scope.get("kind") == "changeset":
        gaps.append("- Changeset scope: only changed files (+ one hop of callers/callees) were reviewed; "
                    "no whole-system claims (OWASP checklist, data classification, compliance) are made.")
    missed = [x for x in (delta or {}).get("gone", []) if x["reason"] == "code unchanged, not reported"]
    if missed:
        gaps.append(f"- {len(missed)} findings of the previous run sit on unchanged code but were not reported "
                    "this run (possible misses — see Changes Since Previous Run): "
                    + ", ".join(f"{x['id']} `{x['file']}:{x['line_start']}`" for x in missed[:6]))
    drop = [e for e in doc.get("merge_errors", []) if e.get("missing") or e.get("unreadable")]
    if drop:
        gaps.append(f"- Reviewer output schema problems: {len(drop)} findings/files dropped (see merged.json)")
    L += gaps or ["- None recorded."]

    L += ["", "## Dashboard", ""]
    sev = Counter(f["severity"] for f in live)
    tot = len(live) or 1
    L.append(table([[s, sev[s], f"{100 * sev[s] / tot:.0f}%", bar(sev[s], max(sev.values() or [0]))]
                    for s in SEVERITIES if sev[s]], ["Severity", "Count", "%", "Share"]))
    L += [""]
    ow = defaultdict(Counter)
    for f in live:
        ow[f["owasp"]][f["severity"]] += 1
    L.append(table([[k, OWASP_2025[k]] + [ow[k][s] for s in SEVERITIES] + [sum(ow[k].values())]
                    for k in sorted(ow)], ["OWASP 2025", "Category"] + SEVERITIES + ["Total"]))
    area = Counter((Path(f["file"]).parts[0] if len(Path(f["file"]).parts) > 1 else "(root)") for f in live)
    L += ["", table([[a, n, bar(n, max(area.values()))] for a, n in area.most_common(10)], ["Area", "Findings", "Share"])]
    L += ["", f"Gate sites: {g.get('total', 0)} tagged, {g.get('in_scope', 0)} in scope, {g.get('answered', 0)} answered "
              f"({g.get('clear', 0)} clear, {g.get('candidate', 0)} candidate, {g.get('unknown', 0)} unknown)."]

    L += ["", "## Changes Since Previous Run", ""]
    if delta:
        gone = delta["gone"]
        L.append(f"Baseline: `{Path(delta['baseline']).name}` ({delta.get('baseline_created') or '?'}). "
                 f"{delta['new']} new, {delta['persisting']} persisting, {len(gone)} no longer reported.")
        if gone:
            L += ["", table([[x["id"], x["title"], f"`{x['file']}:{x['line_start']}`", x["severity"], x["reason"]]
                             for x in gone[:40]], ["Previous ID", "Title", "Location", "Severity", "Why gone"])]
            if len(gone) > 40:
                L.append(f"… and {len(gone) - 40} more (merged.json → delta)")
            L += ["", "_code changed_ = likely fixed, confirm; _code unchanged, not reported_ = possibly missed "
                      "this run, re-check before treating it as fixed."]
    else:
        L.append("_No previous finished run of this repository found — every finding is new._")

    top = [f for f in live if f["severity"] in ("critical", "high")]
    L += ["", "## Critical and High Findings", ""]
    L += [detail(f) for f in top] or ["_None._"]

    rest = [f for f in live if f["severity"] not in ("critical", "high") and not f["id"].startswith("DEP-V")]
    L += ["", "## Other Findings by OWASP Category", ""]
    for k in sorted({f["owasp"] for f in rest}):
        sel = [f for f in rest if f["owasp"] == k]
        L += [f"### {k} {OWASP_2025[k]}", "",
              table([[f["id"], f["title"], loc(f), f["severity"], f["confidence"], f["status"]] for f in sel],
                    ["ID", "Title", "Location", "Severity", "Confidence", "Status"]), ""]
        L += [detail(f) for f in sel if f["severity"] == "medium"]
    if not rest:
        L.append("_None._")

    dv = [f for f in live if f["id"].startswith("DEP-V")]
    L += ["", "## Dependencies", ""]
    L.append(table([[f["id"], f["title"], f["severity"], f.get("ecosystem", ""), "yes" if f.get("transitive") else "no",
                     f["evidence"]] for f in dv], ["ID", "Package", "Severity", "Ecosystem", "Transitive", "Advisories"])
             if dv else "_No known-vulnerable packages reported" + ("" if deps.get("vuln_audit_ran") else " (no audit tool ran)") + "._")

    if oos:
        L += ["", "## Outside Review Scope", "",
              f"{len(oos)} scanner hits in files outside this run's review scope (not reviewed, not counted above):", "",
              table([[f["id"], f["title"], loc(f), f["severity"]] for f in oos[:40]], ["ID", "Title", "Location", "Severity"])]
        if len(oos) > 40:
            L.append(f"… and {len(oos) - 40} more (see merged.json)")
    L += ["", "## Security Architecture", ""]
    if scope.get("kind") == "changeset" and not surface_md:
        L.append("_Omitted in changeset scope — requires a full-scope run._")
    else:
        L.append(surface_md or "_(orchestrator/surface reviewer: write surface.md)_")

    if known:
        L += ["", "## Known from Earlier Runs", "",
              f"{len(known)} findings match a decision in `.security-audit/triage.yml` on unchanged code "
              "(not counted above; review the list when the threat model changes):", "",
              table([[f["id"], f["title"], loc(f), f["severity"], f["triage"]["verdict"], f["triage"].get("id"),
                      f["triage"]["reason"], f["triage"].get("until") or "-"] for f in known[:60]],
                    ["ID", "Title", "Location", "Severity", "Verdict", "Entry", "Reason", "Until"])]
    L += ["", "## Dismissed and Suppressed", ""]
    dis = Counter(d["rule_id"] for d in doc.get("dismissed", []))
    sup = Counter(s["rule_id"] for s in suppressed)
    rows = [[r, dis.get(r, 0), sup.get(r, 0)] for r in sorted(set(dis) | set(sup), key=lambda r: (-(dis[r] + sup[r]), r))]
    L.append(table(rows[:15], ["Rule", "Dismissed by reviewer", "Suppressed"]) if rows else "_None._")
    if rejected:
        L += ["", "Rejected by verifier: " + ", ".join(f"{f['id']}" for f in rejected[:20])]
    L += ["", "## Remediation Roadmap", "", narr.get("roadmap", "_(orchestrator: write narrative.json → roadmap)_"), ""]
    # one pass over the whole report: also repairs tables written by agents (surface.md, narrative)
    report, problems = normalize_md_tables("\n".join(L))
    (run / "report.md").write_text(redact_text(report, red), encoding="utf-8")
    for pr in problems[:10]:
        print(f"WARNING: table repaired — {pr} (follow references/report-tables.md)")
    print(f"report.md written: {len(live)} findings ({dict(sev)}), {len(rejected)} rejected, "
          f"{len(known)} known from triage.yml, {len(gaps)} coverage gaps"
          + (f"; vs previous run: {delta['new']} new, {delta['persisting']} persisting, {len(delta['gone'])} gone"
             if delta else ""))
    if rejected or doc.get("dismissed"):
        print("learn: `scripts/memory.py learn --run-dir <RUN_DIR>` proposes triage.yml entries from the "
              "rejected/dismissed items — show them to the user and apply only approved ones")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["merge", "verify-queue", "report"])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--top-k", type=int, default=30)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--scope", choices=["default", "strict"], default="default",
                    help="verify-queue: strict = critical, cost-risk and not-high-confidence only (solo mode)")
    ap.add_argument("--append", action="store_true",
                    help="verify-queue: keep dispatched batches, queue only findings they do not cover (second wave)")
    a = ap.parse_args()
    run = Path(a.run_dir)
    if a.cmd == "merge":
        cmd_merge(run)
    elif a.cmd == "verify-queue":
        cmd_verify_queue(run, a.top_k, a.batch_size, a.scope, a.append)
    else:
        cmd_report(run)


if __name__ == "__main__":
    main()
