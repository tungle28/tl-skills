#!/usr/bin/env python3
"""
aggregate_findings.py — Phase 5 of the tl-code-review harness.

Merges reviewer outputs, applies verifier verdicts, de-duplicates overlapping
findings, suppresses known issues via a baseline, computes the verdict, and
renders the final Markdown report.

Inputs (all under --dir, default: the latest run, .code-review/latest):
  findings/*.json   one file per shard: {"shard": "S01", "coverage": {...}, "findings": [...]}
                    (a bare JSON array of findings is also accepted)
  verify/*.json     optional: [{"id": "S01-003", "verdict": "confirmed|rejected|uncertain",
                                "severity": "<optional downgrade/upgrade>", "note": "..."}]
  manifest.json, shards.json, static.json, blast.json  (optional, for context sections)
  pr_context.json   optional: CI checks + existing human review comments (fetch_pr_context.py / connector)
  requirements.json optional: [{"ticket": "PAY-12", "criterion": "...", "status": "met|partial|missing|unverifiable",
                                "evidence": "file:line or reason"}]  (written by the cross-cutting reviewer)

Usage
  python aggregate_findings.py --dir $RUN --out $RUN/report.md
  python aggregate_findings.py ... --baseline .code-review/baseline.json      # hide known findings
  python aggregate_findings.py ... --write-baseline                           # snapshot current findings
  python aggregate_findings.py ... --lang vi                                  # Vietnamese section headings
                                  (any BCP-47 tag; vi-VN -> vi, unsupported languages -> en with a warning)
Exit code: 0 approve/comment, 2 request changes (usable as a CI gate), 1 usage error.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under `python -I`
import run_dir  # noqa: E402

SEV_ORDER = {"blocker": 0, "major": 1, "minor": 2, "nit": 3}
SEV_ICON = {"blocker": "🔴", "major": "🟠", "minor": "🟡", "nit": "⚪"}
CONF_ORDER = {"high": 0, "medium": 1, "low": 2}

L10N = {
    "en": {
        "title": "Code Review Report", "scope": "Scope", "verdict": "Verdict", "summary": "Summary",
        "blockers": "Blockers — must fix before merge", "major": "Major — should fix",
        "minor": "Minor", "nits": "Nits", "needs_check": "Needs human confirmation (unverified / low confidence)",
        "preexisting": "Pre-existing issues (not introduced by this change)", "tooling": "Tooling signals",
        "blast": "Blast radius — call sites outside the diff", "coverage": "Coverage & limits",
        "checks": "Checks run", "skipped": "Skipped", "skipped_none": "nothing beyond the defaults",
        "positives": "What looks good", "none": "None.",
        "reqs": "Requirement coverage", "ci": "CI status (from PR platform)",
        "raised": "already raised by a human reviewer",
        "v_block": "❌ REQUEST CHANGES", "v_comment": "💬 APPROVE WITH COMMENTS", "v_ok": "✅ APPROVE",
        "v_assess": "📋 ASSESSMENT (no merge verdict for non-diff scope)",
    },
    "vi": {
        "title": "Báo cáo Code Review", "scope": "Phạm vi", "verdict": "Kết luận", "summary": "Tóm tắt",
        "blockers": "Blocker — bắt buộc sửa trước khi merge", "major": "Major — nên sửa",
        "minor": "Minor", "nits": "Nit", "needs_check": "Cần người xác nhận (chưa verify / độ tin cậy thấp)",
        "preexisting": "Vấn đề có sẵn (không do thay đổi này gây ra)", "tooling": "Tín hiệu từ tooling",
        "blast": "Blast radius — call site ngoài diff", "coverage": "Độ phủ & giới hạn",
        "checks": "Kiểm tra đã chạy", "skipped": "Bỏ qua", "skipped_none": "không có gì ngoài mặc định",
        "positives": "Điểm tốt", "none": "Không có.",
        "reqs": "Độ phủ yêu cầu (ticket)", "ci": "Trạng thái CI (từ nền tảng PR)",
        "raised": "reviewer khác đã nêu",
        "v_block": "❌ REQUEST CHANGES", "v_comment": "💬 APPROVE WITH COMMENTS", "v_ok": "✅ APPROVE",
        "v_assess": "📋 ĐÁNH GIÁ (không áp dụng verdict merge cho phạm vi không phải diff)",
    },
}


def group_paths(paths, limit=15):
    """Excluded paths grouped by top-level folder for the report: ['`.pnpm-store/` (812)', '`a.lock`']."""
    groups = {}
    for p in paths:
        head, sep, _ = p.partition("/")
        key = head + sep
        groups[key] = groups.get(key, 0) + 1
    items = sorted(groups.items(), key=lambda kv: (-kv[1], kv[0]))
    out = [f"`{k}`" + (f" ({n})" if n > 1 or k.endswith("/") else "") for k, n in items[:limit]]
    if len(items) > limit:
        out.append(f"… +{sum(n for _, n in items[limit:])} more excluded files")
    return out


def checks_run(T, manifest, plan, static, blast, prctx, reqs, coverage, verdicts):
    """'Checks run' and 'Skipped' near the top of report.md: what this review executed (scope, static
    tools, reviewers, verifier, blast radius, PR context) and what it did not read."""
    s = manifest.get("stats", {})
    out = [f"\n## {T['checks']}\n\n",
           f"- `resolve_scope.py` — **ran** — mode `{manifest.get('mode', '?')}`, {s.get('files', '?')} files"
           + (f", {s['total_lines_in_scope']} lines in scope" if s.get("total_lines_in_scope") else "") + "\n"]
    for name, e in (static.get("checks") or {}).items():
        st = ("not run" if not static.get("ran") else
              "pass" if e.get("exit_code") == 0 else f"fail (exit {e.get('exit_code')})")
        out.append(f"- `{e.get('cmd', name)}` — **{st}** — {name}\n")
    if static and not static.get("checks"):
        out.append("- Static tools — **not run**\n")
    read = sum(len(c.get("reviewed") or []) for c in coverage)
    planned = {x.get("id") for x in plan.get("shards") or [] if isinstance(x, dict)}
    done = sum(1 for c in coverage if c.get("shard") in planned)
    extra = len(coverage) - done  # cross-cutting and lens passes are not shards
    out.append(f"- Reviewer sub-agents — **{'ran' if coverage else 'not run'}** — "
               + (f"{done}/{len(planned)} shards" if planned else f"{len(coverage)} passes")
               + (f" + {extra} cross-cutting/lens passes" if planned and extra > 0 else "")
               + f", {read} files read" + (f" (depth {plan['depth']})" if plan.get("depth") else "") + "\n")
    out.append(f"- Verifier — **{'ran' if verdicts else 'not run'}** — {len(verdicts)} verdicts\n")
    if blast.get("symbols"):
        syms = blast["symbols"]
        out.append(f"- `blast_radius.py` — **ran** — {len(syms)} changed symbols, "
                   f"{sum(x.get('ref_count') or 0 for x in syms)} references\n")
    if manifest.get("pr"):
        if prctx.get("available"):
            out.append("- PR context — **ran**" + (f" — CI {prctx['ci_summary']}" if prctx.get("ci_summary") else "") + "\n")
        else:
            out.append(f"- PR context — **unavailable** — {prctx.get('reason', 'not fetched')}\n")
    if reqs:
        out.append(f"- Requirement check — **ran** — {len(reqs)} criteria\n")
    skipped = group_paths(manifest.get("excluded") or [])
    if manifest.get("truncated"):
        skipped.append(f"{len(manifest['truncated'])} files beyond --max-files")
    if plan.get("overflow"):
        skipped.append(f"{len(plan['overflow'])} low-risk shards deferred: "
                       + ", ".join(f"`{o['module']}`" for o in plan["overflow"][:6]))
    out.append(f"\n{T['skipped']}: " + (", ".join(skipped) if skipped else T["skipped_none"]) + ".\n")
    return out


def load_json(p, default=None):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def fingerprint(f):
    title = re.sub(r"[^a-z0-9 ]", "", f.get("title", "").lower())
    title = " ".join(sorted(set(title.split())))[:120]
    raw = f"{f.get('file', '')}|{f.get('category', '')}|{title}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def overlaps(a, b, slack=3):
    if a.get("file") != b.get("file"):
        return False
    a1, a2 = a.get("line_start", 0), a.get("line_end", a.get("line_start", 0))
    b1, b2 = b.get("line_start", 0), b.get("line_end", b.get("line_start", 0))
    return a1 - slack <= b2 and b1 - slack <= a2


# Categories reviewers use interchangeably for one defect (a specialist pass and the generalist
# shard reviewer, or a shard reviewer and the cross-cutting reviewer, often label it differently).
RELATED_CATEGORIES = [{"concurrency", "data"}, {"correctness", "data"},
                      {"error-handling", "resilience", "observability"}, {"tests", "test-quality"},
                      {"api-contract", "backward-compat"}]
IDENT_RX = re.compile(r"\b[A-Za-z_][a-z0-9_]*[A-Z][A-Za-z0-9_]*\b")  # camelCase / PascalCase code names


def span_coverage(a, b):
    """Overlapping lines as a share of the shorter finding's span."""
    a1, a2 = a.get("line_start", 0), a.get("line_end", a.get("line_start", 0))
    b1, b2 = b.get("line_start", 0), b.get("line_end", b.get("line_start", 0))
    overlap = min(a2, b2) - max(a1, b1) + 1
    return max(overlap, 0) / max(min(a2 - a1, b2 - b1) + 1, 1)


def title_words(f):
    # \w{2,}, not longer: Vietnamese syllables are short, and a 4-letter floor dropped most of them.
    return set(re.findall(r"\w{2,}", f.get("title", "").lower()))


def same_issue(a, b):
    if not overlaps(a, b):
        return False
    if a.get("category") == b.get("category"):
        return True
    ta, tb = title_words(a), title_words(b)
    jaccard = len(ta & tb) / max(len(ta | tb), 1)
    if jaccard >= 0.5:
        return True
    if span_coverage(a, b) < 0.5:
        return False
    cats = {a.get("category"), b.get("category")}
    if any(cats <= group for group in RELATED_CATEGORIES):
        return True
    # Same code name in both titles and some shared wording: one defect described twice. The wording
    # floor keeps two different claims about one function (e.g. "setBalance overwrites the balance"
    # vs "setBalance returns nothing") apart.
    shared_ident = set(IDENT_RX.findall(a.get("title", ""))) & set(IDENT_RX.findall(b.get("title", "")))
    return bool(shared_ident) and jaccard >= 0.1


def validate(f):
    required = ("file", "severity", "category", "title", "why")
    missing = [k for k in required if not f.get(k)]
    if f.get("severity") not in SEV_ORDER:
        missing.append("severity(enum)")
    return missing


class UsageErrorParser(argparse.ArgumentParser):
    """argparse exits 2 on a bad argument, the same code as a 'request changes' verdict; exit 1 instead
    so a CI gate cannot read a usage error as a review result."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = UsageErrorParser()
    ap.add_argument("--dir", help="the run folder (default: the latest run)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--lang", default="en", help="BCP-47 tag; en and vi have headings, others fall back to en")
    ap.add_argument("--max-nits", type=int, default=10)
    a = ap.parse_args()
    a.lang = run_dir.norm_lang(a.lang, "aggregate")
    a.dir = a.dir or str(run_dir.latest())
    d = Path(a.dir)
    T = L10N[a.lang]

    manifest = load_json(d / "manifest.json", {})
    plan = load_json(d / "shards.json", {})
    static = load_json(d / "static.json", {})
    blast = load_json(d / "blast.json", {})
    prctx = load_json(d / "pr_context.json", {}) or {}
    reqs = load_json(d / "requirements.json", []) or []
    is_diff = manifest.get("mode") in ("uncommitted", "staged", "changeset")

    findings, coverage, positives, invalid = [], [], [], []
    for p in sorted((d / "findings").glob("*.json")):
        data = load_json(p)
        if data is None:
            invalid.append(f"{p.name}: unparsable JSON")
            continue
        items = data if isinstance(data, list) else data.get("findings", [])
        shard = None if isinstance(data, list) else data.get("shard")
        if isinstance(data, dict):
            if data.get("coverage"):
                coverage.append({"shard": shard, **data["coverage"]})
            positives += data.get("positives", [])[:3]
        for i, f in enumerate(items, 1):
            f.setdefault("id", f"{shard or p.stem}-{i:03d}")
            f.setdefault("confidence", "medium")
            f.setdefault("in_diff", True)
            miss = validate(f)
            if miss:
                invalid.append(f"{f['id']}: missing {','.join(miss)}")
                continue
            findings.append(f)

    # Apply verifier verdicts
    verdicts = {}
    for p in sorted((d / "verify").glob("*.json")) if (d / "verify").exists() else []:
        for v in load_json(p, []) or []:
            if v.get("id"):
                verdicts[v["id"]] = v
    dropped = []
    kept = []
    for f in findings:
        v = verdicts.get(f["id"])
        if v:
            f["verification"] = v.get("verdict")
            if v.get("note"):
                f["verify_note"] = v["note"]
            if v.get("verdict") == "rejected":
                dropped.append(f)
                continue
            if v.get("severity") in SEV_ORDER and v["severity"] != f["severity"]:
                f["original_severity"] = f["severity"]
                f["severity"] = v["severity"]
        else:
            f["verification"] = "unverified"
        kept.append(f)
    rejected = len(dropped)

    # Restatements the verifier marked (duplicate_of), including ones cited from another file,
    # which the line-overlap rule below cannot see. The canonical finding keeps the higher severity.
    by_id = {f["id"]: f for f in kept}
    for f in list(kept):
        target = by_id.get((verdicts.get(f["id"]) or {}).get("duplicate_of"))
        while target is not None and target.get("_merged_into"):
            target = by_id.get(target["_merged_into"])
        if target is None or target is f:
            continue
        target.setdefault("also_reported_as", []).extend([f["id"]] + f.pop("also_reported_as", []))
        if SEV_ORDER[f["severity"]] < SEV_ORDER[target["severity"]]:
            target["severity"] = f["severity"]
        f["_merged_into"] = target["id"]
    kept = [f for f in kept if not f.pop("_merged_into", None)]

    # De-duplicate: keep most severe / most confident, merge sources
    kept.sort(key=lambda f: (SEV_ORDER[f["severity"]], CONF_ORDER.get(f["confidence"], 1)))
    merged = []
    for f in kept:
        dup = next((m for m in merged if same_issue(m, f)), None)
        if dup:
            dup.setdefault("also_reported_as", []).extend([f["id"]] + f.get("also_reported_as", []))
        else:
            merged.append(f)

    # Baseline suppression
    for f in merged:
        f["fingerprint"] = fingerprint(f)
    suppressed = 0
    if a.baseline and Path(a.baseline).exists():
        known = set(load_json(a.baseline, {}).get("fingerprints", []))
        before = len(merged)
        merged = [f for f in merged if f["fingerprint"] not in known]
        suppressed = before - len(merged)

    # Mark findings a human already raised on (nearly) the same lines. They stay in
    # the report for completeness but are labelled and never re-posted to the PR.
    human = [c for c in prctx.get("review_comments", []) if not c.get("is_bot") and c.get("path") and c.get("line")]
    for f in merged:
        for c in human:
            if c["path"] == f["file"] and f.get("line_start") and \
                    f["line_start"] - 3 <= c["line"] <= f.get("line_end", f["line_start"]) + 3:
                f["already_raised"] = c.get("author") or True
                break

    # Buckets
    def needs_check(f):
        # Findings that should have been verified but weren't (every blocker, medium-confidence
        # majors), uncertain ones, and low confidence go to a separate bucket instead of silently
        # driving the verdict or silently disappearing. High-confidence majors are not sent to
        # verification, so "unverified" alone doesn't demote them.
        if f["confidence"] == "low" or f["verification"] == "uncertain":
            return True
        return f["verification"] == "unverified" and (
            f["severity"] == "blocker" or (f["severity"] == "major" and f["confidence"] != "high"))

    pre = [f for f in merged if is_diff and not f.get("in_diff", True)]
    main_f = [f for f in merged if f not in pre]
    check = [f for f in main_f if needs_check(f)]
    solid = [f for f in main_f if f not in check]
    by_sev = {s: [f for f in solid if f["severity"] == s] for s in SEV_ORDER}

    if not is_diff:
        verdict = T["v_assess"]
        code = 0
    elif by_sev["blocker"]:
        verdict, code = T["v_block"], 2
    elif prctx.get("ci_summary") == "failing":
        verdict, code = T["v_block"] + " (CI failing)", 2
    elif by_sev["major"] or check or any(r.get("status") == "missing" for r in reqs):
        verdict, code = T["v_comment"], 0
    else:
        verdict, code = T["v_ok"], 0

    # ---------------------------------------------------------- render
    L = []
    s = manifest.get("stats", {})
    L.append(f"# {T['title']}\n\n")
    scope = f"**{T['scope']}:** `{manifest.get('mode', '?')}`"
    if manifest.get("base"):
        scope += f" · `{manifest.get('base')}` → `{manifest.get('head')}`"
    if manifest.get("filters", {}).get("paths"):
        scope += f" · paths: `{', '.join(manifest['filters']['paths'])}`"
    if manifest.get("filters", {}).get("keywords"):
        scope += f" · keywords: `{', '.join(manifest['filters']['keywords'])}`"
    L.append(scope + f" · {s.get('files', '?')} files · +{s.get('added', 0)}/-{s.get('deleted', 0)}\n\n")
    L.append(f"**{T['verdict']}:** {verdict}\n\n")
    counts = " · ".join(f"{SEV_ICON[k]} {k}: {len(v)}" for k, v in by_sev.items())
    L.append(f"**{T['summary']}:** {counts} · needs-check: {len(check)} · pre-existing: {len(pre)} "
             f"· rejected by verifier: {rejected} · baseline-suppressed: {suppressed}"
             + (f" · CI: {prctx['ci_summary']}" if prctx.get("available") else "") + "\n\n")
    if manifest.get("intent"):
        L.append("<details><summary>Change intent (commit messages)</summary>\n\n```\n"
                 + "\n".join(manifest["intent"][:30]) + "\n```\n</details>\n")

    L += checks_run(T, manifest, plan, static, blast, prctx, reqs, coverage, verdicts)

    def render(title, items, full=True, limit=None):
        L.append(f"\n## {title}\n\n")
        if not items:
            L.append(T["none"] + "\n")
            return
        shown = items[:limit] if limit else items
        for f in shown:
            loc = f["file"] + (f":{f['line_start']}" if f.get("line_start") else "")
            if f.get("line_end") and f.get("line_end") != f.get("line_start"):
                loc += f"-{f['line_end']}"
            tag = f"`{f['category']}` · conf: {f['confidence']} · {f['verification']}"
            if f.get("already_raised"):
                who = f["already_raised"] if isinstance(f["already_raised"], str) else ""
                tag += f" · 💬 {T['raised']}" + (f" (@{who})" if who else "")
            L.append(f"\n### {SEV_ICON[f['severity']]} [{f['id']}] {f['title']}\n\n")
            L.append(f"`{loc}` · {tag}\n\n")
            if full:
                if f.get("evidence"):
                    L.append(f"\n```\n{f['evidence'].rstrip()}\n```\n")
                L.append(f"\n**Why it matters:** {f['why']}\n")
                if f.get("scenario"):
                    L.append(f"\n**Failure scenario:** {f['scenario']}\n")
                if f.get("suggestion"):
                    L.append(f"\n**Suggested fix:** {f['suggestion']}\n")
                if f.get("verify_note"):
                    L.append(f"\n_Verifier:_ {f['verify_note']}\n\n")
            else:
                L.append(f"{f['why']}" + (f" → {f['suggestion']}" if f.get("suggestion") else "") + "\n")
            if f.get("also_reported_as"):
                L.append(f"\n_Also reported as: {', '.join(f['also_reported_as'])}_\n")
        if limit and len(items) > limit:
            L.append(f"\n_…and {len(items) - limit} more (see findings.json)._\n")

    render(T["blockers"], by_sev["blocker"])
    render(T["major"], by_sev["major"])
    render(T["needs_check"], check)
    render(T["minor"], by_sev["minor"], full=False)
    render(T["nits"], by_sev["nit"], full=False, limit=a.max_nits)
    if is_diff:
        render(T["preexisting"], pre, full=False, limit=15)

    if blast and blast.get("symbols"):
        L.append(f"\n## {T['blast']}\n")
        L.append("| Symbol | Change | Refs outside diff | Example call site |\n|---|---|---|---|\n")
        for sym in blast["symbols"][:10]:
            ext = next((r for r in sym["refs"] if not r["in_scope"]), None)
            ex = f"`{ext['file']}:{ext['line']}`" if ext else "-"
            L.append(f"| `{sym['symbol']}` | {','.join(sym['change'])} | {sym['out_of_scope_refs']} | {ex} |\n")

    if reqs:
        icon = {"met": "✅", "partial": "🟡", "missing": "❌", "unverifiable": "❔"}
        L.append(f"\n## {T['reqs']}\n\n| Ticket | Criterion | Status | Evidence |\n|---|---|---|---|\n")
        for r in reqs:
            L.append(f"| {r.get('ticket', '')} | {r.get('criterion', '')} | {icon.get(r.get('status'), '')} "
                     f"{r.get('status', '')} | {r.get('evidence', '')} |\n")
        missing = [r for r in reqs if r.get("status") in ("missing", "partial")]
        if missing:
            L.append(f"\n{len(missing)} criterion(s) not fully implemented.\n")

    if prctx.get("available") and prctx.get("checks"):
        L.append(f"\n## {T['ci']}\n\n**{prctx.get('ci_summary', '?')}**\n\n")
        for c in prctx["checks"][:20]:
            mark = {"pass": "✅", "fail": "❌", "pending": "⏳", "skipping": "⏭️"}.get(c.get("bucket"), "•")
            L.append(f"- {mark} {c.get('name')}" + (f" — {c['link']}" if c.get("link") else "") + "\n")

    if positives:
        L.append(f"\n## {T['positives']}\n")
        for p in positives[:6]:
            L.append(f"- {p}\n")

    L.append(f"\n## {T['coverage']}\n")
    if plan.get("shards"):
        L.append(f"- Shards reviewed: {len(plan['shards'])} (depth: {plan.get('depth')})\n")
    if plan.get("overflow"):
        L.append(f"- ⚠️ Deferred low-risk shards (not reviewed): {len(plan['overflow'])} — "
                 + ", ".join(o["module"] for o in plan["overflow"][:8]) + "\n")
    if manifest.get("truncated"):
        L.append(f"- ⚠️ Files beyond --max-files cap (not reviewed): {len(manifest['truncated'])}\n")
    for c in coverage:
        skipped = c.get("skipped") or c.get("not_reviewed")
        if skipped:
            L.append(f"- {c.get('shard')}: skipped {skipped}\n")
    if manifest.get("pr") and not prctx.get("available"):
        L.append(f"- PR platform context unavailable ({prctx.get('reason', 'not fetched')}): CI and existing comments not considered\n")
    if manifest.get("ticket_refs") and not reqs:
        L.append(f"- Ticket refs found ({', '.join(r['key'] for r in manifest['ticket_refs'][:5])}) but requirements not checked\n")
    if invalid:
        L.append(f"- ⚠️ Malformed findings dropped: {len(invalid)} ({'; '.join(invalid[:5])})\n")
    if is_diff and not s.get("tests_touched"):
        L.append("- Production code changed with no test files in the diff.\n")

    report = "".join(L)
    out = Path(a.out) if a.out else d / "report.md"
    out.write_text(report, encoding="utf-8")
    # rejected_findings, coverage and positives feed render_html.py --template card.
    (d / "findings.json").write_text(json.dumps(
        {"verdict": verdict, "findings": merged, "rejected": rejected, "suppressed": suppressed,
         "rejected_findings": dropped, "coverage": coverage, "positives": positives[:6]},
        indent=2, ensure_ascii=False), encoding="utf-8")

    if a.write_baseline:
        bl = Path(a.baseline or run_dir.shared_dir(d) / "baseline.json")
        bl.write_text(json.dumps({"fingerprints": sorted({f["fingerprint"] for f in merged})}, indent=2), encoding="utf-8")
        print(f"[aggregate] baseline written -> {bl} ({len(merged)} fingerprints)")

    print(f"[aggregate] {verdict} | " + counts + f" | needs-check={len(check)} pre-existing={len(pre)} "
          f"rejected={rejected} suppressed={suppressed} invalid={len(invalid)}")
    print(f"[aggregate] report -> {out}")
    sys.exit(code)


if __name__ == "__main__":
    main()
