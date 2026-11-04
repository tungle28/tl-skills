#!/usr/bin/env python3
"""Merge available evaluation outputs into a scorecard with gates.

Usage: python scorecard.py --workspace <dir> --skill-name <name>
                           [--gates default_gates.json] [--previous old_scorecard.json]
                           [--out scorecard.md]
Looks for lint.json, trigger.json, harness.json, (recursively) benchmark.json, and lists
prompts/*.md (the verbatim prompts dispatched, baseline included).
Missing sections are reported as 'not measured', never estimated.
"""
import argparse, sys, json, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import utf8_stdio  # noqa: E402

HERE = Path(__file__).resolve().parent


def load(p):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def quality_from_benchmark(b):
    rs = b.get("run_summary", {})
    cfgs = [k for k in rs if k != "delta"]
    if "with_skill" not in cfgs:
        return None
    base = next((c for c in cfgs if c != "with_skill"), None)
    w = rs["with_skill"].get("pass_rate", {})
    q = {"baseline_config": base, "with_skill_pass_rate": w.get("mean"), "with_skill_sd": w.get("stddev")}
    if base:
        bb = rs[base].get("pass_rate", {})
        q["baseline_pass_rate"], q["baseline_sd"] = bb.get("mean"), bb.get("stddev")
        if w.get("mean") is not None and bb.get("mean") is not None:
            q["pass_rate_delta"] = round(w["mean"] - bb["mean"], 4)
            pooled = ((w.get("stddev") or 0) ** 2 + (bb.get("stddev") or 0) ** 2) ** 0.5
            q["delta_exceeds_pooled_sd"] = abs(q["pass_rate_delta"]) > pooled
        for m in ("tokens", "time_seconds"):
            a_, b_ = rs["with_skill"].get(m, {}).get("mean"), rs[base].get(m, {}).get("mean")
            if a_ is not None and b_:
                q[f"{m}_ratio_vs_baseline"] = round(a_ / b_, 2)
    # non-discriminating assertions
    stats = {}
    for r in b.get("runs", []):
        for e in r.get("expectations", []):
            s = stats.setdefault(e.get("text"), {})
            s.setdefault(r.get("configuration"), []).append(bool(e.get("passed")))
    nd = [t for t, s in stats.items() if len(s) > 1 and all(all(v) for v in s.values())]
    q["non_discriminating_assertions"] = nd
    # with-skill at ~1.0 caps delta at (1 - baseline): a small delta then says the eval is easy, not the skill weak
    q["with_skill_at_ceiling"] = (w.get("mean") or 0) >= 0.98
    q["runs_per_configuration"] = b.get("metadata", {}).get("runs_per_configuration")
    return q


BASELINE_CONFIGS = ("baseline", "without_skill", "old_skill")


def load_prompts(ws):
    """prompts/*.md with optional `key: value` front matter (see references/schemas.md)."""
    out = []
    for p in sorted((ws / "prompts").glob("*.md")) if (ws / "prompts").is_dir() else []:
        text = p.read_text(encoding="utf-8")
        meta, body = {}, text
        if text.startswith("---"):
            head, sep, rest = text[3:].partition("\n---")
            if sep:
                body = rest.lstrip("\n")
                for line in head.splitlines():
                    k, colon, v = line.partition(":")
                    if colon and k.strip():
                        meta[k.strip().lower()] = v.split(" #")[0].strip()
        cfg = meta.get("config") or next((c for c in BASELINE_CONFIGS + ("with_skill", "grader")
                                          if p.stem.startswith(c)), None)
        out.append({"file": f"prompts/{p.name}", "config": cfg, "case": meta.get("case"),
                    "runner": meta.get("runner"), "result": meta.get("result"),
                    "chars": len(body.strip())})
    return out


def get(sections, dotted):
    sec, _, key = dotted.partition(".")
    v = (sections.get(sec) or {}).get(key)
    if isinstance(v, dict) and "mean" in v:
        v = v["mean"]
    if sec == "harness" and key == "severity_kappa":
        v = ((sections.get("harness") or {}).get("severity") or {}).get("quadratic_kappa")
    if sec == "lint" and key == "errors":
        v = ((sections.get("lint") or {}).get("summary") or {}).get("errors")
    return v


def evaluate_gate(g, v):
    if v is None:
        return "not measured"
    ge = g["op"] == ">="
    bad = (lambda t: v < t) if ge else (lambda t: v > t)
    if bad(g["fail"]):
        return "FAIL"
    if "warn" in g and bad(g["warn"]):
        return "WARN"
    return "PASS"


def fmt(v):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--skill-name", required=True)
    ap.add_argument("--gates", type=Path, default=HERE.parent / "references" / "default_gates.json")
    ap.add_argument("--previous", type=Path)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    ws = a.workspace

    sections = {"lint": load(ws / "lint.json"), "trigger": load(ws / "trigger.json"),
                "quality": None, "harness": load(ws / "harness.json")}
    bms = sorted(ws.rglob("benchmark.json"), key=lambda p: p.stat().st_mtime)
    if bms:
        b = load(bms[-1])
        sections["quality"] = quality_from_benchmark(b) if b else None
        if sections["quality"]:
            sections["quality"]["source"] = str(bms[-1].relative_to(ws))

    gates_doc = load(a.gates) or {"gates": []}
    # per-skill overrides: <workspace>/../gates.json (the skill's eval root), merged by metric; each needs a reason
    overrides = []
    ov_path = ws.resolve().parent / "gates.json"
    ov_doc = load(ov_path) if ov_path.exists() else None
    if ov_doc:
        by_metric = {g["metric"]: dict(g) for g in gates_doc["gates"]}
        for o in ov_doc.get("gates", []):
            if not o.get("reason"):
                raise SystemExit(f"{ov_path}: override for {o.get('metric')} has no 'reason'")
            by_metric[o["metric"]] = {**by_metric.get(o["metric"], {}), **o}
            overrides.append(o)
        gates_doc = {"gates": list(by_metric.values())}
    results = []
    for g in gates_doc["gates"]:
        sec = g["metric"].split(".")[0]
        if sections.get(sec) is None:
            continue  # whole family not applicable/measured -> listed separately
        v = get(sections, g["metric"])
        results.append({"metric": g["metric"], "value": v, "op": g["op"], "fail": g["fail"],
                        "warn": g.get("warn"), "status": evaluate_gate(g, v)})
    statuses = {r["status"] for r in results}
    hint = "FAIL" if "FAIL" in statuses else ("CONDITIONAL" if "WARN" in statuses or "not measured" in statuses else "PASS")

    prev = load(a.previous) if a.previous else None
    prev_vals = {g["metric"]: g["value"] for g in (prev or {}).get("gates", [])}

    prompts = load_prompts(ws)
    prompt_warnings = []
    has_baseline_prompt = any(p["config"] in BASELINE_CONFIGS for p in prompts)
    if (sections["quality"] or {}).get("baseline_config") and not has_baseline_prompt:
        prompt_warnings.append("baseline measured but no baseline prompt in prompts/ — the delta can't be reviewed or reproduced")
    if (sections["quality"] or sections["harness"]) and not prompts:
        prompt_warnings.append("no prompts/ recorded for the quality/harness runs")

    card = {"skill": a.skill_name, "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "sections": sections, "prompts": prompts, "prompt_warnings": prompt_warnings,
            "gates": results, "gate_overrides": overrides, "verdict_hint": hint}
    out_md = a.out or (ws / "scorecard.md")
    out_md.with_suffix(".json").write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")

    L = [f"# Skill scorecard — `{a.skill_name}`", "", f"Generated {card['generated_at']} · mechanical verdict hint: **{hint}**", ""]
    L += ["## Coverage", "", "| Family | Status |", "|---|---|"]
    for s in ("lint", "trigger", "quality", "harness"):
        L.append(f"| {s} | {'measured' if sections[s] else 'not measured / not applicable'} |")
    L += ["", "## Gates", "", "| Metric | Value | Gate (fail / warn) | Status |" + (" Prev | Δ |" if prev else ""),
          "|---|---|---|---|" + ("---|---|" if prev else "")]
    for r in results:
        row = f"| {r['metric']} | {fmt(r['value'])} | {r['op']} {r['fail']} / {fmt(r['warn'])} | {r['status']} |"
        if prev:
            pv = prev_vals.get(r["metric"])
            d = (r["value"] - pv) if isinstance(r["value"], (int, float)) and isinstance(pv, (int, float)) else None
            row += f" {fmt(pv)} | {('+' if d and d > 0 else '') + fmt(d) if d is not None else '—'} |"
        L.append(row)
    if overrides:
        L += ["", f"Per-skill gate overrides (`{ov_path.name}` in the skill's eval root):"]
        L += [f"- {o['metric']}: fail {o.get('fail', '—')} / warn {o.get('warn', '—')} — {o['reason']}" for o in overrides]

    lint = sections["lint"]
    if lint:
        per = lint.get("skills") or {a.skill_name: lint}
        L += ["", "## Lint", ""]
        for nm, r in per.items():
            if len(per) > 1:
                L.append(f"- **{nm}**")
            L += [f"- ERROR: {e}" for e in r["errors"]] + [f"- warn: {w}" for w in r["warnings"]]
            t = (r.get("info") or {}).get("tokens_est")
            if t:
                L.append(f"- load cost (estimate): description ≈{t['description_always']} tok always, "
                         f"body ≈{t['body_on_trigger']} tok per trigger, ≈{t['on_demand_md']} tok on demand")
        L += [f"- warn: {w}" for w in lint.get("warnings", []) if lint.get("skills")]
        if lint.get("family"):
            L.append(f"- family duplication: {lint['family']['duplicated_sentences']} sentence(s), share {lint['family']['share_by_skill']}")
        for sb in lint.get("siblings", [])[:3]:
            L.append(f"- description overlap {sb['jaccard']:.2f} with `{sb['skill']}` → use it for near-miss trigger queries")
        if not lint["summary"]["errors"] and not lint["summary"]["warnings"]:
            L.append("- clean")
    t = sections["trigger"]
    if t:
        L += ["", "## Trigger", "", f"- counts: {t['counts']}", f"- flaky queries: {len(t['flaky_queries'])}"]
        L += [f"- {m['type']} ({m['trigger_rate']}): {m['query']}" for m in t["misclassified"][:10]]
        L += [f"- note: {w}" for w in t.get("warnings", [])]
    q = sections["quality"]
    if q:
        L += ["", "## Quality vs baseline", "",
              f"- baseline: `{q.get('baseline_config')}`, runs/config: {q.get('runs_per_configuration')}",
              f"- pass rate: {fmt(q.get('with_skill_pass_rate'))}±{fmt(q.get('with_skill_sd'))} vs {fmt(q.get('baseline_pass_rate'))}±{fmt(q.get('baseline_sd'))}"
              f" (Δ {fmt(q.get('pass_rate_delta'))}; exceeds pooled sd: {q.get('delta_exceeds_pooled_sd')})",
              f"- tokens ×{fmt(q.get('tokens_ratio_vs_baseline'))}, time ×{fmt(q.get('time_seconds_ratio_vs_baseline'))} vs baseline"]
        if q.get("with_skill_at_ceiling") and q.get("pass_rate_delta") is not None:
            L.append(f"- ceiling: with-skill ≈ 1.0, so Δ can be at most {fmt(1 - (q.get('baseline_pass_rate') or 0))}; "
                     "a small Δ means the cases are easy for the baseline. Add discriminating cases before acting on it")
        if q["non_discriminating_assertions"]:
            L.append(f"- non-discriminating assertions ({len(q['non_discriminating_assertions'])}): harden or drop before trusting Δ")
            L += [f"  - {x}" for x in q["non_discriminating_assertions"][:10]]
    h = sections["harness"]
    if h:
        L += ["", "## Harness", "", f"- fixture: {h.get('fixture')} v{h.get('fixture_version')}, GT items {h['ground_truth_items']} (must-find {h['must_find_items']}), runs {h['runs']}, adjudicator: {h.get('adjudicator') or 'none'}",
              f"- severity: exact {fmt(h['severity']['exact_agreement'])}, kappa {fmt(h['severity']['quadratic_kappa'])}, over-rated {h['severity']['over_rated']}, under-rated {h['severity']['under_rated']}",
              f"- stable core share: {fmt(h.get('stable_core_share'))}"]
        L += [f"- **MUST-FIND MISS** {k}: {v}" for k, v in h["missed_must_find"].items()]
        if h.get("cost"):
            L.append(f"- cost: {h['cost']}")
        L += [f"- note: {w}" for w in h.get("warnings", [])]
    if prompts or prompt_warnings:
        L += ["", "## Prompts used", ""]
        if prompts:
            L += ["| File | Config | Case | Runner | Result |", "|---|---|---|---|---|"]
            L += [f"| [{p['file']}]({p['file']}) | {p['config'] or '—'} | {p['case'] or '—'} | {p['runner'] or '—'} | {p['result'] or '—'} |"
                  for p in prompts]
        L += [f"- warn: {w}" for w in prompt_warnings]
    L += ["", "## Verdict, top fixes, confidence", "", "_To be written by the evaluator: verdict with driving metrics, top 3 fixes tied to metrics, sample sizes, gaps, biases._", ""]
    out_md.write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {out_md} and {out_md.with_suffix('.json')} — hint: {hint}")


if __name__ == "__main__":
    main()
