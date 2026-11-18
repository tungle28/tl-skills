#!/usr/bin/env python3
"""Phase 2 — scan: run pattern rules over every inventoried file (whole repo, not only the review
scope), plus an optional Semgrep/OpenGrep pass, then re-rank review shards by risk signal.

Two rule types (see references/rule-authoring.md):
  finding — asserts a likely weakness (hardcoded key, TLS verification disabled, MD5 for passwords)
  gate    — asserts nothing; tags a site where a reviewer must answer a question
            ("does this action taking an id check ownership?"). Gates keep deep review focused.

Outputs: scan/hits.json (all hits), scan/suppressed.json, scan/tools.json,
         scan/shards/<SID>.json (hits + applicable checks per shard); re-ranked shards.json.
"""
import argparse
import fnmatch
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

from common import SEV_WEIGHT, load_state, now_iso, read_json, redact, secret_digest, write_json
from engine import find_engine
from memory import Sources, load_triage, triage_hit
from ruleset import applies_to, check_applies, load_checks, load_rules, match_rule

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

INLINE_IGNORE = re.compile(r"security-audit:\s*ignore(?:\s+([\w\-, ]+))?", re.I)
MAX_SNIPPET = 200
ENTRY_HINTS = re.compile(
    r"\[(Http(Get|Post|Put|Delete|Patch)|Route|ApiController)\b|@(Get|Post|Put|Delete|Patch|Controller)\(|"
    r"\b(app|router)\.(get|post|put|delete|patch)\(|@app\.route\(|@(router|app)\.(get|post|put|delete)\(|"
    r"\bMap(Get|Post|Put|Delete)\(|"
    r"\b\w+\.(GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\(\s*\"/|\bHandleFunc\(|"
    r"\bdefine(Cached)?EventHandler\(|"
    r"\bRoute::(get|post|put|patch|delete|any|match|resource|apiResource)\(|#\[Route\(|@Route\(|"
    r"\bpublic\s+function\s+\w+\s*\(\s*[\w\\]*Request\s+\$request\b")


def load_suppressions(root):
    p = Path(root) / ".security-audit" / "suppressions.yml"
    if not p.exists() or yaml is None:
        return []
    items = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    today = date.today().isoformat()
    out = []
    for s in items:
        if not isinstance(s, dict) or not s.get("rule") or not s.get("reason"):
            continue  # a suppression without a reason is ignored on purpose
        if s.get("until") and str(s["until"]) < today:
            continue  # expired: the finding comes back
        out.append(s)
    return out


def suppressed_by(hit, sups, lines):
    for s in sups:
        if s["rule"] in (hit["rule_id"], "*") and fnmatch.fnmatch(hit["file"], s.get("path", "*")):
            return f"suppressions.yml: {s['reason']}"
    ln = hit["line"]
    for probe in (ln - 1, ln - 2):  # same line or the line above
        if 0 <= probe < len(lines):
            m = INLINE_IGNORE.search(lines[probe])
            if m and (not m.group(1) or hit["rule_id"] in [x.strip() for x in m.group(1).split(",")]):
                return "inline ignore comment"
    return None


def make_hit(rule, rel, line_no, line, secret, is_test):
    snippet = line.strip()
    if secret:
        snippet = snippet.replace(secret, redact(secret))
    if len(snippet) > MAX_SNIPPET:
        snippet = snippet[:MAX_SNIPPET] + "…"
    h = {"rule_id": rule["id"], "type": rule["type"], "title": rule["title"], "file": rel,
         "line": line_no, "snippet": snippet, "owasp": rule.get("owasp"), "cwe": rule.get("cwe"),
         "source": "rule"}
    if rule["type"] == "gate":
        h["question"] = rule["question"]
        h["guidance"] = rule.get("guidance", "")
    else:
        h.update({"severity": rule["severity"], "confidence": rule["confidence"],
                  "message": rule["message"], "fix": rule["fix"]})
        if is_test and rule.get("tests_downgrade", True):
            h["confidence"] = "low"
            if h["severity"] in ("critical", "high", "medium"):
                h["severity"] = "low"
            h["note"] = "in test code — likely not production-reachable"
    if secret:
        h["secret"] = True
    return h


def run_semgrep(root, extra_dirs):
    """Optional adapter. Uses local rule dirs only (no registry download, no telemetry)."""
    eng = find_engine()
    exe = eng["exe"] if eng else None
    cfgs = [d for d in [Path(__file__).resolve().parent.parent / "rules" / "semgrep",
                        Path(root) / ".security-audit" / "semgrep", *map(Path, extra_dirs)]
            if d.is_dir() and any(d.glob("*.y*ml"))]
    if not cfgs:
        return {"tool": "semgrep", "status": "skipped", "reason": "no semgrep rule directories"}, []
    if not exe:
        return {"tool": "semgrep", "status": "skipped",
                "reason": "semgrep/opengrep not installed — dataflow rules in rules/semgrep did not run"}, []
    cmd = [exe, "scan", "--json", "--quiet"] + (["--taint-intrafile"] if eng["intrafile"] else
                                                ["--metrics=off", "--disable-version-check"])
    for c in cfgs:
        cmd += ["--config", str(c)]
    try:
        r = subprocess.run(cmd + [str(root)], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=900)
        data = json.loads(r.stdout or "{}")
    except (subprocess.TimeoutExpired, ValueError) as e:
        return {"tool": Path(exe).name, "status": "failed", "reason": str(e)[:200]}, []
    hits = []
    for res in data.get("results", []):
        md = res.get("extra", {}).get("metadata", {}) or {}
        rel = Path(res["path"]).resolve().relative_to(Path(root).resolve()).as_posix()
        gate = md.get("type") == "gate"
        sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(res["extra"].get("severity"), "medium")
        h = {"rule_id": res["check_id"].split(".")[-1], "type": "gate" if gate else "finding",
             "title": md.get("title") or res["extra"].get("message", "")[:80], "file": rel,
             "line": res["start"]["line"], "snippet": (res["extra"].get("lines") or "").strip()[:MAX_SNIPPET],
             "owasp": md.get("owasp"), "cwe": md.get("cwe"), "source": Path(exe).name}
        if gate:
            h["question"] = md.get("question") or res["extra"].get("message", "")
        else:
            h.update({"severity": md.get("severity", sev), "confidence": md.get("confidence", "medium"),
                      "message": res["extra"].get("message", ""), "fix": md.get("fix", "")})
        hits.append(h)
    return {"tool": Path(exe).name, "status": "ran", "results": len(hits),
            "errors": len(data.get("errors", []))}, hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    a = ap.parse_args()
    run = Path(a.run_dir)
    st = load_state(run)
    inv = read_json(run / "inventory.json")
    # shards_all.json keeps every shard when --max-shards deferred some, so a re-scan with a higher
    # cap (pipeline.py run extend-shards) can bring them back
    shards = read_json(run / "shards_all.json") or read_json(run / "shards.json", [])
    if not inv:
        raise SystemExit("inventory.json missing — run phase 'inventory' first")
    root = Path(inv["root"])
    extra = st.get("rules_dirs", [])

    rules, rule_errors = load_rules(root, extra)
    checks, check_errors = load_checks(root)
    sups = load_suppressions(root)
    known_fp = [e for e in load_triage(root) if e["verdict"] == "false-positive"]
    src = Sources(root)
    tools = [{"tool": "pattern-rules", "status": "ran", "rules": len(rules),
              "rule_errors": rule_errors, "check_errors": check_errors}]

    hits, suppressed = [], []
    # sha256 + length of each secret value: lets merge/report mask it wherever an agent quotes it.
    # The length is what report.md already shows ("[19 chars redacted]"); the value is never stored.
    secret_digests = set()
    texts = {}
    for f in inv["files"]:
        rel, lang = f["path"], f["lang"]
        try:
            text = "" if lang == "key" else (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        texts[rel] = text
        lines = text.splitlines()
        for rule in rules.values():
            if not applies_to(rule, rel, lang):
                continue
            for line_no, line, secret in match_rule(rule, rel, text):
                h = make_hit(rule, rel, line_no, line, secret, f["is_test"])
                if secret:
                    secret_digests.add((secret_digest(secret), len(secret),
                                        any(c.isspace() for c in secret)))
                why = suppressed_by(h, sups, lines) or triage_hit(h, known_fp, src)
                if why:
                    suppressed.append({**h, "suppressed": why})
                else:
                    hits.append(h)

    # Taint phase output (source→sink flows with traces), produced by taint.py before this phase.
    taint = read_json(run / "scan" / "taint.json")
    if taint is None:
        tools.append({"tool": "taint", "status": "skipped", "reason": "taint phase not run (pipeline.py run taint)"})
    else:
        st_t = {"tool": "taint", "status": "ran" if taint.get("status", "").startswith("ran") else taint.get("status"),
                "reason": taint.get("reason", ""), "mode": taint.get("mode"),
                "engine": (taint.get("engine") or {}).get("kind"), "version": (taint.get("engine") or {}).get("version"),
                "languages": taint.get("languages", []), "stats": taint.get("stats", {}),
                "errors": len(taint.get("errors", [])) + len(taint.get("spec_errors", [])),
                # timeouts/memory kills, .vue/.svelte templates, signature-less languages: the report
                # lists them under Coverage Gaps
                "gaps": taint.get("gaps", [])}
        tools.append(st_t)
        for h in taint.get("hits", []):
            why = suppressed_by(h, sups, texts.get(h["file"], "").splitlines()) or triage_hit(h, known_fp, src)
            (suppressed if why else hits).append({**h, **({"suppressed": why} if why else {})})

    sg_status, sg_hits = run_semgrep(root, st.get("semgrep_dirs", []))
    tools.append(sg_status)
    for h in sg_hits:
        why = suppressed_by(h, sups, texts.get(h["file"], "").splitlines()) or triage_hit(h, known_fp, src)
        (suppressed if why else hits).append({**h, **({"suppressed": why} if why else {})})

    # Stable ids so reviewers and the merge step can refer to hits.
    hits.sort(key=lambda h: (h["file"], h["line"], h["rule_id"]))
    for i, h in enumerate(hits, 1):
        h["hit_id"] = f"H{i:04d}"

    # Re-rank shards by risk signal: finding severity + gates + entry points.
    by_file = defaultdict(list)
    for h in hits:
        by_file[h["file"]].append(h)
    for s in shards:
        w = 0
        for rel in s["files"]:
            for h in by_file.get(rel, []):
                w += SEV_WEIGHT.get(h.get("severity"), 0) if h["type"] == "finding" else 2
            w += 3 * len(ENTRY_HINTS.findall(texts.get(rel, "")))
        s["risk_weight"] = w
    shards.sort(key=lambda s: (-s["risk_weight"], s["id"]))
    for i, s in enumerate(shards, 1):
        s["priority_rank"] = i
    cap = inv.get("max_shards") or 0
    write_json(run / "shards_all.json", shards)
    deferred = []
    if cap and len(shards) > cap:
        deferred = [{"id": s["id"], "files": len(s["files"]), "loc": s["loc"],
                     "risk_weight": s["risk_weight"]} for s in shards[cap:]]
        shards = shards[:cap]
    inv["scope"]["deferred_shards"] = deferred
    write_json(run / "inventory.json", inv)
    write_json(run / "shards.json", shards)

    frameworks = inv.get("frameworks", [])
    in_shard = set()
    for s in shards:
        blob = "\n".join(texts.get(rel, "") for rel in s["files"])
        applicable = sorted(cid for cid, c in checks.items()
                            if check_applies(c, s["langs"], frameworks, blob))
        shard_hits = [h for rel in s["files"] for h in by_file.get(rel, [])]
        in_shard.update(h["hit_id"] for h in shard_hits)
        write_json(run / "scan" / "shards" / f"{s['id']}.json", {
            "shard": s["id"], "files": s["files"], "frameworks": frameworks,
            "diff_mode": inv["scope"]["kind"] == "changeset",
            "changed_ranges": {f["path"]: f["changed_ranges"] for f in inv["files"]
                               if f["path"] in s["files"] and f.get("changed_ranges")},
            "applicable_checks": [{"id": cid, "title": checks[cid].get("title", ""),
                                   "path": checks[cid]["path"]} for cid in applicable],
            "findings": [h for h in shard_hits if h["type"] == "finding"],
            "gates": [h for h in shard_hits if h["type"] == "gate"],
        })
    for h in hits:
        h["in_review_scope"] = h["hit_id"] in in_shard

    write_json(run / "scan" / "hits.json", {"generated_at": now_iso(), "hits": hits})
    write_json(run / "scan" / "suppressed.json", suppressed)
    write_json(run / "scan" / "secret_digests.json",
               [{"sha256": d, "len": n, "ws": ws} for d, n, ws in sorted(secret_digests)])
    write_json(run / "scan" / "tools.json", tools)
    write_json(run / "scan" / "checks.json",
               {cid: {k: v for k, v in c.items() if not k.startswith("_")} for cid, c in checks.items()})

    fnd = [h for h in hits if h["type"] == "finding"]
    gts = [h for h in hits if h["type"] == "gate"]
    sev = Counter(h["severity"] for h in fnd)
    print(f"rules={len(rules)} checks={len(checks)} findings={len(fnd)} "
          f"({', '.join(f'{k}:{sev[k]}' for k in ('critical', 'high', 'medium', 'low', 'info') if sev[k])}) "
          f"gates={len(gts)} suppressed={len(suppressed)} outside-review-scope={sum(not h['in_review_scope'] for h in hits)}")
    print("secrets:", sum(1 for h in fnd if h.get("secret")),
          "| taint flows:", sum(1 for h in fnd if h.get("source") == "taint"))
    for t in tools:
        if t["status"] != "ran":
            print(f"COVERAGE GAP: {t['tool']} {t['status']} — {t.get('reason', '')}")
    if rule_errors or check_errors:
        print(f"WARNING: {len(rule_errors) + len(check_errors)} rule/check file problems — see scan/tools.json")
        for e in (rule_errors + check_errors)[:10]:
            print("  ", e)
    if deferred:
        print(f"deferred {len(deferred)} shards (--max-shards {cap}); reviewing top {cap} by risk weight — "
              "add more later with `pipeline.py run extend-shards --max-shards N` (0 = all)")


if __name__ == "__main__":
    main()
