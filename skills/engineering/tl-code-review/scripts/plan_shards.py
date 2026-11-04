#!/usr/bin/env python3
"""
plan_shards.py — Phase 2 of the tl-code-review harness.

Groups in-scope files into shards that one reviewer sub-agent can handle
within a token budget, keeps cohesive files together (same module + layer),
ranks shards by risk, and assigns review lenses from cheap content signals.

Budget model (rough, intentionally conservative):
  diff modes : tokens ≈ (changed_lines * 3 context multiplier + 60 per hunk) * 10
  full modes : tokens ≈ size_lines * 10
  1 line of code ≈ 10 tokens is a reasonable average across C#/TS/Go.

Usage
  python plan_shards.py --manifest $RUN/manifest.json --budget 60000 --out $RUN/shards.json
  python plan_shards.py ... --depth quick     # fewer lenses, skip nits
  python plan_shards.py ... --depth deep      # all lenses on high-risk shards
"""
import argparse
import json
import sys
import os
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under `python -I`
import run_dir  # noqa: E402

TOKENS_PER_LINE = 10

LENS_SIGNALS = {
    "security": re.compile(
        r"\[Authorize|\[AllowAnonymous|@UseGuards|@Public|jwt|bearer|password|secret|apikey|api_key|"
        r"FromSql|ExecuteSql|SqlCommand|raw\(|\$queryRaw|innerHTML|dangerouslySetInnerHTML|eval\(|"
        r"exec\(|Process\.Start|child_process|deserializ|BinaryFormatter|redirect|cors|csrf|"
        r"Request\.(Query|Form|Headers)|req\.(query|body|params)|upload|File\.(Read|Write|Open)", re.I),
    "concurrency": re.compile(
        r"\block\s*\(|Monitor\.|SemaphoreSlim|Mutex|Interlocked|ConcurrentDictionary|Parallel\.|Task\.Run|"
        r"\.Result\b|\.Wait\(\)|ConfigureAwait|async void|Promise\.all|setTimeout|goroutine|go func|"
        r"sync\.|chan\s|WaitGroup|@Transactional|IsolationLevel|SELECT .* FOR UPDATE|rowversion|"
        r"ConcurrencyToken|optimistic|BackgroundService|IHostedService|cron|queue|consumer", re.I),
    "data": re.compile(
        r"DbContext|DbSet|Include\(|AsNoTracking|SaveChanges|BeginTransaction|TransactionScope|"
        r"SELECT|INSERT|UPDATE|DELETE|MERGE|JOIN|migration|AddColumn|DropColumn|AlterColumn|"
        r"createQueryBuilder|getRepository|prisma\.|knex|sequelize|mongoose|Dapper|QueryAsync|"
        r"decimal|Math\.Round|toFixed|parseFloat|double\s+\w*(amount|price|balance|rate)", re.I),
    "performance": re.compile(
        r"foreach|for\s*\(|\.map\(|\.forEach\(|ToList\(\)|ToArray\(\)|\.Count\(\)|\.Any\(\)|"
        r"await\s+.*\bin\b|useEffect|useMemo|useCallback|HttpClient|new HttpClient|fetch\(|axios|"
        r"cache|Redis|IMemoryCache|pagination|Skip\(|Take\(|limit|offset|stream|Buffer|StringBuilder", re.I),
    "api-contract": re.compile(
        r"\[Http(Get|Post|Put|Delete|Patch)|\[Route|@(Get|Post|Put|Delete|Patch)\(|@Controller|router\.|"
        r"app\.(get|post|put|delete)|MapGet|MapPost|\[JsonProperty|JsonPropertyName|@ApiProperty|"
        r"interface\s+\w+(Dto|Request|Response)|class\s+\w+(Dto|Request|Response)|\.proto|openapi|swagger|"
        r"StatusCode|ProblemDetails|HttpException|version", re.I),
}
ALWAYS = ["correctness", "error-handling", "tests"]
SPECIALIST_LENSES = ("concurrency", "data", "security", "api-contract")  # deep: first one a shard has
LAYER_LENSES = {
    "db-migration": ["data", "backward-compat"],
    "api": ["api-contract", "security"],
    "infrastructure": ["data", "resilience"],
    "ci-infra": ["config-ops"],
    "config": ["config-ops"],
    "ui": ["ui-state"],
    "test": ["test-quality"],
}


def module_key(path, depth=2):
    parts = path.split("/")
    # drop common container dirs so "src/Orders/Api/..." groups by "Orders"
    skip = {"src", "source", "app", "apps", "lib", "libs", "packages", "services", "internal", "pkg", "cmd"}
    core = [p for p in parts[:-1] if p.lower() not in skip]
    return "/".join(core[:depth]) or "(root)"


def est_tokens(f, is_diff):
    if is_diff:
        changed = f["added"] + f["deleted"]
        ctx = min(max(f["size_lines"], 0), changed * 3 + 60 * max(len(f["hunks"]), 1))
        return (changed + ctx) * TOKENS_PER_LINE
    return max(f["size_lines"], 0) * TOKENS_PER_LINE


def sniff(root, f, max_bytes=60_000):
    if f["status"] == "D":
        return ""
    try:
        with open(os.path.join(root, f["path"]), "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", help="default: manifest.json of the latest run")
    ap.add_argument("--budget", type=int, default=60000, help="tokens of code per shard")
    ap.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
    ap.add_argument("--max-shards", type=int, default=24)
    ap.add_argument("--out", help="default: shards.json next to the manifest")
    a = ap.parse_args()
    a.manifest = a.manifest or str(run_dir.latest() / "manifest.json")
    a.out = a.out or str(Path(a.manifest).parent / "shards.json")

    m = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    # review_root: the checked-out head version of the files (a worktree for a branch/PR changeset)
    root, is_diff = m.get("review_root") or m["repo_root"], m["mode"] in ("uncommitted", "staged", "changeset")

    groups = {}
    for f in m["files"]:
        if f["status"] == "D":
            groups.setdefault(("(deleted)", "deleted"), []).append(f)
            continue
        groups.setdefault((module_key(f["path"]), f["layer"]), []).append(f)

    shards = []
    for (mod, layer), files in groups.items():
        files.sort(key=lambda x: x["path"])
        cur, cur_tok = [], 0
        for f in files:
            t = est_tokens(f, is_diff)
            if cur and cur_tok + t > a.budget:
                shards.append((mod, layer, cur, cur_tok))
                cur, cur_tok = [], 0
            cur.append(f)
            cur_tok += t
        if cur:
            shards.append((mod, layer, cur, cur_tok))

    # Merge tiny shards (< 15% budget) of the same layer to cut agent overhead.
    merged, pending = [], {}
    for mod, layer, files, tok in shards:
        if tok < a.budget * 0.15:
            p = pending.setdefault(layer, [[], 0, set()])
            if p[1] + tok > a.budget:
                merged.append(("+".join(sorted(p[2]))[:80], layer, p[0], p[1]))
                pending[layer] = p = [[], 0, set()]
            p[0].extend(files); p[1] += tok; p[2].add(mod)
        else:
            merged.append((mod, layer, files, tok))
    for layer, (files, tok, mods) in pending.items():
        if files:
            merged.append(("+".join(sorted(mods))[:80], layer, files, tok))

    out_shards = []
    for mod, layer, files, tok in merged:
        risk = round(sum(f["risk"] for f in files), 2)
        lenses = list(ALWAYS) + LAYER_LENSES.get(layer, [])
        text = "\n".join(sniff(root, f) for f in files[:30])
        for lens, rx in LENS_SIGNALS.items():
            if rx.search(text) and lens not in lenses:
                lenses.append(lens)
        if any(f["sensitive"] for f in files) and "security" not in lenses:
            lenses.append("security")
        out_shards.append({
            "module": mod, "layer": layer, "files": [f["path"] for f in files],
            "est_tokens": tok, "risk": risk, "lenses": lenses,
            "sensitive": any(f["sensitive"] for f in files),
        })

    out_shards.sort(key=lambda s: -s["risk"])
    # Depth tuning
    for i, s in enumerate(out_shards):
        if a.depth == "quick":
            s["lenses"] = [l for l in s["lenses"] if l not in ("performance", "test-quality", "ui-state")]
            s["report_nits"] = False
        elif a.depth == "deep":
            s["report_nits"] = i < 3 and len(out_shards) <= 6
            # Top-risk shards get ONE extra lens-specialist agent, for their highest-value lens. Up to
            # four per shard doubled the cost in evaluation and mostly restated the generalist's findings.
            lens = next((l for l in SPECIALIST_LENSES if l in s["lenses"]), None)
            if lens and s["risk"] >= out_shards[0]["risk"] * 0.5:
                s["specialist_pass"], s["specialist_lens"] = True, lens
        else:
            s["report_nits"] = i < 3 and len(out_shards) <= 6
        s["id"] = f"S{i + 1:02d}"

    overflow = out_shards[a.max_shards:]
    out_shards = out_shards[: a.max_shards]
    # The dispatch list the orchestrator must follow in Phase 3. Printing it makes a skipped
    # reviewer visible: a single-pass review of a HARNESS-sized diff misses what blast.json lists.
    specialists = [f"{s['id']}:{s['specialist_lens']}" for s in out_shards if s.get("specialist_pass")]
    layers = {s["layer"] for s in out_shards}
    cross_cutting = is_diff and (len(out_shards) >= 3 or len(layers) >= 2 or bool(m.get("ticket_refs")))
    dispatch = {"shard_reviewers": [s["id"] for s in out_shards], "specialist_passes": specialists,
                "cross_cutting": cross_cutting}
    plan = {
        "mode": m["mode"], "depth": a.depth, "budget": a.budget,
        "total_est_tokens": sum(s["est_tokens"] for s in out_shards),
        "shards": out_shards,
        "overflow": [{"module": s["module"], "layer": s["layer"], "files": s["files"], "risk": s["risk"]} for s in overflow],
        "dispatch": dispatch,
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[plan_shards] {len(out_shards)} shards, ~{plan['total_est_tokens']:,} code tokens, depth={a.depth}"
          + (f", {len(overflow)} low-risk shards deferred (overflow)" if overflow else ""))
    for s in out_shards[:12]:
        print(f"  {s['id']} risk={s['risk']:>6} ~{s['est_tokens']:>6}t {s['layer']:<14} {s['module'][:40]:<40} "
              f"files={len(s['files'])} lenses={','.join(s['lenses'])}")
    print(f"[plan_shards] DISPATCH: {len(dispatch['shard_reviewers'])} x tl-review-shard-reviewer "
          f"({','.join(dispatch['shard_reviewers'])})"
          + (f"; {len(specialists)} specialist passes ({','.join(specialists)})" if specialists else "")
          + ("; 1 x tl-review-cross-cutting-reviewer" if cross_cutting else ""))
    print(f"[plan_shards] -> {a.out}")


if __name__ == "__main__":
    main()
