#!/usr/bin/env python3
"""
blast_radius.py — Phase 1b of the tl-code-review harness (diff modes only).

A diff reviewed in isolation misses the most expensive class of bug: a change
that is locally correct but breaks a caller (signature change, changed null
contract, renamed DTO field, altered return semantics). This script extracts
the symbols declared/modified inside changed hunks and lists where else in the
repo they are referenced, so reviewers can check those call sites.

It is deliberately heuristic (regex, not a compiler): cheap, language-agnostic,
good enough to point a reviewer at the right files. Treat output as leads.

Usage
  python blast_radius.py --manifest $RUN/manifest.json --out $RUN/blast.json
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under `python -I`
import run_dir  # noqa: E402

# Declarations: capture the symbol name. Covers C#, TS/JS, Go, Python, Java/Kotlin, Dart, SQL.
DECL_PATTERNS = [
    # class / interface / record / struct / enum / type alias
    r"\b(?:class|interface|record|struct|enum|trait|type)\s+([A-Z_a-z][\w]*)",
    # C# / Java / Dart / TS method:  [modifiers] ReturnType Name(   (Name capitalised or camel)
    r"(?:public|private|protected|internal|static|virtual|override|async|abstract|sealed|final)\s+"
    r"(?:[\w<>\[\],.?\s]+?\s+)?([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(",
    # JS/TS function / const arrow / export
    r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(",
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>",
    # TS class method:  name(args) {   / async name(
    r"^\s*(?:async\s+)?([a-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[^={]+)?\s*\{",
    # Go func / method
    r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(",
    # Python def/class
    r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(",
    # SQL objects
    r"(?i)\b(?:create|alter)\s+(?:or\s+replace\s+)?(?:procedure|proc|function|view|table|trigger)\s+(?:\[?\w+\]?\.)?\[?(\w+)\]?",
    # DTO / property-like members: public Type Name { get;   |  name?: Type;  |  json:"name"
    r"public\s+[\w<>\[\],.?]+\s+([A-Z]\w*)\s*\{\s*get",
    r"^\s*(?:readonly\s+)?([a-zA-Z_]\w*)\??\s*:\s*[\w<>\[\]|'\" ]+;\s*$",
]
DECL_RX = [re.compile(p, re.M) for p in DECL_PATTERNS]

STOPWORDS = {
    "if", "for", "while", "switch", "catch", "return", "new", "get", "set", "value", "var",
    "main", "init", "constructor", "render", "toString", "equals", "hashCode", "dispose",
    "Dispose", "ToString", "Equals", "GetHashCode", "then", "map", "filter", "test", "it",
    "describe", "setUp", "tearDown", "id", "Id", "name", "Name", "type", "data", "index",
}
MIN_LEN = 4
MAX_REFS_PER_SYMBOL = 25
MAX_SYMBOLS = 60


def sh(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


def diff_lines(root, manifest, path):
    """Return (added_lines, removed_lines) text for a file in the manifest's range."""
    mode = manifest["mode"]
    if mode == "uncommitted":
        rng = ["HEAD"]
    elif mode == "staged":
        rng = ["--cached"]
    else:
        b, h = manifest["base"], manifest["head"]
        rng = [f"{h}^!"] if b == f"{h}^" else [f"{b}...{h}"]
    out = sh(["git", "diff", "-U0", "-M"] + rng + ["--", path], root)
    if not out:  # untracked file
        try:
            return Path(os.path.join(root, path)).read_text(encoding="utf-8", errors="ignore"), ""
        except OSError:
            return "", ""
    add, rem = [], []
    for line in out.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            add.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            rem.append(line[1:])
    return "\n".join(add), "\n".join(rem)


def extract(text):
    names = set()
    for rx in DECL_RX:
        for m in rx.finditer(text):
            n = m.group(1)
            if n and len(n) >= MIN_LEN and n not in STOPWORDS and not n.isupper():
                names.add(n)
    return names


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", help="default: manifest.json of the latest run")
    ap.add_argument("--out", help="default: blast.json next to the manifest")
    a = ap.parse_args()
    a.manifest = a.manifest or str(run_dir.latest() / "manifest.json")
    a.out = a.out or str(Path(a.manifest).parent / "blast.json")

    manifest = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    if manifest["mode"] not in ("uncommitted", "staged", "changeset"):
        print("[blast_radius] skipped: only meaningful for diff modes")
        return
    root = manifest.get("review_root") or manifest["repo_root"]  # head version for a branch/PR changeset
    in_scope = {f["path"] for f in manifest["files"]}

    symbols = {}  # name -> {"defined_in": set, "kind": modified|removed|added}
    for f in manifest["files"]:
        if f["layer"] == "test":
            continue
        added, removed = diff_lines(root, manifest, f["path"])
        a_names, r_names = extract(added), extract(removed)
        for n in a_names | r_names:
            kind = "modified" if (n in a_names and n in r_names) else ("removed" if n in r_names else "added")
            s = symbols.setdefault(n, {"defined_in": set(), "kinds": set()})
            s["defined_in"].add(f["path"])
            s["kinds"].add(kind)

    # Priority: removed/modified first (they can break callers); pure additions rarely do.
    def prio(item):
        k = item[1]["kinds"]
        return (0 if "removed" in k else 1 if "modified" in k else 2, item[0])

    ranked = sorted(symbols.items(), key=prio)[:MAX_SYMBOLS]
    results, external_files = [], {}
    for name, meta in ranked:
        if meta["kinds"] == {"added"}:
            continue  # new symbol: nobody outside the diff can depend on it yet
        r = subprocess.run(["git", "grep", "-n", "-w", "-I", "-F", name], cwd=root,
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        refs = []
        for line in r.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            p, ln, code = parts
            if p in meta["defined_in"]:
                continue
            if any(x in p for x in ("node_modules/", "/bin/", "/obj/", "dist/", ".min.")):
                continue
            refs.append({"file": p, "line": int(ln), "code": code.strip()[:160], "in_scope": p in in_scope})
        if not refs:
            continue
        out_of_scope = [x for x in refs if not x["in_scope"]]
        for x in out_of_scope:
            external_files[x["file"]] = external_files.get(x["file"], 0) + 1
        results.append({
            "symbol": name,
            "change": sorted(meta["kinds"]),
            "defined_in": sorted(meta["defined_in"]),
            "ref_count": len(refs),
            "out_of_scope_refs": len(out_of_scope),
            "refs": refs[:MAX_REFS_PER_SYMBOL],
            "refs_truncated": len(refs) > MAX_REFS_PER_SYMBOL,
        })

    results.sort(key=lambda x: -x["out_of_scope_refs"])
    blast = {
        "symbols": results,
        "external_files_ranked": sorted(external_files.items(), key=lambda kv: -kv[1])[:40],
        "note": "Heuristic (regex + git grep). Leads for reviewers, not proof of breakage.",
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(blast, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[blast_radius] changed symbols with external refs: {len(results)}; "
          f"files outside diff that reference them: {len(external_files)}")
    for s in results[:8]:
        print(f"  - {s['symbol']} ({','.join(s['change'])}): {s['out_of_scope_refs']} refs outside diff")
    print(f"[blast_radius] -> {out}")


if __name__ == "__main__":
    main()
