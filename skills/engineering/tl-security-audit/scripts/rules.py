#!/usr/bin/env python3
"""Rule authoring tool.

  rules.py validate [--repo R] [--rules-dir D]...   schema + regex check of every rule/check
  rules.py test     [--repo R] [--rules-dir D]... [--id RULE]
        run each rule's `examples`: every `bad` snippet must match, every `good` must not
  rules.py list     [--repo R] [--type finding|gate] [--lang L]
  rules.py try      --id RULE --file PATH           show what one rule matches in one file
"""
import argparse
import sys
from pathlib import Path

from common import detect_lang
from ruleset import applies_to, load_checks, load_rules, match_rule


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["validate", "test", "list", "try"])
    ap.add_argument("--repo")
    ap.add_argument("--rules-dir", action="append", default=[])
    ap.add_argument("--id")
    ap.add_argument("--type")
    ap.add_argument("--lang")
    ap.add_argument("--file")
    a = ap.parse_args()
    rules, errors = load_rules(a.repo, a.rules_dir)
    checks, cerrors = load_checks(a.repo)

    if a.cmd == "validate":
        try:
            from taint import load_specs
            specs, terr = load_specs(a.repo)
            errors = errors + [f"taint {e}" for e in terr]
            print(f"taint specs: {', '.join(sorted(specs))} "
                  f"({sum(len(s['sinks']) for s in specs.values())} sink kinds) — run `taint.py test` to execute examples")
        except ImportError as e:
            print("taint specs not checked:", e)
        for e in errors + cerrors:
            print("ERROR", e)
        no_ex = [r for r in rules.values() if not (r.get("examples") or {}).get("bad")]
        print(f"{len(rules)} rules ({sum(r['type'] == 'gate' for r in rules.values())} gates), "
              f"{len(checks)} checks, {len(errors) + len(cerrors)} errors, "
              f"{len(no_ex)} rules without examples")
        sys.exit(1 if errors or cerrors else 0)

    if a.cmd == "list":
        for r in sorted(rules.values(), key=lambda r: r["id"]):
            if a.type and r["type"] != a.type:
                continue
            if a.lang and a.lang not in r["_langs"] and "any" not in r["_langs"]:
                continue
            print(f"{r['id']:<40} {r['type']:<8} {r.get('severity', '-'):<8} {r['owasp']} "
                  f"{','.join(sorted(r['_langs']))}")
        for c in sorted(checks):
            print(f"{c:<40} check    {'-':<8} {checks[c].get('owasp', '')}")
        return

    if a.cmd == "try":
        r = rules.get(a.id) or sys.exit(f"no rule {a.id}")
        p = Path(a.file)
        text = p.read_text(encoding="utf-8", errors="replace")
        lang = detect_lang(p.name)
        if not applies_to(r, p.as_posix(), lang):
            print(f"note: rule does not apply to language '{lang}' / this path")
        for ln, line, secret in match_rule(r, p.as_posix(), text):
            print(f"{p}:{ln}: {line.strip()[:160]}")
        return

    # test
    fails, tested = 0, 0
    for r in sorted(rules.values(), key=lambda r: r["id"]):
        if a.id and r["id"] != a.id:
            continue
        ex = r.get("examples") or {}
        fname = ex.get("file", "example.txt")
        for kind in ("bad", "good"):
            for snippet in ex.get(kind, []) or []:
                tested += 1
                hit = any(True for _ in match_rule(r, fname, snippet))
                if hit != (kind == "bad"):
                    fails += 1
                    print(f"FAIL {r['id']}: {kind} example {'did not match' if kind == 'bad' else 'matched'}: "
                          f"{snippet.strip()[:100]!r}")
    print(f"{tested} examples, {fails} failures")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
