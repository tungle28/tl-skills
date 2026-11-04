#!/usr/bin/env python3
"""Phase — taint analysis (source → sink dataflow), in three layers:

  L1  intraprocedural            (any engine)
  L2  cross-function, same file  (OpenGrep --taint-intrafile)
  L3  cross-file chains          (this script: taint summaries composed over rounds)

L3 works on the "summary" idea used by interprocedural analyzers, built from intrafile runs:
  round 0  entry rules    : untrusted source → sink            (direct findings, L1+L2)
           summary rules  : parameter P of function F → sink   (facts "F#P reaches <kind>")
  round k  bridge rules   : untrusted source → call F(..P..)   (cross-file finding chains)
           param bridges  : parameter Q of G → call F(..P..)   (new facts "G#Q reaches <kind>")
Calls are resolved by function name + argument position/arity (+ keyword name), so a chain is a
strong *candidate*, not a proof: unique names → confidence medium, ambiguous names → low.

Rule packs: rules/taint/<lang>.yml (+ <repo>/.security-audit/taint/*.yml). See references/taint-analysis.md.

  taint.py --run-dir D [--depth 3] [--max-targets 150] [--timeout 20]
Each round runs the engine once per language, so a slow language (often JS) cannot cost the others
their flows; vendored assets and minified/generated files are not scanned (inventory decides).
  taint.py test [--lang python] [--kind sql-injection]      run the examples in the specs
"""
import argparse
import copy
import json
import re
import subprocess
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import yaml

from common import EXCLUDE_DIRS, GENERATED_SUFFIXES, is_test_path, load_state, now_iso, read_json, write_json
from engine import find_engine

SKILL_DIR = Path(__file__).resolve().parent.parent
RESERVED = ("$SAFN", "$SAP", "$SARV", "$SATY", "$SARET", "$SABODY", "$SAE", "$SAO", "$SAX", "$SART")
COMMON_NAMES = {
    "find", "get", "query", "execute", "exec", "run", "save", "update", "delete", "create", "handle",
    "process", "send", "load", "read", "write", "open", "call", "search", "list", "filter", "add",
    "remove", "set", "fetch", "post", "put", "do", "apply", "parse", "render", "build", "format",
    "validate", "check", "init", "new", "close", "select", "where", "first", "map", "then", "invoke",
    "request", "log", "info", "debug", "error", "print", "join", "push", "insert", "raw", "text",
}
# PHP keywords that are also legal method names (`function list()`): a call pattern `list(...)` does not parse
PHP_KEYWORDS = {"list", "array", "isset", "empty", "unset", "echo", "print", "include", "require", "eval",
                "exit", "die", "new", "clone", "match", "fn", "use", "default", "static"}
SKIP_FUNCS = {"__init__", "__construct", "constructor", "main", "init", "setUp", "build", "toString", "String", "Error"}
IMPACT = {
    "sql-injection": "Read or modify data beyond the caller's rights; depending on DB privileges, full database compromise.",
    "nosql-injection": "Bypass filters (e.g. authentication checks) or read other users' documents.",
    "command-injection": "Arbitrary command execution on the server with the application's privileges.",
    "code-injection": "Arbitrary code execution inside the application process.",
    "path-traversal": "Read or overwrite files outside the intended directory (configuration, keys, other users' files).",
    "ssrf": "Reach internal services or cloud metadata endpoints from the server; possible credential theft.",
    "open-redirect": "Phishing via trusted-looking links; token leakage in OAuth-style flows.",
    "xss": "Script execution in victims' browsers: session/action hijacking, data theft.",
    "template-injection": "Server-side template injection, usually leading to code execution.",
    "unsafe-deserialization": "Object injection, commonly leading to remote code execution.",
    "ldap-injection": "Alter directory queries: authentication bypass or data disclosure.",
    "webview-injection": "Attacker-controlled content inside the app (phishing, JS bridge access).",
    "navigation-injection": "Open unintended in-app screens/actions from an external link.",
    "auth-bypass": "Act as another user, up to an administrator, without their credentials.",
}


# ------------------------------------------------------------------ specs

def load_specs(repo_root=None):
    specs, errors = {}, []
    dirs = [SKILL_DIR / "rules" / "taint"]
    if repo_root:
        dirs.append(Path(repo_root) / ".security-audit" / "taint")
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.y*ml")):
            try:
                s = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as e:
                errors.append(f"{p}: {e}")
                continue
            lang = s.get("language")
            if not lang:
                errors.append(f"{p}: missing 'language'")
                continue
            if lang not in specs:
                specs[lang] = {**s, "sinks": dict(s.get("sinks") or {}), "_files": [str(p)]}
                continue
            base = specs[lang]  # project extension: append lists, add/override sink kinds
            for k in ("sources", "sanitizers", "function_scopes"):
                base[k] = (base.get(k) or []) + (s.get(k) or [])
            for kind, v in (s.get("sinks") or {}).items():
                base["sinks"][kind] = {**base["sinks"].get(kind, {}), **v} if kind in base["sinks"] else v
            for kind in s.get("disabled_kinds") or []:
                base["sinks"].pop(kind, None)
            base["_files"].append(str(p))
    for lang, s in specs.items():
        errors += [f"{lang}: {e}" for e in validate_spec(s)]
    return specs, errors


def validate_spec(s):
    errs = []
    for k in ("engine_languages", "inventory_languages", "function_scopes", "sources", "sinks"):
        if not s.get(k):
            errs.append(f"missing '{k}'")
    for kind, k in (s.get("sinks") or {}).items():
        for f in ("title", "owasp", "cwe", "severity", "message", "fix", "sinks"):
            if not k.get(f):
                errs.append(f"sink '{kind}': missing '{f}'")
        blob = json.dumps(k.get("sinks", [])) + json.dumps(k.get("sanitizers", []))
        for mv in RESERVED:
            if re.search(re.escape(mv) + r"\b", blob):
                errs.append(f"sink '{kind}' uses reserved metavariable {mv}")
    blob = json.dumps(s.get("sources", [])) + json.dumps(s.get("sanitizers", []))
    for mv in RESERVED:
        if re.search(re.escape(mv) + r"\b", blob):
            errs.append(f"sources/sanitizers use reserved metavariable {mv}")
    return errs


# ------------------------------------------------------------------ rule generation

def _sanitizers(spec, kind):
    return (spec.get("sanitizers") or []) + (spec["sinks"][kind].get("sanitizers") or [])


def scope_source(spec):
    return {"patterns": [{"pattern-either": [{"pattern-inside": s} for s in spec["function_scopes"]]},
                         {"pattern": "$SAP"}]}


def _rule(rid, spec, sources, sinks, sanitizers, unify=False):
    r = {"id": rid, "mode": "taint", "languages": spec["engine_languages"], "severity": "ERROR",
         "message": "$SAFN|$SAP" if unify else rid, "pattern-sources": sources, "pattern-sinks": sinks}
    if sanitizers:
        r["pattern-sanitizers"] = sanitizers
    if unify:
        r["options"] = {"taint_unify_mvars": True}
    return r


def entry_rules(spec):
    lang = spec["language"]
    return [_rule(f"entry__{lang}__{kind}", spec, spec["sources"], k["sinks"], _sanitizers(spec, kind))
            for kind, k in spec["sinks"].items()]


def summary_rules(spec):
    lang = spec["language"]
    return [_rule(f"sum__{lang}__{kind}", spec, [scope_source(spec)], k["sinks"], _sanitizers(spec, kind), unify=True)
            for kind, k in spec["sinks"].items()]


def call_patterns(lang, node):
    fn, idx, named, pname = node["fn"], node["idx"], node["named"], node["param"]
    lo, hi, variadic = node["arity_min"], node["arity_max"], node["variadic"]
    pats = []
    if named:
        kw = f"{pname}={{}}" if lang == "python" else f"{pname}: {{}}"
        args = ["...", kw.format("$SAX"), "..."]
        pats.append(", ".join(args))
    elif idx is not None:
        if not variadic and lo == hi:
            args = ["$_"] * hi
            args[idx] = "$SAX"
            pats.append(", ".join(args))
        else:
            pats.append(", ".join(["$_"] * idx + ["$SAX", "..."]))
        if lang == "python":
            pats.append(f"..., {pname}=$SAX, ...")
        if lang == "csharp":
            pats.append(f"..., {pname}: $SAX, ...")
    out = []
    for a in pats:
        if lang == "php":
            out += [f"$SAO->{fn}({a})", f"$SAO::{fn}({a})"]
        else:
            out.append(f"$SAO.{fn}({a})")
        out.append(f"{fn}({a})")
    return out


def bridge_rule(spec, kind, tid, node, entry):
    pats = call_patterns(spec["language"], node)
    sink = [{"patterns": [{"pattern-either": [{"pattern": p} for p in pats]}, {"focus-metavariable": "$SAX"}]}]
    rid = f"{'bent' if entry else 'bpar'}__{spec['language']}__{kind}__{tid}"
    src = spec["sources"] if entry else [scope_source(spec)]
    return _rule(rid, spec, src, sink, _sanitizers(spec, kind), unify=not entry)


# ------------------------------------------------------------------ engine run

def engine_excludes(root, extra=()):
    """--exclude values. Names that are part of the root's own path are dropped: the engine matches
    excludes against the whole path, so a repo copied under e.g. .security-run/ would yield 0 files."""
    own = {part.lower() for part in Path(root).resolve().parts}
    return sorted(d for d in EXCLUDE_DIRS if d.lower() not in own) + list(extra)


def run_engine(engine, rules, root, workdir, name, timeout, files=None, excludes=None):
    cfg = Path(workdir) / f"{name}.yml"
    cfg.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False, allow_unicode=True), encoding="utf-8")
    cmd = [engine["exe"], "scan", "--config", str(cfg), "--json", "--quiet", "--dataflow-traces",
           "--timeout", str(timeout), "--max-target-bytes", "1000000"]
    if engine["intrafile"]:
        cmd.append("--taint-intrafile")
    if engine["kind"] == "semgrep":
        cmd += ["--metrics=off", "--disable-version-check"]
    for d in (engine_excludes(root) if excludes is None else excludes):
        cmd += ["--exclude", d]
    cmd += [str(root)] if not files else [str(Path(root) / f) for f in files]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=max(600, timeout * 60))
        data = json.loads(r.stdout or "{}")
    except subprocess.TimeoutExpired:
        return [], [f"{name}: engine timed out after {max(600, timeout * 60)}s"], time.time() - t0
    except ValueError:
        return [], [f"{name}: engine output not JSON: {(r.stderr or r.stdout)[:300]}"], time.time() - t0
    errs = [f"{name}: {e.get('type', '')}: {str(e.get('message', ''))[:200]}" for e in data.get("errors", [])
            if e.get("level", "error") == "error"]
    return data.get("results", []), errs, time.time() - t0


def rel(root, p):
    try:
        return Path(p).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return p


def rid_parts(check_id):
    return check_id.split(".")[-1].split("__")  # engines prefix ids with the config path


def loc_of(root, cli_loc):
    try:
        loc = cli_loc[1][0] if cli_loc[0] == "CliLoc" else None
        return {"file": rel(root, loc["path"]), "line": loc["start"]["line"], "text": cli_loc[1][1][:160]}
    except (TypeError, KeyError, IndexError):
        return None


# ------------------------------------------------------------------ signature parsing

def _split_top(s, sep=","):
    out, depth, cur, q = [], 0, "", None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in "\"'`":
            q = ch
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == sep and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


DEF_RX = {
    "python": lambda n: rf"\bdef\s+{re.escape(n)}\s*\(",
    "go": lambda n: rf"\bfunc\s*(?:\([^)]*\)\s*)?{re.escape(n)}\s*(?:\[[^\]]*\]\s*)?\(",
    "javascript": lambda n: rf"(?:\bfunction\s*\*?\s*{re.escape(n)}\s*\(|\b{re.escape(n)}\s*(?::\s*[\w<>\[\]|, ]+)?=\s*(?:async\s*)?(?:function\s*)?\(|^\s*(?:(?:public|private|protected|static|async|override|readonly)\s+)*{re.escape(n)}\s*(?:<[^>]*>)?\s*\()",
    "csharp": lambda n: rf"\b(?:public|private|protected|internal|static|async|virtual|override|sealed|partial|\s)+[\w<>\[\],.? ]+\s+{re.escape(n)}\s*(?:<[^>]*>)?\s*\(",
    "dart": lambda n: rf"(?:^|[\s;}}])(?:(?:static|external|async|Future<[^>]*>|[\w<>?,\[\] ]+)\s+)?{re.escape(n)}\s*(?:<[^>]*>)?\s*\((?=[^;]*\)\s*(?:async\s*)?(?:\{{|=>))",
    "php": lambda n: rf"\bfunction\s+&?\s*{re.escape(n)}\s*\(",  # functions and methods (any modifiers)
}


def find_signature(lang, text, fn, near_line):
    if lang not in DEF_RX:
        return None, None
    rx = re.compile(DEF_RX[lang](fn), re.M)
    lines = text.splitlines(keepends=True)
    offs, acc = [], 0
    for l in lines:
        offs.append(acc)
        acc += len(l)
    best = None
    for m in rx.finditer(text):
        ln = text.count("\n", 0, m.start()) + 1
        if ln <= near_line and (best is None or ln > best[0]):
            best = (ln, m.end() - 1)
    if not best:
        return None, None
    i, depth, start = best[1], 0, best[1] + 1
    while i < len(text):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return best[0], text[start:i]
        i += 1
    return None, None


def parse_params(lang, ptxt):
    """→ list of {name, optional, named, variadic}; receivers/self removed."""
    ps = []
    if lang == "dart":
        m = re.search(r"[{\[]", ptxt)
        pos_txt, rest, rest_kind = (ptxt[:m.start()], ptxt[m.start() + 1:].rstrip().rstrip("}]"), ptxt[m.start()]) if m else (ptxt, "", None)
        for c in _split_top(pos_txt):
            n = re.findall(r"(\w+)\s*(?:=.*)?$", re.sub(r"\bthis\.", "", c))
            if n:
                ps.append({"name": n[-1], "optional": False, "named": False, "variadic": False})
        for c in _split_top(rest):
            n = re.findall(r"(\w+)\s*(?:=.*)?$", re.sub(r"\b(?:this|super)\.", "", c))
            if n:
                ps.append({"name": n[-1], "optional": rest_kind == "[" or "required" not in c,
                           "named": rest_kind == "{", "variadic": False})
        return ps
    chunks = _split_top(ptxt)
    if lang == "python":
        kwonly = False
        for c in chunks:
            if c in ("/",):
                continue
            if c == "*":
                kwonly = True
                continue
            if c.startswith("**"):
                continue
            n = re.match(r"\*?(\w+)", c)
            if not n:
                continue
            ps.append({"name": n.group(1), "optional": "=" in c, "named": kwonly,
                       "variadic": c.startswith("*")})
            if c.startswith("*"):
                kwonly = True
        if ps and ps[0]["name"] in ("self", "cls"):
            ps = ps[1:]
        return ps
    if lang == "go":
        pending = []
        for c in chunks:
            toks = c.split()
            if len(toks) >= 2:
                for pn in pending:
                    ps.append({"name": pn, "optional": False, "named": False, "variadic": False})
                pending = []
                ps.append({"name": toks[0], "optional": False, "named": False,
                           "variadic": toks[1].startswith("...")})
            elif len(toks) == 1:
                pending.append(toks[0])
        for pn in pending:  # unnamed params (types only) — keep positions
            ps.append({"name": None, "optional": False, "named": False, "variadic": pn.startswith("...")})
        return ps
    if lang == "javascript":
        for c in chunks:
            c = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", c)
            c = re.sub(r"\b(?:public|private|protected|readonly|override)\s+", "", c).strip()
            if c.startswith("this:") or c.startswith("this "):
                continue
            var = c.startswith("...")
            n = re.match(r"(?:\.\.\.)?(\w+)", c)
            ps.append({"name": n.group(1) if n else None, "optional": "?" in c.split(":")[0] or "=" in c,
                       "named": False, "variadic": var})
        return ps
    if lang == "csharp":
        for c in chunks:
            c = re.sub(r"\[[^\]]*\]\s*", "", c).strip()
            var = bool(re.match(r"params\b", c))
            c2 = re.sub(r"\b(?:this|ref|out|in|params|scoped)\s+", "", c)
            left = c2.split("=")[0].strip()
            n = re.findall(r"(\w+)\s*$", left)
            ps.append({"name": n[-1] if n else None, "optional": "=" in c2, "named": False, "variadic": var})
        return ps
    if lang == "php":
        # `Type $a`, `?int $b = null`, `array &$c`, `string ...$d`, `#[Attr] private readonly Foo $e`
        for c in chunks:
            c = re.sub(r"#\[[^\]]*\]\s*", "", c)
            n = re.search(r"(\.\.\.)?\s*&?\s*\$(\w+)", c)
            ps.append({"name": n.group(2) if n else None, "optional": "=" in c, "named": False,
                       "variadic": bool(n and n.group(1))})
        return ps
    return ps


def param_node(lang, root, file, fn, pname, near_line, cache):
    if lang == "php":
        pname = pname.lstrip("$")  # the engine binds `$id`; signatures are parsed without the sigil
    key = file
    if key not in cache:
        try:
            cache[key] = (Path(root) / file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            cache[key] = ""
    def_line, ptxt = find_signature(lang, cache[key], fn, near_line)
    if ptxt is None:
        return None
    ps = parse_params(lang, ptxt)
    positional = [p for p in ps if not p["named"]]
    target = next((p for p in ps if p["name"] == pname), None)
    if not target:
        return None
    idx = None if target["named"] else positional.index(target)
    if target["variadic"]:
        return None
    fixed = [p for p in positional if not p["variadic"]]
    return {"fn": fn, "param": pname, "idx": idx, "named": target["named"], "file": file, "def_line": def_line,
            "arity_min": sum(1 for p in fixed if not p["optional"]), "arity_max": len(fixed),
            "variadic": any(p["variadic"] for p in positional)}


def count_definitions(lang, fn, files_by_lang, root, cache):
    if lang not in DEF_RX:
        return 0
    rx = re.compile(DEF_RX[lang](fn), re.M)
    n = 0
    for f in files_by_lang.get(lang, []):
        if f not in cache:
            try:
                cache[f] = (Path(root) / f).read_text(encoding="utf-8", errors="replace")
            except OSError:
                cache[f] = ""
        n += len(rx.findall(cache[f]))
        if n > 1:
            return n
    return n


# ------------------------------------------------------------------ analysis

def spec_family(spec):
    """Signature parsing family for a spec (typescript/javascript share one)."""
    l = spec["language"]
    return "javascript" if l in ("javascript", "typescript", "js", "ts") else l


def run_by_language(engine, rules, root, workdir, name, timeout, excludes):
    """One engine run per language: a timeout in one language costs only that language's flows."""
    by_lang = defaultdict(list)
    for r in rules:
        by_lang[r["id"].split("__")[1]].append(r)
    res, errs, secs = [], [], 0.0
    for lang, rs in sorted(by_lang.items()):
        r1, e1, s1 = run_engine(engine, rs, root, workdir, f"{name}_{lang}", timeout, excludes=excludes)
        res, errs, secs = res + r1, errs + e1, secs + s1
    return res, errs, secs


def analyze(root, specs, engine, workdir, files_by_lang, depth=3, max_targets=150, timeout=20, excludes=None):
    t0 = time.time()
    active = {l: s for l, s in specs.items() if any(files_by_lang.get(il) for il in s["inventory_languages"])}
    fam_files = defaultdict(list)
    for l, s in active.items():
        for il in s["inventory_languages"]:
            fam_files[spec_family(s)] += files_by_lang.get(il, [])
    cache, errors, stats = {}, [], {"rounds": 0, "rules_run": 0, "facts": 0, "engine_seconds": 0.0}
    hits, nodes = [], {}  # nodes: key (lang, kind, fn, param) -> node
    # cross-file chains need a signature parser for the language; without one, intra-file only
    no_xfile = sorted(l for l, s in active.items() if spec_family(s) not in DEF_RX)
    gaps = [f"{l}: no signature parser — cross-file chains not followed (intra-file flows only)" for l in no_xfile]

    rules = []
    for l, s in active.items():
        rules += entry_rules(s) + ([] if l in no_xfile else summary_rules(s))
    if not rules:
        return {"hits": [], "errors": [], "gaps": gaps, "stats": stats, "languages": []}
    res, errs, secs = run_by_language(engine, rules, root, workdir, "round0", timeout, excludes)
    errors += errs
    stats["rules_run"] += len(rules)
    stats["engine_seconds"] += secs
    frontier = []
    for r in res:
        parts = rid_parts(r["check_id"])
        if len(parts) < 3:
            continue
        typ, lang, kind = parts[0], parts[1], parts[2]
        spec = active.get(lang)
        if not spec:
            continue
        path = rel(root, r["path"])
        sink = {"file": path, "line": r["start"]["line"], "text": r["extra"].get("lines", "").strip()[:160]}
        tr = r["extra"].get("dataflow_trace") or {}
        if typ == "entry":
            src = loc_of(root, tr.get("taint_source"))
            steps = [loc_of(root, v.get("location") and ["CliLoc", [v["location"], v.get("content", "")]])
                     for v in (tr.get("intermediate_vars") or [])[:4]]
            hits.append(make_hit(spec, kind, sink, src, [s for s in steps if s], "intra", []))
        elif typ == "sum":
            mv = r["extra"].get("metavars", {})
            fn = (mv.get("$SAFN") or {}).get("abstract_content")
            pname = (mv.get("$SAP") or {}).get("abstract_content")
            if not fn or not pname or fn in SKIP_FUNCS or (lang == "php" and fn.lower() in PHP_KEYWORDS) or len(fn) < 3:
                continue
            node = param_node(spec_family(spec), root, path, fn, pname, sink["line"], cache)
            if not node:
                continue
            key = (lang, kind, fn, node["idx"] if not node["named"] else pname)
            if key in nodes:
                continue
            node.update({"lang": lang, "kind": kind, "sink": sink, "via": None, "depth": 0})
            nodes[key] = node
            frontier.append(key)
    stats["facts"] = len(nodes)

    for rnd in range(1, depth + 1):
        if not frontier:
            break
        stats["rounds"] = rnd
        frontier = frontier[:max_targets]
        rules, table = [], {}
        for i, key in enumerate(frontier):
            node = nodes[key]
            spec = active[node["lang"]]
            tid = f"t{rnd}_{i}"
            table[tid] = key
            rules.append(bridge_rule(spec, node["kind"], tid, node, entry=True))
            if rnd < depth:
                rules.append(bridge_rule(spec, node["kind"], tid, node, entry=False))
        res, errs, secs = run_by_language(engine, rules, root, workdir, f"round{rnd}", timeout, excludes)
        errors += errs
        stats["rules_run"] += len(rules)
        stats["engine_seconds"] += secs
        new = []
        for r in res:
            parts = rid_parts(r["check_id"])
            if len(parts) < 4 or parts[3] not in table:
                continue
            typ, lang = parts[0], parts[1]
            target = nodes[table[parts[3]]]
            spec = active[lang]
            call = {"file": rel(root, r["path"]), "line": r["start"]["line"],
                    "text": r["extra"].get("lines", "").strip()[:160]}
            if typ == "bent":
                src = loc_of(root, (r["extra"].get("dataflow_trace") or {}).get("taint_source"))
                chain = chain_of(nodes, table[parts[3]])
                if target["sink"] and call["file"] == target["file"] and call["line"] >= target["def_line"] and \
                        call["line"] <= target["sink"]["line"] and len(chain) == 1:
                    continue  # recursion / same function: already an intra finding
                amb = [n["fn"] for n in chain if n["fn"].lower() in COMMON_NAMES
                       or count_definitions(spec_family(spec), n["fn"], fam_files, root, cache) > 1]
                mode = "xfile-ambiguous" if amb else "xfile"
                hits.append(make_hit(spec, target["kind"], target_sink(chain), src, [], mode,
                                     [{"call": call}] + chain_steps(chain), ambiguous=amb))
            elif typ == "bpar":
                mv = r["extra"].get("metavars", {})
                fn = (mv.get("$SAFN") or {}).get("abstract_content")
                pname = (mv.get("$SAP") or {}).get("abstract_content")
                if not fn or not pname or fn in SKIP_FUNCS or (lang == "php" and fn.lower() in PHP_KEYWORDS) or len(fn) < 3 or fn == target["fn"]:
                    continue
                node = param_node(spec_family(spec), root, call["file"], fn, pname, call["line"], cache)
                if not node:
                    continue
                key = (lang, target["kind"], fn, node["idx"] if not node["named"] else pname)
                if key in nodes:
                    continue
                node.update({"lang": lang, "kind": target["kind"], "sink": None, "depth": rnd,
                             "via": table[parts[3]], "via_call": call})
                nodes[key] = node
                new.append(key)
        frontier = new
        stats["facts"] = len(nodes)

    # Dedupe: same kind + sink location — prefer intra, then fewer hops.
    rank = {"intra": 0, "xfile": 1, "xfile-ambiguous": 2}
    best = {}
    for h in hits:
        k = (h["taint_kind"], h["file"], h["line"])
        if k not in best or (rank[h["taint_mode"]], len(h["trace"])) < (rank[best[k]["taint_mode"]], len(best[k]["trace"])):
            h["other_sources"] = best[k].get("other_sources", 0) + 1 if k in best else h.get("other_sources", 0)
            best[k] = h
        else:
            best[k]["other_sources"] = best[k].get("other_sources", 0) + 1
    stats["seconds"] = round(time.time() - t0, 1)
    stats["engine_seconds"] = round(stats["engine_seconds"], 1)
    return {"hits": list(best.values()), "errors": errors, "gaps": gaps, "stats": stats, "languages": sorted(active)}


def chain_of(nodes, key):
    out, seen = [], set()
    while key and key not in seen:
        seen.add(key)
        out.append(nodes[key])
        key = nodes[key]["via"]
    return out  # [entry-most function, ..., function containing the sink]


def target_sink(chain):
    return chain[-1]["sink"]


def chain_steps(chain):
    steps = []
    for i, n in enumerate(chain):
        steps.append({"enter": {"file": n["file"], "line": n["def_line"], "text": f"{n['fn']}({n['param']})"}})
        if i + 1 < len(chain) and n.get("via_call"):
            steps.append({"call": n["via_call"]})
    return steps


def make_hit(spec, kind, sink, src, steps, mode, chain_steps_, ambiguous=None):
    k = spec["sinks"][kind]
    trace = []
    if src:
        trace.append({"role": "source", **src})
    for s in steps:
        trace.append({"role": "step", **s})
    for s in chain_steps_:
        role, loc = next(iter(s.items()))
        trace.append({"role": role, **loc})
    trace.append({"role": "sink", **sink})
    via = [s["enter"]["text"].split("(")[0] for s in chain_steps_ if "enter" in s]
    title = k["title"] + (f" (via {' → '.join(via)})" if via else "")
    conf = {"intra": "high", "xfile": "medium", "xfile-ambiguous": "low"}[mode]
    sev = k["severity"]
    note = None
    if ambiguous:
        note = f"call resolved by name; ambiguous function name(s): {', '.join(sorted(set(ambiguous)))} — confirm which implementation is called"
    if is_test_path(sink["file"]):
        sev, conf, note = "low", "low", "in test code — likely not production-reachable"
    arrow = " → ".join(f"{t['file']}:{t['line']}" for t in trace)
    return {"rule_id": f"taint-{kind}", "type": "finding", "title": title, "file": sink["file"],
            "line": sink["line"], "snippet": sink["text"], "owasp": k["owasp"], "cwe": k["cwe"],
            "severity": sev, "confidence": conf, "message": k["message"], "flow": arrow,
            "impact": k.get("impact") or IMPACT.get(kind, k["message"]), "fix": k["fix"],
            "source": "taint", "taint_kind": kind, "taint_mode": mode, "trace": trace,
            **({"note": note} if note else {})}


# ------------------------------------------------------------------ CLI

def files_by_language(inv, include_vendor=False):
    out = defaultdict(list)
    for f in inv["files"]:
        if include_vendor or not f.get("is_vendor"):
            out[f["lang"]].append(f["path"])
    return out


def cmd_run(a):
    run = Path(a.run_dir)
    inv = read_json(run / "inventory.json")
    if not inv:
        raise SystemExit("inventory.json missing — run phase 'inventory' first")
    root = Path(inv["root"])
    engine = find_engine()
    specs, spec_errors = load_specs(root)
    out = run / "scan" / "taint.json"
    if not engine:
        write_json(out, {"generated_at": now_iso(), "status": "skipped",
                         "reason": "no taint engine (install OpenGrep: scripts/engine.py install)", "hits": []})
        print("COVERAGE GAP: taint analysis skipped — no OpenGrep/Semgrep. Run scripts/engine.py install (ask the user first).")
        return
    work = run / "taint"
    work.mkdir(parents=True, exist_ok=True)
    a.include_vendor = a.include_vendor or inv.get("include_vendor", False)
    fbl = files_by_language(inv, include_vendor=a.include_vendor)
    own = [d for d in EXCLUDE_DIRS if d.lower() in {x.lower() for x in root.resolve().parts}]
    if own:
        print(f"WARNING: the repo path contains excluded folder name(s) {', '.join(sorted(own))}; "
              "they are not passed to the engine as excludes (a copy of a repo under .security-run/ is scanned)")
    # vendored assets, minified/generated files and the user's --exclude globs are not taint-scanned
    extra = [] if a.include_vendor else list(inv.get("vendor_roots", []))
    extra += ["*" + s for s in GENERATED_SUFFIXES if s.startswith(".")] + list(inv.get("exclude_globs", []))
    result = analyze(root, specs, engine, work, fbl, a.depth, a.max_targets, a.timeout,
                     excludes=engine_excludes(root, extra))
    status = "ran" if not result["errors"] else "ran-with-errors"
    write_json(out, {"generated_at": now_iso(), "status": status, "engine": engine,
                     "mode": "intrafile+xfile" if engine["intrafile"] else "intraprocedural+xfile",
                     "depth": a.depth, "spec_errors": spec_errors,
                     "excluded_vendor_roots": len(inv.get("vendor_roots", [])) if not a.include_vendor else 0,
                     **result})
    hs = result["hits"]
    by = defaultdict(int)
    for h in hs:
        by[h["taint_mode"]] += 1
    print(f"taint: engine={engine['kind']} {engine['version']} languages={','.join(result['languages']) or 'none'} "
          f"flows={len(hs)} (intra {by['intra']}, cross-file {by['xfile']}, ambiguous {by['xfile-ambiguous']}) "
          f"facts={result['stats']['facts']} rounds={result['stats']['rounds']} {result['stats']['seconds']}s")
    if not engine["intrafile"]:
        print("COVERAGE GAP: Semgrep CE has no cross-function taint — install OpenGrep for intrafile flows")
    for g in result["gaps"]:
        print("COVERAGE GAP: taint", g)
    for e in result["errors"]:
        if "timed out" in e:  # that language's flows for that round are missing — never read 0 flows as clean
            print(f"COVERAGE GAP: taint {e.split(':')[0]} timed out — its flows are missing; narrow the scope "
                  "with --exclude or re-run `run taint` with fewer --max-targets")
    for e in (spec_errors + result["errors"])[:10]:
        print("WARNING:", e)


def cmd_test(a):
    engine = find_engine()
    if not engine:
        raise SystemExit("no engine — scripts/engine.py install")
    specs, errs = load_specs(a.repo)
    for e in errs:
        print("SPEC ERROR", e)
    fails, total = len(errs), 0  # a spec that does not load must not pass as "0 failures"
    for lang, spec in sorted(specs.items()):
        if a.lang and lang != a.lang:
            continue
        ext = spec.get("example_ext", ".txt")
        for kind, k in spec["sinks"].items():
            if a.kind and kind != a.kind:
                continue
            cases = []
            for which in ("bad", "good"):
                v = (k.get("examples") or {}).get(which)
                cases += [(which, c) for c in ([v] if isinstance(v, str) else (v or []))]
            for which, code in cases:
                total += 1
                with tempfile.TemporaryDirectory() as td:
                    Path(td, "example" + k.get("example_ext", ext)).write_text(code, encoding="utf-8")
                    one = copy.deepcopy(spec)
                    one["sinks"] = {kind: k}
                    res, e2, _ = run_engine(engine, entry_rules(one), td, td, "t", 20)
                    got = bool(res)
                    if e2 or got != (which == "bad"):
                        fails += 1
                        print(f"FAIL {lang}/{kind} {which}: {'errors ' + str(e2)[:200] if e2 else ('no flow found' if which == 'bad' else 'flow found')}")
        cx = spec.get("crossfile_example")
        if cx and (not a.kind or a.kind == cx["expect"]):
            total += 1
            with tempfile.TemporaryDirectory() as td:
                files = defaultdict(list)
                for name, code in cx["files"].items():
                    Path(td, name).parent.mkdir(parents=True, exist_ok=True)
                    Path(td, name).write_text(code, encoding="utf-8")
                    files[spec["inventory_languages"][0]].append(name)
                wd = Path(td, ".work")
                wd.mkdir()
                r = analyze(td, {lang: spec}, engine, wd, files, depth=3)
                ok = any(h["taint_kind"] == cx["expect"] and h["taint_mode"] != "intra" for h in r["hits"])
                if not ok:
                    fails += 1
                    print(f"FAIL {lang} crossfile: expected {cx['expect']} chain, got "
                          f"{[(h['taint_kind'], h['taint_mode']) for h in r['hits']]} errors={r['errors'][:2]}")
    print(f"{total} taint examples, {fails} failures (engine {engine['kind']} {engine['version']})")
    raise SystemExit(1 if fails else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", default="run", choices=["run", "test"])
    ap.add_argument("--run-dir")
    ap.add_argument("--repo")
    ap.add_argument("--lang")
    ap.add_argument("--kind")
    ap.add_argument("--depth", type=int, default=3, help="max cross-file hops to follow")
    ap.add_argument("--max-targets", type=int, default=150, help="max functions bridged per round")
    ap.add_argument("--timeout", type=int, default=20, help="per-file engine timeout (s)")
    ap.add_argument("--include-vendor", action="store_true", help="also taint-scan vendored front-end assets")
    a = ap.parse_args()
    if a.cmd == "test":
        cmd_test(a)
    else:
        if not a.run_dir:
            ap.error("--run-dir required")
        cmd_run(a)


if __name__ == "__main__":
    main()
