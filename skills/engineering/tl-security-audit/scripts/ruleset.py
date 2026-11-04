"""Load, validate and match pattern rules; load review checks.

Rule sources, in order (a later rule with the same id overrides an earlier one, which is how a
project tunes or disables a built-in rule without editing the skill):
  1. <skill>/rules/*.yml|*.yaml|*.json
  2. <repo>/.security-audit/rules/*
  3. any --rules-dir given at init
Check sources: <skill>/checks/*.md, then <repo>/.security-audit/checks/*.md (same override rule).
"""
import fnmatch
import json
import math
import re
from collections import Counter
from pathlib import Path

from common import CONFIDENCES, OWASP_2025, SEVERITIES

try:
    import yaml  # PyYAML; JSON rule files work without it
except ImportError:  # pragma: no cover
    yaml = None

SKILL_DIR = Path(__file__).resolve().parent.parent
RULE_TYPES = ("finding", "gate")
REQUIRED = {
    "finding": ("id", "title", "languages", "severity", "confidence", "owasp", "cwe", "message", "fix"),
    "gate": ("id", "title", "languages", "owasp", "question"),
}
REGEX_KEYS = ("pattern", "pattern_not", "context_not", "file_requires", "file_excludes", "path_pattern")
LANG_ALIASES = {
    "js": ["javascript", "typescript"], "web": ["javascript", "typescript", "html", "razor"],
    "dotnet": ["csharp", "razor"], "mobile": ["dart", "kotlin", "swift", "java", "xml"],
    "backend": ["csharp", "javascript", "typescript", "python", "go", "java", "php", "ruby"], "config": ["yaml", "json", "xml", "ini", "toml", "env", "terraform"],
}


def _load_file(p):
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".json":
        data = json.loads(text)
    else:
        if yaml is None:
            raise SystemExit(f"{p}: PyYAML not installed (pip install pyyaml) — or use .json rule files")
        data = yaml.safe_load(text)
    if isinstance(data, dict):
        data = data.get("rules", [])
    return data or []


def rule_dirs(repo_root=None, extra=()):
    dirs = [SKILL_DIR / "rules"]
    if repo_root:
        dirs.append(Path(repo_root) / ".security-audit" / "rules")
    dirs += [Path(d) for d in extra]
    return [d for d in dirs if d.is_dir()]


def load_rules(repo_root=None, extra=()):
    """Returns (rules_by_id, errors). Disabled rules are dropped after overriding."""
    rules, errors = {}, []
    for d in rule_dirs(repo_root, extra):
        for p in sorted(d.glob("*")):
            if p.suffix not in (".yml", ".yaml", ".json"):
                continue
            try:
                items = _load_file(p)
            except Exception as e:  # noqa: BLE001 — report and keep going
                errors.append(f"{p}: cannot parse ({e})")
                continue
            for r in items:
                if not isinstance(r, dict) or "id" not in r:
                    errors.append(f"{p}: rule without id")
                    continue
                if r.get("disabled"):
                    rules.pop(r["id"], None)
                    continue
                base = rules.get(r["id"], {})
                merged = {**base, **r, "_source": str(p)}
                errs = validate_rule(merged)
                if errs:
                    errors += [f"{p}: {r['id']}: {e}" for e in errs]
                    continue
                rules[r["id"]] = compile_rule(merged)
    return rules, errors


def validate_rule(r):
    errs = []
    t = r.get("type", "finding")
    if t not in RULE_TYPES:
        return [f"type must be one of {RULE_TYPES}"]
    for k in REQUIRED[t]:
        if not r.get(k):
            errs.append(f"missing '{k}'")
    if not (r.get("pattern") or r.get("path_pattern")):
        errs.append("needs 'pattern' (content) or 'path_pattern' (file-level)")
    if t == "finding":
        if r.get("severity") not in SEVERITIES:
            errs.append(f"severity must be one of {SEVERITIES}")
        if r.get("confidence") not in CONFIDENCES:
            errs.append(f"confidence must be one of {CONFIDENCES}")
    if r.get("owasp") and str(r["owasp"])[:3] not in OWASP_2025:
        errs.append("owasp must be A01..A10 (OWASP Top 10:2025)")
    if r.get("cwe") and not re.fullmatch(r"CWE-\d+", str(r["cwe"])):
        errs.append("cwe must look like CWE-89")
    for k in REGEX_KEYS:
        if r.get(k):
            try:
                re.compile(r[k])
            except re.error as e:
                errs.append(f"{k}: invalid regex ({e})")
    if r.get("secret") and r.get("secret_group") is not None and r.get("pattern"):
        if re.compile(r["pattern"]).groups < int(r["secret_group"]):
            errs.append("secret_group exceeds the number of groups in pattern")
    return errs


def compile_rule(r):
    flags = re.MULTILINE | (re.DOTALL if r.get("multiline") else 0) | (re.I if r.get("ignore_case") else 0)
    c = dict(r)
    c["type"] = r.get("type", "finding")
    for k in REGEX_KEYS:
        if r.get(k):
            c["_" + k] = re.compile(r[k], flags if k == "pattern" else (re.I if r.get("ignore_case") else 0))
    langs = []
    for l in r.get("languages", []):
        langs += LANG_ALIASES.get(l, [l])
    c["_langs"] = set(langs)
    return c


def applies_to(rule, rel, lang):
    if "any" not in rule["_langs"] and lang not in rule["_langs"]:
        return False
    paths = rule.get("paths") or {}
    if paths.get("include") and not any(fnmatch.fnmatch(rel, g) for g in paths["include"]):
        return False
    if paths.get("exclude") and any(fnmatch.fnmatch(rel, g) for g in paths["exclude"]):
        return False
    return True


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def match_rule(rule, rel, text):
    """Yield (line_no, line_text, secret_value_or_None) for each hit of one rule in one file."""
    if rule.get("_path_pattern") and not rule["_path_pattern"].search(rel):
        return
    if rule.get("_file_requires") and not rule["_file_requires"].search(text):
        return
    if rule.get("_file_excludes") and rule["_file_excludes"].search(text):
        return
    if not rule.get("_pattern"):  # file-level rule: the path itself is the finding
        yield 1, "", None
        return
    lines = text.splitlines()
    ctx = int(rule.get("context_lines", 3))
    seen = set()
    for m in rule["_pattern"].finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        if line_no in seen:
            continue
        line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
        if rule.get("_pattern_not") and rule["_pattern_not"].search(line):
            continue
        if rule.get("_context_not"):
            window = "\n".join(lines[max(0, line_no - 1 - ctx): line_no + ctx])
            if rule["_context_not"].search(window):
                continue
        secret = None
        if rule.get("secret"):
            g = int(rule.get("secret_group", 0))
            secret = m.group(g) or ""
            if rule.get("entropy_min") and entropy(secret) < float(rule["entropy_min"]):
                continue
        seen.add(line_no)
        yield line_no, line, secret


# ---------------------------------------------------------------- review checks (markdown)

def _frontmatter(text):
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    head = text[3:end]
    meta = yaml.safe_load(head) if yaml else {}
    return (meta or {}), text[end + 4:]


def load_checks(repo_root=None):
    checks, errors = {}, []
    dirs = [SKILL_DIR / "checks"]
    if repo_root:
        dirs.append(Path(repo_root) / ".security-audit" / "checks")
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.md")):
            meta, _ = _frontmatter(p.read_text(encoding="utf-8"))
            if not meta.get("id"):
                errors.append(f"{p}: missing frontmatter 'id'")
                continue
            if meta.get("disabled"):
                checks.pop(meta["id"], None)
                continue
            for k in ("triggers",):
                for rx in meta.get(k) or []:
                    try:
                        re.compile(rx)
                    except re.error as e:
                        errors.append(f"{p}: bad trigger regex {rx!r} ({e})")
            langs = []
            for l in meta.get("languages") or ["any"]:
                langs += LANG_ALIASES.get(l, [l])
            checks[meta["id"]] = {**meta, "_langs": set(langs), "path": str(p)}
    return checks, errors


def check_applies(check, langs, frameworks, text_blob):
    if "any" not in check["_langs"] and not (check["_langs"] & set(langs)):
        return False
    fws = check.get("frameworks")
    if fws and not set(fws) & set(frameworks):
        return False
    trig = check.get("triggers")
    if trig and not any(re.search(rx, text_blob, re.I | re.M) for rx in trig):
        return False
    return True
