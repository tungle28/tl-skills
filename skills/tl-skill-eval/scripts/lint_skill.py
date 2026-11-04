#!/usr/bin/env python3
"""Static lint of one or more skill folders against Anthropic's hard limits and authoring heuristics.

Usage:
  python lint_skill.py <skill-path> [--json out.json]
  python lint_skill.py <core> <module1> <module2> ... --json out.json   # a skill family: also finds
                                                                         # paragraphs duplicated across them
  python lint_skill.py <skill-path> --siblings <skills-root>             # other skills whose description
                                                                         # overlaps (near-miss sources)
  python lint_skill.py <skill-path> --name-prefix tl-                    # enforce a naming convention

Errors = hard-limit violations. Warnings = heuristics worth a human look. Info includes a load-cost
estimate: description (always in context), SKILL.md body (on trigger), references/agents (on demand).
A WORKFLOW.md user guide at the skill root is not agent context: it is left out of the load cost and
the duplication checks, and flagged when git shows SKILL.md changed after it. Its rendered
WORKFLOW.html is flagged when missing or built from a different WORKFLOW.md (source-sha256 stamp).
"""
import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import est_tokens, parse_frontmatter, read_text, utf8_stdio, write_json  # noqa: E402

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
RESERVED = ("anthropic", "claude")
TIME_WORDS = re.compile(r"\b(currently|as of (19|20)\d\d|latest version|recently released|this year|new in (19|20)\d\d)\b", re.I)
FIRST_SECOND = re.compile(r"^\s*(I |I'm |We |You can |You |This skill lets you)", re.I)
TRIGGER_HINT = re.compile(r"\b(use (this|when|whenever|it)|trigger|when the user|whenever|load (this|it)\b[^.]{0,20}\bwhen)\b", re.I)
SKIP_PARTS = {"node_modules", "__pycache__", "evals", ".git"}
BODY_TOKEN_WARN = 5000
STOP = set("the a an and or of to in for on with by is are be it this that as at from when use user skill skills "
           "not only any all its their into than then also can should must will your you".split())


USER_GUIDE = "WORKFLOW.md"  # human-facing guide; agents never load it
GUIDE_HTML = "WORKFLOW.html"  # the guide rendered by tl-md-to-html; stamped with the guide's sha256


def md_files(skill_path, guide=False):
    """Markdown an agent may load; guide=True also includes the WORKFLOW.md user guide."""
    return [p for p in skill_path.rglob("*.md") if not SKIP_PARTS & set(p.relative_to(skill_path).parts)
            and (guide or p != skill_path / USER_GUIDE)]


def git(cwd, *args):
    try:
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def guide_staleness(skill_path):
    """Is the WORKFLOW.md user guide older than SKILL.md in git? None when it can't be told."""
    if not (skill_path / USER_GUIDE).exists():
        return None
    guide_commit = git(skill_path, "log", "-1", "--format=%H", "--", USER_GUIDE)
    if not guide_commit:  # no git, or the guide isn't committed yet
        return None
    since = git(skill_path, "rev-list", "--count", f"{guide_commit}..HEAD", "--", "SKILL.md")
    dirty = git(skill_path, "status", "--porcelain", "--", "SKILL.md", USER_GUIDE) or ""
    changed = {line[3:].rsplit("/", 1)[-1] for line in dirty.splitlines()}
    return {"skill_commits_since_guide": int(since or 0),
            "skill_uncommitted": "SKILL.md" in changed and USER_GUIDE not in changed}


def guide_html_state(skill_path):
    """'missing', 'stale' or 'ok' for WORKFLOW.html against WORKFLOW.md; None when there is no guide.
    The page carries <meta name="source-sha256"> of the guide it was built from (LF line endings)."""
    import hashlib
    guide, html = skill_path / USER_GUIDE, skill_path / GUIDE_HTML
    if not guide.exists():
        return None
    if not html.exists():
        return "missing"
    want = hashlib.sha256(guide.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    m = re.search(r'<meta name="source-sha256" content="([0-9a-f]{64})"', read_text(html))
    return "ok" if m and m.group(1) == want else "stale"


def lint_agents(skill_path, prefix, errors, warnings):
    agents = sorted((skill_path / "agents").glob("*.md")) if (skill_path / "agents").is_dir() else []
    for p in agents:
        fm, _ = parse_frontmatter(read_text(p))
        rel = p.relative_to(skill_path)
        if not fm or "__yaml_error__" in (fm or {}):
            errors.append(f"{rel}: missing or invalid frontmatter (sub-agent definitions need name/description)")
            continue
        name = str(fm.get("name") or "")
        if not name or not fm.get("description"):
            errors.append(f"{rel}: frontmatter needs name and description")
            continue
        if name != p.stem:
            warnings.append(f"{rel}: agent name '{name}' differs from file name (installers copy by file name)")
        if prefix and not name.startswith(prefix):
            warnings.append(f"{rel}: agent name '{name}' lacks the '{prefix}' prefix")
    return len(agents)


def lint(skill_path, prefix=None):
    errors, warnings, info = [], [], {}
    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        return {"errors": ["SKILL.md not found"], "warnings": [], "info": {}}

    nested = [p for p in skill_path.rglob("SKILL.md") if p != skill_md
              and not SKIP_PARTS & set(p.relative_to(skill_path).parts)]
    if nested:
        errors.append(f"Extra SKILL.md files (only one allowed): {[str(p.relative_to(skill_path)) for p in nested]}")

    text = read_text(skill_md)
    fm, body = parse_frontmatter(text)
    if fm is None:
        errors.append("Missing or malformed YAML frontmatter (--- ... ---)")
        fm = {}
    if "__yaml_error__" in fm:
        errors.append(f"Invalid YAML frontmatter: {fm['__yaml_error__']} (quote values containing ': ')")
        fm = {}
    name = str(fm.get("name", "") or "")
    desc = str(fm.get("description", "") or "")

    if not name:
        errors.append("frontmatter.name missing")
    else:
        if len(name) > 64:
            errors.append(f"name is {len(name)} chars (max 64)")
        if not NAME_RE.match(name):
            errors.append(f"name '{name}' must be lowercase letters, digits, hyphens")
        if any(r in name for r in RESERVED):
            errors.append(f"name '{name}' contains reserved word (anthropic/claude)")
        if name != skill_path.name:
            warnings.append(f"name '{name}' differs from folder name '{skill_path.name}'")
        if prefix and not name.startswith(prefix):
            warnings.append(f"name '{name}' lacks the '{prefix}' prefix")
    if not desc:
        errors.append("frontmatter.description missing")
    else:
        if len(desc) > 1024:
            errors.append(f"description is {len(desc)} chars (max 1024)")
        elif len(desc) > 900:
            warnings.append(f"description is {len(desc)} chars; little headroom under 1024")
        if len(desc) < 80:
            warnings.append("description is very short; likely under-specifies triggers")
        if FIRST_SECOND.match(desc):
            warnings.append("description should be third person (not 'I'/'You')")
        if not TRIGGER_HINT.search(desc):
            warnings.append("description has no explicit 'when to use' / trigger signal")
        if re.search(r"[<>]", desc):
            warnings.append("description contains angle brackets; some validators reject them")
    info["name"] = name
    info["description_chars"] = len(desc)

    body_lines = body.count("\n") + 1
    info["body_lines"] = body_lines
    info["body_words"] = len(body.split())
    if body_lines > 500:
        warnings.append(f"SKILL.md body is {body_lines} lines (guidance: <500); move detail to references/")

    # load cost (estimates): what enters context always / on trigger / on demand
    on_demand = [p for p in md_files(skill_path) if p != skill_md]
    info["tokens_est"] = {
        "description_always": est_tokens(desc),
        "body_on_trigger": est_tokens(body),
        "on_demand_md": sum(est_tokens(read_text(p)) for p in on_demand),
        "note": "chars/4 estimate; Vietnamese and code cost more per char",
    }
    if info["tokens_est"]["body_on_trigger"] > BODY_TOKEN_WARN:
        warnings.append(f"SKILL.md body ≈{info['tokens_est']['body_on_trigger']} tokens on every trigger "
                        f"(> {BODY_TOKEN_WARN}); move rarely-needed detail to references/ or code to scripts/assets")
    history = len(re.findall(r"(?i)\b(confirmed via reviewer feedback|an earlier version|previously|v1 let)\b", body))
    if history >= 3:
        warnings.append(f"{history} change-history phrases in SKILL.md ('an earlier version…'); keep the rule, drop the story")

    # referenced files and depth
    missing = []
    # the lookbehind skips dot-dirs like `.agents/skills/`; `*` and `<>` stay in the match so globs and
    # placeholders are recognised and skipped instead of truncated into a bogus path
    for m in re.finditer(r"(?<![\w.])(?:([a-z0-9][\w-]*)/)?((?:references|scripts|assets|agents)/[\w./*<>-]+)", body):
        owner, ref = m.group(1), m.group(2).rstrip(".,)`")
        if "*" in ref or "<" in ref:
            continue
        # `other-skill/references/x.md` points into a sibling skill; a bare path may also be repo-level
        bases = [skill_path.parent / owner] if owner and owner != skill_path.name else [skill_path]
        if not owner:
            bases += list(skill_path.parents)[:4]
        if not any((b / ref).exists() for b in bases):
            missing.append(f"{owner}/{ref}" if owner else ref)
    if missing:
        warnings.append(f"SKILL.md references files that don't exist: {sorted(set(missing))}")
    sib = set(re.findall(r"\.\./([a-z0-9][\w-]*)/SKILL\.md", text))
    for s in sorted(sib):
        if not (skill_path.parent / s / "SKILL.md").exists():
            warnings.append(f"SKILL.md points at sibling skill '../{s}/SKILL.md', which is not next to this skill")
    guide = skill_path / USER_GUIDE
    # SKILL.md and agent prompts are entry points: a file they name directly is one level deep even if a
    # reference also links to it
    entry_text = body + "".join(read_text(a) for a in (skill_path / "agents").glob("*.md"))
    for p in on_demand + ([guide] if guide.exists() else []):
        t = read_text(p)
        n = t.count("\n") + 1
        if n > 100 and not re.search(r"(?im)^#+\s*(contents|table of contents|toc)\b", t):
            warnings.append(f"{p.relative_to(skill_path)} is {n} lines without a table of contents")
        if p == guide:
            continue
        nested_refs = [r for r in re.findall(r"\b[\w-]+\.md\b", t) if (p.parent / r).exists() and (p.parent / r) != p
                       and not re.search(rf"\b{re.escape(r)}\b", entry_text)]
        if nested_refs and "agents" not in p.relative_to(skill_path).parts:
            warnings.append(f"{p.relative_to(skill_path)} links to other .md files {sorted(set(nested_refs))}; "
                            f"keep references one level deep from SKILL.md")

    stale = guide_staleness(skill_path)
    if stale is not None:
        info["user_guide"] = {"file": USER_GUIDE, **stale}
        if stale["skill_commits_since_guide"]:
            warnings.append(f"{USER_GUIDE} predates {stale['skill_commits_since_guide']} commit(s) to SKILL.md; "
                            f"check the user guide still matches")
        if stale["skill_uncommitted"]:
            warnings.append(f"SKILL.md has uncommitted changes but {USER_GUIDE} doesn't; update the guide if the workflow changed")
    page = guide_html_state(skill_path)
    if page is not None:
        info.setdefault("user_guide", {"file": USER_GUIDE})["html"] = page
        if page != "ok":
            what = "is missing" if page == "missing" else f"was built from an older {USER_GUIDE}"
            warnings.append(f"{GUIDE_HTML} {what}: render {USER_GUIDE} with tl-md-to-html "
                            f"(in the skills repo: python scripts/build_workflow_html.py)")

    info["agents"] = lint_agents(skill_path, prefix, errors, warnings)
    if TIME_WORDS.search(body):
        warnings.append("time-sensitive wording in body (e.g. 'currently', 'latest version'); it will go stale")
    # C:\x (also JSON-escaped C:\\x), dir\sub\, dir\file.ext. A backslash before "." or a single
    # letter (regex \.  \d, escapes \n) is not a path.
    if re.search(r"\b[A-Za-z]:\\(?:\\)?[\w$]|[\w-]+\\[\w-][\w.-]*\\|\b[\w-]+\\[\w-]+\.[A-Za-z]{1,5}\b", body):
        warnings.append("Windows-style backslash paths found; use forward slashes")
    return {"errors": errors, "warnings": warnings, "info": info}


# ------------------------------------------------------------------ family / siblings
def sentences(text):
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    for chunk in re.split(r"(?<=[.!?])\s+|\n\s*\n|\n[-*] ", text):
        words = re.findall(r"[a-z0-9]+", chunk.lower())
        if len(words) >= 12:
            yield " ".join(words), chunk.strip()


def family_duplicates(paths):
    """Sentences (≥12 words) that appear in more than one skill of the family."""
    seen = defaultdict(dict)  # norm -> {skill: example}
    totals = defaultdict(int)
    for sp in paths:
        for p in md_files(sp):
            for norm, raw in sentences(read_text(p)):
                totals[sp.name] += 1
                seen[norm].setdefault(sp.name, f"{p.relative_to(sp)}: {raw[:140]}")
    dups = {n: s for n, s in seen.items() if len(s) > 1}
    per_skill = defaultdict(int)
    for s in dups.values():
        for k in s:
            per_skill[k] += 1
    share = {k: round(per_skill[k] / totals[k], 3) for k in totals if totals[k]}
    examples = [list(s.values())[:2] for s in list(dups.values())[:8]]
    return {"duplicated_sentences": len(dups), "share_by_skill": share, "examples": examples}


def desc_words(desc):
    return {w for w in re.findall(r"[a-zà-ỹ0-9]+", desc.lower()) if w not in STOP and len(w) > 2}


def sibling_overlap(target, root):
    fm, _ = parse_frontmatter(read_text(target / "SKILL.md"))
    mine = desc_words(str((fm or {}).get("description", "")))
    out = []
    for p in Path(root).rglob("SKILL.md"):
        sp = p.parent
        if sp.resolve() == target.resolve() or SKIP_PARTS & set(p.parts):
            continue
        f2, _ = parse_frontmatter(read_text(p))
        other = desc_words(str((f2 or {}).get("description", "")))
        if mine and other:
            j = len(mine & other) / len(mine | other)
            out.append({"skill": str((f2 or {}).get("name") or sp.name), "jaccard": round(j, 3),
                        "shared": sorted(mine & other)[:12]})
    return sorted(out, key=lambda x: -x["jaccard"])[:6]


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("skill_paths", type=Path, nargs="+")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--siblings", type=Path, help="root dir with other skills: report description overlap")
    ap.add_argument("--name-prefix", help="warn when a skill/agent name lacks this prefix, e.g. tl-")
    a = ap.parse_args()
    paths = [p.resolve() for p in a.skill_paths]
    per = {p.name: lint(p, a.name_prefix) for p in paths}
    res = per[paths[0].name] if len(paths) == 1 else {"skills": per, "errors": [], "warnings": [], "info": {}}
    if len(paths) > 1:
        fam = family_duplicates(paths)
        res["family"] = fam
        for k, v in fam["share_by_skill"].items():
            if v >= 0.15:
                res["warnings"].append(f"{k}: {v:.0%} of its sentences are duplicated in sibling skills — "
                                       f"move shared text to one reference and point to it")
    if a.siblings:
        res["siblings"] = sibling_overlap(paths[0], a.siblings)
    n_err = sum(len(r["errors"]) for r in per.values()) + len(res["errors"]) * (len(paths) > 1)
    n_warn = sum(len(r["warnings"]) for r in per.values()) + len(res["warnings"]) * (len(paths) > 1)
    res["summary"] = {"errors": n_err, "warnings": n_warn}
    if a.json:
        write_json(a.json, res)
    for name, r in per.items():
        if len(paths) > 1:
            print(f"== {name}")
        for e in r["errors"]:
            print("ERROR  ", e)
        for w in r["warnings"]:
            print("WARN   ", w)
        t = r["info"].get("tokens_est", {})
        print(f"info: body {r['info'].get('body_lines')} lines, ≈{t.get('body_on_trigger')} tok on trigger, "
              f"≈{t.get('on_demand_md')} tok on demand, description {r['info'].get('description_chars')} chars, "
              f"agents {r['info'].get('agents')}")
    if len(paths) > 1:
        for w in res["warnings"]:
            print("WARN   ", w)
        print(f"family: {res['family']['duplicated_sentences']} duplicated sentence(s); share {res['family']['share_by_skill']}")
    for s in res.get("siblings", []):
        print(f"sibling overlap {s['jaccard']:.2f} {s['skill']}: {', '.join(s['shared'])}")
    print(f"{n_err} error(s), {n_warn} warning(s)")
    sys.exit(1 if n_err else 0)


if __name__ == "__main__":
    main()
