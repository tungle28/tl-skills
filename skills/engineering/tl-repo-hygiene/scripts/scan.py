#!/usr/bin/env python3
"""Mechanical first pass for tl-repo-hygiene.

Lists the project's files (git-tracked when the root is a git repo), estimates tokens, finds agent
instruction files and reports candidate issues that need no judgement to detect: Python files that
do not compile and invalid JSON, broken relative Markdown links, SKILL.md / agent frontmatter problems, duplicate files, tracked junk and very large
always-loaded instruction files. Every item is a candidate; the agent confirms it before acting.

Standard library only, Python 3.9+.

    python scan.py <root> --out <root>/.repo-hygiene/scan.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt", ".venv", "venv",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "target", "bin", "obj", "coverage",
    "graphify-out", ".repo-hygiene",
}
LOCK_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "composer.lock",
    "Gemfile.lock", "uv.lock", "packages.lock.json",
}
JUNK_PATTERNS = [
    re.compile(r"(^|/)__pycache__/"), re.compile(r"\.py[co]$"), re.compile(r"(^|/)\.DS_Store$"),
    re.compile(r"(^|/)Thumbs\.db$"), re.compile(r"(^|/)node_modules/"), re.compile(r"\.(log|tmp|bak|orig|swp)$"),
]
TEXT_EXT = {
    ".md", ".mdx", ".txt", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".sh", ".ps1", ".psm1", ".bat", ".cmd", ".html", ".css", ".scss", ".cs",
    ".go", ".rs", ".java", ".kt", ".php", ".rb", ".dart", ".sql", ".xml", ".csproj", ".sln", ".env",
    ".gitignore", ".gitattributes", "",
}
JSONC_NAMES = {"tsconfig.json", "jsconfig.json", "devcontainer.json", ".eslintrc.json", "launch.json", "settings.json", "extensions.json"}
ALWAYS_LOADED ={"AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", "copilot-instructions.md"}
LARGE_ALWAYS_LOADED_TOKENS = 4000
LARGE_SKILL_TOKENS = 6000
MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")


def list_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True,
        ).stdout.decode("utf-8", "replace")
        files = [f for f in out.split("\0") if f]
        return sorted(f for f in files if (root / f).is_file())
    except (OSError, subprocess.CalledProcessError):
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                files.append((Path(dirpath) / name).relative_to(root).as_posix())
        return sorted(files)


def is_skipped(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in SKIP_DIRS for p in parts[:-1]) or parts[-1] in LOCK_FILES or rel.endswith((".min.js", ".min.css"))


def read_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_EXT:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8-sig", "replace")


def est_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def frontmatter(text: str) -> tuple[dict[str, str], int] | None:
    """Very small YAML-frontmatter reader: top-level `key: value` pairs, folded `>`/`|` blocks joined."""
    if not text.startswith("---"):
        return None
    lines = text.splitlines()
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return None
    data: dict[str, str] = {}
    key = None
    for line in lines[1:end]:
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            data[key] = "" if val in (">", "|", ">-", "|-") else val.strip("\"'")
        elif key and line.startswith((" ", "\t")):
            data[key] = (data[key] + " " + line.strip()).strip()
    return data, end + 1


def classify_instruction(rel: str) -> str | None:
    name = rel.split("/")[-1]
    if name == "SKILL.md":
        return "skill"
    if name in ALWAYS_LOADED:
        return "always-loaded"
    if re.search(r"(^|/)\.(claude|codex|cursor)/agents/[^/]+\.(md|toml)$", rel) or re.search(r"(^|/)agents/[^/]+\.md$", rel):
        return "agent"
    if re.search(r"(^|/)\.cursor/rules/", rel) or re.search(r"(^|/)\.claude/(commands|rules)/", rel):
        return "rule"
    if re.search(r"(^|/)agents/openai\.yaml$", rel):
        return "agent-ui"
    return None


def md_links(text: str):
    in_fence = False
    for no, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for m in MD_LINK.finditer(re.sub(r"`[^`]*`", "", line)):
            yield no, m.group(1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    all_files = list_files(root)
    files, skipped, issues, instructions = [], [], [], []
    by_hash: dict[str, list[str]] = defaultdict(list)
    total_tokens = 0

    def issue(kind: str, file: str, line: int | None, detail: str, category: str) -> None:
        issues.append({"kind": kind, "category": category, "file": file, "line": line, "detail": detail})

    for rel in all_files:
        for pat in JUNK_PATTERNS:
            if pat.search(rel):
                issue("tracked-junk", rel, None, "build/OS artefact present in the project file list", "obsolete")
                break
        if is_skipped(rel):
            skipped.append(rel)
            continue
        path = root / rel
        size = path.stat().st_size
        text = read_text(path)
        tokens = est_tokens(text) if text is not None else 0
        total_tokens += tokens
        entry = {"path": rel, "bytes": size, "lines": text.count("\n") + 1 if text else 0, "tokens": tokens}
        if text is not None and "generated" in text[:600].lower() and ("do not edit" in text[:600].lower() or "auto-generated" in text[:600].lower()):
            entry["generated"] = True
        files.append(entry)
        if size > 0:
            h = hashlib.sha256(path.read_bytes()).hexdigest()
            by_hash[h].append(rel)

        kind = classify_instruction(rel)
        if kind:
            instructions.append({"path": rel, "kind": kind, "tokens": tokens})
        if text is None:
            continue

        suffix = path.suffix.lower()
        if suffix == ".py":
            try:
                compile(text, rel, "exec")
            except SyntaxError as err:
                issue("syntax-error", rel, err.lineno, f"Python does not compile: {err.msg}", "broken")
        elif suffix == ".json" and path.name not in JSONC_NAMES and ".vscode/" not in rel:
            try:
                json.loads(text)
            except ValueError as err:
                issue("syntax-error", rel, getattr(err, "lineno", None), f"invalid JSON: {err}", "broken")

        if suffix in (".md", ".mdx"):
            for no, target in md_links(text):
                if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith(("#", "<", "{")):
                    continue
                target_path = target.split("#")[0].split("?")[0]
                if not target_path:
                    continue
                resolved = (root / target_path.lstrip("/")) if target_path.startswith("/") else (path.parent / unquote(target_path))
                if not resolved.exists():
                    issue("broken-link", rel, no, f"link target not found: {target}", "broken")

        if kind == "always-loaded" and tokens > LARGE_ALWAYS_LOADED_TOKENS:
            issue("large-always-loaded", rel, None, f"~{tokens} tokens loaded every session", "token-waste")

        if kind in ("skill", "agent") and path.suffix == ".md":
            fm = frontmatter(text)
            if fm is None:
                issue("frontmatter-missing", rel, 1, "no YAML frontmatter", "broken")
                continue
            data, body_start = fm
            for key in ("name", "description"):
                if not data.get(key):
                    issue("frontmatter-field", rel, 1, f"missing `{key}`", "broken")
            desc = data.get("description", "")
            if len(desc) > 1024:
                issue("description-too-long", rel, 1, f"description is {len(desc)} chars (limit 1024)", "broken")
            if kind == "skill":
                folder = rel.split("/")[-2] if "/" in rel else root.name
                if data.get("name") and data["name"] != folder:
                    issue("name-mismatch", rel, 1, f"name `{data['name']}` != folder `{folder}`", "inconsistent")
                body_lines = len(text.splitlines()) - body_start
                if body_lines > 500:
                    issue("skill-body-long", rel, None, f"body is {body_lines} lines (guideline <= 500)", "token-waste")
                if tokens > LARGE_SKILL_TOKENS:
                    issue("skill-large", rel, None, f"~{tokens} tokens loaded when the skill triggers", "token-waste")
                # A path may be relative to the skill folder or to any folder above it (e.g. a repo-level
                # scripts/install.py); flag it only when it resolves nowhere between the skill and the root.
                bases = [path.parent, *[p for p in path.parent.parents if p == root or root in p.parents]]
                for ref in sorted(set(re.findall(r"(?<![\w/.-])((?:scripts|references|assets|agents)/[\w./-]+\.\w+)", text))):
                    if not any((b / ref).exists() for b in bases):
                        issue("missing-skill-file", rel, None, f"references `{ref}`, not found in the skill folder", "broken")

    for paths in by_hash.values():
        if len(paths) > 1:
            issue("duplicate-files", paths[0], None, "identical content: " + ", ".join(paths), "obsolete")

    names: dict[str, list[str]] = defaultdict(list)
    for item in instructions:
        if item["kind"] == "skill":
            text = read_text(root / item["path"]) or ""
            fm = frontmatter(text)
            if fm and fm[0].get("name"):
                names[fm[0]["name"]].append(item["path"])
    for name, paths in names.items():
        if len(paths) > 1:
            issue("duplicate-skill-name", paths[0], 1, f"skill name `{name}` used by: " + ", ".join(paths), "inconsistent")

    result = {
        "root": str(root),
        "file_count": len(files),
        "skipped_count": len(skipped),
        "estimated_tokens_total": total_tokens,
        "instruction_files": sorted(instructions, key=lambda x: (-x["tokens"], x["path"])),
        "largest_files": sorted(files, key=lambda x: -x["tokens"])[:25],
        "generated_files": [f["path"] for f in files if f.get("generated")],
        "issues": issues,
        "files": files,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    counts: dict[str, int] = defaultdict(int)
    for i in issues:
        counts[i["kind"]] += 1
    print(f"{len(files)} files scanned ({len(skipped)} skipped), ~{total_tokens} tokens, "
          f"{len(instructions)} instruction files, {len(issues)} candidate issues -> {out}")
    for kind, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {kind}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
