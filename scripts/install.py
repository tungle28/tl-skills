#!/usr/bin/env python3
"""Install the skills in this repository for Claude Code, Cursor or OpenAI Codex.

  python scripts/install.py --target cursor                    # all skills -> ~/.cursor/skills
  python scripts/install.py --target codex                     # all skills -> ~/.agents/skills
  python scripts/install.py --target claude --scope project --project ../my-app
  python scripts/install.py --target all --skills tl-code-refactor,tl-seo-audit --dry-run

Skills are copied flat (<skills-dir>/<skill-name>/SKILL.md) so every tool finds them regardless
of whether it scans category folders. Sub-agent definitions shipped in a skill's agents/*.md are
installed too:
  - claude: copied as-is to .claude/agents/
  - cursor: copied to .cursor/agents/ with the frontmatter converted — Cursor accepts only
    `model: inherit` or a Cursor model ID, and has no `tools`/`skills` fields.
  - codex:  converted to Codex custom-agent TOML in .codex/agents/<name>.toml
    (name, description, developer_instructions = the Markdown body; model inherited).
A skill's WORKFLOW.md is a guide for people reading the repository, so it is not installed.
Skills that only work on one tool (see PLATFORM_ONLY) are skipped for the others, with a note.
Existing files that differ are never overwritten without --force.

After copying, the tools the selected skills use (git, PyYAML, lizard, OpenGrep, pip-audit, …) are
checked. Nothing is installed without asking: each missing tool that can be installed gets its own
[y/N] question (default: no). Without an interactive terminal nothing is installed — the missing
tools and how to install them are only listed. --deps check only reports; --deps skip does nothing.
"""
import argparse
import filecmp
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Windows consoles default to a legacy code page; keep em dashes/arrows from crashing the output.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

REPO = Path(__file__).resolve().parent.parent
SKILLS_SRC = REPO / "skills"
TARGETS = {
    "claude": {"skills": ".claude/skills", "agents": ".claude/agents"},
    "cursor": {"skills": ".cursor/skills", "agents": ".cursor/agents"},
    # Codex reads skills from .agents/skills (repo) and ~/.agents/skills (user); custom agents are
    # TOML files in .codex/agents/ (project) or ~/.codex/agents/ (user).
    "codex": {"skills": ".agents/skills", "agents": ".codex/agents"},
}
# Skills that only make sense on some tools, with the reason shown when they are skipped.
PLATFORM_ONLY = {
    "session-report": ({"claude"}, "reads Claude Code's own transcripts (~/.claude/projects); "
                                   "third-party skill by Anthropic"),
}
# Repository-only files at a skill's root: the user guide (same name as USER_GUIDE in
# tl-skill-eval/scripts/lint_skill.py). Agents never read it.
REPO_ONLY = {"WORKFLOW.md"}
# Claude Code-only frontmatter keys that Cursor does not understand
CURSOR_DROP_KEYS = {"tools", "skills"}


def check_frontmatter(skill_md):
    """Strict-YAML check: an unquoted `key: a: b` value parses in lenient loaders but breaks stricter
    ones (a skill that silently fails to load in one tool). Needs PyYAML; skipped without it."""
    try:
        import yaml
    except ImportError:
        return
    text = skill_md.read_text(encoding="utf-8")
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
    try:
        meta = yaml.safe_load(m.group(1)) if m else None
    except yaml.YAMLError as e:
        sys.exit(f"{skill_md}: frontmatter is not valid YAML — quote values containing ': '\n  {e}")
    if not isinstance(meta, dict) or not meta.get("name") or not meta.get("description"):
        sys.exit(f"{skill_md}: frontmatter needs `name` and `description`")
    if len(str(meta["description"])) > 1024:
        sys.exit(f"{skill_md}: description is {len(str(meta['description']))} chars (limit 1024)")


def find_skills():
    out = {}
    for skill_md in sorted(SKILLS_SRC.rglob("SKILL.md")):
        check_frontmatter(skill_md)
        m = re.search(r"^name:\s*\"?([\w-]+)\"?\s*$", skill_md.read_text(encoding="utf-8"), re.M)
        name = m.group(1) if m else skill_md.parent.name
        if name != skill_md.parent.name:
            sys.exit(f"{skill_md}: name '{name}' must match its folder name '{skill_md.parent.name}'")
        if name in out:
            sys.exit(f"duplicate skill name '{name}': {out[name]} and {skill_md.parent}")
        out[name] = skill_md.parent
    return out


def to_cursor_agent(text):
    """Rewrite a Claude Code agent file's frontmatter for Cursor; the body is unchanged."""
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
    if not m:
        return text
    kept = []
    for line in m.group(1).splitlines():
        key = line.split(":", 1)[0].strip()
        if key in CURSOR_DROP_KEYS:
            continue
        if key == "model":
            line = "model: inherit"
        kept.append(line)
    if not any(l.startswith("model:") for l in kept):
        kept.append("model: inherit")
    return "---\n" + "\n".join(kept) + "\n---\n" + text[m.end():]


def _toml_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def to_codex_agent(text):
    """Claude Code agent Markdown -> Codex custom-agent TOML. The body becomes developer_instructions;
    model is left out so the agent inherits the session's model (Codex has no sonnet/opus)."""
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
    meta, body = {}, text
    if m:
        body = text[m.end():]
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip().strip('"')
    body = body.strip("\n") + "\n"
    # multi-line literal string keeps the Markdown byte-for-byte; fall back to an escaped string
    instr = f"'''\n{body}'''" if "'''" not in body else _toml_str(body)
    return (f"# Generated by scripts/install.py from the skill's agents/*.md — edit the source, not this file.\n"
            f"name = {_toml_str(meta.get('name', ''))}\n"
            f"description = {_toml_str(meta.get('description', ''))}\n"
            f"developer_instructions = {instr}\n")


# ------------------------------------------------------------------ tool dependencies
def find_cosign():
    """cosign on PATH under its plain name or its release name (cosign-windows-amd64 etc.).

    winget and the GitHub release binaries use the release name only; keep in sync with
    tl-security-audit/scripts/engine.py, which does the actual signature check.
    """
    names = ["cosign"] + [f"cosign-{o}-{a}" for o in ("windows", "linux", "darwin")
                          for a in ("amd64", "arm64")]
    return next((exe for exe in map(shutil.which, names) if exe), None)


def cosign_install_hint():
    if sys.platform == "win32":
        return "winget install Sigstore.Cosign"
    if sys.platform == "darwin":
        return "brew install cosign"
    return "see https://docs.sigstore.dev/cosign/system_config/installation/"


DOC_SKILLS = {"tl-architecture-doc": "optional", "tl-architecture-doc-enterprise": "optional", "tl-architecture-doc-feature-view": "optional", "tl-architecture-doc-observability": "optional", "tl-architecture-doc-security": "optional", "tl-development-status-doc": "optional"}
# needs: {skill: "required" | "optional"}. how: ("pip", package) | ("opengrep",) | None (manual only).
TOOLS = [
    {"id": "git", "label": "git", "needs": {"tl-code-commit": "required", "tl-code-review": "required",
                                           "tl-code-refactor": "optional", "tl-security-audit": "optional"},
     "why": "commits; review scope and blast radius; churn/hotspots and --diff scope",
     "check": lambda: bool(shutil.which("git")),
     "how": None, "manual": "install from https://git-scm.com"},
    {"id": "pyyaml", "label": "PyYAML", "needs": {"tl-security-audit": "required"},
     "why": "tl-security-audit rule packs are YAML — the scan phase stops without it",
     "check": lambda: importlib.util.find_spec("yaml") is not None,
     "how": ("pip", "pyyaml"), "manual": "{py} -m pip install pyyaml"},
    {"id": "lizard", "label": "lizard", "needs": {"tl-code-refactor": "optional"},
     "why": "per-function complexity (CCN) for more accurate hotspots",
     "check": lambda: importlib.util.find_spec("lizard") is not None,
     "how": ("pip", "lizard"), "manual": "{py} -m pip install lizard"},
    {"id": "opengrep", "label": "OpenGrep", "needs": {"tl-security-audit": "optional"},
     "why": "taint dataflow analysis (source → sink); without it only single-line patterns run",
     "check": None, "how": ("opengrep",),
     "manual": "{py} <skills-dir>/tl-security-audit/scripts/engine.py install"},
    {"id": "cosign", "label": "cosign", "needs": {"tl-security-audit": "optional"},
     "why": "verifies the OpenGrep download's signature", "check": lambda: bool(find_cosign()),
     "how": None, "manual": cosign_install_hint()},
    {"id": "pip-audit", "label": "pip-audit", "needs": {"tl-security-audit": "optional"},
     "why": "known-vulnerability audit for Python dependencies",
     "check": lambda: bool(shutil.which("pip-audit")) or importlib.util.find_spec("pip_audit") is not None,
     "how": ("pip", "pip-audit"), "manual": "{py} -m pip install pip-audit"},
    {"id": "node", "label": "Node.js", "needs": {"session-report": "required", **DOC_SKILLS},
     "why": "runs the session analyzer and the lavish-axi live review", "check": lambda: bool(shutil.which("node")),
     "how": None, "manual": "install Node.js 18+ from https://nodejs.org"},
    {"id": "lavish-axi", "label": "lavish-axi", "needs": DOC_SKILLS,
     "why": "live in-browser review of the HTML docs (else `npx -y` downloads it on first use)",
     "check": lambda: bool(shutil.which("lavish-axi")),
     "how": ("npm", "lavish-axi"), "manual": "npm install -g lavish-axi"},
    {"id": "gh", "label": "GitHub CLI (gh)", "needs": {"tl-code-review": "optional"},
     "why": "PR metadata, CI status and posting review comments (GitLab: glab)",
     "check": lambda: bool(shutil.which("gh")),
     "how": None, "manual": "see https://cli.github.com"},
    {"id": "osv-scanner", "label": "osv-scanner", "needs": {"tl-security-audit": "optional"},
     "why": "known-vulnerability audit across ecosystems", "check": lambda: bool(shutil.which("osv-scanner")),
     "how": None, "manual": "see https://google.github.io/osv-scanner/installation/"},
]


def interactive():
    return sys.stdin.isatty() and sys.stdout.isatty()


def ask(question):
    """[y/N] — anything but an explicit yes is a no."""
    try:
        return input(f"{question} [y/N] ").strip().lower() in ("y", "yes", "c", "co", "có")
    except EOFError:
        return False


def pip_install(package):
    cmd = [sys.executable, "-m", "pip", "install"]
    if sys.prefix == sys.base_prefix:  # not in a virtualenv: install for this user only
        cmd.append("--user")
    cmd.append(package)
    print("  $", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        return True
    err = (r.stderr or r.stdout).strip().splitlines()
    print("  failed:", *err[-3:], sep="\n    ")
    if "externally-managed" in (r.stderr or ""):
        print("  this Python is managed by the OS — create a virtualenv (python3 -m venv .venv) and "
              "install there, or use pipx. The installer never uses --break-system-packages.")
    return False


def npm_install(package):
    npm = shutil.which("npm")
    if not npm:
        print("  npm not found — install Node.js first")
        return False
    cmd = [npm, "install", "-g", package]
    print("  $", " ".join(cmd))
    return subprocess.run(cmd).returncode == 0


def opengrep_status(engine_py):
    return subprocess.run([sys.executable, str(engine_py), "status"], capture_output=True, text=True).returncode == 0


def opengrep_install(engine_py):
    args = [sys.executable, str(engine_py), "install"]
    if not find_cosign():
        print("  cosign is not installed, so the downloaded OpenGrep binary's signature cannot be verified.")
        if not ask("  Download and run OpenGrep WITHOUT signature verification?"):
            print("  skipped — install cosign, then re-run the installer (or engine.py install)")
            return False
        args.append("--allow-unverified")
    print("  $", " ".join(args))
    return subprocess.run(args).returncode == 0


def check_tools(wanted, skills_dir, available, mode):
    """Report the tools the selected skills use; offer to install missing ones (asking each time)."""
    py = Path(sys.executable).name
    engine_py = (skills_dir / "tl-security-audit" / "scripts" / "engine.py")
    if not engine_py.exists() and "tl-security-audit" in available:
        engine_py = available["tl-security-audit"] / "scripts" / "engine.py"
    relevant = [t for t in TOOLS if any(s in t["needs"] for s in wanted)]
    if not relevant:
        return
    print(f"\ntools used by the selected skills (checked with {sys.executable}):")
    if sys.version_info < (3, 9):
        print(f"  ! Python {sys.version.split()[0]} — the skills' scripts need Python 3.9+")
    missing = []
    for t in relevant:
        ok = opengrep_status(engine_py) if t["id"] == "opengrep" else t["check"]()
        req = [s for s in wanted if t["needs"].get(s) == "required"]
        opt = [s for s in wanted if t["needs"].get(s) == "optional"]
        need = "required" if req else "optional"
        users = "; ".join(x for x in (f"required by {', '.join(req)}" if req else "",
                                       f"optional for {', '.join(opt)}" if opt else "") if x)
        print(f"  {'ok ' if ok else 'MISSING'} {t['label']:<12} ({users}) — {t['why']}")
        if not ok:
            missing.append((t, need))
    if not missing:
        return
    can_ask = mode == "ask" and interactive()
    if mode == "ask" and not can_ask:
        print("\nno interactive terminal — nothing installed. To install the missing tools yourself:")
    elif mode == "check":
        print("\nnothing installed (--deps check). To install the missing tools yourself:")
    for t, need in missing:
        cmd = t["manual"].format(py=py).replace("<skills-dir>/tl-security-audit/scripts/engine.py", str(engine_py))
        if not can_ask or t["how"] is None:
            print(f"  {t['label']}: {cmd}")
            continue
        print()
        if not ask(f"Install {t['label']} ({need}, {t['why']})?"):
            print(f"  skipped — later: {cmd}")
            continue
        kind = t["how"][0]
        ok = (pip_install(t["how"][1]) if kind == "pip" else npm_install(t["how"][1]) if kind == "npm"
              else opengrep_install(engine_py))
        print(f"  {t['label']}: {'installed' if ok else 'not installed — ' + cmd}")
    if any(need == "required" for _, need in missing):
        print("\nnote: a skill with a missing REQUIRED tool will stop at the step that needs it; the skill "
              "itself also asks before installing anything.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=sorted(TARGETS) + ["all"], required=True,
                    help="claude, cursor, codex, or all three")
    ap.add_argument("--scope", choices=["user", "project"], default="user",
                    help="user: ~/.<tool>/  project: <project>/.<tool>/")
    ap.add_argument("--project", default=".", help="project root for --scope project")
    ap.add_argument("--skills", help="comma-separated skill names (default: all)")
    ap.add_argument("--no-agents", action="store_true", help="do not install sub-agent definitions")
    ap.add_argument("--force", action="store_true", help="overwrite files that differ")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--deps", choices=["ask", "check", "skip"], default="ask",
                    help="tools the skills use: ask before installing each missing one (default), "
                         "only report (check), or do nothing (skip)")
    a = ap.parse_args()

    available = find_skills()
    requested = [s.strip() for s in a.skills.split(",")] if a.skills else list(available)
    unknown = [s for s in requested if s not in available]
    if unknown:
        sys.exit(f"unknown skill(s): {', '.join(unknown)}. Available: {', '.join(available)}")
    targets = sorted(TARGETS) if a.target == "all" else [a.target]
    all_wanted = set()
    for target in targets:
        all_wanted |= set(install_target(a, target, requested, available))
    if a.deps != "skip":
        first_dir = (Path.home() if a.scope == "user" else Path(a.project).resolve()) / TARGETS[targets[0]]["skills"]
        check_tools([s for s in requested if s in all_wanted], first_dir, available,
                    "check" if a.dry_run else a.deps)
    if not a.dry_run:
        print("\nrestart the tool (or open a new chat/session) so it picks up new skills and agents")


def install_target(a, target, requested, available):
    base = Path.home() if a.scope == "user" else Path(a.project).resolve()
    skills_dir = base / TARGETS[target]["skills"]
    agents_dir = base / TARGETS[target]["agents"]
    print(f"\n[{target}]")
    wanted = []
    for s in requested:
        only = PLATFORM_ONLY.get(s)
        if only and target not in only[0]:
            if a.skills:  # only mention it when the user asked for it explicitly
                print(f"  skipped {s}: {'/'.join(sorted(only[0]))} only — {only[1]}")
            continue
        wanted.append(s)

    conflicts, n_files, n_agents = [], 0, 0
    for name in wanted:
        src_dir = available[name]
        dst_dir = skills_dir / name
        # files of the skill itself (including agents/, so the skill stays self-contained)
        for src in sorted(p for p in src_dir.rglob("*") if p.is_file()):
            rel = src.relative_to(src_dir)
            if any(part in ("__pycache__", ".refactor-run") for part in rel.parts) or src.suffix == ".pyc":
                continue
            if str(rel) in REPO_ONLY:
                continue
            dst = dst_dir / rel
            if dst.exists():
                if filecmp.cmp(src, dst, shallow=False):
                    continue  # already up to date
                if not a.force:
                    conflicts.append(dst)
                    continue
            n_files += 1
            if not a.dry_run:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        # sub-agent definitions -> the tool's agents folder
        if a.no_agents:
            continue
        for agent in sorted((src_dir / "agents").glob("*.md")):
            text = agent.read_text(encoding="utf-8")
            dst = agents_dir / agent.name
            if target == "cursor":
                text = to_cursor_agent(text)
            elif target == "codex":
                text = to_codex_agent(text)
                dst = agents_dir / (agent.stem + ".toml")
            if dst.exists():
                if dst.read_text(encoding="utf-8") == text:
                    continue  # already up to date
                if not a.force:
                    conflicts.append(dst)
                    continue
            n_agents += 1
            if not a.dry_run:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(text, encoding="utf-8", newline="\n")

    verb = "would install" if a.dry_run else "installed"
    print(f"  {verb} {len(wanted)} skill(s) ({n_files} files) -> {skills_dir}")
    if not a.no_agents:
        note = {"cursor": " (frontmatter converted for Cursor: model: inherit, tools/skills removed)",
                "codex": " (converted to Codex custom-agent TOML)"}.get(target, "")
        print(f"  {verb} {n_agents} sub-agent file(s) -> {agents_dir}" + (note if n_agents else ""))
    if conflicts:
        print(f"  skipped {len(conflicts)} existing file(s) that differ (re-run with --force to overwrite):")
        for c in conflicts[:20]:
            print("    ", c)
    return wanted


if __name__ == "__main__":
    main()
