# TL Skills

Agent skills for coding agents, in the open `SKILL.md` format (a folder with a `SKILL.md` file —
YAML frontmatter `name` + `description`, then Markdown instructions — plus optional `scripts/`,
`references/` and `agents/`). Every skill works in **Claude Code**, **Cursor** and **OpenAI Codex**.

## Skills

| Skill | What it does | Claude Code | Cursor | Codex |
|---|---|:-:|:-:|:-:|
| [`tl-code-review`](skills/engineering/tl-code-review/) | Code review of a snippet, diff, PR, feature, layer or whole repo: fast single pass for small diffs, otherwise scripted scope and blast radius → parallel reviewers → verifier → verdict; optional CI/ticket context and confirmed posting to the PR. [How it works →](skills/engineering/tl-code-review/WORKFLOW.md) | ✅ | ✅ | ✅ |
| [`tl-security-audit`](skills/engineering/tl-security-audit/) | Security audit of a repo, module or PR — from secrets and injection to access control and business logic. [How it works →](skills/engineering/tl-security-audit/WORKFLOW.md) | ✅ | ✅ | ✅ |
| [`tl-skill-eval`](skills/tl-skill-eval/) | Evidence-backed scorecard for a skill: lint (limits, load cost, duplication across a skill family), trigger precision/recall with near misses, quality vs baseline, and seeded-defect metrics for audit skills. Uses `skill-creator` to run evals; trigger and baseline runs need Claude Code, the lint and metrics scripts run anywhere. [How it works →](skills/tl-skill-eval/WORKFLOW.md) | ✅ | ✅ | ✅ |

Skills with a **How it works** link ship a `WORKFLOW.md`: a user guide with the phases, agents, gates
and outputs. Agents don't load it, and the installer doesn't copy it.

Skills reply in the language you write in.

## Install

Requires Python 3.9+ for the installer and the scripted skills. On Windows use `python` or `py -3`
where this README says `python3`.

```bash
git clone https://github.com/tungle28/tl-skills.git && cd tl-skills

python3 scripts/install.py --target claude   # Claude Code: ~/.claude/skills, ~/.claude/agents
python3 scripts/install.py --target cursor   # Cursor:      ~/.cursor/skills, ~/.cursor/agents
python3 scripts/install.py --target codex    # Codex:       ~/.agents/skills, ~/.codex/agents
python3 scripts/install.py --target all      # all three

# Only some skills, into one project, previewing first
python3 scripts/install.py --target claude --scope project --project ../my-app \
  --skills tl-code-review --dry-run
```

Launchers that find a working Python for you: `./scripts/install.sh` (macOS/Linux) and
`.\scripts\install.ps1` (Windows PowerShell), same flags as `install.py`.

Existing files that differ are never overwritten without `--force`. To update, `git pull` and run the
installer again with `--force`.

## Versions

Each release is a tag (`v0.1.0`, …). To pin a version: `git checkout v0.1.0` before installing.

This repository is published from a separate development repository, one snapshot per release, so
pull requests here are not merged directly — open an issue instead.
