# TL Skills

Agent skills for coding agents, in the open `SKILL.md` format (a folder with a `SKILL.md` file —
YAML frontmatter `name` + `description`, then Markdown instructions — plus optional `scripts/`,
`references/` and `agents/`). Every skill works in **Claude Code**, **Cursor** and **OpenAI Codex**.

## Skills

| Skill | What it does | Claude Code | Cursor | Codex |
|---|---|:-:|:-:|:-:|
| [`tl-code-review`](skills/engineering/tl-code-review/) | Code review of a snippet, diff, PR, feature, layer or whole repo: fast single pass for small diffs, otherwise scripted scope and blast radius → parallel reviewers → verifier → verdict; optional CI/ticket context and confirmed posting to the PR. [How it works →](skills/engineering/tl-code-review/WORKFLOW.md) | ✅ | ✅ | ✅ |
| [`tl-security-audit`](skills/engineering/tl-security-audit/) | Security audit of a repo, module or PR — from secrets and injection to access control and business logic. Remembers false positives and accepted risks you approve, and compares each report with the previous run. [How it works →](skills/engineering/tl-security-audit/WORKFLOW.md) | ✅ | ✅ | ✅ |
| [`tl-goal-griller`](skills/productivity/tl-goal-griller/) | Interviews you one question at a time (with a recommended answer each) until a vague idea becomes a verifiable goal spec for a coding agent: outcome, proof, scope, context, validation loop, and when to stop or pause. Platform-neutral; with "just write it" it drafts at once and marks guesses as `[ASSUMPTION]`. | ✅ | ✅ | ✅ |
| [`tl-skill-eval`](skills/tl-skill-eval/) | Evidence-backed scorecard for a skill: lint (limits, load cost, duplication across a skill family), trigger precision/recall with near misses, quality vs baseline, and seeded-defect metrics for audit skills. Uses `skill-creator` to run evals; trigger and baseline runs need Claude Code, the lint and metrics scripts run anywhere. [How it works →](skills/tl-skill-eval/WORKFLOW.md) | ✅ | ✅ | ✅ |

Skills with a **How it works** link ship a `WORKFLOW.md`: a user guide with the phases, agents, gates
and outputs. Next to it, `WORKFLOW.html` is the same guide rendered with its diagrams, for reading in a
browser. Agents don't load either file, and the installer doesn't copy them.

Skills reply in the language you write in.

## Install

Requires Python 3.9+ for the installer and the scripted skills. On Windows use `python` or `py -3`
where this README says `python3`.

### Without cloning

One command downloads the release archive to a temp folder, runs the installer and deletes the
folder. No git needed.

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/tungle28/tl-skills/main/scripts/install.sh | sh -s -- --target claude
```
```powershell
# Windows PowerShell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/tungle28/tl-skills/main/scripts/install.ps1))) -Target claude
```

It takes the same options as `install.py` below (`--target cursor`, `--skills tl-goal-griller`,
`--scope project --project ../my-app`, `--dry-run` …; in PowerShell `-Target`, `-Skills`, `-DryRun` …).
It installs the latest release; add `--version v0.4.0` (PowerShell: `-Version v0.4.0`) to pin one.
Read the script first if you prefer: open the same URL in a browser.

`npx skills add tungle28/tl-skills --skill <name>` ([skills CLI](https://github.com/vercel-labs/skills))
also works, but it copies only the skill folder. `tl-code-review`, `tl-security-audit` and
`tl-skill-eval` ship sub-agents that it does not install, so use the command above for those.

### From a clone

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

Existing files that differ are never overwritten without `--force`. To update, run the no-clone
command again with `--force` (`-Force`), or `git pull` and run the installer again with `--force`.

## Versions

Each release is a tag (`v0.1.0`, …). To pin a version: `--version v0.1.0` with the no-clone command,
or `git checkout v0.1.0` before installing from a clone.

This repository is published from a separate development repository, one snapshot per release, so
pull requests here are not merged directly — open an issue instead.
