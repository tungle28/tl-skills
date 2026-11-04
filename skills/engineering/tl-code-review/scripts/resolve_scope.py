#!/usr/bin/env python3
"""
resolve_scope.py — Phase 0 of the tl-code-review harness.

Turns a review target into a deterministic manifest (JSON) of files, changed
hunks, layer classification and a heuristic risk score. Everything downstream
(blast radius, sharding, reviewers) reads this manifest instead of re-deriving
scope, which keeps sub-agent prompts small and runs reproducible.

Modes
  uncommitted   working tree + index vs HEAD, plus untracked files (default)
  staged        index vs HEAD only (pre-commit review)
  changeset     --base/--head range (merge-base diff, like a PR) or --commit SHA
  feature       files matching --keywords (content or path) and/or --paths
  layer         files matching --paths globs (e.g. "src/**/Controllers/**")
  full          every tracked source file

Each run writes into a new folder .code-review/runs/<YYYYMMDD-HHMMSS>-<label>/ (printed as
`RUN_DIR: <path>`) and makes it .code-review/latest; --run-dir reuses a given run folder and
--out writes the manifest to an exact path instead (its folder is then the run folder).

Usage
  python resolve_scope.py --mode uncommitted
  python resolve_scope.py --mode changeset --base origin/main --head HEAD
  python resolve_scope.py --mode changeset --commit a1b2c3d
  python resolve_scope.py --pr 123 --since-run latest                    # only the commits after that run's head
  python resolve_scope.py --pr https://github.com/org/repo/pull/123      # implies changeset
  python resolve_scope.py --pr 123 --remote origin                        # GitHub/GitLab PR/MR number
  python resolve_scope.py --mode feature --keywords "refund,chargeback" --paths "src/Payments/**"
  python resolve_scope.py --mode layer --paths "src/**/Repositories/**"
  python resolve_scope.py --mode full --exclude "legacy/**"
"""
import argparse
import atexit
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under `python -I`
import run_dir  # noqa: E402

# ---------------------------------------------------------------- config ----

LANG_BY_EXT = {
    ".cs": "csharp", ".csproj": "msbuild", ".sln": "msbuild", ".razor": "razor", ".cshtml": "razor",
    ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".vue": "vue",
    ".go": "go", ".py": "python", ".java": "java", ".kt": "kotlin", ".dart": "dart",
    ".rb": "ruby", ".php": "php", ".rs": "rust", ".swift": "swift",
    ".sql": "sql", ".sh": "shell", ".ps1": "powershell",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".xml": "xml", ".tf": "terraform",
    ".html": "html", ".css": "css", ".scss": "css", ".proto": "protobuf", ".graphql": "graphql",
}
SPECIAL_FILES = {"Dockerfile": "docker", "Makefile": "make", "Jenkinsfile": "groovy"}

DEFAULT_EXCLUDES = [
    "**/node_modules/**", "**/bin/**", "**/obj/**", "**/dist/**", "**/build/**", "**/out/**",
    "**/.next/**", "**/.nuxt/**", "**/coverage/**", "**/vendor/**", "**/.dart_tool/**",
    "**/*.min.js", "**/*.min.css", "**/*.map", "**/*.lock", "**/package-lock.json",
    "**/yarn.lock", "**/pnpm-lock.yaml", "**/go.sum", "**/*.Designer.cs", "**/*.g.cs",
    "**/*.generated.*", "**/*.pb.go", "**/*_pb2.py", "**/__snapshots__/**", "**/*.snap",
    "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif", "**/*.svg", "**/*.ico", "**/*.pdf",
    "**/*.woff*", "**/*.ttf", "**/*.zip", "**/*.dll", "**/*.exe",
    "**/.code-review/**",
]

# First matching rule wins; matched against the lower-cased path.
LAYER_RULES = [
    ("db-migration", r"(^|/)(migrations?|db/migrate|flyway|liquibase)(/|$)|\.sql$"),
    ("test",         r"(^|/)(tests?|__tests__|spec|specs|e2e|testing)(/|$)|\.(test|spec)\.[jt]sx?$|tests?\.cs$|_test\.(go|py|dart)$"),
    ("ci-infra",     r"(^|/)(\.github|\.gitlab|\.azure|azure-pipelines|deploy|deployment|k8s|kubernetes|helm|charts|terraform|infra)(/|$)|dockerfile|docker-compose|\.tf$"),
    ("config",       r"(^|/)(appsettings[^/]*\.json|\.env[^/]*|config|configs|settings)(/|$)?|\.(ya?ml|toml|ini)$"),
    ("api",          r"(^|/)(controllers?|endpoints?|routes?|handlers?|api|grpc|graphql|resolvers?)(/|$)|controller\.(cs|ts)$|\.controller\.ts$"),
    ("ui",           r"(^|/)(components?|pages?|views?|screens?|widgets?|hooks|layouts?|app/\(|ui)(/|$)|\.(tsx|jsx|vue|razor|cshtml)$"),
    ("infrastructure", r"(^|/)(repositor(y|ies)|infrastructure|persistence|data|dal|dbcontext|clients?|adapters?|gateways?|messaging|consumers?|producers?)(/|$)|repository\.(cs|ts|go)$|dbcontext\.cs$"),
    ("application",  r"(^|/)(services?|application|usecases?|use-cases|commands?|queries|features?|workers?|jobs?)(/|$)|service\.(cs|ts|go)$|\.service\.ts$"),
    ("domain",       r"(^|/)(domain|entities|entity|models?|aggregates?|valueobjects?|core)(/|$)"),
]

LAYER_WEIGHT = {
    "db-migration": 3.0, "api": 2.0, "infrastructure": 2.0, "application": 2.0, "domain": 2.0,
    "ci-infra": 1.5, "config": 1.5, "ui": 1.2, "other": 1.0, "test": 0.5,
}
# Path/content hints that raise the stakes regardless of layer.
SENSITIVE_PATH = re.compile(
    r"auth|login|token|jwt|oauth|permission|role|acl|crypto|secret|password|payment|payout|"
    r"refund|transfer|ledger|balance|wallet|invoice|billing|order|transaction|settlement|"
    r"tenant|admin|webhook|kyc|pii", re.I)


def sh(args, cwd, check=True):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        sys.exit(f"[resolve_scope] command failed: {' '.join(args)}\n{r.stderr.strip()}")
    return r.stdout


def rev(ref, root):
    """Commit sha of ref, or None."""
    return sh(["git", "rev-parse", "--verify", "-q", f"{ref}^{{commit}}"], root, check=False).strip() or None


def exclude_from_git(root, out):
    """Keep the artifact folder out of `git status` without touching a tracked file:
    add it to .git/info/exclude, which is local-only."""
    try:
        rel = out.resolve().relative_to(Path(root).resolve())
    except ValueError:
        return  # artifacts outside the repo — nothing to hide
    if len(rel.parts) < 2:
        return
    git_dir = sh(["git", "rev-parse", "--git-dir"], root, check=False).strip()
    if not git_dir:
        return
    entry = "/" + rel.parts[0] + "/"
    excl = Path(git_dir if os.path.isabs(git_dir) else os.path.join(root, git_dir)) / "info" / "exclude"
    lines = excl.read_text(encoding="utf-8").splitlines() if excl.exists() else []
    if entry not in lines:
        excl.parent.mkdir(parents=True, exist_ok=True)
        with open(excl, "a", encoding="utf-8") as fh:
            fh.write(("\n" if lines and lines[-1] else "") + entry + "\n")


def head_checkout(root, head_ref, art_dir):
    """Where the reviewed (NEW-side) version of the files is on disk.

    A changeset whose head isn't the checked-out commit (a branch, a PR ref, a single commit) gets a
    detached worktree at <artifacts>/head, so scripts and reviewers read the head version instead of
    whatever happens to be checked out. Reused when it already points at the right commit.
    """
    sha = sh(["git", "rev-parse", "--verify", "-q", f"{head_ref}^{{commit}}"], root, check=False).strip()
    if not sha or sha == sh(["git", "rev-parse", "HEAD"], root, check=False).strip():
        return root
    wt = Path(art_dir) / "head"
    if (wt / ".git").exists():
        if sh(["git", "rev-parse", "HEAD"], str(wt), check=False).strip() != sha:
            sh(["git", "checkout", "--quiet", "--detach", sha], str(wt))
    else:
        wt.parent.mkdir(parents=True, exist_ok=True)
        sh(["git", "worktree", "add", "--quiet", "--detach", str(wt), sha], root)
    print(f"[resolve_scope] head {head_ref} is not checked out: review files from worktree {wt} "
          f"(remove later with `git worktree remove {wt}`)")
    return str(wt)


def repo_root(start):
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=start,
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def glob_match(path, patterns):
    for p in patterns:
        if fnmatch.fnmatch(path, p) or fnmatch.fnmatch("/" + path, p):
            return True
        # allow "**/x/**" to also match top-level "x/..."
        if p.startswith("**/") and fnmatch.fnmatch(path, p[3:]):
            return True
    return False


def language_of(path):
    name = os.path.basename(path)
    if name in SPECIAL_FILES:
        return SPECIAL_FILES[name]
    return LANG_BY_EXT.get(Path(path).suffix.lower(), "other")


def layer_of(path):
    low = path.lower()
    for layer, rx in LAYER_RULES:
        if re.search(rx, low):
            return layer
    return "other"


def count_lines(abs_path):
    try:
        with open(abs_path, "rb") as f:
            data = f.read(4_000_000)
        if b"\x00" in data[:8000]:
            return -1  # binary
        return data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
    except OSError:
        return 0


HUNK_RX = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_hunks(diff_text):
    """Return {path: [[start, length], ...]} of NEW-side line ranges from a -U0 diff."""
    hunks, cur = {}, None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            p = line[4:].strip()
            cur = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
            if cur:
                hunks.setdefault(cur, [])
        elif line.startswith("@@") and cur:
            m = HUNK_RX.match(line)
            if m:
                start, length = int(m.group(1)), int(m.group(2) or 1)
                if length > 0:
                    hunks[cur].append([start, length])
    return hunks


def risk_score(path, layer, added, deleted, size_lines, is_diff):
    w = LAYER_WEIGHT.get(layer, 1.0)
    if SENSITIVE_PATH.search(path):
        w *= 1.6
    volume = (added + deleted) if is_diff else max(size_lines, 0) / 4
    # log-ish scaling so one giant file doesn't dwarf everything
    vol_factor = 1 + min(volume, 800) ** 0.5 / 6
    return round(w * vol_factor, 2)


PR_URL_RX = [
    ("github", re.compile(r"github\.com[/:]([^/]+)/([^/]+?)/pull/(\d+)")),
    ("gitlab", re.compile(r"gitlab[^/]*/(.+?)/([^/]+?)/-/merge_requests/(\d+)")),
    ("azure", re.compile(r"dev\.azure\.com/[^/]+/[^/]+/_git/([^/]+)/pullrequest/(\d+)")),
]


def resolve_pr(pr, remote, root, base_override):
    """Fetch a PR/MR into local refs and return (base_ref, head_ref, intent_lines).

    Order of preference: GitHub CLI metadata (title/body/base branch) -> provider
    pull refs fetched via plain git -> fail with an actionable message. Never
    checks out or modifies the working tree.
    """
    provider, number, repo_hint = None, None, None
    if pr.isdigit():
        number = pr
        url = sh(["git", "remote", "get-url", remote], root, check=False).strip()
        provider = "gitlab" if "gitlab" in url else "azure" if "dev.azure.com" in url or "visualstudio.com" in url else "github"
    else:
        for prov, rx in PR_URL_RX:
            m = rx.search(pr)
            if m:
                provider, number = prov, m.groups()[-1]
                repo_hint = m.groups()[-2]
                break
        if not number:
            sys.exit(f"[resolve_scope] unrecognised PR reference: {pr}")
        url = sh(["git", "remote", "get-url", remote], root, check=False).strip()
        if repo_hint and repo_hint.removesuffix(".git").lower() not in url.lower():
            print(f"[resolve_scope] warning: PR repo '{repo_hint}' does not match remote '{remote}' ({url}). "
                  "Clone the right repo or pass --remote.")

    intent, base_branch = [], base_override
    if provider == "github" and shutil.which("gh"):
        r = subprocess.run(["gh", "pr", "view", number, "--json", "title,body,baseRefName,headRefName,url"],
                           cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode == 0:
            meta = json.loads(r.stdout)
            base_branch = base_branch or meta.get("baseRefName")
            intent = [f"PR #{number}: {meta.get('title', '')}", ""] + (meta.get("body") or "").splitlines()[:40]
            if meta.get("headRefName"):
                intent.append(f"(head branch: {meta['headRefName']})")

    if not base_branch:  # remote default branch
        head = sh(["git", "symbolic-ref", "-q", f"refs/remotes/{remote}/HEAD"], root, check=False).strip()
        base_branch = head.rsplit("/", 1)[-1] if head else "main"

    pull_ref = {"github": f"pull/{number}/head", "gitlab": f"merge-requests/{number}/head",
                "azure": f"pull/{number}/merge"}[provider]
    local_ref = f"refs/tl-code-review/pr-{number}"
    for spec in (f"+{pull_ref}:{local_ref}", f"+refs/heads/{base_branch}:refs/remotes/{remote}/{base_branch}"):
        r = subprocess.run(["git", "fetch", "--quiet", remote, spec], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            sys.exit(f"[resolve_scope] git fetch {remote} {spec} failed: {r.stderr.strip()}\n"
                     "Check network/credentials, or review with --base/--head on a local branch.")
    base_ref = f"{remote}/{base_branch}"
    if not intent:
        intent = [f"PR #{number} ({provider})"] + sh(
            ["git", "log", "--format=%h %s", f"{base_ref}..{local_ref}"], root).strip().splitlines()
    return base_ref, local_ref, intent


TICKET_PATTERNS = [
    ("jira-like", re.compile(r"\b([A-Z][A-Z0-9]{1,9}-\d{1,6})\b")),      # Jira, Linear, YouTrack: ABC-123
    ("azure-boards", re.compile(r"\bAB#(\d+)\b")),                        # Azure Boards: AB#123
    ("github-issue", re.compile(r"(?:(?<=\s)|^)(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?|refs?|see)?\s*#(\d+)\b", re.I)),
]
# Tokens that look like ticket keys but are standards/encodings.
TICKET_STOP = re.compile(r"^(UTF|SHA|ISO|RFC|HTTP|TLS|SSL|MD|AES|RSA|CVE|X|COVID|PEP|ES|IE|OAUTH)-", re.I)


def extract_ticket_refs(texts):
    """Pull ticket references from branch name, commit messages and PR body.

    Deterministic so every run (and the eval harness) sees the same refs; the
    agent then resolves them through whatever tracker connector exists.
    """
    refs = {}
    for source, text in texts:
        if not text:
            continue
        for kind, rx in TICKET_PATTERNS:
            for m in rx.finditer(text):
                key = m.group(1)
                if kind == "jira-like" and TICKET_STOP.match(key):
                    continue
                if kind == "azure-boards":
                    key = f"AB#{key}"
                elif kind == "github-issue":
                    key = f"#{key}"
                r = refs.setdefault(key, {"key": key, "kind": kind, "found_in": []})
                if source not in r["found_in"]:
                    r["found_in"].append(source)
    return sorted(refs.values(), key=lambda r: (r["kind"], r["key"]))


def recommend_path(mode, files, stats):
    """Deterministic routing: 'fast' = single-pass inline review, 'harness' = full pipeline.

    The harness pays off when scope exceeds one context comfortably or when the
    change is risky enough that an independent verifier is worth its cost.
    """
    reasons = []
    is_diff = mode in ("uncommitted", "staged", "changeset")
    changed = stats["added"] + stats["deleted"]
    n = len(files)
    if mode == "full":
        return "harness", ["full-codebase scope"]
    if is_diff:
        if changed > 200:
            reasons.append(f"{changed} changed lines > 200")
        if n > 8:
            reasons.append(f"{n} files > 8")
    else:
        if stats["total_lines_in_scope"] > 1500:
            reasons.append(f"{stats['total_lines_in_scope']} lines in scope > 1500")
        if n > 8:
            reasons.append(f"{n} files > 8")
    if any(f["layer"] == "db-migration" for f in files) and n > 1:
        reasons.append("schema migration alongside code (deploy-ordering risk)")
    sens_changed = sum(f["added"] + f["deleted"] for f in files if f["sensitive"])
    if is_diff and sens_changed > 80:
        reasons.append(f"{sens_changed} changed lines in sensitive paths (auth/money)")
    if len({f["layer"] for f in files} - {"test", "config"}) >= 3:
        reasons.append("change spans >= 3 layers")
    return ("harness", reasons) if reasons else ("fast", ["small, contained scope"])


def since_run(a, root, base_dir):
    """--since-run: the base becomes the head an earlier run reviewed, so only later commits are in scope."""
    if a.mode != "changeset" or a.commit:
        sys.exit("[resolve_scope] --since-run needs a branch or PR changeset (--pr, or --base/--head)")
    prev = run_dir.latest(base_dir) if a.since_run == "latest" else Path(a.since_run)
    if not prev.is_absolute() and a.since_run != "latest":
        prev = Path(root) / prev
    try:
        pm = json.loads((prev / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        sys.exit(f"[resolve_scope] --since-run: no manifest.json in {prev}")
    old, new = pm.get("head_sha"), rev(a.head, root)
    if not old:
        sys.exit(f"[resolve_scope] --since-run: {prev.name} records no head_sha (made before runs did); "
                 "pass --base <the sha it reviewed> instead")
    if not new:
        sys.exit(f"[resolve_scope] --since-run: head {a.head} is not a commit")
    if old == new:
        sys.exit(f"[resolve_scope] nothing new since {prev.name}: it reviewed {old[:8]}, the head now. "
                 "Tell the user; review again from scratch only if they ask (without --since-run, or --depth quick)")
    if subprocess.run(["git", "merge-base", "--is-ancestor", old, new], cwd=root).returncode != 0:
        sys.exit(f"[resolve_scope] --since-run: {old[:8]} reviewed by {prev.name} is not an ancestor of {new[:8]} "
                 "(rebased or force-pushed): the diff since it would mix in other commits. Review the whole change instead")
    a.base = old
    return {"run": prev.name, "head_sha": old}


# ------------------------------------------------------------------ main ----

def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", default="uncommitted",
                    choices=["uncommitted", "staged", "changeset", "feature", "layer", "full"])
    ap.add_argument("--base", help="changeset: base ref (merge-base is used, like a PR)")
    ap.add_argument("--head", default="HEAD", help="changeset: head ref")
    ap.add_argument("--commit", help="changeset: review a single commit")
    ap.add_argument("--pr", help="PR/MR URL or number (GitHub, GitLab, Azure DevOps); implies changeset")
    ap.add_argument("--remote", default="origin", help="git remote used to fetch --pr refs")
    ap.add_argument("--paths", default="", help="comma-separated globs (feature/layer/full filter)")
    ap.add_argument("--keywords", default="", help="feature: comma-separated keywords (case-insensitive)")
    ap.add_argument("--include", default="", help="extra globs to force-include")
    ap.add_argument("--exclude", default="", help="extra globs to exclude")
    ap.add_argument("--max-files", type=int, default=400, help="safety cap; excess reported, not dropped silently")
    ap.add_argument("--repo", default=".", help="path inside the repository")
    ap.add_argument("--run-dir", help="write into this run folder instead of a new one")
    ap.add_argument("--label", help="run folder label (default: pr<n>, the head ref or the mode)")
    ap.add_argument("--since-run", help="changeset: review only the commits after the head an earlier run reviewed "
                                         "(its run folder, or `latest`)")
    ap.add_argument("--out", help="exact manifest path (legacy; its folder becomes the run folder)")
    a = ap.parse_args()

    root = repo_root(a.repo)
    if not root:
        sys.exit("[resolve_scope] not a git repository — diff modes need git. "
                 "For a plain folder use --mode full/layer after `git init`, or review files directly.")

    split = lambda s: [x.strip() for x in s.split(",") if x.strip()]
    paths, keywords = split(a.paths), split(a.keywords)
    excludes = DEFAULT_EXCLUDES + split(a.exclude)
    includes = split(a.include)

    pr_intent = None
    review_root = root  # where the NEW-side files are read from (see head_checkout)
    if a.pr:
        a.mode = "changeset"
        a.base, a.head, pr_intent = resolve_pr(a.pr, a.remote, root, a.base)
    base_dir = Path(root) / run_dir.BASE
    since = since_run(a, root, base_dir) if a.since_run else None
    if a.out:
        out = Path(a.out if os.path.isabs(a.out) else os.path.join(root, a.out))
    elif a.run_dir:
        out = Path(a.run_dir if os.path.isabs(a.run_dir) else os.path.join(root, a.run_dir)) / "manifest.json"
    else:
        num = re.search(r"(\d+)/*$", a.pr) if a.pr else None
        label = a.label or (f"pr{num.group(1)}" if num else f"commit-{a.commit[:8]}" if a.commit
                            else a.head if a.mode == "changeset" else a.mode) + ("-since" if since else "")
        out = run_dir.new_run(base_dir, label) / "manifest.json"
        # a run that stops before its manifest is written (bad ref, no files…) leaves no folder behind
        atexit.register(lambda: out.exists() or run_dir.discard(out.parent, root))
    is_diff = a.mode in ("uncommitted", "staged", "changeset")
    status_map, numstat, hunks, intent = {}, {}, {}, []
    base_ref = head_ref = None

    if is_diff:
        has_head = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=root,
                                  capture_output=True).returncode == 0
        if a.mode == "uncommitted":
            rng = ["HEAD"] if has_head else ["--cached"]
            base_ref, head_ref = ("HEAD" if has_head else "(empty)"), "WORKTREE"
        elif a.mode == "staged":
            rng = ["--cached"]
            base_ref, head_ref = "HEAD", "INDEX"
        else:
            if a.commit:
                rng = [f"{a.commit}^!"]
                base_ref, head_ref = f"{a.commit}^", a.commit
                intent = sh(["git", "log", "-1", "--format=%h %s%n%n%b", a.commit], root).strip().splitlines()
            else:
                if not a.base:
                    sys.exit("[resolve_scope] changeset mode needs --base (e.g. origin/main) or --commit")
                rng = [f"{a.base}...{a.head}"]
                base_ref, head_ref = a.base, a.head
                intent = pr_intent or sh(["git", "log", "--format=%h %s", f"{a.base}..{a.head}"], root).strip().splitlines()
                if since:  # what the change claims is the PR's; what is new is these commits
                    intent = ([f"(re-review since run {since['run']}, which reviewed {since['head_sha'][:8]}: only these commits)"]
                              + sh(["git", "log", "--format=%h %s", f"{a.base}..{a.head}"], root).strip().splitlines()
                              + ([""] + pr_intent if pr_intent else []))

        for line in sh(["git", "diff", "--name-status", "-M"] + rng, root).splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                st = parts[0][0]
                path = parts[-1]
                status_map[path] = {"status": st, "old_path": parts[1] if st == "R" else None}
        for line in sh(["git", "diff", "--numstat", "-M"] + rng, root).splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                ad, de, p = parts
                if "=>" in p:  # rename notation a/{x => y}/b
                    p = re.sub(r"\{[^}]*=> ([^}]*)\}", r"\1", p).replace("//", "/")
                numstat[p] = (int(ad) if ad.isdigit() else 0, int(de) if de.isdigit() else 0)
        hunks = parse_hunks(sh(["git", "diff", "-U0", "-M"] + rng, root))
        if a.mode == "changeset":
            review_root = head_checkout(root, head_ref, out.parent)

        if a.mode == "uncommitted":
            for p in sh(["git", "ls-files", "--others", "--exclude-standard"], root).splitlines():
                n = count_lines(os.path.join(root, p))
                if n >= 0:
                    status_map[p] = {"status": "?", "old_path": None}
                    numstat[p] = (n, 0)
                    hunks[p] = [[1, n]] if n else []
        candidates = list(status_map.keys())
    else:
        candidates = sh(["git", "ls-files"], root).splitlines()
        if a.mode in ("layer", "feature") and not paths and not keywords:
            sys.exit(f"[resolve_scope] --mode {a.mode} needs --paths and/or --keywords")

    keyword_hits = {}
    if a.mode == "feature" and keywords:
        for kw in keywords:
            r = subprocess.run(["git", "grep", "-l", "-i", "-I", "-F", kw], cwd=root,
                               capture_output=True, text=True, encoding="utf-8", errors="replace")
            for p in r.stdout.splitlines():
                keyword_hits.setdefault(p, set()).add(kw)
            for p in candidates:  # path/name match
                if kw.lower() in p.lower():
                    keyword_hits.setdefault(p, set()).add(kw)

    files, excluded = [], []
    for p in sorted(set(candidates)):
        forced = glob_match(p, includes)
        if not forced and glob_match(p, excludes):
            excluded.append(p)
            continue
        if not is_diff:
            if a.mode == "feature":
                if p not in keyword_hits and not (paths and glob_match(p, paths)):
                    continue
                if keywords and paths and p not in keyword_hits and not forced:
                    continue  # both given: path glob narrows keyword hits
            elif paths and not glob_match(p, paths) and not forced:
                continue
        elif paths and not glob_match(p, paths) and not forced:
            continue

        st = status_map.get(p, {}).get("status", "T")  # T = tracked, not a diff
        abs_p = os.path.join(review_root, p)
        size = 0 if st == "D" else count_lines(abs_p)
        if size < 0:
            excluded.append(p)
            continue
        ad, de = numstat.get(p, (0, 0))
        layer = layer_of(p)
        entry = {
            "path": p,
            "status": st,
            "language": language_of(p),
            "layer": layer,
            "size_lines": size,
            "added": ad,
            "deleted": de,
            "hunks": hunks.get(p, []) if is_diff else [],
            "sensitive": bool(SENSITIVE_PATH.search(p)),
            "risk": risk_score(p, layer, ad, de, size, is_diff),
        }
        old = status_map.get(p, {}).get("old_path")
        if old:
            entry["old_path"] = old
        if keyword_hits.get(p):
            entry["keyword_hits"] = sorted(keyword_hits[p])
        files.append(entry)

    files.sort(key=lambda f: -f["risk"])
    truncated = []
    if len(files) > a.max_files:
        truncated = [f["path"] for f in files[a.max_files:]]
        files = files[: a.max_files]

    langs, layers = {}, {}
    for f in files:
        langs[f["language"]] = langs.get(f["language"], 0) + 1
        layers[f["layer"]] = layers.get(f["layer"], 0) + 1

    stats_pre = {"added": sum(f["added"] for f in files), "deleted": sum(f["deleted"] for f in files),
                 "total_lines_in_scope": sum(max(f["size_lines"], 0) for f in files)}
    path_rec, path_reasons = recommend_path(a.mode, files, stats_pre)
    branch = ""
    if is_diff and not a.pr:
        ref = a.head if (a.mode == "changeset" and not a.commit) else "HEAD"
        branch = sh(["git", "rev-parse", "--abbrev-ref", ref], root, check=False).strip()
        if branch == "HEAD":
            branch = ""
    ticket_refs = extract_ticket_refs([("branch", branch)] + [("intent", "\n".join(intent))])
    if a.pr:  # the PR's own number is not a linked issue
        own = re.search(r"(\d+)$", a.pr.rstrip("/"))
        ticket_refs = [r for r in ticket_refs if not (own and r["key"] == f"#{own.group(1)}")]
    manifest = {
        "mode": a.mode,
        "pr": a.pr,
        "recommended_path": path_rec,
        "recommended_path_reasons": path_reasons,
        "repo_root": root,
        "review_root": review_root,
        "base": base_ref,
        "head": head_ref,
        # the commits behind the refs, so compare_runs.py can tell whether two runs saw the same code
        "base_sha": rev(base_ref, root) if a.mode == "changeset" else None,
        "head_sha": rev(head_ref, root) if a.mode == "changeset" else None,
        "filters": {"paths": paths, "keywords": keywords, "include": includes, "exclude": split(a.exclude)},
        "intent": intent,  # commit messages / PR body: what the change CLAIMS to do
        "branch": branch,
        "ticket_refs": ticket_refs,  # resolve via tracker connector in Phase 1d
        "since_run": since,  # an incremental re-review: findings outside these commits are not this run's to report
        "stats": {
            "files": len(files),
            "added": sum(f["added"] for f in files),
            "deleted": sum(f["deleted"] for f in files),
            "total_lines_in_scope": sum(max(f["size_lines"], 0) for f in files),
            "languages": langs,
            "layers": layers,
            "tests_touched": layers.get("test", 0) > 0,
        },
        "files": files,
        "excluded": excluded,
        "truncated": truncated,
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    exclude_from_git(root, out)
    run_dir.set_latest(base_dir, out.parent)

    s = manifest["stats"]
    print(f"[resolve_scope] mode={a.mode} files={s['files']} +{s['added']}/-{s['deleted']} "
          f"lines_in_scope={s['total_lines_in_scope']} excluded={len(excluded)} truncated={len(truncated)}")
    print(f"[resolve_scope] layers={s['layers']} languages={s['languages']}")
    if is_diff and not s["tests_touched"] and any(f["layer"] not in ("test", "config", "ci-infra") for f in files):
        print("[resolve_scope] note: production code changed but no test files touched")
    if ticket_refs:
        print(f"[resolve_scope] ticket refs: {', '.join(r['key'] for r in ticket_refs)}")
    print(f"[resolve_scope] recommended path: {path_rec.upper()} ({'; '.join(path_reasons)})")
    print(f"[resolve_scope] manifest -> {out}")
    print(f"RUN_DIR: {out.parent}")


if __name__ == "__main__":
    main()
