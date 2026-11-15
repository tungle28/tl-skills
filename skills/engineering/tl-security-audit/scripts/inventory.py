#!/usr/bin/env python3
"""Phase 1 — inventory: source + config files, frameworks, lockfiles, scope, review shards.

The inventory (and the rule scan that follows) always covers the whole repository: scripts cost no
tokens, and a secret or a misconfiguration outside the review scope is still a real exposure.
Only the token-expensive review is restricted to the chosen scope.
"""
import argparse
import fnmatch
import json
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from common import (CONFIG_LANGS, EXCLUDE_DIRS, LOCKFILES, MIGRATION_DIRS, detect_lang,
                    is_generated, is_test_path, now_iso, vendor_root, write_json)

MAX_FILE_BYTES = 1_000_000

# Framework detection: dependency name (regex, case-insensitive) -> framework label.
FRAMEWORK_SIGNALS = {
    r"^@nestjs/core$": "nestjs", r"^express$": "express", r"^fastify$": "fastify",
    r"^next$": "nextjs", r"^react$": "react", r"^vue$": "vue", r"^nuxt$": "nuxt",
    r"^@angular/core$": "angular", r"^prisma$|^@prisma/client$": "prisma",
    r"^typeorm$": "typeorm", r"^sequelize$": "sequelize", r"^mongoose$": "mongoose",
    r"^jsonwebtoken$|^jose$": "jwt", r"^passport": "passport", r"^graphql$|^@apollo/server$": "graphql",
    r"^microsoft\.aspnetcore": "aspnetcore", r"^microsoft\.entityframeworkcore": "efcore",
    r"^dapper$": "dapper", r"^newtonsoft\.json$": "newtonsoft", r"^hangfire": "hangfire",
    r"^masstransit": "masstransit", r"^rabbitmq": "rabbitmq", r"^confluent\.kafka$|^kafkajs$": "kafka",
    r"^stackexchange\.redis$|^ioredis$|^redis$": "redis", r"^identityserver|^duende": "identityserver",
    r"^django$": "django", r"^flask$": "flask", r"^fastapi$": "fastapi", r"^sqlalchemy$": "sqlalchemy",
    r"^celery$": "celery",
    # Go (module paths from go.mod)
    r"^github\.com/gin-gonic/gin$": "gin", r"^github\.com/labstack/echo": "echo",
    r"^github\.com/go-chi/chi": "chi", r"^github\.com/gofiber/fiber": "fiber",
    r"^github\.com/gorilla/mux$": "gorilla", r"^gorm\.io/gorm$": "gorm",
    r"^github\.com/jackc/pgx": "pgx", r"^github\.com/jmoiron/sqlx$": "sqlx",
    r"^github\.com/golang-jwt/jwt": "jwt", r"^google\.golang\.org/grpc$": "grpc",
    # Nuxt ecosystem
    r"^nuxt-auth-utils$|^@sidebase/nuxt-auth$|^@nuxtjs/auth": "nuxt-auth", r"^h3$": "h3",
    # Flutter / Dart (pubspec.yaml)
    r"^flutter$": "flutter", r"^dio$": "dio", r"^webview_flutter$|^flutter_inappwebview$": "webview",
    r"^flutter_secure_storage$": "secure-storage", r"^shared_preferences$": "shared-preferences",
    r"^sqflite$|^drift$": "sqflite", r"^firebase_core$": "firebase", r"^local_auth$": "local-auth",
    r"^app_links$|^uni_links$|^firebase_dynamic_links$": "deep-links", r"^openai$|^anthropic$|^@anthropic-ai/sdk$|^langchain": "llm",
    # PHP (composer.json)
    r"^laravel/framework$|^laravel/lumen-framework$": "laravel",
    r"^symfony/framework-bundle$|^symfony/http-kernel$": "symfony",
}


def git_changed_ranges(root, base):
    """Changed line ranges (new side) vs merge-base(base, HEAD), incl. uncommitted edits."""
    try:
        mb = subprocess.run(["git", "merge-base", base, "HEAD"], cwd=root, capture_output=True,
                            text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise SystemExit(f"--diff: cannot resolve merge-base with '{base}' (git repo? branch name?)")
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root, capture_output=True,
                          text=True).stdout.strip()
    out = subprocess.run(["git", "diff", "-U0", "--relative", "--no-color", mb, "--", "."],
                         cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    ranges, cur = {}, None
    for line in out.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            cur = None if path == "/dev/null" else path[2:] if path.startswith("b/") else path
            if cur:
                ranges.setdefault(cur, [])
        elif line.startswith("@@") and cur:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            start, count = int(m.group(1)), int(m.group(2) or 1)
            if count:
                ranges[cur].append([start, start + count - 1])
    for u in subprocess.run(["git", "ls-files", "--others", "--exclude-standard"], cwd=root,
                            capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.split():
        ranges.setdefault(u, [[1, 10**9]])
    return {"merge_base": mb[:12], "head": head}, {k: v for k, v in ranges.items() if v}


def count_loc(path, lang):
    try:
        if lang == "key":
            return 1  # keys/certs: presence matters, content is not "code"
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = [l for l in text.splitlines() if l.strip()]
    if lines and lang not in CONFIG_LANGS and sum(len(l) for l in lines) / len(lines) > 300:
        return None  # minified / generated blob
    return len(lines)


def walk(root, extra_excludes, skipped=None):
    """Yield (path, rel). `skipped`, if given, collects what was left out for the report:
    {"dirs": set of excluded folder paths found, "glob_files": count of files matched by --exclude}."""
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        keep = []
        for d in dirnames:
            if d in EXCLUDE_DIRS or f"{rel_dir}/{d}".lstrip("./") in EXCLUDE_DIRS:
                if skipped is not None and d != ".git":
                    skipped["dirs"].add(d if rel_dir == "." else f"{rel_dir}/{d}")
            else:
                keep.append(d)
        dirnames[:] = keep
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, g) for g in extra_excludes):
                if skipped is not None:
                    skipped["glob_files"] += 1
                continue
            yield p, rel


def collapse_dirs(paths, limit=40):
    """Excluded folder paths for the report: one entry per name when a name repeats
    (`node_modules` x12 -> `**/node_modules (12)`), capped at `limit` entries."""
    by_name = defaultdict(list)
    for p in paths:
        by_name[p.rsplit("/", 1)[-1]].append(p)
    out = [v[0] if len(v) == 1 else f"**/{k} ({len(v)})" for k, v in sorted(by_name.items())]
    return out[:limit] + ([f"… +{len(out) - limit}"] if len(out) > limit else [])


def dep_names(root, lockfiles, files):
    """Best-effort dependency names from manifests, for framework detection only."""
    names = set()
    for f in files:
        rel, p = f["path"], root / f["path"]
        base = Path(rel).name.lower()
        try:
            if base in ("package.json", "composer.json"):
                d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                for k in ("dependencies", "devDependencies", "peerDependencies", "require", "require-dev"):
                    names.update((d.get(k) or {}).keys())
            elif base.endswith((".csproj", ".props")) or base == "packages.config":
                names.update(re.findall(r'(?:PackageReference|package)\s+(?:Include|id)="([^"]+)"',
                                        p.read_text(encoding="utf-8", errors="replace"), re.I))
            elif base == "go.mod":
                names.update(re.findall(r"^\s*(?:require\s+)?([\w.\-]+\.[a-z]{2,}/[\w.\-/]+)\s+v\d",
                                        p.read_text(encoding="utf-8", errors="replace"), re.M))
            elif base == "pubspec.yaml":
                text = p.read_text(encoding="utf-8", errors="replace")
                names.update(re.findall(r"^\s{2}([a-z_][a-z0-9_]*)\s*:", text, re.M))
                if re.search(r"sdk\s*:\s*flutter", text):
                    names.add("flutter")
            elif base in ("requirements.txt", "pyproject.toml", "pipfile"):
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    m = re.match(r'\s*"?([A-Za-z0-9_.\-]+)', line)
                    if m and not line.strip().startswith(("#", "[")):
                        names.add(m.group(1))
        except (OSError, ValueError):
            continue
    return names


def build_shards(files, max_loc, max_files):
    by_dir = defaultdict(list)
    for f in files:
        by_dir[str(Path(f["path"]).parent)].append(f)
    shards, cur = [], {"files": [], "loc": 0}

    def flush():
        if cur["files"]:
            shards.append({"files": [f["path"] for f in cur["files"]], "loc": cur["loc"],
                           "langs": sorted({f["lang"] for f in cur["files"]}),
                           "dirs": sorted({str(Path(f["path"]).parent) for f in cur["files"]})})
        cur["files"], cur["loc"] = [], 0

    for d in sorted(by_dir):  # neighbouring dirs tend to share a shard (cohesive context)
        group = sorted(by_dir[d], key=lambda f: f["path"])
        gloc = sum(f["loc"] for f in group)
        if cur["files"] and (cur["loc"] + gloc > max_loc or len(cur["files"]) + len(group) > max_files):
            flush()
        for f in group:
            if cur["files"] and (cur["loc"] + f["loc"] > max_loc or len(cur["files"]) >= max_files):
                flush()
            cur["files"].append(f)
            cur["loc"] += f["loc"]
    flush()
    for i, s in enumerate(shards, 1):  # provisional; the scan phase re-ranks by risk signals
        s["id"] = f"S{i:02d}"
        s["priority_rank"] = i
    return shards


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--max-shard-loc", type=int, default=3000)
    ap.add_argument("--max-shard-files", type=int, default=25)
    ap.add_argument("--include-tests", action="store_true", help="review test code too")
    ap.add_argument("--include-migrations", action="store_true", help="review migrations too")
    ap.add_argument("--include-vendor", action="store_true",
                    help="review vendored front-end assets (public/themes, app-assets, …) too")
    ap.add_argument("--exclude", action="append", default=[], help="glob on relative path")
    ap.add_argument("--only", action="append", default=[], help="glob; restricts REVIEW scope")
    ap.add_argument("--path", action="append", default=[], help="sub-folder to review (repeatable)")
    ap.add_argument("--diff", metavar="BASE", help="changeset scope: files changed vs merge-base(BASE)")
    ap.add_argument("--max-shards", type=int, default=0, help="review only the top-N shards")
    a = ap.parse_args()
    a.only += [p.rstrip("/") + "/*" for p in a.path]

    root = Path(a.root).resolve()
    is_git = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
                            capture_output=True).returncode == 0
    diff_refs, changed = None, {}
    if a.diff:
        if not is_git:
            raise SystemExit("--diff requires a git repository")
        diff_refs, changed = git_changed_ranges(root, a.diff)

    files, lockfiles, skipped, unknown, vendor_roots = [], [], 0, 0, set()
    left_out = {"dirs": set(), "glob_files": 0}
    for p, rel in walk(root, a.exclude, left_out):
        if p.name.lower() in LOCKFILES:
            lockfiles.append(rel)
            continue
        lang = detect_lang(rel)
        if not lang or is_generated(rel):
            unknown += 1
            continue
        loc = count_loc(p, lang)
        if loc is None:
            skipped += 1
            continue
        is_mig = any(part.lower() in MIGRATION_DIRS for part in Path(rel).parts[:-1])
        in_scope = ((not a.only or any(fnmatch.fnmatch(rel, g) for g in a.only))
                    and (not a.diff or rel in changed))
        f = {"path": rel, "lang": lang, "loc": loc, "is_test": is_test_path(rel),
             "is_migration": is_mig, "is_config": lang in CONFIG_LANGS, "in_scope": in_scope}
        vr = vendor_root(rel, lang)
        if vr:
            f["is_vendor"] = True
            vendor_roots.add(vr)
        if a.diff and rel in changed:
            f["changed_ranges"] = changed[rel]
        files.append(f)

    deps = dep_names(root, lockfiles, files)
    frameworks = sorted({fw for rx, fw in FRAMEWORK_SIGNALS.items()
                         for n in deps if re.search(rx, n, re.I)})

    langs = defaultdict(lambda: {"files": 0, "loc": 0})
    for f in files:
        langs[f["lang"]]["files"] += 1
        langs[f["lang"]]["loc"] += f["loc"]

    reviewable = [f for f in files if f["in_scope"] and f["lang"] != "key"
                  and (a.include_tests or not f["is_test"])
                  and (a.include_migrations or not f["is_migration"])
                  and (a.include_vendor or not f.get("is_vendor"))]
    shards = build_shards(reviewable, a.max_shard_loc, a.max_shard_files)
    scope = {"only": a.only, "diff_base": a.diff, "diff_refs": diff_refs,
             "max_shards": a.max_shards or None, "deferred_shards": [],
             "whole_repo": not (a.only or a.diff),
             "kind": "changeset" if a.diff else ("partial" if a.only else "full")}
    inv = {
        "root": str(root), "generated_at": now_iso(), "git": is_git, "scope": scope,
        "frameworks": frameworks, "lockfiles": sorted(lockfiles),
        "totals": {"files": len(files), "loc": sum(f["loc"] for f in files),
                   "config_files": sum(f["is_config"] for f in files),
                   "test_files": sum(f["is_test"] for f in files),
                   "in_scope_files": len(reviewable),
                   "reviewable_files": sum(len(s["files"]) for s in shards),
                   "reviewable_loc": sum(s["loc"] for s in shards),
                   "vendor_files": sum(1 for f in files if f.get("is_vendor")),
                   "skipped_large_or_minified": skipped, "unrecognized_files": unknown},
        # taint skips these (rules and secrets still scan them); review skips them unless --include-vendor
        "vendor_roots": sorted(vendor_roots), "include_vendor": a.include_vendor, "exclude_globs": a.exclude,
        # what the report lists under "Skipped": excluded folders actually present, --exclude hits, flags
        "excluded": {"dirs": collapse_dirs(left_out["dirs"]), "glob_files": left_out["glob_files"],
                     "include_tests": a.include_tests, "include_migrations": a.include_migrations},
        "languages": dict(langs), "files": files, "max_shards": a.max_shards,
    }
    write_json(Path(a.run_dir) / "inventory.json", inv)
    write_json(Path(a.run_dir) / "shards.json", shards)
    (Path(a.run_dir) / "shards_all.json").unlink(missing_ok=True)  # stale after a new inventory
    t = inv["totals"]
    print(f"files={t['files']} (config {t['config_files']}) loc={t['loc']} "
          f"reviewable={t['reviewable_files']} ({t['reviewable_loc']} loc) shards={len(shards)} git={is_git}")
    print("frameworks:", ", ".join(frameworks) or "none detected")
    print("lockfiles:", ", ".join(sorted(lockfiles)) or "none")
    if scope["kind"] == "changeset":
        print(f"scope: changeset vs {a.diff} (merge-base {diff_refs['merge_base']}, head {diff_refs['head']}), "
              f"{len(reviewable)} files")
    if vendor_roots:
        print(f"vendored assets: {t['vendor_files']} files under {len(vendor_roots)} dirs "
              f"({', '.join(sorted(vendor_roots)[:5])}{', …' if len(vendor_roots) > 5 else ''}) — "
              f"{'reviewed' if a.include_vendor else 'not reviewed (--include-vendor to review)'}, not taint-scanned")
    print("languages:", ", ".join(f"{k}:{v['files']}f" for k, v in
                                  sorted(langs.items(), key=lambda kv: -kv[1]['loc'])))


if __name__ == "__main__":
    main()
