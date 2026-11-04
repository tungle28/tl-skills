#!/usr/bin/env python3
"""
run_static_checks.py — Phase 1c (optional) of the tl-code-review harness.

Let deterministic tools catch what they are good at (types, lint, formatting,
failing tests) so reviewer agents spend tokens on judgment instead. The script
DETECTS the project's own toolchain and, only with --run, executes it with a
timeout. It never installs anything and never modifies files.

Output: $RUN/static.json  -> {tool: {cmd, exit_code, output_tail}}
Reviewers treat these results as signals: a finding already reported by a
linter should not be re-reported by an agent (it goes in the "Tooling" section).

Usage
  python run_static_checks.py --manifest $RUN/manifest.json            # detect only (dry run)
  python run_static_checks.py --manifest $RUN/manifest.json --run      # execute
  python run_static_checks.py ... --run --with-tests                            # also run test suites (slow)
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under `python -I`
import run_dir  # noqa: E402


def exists(root, *names):
    return any((Path(root) / n).exists() for n in names)


def find(root, pattern, limit=3):
    out = []
    for p in Path(root).rglob(pattern):
        if any(x in p.parts for x in ("node_modules", "bin", "obj", ".git")):
            continue
        out.append(p)
        if len(out) >= limit:
            break
    return out


def detect(root, files, with_tests):
    checks = []
    js = [f for f in files if f.endswith((".ts", ".tsx", ".js", ".jsx", ".vue", ".mjs", ".cjs"))]
    cs = [f for f in files if f.endswith(".cs")]
    py = [f for f in files if f.endswith(".py")]
    go = [f for f in files if f.endswith(".go")]
    dart = [f for f in files if f.endswith(".dart")]

    if exists(root, "package.json"):
        runner = "pnpm" if exists(root, "pnpm-lock.yaml") else "yarn" if exists(root, "yarn.lock") else "npx"
        pre = [runner] if runner == "npx" else [runner, "exec"]
        if js and exists(root, "node_modules/.bin/eslint"):
            checks.append(("eslint", pre + ["eslint", "--no-color", "--format", "unix"] + js[:200]))
        if exists(root, "tsconfig.json", "node_modules/.bin/tsc") and exists(root, "node_modules/.bin/tsc"):
            checks.append(("tsc", pre + ["tsc", "--noEmit", "--pretty", "false"]))
        if with_tests:
            checks.append(("npm-test", ["npm", "test", "--silent"]))

    slns = find(root, "*.sln", 1) or find(root, "*.csproj", 1)
    if cs and slns and shutil.which("dotnet"):
        target = str(slns[0].relative_to(root))
        checks.append(("dotnet-build", ["dotnet", "build", target, "-nologo", "-clp:ErrorsOnly;NoSummary"]))
        checks.append(("dotnet-format", ["dotnet", "format", target, "--verify-no-changes", "--no-restore",
                                         "--include"] + cs[:200]))
        if with_tests:
            checks.append(("dotnet-test", ["dotnet", "test", target, "--no-build", "-nologo"]))

    if py:
        if shutil.which("ruff"):
            checks.append(("ruff", ["ruff", "check", "--output-format", "concise"] + py[:200]))
        if shutil.which("mypy") and exists(root, "mypy.ini", "pyproject.toml", "setup.cfg"):
            checks.append(("mypy", ["mypy", "--no-error-summary"] + py[:200]))
        if with_tests and shutil.which("pytest"):
            checks.append(("pytest", ["pytest", "-q", "-x"]))

    if go and exists(root, "go.mod") and shutil.which("go"):
        pkgs = sorted({"./" + os.path.dirname(f) if os.path.dirname(f) else "." for f in go})
        checks.append(("go-vet", ["go", "vet"] + pkgs))
        if shutil.which("staticcheck"):
            checks.append(("staticcheck", ["staticcheck"] + pkgs))
        if with_tests:
            checks.append(("go-test", ["go", "test"] + pkgs))

    if dart and shutil.which("dart"):
        checks.append(("dart-analyze", ["dart", "analyze"] + dart[:200]))

    return checks


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", help="default: manifest.json of the latest run")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--with-tests", action="store_true")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--out", help="default: static.json next to the manifest")
    a = ap.parse_args()
    a.manifest = a.manifest or str(run_dir.latest() / "manifest.json")
    a.out = a.out or str(Path(a.manifest).parent / "static.json")

    m = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    root = m.get("review_root") or m["repo_root"]  # lint the head version, not whatever is checked out
    files = [f["path"] for f in m["files"] if f["status"] != "D"]
    checks = detect(root, files, a.with_tests)

    result = {"ran": a.run, "checks": {}}
    for name, cmd in checks:
        entry = {"cmd": " ".join(cmd[:8]) + (" ..." if len(cmd) > 8 else "")}
        if a.run:
            try:
                r = subprocess.run([shutil.which(cmd[0]) or cmd[0]] + cmd[1:], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=a.timeout)
                out = (r.stdout + "\n" + r.stderr).strip().splitlines()
                entry.update(exit_code=r.returncode, output_tail="\n".join(out[-120:]))
            except subprocess.TimeoutExpired:
                entry.update(exit_code=None, output_tail=f"timeout after {a.timeout}s")
            except FileNotFoundError as e:
                entry.update(exit_code=None, output_tail=f"not runnable: {e}")
        result["checks"][name] = entry

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    if not checks:
        print("[static] no project toolchain detected for the files in scope (agents will review without tool signals)")
    for name, e in result["checks"].items():
        status = "detected" if not a.run else ("ok" if e.get("exit_code") == 0 else f"exit={e.get('exit_code')}")
        print(f"[static] {name:<14} {status:<10} {e['cmd']}")
    print(f"[static] -> {a.out}")


if __name__ == "__main__":
    main()
