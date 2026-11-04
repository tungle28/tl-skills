#!/usr/bin/env python3
"""Phase 3 — dependencies (OWASP A03:2025 Software Supply Chain Failures).

Two layers:
  1. Manifest hygiene, always (no network): missing lockfiles, floating versions, git/URL deps,
     extra package indexes (dependency confusion), install scripts.
  2. Known-vulnerability audit, when a tool is available: osv-scanner, npm audit, dotnet list
     package --vulnerable, pip-audit, govulncheck. A tool that is missing or fails is recorded as a
     coverage gap — never silently treated as "no vulnerabilities".
"""
import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

from common import read_json, write_json
from scan import load_suppressions, suppressed_by

SEV_MAP = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium",
           "low": "low", "info": "info", "unknown": "medium"}
TIMEOUT = 600


def run(cmd, cwd, timeout=TIMEOUT):
    try:
        # explicit UTF-8: the locale code page (cp1252 on Windows) cannot decode tool output
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return -1, "", str(e)


def static_finding(title, file, line, severity, message, fix, cwe="CWE-1104", rule="dep-hygiene"):
    return {"rule_id": rule, "type": "finding", "title": title, "file": file, "line": line,
            "snippet": "", "owasp": "A03", "cwe": cwe, "severity": severity, "confidence": "high",
            "message": message, "fix": fix, "source": "deps"}


def line_of(text, needle):
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def hygiene(root, files, lockfiles):
    out, ecos = [], set()
    lock_dirs = {str(Path(l).parent) for l in lockfiles}
    for f in files:
        rel, base = f["path"], Path(f["path"]).name.lower()
        d = str(Path(rel).parent)
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if base == "package.json" and "node_modules" not in rel:
            ecos.add("npm")
            try:
                pkg = json.loads(text)
            except ValueError:
                continue
            if (pkg.get("dependencies") or pkg.get("devDependencies")) and d not in lock_dirs \
                    and not pkg.get("workspaces") and not any(Path(l).parent in Path(d).parents for l in lockfiles):
                out.append(static_finding("No lockfile next to package.json", rel, 1, "medium",
                                          "Installs resolve versions at install time, so builds are not reproducible and a compromised new release is pulled in automatically.",
                                          "Commit package-lock.json / pnpm-lock.yaml / yarn.lock and install with `npm ci` in CI."))
            for sect in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, ver in (pkg.get(sect) or {}).items():
                    v = str(ver)
                    if v in ("*", "latest", "") or v.startswith(("x", ">")):
                        out.append(static_finding(f"Unbounded version for {name}", rel, line_of(text, f'"{name}"'),
                                                  "medium", f"`{name}: {v}` accepts any future release.",
                                                  "Pin a version range with an upper bound (or exact) and rely on the lockfile."))
                    elif re.match(r"(git\+|git:|github:|https?://|file:)", v):
                        out.append(static_finding(f"Dependency {name} installed from URL/git", rel,
                                                  line_of(text, f'"{name}"'), "low",
                                                  f"`{name}` comes from `{v[:60]}` — bypasses registry integrity checks and advisories.",
                                                  "Publish to (or mirror in) a registry you control, or pin to an immutable commit SHA."))
            for hook in ("preinstall", "install", "postinstall"):
                if hook in (pkg.get("scripts") or {}):
                    out.append(static_finding(f"`{hook}` script in package.json", rel, line_of(text, f'"{hook}"'),
                                              "info", "Install hooks run arbitrary code on every install (dev machines and CI).",
                                              "Confirm the hook is necessary; consider `--ignore-scripts` in CI for third-party packages.",
                                              cwe="CWE-829", rule="dep-install-script"))
        elif base.endswith(".csproj"):
            ecos.add("nuget")
            for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]*)")?', text):
                if m.group(2) and ("*" in m.group(2)):
                    out.append(static_finding(f"Floating NuGet version for {m.group(1)}", rel,
                                              text.count("\n", 0, m.start()) + 1, "medium",
                                              f"Version `{m.group(2)}` resolves to whatever is newest at restore time.",
                                              "Pin an exact version; enable `RestorePackagesWithLockFile` for reproducible restores."))
        elif base in ("requirements.txt", "requirements-dev.txt") or re.match(r"requirements.*\.txt$", base):
            ecos.add("pip")
            for i, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if s.startswith(("--extra-index-url", "--index-url", "-i ")):
                    out.append(static_finding("Custom / extra package index", rel, i, "medium",
                                              "With `--extra-index-url`, pip may pick a same-named package from the public index (dependency confusion).",
                                              "Use a single internal index that proxies PyPI, or pin hashes (`--require-hashes`).",
                                              cwe="CWE-427", rule="dep-confusion"))
                elif s and not s.startswith(("#", "-")) and "==" not in s and "@" not in s:
                    out.append(static_finding(f"Unpinned Python dependency `{s[:40]}`", rel, i, "low",
                                              "Unpinned requirements resolve to the newest release on every install.",
                                              "Pin with `==` (generate with pip-compile) and ideally `--require-hashes`."))
        elif base == "go.mod":
            ecos.add("go")
            if not (root / d / "go.sum").exists() and re.search(r"^\s*require\b", text, re.M):
                out.append(static_finding("go.mod without go.sum", rel, 1, "medium",
                                          "Without go.sum, module content is not pinned to verified checksums.",
                                          "Commit go.sum (go mod tidy) and keep GOFLAGS=-mod=readonly / GONOSUMDB unset in CI."))
            for m in re.finditer(r"^\s*replace\s+(\S+)[^\n]*=>\s*(\S+)", text, re.M):
                if m.group(2).startswith((".", "/")):
                    out.append(static_finding(f"Local replace directive for {m.group(1)}", rel,
                                              text.count("\n", 0, m.start()) + 1, "low",
                                              "A replace to a local path builds whatever is on disk, bypassing the checksum database.",
                                              "Use only for local development; remove before release or point to a tagged version.",
                                              cwe="CWE-829"))
        elif base == "pubspec.yaml":
            ecos.add("pub")
            is_app = "publish_to: none" in text.replace("'", "").replace('"', "") or "sdk: flutter" in text
            if is_app and not (root / d / "pubspec.lock").exists():
                out.append(static_finding("Flutter/Dart app without pubspec.lock", rel, 1, "medium",
                                          "Applications should commit pubspec.lock so every build resolves the same package versions.",
                                          "Commit pubspec.lock and use `flutter pub get --enforce-lockfile` in CI."))
            for m in re.finditer(r"^\s{2,4}([a-z_][a-z0-9_]*)\s*:\s*(any|['\"]?any['\"]?)\s*$", text, re.M):
                out.append(static_finding(f"Unbounded version for {m.group(1)}", rel,
                                          text.count("\n", 0, m.start()) + 1, "medium",
                                          f"`{m.group(1)}: any` accepts every future release.",
                                          "Use a caret constraint (^x.y.z) and rely on pubspec.lock."))
            for m in re.finditer(r"^\s{2,4}([a-z_][a-z0-9_]*)\s*:\s*\n\s+git\s*:", text, re.M):
                block = text[m.start():m.start() + 300]
                if not re.search(r"ref\s*:\s*[0-9a-f]{40}", block):
                    out.append(static_finding(f"Git dependency {m.group(1)} not pinned to a commit", rel,
                                              text.count("\n", 0, m.start()) + 1, "low",
                                              f"`{m.group(1)}` is fetched from git by branch/tag, which can move.",
                                              "Pin `ref:` to a full commit SHA or publish to a registry you control."))
        elif base in ("pyproject.toml",):
            ecos.add("pip")
    return out, ecos


def audit_osv(root):
    exe = shutil.which("osv-scanner")
    if not exe:
        return {"tool": "osv-scanner", "status": "skipped", "reason": "not installed"}, []
    code, out, err = run([exe, "--format", "json", "-r", str(root)], root)
    if code == 128 or "No package sources found" in (err or "") + (out or ""):
        # osv-scanner exits 128 when it finds no lockfile/manifest it can read: nothing was audited
        return {"tool": "osv-scanner", "status": "skipped", "reason": "no lockfile or manifest osv-scanner can read"}, []
    try:
        data = json.loads(out)
    except ValueError:
        return {"tool": "osv-scanner", "status": "failed", "reason": (err or out)[:200]}, []
    vulns = []
    for res in data.get("results", []):
        src = res.get("source", {}).get("path", "")
        for p in res.get("packages", []):
            pk = p.get("package", {})
            for v in p.get("vulnerabilities", []):
                sev = (v.get("database_specific") or {}).get("severity", "unknown")
                vulns.append({"package": pk.get("name"), "version": pk.get("version"),
                              "ecosystem": pk.get("ecosystem"), "advisory": v.get("id"),
                              "summary": v.get("summary", "")[:160], "severity": SEV_MAP.get(str(sev).lower(), "medium"),
                              "manifest": str(Path(src).relative_to(root)) if src.startswith(str(root)) else src,
                              "tool": "osv-scanner"})
    return {"tool": "osv-scanner", "status": "ran", "results": len(vulns)}, vulns


def audit_npm(root, lockfiles):
    exe = shutil.which("npm")
    locks = [l for l in lockfiles if Path(l).name == "package-lock.json"]
    if not locks:
        return {"tool": "npm audit", "status": "skipped", "reason": "no package-lock.json"}, []
    if not exe:
        return {"tool": "npm audit", "status": "skipped", "reason": "npm not installed"}, []
    vulns, failed = [], []
    for lock in locks:
        d = root / Path(lock).parent
        code, out, err = run([exe, "audit", "--json", "--package-lock-only"], d)
        try:
            data = json.loads(out)
        except ValueError:
            failed.append(f"{lock}: {(err or out)[:120]}")
            continue
        if "error" in data:
            failed.append(f"{lock}: {str(data['error'])[:120]}")
            continue
        for name, v in (data.get("vulnerabilities") or {}).items():
            advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
            if not advisories:
                continue  # only transitive "via" another package; reported under that package
            a0 = advisories[0]
            vulns.append({"package": name, "version": v.get("range"), "ecosystem": "npm",
                          "advisory": a0.get("url") or a0.get("source"), "summary": a0.get("title", "")[:160],
                          "severity": SEV_MAP.get(v.get("severity", "unknown"), "medium"),
                          "fix_available": bool(v.get("fixAvailable")), "manifest": lock, "tool": "npm audit"})
    status = "failed" if failed and not vulns else "ran"
    return {"tool": "npm audit", "status": status, "results": len(vulns),
            **({"reason": "; ".join(failed)[:300]} if failed else {})}, vulns


def audit_dotnet(root, files):
    exe = shutil.which("dotnet")
    projs = [f["path"] for f in files if f["path"].endswith(".csproj")]
    if not projs:
        return {"tool": "dotnet list package --vulnerable", "status": "skipped", "reason": "no .csproj"}, []
    if not exe:
        return {"tool": "dotnet list package --vulnerable", "status": "skipped",
                "reason": "dotnet SDK not installed"}, []
    vulns, failed = [], []
    for proj in projs:
        code, out, err = run([exe, "list", proj, "package", "--vulnerable", "--include-transitive",
                              "--format", "json"], root)
        try:
            data = json.loads(out)
        except ValueError:
            failed.append(f"{proj}: {(err or out)[:120]} (run `dotnet restore` first?)")
            continue
        for p in data.get("projects", []):
            for fw in p.get("frameworks", []):
                for kind in ("topLevelPackages", "transitivePackages"):
                    for pk in fw.get(kind, []):
                        for v in pk.get("vulnerabilities", []):
                            vulns.append({"package": pk.get("id"), "version": pk.get("resolvedVersion"),
                                          "ecosystem": "nuget", "advisory": v.get("advisoryurl"),
                                          "summary": "", "severity": SEV_MAP.get(str(v.get("severity", "")).lower(), "medium"),
                                          "transitive": kind == "transitivePackages", "manifest": proj,
                                          "tool": "dotnet"})
    status = "failed" if failed and not vulns else "ran"
    return {"tool": "dotnet list package --vulnerable", "status": status, "results": len(vulns),
            **({"reason": "; ".join(failed)[:300]} if failed else {})}, vulns


def audit_pip(root, files):
    exe = shutil.which("pip-audit")
    reqs = [f["path"] for f in files if re.match(r"requirements.*\.txt$", Path(f["path"]).name)]
    if not reqs:
        return {"tool": "pip-audit", "status": "skipped", "reason": "no requirements*.txt"}, []
    if not exe:
        return {"tool": "pip-audit", "status": "skipped", "reason": "pip-audit not installed"}, []
    vulns, failed = [], []
    for req in reqs:
        code, out, err = run([exe, "-r", req, "-f", "json", "--progress-spinner", "off"], root)
        try:
            data = json.loads(out)
        except ValueError:
            failed.append(f"{req}: {(err or out)[:120]}")
            continue
        for dep in data.get("dependencies", data if isinstance(data, list) else []):
            for v in dep.get("vulns", []):
                vulns.append({"package": dep.get("name"), "version": dep.get("version"), "ecosystem": "pypi",
                              "advisory": v.get("id"), "summary": (v.get("description") or "")[:160],
                              "severity": "medium", "fixed_in": v.get("fix_versions"), "manifest": req,
                              "tool": "pip-audit"})
    status = "failed" if failed and not vulns else "ran"
    return {"tool": "pip-audit", "status": status, "results": len(vulns),
            **({"reason": "; ".join(failed)[:300]} if failed else {})}, vulns


def audit_go(root, files):
    if not any(Path(f["path"]).name == "go.mod" for f in files):
        return {"tool": "govulncheck", "status": "skipped", "reason": "no go.mod"}, []
    exe = shutil.which("govulncheck")
    if not exe:
        return {"tool": "govulncheck", "status": "skipped", "reason": "govulncheck not installed"}, []
    code, out, err = run([exe, "-json", "./..."], root)
    vulns = []
    for chunk in re.split(r"\n(?=\{)", out or ""):
        try:
            o = json.loads(chunk)
        except ValueError:
            continue
        f = o.get("finding")
        if f and f.get("trace"):
            vulns.append({"package": f["trace"][0].get("module"), "version": f["trace"][0].get("version"),
                          "ecosystem": "go", "advisory": f.get("osv"), "summary": "reachable (call path found)",
                          "severity": "high", "manifest": "go.mod", "tool": "govulncheck"})
    return {"tool": "govulncheck", "status": "ran" if out else "failed",
            "results": len(vulns), **({} if out else {"reason": err[:200]})}, vulns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--offline", action="store_true", help="skip tools that need network access")
    a = ap.parse_args()
    run_dir = Path(a.run_dir)
    inv = read_json(run_dir / "inventory.json")
    if not inv:
        raise SystemExit("inventory.json missing")
    root = Path(inv["root"])
    files, lockfiles = inv["files"], inv.get("lockfiles", [])

    static, ecos = hygiene(root, files, lockfiles)
    sups = load_suppressions(root)
    kept, dropped = [], []
    for h in static:
        why = suppressed_by(h, sups, [])
        (dropped if why else kept).append({**h, **({"suppressed": why} if why else {})})
    static = kept
    tools, vulns = [], []
    auditors = [lambda: audit_osv(root)]
    if not a.offline:
        auditors += [lambda: audit_npm(root, lockfiles), lambda: audit_dotnet(root, files),
                     lambda: audit_pip(root, files), lambda: audit_go(root, files)]
    for fn in auditors:
        st, vs = fn()
        tools.append(st)
        vulns += vs
    # de-dup the same advisory reported by several tools
    seen, uniq = set(), []
    for v in vulns:
        k = (v.get("package"), v.get("version"), v.get("advisory"))
        if k not in seen:
            seen.add(k)
            uniq.append(v)
    ran_vuln_tool = any(t["status"] == "ran" for t in tools)
    write_json(run_dir / "deps.json", {"ecosystems": sorted(ecos), "lockfiles": lockfiles,
                                       "tools": tools, "vulnerabilities": uniq, "hygiene": static,
                                       "suppressed": dropped,
                                       "vuln_audit_ran": ran_vuln_tool})
    print(f"ecosystems={','.join(sorted(ecos)) or 'none'} hygiene_findings={len(static)} suppressed={len(dropped)} "
          f"known_vulns={len(uniq)}")
    for t in tools:
        if t["status"] != "ran" and not (t["status"] == "skipped" and t.get("reason", "").startswith("no ")):
            print(f"COVERAGE GAP: {t['tool']} {t['status']} — {t.get('reason', '')}")
    if ecos and not ran_vuln_tool:
        print("COVERAGE GAP: no known-vulnerability audit ran — dependency CVEs were NOT checked.")


if __name__ == "__main__":
    main()
