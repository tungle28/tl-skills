"""Shared helpers for the tl-security-audit pipeline scripts."""
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Windows consoles default to a legacy code page (cp1252…); printing a non-ASCII path or an em dash
# would crash a phase with UnicodeEncodeError or garble output. Every script imports this module.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# Source code
LANG_BY_EXT = {
    ".cs": "csharp", ".cshtml": "razor", ".razor": "razor",
    ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".vue": "javascript", ".svelte": "javascript",
    ".py": "python", ".java": "java", ".kt": "kotlin", ".go": "go", ".rb": "ruby", ".php": "php",
    ".dart": "dart", ".kts": "kotlin", ".plist": "xml", ".entitlements": "xml",
    ".rs": "rust", ".swift": "swift", ".scala": "scala", ".c": "c", ".h": "c", ".cpp": "cpp",
    ".cc": "cpp", ".hpp": "cpp", ".sql": "sql", ".html": "html", ".htm": "html",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    # Config / infrastructure — scanned by rules and reviewed like code
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".xml": "xml", ".config": "xml",
    ".csproj": "xml", ".props": "xml", ".tf": "terraform", ".tfvars": "terraform",
    ".toml": "toml", ".gradle": "groovy", ".ini": "ini", ".properties": "ini", ".conf": "ini",
    ".pem": "key", ".key": "key", ".p12": "key", ".pfx": "key",
}
LANG_BY_NAME = {
    "dockerfile": "dockerfile", "containerfile": "dockerfile", "jenkinsfile": "groovy",
    ".npmrc": "ini", ".pypirc": "ini", "web.config": "xml", "go.mod": "gomod", "go.work": "gomod",
    "podfile": "ruby", "gemfile": "ruby", "pipfile": "toml", "setup.cfg": "ini",
}
CONFIG_LANGS = {"yaml", "json", "xml", "terraform", "toml", "ini", "dockerfile", "env", "key", "groovy", "gomod",
                "pip-requirements"}

EXCLUDE_DIRS = {
    ".git", "node_modules", "bin", "obj", "dist", "build", "out", "target", ".next", ".nuxt",
    ".turbo", "coverage", "vendor", ".venv", "venv", "__pycache__", ".idea", ".vs", ".vscode",
    ".security-run", ".security-audit", ".refactor-run", ".gradle", ".terraform", ".mypy_cache", ".pytest_cache",
    "bower_components", ".cache", ".yarn", ".dart_tool", ".pub-cache", ".fvm", "Pods",
    ".symlinks", "ephemeral",
}
# Lockfiles are dependency data (deps phase), not code to review line by line.
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "packages.lock.json",
             "poetry.lock", "pipfile.lock", "go.sum", "pubspec.lock", "composer.lock", "gemfile.lock", "cargo.lock"}
MIGRATION_DIRS = {"migrations"}
GENERATED_SUFFIXES = (
    ".designer.cs", ".g.cs", ".g.i.cs", ".min.js", ".min.css", ".d.ts", "assemblyinfo.cs",
    ".pb.go", ".sql.go", "_templ.go", "_string.go", "zz_generated.deepcopy.go", "_pb2.py",
    ".g.dart", ".freezed.dart", ".mocks.dart", ".pb.dart", ".gr.dart", ".config.dart", ".generated.ts", ".generated.cs", "modelsnapshot.cs", ".map",
)
# Third-party front-end assets copied into the repo (admin themes, jQuery plugins): not first-party
# code, and the main cost of a taint run when scanned. A segment from VENDOR_DIRS marks them alone;
# a generic one (lib, plugins, themes) only below a web-asset root (public/, static/, assets/…).
VENDOR_DIRS = {"app-assets", "third_party", "third-party", "thirdparty", "vendors", "bower_components"}
VENDOR_WEAK_DIRS = {"lib", "libs", "plugins", "themes", "vendor"}
WEB_ASSET_ROOTS = {"public", "static", "assets", "wwwroot", "web", "webroot", "resources"}
VENDOR_LANGS = {"javascript", "typescript", "html"}
TEST_DIR_NAMES = {"test", "tests", "spec", "specs", "__tests__", "__mocks__", "e2e", "fixtures",
                  "integration_test", "testdata", "test_driver"}

STATE_FILE = "state.json"
PHASES = ["inventory", "taint", "scan", "deps", "review", "merge", "verify", "report", "fix"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
CONFIDENCES = ["high", "medium", "low"]
OWASP_2025 = {
    "A01": "Broken Access Control", "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures", "A04": "Cryptographic Failures",
    "A05": "Injection", "A06": "Insecure Design", "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures", "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}


def detect_lang(path):
    p = Path(path)
    name = p.name.lower()
    if name in LANG_BY_NAME:
        return LANG_BY_NAME[name]
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return "env"
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "dockerfile"
    # requirements.txt / requirements-dev.txt / requirements/prod.txt: dependency manifests the deps
    # phase must see (a .txt extension is otherwise not inventoried)
    if name.endswith(".txt") and (name.startswith("requirements") or p.parent.name.lower() == "requirements"):
        return "pip-requirements"
    return LANG_BY_EXT.get(p.suffix.lower())


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path, default=None):
    p = Path(path)
    if not p.exists():
        return default
    with open(p, encoding="utf-8-sig") as f:  # tolerate a BOM (PowerShell 5.1 writes one)
        return json.load(f)


def write_json(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)  # atomic: a crashed phase never leaves half-written state


def is_test_path(rel):
    parts = [p.lower() for p in Path(rel).parts]
    name = parts[-1]
    if any(p in TEST_DIR_NAMES for p in parts[:-1]):
        return True
    if any(p.endswith((".tests", ".test", ".specs", ".unittests", ".integrationtests"))
           for p in parts[:-1]):
        return True
    return (".test." in name or ".spec." in name or name.startswith("test_")
            or name.endswith(("_test.py", "_test.go", "_test.dart", "tests.cs", "test.cs", "test.java")))


def is_generated(rel):
    return rel.lower().endswith(GENERATED_SUFFIXES)


def vendor_root(rel, lang):
    """Directory prefix of a vendored front-end asset tree containing `rel`, or None."""
    if lang not in VENDOR_LANGS:
        return None
    parts = Path(rel).parts[:-1]
    web = False
    for i, part in enumerate(parts):
        low = part.lower()
        if low in VENDOR_DIRS or (web and low in VENDOR_WEAK_DIRS):
            return "/".join(parts[:i + 1])
        web = web or low in WEB_ASSET_ROOTS
    return None


def load_state(run_dir):
    return read_json(Path(run_dir) / STATE_FILE, {})


def save_state(run_dir, state):
    state["updated_at"] = now_iso()
    write_json(Path(run_dir) / STATE_FILE, state)


def mark(run_dir, phase, status, note=None):
    state = load_state(run_dir)
    ph = state.setdefault("phases", {}).setdefault(phase, {})
    ph["status"] = status
    ph["at"] = now_iso()
    if note:
        ph["note"] = note
    save_state(run_dir, state)


def secret_digest(value):
    """sha256 of a secret value. The scan stores only digests, never the value itself."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def redact(text, keep=4):
    """Mask a secret value: keep a short prefix for identification, never the full value."""
    text = str(text)
    if len(text) <= keep + 4:
        return "*" * len(text)
    return f"{text[:keep]}…[{len(text)} chars redacted]"
