#!/usr/bin/env python3
"""Taint engine management.

The taint phase needs OpenGrep (preferred: open-source intrafile cross-function taint via
--taint-intrafile) or Semgrep CE (fallback: intraprocedural taint only).

  engine.py status                     which engine would be used, version, capabilities
  engine.py install [--version vX.Y.Z] [--allow-unverified]
                                       download the pinned OpenGrep release into the user cache
                                       (ASK THE USER FIRST on their own machine)

Lookup order: $SECURITY_AUDIT_OPENGREP, `opengrep` on PATH, <cache>/opengrep, `semgrep` on PATH.
Cache dir: $SECURITY_AUDIT_CACHE or ~/.cache/security-audit/bin.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

PINNED_VERSION = "v1.30.0"  # tested with this skill's taint rule packs
RELEASE_URL = "https://github.com/opengrep/opengrep/releases/download/{version}/{asset}"
COSIGN_IDENTITY = "https://github.com/opengrep/opengrep.+"
COSIGN_ISSUER = "https://token.actions.githubusercontent.com"


def find_cosign():
    """Path of the cosign executable, or None.

    Release binaries (and winget, which only registers the file name as its alias) are called
    cosign-<os>-<arch>, e.g. cosign-windows-amd64.exe; package managers such as Homebrew install
    plain `cosign`. Looking up only `cosign` would report a correctly installed cosign as missing
    and push the user towards an unverified download.
    """
    names = ["cosign"] + [f"cosign-{o}-{a}" for o in ("windows", "linux", "darwin")
                          for a in ("amd64", "arm64")]
    for n in names:
        exe = shutil.which(n)
        if exe:
            return exe
    return None


def cache_dir():
    return Path(os.environ.get("SECURITY_AUDIT_CACHE", Path.home() / ".cache" / "security-audit" / "bin"))


def _version(exe):
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        return (r.stdout or r.stderr).strip().splitlines()[-1] if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def find_engine():
    """Return {"exe", "kind": opengrep|semgrep, "version", "intrafile": bool} or None."""
    cands = []
    if os.environ.get("SECURITY_AUDIT_OPENGREP"):
        cands.append(("opengrep", os.environ["SECURITY_AUDIT_OPENGREP"]))
    if shutil.which("opengrep"):
        cands.append(("opengrep", shutil.which("opengrep")))
    for name in ("opengrep", "opengrep.exe"):  # install() writes opengrep.exe on Windows
        cached = cache_dir() / name
        if cached.exists():
            cands.append(("opengrep", str(cached)))
    if shutil.which("semgrep"):
        cands.append(("semgrep", shutil.which("semgrep")))
    for kind, exe in cands:
        v = _version(exe)
        if v:
            return {"exe": exe, "kind": kind, "version": v, "intrafile": kind == "opengrep"}
    return None


def asset_name():
    sysname, arch = platform.system(), platform.machine().lower()
    x86 = arch in ("x86_64", "amd64")
    if sysname == "Darwin":
        return "opengrep_osx_x86" if x86 else "opengrep_osx_arm64"
    if sysname == "Linux":
        musl = False
        try:
            musl = "musl" in subprocess.run(["ldd", "--version"], capture_output=True, text=True).stdout + \
                   subprocess.run(["ldd", "--version"], capture_output=True, text=True).stderr
        except OSError:
            pass
        if musl:
            return "opengrep_musllinux_x86" if x86 else "opengrep_musllinux_aarch64"
        return "opengrep_manylinux_x86" if x86 else "opengrep_manylinux_aarch64"
    if sysname == "Windows":
        return "opengrep_windows_x86.exe"
    raise SystemExit(f"unsupported platform {sysname}/{arch}; install opengrep manually and set SECURITY_AUDIT_OPENGREP")


def _download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "security-audit-skill"})
    with urllib.request.urlopen(req, timeout=300) as r, open(dest, "wb") as f:  # noqa: S310 — fixed https host
        shutil.copyfileobj(r, f)


def install(version=PINNED_VERSION, allow_unverified=False):
    if not version.startswith("v") or not all(p.isdigit() for p in version[1:].split(".")):
        raise SystemExit("version must look like v1.30.0")
    cosign = find_cosign()
    if not cosign and not allow_unverified:
        # Running a downloaded executable whose signature was never checked is the user's call,
        # not the agent's: stop and let the orchestrator ask.
        raise SystemExit("cosign is not installed, so the OpenGrep binary's signature cannot be verified.\n"
                         "Ask the user: install cosign (https://docs.sigstore.dev) and re-run, or accept an "
                         "unverified download with: engine.py install --allow-unverified")
    asset = asset_name()
    url = RELEASE_URL.format(version=version, asset=asset)
    d = cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "opengrep.download"
    print(f"downloading {url}")
    _download(url, tmp)
    tmp.chmod(0o755)
    verified = "unverified (cosign not installed)"
    if cosign:
        try:
            _download(url + ".cert", d / "opengrep.cert")
            _download(url + ".sig", d / "opengrep.sig")
            r = subprocess.run([cosign, "verify-blob", "--cert", str(d / "opengrep.cert"),
                                "--signature", str(d / "opengrep.sig"),
                                "--certificate-identity-regexp", COSIGN_IDENTITY,
                                "--certificate-oidc-issuer", COSIGN_ISSUER, str(tmp)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                tmp.unlink(missing_ok=True)
                raise SystemExit(f"signature verification FAILED — binary removed:\n{r.stderr[:500]}")
            verified = "cosign signature verified"
        except OSError as e:
            verified = f"unverified (signature download failed: {e})"
    v = _version(str(tmp))
    if not v:
        tmp.unlink(missing_ok=True)
        raise SystemExit("downloaded binary does not run on this platform")
    final = d / ("opengrep.exe" if asset.endswith(".exe") else "opengrep")
    os.replace(tmp, final)
    sha = hashlib.sha256(final.read_bytes()).hexdigest()
    info = {"exe": str(final), "version": v, "asset": asset, "sha256": sha, "verification": verified}
    (d / "opengrep.json").write_text(json.dumps(info, indent=2))
    print(json.dumps(info, indent=2))
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["status", "install"])
    ap.add_argument("--version", default=PINNED_VERSION)
    ap.add_argument("--allow-unverified", action="store_true",
                    help="install even though cosign is missing (only with the user's explicit OK)")
    a = ap.parse_args()
    if a.cmd == "install":
        install(a.version, a.allow_unverified)
        return
    e = find_engine()
    if not e:
        print("no taint engine found. Install OpenGrep (ask the user first):\n"
              f"  python3 {Path(__file__).name} install     # (Windows: python) pinned {PINNED_VERSION}, into {cache_dir()}")
        sys.exit(1)
    meta = cache_dir() / "opengrep.json"
    extra = json.loads(meta.read_text()) if meta.exists() and e["exe"].startswith(str(cache_dir())) else {}
    print(json.dumps({**e, **{k: extra[k] for k in ("sha256", "verification") if k in extra}}, indent=2))
    if not e["intrafile"]:
        print("note: Semgrep CE has no cross-function taint; install OpenGrep for intrafile + cross-file chains")


if __name__ == "__main__":
    main()
