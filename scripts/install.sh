#!/bin/sh
# macOS / Linux launcher for scripts/install.py.
#
#   sh scripts/install.sh                                   # all skills -> Claude Code (~/.claude)
#   sh scripts/install.sh --target cursor
#   sh scripts/install.sh --target all --skills tl-code-review,tl-security-audit --dry-run
#   sh scripts/install.sh --target claude --scope project --project ../my-app
#
# Without a clone (downloads the release archive to a temp dir, installs, deletes it):
#   curl -fsSL https://raw.githubusercontent.com/tungle28/tl-skills/main/scripts/install.sh | sh -s -- --target claude
#   ... | sh -s -- --target cursor --skills tl-goal-griller --version v0.4.0
#
# It only finds a working Python 3.9+ and forwards every option to install.py unchanged (see that
# file for what they do). Unlike install.py, --target defaults to claude. If Python is missing it
# offers to install it (asks first; without a terminal it only prints what to run).
# --version vX.Y.Z is read here, not by install.py: it picks the release to download when the
# script runs outside a clone (default: the latest release, i.e. the main branch).
# Windows: use scripts\install.ps1.

set -eu

REPO=tungle28/tl-skills
py=""
tmp=""

# A name on PATH is not proof of an interpreter (the Windows Store shim, an old 2.x python), so
# run each candidate and check the version. WindowsApps matters when this runs under Git Bash.
find_python() {
  py=""
  for candidate in python3 python py; do
    path=$(command -v "$candidate" 2>/dev/null) || continue
    case $path in *WindowsApps*) continue ;; esac
    # macOS: /usr/bin/python3 is a shim that opens the Command Line Tools install dialog when
    # run without them, so do not even probe it unless xcode-select finds the tools.
    if [ "$path" = /usr/bin/python3 ] && [ "$(uname -s 2>/dev/null)" = Darwin ] \
      && ! xcode-select -p >/dev/null 2>&1; then
      continue
    fi
    if "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
      py=$candidate
      return 0
    fi
  done
  return 1
}

# Prefix for package-manager commands that need root.
as_root() {
  if [ "$(id -u 2>/dev/null || echo 1)" = 0 ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else echo "install.sh: need root to run: $*" >&2; return 1
  fi
}

# Sets `how` to the command that installs Python here, or "" if we do not know one.
pick_installer() {
  how=""
  case $(uname -s 2>/dev/null || echo unknown) in
    Darwin)
      if command -v brew >/dev/null 2>&1; then how="brew install python"
      else how="xcode-select --install"; fi ;;
    Linux)
      if command -v apt-get >/dev/null 2>&1; then how="as_root apt-get install -y python3"
      elif command -v dnf >/dev/null 2>&1; then how="as_root dnf install -y python3"
      elif command -v pacman >/dev/null 2>&1; then how="as_root pacman -S --noconfirm python"
      elif command -v zypper >/dev/null 2>&1; then how="as_root zypper install -y python3"
      elif command -v apk >/dev/null 2>&1; then how="as_root apk add python3"
      fi ;;
  esac
}

ensure_python() {
  find_python && return 0
  echo "install.sh: no working Python 3.9+ found (install.py needs it)." >&2
  pick_installer
  if [ -n "$how" ] && [ -t 0 ]; then
    printf 'Install Python now with `%s`? [y/N] ' "$(echo "$how" | sed 's/^as_root /sudo /')"
    read -r answer || answer=n
    case $answer in
      y | Y | yes | YES)
        if [ "$how" = "xcode-select --install" ]; then
          # With the tools already present --install exits non-zero ("already installed"), and
          # their python3 can still be older than 3.9: that is not a dialog to wait for.
          if xcode-select -p >/dev/null 2>&1; then
            echo "install.sh: the Command Line Tools are already installed, but their python3 is older than 3.9." >&2
            echo "  Install a newer one: brew install python   (or https://www.python.org/downloads/), then re-run." >&2
            exit 1
          fi
          rc=0
          out=$($how 2>&1) || rc=$?
          [ -z "$out" ] || echo "$out" >&2
          if [ "$rc" -ne 0 ]; then
            # An install request that is still pending means the dialog is already open.
            case $out in
              *[Ii]nstall\ requested* | *[Aa]lready\ requested* | *[Rr]equest*[Pp]ending*) ;;
              *) echo "install.sh: 'xcode-select --install' failed (exit $rc)." >&2; exit 1 ;;
            esac
          fi
          echo "A dialog to install the Command Line Tools (includes python3) is open or was just opened."
          echo "Re-run this script when it finishes."
          exit 0
        fi
        $how || { echo "install.sh: the Python install failed." >&2; exit 1; }
        hash -r 2>/dev/null || :
        find_python || { echo "install.sh: Python installed but not found on PATH; open a new terminal and re-run." >&2; exit 1; }
        ;;
      *) echo "Skipped. Install Python 3.9+ and re-run." >&2; exit 1 ;;
    esac
  else
    echo "  macOS:   brew install python   (or: xcode-select --install)" >&2
    echo "  Debian:  sudo apt install python3" >&2
    echo "  Other:   https://www.python.org/downloads/" >&2
    exit 1
  fi
}

# Downloads the release archive for $1 ("" = latest) into a temp dir and sets `src` to the
# extracted checkout. Plain HTTPS + tar: no git needed.
fetch_release() {
  if [ -n "$1" ]; then url="https://github.com/$REPO/archive/refs/tags/$1.tar.gz"
  else url="https://github.com/$REPO/archive/refs/heads/main.tar.gz"; fi
  tmp=$(mktemp -d 2>/dev/null || mktemp -d -t tl-skills)
  trap 'rm -rf "$tmp"' EXIT INT TERM
  echo "install.sh: downloading $url" >&2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp/src.tar.gz" || { echo "install.sh: download failed: $url" >&2; exit 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp/src.tar.gz" "$url" || { echo "install.sh: download failed: $url" >&2; exit 1; }
  else
    echo "install.sh: need curl or wget to download $url" >&2; exit 1
  fi
  tar -xzf "$tmp/src.tar.gz" -C "$tmp" || { echo "install.sh: could not extract the archive." >&2; exit 1; }
  for d in "$tmp"/*/; do
    if [ -f "$d/scripts/install.py" ]; then src=${d%/}; return 0; fi
  done
  echo "install.sh: the archive has no scripts/install.py." >&2; exit 1
}

main() {
  # --version is ours, not install.py's: take it out of the arguments.
  version="" n=$#
  while [ "$n" -gt 0 ]; do
    arg=$1; shift; n=$((n - 1))
    case $arg in
      --version) [ "$n" -gt 0 ] || { echo "install.sh: --version needs a value (e.g. v0.4.0)" >&2; exit 2; }
                 version=$1; shift; n=$((n - 1)) ;;
      --version=*) version=${arg#--version=} ;;
      *) set -- "$@" "$arg" ;;
    esac
  done
  case $version in
    "" | v[0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "install.sh: --version must look like v0.4.0, got '$version'" >&2; exit 2 ;;
  esac
  case $version in *[!v0-9.]*) echo "install.sh: --version must look like v0.4.0, got '$version'" >&2; exit 2 ;; esac

  # Default the target, but leave --help and an explicit --target/--target=X alone.
  has_target=0
  for arg in "$@"; do
    case $arg in --target | --target=* | -h | --help) has_target=1 ;; esac
  done
  [ "$has_target" = 1 ] || set -- --target claude "$@"

  ensure_python

  # Inside a clone, install from it. Piped (curl ... | sh) $0 is the shell, so there is no
  # install.py next to it: download the release instead.
  here=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || here=""
  if [ -n "$here" ] && [ -f "$here/install.py" ] && [ -d "$here/../skills" ]; then
    [ -z "$version" ] || echo "install.sh: --version ignored; installing from this checkout ($here/..)" >&2
    exec "$py" "$here/install.py" "$@"
  fi

  fetch_release "$version"
  # A piped script's stdin is the pipe: give install.py the terminal so it can still ask.
  if (: </dev/tty) 2>/dev/null; then
    "$py" "$src/scripts/install.py" "$@" </dev/tty
  else
    "$py" "$src/scripts/install.py" "$@"
  fi
}

# Everything above only defines functions, so a piped script is fully read before any of it runs.
main "$@"
