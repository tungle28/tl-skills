"""Shared helpers for the tl-skill-eval scripts (stdlib only).

Everything is read and written as UTF-8 explicitly: on Windows the default code page (cp1252)
breaks on Vietnamese text in eval sets, findings and descriptions.
"""
import json
import re
import sys
from pathlib import Path

FRONTMATTER_RE = re.compile(r"^---\r?\n(.*?)\r?\n---\r?\n(.*)$", re.S)  # CRLF checkouts too


def utf8_stdio():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def read_text(p):
    return Path(p).read_text(encoding="utf-8", errors="replace")


def read_json(p, default=None):
    try:
        return json.loads(read_text(p))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as e:
        sys.exit(f"{p}: invalid JSON — {e}")


def write_json(p, obj):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def parse_frontmatter(text):
    """(dict | None, body). dict has '__yaml_error__' when YAML is invalid."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None, text
    raw, body = m.group(1), m.group(2)
    try:
        import yaml
    except ImportError:
        yaml = None
    if yaml:
        try:
            return (yaml.safe_load(raw) or {}), body
        except yaml.YAMLError as e:
            return {"__yaml_error__": str(e).splitlines()[0]}, body
    fm = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip().strip('"')
    return fm, body


def est_tokens(text):
    """Rough size signal (chars/4 for English; non-Latin text costs more). Label it as an estimate."""
    return round(len(text) / 4)
