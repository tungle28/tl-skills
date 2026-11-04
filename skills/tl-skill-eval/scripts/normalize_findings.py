#!/usr/bin/env python3
"""Convert a harness skill's run output into findings_run<i>.json for harness_metrics.py.

  python normalize_findings.py <run-output> --run-id run1 --out findings_run1.json [--format auto]

Formats (auto-detected):
  tl-architecture-doc   a .src dir (docset.json + findings/*.json); file/line from the first citation
  tl-code-refactor      a RUN_DIR with merged.json (kind/category/severity/file/line_start)
  tl-security-audit     a RUN_DIR with merged.json whose findings carry `owasp`
  generic               a JSON file already shaped {"findings": [{file, line_start, ...}]}

Dropped: findings the skill's own verifier rejected, fixed/history items, positive findings
("Good practice"). Severity is mapped to info/low/medium/high/critical; the mapping is written into
the output (`severity_map`) so the scorecard can state it. Paths: forward slashes, relative to the
repo root. For a multi-layer architecture doc, pass --layer-root be=api/ to prefix layer-relative paths.
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import read_json, utf8_stdio, write_json  # noqa: E402

CITE_RE = re.compile(r"([\w.\-/\\@\[\]+~$()]+):(\d+)(?:\s*[-–]\s*(\d+))?")
ARCHDOC_SEV = {"Critical": "critical", "Medium": "medium", "Low": "low"}
PASS_SEV = {s: s for s in ("info", "low", "medium", "high", "critical")}


def detect(src):
    src = Path(src)
    if src.is_file():
        return "generic"
    if (src / "docset.json").exists() and (src / "findings").is_dir():
        return "tl-architecture-doc"
    merged = read_json(src / "merged.json")
    if merged:
        return "tl-security-audit" if any("owasp" in f for f in merged.get("findings", [])) else "tl-code-refactor"
    sys.exit(f"cannot detect the format of {src} — pass --format")


def from_archdoc(src, layer_roots):
    out = []
    for p in sorted((Path(src) / "findings").glob("*.json")):
        data = read_json(p)
        items = data.get("findings", []) if isinstance(data, dict) else data
        layer_default = data.get("layer") if isinstance(data, dict) else None
        for f in items:
            if f.get("status", "open") != "open" or (f.get("verification") or {}).get("verdict") == "rejected":
                continue
            if f.get("severity") not in ARCHDOC_SEV:
                continue
            m = next((CITE_RE.search(c) for c in f.get("citations") or [] if CITE_RE.search(c)), None)
            if not m:
                continue
            layer = f.get("layer") or layer_default
            path = layer_roots.get(layer, "") + m.group(1).replace("\\", "/")
            l1 = int(m.group(2))
            out.append({"id": f["id"], "file": path, "line_start": l1, "line_end": int(m.group(3) or l1),
                        "category": f.get("category"), "severity": ARCHDOC_SEV[f["severity"]],
                        "title": f.get("title"), "layer": layer,
                        "verdict": (f.get("verification") or {}).get("verdict")})
    return out, ARCHDOC_SEV


def from_merged(src, fmt):
    doc = read_json(Path(src) / "merged.json")
    out = []
    for f in doc.get("findings", []):
        if str(f.get("status", "")).lower() == "rejected":
            continue
        cat = f.get("category") or (f.get("owasp") if fmt == "tl-security-audit" else None) or f.get("dimension")
        out.append({"id": f["id"], "file": str(f.get("file", "")).replace("\\", "/"),
                    "line_start": f.get("line_start"), "line_end": f.get("line_end") or f.get("line_start"),
                    "category": cat, "severity": str(f.get("severity", "")).lower(), "title": f.get("title"),
                    "kind": f.get("kind"), "owasp": f.get("owasp"), "verdict": f.get("status")})
    return out, PASS_SEV


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_output")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--format", default="auto",
                    choices=["auto", "tl-architecture-doc", "tl-code-refactor", "tl-security-audit", "generic"])
    ap.add_argument("--layer-root", action="append", default=[], help="archdoc layer=path/ prefix (repeatable)")
    a = ap.parse_args()
    fmt = detect(a.run_output) if a.format == "auto" else a.format
    if fmt == "tl-architecture-doc":
        roots = dict(x.split("=", 1) for x in a.layer_root)
        roots = {k: (v.rstrip("/") + "/" if v else "") for k, v in roots.items()}
        findings, sev_map = from_archdoc(a.run_output, roots)
    elif fmt in ("tl-code-refactor", "tl-security-audit"):
        findings, sev_map = from_merged(a.run_output, fmt)
    else:
        doc = read_json(a.run_output)
        findings, sev_map = doc.get("findings", []), PASS_SEV
    write_json(a.out, {"run_id": a.run_id, "source_format": fmt, "source": str(a.run_output),
                       "severity_map": sev_map, "findings": findings})
    print(f"{fmt}: {len(findings)} finding(s) -> {a.out}")


if __name__ == "__main__":
    main()
