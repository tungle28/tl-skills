#!/usr/bin/env python3
"""
post_review.py — Phase 6 (optional) of the tl-code-review harness.

Publishes aggregated findings to the PR as ONE review with inline comments.
Posting speaks for the user in front of their team, so the script is built to
make accidental or noisy posting hard:

  * DRY-RUN BY DEFAULT: writes review_payload.json + review_preview.md and
    exits. Only --confirm sends anything. The orchestrator must show the
    preview and get an explicit "yes" from the user before passing --confirm.
  * Never approves. Default event is COMMENT; REQUEST_CHANGES only via explicit
    --event REQUEST_CHANGES.
  * Idempotent: each comment carries a hidden fingerprint marker; findings
    already posted by a previous run are skipped.
  * Skips findings a human already raised on the same lines (pr_context.json).
  * Stale guard: refuses to post if the PR head moved since the review was
    run (comments would anchor to code nobody reviewed) unless --allow-stale.
  * Only lines inside the diff can carry inline comments (platform rule);
    everything else goes into the review summary body.

Supported: GitHub via `gh`. Other platforms: use --format markdown and paste,
or post through a connector if one exists.

Usage
  python post_review.py --dir $RUN                        # dry run: preview only
  python post_review.py --dir $RUN --confirm              # post as COMMENT
  python post_review.py --dir $RUN --severities blocker,major,minor
  python post_review.py --dir $RUN --format markdown      # just render for copy/paste
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under `python -I`
import run_dir  # noqa: E402

SEV_ICON = {"blocker": "🔴", "major": "🟠", "minor": "🟡", "nit": "⚪"}
MARKER = "<!-- tl-code-review:fp={fp} -->"
MARKER_RX = re.compile(r"<!-- tl-code-review:fp=([0-9a-f]{8,}) -->")


def run(cmd, cwd, input_text=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", input=input_text)
    return r.returncode, r.stdout, r.stderr


def load(p, default=None):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def in_hunks(line, hunks):
    return any(start <= line < start + length for start, length in hunks)


def comment_body(f, lang):
    why = "Tại sao" if lang == "vi" else "Why"
    fix = "Đề xuất sửa" if lang == "vi" else "Suggested fix"
    scen = "Kịch bản lỗi" if lang == "vi" else "Failure scenario"
    parts = [f"{SEV_ICON[f['severity']]} **[{f['severity']}] {f['title']}**", "", f"**{why}:** {f['why']}"]
    if f.get("scenario"):
        parts += ["", f"**{scen}:** {f['scenario']}"]
    if f.get("suggestion"):
        parts += ["", f"**{fix}:** {f['suggestion']}"]
    parts += ["", f"<sub>`{f['category']}` · confidence: {f['confidence']} · {f.get('verification', 'unverified')} "
                  f"· tl-code-review skill</sub>", MARKER.format(fp=f["fingerprint"])]
    return "\n".join(parts)


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", help="the run folder (default: the latest run)")
    ap.add_argument("--severities", default="blocker,major")
    ap.add_argument("--include-unverified", action="store_true",
                    help="also post blocker/major findings the verifier could not confirm")
    ap.add_argument("--event", choices=["COMMENT", "REQUEST_CHANGES"], default="COMMENT")
    ap.add_argument("--lang", choices=["en", "vi"], default="en")
    ap.add_argument("--format", choices=["github", "markdown"], default="github")
    ap.add_argument("--confirm", action="store_true", help="actually post (otherwise dry run)")
    ap.add_argument("--allow-stale", action="store_true")
    a = ap.parse_args()
    a.dir = a.dir or str(run_dir.latest())
    d = Path(a.dir)

    manifest = load(d / "manifest.json", {})
    agg = load(d / "findings.json")
    ctx = load(d / "pr_context.json", {}) or {}
    if not agg:
        sys.exit("[post_review] findings.json missing — run aggregate_findings.py first")
    root = manifest.get("repo_root", ".")
    hunks = {f["path"]: f["hunks"] for f in manifest.get("files", [])}
    sev = set(a.severities.split(","))

    selected, skipped = [], {"pre-existing": 0, "already raised": 0, "unverified": 0, "severity": 0}
    for f in agg["findings"]:
        if f["severity"] not in sev:
            skipped["severity"] += 1
        elif not f.get("in_diff", True):
            skipped["pre-existing"] += 1
        elif f.get("already_raised"):
            skipped["already raised"] += 1
        elif (f["severity"] in ("blocker", "major") and f.get("verification") in ("unverified", "uncertain")
              and not a.include_unverified) or f.get("confidence") == "low":
            skipped["unverified"] += 1
        else:
            selected.append(f)

    inline, body_items = [], []
    for f in selected:
        line = f.get("line_end") or f.get("line_start")
        if f.get("file") in hunks and line and in_hunks(line, hunks[f["file"]]):
            c = {"path": f["file"], "line": line, "side": "RIGHT", "body": comment_body(f, a.lang)}
            if f.get("line_start") and f.get("line_end") and f["line_end"] > f["line_start"] \
                    and in_hunks(f["line_start"], hunks[f["file"]]):
                c.update(start_line=f["line_start"], start_side="RIGHT")
            inline.append((f, c))
        else:
            body_items.append(f)

    verdict = agg.get("verdict", "")
    head = ("## Code review (automated)" if a.lang == "en" else "## Code review (tự động)")
    summary = [head, "", f"**Verdict:** {verdict}", "",
               f"{len(inline)} inline comment(s)" + (f", {len(body_items)} finding(s) outside the diff lines:" if body_items else ".")]
    for f in body_items:
        loc = f"{f['file']}:{f.get('line_start', '?')}"
        summary.append(f"- {SEV_ICON[f['severity']]} **{f['title']}** (`{loc}`) — {f['why']}"
                       + (f" → {f['suggestion']}" if f.get("suggestion") else "")
                       + f" {MARKER.format(fp=f['fingerprint'])}")
    ci = ctx.get("ci_summary")
    if ci and ci != "none":
        summary += ["", f"CI at review time: **{ci}**"]
    summary += ["", "<sub>Generated by the tl-code-review skill; findings were verified by a second pass where marked. "
                "Reply to a comment if it is a false positive.</sub>"]
    body = "\n".join(summary)

    preview = [f"# Review preview — event: {a.event}", "", body, "", "---", "## Inline comments", ""]
    for f, c in inline:
        preview += [f"### `{c['path']}:{c.get('start_line', c['line'])}-{c['line']}`", "", c["body"], ""]
    preview += ["---", f"Skipped: {skipped}"]
    (d / "review_preview.md").write_text("\n".join(preview), encoding="utf-8")

    if a.format == "markdown":
        print("\n".join(preview))
        return

    pr_number = ctx.get("pr_number") or (ctx.get("pr") or {}).get("number")
    if not pr_number:
        m = re.search(r"(\d+)$", str(manifest.get("pr") or ""))
        pr_number = m.group(1) if m else None

    payload = {"event": a.event, "body": body, "comments": [c for _, c in inline]}
    (d / "review_payload.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[post_review] {len(inline)} inline + {len(body_items)} in summary | skipped {skipped}")
    print(f"[post_review] preview -> {d / 'review_preview.md'}")

    if not a.confirm:
        print("[post_review] DRY RUN — nothing posted. Show the preview to the user; rerun with --confirm only after an explicit yes.")
        return
    if not selected:
        print("[post_review] nothing to post")
        return
    if not pr_number:
        sys.exit("[post_review] no PR number (run fetch_pr_context.py or resolve_scope.py --pr)")
    if not shutil.which("gh"):
        sys.exit("[post_review] gh CLI not available — use --format markdown and paste, or a connector")

    # Stale guard: the reviewed head must still be the PR head.
    code, out, _ = run(["gh", "pr", "view", str(pr_number), "--json", "headRefOid"], root)
    pr_head = (json.loads(out).get("headRefOid") if code == 0 and out.strip() else None)
    reviewed = manifest.get("head")
    _, reviewed_sha, _ = run(["git", "rev-parse", reviewed], root) if reviewed else (1, "", "")
    reviewed_sha = reviewed_sha.strip()
    if pr_head and reviewed_sha and pr_head != reviewed_sha and not a.allow_stale:
        sys.exit(f"[post_review] PR head moved ({reviewed_sha[:8]} reviewed, {pr_head[:8]} now). "
                 "Re-run the review, or pass --allow-stale.")
    if pr_head:
        payload["commit_id"] = pr_head

    # Idempotency: drop comments whose fingerprint is already on the PR.
    code, out, _ = run(["gh", "api", "--paginate", f"repos/{{owner}}/{{repo}}/pulls/{pr_number}/comments"], root)
    posted = set(MARKER_RX.findall(out or ""))
    code, out, _ = run(["gh", "api", "--paginate", f"repos/{{owner}}/{{repo}}/pulls/{pr_number}/reviews"], root)
    posted |= set(MARKER_RX.findall(out or ""))
    before = len(payload["comments"])
    payload["comments"] = [c for c in payload["comments"] if not (set(MARKER_RX.findall(c["body"])) & posted)]
    if before != len(payload["comments"]):
        print(f"[post_review] {before - len(payload['comments'])} comment(s) already posted by a previous run — skipped")
    if not payload["comments"] and not body_items:
        print("[post_review] everything was already posted")
        return

    code, out, err = run(["gh", "api", "--method", "POST", f"repos/{{owner}}/{{repo}}/pulls/{pr_number}/reviews",
                          "--input", "-"], root, input_text=json.dumps(payload))
    if code != 0:
        sys.exit(f"[post_review] post failed: {err.strip()[:400]}")
    res = json.loads(out) if out.strip() else {}
    print(f"[post_review] posted review {res.get('id')} ({a.event}) -> {res.get('html_url')}")


if __name__ == "__main__":
    main()
