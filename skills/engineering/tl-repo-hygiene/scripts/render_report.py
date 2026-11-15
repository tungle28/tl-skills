#!/usr/bin/env python3
"""Render tl-repo-hygiene findings.json into a self-contained, reviewable HTML report.

The report lists applied fixes and open proposals. Each proposal has Approve / Reject / Later and a
note; "Copy decisions" puts a Markdown list (with the report path, each item's location and an
instruction for the agent) on the clipboard for the user to paste back. Choices are kept in the
viewer's browser (localStorage) only. All text is HTML-escaped.

After approved proposals are applied, the agent records each outcome with record_fix.py in
fixes.json next to findings.json (findings.json itself is not edited). The renderer reads it:
a proposal recorded as fixed moves to "Fixed automatically" with what changed and how it was
verified (the original proposal stays in a collapsed block); partial or failed attempts are shown on
the proposal card; a "Fix results" block under the summary counts them.

Standard library only, Python 3.9+.

    python render_report.py findings.json --out report.html [--fixes fixes.json]
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

CATEGORIES = ["broken", "inconsistent", "inefficient", "inaccurate", "token-waste", "obsolete"]
SEVERITIES = ["high", "medium", "low"]
FIX_STATUSES = ["fixed", "partial", "failed"]

LABELS = {
    "en": {
        "title": "Repo hygiene", "summary": "Summary", "fixed": "Fixed automatically", "proposals": "Proposals for review",
        "checks": "Checks run", "skipped": "Skipped", "all": "All", "evidence": "Evidence", "problem": "Problem",
        "rec": "Recommendation", "risk": "Risk", "effort": "Effort", "verify": "Verified by", "files": "Files",
        "approve": "Approve", "reject": "Reject", "later": "Later", "note": "Note (optional)",
        "copy": "Copy decisions", "copied": "Copied — paste it back to the agent",
        "decided": "decided", "none_fixed": "No automatic fixes were applied.", "none_prop": "No open proposals.",
        "saving": "Est. saving", "tokens": "tokens", "generated": "Generated",
        "broken": "Broken", "inconsistent": "Inconsistent", "inefficient": "Inefficient", "inaccurate": "Inaccurate",
        "token-waste": "Token waste", "obsolete": "Obsolete", "high": "High", "medium": "Medium", "low": "Low",
        "decisions_head": "Decisions on repo-hygiene proposals",
        "head": "Apply the decisions below to the tl-repo-hygiene report `{src}`: apply only the Approve items, "
                "verify each, record each outcome with scripts/record_fix.py `{fixes}`, then render the report again.",
        "note_only": "Comment only, no decision", "copy_empty": "Choose Approve, Reject or Later on at least one proposal first.",
        "search": "Search ID, title, file…", "sev_all": "Severity: all",
        "applied": "Applied after review", "what": "What changed", "commit": "Commit", "original": "Original proposal",
        "status_fixed": "Fixed", "status_partial": "Partly fixed", "status_failed": "Fix attempt failed",
        "fix_results": "Fix results",
        "fix_line": "{fixed} fixed · {partial} partly fixed · {failed} not fixed · last update {at}",
    },
    "vi": {
        "title": "Vệ sinh repo", "summary": "Tóm tắt", "fixed": "Đã tự sửa", "proposals": "Đề xuất chờ duyệt",
        "checks": "Kiểm tra đã chạy", "skipped": "Bỏ qua", "all": "Tất cả", "evidence": "Bằng chứng", "problem": "Vấn đề",
        "rec": "Đề xuất", "risk": "Rủi ro", "effort": "Công sức", "verify": "Đã xác minh bằng", "files": "File",
        "approve": "Duyệt", "reject": "Bỏ", "later": "Để sau", "note": "Ghi chú (tuỳ chọn)",
        "copy": "Sao chép quyết định", "copied": "Đã sao chép — dán lại cho agent",
        "decided": "đã quyết", "none_fixed": "Không có sửa tự động nào.", "none_prop": "Không còn đề xuất nào.",
        "saving": "Tiết kiệm ước tính", "tokens": "token", "generated": "Tạo lúc",
        "broken": "Lỗi", "inconsistent": "Thiếu nhất quán", "inefficient": "Kém hiệu quả", "inaccurate": "Sai chuyên môn",
        "token-waste": "Lãng phí token", "obsolete": "Không còn cần", "high": "Cao", "medium": "Trung bình", "low": "Thấp",
        "decisions_head": "Quyết định cho các đề xuất repo-hygiene",
        "head": "Áp dụng các quyết định dưới đây cho báo cáo tl-repo-hygiene `{src}`: chỉ làm các mục Duyệt, "
                "xác minh từng mục, ghi kết quả từng mục bằng scripts/record_fix.py `{fixes}`, rồi dựng lại báo cáo.",
        "note_only": "Chỉ ghi chú, chưa quyết", "copy_empty": "Hãy chọn Duyệt, Bỏ hoặc Để sau cho ít nhất một đề xuất.",
        "search": "Tìm ID, tiêu đề, file…", "sev_all": "Mức độ: tất cả",
        "applied": "Áp dụng sau khi duyệt", "what": "Đã làm", "commit": "Commit", "original": "Đề xuất gốc",
        "status_fixed": "Đã sửa", "status_partial": "Sửa một phần", "status_failed": "Sửa chưa được",
        "fix_results": "Kết quả sửa",
        "fix_line": "{fixed} đã sửa · {partial} sửa một phần · {failed} chưa sửa được · cập nhật lần cuối {at}",
    },
}


def fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def validate(data: dict) -> None:
    if not isinstance(data, dict):
        fail("top level must be an object")
    for key in ("fixed", "proposals"):
        if not isinstance(data.get(key, []), list):
            fail(f"`{key}` must be a list")
    seen = set()
    for i, f in enumerate(data.get("fixed", [])):
        for k in ("id", "category", "title", "what"):
            if not f.get(k):
                fail(f"fixed[{i}] missing `{k}`")
        if f.get("severity") is not None and f["severity"] not in SEVERITIES:
            fail(f"fixed[{i}].severity must be one of {SEVERITIES}")
    for i, p in enumerate(data.get("proposals", [])):
        for k in ("id", "category", "severity", "title", "problem", "recommendation"):
            if not p.get(k):
                fail(f"proposals[{i}] missing `{k}`")
        if p["severity"] not in SEVERITIES:
            fail(f"proposals[{i}].severity must be one of {SEVERITIES}")
    for item in data.get("fixed", []) + data.get("proposals", []):
        if item["category"] not in CATEGORIES:
            fail(f"{item['id']}: category must be one of {CATEGORIES}")
        if item["id"] in seen:
            fail(f"duplicate id {item['id']}")
        seen.add(item["id"])


def load_fixes(path) -> dict:
    """{proposal id: entry} from the fixes.json record_fix.py writes; missing or unreadable -> {}."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    items = doc.get("fixes", []) if isinstance(doc, dict) else []
    return {str(x["id"]): x for x in items
            if isinstance(x, dict) and x.get("id") and x.get("status") in FIX_STATUSES}


def e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def evidence_html(ev) -> str:
    items = []
    for x in ev or []:
        if isinstance(x, str):
            items.append(f"<li><code>{e(x)}</code></li>")
            continue
        loc = e(x.get("file", ""))
        if x.get("line"):
            loc += f":{e(x['line'])}"
        note = f" — {e(x['note'])}" if x.get("note") else ""
        items.append(f"<li><code>{loc}</code>{note}</li>")
    return "<ul class='ev'>" + "".join(items) + "</ul>" if items else ""


def first_loc(p: dict) -> str:
    """The first evidence location, for the copied decision line."""
    for x in p.get("evidence") or []:
        if isinstance(x, str):
            return x
        if isinstance(x, dict) and x.get("file"):
            return x["file"] + (f":{x['line']}" if x.get("line") else "")
    return ""


def fix_lines(L: dict, f: dict) -> str:
    files = ", ".join(f"<code>{e(x)}</code>" for x in f.get("files") or [])
    return (f"<p><b>{e(L['what'])}:</b> {e(f.get('what'))}</p>"
            + (f"<p class='muted'><b>{e(L['verify'])}:</b> {e(f['verify'])}</p>" if f.get("verify") else "")
            + (f"<p class='muted'><b>{e(L['files'])}:</b> {files}</p>" if files else "")
            + (f"<p class='muted'><b>{e(L['commit'])}:</b> <code>{e(f['commit'])}</code></p>" if f.get("commit") else ""))


def summary_html(summary) -> str:
    """The summary as one bullet per point: a list of strings, or a string with one point per line
    (leading "- " is dropped). A single-line string stays a paragraph."""
    if isinstance(summary, list):
        points = [str(x).strip() for x in summary]
    else:
        points = [ln.strip().lstrip("-*• ").strip() for ln in str(summary or "").splitlines()]
    points = [p for p in points if p]
    if len(points) <= 1:
        return f"<p>{e(points[0] if points else '')}</p>"
    return "<ul class='summary'>" + "".join(f"<li>{e(p)}</li>" for p in points) + "</ul>"


def render(data: dict, fixes: dict | None = None, source: str = "", fixes_file: str = "") -> str:
    lang = data.get("language", "en")
    L = LABELS.get(lang, LABELS["en"])
    fixes = fixes or {}
    fixed, props = data.get("fixed", []), data.get("proposals", [])
    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    props = sorted(props, key=lambda p: sev_order[p["severity"]])
    # proposals applied after review: recorded as fixed in fixes.json, findings.json untouched
    applied = [p for p in props if fixes.get(p["id"], {}).get("status") == "fixed"]
    props = [p for p in props if p not in applied]

    def count(items, key, val):
        return sum(1 for x in items if x.get(key) == val)

    stat_tiles = [f"<div class='tile ok'><b>{len(fixed) + len(applied)}</b><span>{e(L['fixed'])}</span></div>"]
    for s in SEVERITIES:
        stat_tiles.append(f"<div class='tile sev-{s}'><b>{count(props, 'severity', s)}</b><span>{e(L['proposals'])} · {e(L[s])}</span></div>")
    saving = sum(int(p.get("saving_tokens") or 0) for p in props)
    if saving:
        stat_tiles.append(f"<div class='tile'><b>~{saving:,}</b><span>{e(L['saving'])} ({e(L['tokens'])})</span></div>")

    filters = [f"<button class='chip on' data-cat='all'>{e(L['all'])}</button>"]
    for c in CATEGORIES:
        n = count(props, "category", c) + count(fixed, "category", c) + count(applied, "category", c)
        if n:
            filters.append(f"<button class='chip' data-cat='{c}'>{e(L[c])} <small>{n}</small></button>")
    filters.append(f"<select id='sev' aria-label='{e(L['sev_all'])}'><option value=''>{e(L['sev_all'])}</option>"
                   + "".join(f"<option value='{s}'>{e(L[s])}</option>" for s in SEVERITIES) + "</select>")
    filters.append(f"<input type='search' id='q' placeholder='{e(L['search'])}' aria-label='{e(L['search'])}'>")

    def proposal_body(p):
        meta = []
        if p.get("effort"):
            meta.append(f"{e(L['effort'])}: <b>{e(p['effort'])}</b>")
        if p.get("saving_tokens"):
            meta.append(f"{e(L['saving'])}: <b>~{e(p['saving_tokens'])}</b> {e(L['tokens'])}")
        return (f"<h4>{e(L['problem'])}</h4><p>{e(p['problem'])}</p>"
                f"<h4>{e(L['rec'])}</h4><p>{e(p['recommendation'])}</p>"
                + (f"<h4>{e(L['risk'])}</h4><p>{e(p['risk'])}</p>" if p.get('risk') else '')
                + (f"<h4>{e(L['evidence'])}</h4>{evidence_html(p.get('evidence'))}" if p.get('evidence') else '')
                + (f"<p class='muted'>{' · '.join(meta)}</p>" if meta else ''))

    def search_text(x):
        return e(" ".join([x["id"], x["title"]] + [first_loc(x)] + list(x.get("files") or [])).lower())

    fixed_html = []
    for f in fixed:
        files = "".join(f"<li><code>{e(x)}</code></li>" for x in f.get("files", []))
        fixed_html.append(f"""
<article class="card fixed{' sev-' + e(f['severity']) if f.get('severity') else ''}" data-cat="{e(f['category'])}" data-sev="{e(f.get('severity', ''))}" data-q="{search_text(f)}">
  <header><span class="id">{e(f['id'])}</span>{f"<span class='sev'>{e(L[f['severity']])}</span>" if f.get('severity') else ''}<span class="cat">{e(L[f['category']])}</span><h3>{e(f['title'])}</h3></header>
  <p>{e(f['what'])}</p>
  {f"<p class='muted'><b>{e(L['verify'])}:</b> {e(f['verify'])}</p>" if f.get('verify') else ''}
  {f"<ul class='ev'>{files}</ul>" if files else ''}
</article>""")
    for p in applied:
        fixed_html.append(f"""
<article class="card fixed sev-{e(p['severity'])}" data-cat="{e(p['category'])}" data-sev="{e(p['severity'])}" data-q="{search_text(p)}">
  <header><span class="id">{e(p['id'])}</span><span class="sev">{e(L[p['severity']])}</span><span class="cat">{e(L[p['category']])}</span><span class="cat ok">{e(L['applied'])}</span><h3>{e(p['title'])}</h3></header>
  <div class="fixbox">{fix_lines(L, fixes[p['id']])}</div>
  <details><summary>{e(L['original'])}</summary>{proposal_body(p)}</details>
</article>""")

    prop_html = []
    for p in props:
        pid = e(p["id"])
        f = fixes.get(p["id"])
        note = (f"<div class='fixnote'><b>{e(L['status_' + f['status']])}</b>{fix_lines(L, f)}</div>" if f else "")
        prop_html.append(f"""
<article class="card prop sev-{e(p['severity'])}" data-cat="{e(p['category'])}" data-sev="{e(p['severity'])}" data-id="{pid}" data-title="{e(p['title'])}" data-loc="{e(first_loc(p))}" data-q="{search_text(p)}">
  <header><span class="id">{pid}</span><span class="sev">{e(L[p['severity']])}</span><span class="cat">{e(L[p['category']])}</span><h3>{e(p['title'])}</h3></header>
  {note}{proposal_body(p)}
  <div class="decide" role="radiogroup">
    <label><input type="radio" name="d-{pid}" value="approve"> {e(L['approve'])}</label>
    <label><input type="radio" name="d-{pid}" value="reject"> {e(L['reject'])}</label>
    <label><input type="radio" name="d-{pid}" value="later"> {e(L['later'])}</label>
    <input type="text" class="note" placeholder="{e(L['note'])}">
  </div>
</article>""")

    # "Fix results": what the review-and-apply round changed, under the summary
    recorded = [(p, fixes[p["id"]]) for p in data.get("proposals", []) if p["id"] in fixes]
    results = ""
    if recorded:
        rank = {s: i for i, s in enumerate(FIX_STATUSES)}
        recorded.sort(key=lambda pf: (rank[pf[1]["status"]], pf[0]["id"]))
        n = {s: sum(1 for _, f in recorded if f["status"] == s) for s in FIX_STATUSES}
        at = max((f.get("at") or "" for _, f in recorded), default="").replace("T", " ").replace("Z", " UTC")
        lis = "".join(f"<li><b>{e(L['status_' + f['status']])}</b> · <code>{e(p['id'])}</code> [{e(L[p['severity']])}] "
                      f"{e(p['title'])} — {e(f.get('what'))}</li>" for p, f in recorded)
        results = (f"<div class='fix-results'><h4>{e(L['fix_results'])}</h4>"
                   f"<p>{e(L['fix_line'].format(at=at or '-', **n))}</p><ul class='ev'>{lis}</ul></div>")

    checks = "".join(
        f"<li><code>{e(c.get('command'))}</code> — <b>{e(c.get('result'))}</b>{(' — ' + e(c['note'])) if c.get('note') else ''}</li>"
        for c in data.get("checks_run", [])
    )
    skipped = ", ".join(f"<code>{e(s)}</code>" for s in data.get("skipped", []))
    project = data.get("project") or Path(data.get("root", "project")).name
    storage_key = "tl-repo-hygiene:" + str(data.get("root", project)) + ":" + str(data.get("generated", ""))
    labels_js = json.dumps({**{k: L[k] for k in ("approve", "reject", "later", "copied", "copy", "decided",
                                                  "decisions_head", "note_only", "copy_empty")},
                            "head": L["head"].format(src=source or "findings.json", fixes=fixes_file or "fixes.json")},
                           ensure_ascii=False).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="{e(lang)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(L['title'])} · {e(project)}</title>
<link rel="icon" href="data:,">
<style>
:root {{ --bg:#f7f7f5; --card:#fff; --fg:#1d1d1b; --muted:#6b6b66; --line:#e3e2dd; --accent:#2f5bd3;
  --high:#c0362c; --medium:#b7791f; --low:#4a7c59; --ok:#2e7d4f; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ --bg:#151513; --card:#1f1f1c; --fg:#ecebe6;
  --muted:#a09f98; --line:#33332f; --accent:#7b9cff; --high:#ff7a6e; --medium:#e7b24f; --low:#7fc191; --ok:#6fcf97; }} }}
:root[data-theme="dark"] {{ --bg:#151513; --card:#1f1f1c; --fg:#ecebe6;
  --muted:#a09f98; --line:#33332f; --accent:#7b9cff; --high:#ff7a6e; --medium:#e7b24f; --low:#7fc191; --ok:#6fcf97; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:980px; margin:0 auto; padding:24px 16px 120px; }}
h1 {{ font-size:26px; margin:0 0 4px; }} h2 {{ font-size:19px; margin:36px 0 12px; }}
h3 {{ font-size:16px; margin:0; flex-basis:100%; }} h4 {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin:12px 0 2px; }}
p {{ margin:4px 0; }} code {{ font:13px ui-monospace,Consolas,monospace; background:var(--line); padding:1px 5px; border-radius:4px; word-break:break-all; }}
.muted {{ color:var(--muted); font-size:14px; }}
.tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin:18px 0; }}
.tile {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px; }}
.tile b {{ display:block; font-size:24px; }} .tile span {{ color:var(--muted); font-size:13px; }}
.tile.ok b {{ color:var(--ok); }} .tile.sev-high b {{ color:var(--high); }} .tile.sev-medium b {{ color:var(--medium); }} .tile.sev-low b {{ color:var(--low); }}
.filters {{ display:flex; flex-wrap:wrap; gap:6px; align-items:center; position:sticky; top:0; background:var(--bg); padding:10px 0; z-index:2; }}
.chip {{ border:1px solid var(--line); background:var(--card); color:var(--fg); border-radius:999px; padding:4px 12px; cursor:pointer; font:inherit; font-size:13px; }}
.chip.on {{ border-color:var(--accent); color:var(--accent); }}
.filters select, .filters input {{ font:inherit; font-size:13px; padding:4px 8px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--fg); }}
.filters input {{ flex:1 1 180px; min-width:0; }}
.card {{ background:var(--card); border:1px solid var(--line); border-left:4px solid var(--line); border-radius:10px; padding:14px 16px; margin:10px 0; }}
.card.sev-high {{ border-left-color:var(--high); }} .card.sev-medium {{ border-left-color:var(--medium); }} .card.sev-low {{ border-left-color:var(--low); }}
.card.card.fixed {{ border-left-color:var(--ok); }}
.card header {{ display:flex; flex-wrap:wrap; gap:6px; align-items:center; margin-bottom:6px; }}
.id,.sev,.cat {{ font-size:12px; padding:1px 8px; border-radius:999px; border:1px solid var(--line); color:var(--muted); }}
.sev-high .sev {{ color:var(--high); border-color:var(--high); }} .sev-medium .sev {{ color:var(--medium); border-color:var(--medium); }}
.sev-low .sev {{ color:var(--low); border-color:var(--low); }} .cat.ok {{ color:var(--ok); border-color:var(--ok); }}
.ev {{ margin:4px 0; padding-left:20px; font-size:14px; }} .summary {{ margin:4px 0; padding-left:20px; }} .summary li {{ margin:3px 0; }}
.fixbox {{ margin:8px 0; padding:8px 12px; border-radius:8px; background:var(--bg); }}
.fixnote {{ margin:8px 0; padding:8px 12px; border-radius:8px; border:1px dashed var(--medium); font-size:14px; }}
.fix-results {{ margin:12px 0; padding:10px 14px; border:1px solid var(--line); border-left:4px solid var(--ok); border-radius:8px; background:var(--card); }}
details {{ margin-top:8px; }} summary {{ cursor:pointer; color:var(--muted); }}
.decide {{ display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin-top:12px; padding-top:10px; border-top:1px dashed var(--line); }}
.decide label {{ cursor:pointer; }} .note {{ flex:1 1 200px; min-width:0; padding:6px 8px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--fg); font:inherit; }}
.card.d-approve {{ outline:2px solid var(--ok); }} .card.d-reject {{ opacity:.6; }}
.bar {{ position:fixed; left:0; right:0; bottom:0; background:var(--card); border-top:1px solid var(--line); padding:10px 16px; display:flex; gap:12px; align-items:center; justify-content:center; z-index:3; }}
.bar[hidden] {{ display:none; }}
.bar button {{ background:var(--accent); color:#fff; border:0; border-radius:8px; padding:8px 16px; font:inherit; cursor:pointer; }}
.hidden {{ display:none; }}
@media print {{ .filters, .bar, .decide {{ display:none; }} body {{ background:#fff; color:#000; }} }}
</style>
</head>
<body>
<main>
<h1>{e(L['title'])} · {e(project)}</h1>
<p class="muted">{e(data.get('root', ''))} · {e(L['generated'])}: {e(data.get('generated', ''))}</p>
<div class="tiles">{''.join(stat_tiles)}</div>
<h2>{e(L['summary'])}</h2>
{summary_html(data.get('summary'))}
{results}
{f"<h4>{e(L['checks'])}</h4><ul class='ev'>{checks}</ul>" if checks else ''}
{f"<p class='muted'>{e(L['skipped'])}: {skipped}</p>" if skipped else ''}
<div class="filters">{''.join(filters)}</div>
<h2>{e(L['proposals'])} ({len(props)})</h2>
{''.join(prop_html) or f"<p class='muted'>{e(L['none_prop'])}</p>"}
<h2>{e(L['fixed'])} ({len(fixed) + len(applied)})</h2>
{''.join(fixed_html) or f"<p class='muted'>{e(L['none_fixed'])}</p>"}
</main>
<div class="bar"><span id="progress" class="muted"></span><button id="copy" type="button"></button></div>
<script>
(function () {{
  var L = {labels_js};
  var KEY = {json.dumps(storage_key, ensure_ascii=False).replace("</", "<\\/")};
  var state = {{}};
  try {{ state = JSON.parse(localStorage.getItem(KEY) || "{{}}") || {{}}; }} catch (err) {{ state = {{}}; }}
  function save() {{ try {{ localStorage.setItem(KEY, JSON.stringify(state)); }} catch (err) {{}} }}
  var cards = Array.prototype.slice.call(document.querySelectorAll(".card.prop"));
  var copyBtn = document.getElementById("copy");
  if (!cards.length) {{ document.querySelector(".bar").hidden = true; }}
  copyBtn.textContent = L.copy;
  function set(id, k, v) {{ var s = state[id] = state[id] || {{}}; if (v) s[k] = v; else delete s[k];
    if (!s.d && !s.n) delete state[id]; save(); }}
  function refresh() {{
    var n = 0;
    cards.forEach(function (c) {{
      var s = state[c.dataset.id] || {{}};
      c.classList.remove("d-approve", "d-reject", "d-later");
      if (s.d) {{ c.classList.add("d-" + s.d); n++; }}
    }});
    document.getElementById("progress").textContent = n + " / " + cards.length + " " + L.decided;
  }}
  cards.forEach(function (c) {{
    var id = c.dataset.id, s = state[id] || {{}};
    c.querySelectorAll("input[type=radio]").forEach(function (r) {{
      if (s.d === r.value) r.checked = true;
      r.addEventListener("change", function () {{ set(id, "d", r.value); refresh(); }});
    }});
    var note = c.querySelector(".note");
    note.value = s.n || "";
    note.addEventListener("input", function () {{ set(id, "n", note.value); }});
  }});
  var cat = "all", sev = document.getElementById("sev"), q = document.getElementById("q");
  function filter() {{
    var text = q.value.trim().toLowerCase();
    document.querySelectorAll(".card").forEach(function (c) {{
      var on = (cat === "all" || c.dataset.cat === cat) && (!sev.value || c.dataset.sev === sev.value)
        && (!text || (c.dataset.q || "").indexOf(text) >= 0);
      c.classList.toggle("hidden", !on);
    }});
  }}
  document.querySelectorAll(".chip").forEach(function (chip) {{
    chip.addEventListener("click", function () {{
      document.querySelectorAll(".chip").forEach(function (x) {{ x.classList.remove("on"); }});
      chip.classList.add("on"); cat = chip.dataset.cat; filter();
    }});
  }});
  sev.addEventListener("change", filter); q.addEventListener("input", filter);
  function one(s) {{ return String(s || "").replace(/\\s+/g, " ").trim(); }}
  copyBtn.addEventListener("click", function () {{
    var groups = {{ approve: [], reject: [], later: [], note: [] }}, n = 0;
    cards.forEach(function (c) {{
      var s = state[c.dataset.id];
      if (!s) return;
      n++;
      groups[s.d || "note"].push("- " + c.dataset.id + " " + one(c.dataset.title) +
        (c.dataset.loc ? " — `" + c.dataset.loc + "`" : "") + (s.n ? " — " + one(s.n) : ""));
    }});
    if (!n) {{ alert(L.copy_empty); return; }}
    var out = [L.head, "", "## " + L.decisions_head];
    ["approve", "reject", "later", "note"].forEach(function (k) {{
      if (groups[k].length) out.push("", "### " + (k === "note" ? L.note_only : L[k]) + " (" + groups[k].length + ")", groups[k].join("\\n"));
    }});
    var text = out.join("\\n");
    function done() {{ copyBtn.textContent = L.copied; setTimeout(function () {{ copyBtn.textContent = L.copy; }}, 2500); }}
    function fallback() {{
      var ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select(); var ok = false;
      try {{ ok = document.execCommand("copy"); }} catch (err) {{}}
      document.body.removeChild(ta); if (ok) done(); else window.prompt(L.copy, text);
    }}
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(text).then(done, fallback);
    }} else {{ fallback(); }}
  }});
  // the copy button belongs where decisions are made: show it only while a proposal card is on screen
  var bar = document.querySelector(".bar");
  if (cards.length && window.IntersectionObserver) {{
    var onScreen = new Set(); bar.hidden = true;
    var io = new IntersectionObserver(function (es) {{
      es.forEach(function (e) {{ if (e.isIntersecting) onScreen.add(e.target); else onScreen.delete(e.target); }});
      bar.hidden = !onScreen.size;
    }});
    cards.forEach(function (c) {{ io.observe(c); }});
  }}
  refresh();
}})();
</script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("findings")
    ap.add_argument("--out", required=True)
    ap.add_argument("--fixes", help="fix outcomes from record_fix.py (default: fixes.json next to findings.json)")
    args = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    src = Path(args.findings)
    try:
        data = json.loads(src.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"cannot read {args.findings}: {err}")
    validate(data)
    fixes_file = Path(args.fixes) if args.fixes else src.with_name("fixes.json")
    fixes = load_fixes(fixes_file)
    unknown = sorted(set(fixes) - {p["id"] for p in data.get("proposals", [])})
    if unknown:  # a typo in record_fix.py --id, or an id of an automatic fix, would vanish without a trace
        print(f"warning: fixes.json ids with no matching proposal: {', '.join(unknown)}", file=sys.stderr)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(data, fixes, str(src.resolve()), str(fixes_file.resolve())), encoding="utf-8")
    applied = sum(1 for p in data.get("proposals", []) if fixes.get(p["id"], {}).get("status") == "fixed")
    print(f"report: {out.resolve()} ({len(data.get('fixed', []))} fixed, {len(data.get('proposals', [])) - applied} "
          f"proposals" + (f", {applied} applied after review" if applied else "") + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
