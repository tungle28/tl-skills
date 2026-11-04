"""Render a harness code review as one self-contained HTML page for review.

    python render_html.py --dir $RUN             # -> $RUN/report.html
    python render_html.py --dir $RUN --lang vi -o out.html
    python render_html.py --dir $RUN --lang vi --template card

Run it after aggregate_findings.py. The default template (tabs) has two tabs: Report (report.md as
written, with a section nav) and Findings (every finding from findings.json in one table, filterable by
severity, category, verification, bucket and free text; a row expands to the evidence, why it matters,
the failure scenario and the fix). The card template is a printable summary: PR facts, count cards,
one card per finding grouped as verified, needing confirmation, minor and rejected, then coverage and
open items. Standard library only; the page works offline (no external scripts, fonts or stylesheets).
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under `python -I`
import run_dir  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# ============================================================================ shared core
# Identical in tl-security-audit, tl-code-refactor and tl-code-review (each skill installs on its
# own, so the core is copied, not imported). Change one copy, then copy the block to the others.

TABLE_SEP_RE = re.compile(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
LIST_RE = re.compile(r"^(\s*)([-*]|\d+[.)])\s+(.*)$")


def slugify(text):
    slug = re.sub(r"[^\w\s-]", "", text.lower(), flags=re.UNICODE)
    return re.sub(r"[\s_]+", "-", slug).strip("-") or "section"


class Markdown:
    """The Markdown subset the skills' report.md files use: headings, pipe tables, nested lists,
    fenced code, <details>/<summary> lines, inline code, bold, italic and links. Table cells that are
    exactly a severity name get a badge."""

    def __init__(self, severities):
        self.sev = [s.lower() for s in severities]

    def badge(self, text):
        key = re.sub(r"[*_`\s]", "", text).lower()
        if key in self.sev:
            return f'<span class="sev s{self.sev.index(key)}">{html.escape(key)}</span>'
        return None

    def inline(self, text):
        codes = []

        def keep(m):
            codes.append(m.group(1))
            return f"\x00{len(codes) - 1}\x00"

        text = re.sub(r"`([^`]+)`", keep, text)
        text = html.escape(text, quote=False)
        text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)",
                      lambda m: f'<a href="{html.escape(m.group(2))}">{m.group(1)}</a>', text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", text)
        text = re.sub(r"(?<![\w_])_(?!\s)(.+?)(?<!\s)_(?![\w_])", r"<em>\1</em>", text)
        return re.sub(r"\x00(\d+)\x00",
                      lambda m: f"<code>{html.escape(codes[int(m.group(1))], quote=False)}</code>", text)

    @staticmethod
    def split_row(line):
        line = line.strip()
        line = line[1:] if line.startswith("|") else line
        line = line[:-1] if line.endswith("|") and not line.endswith("\\|") else line
        cells, buf, in_code, i = [], "", False, 0
        while i < len(line):
            ch = line[i]
            if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
                buf += "|"
                i += 2
                continue
            if ch == "`":
                in_code = not in_code
            if ch == "|" and not in_code:
                cells.append(buf.strip())
                buf = ""
            else:
                buf += ch
            i += 1
        cells.append(buf.strip())
        return cells

    def cell(self, text):
        return self.badge(text) or self.inline(text)

    def convert(self, md):
        """Return (body_html, [(anchor, h2 title)])."""
        lines = md.splitlines()
        out, sections, stack, para, used = [], [], [], [], set()
        i = 0

        def close_para():
            if para:
                out.append(f"<p>{self.inline(' '.join(para))}</p>")
                para.clear()

        def close_lists():
            while stack:
                out.append(f"</li></{stack.pop()}>")

        def anchor(title):
            base = a = slugify(title)
            n = 2
            while a in used:
                a, n = f"{base}-{n}", n + 1
            used.add(a)
            return a

        while i < len(lines):
            line = lines[i]
            s = line.strip()
            if s.startswith("```"):
                close_para(); close_lists()
                i += 1
                code = []
                while i < len(lines) and not lines[i].strip().startswith("```"):
                    code.append(lines[i])
                    i += 1
                out.append(f"<pre><code>{html.escape(chr(10).join(code), quote=False)}</code></pre>")
                i += 1
                continue
            m = re.match(r"^<details>\s*<summary>(.*)</summary>\s*$", s)
            if m or s in ("<details>", "</details>"):
                close_para(); close_lists()
                out.append(f"<details><summary>{self.inline(m.group(1))}</summary>" if m else s)
                i += 1
                continue
            m = re.match(r"^(#{1,6})\s+(.*)$", s)
            if m:
                close_para(); close_lists()
                level, title = min(len(m.group(1)), 4), m.group(2).strip()
                if level == 1:
                    out.append(f"<h1>{self.inline(title)}</h1>")
                else:
                    a = anchor(title)
                    if level == 2:
                        sections.append((a, title))
                    out.append(f'<h{level} id="{a}">{self.inline(title)}</h{level}>')
                i += 1
                continue
            if s.startswith("|") and i + 1 < len(lines) and TABLE_SEP_RE.match(lines[i + 1].strip()):
                close_para(); close_lists()
                head = self.split_row(s)
                i += 2
                out.append('<div class="table-wrap"><table><thead><tr>'
                           + "".join(f"<th>{self.inline(c)}</th>" for c in head) + "</tr></thead><tbody>")
                while i < len(lines) and lines[i].strip().startswith("|"):
                    out.append("<tr>" + "".join(f"<td>{self.cell(c)}</td>"
                                                for c in self.split_row(lines[i])) + "</tr>")
                    i += 1
                out.append("</tbody></table></div>")
                continue
            m = LIST_RE.match(line)
            if m:
                close_para()
                depth = len(m.group(1).expandtabs(2)) // 2 + 1
                tag = "ol" if m.group(2)[0].isdigit() else "ul"
                if depth > len(stack):
                    while depth > len(stack):
                        out.append(f"<{tag}>")
                        stack.append(tag)
                else:
                    while len(stack) > depth:
                        out.append(f"</li></{stack.pop()}>")
                    out.append("</li>")
                out.append(f"<li>{self.inline(m.group(3))}")
                i += 1
                continue
            if not s:
                close_para(); close_lists()
            elif stack:
                out[-1] += " " + self.inline(s)
            else:
                para.append(s)
            i += 1
        close_para(); close_lists()
        return "\n".join(out), sections


CSS = """
:root{--bg:#fbfbfa;--panel:#fff;--text:#1f2328;--muted:#5f6670;--border:#e3e5e8;--accent:#2f6fd1;--code-bg:#f2f3f5;
--s0:#b42318;--s0-bg:#fdecec;--s1:#c2410c;--s1-bg:#fdefe3;--s2:#a16207;--s2-bg:#fdf6dc;--s3:#1d5fa8;--s3-bg:#e8f1fb;--s4:#4b5563;--s4-bg:#eef0f3}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#15171a;--panel:#1d2024;--text:#e6e8eb;--muted:#9aa3ad;
--border:#30343a;--accent:#79a8f0;--code-bg:#262a30;--s0:#f28b82;--s0-bg:#3b1f1f;--s1:#f6a35c;--s1-bg:#3a2614;--s2:#e8c65a;
--s2-bg:#352d12;--s3:#8ab8f0;--s3-bg:#1b2a3d;--s4:#b6bec8;--s4-bg:#2a2e34}}
:root[data-theme="dark"]{--bg:#15171a;--panel:#1d2024;--text:#e6e8eb;--muted:#9aa3ad;--border:#30343a;--accent:#79a8f0;
--code-bg:#262a30;--s0:#f28b82;--s0-bg:#3b1f1f;--s1:#f6a35c;--s1-bg:#3a2614;--s2:#e8c65a;--s2-bg:#352d12;--s3:#8ab8f0;
--s3-bg:#1b2a3d;--s4:#b6bec8;--s4-bg:#2a2e34}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{position:sticky;top:0;z-index:2;background:var(--bg);border-bottom:1px solid var(--border)}
.bar{display:flex;gap:8px;align-items:center;max-width:1320px;margin:0 auto;padding:10px 16px}
.bar .title{font-weight:600;margin-right:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
button{font:inherit;font-size:13px;padding:4px 12px;border-radius:16px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer;white-space:nowrap}
button[aria-selected="true"],button[aria-pressed="true"]{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
.layout{display:grid;grid-template-columns:220px minmax(0,1fr);gap:32px;max-width:1320px;margin:0 auto;padding:20px 16px}
.layout.wide{grid-template-columns:minmax(0,1fr)}
nav{position:sticky;top:64px;align-self:start;font-size:14px;max-height:calc(100vh - 80px);overflow:auto}
nav a{display:block;padding:4px 8px;border-radius:6px;color:var(--muted);text-decoration:none}
nav a:hover{background:var(--code-bg);color:var(--text)}
main{min-width:0}p,li{overflow-wrap:break-word}
.panel[hidden],nav[hidden]{display:none}
h1{font-size:25px;margin:0 0 12px}h2{font-size:19px;margin:34px 0 12px;padding-top:12px;border-top:1px solid var(--border)}
h3{font-size:16px;margin:24px 0 8px}h4{font-size:15px;margin:20px 0 6px}
a{color:var(--accent)}
code{font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;background:var(--code-bg);padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--code-bg);padding:12px;border-radius:8px;overflow-x:auto;margin:8px 0}pre code{padding:0;background:none;overflow-wrap:normal}
details{margin:8px 0}summary{cursor:pointer;color:var(--muted)}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:8px;background:var(--panel);margin:8px 0}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--border)}
th{background:var(--code-bg);font-weight:600;white-space:nowrap}tr:last-child td{border-bottom:none}
.sev{display:inline-block;font-weight:700;font-size:12px;padding:0 8px;border-radius:10px;line-height:20px;white-space:nowrap}
.s0{color:var(--s0);background:var(--s0-bg)}.s1{color:var(--s1);background:var(--s1-bg)}.s2{color:var(--s2);background:var(--s2-bg)}
.s3{color:var(--s3);background:var(--s3-bg)}.s4{color:var(--s4);background:var(--s4-bg)}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 12px}
.filters select,.filters input{font:inherit;font-size:13px;padding:4px 8px;border-radius:8px;border:1px solid var(--border);background:var(--panel);color:var(--text)}
.filters input{min-width:200px;flex:1}
.count{color:var(--muted);font-size:13px;margin:0 0 8px}
#rows tr.f{cursor:pointer}#rows tr.f:hover td{background:var(--code-bg)}
#rows tr.f td:first-child{white-space:nowrap}#rows tr.f td:nth-child(4){min-width:24ch}
#rows tr.d td{background:var(--code-bg);padding:12px 16px}
.dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 16px;margin:0;position:sticky;left:16px;max-width:min(1100px,calc(100vw - 64px))}
.dl dt{font-weight:600;color:var(--muted)}.dl dd{margin:0;overflow-wrap:anywhere}
.empty{color:var(--muted);padding:16px}
@media (max-width:860px){.layout{grid-template-columns:1fr;gap:8px}nav{position:static;max-height:none;display:flex;flex-wrap:wrap;gap:4px}
.dl{grid-template-columns:1fr}.filters input{min-width:0}}
@media print{header,nav,.filters{display:none}.layout{display:block;padding:0}.panel[hidden]{display:block}body{background:#fff;color:#000}}
"""

JS = """
(function(){
  var data=JSON.parse(document.getElementById("data").textContent);
  var sevs=data.severities, rows=data.rows, facets=data.facets;
  function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];});}
  function md(s){return esc(s).replace(/`([^`]+)`/g,"<code>$1</code>").replace(/\\*\\*(.+?)\\*\\*/g,"<strong>$1</strong>");}
  function badge(s){var i=sevs.indexOf(s);return '<span class="sev s'+(i<0?4:i)+'">'+esc(s)+'</span>';}
  // tabs
  var tabs=document.querySelectorAll("[data-tab]");
  function show(name){tabs.forEach(function(t){var on=t.getAttribute("data-tab")===name;t.setAttribute("aria-selected",on);
    document.getElementById("panel-"+t.getAttribute("data-tab")).hidden=!on;});
    document.getElementById("nav").hidden=name!=="report";
    document.querySelector(".layout").classList.toggle("wide",name!=="report");try{location.hash=name==="report"?"":"findings";}catch(e){}}
  tabs.forEach(function(t){t.addEventListener("click",function(){show(t.getAttribute("data-tab"));});});
  // filters
  var active=new Set(sevs), f=document.getElementById("filters");
  sevs.forEach(function(s){var n=rows.filter(function(r){return r.sev===s;}).length;if(!n)return;
    var b=document.createElement("button");b.type="button";b.setAttribute("aria-pressed","true");
    b.innerHTML=badge(s)+" "+n;b.addEventListener("click",function(){if(active.has(s))active.delete(s);else active.add(s);
    b.setAttribute("aria-pressed",active.has(s));draw();});f.appendChild(b);});
  var sel={};
  facets.forEach(function(k){var vals=Array.from(new Set(rows.map(function(r){return r.facets[k];}).filter(Boolean))).sort();
    if(vals.length<2)return;var s=document.createElement("select");s.setAttribute("aria-label",k);
    s.innerHTML='<option value="">'+esc(k)+': all</option>'+vals.map(function(v){return '<option>'+esc(v)+'</option>';}).join("");
    s.addEventListener("change",draw);sel[k]=s;f.appendChild(s);});
  var q=document.createElement("input");q.type="search";q.placeholder="Search ID, title, file…";q.addEventListener("input",draw);f.appendChild(q);
  var open=new Set();
  function draw(){var text=q.value.trim().toLowerCase(),html="",shown=0;
    rows.forEach(function(r,i){if(!active.has(r.sev))return;
      for(var k in sel){if(sel[k].value&&r.facets[k]!==sel[k].value)return;}
      if(text&&(r.id+" "+r.title+" "+r.loc).toLowerCase().indexOf(text)<0)return;shown++;
      html+='<tr class="f" data-i="'+i+'" tabindex="0" aria-expanded="'+open.has(i)+'"><td>'+esc(r.id)+'</td><td>'+badge(r.sev)+'</td><td>'+md(r.title)+
        '</td><td><code>'+esc(r.loc)+'</code></td>'+facets.map(function(k){return '<td>'+esc(r.facets[k]||"")+'</td>';}).join("")+'</tr>';
      if(open.has(i))html+='<tr class="d"><td colspan="'+(4+facets.length)+'"><dl class="dl">'+r.details.map(function(d){
        return '<dt>'+esc(d[0])+'</dt><dd>'+(d[2]?'<pre><code>'+esc(d[1])+'</code></pre>':md(d[1]))+'</dd>';}).join("")+'</dl></td></tr>';});
    document.getElementById("rows").innerHTML=html||'<tr><td class="empty" colspan="'+(4+facets.length)+'">No findings match the filters.</td></tr>';
    document.getElementById("count").textContent=shown+" of "+rows.length+" findings";}
  function toggle(tr){var i=+tr.getAttribute("data-i");if(open.has(i))open.delete(i);else open.add(i);draw();}
  document.getElementById("rows").addEventListener("click",function(e){var tr=e.target.closest("tr.f");if(tr&&!getSelection().toString())toggle(tr);});
  document.getElementById("rows").addEventListener("keydown",function(e){var tr=e.target.closest("tr.f");if(tr&&(e.key==="Enter"||e.key===" ")){e.preventDefault();toggle(tr);}});
  document.getElementById("theme").addEventListener("click",function(){var r=document.documentElement;
    var dark=r.getAttribute("data-theme")==="dark"||(!r.getAttribute("data-theme")&&matchMedia("(prefers-color-scheme: dark)").matches);
    r.setAttribute("data-theme",dark?"light":"dark");});
  draw();show(location.hash==="#findings"?"findings":"report");
})();
"""


def page(report_md, rows, severities, facets, lang):
    """rows: [{id, sev, title, loc, facets: {name: value}, details: [[label, text, is_code], ...]}]."""
    body, sections = Markdown(severities).convert(report_md)
    m = re.search(r"^#\s+(.*)$", report_md, re.M)
    title = re.sub(r"[`*]", "", m.group(1)).strip() if m else "Report"
    nav = "".join(f'<a href="#{a}">{Markdown(severities).inline(t)}</a>' for a, t in sections)
    head_cells = "".join(f"<th>{html.escape(h)}</th>" for h in ["ID", "Severity", "Title", "Location", *facets])
    data = json.dumps({"severities": severities, "facets": facets, "rows": rows}, ensure_ascii=False)
    data = data.replace("</", "<\\/")  # the JSON sits inside a <script> element
    return (f'<!doctype html><html lang="{html.escape(lang)}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>'
            f'<link rel="icon" href="data:,"><style>{CSS}</style></head><body>'
            f'<header><div class="bar"><span class="title">{html.escape(title)}</span>'
            f'<button type="button" data-tab="report" aria-selected="true">Report</button>'
            f'<button type="button" data-tab="findings" aria-selected="false">Findings ({len(rows)})</button>'
            f'<button type="button" id="theme" title="Switch light/dark">◐</button></div></header>'
            f'<div class="layout"><nav id="nav" aria-label="Sections">{nav}</nav><main>'
            f'<section id="panel-report" class="panel">{body}</section>'
            f'<section id="panel-findings" class="panel" hidden><div class="filters" id="filters"></div>'
            f'<p class="count" id="count"></p><div class="table-wrap"><table><thead><tr>{head_cells}</tr></thead>'
            f'<tbody id="rows"></tbody></table></div></section></main></div>'
            f'<script type="application/json" id="data">{data}</script><script>{JS}</script></body></html>')


def write_page(out, report_md, rows, severities, facets, lang):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page(report_md, rows, severities, facets, lang), encoding="utf-8")
    print(f"{out.resolve()} ({len(rows)} findings)")

# ============================================================================ end shared core


SEVERITIES = ["blocker", "major", "minor", "nit"]


def location(f):
    loc = f.get("file", "?")
    if f.get("line_start"):
        loc += f":{f['line_start']}"
        if f.get("line_end") and f["line_end"] != f["line_start"]:
            loc += f"-{f['line_end']}"
    return loc


def bucket(f, is_diff):
    # Mirrors aggregate_findings.py: pre-existing (outside the diff), then needs-check, then main.
    if is_diff and not f.get("in_diff", True):
        return "pre-existing"
    if f.get("confidence") == "low" or f.get("verification") == "uncertain" or (
            f.get("verification") == "unverified" and (
            f.get("severity") == "blocker" or (f.get("severity") == "major" and f.get("confidence") != "high"))):
        return "needs-check"
    return "main"


def rows_from(d):
    doc = json.loads((d / "findings.json").read_text(encoding="utf-8"))
    manifest = {}
    if (d / "manifest.json").exists():
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    is_diff = manifest.get("mode") in ("uncommitted", "staged", "changeset")  # as aggregate_findings.py
    found = sorted(doc.get("findings", []),
                   key=lambda f: (SEVERITIES.index(f["severity"]) if f.get("severity") in SEVERITIES else 9, f["id"]))
    rows = []
    for f in found:
        meta = " · ".join(x for x in (f"confidence {f.get('confidence')}",
                                      "already raised on the PR" if f.get("already_raised") else "",
                                      "also reported as " + ", ".join(f["also_reported_as"])
                                      if f.get("also_reported_as") else "") if x)
        details = [["Details", meta, False]]
        if f.get("evidence"):
            details.append(["Evidence", f["evidence"].rstrip(), True])
        details += [[label, f[key], False] for label, key in (
            ("Why it matters", "why"), ("Failure scenario", "scenario"), ("Suggested fix", "suggestion"),
            ("Verifier", "verify_note")) if f.get(key)]
        rows.append({"id": f["id"], "sev": f.get("severity", ""), "title": f.get("title", ""), "loc": location(f),
                     "facets": {"Category": f.get("category", ""), "Verification": f.get("verification", ""),
                                "Bucket": bucket(f, is_diff)},
                     "details": details})
    return rows


# ============================================================================ card template

CARD_CSS = """
:root{--bg:#f6f7f5;--card:#fff;--ink:#1c2321;--mute:#5c6762;--line:#dde2de;--accent:#2f6b57;--blk:#a1262b;--maj:#b45309;--min:#456b8f;--ok:#2f6b57;--bad:#8a5a00;--code:#eef1ee;--maj-bg:#fdf1e3;--min-bg:#eaf1f7;--wait-bg:#fff7d6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121615;--card:#1b211f;--ink:#e6ece9;--mute:#9aa7a1;--line:#2c3532;--accent:#6fc3a6;--blk:#ff8a8f;--maj:#f4a85a;--min:#8fb8de;--ok:#6fc3a6;--bad:#f2c36b;--code:#232b28;--maj-bg:#33261a;--min-bg:#1d2a37;--wait-bg:#3a3318}}
:root[data-theme="dark"]{--bg:#121615;--card:#1b211f;--ink:#e6ece9;--mute:#9aa7a1;--line:#2c3532;--accent:#6fc3a6;--blk:#ff8a8f;--maj:#f4a85a;--min:#8fb8de;--ok:#6fc3a6;--bad:#f2c36b;--code:#232b28;--maj-bg:#33261a;--min-bg:#1d2a37;--wait-bg:#3a3318}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;line-height:1.25;margin:0 0 4px}
h2{font-size:1.2rem;margin:36px 0 12px;padding-top:12px;border-top:1px solid var(--line)}
h3{font-size:1rem;margin:0}
p{margin:0 0 10px}
code{background:var(--code);padding:1px 5px;border-radius:4px;font-size:.88em;overflow-wrap:anywhere}
pre{background:var(--code);padding:8px 10px;border-radius:6px;overflow-x:auto;margin:0;font-size:.85rem}pre code{padding:0;background:none;overflow-wrap:normal}
.sub{color:var(--mute);margin-bottom:16px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin:12px 0}
.meta div{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.meta b{display:block;font-size:.75rem;color:var(--mute);text-transform:uppercase;letter-spacing:.04em;font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
.cards .c{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.cards .n{font-size:1.9rem;font-weight:700;line-height:1.1}
.cards .l{color:var(--mute);font-size:.85rem}
.n.blk{color:var(--blk)}.n.maj{color:var(--maj)}.n.min{color:var(--min)}
.wait{background:var(--wait-bg);border:1px solid var(--maj);border-radius:10px;padding:10px 12px;margin:12px 0}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);border-radius:10px;font-size:.92rem}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mute)}
.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--min);border-radius:10px;padding:12px 14px;margin:12px 0}
.f.blk{border-left-color:var(--blk)}.f.maj{border-left-color:var(--maj)}.f.wait{border-left-color:var(--maj);background:var(--wait-bg)}.f.drop{border-left-color:var(--mute);opacity:.92}
.f header{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;margin-bottom:8px}
.id{font-weight:700;color:var(--accent)}
.badge{display:inline-block;border-radius:999px;padding:1px 10px;font-size:.78rem;font-weight:600;border:1px solid currentColor;white-space:nowrap}
td:first-child{white-space:nowrap}
.b-blk{color:var(--blk)}.b-maj{color:var(--maj)}.b-min{color:var(--min)}.b-ok{color:var(--ok)}.b-bad{color:var(--bad)}.b-mute{color:var(--mute)}
dl{margin:0;display:grid;grid-template-columns:max-content 1fr;gap:4px 12px}
dt{color:var(--mute);font-size:.85rem}
dd{margin:0;overflow-wrap:anywhere;min-width:0}
@media (max-width:560px){dl{grid-template-columns:1fr}dt{margin-top:6px}}
ul{margin:6px 0 10px;padding-left:20px}
li{margin:3px 0}
footer{margin-top:40px;color:var(--mute);font-size:.85rem;border-top:1px solid var(--line);padding-top:12px}
@media print{body{background:#fff;color:#000}.f,.cards .c,.meta div{break-inside:avoid}}
"""

CARD_TEXT = {
    "en": {
        "title": "Code review", "title_pr": "Code review PR #{n}", "head": "Head", "base": "Base",
        "size": "Size", "size_v": "{files} files (+{added} / −{deleted})", "verdict": "Verdict", "ci": "CI",
        "s_summary": "1. Summary", "s_serious": "2. Blockers and majors", "s_check": "3. Needs human confirmation",
        "s_minor": "4. Minor and nit", "s_dropped": "5. Rejected and pre-existing", "s_scope": "6. Coverage",
        "s_open": "7. Open items",
        "c_blocker": "Blocker", "c_major": "Major", "c_check": "Needs confirmation", "c_minor": "Minor",
        "c_nit": "Nit", "c_rejected": "Rejected by the verifier",
        "wait": "<b>Not confirmed yet:</b> {n} finding(s) in section 3 were not verified, are uncertain or have "
                "low confidence. They are counted apart from the verified ones until someone confirms them.",
        "wait_section": "<b>Not confirmed.</b> Severity below is the reviewer's; treat it as final only after a "
                        "second check.",
        "t_id": "ID", "t_from": "Initial", "t_to": "Final", "t_ver": "Verification", "t_title": "Finding",
        "none": "None.",
        "f_file": "File", "f_evidence": "Evidence", "f_why": "Why it matters", "f_scenario": "Failure scenario",
        "f_fix": "Suggested fix", "f_verifier": "Verifier", "f_also": "Also reported as",
        "f_raised": "Raised on the PR", "f_category": "Category", "f_confidence": "Confidence",
        "f_reason": "Why rejected", "initial": "Initial: {s}",
        "v_confirmed": "Verified", "v_unverified": "Not verified", "v_uncertain": "Uncertain",
        "v_rejected": "Rejected", "pre": "Pre-existing",
        "reviewed": "<b>Reviewed:</b>", "not_reviewed": "<b>Not reviewed or not checked:</b>",
        "shard_files": "{shard}: {n} file(s)", "shard_skipped": "{shard}: skipped {what}",
        "overflow": "Deferred low-risk shards: {n} ({names})", "truncated": "Files beyond the file cap: {n}",
        "no_tests": "Production code changed with no test files in the diff.",
        "tools_off": "Static tools not run.", "pr_off": "PR platform context unavailable ({why}).",
        "positives": "<b>Looks right:</b>",
        "o_check": "Confirm {ids} with a second check.", "o_req": "Requirement {ticket}: {criterion} ({status}).",
        "o_ci": "CI is failing.", "o_tests": "Add tests for the changed production code.",
        "footer": "Generated by tl-code-review from <code>{dir}</code>. Verdict and counts come from "
                  "aggregate_findings.py; nothing was added by hand.",
    },
    "vi": {
        "title": "Review code", "title_pr": "Review code PR #{n}", "head": "Head", "base": "Base",
        "size": "Quy mô", "size_v": "{files} file (+{added} / −{deleted})", "verdict": "Kết luận", "ci": "CI",
        "s_summary": "1. Tóm tắt kết luận", "s_serious": "2. Blocker và major", "s_check": "3. Cần người xác nhận",
        "s_minor": "4. Minor và nit", "s_dropped": "5. Finding bị bác và vấn đề có sẵn",
        "s_scope": "6. Phạm vi đã đọc và chưa đọc", "s_open": "7. Việc còn mở",
        "c_blocker": "Blocker", "c_major": "Major", "c_check": "Cần xác nhận", "c_minor": "Minor",
        "c_nit": "Nit", "c_rejected": "Bị verifier bác",
        "wait": "<b>Chưa được xác nhận:</b> {n} finding ở mục 3 chưa qua verifier, không chắc chắn hoặc có độ tin "
                "cậy thấp. Chúng được đếm riêng, không gộp với finding đã kiểm chứng.",
        "wait_section": "<b>Chưa được người thứ hai kiểm chứng.</b> Mức dưới đây là đánh giá của reviewer; chỉ coi "
                        "là chốt sau một lượt kiểm chứng.",
        "t_id": "ID", "t_from": "Mức ban đầu", "t_to": "Mức chốt", "t_ver": "Kiểm chứng", "t_title": "Finding",
        "none": "Không có.",
        "f_file": "File", "f_evidence": "Bằng chứng", "f_why": "Lỗi", "f_scenario": "Tình huống",
        "f_fix": "Gợi ý sửa", "f_verifier": "Kiểm chứng", "f_also": "Cũng được báo là",
        "f_raised": "Đã có người nêu trên PR", "f_category": "Loại", "f_confidence": "Độ tin cậy",
        "f_reason": "Vì sao bác", "initial": "Ban đầu: {s}",
        "v_confirmed": "Đã kiểm chứng", "v_unverified": "Chưa kiểm chứng", "v_uncertain": "Không chắc",
        "v_rejected": "Bị bác", "pre": "Có sẵn",
        "reviewed": "<b>Đã đọc:</b>", "not_reviewed": "<b>Chưa đọc hoặc chưa kiểm:</b>",
        "shard_files": "{shard}: {n} file", "shard_skipped": "{shard}: bỏ qua {what}",
        "overflow": "Shard rủi ro thấp chưa review: {n} ({names})", "truncated": "File vượt giới hạn số file: {n}",
        "no_tests": "Code production thay đổi nhưng diff không có file test nào.",
        "tools_off": "Không chạy công cụ tĩnh.", "pr_off": "Không lấy được ngữ cảnh PR ({why}).",
        "positives": "<b>Không thấy sai:</b>",
        "o_check": "Kiểm chứng {ids} bằng một lượt thứ hai.", "o_req": "Yêu cầu {ticket}: {criterion} ({status}).",
        "o_ci": "CI đang lỗi.", "o_tests": "Thêm test cho phần code production đã đổi.",
        "footer": "Tạo bởi tl-code-review từ <code>{dir}</code>. Kết luận và số đếm lấy từ aggregate_findings.py; "
                  "không thêm gì bằng tay.",
    },
}

SEV_CLASS = {"blocker": "blk", "major": "maj", "minor": "min", "nit": "mute"}


def load(p, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def card_page(d, lang):
    T = CARD_TEXT.get(lang, CARD_TEXT["en"])
    md = Markdown(SEVERITIES)
    doc = load(d / "findings.json", {})
    manifest = load(d / "manifest.json", {})
    prctx = load(d / "pr_context.json", {}) or {}
    plan = load(d / "shards.json", {})
    static = load(d / "static.json", {})
    reqs = load(d / "requirements.json", []) or []
    is_diff = manifest.get("mode") in ("uncommitted", "staged", "changeset")
    order = lambda f: (SEVERITIES.index(f["severity"]) if f.get("severity") in SEVERITIES else 9, f.get("id", ""))
    found = sorted(doc.get("findings", []), key=order)
    by = {b: [f for f in found if bucket(f, is_diff) == b] for b in ("main", "needs-check", "pre-existing")}
    main_f, check, pre = by["main"], by["needs-check"], by["pre-existing"]
    serious = [f for f in main_f if f.get("severity") in ("blocker", "major")]
    light = [f for f in main_f if f.get("severity") in ("minor", "nit")]
    dropped = sorted(doc.get("rejected_findings", []), key=order)
    n_rejected = doc.get("rejected", len(dropped))
    count = lambda s: sum(1 for f in main_f if f.get("severity") == s)

    def ver_badge(f):
        v = f.get("verification") or "unverified"
        cls = {"confirmed": "b-ok", "rejected": "b-mute"}.get(v, "b-bad")
        return f'<span class="badge {cls}">{html.escape(T.get("v_" + v, v))}</span>'

    def card(f, kind=""):
        sev = f.get("severity", "")
        cls = kind or SEV_CLASS.get(sev, "")
        badges = (f'<span class="badge b-{SEV_CLASS.get(sev, "mute")}">{html.escape(sev.upper())}</span>'
                  + ver_badge(f))
        if f.get("original_severity"):
            badges += f'<span class="badge b-mute">{html.escape(T["initial"].format(s=f["original_severity"]))}</span>'
        if kind == "drop" and f in pre:
            badges += f'<span class="badge b-mute">{T["pre"]}</span>'
        rows = [(T["f_file"], f"<code>{html.escape(location(f))}</code>"),
                (T["f_category"], html.escape(f"{f.get('category', '')} · {T['f_confidence'].lower()} "
                                              f"{f.get('confidence', '')}"))]
        if f.get("evidence"):
            rows.append((T["f_evidence"], f"<pre><code>{html.escape(f['evidence'].rstrip())}</code></pre>"))
        for label, key in (("f_why", "why"), ("f_scenario", "scenario"), ("f_fix", "suggestion")):
            if f.get(key):
                rows.append((T[label], md.inline(f[key])))
        if f.get("verify_note"):
            rows.append((T["f_reason"] if f.get("verification") == "rejected" else T["f_verifier"],
                         md.inline(f["verify_note"])))
        if f.get("also_reported_as"):
            rows.append((T["f_also"], html.escape(", ".join(f["also_reported_as"]))))
        if f.get("already_raised"):
            who = f["already_raised"] if isinstance(f["already_raised"], str) else ""
            rows.append((T["f_raised"], html.escape(f"@{who}" if who else "✓")))
        dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
        return (f'<article class="f {cls}"><header><span class="id">{html.escape(f.get("id", ""))}</span>{badges}'
                f'</header><h3>{md.inline(f.get("title", ""))}</h3><dl>{dl}</dl></article>')

    def cards(items, kind=""):
        return "".join(card(f, kind) for f in items) or f'<p>{T["none"]}</p>'

    pr = prctx.get("pr") or {}
    pr_no = pr.get("number") or manifest.get("pr")
    repo = Path(manifest.get("repo_root", "")).name
    title = (T["title_pr"].format(n=pr_no) if pr_no else T["title"]) + (f" · {repo}" if repo else "")
    s = manifest.get("stats", {})
    meta = [(T["head"], f"<code>{html.escape(str(manifest.get('head', '?')))}</code>"),
            (T["base"], f"<code>{html.escape(str(manifest.get('base', '?')))}</code>"),
            (T["size"], html.escape(T["size_v"].format(files=s.get("files", "?"), added=s.get("added", 0),
                                                         deleted=s.get("deleted", 0)))),
            (T["verdict"], html.escape(doc.get("verdict", "?")))]
    if prctx.get("available") and prctx.get("ci_summary"):
        meta.append((T["ci"], html.escape(prctx["ci_summary"])))

    tiles = [("blk", count("blocker"), T["c_blocker"]), ("maj", count("major"), T["c_major"])]
    if check:
        tiles.append(("maj", f"+{len(check)}", T["c_check"]))
    tiles.append(("min", count("minor"), T["c_minor"]))
    if count("nit"):
        tiles.append(("", count("nit"), T["c_nit"]))
    tiles.append(("", n_rejected, T["c_rejected"]))
    tiles_html = "".join(f'<div class="c"><div class="n {c}">{n}</div><div class="l">{html.escape(l)}</div></div>'
                         for c, n, l in tiles)

    def sev_cell(x):
        return f'<span class="badge b-{SEV_CLASS.get(x, "mute")}">{html.escape(x.upper())}</span>' if x else ""

    table = "".join(f"<tr><td>{html.escape(f.get('id', ''))}</td>"
                    f"<td>{sev_cell(f.get('original_severity') or f.get('severity', ''))}</td>"
                    f"<td>{sev_cell('' if f in dropped else f.get('severity', ''))}</td>"
                    f"<td>{ver_badge(f)}</td><td>{md.inline(f.get('title', ''))}</td></tr>"
                    for f in serious + check + light + pre + dropped)

    reviewed, not_reviewed = [], []
    for c in doc.get("coverage", []):
        if c.get("reviewed"):
            reviewed.append(T["shard_files"].format(shard=c.get("shard") or "?", n=len(c["reviewed"])))
        skipped = c.get("skipped") or c.get("not_reviewed")
        if skipped:
            not_reviewed.append(T["shard_skipped"].format(shard=c.get("shard") or "?", what=skipped))
    if plan.get("overflow"):
        not_reviewed.append(T["overflow"].format(n=len(plan["overflow"]),
                                                 names=", ".join(o["module"] for o in plan["overflow"][:8])))
    if manifest.get("truncated"):
        not_reviewed.append(T["truncated"].format(n=len(manifest["truncated"])))
    if static and not static.get("ran"):
        not_reviewed.append(T["tools_off"])
    if manifest.get("pr") and not prctx.get("available"):
        not_reviewed.append(T["pr_off"].format(why=prctx.get("reason", "not fetched")))
    if is_diff and not s.get("tests_touched"):
        not_reviewed.append(T["no_tests"])
    ul = lambda items: "<ul>" + "".join(f"<li>{md.inline(str(x))}</li>" for x in items) + "</ul>"
    scope = ""
    if reviewed:
        scope += f"<p>{T['reviewed']}</p>{ul(reviewed)}"
    if doc.get("positives"):
        scope += f"<p>{T['positives']}</p>{ul(doc['positives'])}"
    if not_reviewed:
        scope += f"<p>{T['not_reviewed']}</p>{ul(not_reviewed)}"

    open_items = []
    if check:
        open_items.append(T["o_check"].format(ids=", ".join(f["id"] for f in check)))
    open_items += [T["o_req"].format(ticket=r.get("ticket", ""), criterion=r.get("criterion", ""),
                                     status=r.get("status", ""))
                   for r in reqs if r.get("status") in ("missing", "partial")]
    if prctx.get("ci_summary") == "failing":
        open_items.append(T["o_ci"])
    if is_diff and not s.get("tests_touched"):
        open_items.append(T["o_tests"])

    sub = md.inline(pr.get("title", "")) if pr.get("title") else ""
    body = (f"<main><h1>{html.escape(title)}</h1>" + (f'<p class="sub">{sub}</p>' if sub else "")
            + '<div class="meta">' + "".join(f"<div><b>{k}</b>{v}</div>" for k, v in meta) + "</div>"
            + f'<h2 id="summary">{T["s_summary"]}</h2>'
            + (f'<div class="wait">{T["wait"].format(n=len(check))}</div>' if check else "")
            + f'<div class="cards">{tiles_html}</div>'
            + (f'<div class="tablewrap"><table><thead><tr><th>{T["t_id"]}</th><th>{T["t_from"]}</th>'
               f'<th>{T["t_to"]}</th><th>{T["t_ver"]}</th><th>{T["t_title"]}</th></tr></thead>'
               f'<tbody>{table}</tbody></table></div>' if table else "")
            + f'<h2 id="serious">{T["s_serious"]}</h2>{cards(serious)}'
            + f'<h2 id="check">{T["s_check"]}</h2>'
            + (f'<div class="wait">{T["wait_section"]}</div>' if check else "") + cards(check, "wait")
            + f'<h2 id="minor">{T["s_minor"]}</h2>{cards(light)}'
            + f'<h2 id="dropped">{T["s_dropped"]}</h2>{cards(dropped + pre, "drop")}'
            + f'<h2 id="scope">{T["s_scope"]}</h2>' + (scope or f'<p>{T["none"]}</p>')
            + f'<h2 id="open">{T["s_open"]}</h2>' + (ul(open_items) if open_items else f'<p>{T["none"]}</p>')
            + f'<footer><p>{T["footer"].format(dir=html.escape(str(d)))}</p></footer></main>')
    return (f'<!doctype html><html lang="{html.escape(lang)}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>'
            f'<link rel="icon" href="data:,"><style>{CARD_CSS}</style></head><body>{body}</body></html>'), len(found)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", help="the run folder (default: the latest run)")
    ap.add_argument("--report", help="report.md path, if aggregate_findings.py used --out (default: <dir>/report.md)")
    ap.add_argument("-o", "--output", help="HTML path (default: next to report.md, .html)")
    ap.add_argument("--lang", default="en", help="language of the report content, e.g. vi (default: en)")
    ap.add_argument("--template", default="tabs", choices=["tabs", "card"],
                    help="tabs: report and filterable findings table (default); card: printable summary with "
                         "one card per finding")
    a = ap.parse_args()
    a.dir = a.dir or str(run_dir.latest())
    d = Path(a.dir)
    report = Path(a.report) if a.report else d / "report.md"
    if not report.exists() or not (d / "findings.json").exists():
        sys.exit("report.md or findings.json missing — run aggregate_findings.py first")
    out = a.output or report.with_suffix(".html")
    if a.template == "card":
        text, n = card_page(d, a.lang)
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"{out.resolve()} ({n} findings)")
        return
    write_page(out, report.read_text(encoding="utf-8"), rows_from(d),
               SEVERITIES, ["Category", "Verification", "Bucket"], a.lang)


if __name__ == "__main__":
    main()
