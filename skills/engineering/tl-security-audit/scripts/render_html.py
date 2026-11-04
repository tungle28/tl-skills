"""Render the finished audit as one self-contained HTML page for review.

    python render_html.py --run-dir <run>            # -> <run>/report.html
    python render_html.py --run-dir <run> -o out.html

Run it after 'findings.py report'. The page has two tabs: Report (report.md as written, with a section
nav and severity badges) and Findings (every live finding from merged.json in one table, filterable
by severity, OWASP category, status and free text; a row expands to its evidence, attack scenario,
impact and fix). Secrets are masked with the same rules report.md uses. Standard library only; the
page works offline (no external scripts, fonts or stylesheets).
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path

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


sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import OWASP_2025, SEVERITIES, load_state, read_json  # noqa: E402
from findings import redact_obj, secret_rules  # noqa: E402
from memory import NOT_LIVE  # noqa: E402


def location(f):
    end = f.get("line_end")
    return f"{f['file']}:{f['line_start']}" + (f"-{end}" if end and end != f["line_start"] else "")


def rows_from(run):
    doc = read_json(run / "merged.json") or {}
    live = [f for f in doc.get("findings", []) if f.get("status") not in NOT_LIVE]
    live.sort(key=lambda f: (SEVERITIES.index(f["severity"]) if f.get("severity") in SEVERITIES else 9, f["id"]))
    rows = []
    for f in live:
        ow = f.get("owasp", "")
        details = [[label, f[key], False] for label, key in (
            ("Evidence", "evidence"), ("Attack scenario", "attack_scenario"), ("Impact", "impact"),
            ("Fix", "fix"), ("Note", "note"), ("Verification", "verification_note")) if f.get(key)]
        meta = " · ".join(x for x in (f.get("cwe"), f"confidence {f.get('confidence')}",
                                      f"requires {f.get('requires')}", f.get("kind")) if x)
        details.insert(0, ["Details", meta, False])
        rows.append({"id": f["id"], "sev": f["severity"], "title": f.get("title", ""), "loc": location(f),
                     "facets": {"OWASP": f"{ow} {OWASP_2025.get(ow, '')}".strip(), "Status": f.get("status", ""),
                                **({"Change": f["delta"]} if f.get("delta") else {})},
                     "details": details})
    # Reviewers and the narrative can quote a secret; report.md masks them, so the page must too.
    return redact_obj(rows, secret_rules(run))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("-o", "--output", help="HTML path (default: <run>/report.html)")
    ap.add_argument("--lang", help="language of the report content (default: the run's language)")
    a = ap.parse_args()
    run = Path(a.run_dir)
    a.lang = a.lang or load_state(run).get("lang") or "en"
    report = run / "report.md"
    if not report.exists():
        sys.exit("report.md missing — run 'findings.py report' first")
    write_page(a.output or run / "report.html", report.read_text(encoding="utf-8"), rows_from(run),
               SEVERITIES, ["OWASP", "Status"], a.lang)


if __name__ == "__main__":
    main()
