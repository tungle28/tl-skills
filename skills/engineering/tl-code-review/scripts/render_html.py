"""Render a harness code review as one self-contained HTML page for review.

    python render_html.py --dir $RUN             # -> $RUN/report.html
    python render_html.py --dir $RUN --lang vi -o out.html
    python render_html.py --dir $RUN --lang vi --template card

Run it after aggregate_findings.py. The default template (tabs) has two tabs: Report (report.md as
written, with a section nav) and Findings (one card per finding from findings.json — evidence, why it
matters, failure scenario, fix — with Fix / Skip / Later and a note, filterable by severity, category,
verification, bucket, decision and free text; "Copy for agent" puts the decisions and the run path on
the clipboard). The card template is a printable summary: PR facts, count cards,
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
:root{--bg:#fbfbfa;--panel:#fff;--text:#1f2328;--muted:#5f6670;--border:#e3e5e8;--accent:#2f6fd1;--code-bg:#f2f3f5;--ok:#2e7d4f;
--s0:#b42318;--s0-bg:#fdecec;--s1:#c2410c;--s1-bg:#fdefe3;--s2:#a16207;--s2-bg:#fdf6dc;--s3:#1d5fa8;--s3-bg:#e8f1fb;--s4:#4b5563;--s4-bg:#eef0f3}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#15171a;--panel:#1d2024;--text:#e6e8eb;--muted:#9aa3ad;
--border:#30343a;--accent:#79a8f0;--code-bg:#262a30;--ok:#6fcf97;--s0:#f28b82;--s0-bg:#3b1f1f;--s1:#f6a35c;--s1-bg:#3a2614;--s2:#e8c65a;
--s2-bg:#352d12;--s3:#8ab8f0;--s3-bg:#1b2a3d;--s4:#b6bec8;--s4-bg:#2a2e34}}
:root[data-theme="dark"]{--bg:#15171a;--panel:#1d2024;--text:#e6e8eb;--muted:#9aa3ad;--border:#30343a;--accent:#79a8f0;
--code-bg:#262a30;--ok:#6fcf97;--s0:#f28b82;--s0-bg:#3b1f1f;--s1:#f6a35c;--s1-bg:#3a2614;--s2:#e8c65a;--s2-bg:#352d12;--s3:#8ab8f0;
--s3-bg:#1b2a3d;--s4:#b6bec8;--s4-bg:#2a2e34}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header.top{position:sticky;top:0;z-index:3;background:var(--bg);border-bottom:1px solid var(--border)}
.bar{display:flex;gap:8px;align-items:center;max-width:1320px;margin:0 auto;padding:10px 16px}
.bar .title{font-weight:600;margin-right:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
button{font:inherit;font-size:13px;padding:4px 12px;border-radius:16px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer;white-space:nowrap}
button[aria-selected="true"],button[aria-pressed="true"]{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
.layout{display:grid;grid-template-columns:220px minmax(0,1fr);gap:32px;max-width:1320px;margin:0 auto;padding:20px 16px 96px}
.layout.wide{grid-template-columns:minmax(0,1fr);max-width:1040px}
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
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;position:sticky;top:49px;z-index:2;background:var(--bg);padding:10px 0;margin:0 0 4px}
.filters select,.filters input{font:inherit;font-size:13px;padding:4px 8px;border-radius:8px;border:1px solid var(--border);background:var(--panel);color:var(--text)}
.filters input{min-width:180px;flex:1}
.count{color:var(--muted);font-size:13px;margin:0 0 8px}
.card{background:var(--panel);color:var(--text);border:1px solid var(--border);border-left:4px solid var(--s4);border-radius:10px;padding:14px 16px;margin:10px 0}
.card.sv0{border-left-color:var(--s0)}.card.sv1{border-left-color:var(--s1)}.card.sv2{border-left-color:var(--s2)}.card.sv3{border-left-color:var(--s3)}
.card>header{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:4px}
.card h3{font-size:16px;margin:2px 0 0;flex-basis:100%}
.card h4{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:12px 0 2px}
.card p{margin:4px 0}.card .loc{margin:2px 0 0}.card .meta{color:var(--muted);font-size:13px}
.id,.chip{font-size:12px;padding:1px 8px;border-radius:999px;border:1px solid var(--border);color:var(--muted);white-space:nowrap}
.id{font-weight:600;color:var(--text)}
.decide{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;margin-top:12px;padding-top:10px;border-top:1px dashed var(--border)}
.decide label{cursor:pointer;font-size:14px;white-space:nowrap}
.note{flex:1 1 220px;min-width:0;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font:inherit;font-size:14px}
.card.d-fix{outline:2px solid var(--ok);outline-offset:-1px}.card.d-skip{opacity:.6}.card.d-later{outline:1px dashed var(--muted);outline-offset:-1px}
.dock{position:fixed;left:0;right:0;bottom:0;z-index:4;background:var(--panel);border-top:1px solid var(--border);padding:10px 16px;display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;justify-content:center}
.dock .progress{color:var(--muted);font-size:14px}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-size:14px;padding:7px 16px;border-radius:8px}
:root[data-theme="dark"] button.primary{color:#0d1117}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) button.primary{color:#0d1117}}
.empty{color:var(--muted);padding:16px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:4px 0 12px}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:10px 12px}
.tile b{display:block;font-size:22px;line-height:1.2}.tile span{color:var(--muted);font-size:13px}
.tile.ok b{color:var(--ok)}.tile.sv0 b{color:var(--s0)}.tile.sv1 b{color:var(--s1)}.tile.sv2 b{color:var(--s2)}.tile.sv3 b{color:var(--s3)}
h2.fixed-head{margin-top:28px}
.card.fixed{border-left-color:var(--ok)}.chip.ok{color:var(--ok);border-color:var(--ok)}
.fixbox{margin:8px 0 0;padding:8px 12px;border-radius:8px;background:var(--code-bg)}
.fix-results{padding:10px 14px;border:1px solid var(--border);border-left:4px solid var(--ok);border-radius:8px;background:var(--panel)}.fix-results ul{margin:6px 0 0;padding-left:20px}
.fixnote{margin:8px 0;padding:8px 12px;border-radius:8px;border:1px dashed var(--s1);font-size:14px}
.hidden{display:none}.dock[hidden]{display:none}.card{scroll-margin-top:110px}td a[href^="#f-"]{white-space:nowrap}
@media (max-width:860px){.layout{grid-template-columns:1fr;gap:8px}nav{position:static;max-height:none;display:flex;flex-wrap:wrap;gap:4px}
.filters{top:0;position:static}.filters input{min-width:0}}
@media print{header.top,nav,.filters,.dock,.decide{display:none}.layout{display:block;padding:0}.panel[hidden]{display:block}body{background:#fff;color:#000}}
"""

UI_TEXT = {
    "en": {
        "report": "Report", "findings": "Findings", "theme": "Switch light/dark",
        "search": "Search ID, title, file…", "fix": "Fix", "skip": "Skip", "later": "Later",
        "note": "Note for the agent (optional)", "decision": "Decision",
        "copy": "Copy for agent", "copied": "Copied — paste it to the agent",
        "copy_empty": "Choose Fix, Skip or Later on at least one finding first.",
        "decided": "decided", "of": "of", "shown": "findings shown",
        "fix_shown": "Mark shown as Fix", "clear": "Clear decisions", "clear_ask": "Clear every decision and note?",
        "dec_all": "Decision: all", "undecided": "Undecided", "all": "all",
        "none": "No findings match the filters.",
        "g_fix": "Fix", "g_skip": "Skip — do not fix", "g_later": "Later — not now", "g_note": "Comment only, no decision",
        "fixed": "Fixed", "pending": "Pending", "f_what": "What changed", "f_verify": "Verified by",
        "f_files": "Files", "f_commit": "Commit", "partial": "Partly fixed", "failed": "Fix attempt failed",
        "details": "Finding details", "fix_results": "Fix results",
        "fix_line": "{fixed} fixed · {partial} partly fixed · {failed} not fixed · last update {at}",
        "c_id": "ID", "c_sev": "Severity", "c_title": "Issue", "c_loc": "Location", "c_status": "Status",
    },
    "vi": {
        "report": "Báo cáo", "findings": "Finding", "theme": "Đổi sáng/tối",
        "search": "Tìm ID, tiêu đề, file…", "fix": "Sửa", "skip": "Bỏ qua", "later": "Để sau",
        "note": "Ghi chú cho agent (tuỳ chọn)", "decision": "Quyết định",
        "copy": "Sao chép cho agent", "copied": "Đã sao chép — dán cho agent",
        "copy_empty": "Hãy chọn Sửa, Bỏ qua hoặc Để sau cho ít nhất một finding.",
        "decided": "đã quyết", "of": "/", "shown": "finding đang hiện",
        "fix_shown": "Đánh dấu Sửa cho mục đang hiện", "clear": "Xoá quyết định",
        "clear_ask": "Xoá mọi quyết định và ghi chú?",
        "dec_all": "Quyết định: tất cả", "undecided": "Chưa quyết", "all": "tất cả",
        "none": "Không có finding nào khớp bộ lọc.",
        "g_fix": "Sửa", "g_skip": "Bỏ qua — không sửa", "g_later": "Để sau — chưa làm", "g_note": "Chỉ ghi chú, chưa quyết",
        "fixed": "Đã sửa", "pending": "Chờ duyệt", "f_what": "Đã làm", "f_verify": "Đã xác minh bằng",
        "f_files": "File", "f_commit": "Commit", "partial": "Sửa một phần", "failed": "Sửa chưa được",
        "details": "Chi tiết finding", "fix_results": "Kết quả sửa",
        "fix_line": "{fixed} đã sửa · {partial} sửa một phần · {failed} chưa sửa được · cập nhật lần cuối {at}",
        "c_id": "ID", "c_sev": "Mức", "c_title": "Vấn đề", "c_loc": "Vị trí", "c_status": "Trạng thái",
    },
}


def ui_text(lang):
    return UI_TEXT.get(re.split(r"[-_]", (lang or "en").lower())[0], UI_TEXT["en"])


JS = r"""
(function(){
  var data=JSON.parse(document.getElementById("data").textContent);
  var sevs=data.severities, rows=data.rows, facets=data.facets, T=data.text, H=data.handoff||{};
  var CHOICES=["fix","skip","later"];
  function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];});}
  function md(s){return esc(s).replace(/`([^`]+)`/g,"<code>$1</code>").replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>");}
  function si(s){var i=sevs.indexOf(s);return i<0?4:Math.min(i,4);}
  function badge(s){return '<span class="sev s'+si(s)+'">'+esc(s)+'</span>';}
  // tabs
  var tabs=document.querySelectorAll("[data-tab]");
  function show(name){tabs.forEach(function(t){var on=t.getAttribute("data-tab")===name;t.setAttribute("aria-selected",on);
    document.getElementById("panel-"+t.getAttribute("data-tab")).hidden=!on;});
    document.getElementById("nav").hidden=name!=="report";
    document.querySelector(".dock").hidden=name!=="findings";  // decisions are made, and copied, on the Findings tab
    document.querySelector(".layout").classList.toggle("wide",name!=="report");try{location.hash=name==="report"?"":"findings";}catch(e){}}
  tabs.forEach(function(t){t.addEventListener("click",function(){show(t.getAttribute("data-tab"));});});
  // an ID in the Report tab's finding tables opens that finding's card
  document.addEventListener("click",function(ev){var a=ev.target.closest&&ev.target.closest('a[href^="#f-"]');if(!a)return;
    var el=document.getElementById(decodeURIComponent(a.getAttribute("href").slice(1)));if(!el)return;
    ev.preventDefault();show("findings");el.scrollIntoView({block:"start"});});
  // decisions, kept in this browser only
  var KEY="tl-findings:"+(H.key||document.title), state={};
  try{state=JSON.parse(localStorage.getItem(KEY)||"{}")||{};}catch(e){state={};}
  function save(){try{localStorage.setItem(KEY,JSON.stringify(state));}catch(e){}}
  function set(id,k,v,quiet){var s=state[id]=state[id]||{};if(v)s[k]=v;else delete s[k];
    if(!s.d&&!s.n)delete state[id];save();if(!quiet)refresh();}
  // cards: findings record_fix.py marked fixed leave the decision list for the "Fixed" section
  function isFixed(r){return !!(r.fix&&r.fix.status==="fixed");}
  var pend=rows.filter(function(r){return !isFixed(r);}), fixed=rows.filter(isFixed);
  function head(r,extra){var chips=facets.map(function(k){var v=r.facets[k];return v?'<span class="chip" title="'+esc(k)+'">'+esc(v)+'</span>':"";}).join("");
    return '<header><span class="id">'+esc(r.id)+'</span>'+badge(r.sev)+(extra||"")+chips+'<h3>'+md(r.title)+'</h3></header>'+
      (r.loc?'<p class="loc"><code>'+esc(r.loc)+'</code></p>':'');}
  function body(r){return r.details.map(function(d){
      if(d[0]==="Details")return '<p class="meta">'+md(d[1])+'</p>';
      return '<h4>'+esc(d[0])+'</h4>'+(d[2]?'<pre><code>'+esc(d[1])+'</code></pre>':'<p>'+md(d[1])+'</p>');}).join("");}
  function fixLines(f){return '<p><b>'+esc(T.f_what)+':</b> '+md(f.what)+'</p>'+
      (f.verify?'<p class="meta"><b>'+esc(T.f_verify)+':</b> '+md(f.verify)+'</p>':'')+
      (f.files&&f.files.length?'<p class="meta"><b>'+esc(T.f_files)+':</b> '+f.files.map(function(x){return '<code>'+esc(x)+'</code>';}).join(", ")+'</p>':'')+
      (f.commit?'<p class="meta"><b>'+esc(T.f_commit)+':</b> <code>'+esc(f.commit)+'</code></p>':'');}
  var box=document.getElementById("cards");
  box.innerHTML=pend.map(function(r,i){
    var opts=CHOICES.map(function(c){return '<label><input type="radio" name="d'+i+'" value="'+c+'"> '+esc(T[c])+'</label>';}).join("");
    var note=r.fix?'<div class="fixnote"><b>'+esc(T[r.fix.status]||r.fix.status)+'</b>'+fixLines(r.fix)+'</div>':'';
    return '<article class="card sv'+si(r.sev)+'" id="f-'+esc(r.id)+'">'+head(r)+note+body(r)+
      '<div class="decide" role="radiogroup" aria-label="'+esc(T.decision+" "+r.id)+'">'+opts+
      '<input type="text" class="note" placeholder="'+esc(T.note)+'" aria-label="'+esc(T.note)+'"></div></article>';}).join("");
  var fbox=document.getElementById("fixed"), fhead=document.getElementById("fixed-head");
  fbox.innerHTML=fixed.map(function(r){
    return '<article class="card fixed" id="f-'+esc(r.id)+'">'+head(r,'<span class="chip ok">'+esc(T.fixed)+'</span>')+
      '<div class="fixbox">'+fixLines(r.fix)+'</div><details><summary>'+esc(T.details)+'</summary>'+body(r)+'</details></article>';}).join("");
  fhead.hidden=!fixed.length;fhead.textContent=T.fixed+" ("+fixed.length+")";
  var tiles='<div class="tile ok"><b>'+fixed.length+'</b><span>'+esc(T.fixed)+'</span></div>';
  sevs.forEach(function(s){var n=pend.filter(function(r){return r.sev===s;}).length;
    if(n)tiles+='<div class="tile sv'+si(s)+'"><b>'+n+'</b><span>'+esc(T.pending)+' · '+esc(s)+'</span></div>';});
  document.getElementById("tiles").innerHTML=tiles;
  var cards=[].slice.call(box.children), fcards=[].slice.call(fbox.children);
  cards.forEach(function(c,i){var id=pend[i].id, s=state[id]||{};
    c.querySelectorAll("input[type=radio]").forEach(function(r){if(s.d===r.value)r.checked=true;
      r.addEventListener("change",function(){set(id,"d",r.value);});});
    var n=c.querySelector(".note");n.value=s.n||"";n.addEventListener("input",function(){set(id,"n",n.value,true);});});
  // filters
  var active=new Set(sevs), f=document.getElementById("filters");
  sevs.forEach(function(s){var n=rows.filter(function(r){return r.sev===s;}).length;if(!n)return;
    var b=document.createElement("button");b.type="button";b.setAttribute("aria-pressed","true");
    b.innerHTML=badge(s)+" "+n;b.addEventListener("click",function(){if(active.has(s))active.delete(s);else active.add(s);
    b.setAttribute("aria-pressed",active.has(s));refresh();});f.appendChild(b);});
  var sel={};
  facets.forEach(function(k){var vals=Array.from(new Set(rows.map(function(r){return r.facets[k];}).filter(Boolean))).sort();
    if(vals.length<2)return;var s=document.createElement("select");s.setAttribute("aria-label",k);
    s.innerHTML='<option value="">'+esc(k)+': '+esc(T.all)+'</option>'+vals.map(function(v){return '<option>'+esc(v)+'</option>';}).join("");
    s.addEventListener("change",refresh);sel[k]=s;f.appendChild(s);});
  var dsel=document.createElement("select");dsel.setAttribute("aria-label",T.decision);
  dsel.innerHTML='<option value="">'+esc(T.dec_all)+'</option><option value="none">'+esc(T.undecided)+'</option>'+
    CHOICES.map(function(c){return '<option value="'+c+'">'+esc(T[c])+'</option>';}).join("");
  dsel.addEventListener("change",refresh);f.appendChild(dsel);
  var q=document.createElement("input");q.type="search";q.placeholder=T.search;q.addEventListener("input",refresh);f.appendChild(q);
  var bulk=document.createElement("button");bulk.type="button";bulk.textContent=T.fix_shown;f.appendChild(bulk);
  var clr=document.createElement("button");clr.type="button";clr.textContent=T.clear;f.appendChild(clr);
  function visible(r,anyDecision){var d=(state[r.id]||{}).d||"none",text=q.value.trim().toLowerCase();
    if(!active.has(r.sev))return false;
    for(var k in sel){if(sel[k].value&&r.facets[k]!==sel[k].value)return false;}
    if(!anyDecision&&dsel.value&&dsel.value!==d)return false;
    return !text||(r.id+" "+r.title+" "+r.loc).toLowerCase().indexOf(text)>=0;}
  var empty=document.getElementById("empty");
  function refresh(){var shown=0,decided=0,fix=0;
    pend.forEach(function(r,i){var c=cards[i],d=(state[r.id]||{}).d,on=visible(r);
      c.classList.remove("d-fix","d-skip","d-later");if(d){c.classList.add("d-"+d);decided++;if(d==="fix")fix++;}
      c.querySelectorAll("input[type=radio]").forEach(function(x){x.checked=x.value===d;});
      c.classList.toggle("hidden",!on);if(on)shown++;});
    fixed.forEach(function(r,i){var on=visible(r,true);fcards[i].classList.toggle("hidden",!on);if(on)shown++;});
    empty.hidden=shown>0;
    document.getElementById("count").textContent=shown+" "+T.of+" "+rows.length+" "+T.shown;
    document.getElementById("progress").textContent=decided+" / "+pend.length+" "+T.decided+" · "+T.fix+": "+fix+
      (fixed.length?" · "+T.fixed+": "+fixed.length:"");}
  bulk.addEventListener("click",function(){pend.forEach(function(r){if(visible(r))set(r.id,"d","fix",true);});refresh();});
  clr.addEventListener("click",function(){if(!confirm(T.clear_ask))return;state={};save();
    cards.forEach(function(c){c.querySelector(".note").value="";});refresh();});
  // copy for agent
  var copyBtn=document.getElementById("copy");copyBtn.textContent=T.copy;
  function plain(s){return String(s||"").replace(/\s+/g," ").trim();}
  function textOut(){var g={fix:[],skip:[],later:[],note:[]},n=0;
    pend.forEach(function(r){var s=state[r.id];if(!s)return;n++;
      g[s.d||"note"].push("- "+r.id+" ["+r.sev+"] "+plain(r.title)+(r.loc?" — `"+r.loc+"`":"")+(s.n?" — "+plain(s.n):""));});
    if(!n)return "";
    var out=H.head?[H.head]:[];
    ["fix","skip","later","note"].forEach(function(k){if(g[k].length)out.push("","### "+T["g_"+k]+" ("+g[k].length+")",g[k].join("\n"));});
    return out.join("\n").replace(/^\n+/,"");}
  function fallback(text){var ta=document.createElement("textarea");ta.value=text;ta.style.position="fixed";ta.style.opacity="0";
    document.body.appendChild(ta);ta.select();var ok=false;try{ok=document.execCommand("copy");}catch(e){}
    document.body.removeChild(ta);if(ok)done();else window.prompt(T.copy,text);}
  function done(){copyBtn.textContent=T.copied;setTimeout(function(){copyBtn.textContent=T.copy;},2500);}
  copyBtn.addEventListener("click",function(){var text=textOut();if(!text){alert(T.copy_empty);return;}
    if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(text).then(done,function(){fallback(text);});
    else fallback(text);});
  document.getElementById("theme").addEventListener("click",function(){var r=document.documentElement;
    var dark=r.getAttribute("data-theme")==="dark"||(!r.getAttribute("data-theme")&&matchMedia("(prefers-color-scheme: dark)").matches);
    r.setAttribute("data-theme",dark?"light":"dark");});
  refresh();show(location.hash==="#findings"||!document.getElementById("panel-report").textContent.trim()?"findings":"report");
})();
"""


def load_fixes(path):
    """{finding id: entry} from the fixes.json record_fix.py writes; missing or unreadable -> {}."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    items = doc.get("fixes", []) if isinstance(doc, dict) else []
    return {str(x["id"]): x for x in items if isinstance(x, dict) and x.get("id")}


def fix_results(rows, fixes, T, inline):
    """'Fix results' block for the top of the Report tab: counts and one line per recorded outcome, from
    fixes.json. report.md stays the audit as written; this block is how the page says what changed since."""
    by_id = {r["id"]: r for r in rows}
    items = [{**f, "id": k} for k, f in (fixes or {}).items() if k in by_id]
    if not items:
        return ""
    rank = {"fixed": 0, "partial": 1, "failed": 2}
    items.sort(key=lambda f: (rank.get(f.get("status"), 3), f["id"]))
    n = {s: sum(1 for f in items if f.get("status") == s) for s in rank}
    at = max((f.get("at") or "" for f in items), default="").replace("T", " ").replace("Z", " UTC")
    e = html.escape
    lis = "".join(f'<li><b>{e(T.get(f.get("status"), f.get("status", "")))}</b> · <code>{e(f["id"])}</code> '
                  f'[{e(by_id[f["id"]].get("sev", ""))}] {inline(by_id[f["id"]].get("title", ""))} — '
                  f'{inline(f.get("what", ""))}</li>' for f in items)
    return (f'<section class="fix-results" id="fix-results"><h2>{e(T["fix_results"])}</h2>'
            f'<p>{e(T["fix_line"].format(at=at or "-", **n))}</p><ul>{lis}</ul></section>')


HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
# report.md's "…and N more (see findings.json)" line after a truncated list: not part of the last block
STATUS_ICON = {"fixed": "✅", "partial": "🟡", "failed": "❌"}
MORE_RE = re.compile(r"^_?(?:…|\.\.\.)\s*and \d+ more\b")


def compact_findings(report_md, rows, T):
    """Report tab text: each run of per-finding detail blocks in report.md (a ### to ###### heading that
    names a finding ID, down to the next heading of the same or a higher level) becomes one short table —
    ID (links to the card), severity, issue, location, fix status (from fixes.json). The details live on the Findings tab; report.md
    itself is not changed. IDs a table of the same section already lists are not listed again."""
    by_id = {r["id"]: r for r in rows}
    if not by_id:
        return report_md
    id_re = re.compile(r"(?<![\w-])(" + "|".join(re.escape(i) for i in sorted(by_id, key=len, reverse=True))
                       + r")(?![\w-])")
    lines = report_md.splitlines()
    out, run, listed, fence, i = [], [], set(), False, 0

    def cell(s):
        return re.sub(r"\s+", " ", str(s or "")).strip().replace("|", "\\|")

    def status(r):  # recorded by record_fix.py; a finding nobody has fixed yet shows a dash
        st = (r.get("fix") or {}).get("status")
        return f"{STATUS_ICON[st]} {cell(T.get(st, st))}" if st in STATUS_ICON else "—"

    def flush():
        ids = [x for x in dict.fromkeys(run) if x not in listed]
        run.clear()
        if not ids:
            return
        out.extend(["", f"| {T['c_id']} | {T['c_sev']} | {T['c_title']} | {T['c_loc']} | {T['c_status']} |",
                    "|---|---|---|---|---|"])
        for x in ids:
            r = by_id[x]
            out.append(f"| [{cell(x)}](#f-{x}) | {cell(r.get('sev'))} | {cell(r.get('title'))} | "
                       + (f"`{cell(r['loc'])}`" if r.get("loc") else "") + f" | {status(r)} |")
        out.append("")

    while i < len(lines):
        line, s = lines[i], lines[i].strip()
        if s.startswith("```"):
            fence = not fence
        m = None if fence else HEADING_RE.match(s)
        hit = id_re.search(m.group(2)) if m and len(m.group(1)) >= 3 else None
        if hit:  # a finding's detail block: skip it, down to the next heading at its level or above
            level, inner = len(m.group(1)), False
            run.append(hit.group(1))
            i += 1
            while i < len(lines):
                t = lines[i].strip()
                if t.startswith("```"):
                    inner = not inner
                elif not inner:
                    h = HEADING_RE.match(t)
                    if (h and len(h.group(1)) <= level) or MORE_RE.match(t):
                        break
                i += 1
            continue
        if m:
            flush()
            listed.clear()
        elif not fence and MORE_RE.match(s):
            flush()  # the table first, then the note that says it is truncated
        elif s.startswith("|") and not fence:
            listed.update(id_re.findall(s))
        out.append(line)
        i += 1
    flush()
    return "\n".join(out)


def page(report_md, rows, severities, facets, lang, handoff=None, fixes=None):
    """rows: [{id, sev, title, loc, facets: {name: value}, details: [[label, text, is_code], ...]}].
    A detail labelled "Details" is shown as the card's meta line. handoff: {"head": line placed above
    the decisions when they are copied for the agent, "key": what keeps decisions apart between runs}.
    fixes: load_fixes() output; a finding recorded as fixed moves to the "Fixed" section, a partial or
    failed attempt is shown on its card."""
    T = ui_text(lang)
    fixes = fixes or {}
    rows = [{**r, "fix": fixes[r["id"]]} if r["id"] in fixes else r for r in rows]
    body, sections = Markdown(severities).convert(compact_findings(report_md, rows, T))
    m = re.search(r"^#\s+(.*)$", report_md, re.M)
    title = re.sub(r"[`*]", "", m.group(1)).strip() if m else "Report"
    nav = "".join(f'<a href="#{a}">{Markdown(severities).inline(t)}</a>' for a, t in sections)
    done = fix_results(rows, fixes, T, Markdown(severities).inline)
    if done:  # right under the title, before the audit's own sections
        body = body.replace("</h1>", "</h1>" + done, 1) if "</h1>" in body else done + body
        nav = f'<a href="#fix-results">{html.escape(T["fix_results"])}</a>' + nav
    data = json.dumps({"severities": severities, "facets": facets, "rows": rows, "text": T,
                       "handoff": handoff or {}}, ensure_ascii=False)
    data = data.replace("</", "<\\/")  # the JSON sits inside a <script> element
    e = html.escape
    return (f'<!doctype html><html lang="{e(lang)}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>'
            f'<link rel="icon" href="data:,"><style>{CSS}</style></head><body>'
            f'<header class="top"><div class="bar"><span class="title">{e(title)}</span>'
            f'<button type="button" data-tab="report" aria-selected="true">{e(T["report"])}</button>'
            f'<button type="button" data-tab="findings" aria-selected="false">{e(T["findings"])} ({len(rows)})</button>'
            f'<button type="button" id="theme" title="{e(T["theme"])}">◐</button></div></header>'
            f'<div class="layout"><nav id="nav" aria-label="Sections">{nav}</nav><main>'
            f'<section id="panel-report" class="panel">{body}</section>'
            f'<section id="panel-findings" class="panel" hidden><div class="tiles" id="tiles"></div>'
            f'<div class="filters" id="filters"></div>'
            f'<p class="count" id="count"></p><div id="cards"></div>'
            f'<h2 class="fixed-head" id="fixed-head" hidden></h2><div id="fixed"></div>'
            f'<p class="empty" id="empty" hidden>{e(T["none"])}</p></section></main></div>'
            f'<div class="dock" hidden><span class="progress" id="progress"></span>'
            f'<button type="button" class="primary" id="copy"></button></div>'
            f'<script type="application/json" id="data">{data}</script><script>{JS}</script></body></html>')


def write_page(out, report_md, rows, severities, facets, lang, handoff=None, fixes=None):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page(report_md, rows, severities, facets, lang, handoff, fixes), encoding="utf-8")
    n_fixed = sum(1 for r in rows if (fixes or {}).get(r["id"], {}).get("status") == "fixed")
    unknown = sorted(set(fixes or {}) - {r["id"] for r in rows})
    if unknown:  # a typo in record_fix.py --id would otherwise vanish without a trace
        print(f"warning: fixes.json ids with no matching finding: {', '.join(unknown)}", file=sys.stderr)
    print(f"{out.resolve()} ({len(rows)} findings" + (f", {n_fixed} fixed" if n_fixed else "") + ")")

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
.n.blk{color:var(--blk)}.n.maj{color:var(--maj)}.n.min{color:var(--min)}.n.ok{color:var(--ok)}
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
        "x_fixed": "Fixed", "x_partial": "Partly fixed", "x_failed": "Not fixed", "c_fixed": "Fixed since",
        "f_fixres": "Fix result", "f_fixverify": "Verified by", "f_fixfiles": "Files", "f_fixcommit": "Commit",
        "footer": "Generated from <code>{dir}</code>. Verdict and counts come from "
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
        "x_fixed": "Đã sửa", "x_partial": "Sửa một phần", "x_failed": "Chưa sửa được", "c_fixed": "Đã sửa sau review",
        "f_fixres": "Kết quả sửa", "f_fixverify": "Kiểm chứng bằng", "f_fixfiles": "File", "f_fixcommit": "Commit",
        "footer": "Tạo từ <code>{dir}</code>. Kết luận và số đếm lấy từ aggregate_findings.py; "
                  "không thêm gì bằng tay.",
    },
}

SEV_CLASS = {"blocker": "blk", "major": "maj", "minor": "min", "nit": "mute"}


def load(p, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def card_page(d, lang, fixes=None):
    """fixes: load_fixes() output. The card page keeps every finding in its section (it is the audit as
    reviewed) and marks a recorded outcome on the finding's card, with a tile counting the fixed ones."""
    T = CARD_TEXT.get(run_dir.norm_lang(lang, "render_html"), CARD_TEXT["en"])  # vi-VN -> vi
    fixes = fixes or {}
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
        fx = fixes.get(f.get("id", ""))
        if fx:
            st = fx.get("status", "")
            badges += (f'<span class="badge {"b-ok" if st == "fixed" else "b-bad"}">'
                       f'{html.escape(T.get("x_" + st, st))}</span>')
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
        if fx:
            rows.append((T["f_fixres"], md.inline(fx.get("what", ""))))
            if fx.get("verify"):
                rows.append((T["f_fixverify"], md.inline(fx["verify"])))
            if fx.get("files"):
                rows.append((T["f_fixfiles"], ", ".join(f"<code>{html.escape(str(x))}</code>" for x in fx["files"])))
            if fx.get("commit"):
                rows.append((T["f_fixcommit"], f"<code>{html.escape(str(fx['commit']))}</code>"))
        dl ="".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
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
    n_fixed = sum(1 for f in found if fixes.get(f.get("id", ""), {}).get("status") == "fixed")
    if n_fixed:
        tiles.append(("ok", n_fixed, T["c_fixed"]))
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
    fixes = load_fixes(d / "fixes.json")  # record_fix.py output
    if a.template == "card":
        text, n = card_page(d, a.lang, fixes)
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        doc = load(d / "findings.json", {})
        unknown = sorted(set(fixes) - {f.get("id") for f in doc.get("findings", []) + doc.get("rejected_findings", [])})
        if unknown:
            print(f"warning: fixes.json ids with no matching finding: {', '.join(unknown)}", file=sys.stderr)
        n_fixed = sum(1 for e in fixes.values() if e.get("status") == "fixed" and e.get("id") not in unknown)
        print(f"{out.resolve()} ({n} findings" + (f", {n_fixed} fixed" if n_fixed else "") + ")")
        return
    where = str(d.resolve())
    head = {"vi": f"Sửa các finding trong mục Sửa của lần review tl-code-review `{where}` (chi tiết ở findings.json); "
                  "không đụng mục Bỏ qua và Để sau. Sửa xong thì chạy lại test liên quan.",
            }.get(run_dir.norm_lang(a.lang, "render_html"),
                  f"Fix the findings under Fix from the tl-code-review run `{where}` (details in findings.json); "
                  "leave Skip and Later alone. Run the relevant tests after fixing.")
    write_page(out, report.read_text(encoding="utf-8"), rows_from(d),
               SEVERITIES, ["Category", "Verification", "Bucket"], a.lang, {"head": head, "key": "review:" + where},
               fixes)


if __name__ == "__main__":
    main()
