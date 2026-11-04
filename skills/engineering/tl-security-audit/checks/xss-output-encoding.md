---
id: xss-output-encoding
title: XSS and output encoding
owasp: A05
cwe: [CWE-79, CWE-80]
languages: [web, python, html]
triggers: ['(?i)innerHTML|dangerouslySetInnerHTML|Html\.Raw|v-html|\[innerHTML\]|bypassSecurityTrust|mark_safe|\|safe|document\.write|href=|src=']
---
# XSS

Modern frameworks encode by default; findings are where that default is bypassed.
- **Bypasses:** `dangerouslySetInnerHTML`, `v-html`, Angular `[innerHTML]` + `bypassSecurityTrust*`,
  Razor `Html.Raw`, Jinja `|safe`/`Markup`, Django `mark_safe`.
- **URL contexts:** user-controlled `href`/`src` allow `javascript:` URLs unless the scheme is
  allow-listed (React warns but does not block all cases).
- **DOM sinks:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`,
  `eval` of fragments, `postMessage` handlers without origin checks.
- **Rich text / markdown:** rendered to HTML without an allow-list sanitizer (DOMPurify, HtmlSanitizer,
  bleach/nh3); sanitizer configured to allow `style`/`on*`/`iframe`.
- **JSON in HTML:** server-rendered state (`<script>window.__STATE__ = ...`) without escaping `</script>`.
- **Defense in depth:** Content-Security-Policy (no `unsafe-inline` for scripts), `X-Content-Type-Options`.
  A missing CSP alone is hardening, not a vulnerability.

Severity: stored XSS in an authenticated app handling money/PII → high (session/action hijack);
reflected XSS behind auth → medium; self-XSS → low/info.
