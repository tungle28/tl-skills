---
id: llm-integration
title: LLM / AI feature integration
owasp: A05
cwe: [CWE-77, CWE-200, CWE-285]
languages: [csharp, js, python]
frameworks: [llm]
---
# LLM integrations (see also OWASP Top 10 for LLM Applications)

- **Prompt injection:** untrusted content (emails, documents, web pages, user messages) placed in
  prompts that can trigger tools/actions. Controls: tool allow-lists per context, human
  confirmation for side effects, least-privilege credentials for tools, separating instructions
  from data.
- **Excessive agency:** the model can call tools that act across users/tenants (DB queries without
  the caller's scope, sending email, payments).
- **Output handling:** model output rendered as HTML (XSS), executed as code/SQL/shell, or used in
  URLs (SSRF) without validation.
- **Data exposure:** secrets/PII in system prompts or logs; cross-user data in shared context/caches;
  retrieval (RAG) without per-user authorization on documents.
- **Cost/abuse:** no per-user rate or token limits; API keys in client code (see runaway-cost).
