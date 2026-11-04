---
id: nuxt-server
title: Nuxt / Nitro full-stack security
owasp: A01
cwe: [CWE-639, CWE-306, CWE-200, CWE-602, CWE-918]
languages: [js]
frameworks: [nuxt]
---
# Nuxt / Nitro

A Nuxt app is two programs sharing one repo: browser code (pages, components, composables,
`middleware/`) that attackers fully control, and server code (`server/**`) that is the real API.

- **Server routes are public HTTP endpoints.** Every file in `server/api` and `server/routes` is
  reachable directly, regardless of which pages call it. Each needs its own session check
  (`requireUserSession`, `getServerSession`, `event.context.user` set by `server/middleware`) *and*
  an ownership/tenant check for ids from `getRouterParam`/`getQuery`/`readBody`.
- **Route middleware (`middleware/*.ts`, `definePageMeta({ middleware })`) is not access control.**
  It hides pages; it does not protect data. Find the server route or backend API behind each
  protected page and confirm it enforces the same rule.
- **Backend-for-frontend delegation:** when server routes proxy to a backend (`$fetch(apiBase + …)`,
  `proxyRequest`), confirm the backend authenticates the *user* (forwarded token) and enforces
  ownership itself. A service token shared by all users turns the Nuxt layer into the only guard.
- **Payload and config exposure:** `runtimeConfig.public`, `app.config`, and anything placed in
  `useState` / `useAsyncData` during SSR is serialized into the page (`window.__NUXT__`). Server-only
  secrets must be read only in `server/`. Check for full DB objects (password hashes, internal
  fields) returned from server routes and rendered into the payload.
- **Validation:** prefer `readValidatedBody` / `getValidatedQuery` with a strict schema; `readBody`
  passed into ORM writes is mass assignment.
- **SSR-specific XSS:** `v-html`, `useHead({ script: [{ innerHTML: … }] })` or `innerHTML` with
  user data render on the server into HTML.
- **SSRF:** server routes fetching caller-supplied URLs (image proxies, link previews, `/api/proxy`).
- **CSRF:** cookie-session apps with state-changing routes should use SameSite cookies plus an
  origin/CSRF check (e.g. `nuxt-csurf`); nuxt-auth-utils sessions are cookie-based.
- **Nitro routeRules / headers:** CORS configuration, security headers (`nuxt-security` module or
  routeRules headers), caching of authenticated responses (`cache`/`swr` rules on per-user routes
  can serve one user's data to another).
