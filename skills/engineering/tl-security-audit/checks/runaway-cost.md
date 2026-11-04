---
id: runaway-cost
title: Runaway loops and uncontrolled billing risk
owasp: A06
cwe: [CWE-834, CWE-400, CWE-770]
languages: [csharp, js, python, java, go, yaml, terraform, toml]
triggers: ['(?i)retry|requeue|nack|cron|schedule|interval|recurring|webhook|callback|publish|emit|enqueue|durable|worker|lambda|function|queue']
---
# Runaway loops / uncontrolled cost

Blast radius is financial or availability, not "a slow request": a self-triggering retry loop has
created billions of cloud objects and a five-figure bill within hours before anyone noticed.

## Look for
- **Self-triggering handlers:** a webhook/callback that ends up calling itself (directly or via
  another service); an event handler emitting the event type it consumes; an actor/durable object/
  worker that spawns another of its kind.
- **Unbounded retries:** any retry/requeue path missing *either* a max-attempt cap *or* backoff —
  one without the other is still unsafe. Poison messages without a dead-letter queue.
- **Overlapping schedules:** cron/recurring jobs with no lock or idempotency guard; jobs running on
  every replica.
- **Fan-out without ceiling:** one request/event creating N calls/resources where N is unbounded
  (recursive job spawning, pagination-driven fan-out).
- **Missing platform safeguards:** no budget alert, spending cap, concurrency limit or rate limit on
  pay-per-use resources (serverless, LLM APIs, SMS/email providers, queues). Check IaC and config.

## Severity rule (overrides normal performance severity)
When the pattern targets a resource billed per invocation/object/request — or would exhaust a quota
badly enough to take the service down — classify **high** (critical if nothing bounds it at any
layer), regardless of how small the code change looks. Use `kind: cost-risk`. State the blast
radius plainly and apply this **regardless of the project's current billing plan**: on a free tier
it is an availability risk; on pay-per-use (or a client reusing the code on a paid account) it is a
direct financial risk.
