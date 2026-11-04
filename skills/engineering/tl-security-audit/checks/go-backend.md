---
id: go-backend
title: Go backend pitfalls
owasp: A06
cwe: [CWE-362, CWE-400, CWE-190, CWE-252, CWE-770]
languages: [go]
---
# Go-specific review points

- **Router groups and middleware order:** auth middleware must be attached before the routes it
  protects (`r.Group("/api", authMW)`, `e.Group(...).Use(...)`, `chi.Route(...)` + `r.Use`). Routes
  registered on the root router or before `Use()` are unguarded. Check `NoRoute`/static handlers too.
- **Context and timeouts:** outbound HTTP/DB calls without `context` deadlines; `http.DefaultClient`
  (no timeout); `http.Server` without Read/Write/Idle timeouts; unbounded `io.ReadAll(r.Body)`.
- **Data races:** maps or counters shared across goroutines/handlers without a mutex (a race on a
  balance/limit/rate-limit map is a correctness *and* security bug). Suggest `go test -race` coverage.
- **Integer handling:** `strconv.Atoi` → `int32`/`uint` conversions that overflow; amounts in `float64`
  (use integer minor units or `shopspring/decimal`).
- **Ignored errors:** `_ = tx.Commit()`, unchecked `rows.Err()`, unchecked `Close()` on writers,
  ignored errors from signature/crypto verification → fail-open paths (A10).
- **SQL:** `database/sql`/pgx/sqlx placeholders only protect *values*; dynamic `ORDER BY`/column
  names need allow-lists; sqlc queries filtered by `id` only need an owner/tenant clause or a proven
  scoped caller (gate `go-sql-no-tenant`).
- **Binding / mass assignment:** `c.ShouldBind(&entity)` / `json.Decode(&model)` straight into a DB
  model lets callers set `Role`, `OwnerID`, `Balance` — bind into request DTOs.
- **Goroutine fan-out:** `go func()` per item with no semaphore/errgroup limit; panics in goroutines
  without recover crashing the process; background work using the request context after return.
- **gRPC:** auth interceptors applied to both unary and stream servers; reflection service enabled
  in production; plaintext `grpc.WithInsecure()` / `insecure.NewCredentials()` on non-local links.
