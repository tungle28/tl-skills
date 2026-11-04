---
id: api-data-exposure
title: API data exposure and input validation
owasp: A01
cwe: [CWE-213, CWE-915, CWE-20]
languages: [csharp, js, python, java, go]
triggers: ['(?i)dto|response|return Ok|res\.json|serializ|select|include|toJSON|model_dump|schema']
---
# API data exposure

- **Excessive data exposure:** returning entities instead of DTOs (password hashes, internal flags,
  other users' fields, tenant ids); `.Include()` chains leaking related records; GraphQL resolvers
  without field-level authorization.
- **Mass assignment:** see access-control; also `[Bind]`-less MVC models, `Object.assign`,
  `**request.json`, Mongoose `new Model(req.body)`.
- **Validation:** server-side validation of types, ranges, lengths and formats at the boundary
  (FluentValidation, DataAnnotations, class-validator with `whitelist: true, forbidNonWhitelisted`,
  pydantic). Client-only validation is not a control.
- **Enumeration:** sequential ids plus verbose "not found" vs "forbidden" responses revealing existence.
