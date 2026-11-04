---
id: injection
title: Injection — SQL, NoSQL, OS command, template, LDAP, header, log
owasp: A05
cwe: [CWE-89, CWE-943, CWE-78, CWE-1336, CWE-90, CWE-113, CWE-117]
languages: [csharp, js, python, java, go, php, ruby, sql]
triggers: ['(?i)select |insert |update |delete |exec|query|command|process|spawn|shell|template|render|ldap|header']
---
# Injection

For each sink: (1) what reaches it, (2) can a caller influence it, (3) is the framework's safe API
used. Most false positives come from skipping step 3.

## Safe by construction (usually refutes a candidate)
- EF Core LINQ, `FromSql`/`ExecuteSql` with interpolation (FormattableString → parameters).
- Dapper / ADO.NET / pg / mysql2 with placeholders and a separate values argument.
- Prisma query API and tagged `$queryRaw\`...\``; TypeORM query builder with parameters.
- `execFile`/`spawn` with an argument array and no shell; `subprocess.run([...])`.

## Still dangerous with a "safe" API
- Identifiers cannot be parameterized: dynamic `ORDER BY`, column/table names, `ASC/DESC` must be
  allow-listed.
- `LIKE` patterns with user wildcards (performance/DoS, data probing).
- Stored procedures that build dynamic SQL internally (`EXEC(@sql)`, `sp_executesql` with
  concatenation) — check the .sql files, not only the calling code.
- ORMs' raw fragments: `Sequelize.literal`, `knex.raw`, `whereRaw`, SQLAlchemy `text()` with f-strings.
- NoSQL: request objects passed as filters (`{"$ne": null}`), `$where`, `$regex` from input.
- Server-side template injection: user input used as the template (not as a variable) in Razor
  runtime compilation, Handlebars/EJS/Pug/Jinja2 `Template(user_input)`.
- Header/response splitting: user values in `Location`, `Set-Cookie`, custom headers without CR/LF
  stripping. Log injection/forging: raw user input with newlines in logs used for audit.
- LDAP filters built by concatenation; XPath; regex built from input (ReDoS).

## Reporting
Name the exact source (e.g. `[FromQuery] string sort`) and the sink line. The attack scenario is
described in words ("the sort parameter is appended to ORDER BY, letting a caller alter the query
and extract other columns") — no payloads.
