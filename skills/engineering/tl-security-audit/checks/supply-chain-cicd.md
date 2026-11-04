---
id: supply-chain-cicd
title: Software supply chain and CI/CD
owasp: A03
cwe: [CWE-1104, CWE-829, CWE-494, CWE-427]
languages: [yaml, json, xml, dockerfile, groovy, toml, ini]
triggers: ['(?i)uses:|steps:|pipeline|workflow|dependencies|PackageReference|FROM |registry|npmrc|nuget']
---
# Supply chain and pipelines (A03 — new in 2025)

- **Dependencies:** deps phase lists known CVEs and hygiene findings; review adds *reachability*:
  is the vulnerable function used? A critical CVE in a dev-only tool is lower priority than a
  medium one in the request path.
- **Integrity:** lockfiles committed and used (`npm ci`, `dotnet restore --locked-mode`,
  `pip install --require-hashes`); private registries configured so internal package names cannot
  be claimed on public registries (dependency confusion — scoped packages, `packageSourceMapping`
  in NuGet.config).
- **Pipelines:** untrusted input in scripts (`${{ github.event.* }}`), `pull_request_target` with
  checkout of PR code, third-party actions not pinned to SHA, broad token permissions, secrets
  available to fork PRs, self-hosted runners on public repos, deployment jobs without environment
  protection/approvals.
- **Artifacts:** images built from unpinned bases, no image scanning/signing, artifacts downloaded
  over HTTP or without checksums.
- **Azure DevOps:** secret variables echoed, `System.AccessToken` exposed to scripts from forks,
  pipelines editable by anyone who can push a branch (YAML from the branch runs with production service connections).
