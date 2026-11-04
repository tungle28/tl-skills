---
id: infrastructure-containers
title: Containers, Kubernetes and cloud infrastructure
owasp: A02
cwe: [CWE-250, CWE-284, CWE-732, CWE-16]
languages: [dockerfile, yaml, terraform, json]
triggers: ['(?i)FROM |kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|Ingress|Service)|resource\s+"|securityContext|services:']
---
# Infrastructure

- **Containers:** non-root user, minimal base, no secrets in layers, read-only root filesystem where
  possible, no unnecessary packages (compilers, shells) in runtime stages.
- **Kubernetes:** securityContext (runAsNonRoot, drop ALL, no privilege escalation), resource
  limits, NetworkPolicies (default deny), no hostPath/hostNetwork, secrets not in plain ConfigMaps,
  service accounts with minimal RBAC and `automountServiceAccountToken: false` when unused,
  Ingress TLS.
- **Cloud (Terraform/Bicep/CloudFormation):** public storage, open security groups for management
  and database ports, encryption at rest, public database endpoints, overly broad IAM (`*` actions
  or resources), missing logging (CloudTrail/Activity logs), key rotation.
- **Compose files used beyond local dev:** default passwords, exposed database ports.
