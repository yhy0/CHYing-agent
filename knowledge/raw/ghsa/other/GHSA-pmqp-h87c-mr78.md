# XML Entity Expansion and Improper Input Validation in Kubernetes API server

**GHSA**: GHSA-pmqp-h87c-mr78 | **CVE**: CVE-2019-11253 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-20, CWE-776

**Affected Packages**:
- **k8s.io/kubernetes** (go): >= 1.0.0, < 1.13.12
- **k8s.io/kubernetes** (go): >= 1.14.0, < 1.14.8
- **k8s.io/kubernetes** (go): >= 1.15.0, < 1.15.5
- **k8s.io/kubernetes** (go): >= 1.16.0, < 1.16.2

## Description

Improper input validation in the Kubernetes API server in versions v1.0-1.12 and versions prior to v1.13.12, v1.14.8, v1.15.5, and v1.16.2 allows authorized users to send malicious YAML or JSON payloads, causing the API server to consume excessive CPU or memory, potentially crashing and becoming unavailable. Prior to v1.14.0, default RBAC policy authorized anonymous users to submit requests that could trigger this vulnerability. Clusters upgraded from a version prior to v1.14.0 keep the more permissive policy by default for backwards compatibility.

### Specific Go Packages Affected
k8s.io/kubernetes/pkg/apiserver
