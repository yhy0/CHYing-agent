# Observability Operator is vulnerable to Incorrect Privilege Assignment through its Custom Resource MonitorStack

**GHSA**: GHSA-mj6p-p843-x5wc | **CVE**: CVE-2025-2843 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-266

**Affected Packages**:
- **github.com/rhobs/observability-operator** (go): < 1.3.0

## Description

A flaw was found in the Observability Operator. The Operator creates a ServiceAccount with *ClusterRole* upon deployment of the *Namespace-Scoped* Custom Resource MonitorStack. This issue allows an adversarial Kubernetes Account with only namespaced-level roles, for example, a tenant controlling a namespace, to create a MonitorStack in the authorized namespace and then elevate permission to the cluster level by impersonating the ServiceAccount created by the Operator, resulting in privilege escalation and other issues.
