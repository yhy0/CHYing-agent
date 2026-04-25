# Meshery SQL Injection vulnerability

**GHSA**: GHSA-652r-q29p-m25h | **CVE**: CVE-2024-29031 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/layer5io/meshery** (go): < 0.7.17

## Description

Meshery is an open source, cloud native manager that enables the design and management of Kubernetes-based infrastructure and applications. A SQL injection vulnerability in Meshery prior to version 0.7.17 allows a remote attacker to obtain sensitive information via the `order` parameter of `GetMeshSyncResources`. Version 0.7.17 contains a patch for this issue.
