# OpenShift GitOps authenticated attackers can obtain cluster root access through forged ArgoCD custom resources

**GHSA**: GHSA-pcqx-8qww-7f4v | **CVE**: CVE-2025-13888 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-266

**Affected Packages**:
- **github.com/redhat-developer/gitops-operator** (go): < 1.16.2

## Description

A flaw was found in OpenShift GitOps. Namespace admins can create ArgoCD Custom Resources (CRs) that trick the system into granting them elevated permissions in other namespaces, including privileged namespaces. An authenticated attacker can then use these elevated permissions to create privileged workloads that run on master nodes, effectively giving them root access to the entire cluster.
