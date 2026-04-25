# Open Cluster Management vulnerable to Trust Boundary Violation

**GHSA**: GHSA-jhh6-6fhp-q2xp | **CVE**: CVE-2024-9779 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-266, CWE-501

**Affected Packages**:
- **open-cluster-management.io/ocm** (go): < 0.13.0

## Description

A flaw was found in Open Cluster Management (OCM) when a user has access to the worker nodes which contain the cluster-manager or klusterlet deployments. The cluster-manager deployment uses a service account with the same name "cluster-manager" which is bound to a ClusterRole also named "cluster-manager", which includes the permission to create Pod resources. If this deployment runs a pod on an attacker-controlled node, the attacker can obtain the cluster-manager's token and steal any service account token by creating and mounting the target service account to control the whole cluster.
