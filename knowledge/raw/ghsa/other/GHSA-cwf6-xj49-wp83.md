#  OpenFeature Operator vulnerable to Cluster-level Privilege Escalation

**GHSA**: GHSA-cwf6-xj49-wp83 | **CVE**: CVE-2023-29018 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/open-feature/open-feature-operator** (go): < 0.2.32

## Description

### Impact

On a node controlled by an attacker or malicious user, the lax permissions configured on `open-feature-operator-controller-manager` can be used to further escalate the privileges of any service account in the cluster.

The increased privileges could be used to modify cluster state, leading to DoS, or read sensitive data, including secrets.

### Patches

The patch mitigates this issue by restricting the resources the `open-feature-operator-controller-manager` can modify.
