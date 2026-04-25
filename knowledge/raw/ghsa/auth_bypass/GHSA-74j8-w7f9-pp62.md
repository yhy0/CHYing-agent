# Improper configuration of RBAC permissions obtaining cluster control permissions

**GHSA**: GHSA-74j8-w7f9-pp62 | **CVE**: CVE-2023-33190 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-287, CWE-863

**Affected Packages**:
- **github.com/labring/sealos** (go): < 4.2.1-rc4

## Description

### Summary
Improper configuration of RBAC permissions resulted in obtaining cluster control permissions, which could control the entire cluster deployed with Sealos, as well as hundreds of pods and other resources within the cluster.

### Details
detail's is disable by publish.

### PoC
detail's is disable by publish.

### Impact
+ sealos public cloud user
+ CWE-287 Improper Authentication

