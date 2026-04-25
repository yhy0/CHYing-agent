# KubePi may allow unauthorized access to system API

**GHSA**: GHSA-gqx8-hxmv-c4v4 | **CVE**: CVE-2023-22478 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-862

**Affected Packages**:
- **github.com/KubeOperator/kubepi** (go): <= 1.6.3

## Description

### Summary
Unauthorized access refers to the ability to bypass the system's preset permission settings to access some API interfaces. The attack exploits a flaw in how online applications handle routing permissions.

### Affected Version
<= v1.6.3

### Patches
The vulnerability has been fixed in v1.6.4.

https://github.com/KubeOperator/KubePi/commit/0c6774bf5d9003ae4d60257a3f207c131ff4a6d6

### Workarounds
It is recommended to upgrade the version to v1.6.4.

### For more information
If you have any questions or comments about this advisory, please open an issue.

### References
https://github.com/KubeOperator/KubePi/releases/tag/v1.6.4
