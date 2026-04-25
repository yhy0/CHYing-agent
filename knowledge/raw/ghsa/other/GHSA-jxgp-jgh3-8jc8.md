# KubeOperator allows unauthorized access to system API

**GHSA**: GHSA-jxgp-jgh3-8jc8 | **CVE**: CVE-2023-22480 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-285, CWE-863

**Affected Packages**:
- **github.com/KubeOperator/KubeOperator** (go): <= 3.16.3

## Description

### Summary

Unauthorized access refers to the ability to bypass the system's preset permission settings to access some API interfaces. The attack exploits a flaw in how online applications handle routing permissions.

### Affected Version

<= v3.16.3

### Patches

The vulnerability has been fixed in v3.16.3.

https://github.com/KubeOperator/KubeOperator/commit/7ef42bf1c16900d13e6376f8be5ecdbfdfb44aaf

### Workarounds

It is recommended to upgrade the version to v3.16.4.

### For more information

If you have any questions or comments about this advisory, please open an issue.

### References

https://github.com/KubeOperator/KubeOperator/releases/tag/v3.16.4
