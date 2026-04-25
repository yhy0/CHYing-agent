# Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable to remote code execution

**GHSA**: GHSA-xjw9-4gw8-4rqx | **CVE**: CVE-2026-26030 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94

**Affected Packages**:
- **semantic-kernel** (pip): < 1.39.4

## Description

### Impact:
An RCE vulnerability has been identified in Microsoft Semantic Kernel Python SDK, specifically within the `InMemoryVectorStore` filter functionality.

### Patches:
The problem has been fixed in [python-1.39.4](https://github.com/microsoft/semantic-kernel/releases/tag/python-1.39.4). Users should upgrade this version or higher.

### Workarounds:
Avoid using `InMemoryVectorStore` for production scenarios.

### References:
[Release python-1.39.4 · microsoft/semantic-kernel · GitHub](https://github.com/microsoft/semantic-kernel/releases/tag/python-1.39.4)
[PR to block use of dangerous attribute names that must not be accessed in filter expressions](https://github.com/microsoft/semantic-kernel/pull/13505)
