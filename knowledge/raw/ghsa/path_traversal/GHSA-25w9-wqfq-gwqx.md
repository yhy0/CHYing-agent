# SiYuan has an arbitrary file read and path traversal via /api/export/exportResources

**GHSA**: GHSA-25w9-wqfq-gwqx | **CVE**: CVE-2024-55658 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/siyuan-note/siyuan/kernel** (go): <= 0.0.0-20241210012039-5129ad926a21

## Description

### Summary

Siyuan's /api/export/exportResources endpoint is vulnerable to arbitary file read via path traversal. It is possible to manipulate the paths parameter to access and download arbitrary files from the host system by traversing the workspace directory structure.

### Impact
Arbitrary File Read
