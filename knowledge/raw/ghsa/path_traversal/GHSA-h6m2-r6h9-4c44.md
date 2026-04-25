# BBOT's insufficient sanitization issues in gitdumper.py can lead to RCE

**GHSA**: GHSA-h6m2-r6h9-4c44 | **CVE**: CVE-2025-10283 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-22

**Affected Packages**:
- **bbot** (pip): < 2.7.0

## Description

### Summary

bbot's `gitdumper.py` insufficiently sanitises a `.git/config` file, leading to Remote Code Execution (RCE).

bbot's `gitdumper.py` can be made to consume a malicious `.git/index` file, leading to arbitrary file write which can be used to achieve Remote Code Execution (RCE).

### Impact

A user who uses bbot to scan a malicious webserver may have arbitrary code executed on their system.
