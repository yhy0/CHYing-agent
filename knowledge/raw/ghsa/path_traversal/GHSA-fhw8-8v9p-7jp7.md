# BBOT's various issues in unarchive.py can cause arbitrary file write and RCE

**GHSA**: GHSA-fhw8-8v9p-7jp7 | **CVE**: CVE-2025-10284 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-22

**Affected Packages**:
- **bbot** (pip): < 2.7.0

## Description

### Summary

Various issues in bbot's `unarchive.py` allow a malicious site to cause bbot to write arbitrary files to arbitrary locations. This can be used to achieve Remote Code Execution (RCE).

### Impact

A user who uses bbot to scan a malicious webserver may have arbitrary code executed on their system.
