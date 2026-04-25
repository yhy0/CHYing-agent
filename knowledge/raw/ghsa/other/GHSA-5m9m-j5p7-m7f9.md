# Casdoor is vulnerable to Improper Authorization

**GHSA**: GHSA-5m9m-j5p7-m7f9 | **CVE**: CVE-2025-61524 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-285

**Affected Packages**:
- **github.com/casdoor/casdoor** (go): < 2.63.0

## Description

An issue in the permission verification module and organization/application editing interface in Casdoor before 2.63.0 allows remote authenticated administrators of any organization within the system to bypass the system's permission verification mechanism by directly concatenating URLs after login.
