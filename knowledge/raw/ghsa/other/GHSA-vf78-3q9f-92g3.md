# Hard-coded System User Credentials in Folio Data Export Spring module 

**GHSA**: GHSA-vf78-3q9f-92g3 | **CVE**: CVE-2024-23687 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-798

**Affected Packages**:
- **org.folio:mod-data-export-spring** (maven): >= 2.0.0, < 2.0.2
- **org.folio:mod-data-export-spring** (maven): < 1.5.4

## Description

### Impact
The module creates a system user that is used to perform internal module-to-module operations.  Credentials for this user are hard-coded in the source code.  This makes it trivial to authenticate as this user, resulting in unauthorized access to potentially dangerous APIs, allowing to view and modify configuration including single-sign-on configuration, to read, add and modify user data, and to read and transfer fees/fines in a patron's account.

### Patches
Upgrade mod-data-export-spring to >=2.0.2, or a 1.5.x version >=1.5.4.

### Workarounds
No known workarounds.

### References
https://wiki.folio.org/x/hbMMBw - FOLIO Security Advisory with Upgrade Instructions
https://github.com/folio-org/mod-data-export-spring/commit/93aff4566bff59e30f4121b5a2bda5b0b508a446 - Fix
