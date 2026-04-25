# CasaOS contains weak JWT secrets

**GHSA**: GHSA-m5q5-8mfw-p2hr | **CVE**: CVE-2023-37266 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-287, CWE-1391

**Affected Packages**:
- **github.com/IceWhaleTech/CasaOS** (go): < 0.4.4

## Description

### Impact

Unauthenticated attackers can craft arbitrary JWTs and access features that usually require authentication and execute arbitrary commands as `root` on CasaOS instances.

### Patches

The problem was addressed by improving the validation of JWTs in 705bf1f. This patch is part of CasaOS 0.4.4.

### Workarounds

Users should upgrade to CasaOS 0.4.4. If they can't, they should temporarily restrict access to CasaOS to untrusted users, for instance by not exposing it publicly.

### References

- 705bf1f
- https://www.sonarsource.com/blog/security-vulnerabilities-in-casaos/

