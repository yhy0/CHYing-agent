# CasaOS Gateway vulnerable to incorrect identification of source IP addresses

**GHSA**: GHSA-vjh7-5r6x-xh6g | **CVE**: CVE-2023-37265 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-306, CWE-348

**Affected Packages**:
- **github.com/IceWhaleTech/CasaOS-Gateway** (go): < 0.4.4

## Description

### Impact

Unauthenticated attackers can execute arbitrary commands as `root` on CasaOS instances.

### Patches

The problem was addressed by improving the detection of client IP addresses in 391dd7f. This patch is part of CasaOS 0.4.4.

### Workarounds

Users should upgrade to CasaOS 0.4.4. If they can't, they should temporarily restrict access to CasaOS to untrusted users, for instance by not exposing it publicly. 

### References

- 391dd7f
- https://www.sonarsource.com/blog/security-vulnerabilities-in-casaos/
