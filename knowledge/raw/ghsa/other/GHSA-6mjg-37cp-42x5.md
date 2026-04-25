# Improper Privilege Management in sap-xssec

**GHSA**: GHSA-6mjg-37cp-42x5 | **CVE**: CVE-2023-50423 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269

**Affected Packages**:
- **sap-xssec** (pip): < 4.1.0

## Description

### Impact

SAP BTP Security Services Integration Library ([Python] sap-xssec) allows under certain conditions an escalation of privileges. On successful exploitation, an unauthenticated attacker can obtain arbitrary permissions within the application.

### Patches
Upgrade to patched version >= 4.1.0
We always recommend to upgrade to the latest released version.

### Workarounds
No workarounds

### References
https://www.cve.org/CVERecord?id=CVE-2023-50423

