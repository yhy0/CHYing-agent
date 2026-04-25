# Improper Privilege Management in github.com/sap/cloud-security-client-go

**GHSA**: GHSA-m8rw-rcpq-2vp2 | **CVE**: CVE-2023-50424 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/sap/cloud-security-client-go** (go): < 0.17.0

## Description

### Impact
SAP BTP Security Services Integration Library ([Golang] github.com/sap/cloud-security-client-go) allows under certain conditions an escalation of privileges. On successful exploitation, an unauthenticated attacker can obtain arbitrary permissions within the application.

### Patches
Upgrade to patched version >= 0.17.0
We always recommend to upgrade to the latest released version.

### Workarounds
No workarounds

### References
https://www.cve.org/CVERecord?id=CVE-2023-50424
