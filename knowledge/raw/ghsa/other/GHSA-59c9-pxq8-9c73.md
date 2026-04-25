# Improper JWT Signature Validation in SAP Security Services Library 

**GHSA**: GHSA-59c9-pxq8-9c73 | **CVE**: CVE-2023-50422 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269

**Affected Packages**:
- **com.sap.cloud.security:java-security** (maven): < 2.17.0
- **com.sap.cloud.security:java-security** (maven): >= 3.0.0, < 3.3.0
- **com.sap.cloud.security:spring-security** (maven): < 2.17.0
- **com.sap.cloud.security:spring-security** (maven): >= 3.0.0, < 3.3.0
- **com.sap.cloud.security.xsuaa:spring-xsuaa** (maven): < 2.17.0
- **com.sap.cloud.security.xsuaa:spring-xsuaa** (maven): >= 3.0.0, < 3.3.0

## Description

### Impact
SAP BTP Security Services Integration Library ([Java] cloud-security-services-integration-library) allows under certain conditions an escalation of privileges. On successful exploitation, an unauthenticated attacker can obtain arbitrary permissions within the application.

### Patches
Upgrade to patched version >= 2.17.0 or >= 3.3.0 
We always recommend to upgrade to the latest released version.

### Workarounds
No workarounds

### References
https://www.cve.org/CVERecord?id=CVE-2023-50422

