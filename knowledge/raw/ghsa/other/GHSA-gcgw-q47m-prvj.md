# Duplicate Advisory: Improper JWT Signature Validation in SAP Security Services Library 

**GHSA**: GHSA-gcgw-q47m-prvj | **CVE**: N/A | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269, CWE-639, CWE-749

**Affected Packages**:
- **com.sap.cloud.security:java-security** (maven): < 2.17.0
- **com.sap.cloud.security:java-security** (maven): >= 3.0.0, < 3.3.0
- **com.sap.cloud.security.xsuaa:spring-xsuaa** (maven): < 2.17.0
- **com.sap.cloud.security.xsuaa:spring-xsuaa** (maven): >= 3.0.0, < 3.3.0
- **com.sap.cloud.security:spring-security** (maven): < 2.17.0
- **com.sap.cloud.security:spring-security** (maven): >= 3.0.0, < 3.3.0

## Description

## Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-59c9-pxq8-9c73. This link is maintained to preserve external references.

## Original Description
SAP BTP Security Services Integration Library ([Java] cloud-security-services-integration-library) - versions below 2.17.0 and versions from 3.0.0 to before 3.3.0, allow under certain conditions an escalation of privileges. On successful exploitation, an unauthenticated attacker can obtain arbitrary permissions within the application.


