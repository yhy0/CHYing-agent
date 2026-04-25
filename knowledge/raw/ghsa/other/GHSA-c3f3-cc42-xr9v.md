# Apache Camel: KeycloakSecurityPolicy does not validate issuer of JWT tokens against configured realm

**GHSA**: GHSA-c3f3-cc42-xr9v | **CVE**: CVE-2026-23552 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-346

**Affected Packages**:
- **org.apache.camel:camel-keycloak** (maven): >= 4.15.0, < 4.18.0

## Description

Cross-Realm Token Acceptance Bypass in KeycloakSecurityPolicy Apache Camel Keycloak component. 

The Camel-Keycloak KeycloakSecurityPolicy does not validate the iss (issuer) claim of JWT tokens against the configured realm. A token issued by one Keycloak realm is silently accepted by a policy configured for a completely different realm, breaking tenant isolation.
This issue affects Apache Camel: from 4.15.0 before 4.18.0.

Users are recommended to upgrade to version 4.18.0, which fixes the issue.
