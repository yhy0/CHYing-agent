# Keycloak affected by improper invitation token validation

**GHSA**: GHSA-hcvw-475w-8g7p | **CVE**: CVE-2026-1529 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-347

**Affected Packages**:
- **org.keycloak:keycloak-services** (maven): >= 26.5.0, < 26.5.3
- **org.keycloak:keycloak-services** (maven): < 26.2.13
- **org.keycloak:keycloak-services** (maven): >= 26.3.0, < 26.4.9

## Description

A flaw was found in Keycloak. An attacker can exploit this vulnerability by modifying the organization ID and target email within a legitimate invitation token's JSON Web Token (JWT) payload. This lack of cryptographic signature verification allows the attacker to successfully self-register into an unauthorized organization, leading to unauthorized access.
