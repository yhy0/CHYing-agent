# Keycloak path traversal vulnerability in redirection validation

**GHSA**: GHSA-72vp-xfrc-42xm | **CVE**: CVE-2024-1132 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **org.keycloak:keycloak-services** (maven): < 22.0.10
- **org.keycloak:keycloak-services** (maven): >= 23.0.0, < 24.0.3

## Description

A flaw was found in Keycloak, where it does not properly validate URLs included in a redirect. An attacker can use this flaw to construct a malicious request to bypass validation and access other URLs and potentially sensitive information within the domain or possibly conduct further attacks. This flaw affects any client that utilizes a wildcard in the Valid Redirect URIs field.

#### Acknowledgements:
Special thanks to Axel Flamcourt for reporting this issue and helping us improve our project.
