# Incorrect TLS certificate auth method in Vault

**GHSA**: GHSA-r3w7-mfpm-c2vw | **CVE**: CVE-2024-2048 | **Severity**: high (CVSS 8.1)

**CWE**: N/A

**Affected Packages**:
- **github.com/hashicorp/vault** (go): >= 1.15.0, < 1.15.5
- **github.com/hashicorp/vault** (go): < 1.14.10

## Description

Vault and Vault Enterprise (“Vault”) TLS certificate auth method did not correctly validate client certificates when configured with a non-CA certificate as trusted certificate. In this configuration, an attacker may be able to craft a malicious certificate that could be used to bypass authentication. Fixed in Vault 1.15.5 and 1.14.10.
