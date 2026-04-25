# Hashicorp Vault and Vault Enterprise vulnerable to a denial of service when processing JSON

**GHSA**: GHSA-vp5w-xcfc-73wf | **CVE**: CVE-2025-12044 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/hashicorp/vault** (go): >= 1.20.3, < 1.21.0

## Description

Vault and Vault Enterprise ("Vault") are vulnerable to an unauthenticated denial of service when processing JSON payloads. This occurs due to a regression from a previous fix for [+HCSEC-2025-24+|https://discuss.hashicorp.com/t/hcsec-2025-24-vault-denial-of-service-though-complex-json-payloads/76393]  which allowed for processing JSON payloads before applying rate limits. This vulnerability, CVE-2025-12044, is fixed in Vault Community Edition 1.21.0 and Vault Enterprise 1.16.27, 1.19.11, 1.20.5, and 1.21.0.
