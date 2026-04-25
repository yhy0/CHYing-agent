# HashiCorp Vault Incorrect Permission Assignment for Critical Resource

**GHSA**: GHSA-pfmw-vj74-ph8g | **CVE**: CVE-2021-43998 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-732

**Affected Packages**:
- **github.com/hashicorp/vault** (go): >= 1.8.0, < 1.8.5
- **github.com/hashicorp/vault** (go): >= 0.11.0, < 1.7.6

## Description

HashiCorp Vault and Vault Enterprise 0.11.0 up to 1.7.5 and 1.8.4 templated ACL policies would always match the first-created entity alias if multiple entity aliases exist for a specified entity and mount combination, potentially resulting in incorrect policy enforcement. Fixed in Vault and Vault Enterprise 1.7.6, 1.8.5, and 1.9.0.
