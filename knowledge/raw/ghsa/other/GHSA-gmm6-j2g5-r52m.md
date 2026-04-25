# Vault’s Terraform Provider incorrectly set default deny_null_bind parameter for LDAP auth method to false by default

**GHSA**: GHSA-gmm6-j2g5-r52m | **CVE**: CVE-2025-13357 | **Severity**: high (CVSS 7.4)

**CWE**: CWE-1188

**Affected Packages**:
- **github.com/hashicorp/terraform-provider-vault** (go): < 5.5.0

## Description

Vault’s Terraform Provider incorrectly set the default deny_null_bind parameter for the LDAP auth method to false by default, potentially resulting in an insecure configuration. If the underlying LDAP server allowed anonymous or unauthenticated binds, this could result in authentication bypass. This vulnerability, CVE-2025-13357, is fixed in Vault Terraform Provider v5.5.0.
