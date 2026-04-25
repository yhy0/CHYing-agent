# Hashicorp Vault vulnerable to Improper Check or Handling of Exceptional Conditions 

**GHSA**: GHSA-2qmw-pvf7-4mw6 | **CVE**: CVE-2024-6468 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-703

**Affected Packages**:
- **github.com/hashicorp/vault** (go): >= 1.16.0-rc1, < 1.16.3
- **github.com/hashicorp/vault** (go): >= 1.17.0-rc1, < 1.17.2
- **github.com/hashicorp/vault** (go): >= 1.10.0, < 1.15.12

## Description

Vault and Vault Enterprise did not properly handle requests originating from unauthorized IP addresses when the TCP listener option, proxy_protocol_behavior, was set to deny_unauthorized. When receiving a request from a source IP address that was not listed in proxy_protocol_authorized_addrs, the Vault API server would shut down and no longer respond to any HTTP requests, potentially resulting in denial of service.

While this bug also affected versions of Vault up to 1.17.1 and 1.16.5, a separate regression in those release series did not allow Vault operators to configure the deny_unauthorized option, thus not allowing the conditions for the denial of service to occur.

Fixed in Vault and Vault Enterprise 1.17.2, 1.16.6, and 1.15.12
