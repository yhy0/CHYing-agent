# Hashicorp Vault vulnerable to denial of service through memory exhaustion

**GHSA**: GHSA-g233-2p4r-3q7v | **CVE**: CVE-2024-8185 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-636

**Affected Packages**:
- **github.com/hashicorp/vault** (go): >= 1.2.0, < 1.18.1
- **github.com/openbao/openbao** (go): < 2.0.3

## Description

Vault Community and Vault Enterprise (“Vault”) clusters using Vault’s Integrated Storage backend are vulnerable to a denial-of-service (DoS) attack through memory exhaustion through a Raft cluster join API endpoint. An attacker may send a large volume of requests to the endpoint which may cause Vault to consume excessive system memory resources, potentially leading to a crash of the underlying system and the Vault process itself.

This vulnerability, CVE-2024-8185, is fixed in Vault Community 1.18.1 and Vault Enterprise 1.18.1, 1.17.8, and 1.16.12.
