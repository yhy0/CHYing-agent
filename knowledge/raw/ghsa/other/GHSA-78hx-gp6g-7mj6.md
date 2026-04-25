# Memory leaks in code encrypting and verifying RSA payloads

**GHSA**: GHSA-78hx-gp6g-7mj6 | **CVE**: CVE-2024-1394 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400, CWE-401

**Affected Packages**:
- **github.com/golang-fips/go** (go): <= 1.22.1
- **github.com/golang-fips/openssl/v2** (go): <= 2.0.0
- **github.com/microsoft/go-crypto-openssl** (go): <= 0.2.8
- **github.com/microsoft/go-crypto-openssl/openssl** (go): <= 0.2.8

## Description

Using crafted public RSA keys which are not compliant with SP 800-56B can cause a small memory leak when encrypting and verifying payloads.

An attacker can leverage this flaw to gradually erode available memory to the point where the host crashes for lack of resources. Upon restart the attacker would have to begin again, but nevertheless there is the potential to deny service.
