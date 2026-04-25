# libp2p nodes vulnerable to attack using large RSA keys

**GHSA**: GHSA-876p-8259-xjgg | **CVE**: CVE-2023-39533 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/libp2p/go-libp2p** (go): < 0.27.8
- **github.com/libp2p/go-libp2p** (go): >= 0.28.0, < 0.28.2
- **github.com/libp2p/go-libp2p** (go): = 0.29.0

## Description

### Impact
A malicious peer can use large RSA keys to run a resource exhaustion attack & force a node to spend time doing signature verification of the large key. This vulnerability is present in the core/crypto module of go-libp2p and can occur during the Noise handshake and the libp2p x509 extension verification step.
To prevent this attack, go-libp2p now restricts RSA keys to <= 8192 bits.

### Patches
Users should upgrade their go-libp2p versions to >=v0.27.8, >= v0.28.2, or >=v0.29.1
To protect your application, it's necessary to update to these patch releases **AND** to use the updated Go compiler (1.20.7 or 1.19.12, respectively)

### Workarounds
There are no known workarounds

### References
The Golang crypto/tls package also had this vulnerability ("verifying certificate chains containing large RSA keys is slow” https://github.com/golang/go/issues/61460)
Fix in golang/go crypto/tls: https://github.com/golang/go/commit/2350afd2e8ab054390e284c95d5b089c142db017
Fix in quic-go https://github.com/quic-go/quic-go/pull/4012

