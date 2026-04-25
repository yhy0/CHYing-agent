# Go-Ethereum vulnerable to denial of service via malicious p2p message

**GHSA**: GHSA-ppjg-v974-84cm | **CVE**: CVE-2023-40591 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/ethereum/go-ethereum** (go): < 1.12.1-stable

## Description

### Impact

A vulnerable node, can be made to consume unbounded amounts of memory when handling specially crafted p2p messages sent from an attacker node.

### Details

The p2p handler spawned a new goroutine to respond to `ping` requests. By flooding a node with ping requests, an unbounded number of goroutines can be created, leading to resource exhaustion and potentially crash due to OOM.

### Patches

The fix is included in geth version `1.12.1-stable`, i.e, `1.12.2-unstable` and onwards. 

Fixed by https://github.com/ethereum/go-ethereum/pull/27887

### Workarounds

No known workarounds. 

### Credits

This bug was reported by Patrick McHardy and reported via [bounty@ethereum.org](mailto:bounty@ethereum.org). 

### References


