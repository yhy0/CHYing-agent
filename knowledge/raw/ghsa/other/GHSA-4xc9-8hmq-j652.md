# go-ethereum vulnerable to DoS via malicious p2p message

**GHSA**: GHSA-4xc9-8hmq-j652 | **CVE**: CVE-2024-32972 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/ethereum/go-ethereum** (go): < 1.13.15

## Description

### Impact

A vulnerable node can be made to consume very large amounts of memory when handling specially crafted p2p messages sent from an attacker node.

In order to carry out the attack, the attacker establishes a peer connections to the victim, and sends a malicious `GetBlockHeadersRequest` message with a `count` of  `0`, using the `ETH` protocol. 

In `descendants := chain.GetHeadersFrom(num+count-1, count-1)`, the value of `count-1` is passed to the function `GetHeadersFrom(number, count uint64)` as parameter `count`. Due to integer overflow, `UINT64_MAX` value is then passed as the `count` argument to function `GetHeadersFrom(number, count uint64)`. This allows an attacker to bypass `maxHeadersServe` and request all headers from the latest block back to the genesis block. 

### Patches

The fix has been included in geth version `1.13.15` and onwards. 

The vulnerability was patched in: https://github.com/ethereum/go-ethereum/pull/29534

### Workarounds

No workarounds have been made public. 

### References

No more information is released at this time.

### Credit

This issue was disclosed responsibly by DongHan Kim via the Ethereum bug bounty program. Thank you for your cooperation. 
