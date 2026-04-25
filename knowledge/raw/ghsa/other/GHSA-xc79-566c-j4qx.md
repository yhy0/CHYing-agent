# Parallax is vulnerable to DoS via malicious p2p message

**GHSA**: GHSA-xc79-566c-j4qx | **CVE**: N/A | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/microstack-tech/parallax** (go): < 0.1.4

## Description

### Impact

A vulnerable node can be made to consume very large amounts of memory when handling specially crafted p2p messages sent from an attacker node.

In order to carry out the attack, the attacker establishes a peer connections to the victim, and sends a malicious `GetBlockHeadersRequest` message with a `count` of `0`, using the `Parallax` protocol.

In `descendants := chain.GetHeadersFrom(num+count-1, count-1)`, the value of `count-1` is passed to the function `GetHeadersFrom(number, count uint64)` as parameter `count`. Due to integer overflow, `UINT64_MAX` value is then passed as the `count` argument to function `GetHeadersFrom(number, count uint64)`. This allows an attacker to bypass `maxHeadersServe` and request all headers from the latest block back to the genesis block.

### Patches

The fix has been included in the Parallax client version `0.1.4` and onwards.

The vulnerability was patched in: https://github.com/microstack-tech/parallax/commit/f759e9090aaf00a43c616d7cbd133c44bb1ed01e

### Workarounds

No workarounds have been made public.

### Credit

This issue was disclosed responsibly by DongHan Kim via the Ethereum bug bounty program, the cooperation is appreciated.
