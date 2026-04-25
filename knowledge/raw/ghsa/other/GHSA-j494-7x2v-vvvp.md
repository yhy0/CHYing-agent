# mx-chain-go's relayed transactions always increment nonce

**GHSA**: GHSA-j494-7x2v-vvvp | **CVE**: CVE-2023-34458 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/multiversx/mx-chain-go** (go): < 1.4.17

## Description

### Impact
When executing a relayed transaction, if the inner transaction failed, it would have increased the inner transaction's sender account nonce. This could have contributed to a limited DoS attack on a targeted account. The fix is a breaking change so a new flag `RelayedNonceFixEnableEpoch` was needed. This was a strict processing issue while validating blocks on a chain.

### Patches
v1.4.17 and later versions contain the fix for this issue

### Workarounds
there were no workarounds for this issue. The affected account could only wait for the DoS attack to finish as the attack was not free or to attempt to send transactions in a very fast manner so as to compete on the same nonce with the attacker.

### References
For the future understanding of this issue, on v1.4.17 and onwards versions, we have this integration test that addresses the issue and tests the fix. 
https://github.com/multiversx/mx-chain-go/blob/babdb144f1316ab6176bf3dbd7d4621120414d43/integrationTests/vm/txsFee/relayedMoveBalance_test.go#LL165C14-L165C14

