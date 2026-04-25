# btcd did not correctly re-implement Bitcoin Core's "FindAndDelete()" functionality

**GHSA**: GHSA-27vh-h6mc-q6g8 | **CVE**: CVE-2024-38365 | **Severity**: high (CVSS 7.4)

**CWE**: CWE-670

**Affected Packages**:
- **github.com/btcsuite/btcd** (go): < 0.24.2-beta.rc1

## Description

### Impact

The btcd Bitcoin client (versions 0.10 to 0.24) did not correctly re-implement Bitcoin Core's "FindAndDelete()" functionality. This
logic is consensus-critical: the difference in behavior with the other Bitcoin clients can lead to btcd clients accepting an invalid Bitcoin block (or rejecting a valid one). 

This consensus failure can be leveraged to cause a chain split (accepting an invalid Bitcoin block) or be exploited to DoS the btcd nodes (rejecting a valid Bitcoin block). An attacker can create a standard transaction where FindAndDelete doesn't return a match but removeOpCodeByData does making btcd get a different sighash, leading to a chain split. Importantly, this vulnerability can be exploited remotely by any Bitcoin user and does not require any hash power. This is because the difference in behavior can be triggered by a "standard" Bitcoin
transaction, that is a transaction which gets relayed through the P2P network before it gets included in a Bitcoin block.

#### `FindAndDelete` vs. `removeOpcodeByData`

`removeOpcodeByData(script []byte, dataToRemove []byte)` removes any data pushes from `script` that *contain* `dataToRemove`. However, `FindAndDelete` only removes *exact* matches. So for example, with `script = "<data> <data||foo>"` and `dataToRemove = "data"` btcd will remove both data pushes but Bitcoin Core's `FindAndDelete` only removes the first `<data>` push.


### Patches

This has been patched in `btcd` version v0.24.2-beta. 

### References

`FindAndDelete`: https://github.com/btcsuite/btcd/security/advisories/GHSA-27vh-h6mc-q6g8
