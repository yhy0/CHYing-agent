# Authentication bypass by capture-replay in github.com/cosmos/ethermint

**GHSA**: GHSA-x5f3-qmwj-4f84 | **CVE**: CVE-2021-25835 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-294, CWE-295

**Affected Packages**:
- **github.com/cosmos/ethermint** (go): < 0.4.1

## Description

Cosmos Network Ethermint <= v0.4.0 is affected by a cross-chain transaction replay vulnerability in the EVM module. Since ethermint uses the same chainIDEpoch and signature schemes with ethereum for compatibility, a verified signature in ethereum is still valid in ethermint with the same msg content and chainIDEpoch, which enables "cross-chain transaction replay" attack.

### Specific Go Packages Affected
github.com/cosmos/ethermint/rpc/namespaces/eth
