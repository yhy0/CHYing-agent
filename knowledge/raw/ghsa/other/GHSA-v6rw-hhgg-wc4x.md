# Evmos vulnerable to DOS and transaction fee expropiation through Authz exploit

**GHSA**: GHSA-v6rw-hhgg-wc4x | **CVE**: N/A | **Severity**: critical (CVSS 9.1)

**CWE**: N/A

**Affected Packages**:
- **github.com/evmos/evmos/v11** (go): < 12.0.0

## Description

## Impact
_What kind of vulnerability is it? Who is impacted?_

An attacker can use this bug to bypass the block gas limit and gas payment completely to perform a full Denial-of-Service against the chain.

## Disclosure

Evmos versions below `v11.0.1` do not check for `MsgEthereumTx` messages that are nested under other messages. This allows a malicious actor to perform EVM transactions that do not meet the checks performed under `newEthAnteHandler`. This opens the possibility for the DOS of validators and consequently halt the chain through an infinite EVM execution.

### Additional details

The attack scenario is as follows:

1. The attacker deploys a simple smart contract with an infinite loop to the chain.  
2. The attacker calls the smart contract using an embedded transaction with an extremely high gas value (`uint64` max or similar). 
3. Once the transaction is included in a block, nodes will try to execute the EVM transaction with almost infinite gas and get stuck. **This stops new block creation and effectively halts the chain, requiring a manual restart of all nodes.**

## Users Impacted
All Evmos users are impacted by this vulnerability as it has the potential to halt the chain. Users' funds and chain state are safe but when under attack, the chain could be deemed unusable. 

## Patches

_Has the problem been patched? What versions should users upgrade to?_

The vulnerability has been patched on Evmos versions ≥v12.0.0.

### Details

As a temporary workaround, the fix blocks `MsgEthereumTxs` messages from being sent under the `authz` module's `MsgExec` message. It also covers the scenario in which `MsgEthereumTx` are deeply nested by:

- Doing a recursive check over the nested messages of `MsgExec`
- Limiting the amount of possible nested messages (inner messages) in `MsgExec`

This is done by adding an additional `AnteHandler` decorator (`AuthzLimiterDecorator`) for Cosmos and EIP-712 transactions.

This is a state machine-breaking change as it restricts previously allowed messages and thus requires a hard-fork upgrade.

## References
__Are there any links users can visit to find out more?__

### For more information
If you have any questions or comments about this advisory:

- Reach out to the Core Team in [Discord](https://discord.gg/evmos)
- Open a discussion in [evmos/evmos](https://github.com/evmos/evmos/discussions)
- Email us at [security@evmos.org](mailto:security@evmos.org) for security questions
- For Press, email us at [evmos@west-comms.com](mailto:evmos@west-comms.com).

