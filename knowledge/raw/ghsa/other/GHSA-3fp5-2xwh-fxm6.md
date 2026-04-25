# Evmos transaction execution not accounting for all state transition after interaction with precompiles

**GHSA**: GHSA-3fp5-2xwh-fxm6 | **CVE**: CVE-2024-32644 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-662

**Affected Packages**:
- **github.com/evmos/evmos/v16** (go): <= 16.0.4
- **github.com/evmos/evmos/v7** (go): <= 7.0.0
- **github.com/evmos/evmos/v6** (go): <= 6.0.4
- **github.com/evmos/evmos/v5** (go): <= 5.0.0
- **github.com/tharsis/evmos** (go): <= 1.1.3
- **github.com/tharsis/evmos/v2** (go): <= 2.0.2
- **github.com/tharsis/evmos/v3** (go): <= 3.0.3
- **github.com/tharsis/evmos/v4** (go): <= 4.0.2
- **github.com/tharsis/evmos/v5** (go): <= 5.0.1

## Description

### Context

- [`stateObject`](https://github.com/evmos/evmos/blob/b196a522ba4951890b40992e9f97aa610f8b5f9c/x/evm/statedb/state_object.go#L53-L68): represents the state of an account and is used to store its updates during a state transition. This is accomplished using two in memory Storage variables: `originStorage` and `dirtyStorage`
- [`StateDB`](https://github.com/evmos/evmos/blob/b196a522ba4951890b40992e9f97aa610f8b5f9c/x/evm/statedb/statedb.go#L33-L55): it is the general interface to retrieve accounts and holds a map of stateObjects.

### Impact

An external contributor, @iczc, discovered a way to mint arbitrary tokens due to the possibility to have two different states not in sync during the execution of a transaction. The exploit is based on the fact that to sync the Cosmos SDK state and the EVM one, we rely on the `stateDB.Commit()` method. When we call this method, we iterate though all the `dirtyStorage` and, **if and only if** it is different than the `originStorage`, we [set the new state](https://github.com/evmos/evmos/blob/b196a522ba4951890b40992e9f97aa610f8b5f9c/x/evm/statedb/statedb.go#L460-L465). Setting the new state means we update the Cosmos SDK KVStore. 

Below, are described the steps to perform the attack:

- User send a tx to a smart contract (SC) that is calling a precompile. 
- The SC perform a state transition of its state from A to B.
- The SC call the precompile.
- The SC perform a state transition of its state from B to A (revert of the previous).
- Once the transaction is executed, and the final **Commit** is performed, the state A will not be committed to the store because A is the same as `originStorage`. 

If the tx is executed correctly, this is what happens at the store level:

- Initial state A is loaded from the KVStore and the dirtyStorage is set to B.
- Before running the precompile, the `dirtyStorage` is committed to the KVStore without changing the `originStorage`.
- Now, since we have a `dirtyStorage`, it is updated to the previous value A without changing the `originStorage`.

Since the tx executed correctly, the evm calls the commit to persist the dirtyStorage. However, since dirtyStorage is equal to originStorage, nothing will be changed.

To summarize, if a contract storage state that is the same before and after a transaction, but is changed during the transaction and can call an external contract after the change, it can be exploited to make the transaction similar to non-atomic. The vulnerability is **critical** since this could lead to drain of funds through creative SC interactions. 

### Severity

Based on [ImmuneFi Severity Classification System](https://immunefisupport.zendesk.com/hc/en-us/articles/13332717597585-Severity-Classification-System) the severity was evaluated to `Critical` since the attack could have lead to direct loss of funds.

### Patches

The issue has been patched in versions >=V17.0.0. 

## For more information
If you have any questions or comments about this advisory:

Reach out to the Core Team in [Discord](https://discord.gg/evmos)
Open a discussion in [evmos/evmos](https://github.com/evmos/evmos/discussions)
Email us at [security@evmos.org](mailto:security@evmos.org) for security questions

