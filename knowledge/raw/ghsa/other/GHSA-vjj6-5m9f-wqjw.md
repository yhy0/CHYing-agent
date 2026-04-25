# NULL Pointer Dereference in HyperLedger Fabric

**GHSA**: GHSA-vjj6-5m9f-wqjw | **CVE**: CVE-2021-43667 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-476

**Affected Packages**:
- **github.com/hyperledger/fabric** (go): >= 2.3.0, < 2.3.3
- **github.com/hyperledger/fabric** (go): < 2.2.4

## Description

A vulnerability has been detected in HyperLedger Fabric v1.4.0, v2.0.0, v2.1.0. This bug can be leveraged by constructing a message whose payload is nil and sending this message with the method 'forwardToLeader'. This bug has been admitted and fixed by the developers of Fabric. If leveraged, any leader node will crash.
