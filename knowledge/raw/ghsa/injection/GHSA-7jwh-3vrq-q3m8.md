# pgproto3 SQL Injection via Protocol Message Size Overflow

**GHSA**: GHSA-7jwh-3vrq-q3m8 | **CVE**: N/A | **Severity**: high (CVSS 9.8)

**CWE**: CWE-89, CWE-190

**Affected Packages**:
- **github.com/jackc/pgproto3** (go): < 2.3.3
- **github.com/jackc/pgproto3/v2** (go): < 2.3.3

## Description

### Impact

SQL injection can occur if an attacker can cause a single query or bind message to exceed 4 GB in size. An integer overflow in the calculated message size can cause the one large message to be sent as multiple messages under the attacker's control.

### Patches

The problem is resolved in v2.3.3

### Workarounds

Reject user input large enough to cause a single query or bind message to exceed 4 GB in size.

