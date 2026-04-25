# pgx SQL Injection via Protocol Message Size Overflow

**GHSA**: GHSA-mrww-27vc-gghv | **CVE**: CVE-2024-27304 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-89, CWE-190

**Affected Packages**:
- **github.com/jackc/pgx** (go): < 4.18.2
- **github.com/jackc/pgx** (go): >= 5.0.0, < 5.5.4
- **github.com/jackc/pgx/v4** (go): < 4.18.2
- **github.com/jackc/pgx/v5** (go): >= 5.0.0, < 5.5.4

## Description

### Impact

SQL injection can occur if an attacker can cause a single query or bind message to exceed 4 GB in size. An integer overflow in the calculated message size can cause the one large message to be sent as multiple messages under the attacker's control.

### Patches

The problem is resolved in v4.18.2 and v5.5.4.

### Workarounds

Reject user input large enough to cause a single query or bind message to exceed 4 GB in size.

