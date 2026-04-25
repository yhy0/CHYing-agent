# IBAX go-ibax vulnerable to SQL injection

**GHSA**: GHSA-g23g-mw97-65c8 | **CVE**: CVE-2022-3802 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/IBAX-io/go-ibax** (go): < 1.4.2

## Description

SQL Injection vulnerability in `/packages/api/database.go` of go-ibax via `where` parameter allows attacker to spoof identity, tamper with existing data, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server. This issue affects versions starting from commits on Jul 18, 2020.
