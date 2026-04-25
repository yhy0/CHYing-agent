# llama-index-packs-finchat SQL Injection vulnerability

**GHSA**: GHSA-x48g-hm9c-ww42 | **CVE**: CVE-2024-12909 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-89

**Affected Packages**:
- **llama-index-packs-finchat** (pip): <= 0.3.0

## Description

A vulnerability in the FinanceChatLlamaPack of the llama-index-packs-finchat package, versions up to v0.3.0, allows for SQL injection in the `run_sql_query` function of the `database_agent`. This vulnerability can be exploited by an attacker to inject arbitrary SQL queries, leading to remote code execution (RCE) through the use of PostgreSQL's large object functionality.

The issue is resolved by no longer officially supporting the package and moving it into the `stale_packages` branch on the repo, this removing it from documentation etc.
