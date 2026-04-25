#  LlamaIndex Retrievers Integration: DuckDBRetriever SQL Injection

**GHSA**: GHSA-339r-cjv9-x78g | **CVE**: CVE-2024-11958 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **llama-index-retrievers-duckdb-retriever** (pip): < 0.4.0

## Description

A SQL injection vulnerability exists in the `duckdb_retriever` component of the run-llama/llama_index repository, specifically in llama-index-retrievers-duckdb-retriever prior to v0.4.0. The vulnerability arises from the construction of SQL queries without using prepared statements, allowing an attacker to inject arbitrary SQL code. This can lead to remote code execution (RCE) by installing the shellfs extension and executing malicious commands.
