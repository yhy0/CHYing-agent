# llama_index vulnerable to SQL Injection

**GHSA**: GHSA-v3c8-3pr6-gr7p | **CVE**: CVE-2025-1793 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **llama-index** (pip): < 0.12.28

## Description

Multiple vector store integrations in run-llama/llama_index version v0.12.21 have SQL injection vulnerabilities. These vulnerabilities allow an attacker to read and write data using SQL, potentially leading to unauthorized access to data of other users depending on the usage of the llama-index library in a web application.
