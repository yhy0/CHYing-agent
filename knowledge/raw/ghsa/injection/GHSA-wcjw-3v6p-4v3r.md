# MindsDB Eval Injection vulnerability

**GHSA**: GHSA-wcjw-3v6p-4v3r | **CVE**: CVE-2024-45846 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **mindsdb** (pip): >= 23.10.3.0, < 24.7.4.1

## Description

An arbitrary code execution vulnerability exists in versions 23.10.3.0 up to 24.7.4.1 of the MindsDB platform, when the Weaviate integration is installed on the server. If a specially crafted ‘SELECT WHERE’ clause containing Python code is run against a database created with the Weaviate engine, the code will be passed to an eval function and executed on the server.
