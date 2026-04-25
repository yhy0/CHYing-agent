# MindsDB Eval Injection vulnerability

**GHSA**: GHSA-wf9g-c67g-h4ch | **CVE**: CVE-2024-45851 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **mindsdb** (pip): >= 23.10.5.0, < 24.7.4.1

## Description

An arbitrary code execution vulnerability exists in versions 23.10.5.0 up to 24.7.4.1 of the MindsDB platform, when the Microsoft SharePoint integration is installed on the server. For databases created with the SharePoint engine, an ‘INSERT’ query can be used for list item creation. If such a query is specially crafted to contain Python code and is run against the database, the code will be passed to an eval function and executed on the server.
