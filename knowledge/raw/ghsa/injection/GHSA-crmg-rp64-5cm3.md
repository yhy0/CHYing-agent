# MindsDB Eval Injection vulnerability

**GHSA**: GHSA-crmg-rp64-5cm3 | **CVE**: CVE-2024-45847 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **mindsdb** (pip): >= 23.11.4.2, < 24.7.4.1

## Description

An arbitrary code execution vulnerability exists in versions 23.11.4.2 up to 24.7.4.1 of the MindsDB platform, when one of several integrations is installed on the server. If a specially crafted ‘UPDATE’ query containing Python code is run against a database created with the specified integration engine, the code will be passed to an eval function and executed on the server.
