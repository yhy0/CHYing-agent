# pgAdmin 4 Vulnerable to Remote Code Execution

**GHSA**: GHSA-g73c-fw68-pwx3 | **CVE**: CVE-2025-2945 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94

**Affected Packages**:
- **pgadmin4** (pip): < 9.2

## Description

Remote Code Execution security vulnerability in pgAdmin 4  (Query Tool and Cloud Deployment modules).

The vulnerability is associated with the 2 POST endpoints; /sqleditor/query_tool/download, where the query_commited parameter and /cloud/deploy endpoint, where the high_availability parameter is unsafely passed to the Python eval() function, allowing arbitrary code execution.


This issue affects pgAdmin 4: before 9.2.
