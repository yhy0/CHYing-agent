# Apache UIMA DUCC allows remote code execution 

**GHSA**: GHSA-34m5-796p-mjcp | **CVE**: CVE-2023-28935 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-77

**Affected Packages**:
- **org.apache.uima:uima-ducc-parent** (maven): <= 3.0.0

## Description

** UNSUPPORTED WHEN ASSIGNED ** Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in Apache Software Foundation Apache UIMA DUCC. When using the "Distributed UIMA Cluster Computing" (DUCC) module of Apache UIMA, an authenticated user that has the permissions to modify core entities can cause command execution as the system user that runs the web process. As the "Distributed UIMA Cluster Computing" module for UIMA is retired, we do not plan to release a fix for this issue. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.
