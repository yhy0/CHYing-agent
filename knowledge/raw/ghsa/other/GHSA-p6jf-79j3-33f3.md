# carbon-apimgt does not properly restrict uploaded files

**GHSA**: GHSA-p6jf-79j3-33f3 | **CVE**: CVE-2025-13590 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-434

**Affected Packages**:
- **org.wso2.carbon.apimgt:org.wso2.carbon.apimgt.impl** (maven): < 9.32.167

## Description

A malicious actor with administrative privileges can upload an arbitrary file to a user-controlled location within the deployment via a system REST API. Successful uploads may lead to remote code execution. 

 By leveraging the vulnerability, a malicious actor may perform Remote Code Execution by uploading a specially crafted payload.
