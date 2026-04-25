# Apache Struts vulnerable to path traversal

**GHSA**: GHSA-2j39-qcjm-428w | **CVE**: CVE-2023-50164 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-552

**Affected Packages**:
- **org.apache.struts:struts2-core** (maven): >= 6.0.0, < 6.3.0.2
- **org.apache.struts:struts2-core** (maven): >= 2.0.0, < 2.5.33

## Description

An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution.
Users are recommended to upgrade to versions Struts 2.5.33 or Struts 6.3.0.2 or greater to fix this issue.
