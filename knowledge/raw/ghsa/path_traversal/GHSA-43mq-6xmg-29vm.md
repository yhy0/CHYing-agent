# Apache Struts file upload logic is flawed

**GHSA**: GHSA-43mq-6xmg-29vm | **CVE**: CVE-2024-53677 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22, CWE-434, CWE-915

**Affected Packages**:
- **org.apache.struts:struts2-core** (maven): < 6.4.0

## Description

File upload logic is flawed vulnerability in Apache Struts. An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution.

This issue affects Apache Struts: from 2.0.0 before 6.4.0.

Users are recommended to upgrade to version 6.4.0 at least and migrate to the new file upload mechanism https://struts.apache.org/core-developers/file-upload. If you are not using an old file upload logic based on FileuploadInterceptor your application is safe.

You can find more details in  https://cwiki.apache.org/confluence/display/WW/S2-067 .
