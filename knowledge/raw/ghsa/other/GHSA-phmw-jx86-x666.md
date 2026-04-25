# Authenticated Rundeck users can view or delete jobs they do not have authorization for.

**GHSA**: GHSA-phmw-jx86-x666 | **CVE**: CVE-2023-48222 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-862

**Affected Packages**:
- **org.rundeck:rundeck** (maven): >= 4.12.0, < 4.17.3

## Description

Access to two URLs used in both Rundeck Open Source and Process Automation products could allow authenticated users to access the URL path, which would allow access to view or delete jobs, without the necessary authorization checks.

The affected URLs are:
- `http[s]://[host]/context/rdJob/*` 
- `http[s]://[host]/context/api/*/incubator/jobs`

### Impact

Rundeck, Process Automation version 4.12.0 up to 4.16.0

### Patches

Patched versions: 4.17.3

### Workarounds

Access to two URLs used in either Rundeck Open Source or Process Automation products could be blocked at a load balancer level.
- `http[s]://host/context/rdJob/*` 
- `http[s]://host/context/api/*/incubator/jobs`

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [our forums](https://community.pagerduty.com/forum/c/process-automation)
* Enterprise Customers can open a [Support ticket](https://support.rundeck.com)


