# codechecker vulnerable to authentication bypass when using specifically crafted URLs

**GHSA**: GHSA-f3f8-vx3w-hp5q | **CVE**: CVE-2024-10081 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-288

**Affected Packages**:
- **codechecker** (pip): < 6.24.2

## Description

### Summary
Authentication bypass occurs when the API URL ends with Authentication, Configuration or ServerInfo. This bypass allows superuser access to all API endpoints other than Authentication. These endpoints include the ability to add, edit, and remove products, among others.

### Details
All endpoints, apart from the /Authentication is affected by the vulnerability.

The vulnerability allows unauthenticated users to access all API functionality.
You can look for the following pattern in the logs to check if the vulnerabilty was exploited:
![image](https://github.com/user-attachments/assets/6ba02231-a3d8-4832-aee6-f96462b7441e)

Note that the url starts with v and contains a valid CodeChecker endpoint, but it ends in `Authentication`, `Configuration` or `ServerInfo` and it was made by an `Anonymous` user.

### Impact
This authentication bypass allows querying, adding, changing, and deleting Products contained on the CodeChecker server, without authentication, by an anonymous user.
