# Request smuggling leading to endpoint restriction bypass in Gunicorn

**GHSA**: GHSA-w3h3-4rj7-4ph4 | **CVE**: CVE-2024-1135 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-444

**Affected Packages**:
- **gunicorn** (pip): < 22.0.0

## Description

Gunicorn fails to properly validate Transfer-Encoding headers, leading to HTTP Request Smuggling (HRS) vulnerabilities. By crafting requests with conflicting Transfer-Encoding headers, attackers can bypass security restrictions and access restricted endpoints. This issue is due to Gunicorn's handling of Transfer-Encoding headers, where it incorrectly processes requests with multiple, conflicting Transfer-Encoding headers, treating them as chunked regardless of the final encoding specified. This vulnerability has been shown to allow access to endpoints restricted by gunicorn. This issue has been addressed in version 22.0.0.

To be affected users must have a network path which does not filter out invalid requests. These users are advised to block access to restricted endpoints via a firewall or other mechanism if they are unable to update.
