# Whoogle Search Server-Side Request Forgery vulnerability

**GHSA**: GHSA-3q6g-qmpx-rqw4 | **CVE**: CVE-2024-22205 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-918

**Affected Packages**:
- **whoogle-search** (pip): >= 0, < 0.8.4

## Description

Whoogle Search is a self-hosted metasearch engine. In versions 0.8.3 and prior, the `window` endpoint does not sanitize user-supplied input from the `location` variable and passes it to the `send` method which sends a `GET` request on lines 339-343 in `request.py,` which leads to a server-side request forgery. This issue allows for crafting GET requests to internal and external resources on behalf of the server. For example, this issue would allow for accessing resources on the internal network that the server has access to, even though these resources may not be accessible on the internet. This issue is fixed in version 0.8.4.


