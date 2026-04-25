# Whoogle Search Path Traversal vulnerability

**GHSA**: GHSA-q97g-c29h-x2p7 | **CVE**: CVE-2024-22203 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-918

**Affected Packages**:
- **whoogle-search** (pip): >= 0, < 0.8.4

## Description

Whoogle Search is a self-hosted metasearch engine. In versions prior to 0.8.4, the `element` method in `app/routes.py` does not validate the user-controlled `src_type` and `element_url` variables and passes them to the `send` method which sends a GET request on lines 339-343 in `request.py`, which leads to a server-side request forgery. This issue allows for crafting GET requests to internal and external resources on behalf of the server. For example, this issue would allow for accessing resources on the internal network that the server has access to, even though these resources may not be accessible on the internet. This issue is fixed in version 0.8.4.
