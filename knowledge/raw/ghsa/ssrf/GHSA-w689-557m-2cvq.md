# Server-Side Request Forgery in gogs webhook

**GHSA**: GHSA-w689-557m-2cvq | **CVE**: CVE-2022-1285 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-918

**Affected Packages**:
- **gogs.io/gogs** (go): < 0.12.8

## Description

### Impact

The malicious user is able to discover services in the internal network through webhook functionality. All installations accepting public traffic are affected.

### Patches

Webhook payload URLs are revalidated before each delivery to make sure they are not resolved to blocked local network addresses. Users should upgrade to 0.12.8 or the latest 0.13.0+dev.

### Workarounds

Run Gogs in its own private network.

### References

https://huntr.dev/bounties/da1fbd6e-7a02-458e-9c2e-6d226c47046d/

### For more information

If you have any questions or comments about this advisory, please post on https://github.com/gogs/gogs/issues/6901.

