# GoAuthentik vulnerable to Insufficient Authorization for several API endpoints

**GHSA**: GHSA-qxqc-27pr-wgc8 | **CVE**: CVE-2024-42490 | **Severity**: critical (CVSS 8.7)

**CWE**: CWE-285, CWE-863

**Affected Packages**:
- **goauthentik.io** (go): >= 2024.6.0-rc1, < 2024.6.4
- **goauthentik.io** (go): < 2024.4.4

## Description

### Summary

Several API endpoints can be accessed by users without correct authentication/authorization.

The main API endpoints affected by this:

-   `/api/v3/crypto/certificatekeypairs/<uuid>/view_certificate/`
-   `/api/v3/crypto/certificatekeypairs/<uuid>/view_private_key/`
-   `/api/v3/.../used_by/`

Note that all of the affected API endpoints require the knowledge of the ID of an object, which especially for certificates is not accessible to an unprivileged user. Additionally the IDs for most objects are UUIDv4, meaning they are not easily guessable/enumerable.

### Patches

authentik 2024.4.4, 2024.6.4 and 2024.8.0 fix this issue.

### Workarounds

Access to the API endpoints can be blocked at a Reverse-proxy/Load balancer level to prevent this issue from being exploited.

### For more information

If you have any questions or comments about this advisory:

-   Email us at [security@goauthentik.io](mailto:security@goauthentik.io)

