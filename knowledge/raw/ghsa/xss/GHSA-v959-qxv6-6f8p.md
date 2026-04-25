# ZITADEL Vulnerable to Account Takeover via DOM-Based XSS in Zitadel V2 Login

**GHSA**: GHSA-v959-qxv6-6f8p | **CVE**: CVE-2025-67495 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/zitadel/zitadel** (go): < 1.80.0-v2.20.0.20251208091519-4c879b47334e
- **github.com/zitadel/zitadel** (go): >= 1.83.4, <= 1.87.5
- **github.com/zitadel/zitadel** (go): >= 4.0.0-rc.1, < 4.7.1
- **github.com/zitadel/zitadel/v2** (go): < 1.80.0-v2.20.0.20251208091519-4c879b47334e

## Description

### Summary

A potential vulnerability exists in ZITADEL's logout endpoint in login V2. This endpoint accepts serval parameters including a `post_logout_redirect`. When this parameter is specified, users will be redirected to the site that is provided via this parameter.
ZITADEL's login UI did not ensure that this parameter contained an allowed value and even executed passed scripts.

### Impact

Zitadel is vulnerable to a DOM-Based XSS vulnerability. More specifically, the /logout endpoint insecurely routed to value that is supplied in the post_logout_redirect GET parameter. As a result, malicious JS code could be executed on Zitadel users’ browsers, in the Zitadel V2 Login domain.

An unauthenticated remote attacker can exploit this DOM-based XSS vulnerability, and thus, execute malicious JavaScript code on behalf of Zitadel users. By doing so, such an attacker could reset the password of their victims, and take over their accounts.

Note that for this to work, multiple user sessions need to be active in the same browser. Additionally, it's important to note that an account takeover is mitigated for accounts that have Multi-Factor Authentication (MFA) or Passwordless authentication enabled.

### Affected Versions

Systems using the login UI (v2) and running one of the following versions are affected:
- **v4.x**: `4.0.0-rc.1` through `4.7.0`

### Patches

The vulnerability has been addressed in the latest release. The patch resolves the issue by ensuring the information was passed for the ZITADEL API using a JSON Web Token (JWT).
If you're running your own login UI, we recommend switching over to the new `logout_token` parameter, which contains all information previously passed via specific query parameters. The contained JWT's signature needs to be verified with the instance OAuth2/OIDC public keys (jwks_uri).

Before you upgrade, ensure that:
- the `ZITADEL_API_URL` is set and is pointing to your instance, resp. system in multi-instance deployments.
- the HTTP `host` (or a `x-forwarded-host`) is passed in your reverse proxy to the login UI.
- a `x-zitadel-instance-host` (or `x-zitadel-forward-host`) is set in your reverse for multi-instance deployments. If you're running a single instance solution, you don't need to take any actions.

Patched versions:
- 4.x: Upgrade to >=[4.7.1](https://github.com/zitadel/zitadel/releases/tag/v4.7.1)

### Workarounds

The recommended solution is to update ZITADEL to a patched version.

### Questions

If you have any questions or comments about this advisory, please email us at [security@zitadel.com](mailto:security@zitadel.com)

### Credits

Thanks to Amit Laish – GE Vernova for finding and reporting the vulnerability.
