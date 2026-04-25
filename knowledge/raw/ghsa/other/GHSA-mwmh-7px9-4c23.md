# ZITADEL Vulnerable to Account Takeover via Malicious Forwarded Header Injection

**GHSA**: GHSA-mwmh-7px9-4c23 | **CVE**: CVE-2025-64101 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-601, CWE-640

**Affected Packages**:
- **github.com/zitadel/zitadel/v2** (go): >= 2.0.0, < 2.71.18
- **github.com/zitadel/zitadel/v2** (go): < 1.80.0-v2.20.0.20251029090537-72a5c33e6ac3

## Description

### Impact

A potential vulnerability exists in ZITADEL's password reset mechanism. ZITADEL utilizes the Forwarded or X-Forwarded-Host header from incoming requests to construct the URL for the password reset confirmation link. This link, containing a secret code, is then emailed to the user.

If an attacker can manipulate these headers (e.g., via host header injection), they could cause ZITADEL to generate a password reset link pointing to a malicious domain controlled by the attacker. If the user clicks this manipulated link in the email, the secret reset code embedded in the URL can be captured by the attacker. This captured code could then be used to reset the user's password and gain unauthorized access to their account.

It's important to note that this specific attack vector is mitigated for accounts that have Multi-Factor Authentication (MFA) or Passwordless authentication enabled.

### Affected Versions

Systems running one of the following versions:
- **4.x**: `4.0.0` to `4.5.0` (including RC versions)
- **3.x**: `3.0.0` to `3.4.2` (including RC versions)
- **2.x**: `v2.0.0` to `2.71.17`

### Patches

Patched version ensure proper validation of the headers:

4.x: Upgrade to >=[4.6.0](https://github.com/zitadel/zitadel/releases/tag/v4.6.0)
3.x: Update to >=[3.4.3](https://github.com/zitadel/zitadel/releases/tag/v3.4.3)
2.x: Update to >=[2.71.18](https://github.com/zitadel/zitadel/releases/tag/v2.71.18)

### Workarounds

The recommended solution is to update ZITADEL to a patched version.

A ZITADEL fronting proxy can be configured to delete all Forwarded and X-Forwarded-Host header values before sending requests to ZITADEL self-hosted environments.

### Questions

If you have any questions or comments about this advisory, please email us at [security@zitadel.com](mailto:security@zitadel.com)

### Credits

Thanks to Amit Laish – GE Vernova for finding and reporting the vulnerability.
