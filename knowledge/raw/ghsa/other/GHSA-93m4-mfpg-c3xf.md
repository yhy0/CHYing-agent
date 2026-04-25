# ZITADEL Allows Account Takeover via Malicious X-Forwarded-Proto Header Injection

**GHSA**: GHSA-93m4-mfpg-c3xf | **CVE**: CVE-2025-48936 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-601

**Affected Packages**:
- **github.com/zitadel/zitadel** (go): < 0.0.0-20250528081227-c097887bc5f6
- **github.com/zitadel/zitadel/v2** (go): >= 2.38.3, < 2.70.12
- **github.com/zitadel/zitadel/v2** (go): >= 3.0.0-rc1, < 3.2.2
- **github.com/zitadel/zitadel/v2** (go): >= 2.71.0, <= 2.71.10
- **github.com/zitadel/zitadel/v2** (go): < 2.38.2-0.20240919104753-94d1eb767837

## Description

### Impact

A potential vulnerability exists in ZITADEL's password reset mechanism. ZITADEL utilizes the Forwarded or X-Forwarded-Host header from incoming requests to construct the URL for the password reset confirmation link. This link, containing a secret code, is then emailed to the user.

If an attacker can manipulate these headers (e.g., via host header injection), they could cause ZITADEL to generate a password reset link pointing to a malicious domain controlled by the attacker. If the user clicks this manipulated link in the email, the secret reset code embedded in the URL can be captured by the attacker. This captured code could then be used to reset the user's password and gain unauthorized access to their account.

It's important to note that this specific attack vector is mitigated for accounts that have Multi-Factor Authentication (MFA) or Passwordless authentication enabled.

### Patches

Patched version ensure proper validation of the headers and do not allow downgrading from https to http.

3.x versions are fixed on >=[3.2.2](https://github.com/zitadel/zitadel/releases/tag/v3.2.2)
2.71.x versions are fixed on >=[2.71.11](https://github.com/zitadel/zitadel/releases/tag/v2.71.11)
2.x versions are fixed on >=[2.70.12](https://github.com/zitadel/zitadel/releases/tag/v2.70.12)

### Workarounds

The recommended solution is to update ZITADEL to a patched version.

A ZITADEL fronting proxy can be configured to delete all Forwarded and X-Forwarded-Host header values before sending requests to ZITADEL self-hosted environments.

### Questions

If you have any questions or comments about this advisory, please email us at [security@zitadel.com](mailto:security@zitadel.com)

### Credits

Thanks to Amit Laish – GE Vernova for finding and reporting the vulnerability.
