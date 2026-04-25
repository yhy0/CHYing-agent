# Coder's OIDC authentication allows email with partially matching domain to register

**GHSA**: GHSA-7cc2-r658-7xpf | **CVE**: CVE-2024-27918 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-20

**Affected Packages**:
- **github.com/coder/coder/v2** (go): >= 2.8.0, < 2.8.4
- **github.com/coder/coder/v2** (go): >= 2.7.0, < 2.7.3
- **github.com/coder/coder/v2** (go): < 2.6.1
- **github.com/coder/coder** (go): <= 0.27.3

## Description

### Summary
A vulnerability in Coder's OIDC authentication could allow an attacker to bypass the `CODER_OIDC_EMAIL_DOMAIN` verification and create an account with an email not in the allowlist. Deployments are only affected if the OIDC provider allows users to create accounts on the provider (such as public providers like `google.com`).

### Details
During OIDC registration, the user's email was improperly validated against the allowed `CODER_OIDC_EMAIL_DOMAIN`s. This could allow a user with a domain that only partially matched an allowed domain to successfully login or register (e.g. `user@exploitcorp.com` would match the allowed domain `corp.com`).

An attacker could register a domain name that exploited this vulnerability and register on a Coder instance with a public OIDC provider.

### Impact
Coder instances with OIDC enabled and protected by the `CODER_OIDC_EMAIL_DOMAIN` configuration.

Coder instances using a private OIDC provider are not affected, as arbitrary users cannot register through a private OIDC provider without first having an account on the provider.

Public OIDC providers (such as `google.com` without permitted domains set on the OAuth2 App) are impacted.

GitHub authentication and external authentication are not impacted.

### Was my deployment impacted?
To check if your deployment was exploited:
- View the audit log on your deployment for unexpected registered users (using the `action:register` filter)
- Check the users list for unexpected users
    - Users created via this exploit will have a domain that ends with one of the allowed domains but doesn’t fully match (e.g. `@exploitcorp.com` instead of `@corp.com`)

### Patched Versions
This vulnerability is remedied in
- v2.8.4
- v2.7.3
- v2.6.1

All versions prior to these patches are affected by the vulnerability. **It is recommended that customers upgrade their deployments as soon as possible if they are utilizing OIDC authentication with the `CODER_OIDC_EMAIL_DOMAIN` setting.**

### Thanks
- https://github.com/arcz
- https://www.trailofbits.com

### References
https://github.com/coder/coder/security/advisories/GHSA-7cc2-r658-7xpf
https://github.com/coder/coder/commit/4439a920e454a82565e445e4376c669e3b89591c
https://nvd.nist.gov/vuln/detail/CVE-2024-27918
