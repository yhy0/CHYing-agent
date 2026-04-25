# Privilege escalation via ApiTokensEndpoint

**GHSA**: GHSA-9jcq-jf57-c62c | **CVE**: CVE-2023-39349 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-284

**Affected Packages**:
- **sentry** (pip): >= 22.1.0, < 23.7.2

## Description

### Impact
An attacker with access to a token with few or no scopes can query `/api/0/api-tokens/` for a list of all tokens created by a user, including tokens with greater scopes, and use those tokens in other requests.

There is no evidence that the issue was exploited on https://sentry.io. For self-hosted users, it is advised to rotate user auth tokens via `https://your-self-hosted-sentry-installation/settings/account/api/auth-tokens/`.

### Patches
The issue was fixed in https://github.com/getsentry/sentry/pull/53850 and is available in the release 23.7.2 of [sentry](https://github.com/getsentry/sentry/releases/tag/23.7.2) and [self-hosted](https://github.com/getsentry/self-hosted/releases/tag/23.7.2).

### Workarounds
There are no known workarounds.
