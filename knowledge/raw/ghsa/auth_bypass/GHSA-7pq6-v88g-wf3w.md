# Sentry's improper authentication on SAML SSO process allows user impersonation

**GHSA**: GHSA-7pq6-v88g-wf3w | **CVE**: CVE-2025-22146 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-287

**Affected Packages**:
- **sentry** (pip): >= 21.12.0, < 25.1.0

## Description

### Impact
A critical vulnerability was discovered in the SAML SSO implementation of Sentry. It was reported to us via our private bug bounty program.

The vulnerability allows an attacker to take over any user account by using a malicious SAML Identity Provider and another organization on the same Sentry instance. The victim email address must be known in order to exploit this vulnerability.

### Patches
- [Sentry SaaS](https://sentry.io): The fix was deployed on Jan 14, 2025.
- [Self-Hosted Sentry](https://github.com/getsentry/self-hosted): If only a single organization is allowed (`SENTRY_SINGLE_ORGANIZATION = True`), then no action is needed. Otherwise, users should upgrade to version 25.1.0 or higher.

### Workarounds
No known workarounds.

### References
- https://github.com/getsentry/sentry/pull/83407
