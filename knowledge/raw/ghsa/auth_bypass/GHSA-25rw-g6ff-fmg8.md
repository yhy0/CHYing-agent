# ZITADEL: Login V2 UI Policy Bypass Allows Unauthorized Self-Registration and Authentication

**GHSA**: GHSA-25rw-g6ff-fmg8 | **CVE**: CVE-2026-29193 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/zitadel/zitadel/v2** (go): >= 4.0.0, <= 4.12.0
- **github.com/zitadel/zitadel** (go): >= 4.0.0, <= 4.12.0

## Description

### Summary

A vulnerability in Zitadel's login V2 UI allowed users to bypass login behavior and security policies and self-register new accounts or sign in using password even if corresponding options were disabled in their organizaton.

### Impact

Zitadel enables administrators to configure their organization’s login behavior and security policies. As part of this functionality, they can disable user self-registration, enforce passwordless logins only, and more.

Due to improper enforcement an attacker could send direct HTTP requests to the login UI and create accounts in organizations that have disabled user self-registration, and gain unauthorized access to the system.
The same attack vector could be used to authenticate for example using username and password even when this login method was disabled.

### Affected Versions

Systems running one of the following versions are affected:
- **4.x**: `4.0.0` through `4.12.0` (including RC versions)

### Patches

The vulnerability has been addressed in the latest releases. The patch resolves the issue by enforcing the policies on the logiin UI server.

4.x: Upgrade to >=[4.12.1](https://github.com/zitadel/zitadel/releases/tag/v4.12.1)

### Workarounds

The recommended solution is to upgrade to a patched version.

### Questions

If there are any questions or comments about this advisory, please send an email to [security@zitadel.com](mailto:security@zitadel.com)

### Credits 

ZITADEL extends thanks once again to Amit Laish from GE Vernova for finding and reporting the vulnerability.
