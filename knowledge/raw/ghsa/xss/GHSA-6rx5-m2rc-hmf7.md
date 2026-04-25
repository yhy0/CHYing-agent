# ZITADEL: Stored XSS via Default URI Redirect Leads to Account Takeover

**GHSA**: GHSA-6rx5-m2rc-hmf7 | **CVE**: CVE-2026-29192 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/zitadel/zitadel/v2** (go): >= 4.0.0, < 4.12.0
- **github.com/zitadel/zitadel** (go): >= 4.0.0, < 4.12.0

## Description

### Summary

A vulnerability in Zitadel's login V2 interface was discovered, allowing for possible account takeover.

### Impact

Zitadel allows organization administrators to change the default redirect URI for their organization. This setting enables them to redirect users to an arbitrary location after they log in.

Due to missing restrictions and improper handling, malicious javascrtipt code could be executed in Zitadel login UI (v2) using the users’ browser. 

An unauthenticated remote attacker can exploit this Stored XSS vulnerability, reset the password of their victims, and take over their accounts.

It's important to note that this specific attack vector is mitigated for accounts that have Multi-Factor Authentication (MFA) or Passwordless authentication enabled.Stored XSS vulnerability. 

### Affected Versions

Systems running one of the following versions are affected:
- **4.x**: `4.0.0` through `4.11.1` (including RC versions)

### Patches

The vulnerability has been addressed in the latest releases. The login UI prevents execution of such code. Additionally, the page to change the password, now always requires the user's current password regardless of the state of the authenticated session.

4.x: Upgrade to >= [4.12.0](https://github.com/zitadel/zitadel/releases/tag/v4.12.0)

### Workarounds

The recommended solution is to upgrade to a patched version.

### Questions

If there are any questions or comments about this advisory, please send an email to [security@zitadel.com](mailto:security@zitadel.com)

### Credits

ZITADEL extends thanks once again to Amit Laish from GE Vernova for finding and reporting the vulnerability.
