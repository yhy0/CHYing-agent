# SFTPGo vulnerable to recovery codes abuse

**GHSA**: GHSA-54qx-8p8w-xhg8 | **CVE**: CVE-2022-36071 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-287, CWE-916

**Affected Packages**:
- **github.com/drakkan/sftpgo/v2** (go): >= 2.2.0, < 2.3.4

## Description

### Impact

SFTPGo WebAdmin and WebClient support login using TOTP (Time-based One Time Passwords) as a seconday authentication factor. Because TOTPs are often configured on mobile devices that can be lost, stolen or damaged, SFTPGo also supports recovery codes. These are a set of one time use codes that can be used instead of the TOTP.

In SFTPGo versions from v2.2.0 to v2.3.3 recovery codes can be generated before enabling two-factor authentication.
An attacker who knows the user's password could potentially generate some recovery codes and then bypass two-factor authentication after it is enabled on the account at a later time.

### Patches

Fixed in v2.3.4.
Recovery codes can now only be generated after enabling two-factor authentication and are deleted after disabling it.

### Workarounds

Regenerate recovery codes after enabling two-factor authentication.

### References

https://github.com/drakkan/sftpgo/issues/965

