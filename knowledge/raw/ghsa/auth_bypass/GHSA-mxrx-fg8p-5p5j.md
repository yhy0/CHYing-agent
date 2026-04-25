# Bifrost vulnerable to authentication check flaw that leads to authentication bypass

**GHSA**: GHSA-mxrx-fg8p-5p5j | **CVE**: CVE-2022-39267 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/brokercap/Bifrost** (go): < 1.8.7-release

## Description

### Impact
The admin and monitor user groups need to be authenticated by username and password. If we delete the X-Requested-With: XMLHttpRequest field in the request header,the authentication will be bypassed.

### Patches
https://github.com/brockercap/Bifrost/pull/201

### Workarounds
Upgrade to the latest version
