# Full authentication bypass if SASL authorization username is specified

**GHSA**: GHSA-4g76-w3xw-2x6w | **CVE**: CVE-2023-27582 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/foxcpp/maddy** (go): >= 0.2.0, < 0.6.3

## Description

### Impact

maddy 0.2.0 - 0.6.2 allows a full authentication bypass if SASL authorization username is specified when using the PLAIN authentication mechanisms. Instead of validating the specified authorization username, it is accepted as is after checking the credentials for the authentication username.

### Patches

maddy 0.6.3 includes the fix for the bug. 

### Workarounds

There is no way to fix the issue without upgrading.

### References

* Commit that introduced the vulnerable code: https://github.com/foxcpp/maddy/commit/55a91a37b71210f34f98f4d327c30308fe24399a
* Fix: https://github.com/foxcpp/maddy/commit/9f58cb64b39cdc01928ec463bdb198c4c2313a9c

