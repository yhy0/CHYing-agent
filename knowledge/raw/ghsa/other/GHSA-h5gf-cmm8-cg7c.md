# CasaOS-UserService allows unauthorized access to any file 

**GHSA**: GHSA-h5gf-cmm8-cg7c | **CVE**: CVE-2024-24765 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-200

**Affected Packages**:
- **github.com/IceWhaleTech/CasaOS-UserService** (go): < 0.4.7

## Description

### Summary

http://demo.casaos.io/v1/users/image?path=/var/lib/casaos/1/avatar.png

Originally it was to get the url of the user's avatar, but the path filtering was not strict, making it possible to get any file on the system.


### Details

Construct paths to get any file.

Such as the CasaOS user database, and furthermore can obtain system root privileges.

### PoC

http://demo.casaos.io/v1/users/image?path=/var/lib/casaos/conf/../db/user.db

### Impact

v0.4.6 all previous versions

