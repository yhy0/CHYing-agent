# Gogs vulnerable to improper PAM authorization handling

**GHSA**: GHSA-gw5h-h6hj-f56g | **CVE**: CVE-2022-0871 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-862

**Affected Packages**:
- **gogs.io/gogs** (go): < 0.12.5

## Description

### Impact

Expired PAM accounts and accounts with expired passwords are continued to be seen as valid. Installations use PAM as authentication sources are affected.

### Patches

Expired PAM accounts and accounts with expired passwords are no longer being seen as valid. Users should upgrade to 0.12.5 or the latest 0.13.0+dev.

### Workarounds

In addition to marking PAM accounts as expired, also disable/lock them. Running `usermod -L <username>` will add an exclamation mark to the password hash and would result in wrong passwords responses when trying to login. 

### References

https://huntr.dev/bounties/ea82cfc9-b55c-41fe-ae58-0d0e0bd7ab62/

### For more information

If you have any questions or comments about this advisory, please post on https://github.com/gogs/gogs/issues/6810.

