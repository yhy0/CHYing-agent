# Gogs allows deletion of internal files

**GHSA**: GHSA-ccqv-43vm-4f3w | **CVE**: CVE-2024-39931 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-552

**Affected Packages**:
- **gogs.io/gogs** (go): <= 0.13.0

## Description

### Impact

Unprivileged user accounts can execute arbitrary commands on the Gogs instance with the privileges of the account specified by `RUN_USER` in the configuration. It allows attackers to access and alter any users' code hosted on the same instance.

### Patches

Deletion of `.git` files has been prohibited (https://github.com/gogs/gogs/pull/7870). Users should upgrade to 0.13.1 or the latest 0.14.0+dev.

### Workarounds

No viable workaround available, please only grant access to trusted users to your Gogs instance on affected versions.

### References

https://www.cve.org/CVERecord?id=CVE-2024-39931

