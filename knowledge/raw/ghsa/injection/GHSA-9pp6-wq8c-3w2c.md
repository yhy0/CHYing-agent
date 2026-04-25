# Gogs allows argument injection during the previewing of changes

**GHSA**: GHSA-9pp6-wq8c-3w2c | **CVE**: CVE-2024-39932 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94

**Affected Packages**:
- **gogs.io/gogs** (go): <= 0.13.0

## Description

### Impact

Unprivileged user accounts can write to arbitrary files on the filesystem. We could demonstrate its exploitation to force a re-installation of the instance, granting administrator rights. It allows accessing and altering any user's code hosted on the same instance.

### Patches

Unintended Git options has been ignored for diff preview (https://github.com/gogs/gogs/pull/7871). Users should upgrade to 0.13.1 or the latest 0.14.0+dev.

### Workarounds

No viable workaround available, please only grant access to trusted users to your Gogs instance on affected versions.

### References

https://www.cve.org/CVERecord?id=CVE-2024-39932

