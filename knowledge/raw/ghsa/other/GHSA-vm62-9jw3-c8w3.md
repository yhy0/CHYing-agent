# Gogs has an argument Injection in the built-in SSH server

**GHSA**: GHSA-vm62-9jw3-c8w3 | **CVE**: CVE-2024-39930 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-88

**Affected Packages**:
- **gogs.io/gogs** (go): <= 0.13.0

## Description

### Impact

When the built-in SSH server is enabled (`[server] START_SSH_SERVER = true`), unprivileged user accounts with at least one SSH key can execute arbitrary commands on the Gogs instance with the privileges of the user specified by `RUN_USER` in the configuration. It allows attackers to access and alter any users' code hosted on the same instance.

### Patches

The `env` command sent to the internal SSH server has been changed to be a passthrough (https://github.com/gogs/gogs/pull/7868), i.e. the feature is effectively removed. Users should upgrade to 0.13.1 or the latest 0.14.0+dev.

### Workarounds

[Disable the use of built-in SSH server](https://github.com/gogs/gogs/blob/7adac94f1e93cc5c3545ea31688662dcef9cd737/conf/app.ini#L76-L77) on operating systems other than Windows.

### References

https://www.cve.org/CVERecord?id=CVE-2024-39930

