# Insecure permissions on user namespace / fakeroot temporary rootfs in Singularity

**GHSA**: GHSA-w6v2-qchm-grj7 | **CVE**: CVE-2020-25039 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-668, CWE-732

**Affected Packages**:
- **github.com/sylabs/singularity** (go): >= 3.2.0, < 3.6.3

## Description

### Impact

Insecure permissions on temporary directories used in fakeroot or user namespace container execution.

When a Singularity action command (run, shell, exec) is run with the fakeroot or user namespace option, Singularity will extract a container image to a temporary sandbox directory. Due to insecure permissions on the temporary directory it is possible for any user with access to the system to read the contents of the image. Additionally, if the image contains a world-writable file or directory, it is possible for a user to inject arbitrary content into the running container.

### Patches

This issue is addressed in Singularity 3.6.3.

All users are advised to upgrade to 3.6.3.

### Workarounds

The issue is mitigated if `TMPDIR` is set to a location that is only accessible to the user, as any subdirectories directly under `TMPDIR` cannot then be accessed by others. However, this is difficult to enforce so it is not recommended to rely on this as a mitigation.

### For more information

General questions about the impact of the advisory / changes made in the 3.6.0 release can be asked in the:

* [Singularity Slack Channel](https://bit.ly/2m0g3lX)
* [Singularity Mailing List](https://groups.google.com/a/lbl.gov/forum/??sdf%7Csort:date#!forum/singularity)

Any sensitive security concerns should be directed to: security@sylabs.io

See our Security Policy here: https://sylabs.io/security-policy
