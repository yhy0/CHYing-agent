# Insecure permissions on build temporary rootfs in Singularity

**GHSA**: GHSA-jv9c-w74q-6762 | **CVE**: CVE-2020-25040 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-668, CWE-732

**Affected Packages**:
- **github.com/sylabs/singularity** (go): < 3.6.3

## Description

### Impact

Insecure permissions on temporary directories used in explicit and implicit container build operations.

When a Singularity command that results in a container build operation is executed, it is possible for a user with access to the system to read the contents of the image during the build. Additionally, if the image contains a world-writable file or directory, it is possible for a user to inject arbitrary content into the running build, which in certain circumstances may enable arbitrary code execution during the build and/or when the built container is run.

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
