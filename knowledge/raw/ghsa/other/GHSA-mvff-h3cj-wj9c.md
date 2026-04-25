# Unprivileged pod using `hostPath` can side-step active LSM when it is SELinux

**GHSA**: GHSA-mvff-h3cj-wj9c | **CVE**: CVE-2021-43816 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-281

**Affected Packages**:
- **github.com/containerd/containerd** (go): >= 1.5.0, < 1.5.9

## Description

### Impact

Containers launched through containerd’s CRI implementation on Linux systems which use the SELinux security module and containerd versions since v1.5.0 can cause arbitrary files and directories on the host to be relabeled to match the container process label through the use of specially-configured bind mounts in a hostPath volume. This relabeling elevates permissions for the container, granting full read/write access over the affected files and directories. Kubernetes and crictl can both be configured to use containerd’s CRI implementation.

If you are not using containerd’s CRI implementation (through one of the mechanisms described above), you are not affected by this issue.

### Patches

This bug has been fixed in containerd 1.5.9.  Because file labels persist independently of containerd, users should both update to these versions as soon as they are released and validate that all files on their host are correctly labeled.

### Workarounds

Ensure that no sensitive files or directories are used as a hostPath volume source location.  Policy enforcement mechanisms such a Kubernetes Pod Security Policy [AllowedHostPaths](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems) may be specified to limit the files and directories that can be bind-mounted to containers.

### For more information

If you have any questions or comments about this advisory:

* Open an issue in [containerd](https://github.com/containerd/containerd/issues/new/choose)
* Email us at [security@containerd.io](mailto:security@containerd.io)
