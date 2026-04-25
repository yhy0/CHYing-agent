# containerd CRI plugin: Insecure handling of image volumes

**GHSA**: GHSA-crp2-qrr5-8pq7 | **CVE**: CVE-2022-23648 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-200

**Affected Packages**:
- **github.com/containerd/containerd** (go): < 1.4.13
- **github.com/containerd/containerd** (go): >= 1.5.0, < 1.5.10
- **github.com/containerd/containerd** (go): >= 1.6.0, < 1.6.1

## Description

### Impact

A bug was found in containerd where containers launched through containerd’s CRI implementation with a specially-crafted image configuration could gain access to read-only copies of arbitrary files and directories on the host.  This may bypass any policy-based enforcement on container setup (including a Kubernetes Pod Security Policy) and expose potentially sensitive information.  Kubernetes and crictl can both be configured to use containerd’s CRI implementation.

### Patches

This bug has been fixed in containerd 1.6.1, 1.5.10 and 1.4.13.  Users should update to these versions to resolve the issue.

### Workarounds

Ensure that only trusted images are used.

### Credits

The containerd project would like to thank Felix Wilhelm of Google Project Zero for responsibly disclosing this issue in accordance with the [containerd security policy](https://github.com/containerd/project/blob/main/SECURITY.md).

### For more information

If you have any questions or comments about this advisory:

* Open an issue in [containerd](https://github.com/containerd/containerd/issues/new/choose)
* Email us at [security@containerd.io](mailto:security@containerd.io)
