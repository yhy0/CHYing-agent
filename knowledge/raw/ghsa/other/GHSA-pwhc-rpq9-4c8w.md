# containerd affected by a local privilege escalation via wide permissions on CRI directory

**GHSA**: GHSA-pwhc-rpq9-4c8w | **CVE**: CVE-2024-25621 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-279

**Affected Packages**:
- **github.com/containerd/containerd** (go): < 1.7.29
- **github.com/containerd/containerd/v2** (go): < 2.0.7
- **github.com/containerd/containerd/v2** (go): >= 2.1.0-beta.0, < 2.1.5
- **github.com/containerd/containerd/v2** (go): >= 2.2.0-beta.0, < 2.2.0

## Description

### Impact

An overly broad default permission vulnerability was found in containerd.

- `/var/lib/containerd` was created with the permission bits 0o711, while it should be created with 0o700
  - Allowed local users on the host to potentially access the metadata store and the content store
- `/run/containerd/io.containerd.grpc.v1.cri` was created with 0o755, while it should be created with 0o700
  - Allowed local users on the host to potentially access the contents of Kubernetes local volumes. The contents of volumes might include setuid binaries, which could allow a local user on the host to elevate privileges on the host.
- `/run/containerd/io.containerd.sandbox.controller.v1.shim` was created with 0o711, while it should be created with 0o700

The directory paths may differ depending on the daemon configuration.
When the `temp` directory path is specified in the daemon configuration, that directory was also created with 0o711, while it should be created with 0o700.

### Patches

This bug has been fixed in the following containerd versions:

* 2.2.0
* 2.1.5
* 2.0.7
* 1.7.29

Users should update to these versions to resolve the issue.
These updates automatically change the permissions of the existing directories.

> [!NOTE]
>
> `/run/containerd` and `/run/containerd/io.containerd.runtime.v2.task` are still created with 0o711.
> This is an expected behavior for supporting userns-remapped containers.

### Workarounds

The system administrator on the host can manually chmod the directories to not 
have group or world accessible permisisons:

```
chmod 700 /var/lib/containerd
chmod 700 /run/containerd/io.containerd.grpc.v1.cri
chmod 700 /run/containerd/io.containerd.sandbox.controller.v1.shim
```

An alternative mitigation would be to run containerd in [rootless mode](https://github.com/containerd/containerd/blob/main/docs/rootless.md).

### Credits

The containerd project would like to thank David Leadbeater for responsibly disclosing this issue in accordance with the [containerd security policy](https://github.com/containerd/project/blob/main/SECURITY.md).

### For more information

If you have any questions or comments about this advisory:

* Open an issue in [containerd](https://github.com/containerd/containerd/issues/new/choose)
* Email us at [security@containerd.io](mailto:security@containerd.io)

To report a security issue in containerd:

* [Report a new vulnerability](https://github.com/containerd/containerd/security/advisories/new)
