# podman kube play symlink traversal vulnerability

**GHSA**: GHSA-wp3j-xq48-xpjw | **CVE**: CVE-2025-9566 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22, CWE-61

**Affected Packages**:
- **github.com/containers/podman/v5** (go): <= 5.6.0
- **github.com/containers/podman/v4** (go): <= 4.9.5

## Description

### Impact

The podman kube play command can overwrite host files when the kube file contains a ConfigMap or Secret volume mount and the volume already contains a symlink to a host file.
This allows a malicious container to write to arbitrary files on the host BUT the attacker only controls the target path not the contents that will be written to the file. The contents are defined in the yaml file by the end user.

### Requirements to exploit:
podman kube play must be used with a ConfigMap or Secret volume mount AND must be run more than once on the same volume. All the attacker has to do is create the malicious symlink on the volume the first time it is started. After that all following starts would follow the symlink and write to the host location. 


### Patches
Fixed in podman v5.6.1
https://github.com/containers/podman/commit/43fbde4e665fe6cee6921868f04b7ccd3de5ad89

### Workarounds

Don't use podman kube play with ConfigMap or Secret volume mounts.

### PR with test for CI

Adding on 9/8/2025 by @TomSweeneyRedHat , this is the PR containing the test in CI: https://github.com/containers/podman/pull/27001
