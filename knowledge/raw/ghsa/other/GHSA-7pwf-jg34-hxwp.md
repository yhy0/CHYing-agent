# Improper path handling in Kustomization files allows for denial of service

**GHSA**: GHSA-7pwf-jg34-hxwp | **CVE**: CVE-2022-24878 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-674

**Affected Packages**:
- **github.com/fluxcd/kustomize-controller** (go): >= 0.16.0, < 0.24.0
- **github.com/fluxcd/flux2** (go): >= 0.19.0, < 0.29.0

## Description

The kustomize-controller enables the use of Kustomize’s functionality when applying Kubernetes declarative state onto a cluster. A malicious user can use a specially crafted `kustomization.yaml` to cause Denial of Service at controller level.

In multi-tenancy deployments this can lead to multiple tenants not being able to apply their Kustomizations until the malicious `kustomization.yaml` is removed and the controller restarted.

### Impact

Within the affected versions, users with write access to a Flux source are able to craft a malicious `kustomization.yaml` file which causes the controller to enter an endless loop.

### Patches

This vulnerability was fixed in kustomize-controller v0.24.0 and included in flux2 v0.29.0 released on 2022-04-20. The changes introduce better handling of Kustomization files blocking references that could lead to endless loops.

### Credits

The Flux engineering team found and patched this vulnerability.

### For more information

If you have any questions or comments about this advisory please open an issue in the [flux2 repository](http://github.com/fluxcd/flux2).
