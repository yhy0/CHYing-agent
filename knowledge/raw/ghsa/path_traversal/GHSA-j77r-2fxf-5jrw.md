# Improper path handling in kustomization files allows path traversal

**GHSA**: GHSA-j77r-2fxf-5jrw | **CVE**: CVE-2022-24877 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/fluxcd/kustomize-controller** (go): < 0.24.0
- **github.com/fluxcd/flux2** (go): < 0.29.0

## Description

The kustomize-controller enables the use of Kustomize’s functionality when applying Kubernetes declarative state onto a cluster. A malicious user can use built-in features and a specially crafted `kustomization.yaml` to expose sensitive data from the controller’s pod filesystem. In multi-tenancy deployments this can lead to privilege escalation if the controller's service account has elevated permissions.

Within the affected versions, users with write access to a Flux source are able to use built-in features to expose sensitive data from the controller’s pod filesystem using a malicious `kustomization.yaml` file.

This vulnerability was fixed in kustomize-controller v0.24.0 and included in flux2 v0.29.0 released on 2022-04-20. The changes introduce a new Kustomize file system implementation which ensures that all files being handled are contained within the Kustomization working directory, blocking references to any files that do not meet that requirement.

Automated tooling (e.g. conftest) could be employed as a workaround, as part of a user's CI/CD pipeline to ensure that their `kustomization.yaml` files conform with specific policies, blocking access to sensitive path locations.
