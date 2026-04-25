# Improper kubeconfig validation allows arbitrary code execution

**GHSA**: GHSA-vvmq-fwmg-2gjc | **CVE**: CVE-2022-24817 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94

**Affected Packages**:
- **github.com/fluxcd/flux2** (go): >= 0.1.0, < 0.29.0
- **github.com/fluxcd/kustomize-controller** (go): >= 0.1.0, < 0.23.0
- **github.com/fluxcd/helm-controller** (go): >= 0.2.0, < 0.19.0

## Description

Flux2 can reconcile the state of a remote cluster when provided with a [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#file-references) with the correct access rights. `Kubeconfig` files can define [commands](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins) to be executed to generate on-demand authentication tokens. A malicious user with write access to a Flux source or direct access to the target cluster, could craft a `kubeconfig` to execute arbitrary code inside the controller’s container.

In multi-tenancy deployments this can also lead to privilege escalation if the controller's service account has elevated permissions.

### Impact

Within the affected versions range, one of the permissions set below would be required for the vulnerability to be exploited:
- Direct access to the cluster to create Flux `Kustomization` or `HelmRelease` objects and Kubernetes Secrets.
- Direct access to the cluster to modify existing Kubernetes secrets being used as `kubeconfig` in existing Flux `Kustomization` or `HelmRelease` objects.
- Direct access to the cluster to modify existing Flux `Kustomization` or `HelmRelease` objects and access to create or modify existing Kubernetes secrets.
- Access rights to make changes to a configured Flux Source (i.e. Git repository).

### Patches

This vulnerability was fixed in kustomize-controller [v0.23.0](https://github.com/fluxcd/kustomize-controller/releases/tag/v0.23.0) and helm-controller [v0.19.0](https://github.com/fluxcd/helm-controller/releases/tag/v0.19.0), both included in flux2 [v0.29.0](https://github.com/fluxcd/flux2/releases/tag/v0.29.0). Starting from the fixed versions, both controllers disable the use of command execution from `kubeconfig` files by default, users have to opt-in by adding the flag `--insecure-kubeconfig-exec` to the controller’s command arguments. Users are no longer allowed to refer to files in the controller’s filesystem in the `kubeconfig` files provided for the remote apply feature.

### Workarounds

- The functionality can be disabled via Validating Admission webhooks (e.g. OPA Gatekeeper, Kyverno) by restricting users from being able to set the `spec.kubeConfig` field in Flux `Kustomization` and `HelmRelease` objects.
- Applying restrictive AppArmor and SELinux profiles on the controller’s pod to limit what binaries can be executed.

### Credits

The Flux engineering team found and patched this vulnerability.

### For more information

If you have any questions or comments about this advisory please open an issue in the [flux2 repository](http://github.com/fluxcd/flux2).

