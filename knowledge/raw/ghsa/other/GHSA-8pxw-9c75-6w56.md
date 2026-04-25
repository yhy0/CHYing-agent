# NeuVector admin account has insecure default password

**GHSA**: GHSA-8pxw-9c75-6w56 | **CVE**: CVE-2025-8077 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-1393

**Affected Packages**:
- **github.com/neuvector/neuvector** (go): >= 5.0.0, < 5.4.6

## Description

### Impact

A vulnerability exists in NeuVector versions up to and including **5.4.5**, where a fixed string is used as the default password for the built-in `admin` account. If this password is not changed immediately after deployment, any workload with network access within the cluster could use the default credentials to obtain an authentication token. This token can then be used to perform any operation via NeuVector APIs.

In earlier versions, NeuVector supports setting the default (bootstrap) password for the `admin` account using a Kubernetes Secret named `neuvector-bootstrap-secret`. This Secret must contain a key named `bootstrapPassword`. However, if NeuVector fails to retrieve this value, it falls back to the fixed default password.

### Patches

This issue is resolved in NeuVector version **5.4.6** and later. For rolling upgrades, it's strongly recommended to change the default `admin` password to a secure one.

Starting from version **5.4.6**, NeuVector introduces additional Kubernetes RBAC permissions to ensure the bootstrap password can be securely managed via Secrets:

```
kubectl create role neuvector-binding-secret-controller \
  --verb=create,patch,update --resource=secrets -n {neuvector}

kubectl create rolebinding neuvector-binding-secret-controller \
  --role=neuvector-binding-secret-controller \
  --serviceaccount=neuvector:controller \
  --serviceaccount=neuvector:default -n {neuvector}
```

- These RBAC roles are automatically applied when deploying via Helm.
- If deploying or upgrading manually, you must create these roles before starting NeuVector.

**NOTE:** If these roles are not present, the NeuVector controller (from version 5.4.6 onward) does not start.

#### Behavior in Patched Versions

- **Upgrades:** NeuVector does not reset any existing account passwords. It's strongly recommended to change the default `admin` password to a secure one.
- **New deployments:**
  - If `bootstrapPassword` is not set in the `neuvector-bootstrap-secret, NeuVector generates a secure password and stores it in the same Secret.

On first login, the default `admin` must retrieve the password using:

```
kubectl get secret -n {neuvector} neuvector-bootstrap-secret \
  -o go-template='{{ .data.bootstrapPassword | base64decode }}{{ "\n" }}'
```

The password must be changed during the first login via the NeuVector UI.

**NOTE:** If the default `admin` password is set using a Kubernetes ConfigMap or a persistent backup (not a fixed string), this value takes precedence over the Secret-based mechanism.

### Workarounds

For existing vulnerable versions, log in to the NeuVector UI immediately after deployment and update the default `admin` password.

### References

If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [NeuVector](https://github.com/neuvector/neuvector/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-neuvector/support-matrix/all-supported-versions/neuvector-v-all-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/#suse-security).
