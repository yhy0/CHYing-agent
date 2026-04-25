# Envoy Admin Interface Exposed through prometheus metrics endpoint

**GHSA**: GHSA-j777-63hf-hx76 | **CVE**: CVE-2025-24030 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-419

**Affected Packages**:
- **github.com/envoyproxy/gateway** (go): < 1.2.6

## Description

### Impact
A user with access to a Kubernetes cluster where Envoy Gateway is installed can use a path traversal attack to execute Envoy Admin interface commands on proxies managed by Envoy Gateway. The admin interface can be used to terminate the Envoy process and extract the Envoy configuration (possibly containing confidential data). 

For example, the following command, if run from within the Kubernetes cluster, can be used to get the configuration dump of the proxy:
```
curl --path-as-is http://<Proxy-Service-ClusterIP>:19001/stats/prometheus/../../config_dump
```
### Patches
1.2.6

### Workarounds
The `EnvoyProxy` API can be used to apply a bootstrap config patch that restricts access strictly to the prometheus stats endpoint. Find below an example of such a bootstrap patch. 

```
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: custom-proxy-config
  namespace: default
spec:
  bootstrap:
    type: JSONPatch
    jsonPatches:
    - op: "add"
      path: "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config/normalize_path"
      value: true
    - op: "replace"
      path: "/static_resources/listeners/0/filter_chains/0/filters/0/typed_config/route_config/virtual_hosts/0/routes/0/match"
      value:
        path: "/stats/prometheus"
        headers:
          - name: ":method"
            exact_match: GET
```

### References
- Envoy Admin Interface: https://www.envoyproxy.io/docs/envoy/latest/operations/admin
- Envoy Configuration Best Practices: https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge
