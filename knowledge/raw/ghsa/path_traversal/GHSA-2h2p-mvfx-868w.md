# SiYuan Vulnerable to Path Traversal in /export Endpoint Allows Arbitrary File Read and Secret Leakage

**GHSA**: GHSA-2h2p-mvfx-868w | **CVE**: CVE-2026-30869 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-22, CWE-200, CWE-285

**Affected Packages**:
- **github.com/siyuan-note/siyuan/kernel** (go): <= 3.5.9

## Description

### Summary
A path traversal vulnerability in the `/export` endpoint allows an attacker to read arbitrary files from the server filesystem. By exploiting double‑encoded traversal sequences, an attacker can access sensitive files such as `conf/conf.json`, which contains secrets including the API token, cookie signing key, and workspace access authentication code.

Leaking these secrets may enable administrative access to the SiYuan kernel API, and in certain deployment scenarios could potentially be chained into `remote code execution (RCE)`.

### Details
File: [serve.go](app://-/index.html?hostId=local#), [session.go](app://-/index.html?hostId=local#)
Lines: serve.go 303, 315, 320, 340, 955-957; session.go 292-295

Vulnerable Code:
```
// session.go
if localhost {
    if strings.HasPrefix(c.Request.RequestURI, "/assets/") || strings.HasPrefix(c.Request.RequestURI, "/export/") {
        c.Set(RoleContextKey, RoleAdministrator)
        c.Next()
        return
    }
}

// serve.go
filePath := strings.TrimPrefix(c.Request.URL.Path, "/export/")
decodedPath, err := url.PathUnescape(filePath)
fullPath := filepath.Join(exportBaseDir, decodedPath)
c.File(fullPath)

// CORS
c.Header("Access-Control-Allow-Origin", "*")

```
Points of Vulnerability:

- `/export/*` trusts url.PathUnescape output and joins it without enforcing fullPath to stay under exportBaseDir.
- Double-encoded traversal (`%252e%252e`) bypasses `ServeFile` dot-dot URL rejection but is decoded by app logic into ...
- `CheckAuth` grants admin for localhost requests to `/export/*` when access auth code is set.
- Global CORS `Access-Control-Allow-Origin: *` allows hostile web pages to read localhost responses.

### PoC

Reproduction Steps:

1. Send a GET request to `/export/%252e%252e/%252e%252e/conf/conf.json` or `export/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd`

2. If HTTP 200 is returned, inspect the response body for sensitive fields:
```
api.token
cookieKey
accessAuthCode
```
or
```
/etc/passwd
```

3. (Optional) If api.token is present, test admin API access:
```
POST /api/system/getNetwork
Header: Authorization: Token <leaked token>
```

4. Confirm that the response indicates administrative privileges.
All steps can be performed with read-only HTTP requests; no Docker or local modifications are needed.
### Impact

This vulnerability can lead to serious compromise of a SiYuan instance, including:

**Arbitrary File Disclosure**
- Attackers can read files anywhere on the server filesystem, including system files such as /etc/passwd.

**Exposure of Sensitive Secrets**
- Configuration files such as conf/conf.json contain sensitive information including:
- API tokens
- cookie signing keys
- workspace authentication codes

**Administrative API Access**
- Leaked tokens can allow attackers to interact with privileged SiYuan kernel APIs.

**Cross‑Origin Localhost Data Exfiltration**
- Because the server sets `Access-Control-Allow-Origin: *`, a malicious website can exploit the vulnerability to read files from a victim's local SiYuan instance running on 127.0.0.1.

**Potential Remote Code Execution (RCE)**
- Disclosure of authentication secrets and internal configuration may enable attackers to chain this vulnerability with other application features or APIs to achieve remote code execution or full system compromise.
