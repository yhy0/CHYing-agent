# Traefik: tcp router clears read deadlines before tls forwarding, enabling stalled handshakes (Slowloris DOS)

**GHSA**: GHSA-xw98-5q62-jx94 | **CVE**: CVE-2026-26999 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/traefik/traefik/v2** (go): <= 2.11.37
- **github.com/traefik/traefik/v3** (go): <= 3.6.8

## Description

## Impact

There is a potential vulnerability in Traefik managing TLS handshake on TCP routers.

When Traefik processes a TLS connection on a TCP router, the read deadline used to bound protocol sniffing is cleared before the TLS handshake is completed. When a TLS handshake read error occurs, the code attempts a second handshake with different connection parameters, silently ignoring the initial error. A remote unauthenticated client can exploit this by sending an incomplete TLS record and stopping further data transmission, causing the TLS handshake to stall indefinitely and holding connections open.

By opening many such stalled connections in parallel, an attacker can exhaust file descriptors and goroutines, degrading availability of all services on the affected entrypoint.

## Patches

- https://github.com/traefik/traefik/releases/tag/v2.11.38
- https://github.com/traefik/traefik/releases/tag/v3.6.9

## Workarounds

No workaround available.

## For more information

If there are any questions or comments about this advisory, please [open an issue](https://github.com/traefik/traefik/issues).

---

<details>
<summary>Original Description</summary>

Traefik's TCP router uses a connection-level read deadline to bound protocol sniffing (peeking a TLS client hello), but then clears the deadline via conn.SetDeadline(time.Time{}) before delegating the connection to TLS forwarding.

A remote unauthenticated client can send an incomplete TLS record header and stop sending data. After the initial peek times out, the router clears the deadline and the subsequent TLS handshake reads can stall indefinitely, holding connections open and consuming resources.

### Expected vs Actual

Expected: if an entrypoint-level read deadline is used to bound initial protocol sniffing, TLS handshake reads should remain bounded by a deadline (either the same deadline is preserved, or a dedicated handshake timeout is enforced).

Actual: after protocol sniffing the router clears the connection deadline and delegates to TLS handling; an attacker can keep the TLS handshake stalled beyond the configured read timeout.

### Severity

HIGH
CWE: CWE-400 (Uncontrolled Resource Consumption)

### Affected Code

- pkg/server/router/tcp/router.go: (*Router).ServeTCP clears the deadline before TLS forwarding
- conn.SetDeadline(time.Time{}) removes the entrypoint-level deadline that previously bounded reads

### Root Cause

In (*Router).ServeTCP, after sniffing a TLS client hello, the router removes the connection read deadline:

    // Remove read/write deadline and delegate this to underlying TCP server
    // (for now only handled by HTTP Server)
    if err := conn.SetDeadline(time.Time{}); err != nil {
        ...
    }

TLS handshake reads that happen after this point are not guaranteed to have any deadline, so a client that stops sending bytes can keep the connection open indefinitely.

### Attacker Control

Attacker-controlled input is the raw TCP byte stream on an entrypoint that routes to a TLS forwarder. The attacker controls:

1. Sending a partial TLS record header (enough to trigger the TLS sniffing path)
2. Stopping further sends so the subsequent handshake read blocks

### Impact

Each stalled connection occupies file descriptors and goroutines (and may consume additional memory depending on buffering). By opening many such connections in parallel, an attacker can cause resource exhaustion and degrade availability.

### Reproduction

Attachments include poc.zip with a self-contained integration harness. It pins the repository commit, applies fix.patch as the control variant, and runs a regression-style test that demonstrates the stall in canonical mode and the timeout in control mode.

Run canonical (vulnerable):

    unzip poc.zip -d poc
    cd poc
    make test

Canonical output excerpt: PROOF_MARKER

Run control (deadline preserved / no stall):

    unzip poc.zip -d poc
    cd poc
    make control

Control output excerpt: NC_MARKER

### Recommended Fix

Do not clear the entrypoint-level deadline prior to completing TLS handshake, or enforce a dedicated handshake timeout for the TLS forwarder path.

Fix accepted when: an incomplete TLS record cannot stall past the configured entrypoint-level read deadline (or an explicit handshake timeout), and a regression test covers the canonical/control behavior.

</details>
