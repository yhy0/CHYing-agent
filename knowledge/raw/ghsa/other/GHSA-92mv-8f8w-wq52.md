# traefik CVE-2024-45410 fix bypass: lowercase `Connection` tokens can delete traefik-managed forwarded identity headers (for example, `X-Real-Ip`)

**GHSA**: GHSA-92mv-8f8w-wq52 | **CVE**: CVE-2026-29054 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-178

**Affected Packages**:
- **github.com/traefik/traefik/v2** (go): >= 2.11.9, <= 2.11.37
- **github.com/traefik/traefik/v3** (go): >= 3.1.3, <= 3.6.8

## Description

## Impact

There is a potential vulnerability in Traefik managing the `Connection` header with `X-Forwarded` headers.

When Traefik processes HTTP/1.1 requests, the protection put in place to prevent the removal of Traefik-managed `X-Forwarded` headers (such as `X-Real-Ip`, `X-Forwarded-Host`, `X-Forwarded-Port`, etc.) via the `Connection` header does not handle case sensitivity correctly. The `Connection` tokens are compared case-sensitively against the protected header names, but the actual header deletion operates case-insensitively. As a result, a remote unauthenticated client can use lowercase `Connection` tokens (e.g. `Connection: x-real-ip`) to bypass the protection and trigger the removal of Traefik-managed forwarded identity headers.

This is a bypass of the fix for [CVE-2024-45410](https://github.com/traefik/traefik/security/advisories/GHSA-62c8-mh53-4cqv).

Depending on the deployment, the impact may be higher if downstream services rely on these headers (such as `X-Real-Ip` or `X-Forwarded-*`) for authentication, authorization, routing, or scheme decisions.

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

Traefik's XForwarded middleware (removeConnectionHeaders) tries to prevent clients from using the Connection header to strip trusted X-Forwarded-* headers, but the protection compares the Connection tokens case-sensitively while the deletion is case-insensitive.

As a result, a remote unauthenticated client can send a lowercase token like Connection: x-real-ip and still trigger deletion of traefik-managed X-Real-Ip (and similarly named headers in the managed list).

This can cause downstream routing, scheme, and header-based authn/authz decisions to be evaluated with missing trusted forwarding identity headers.

### Severity

CRITICAL

Rationale: the PoC demonstrates an end-to-end access control bypass pattern when a downstream service uses proxy-provided identity headers (for example, X-Real-Ip) for IP allowlists or trust decisions. A remote unauthenticated client can strip the traefik-managed identity header via a lowercase Connection token, causing the downstream service to evaluate the request without the expected header signal.

### Relevant Links

- Repository: https://github.com/traefik/traefik
- Pinned commit: a4a91344edcdd6276c1b766ca19ee3f0e346480f
- Callsite (pinned): https://github.com/traefik/traefik/blob/a4a91344edcdd6276c1b766ca19ee3f0e346480f/pkg/middlewares/forwardedheaders/forwarded_header.go#L225

### Vulnerability Details

#### Root Cause

removeConnectionHeaders uses a case-sensitive membership check for protected header names when inspecting Connection tokens, but it deletes headers via net/http which treats header names case-insensitively. A lowercase token bypasses the protection check and still triggers deletion.

#### Attacker Control / Attack Path

Remote unauthenticated HTTP client (untrusted IP) sends Connection: x-real-ip, and Traefik deletes the generated X-Real-Ip header.

### Proof of Concept

The attached poc.zip contains a deterministic, make-based integration PoC with a canonical run and a negative control.

Canonical (vulnerable):

    unzip poc.zip -d poc
    cd poc
    make test

Output contains:

    [CALLSITE_HIT]: pkg/middlewares/forwardedheaders/forwarded_header.go:225
    [PROOF_MARKER]: downstream_admin_bypass=1 x_real_ip_present=0

Control (same env, no lowercase token):

    unzip poc.zip -d poc
    cd poc
    make test

Output contains:

    [CALLSITE_HIT]: pkg/middlewares/forwardedheaders/forwarded_header.go:225
    [NC_MARKER]: downstream_admin_bypass=0 x_real_ip_present=1

Expected: Connection tokens are handled case-insensitively and protected identity headers (for example, X-Real-Ip and X-Forwarded-*) are not deleted due to client-supplied Connection options (regardless of token casing).

Actual: Lowercase Connection tokens bypass the protection check and still trigger deletion of traefik-managed identity headers (for example, X-Real-Ip).

### Recommended Fix

- Case-fold (or otherwise canonicalize) Connection header tokens before comparing them against protected header names.
- Add a regression test covering lowercase tokens (for example, Connection: x-real-ip).

Fix accepted when: a request with Connection: x-real-ip does not cause deletion of traefik-managed X-Real-Ip, and a regression test covers this behavior.

</details>
