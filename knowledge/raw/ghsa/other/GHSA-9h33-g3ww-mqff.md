# Pocket ID: OAuth redirect_uri validation bypass via userinfo/host confusion

**GHSA**: GHSA-9h33-g3ww-mqff | **CVE**: CVE-2026-28512 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-601

**Affected Packages**:
- **github.com/pocket-id/pocket-id/backend** (go): < 0.0.0-20260228130835-3a339e33191c

## Description

### Impact
A flaw in callback URL validation allowed crafted `redirect_uri` values containing URL userinfo (`@`) to bypass legitimate callback pattern checks. If an attacker can trick a user into opening a malicious authorization link, the authorization code may be redirected to an attacker-controlled host.

### Patches
Fixed in `v2.3.1` (commit 3a339e33191c31b68bf57db907f800d9de5ffbc8).
The fix replaces delimiter-based callback matching with structured URL pattern matching and updates validation logic/tests.

### Workarounds
- Reject callback URLs containing userinfo (`@`) at reverse proxy / app policy level if feasible.
