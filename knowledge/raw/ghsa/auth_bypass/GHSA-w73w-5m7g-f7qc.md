# Authorization bypass in github.com/dgrijalva/jwt-go

**GHSA**: GHSA-w73w-5m7g-f7qc | **CVE**: CVE-2020-26160 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-287, CWE-755

**Affected Packages**:
- **github.com/dgrijalva/jwt-go/v4** (go): < 4.0.0-preview1
- **github.com/dgrijalva/jwt-go** (go): >= 0.0.0-20150717181359-44718f8a89b0, <= 3.2.0

## Description

jwt-go allows attackers to bypass intended access restrictions in situations with `[]string{}` for `m["aud"]` (which is allowed by the specification). Because the type assertion fails, "" is the value of aud. This is a security problem if the JWT token is presented to a service that lacks its own audience check. There is no patch available and users of jwt-go are advised to migrate to [golang-jwt](https://github.com/golang-jwt/jwt) at version 3.2.1
