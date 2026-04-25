# Fiber has Insecure CORS Configuration, Allowing Wildcard Origin with Credentials

**GHSA**: GHSA-fmg4-x8pw-hjhg | **CVE**: CVE-2024-25124 | **Severity**: critical (CVSS 9.4)

**CWE**: CWE-346

**Affected Packages**:
- **github.com/gofiber/fiber/v2** (go): < 2.52.1

## Description

The CORS middleware allows for insecure configurations that could potentially expose the application to multiple CORS-related vulnerabilities. Specifically, it allows setting the Access-Control-Allow-Origin header to a wildcard ("*") while also having the Access-Control-Allow-Credentials set to true, which goes against recommended security best practices.

## Impact
The impact of this misconfiguration is high as it can lead to unauthorized access to sensitive user data and expose the system to various types of attacks listed in the PortSwigger article linked in the references.

## Proof of Concept
The code in cors.go allows setting a wildcard in the AllowOrigins while having AllowCredentials set to true, which could lead to various vulnerabilities.

## Potential Solution
Here is a potential solution to ensure the CORS configuration is secure:

```go
func New(config ...Config) fiber.Handler {
    if cfg.AllowCredentials && cfg.AllowOrigins == "*" {
        panic("[CORS] Insecure setup, 'AllowCredentials' is set to true, and 'AllowOrigins' is set to a wildcard.")
    }
    // Return new handler goes below
}

The middleware will not allow insecure configurations when using `AllowCredentials` and `AllowOrigins`.
```

## Workarounds
For the meantime, users are advised to manually validate the CORS configurations in their implementation to ensure that they do not allow a wildcard origin when credentials are enabled. The browser fetch api, browsers and utilities that enforce CORS policies are not affected by this.

## References
[MDN Web Docs on CORS Errors](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials)
[CodeQL on CORS Misconfiguration](https://codeql.github.com/codeql-query-help/javascript/js-cors-misconfiguration-for-credentials/)
[PortSwigger on Exploiting CORS Misconfigurations](http://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html)
[WhatWG CORS protocol and credentials ](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)
