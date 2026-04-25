# Authelia vulnerable to an authentication bypassed with malformed request URI on nginx

**GHSA**: GHSA-68wm-pfjf-wqp6 | **CVE**: CVE-2021-32637 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/authelia/authelia/v4** (go): >= 4.0.0-alpha1, <= 4.29.2

## Description

### Impact
This affects uses who are using nginx ngx_http_auth_request_module with Authelia, it allows a malicious individual who crafts a malformed HTTP request to bypass the authentication mechanism. It additionally could theoretically affect other proxy servers, but all of the ones we officially support except nginx do not allow malformed URI paths.

### Patches
The problem is rectified entirely in v4.29.3. As this patch is relatively straightforward we can back port this to any version upon request. Alternatively we are supplying a git patch to 4.25.1 which should be relatively straightforward to apply to any version, the git patches for specific versions can be found below.

<details><summary>Patch for 4.25.1:</summary><p>

```patch
From ca22f3d2c44ca7bef043ffbeeb06d6659c1d550f Mon Sep 17 00:00:00 2001
From: James Elliott <james-d-elliott@users.noreply.github.com>
Date: Wed, 19 May 2021 12:10:13 +1000
Subject: [PATCH] fix(handlers): verify returns 200 on malformed request

This is a git patch for commit at tag v4.25.1 to address a potential method to bypass authentication in proxies that forward malformed information to Authelia in the forward auth process. Instead of returning a 200 this ensures that Authelia returns a 401 when this occurs.
---
 internal/handlers/handler_verify.go | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/internal/handlers/handler_verify.go b/internal/handlers/handler_verify.go
index 65c064ce..4dd9702d 100644
--- a/internal/handlers/handler_verify.go
+++ b/internal/handlers/handler_verify.go
@@ -396,7 +396,9 @@ func VerifyGet(cfg schema.AuthenticationBackendConfiguration) middlewares.Reques
 		targetURL, err := getOriginalURL(ctx)
 
 		if err != nil {
-			ctx.Error(fmt.Errorf("Unable to parse target URL: %s", err), operationFailedMessage)
+			ctx.Logger.Error(fmt.Errorf("Unable to parse target URL: %s", err))
+			ctx.ReplyUnauthorized()
+
 			return
 		}
 
-- 
2.31.1
```

</p></details>

### Workarounds
The most relevant workaround is upgrading. **If you need assistance with an upgrade please contact us on [Matrix](https://riot.im/app/#/room/#authelia:matrix.org) or [Discord](https://discord.authelia.com).** Please just let us know you're needing help upgrading to above 4.29.2. 

You can add an block which fails requests that contains a malformed URI in the internal location block. We have crafted one that should work in most instances, it basically checks no chars that are required to be URL-encoded for either the path or the query are in the URI. Basically this regex checks that the characters between the square braces are the only characters in the $request_uri header, if they exist, it returns a HTTP 401 status code. The characters in the regex match are tested to not cause a parsing error that would result in a failure, however they are not exhaustive since query strings seem to not always conform to the RFC.

<details><summary>authelia.conf:</summary><p>

```nginx
location /authelia {
    internal;
    # **IMPORTANT**
    # This block rejects requests with a 401 which contain characters that are unable to be parsed.
    # It is necessary for security prior to v4.29.3 due to the fact we returned an invalid code in the event of a parser error.
    # You may comment this section if you're using Authelia v4.29.3 or above. We strongly recommend upgrading.
    # RFC3986: http://tools.ietf.org/html/rfc3986
    # Commentary on RFC regarding Query Strings: https://www.456bereastreet.com/archive/201008/what_characters_are_allowed_unencoded_in_query_strings/
    if ($request_uri ~ [^a-zA-Z0-9_+-=\!@$%&*?~.:#'\;\(\)\[\]]) {
        return 401;
    }

    # Include the remainder of the block here. 
}
````

</p></details>

### Discovery

This issue was discovered by:

Siemens Energy
Cybersecurity Red Team

- Silas Francisco
- Ricardo Pesqueira


### Identifying active exploitation of the vulnerability

The following regex should match log entries that are an indication of the vulnerability being exploited:
```regex
level=error msg="Unable to parse target URL: Unable to parse URL (extracted from X-Original-URL header)?.*?: parse.*?net/url:.*github\.com/authelia/authelia/internal/handlers/handler_verify\.go
```

Example log entry ***with*** X-Original-URL configured:
```log
time="2021-05-21T16:31:15+10:00" level=error msg="Unable to parse target URL: Unable to parse URL extracted from X-Original-URL header: parse \"https://example.com/": net/url: invalid control character in URL" method=GET path=/api/verify remote_ip=192.168.1.10 stack="github.com/authelia/authelia/internal/middlewares/authelia_context.go:65 (*AutheliaCtx).Error\ngithub.com/authelia/authelia/internal/handlers/handler_verify.go:431     VerifyGet.func1\ngithub.com/authelia/authelia/internal/middlewares/authelia_context.go:50 AutheliaMiddleware.func1.1\ngithub.com/fasthttp/router@v1.3.12/router.go:414                         (*Router).Handler\ngithub.com/authelia/authelia/internal/middlewares/log_request.go:14      LogRequestMiddleware.func1\ngithub.com/valyala/fasthttp@v1.24.0/server.go:2219                       (*Server).serveConn\ngithub.com/valyala/fasthttp@v1.24.0/workerpool.go:223                    (*workerPool).workerFunc\ngithub.com/valyala/fasthttp@v1.24.0/workerpool.go:195                    (*workerPool).getCh.func1\nruntime/asm_amd64.s:1371                                                 goexit"
```

Example log entry ***without*** X-Original-URL configured:
```log
time="2021-05-21T16:30:17+10:00" level=error msg="Unable to parse target URL: Unable to parse URL https://example.com/: parse \"https://example.com/": net/url: invalid control character in URL" method=GET path=/api/verify remote_ip=192.168.1.10 stack="github.com/authelia/authelia/internal/middlewares/authelia_context.go:65 (*AutheliaCtx).Error\ngithub.com/authelia/authelia/internal/handlers/handler_verify.go:431     VerifyGet.func1\ngithub.com/authelia/authelia/internal/middlewares/authelia_context.go:50 AutheliaMiddleware.func1.1\ngithub.com/fasthttp/router@v1.3.12/router.go:414                         (*Router).Handler\ngithub.com/authelia/authelia/internal/middlewares/log_request.go:14      LogRequestMiddleware.func1\ngithub.com/valyala/fasthttp@v1.24.0/server.go:2219                       (*Server).serveConn\ngithub.com/valyala/fasthttp@v1.24.0/workerpool.go:223                    (*workerPool).workerFunc\ngithub.com/valyala/fasthttp@v1.24.0/workerpool.go:195                    (*workerPool).getCh.func1\nruntime/asm_amd64.s:1371                                                 goexit"
```

### For more information
If you have any questions or comments about this advisory:
* Open a [Discussion](https://github.com/authelia/authelia/discussions)
* Email us at [security@authelia.com](mailto:security@authelia.com)

### Edit / Adjustment

This CVE has been edited adjusting the score to more accurately reflect the guidance in the [official CVSS 3.1 guide](https://www.first.org/cvss/specification-document). Due to misunderstandings about the CVSS indicators this was incorrectly assigned but this has been corrected. Under close evaluation the score we originally assigned to this CVE is inappropriate in two clearly identifiable criteria:

- Complexity (Low -> High): This attack requires the administrator be using NGINX's auth_request module. This means the attack cannot be exploited at will but rather requires a pre-condition separate to the vulnerable system outside of the attackers control (a vulnerable version of NGINX - at the time of this writing NGINX's security team has *refused* to fix the clear bug on their end but that's effectively irrelevant since we operate with more than just a NGINX proxy and no other proxy has this vulnerability), and requires the attacker have gathered knowledge about the system for this likely to be exploited.
 - Availability (High -> None): This attack does not alter availability directly.
