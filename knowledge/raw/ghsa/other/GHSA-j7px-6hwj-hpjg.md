# Open Redirect in OAuth2 Proxy

**GHSA**: GHSA-j7px-6hwj-hpjg | **CVE**: CVE-2020-11053 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-601

**Affected Packages**:
- **github.com/oauth2-proxy/oauth2-proxy** (go): < 5.1.1

## Description

### Impact
As users can provide a redirect address for the proxy to send the authenticated user to at the end of the authentication flow. This is expected to be the original URL that the user was trying to access.
This redirect URL is checked within the proxy and validated before redirecting the user to prevent malicious actors providing redirects to potentially harmful sites.

However, by crafting a redirect URL with HTML encoded whitespace characters (eg. `%0a`, `%0b`,`%09`,`%0d`) the validation could be bypassed and allow a redirect to any URL provided.

### Patches
@rootxharsh and @iamnoooob provided this patch as potential solution:
```
From 4b941f56eda310b5c4dc8080b7635a6bfabccad4 Mon Sep 17 00:00:00 2001
From: Harsh Jaiswal <harsh@pop-os.localdomain>
Date: Fri, 1 May 2020 20:38:31 +0530
Subject: [PATCH] Fixes redirect issue

---
 oauthproxy.go | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/oauthproxy.go b/oauthproxy.go
index 1e9bb7c..f8beb4d 100644
--- a/oauthproxy.go
+++ b/oauthproxy.go
@@ -577,8 +577,9 @@ func validOptionalPort(port string) bool {

 // IsValidRedirect checks whether the redirect URL is whitelisted
 func (p *OAuthProxy) IsValidRedirect(redirect string) bool {
+       matched, _ := regexp.MatchString(`^/\s+/|\\`, redirect)
        switch {
-       case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") && !strings.HasPrefix(redirect, "/\\"):
+       case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") && !matched:
                return true
        case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
                redirectURL, err := url.Parse(redirect)
--
2.17.1
```

This issue was also reported to us separately by @mik317 several hours later

The fix was implemented in [#xxx]() and released as version 5.1.1
