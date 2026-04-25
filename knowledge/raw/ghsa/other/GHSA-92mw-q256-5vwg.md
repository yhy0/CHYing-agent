# github.com/argoproj/argo-cd Cross-Site Request Forgery vulnerability

**GHSA**: GHSA-92mw-q256-5vwg | **CVE**: CVE-2024-22424 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-352

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): >= 0.1.0, <= 1.8.7
- **github.com/argoproj/argo-cd/v2** (go): < 2.7.16
- **github.com/argoproj/argo-cd/v2** (go): >= 2.8.0-rc1, < 2.8.8
- **github.com/argoproj/argo-cd/v2** (go): >= 2.9.0-rc1, < 2.9.4
- **github.com/argoproj/argo-cd/v2** (go): = 2.10.0-rc1

## Description

### Impact

The Argo CD API prior to versions 2.10-rc2, 2.9.4, 2.8.8, and 2.7.16 are vulnerable to a cross-server request forgery (CSRF) attack when the attacker has the ability to write HTML to a page on the same parent domain as Argo CD.

A CSRF attack works by tricking an authenticated Argo CD user into loading a web page which contains code to call Argo CD API endpoints on the victim’s behalf. For example, an attacker could send an Argo CD user a link to a page which looks harmless but in the background calls an Argo CD API endpoint to create an application running malicious code.

Argo CD uses the “Lax” SameSite cookie policy to prevent CSRF attacks where the attacker controls an external domain. The malicious external website can attempt to call the Argo CD API, but the web browser will refuse to send the Argo CD auth token with the request.

Many companies host Argo CD on an internal subdomain, such as [https://argo-cd.internal.example.com](https://argo-cd.example.com/). If an attacker can place malicious code on, for example, https://test.internal.example.com/, they can still perform a CSRF attack. In this case, the “Lax” SameSite cookie does not prevent the browser from sending the auth cookie, because the destination is a parent domain of the Argo CD API.

Browsers generally block such attacks by applying CORS policies to sensitive requests with sensitive content types. Specifically, browsers will send a “preflight request” for POSTs with content type “application/json” asking the destination API “are you allowed to accept requests from my domain?” If the destination API does not answer “yes,” the browser will block the request.

Before the patched versions, Argo CD did not validate that requests contained the correct content type header. So an attacker could bypass the browser’s CORS check by setting the content type to something which is considered “not sensitive” such as “text/plain.” The browser wouldn’t send the preflight request, and Argo CD would happily accept the contents (which are actually still JSON) and perform the requested action (such as running malicious code).

### Patches

A patch for this vulnerability has been released in the following Argo CD versions:

* 2.10-rc2
* 2.9.4
* 2.8.8
* 2.7.16

🚨 **The patch contains a breaking API change.** 🚨 The Argo CD API will no longer accept non-GET requests which do not specify application/json as their Content-Type. The accepted content types list is configurable, and it is possible (but discouraged) to disable the content type check completely.

### Workarounds

The only way to completely resolve the issue is to upgrade.

### Credits

The Argo CD team would like to express their gratitude to An Trinh of [Calif](https://calif.io/) who reported the issue confidentially according to our [guidelines](https://github.com/argoproj/argo-cd/blob/master/SECURITY.md#reporting-a-vulnerability) and published a helpful [blog post](https://blog.calif.io/p/argo-cd-csrf) to describe the issue. We would also like to thank them for actively participating in the review for the patch.

### References

* The problem was originally reported in a [GitHub issue](https://github.com/argoproj/argo-cd/issues/2496)
