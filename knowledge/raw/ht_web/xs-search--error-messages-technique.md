# XS-Search/XS-Leaks - Error Messages Technique

## Error Messages Technique


### Media Error

- **Inclusion Methods**: HTML Elements (Video, Audio)
- **Detectable Difference**: Status Code
- **More info**: [https://bugs.chromium.org/p/chromium/issues/detail?id=828265](https://bugs.chromium.org/p/chromium/issues/detail?id=828265)
- **Summary:** In Firefox is possible to accurately leak a cross-origin request’s status code.
- **Code Example**: [https://jsbin.com/nejatopusi/1/edit?html,css,js,output](https://jsbin.com/nejatopusi/1/edit?html,css,js,output)

```javascript
// Code saved here in case it dissapear from the link
// Based on MDN MediaError example: https://mdn.github.io/dom-examples/media/mediaerror/
window.addEventListener("load", startup, false)
function displayErrorMessage(msg) {
  document.getElementById("log").innerHTML += msg
}

function startup() {
  let audioElement = document.getElementById("audio")
  // "https://mdn.github.io/dom-examples/media/mediaerror/assets/good.mp3";
  document.getElementById("startTest").addEventListener(
    "click",
    function () {
      audioElement.src = document.getElementById("testUrl").value
    },
    false
  )
  // Create the event handler
  var errHandler = function () {
    let err = this.error
    let message = err.message
    let status = ""

    // Chrome error.message when the request loads successfully: "DEMUXER_ERROR_COULD_NOT_OPEN: FFmpegDemuxer: open context failed"
    // Firefox error.message when the request loads successfully: "Failed to init decoder"
    if (
      message.indexOf("DEMUXER_ERROR_COULD_NOT_OPEN") != -1 ||
      message.indexOf("Failed to init decoder") != -1
    ) {
      status = "Success"
    } else {
      status = "Error"
    }
    displayErrorMessage(
      "<strong>Status: " +
        status +
        "</strong> (Error code:" +
        err.code +
        " / Error Message: " +
        err.message +
        ")<br>"
    )
  }
  audioElement.onerror = errHandler
}
```

The `MediaError` interface's message property uniquely identifies resources that load successfully with a distinct string. An attacker can exploit this feature by observing the message content, thereby deducing the response status of a cross-origin resource.

### CORS Error

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Header
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.3)
- **Summary:** In Security Assertions (SA), CORS error messages inadvertently expose the full URL of redirected requests.
- **Code Example**: [https://xsinator.com/testing.html#CORS%20Error%20Leak](https://xsinator.com/testing.html#CORS%20Error%20Leak)

This technique enables an attacker to **extract the destination of a cross-origin site's redirect** by exploiting how Webkit-based browsers handle CORS requests. Specifically, when a **CORS-enabled request** is sent to a target site that issues a redirect based on user state and the browser subsequently denies the request, the **full URL of the redirect's target** is disclosed within the error message. This vulnerability not only reveals the fact of the redirect but also exposes the redirect's endpoint and any **sensitive query parameters** it may contain.

### SRI Error

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Header
- **More info**: [https://xsinator.com/paper.pdf](https://xsinator.com/paper.pdf) (5.3)
- **Summary:** In Security Assertions (SA), CORS error messages inadvertently expose the full URL of redirected requests.
- **Code Example**: [https://xsinator.com/testing.html#SRI%20Error%20Leak](https://xsinator.com/testing.html#SRI%20Error%20Leak)

An attacker can exploit **verbose error messages** to deduce the size of cross-origin responses. This is possible due to the mechanism of Subresource Integrity (SRI), which uses the integrity attribute to validate that resources fetched, often from CDNs, haven't been tampered with. For SRI to work on cross-origin resources, these must be **CORS-enabled**; otherwise, they're not subject to integrity checks. In Security Assertions (SA), much like the CORS error XS-Leak, an error message can be captured after a fetch request with an integrity attribute fails. Attackers can deliberately **trigger this error** by assigning a **bogus hash value** to the integrity attribute of any request. In SA, the resulting error message inadvertently reveals the content length of the requested resource. This information leakage allows an attacker to discern variations in response size, paving the way for sophisticated XS-Leak attacks.

### CSP Violation/Detection

- **Inclusion Methods**: Pop-ups
- **Detectable Difference**: Status Code
- **More info**: [https://bugs.chromium.org/p/chromium/issues/detail?id=313737](https://bugs.chromium.org/p/chromium/issues/detail?id=313737), [https://lists.w3.org/Archives/Public/public-webappsec/2013May/0022.html](https://lists.w3.org/Archives/Public/public-webappsec/2013May/0022.html), [https://xsleaks.dev/docs/attacks/navigations/#cross-origin-redirects](https://xsleaks.dev/docs/attacks/navigations/#cross-origin-redirects)
- **Summary:** Allowing only the victims website in the CSP if we accessed it tries to redirect to a different domain the CSP will trigger a detectable error.
- **Code Example**: [https://xsinator.com/testing.html#CSP%20Violation%20Leak](https://xsinator.com/testing.html#CSP%20Violation%20Leak), [https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/secrets#intended-solution-csp-violation](https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/secrets#intended-solution-csp-violation)

A XS-Leak can use the CSP to detect if a cross-origin site was redirected to a different origin. This leak can detect the redirect, but additionally, the domain of the redirect target leaks. The basic idea of this attack is to **allow the target domain on the attacker site**. Once a request is issued to the target domain, it **redirects** to a cross-origin domain. **CSP blocks** the access to it and creates a **violation report used as a leak technique**. Depending on the browser, **this report may leak the target location of the redirect**.\
Modern browsers won't indicate the URL it was redirected to, but you can still detect that a cross-origin redirect was triggered.

### Cache

- **Inclusion Methods**: Frames, Pop-ups
- **Detectable Difference**: Page Content
- **More info**: [https://xsleaks.dev/docs/attacks/cache-probing/#cache-probing-with-error-events](https://xsleaks.dev/docs/attacks/cache-probing/#cache-probing-with-error-events), [https://sirdarckcat.blogspot.com/2019/03/http-cache-cross-site-leaks.html](https://sirdarckcat.blogspot.com/2019/03/http-cache-cross-site-leaks.html)
- **Summary:** Clear the file from the cache. Opens target page checks if the file is present in the cache.
- **Code Example:**

Browsers might use one shared cache for all websites. Regardless of their origin, it is possible to deduct whether a target page has **requested a specific file**.

If a page loads an image only if the user is logged in, you can **invalidate** the **resource** (so it's no longer cached if it was, see more info links), **perform a request** that could load that resource and try to load the resource **with a bad request** (e.g. using an overlong referer header). If the resource load **didn't trigger any error**, it's because it was **cached**.

### CSP Directive

- **Inclusion Methods**: Frames
- **Detectable Difference**: Header
- **More info**: [https://bugs.chromium.org/p/chromium/issues/detail?id=1105875](https://bugs.chromium.org/p/chromium/issues/detail?id=1105875)
- **Summary:** CSP header directives can be probed using the CSP iframe attribute, revealing policy details.
- **Code Example**: [https://xsinator.com/testing.html#CSP%20Directive%20Leak](https://xsinator.com/testing.html#CSP%20Directive%20Leak)

A novel feature in Google Chrome (GC) allows web pages to **propose a Content Security Policy (CSP)** by setting an attribute on an iframe element, with policy directives transmitted along with the HTTP request. Normally, the embedded content must **authorize this via an HTTP header**, or an **error page is displayed**. However, if the iframe is already governed by a CSP and the newly proposed policy isn't more restrictive, the page will load normally. This mechanism opens a pathway for an attacker to **detect specific CSP directives** of a cross-origin page by identifying the error page. Although this vulnerability was marked as fixed, our findings reveal a **new leak technique** capable of detecting the error page, suggesting that the underlying problem was never fully addressed.

### **CORP**

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Header
- **More info**: [**https://xsleaks.dev/docs/attacks/browser-features/corp/**](https://xsleaks.dev/docs/attacks/browser-features/corp/)
- **Summary:** Resources secured with Cross-Origin Resource Policy (CORP) will throw an error when fetched from a disallowed origin.
- **Code Example**: [https://xsinator.com/testing.html#CORP%20Leak](https://xsinator.com/testing.html#CORP%20Leak)

The CORP header is a relatively new web platform security feature that when set b**locks no-cors cross-origin requests to the given resource**. The presence of the header can be detected, because a resource protected with CORP will **throw an error when fetched**.

### CORB

- **Inclusion Methods**: HTML Elements
- **Detectable Difference**: Headers
- **More info**: [https://xsleaks.dev/docs/attacks/browser-features/corb/#detecting-the-nosniff-header](https://xsleaks.dev/docs/attacks/browser-features/corb/#detecting-the-nosniff-header)
- **Summary**: CORB can allow attackers to detect when the **`nosniff` header is present** in the request.
- **Code Example**: [https://xsinator.com/testing.html#CORB%20Leak](https://xsinator.com/testing.html#CORB%20Leak)

Check the link for more information about the attack.

### CORS error on Origin Reflection misconfiguration <a href="#cors-error-on-origin-reflection-misconfiguration" id="cors-error-on-origin-reflection-misconfiguration"></a>

- **Inclusion Methods**: Fetch API
- **Detectable Difference**: Headers
- **More info**: [https://xsleaks.dev/docs/attacks/cache-probing/#cors-error-on-origin-reflection-misconfiguration](https://xsleaks.dev/docs/attacks/cache-probing/#cors-error-on-origin-reflection-misconfiguration)
- **Summary**: If the Origin header is reflected in the header `Access-Control-Allow-Origin` it's possible to check if a resource is in the cache already.
- **Code Example**: [https://xsleaks.dev/docs/attacks/cache-probing/#cors-error-on-origin-reflection-misconfiguration](https://xsleaks.dev/docs/attacks/cache-probing/#cors-error-on-origin-reflection-misconfiguration)

In case the **Origin header** is being **reflected** in the header `Access-Control-Allow-Origin` an attacker can abuse this behaviour to try to **fetch** the **resource** in **CORS** mode. If an **error** **isn't** triggered, it means that it was **correctly retrieved form the web**, if an error is **triggered**, it's because it was **accessed from the cache** (the error appears because the cache saves a response with a CORS header allowing the original domain and not the attackers domain)**.**\
Note that if the origin isn't reflected but a wildcard is used (`Access-Control-Allow-Origin: *`) this won't work.
