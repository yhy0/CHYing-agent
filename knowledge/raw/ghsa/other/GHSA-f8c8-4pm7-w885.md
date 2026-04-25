# Cross-Site Request Forgery in CodeChecker API

**GHSA**: GHSA-f8c8-4pm7-w885 | **CVE**: CVE-2024-53829 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-352

**Affected Packages**:
- **codechecker** (pip): < 6.24.5

## Description

### Summary
Cross-site request forgery allows an unauthenticated attacker to hijack the authentication of a logged in user, and use the web API with the same permissions.

### Details
Security attributes like HttpOnly and SameSite are missing from the session cookie, allowing its use from XHR requests and form submissions.
The CodeChecker API endpoints only require the session cookie, they do not require a CSRF token, and missing HTTP headers allow the form submission to succeed (but not XHR). This means that the attacker needs to know the ID of products to edit or delete them, but it does not need knowledge to create new products with the SQLite backend.

### PoC
With a superuser logged into CodeChecker.

```html
<html><body>
    <form action="https://codechecker.example.com/v6.58/Products" method="POST" enctype="text/plain">
        <input type="text" name='[1,"getProducts",1,1,{}]' value=''>
    </form>
    <script>document.forms[0].submit()</script>
</body></html>
```
Or the same form attack on any of the applicable endpoints.

### Impact
The vulnerability allows an attacker to make requests to CodeChecker as the currently logged in user, including but not limited to adding, removing or editing products. The attacker needs to know the ID of the available products to modify or delete them. The attacker cannot directly exfiltrate data from CodeChecker, due to being limited to form-based CSRF.
