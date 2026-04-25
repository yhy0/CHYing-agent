# Gogs: Stored XSS via data URI in issue comments

**GHSA**: GHSA-xrcr-gmf5-2r8j | **CVE**: CVE-2026-26022 | **Severity**: high (CVSS 8.7)

**CWE**: CWE-79

**Affected Packages**:
- **gogs.io/gogs** (go): <= 0.14.1

## Description

### Summary
A Stored Cross-site Scripting (XSS) vulnerability exists in the comment and issue description functionality. The application's HTML sanitizer explicitly allows `data:` URI schemes, enabling authenticated users to inject arbitrary JavaScript execution via malicious links.

### Details
The vulnerability is located in `internal/markup/sanitizer.go`. The application uses the `bluemonday` HTML sanitizer but explicitly weakens the security policy by allowing the `data` URL scheme:

```go
// internal/markup/sanitizer.go
func NewSanitizer() {
    sanitizer.init.Do(func() {
        // ...
        // Data URLs
        sanitizer.policy.AllowURLSchemes("data")
        // ...
    })
}
```

While the Markdown renderer rewrites relative links (mitigating standard Markdown `[link](data:...)` attacks), Gogs supports **Raw HTML** input. Raw HTML anchor tags bypass the Markdown parser's link rewriting and are processed directly by the sanitizer. Since the sanitizer is configured to allow `data:` URIs, payloads like `<a href="data:text/html...">` are rendered as-is.

### PoC
1.  Create a file named `exploit.md` in a repository.
2.  Add the following content (Raw HTML):
    ```html
    <a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">Click me for XSS</a>
    ```
3.  Commit and push the file.
4.  Navigate to the file in the Gogs web interface.
5.  Click the "Click me for XSS" link.
6.  **Result:** An alert box with "XSS" appears, executing the JavaScript payload.

### Impact
This is a **Stored XSS** vulnerability. Any user who views the malicious comment and clicks the link will execute the attacker-supplied JavaScript in their browser context. This allows attackers to:
*   Steal authentication cookies and session tokens.
*   Perform arbitrary actions on behalf of the victim (e.g., modifying repositories, adding collaborators).
*   Redirect users to malicious sites.
