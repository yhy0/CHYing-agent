# Vikunja: Stored XSS via Unsanitized SVG Attachment Upload Leads to Token Exposure

**GHSA**: GHSA-7jp5-298q-jg98 | **CVE**: CVE-2026-27616 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-79

**Affected Packages**:
- **code.vikunja.io/api** (go): <= 0.24.6

## Description

**Details**
The application allows users to upload SVG files as task attachments. SVG is an XML-based format that supports JavaScript execution through elements such as <script> tags or event handlers like onload.

The application does not sanitize SVG content before storing it. When the uploaded SVG file is accessed via its direct URL, it is rendered inline in the browser under the application's origin. As a result, embedded JavaScript executes in the context of the authenticated user.

Because the authentication token is stored in localStorage, it is accessible via JavaScript and can be retrieved by a malicious payload.

Key security issues identified:

 _No server-side sanitization of SVG content.
SVG attachments are rendered inline instead of being forced as a download.
Embedded JavaScript within SVG files is allowed to execute.
 Authentication tokens stored in localStorage are accessible to client-side scripts._

**PoC**

_**Tested Environment**_

[ ] Application version: 1.1.0
[ ] Deployment type: Self-hosted

**Steps to Reproduce**

1. Log in to an account.
2. Go to Projects and Create a new task or open an existing task.
3. Upload the following SVG file as an attachment:

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg
 onload="alert(localStorage.getItem('token'))"
 xmlns="http://www.w3.org/2000/svg">
</svg>

```
4. After uploading ,save the Task and open the project , copy the direct URL of the attachment.
5. Open the attachment URL in a new browser tab.
6. The embedded JavaScript executes immediately and displays the authentication token stored in `localStorage`.

This confirms that arbitrary JavaScript embedded in an uploaded SVG file executes within the application's context.

**Impact**

This vulnerability is classified as **Stored Cross-Site Scripting (XSS).**

**Potential impact includes:**

Execution of arbitrary JavaScript in a victim’s browser.
Exposure of authentication tokens.
Potential account takeover.
Ability to perform authenticated actions on behalf of the victim.
Possible privilege escalation if higher-privileged users open the malicious attachment.
Any authenticated user who accesses a malicious SVG attachment may be affected.

**Recommendations**

This vulnerability can be mitigated by implementing proper server-side sanitization of SVG uploads and preventing inline execution of uploaded files.

Specifically:

- Sanitize all uploaded SVG files to remove <script> elements, event handlers (e.g., onload), and other executable content.
- Serve attachments with Content-Disposition: attachment to prevent inline rendering.
- Implement a strict Content Security Policy (CSP) to block script execution within uploaded files.
- Store authentication tokens in HttpOnly, Secure cookies instead of localStorage to prevent JavaScript access.
- Applying these controls will prevent stored XSS via SVG uploads and significantly reduce the risk of token exposure and account takeover.

**Attachment**
[Stored XSS Proof of concept.pdf](https://github.com/user-attachments/files/25414870/Stored.XSS.Proof.of.concept.pdf)

A fix is available at https://github.com/go-vikunja/vikunja/releases/tag/v2.0.0.
