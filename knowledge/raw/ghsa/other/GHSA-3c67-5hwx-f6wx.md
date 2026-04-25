# Gradios's CORS origin validation is not performed when the request has a cookie

**GHSA**: GHSA-3c67-5hwx-f6wx | **CVE**: CVE-2024-47084 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-285, CWE-346

**Affected Packages**:
- **gradio** (pip): < 4.44.0

## Description

### Impact
**What kind of vulnerability is it? Who is impacted?**

This vulnerability is related to **CORS origin validation**, where the Gradio server fails to validate the request origin when a cookie is present. This allows an attacker’s website to make unauthorized requests to a local Gradio server. Potentially, attackers can upload files, steal authentication tokens, and access user data if the victim visits a malicious website while logged into Gradio. This impacts users who have deployed Gradio locally and use basic authentication.

### Patches
Yes, please upgrade to `gradio>=4.44` to address this issue.

### Workarounds
**Is there a way for users to fix or remediate the vulnerability without upgrading?**

As a workaround, users can manually enforce stricter CORS origin validation by modifying the `CustomCORSMiddleware` class in their local Gradio server code. Specifically, they can bypass the condition that skips CORS validation for requests containing cookies to prevent potential exploitation.


