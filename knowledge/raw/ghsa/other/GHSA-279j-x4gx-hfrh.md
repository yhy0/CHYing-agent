# Gradio uses insecure communication between the FRP client and server

**GHSA**: GHSA-279j-x4gx-hfrh | **CVE**: CVE-2024-47871 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-311

**Affected Packages**:
- **gradio** (pip): < 5.0.0

## Description

### Impact  
**What kind of vulnerability is it? Who is impacted?**

This vulnerability involves **insecure communication** between the FRP (Fast Reverse Proxy) client and server when Gradio's `share=True` option is used. HTTPS is not enforced on the connection, allowing attackers to intercept and read files uploaded to the Gradio server, as well as modify responses or data sent between the client and server. This impacts users who are sharing Gradio demos publicly over the internet using `share=True` without proper encryption, exposing sensitive data to potential eavesdroppers.

### Patches  
Yes, please upgrade to `gradio>=5` to address this issue.

### Workarounds  
**Is there a way for users to fix or remediate the vulnerability without upgrading?**

As a workaround, users can avoid using `share=True` in production environments and instead host their Gradio applications on servers with HTTPS enabled to ensure secure communication.
