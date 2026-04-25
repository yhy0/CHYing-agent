# Gradio makes the `/file` secure against file traversal and server-side request forgery attacks

**GHSA**: GHSA-6qm2-wpxq-7qh2 | **CVE**: CVE-2023-51449 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-22

**Affected Packages**:
- **gradio** (pip): < 4.11.0

## Description

Older versions of `gradio` contained a vulnerability in the `/file` route which made them susceptible to file traversal attacks in which an attacker could access arbitrary files on a machine running a Gradio app with a public URL (e.g. if the demo was created with `share=True`, or on Hugging Face Spaces) if they knew the path of files to look for. 

This was not possible through regular URLs passed into a browser, but it was possible through the use of programmatic tools such as `curl` with the `--pass-as-is` flag. 

Furthermore,  the `/file` route in Gradio apps also contained a vulnerability that made it possible to use it for SSRF attacks.

Both of these vulnerabilities have been fixed in `gradio==4.11.0`
