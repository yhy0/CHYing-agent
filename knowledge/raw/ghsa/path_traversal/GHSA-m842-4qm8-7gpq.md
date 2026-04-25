# Gradio allows users to access arbitrary files

**GHSA**: GHSA-m842-4qm8-7gpq | **CVE**: CVE-2024-1728 | **Severity**: critical (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **gradio** (pip): < 4.19.2

## Description

### Impact
This vulnerability allows users of Gradio applications that have a public link (such as on Hugging Face Spaces) to access files on the machine hosting the Gradio application. This involves intercepting and modifying the network requests made by the Gradio app to the server. 

### Patches
Yes, the problem has been patched in Gradio version 4.19.2 or higher. We have no knowledge of this exploit being used against users of Gradio applications, but we encourage all users to upgrade to Gradio 4.19.2 or higher.

Fixed in: https://github.com/gradio-app/gradio/commit/16fbe9cd0cffa9f2a824a0165beb43446114eec7
CVE: https://nvd.nist.gov/vuln/detail/CVE-2024-1728
