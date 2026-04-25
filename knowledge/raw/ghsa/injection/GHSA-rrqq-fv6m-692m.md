# vanna vulnerable to remote code execution caused by prompt injection

**GHSA**: GHSA-rrqq-fv6m-692m | **CVE**: CVE-2024-5826 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **vanna** (pip): <= 0.6.2

## Description

In the latest version of vanna-ai/vanna, the `vanna.ask` function is vulnerable to remote code execution due to prompt injection. The root cause is the lack of a sandbox when executing LLM-generated code, allowing an attacker to manipulate the code executed by the `exec` function in `src/vanna/base/base.py`. This vulnerability can be exploited by an attacker to achieve remote code execution on the app backend server, potentially gaining full control of the server.
