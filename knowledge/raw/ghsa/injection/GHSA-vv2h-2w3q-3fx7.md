# PandasAI interactive prompt function Remote Code Execution (RCE)

**GHSA**: GHSA-vv2h-2w3q-3fx7 | **CVE**: CVE-2024-12366 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **pandasai** (pip): <= 2.4.2

## Description

PandasAI uses an interactive prompt function that is vulnerable to prompt injection and run arbitrary Python code that can lead to Remote Code Execution (RCE) instead of the intended explanation of the natural language processing by the LLM. The security controls of PandasAI (2.4.3 and earlier) fail to distinguish between legitimate and malicious inputs, allowing the attackers to manipulate the system into executing untrusted code, leading to untrusted code execution (RCE), system compromise, or pivoting attacks on connected services.
