# smolagents has Sandbox Escape Vulnerability in the local_python_executor.py Module

**GHSA**: GHSA-6v92-r5mx-h5fx | **CVE**: CVE-2025-5120 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-94

**Affected Packages**:
- **smolagents** (pip): < 1.17.0

## Description

A sandbox escape vulnerability was identified in huggingface/smolagents version 1.14.0, allowing attackers to bypass the restricted execution environment and achieve remote code execution (RCE). The vulnerability stems from the local_python_executor.py module, which inadequately restricts Python code execution despite employing static and dynamic checks. Attackers can exploit whitelisted modules and functions to execute arbitrary code, compromising the host system. This flaw undermines the core security boundary intended to isolate untrusted code, posing risks such as unauthorized code execution, data leakage, and potential integration-level compromise. The issue is resolved in version 1.17.0.
