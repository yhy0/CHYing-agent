# LoLLMS Code Injection vulnerability

**GHSA**: GHSA-jccx-m9v4-9hwh | **CVE**: CVE-2024-6982 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-94

**Affected Packages**:
- **lollms** (pip): < 11.0.0

## Description

A remote code execution vulnerability exists in the Calculate function of parisneo/lollms version 9.8. The vulnerability arises from the use of Python's `eval()` function to evaluate mathematical expressions within a Python sandbox that disables `__builtins__` and only allows functions from the `math` module. This sandbox can be bypassed by loading the `os` module using the `_frozen_importlib.BuiltinImporter` class, allowing an attacker to execute arbitrary commands on the server. The issue is fixed in version 9.10.
