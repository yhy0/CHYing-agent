# LangChain Experimental vulnerable to arbitrary code execution

**GHSA**: GHSA-v8vj-cv27-hjv8 | **CVE**: CVE-2024-27444 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-749

**Affected Packages**:
- **langchain-experimental** (pip): < 0.0.52

## Description

langchain_experimental (aka LangChain Experimental) before 0.0.52, part of LangChain before 0.1.8, allows an attacker to bypass the CVE-2023-44467 fix and execute arbitrary code via the `__import__`, `__subclasses__`, `__builtins__`, `__globals__`, `__getattribute__`, `__bases__`, `__mro__`, or `__base__` attribute in Python code. These are not prohibited by `pal_chain/base.py`.
