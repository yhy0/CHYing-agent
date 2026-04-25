# DB-GPT Arbitrary File Write vulnerability

**GHSA**: GHSA-7gj6-22m4-qfhx | **CVE**: CVE-2024-10901 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-89, CWE-434

**Affected Packages**:
- **dbgpt** (pip): <= 0.6.3

## Description

In eosphoros-ai/db-gpt version v0.6.3 and earlier, the web API `POST /api/v1/editor/chart/run` allows execution of arbitrary SQL queries without any access control. This vulnerability can be exploited by attackers to perform Arbitrary File Write, enabling them to write arbitrary files to the victim's file system. This can potentially lead to Remote Code Execution (RCE) by writing malicious files such as `__init__.py` in the Python's `/site-packages/` directory.
