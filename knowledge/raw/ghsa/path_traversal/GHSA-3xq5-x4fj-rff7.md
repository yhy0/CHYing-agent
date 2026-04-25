# DB-GPT vulnerable to Arbitrary File Upload with Path Traversal

**GHSA**: GHSA-3xq5-x4fj-rff7 | **CVE**: CVE-2024-10902 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-22, CWE-73

**Affected Packages**:
- **dbgpt** (pip): <= 0.6.0

## Description

In eosphoros-ai/db-gpt version v0.6.0, the web API `POST /v1/personal/agent/upload` is vulnerable to Arbitrary File Upload with Path Traversal. This vulnerability allows unauthorized attackers to upload arbitrary files to the victim's file system at any location. The impact of this vulnerability includes the potential for remote code execution (RCE) by writing malicious files, such as a malicious `__init__.py` in the Python's `/site-packages/` directory.
