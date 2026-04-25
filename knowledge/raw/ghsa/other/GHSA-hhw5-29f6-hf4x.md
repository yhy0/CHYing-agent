# DB-GPT Absolute Path Traversal vulnerability

**GHSA**: GHSA-hhw5-29f6-hf4x | **CVE**: CVE-2024-10831 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-36

**Affected Packages**:
- **dbgpt** (pip): <= 0.6.0

## Description

In eosphoros-ai/db-gpt version 0.6.0, the endpoint for uploading files is vulnerable to absolute path traversal. This vulnerability allows an attacker to upload arbitrary files to arbitrary locations on the target server. The issue arises because the `file_key` and `doc_file.filename` parameters are user-controllable, enabling the construction of paths outside the intended directory. This can lead to overwriting essential system files, such as SSH keys, for further exploitation.
