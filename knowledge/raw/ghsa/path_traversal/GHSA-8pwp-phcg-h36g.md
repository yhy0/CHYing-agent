# DB-GPT Path Traversal vulnerability

**GHSA**: GHSA-8pwp-phcg-h36g | **CVE**: CVE-2024-10830 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-22

**Affected Packages**:
- **dbgpt** (pip): <= 0.6.0

## Description

A Path Traversal vulnerability exists in the eosphoros-ai/db-gpt version 0.6.0 at the API endpoint `/v1/resource/file/delete`. This vulnerability allows an attacker to delete any file on the server by manipulating the `file_key` parameter. The `file_key` parameter is not properly sanitized, enabling an attacker to specify arbitrary file paths. If the specified file exists, the application will delete it.
