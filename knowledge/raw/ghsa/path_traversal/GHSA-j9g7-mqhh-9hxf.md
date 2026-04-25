# DB-GPT Absolute Path Traversal in knowledge/{space_name}/document/upload

**GHSA**: GHSA-j9g7-mqhh-9hxf | **CVE**: CVE-2024-10833 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-22, CWE-36

**Affected Packages**:
- **dbgpt** (pip): < 0.6.2

## Description

eosphoros-ai/db-gpt version 0.6.0 is vulnerable to an arbitrary file write through the knowledge API. The endpoint for uploading files as 'knowledge' is susceptible to absolute path traversal, allowing attackers to write files to arbitrary locations on the target server. This vulnerability arises because the 'doc_file.filename' parameter is user-controllable, enabling the construction of absolute paths.
