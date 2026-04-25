# pgAdmin 4 vulnerable to Unsafe Deserialization and Remote Code Execution by an Authenticated user

**GHSA**: GHSA-rj98-crf4-g69w | **CVE**: CVE-2024-2044 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-22, CWE-31, CWE-502

**Affected Packages**:
- **pgAdmin4** (pip): < 8.4

## Description

pgAdmin prior to version 8.4 is affected by a path-traversal vulnerability while deserializing users’ sessions in the session handling code. If the server is running on Windows, an unauthenticated attacker can load and deserialize remote pickle objects and gain code execution. If the server is running on POSIX/Linux, an authenticated attacker can upload pickle objects, deserialize them and gain code execution.
