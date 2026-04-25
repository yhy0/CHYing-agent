# InvokeAI has External Control of File Name or Path

**GHSA**: GHSA-vv9c-xxg7-wmv7 | **CVE**: CVE-2025-6237 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22, CWE-73

**Affected Packages**:
- **invokeai** (pip): < 6.7.0

## Description

### Path Traversal Vulnerability in InvokeAI

A path traversal vulnerability in **InvokeAI** (versions < 6.7.0) allows an unauthenticated remote attacker to read files outside the intended media directory via the **bulk downloads** API.

The endpoint accepts a user-controlled file/item name and concatenates it into a filesystem path without proper canonicalization or allow-listing. By supplying sequences such as `../` (or absolute paths), an attacker can cause the server to traverse directories and return arbitrary files.

In certain storage or back-end configurations, abusing attacker-controlled paths can also lead to unintended overwriting or deletion of files referenced by the crafted path.

The issue is fixed in **6.7.0**, which normalizes and validates input paths and rejects traversal attempts.

**Affected versions:** `< 6.7.0`
**Patched version:** `6.7.0`
