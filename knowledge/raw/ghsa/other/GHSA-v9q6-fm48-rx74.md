# Authentication bypass in dtale

**GHSA**: GHSA-v9q6-fm48-rx74 | **CVE**: CVE-2024-3408 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-20, CWE-798

**Affected Packages**:
- **dtale** (pip): <= 3.10.0

## Description

man-group/dtale version 3.10.0 is vulnerable to an authentication bypass and remote code execution (RCE) due to improper input validation. The vulnerability arises from a hardcoded `SECRET_KEY` in the flask configuration, allowing attackers to forge a session cookie if authentication is enabled. Additionally, the application fails to properly restrict custom filter queries, enabling attackers to execute arbitrary code on the server by bypassing the restriction on the `/update-settings` endpoint, even when `enable_custom_filters` is not enabled. This vulnerability allows attackers to bypass authentication mechanisms and execute remote code on the server.
