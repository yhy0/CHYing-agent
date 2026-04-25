# LoLLMS Path Traversal vulnerability

**GHSA**: GHSA-3x47-w4rx-6pm7 | **CVE**: CVE-2024-3429 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-22, CWE-29

**Affected Packages**:
- **lollms** (pip): < 9.5.0

## Description

A path traversal vulnerability exists in the parisneo/lollms application, specifically within the `sanitize_path_from_endpoint` and `sanitize_path` functions in `lollms_core\lollms\security.py`. This vulnerability allows for arbitrary file reading when the application is running on Windows. The issue arises due to insufficient sanitization of user-supplied input, enabling attackers to bypass the path traversal protection mechanisms by crafting malicious input. Successful exploitation could lead to unauthorized access to sensitive files, information disclosure, and potentially a denial of service (DoS) condition by including numerous large or resource-intensive files. This vulnerability affects the latest version prior to 9.5.0.
