# LoLLMS Command Injection vulnerability

**GHSA**: GHSA-pwc9-q4hj-pg8g | **CVE**: CVE-2024-4078 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-77

**Affected Packages**:
- **lollms** (pip): < 9.5.0

## Description

A vulnerability in the parisneo/lollms, specifically in the `/unInstall_binding` endpoint, allows for arbitrary code execution due to insufficient sanitization of user input. The issue arises from the lack of path sanitization when handling the `name` parameter in the `unInstall_binding` function, allowing an attacker to traverse directories and execute arbitrary code by loading a malicious `__init__.py` file. This vulnerability affects the latest version of the software. The exploitation of this vulnerability could lead to remote code execution on the system where parisneo/lollms is deployed.
