# Open WebUI Cross-Site Request Forgery (CSRF) Vulnerability

**GHSA**: GHSA-85jc-8h5p-8vw8 | **CVE**: CVE-2024-7806 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-352

**Affected Packages**:
- **open-webui** (pip): < 0.3.33

## Description

A vulnerability in open-webui/open-webui versions <= 0.3.8 allows remote code execution by non-admin users via Cross-Site Request Forgery (CSRF). The application uses cookies with the SameSite attribute set to lax for authentication and lacks CSRF tokens. This allows an attacker to craft a malicious HTML that, when accessed by a victim, can modify the Python code of an existing pipeline and execute arbitrary code with the victim's privileges.
