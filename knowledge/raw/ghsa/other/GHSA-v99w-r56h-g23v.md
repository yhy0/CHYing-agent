# Owncast Cross-Site Request Forgery vulnerability

**GHSA**: GHSA-v99w-r56h-g23v | **CVE**: CVE-2024-29026 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-352

**Affected Packages**:
- **github.com/owncast/owncast** (go): <= 0.1.2

## Description

Owncast is an open source, self-hosted, decentralized, single user live video streaming and chat server. In versions 0.1.2 and prior, a lenient CORS policy allows attackers to make a cross origin request, reading privileged information. This can be used to leak the admin password. Commit 9215d9ba0f29d62201d3feea9e77dcd274581624 fixes this issue.
