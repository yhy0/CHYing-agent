# Crawl4AI Has Local File Inclusion in Docker API via file:// URLs

**GHSA**: GHSA-vx9w-5cx4-9796 | **CVE**: CVE-2026-26217 | **Severity**: critical (CVSS 8.6)

**CWE**: CWE-22

**Affected Packages**:
- **crawl4ai** (pip): < 0.8.0

## Description

A local file inclusion vulnerability exists in the Crawl4AI Docker API. The /execute_js, /screenshot, /pdf, and /html endpoints accept file:// URLs, allowing attackers to read arbitrary files from the server filesystem.

Attack Vector:
```json
POST /execute_js
{
    "url": "file:///etc/passwd",
    "scripts": ["document.body.innerText"]
}
```
Impact

An unauthenticated attacker can:
- Read sensitive files (/etc/passwd, /etc/shadow, application configs)
- Access environment variables via /proc/self/environ
- Discover internal application structure
- Potentially read credentials and API keys

Workarounds

1. Disable the Docker API
2. Add authentication to the API
3. Use network-level filtering
