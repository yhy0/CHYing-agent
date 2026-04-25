# Langflow CORS misconfiguration enables Account Takeover and RCE

**GHSA**: GHSA-577h-p2hh-v4mv | **CVE**: CVE-2025-34291 | **Severity**: critical (CVSS 8.8)

**CWE**: CWE-346

**Affected Packages**:
- **langflow** (pip): <= 1.6.9

## Description

Langflow versions up to and including 1.6.9 contain a chained vulnerability that enables account takeover and remote code execution. An overly permissive CORS configuration (allow_origins='*' with allow_credentials=True) combined with a refresh token cookie configured as SameSite=None allows a malicious webpage to perform cross-origin requests that include credentials and successfully call the refresh endpoint. An attacker-controlled origin can therefore obtain fresh access_token / refresh_token pairs for a victim session. Obtained tokens permit access to authenticated endpoints — including built-in code-execution functionality — allowing the attacker to execute arbitrary code and achieve full system compromise.
