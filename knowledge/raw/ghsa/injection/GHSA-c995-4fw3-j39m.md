# Duplicate Advisory: Langflow Vulnerable to Code Injection via the `/api/v1/validate/code` endpoint

**GHSA**: GHSA-c995-4fw3-j39m | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94, CWE-306

**Affected Packages**:
- **langflow** (pip): < 1.3.0

## Description

### Duplicate Advisory

This advisory has been withdrawn because it is a duplicate of GHSA-rvqx-wpfh-mfx7. This link is maintained to preserve external references.

### Original Description

Langflow versions prior to 1.3.0 are susceptible to code injection in the `/api/v1/validate/code` endpoint. A remote and unauthenticated attacker can send crafted HTTP requests to execute arbitrary code.
