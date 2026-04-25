# Gogs: DOM-based XSS via milestone selection

**GHSA**: GHSA-vgjm-2cpf-4g7c | **CVE**: CVE-2026-26276 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-79

**Affected Packages**:
- **gogs.io/gogs** (go): <= 0.13.3

## Description

# Summary

It was confirmed in a test environment that an attacker can store an HTML/JavaScript payload in a repository’s **Milestone name**, and when another user selects that Milestone on the **New Issue** page (`/issues/new`), a **DOM-Based XSS** is triggered.

# Impact

* Theft of information accessible in the victim’s session.
* Extraction of CSRF tokens and submission of state-changing requests with the victim’s privileges.
* Repository operations performed with the victim’s privileges (Issue operations, settings changes, etc.).

(The impact scope depends on the victim’s permission level.)

# Remediation

A fix is available at https://github.com/gogs/gogs/releases/tag/v0.14.2
