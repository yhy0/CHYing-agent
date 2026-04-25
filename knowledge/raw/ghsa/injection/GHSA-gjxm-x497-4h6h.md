# Duplicate Advisory: D-Tale Command Injection vulnerability

**GHSA**: GHSA-gjxm-x497-4h6h | **CVE**: CVE-2025-0655 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-77, CWE-78

**Affected Packages**:
- **dtale** (pip): < 3.17.0

## Description

## Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-832w-fhmw-w4f4. This link is maintained to preserve external references.

## Original Description
A vulnerability in man-group/dtale versions 3.15.1 allows an attacker to override global state settings to enable the `enable_custom_filters` feature, which is typically restricted to trusted environments. Once enabled, the attacker can exploit the /test-filter endpoint to execute arbitrary system commands, leading to remote code execution (RCE). This issue is addressed in version 3.16.1.
