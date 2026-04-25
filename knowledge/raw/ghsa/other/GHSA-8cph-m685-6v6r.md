# OpenFGA Authorization Bypass

**GHSA**: GHSA-8cph-m685-6v6r | **CVE**: CVE-2024-31452 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-285, CWE-863

**Affected Packages**:
- **github.com/openfga/openfga** (go): >= 1.5.0, < 1.5.3

## Description

# Overview
Some end users of OpenFGA v1.5.0 or later are vulnerable to authorization bypass when calling Check or ListObjects APIs.

# Am I Affected?
You are very likely affected if your model involves exclusion (e.g. `a but not b`) or intersection (e.g. `a and b`) and you have any cyclical relationships. If you are using these, please update as soon as possible.

# Fix
Update to v1.5.3

# Backward Compatibility
This update is backward compatible.
