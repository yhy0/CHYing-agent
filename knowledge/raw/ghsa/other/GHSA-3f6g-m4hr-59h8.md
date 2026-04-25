# OpenFGA Authorization Bypass

**GHSA**: GHSA-3f6g-m4hr-59h8 | **CVE**: CVE-2024-42473 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-285, CWE-863

**Affected Packages**:
- **github.com/openfga/openfga** (go): >= 1.5.7, < 1.5.9

## Description

## Overview

OpenFGA v1.5.7 and v1.5.8 are vulnerable to authorization bypass when calling Check API with a model that uses `but not` and `from` expressions and a userset. 

## Fix

- If you are using OpenFGA within Docker or as a Go library, as a binary, or through Docker, upgrade to v1.5.9 as soon as possible
- If using Helm chart, upgrade to 0.2.12 as soon as possible. 

This fix is backward compatible.
