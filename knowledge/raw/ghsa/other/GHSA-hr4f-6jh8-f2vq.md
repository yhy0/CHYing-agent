# OpenFGA DoS vulnerability

**GHSA**: GHSA-hr4f-6jh8-f2vq | **CVE**: CVE-2023-45810 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/openfga/openfga** (go): < 1.3.4

## Description

## Overview
OpenFGA is vulnerable to a DoS attack. When a number of ListObjects calls are executed, in some scenarios, those calls are not releasing resources even after a response has been sent, and the service as a whole becomes unresponsive.

## Fix
Upgrade to v1.3.4. This upgrade is backwards compatible.
