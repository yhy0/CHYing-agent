# Directory traversal in zenml

**GHSA**: GHSA-6h3f-43vq-53hj | **CVE**: CVE-2024-2083 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-29

**Affected Packages**:
- **zenml** (pip): < 0.55.5

## Description

A directory traversal vulnerability exists in the zenml-io/zenml repository, specifically within the /api/v1/steps endpoint. Attackers can exploit this vulnerability by manipulating the 'logs' URI path in the request to fetch arbitrary file content, bypassing intended access restrictions. The vulnerability arises due to the lack of validation for directory traversal patterns, allowing attackers to access files outside of the restricted directory.
