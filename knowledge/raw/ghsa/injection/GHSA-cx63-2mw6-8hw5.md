# setuptools vulnerable to Command Injection via package URL

**GHSA**: GHSA-cx63-2mw6-8hw5 | **CVE**: CVE-2024-6345 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **setuptools** (pip): < 70.0.0

## Description

A vulnerability in the `package_index` module of pypa/setuptools versions up to 69.1.1 allows for remote code execution via its download functions. These functions, which are used to download packages from URLs provided by users or retrieved from package index servers, are susceptible to code injection. If these functions are exposed to user-controlled inputs, such as package URLs, they can execute arbitrary commands on the system. The issue is fixed in version 70.0.
