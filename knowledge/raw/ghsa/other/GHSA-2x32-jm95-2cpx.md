# Authentication Bypass in dex

**GHSA**: GHSA-2x32-jm95-2cpx | **CVE**: CVE-2020-27847 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-228, CWE-290

**Affected Packages**:
- **github.com/dexidp/dex** (go): < 2.27.0

## Description

A vulnerability exists in the SAML connector of the github.com/dexidp/dex library used to process SAML Signature Validation. This flaw allows an attacker to bypass SAML authentication. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability. This flaw affects dex versions before 2.27.0.
