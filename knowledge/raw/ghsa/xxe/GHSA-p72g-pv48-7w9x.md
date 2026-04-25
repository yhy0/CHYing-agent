# Apache Tika XXE Vulnerability via Crafted XFA File Inside a PDF

**GHSA**: GHSA-p72g-pv48-7w9x | **CVE**: CVE-2025-54988 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-611

**Affected Packages**:
- **org.apache.tika:tika-parser-pdf-module** (maven): >= 1.13, < 3.2.2
- **org.apache.tika:tika-parsers** (maven): >= 1.13, < 2.0.0-ALPHA

## Description

Critical XXE in Apache Tika (tika-parser-pdf-module) in Apache Tika 1.13 through and including 3.2.1 on all platforms allows an attacker to carry out XML External Entity injection via a crafted XFA file inside of a PDF. An attacker may be able to read sensitive data or trigger malicious requests to internal resources or third-party servers. Note that the tika-parser-pdf-module is used as a dependency in several Tika packages including at least: tika-parsers-standard-modules, tika-parsers-standard-package, tika-app, tika-grpc and tika-server-standard.

Users are recommended to upgrade to version 3.2.2, which fixes this issue.
