# Duplicate Advisory: ecnepsnai/web vulnerable to Uncontrolled Resource Consumption

**GHSA**: GHSA-jpgg-cp2x-qrw3 | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-400, CWE-476

**Affected Packages**:
- **github.com/ecnepsnai/web** (go): >= 1.4.0, < 1.5.2

## Description

## Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-5gjg-jgh4-gppm. This link is maintained to preserve external references.

## Original Description
Web Sockets do not execute any AuthenticateMethod methods which may be set, leading to a nil pointer dereference if the returned UserData pointer is assumed to be non-nil, or authentication bypass. This issue only affects WebSockets with an AuthenticateMethod hook. Request handlers that do not explicitly use WebSockets are not vulnerable.
