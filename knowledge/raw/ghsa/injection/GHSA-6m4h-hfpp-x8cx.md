# docconv OS Command Injection vulnerability

**GHSA**: GHSA-6m4h-hfpp-x8cx | **CVE**: CVE-2022-4643 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/sajari/docconv** (go): < 1.2.1
- **code.sajari.com/docconv** (go): >= 1.1.0, < 1.3.5

## Description

A vulnerability was found in docconv prior to version 1.2.1. It has been declared as critical. This vulnerability affects the function ConvertPDFImages of the file pdf_ocr.go. The manipulation of the argument path leads to os command injection. The attack can be initiated remotely. Upgrading to version 1.2.1 can address this issue. The name of the patch is b19021ade3d0b71c89d35cb00eb9e589a121faa5. It is recommended to upgrade the affected component. VDB-216502 is the identifier assigned to this vulnerability.
