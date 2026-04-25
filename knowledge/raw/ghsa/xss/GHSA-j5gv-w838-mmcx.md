# Liferay Portal and Liferay DXP Vulnerable to XSS via the Page Tree Menu

**GHSA**: GHSA-j5gv-w838-mmcx | **CVE**: CVE-2023-44310 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **com.liferay:com.liferay.layout.impl** (maven): < 6.0.102
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3.10.fp1, <= 7.3.10.fp23
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.0, < 7.4.13.u79

## Description

Stored cross-site scripting (XSS) vulnerability in Page Tree menu in Liferay Layout Implementation before 6.0.102 from Liferay Portal (7.3.6 through 7.4.3.78), and Liferay DXP 7.3 fix pack 1 through update 23, and 7.4 before update 79 allows remote attackers to inject arbitrary web script or HTML via a crafted payload injected into page's "Name" text field.
