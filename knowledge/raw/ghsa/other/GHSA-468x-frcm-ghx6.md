# Liferay Portal and Liferay DXP vulnerable to reflected Cross-site Scripting

**GHSA**: GHSA-468x-frcm-ghx6 | **CVE**: CVE-2023-40191 | **Severity**: critical (CVSS 9.1)

**CWE**: N/A

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): >= 7.4.3.44, <= 7.4.3.97
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q3, < 2023.Q3.6
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.13.u44, <= 7.4.13.u92

## Description

Reflected cross-site scripting (XSS) vulnerability in the instance settings for Accounts in Liferay Portal 7.4.3.44 through 7.4.3.97, and Liferay DXP 2023.Q3 before patch 6, and 7.4 update 44 through 92 allows remote attackers to inject arbitrary web script or HTML via a crafted payload injected into the “Blocked Email Domains” text field
