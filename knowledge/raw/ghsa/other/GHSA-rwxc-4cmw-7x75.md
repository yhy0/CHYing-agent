# Liferay Portal and Liferay DXP vulnerable to stored Cross-site Scripting

**GHSA**: GHSA-rwxc-4cmw-7x75 | **CVE**: CVE-2024-26266 | **Severity**: critical (CVSS 9.1)

**CWE**: N/A

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): <= 7.4.3.13
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.13.u1, < 7.4.13.u10
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3.10.ep3, < 7.3.10.u4
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.2.0, < 7.2.10.fp17

## Description

Multiple stored cross-site scripting (XSS) vulnerabilities in Liferay Portal 7.2.0 through 7.4.3.13, and older unsupported versions, and Liferay DXP 7.4 before update 10, 7.3 before update 4, 7.2 before fix pack 17, and older unsupported versions allow remote authenticated users to inject arbitrary web script or HTML via a crafted payload injected into the first/middle/last name text field of the user who creates an entry in the (1) Announcement widget, or (2) Alerts widget.
