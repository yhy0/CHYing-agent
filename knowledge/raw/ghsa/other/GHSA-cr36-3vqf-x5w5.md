# Liferay Portal Expando module and Liferay DXP vulnerable to stored Cross-site Scripting

**GHSA**: GHSA-cr36-3vqf-x5w5 | **CVE**: CVE-2024-25601 | **Severity**: critical (CVSS 9.1)

**CWE**: N/A

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): <= 7.4.2
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3.0, < 7.3.10.u4
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.2.0, < 7.2.10.fp17

## Description

Stored cross-site scripting (XSS) vulnerability in Expando module's geolocation custom fields in Liferay Portal 7.2.0 through 7.4.2, and older unsupported versions, and Liferay DXP 7.3 before service pack 3, 7.2 before fix pack 17, and older unsupported versions allows remote authenticated users to inject arbitrary web script or HTML via a crafted payload injected into the name text field of a geolocation custom field.
