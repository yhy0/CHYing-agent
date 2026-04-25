# Liferay Portal has a Stored XSS with Blog entries (Insecure defaults)

**GHSA**: GHSA-vvpf-53qx-cxhh | **CVE**: CVE-2024-25610 | **Severity**: critical (CVSS 9.1)

**CWE**: N/A

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): < 7.4.3.13
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.0, < 7.4.13.u9
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3.0, < 7.3.10.u4
- **com.liferay.portal:release.dxp.bom** (maven): < 7.2.10.fp19
- **com.liferay.portal:com.liferay.portal.web** (maven): < 5.0.96

## Description

In Liferay Portal 7.2.0 through 7.4.3.12, and older unsupported versions, and Liferay DXP 7.4 before update 9, 7.3 before update 4, 7.2 before fix pack 19, and older unsupported versions, the default configuration does not sanitize blog entries of JavaScript, which allows remote authenticated users to inject arbitrary web script or HTML (XSS) via a crafted payload injected into a blog entry’s content text field.
