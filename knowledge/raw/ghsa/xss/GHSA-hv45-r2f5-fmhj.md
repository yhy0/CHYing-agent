# Liferay Portal and Liferay DXP Vulnerable to XSS in the Wiki Widget

**GHSA**: GHSA-hv45-r2f5-fmhj | **CVE**: CVE-2023-42628 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **com.liferay:com.liferay.wiki.web** (maven): < 7.0.95
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.0.10.fp83, <= 7.0.10.fp102
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.1.0, <= 7.1.10.fp28
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.2.0, <= 7.2.10.fp20
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3.0, < 7.3.10.u34
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.0, < 7.4.13.u88

## Description

Stored cross-site scripting (XSS) vulnerability in the Wiki widget in Liferay Wiki Web before 7.0.95 from Liferay Portal (7.1.0 through 7.4.3.87), and Liferay DXP 7.0 fix pack 83 through 102, 7.1 fix pack 28 and earlier, 7.2 fix pack 20 and earlier, 7.3 update 33 and earlier, and 7.4 before update 88 allows remote attackers to inject arbitrary web script or HTML into a parent wiki page via a crafted payload injected into a wiki page's ‘Content’ text field.
