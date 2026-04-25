# Liferay Portal and Liferay DXP Vulnerable to XSS in the Fragment Components

**GHSA**: GHSA-j663-6jpj-xx8c | **CVE**: CVE-2023-44309 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **com.liferay:com.liferay.fragment.entry.processor.impl** (maven): < 3.0.25
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.0, < 7.4.13.u54

## Description

Multiple stored cross-site scripting (XSS) vulnerabilities in the fragment components before 3.0.25 from Liferay Portal (7.4.2 through 7.4.3.53), and Liferay DXP 7.4 before update 54 allow remote attackers to inject arbitrary web script or HTML via a crafted payload injected into any non-HTML field of a linked source asset.
