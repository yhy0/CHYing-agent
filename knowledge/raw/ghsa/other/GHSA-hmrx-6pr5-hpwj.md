# Liferay Portal and Liferay DXP Vulnerable to Cross-Site Request Forgery (CSRF) via the Content Page Editor

**GHSA**: GHSA-hmrx-6pr5-hpwj | **CVE**: CVE-2024-26273 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-352

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): >= 7.4.0, < 7.4.3.104
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q4.0, < 2023.Q4.3
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q3.1, < 2023.Q3.6
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.GA, <= 7.4u92
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3u29, < 7.3u36

## Description

Cross-site request forgery (CSRF) vulnerability in the content page editor in Liferay Portal 7.4.0 through 7.4.3.103, and Liferay DXP 2023.Q4.0 through 2023.Q4.2, 2023.Q3.1 through 2023.Q3.5, 7.4 GA through update 92 and 7.3 update 29 through update 35 allows remote attackers to (1) change user passwords, (2) shut down the server, (3) execute arbitrary code in the scripting console, (4) and perform other administrative actions via the `_com_liferay_commerce_catalog_web_internal_portlet_CommerceCatalogsPortlet_redirect` parameter.
