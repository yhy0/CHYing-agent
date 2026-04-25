# Liferay Portal and Liferay DXP Vulnerable to Cross-Site Request Forgery (CSRF) via the My Account Widget

**GHSA**: GHSA-6c4v-x9v2-rjm8 | **CVE**: CVE-2024-26271 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-352

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): >= 7.4.3.75, < 7.4.3.112
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q4.0, < 2023.Q4.3
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q3.1, < 2023.Q3.6
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3u32, <= 7.3u36
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4u75, <= 7.4u92

## Description

Cross-site request forgery (CSRF) vulnerability in the My Account widget in Liferay Portal 7.4.3.75 through 7.4.3.111, and Liferay DXP 2023.Q4.0 through 2023.Q4.2, 2023.Q3.1 through 2023.Q3.5, 7.4 update 75 through update 92 and 7.3 update 32 through update 36 allows remote attackers to (1) change user passwords, (2) shut down the server, (3) execute arbitrary code in the scripting console, (4) and perform other administrative actions via the _com_liferay_my_account_web_portlet_MyAccountPortlet_backURL parameter.
