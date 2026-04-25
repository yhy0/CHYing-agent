# Liferay Portal and Liferay DXP Vulnerable to Cross-Site Request Forgery (CSRF) via the Content Page Editor

**GHSA**: GHSA-p63m-vmjr-wg37 | **CVE**: CVE-2024-26272 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-352

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): >= 7.3.2, < 7.4.3.108
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q4.0, < 2023.Q4.3
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q3.1, < 2023.Q3.6
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3.GA, < 7.3u36
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.GA, <= 7.4u92

## Description

Cross-site request forgery (CSRF) vulnerability in the content page editor in Liferay Portal 7.3.2 through 7.4.3.107, and Liferay DXP 2023.Q4.0 through 2023.Q4.2, 2023.Q3.1 through 2023.Q3.5, 7.4 GA through update 92 and 7.3 GA through update 35 allows remote attackers to (1) change user passwords, (2) shut down the server, (3) execute arbitrary code in the scripting console, (4) and perform other administrative actions via the p_l_back_url parameter.
