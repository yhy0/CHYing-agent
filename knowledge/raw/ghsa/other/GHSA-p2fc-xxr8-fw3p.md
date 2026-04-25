# Liferay Portal and Liferay DXP Vulnerable to CSRF via the Layout Module

**GHSA**: GHSA-p2fc-xxr8-fw3p | **CVE**: CVE-2023-35030 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-352

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): >= 7.4.3.70-ga70, < 7.4.3.77-ga77
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.13.u70, <= 7.4.13.u76

## Description

Cross-site request forgery (CSRF) vulnerability in the Layout module's SEO configuration in Liferay Portal 7.4.3.70 through 7.4.3.76, and Liferay DXP 7.4 update 70 through 76 allows remote attackers to execute arbitrary code in the scripting console via the `_com_liferay_layout_admin_web_portlet_GroupPagesPortlet_backURL` parameter.
