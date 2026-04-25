# Liferay Portal and Liferay DXP Vulnerable to XSS via the OAuth2ProviderApplicationRedirect Class

**GHSA**: GHSA-49gm-5685-8fxv | **CVE**: CVE-2023-44311 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-79

**Affected Packages**:
- **com.liferay:com.liferay.oauth2.provider.rest** (maven): < 4.0.51
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.13.u41, < 7.4.13.u90

## Description

Multiple reflected cross-site scripting (XSS) vulnerabilities in the Plugin for OAuth 2.0 module's OAuth2ProviderApplicationRedirect class before 4.0.51 from Liferay Portal (7.4.3.41 through 7.4.3.89), and Liferay DXP 7.4 update 41 through update 89 allow remote attackers to inject arbitrary web script or HTML via the (1) code, or (2) error parameter. This issue is caused by an incomplete fix in CVE-2023-33941.
