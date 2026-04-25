# Liferay Portal and Liferay DXP Vulnerable to Stored XSS in the Manage Vocabulary Page

**GHSA**: GHSA-g44j-f8wm-6622 | **CVE**: CVE-2023-42629 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **com.liferay:com.liferay.asset.categories.admin.web** (maven): < 5.0.87
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.0, < 7.4.13.u88

## Description

Stored cross-site scripting (XSS) vulnerability in the manage vocabulary page in the Asset Categories Admin Web module before 5.0.87 from Liferay Portal (7.4.2 through 7.4.3.87), and Liferay DXP 7.4 before update 88 allows remote attackers to inject arbitrary web script or HTML via a crafted payload injected into a Vocabulary's 'description' text field.
