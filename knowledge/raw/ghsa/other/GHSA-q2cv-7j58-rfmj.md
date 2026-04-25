# Liferay Portal Document and Media widget and Liferay DXP vulnerable to stored Cross-site Scripting

**GHSA**: GHSA-q2cv-7j58-rfmj | **CVE**: CVE-2023-47795 | **Severity**: critical (CVSS 9.1)

**CWE**: N/A

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): >= 7.4.3.18, <= 7.4.3.101
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q3, < 2023.Q3.6
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.13.u18, <= 7.4.13.u92

## Description

Stored cross-site scripting (XSS) vulnerability in the Document and Media widget in Liferay Portal 7.4.3.18 through 7.4.3.101, and Liferay DXP 2023.Q3 before patch 6, and 7.4 update 18 through 92 allows remote authenticated users to inject arbitrary web script or HTML via a crafted payload injected into a document's “Title” text field.
