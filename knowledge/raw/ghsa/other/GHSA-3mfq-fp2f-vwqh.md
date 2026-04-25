# Liferay Portal and Liferay DXP Workflow Component Does Not Check User Permissions

**GHSA**: GHSA-3mfq-fp2f-vwqh | **CVE**: CVE-2024-38002 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-862, CWE-863

**Affected Packages**:
- **com.liferay.portal:release.portal.bom** (maven): >= 7.3.2-ga3, < 7.4.3.112-ga112
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q4.0, < 2023.Q4.6
- **com.liferay.portal:release.dxp.bom** (maven): >= 2023.Q3.1, < 2023.Q3.9
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3-ga, < 7.3.10.u36
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4-ga, < 7.4.13.u92

## Description

The workflow component in Liferay Portal 7.3.2 through 7.4.3.111, and Liferay DXP 2023.Q4.0 through 2023.Q4.5, 2023.Q3.1 through 2023.Q3.8, 7.4 GA through update 92 and 7.3 GA through update 36 does not properly check user permissions before updating a workflow definition, which allows remote authenticated users to modify workflow definitions and execute arbitrary code (RCE) via the headless API.
