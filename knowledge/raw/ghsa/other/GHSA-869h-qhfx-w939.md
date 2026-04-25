# Liferay Portal has an XXE vulnerability in Java2WsddTask._format

**GHSA**: GHSA-869h-qhfx-w939 | **CVE**: CVE-2024-25606 | **Severity**: high (CVSS 8.1)

**CWE**: N/A

**Affected Packages**:
- **com.liferay.portal:com.liferay.util.java** (maven): < 14.0.0
- **com.liferay.portal:release.portal.bom** (maven): < 7.4.3.8
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.3.0, < 7.3.10.u12
- **com.liferay.portal:release.dxp.bom** (maven): >= 7.4.0, < 7.4.13.u4
- **com.liferay.portal:release.dxp.bom** (maven): < 7.2.10.fp20

## Description

XXE vulnerability in Liferay Portal 7.2.0 through 7.4.3.7, and older unsupported versions, and Liferay DXP 7.4 before update 4, 7.3 before update 12, 7.2 before fix pack 20, and older unsupported versions allows attackers with permission to deploy widgets/portlets/extensions to obtain sensitive information or consume system resources via the Java2WsddTask._format method.
