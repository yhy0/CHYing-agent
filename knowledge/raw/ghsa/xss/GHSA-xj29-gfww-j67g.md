# Jenkins JaCoCo Plugin vulnerable to Stored Cross-site Scripting

**GHSA**: GHSA-xj29-gfww-j67g | **CVE**: CVE-2023-28669 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **org.jenkins-ci.plugins:jacoco** (maven): < 3.3.2.1

## Description

Jenkins JaCoCo Plugin 3.3.2 and earlier does not escape class and method names shown on the UI, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to control input files for the 'Record JaCoCo coverage report' post-build action. Version 3.3.2.1 escapes class and method names shown on the UI.
