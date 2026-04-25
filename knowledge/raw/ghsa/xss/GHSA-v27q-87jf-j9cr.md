# Jenkins Pipeline Aggregator View Plugin vulnerable to Cross-site Scripting

**GHSA**: GHSA-v27q-87jf-j9cr | **CVE**: CVE-2023-28670 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **com.paul8620.jenkins.plugins:pipeline-aggregator-view** (maven): < 1.14

## Description

Jenkins Pipeline Aggregator View Plugin 1.13 and earlier does not escape a variable representing the current view's URL in inline JavaScript, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by authenticated attackers with Overall/Read permission. Version 1.14 obtains the current URL in a way not susceptible to XSS.
