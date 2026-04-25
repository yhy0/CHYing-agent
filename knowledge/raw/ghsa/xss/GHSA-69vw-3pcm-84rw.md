# Jenkins Stored Cross-site Scripting vulnerability 

**GHSA**: GHSA-69vw-3pcm-84rw | **CVE**: CVE-2023-39151 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **org.jenkins-ci.main:jenkins-core** (maven): < 2.401.3
- **org.jenkins-ci.main:jenkins-core** (maven): = 2.415
- **org.jenkins-ci.main:jenkins-core** (maven): >= 2.402, < 2.414.1

## Description

Jenkins applies formatting to the console output of builds, transforming plain URLs into hyperlinks. Jenkins 2.415 and earlier, 2.414 and earlier, and LTS 2.401.2 and earlier does not sanitize or properly encode URLs of these hyperlinks in build logs. This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to control build log contents. Jenkins 2.416, 2.414.1, and LTS 2.401.3 encodes URLs of affected hyperlink annotations in build logs.

