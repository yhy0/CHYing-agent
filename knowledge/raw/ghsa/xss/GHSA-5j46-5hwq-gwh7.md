# Jenkins Cross-site Scripting vulnerability

**GHSA**: GHSA-5j46-5hwq-gwh7 | **CVE**: CVE-2023-43495 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **org.jenkins-ci.main:jenkins-core** (maven): >= 2.50, < 2.414.2
- **org.jenkins-ci.main:jenkins-core** (maven): >= 2.415, < 2.424

## Description

`ExpandableDetailsNote` allows annotating build log content with additional information that can be revealed when interacted with.

Jenkins 2.423 and earlier, LTS 2.414.1 and earlier does not escape the value of the `caption` constructor parameter of `ExpandableDetailsNote`.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to provide `caption` parameter values.

As of publication, the related API is not used within Jenkins (core), and the Jenkins security team is not aware of any affected plugins.
Jenkins 2.424, LTS 2.414.2 escapes `caption` constructor parameter values.
