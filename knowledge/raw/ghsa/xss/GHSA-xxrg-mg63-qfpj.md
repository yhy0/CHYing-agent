# Jenkins AnchorChain Plugin Has a Cross-Site Scripting (XSS) Vulnerability

**GHSA**: GHSA-xxrg-mg63-qfpj | **CVE**: CVE-2025-30196 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **org.jenkins-ci.plugins:anchorchain** (maven): = 1.0

## Description

Jenkins AnchorChain Plugin 1.0 does not limit URL schemes for links it creates based on workspace content, allowing the javascript: scheme.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to control the input file for the Anchor Chain post-build step.

As of publication of this advisory, there is no fix.
