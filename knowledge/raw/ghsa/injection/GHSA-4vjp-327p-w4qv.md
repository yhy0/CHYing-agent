# Jenkins Templating Engine Plugin Vulnerable to Arbitrary Code Execution

**GHSA**: GHSA-4vjp-327p-w4qv | **CVE**: CVE-2025-31722 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **org.jenkins-ci.plugins:templating-engine** (maven): < 2.5.4

## Description

Jenkins Templating Engine Plugin allows defining libraries both in the global configuration, as well as scoped to folders containing the pipelines using them. While libraries in the global configuration can only be set up by administrators and can therefore be trusted, libraries defined in folders can be configured by users with Item/Configure permission.

In Templating Engine Plugin 2.5.3 and earlier, libraries defined in folders are not subject to sandbox protection. This vulnerability allows attackers with Item/Configure permission to execute arbitrary code in the context of the Jenkins controller JVM.

In Templating Engine Plugin 2.5.4, libraries defined in folders are subject to sandbox protection.
