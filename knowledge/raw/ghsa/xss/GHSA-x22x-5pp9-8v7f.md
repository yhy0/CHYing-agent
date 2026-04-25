# Content-Security-Policy disabled by Red Hat Dependency Analytics Jenkins Plugin

**GHSA**: GHSA-x22x-5pp9-8v7f | **CVE**: CVE-2024-23905 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-79

**Affected Packages**:
- **io.jenkins.plugins:redhat-dependency-analytics** (maven): < 0.9.0

## Description

Jenkins sets the Content-Security-Policy header to static files served by Jenkins (specifically DirectoryBrowserSupport), such as workspaces, /userContent, or archived artifacts, unless a Resource Root URL is specified.

Red Hat Dependency Analytics Plugin 0.7.1 and earlier globally disables the Content-Security-Policy header for static files served by Jenkins whenever the 'Invoke Red Hat Dependency Analytics (RHDA)' build step is executed. This allows cross-site scripting (XSS) attacks by users with the ability to control files in workspaces, archived artifacts, etc.

