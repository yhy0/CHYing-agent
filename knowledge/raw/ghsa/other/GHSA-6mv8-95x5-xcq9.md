# H2O local file inclusion vulnerability

**GHSA**: GHSA-6mv8-95x5-xcq9 | **CVE**: CVE-2023-6038 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-29, CWE-862

**Affected Packages**:
- **ai.h2o:h2o-core** (maven): <= 3.40.0.4

## Description

A Local File Inclusion (LFI) vulnerability exists in the h2o-3 REST API, allowing unauthenticated remote attackers to read arbitrary files on the server with the permissions of the user running the h2o-3 instance. This issue affects the default installation and does not require user interaction. The vulnerability can be exploited by making specific GET or POST requests to the ImportFiles and ParseSetup endpoints, respectively. This issue was identified in version 3.40.0.4 of h2o-3.
