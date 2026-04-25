# SQL Injection in Gogs

**GHSA**: GHSA-g6xv-8q23-w2q3 | **CVE**: CVE-2014-8682 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-89

**Affected Packages**:
- **gogs.io/gogs** (go): >= 0.3.1, < 0.5.8

## Description

Multiple SQL injection vulnerabilities in Gogs (aka Go Git Service) 0.3.1-9 through 0.5.x before 0.5.6.1105 Beta allow remote attackers to execute arbitrary SQL commands via the q parameter to (1) api/v1/repos/search, which is not properly handled in models/repo.go, or (2) api/v1/users/search, which is not properly handled in models/user.go.
